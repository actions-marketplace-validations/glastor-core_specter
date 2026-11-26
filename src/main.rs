pub mod commit_guard;
pub mod config;
pub mod differ;
pub mod extractor;
#[cfg(test)]
mod golden_fpr_suite;
pub mod reachability;
pub mod report;
mod rust_ast;
mod ts_ast;

use anyhow::{Context, Result};
use clap::Parser;
use commit_guard::evaluate_commit_alignment;
use config::SpecterConfig;
use differ::diff_contracts_with_config;
use extractor::{
    ContractSnapshot, detect_language, extract_directory_contract_with_config,
    extract_in_memory_files_with_config, should_skip_dir, should_skip_file,
};
use report::{
    AuditVerdict, SpecterAuditReport, emit_github_telemetry, render_markdown_report,
    render_terminal_colored_diff, write_cyclonedx_sbom, write_sarif_report,
};
use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "specter",
    author = "Andrés Antonio Cardoso <ventas@glastor.es>",
    version,
    about = "GLASTOR® Specter — Zero-Compiler Polyglot AST API Contract Differ, Trojan Breaking-Change Detector & Mathematical SemVer Gatekeeper"
)]
pub struct CliArgs {
    /// Path to the current (HEAD) source directory to audit
    #[arg(long, env = "INPUT_HEAD_DIR", default_value = ".")]
    pub head_dir: String,

    /// Optional path to a base source directory to compare against
    #[arg(long, env = "INPUT_BASE_DIR", default_value = "")]
    pub base_dir: String,

    /// Optional Git reference (e.g., 'origin/main' or 'HEAD~1') to extract base API contract from
    #[arg(long, env = "INPUT_BASE_REF", default_value = "")]
    pub base_ref: String,

    /// Optional path to a previously saved ContractSnapshot JSON baseline
    #[arg(long, env = "INPUT_BASELINE_JSON", default_value = "")]
    pub baseline_json: String,

    /// Optional path to save the current HEAD ContractSnapshot JSON (for baseline caching)
    #[arg(long, env = "INPUT_SAVE_SNAPSHOT", default_value = "")]
    pub save_snapshot: String,

    /// Commit message or PR title to verify against AST contract impact (Trojan Commit Guard)
    #[arg(long, env = "INPUT_COMMIT_MESSAGE", default_value = "")]
    pub commit_message: String,

    /// Fail the workflow if any MAJOR breaking API change is detected (even if declared)
    #[arg(long, env = "INPUT_FAIL_ON_BREAKING", default_value_t = false)]
    pub fail_on_breaking: bool,

    /// Fail the workflow if a Trojan Breaking Change is detected (MAJOR change disguised as fix/feat/chore)
    #[arg(long, env = "INPUT_FAIL_ON_TROJAN", default_value_t = true)]
    pub fail_on_trojan: bool,

    /// Also fail if a MINOR public symbol addition is disguised as a PATCH commit (fix/chore)
    #[arg(
        long,
        alias = "strict-minor",
        env = "INPUT_STRICT_SEMVER",
        default_value_t = false
    )]
    pub strict_semver: bool,

    /// Optional explicit path to a `specter.toml` configuration file
    #[arg(long, env = "INPUT_CONFIG", default_value = "")]
    pub config: String,

    /// Optional path to export full JSON audit telemetry
    #[arg(long, env = "INPUT_OUTPUT_JSON", default_value = "")]
    pub output_json: String,

    /// Optional path to export SARIF 2.1.0 report for GitHub Security (Code Scanning)
    #[arg(long, env = "INPUT_OUTPUT_SARIF", default_value = "")]
    pub output_sarif: String,

    /// Optional path to export CycloneDX 1.5 API Contract SBOM JSON
    #[arg(long, env = "INPUT_OUTPUT_SBOM", default_value = "")]
    pub output_sbom: String,

    /// Optional path to export Markdown report for PR Sticky Comments
    #[arg(long, env = "INPUT_OUTPUT_MARKDOWN", default_value = "")]
    pub output_markdown: String,

    /// Optional format for stdout report: 'auto', 'text', 'markdown', or 'json'
    #[arg(long, env = "INPUT_FORMAT", default_value = "auto")]
    pub format: String,

    /// Color mode for terminal diff: 'auto', 'always', or 'never'
    #[arg(long, env = "INPUT_COLOR", default_value = "auto")]
    pub color: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("❌ [GLASTOR Specter Fatal Error]: {:#}", err);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let start = Instant::now();
    let args = CliArgs::parse();

    let head_path = Path::new(args.head_dir.trim());
    let config = if !args.config.trim().is_empty() {
        SpecterConfig::load_from_file(Path::new(args.config.trim()))?
    } else {
        SpecterConfig::load_from_dir(head_path)?
    };
    let strict_minor = args.strict_semver || config.strict_minor;

    let head_snapshot =
        extract_directory_contract_with_config(head_path, &config).with_context(|| {
            format!(
                "Failed to extract HEAD API contract from {}",
                head_path.display()
            )
        })?;

    // Save current snapshot if requested
    if !args.save_snapshot.trim().is_empty() {
        let save_path = Path::new(args.save_snapshot.trim());
        if let Some(parent) = save_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(save_path, serde_json::to_string_pretty(&head_snapshot)?)?;
    }

    // Resolve BASE snapshot from (1) --baseline-json, (2) --base-dir, (3) --base-ref, or fallback to HEAD
    let base_snapshot = resolve_base_snapshot(&args, &head_snapshot, &config)?;

    let diff = diff_contracts_with_config(&base_snapshot, &head_snapshot, &config);

    // Resolve commit message (from CLI flag or fallback to git log -1 if available)
    let resolved_commit_msg = resolve_commit_message(&args.commit_message);
    let commit_guard = evaluate_commit_alignment(
        diff.required_bump,
        resolved_commit_msg.as_deref(),
        strict_minor,
    );

    let mut failure_reasons = Vec::new();
    if args.fail_on_breaking && diff.breaking_count > 0 {
        failure_reasons.push(format!(
            "Detected {} MAJOR breaking API contract mutation(s) with --fail-on-breaking enabled.",
            diff.breaking_count
        ));
    }
    if args.fail_on_trojan && commit_guard.trojan_breaking {
        failure_reasons.push(commit_guard.summary.clone());
    }
    if strict_minor && !commit_guard.aligned && !commit_guard.trojan_breaking {
        failure_reasons.push(commit_guard.summary.clone());
    }

    let verdict = if !failure_reasons.is_empty() {
        AuditVerdict::Failed
    } else if diff.breaking_count > 0 || commit_guard.undeclared_minor {
        AuditVerdict::Warning
    } else {
        AuditVerdict::Passed
    };

    let duration_ms = start.elapsed().as_millis();
    let report = SpecterAuditReport {
        tool: "glastor-core/specter".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        verdict,
        duration_ms,
        files_scanned: head_snapshot.files_scanned,
        languages: head_snapshot.languages.clone(),
        diff,
        commit_guard,
        failure_reasons,
    };

    let markdown = render_markdown_report(&report);

    let is_ci = std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok();
    let format = args.format.to_lowercase();
    let use_color = match args.color.to_lowercase().as_str() {
        "always" => true,
        "never" => false,
        _ => !is_ci,
    };

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if format == "markdown" || (format == "auto" && is_ci) {
        println!("{}", markdown);
    } else {
        println!("{}", render_terminal_colored_diff(&report, use_color));
    }

    if !args.output_markdown.trim().is_empty() {
        let md_path = Path::new(args.output_markdown.trim());
        if let Some(parent) = md_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(md_path, &markdown)?;
    }

    if !args.output_json.trim().is_empty() {
        let json_path = Path::new(args.output_json.trim());
        if let Some(parent) = json_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(json_path, serde_json::to_string_pretty(&report)?)?;
    }

    if !args.output_sarif.trim().is_empty() {
        write_sarif_report(&report, Path::new(args.output_sarif.trim()))?;
    }

    if !args.output_sbom.trim().is_empty() {
        write_cyclonedx_sbom(&head_snapshot, &report, Path::new(args.output_sbom.trim()))?;
    }

    emit_github_telemetry(&report, &markdown)?;

    if verdict == AuditVerdict::Failed {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn resolve_base_snapshot(
    args: &CliArgs,
    head_fallback: &ContractSnapshot,
    config: &SpecterConfig,
) -> Result<ContractSnapshot> {
    // 1. Check --baseline-json if file exists
    let baseline_json = args.baseline_json.trim();
    if !baseline_json.is_empty() {
        let p = Path::new(baseline_json);
        if p.exists()
            && let Ok(raw) = fs::read_to_string(p)
            && let Ok(snap) = serde_json::from_str::<ContractSnapshot>(&raw)
        {
            return Ok(snap);
        }
    }

    // 2. Check --base-dir if provided and exists
    let base_dir = args.base_dir.trim();
    if !base_dir.is_empty() {
        let p = Path::new(base_dir);
        if p.exists() {
            return extract_directory_contract_with_config(p, config);
        }
    }

    // 3. Check --base-ref via git archive / git worktree if provided
    let base_ref = args.base_ref.trim();
    if !base_ref.is_empty()
        && let Ok(snap) =
            extract_git_ref_contract(Path::new(args.head_dir.trim()), base_ref, config)
    {
        return Ok(snap);
    }

    // 4. Fallback to HEAD snapshot (initial baseline creation / self-audit)
    Ok(head_fallback.clone())
}

/// Zero-Disk In-Memory Git Ref Extractor: reads source blobs directly from the Git object store
/// via `git ls-tree` and `git show` without creating any temporary worktrees on disk.
fn extract_git_ref_contract(
    repo_dir: &Path,
    git_ref: &str,
    config: &SpecterConfig,
) -> Result<ContractSnapshot> {
    let ls_out = Command::new("git")
        .current_dir(repo_dir)
        .args(["ls-tree", "-r", "--name-only", git_ref])
        .output()
        .with_context(|| format!("Failed to execute git ls-tree for ref {}", git_ref))?;

    if !ls_out.status.success() {
        anyhow::bail!("Git ref `{}` not found in repository", git_ref);
    }

    let file_list = String::from_utf8_lossy(&ls_out.stdout);
    let mut in_memory_files = Vec::new();

    for raw_line in file_list.lines() {
        let rel_path = raw_line.trim().replace('\\', "/");
        if rel_path.is_empty() {
            continue;
        }
        let is_manifest = matches!(
            rel_path.as_str(),
            "Cargo.toml" | "package.json" | "deno.json" | "deno.jsonc"
        );
        if !is_manifest {
            let p = Path::new(&rel_path);
            let file_name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if should_skip_file(&file_name)
                || p.components()
                    .any(|c| should_skip_dir(&c.as_os_str().to_string_lossy()))
                || detect_language(p).is_none()
            {
                continue;
            }
        }

        let spec = format!("{}:{}", git_ref, rel_path);
        if let Ok(blob_out) = Command::new("git")
            .current_dir(repo_dir)
            .args(["show", &spec])
            .output()
            && blob_out.status.success()
            && let Ok(content) = String::from_utf8(blob_out.stdout)
        {
            in_memory_files.push((rel_path, content));
        }
    }

    Ok(extract_in_memory_files_with_config(
        &in_memory_files,
        config,
    ))
}

fn resolve_commit_message(explicit: &str) -> Option<String> {
    let trimmed = explicit.trim();
    if !trimmed.is_empty() {
        return Some(trimmed.to_string());
    }
    None
}

// ============================================================================
// COMPREHENSIVE UNIT & E2E INTEGRATION TEST SUITE (16 TESTS)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit_guard::{evaluate_commit_alignment, parse_conventional_commit};
    use crate::differ::{ChangeCode, SemverImpact, diff_contracts};
    use crate::extractor::{
        Language, SymbolKind, extract_directory_contract, extract_from_source,
        extract_in_memory_files,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn tempdir() -> Result<TestDir> {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "glastor-specter-test-{}-{}",
            std::process::id(),
            id
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(TestDir { path })
    }

    #[test]
    fn test_01_extract_rust_public_functions_and_ignore_private() {
        let code = r#"
            // Internal helper should be ignored
            fn internal_helper(x: i32) -> i32 { x + 1 }
            pub(crate) fn crate_only(y: &str) -> bool { true }

            /// Public API function
            pub async fn verify_token(token: &str, strict: Option<bool>) -> Result<bool, String> {
                Ok(true)
            }
        "#;
        let symbols = extract_from_source(code, "src/auth.rs", Language::Rust);
        assert_eq!(symbols.len(), 1);
        let sym = &symbols[0];
        assert_eq!(sym.name, "verify_token");
        assert_eq!(sym.kind, SymbolKind::Function);
        assert!(sym.is_async);
        assert_eq!(sym.params.len(), 2);
        assert_eq!(sym.params[0].name, "token");
        assert!(!sym.params[0].optional);
        assert_eq!(sym.params[1].name, "strict");
        assert!(sym.params[1].optional);
        assert_eq!(sym.return_type, "Result<bool, String>");
    }

    #[test]
    fn test_02_extract_rust_struct_and_enum_contracts() {
        let code = r#"
            pub struct GatewayConfig {
                pub host: String,
                pub port: u16,
                pub timeout_ms: Option<u64>,
                secret_key: String, // private field ignored!
            }

            pub enum Verdict {
                Allow,
                Deny(String),
            }
        "#;
        let symbols = extract_from_source(code, "src/config.rs", Language::Rust);
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "GatewayConfig");
        assert_eq!(symbols[0].fields.len(), 3);
        assert!(symbols[0].fields[2].optional);
        assert_eq!(symbols[1].name, "Verdict");
        assert_eq!(symbols[1].fields.len(), 2);
    }

    #[test]
    fn test_03_extract_typescript_functions_and_interfaces() {
        let code = r#"
            export interface RetryOptions {
                maxRetries: number;
                jitterMs?: number;
                readonly backoffFactor?: number;
            }

            export async function dispatchEdgeRequest(
                url: string,
                options?: RetryOptions,
                timeoutMs: number = 5000
            ): Promise<Response> {
                return fetch(url);
            }
        "#;
        let symbols = extract_from_source(code, "src/medusa.ts", Language::TypeScript);
        assert_eq!(symbols.len(), 2);
        let iface = &symbols[0];
        assert_eq!(iface.name, "RetryOptions");
        assert_eq!(iface.fields.len(), 3);
        assert!(!iface.fields[0].optional);
        assert!(iface.fields[1].optional);
        assert!(iface.fields[2].optional);

        let func = &symbols[1];
        assert_eq!(func.name, "dispatchEdgeRequest");
        assert!(func.is_async);
        assert_eq!(func.params.len(), 3);
        assert!(!func.params[0].optional);
        assert!(func.params[1].optional);
        assert!(func.params[2].optional);
        assert_eq!(func.return_type, "Promise<Response>");
    }

    #[test]
    fn test_04_patch_impact_when_only_internal_body_changes() {
        let base_dir = tempdir().unwrap();
        let head_dir = tempdir().unwrap();

        fs::write(
            base_dir.path().join("mod.ts"),
            "export function calculateHash(input: string): string { return input.trim(); }",
        )
        .unwrap();
        fs::write(
            head_dir.path().join("mod.ts"),
            "// Refactored internal logic\nexport function calculateHash(input: string): string {\n  const clean = input.toLowerCase();\n  return clean;\n}",
        )
        .unwrap();

        let base_snap = extract_directory_contract(base_dir.path()).unwrap();
        let head_snap = extract_directory_contract(head_dir.path()).unwrap();
        let diff = diff_contracts(&base_snap, &head_snap);

        assert!(!diff.contract_mutated);
        assert_eq!(diff.base_fingerprint, diff.head_fingerprint);
        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert_eq!(diff.breaking_count, 0);
        assert_eq!(diff.minor_count, 0);
    }

    #[test]
    fn test_05_minor_impact_when_new_symbol_or_optional_param_added() {
        let base_dir = tempdir().unwrap();
        let head_dir = tempdir().unwrap();

        fs::write(
            base_dir.path().join("mod.ts"),
            "export function connect(url: string): boolean { return true; }",
        )
        .unwrap();
        fs::write(
            head_dir.path().join("mod.ts"),
            "export function connect(url: string, retries?: number): boolean { return true; }\nexport function disconnect(): void {}",
        )
        .unwrap();

        let base_snap = extract_directory_contract(base_dir.path()).unwrap();
        let head_snap = extract_directory_contract(head_dir.path()).unwrap();
        let diff = diff_contracts(&base_snap, &head_snap);

        assert!(diff.contract_mutated);
        assert_eq!(diff.required_bump, SemverImpact::Minor);
        assert_eq!(diff.breaking_count, 0);
        assert_eq!(diff.minor_count, 2);
    }

    #[test]
    fn test_06_major_breaking_when_symbol_removed() {
        let base_dir = tempdir().unwrap();
        let head_dir = tempdir().unwrap();

        fs::write(
            base_dir.path().join("lib.rs"),
            "pub fn legacy_api() -> u32 { 42 }\npub fn active_api() -> u32 { 1 }",
        )
        .unwrap();
        fs::write(
            head_dir.path().join("lib.rs"),
            "pub fn active_api() -> u32 { 1 }",
        )
        .unwrap();

        let base_snap = extract_directory_contract(base_dir.path()).unwrap();
        let head_snap = extract_directory_contract(head_dir.path()).unwrap();
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Major);
        assert_eq!(diff.breaking_count, 1);
        assert_eq!(diff.findings[0].code, ChangeCode::SymbolRemoved);
    }

    #[test]
    fn test_07_major_breaking_when_optional_param_becomes_required() {
        let base_dir = tempdir().unwrap();
        let head_dir = tempdir().unwrap();

        fs::write(
            base_dir.path().join("api.ts"),
            "export function createClient(endpoint: string, timeoutMs?: number): void {}",
        )
        .unwrap();
        fs::write(
            head_dir.path().join("api.ts"),
            "export function createClient(endpoint: string, timeoutMs: number): void {}",
        )
        .unwrap();

        let base_snap = extract_directory_contract(base_dir.path()).unwrap();
        let head_snap = extract_directory_contract(head_dir.path()).unwrap();
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Major);
        assert_eq!(diff.findings[0].code, ChangeCode::ParamBecameRequired);
    }

    #[test]
    fn test_08_major_breaking_when_return_type_or_async_mutates() {
        let base_dir = tempdir().unwrap();
        let head_dir = tempdir().unwrap();

        fs::write(
            base_dir.path().join("lib.rs"),
            "pub fn validate(input: &str) -> bool { true }",
        )
        .unwrap();
        fs::write(
            head_dir.path().join("lib.rs"),
            "pub async fn validate(input: &str) -> Result<bool, String> { Ok(true) }",
        )
        .unwrap();

        let base_snap = extract_directory_contract(base_dir.path()).unwrap();
        let head_snap = extract_directory_contract(head_dir.path()).unwrap();
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Major);
        assert_eq!(diff.breaking_count, 2); // AsyncModifierChanged + ReturnTypeChanged
    }

    #[test]
    fn test_09_major_breaking_when_interface_field_removed_or_type_changed() {
        let base_dir = tempdir().unwrap();
        let head_dir = tempdir().unwrap();

        fs::write(
            base_dir.path().join("types.ts"),
            "export interface MedusaConfig {\n  apiKey: string;\n  retries: number;\n}",
        )
        .unwrap();
        fs::write(
            head_dir.path().join("types.ts"),
            "export interface MedusaConfig {\n  apiKey: string;\n  retries: string;\n}",
        )
        .unwrap();

        let base_snap = extract_directory_contract(base_dir.path()).unwrap();
        let head_snap = extract_directory_contract(head_dir.path()).unwrap();
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Major);
        assert_eq!(diff.findings[0].code, ChangeCode::FieldTypeChanged);
    }

    #[test]
    fn test_10_trojan_commit_guard_blocks_undeclared_breaking_change() {
        let verdict = evaluate_commit_alignment(
            SemverImpact::Major,
            Some("fix(gateway): optimize retry config parameters"),
            false,
        );
        assert!(!verdict.aligned);
        assert!(verdict.trojan_breaking);
        assert!(verdict.summary.contains("TROJAN BREAKING CHANGE"));
    }

    #[test]
    fn test_11_commit_guard_allows_declared_breaking_change_bang() {
        let verdict = evaluate_commit_alignment(
            SemverImpact::Major,
            Some("feat(gateway)!: require explicit timeoutMs in createClient"),
            false,
        );
        assert!(verdict.aligned);
        assert!(!verdict.trojan_breaking);
    }

    #[test]
    fn test_12_commit_guard_allows_breaking_change_footer() {
        let msg =
            "refactor(core): unify auth pipeline\n\nBREAKING CHANGE: verify_token is now async";
        let intent = parse_conventional_commit(msg);
        assert!(intent.declares_breaking);
        assert_eq!(intent.declared_bump, SemverImpact::Major);
    }

    #[test]
    fn test_13_strict_semver_flags_minor_addition_in_fix_commit() {
        let verdict = evaluate_commit_alignment(
            SemverImpact::Minor,
            Some("fix(core): patch edge case and add helper"),
            true,
        );
        assert!(!verdict.aligned);
        assert!(verdict.undeclared_minor);
    }

    #[test]
    fn test_14_sarif_and_cyclonedx_sbom_generation() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("lib.rs"),
            "pub fn execute_vortex(shard: u32) -> bool { true }",
        )
        .unwrap();

        let snap = extract_directory_contract(dir.path()).unwrap();
        let diff = diff_contracts(&snap, &snap);
        let commit_guard =
            evaluate_commit_alignment(diff.required_bump, Some("chore: audit"), false);

        let report = SpecterAuditReport {
            tool: "glastor-core/specter".to_string(),
            version: "0.1.0".to_string(),
            verdict: AuditVerdict::Passed,
            duration_ms: 2,
            files_scanned: snap.files_scanned,
            languages: snap.languages.clone(),
            diff,
            commit_guard,
            failure_reasons: vec![],
        };

        let sarif_path = dir.path().join("specter.sarif");
        let sbom_path = dir.path().join("specter.cdx.json");

        write_sarif_report(&report, &sarif_path).unwrap();
        write_cyclonedx_sbom(&snap, &report, &sbom_path).unwrap();

        assert!(sarif_path.exists());
        assert!(sbom_path.exists());

        let sbom_txt = fs::read_to_string(&sbom_path).unwrap();
        assert!(sbom_txt.contains("CycloneDX"));
        assert!(sbom_txt.contains("execute_vortex"));
    }

    #[test]
    fn test_15_comment_stripper_preserves_exact_line_numbers() {
        let src = "/* line 1\nline 2\nline 3 */\npub fn line_four() -> bool { true }\n";
        let syms = extract_from_source(src, "src/lib.rs", Language::Rust);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].line, 4);
    }

    #[test]
    fn test_16_self_audit_own_codebase_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let snap = extract_directory_contract(root).unwrap();
        assert!(snap.files_scanned >= 4);
        assert!(!snap.symbols.is_empty());
        assert_eq!(snap.contract_sha256.len(), 64);
    }

    #[test]
    fn test_17_extract_rust_impl_methods_and_pub_use_reexports() {
        let code = r#"
            pub use crate::engine::{VortexShard, execute_shard as run_shard};

            pub struct MedusaProxy {
                pub endpoint: String,
            }

            impl MedusaProxy {
                pub async fn forward_request(&self, payload: &[u8], retries: Option<u8>) -> Result<u16, String> {
                    Ok(200)
                }

                fn private_helper(&self) {}
            }
        "#;
        let syms = extract_from_source(code, "src/lib.rs", Language::Rust);
        assert_eq!(syms.len(), 4); // 2 re-exports + 1 struct + 1 public method
        assert!(
            syms.iter()
                .any(|s| s.kind == SymbolKind::ReExport && s.name == "VortexShard")
        );
        assert!(
            syms.iter()
                .any(|s| s.kind == SymbolKind::ReExport && s.name == "run_shard")
        );
        let method = syms
            .iter()
            .find(|s| s.kind == SymbolKind::Method)
            .expect("Expected MedusaProxy::forward_request method");
        assert_eq!(method.name, "MedusaProxy::forward_request");
        assert!(method.is_async);
        assert_eq!(method.params.len(), 2);
        assert!(method.params[1].optional);
    }

    #[test]
    fn test_18_extract_typescript_class_methods_and_barrel_reexports() {
        let code = r#"
            export { createGateway, type GatewayOptions as Options } from "./gateway.ts";
            export * from "./constants.ts";

            export class CircuitBreaker {
                public readonly threshold: number;
                private secretState: string;

                public async execute(action: string, fallback?: boolean): Promise<boolean> {
                    return true;
                }

                private resetInternal(): void {}
            }
        "#;
        let syms = extract_from_source(code, "src/mod.ts", Language::TypeScript);
        // 3 re-exports + 1 class + 1 public method
        assert_eq!(syms.len(), 5);
        assert!(
            syms.iter()
                .any(|s| s.kind == SymbolKind::ReExport && s.name == "createGateway")
        );
        assert!(
            syms.iter()
                .any(|s| s.kind == SymbolKind::ReExport && s.name == "Options")
        );
        let method = syms
            .iter()
            .find(|s| s.kind == SymbolKind::Method)
            .expect("Expected CircuitBreaker::execute method");
        assert_eq!(method.name, "CircuitBreaker::execute");
        assert!(method.is_async);
        assert_eq!(method.params.len(), 2);
        assert!(method.params[1].optional);
    }

    #[test]
    fn test_19_major_breaking_spc013_when_barrel_reexport_removed() {
        let base_files = vec![(
            "src/mod.ts".to_string(),
            "export { verifyJwt, signJwt } from \"./jwt.ts\";".to_string(),
        )];
        let head_files = vec![(
            "src/mod.ts".to_string(),
            "export { verifyJwt } from \"./jwt.ts\";".to_string(),
        )];

        let base_snap = extract_in_memory_files(&base_files);
        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Major);
        assert_eq!(diff.breaking_count, 1);
        assert_eq!(diff.findings[0].code, ChangeCode::ReExportRemoved);
        assert_eq!(diff.findings[0].code.rule_id(), "SPC013");
    }

    #[test]
    fn test_20_migration_guide_rendered_on_breaking_change() {
        let base_files = vec![(
            "src/api.rs".to_string(),
            "pub fn connect(host: &str, timeout: Option<u64>) -> bool { true }".to_string(),
        )];
        let head_files = vec![(
            "src/api.rs".to_string(),
            "pub fn connect(host: &str, timeout: u64) -> bool { true }".to_string(),
        )];

        let base_snap = extract_in_memory_files(&base_files);
        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);
        let commit_guard =
            evaluate_commit_alignment(diff.required_bump, Some("fix(net): enforce timeout"), false);

        let report = SpecterAuditReport {
            tool: "glastor-core/specter".to_string(),
            version: "0.1.0".to_string(),
            verdict: AuditVerdict::Failed,
            duration_ms: 1,
            files_scanned: 1,
            languages: vec!["Rust".to_string()],
            diff,
            commit_guard,
            failure_reasons: vec!["Trojan breaking change".to_string()],
        };

        let md = render_markdown_report(&report);
        assert!(md.contains("Automated Migration Guide & Conventional Commit Fix"));
        assert!(md.contains("feat(net)!: update public API surface contract"));
        assert!(md.contains("BREAKING CHANGE:"));
        assert!(md.contains("[SPC004]"));
    }

    #[test]
    fn test_21_rust_lifetimes_raw_strings_and_nested_block_comments() {
        let code = r####"
/* outer comment /* nested comment
pub fn fake_inside_nested() -> bool { false }
*/ still inside outer comment
pub fn also_fake() -> bool { false }
*/
pub fn parse<'a>(input: &'a str) -> &'a str {
    // comment after lifetime 'a should still be stripped!
    let _raw = r#"
pub fn fake_inside_raw_string() -> u32 { 42 }
"#;
    let _ch = '\'';
    input
}
"####;
        let syms = extract_from_source(code, "src/parser.rs", Language::Rust);
        assert_eq!(syms.len(), 1, "Expected only `parse`, got: {:?}", syms);
        assert_eq!(syms[0].name, "parse");
        assert_eq!(syms[0].params[0].ty, "&'0 str");
        assert_eq!(syms[0].return_type, "&'0 str");
    }

    #[test]
    fn test_22_ignore_rust_doc_hidden_items_methods_and_fields() {
        let code = r#"
#[doc(hidden)]
pub fn internal_macro_helper() -> bool { true }

pub struct Client {
    pub endpoint: String,
    #[doc(hidden)]
    pub __internal_token: String,
}

impl Client {
    pub fn send(&self, body: &str) -> bool { true }

    #[doc(hidden)]
    #[inline]
    pub fn __debug_dump(&self) {}
}
"#;
        let syms = extract_from_source(code, "src/client.rs", Language::Rust);
        assert_eq!(
            syms.len(),
            2,
            "Expected only Client and Client::send, got: {:?}",
            syms
        );
        let client_struct = syms.iter().find(|s| s.kind == SymbolKind::Struct).unwrap();
        assert_eq!(client_struct.fields.len(), 1);
        assert_eq!(client_struct.fields[0].name, "endpoint");
        assert!(syms.iter().any(|s| s.name == "Client::send"));
    }

    #[test]
    fn test_23_ignore_ts_jsdoc_internal_and_private_exports() {
        let code = r#"
/**
 * Internal helper used by tests
 * @internal
 */
export function _internalBoot(): void {}

/** @private */
export const SECRET_FLAG: boolean = true;

export class Engine {
    /** @internal */
    public debugState: string;
    public version: string;

    /** @internal */
    public resetInternal(): void {}

    public run(input: string): boolean {
        return true;
    }
}
"#;
        let syms = extract_from_source(code, "src/engine.ts", Language::TypeScript);
        assert_eq!(
            syms.len(),
            2,
            "Expected Engine class and Engine::run, got: {:?}",
            syms
        );
        let cls = syms.iter().find(|s| s.kind == SymbolKind::Class).unwrap();
        assert_eq!(cls.fields.len(), 1);
        assert_eq!(cls.fields[0].name, "version");
        assert!(syms.iter().any(|s| s.name == "Engine::run"));
    }

    #[test]
    fn test_24_rust_struct_and_enum_attributes_do_not_drop_fields() {
        let base_files = vec![(
            "src/model.rs".to_string(),
            r#"
pub struct User {
    pub id: u64,
    pub email: String,
}
pub enum Status {
    Active,
    Disabled,
}
"#
            .to_string(),
        )];
        let head_files = vec![(
            "src/model.rs".to_string(),
            r#"
pub struct User {
    #[serde(rename = "user_id")]
    pub id: u64,
    #[serde(default, alias = "mail,addr")]
    pub email: String,
}
pub enum Status {
    #[serde(rename = "active")]
    Active,
    Disabled,
}
"#
            .to_string(),
        )];

        let base_snap = extract_in_memory_files(&base_files);
        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert!(!diff.contract_mutated);
        assert_eq!(diff.breaking_count, 0);
    }

    #[test]
    fn test_25_ts_class_brace_depth_ignores_nested_helpers() {
        let code = r#"
export class Gateway {
    public async dispatch(url: string): Promise<number> {
        const helper = {
            nestedCall(x: number) {
                return x + 1;
            }
        };
        function innerLocal(a: string) {
            return a.length;
        }
        return helper.nestedCall(innerLocal(url));
    }
}
"#;
        let syms = extract_from_source(code, "src/gateway.ts", Language::TypeScript);
        let methods: Vec<_> = syms
            .iter()
            .filter(|s| s.kind == SymbolKind::Method)
            .collect();
        assert_eq!(
            methods.len(),
            1,
            "Nested helpers must not be extracted as class methods: {:?}",
            methods
        );
        assert_eq!(methods[0].name, "Gateway::dispatch");
    }

    #[test]
    fn test_26_const_value_changes_do_not_trigger_breaking_change() {
        let base_files = vec![
            (
                "src/lib.rs".to_string(),
                "pub const VERSION: &str = \"0.8.1\";\npub const MAX_CONN: usize = 32;".to_string(),
            ),
            (
                "src/mod.ts".to_string(),
                "export const VERSION = \"0.8.1\";\nexport const MAX_RETRIES: number = 3;"
                    .to_string(),
            ),
        ];
        let head_files = vec![
            (
                "src/lib.rs".to_string(),
                "pub const VERSION: &str = \"0.9.0\";\npub const MAX_CONN: usize = 64;".to_string(),
            ),
            (
                "src/mod.ts".to_string(),
                "export const VERSION = \"0.9.0\";\nexport const MAX_RETRIES: number = 5;"
                    .to_string(),
            ),
        ];

        let base_snap = extract_in_memory_files(&base_files);
        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert!(!diff.contract_mutated);

        // Changing the annotated type of a const MUST still be MAJOR (SPC006)
        let breaking_head = vec![(
            "src/mod.ts".to_string(),
            "export const VERSION = \"0.9.0\";\nexport const MAX_RETRIES: string = \"5\";"
                .to_string(),
        )];
        let ts_base = extract_in_memory_files(&base_files[1..]);
        let ts_head = extract_in_memory_files(&breaking_head);
        let ts_diff = diff_contracts(&ts_base, &ts_head);
        assert_eq!(ts_diff.required_bump, SemverImpact::Major);
        assert_eq!(ts_diff.findings[0].code, ChangeCode::ReturnTypeChanged);
    }

    #[test]
    fn test_27_canonical_signature_ignores_param_lifetime_and_generic_renames() {
        let base_files = vec![(
            "src/api.rs".to_string(),
            "pub fn transform<'a, T: Clone, U>(input: &'a str, item: T, extra: U) -> Result<&'a str, U> { Ok(input) }".to_string(),
        )];
        let head_files = vec![(
            "src/api.rs".to_string(),
            "pub fn transform<'buf, Item: Clone, Err>(source: &'buf str, value: Item, err: Err) -> Result<&'buf str, Err> { Ok(source) }".to_string(),
        )];

        let base_snap = extract_in_memory_files(&base_files);
        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert!(!diff.contract_mutated);
        assert_eq!(diff.breaking_count, 0);
    }

    #[test]
    fn test_28_canonical_ts_unions_and_array_syntax() {
        let base_files = vec![(
            "src/api.ts".to_string(),
            r#"
export function normalize<T>(items: Array<string | number>, value: T): Promise<Array<number | string>> {
    return Promise.resolve(items);
}
export type Id = string | number;
"#
            .to_string(),
        )];
        let head_files = vec![(
            "src/api.ts".to_string(),
            r#"
export function normalize<Item>(list: (number | string)[], v: Item): Promise<(string | number)[]> {
    return Promise.resolve(list);
}
export type Id = number | string;
"#
            .to_string(),
        )];

        let base_snap = extract_in_memory_files(&base_files);
        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);

        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert!(!diff.contract_mutated);
        assert_eq!(diff.breaking_count, 0);
    }

    #[test]
    fn test_29_rust_syn_cfg_test_middle_of_file_and_pub_crate() {
        let code = r#"
pub fn before_tests(x: u32) -> u32 { x }

#[cfg(test)]
mod tests {
    pub fn test_helper_ignored() -> bool { true }
}

pub(crate) fn crate_only() -> bool { false }
pub(super) fn super_only() -> bool { false }

mod private_mod {
    pub fn hidden_inside_private_mod() -> bool { false }
}

pub fn after_tests<T>(val: T) -> T
where
    T: Clone + Send,
{
    val
}
"#;
        let syms = extract_from_source(code, "src/lib.rs", Language::Rust);
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["before_tests", "after_tests"],
            "Expected only truly public items before & after #[cfg(test)], got: {:?}",
            names
        );
    }

    #[test]
    fn test_30_rust_non_exhaustive_enum_and_struct_semver() {
        // 1. Exhaustive enum adding a variant -> MAJOR
        let base_ex = vec![(
            "src/err.rs".to_string(),
            "pub enum ApiError { NotFound, Timeout }".to_string(),
        )];
        let head_ex = vec![(
            "src/err.rs".to_string(),
            "pub enum ApiError { NotFound, Timeout, RateLimited }".to_string(),
        )];
        let diff_ex = diff_contracts(
            &extract_in_memory_files(&base_ex),
            &extract_in_memory_files(&head_ex),
        );
        assert_eq!(diff_ex.required_bump, SemverImpact::Major);
        assert_eq!(diff_ex.breaking_count, 1);

        // 2. #[non_exhaustive] enum adding a variant -> MINOR
        let base_ne = vec![(
            "src/err.rs".to_string(),
            "#[non_exhaustive]\npub enum ApiError { NotFound, Timeout }".to_string(),
        )];
        let head_ne = vec![(
            "src/err.rs".to_string(),
            "#[non_exhaustive]\npub enum ApiError { NotFound, Timeout, RateLimited }".to_string(),
        )];
        let diff_ne = diff_contracts(
            &extract_in_memory_files(&base_ne),
            &extract_in_memory_files(&head_ne),
        );
        assert_eq!(diff_ne.required_bump, SemverImpact::Minor);
        assert_eq!(diff_ne.breaking_count, 0);

        // 3. #[non_exhaustive] struct adding a pub field -> MINOR
        let base_st = vec![(
            "src/cfg.rs".to_string(),
            "#[non_exhaustive]\npub struct Config { pub host: String }".to_string(),
        )];
        let head_st = vec![(
            "src/cfg.rs".to_string(),
            "#[non_exhaustive]\npub struct Config { pub host: String, pub port: u16 }".to_string(),
        )];
        let diff_st = diff_contracts(
            &extract_in_memory_files(&base_st),
            &extract_in_memory_files(&head_st),
        );
        assert_eq!(diff_st.required_bump, SemverImpact::Minor);
        assert_eq!(diff_st.breaking_count, 0);

        // 4. Adding #[non_exhaustive] to a previously exhaustive enum -> MAJOR
        let diff_added_ne = diff_contracts(
            &extract_in_memory_files(&base_ex),
            &extract_in_memory_files(&base_ne),
        );
        assert_eq!(diff_added_ne.required_bump, SemverImpact::Major);
    }

    #[test]
    fn test_31_ts_oxc_arrow_functions_destructuring_and_decorators() {
        let code = r#"
export const fetchUser = async <T>(id: string, { retry = true }: { retry?: boolean }): Promise<T> => {
    return {} as T;
};

/** @internal */
export const internalArrow = (x: number): number => x * 2;

@sealed
export class Service {
    @log
    public execute(payload: string): boolean {
        return true;
    }
}
"#;
        let syms = extract_from_source(code, "src/service.ts", Language::TypeScript);
        let arrow = syms
            .iter()
            .find(|s| s.name == "fetchUser")
            .expect("Expected exported arrow function fetchUser");
        assert_eq!(arrow.kind, SymbolKind::Function);
        assert!(arrow.is_async);
        assert_eq!(arrow.params.len(), 2);
        assert_eq!(arrow.return_type, "Promise<T0>");
        assert!(!syms.iter().any(|s| s.name == "internalArrow"));
        assert!(syms.iter().any(|s| s.name == "Service::execute"));
    }

    #[test]
    fn test_32_ts_contravariant_param_widening_is_minor() {
        let base_files = vec![(
            "src/api.ts".to_string(),
            "export function lookup(id: string): boolean { return true; }".to_string(),
        )];
        let head_files = vec![(
            "src/api.ts".to_string(),
            "export function lookup(id: string | number): boolean { return true; }".to_string(),
        )];

        let diff = diff_contracts(
            &extract_in_memory_files(&base_files),
            &extract_in_memory_files(&head_files),
        );
        assert_eq!(diff.required_bump, SemverImpact::Minor);
        assert_eq!(diff.breaking_count, 0);
        assert_eq!(diff.findings[0].code, ChangeCode::OptionalMemberAdded);
    }

    #[test]
    fn test_33_ts_covariant_return_narrowing_is_compatible() {
        let base_files = vec![(
            "src/api.ts".to_string(),
            "export function getToken(): string | number { return 'abc'; }".to_string(),
        )];
        let head_narrow = vec![(
            "src/api.ts".to_string(),
            "export function getToken(): string { return 'abc'; }".to_string(),
        )];
        let diff_narrow = diff_contracts(
            &extract_in_memory_files(&base_files),
            &extract_in_memory_files(&head_narrow),
        );
        assert_eq!(diff_narrow.required_bump, SemverImpact::Patch);
        assert_eq!(diff_narrow.breaking_count, 0);

        // Widening a return type (`string` -> `string | number`) MUST still be MAJOR!
        let diff_wide = diff_contracts(
            &extract_in_memory_files(&head_narrow),
            &extract_in_memory_files(&base_files),
        );
        assert_eq!(diff_wide.required_bump, SemverImpact::Major);
        assert_eq!(diff_wide.findings[0].code, ChangeCode::ReturnTypeChanged);
    }

    #[test]
    fn test_34_rust_reachability_ignores_private_modules_and_tracks_pub_use() {
        let files = vec![
            (
                "src/lib.rs".to_string(),
                "mod internal;\npub use internal::Client;".to_string(),
            ),
            (
                "src/internal.rs".to_string(),
                r#"
pub struct Client {
    pub endpoint: String,
}
impl Client {
    pub fn send(&self, body: &str) -> bool { true }
}
pub fn internal_unexported_helper() -> u32 { 42 }
"#
                .to_string(),
            ),
        ];

        let snap = extract_in_memory_files(&files);
        assert!(snap.symbols.contains_key("crate::Client"));
        assert!(snap.symbols.contains_key("crate::Client::send"));
        assert!(
            !snap
                .symbols
                .values()
                .any(|s| s.name == "internal_unexported_helper"),
            "Unexported pub fn inside private `mod internal` must be ignored"
        );
    }

    #[test]
    fn test_35_rust_logical_id_immune_to_internal_file_move() {
        let base_files = vec![
            (
                "src/lib.rs".to_string(),
                "mod old_http;\npub use old_http::Client;".to_string(),
            ),
            (
                "src/old_http.rs".to_string(),
                "pub struct Client { pub host: String }\nimpl Client { pub fn send(&self) -> bool { true } }".to_string(),
            ),
        ];
        let head_files = vec![
            (
                "src/lib.rs".to_string(),
                "mod new_transport;\npub use new_transport::Client;".to_string(),
            ),
            (
                "src/new_transport.rs".to_string(),
                "pub struct Client { pub host: String }\nimpl Client { pub fn send(&self) -> bool { true } }".to_string(),
            ),
        ];

        let diff = diff_contracts(
            &extract_in_memory_files(&base_files),
            &extract_in_memory_files(&head_files),
        );
        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert_eq!(diff.breaking_count, 0);
        assert!(!diff.contract_mutated);
    }

    #[test]
    fn test_36_ts_package_json_exports_reachability_and_file_move() {
        let base_files = vec![
            (
                "package.json".to_string(),
                r#"{ "name": "@glastor/sdk", "exports": { ".": "./src/index.ts" } }"#.to_string(),
            ),
            (
                "src/index.ts".to_string(),
                r#"export { Client } from "./v1/client.ts";"#.to_string(),
            ),
            (
                "src/v1/client.ts".to_string(),
                "export class Client { public send(msg: string): boolean { return true; } }"
                    .to_string(),
            ),
            (
                "src/internal/secret.ts".to_string(),
                "export function secretInternal(): void {}".to_string(),
            ),
        ];
        let head_files = vec![
            (
                "package.json".to_string(),
                r#"{ "name": "@glastor/sdk", "exports": { ".": "./src/index.ts" } }"#.to_string(),
            ),
            (
                "src/index.ts".to_string(),
                r#"export { Client } from "./http/client.ts";"#.to_string(),
            ),
            (
                "src/http/client.ts".to_string(),
                "export class Client { public send(msg: string): boolean { return true; } }"
                    .to_string(),
            ),
        ];

        let base_snap = extract_in_memory_files(&base_files);
        assert!(base_snap.symbols.contains_key("pkg::Client"));
        assert!(base_snap.symbols.contains_key("pkg::Client::send"));
        assert!(
            !base_snap
                .symbols
                .values()
                .any(|s| s.name == "secretInternal")
        );

        let head_snap = extract_in_memory_files(&head_files);
        let diff = diff_contracts(&base_snap, &head_snap);
        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert_eq!(diff.breaking_count, 0);
        assert!(!diff.contract_mutated);
    }

    #[test]
    fn test_37_deno_json_exports_reachability() {
        let files = vec![
            (
                "deno.json".to_string(),
                r#"{ "exports": { ".": "./mod.ts", "./utils": "./utils.ts" } }"#.to_string(),
            ),
            (
                "mod.ts".to_string(),
                "export function start(): void {}".to_string(),
            ),
            (
                "utils.ts".to_string(),
                "export function hash(s: string): string { return s; }".to_string(),
            ),
            (
                "internal.ts".to_string(),
                "export function unexported(): void {}".to_string(),
            ),
        ];

        let snap = extract_in_memory_files(&files);
        assert!(snap.symbols.contains_key("pkg::start"));
        assert!(snap.symbols.contains_key("pkg/utils::hash"));
        assert!(!snap.symbols.values().any(|s| s.name == "unexported"));
    }

    #[test]
    fn test_38_specter_toml_ignore_paths_symbols_rules_and_severity() {
        let cfg = SpecterConfig::parse_toml(
            r#"
ignore_paths = ["src/legacy/**"]
ignore_symbols = ["*_experimental"]
ignore_rules = ["SPC012"]
strict_minor = true

[rule_severity]
SPC011 = "patch"
"#,
        )
        .unwrap();

        assert!(cfg.strict_minor);
        let base = vec![
            (
                "src/legacy/old.rs".to_string(),
                "pub fn removed_legacy() -> bool { true }".to_string(),
            ),
            (
                "src/api.rs".to_string(),
                "pub fn foo_experimental(x: u32) -> u32 { x }\npub fn stable() -> bool { true }"
                    .to_string(),
            ),
        ];
        let head = vec![(
            "src/api.rs".to_string(),
            "pub fn stable() -> bool { true }\npub fn brand_new() -> bool { true }".to_string(),
        )];

        let base_snap = extract_in_memory_files_with_config(&base, &cfg);
        let head_snap = extract_in_memory_files_with_config(&head, &cfg);
        let diff = diff_contracts_with_config(&base_snap, &head_snap, &cfg);

        // `removed_legacy` ignored by path, `foo_experimental` ignored by symbol,
        // `brand_new` (SPC011) downgraded to `patch` via rule_severity!
        assert_eq!(diff.required_bump, SemverImpact::Patch);
        assert_eq!(diff.breaking_count, 0);
        assert_eq!(diff.minor_count, 0);
    }

    #[test]
    fn test_39_inline_specter_ignore_requires_reason() {
        let base = vec![(
            "src/api.rs".to_string(),
            "pub fn fetch(id: u32) -> bool { true }".to_string(),
        )];

        // With valid `-- reason`: SPC005 is suppressed
        let head_suppressed = vec![(
            "src/api.rs".to_string(),
            "// specter-ignore: SPC005 -- planned v2 string IDs approved in RFC-12\npub fn fetch(id: &str) -> bool { true }".to_string(),
        )];
        let diff_ok = diff_contracts(
            &extract_in_memory_files(&base),
            &extract_in_memory_files(&head_suppressed),
        );
        assert_eq!(diff_ok.required_bump, SemverImpact::Patch);
        assert_eq!(diff_ok.breaking_count, 0);

        // Without `-- reason`: suppression is rejected and SPC005 still fires!
        let head_no_reason = vec![(
            "src/api.rs".to_string(),
            "// specter-ignore: SPC005\npub fn fetch(id: &str) -> bool { true }".to_string(),
        )];
        let diff_fail = diff_contracts(
            &extract_in_memory_files(&base),
            &extract_in_memory_files(&head_no_reason),
        );
        assert_eq!(diff_fail.required_bump, SemverImpact::Major);
        assert_eq!(diff_fail.findings[0].code, ChangeCode::ParamTypeChanged);
    }
}

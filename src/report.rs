use crate::commit_guard::CommitGuardVerdict;
use crate::differ::{ContractDiffResult, SemverImpact};
use crate::extractor::ContractSnapshot;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Overall audit verdict emitted by Specter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditVerdict {
    Passed,
    Warning,
    Failed,
}

impl AuditVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditVerdict::Passed => "passed",
            AuditVerdict::Warning => "warning",
            AuditVerdict::Failed => "failed",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            AuditVerdict::Passed => "🟢 PASSED",
            AuditVerdict::Warning => "🟡 WARNING",
            AuditVerdict::Failed => "🔴 BLOCKED",
        }
    }
}

/// Complete audit report serializable to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecterAuditReport {
    pub tool: String,
    pub version: String,
    pub verdict: AuditVerdict,
    pub duration_ms: u128,
    pub files_scanned: usize,
    pub languages: Vec<String>,
    pub diff: ContractDiffResult,
    pub commit_guard: CommitGuardVerdict,
    pub failure_reasons: Vec<String>,
}

/// Renders Markdown + Mermaid summary for `$GITHUB_STEP_SUMMARY` and PR Sticky Comments.
pub fn render_markdown_report(report: &SpecterAuditReport) -> String {
    let mut md = String::new();
    md.push_str("<!-- glastor-specter-sticky-comment -->\n");
    md.push_str("## 🛡️ GLASTOR® Specter — Semantic API Contract & SemVer Audit\n\n");

    let base_short = &report.diff.base_fingerprint[..12.min(report.diff.base_fingerprint.len())];
    let head_short = &report.diff.head_fingerprint[..12.min(report.diff.head_fingerprint.len())];

    md.push_str("| Metric | Value | Status |\n");
    md.push_str("| :--- | :--- | :--- |\n");
    md.push_str(&format!(
        "| **Audit Verdict** | `{}` | {} |\n",
        report.verdict.as_str().to_uppercase(),
        report.verdict.badge()
    ));
    md.push_str(&format!(
        "| **Mathematical SemVer Impact** | `{}` | {} |\n",
        report.diff.required_bump.as_str().to_uppercase(),
        report.diff.required_bump.badge()
    ));
    md.push_str(&format!(
        "| **Contract SHA-256 Fingerprint** | `{}` → `{}` | {} |\n",
        base_short,
        head_short,
        if report.diff.contract_mutated {
            "🔄 Mutated"
        } else {
            "🔒 Immutable (100% Identical)"
        }
    ));
    md.push_str(&format!(
        "| **Exported Public Symbols** | `{}` base → `{}` head | 📁 {} files ({}) |\n",
        report.diff.symbols_base_count,
        report.diff.symbols_head_count,
        report.files_scanned,
        if report.languages.is_empty() {
            "N/A".to_string()
        } else {
            report.languages.join(", ")
        }
    ));
    md.push_str(&format!(
        "| **Contract Findings** | `{}` breaking / `{}` minor | ⚡ `{}` ms |\n",
        report.diff.breaking_count, report.diff.minor_count, report.duration_ms
    ));

    if report.commit_guard.evaluated {
        let cg_badge = if report.commit_guard.trojan_breaking {
            "🚨 TROJAN BREAKING CHANGE"
        } else if !report.commit_guard.aligned {
            "🟡 UNDECLARED MINOR"
        } else {
            "🟢 ALIGNED"
        };
        md.push_str(&format!(
            "| **Conventional Commit Guard** | `{}` | {} |\n",
            report.commit_guard.summary.replace('|', "\\|"),
            cg_badge
        ));
    }
    md.push('\n');

    // Mermaid Pipeline Flow Diagram
    md.push_str("```mermaid\n");
    md.push_str("flowchart LR\n");
    md.push_str(&format!(
        "    B[\"Base Contract<br/>SHA256: {}...\"] --> E[\"GLASTOR® Specter<br/>Polyglot AST Differ\"]\n",
        base_short
    ));
    md.push_str(&format!(
        "    H[\"Head Contract<br/>SHA256: {}...\"] --> E\n",
        head_short
    ));
    md.push_str(&format!(
        "    E --> V[\"SemVer: {}<br/>Verdict: {}\"]\n",
        report.diff.required_bump.as_str().to_uppercase(),
        report.verdict.as_str().to_uppercase()
    ));
    md.push_str("```\n\n");

    if !report.failure_reasons.is_empty() {
        md.push_str("### 🚨 Gatekeeper Blocking Reasons\n");
        for reason in &report.failure_reasons {
            md.push_str(&format!("- ❌ **{}**\n", reason));
        }
        md.push('\n');
    }

    if !report.diff.findings.is_empty() {
        md.push_str("### 🔍 Audited Public Surface Mutations\n\n");
        md.push_str(
            "| Rule | Impact | Language | Symbol | Location | Before → After | Explanation |\n",
        );
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for f in &report.diff.findings {
            let impact_tag = match f.impact {
                SemverImpact::Major => "🔴 `MAJOR`",
                SemverImpact::Minor => "🟡 `MINOR`",
                SemverImpact::Patch => "🟢 `PATCH`",
            };
            md.push_str(&format!(
                "| `{}` | {} | `{}` | `{}` | `{}:{}` | `{}` → `{}` | {} |\n",
                f.code.rule_id(),
                impact_tag,
                f.language.as_str(),
                f.symbol_name,
                f.file,
                f.line,
                f.before.replace('|', "\\|"),
                f.after.replace('|', "\\|"),
                f.reason.replace('|', "\\|")
            ));
        }
        md.push('\n');

        if report.diff.breaking_count > 0 {
            md.push_str(&render_migration_guide(report));
        }
    } else {
        md.push_str("> ✅ **Zero Public API Surface Mutations:** All exported functions, structs, interfaces, and types preserve 100% binary & semantic contract compatibility.\n\n");
    }

    md.push_str("---\n");
    md.push_str("*Powered by **[GLASTOR® Core](https://glastor.es)** (`vortex` → `specter` → `byte-gauge` → `medusa`)*\n");
    md
}

fn render_migration_guide(report: &SpecterAuditReport) -> String {
    let mut guide = String::new();
    guide.push_str("<details>\n<summary>💡 <b>Automated Migration Guide & Conventional Commit Fix (Click to Expand)</b></summary>\n\n");
    guide.push_str("If this `MAJOR` breaking change is intentional, declare it explicitly in your commit or PR title so downstream consumers and automated release pipelines bump the major version safely:\n\n");

    let scope = report
        .commit_guard
        .intent
        .as_ref()
        .and_then(|i| i.scope.clone())
        .unwrap_or_else(|| "api".to_string());

    guide.push_str("```text\n");
    guide.push_str(&format!(
        "feat({})!: update public API surface contract\n\nBREAKING CHANGE:\n",
        scope
    ));
    for f in report
        .diff
        .findings
        .iter()
        .filter(|f| f.impact == SemverImpact::Major)
    {
        guide.push_str(&format!(
            "- [{}] `{}` ({}:{}): {} (`{}` -> `{}`)\n",
            f.code.rule_id(),
            f.symbol_name,
            f.file,
            f.line,
            f.reason,
            f.before,
            f.after
        ));
    }
    guide.push_str("```\n</details>\n\n");
    guide
}

/// Writes outputs to `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY` when running in GitHub Actions.
pub fn emit_github_telemetry(report: &SpecterAuditReport, markdown: &str) -> Result<()> {
    // 1. Emit GitHub Workflow Command annotations (renders directly on PR code lines)
    if env::var("GITHUB_ACTIONS").is_ok() {
        for finding in &report.diff.findings {
            let line = finding.line.max(1);
            match finding.impact {
                SemverImpact::Major => {
                    println!(
                        "::error file={},line={},title=[Specter {}] Trojan Breaking Change::{} ('{}' -> '{}')",
                        finding.file,
                        line,
                        finding.code.rule_id(),
                        finding.reason,
                        finding.before,
                        finding.after
                    );
                }
                SemverImpact::Minor => {
                    println!(
                        "::notice file={},line={},title=[Specter {}] SemVer Minor Addition::{} ('{}')",
                        finding.file,
                        line,
                        finding.code.rule_id(),
                        finding.reason,
                        finding.after
                    );
                }
                SemverImpact::Patch => {}
            }
        }
    }

    if let Ok(summary_path) = env::var("GITHUB_STEP_SUMMARY")
        && !summary_path.trim().is_empty()
    {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&summary_path)?;
        writeln!(file, "{}", markdown)?;
    }

    if let Ok(output_path) = env::var("GITHUB_OUTPUT")
        && !output_path.trim().is_empty()
    {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output_path)?;
        let commit_intent_str = report
            .commit_guard
            .intent
            .as_ref()
            .map(|i| i.declared_bump.as_str())
            .unwrap_or("unverified");

        writeln!(file, "status={}", report.verdict.as_str())?;
        writeln!(file, "semver_bump={}", report.diff.required_bump.as_str())?;
        writeln!(file, "base_fingerprint={}", report.diff.base_fingerprint)?;
        writeln!(file, "head_fingerprint={}", report.diff.head_fingerprint)?;
        writeln!(file, "contract_mutated={}", report.diff.contract_mutated)?;
        writeln!(file, "breaking_count={}", report.diff.breaking_count)?;
        writeln!(file, "minor_count={}", report.diff.minor_count)?;
        writeln!(file, "symbols_base={}", report.diff.symbols_base_count)?;
        writeln!(file, "symbols_head={}", report.diff.symbols_head_count)?;
        writeln!(file, "commit_intent={}", commit_intent_str)?;
        writeln!(
            file,
            "trojan_detected={}",
            report.commit_guard.trojan_breaking
        )?;
        writeln!(file, "files_scanned={}", report.files_scanned)?;
        writeln!(file, "languages={}", report.languages.join(","))?;
        writeln!(file, "duration_ms={}", report.duration_ms)?;
    }

    Ok(())
}

/// Writes a SARIF 2.1.0 report for GitHub Security / Code Scanning.
pub fn write_sarif_report(report: &SpecterAuditReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let results: Vec<serde_json::Value> = report
        .diff
        .findings
        .iter()
        .map(|f| {
            let level = match f.impact {
                SemverImpact::Major => "error",
                SemverImpact::Minor => "note",
                SemverImpact::Patch => "none",
            };
            serde_json::json!({
                "ruleId": f.code.rule_id(),
                "level": level,
                "message": {
                    "text": format!("{} ({} -> {})", f.reason, f.before, f.after)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file
                        },
                        "region": {
                            "startLine": f.line.max(1)
                        }
                    }
                }]
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GLASTOR Specter",
                    "organization": "GLASTOR Core",
                    "informationUri": "https://github.com/glastor-core/specter",
                    "version": report.version,
                    "rules": [
                        {"id": "SPC001", "shortDescription": {"text": "Exported Symbol Removed"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC002", "shortDescription": {"text": "Required Parameter Added"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC003", "shortDescription": {"text": "Function Parameter Removed"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC004", "shortDescription": {"text": "Optional Parameter Became Required"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC005", "shortDescription": {"text": "Parameter Type Mutated"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC006", "shortDescription": {"text": "Return Type Mutated"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC007", "shortDescription": {"text": "Async/Sync Contract Mutated"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC008", "shortDescription": {"text": "Public Field or Variant Removed"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC009", "shortDescription": {"text": "Optional Field Became Required"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC010", "shortDescription": {"text": "Public Field Type Mutated"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "SPC011", "shortDescription": {"text": "New Exported Symbol Added"}, "defaultConfiguration": {"level": "note"}},
                        {"id": "SPC012", "shortDescription": {"text": "Backward-Compatible Optional Member Added"}, "defaultConfiguration": {"level": "note"}},
                        {"id": "SPC013", "shortDescription": {"text": "Public Barrel Re-Export Removed"}, "defaultConfiguration": {"level": "error"}}
                    ]
                }
            },
            "results": results
        }]
    });

    fs::write(path, serde_json::to_string_pretty(&sarif)?)?;
    Ok(())
}

/// Writes a CycloneDX 1.5 JSON API Contract SBOM attesting the public surface symbols & hashes.
pub fn write_cyclonedx_sbom(
    snapshot: &ContractSnapshot,
    report: &SpecterAuditReport,
    path: &Path,
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let components: Vec<serde_json::Value> = snapshot
        .symbols
        .values()
        .map(|s| {
            serde_json::json!({
                "type": "library",
                "name": s.id,
                "version": report.version,
                "description": format!("Exported {} {} in {}", s.language.as_str(), s.kind.as_str(), s.file),
                "hashes": [{
                    "alg": "SHA-256",
                    "content": s.signature_hash
                }]
            })
        })
        .collect();

    let sbom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "GLASTOR Core",
                "name": "specter",
                "version": report.version
            }],
            "component": {
                "type": "application",
                "name": "public-api-contract",
                "version": report.version,
                "hashes": [{
                    "alg": "SHA-256",
                    "content": snapshot.contract_sha256
                }]
            }
        },
        "components": components
    });

    fs::write(path, serde_json::to_string_pretty(&sbom)?)?;
    Ok(())
}

/// Renders a terminal-friendly, ANSI-colored diff review for interactive CLI usage.
pub fn render_terminal_colored_diff(report: &SpecterAuditReport, use_color: bool) -> String {
    let (c_bold, c_reset, c_red, c_green, c_yellow, _c_cyan, c_dim) = if use_color {
        (
            "\x1b[1m", "\x1b[0m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m", "\x1b[2m",
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    let mut out = String::new();
    out.push_str(&format!(
        "\n{}🛡️  GLASTOR® Specter v{} — API Contract & SemVer Audit{}\n",
        c_bold, report.version, c_reset
    ));
    out.push_str(&format!(
        "{}──────────────────────────────────────────────────────────────────────────────{}\n",
        c_dim, c_reset
    ));

    let verdict_color = match report.verdict {
        AuditVerdict::Passed => c_green,
        AuditVerdict::Warning => c_yellow,
        AuditVerdict::Failed => c_red,
    };
    out.push_str(&format!(
        "  Status:       {}{}{} ({} ms, {} files scanned)\n",
        verdict_color,
        report.verdict.badge(),
        c_reset,
        report.duration_ms,
        report.files_scanned
    ));
    out.push_str(&format!(
        "  Required:     {}SemVer {} Bump{}\n",
        c_bold,
        report.diff.required_bump.as_str().to_uppercase(),
        c_reset
    ));
    let base_short = &report.diff.base_fingerprint[..8.min(report.diff.base_fingerprint.len())];
    let head_short = &report.diff.head_fingerprint[..8.min(report.diff.head_fingerprint.len())];
    out.push_str(&format!(
        "  Fingerprint:  {}{} → {}{}\n",
        c_dim, base_short, head_short, c_reset
    ));
    out.push_str(&format!(
        "  Mutations:    {} breaking (MAJOR), {} backwards-compatible (MINOR)\n",
        report.diff.breaking_count, report.diff.minor_count
    ));
    out.push_str(&format!(
        "{}──────────────────────────────────────────────────────────────────────────────{}\n",
        c_dim, c_reset
    ));

    if report.diff.findings.is_empty() {
        out.push_str(&format!(
            "  {}✨ Public API contract is 100% immutable & identical to baseline.{}\n",
            c_green, c_reset
        ));
    } else {
        out.push_str(&format!(
            "{}Detailed Mutations & Contract Diffs:{}\n",
            c_bold, c_reset
        ));
        for finding in &report.diff.findings {
            let (tag, color) = match finding.impact {
                SemverImpact::Major => ("[-]", c_red),
                SemverImpact::Minor => ("[+]", c_green),
                SemverImpact::Patch => ("[~]", c_yellow),
            };
            out.push_str(&format!(
                "  {}{}{} {} ({}:{}) {}\n",
                color,
                tag,
                c_reset,
                finding.symbol_name,
                finding.file,
                finding.line.max(1),
                c_dim
            ));
            out.push_str(&format!(
                "      {}Reason:{}   {}\n",
                c_dim, c_reset, finding.reason
            ));
            if !finding.before.is_empty() {
                out.push_str(&format!(
                    "      {}Before:{}   {}{}{}\n",
                    c_dim, c_reset, c_red, finding.before, c_reset
                ));
            }
            if !finding.after.is_empty() {
                out.push_str(&format!(
                    "      {}After:{}    {}{}{}\n",
                    c_dim, c_reset, c_green, finding.after, c_reset
                ));
            }
        }
    }
    out.push_str(&format!(
        "{}──────────────────────────────────────────────────────────────────────────────{}\n\n",
        c_dim, c_reset
    ));

    out
}

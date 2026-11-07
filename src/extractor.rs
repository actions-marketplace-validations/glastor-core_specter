use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Supported source languages for polyglot API surface extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Language {
    Rust,
    TypeScript,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::TypeScript => "TypeScript",
        }
    }
}

/// Kind of exported public API symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Method,
    Struct,
    Interface,
    Enum,
    Trait,
    TypeAlias,
    Class,
    Const,
    ReExport,
}

impl SymbolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SymbolKind::Function => "function",
            SymbolKind::Method => "method",
            SymbolKind::Struct => "struct",
            SymbolKind::Interface => "interface",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::TypeAlias => "type",
            SymbolKind::Class => "class",
            SymbolKind::Const => "const",
            SymbolKind::ReExport => "re-export",
        }
    }
}

/// Canonical parameter in an exported function or method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParamContract {
    pub name: String,
    pub ty: String,
    pub optional: bool,
    pub variadic: bool,
}

/// Canonical member field or variant in an exported struct, interface, enum, or class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FieldContract {
    pub name: String,
    pub ty: String,
    pub optional: bool,
}

/// Canonical representation of a single exported public symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSymbol {
    pub id: String,
    pub name: String,
    pub kind: SymbolKind,
    pub language: Language,
    pub file: String,
    pub line: usize,
    pub is_async: bool,
    pub params: Vec<ParamContract>,
    pub return_type: String,
    pub fields: Vec<FieldContract>,
    pub signature_hash: String,
}

impl PublicSymbol {
    pub fn compute_signature_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update(b"|");
        hasher.update(self.kind.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(if self.is_async {
            b"async".as_slice()
        } else {
            b"sync".as_slice()
        });
        hasher.update(b"|");
        for p in &self.params {
            hasher.update(p.name.as_bytes());
            hasher.update(b":");
            hasher.update(p.ty.as_bytes());
            hasher.update(if p.optional { b"?" } else { b"!" });
            hasher.update(if p.variadic {
                b"...".as_slice()
            } else {
                b"".as_slice()
            });
            hasher.update(b",");
        }
        hasher.update(b"->");
        hasher.update(self.return_type.as_bytes());
        hasher.update(b"|");
        for f in &self.fields {
            hasher.update(f.name.as_bytes());
            hasher.update(b":");
            hasher.update(f.ty.as_bytes());
            hasher.update(if f.optional { b"?" } else { b"!" });
            hasher.update(b";");
        }
        self.signature_hash = to_hex(&hasher.finalize());
    }
}

/// Full deterministic snapshot of a repository's exported public API contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSnapshot {
    pub schema_version: String,
    pub contract_sha256: String,
    pub files_scanned: usize,
    pub languages: Vec<String>,
    pub symbols: BTreeMap<String, PublicSymbol>,
}

/// Recursively scans a source directory and extracts its deterministic `ContractSnapshot`.
pub fn extract_directory_contract(root: &Path) -> Result<ContractSnapshot> {
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    files.sort();

    let mut symbols = BTreeMap::new();
    let mut languages_set = BTreeSet::new();
    let mut files_scanned = 0usize;

    for (rel_path, full_path, lang) in files {
        let content = match fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        files_scanned += 1;
        languages_set.insert(lang.as_str().to_string());

        let extracted = extract_from_source(&content, &rel_path, lang);
        for mut sym in extracted {
            sym.compute_signature_hash();
            symbols.insert(sym.id.clone(), sym);
        }
    }

    let contract_sha256 = compute_snapshot_fingerprint(&symbols);

    Ok(ContractSnapshot {
        schema_version: "1.1.0".to_string(),
        contract_sha256,
        files_scanned,
        languages: languages_set.into_iter().collect(),
        symbols,
    })
}

/// Builds a `ContractSnapshot` from an in-memory list of `(relative_path, source_content)` pairs.
/// Used by the Zero-Disk Git Reference extractor (`--base-ref`).
pub fn extract_in_memory_files(files: &[(String, String)]) -> ContractSnapshot {
    let mut symbols = BTreeMap::new();
    let mut languages_set = BTreeSet::new();
    let mut files_scanned = 0usize;

    for (rel_path, content) in files {
        let p = Path::new(rel_path);
        let file_name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if should_skip_file(&file_name)
            || p.components()
                .any(|c| should_skip_dir(&c.as_os_str().to_string_lossy()))
        {
            continue;
        }
        let Some(lang) = detect_language(p) else {
            continue;
        };

        files_scanned += 1;
        languages_set.insert(lang.as_str().to_string());

        let extracted = extract_from_source(content, rel_path, lang);
        for mut sym in extracted {
            sym.compute_signature_hash();
            symbols.insert(sym.id.clone(), sym);
        }
    }

    let contract_sha256 = compute_snapshot_fingerprint(&symbols);

    ContractSnapshot {
        schema_version: "1.1.0".to_string(),
        contract_sha256,
        files_scanned,
        languages: languages_set.into_iter().collect(),
        symbols,
    }
}

/// Extracts public symbols from a single file's content.
pub fn extract_from_source(content: &str, rel_file: &str, lang: Language) -> Vec<PublicSymbol> {
    let stripped = strip_comments_preserving_lines(content);
    match lang {
        Language::Rust => extract_rust_symbols(&stripped, rel_file),
        Language::TypeScript => extract_ts_symbols(&stripped, rel_file),
    }
}

fn collect_source_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf, Language)>,
) -> Result<()> {
    if !current.exists() {
        return Ok(());
    }
    if current.is_file() {
        if let Some(lang) = detect_language(current) {
            let rel = current
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());
            out.push((rel, current.to_path_buf(), lang));
        }
        return Ok(());
    }

    let entries = fs::read_dir(current)
        .with_context(|| format!("Failed to read directory {}", current.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();

        if path.is_dir() {
            if should_skip_dir(&file_name) {
                continue;
            }
            collect_source_files(root, &path, out)?;
        } else if path.is_file() {
            if should_skip_file(&file_name) {
                continue;
            }
            if let Some(lang) = detect_language(&path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path, lang));
            }
        }
    }
    Ok(())
}

pub fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "target"
            | "node_modules"
            | "dist"
            | "build"
            | "coverage"
            | "vendor"
            | ".vortex"
            | ".byte-gauge"
            | ".specter"
            | ".github"
            | "tests"
            | "benches"
            | "examples"
    )
}

pub fn should_skip_file(name: &str) -> bool {
    name.ends_with(".test.ts")
        || name.ends_with("_test.ts")
        || name.ends_with(".spec.ts")
        || name.ends_with(".test.js")
        || name.ends_with("_test.rs")
        || name.ends_with(".d.ts")
}

pub fn detect_language(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_string_lossy().to_lowercase();
    match ext.as_str() {
        "rs" => Some(Language::Rust),
        "ts" | "tsx" | "mts" | "cts" | "js" | "mjs" => Some(Language::TypeScript),
        _ => None,
    }
}

/// Replaces `//` and `/* ... */` comments with spaces while keeping `\n` intact
/// so line numbers remain 100% accurate.
pub fn strip_comments_preserving_lines(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string: Option<u8> = None;

    while i < bytes.len() {
        let b = bytes[i];

        if let Some(quote) = in_string {
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }

        if b == b'"' || b == b'\'' || b == b'`' {
            in_string = Some(b);
            out.push(b as char);
            i += 1;
            continue;
        }

        // Line comment `//`
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        // Block comment `/* ... */`
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    break;
                }
                if bytes[i] == b'\n' {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                i += 1;
            }
            continue;
        }

        out.push(b as char);
        i += 1;
    }

    out
}

// ============================================================================
// RUST PUBLIC SURFACE EXTRACTOR (`pub fn`, `impl`, `pub use`, `pub struct`, `pub enum`, `pub trait`, `pub type`, `pub const`)
// ============================================================================

fn extract_rust_symbols(source: &str, rel_file: &str) -> Vec<PublicSymbol> {
    let mut symbols = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Ignore `#[cfg(test)]` modules at the bottom of a file
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }

        // 1. Check `impl` blocks for public methods (`pub fn`, `pub async fn`, `pub const fn`)
        if is_rust_impl_block(trimmed)
            && let Some(impl_target) = parse_rust_impl_target(trimmed)
        {
            let (body_lines, end_idx) = collect_brace_block(&lines, i);
            extract_rust_impl_methods(&body_lines, i, &impl_target, rel_file, &mut symbols);
            i = end_idx + 1;
            continue;
        }

        // 2. Check `pub use` barrel re-exports
        if let Some(reexport_rest) = trimmed.strip_prefix("pub use ") {
            let start_line = i + 1;
            let mut combined = reexport_rest.to_string();
            let mut j = i;
            while j < lines.len() && !lines[j].contains(';') {
                j += 1;
                if j < lines.len() {
                    combined.push(' ');
                    combined.push_str(lines[j].trim());
                }
            }
            for sym in parse_rust_pub_use(&combined, rel_file, start_line) {
                symbols.push(sym);
            }
            i = j + 1;
            continue;
        }

        // 3. Check top-level `pub` items
        if is_rust_public_item(trimmed) {
            let start_line = i + 1;
            let mut combined = String::new();
            let mut j = i;
            while j < lines.len() {
                combined.push_str(lines[j].trim());
                combined.push(' ');
                if lines[j].contains('{') || lines[j].contains(';') {
                    break;
                }
                j += 1;
            }

            if let Some(mut sym) = parse_rust_declaration(&combined, rel_file, start_line, None) {
                if matches!(sym.kind, SymbolKind::Struct | SymbolKind::Enum)
                    && combined.contains('{')
                {
                    let (body_lines, end_idx) = collect_brace_block(&lines, i);
                    sym.fields = parse_rust_body_fields(&body_lines, &sym.kind);
                    i = end_idx + 1;
                    symbols.push(sym);
                    continue;
                }
                symbols.push(sym);
            }
        }
        i += 1;
    }

    symbols
}

fn is_rust_impl_block(trimmed: &str) -> bool {
    (trimmed.starts_with("impl ") || trimmed.starts_with("impl<")) && trimmed.contains('{')
}

fn parse_rust_impl_target(trimmed: &str) -> Option<String> {
    let before_brace = trimmed.split('{').next()?.trim();
    let without_where = before_brace.split(" where ").next()?.trim();
    // If `impl Trait for Type`, target is `Type`; otherwise after `impl` / generics
    if let Some(for_idx) = without_where.rfind(" for ") {
        let target_raw = without_where[for_idx + 5..].trim();
        let target_base = target_raw.split('<').next()?.trim();
        extract_identifier(target_base)
    } else {
        let after_impl = without_where.strip_prefix("impl")?.trim();
        let after_generics = if after_impl.starts_with('<') {
            let close = find_matching_angle(after_impl)?;
            after_impl[close + 1..].trim()
        } else {
            after_impl
        };
        let target_base = after_generics.split('<').next()?.trim();
        extract_identifier(target_base)
    }
}

fn extract_rust_impl_methods(
    body_lines: &[String],
    block_start_idx: usize,
    impl_target: &str,
    rel_file: &str,
    out: &mut Vec<PublicSymbol>,
) {
    let mut k = 1; // skip opening `impl ... {` line
    while k < body_lines.len() {
        let line_trimmed = body_lines[k].trim();
        if is_rust_public_fn(line_trimmed) {
            let abs_line = block_start_idx + k + 1;
            let mut combined = String::new();
            let mut m = k;
            while m < body_lines.len() {
                combined.push_str(body_lines[m].trim());
                combined.push(' ');
                if body_lines[m].contains('{') || body_lines[m].contains(';') {
                    break;
                }
                m += 1;
            }
            if let Some(sym) =
                parse_rust_declaration(&combined, rel_file, abs_line, Some(impl_target))
            {
                out.push(sym);
            }
        }
        k += 1;
    }
}

fn is_rust_public_fn(trimmed: &str) -> bool {
    let Some(rest) = trimmed.strip_prefix("pub ") else {
        return false;
    };
    let r = rest.trim_start();
    r.starts_with("fn ")
        || r.starts_with("async fn ")
        || r.starts_with("const fn ")
        || r.starts_with("unsafe fn ")
}

fn parse_rust_pub_use(raw: &str, rel_file: &str, line: usize) -> Vec<PublicSymbol> {
    let clean = raw.split(';').next().unwrap_or(raw).trim();
    let mut out = Vec::new();

    if let Some(open_brace) = clean.find('{')
        && let Some(close_brace) = clean.rfind('}')
    {
        let prefix = clean[..open_brace].trim().trim_end_matches("::");
        let items = &clean[open_brace + 1..close_brace];
        for item in items.split(',') {
            let tok = item.trim();
            if tok.is_empty() || tok == "self" {
                continue;
            }
            let exported_name = if let Some(as_idx) = tok.find(" as ") {
                tok[as_idx + 4..].trim()
            } else {
                tok
            };
            if let Some(ident) = extract_identifier(exported_name) {
                out.push(PublicSymbol {
                    id: format!("{}::reexport::{}", rel_file, ident),
                    name: ident,
                    kind: SymbolKind::ReExport,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    params: Vec::new(),
                    return_type: format!("{}::{}", prefix, tok),
                    fields: Vec::new(),
                    signature_hash: String::new(),
                });
            }
        }
    } else {
        let exported_name = if let Some(as_idx) = clean.find(" as ") {
            clean[as_idx + 4..].trim()
        } else {
            clean.rsplit("::").next().unwrap_or(clean).trim()
        };
        let name = if exported_name == "*" {
            format!("*({})", clean)
        } else {
            extract_identifier(exported_name).unwrap_or_else(|| clean.to_string())
        };
        out.push(PublicSymbol {
            id: format!("{}::reexport::{}", rel_file, name),
            name,
            kind: SymbolKind::ReExport,
            language: Language::Rust,
            file: rel_file.to_string(),
            line,
            is_async: false,
            params: Vec::new(),
            return_type: clean.to_string(),
            fields: Vec::new(),
            signature_hash: String::new(),
        });
    }

    out
}

fn is_rust_public_item(trimmed: &str) -> bool {
    if !trimmed.starts_with("pub ") {
        return false;
    }
    let rest = trimmed["pub ".len()..].trim_start();
    rest.starts_with("fn ")
        || rest.starts_with("async fn ")
        || rest.starts_with("const fn ")
        || rest.starts_with("unsafe fn ")
        || rest.starts_with("struct ")
        || rest.starts_with("enum ")
        || rest.starts_with("trait ")
        || rest.starts_with("type ")
        || rest.starts_with("const ")
}

fn parse_rust_declaration(
    decl: &str,
    rel_file: &str,
    line: usize,
    owner_type: Option<&str>,
) -> Option<PublicSymbol> {
    let after_pub = decl.trim().strip_prefix("pub ")?.trim();
    let (is_async, rest) = if let Some(r) = after_pub.strip_prefix("async ") {
        (true, r.trim())
    } else if after_pub.starts_with("const fn ") {
        (false, &after_pub[6..])
    } else {
        (false, after_pub)
    };

    if let Some(fn_rest) = rest.strip_prefix("fn ") {
        let raw_name = extract_identifier(fn_rest)?;
        let (name, kind) = match owner_type {
            Some(owner) => (format!("{}::{}", owner, raw_name), SymbolKind::Method),
            None => (raw_name, SymbolKind::Function),
        };
        let params_raw = extract_balanced_parens(fn_rest)?;
        let params = parse_rust_params(&params_raw);
        let return_type = extract_rust_return_type(fn_rest);
        return Some(PublicSymbol {
            id: format!("{}::{}", rel_file, name),
            name,
            kind,
            language: Language::Rust,
            file: rel_file.to_string(),
            line,
            is_async,
            params,
            return_type,
            fields: Vec::new(),
            signature_hash: String::new(),
        });
    }

    for (prefix, kind) in [
        ("struct ", SymbolKind::Struct),
        ("enum ", SymbolKind::Enum),
        ("trait ", SymbolKind::Trait),
        ("type ", SymbolKind::TypeAlias),
        ("const ", SymbolKind::Const),
    ] {
        if let Some(item_rest) = rest.strip_prefix(prefix) {
            let name = extract_identifier(item_rest)?;
            let return_type = if matches!(kind, SymbolKind::TypeAlias | SymbolKind::Const) {
                extract_after_equals_or_colon(item_rest)
            } else {
                String::new()
            };
            return Some(PublicSymbol {
                id: format!("{}::{}", rel_file, name),
                name,
                kind,
                language: Language::Rust,
                file: rel_file.to_string(),
                line,
                is_async: false,
                params: Vec::new(),
                return_type,
                fields: Vec::new(),
                signature_hash: String::new(),
            });
        }
    }

    None
}

fn parse_rust_params(raw: &str) -> Vec<ParamContract> {
    let mut out = Vec::new();
    for part in split_top_level_commas(raw) {
        let p = part.trim();
        if p.is_empty() || p == "self" || p == "&self" || p == "&mut self" || p == "mut self" {
            continue;
        }
        if let Some(colon_idx) = p.find(':') {
            let raw_name = p[..colon_idx].trim().trim_start_matches("mut ").trim();
            let raw_ty = normalize_type(&p[colon_idx + 1..]);
            let optional = raw_ty.starts_with("Option<");
            out.push(ParamContract {
                name: raw_name.to_string(),
                ty: raw_ty,
                optional,
                variadic: false,
            });
        }
    }
    out
}

fn extract_rust_return_type(fn_decl: &str) -> String {
    let mut depth = 0i32;
    let mut after_parens_idx = None;
    for (idx, ch) in fn_decl.char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                after_parens_idx = Some(idx + 1);
                break;
            }
        }
    }

    let tail = match after_parens_idx {
        Some(i) if i < fn_decl.len() => &fn_decl[i..],
        _ => return "()".to_string(),
    };

    let before_body = tail
        .split('{')
        .next()
        .unwrap_or(tail)
        .split(';')
        .next()
        .unwrap_or(tail);
    let before_where = before_body.split(" where ").next().unwrap_or(before_body);

    if let Some(arrow_idx) = before_where.find("->") {
        normalize_type(&before_where[arrow_idx + 2..])
    } else {
        "()".to_string()
    }
}

fn parse_rust_body_fields(body_lines: &[String], kind: &SymbolKind) -> Vec<FieldContract> {
    let mut fields = Vec::new();
    let joined = body_lines.join("\n");
    let inner = extract_between_outer_braces(&joined);

    for item in split_top_level_commas(&inner) {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        match kind {
            SymbolKind::Struct => {
                if let Some(rest) = trimmed.strip_prefix("pub ")
                    && let Some(colon_idx) = rest.find(':')
                {
                    let name = rest[..colon_idx].trim().to_string();
                    let ty = normalize_type(&rest[colon_idx + 1..]);
                    let optional = ty.starts_with("Option<");
                    fields.push(FieldContract { name, ty, optional });
                }
            }
            SymbolKind::Enum => {
                if let Some(name) = extract_identifier(trimmed) {
                    let payload = trimmed[name.len()..].split('=').next().unwrap_or("").trim();
                    fields.push(FieldContract {
                        name,
                        ty: normalize_type(payload),
                        optional: false,
                    });
                }
            }
            _ => {}
        }
    }
    fields
}

// ============================================================================
// TYPESCRIPT / DENO PUBLIC SURFACE EXTRACTOR (`export function`, `export class` methods, `export { ... } from`, `export interface`, `export type`, `export const`, `export enum`)
// ============================================================================

fn extract_ts_symbols(source: &str, rel_file: &str) -> Vec<PublicSymbol> {
    let mut symbols = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("export ") {
            let start_line = i + 1;

            // 1. Check barrel re-exports: `export { a, b } from "./mod.ts"` or `export * from "./mod.ts"`
            if is_ts_reexport(trimmed) {
                let mut combined = String::new();
                let mut j = i;
                while j < lines.len() {
                    combined.push_str(lines[j].trim());
                    combined.push(' ');
                    if lines[j].contains(';') || lines[j].contains("from ") {
                        break;
                    }
                    j += 1;
                }
                for sym in parse_ts_reexport(&combined, rel_file, start_line) {
                    symbols.push(sym);
                }
                i = j + 1;
                continue;
            }

            let mut combined = String::new();
            let mut j = i;
            while j < lines.len() {
                combined.push_str(lines[j].trim());
                combined.push(' ');
                if lines[j].contains('{') || lines[j].contains(';') {
                    break;
                }
                j += 1;
            }

            if let Some(mut sym) = parse_ts_declaration(&combined, rel_file, start_line) {
                if matches!(
                    sym.kind,
                    SymbolKind::Interface | SymbolKind::Enum | SymbolKind::Class
                ) && combined.contains('{')
                {
                    let (body_lines, end_idx) = collect_brace_block(&lines, i);
                    sym.fields = parse_ts_body_fields(&body_lines, &sym.kind);
                    if sym.kind == SymbolKind::Class {
                        let class_name = sym.name.clone();
                        symbols.push(sym);
                        extract_ts_class_methods(
                            &body_lines,
                            i,
                            &class_name,
                            rel_file,
                            &mut symbols,
                        );
                    } else {
                        symbols.push(sym);
                    }
                    i = end_idx + 1;
                    continue;
                }
                symbols.push(sym);
            }
        }
        i += 1;
    }

    symbols
}

fn is_ts_reexport(trimmed: &str) -> bool {
    let Some(after) = trimmed.strip_prefix("export ") else {
        return false;
    };
    let clean = after.strip_prefix("type ").unwrap_or(after).trim_start();
    clean.starts_with('{') || clean.starts_with('*')
}

fn parse_ts_reexport(decl: &str, rel_file: &str, line: usize) -> Vec<PublicSymbol> {
    let mut out = Vec::new();
    let clean = decl.trim().trim_end_matches(';').trim();
    let source_mod = if let Some(from_idx) = clean.rfind(" from ") {
        clean[from_idx + 6..]
            .trim()
            .trim_matches(['"', '\''])
            .to_string()
    } else {
        "local".to_string()
    };

    if let Some(open_brace) = clean.find('{')
        && let Some(close_brace) = clean.rfind('}')
    {
        let inner = &clean[open_brace + 1..close_brace];
        for part in inner.split(',') {
            let tok = part
                .trim()
                .strip_prefix("type ")
                .unwrap_or(part.trim())
                .trim();
            if tok.is_empty() {
                continue;
            }
            let exported_name = if let Some(as_idx) = tok.find(" as ") {
                tok[as_idx + 4..].trim()
            } else {
                tok
            };
            if let Some(ident) = extract_identifier(exported_name) {
                out.push(PublicSymbol {
                    id: format!("{}::reexport::{}", rel_file, ident),
                    name: ident,
                    kind: SymbolKind::ReExport,
                    language: Language::TypeScript,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    params: Vec::new(),
                    return_type: format!("from {}", source_mod),
                    fields: Vec::new(),
                    signature_hash: String::new(),
                });
            }
        }
    } else if clean.contains('*') {
        let name = format!("*({})", source_mod);
        out.push(PublicSymbol {
            id: format!("{}::reexport::{}", rel_file, name),
            name,
            kind: SymbolKind::ReExport,
            language: Language::TypeScript,
            file: rel_file.to_string(),
            line,
            is_async: false,
            params: Vec::new(),
            return_type: format!("from {}", source_mod),
            fields: Vec::new(),
            signature_hash: String::new(),
        });
    }

    out
}

fn extract_ts_class_methods(
    body_lines: &[String],
    block_start_idx: usize,
    class_name: &str,
    rel_file: &str,
    out: &mut Vec<PublicSymbol>,
) {
    let mut k = 1;
    while k < body_lines.len() {
        let trimmed = body_lines[k].trim();
        if let Some(sym) =
            try_parse_ts_class_method(trimmed, block_start_idx + k + 1, class_name, rel_file)
        {
            out.push(sym);
        }
        k += 1;
    }
}

fn try_parse_ts_class_method(
    trimmed: &str,
    line: usize,
    class_name: &str,
    rel_file: &str,
) -> Option<PublicSymbol> {
    if trimmed.is_empty()
        || trimmed.starts_with("private ")
        || trimmed.starts_with("protected ")
        || trimmed.starts_with('#')
        || !trimmed.contains('(')
        || !trimmed.contains('{')
    {
        return None;
    }

    let s1 = trimmed.strip_prefix("public ").unwrap_or(trimmed).trim();
    let s2 = s1.strip_prefix("static ").unwrap_or(s1).trim();
    let (is_async, s3) = if let Some(r) = s2.strip_prefix("async ") {
        (true, r.trim())
    } else {
        (false, s2)
    };

    let method_name = extract_identifier(s3)?;
    if matches!(
        method_name.as_str(),
        "if" | "for" | "while" | "switch" | "catch" | "constructor"
    ) {
        return None;
    }

    let params_raw = extract_balanced_parens(s3)?;
    let params = parse_ts_params(&params_raw);
    let return_type = extract_ts_return_type(s3);
    let full_name = format!("{}::{}", class_name, method_name);

    Some(PublicSymbol {
        id: format!("{}::{}", rel_file, full_name),
        name: full_name,
        kind: SymbolKind::Method,
        language: Language::TypeScript,
        file: rel_file.to_string(),
        line,
        is_async,
        params,
        return_type,
        fields: Vec::new(),
        signature_hash: String::new(),
    })
}

fn parse_ts_declaration(decl: &str, rel_file: &str, line: usize) -> Option<PublicSymbol> {
    let after_export = decl.trim().strip_prefix("export ")?.trim();
    let after_default = after_export
        .strip_prefix("default ")
        .map(|s| s.trim())
        .unwrap_or(after_export);

    let (is_async, rest) = if let Some(r) = after_default.strip_prefix("async ") {
        (true, r.trim())
    } else {
        (false, after_default)
    };

    if let Some(fn_rest) = rest.strip_prefix("function ") {
        let name = extract_identifier(fn_rest).unwrap_or_else(|| "default".to_string());
        let params_raw = extract_balanced_parens(fn_rest)?;
        let params = parse_ts_params(&params_raw);
        let return_type = extract_ts_return_type(fn_rest);
        return Some(PublicSymbol {
            id: format!("{}::{}", rel_file, name),
            name,
            kind: SymbolKind::Function,
            language: Language::TypeScript,
            file: rel_file.to_string(),
            line,
            is_async,
            params,
            return_type,
            fields: Vec::new(),
            signature_hash: String::new(),
        });
    }

    for (prefix, kind) in [
        ("interface ", SymbolKind::Interface),
        ("type ", SymbolKind::TypeAlias),
        ("class ", SymbolKind::Class),
        ("enum ", SymbolKind::Enum),
        ("const ", SymbolKind::Const),
    ] {
        if let Some(item_rest) = rest.strip_prefix(prefix) {
            let name = extract_identifier(item_rest)?;
            let return_type = if matches!(kind, SymbolKind::TypeAlias | SymbolKind::Const) {
                extract_after_equals_or_colon(item_rest)
            } else {
                String::new()
            };
            return Some(PublicSymbol {
                id: format!("{}::{}", rel_file, name),
                name,
                kind,
                language: Language::TypeScript,
                file: rel_file.to_string(),
                line,
                is_async: false,
                params: Vec::new(),
                return_type,
                fields: Vec::new(),
                signature_hash: String::new(),
            });
        }
    }

    None
}

fn parse_ts_params(raw: &str) -> Vec<ParamContract> {
    let mut out = Vec::new();
    for part in split_top_level_commas(raw) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let variadic = p.starts_with("...");
        let clean = p.trim_start_matches("...").trim();

        let has_default = has_top_level_equals(clean);
        let before_default = split_top_level_equals(clean);

        if let Some(colon_idx) = find_top_level_colon(before_default) {
            let raw_name = before_default[..colon_idx].trim();
            let optional_mark = raw_name.ends_with('?');
            let name = raw_name.trim_end_matches('?').trim().to_string();
            let ty = normalize_type(&before_default[colon_idx + 1..]);
            out.push(ParamContract {
                name,
                ty,
                optional: optional_mark || has_default,
                variadic,
            });
        } else {
            let optional_mark = before_default.ends_with('?');
            let name = before_default.trim_end_matches('?').trim().to_string();
            out.push(ParamContract {
                name,
                ty: "any".to_string(),
                optional: optional_mark || has_default,
                variadic,
            });
        }
    }
    out
}

fn extract_ts_return_type(fn_decl: &str) -> String {
    let mut depth = 0i32;
    let mut after_parens_idx = None;
    for (idx, ch) in fn_decl.char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                after_parens_idx = Some(idx + 1);
                break;
            }
        }
    }

    let tail = match after_parens_idx {
        Some(i) if i < fn_decl.len() => &fn_decl[i..],
        _ => return "unknown".to_string(),
    };

    let before_body = tail
        .split('{')
        .next()
        .unwrap_or(tail)
        .split(';')
        .next()
        .unwrap_or(tail);
    if let Some(colon_idx) = before_body.find(':') {
        normalize_type(&before_body[colon_idx + 1..])
    } else {
        "void".to_string()
    }
}

fn parse_ts_body_fields(body_lines: &[String], kind: &SymbolKind) -> Vec<FieldContract> {
    let mut fields = Vec::new();
    let joined = body_lines.join("\n");
    let inner = extract_between_outer_braces(&joined);

    let separator = if *kind == SymbolKind::Enum { ',' } else { ';' };
    for raw_line in inner.split(['\n', separator]) {
        let trimmed = raw_line.trim().trim_end_matches(',').trim();
        if trimmed.is_empty()
            || trimmed.starts_with("private ")
            || trimmed.starts_with("protected ")
            || trimmed.starts_with('#')
            || trimmed.contains('(')
        {
            continue;
        }
        let after_pub = trimmed.strip_prefix("public ").unwrap_or(trimmed).trim();
        let clean = after_pub
            .strip_prefix("readonly ")
            .unwrap_or(after_pub)
            .trim();

        if *kind == SymbolKind::Enum {
            if let Some(name) = extract_identifier(clean) {
                fields.push(FieldContract {
                    name,
                    ty: "enum_member".to_string(),
                    optional: false,
                });
            }
            continue;
        }

        if let Some(colon_idx) = find_top_level_colon(clean) {
            let left = clean[..colon_idx].trim();
            let optional = left.ends_with('?');
            let name = left.trim_end_matches('?').trim().to_string();
            if name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
                && !name.is_empty()
            {
                let ty = normalize_type(&clean[colon_idx + 1..]);
                fields.push(FieldContract { name, ty, optional });
            }
        }
    }
    fields
}

// ============================================================================
// LOW-LEVEL LEXICAL HELPERS
// ============================================================================

fn find_matching_angle(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in s.char_indices() {
        if ch == '<' {
            depth += 1;
        } else if ch == '>' {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn collect_brace_block(lines: &[&str], start_idx: usize) -> (Vec<String>, usize) {
    let mut collected = Vec::new();
    let mut depth = 0i32;
    let mut seen_open = false;
    let mut idx = start_idx;

    while idx < lines.len() {
        let line = lines[idx];
        collected.push(line.to_string());
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                seen_open = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if seen_open && depth <= 0 {
            return (collected, idx);
        }
        idx += 1;
    }

    (collected, lines.len().saturating_sub(1))
}

fn extract_between_outer_braces(s: &str) -> String {
    let start = match s.find('{') {
        Some(i) => i + 1,
        None => return String::new(),
    };
    let end = s.rfind('}').unwrap_or(s.len());
    if start <= end {
        s[start..end].to_string()
    } else {
        String::new()
    }
}

fn extract_identifier(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let mut ident = String::new();
    for ch in trimmed.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            ident.push(ch);
        } else {
            break;
        }
    }
    if ident.is_empty() { None } else { Some(ident) }
}

fn extract_balanced_parens(s: &str) -> Option<String> {
    let open_idx = s.find('(')?;
    let mut depth = 0i32;
    for (offset, ch) in s[open_idx..].char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(s[open_idx + 1..open_idx + offset].to_string());
            }
        }
    }
    None
}

fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth_angle = 0i32;
    let mut depth_paren = 0i32;
    let mut depth_brace = 0i32;
    let mut depth_bracket = 0i32;

    for ch in s.chars() {
        match ch {
            '<' => depth_angle += 1,
            '>' => depth_angle = (depth_angle - 1).max(0),
            '(' => depth_paren += 1,
            ')' => depth_paren = (depth_paren - 1).max(0),
            '{' => depth_brace += 1,
            '}' => depth_brace = (depth_brace - 1).max(0),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = (depth_bracket - 1).max(0),
            ',' if depth_angle == 0
                && depth_paren == 0
                && depth_brace == 0
                && depth_bracket == 0 =>
            {
                parts.push(current.trim().to_string());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

fn find_top_level_colon(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in s.char_indices() {
        match ch {
            '<' | '(' | '{' | '[' => depth += 1,
            '>' | ')' | '}' | ']' => depth = (depth - 1).max(0),
            ':' if depth == 0 => return Some(idx),
            _ => {}
        }
    }
    None
}

fn has_top_level_equals(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'{' | b'[' => depth += 1,
            b'>' | b')' | b'}' | b']' => depth = (depth - 1).max(0),
            b'=' if depth == 0 => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'>' {
                    i += 2;
                    continue;
                }
                return true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn split_top_level_equals(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'{' | b'[' => depth += 1,
            b'>' | b')' | b'}' | b']' => depth = (depth - 1).max(0),
            b'=' if depth == 0 => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'>' {
                    i += 2;
                    continue;
                }
                return s[..i].trim();
            }
            _ => {}
        }
        i += 1;
    }
    s
}

fn extract_after_equals_or_colon(s: &str) -> String {
    let clean = s.split(';').next().unwrap_or(s);
    if let Some(colon) = find_top_level_colon(clean) {
        let rhs = &clean[colon + 1..];
        let before_eq = split_top_level_equals(rhs);
        normalize_type(before_eq)
    } else if let Some(eq_idx) = clean.find('=') {
        normalize_type(&clean[eq_idx + 1..])
    } else {
        String::new()
    }
}

pub fn normalize_type(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn compute_snapshot_fingerprint(symbols: &BTreeMap<String, PublicSymbol>) -> String {
    let mut hasher = Sha256::new();
    for (id, sym) in symbols {
        hasher.update(id.as_bytes());
        hasher.update(b"=");
        hasher.update(sym.signature_hash.as_bytes());
        hasher.update(b"\n");
    }
    to_hex(&hasher.finalize())
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

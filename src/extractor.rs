use crate::config::SpecterConfig;
use crate::{reachability, rust_ast, ts_ast};
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
    #[serde(default)]
    pub is_non_exhaustive: bool,
    pub params: Vec<ParamContract>,
    pub return_type: String,
    pub fields: Vec<FieldContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<String>,
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
        if self.is_non_exhaustive {
            hasher.update(b"non_exhaustive|");
        }
        for p in &self.params {
            // Positional parameter names are ignored in Rust/TS to prevent rename false positives.
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

/// Recursively scans a source directory and extracts its deterministic `ContractSnapshot`,
/// automatically loading `specter.toml` / `.specter.toml` if present.
pub fn extract_directory_contract(root: &Path) -> Result<ContractSnapshot> {
    let config = SpecterConfig::load_from_dir(root).unwrap_or_default();
    extract_directory_contract_with_config(root, &config)
}

/// Recursively scans a source directory using an explicit `SpecterConfig`.
pub fn extract_directory_contract_with_config(
    root: &Path,
    config: &SpecterConfig,
) -> Result<ContractSnapshot> {
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    files.sort();

    let mut file_map = BTreeMap::new();

    // Load root manifest files if present for entry-point reachability auto-discovery
    for manifest in ["Cargo.toml", "package.json", "deno.json", "deno.jsonc"] {
        let p = root.join(manifest);
        if p.is_file()
            && let Ok(c) = fs::read_to_string(&p)
        {
            file_map.insert(manifest.to_string(), c);
        }
    }

    for (rel_path, full_path, _lang) in files {
        if let Ok(c) = fs::read_to_string(&full_path) {
            file_map.insert(rel_path, c);
        }
    }

    Ok(extract_snapshot_from_file_map(&file_map, config))
}

/// Builds a `ContractSnapshot` from an in-memory list of `(relative_path, source_content)` pairs.
/// Used by the Zero-Disk Git Reference extractor (`--base-ref`).
pub fn extract_in_memory_files(files: &[(String, String)]) -> ContractSnapshot {
    extract_in_memory_files_with_config(files, &SpecterConfig::default())
}

/// Builds a `ContractSnapshot` from in-memory files using an explicit `SpecterConfig`.
pub fn extract_in_memory_files_with_config(
    files: &[(String, String)],
    config: &SpecterConfig,
) -> ContractSnapshot {
    let mut file_map = BTreeMap::new();
    for (rel_path, content) in files {
        let norm = rel_path.replace('\\', "/");
        if matches!(
            norm.as_str(),
            "Cargo.toml" | "package.json" | "deno.json" | "deno.jsonc"
        ) {
            file_map.insert(norm, content.clone());
            continue;
        }
        let p = Path::new(&norm);
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
        if detect_language(p).is_some() {
            file_map.insert(norm, content.clone());
        }
    }

    extract_snapshot_from_file_map(&file_map, config)
}

fn extract_snapshot_from_file_map(
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
) -> ContractSnapshot {
    let mut symbols = BTreeMap::new();
    let mut languages_set = BTreeSet::new();
    let mut files_scanned = 0usize;

    // 1. Try entry-point reachability resolution for Rust and TypeScript/Deno
    let rust_reach = reachability::resolve_rust_reachability(file_map, config);
    if rust_reach.used_entry_points {
        files_scanned += rust_reach.files_scanned;
        languages_set.insert(Language::Rust.as_str().to_string());
        for (id, sym) in rust_reach.symbols {
            if !config.is_symbol_ignored(&id, &sym.name) {
                symbols.insert(id, sym);
            }
        }
    }

    let ts_reach = reachability::resolve_ts_reachability(file_map, config);
    if ts_reach.used_entry_points {
        files_scanned += ts_reach.files_scanned;
        languages_set.insert(Language::TypeScript.as_str().to_string());
        for (id, sym) in ts_reach.symbols {
            if !config.is_symbol_ignored(&id, &sym.name) {
                symbols.insert(id, sym);
            }
        }
    }

    // 2. Fallback to direct file extraction for languages without a discovered entry point
    for (rel_path, content) in file_map {
        if config.is_path_ignored(rel_path) {
            continue;
        }
        let Some(lang) = detect_language(Path::new(rel_path)) else {
            continue;
        };
        if (lang == Language::Rust && rust_reach.used_entry_points)
            || (lang == Language::TypeScript && ts_reach.used_entry_points)
        {
            continue;
        }

        files_scanned += 1;
        languages_set.insert(lang.as_str().to_string());

        let extracted = extract_from_source(content, rel_path, lang);
        for mut sym in extracted {
            if config.is_symbol_ignored(&sym.id, &sym.name) {
                continue;
            }
            sym.compute_signature_hash();
            symbols.insert(sym.id.clone(), sym);
        }
    }

    let contract_sha256 = compute_snapshot_fingerprint(&symbols);

    ContractSnapshot {
        schema_version: "1.3.0".to_string(),
        contract_sha256,
        files_scanned,
        languages: languages_set.into_iter().collect(),
        symbols,
    }
}

/// Extracts public symbols from a single file's content using real zero-compiler AST parsers
/// (`syn` for Rust 2024, `oxc_parser` for TypeScript/JavaScript).
pub fn extract_from_source(content: &str, rel_file: &str, lang: Language) -> Vec<PublicSymbol> {
    match lang {
        Language::Rust => rust_ast::extract_rust_symbols(content, rel_file),
        Language::TypeScript => ts_ast::extract_ts_symbols(content, rel_file),
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
    strip_comments_for_lang(input, Language::Rust)
}

/// Language-aware comment stripper preserving exact line numbers.
/// For Rust: handles lifetimes (`'a`, `'static`), raw strings (`r#"..."#`), and nested `/* /* */ */`.
/// For TypeScript: handles `'...'`, `"..."`, and template literals `` `...` ``.
pub fn strip_comments_for_lang(input: &str, lang: Language) -> String {
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

        if lang == Language::Rust
            && let Some((raw_start, hash_count)) = detect_rust_raw_string(bytes, i)
        {
            while i < raw_start {
                out.push(bytes[i] as char);
                i += 1;
            }
            while i < bytes.len() {
                if bytes[i] == b'"' {
                    let mut hashes = 0usize;
                    while hashes < hash_count
                        && i + 1 + hashes < bytes.len()
                        && bytes[i + 1 + hashes] == b'#'
                    {
                        hashes += 1;
                    }
                    if hashes == hash_count {
                        out.push('"');
                        for _ in 0..hash_count {
                            out.push('#');
                        }
                        i += 1 + hash_count;
                        break;
                    }
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

        if lang == Language::Rust && b == b'\'' {
            if let Some(char_end) = detect_rust_char_literal_end(bytes, i) {
                while i <= char_end {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            } else {
                out.push('\'');
                i += 1;
            }
            continue;
        }

        if b == b'"' || (lang == Language::TypeScript && (b == b'\'' || b == b'`')) {
            in_string = Some(b);
            out.push(b as char);
            i += 1;
            continue;
        }

        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if lang == Language::Rust
                    && bytes[i] == b'/'
                    && i + 1 < bytes.len()
                    && bytes[i + 1] == b'*'
                {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
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

fn detect_rust_raw_string(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
    if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
        return None;
    }
    let mut j = i;
    if (bytes[j] == b'b' || bytes[j] == b'c') && j + 1 < bytes.len() && bytes[j + 1] == b'r' {
        j += 2;
    } else if bytes[j] == b'r' {
        j += 1;
    } else {
        return None;
    }
    let mut hashes = 0usize;
    while j < bytes.len() && bytes[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'"' {
        Some((j + 1, hashes))
    } else {
        None
    }
}

fn detect_rust_char_literal_end(bytes: &[u8], i: usize) -> Option<usize> {
    if i + 2 >= bytes.len() {
        return None;
    }
    if bytes[i + 1] == b'\\' {
        let mut j = i + 2;
        if j < bytes.len() {
            j += 1;
        }
        let limit = (i + 14).min(bytes.len());
        while j < limit && bytes[j] != b'\n' {
            if bytes[j] == b'\'' {
                return Some(j);
            }
            j += 1;
        }
        None
    } else {
        let b1 = bytes[i + 1];
        if b1 == b'\n' || b1 == b'\r' || b1 == b'\'' {
            return None;
        }
        let char_len = if b1 < 0x80 {
            1
        } else if (b1 & 0xE0) == 0xC0 {
            2
        } else if (b1 & 0xF0) == 0xE0 {
            3
        } else {
            4
        };
        let close_idx = i + 1 + char_len;
        if close_idx < bytes.len() && bytes[close_idx] == b'\'' {
            Some(close_idx)
        } else {
            None
        }
    }
}

// ============================================================================
// CANONICAL TYPE NORMALIZATION & VARIANCE HELPERS
// ============================================================================

/// Canonicalizes Rust lifetimes (`'a`, `'input` -> `'0`, `'1`) and positional generic type
/// parameters (`T`, `Item` -> `T0`, `T1`) across function parameters and return type.
pub(crate) fn canonicalize_rust_fn_signature(
    generics_raw: Option<&str>,
    params: &mut [ParamContract],
    return_type: &mut String,
) {
    let mut lifetime_map: BTreeMap<String, String> = BTreeMap::new();
    let mut generic_map: BTreeMap<String, String> = BTreeMap::new();
    let mut next_lt = 0usize;
    let mut next_ty = 0usize;

    if let Some(raw) = generics_raw {
        for part in split_top_level_commas(raw) {
            let tok = part.trim();
            if tok.is_empty() || tok.starts_with("const ") {
                continue;
            }
            if tok.starts_with('\'') {
                let lt_name = tok.split([':', '+', ' ', '=']).next().unwrap_or("").trim();
                if lt_name.len() > 1
                    && lt_name != "'static"
                    && lt_name != "'_"
                    && !lifetime_map.contains_key(lt_name)
                {
                    lifetime_map.insert(lt_name.to_string(), format!("'{}", next_lt));
                    next_lt += 1;
                }
            } else if let Some(ident) = extract_identifier(tok)
                && !generic_map.contains_key(&ident)
            {
                generic_map.insert(ident, format!("T{}", next_ty));
                next_ty += 1;
            }
        }
    }

    for p in params.iter() {
        collect_rust_lifetimes(&p.ty, &mut lifetime_map, &mut next_lt);
    }
    collect_rust_lifetimes(return_type, &mut lifetime_map, &mut next_lt);

    if lifetime_map.is_empty() && generic_map.is_empty() {
        return;
    }

    for p in params.iter_mut() {
        p.ty = rewrite_rust_type_tokens(&p.ty, &lifetime_map, &generic_map);
        p.optional = p.ty.starts_with("Option<");
    }
    *return_type = rewrite_rust_type_tokens(return_type, &lifetime_map, &generic_map);
}

fn collect_rust_lifetimes(ty: &str, map: &mut BTreeMap<String, String>, next_lt: &mut usize) {
    let bytes = ty.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let lt = &ty[start..i];
            if lt.len() > 1 && lt != "'static" && lt != "'_" && !map.contains_key(lt) {
                map.insert(lt.to_string(), format!("'{}", *next_lt));
                *next_lt += 1;
            }
        } else {
            i += 1;
        }
    }
}

fn rewrite_rust_type_tokens(
    ty: &str,
    lifetime_map: &BTreeMap<String, String>,
    generic_map: &BTreeMap<String, String>,
) -> String {
    let mut out = String::with_capacity(ty.len());
    let chars: Vec<char> = ty.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch == '\'' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            if let Some(mapped) = lifetime_map.get(&tok) {
                out.push_str(mapped);
            } else {
                out.push_str(&tok);
            }
        } else if ch.is_alphabetic() || ch == '_' {
            let prev_is_colon = out.ends_with("::");
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            let next_is_colon = i + 1 < chars.len() && chars[i] == ':' && chars[i + 1] == ':';
            if !prev_is_colon
                && !next_is_colon
                && let Some(mapped) = generic_map.get(&tok)
            {
                out.push_str(mapped);
            } else {
                out.push_str(&tok);
            }
        } else {
            out.push(ch);
            i += 1;
        }
    }

    out
}

/// Canonicalizes positional generic type parameters (`T`, `U` -> `T0`, `T1`) in TypeScript functions/methods.
pub(crate) fn canonicalize_ts_fn_signature(
    generics_raw: Option<&str>,
    params: &mut [ParamContract],
    return_type: &mut String,
) {
    let Some(raw) = generics_raw else {
        return;
    };
    let mut generic_map: BTreeMap<String, String> = BTreeMap::new();
    let mut next_ty = 0usize;

    for part in split_top_level_commas(raw) {
        let tok = part.trim();
        if let Some(ident) = extract_identifier(tok)
            && !generic_map.contains_key(&ident)
        {
            generic_map.insert(ident, format!("T{}", next_ty));
            next_ty += 1;
        }
    }

    if generic_map.is_empty() {
        return;
    }

    let empty_lt = BTreeMap::new();
    for p in params.iter_mut() {
        let rewritten = rewrite_rust_type_tokens(&p.ty, &empty_lt, &generic_map);
        p.ty = normalize_ts_type(&rewritten);
    }
    let rewritten_ret = rewrite_rust_type_tokens(return_type, &empty_lt, &generic_map);
    *return_type = normalize_ts_type(&rewritten_ret);
}

/// Returns `true` if every top-level union member of `narrow` is contained in `wide`,
/// and `wide` strictly has more members (e.g. `string` is a subset of `number | string`).
pub(crate) fn is_ts_union_subset(narrow: &str, wide: &str) -> bool {
    let narrow_norm = normalize_ts_type(narrow);
    let wide_norm = normalize_ts_type(wide);
    if narrow_norm.is_empty() || wide_norm.is_empty() || narrow_norm == wide_norm {
        return false;
    }
    let narrow_set: BTreeSet<String> = split_top_level_pipe(&narrow_norm)
        .into_iter()
        .map(|s| normalize_ts_type(&s))
        .filter(|s| !s.is_empty())
        .collect();
    let wide_set: BTreeSet<String> = split_top_level_pipe(&wide_norm)
        .into_iter()
        .map(|s| normalize_ts_type(&s))
        .filter(|s| !s.is_empty())
        .collect();

    !narrow_set.is_empty() && wide_set.len() > narrow_set.len() && narrow_set.is_subset(&wide_set)
}

/// Canonicalizes TypeScript types:
/// - Collapses whitespace
/// - Converts `Array<T>` -> `T[]` (parenthesizing union inner types: `Array<A | B>` -> `(A | B)[]`)
/// - Sorts top-level union members alphabetically (`string | number` == `number | string`)
/// - Recursively normalizes generic type arguments (`Promise<string | number>`)
pub fn normalize_ts_type(raw: &str) -> String {
    let collapsed = normalize_type(raw);
    if collapsed.is_empty() {
        return collapsed;
    }

    let union_parts = split_top_level_pipe(&collapsed);
    if union_parts.len() > 1 {
        let mut normalized: Vec<String> = union_parts
            .into_iter()
            .map(|part| normalize_ts_type(&part))
            .filter(|s| !s.is_empty())
            .collect();
        normalized.sort();
        normalized.dedup();
        return normalized.join(" | ");
    }

    let single = collapsed.trim();

    if single.starts_with('(')
        && single.ends_with(')')
        && find_matching_paren_at_zero(single) == Some(single.len() - 1)
    {
        return normalize_ts_type(&single[1..single.len() - 1]);
    }

    if let Some(inner) = single.strip_suffix("[]") {
        let inner_trimmed = inner.trim();
        let norm_inner = normalize_ts_type(inner_trimmed);
        if split_top_level_pipe(&norm_inner).len() > 1 {
            return format!("({})[]", norm_inner);
        }
        return format!("{}[]", norm_inner);
    }

    if let Some(rest) = single.strip_prefix("Array<")
        && let Some(close_idx) = find_matching_angle(&single["Array".len()..])
        && "Array".len() + close_idx == single.len() - 1
    {
        let inner = &rest[..rest.len() - 1];
        let norm_inner = normalize_ts_type(inner);
        if split_top_level_pipe(&norm_inner).len() > 1 {
            return format!("({})[]", norm_inner);
        }
        return format!("{}[]", norm_inner);
    }

    if let Some(open_angle) = single.find('<')
        && single.ends_with('>')
        && find_matching_angle(&single[open_angle..]) == Some(single.len() - 1 - open_angle)
    {
        let base = single[..open_angle].trim();
        let args_raw = &single[open_angle + 1..single.len() - 1];
        let norm_args: Vec<String> = split_top_level_commas(args_raw)
            .into_iter()
            .map(|a| normalize_ts_type(&a))
            .collect();
        return format!("{}<{}>", base, norm_args.join(", "));
    }

    single.to_string()
}

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

fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth_angle = 0i32;
    let mut depth_paren = 0i32;
    let mut depth_brace = 0i32;
    let mut depth_bracket = 0i32;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    for ch in s.chars() {
        if let Some(quote) = in_string {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = Some(ch);
                current.push(ch);
                continue;
            }
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

fn split_top_level_pipe(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth_angle = 0i32;
    let mut depth_paren = 0i32;
    let mut depth_brace = 0i32;
    let mut depth_bracket = 0i32;
    let mut in_string: Option<char> = None;

    for ch in s.chars() {
        if let Some(quote) = in_string {
            current.push(ch);
            if ch == quote {
                in_string = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => {
                in_string = Some(ch);
                current.push(ch);
                continue;
            }
            '<' => depth_angle += 1,
            '>' => depth_angle = (depth_angle - 1).max(0),
            '(' => depth_paren += 1,
            ')' => depth_paren = (depth_paren - 1).max(0),
            '{' => depth_brace += 1,
            '}' => depth_brace = (depth_brace - 1).max(0),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = (depth_bracket - 1).max(0),
            '|' if depth_angle == 0
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

fn find_matching_paren_at_zero(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in s.char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
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

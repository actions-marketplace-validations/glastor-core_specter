use crate::config::SpecterConfig;
use crate::extractor::{Language, PublicSymbol, SymbolKind};
use crate::{rust_ast, ts_ast};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::{Item, UseTree, Visibility};

/// Result of running entry-point reachability resolution for a language.
pub struct ReachabilityResult {
    /// True if at least one entry point was found and graph resolution was applied.
    pub used_entry_points: bool,
    pub files_scanned: usize,
    pub symbols: BTreeMap<String, PublicSymbol>,
}

/// Resolves Rust public API reachability starting from `config.entry_points`,
/// `Cargo.toml` `[lib] path`, or `src/lib.rs`.
///
/// Assigns **Logical Symbol IDs** (e.g. `crate::Client::send`) instead of physical file paths
/// (`src/client/http.rs::Client::send`), making internal file moves 100% immune to false `SPC001`
/// and automatically ignoring `pub` items inside private modules unless re-exported via `pub use`.
pub fn resolve_rust_reachability(
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
) -> ReachabilityResult {
    let entries = discover_rust_entry_points(file_map, config);
    if entries.is_empty() {
        return ReachabilityResult {
            used_entry_points: false,
            files_scanned: 0,
            symbols: BTreeMap::new(),
        };
    }

    let mut symbols = BTreeMap::new();
    let mut visited_files = BTreeSet::new();

    for (prefix, entry) in entries {
        if config.is_path_ignored(&entry) {
            continue;
        }
        walk_rust_module(
            &entry,
            &prefix,
            file_map,
            config,
            &mut visited_files,
            &mut symbols,
        );
    }

    ReachabilityResult {
        used_entry_points: true,
        files_scanned: visited_files.len(),
        symbols,
    }
}

fn discover_rust_entry_points(
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
) -> Vec<(String, String)> {
    let explicit: Vec<(String, String)> = config
        .entry_points
        .iter()
        .map(|p| normalize_rel_path(p))
        .filter(|p| p.ends_with(".rs") && file_map.contains_key(p))
        .map(|p| ("crate".to_string(), p))
        .collect();
    if !explicit.is_empty() {
        return explicit;
    }

    // Check `Cargo.toml` for explicit `[lib] path = "..."` or Cargo `[workspace]` members
    if let Some(cargo_toml) = file_map.get("Cargo.toml")
        && let Ok(val) = cargo_toml.parse::<toml::Value>()
    {
        if let Some(lib_path) = val
            .get("lib")
            .and_then(|l| l.get("path"))
            .and_then(|p| p.as_str())
        {
            let norm = normalize_rel_path(lib_path);
            if file_map.contains_key(&norm) {
                return vec![("crate".to_string(), norm)];
            }
        }
        if val.get("workspace").is_some() {
            let ws_libs: Vec<(String, String)> = file_map
                .keys()
                .filter(|k| k.ends_with("/src/lib.rs"))
                .map(|k| {
                    let crate_dir = k.trim_end_matches("/src/lib.rs");
                    let crate_name = crate_dir.rsplit('/').next().unwrap_or(crate_dir);
                    (crate_name.to_string(), k.clone())
                })
                .collect();
            if !ws_libs.is_empty() {
                return ws_libs;
            }
        }
    }

    if file_map.contains_key("src/lib.rs") {
        return vec![("crate".to_string(), "src/lib.rs".to_string())];
    }

    Vec::new()
}

fn walk_rust_module(
    file_path: &str,
    logical_prefix: &str,
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
    visited_files: &mut BTreeSet<String>,
    out_symbols: &mut BTreeMap<String, PublicSymbol>,
) {
    if !visited_files.insert(file_path.to_string()) || config.is_path_ignored(file_path) {
        return;
    }
    let Some(content) = file_map.get(file_path) else {
        return;
    };

    // 1. Emit all directly public non-reexport symbols under their logical path
    let direct_syms = rust_ast::extract_rust_symbols(content, file_path);
    for mut sym in direct_syms {
        if sym.kind == SymbolKind::ReExport {
            continue;
        }
        let logical_id = format!("{}::{}", logical_prefix, sym.name);
        sym.id = logical_id.clone();
        sym.compute_signature_hash();
        out_symbols.insert(logical_id, sym);
    }

    // 2. Parse module structure for `pub mod` declarations and `pub use` re-exports
    let Ok(parsed) = syn::parse_file(content) else {
        return;
    };

    let mut child_mods: BTreeMap<String, (bool, String)> = BTreeMap::new();
    for item in &parsed.items {
        if let Item::Mod(m) = item
            && m.content.is_none()
        {
            let mod_name = m.ident.to_string();
            let is_pub = matches!(m.vis, Visibility::Public(_));
            if let Some(resolved_file) = resolve_rust_child_mod(file_path, &mod_name, file_map) {
                child_mods.insert(mod_name, (is_pub, resolved_file));
            }
        }
    }

    // Recurse into `pub mod` children
    for (mod_name, (is_pub, resolved_file)) in &child_mods {
        if *is_pub {
            let next_prefix = format!("{}::{}", logical_prefix, mod_name);
            walk_rust_module(
                resolved_file,
                &next_prefix,
                file_map,
                config,
                visited_files,
                out_symbols,
            );
        }
    }

    // Resolve `pub use` re-exports (including those lifting symbols out of private `mod` files!)
    for item in &parsed.items {
        if let Item::Use(u) = item
            && matches!(u.vis, Visibility::Public(_))
        {
            let line = u.use_token.span.start().line;
            let mut entries = Vec::new();
            flatten_use_tree(&u.tree, &[], &mut entries);

            for (segments, alias, is_glob) in entries {
                if let Some((target_file, target_sym_name)) =
                    resolve_rust_use_target(file_path, &segments, &child_mods, file_map, is_glob)
                {
                    if config.is_path_ignored(&target_file) {
                        continue;
                    }
                    visited_files.insert(target_file.clone());
                    let Some(target_src) = file_map.get(&target_file) else {
                        continue;
                    };
                    let target_syms = rust_ast::extract_rust_symbols(target_src, &target_file);

                    if is_glob {
                        for mut s in target_syms {
                            if s.kind == SymbolKind::ReExport {
                                continue;
                            }
                            let logical_id = format!("{}::{}", logical_prefix, s.name);
                            s.id = logical_id.clone();
                            s.compute_signature_hash();
                            out_symbols.insert(logical_id, s);
                        }
                    } else if let Some(orig_name) = target_sym_name {
                        let exported_name = alias.unwrap_or_else(|| orig_name.clone());
                        let mut matched_any = false;
                        for mut s in target_syms {
                            if s.kind == SymbolKind::ReExport {
                                continue;
                            }
                            if s.name == orig_name {
                                matched_any = true;
                                s.name = exported_name.clone();
                                let logical_id = format!("{}::{}", logical_prefix, exported_name);
                                s.id = logical_id.clone();
                                s.compute_signature_hash();
                                out_symbols.insert(logical_id, s);
                            } else if s.kind == SymbolKind::Method
                                && let Some(method_suffix) =
                                    s.name.strip_prefix(&format!("{}::", orig_name))
                            {
                                matched_any = true;
                                let renamed_method =
                                    format!("{}::{}", exported_name, method_suffix);
                                s.name = renamed_method.clone();
                                let logical_id = format!("{}::{}", logical_prefix, renamed_method);
                                s.id = logical_id.clone();
                                s.compute_signature_hash();
                                out_symbols.insert(logical_id, s);
                            }
                        }
                        if !matched_any {
                            emit_external_reexport(
                                logical_prefix,
                                &exported_name,
                                &segments.join("::"),
                                file_path,
                                line,
                                Language::Rust,
                                out_symbols,
                            );
                        }
                    }
                } else {
                    // External crate re-export (e.g. `pub use serde::Serialize;`)
                    let exported_name = if is_glob {
                        format!("*({}::*)", segments.join("::"))
                    } else {
                        alias.unwrap_or_else(|| {
                            segments.last().cloned().unwrap_or_else(|| "*".to_string())
                        })
                    };
                    emit_external_reexport(
                        logical_prefix,
                        &exported_name,
                        &segments.join("::"),
                        file_path,
                        line,
                        Language::Rust,
                        out_symbols,
                    );
                }
            }
        }
    }
}

fn flatten_use_tree(
    tree: &UseTree,
    prefix: &[String],
    out: &mut Vec<(Vec<String>, Option<String>, bool)>,
) {
    match tree {
        UseTree::Path(p) => {
            let mut next = prefix.to_vec();
            next.push(p.ident.to_string());
            flatten_use_tree(&p.tree, &next, out);
        }
        UseTree::Name(n) => {
            let ident = n.ident.to_string();
            if ident == "self" {
                return;
            }
            let mut segs = prefix.to_vec();
            segs.push(ident);
            out.push((segs, None, false));
        }
        UseTree::Rename(r) => {
            let alias = r.rename.to_string();
            if alias == "_" {
                return;
            }
            let mut segs = prefix.to_vec();
            segs.push(r.ident.to_string());
            out.push((segs, Some(alias), false));
        }
        UseTree::Glob(_) => {
            out.push((prefix.to_vec(), None, true));
        }
        UseTree::Group(g) => {
            for item in &g.items {
                flatten_use_tree(item, prefix, out);
            }
        }
    }
}

fn resolve_rust_use_target(
    current_file: &str,
    segments: &[String],
    child_mods: &BTreeMap<String, (bool, String)>,
    file_map: &BTreeMap<String, String>,
    is_glob: bool,
) -> Option<(String, Option<String>)> {
    if segments.is_empty() {
        return None;
    }

    let (start_file, rest) = match segments[0].as_str() {
        "crate" => {
            let root = if file_map.contains_key("src/lib.rs") {
                "src/lib.rs".to_string()
            } else {
                current_file.to_string()
            };
            (root, &segments[1..])
        }
        "self" => (current_file.to_string(), &segments[1..]),
        first => {
            if let Some((_, child_file)) = child_mods.get(first) {
                let remaining = &segments[1..];
                if is_glob {
                    if remaining.is_empty() {
                        return Some((child_file.clone(), None));
                    }
                    (child_file.clone(), remaining)
                } else if remaining.len() == 1 {
                    return Some((child_file.clone(), Some(remaining[0].clone())));
                } else {
                    (child_file.clone(), remaining)
                }
            } else {
                return None;
            }
        }
    };

    if is_glob {
        let mut cur = start_file;
        for seg in rest {
            cur = resolve_rust_child_mod(&cur, seg, file_map)?;
        }
        return Some((cur, None));
    }

    if rest.len() < 2 {
        return None;
    }
    let mut cur = start_file;
    for seg in &rest[..rest.len() - 1] {
        cur = resolve_rust_child_mod(&cur, seg, file_map)?;
    }
    let sym_name = rest.last()?.clone();
    Some((cur, Some(sym_name)))
}

fn resolve_rust_child_mod(
    parent_file: &str,
    mod_name: &str,
    file_map: &BTreeMap<String, String>,
) -> Option<String> {
    let p = Path::new(parent_file);
    let file_name = p.file_name()?.to_string_lossy();
    let parent_dir = p
        .parent()
        .map(|d| d.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();

    let base_dir = if file_name == "lib.rs" || file_name == "mod.rs" || file_name == "main.rs" {
        parent_dir
    } else {
        let stem = p.file_stem()?.to_string_lossy();
        if parent_dir.is_empty() {
            stem.to_string()
        } else {
            format!("{}/{}", parent_dir, stem)
        }
    };

    let candidates = if base_dir.is_empty() {
        vec![format!("{}.rs", mod_name), format!("{}/mod.rs", mod_name)]
    } else {
        vec![
            format!("{}/{}.rs", base_dir, mod_name),
            format!("{}/{}/mod.rs", base_dir, mod_name),
        ]
    };

    candidates.into_iter().find(|c| file_map.contains_key(c))
}

// ============================================================================
// TYPESCRIPT / DENO ENTRY-POINT REACHABILITY & LOGICAL SYMBOL IDS
// ============================================================================

/// Resolves TypeScript/Deno public API reachability starting from `config.entry_points`,
/// `package.json` (`exports` / `module` / `main`), or `deno.json` (`exports`).
pub fn resolve_ts_reachability(
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
) -> ReachabilityResult {
    let entries = discover_ts_entry_points(file_map, config);
    if entries.is_empty() {
        return ReachabilityResult {
            used_entry_points: false,
            files_scanned: 0,
            symbols: BTreeMap::new(),
        };
    }

    let mut symbols = BTreeMap::new();
    let mut visited_files = BTreeSet::new();

    for (prefix, entry_path) in entries {
        if config.is_path_ignored(&entry_path) {
            continue;
        }
        walk_ts_entry(
            &entry_path,
            &prefix,
            file_map,
            config,
            &mut visited_files,
            &mut symbols,
        );
    }

    ReachabilityResult {
        used_entry_points: true,
        files_scanned: visited_files.len(),
        symbols,
    }
}

fn discover_ts_entry_points(
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
) -> Vec<(String, String)> {
    let explicit: Vec<(String, String)> = config
        .entry_points
        .iter()
        .map(|p| normalize_rel_path(p))
        .filter(|p| is_ts_file(p) && file_map.contains_key(p))
        .map(|p| ("pkg".to_string(), p))
        .collect();
    if !explicit.is_empty() {
        return explicit;
    }

    let mut discovered = Vec::new();

    // 1. Check `package.json` (`exports`, `module`, `main`)
    if let Some(pkg_raw) = file_map.get("package.json")
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(pkg_raw)
    {
        if let Some(exports) = val.get("exports") {
            collect_json_exports(exports, "pkg", file_map, &mut discovered);
        }
        if discovered.is_empty() {
            for field in ["module", "main"] {
                if let Some(path_str) = val.get(field).and_then(|v| v.as_str())
                    && let Some(resolved) = resolve_ts_relative_path("", path_str, file_map)
                {
                    discovered.push(("pkg".to_string(), resolved));
                    break;
                }
            }
        }
    }

    // 2. Check `deno.json` / `deno.jsonc` (`exports`)
    if discovered.is_empty() {
        for deno_cfg in ["deno.json", "deno.jsonc"] {
            if let Some(raw) = file_map.get(deno_cfg)
                && let Ok(val) = serde_json::from_str::<serde_json::Value>(raw)
                && let Some(exports) = val.get("exports")
            {
                collect_json_exports(exports, "pkg", file_map, &mut discovered);
                break;
            }
        }
    }

    discovered
}

fn collect_json_exports(
    exports: &serde_json::Value,
    default_prefix: &str,
    file_map: &BTreeMap<String, String>,
    out: &mut Vec<(String, String)>,
) {
    match exports {
        serde_json::Value::String(s) => {
            if let Some(resolved) = resolve_ts_relative_path("", s, file_map) {
                out.push((default_prefix.to_string(), resolved));
            }
        }
        serde_json::Value::Object(map) => {
            // Conditional export object like `{ "import": "./src/index.ts", "default": "..." }`
            for cond in ["import", "default", "deno", "browser", "node"] {
                if let Some(serde_json::Value::String(s)) = map.get(cond)
                    && let Some(resolved) = resolve_ts_relative_path("", s, file_map)
                {
                    out.push((default_prefix.to_string(), resolved));
                    return;
                }
            }
            // Subpath exports like `{ ".": "./src/index.ts", "./utils": "./src/utils.ts" }`
            for (k, v) in map {
                if !k.starts_with('.') {
                    continue;
                }
                let subpath_prefix = if k == "." {
                    default_prefix.to_string()
                } else {
                    format!("{}/{}", default_prefix, k.trim_start_matches("./"))
                };
                collect_json_exports(v, &subpath_prefix, file_map, out);
            }
        }
        _ => {}
    }
}

fn walk_ts_entry(
    file_path: &str,
    logical_prefix: &str,
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
    visited_files: &mut BTreeSet<String>,
    out_symbols: &mut BTreeMap<String, PublicSymbol>,
) {
    if !visited_files.insert(file_path.to_string()) || config.is_path_ignored(file_path) {
        return;
    }
    let Some(content) = file_map.get(file_path) else {
        return;
    };

    let syms = ts_ast::extract_ts_symbols(content, file_path);
    for mut sym in syms {
        if sym.kind != SymbolKind::ReExport {
            let logical_id = format!("{}::{}", logical_prefix, sym.name);
            sym.id = logical_id.clone();
            sym.compute_signature_hash();
            out_symbols.insert(logical_id, sym);
            continue;
        }

        // Barrel re-export: `return_type` is `"from <specifier>"`
        let Some(specifier) = sym.return_type.strip_prefix("from ") else {
            continue;
        };
        if specifier == "local" {
            continue;
        }

        if let Some(target_file) = resolve_ts_relative_path(file_path, specifier, file_map) {
            if config.is_path_ignored(&target_file) {
                continue;
            }
            if sym.name.starts_with("*(") {
                // `export * from "./mod.ts"`
                walk_ts_entry(
                    &target_file,
                    logical_prefix,
                    file_map,
                    config,
                    visited_files,
                    out_symbols,
                );
            } else {
                // Named re-export `export { Foo } from "./internal/foo.ts"`
                let mut chain_visited = BTreeSet::new();
                resolve_ts_named_reexport(
                    &target_file,
                    &sym.name,
                    &sym.name,
                    logical_prefix,
                    file_map,
                    config,
                    visited_files,
                    &mut chain_visited,
                    out_symbols,
                );
            }
        } else {
            // External package re-export
            emit_external_reexport(
                logical_prefix,
                &sym.name,
                &sym.return_type,
                file_path,
                sym.line,
                Language::TypeScript,
                out_symbols,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_ts_named_reexport(
    target_file: &str,
    lookup_name: &str,
    exported_name: &str,
    logical_prefix: &str,
    file_map: &BTreeMap<String, String>,
    config: &SpecterConfig,
    visited_files: &mut BTreeSet<String>,
    chain_visited: &mut BTreeSet<String>,
    out_symbols: &mut BTreeMap<String, PublicSymbol>,
) {
    if !chain_visited.insert(target_file.to_string()) || config.is_path_ignored(target_file) {
        return;
    }
    visited_files.insert(target_file.to_string());
    let Some(content) = file_map.get(target_file) else {
        return;
    };

    let target_syms = ts_ast::extract_ts_symbols(content, target_file);
    let mut found = false;

    for mut s in target_syms.clone() {
        if s.kind == SymbolKind::ReExport {
            continue;
        }
        if s.name == lookup_name {
            found = true;
            s.name = exported_name.to_string();
            let logical_id = format!("{}::{}", logical_prefix, exported_name);
            s.id = logical_id.clone();
            s.compute_signature_hash();
            out_symbols.insert(logical_id, s);
        } else if s.kind == SymbolKind::Method
            && let Some(method_suffix) = s.name.strip_prefix(&format!("{}::", lookup_name))
        {
            found = true;
            let renamed = format!("{}::{}", exported_name, method_suffix);
            s.name = renamed.clone();
            let logical_id = format!("{}::{}", logical_prefix, renamed);
            s.id = logical_id.clone();
            s.compute_signature_hash();
            out_symbols.insert(logical_id, s);
        }
    }

    if !found {
        // Follow chained re-exports inside `target_file`
        for s in target_syms {
            if s.kind == SymbolKind::ReExport
                && let Some(specifier) = s.return_type.strip_prefix("from ")
                && (s.name == lookup_name || s.name.starts_with("*("))
                && let Some(next_file) = resolve_ts_relative_path(target_file, specifier, file_map)
            {
                resolve_ts_named_reexport(
                    &next_file,
                    lookup_name,
                    exported_name,
                    logical_prefix,
                    file_map,
                    config,
                    visited_files,
                    chain_visited,
                    out_symbols,
                );
            }
        }
    }
}

fn resolve_ts_relative_path(
    from_file: &str,
    specifier: &str,
    file_map: &BTreeMap<String, String>,
) -> Option<String> {
    if !specifier.starts_with('.') && !from_file.is_empty() {
        return None;
    }
    let base_dir = Path::new(from_file)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();

    let joined = join_normalized_path(&base_dir, specifier);
    let mut candidates = vec![joined.clone()];
    // Handle `.js` -> `.ts` ESM TypeScript import convention
    if let Some(stem) = joined.strip_suffix(".js") {
        candidates.push(format!("{}.ts", stem));
        candidates.push(format!("{}.tsx", stem));
    }
    if let Some(stem) = joined.strip_suffix(".mjs") {
        candidates.push(format!("{}.mts", stem));
    }
    for ext in [
        ".ts",
        ".tsx",
        ".mts",
        ".js",
        ".mjs",
        "/index.ts",
        "/mod.ts",
        "/index.js",
    ] {
        candidates.push(format!("{}{}", joined, ext));
    }

    candidates.into_iter().find(|c| file_map.contains_key(c))
}

fn emit_external_reexport(
    logical_prefix: &str,
    exported_name: &str,
    return_type: &str,
    file_path: &str,
    line: usize,
    language: Language,
    out_symbols: &mut BTreeMap<String, PublicSymbol>,
) {
    let logical_id = format!("{}::reexport::{}", logical_prefix, exported_name);
    let mut sym = PublicSymbol {
        id: logical_id.clone(),
        name: exported_name.to_string(),
        kind: SymbolKind::ReExport,
        language,
        file: file_path.to_string(),
        line,
        is_async: false,
        is_non_exhaustive: false,
        params: Vec::new(),
        return_type: return_type.to_string(),
        fields: Vec::new(),
        suppressions: Vec::new(),
        signature_hash: String::new(),
    };
    sym.compute_signature_hash();
    out_symbols.insert(logical_id, sym);
}

fn normalize_rel_path(p: &str) -> String {
    p.replace('\\', "/").trim_start_matches("./").to_string()
}

fn join_normalized_path(base_dir: &str, rel: &str) -> String {
    let combined = if base_dir.is_empty() {
        rel.to_string()
    } else {
        format!("{}/{}", base_dir, rel)
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in combined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

fn is_ts_file(p: &str) -> bool {
    p.ends_with(".ts")
        || p.ends_with(".tsx")
        || p.ends_with(".mts")
        || p.ends_with(".cts")
        || p.ends_with(".js")
        || p.ends_with(".mjs")
}

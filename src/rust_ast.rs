use crate::config::extract_inline_suppressions;
use crate::extractor::{
    FieldContract, Language, ParamContract, PublicSymbol, SymbolKind,
    canonicalize_rust_fn_signature, normalize_type,
};
use quote::ToTokens;
use syn::{
    Attribute, Fields, FnArg, GenericParam, Generics, ImplItem, Item, Meta, Pat, ReturnType, Type,
    UseTree, Visibility,
};

/// Extracts public API symbols from Rust source using the official `syn` AST parser
/// (zero-compiler, full Rust 2024 grammar support).
pub fn extract_rust_symbols(source: &str, rel_file: &str) -> Vec<PublicSymbol> {
    let Ok(file) = syn::parse_file(source) else {
        return Vec::new();
    };

    let mut symbols = Vec::new();
    collect_items(&file.items, rel_file, None, &mut symbols);
    for sym in &mut symbols {
        sym.suppressions = extract_inline_suppressions(source, sym.line);
    }
    symbols
}

fn collect_items(
    items: &[Item],
    rel_file: &str,
    mod_prefix: Option<&str>,
    out: &mut Vec<PublicSymbol>,
) {
    for item in items {
        match item {
            Item::Fn(item_fn) => {
                if !is_public(&item_fn.vis) || is_skipped_attrs(&item_fn.attrs) {
                    continue;
                }
                let raw_name = item_fn.sig.ident.to_string();
                let name = qualify_name(mod_prefix, &raw_name);
                let line = item_fn.sig.fn_token.span.start().line;
                let is_async = item_fn.sig.asyncness.is_some();
                let (mut params, mut return_type) = extract_fn_signature(&item_fn.sig);
                let generics_str = format_generics_inner(&item_fn.sig.generics);
                canonicalize_rust_fn_signature(
                    generics_str.as_deref(),
                    &mut params,
                    &mut return_type,
                );
                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::Function,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async,
                    is_non_exhaustive: false,
                    params,
                    return_type,
                    fields: Vec::new(),
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            Item::Struct(item_struct) => {
                if !is_public(&item_struct.vis) || is_skipped_attrs(&item_struct.attrs) {
                    continue;
                }
                let raw_name = item_struct.ident.to_string();
                let name = qualify_name(mod_prefix, &raw_name);
                let line = item_struct.struct_token.span.start().line;
                let is_non_exhaustive = has_non_exhaustive_attr(&item_struct.attrs);
                let fields = extract_struct_fields(&item_struct.fields);
                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::Struct,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    is_non_exhaustive,
                    params: Vec::new(),
                    return_type: String::new(),
                    fields,
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            Item::Enum(item_enum) => {
                if !is_public(&item_enum.vis) || is_skipped_attrs(&item_enum.attrs) {
                    continue;
                }
                let raw_name = item_enum.ident.to_string();
                let name = qualify_name(mod_prefix, &raw_name);
                let line = item_enum.enum_token.span.start().line;
                let is_non_exhaustive = has_non_exhaustive_attr(&item_enum.attrs);
                let mut fields = Vec::new();
                for variant in &item_enum.variants {
                    if is_skipped_attrs(&variant.attrs) {
                        continue;
                    }
                    let payload = match &variant.fields {
                        Fields::Unit => String::new(),
                        Fields::Unnamed(u) => format_tokens(u),
                        Fields::Named(n) => format_tokens(n),
                    };
                    fields.push(FieldContract {
                        name: variant.ident.to_string(),
                        ty: payload,
                        optional: false,
                    });
                }
                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::Enum,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    is_non_exhaustive,
                    params: Vec::new(),
                    return_type: String::new(),
                    fields,
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            Item::Trait(item_trait) => {
                if !is_public(&item_trait.vis) || is_skipped_attrs(&item_trait.attrs) {
                    continue;
                }
                let raw_name = item_trait.ident.to_string();
                let name = qualify_name(mod_prefix, &raw_name);
                let line = item_trait.trait_token.span.start().line;
                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::Trait,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    is_non_exhaustive: false,
                    params: Vec::new(),
                    return_type: String::new(),
                    fields: Vec::new(),
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            Item::Type(item_type) => {
                if !is_public(&item_type.vis) || is_skipped_attrs(&item_type.attrs) {
                    continue;
                }
                let raw_name = item_type.ident.to_string();
                let name = qualify_name(mod_prefix, &raw_name);
                let line = item_type.type_token.span.start().line;
                let return_type = format_rust_type(&item_type.ty);
                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::TypeAlias,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    is_non_exhaustive: false,
                    params: Vec::new(),
                    return_type,
                    fields: Vec::new(),
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            Item::Const(item_const) => {
                if !is_public(&item_const.vis) || is_skipped_attrs(&item_const.attrs) {
                    continue;
                }
                let raw_name = item_const.ident.to_string();
                let name = qualify_name(mod_prefix, &raw_name);
                let line = item_const.const_token.span.start().line;
                // Extract ONLY the type annotation, never the literal value
                let return_type = format_rust_type(&item_const.ty);
                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::Const,
                    language: Language::Rust,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    is_non_exhaustive: false,
                    params: Vec::new(),
                    return_type,
                    fields: Vec::new(),
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            Item::Use(item_use) => {
                if !is_public(&item_use.vis) || is_skipped_attrs(&item_use.attrs) {
                    continue;
                }
                let line = item_use.use_token.span.start().line;
                collect_use_tree(&item_use.tree, "", rel_file, line, out);
            }
            Item::Impl(item_impl) => {
                if is_skipped_attrs(&item_impl.attrs) {
                    continue;
                }
                let Some(impl_target) = extract_impl_target_name(&item_impl.self_ty) else {
                    continue;
                };
                let impl_generics = format_generics_inner(&item_impl.generics);
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(method) = impl_item {
                        if !is_public(&method.vis) || is_skipped_attrs(&method.attrs) {
                            continue;
                        }
                        let full_name = qualify_name(
                            mod_prefix,
                            &format!("{}::{}", impl_target, method.sig.ident),
                        );
                        let line = method.sig.fn_token.span.start().line;
                        let is_async = method.sig.asyncness.is_some();
                        let (mut params, mut return_type) = extract_fn_signature(&method.sig);
                        let combined_generics = merge_generics(
                            impl_generics.as_deref(),
                            format_generics_inner(&method.sig.generics).as_deref(),
                        );
                        canonicalize_rust_fn_signature(
                            combined_generics.as_deref(),
                            &mut params,
                            &mut return_type,
                        );
                        out.push(PublicSymbol {
                            id: format!("{}::{}", rel_file, full_name),
                            name: full_name,
                            kind: SymbolKind::Method,
                            language: Language::Rust,
                            file: rel_file.to_string(),
                            line,
                            is_async,
                            is_non_exhaustive: false,
                            params,
                            return_type,
                            fields: Vec::new(),
                            suppressions: Vec::new(),
                            signature_hash: String::new(),
                        });
                    }
                }
            }
            Item::Mod(item_mod) => {
                // Only descend into public inline modules (`pub mod foo { ... }`).
                // Private inline modules (`mod internal { ... }`) and `#[cfg(test)] mod tests` are skipped!
                if !is_public(&item_mod.vis) || is_skipped_attrs(&item_mod.attrs) {
                    continue;
                }
                if let Some((_, sub_items)) = &item_mod.content {
                    let next_prefix = qualify_name(mod_prefix, &item_mod.ident.to_string());
                    collect_items(sub_items, rel_file, Some(&next_prefix), out);
                }
            }
            _ => {}
        }
    }
}

fn qualify_name(prefix: Option<&str>, name: &str) -> String {
    match prefix {
        Some(p) => format!("{}::{}", p, name),
        None => name.to_string(),
    }
}

fn is_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn is_skipped_attrs(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| is_cfg_test_attr(a) || is_doc_hidden_attr(a))
}

fn is_cfg_test_attr(attr: &Attribute) -> bool {
    if !attr.path().is_ident("cfg") {
        return false;
    }
    if let Meta::List(list) = &attr.meta {
        let tokens = list.tokens.to_string();
        let trimmed = tokens.trim();
        return trimmed == "test"
            || trimmed.starts_with("test,")
            || trimmed.contains(", test")
            || trimmed.contains("(test)");
    }
    false
}

fn is_doc_hidden_attr(attr: &Attribute) -> bool {
    if !attr.path().is_ident("doc") {
        return false;
    }
    if let Meta::List(list) = &attr.meta {
        let tokens = list.tokens.to_string();
        return tokens.split(',').any(|part| part.trim() == "hidden");
    }
    false
}

fn has_non_exhaustive_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("non_exhaustive"))
}

fn extract_struct_fields(fields: &Fields) -> Vec<FieldContract> {
    let mut out = Vec::new();
    match fields {
        Fields::Named(named) => {
            for f in &named.named {
                if !is_public(&f.vis) || is_skipped_attrs(&f.attrs) {
                    continue;
                }
                if let Some(ident) = &f.ident {
                    let ty = format_rust_type(&f.ty);
                    let optional = ty.starts_with("Option<");
                    out.push(FieldContract {
                        name: ident.to_string(),
                        ty,
                        optional,
                    });
                }
            }
        }
        Fields::Unnamed(unnamed) => {
            for (idx, f) in unnamed.unnamed.iter().enumerate() {
                if !is_public(&f.vis) || is_skipped_attrs(&f.attrs) {
                    continue;
                }
                let ty = format_rust_type(&f.ty);
                let optional = ty.starts_with("Option<");
                out.push(FieldContract {
                    name: idx.to_string(),
                    ty,
                    optional,
                });
            }
        }
        Fields::Unit => {}
    }
    out
}

fn extract_fn_signature(sig: &syn::Signature) -> (Vec<ParamContract>, String) {
    let mut params = Vec::new();
    for arg in &sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            let name = extract_pat_name(&pat_type.pat);
            let ty = format_rust_type(&pat_type.ty);
            let optional = ty.starts_with("Option<");
            params.push(ParamContract {
                name,
                ty,
                optional,
                variadic: false,
            });
        }
    }

    let return_type = match &sig.output {
        ReturnType::Default => "()".to_string(),
        ReturnType::Type(_, ty) => format_rust_type(ty),
    };

    (params, return_type)
}

fn extract_pat_name(pat: &Pat) -> String {
    match pat {
        Pat::Ident(pi) => pi.ident.to_string(),
        _ => format_tokens(pat),
    }
}

fn extract_impl_target_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(tp) => tp.path.segments.last().map(|seg| seg.ident.to_string()),
        Type::Reference(tr) => extract_impl_target_name(&tr.elem),
        _ => None,
    }
}

fn collect_use_tree(
    tree: &UseTree,
    prefix: &str,
    rel_file: &str,
    line: usize,
    out: &mut Vec<PublicSymbol>,
) {
    match tree {
        UseTree::Path(p) => {
            let next_prefix = if prefix.is_empty() {
                p.ident.to_string()
            } else {
                format!("{}::{}", prefix, p.ident)
            };
            collect_use_tree(&p.tree, &next_prefix, rel_file, line, out);
        }
        UseTree::Name(n) => {
            let ident = n.ident.to_string();
            if ident == "self" {
                return;
            }
            let full_path = if prefix.is_empty() {
                ident.clone()
            } else {
                format!("{}::{}", prefix, ident)
            };
            out.push(PublicSymbol {
                id: format!("{}::reexport::{}", rel_file, ident),
                name: ident,
                kind: SymbolKind::ReExport,
                language: Language::Rust,
                file: rel_file.to_string(),
                line,
                is_async: false,
                is_non_exhaustive: false,
                params: Vec::new(),
                return_type: full_path,
                fields: Vec::new(),
                suppressions: Vec::new(),
                signature_hash: String::new(),
            });
        }
        UseTree::Rename(r) => {
            let alias = r.rename.to_string();
            if alias == "_" {
                return;
            }
            let full_path = if prefix.is_empty() {
                format!("{} as {}", r.ident, alias)
            } else {
                format!("{}::{} as {}", prefix, r.ident, alias)
            };
            out.push(PublicSymbol {
                id: format!("{}::reexport::{}", rel_file, alias),
                name: alias,
                kind: SymbolKind::ReExport,
                language: Language::Rust,
                file: rel_file.to_string(),
                line,
                is_async: false,
                is_non_exhaustive: false,
                params: Vec::new(),
                return_type: full_path,
                fields: Vec::new(),
                suppressions: Vec::new(),
                signature_hash: String::new(),
            });
        }
        UseTree::Glob(_) => {
            let full_path = if prefix.is_empty() {
                "*".to_string()
            } else {
                format!("{}::*", prefix)
            };
            let name = format!("*({})", full_path);
            out.push(PublicSymbol {
                id: format!("{}::reexport::{}", rel_file, name),
                name,
                kind: SymbolKind::ReExport,
                language: Language::Rust,
                file: rel_file.to_string(),
                line,
                is_async: false,
                is_non_exhaustive: false,
                params: Vec::new(),
                return_type: full_path,
                fields: Vec::new(),
                suppressions: Vec::new(),
                signature_hash: String::new(),
            });
        }
        UseTree::Group(g) => {
            for item in &g.items {
                collect_use_tree(item, prefix, rel_file, line, out);
            }
        }
    }
}

fn format_generics_inner(generics: &Generics) -> Option<String> {
    if generics.params.is_empty() {
        return None;
    }
    let parts: Vec<String> = generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Lifetime(lt) => Some(lt.lifetime.to_string()),
            GenericParam::Type(tp) => Some(tp.ident.to_string()),
            GenericParam::Const(_) => None,
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn merge_generics(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a, b) {
        (Some(x), Some(y)) => Some(format!("{}, {}", x, y)),
        (Some(x), None) => Some(x.to_string()),
        (None, Some(y)) => Some(y.to_string()),
        (None, None) => None,
    }
}

/// Formats a `syn::Type` into a compact, canonical Rust type string without spurious
/// token-stream whitespace (e.g., `&'a str`, `Result<u16, String>`, `&[u8]`).
fn format_rust_type(ty: &Type) -> String {
    compact_rust_tokens(&format_tokens(ty))
}

fn format_tokens<T: ToTokens>(node: &T) -> String {
    normalize_type(&node.to_token_stream().to_string())
}

fn compact_rust_tokens(raw: &str) -> String {
    let mut s = raw.to_string();
    for (from, to) in [
        (" < ", "<"),
        ("< ", "<"),
        (" <", "<"),
        (" >", ">"),
        (" , ", ", "),
        (" ,", ","),
        (" :: ", "::"),
        (":: ", "::"),
        (" ::", "::"),
        ("& ", "&"),
        ("& '", "&'"),
        ("( ", "("),
        (" )", ")"),
        ("[ ", "["),
        (" ]", "]"),
        (" ; ", "; "),
        (" -> ", " -> "),
    ] {
        while s.contains(from) {
            s = s.replace(from, to);
        }
    }
    s.trim().to_string()
}

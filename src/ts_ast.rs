use crate::config::extract_inline_suppressions;
use crate::extractor::{
    FieldContract, Language, ParamContract, PublicSymbol, SymbolKind, canonicalize_ts_fn_signature,
    normalize_ts_type,
};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPattern, Class, ClassElement, Declaration, ExportDefaultDeclarationKind, Expression,
    FormalParameters, Function, ModuleExportName, PropertyKey, Statement, TSAccessibility,
    TSEnumMemberName, TSSignature, TSTypeParameterDeclaration, VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use std::path::Path;

/// Extracts public API symbols from TypeScript / JavaScript / Deno source using
/// `oxc_parser` (pure Rust, sub-millisecond zero-compiler AST).
pub fn extract_ts_symbols(source: &str, rel_file: &str) -> Vec<PublicSymbol> {
    let allocator = Allocator::default();
    let source_type =
        SourceType::from_path(Path::new(rel_file)).unwrap_or_else(|_| SourceType::ts());
    let ret = Parser::new(&allocator, source, source_type).parse();

    let line_starts = build_line_starts(source);
    let mut symbols = Vec::new();

    for stmt in &ret.program.body {
        match stmt {
            Statement::ExportDeclaration(export_decl) => {
                if has_internal_jsdoc_before(source, export_decl.span.start) {
                    continue;
                }
                extract_exported_declaration(
                    &export_decl.declaration,
                    source,
                    rel_file,
                    &line_starts,
                    &mut symbols,
                );
            }
            Statement::ExportDefaultDeclaration(export_default) => {
                if has_internal_jsdoc_before(source, export_default.span.start) {
                    continue;
                }
                let line = offset_to_line(&line_starts, export_default.span.start);
                match &export_default.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
                        let name = func
                            .id
                            .as_ref()
                            .map(|id| id.name.to_string())
                            .unwrap_or_else(|| "default".to_string());
                        symbols.push(build_ts_function(func, name, rel_file, line, source));
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(cls) => {
                        let name = cls
                            .id
                            .as_ref()
                            .map(|id| id.name.to_string())
                            .unwrap_or_else(|| "default".to_string());
                        extract_ts_class(
                            cls,
                            name,
                            rel_file,
                            line,
                            source,
                            &line_starts,
                            &mut symbols,
                        );
                    }
                    ExportDefaultDeclarationKind::TSInterfaceDeclaration(iface) => {
                        symbols.push(build_ts_interface(
                            iface,
                            rel_file,
                            line,
                            source,
                            &line_starts,
                        ));
                    }
                    ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => {
                        let (mut params, mut return_type) = extract_ts_params_and_return(
                            &arrow.params,
                            arrow.return_type.as_deref(),
                            source,
                        );
                        let generics = format_ts_generics(arrow.type_parameters.as_deref());
                        canonicalize_ts_fn_signature(
                            generics.as_deref(),
                            &mut params,
                            &mut return_type,
                        );
                        symbols.push(PublicSymbol {
                            id: format!("{}::default", rel_file),
                            name: "default".to_string(),
                            kind: SymbolKind::Function,
                            language: Language::TypeScript,
                            file: rel_file.to_string(),
                            line,
                            is_async: arrow.r#async,
                            is_non_exhaustive: false,
                            params,
                            return_type,
                            fields: Vec::new(),
                            suppressions: Vec::new(),
                            signature_hash: String::new(),
                        });
                    }
                    _ => {}
                }
            }
            Statement::ExportNamedDeclaration(named) => {
                if has_internal_jsdoc_before(source, named.span.start) {
                    continue;
                }
                let line = offset_to_line(&line_starts, named.span.start);
                for spec in &named.specifiers {
                    let exported_name = module_export_name(&spec.exported);
                    symbols.push(PublicSymbol {
                        id: format!("{}::reexport::{}", rel_file, exported_name),
                        name: exported_name,
                        kind: SymbolKind::ReExport,
                        language: Language::TypeScript,
                        file: rel_file.to_string(),
                        line,
                        is_async: false,
                        is_non_exhaustive: false,
                        params: Vec::new(),
                        return_type: "from local".to_string(),
                        fields: Vec::new(),
                        suppressions: Vec::new(),
                        signature_hash: String::new(),
                    });
                }
            }
            Statement::ExportFromDeclaration(reexport) => {
                if has_internal_jsdoc_before(source, reexport.span.start) {
                    continue;
                }
                let line = offset_to_line(&line_starts, reexport.span.start);
                let source_mod = reexport.source.value.to_string();
                for spec in &reexport.specifiers {
                    let exported_name = module_export_name(&spec.exported);
                    symbols.push(PublicSymbol {
                        id: format!("{}::reexport::{}", rel_file, exported_name),
                        name: exported_name,
                        kind: SymbolKind::ReExport,
                        language: Language::TypeScript,
                        file: rel_file.to_string(),
                        line,
                        is_async: false,
                        is_non_exhaustive: false,
                        params: Vec::new(),
                        return_type: format!("from {}", source_mod),
                        fields: Vec::new(),
                        suppressions: Vec::new(),
                        signature_hash: String::new(),
                    });
                }
            }
            Statement::ExportAllDeclaration(export_all) => {
                if has_internal_jsdoc_before(source, export_all.span.start) {
                    continue;
                }
                let line = offset_to_line(&line_starts, export_all.span.start);
                let source_mod = export_all.source.value.to_string();
                let name = match &export_all.exported {
                    Some(alias) => module_export_name(alias),
                    None => format!("*({})", source_mod),
                };
                symbols.push(PublicSymbol {
                    id: format!("{}::reexport::{}", rel_file, name),
                    name,
                    kind: SymbolKind::ReExport,
                    language: Language::TypeScript,
                    file: rel_file.to_string(),
                    line,
                    is_async: false,
                    is_non_exhaustive: false,
                    params: Vec::new(),
                    return_type: format!("from {}", source_mod),
                    fields: Vec::new(),
                    suppressions: Vec::new(),
                    signature_hash: String::new(),
                });
            }
            _ => {}
        }
    }

    for sym in &mut symbols {
        sym.suppressions = extract_inline_suppressions(source, sym.line);
    }
    symbols
}

fn extract_exported_declaration(
    decl: &Declaration<'_>,
    source: &str,
    rel_file: &str,
    line_starts: &[u32],
    out: &mut Vec<PublicSymbol>,
) {
    match decl {
        Declaration::FunctionDeclaration(func) => {
            let name = func
                .id
                .as_ref()
                .map(|id| id.name.to_string())
                .unwrap_or_else(|| "default".to_string());
            let line = offset_to_line(line_starts, func.span.start);
            out.push(build_ts_function(func, name, rel_file, line, source));
        }
        Declaration::ClassDeclaration(cls) => {
            let name = cls
                .id
                .as_ref()
                .map(|id| id.name.to_string())
                .unwrap_or_else(|| "default".to_string());
            let line = offset_to_line(line_starts, cls.span.start);
            extract_ts_class(cls, name, rel_file, line, source, line_starts, out);
        }
        Declaration::TSInterfaceDeclaration(iface) => {
            let line = offset_to_line(line_starts, iface.span.start);
            out.push(build_ts_interface(
                iface,
                rel_file,
                line,
                source,
                line_starts,
            ));
        }
        Declaration::TSTypeAliasDeclaration(alias) => {
            let name = alias.id.name.to_string();
            let line = offset_to_line(line_starts, alias.span.start);
            let raw_ty = slice_span(source, alias.type_annotation.span());
            let return_type = normalize_ts_type(raw_ty);
            out.push(PublicSymbol {
                id: format!("{}::{}", rel_file, name),
                name,
                kind: SymbolKind::TypeAlias,
                language: Language::TypeScript,
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
        Declaration::TSEnumDeclaration(en) => {
            let name = en.id.name.to_string();
            let line = offset_to_line(line_starts, en.span.start);
            let mut fields = Vec::new();
            for member in &en.body.members {
                if has_internal_jsdoc_before(source, member.span.start) {
                    continue;
                }
                let member_name = match &member.id {
                    TSEnumMemberName::Identifier(id) => id.name.to_string(),
                    TSEnumMemberName::String(s) => s.value.to_string(),
                    TSEnumMemberName::ComputedString(s) => s.value.to_string(),
                    TSEnumMemberName::ComputedTemplateString(t) => {
                        slice_span(source, t.span).to_string()
                    }
                };
                fields.push(FieldContract {
                    name: member_name,
                    ty: "enum_member".to_string(),
                    optional: false,
                });
            }
            out.push(PublicSymbol {
                id: format!("{}::{}", rel_file, name),
                name,
                kind: SymbolKind::Enum,
                language: Language::TypeScript,
                file: rel_file.to_string(),
                line,
                is_async: false,
                is_non_exhaustive: false,
                params: Vec::new(),
                return_type: String::new(),
                fields,
                suppressions: Vec::new(),
                signature_hash: String::new(),
            });
        }
        Declaration::VariableDeclaration(var_decl) => {
            if !matches!(
                var_decl.kind,
                VariableDeclarationKind::Const
                    | VariableDeclarationKind::Let
                    | VariableDeclarationKind::Var
            ) {
                return;
            }
            for declarator in &var_decl.declarations {
                let Some(name) = binding_pattern_name(&declarator.id) else {
                    continue;
                };
                let line = offset_to_line(line_starts, declarator.span.start);

                // Resolve exported arrow functions and function expressions as first-class Functions!
                if let Some(init) = &declarator.init {
                    match init {
                        Expression::ArrowFunctionExpression(arrow) => {
                            let (mut params, mut return_type) = extract_ts_params_and_return(
                                &arrow.params,
                                arrow.return_type.as_deref(),
                                source,
                            );
                            let generics = format_ts_generics(arrow.type_parameters.as_deref());
                            canonicalize_ts_fn_signature(
                                generics.as_deref(),
                                &mut params,
                                &mut return_type,
                            );
                            out.push(PublicSymbol {
                                id: format!("{}::{}", rel_file, name),
                                name,
                                kind: SymbolKind::Function,
                                language: Language::TypeScript,
                                file: rel_file.to_string(),
                                line,
                                is_async: arrow.r#async,
                                is_non_exhaustive: false,
                                params,
                                return_type,
                                fields: Vec::new(),
                                suppressions: Vec::new(),
                                signature_hash: String::new(),
                            });
                            continue;
                        }
                        Expression::FunctionExpression(func) => {
                            out.push(build_ts_function(func, name, rel_file, line, source));
                            continue;
                        }
                        _ => {}
                    }
                }

                // Non-function constant: extract ONLY the type annotation (never literal value)
                let return_type = declarator
                    .type_annotation
                    .as_deref()
                    .map(|ta| normalize_ts_type(slice_span(source, ta.type_annotation.span())))
                    .unwrap_or_else(|| "inferred".to_string());

                out.push(PublicSymbol {
                    id: format!("{}::{}", rel_file, name),
                    name,
                    kind: SymbolKind::Const,
                    language: Language::TypeScript,
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
        }
        _ => {}
    }
}

fn build_ts_function(
    func: &Function<'_>,
    name: String,
    rel_file: &str,
    line: usize,
    source: &str,
) -> PublicSymbol {
    let (mut params, mut return_type) =
        extract_ts_params_and_return(&func.params, func.return_type.as_deref(), source);
    let generics = format_ts_generics(func.type_parameters.as_deref());
    canonicalize_ts_fn_signature(generics.as_deref(), &mut params, &mut return_type);

    PublicSymbol {
        id: format!("{}::{}", rel_file, name),
        name,
        kind: SymbolKind::Function,
        language: Language::TypeScript,
        file: rel_file.to_string(),
        line,
        is_async: func.r#async,
        is_non_exhaustive: false,
        params,
        return_type,
        fields: Vec::new(),
        suppressions: Vec::new(),
        signature_hash: String::new(),
    }
}

fn extract_ts_class(
    cls: &Class<'_>,
    class_name: String,
    rel_file: &str,
    line: usize,
    source: &str,
    line_starts: &[u32],
    out: &mut Vec<PublicSymbol>,
) {
    let mut fields = Vec::new();
    let mut methods = Vec::new();

    for elem in &cls.body.body {
        match elem {
            ClassElement::PropertyDefinition(prop) => {
                if matches!(
                    prop.accessibility,
                    Some(TSAccessibility::Private | TSAccessibility::Protected)
                ) || matches!(prop.key, PropertyKey::PrivateIdentifier(_))
                    || has_internal_jsdoc_before(source, prop.span.start)
                {
                    continue;
                }
                if let Some(prop_name) = property_key_name(&prop.key) {
                    let ty = prop
                        .type_annotation
                        .as_deref()
                        .map(|ta| normalize_ts_type(slice_span(source, ta.type_annotation.span())))
                        .unwrap_or_else(|| "any".to_string());
                    fields.push(FieldContract {
                        name: prop_name,
                        ty,
                        optional: prop.optional,
                    });
                }
            }
            ClassElement::MethodDefinition(method) => {
                if matches!(
                    method.accessibility,
                    Some(TSAccessibility::Private | TSAccessibility::Protected)
                ) || matches!(method.key, PropertyKey::PrivateIdentifier(_))
                    || method.kind.is_constructor()
                    || has_internal_jsdoc_before(source, method.span.start)
                {
                    continue;
                }
                if let Some(method_name) = property_key_name(&method.key) {
                    let m_line = offset_to_line(line_starts, method.span.start);
                    let (mut params, mut return_type) = extract_ts_params_and_return(
                        &method.value.params,
                        method.value.return_type.as_deref(),
                        source,
                    );
                    let generics = format_ts_generics(method.value.type_parameters.as_deref());
                    canonicalize_ts_fn_signature(
                        generics.as_deref(),
                        &mut params,
                        &mut return_type,
                    );
                    let full_name = format!("{}::{}", class_name, method_name);
                    methods.push(PublicSymbol {
                        id: format!("{}::{}", rel_file, full_name),
                        name: full_name,
                        kind: SymbolKind::Method,
                        language: Language::TypeScript,
                        file: rel_file.to_string(),
                        line: m_line,
                        is_async: method.value.r#async,
                        is_non_exhaustive: false,
                        params,
                        return_type,
                        fields: Vec::new(),
                        suppressions: Vec::new(),
                        signature_hash: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    out.push(PublicSymbol {
        id: format!("{}::{}", rel_file, class_name),
        name: class_name,
        kind: SymbolKind::Class,
        language: Language::TypeScript,
        file: rel_file.to_string(),
        line,
        is_async: false,
        is_non_exhaustive: false,
        params: Vec::new(),
        return_type: String::new(),
        fields,
        suppressions: Vec::new(),
        signature_hash: String::new(),
    });
    out.extend(methods);
}

fn build_ts_interface(
    iface: &oxc_ast::ast::TSInterfaceDeclaration<'_>,
    rel_file: &str,
    line: usize,
    source: &str,
    _line_starts: &[u32],
) -> PublicSymbol {
    let name = iface.id.name.to_string();
    let mut fields = Vec::new();

    for sig in &iface.body.body {
        if let TSSignature::TSPropertySignature(prop) = sig {
            if has_internal_jsdoc_before(source, prop.span.start) {
                continue;
            }
            if let Some(prop_name) = property_key_name(&prop.key) {
                let ty = prop
                    .type_annotation
                    .as_deref()
                    .map(|ta| normalize_ts_type(slice_span(source, ta.type_annotation.span())))
                    .unwrap_or_else(|| "any".to_string());
                fields.push(FieldContract {
                    name: prop_name,
                    ty,
                    optional: prop.optional,
                });
            }
        }
    }

    PublicSymbol {
        id: format!("{}::{}", rel_file, name),
        name,
        kind: SymbolKind::Interface,
        language: Language::TypeScript,
        file: rel_file.to_string(),
        line,
        is_async: false,
        is_non_exhaustive: false,
        params: Vec::new(),
        return_type: String::new(),
        fields,
        suppressions: Vec::new(),
        signature_hash: String::new(),
    }
}

fn extract_ts_params_and_return(
    formal: &FormalParameters<'_>,
    ret_ann: Option<&oxc_ast::ast::TSTypeAnnotation<'_>>,
    source: &str,
) -> (Vec<ParamContract>, String) {
    let mut params = Vec::new();
    for item in &formal.items {
        let name = binding_pattern_name(&item.pattern)
            .unwrap_or_else(|| slice_span(source, item.pattern.span()).to_string());
        let ty = item
            .type_annotation
            .as_deref()
            .map(|ta| normalize_ts_type(slice_span(source, ta.type_annotation.span())))
            .unwrap_or_else(|| "any".to_string());
        let optional = item.optional || item.initializer.is_some();
        params.push(ParamContract {
            name,
            ty,
            optional,
            variadic: false,
        });
    }

    if let Some(rest) = &formal.rest {
        let name = binding_pattern_name(&rest.rest.argument)
            .unwrap_or_else(|| slice_span(source, rest.rest.argument.span()).to_string());
        let ty = rest
            .type_annotation
            .as_deref()
            .map(|ta| normalize_ts_type(slice_span(source, ta.type_annotation.span())))
            .unwrap_or_else(|| "any[]".to_string());
        params.push(ParamContract {
            name,
            ty,
            optional: false,
            variadic: true,
        });
    }

    let return_type = ret_ann
        .map(|ta| normalize_ts_type(slice_span(source, ta.type_annotation.span())))
        .unwrap_or_else(|| "void".to_string());

    (params, return_type)
}

fn format_ts_generics(type_params: Option<&TSTypeParameterDeclaration<'_>>) -> Option<String> {
    let tp = type_params?;
    if tp.params.is_empty() {
        return None;
    }
    let names: Vec<String> = tp.params.iter().map(|p| p.name.name.to_string()).collect();
    Some(names.join(", "))
}

fn binding_pattern_name(pat: &BindingPattern<'_>) -> Option<String> {
    match pat {
        BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
        _ => None,
    }
}

fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.to_string()),
        _ => None,
    }
}

fn module_export_name(name: &ModuleExportName<'_>) -> String {
    match name {
        ModuleExportName::IdentifierName(id) => id.name.to_string(),
        ModuleExportName::IdentifierReference(id) => id.name.to_string(),
        ModuleExportName::StringLiteral(s) => s.value.to_string(),
    }
}

fn slice_span(source: &str, span: Span) -> &str {
    let start = (span.start as usize).min(source.len());
    let end = (span.end as usize).min(source.len());
    if start <= end {
        &source[start..end]
    } else {
        ""
    }
}

fn build_line_starts(source: &str) -> Vec<u32> {
    let mut starts = vec![0u32];
    for (idx, b) in source.bytes().enumerate() {
        if b == b'\n' {
            starts.push((idx + 1) as u32);
        }
    }
    starts
}

fn offset_to_line(line_starts: &[u32], offset: u32) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(idx) => idx + 1,
        Err(idx) => idx.max(1),
    }
}

/// Checks if the trivia (comments/whitespace/decorators) immediately preceding `node_start`
/// contains a JSDoc or line comment with `@internal` or `@private`.
fn has_internal_jsdoc_before(source: &str, node_start: u32) -> bool {
    let prefix = &source[..(node_start as usize).min(source.len())];
    let lines: Vec<&str> = prefix.lines().collect();
    let mut in_block = false;

    // Walk backwards through contiguous blank lines, decorators, and comments
    for line in lines.iter().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if in_block {
            if contains_internal_tag(trimmed) {
                return true;
            }
            if trimmed.contains("/*") {
                in_block = false;
            }
            continue;
        }
        if trimmed.ends_with("*/") {
            if contains_internal_tag(trimmed) {
                return true;
            }
            if !trimmed.contains("/*") {
                in_block = true;
            }
            continue;
        }
        if trimmed.starts_with("//") {
            if contains_internal_tag(trimmed) {
                return true;
            }
            continue;
        }
        if trimmed.starts_with('@') {
            continue;
        }
        break;
    }

    false
}

fn contains_internal_tag(text: &str) -> bool {
    for tag in ["@internal", "@private"] {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(tag) {
            let abs = search_from + pos;
            let before_ok = abs == 0 || !text.as_bytes()[abs - 1].is_ascii_alphanumeric();
            let after_idx = abs + tag.len();
            let after_ok = after_idx >= text.len()
                || !(text.as_bytes()[after_idx].is_ascii_alphanumeric()
                    || text.as_bytes()[after_idx] == b'_');
            if before_ok && after_ok {
                return true;
            }
            search_from = after_idx;
        }
    }
    false
}

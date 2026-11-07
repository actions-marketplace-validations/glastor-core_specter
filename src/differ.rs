use crate::extractor::{
    ContractSnapshot, FieldContract, Language, ParamContract, PublicSymbol, SymbolKind,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Mathematical SemVer impact level determined from AST contract comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemverImpact {
    Patch,
    Minor,
    Major,
}

impl SemverImpact {
    pub fn as_str(&self) -> &'static str {
        match self {
            SemverImpact::Patch => "patch",
            SemverImpact::Minor => "minor",
            SemverImpact::Major => "major",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            SemverImpact::Patch => "🟢 PATCH (Compatible)",
            SemverImpact::Minor => "🟡 MINOR (Feature)",
            SemverImpact::Major => "🔴 MAJOR (Breaking)",
        }
    }
}

/// Specific contract change rule ID (maps directly to SARIF 2.1.0 rule definitions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeCode {
    /// SPC001: Exported public symbol was removed
    SymbolRemoved,
    /// SPC002: Required parameter added to exported function
    RequiredParamAdded,
    /// SPC003: Existing parameter removed from exported function
    ParamRemoved,
    /// SPC004: Optional parameter became required
    ParamBecameRequired,
    /// SPC005: Parameter type changed incompatibly
    ParamTypeChanged,
    /// SPC006: Function return type changed
    ReturnTypeChanged,
    /// SPC007: Function async/sync modifier changed
    AsyncModifierChanged,
    /// SPC008: Public struct/interface field or enum variant removed
    FieldRemoved,
    /// SPC009: Optional struct/interface field became required
    FieldBecameRequired,
    /// SPC010: Public struct/interface field type changed
    FieldTypeChanged,
    /// SPC011: New exported public symbol added (MINOR)
    SymbolAdded,
    /// SPC012: Optional parameter or field added (MINOR)
    OptionalMemberAdded,
    /// SPC013: Exported barrel re-export (`pub use` / `export { ... } from`) removed (MAJOR)
    ReExportRemoved,
}

impl ChangeCode {
    pub fn rule_id(&self) -> &'static str {
        match self {
            ChangeCode::SymbolRemoved => "SPC001",
            ChangeCode::RequiredParamAdded => "SPC002",
            ChangeCode::ParamRemoved => "SPC003",
            ChangeCode::ParamBecameRequired => "SPC004",
            ChangeCode::ParamTypeChanged => "SPC005",
            ChangeCode::ReturnTypeChanged => "SPC006",
            ChangeCode::AsyncModifierChanged => "SPC007",
            ChangeCode::FieldRemoved => "SPC008",
            ChangeCode::FieldBecameRequired => "SPC009",
            ChangeCode::FieldTypeChanged => "SPC010",
            ChangeCode::SymbolAdded => "SPC011",
            ChangeCode::OptionalMemberAdded => "SPC012",
            ChangeCode::ReExportRemoved => "SPC013",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            ChangeCode::SymbolRemoved => "Exported Symbol Removed",
            ChangeCode::RequiredParamAdded => "Required Parameter Added",
            ChangeCode::ParamRemoved => "Function Parameter Removed",
            ChangeCode::ParamBecameRequired => "Optional Parameter Became Required",
            ChangeCode::ParamTypeChanged => "Parameter Type Mutated",
            ChangeCode::ReturnTypeChanged => "Return Type Mutated",
            ChangeCode::AsyncModifierChanged => "Async/Sync Contract Mutated",
            ChangeCode::FieldRemoved => "Public Field or Variant Removed",
            ChangeCode::FieldBecameRequired => "Optional Field Became Required",
            ChangeCode::FieldTypeChanged => "Public Field Type Mutated",
            ChangeCode::SymbolAdded => "New Exported Symbol Added",
            ChangeCode::OptionalMemberAdded => "Backward-Compatible Optional Member Added",
            ChangeCode::ReExportRemoved => "Public Barrel Re-Export Removed",
        }
    }
}

/// A single audited change between the base and head API contract snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractFinding {
    pub code: ChangeCode,
    pub impact: SemverImpact,
    pub symbol_id: String,
    pub symbol_name: String,
    pub symbol_kind: SymbolKind,
    pub language: Language,
    pub file: String,
    pub line: usize,
    pub before: String,
    pub after: String,
    pub reason: String,
}

/// Complete result of comparing two `ContractSnapshot` instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDiffResult {
    pub base_fingerprint: String,
    pub head_fingerprint: String,
    pub contract_mutated: bool,
    pub required_bump: SemverImpact,
    pub breaking_count: usize,
    pub minor_count: usize,
    pub symbols_base_count: usize,
    pub symbols_head_count: usize,
    pub findings: Vec<ContractFinding>,
}

/// Compares `base` and `head` public API snapshots and returns the deterministic SemVer impact.
pub fn diff_contracts(base: &ContractSnapshot, head: &ContractSnapshot) -> ContractDiffResult {
    let mut findings = Vec::new();

    // 1. Check every symbol in `base` against `head`
    for (id, base_sym) in &base.symbols {
        match head.symbols.get(id) {
            None => {
                let code = if base_sym.kind == SymbolKind::ReExport {
                    ChangeCode::ReExportRemoved
                } else {
                    ChangeCode::SymbolRemoved
                };
                findings.push(ContractFinding {
                    code,
                    impact: SemverImpact::Major,
                    symbol_id: id.clone(),
                    symbol_name: base_sym.name.clone(),
                    symbol_kind: base_sym.kind.clone(),
                    language: base_sym.language,
                    file: base_sym.file.clone(),
                    line: base_sym.line,
                    before: format_symbol_summary(base_sym),
                    after: "(deleted)".to_string(),
                    reason: format!(
                        "Exported {} `{}` was removed from `{}`",
                        base_sym.kind.as_str(),
                        base_sym.name,
                        base_sym.file
                    ),
                });
            }
            Some(head_sym) => {
                if base_sym.signature_hash != head_sym.signature_hash {
                    diff_single_symbol(base_sym, head_sym, &mut findings);
                }
            }
        }
    }

    // 2. Check for brand-new exported symbols in `head`
    for (id, head_sym) in &head.symbols {
        if !base.symbols.contains_key(id) {
            findings.push(ContractFinding {
                code: ChangeCode::SymbolAdded,
                impact: SemverImpact::Minor,
                symbol_id: id.clone(),
                symbol_name: head_sym.name.clone(),
                symbol_kind: head_sym.kind.clone(),
                language: head_sym.language,
                file: head_sym.file.clone(),
                line: head_sym.line,
                before: "(none)".to_string(),
                after: format_symbol_summary(head_sym),
                reason: format!(
                    "New exported {} `{}` added in `{}`",
                    head_sym.kind.as_str(),
                    head_sym.name,
                    head_sym.file
                ),
            });
        }
    }

    // Sort findings: MAJOR first, then MINOR, then by symbol_id
    findings.sort_by(|a, b| {
        b.impact
            .cmp(&a.impact)
            .then_with(|| a.symbol_id.cmp(&b.symbol_id))
    });

    let breaking_count = findings
        .iter()
        .filter(|f| f.impact == SemverImpact::Major)
        .count();
    let minor_count = findings
        .iter()
        .filter(|f| f.impact == SemverImpact::Minor)
        .count();

    let required_bump = if breaking_count > 0 {
        SemverImpact::Major
    } else if minor_count > 0 {
        SemverImpact::Minor
    } else {
        SemverImpact::Patch
    };

    ContractDiffResult {
        base_fingerprint: base.contract_sha256.clone(),
        head_fingerprint: head.contract_sha256.clone(),
        contract_mutated: base.contract_sha256 != head.contract_sha256,
        required_bump,
        breaking_count,
        minor_count,
        symbols_base_count: base.symbols.len(),
        symbols_head_count: head.symbols.len(),
        findings,
    }
}

fn diff_single_symbol(
    base: &PublicSymbol,
    head: &PublicSymbol,
    findings: &mut Vec<ContractFinding>,
) {
    // 1. Check async modifier change
    if base.is_async != head.is_async {
        findings.push(ContractFinding {
            code: ChangeCode::AsyncModifierChanged,
            impact: SemverImpact::Major,
            symbol_id: head.id.clone(),
            symbol_name: head.name.clone(),
            symbol_kind: head.kind.clone(),
            language: head.language,
            file: head.file.clone(),
            line: head.line,
            before: if base.is_async { "async" } else { "sync" }.to_string(),
            after: if head.is_async { "async" } else { "sync" }.to_string(),
            reason: format!(
                "Function `{}` changed execution model from `{}` to `{}`",
                head.name,
                if base.is_async { "async" } else { "sync" },
                if head.is_async { "async" } else { "sync" }
            ),
        });
    }

    // 2. Check return type mutation
    if base.return_type != head.return_type {
        findings.push(ContractFinding {
            code: ChangeCode::ReturnTypeChanged,
            impact: SemverImpact::Major,
            symbol_id: head.id.clone(),
            symbol_name: head.name.clone(),
            symbol_kind: head.kind.clone(),
            language: head.language,
            file: head.file.clone(),
            line: head.line,
            before: base.return_type.clone(),
            after: head.return_type.clone(),
            reason: format!(
                "Return/value type of `{}` mutated from `{}` to `{}`",
                head.name, base.return_type, head.return_type
            ),
        });
    }

    // 3. Check function parameters positionally
    diff_params(base, head, findings);

    // 4. Check struct/interface/enum fields by name
    diff_fields(base, head, findings);
}

fn diff_params(base: &PublicSymbol, head: &PublicSymbol, findings: &mut Vec<ContractFinding>) {
    let min_len = base.params.len().min(head.params.len());

    for i in 0..min_len {
        let bp: &ParamContract = &base.params[i];
        let hp: &ParamContract = &head.params[i];

        let became_required = bp.optional
            && !hp.optional
            && (bp.ty == hp.ty || bp.ty == format!("Option<{}>", hp.ty));

        if became_required {
            findings.push(ContractFinding {
                code: ChangeCode::ParamBecameRequired,
                impact: SemverImpact::Major,
                symbol_id: head.id.clone(),
                symbol_name: head.name.clone(),
                symbol_kind: head.kind.clone(),
                language: head.language,
                file: head.file.clone(),
                line: head.line,
                before: format!("{}?: {}", bp.name, bp.ty),
                after: format!("{}: {}", hp.name, hp.ty),
                reason: format!(
                    "Optional parameter `{}` in `{}` became required",
                    hp.name, head.name
                ),
            });
        } else if bp.ty != hp.ty {
            findings.push(ContractFinding {
                code: ChangeCode::ParamTypeChanged,
                impact: SemverImpact::Major,
                symbol_id: head.id.clone(),
                symbol_name: head.name.clone(),
                symbol_kind: head.kind.clone(),
                language: head.language,
                file: head.file.clone(),
                line: head.line,
                before: format!("{}: {}", bp.name, bp.ty),
                after: format!("{}: {}", hp.name, hp.ty),
                reason: format!(
                    "Parameter #{idx} (`{name}`) in `{fn_name}` changed type from `{old}` to `{new}`",
                    idx = i + 1,
                    name = hp.name,
                    fn_name = head.name,
                    old = bp.ty,
                    new = hp.ty
                ),
            });
        } else if !bp.optional && hp.optional {
            findings.push(ContractFinding {
                code: ChangeCode::OptionalMemberAdded,
                impact: SemverImpact::Minor,
                symbol_id: head.id.clone(),
                symbol_name: head.name.clone(),
                symbol_kind: head.kind.clone(),
                language: head.language,
                file: head.file.clone(),
                line: head.line,
                before: format!("{}: {}", bp.name, bp.ty),
                after: format!("{}?: {}", hp.name, hp.ty),
                reason: format!(
                    "Required parameter `{}` in `{}` relaxed to optional",
                    hp.name, head.name
                ),
            });
        }
    }

    // Removed parameters
    if base.params.len() > head.params.len() {
        for bp in &base.params[min_len..] {
            findings.push(ContractFinding {
                code: ChangeCode::ParamRemoved,
                impact: SemverImpact::Major,
                symbol_id: head.id.clone(),
                symbol_name: head.name.clone(),
                symbol_kind: head.kind.clone(),
                language: head.language,
                file: head.file.clone(),
                line: head.line,
                before: format!("{}: {}", bp.name, bp.ty),
                after: "(removed)".to_string(),
                reason: format!(
                    "Parameter `{}` was removed from exported function `{}`",
                    bp.name, head.name
                ),
            });
        }
    }

    // Added parameters
    if head.params.len() > base.params.len() {
        for hp in &head.params[min_len..] {
            if hp.optional || hp.variadic {
                findings.push(ContractFinding {
                    code: ChangeCode::OptionalMemberAdded,
                    impact: SemverImpact::Minor,
                    symbol_id: head.id.clone(),
                    symbol_name: head.name.clone(),
                    symbol_kind: head.kind.clone(),
                    language: head.language,
                    file: head.file.clone(),
                    line: head.line,
                    before: "(none)".to_string(),
                    after: format!("{}?: {}", hp.name, hp.ty),
                    reason: format!(
                        "Backward-compatible optional parameter `{}` added to `{}`",
                        hp.name, head.name
                    ),
                });
            } else {
                findings.push(ContractFinding {
                    code: ChangeCode::RequiredParamAdded,
                    impact: SemverImpact::Major,
                    symbol_id: head.id.clone(),
                    symbol_name: head.name.clone(),
                    symbol_kind: head.kind.clone(),
                    language: head.language,
                    file: head.file.clone(),
                    line: head.line,
                    before: "(none)".to_string(),
                    after: format!("{}: {}", hp.name, hp.ty),
                    reason: format!(
                        "New required parameter `{}: {}` added to `{}` (breaks existing callers)",
                        hp.name, hp.ty, head.name
                    ),
                });
            }
        }
    }
}

fn diff_fields(base: &PublicSymbol, head: &PublicSymbol, findings: &mut Vec<ContractFinding>) {
    let base_map: BTreeMap<&str, &FieldContract> =
        base.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let head_map: BTreeMap<&str, &FieldContract> =
        head.fields.iter().map(|f| (f.name.as_str(), f)).collect();

    for (name, bf) in &base_map {
        match head_map.get(name) {
            None => {
                findings.push(ContractFinding {
                    code: ChangeCode::FieldRemoved,
                    impact: SemverImpact::Major,
                    symbol_id: head.id.clone(),
                    symbol_name: head.name.clone(),
                    symbol_kind: head.kind.clone(),
                    language: head.language,
                    file: head.file.clone(),
                    line: head.line,
                    before: format!("{}: {}", bf.name, bf.ty),
                    after: "(removed)".to_string(),
                    reason: format!(
                        "Public field/variant `{}` removed from {} `{}`",
                        bf.name,
                        head.kind.as_str(),
                        head.name
                    ),
                });
            }
            Some(hf) => {
                if bf.ty != hf.ty {
                    findings.push(ContractFinding {
                        code: ChangeCode::FieldTypeChanged,
                        impact: SemverImpact::Major,
                        symbol_id: head.id.clone(),
                        symbol_name: head.name.clone(),
                        symbol_kind: head.kind.clone(),
                        language: head.language,
                        file: head.file.clone(),
                        line: head.line,
                        before: format!("{}: {}", bf.name, bf.ty),
                        after: format!("{}: {}", hf.name, hf.ty),
                        reason: format!(
                            "Field `{}` in `{}` changed type from `{}` to `{}`",
                            hf.name, head.name, bf.ty, hf.ty
                        ),
                    });
                } else if bf.optional && !hf.optional {
                    findings.push(ContractFinding {
                        code: ChangeCode::FieldBecameRequired,
                        impact: SemverImpact::Major,
                        symbol_id: head.id.clone(),
                        symbol_name: head.name.clone(),
                        symbol_kind: head.kind.clone(),
                        language: head.language,
                        file: head.file.clone(),
                        line: head.line,
                        before: format!("{}?: {}", bf.name, bf.ty),
                        after: format!("{}: {}", hf.name, hf.ty),
                        reason: format!(
                            "Optional field `{}` in `{}` became required",
                            hf.name, head.name
                        ),
                    });
                }
            }
        }
    }

    for (name, hf) in &head_map {
        if !base_map.contains_key(name) {
            if hf.optional || head.kind == SymbolKind::Interface {
                findings.push(ContractFinding {
                    code: ChangeCode::OptionalMemberAdded,
                    impact: SemverImpact::Minor,
                    symbol_id: head.id.clone(),
                    symbol_name: head.name.clone(),
                    symbol_kind: head.kind.clone(),
                    language: head.language,
                    file: head.file.clone(),
                    line: head.line,
                    before: "(none)".to_string(),
                    after: format!(
                        "{}{}: {}",
                        hf.name,
                        if hf.optional { "?" } else { "" },
                        hf.ty
                    ),
                    reason: format!(
                        "New member `{}` added to {} `{}`",
                        hf.name,
                        head.kind.as_str(),
                        head.name
                    ),
                });
            } else {
                // Adding a non-optional field to a Rust `pub struct` or variant to exhaustive `pub enum`
                findings.push(ContractFinding {
                    code: ChangeCode::OptionalMemberAdded,
                    impact: SemverImpact::Minor,
                    symbol_id: head.id.clone(),
                    symbol_name: head.name.clone(),
                    symbol_kind: head.kind.clone(),
                    language: head.language,
                    file: head.file.clone(),
                    line: head.line,
                    before: "(none)".to_string(),
                    after: format!("{}: {}", hf.name, hf.ty),
                    reason: format!(
                        "New public member `{}` added to {} `{}`",
                        hf.name,
                        head.kind.as_str(),
                        head.name
                    ),
                });
            }
        }
    }
}

pub fn format_symbol_summary(sym: &PublicSymbol) -> String {
    match sym.kind {
        SymbolKind::Function | SymbolKind::Method => {
            let params = sym
                .params
                .iter()
                .map(|p| {
                    format!(
                        "{}{}{}: {}",
                        if p.variadic { "..." } else { "" },
                        p.name,
                        if p.optional { "?" } else { "" },
                        p.ty
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{}fn {}({}) -> {}",
                if sym.is_async { "async " } else { "" },
                sym.name,
                params,
                sym.return_type
            )
        }
        SymbolKind::Struct | SymbolKind::Interface | SymbolKind::Class | SymbolKind::Enum => {
            format!(
                "{} {} ({{ {} fields }})",
                sym.kind.as_str(),
                sym.name,
                sym.fields.len()
            )
        }
        SymbolKind::ReExport => format!("re-export {} ({})", sym.name, sym.return_type),
        _ => format!("{} {} = {}", sym.kind.as_str(), sym.name, sym.return_type),
    }
}

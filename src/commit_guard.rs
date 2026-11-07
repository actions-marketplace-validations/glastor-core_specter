use crate::differ::SemverImpact;
use serde::{Deserialize, Serialize};

/// Declared SemVer intent parsed from a Conventional Commit message or PR title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitIntent {
    pub raw_message: String,
    pub commit_type: String,
    pub scope: Option<String>,
    pub declares_breaking: bool,
    pub declared_bump: SemverImpact,
}

/// Evaluation of whether the commit message truthfully reflects the AST contract change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitGuardVerdict {
    pub evaluated: bool,
    pub intent: Option<CommitIntent>,
    pub aligned: bool,
    pub trojan_breaking: bool,
    pub undeclared_minor: bool,
    pub summary: String,
}

/// Parses a Conventional Commit string (e.g., `fix(gateway): adjust timeout` or `feat(api)!: v2`).
pub fn parse_conventional_commit(message: &str) -> CommitIntent {
    let trimmed = message.trim();
    let first_line = trimmed.lines().next().unwrap_or("").trim();

    let has_breaking_footer =
        trimmed.contains("BREAKING CHANGE:") || trimmed.contains("BREAKING-CHANGE:");

    if let Some(colon_idx) = first_line.find(':') {
        let prefix = first_line[..colon_idx].trim();
        let bang = prefix.ends_with('!');
        let clean_prefix = prefix.trim_end_matches('!');

        let (commit_type, scope) = if let Some(open_paren) = clean_prefix.find('(') {
            let ctype = clean_prefix[..open_paren].trim().to_lowercase();
            let s = clean_prefix[open_paren + 1..]
                .trim_end_matches(')')
                .trim()
                .to_string();
            (ctype, if s.is_empty() { None } else { Some(s) })
        } else {
            (clean_prefix.to_lowercase(), None)
        };

        let declares_breaking = bang || has_breaking_footer;
        let declared_bump = if declares_breaking {
            SemverImpact::Major
        } else if commit_type == "feat" {
            SemverImpact::Minor
        } else {
            SemverImpact::Patch
        };

        return CommitIntent {
            raw_message: first_line.to_string(),
            commit_type,
            scope,
            declares_breaking,
            declared_bump,
        };
    }

    CommitIntent {
        raw_message: first_line.to_string(),
        commit_type: "untyped".to_string(),
        scope: None,
        declares_breaking: has_breaking_footer,
        declared_bump: if has_breaking_footer {
            SemverImpact::Major
        } else {
            SemverImpact::Patch
        },
    }
}

/// Cross-checks the actual AST `SemverImpact` against the declared `CommitIntent`.
pub fn evaluate_commit_alignment(
    actual_impact: SemverImpact,
    commit_msg: Option<&str>,
    strict_minor: bool,
) -> CommitGuardVerdict {
    let msg = match commit_msg {
        Some(m) if !m.trim().is_empty() => m,
        _ => {
            return CommitGuardVerdict {
                evaluated: false,
                intent: None,
                aligned: true,
                trojan_breaking: false,
                undeclared_minor: false,
                summary: "No commit message provided for Trojan Commit verification".to_string(),
            };
        }
    };

    let intent = parse_conventional_commit(msg);

    // Case 1: Trojan Breaking Change (AST is MAJOR, but commit did NOT declare `!` or `BREAKING CHANGE:`)
    if actual_impact == SemverImpact::Major && !intent.declares_breaking {
        return CommitGuardVerdict {
            evaluated: true,
            aligned: false,
            trojan_breaking: true,
            undeclared_minor: false,
            summary: format!(
                "TROJAN BREAKING CHANGE: Commit `{}` declares `{}` ({}), but mutates public API contract with MAJOR breaking impact!",
                intent.raw_message,
                intent.commit_type,
                intent.declared_bump.as_str().to_uppercase()
            ),
            intent: Some(intent),
        };
    }

    // Case 2: Undeclared Minor Feature (AST added public exports, commit says `fix:` / `chore:`)
    if actual_impact == SemverImpact::Minor && intent.declared_bump == SemverImpact::Patch {
        let aligned = !strict_minor;
        return CommitGuardVerdict {
            evaluated: true,
            aligned,
            trojan_breaking: false,
            undeclared_minor: true,
            summary: format!(
                "Commit `{}` declares `{}` (PATCH), but exports new public API symbols (requires MINOR `feat:` bump)",
                intent.raw_message, intent.commit_type
            ),
            intent: Some(intent),
        };
    }

    CommitGuardVerdict {
        evaluated: true,
        aligned: true,
        trojan_breaking: false,
        undeclared_minor: false,
        summary: format!(
            "Commit `{}` ({}) is mathematically aligned with AST impact ({})",
            intent.raw_message,
            intent.declared_bump.as_str().to_uppercase(),
            actual_impact.as_str().to_uppercase()
        ),
        intent: Some(intent),
    }
}

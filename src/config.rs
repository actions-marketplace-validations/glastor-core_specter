use crate::differ::SemverImpact;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Configurable per-rule severity override in `specter.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Major,
    Minor,
    Patch,
    Off,
}

impl RuleSeverity {
    pub fn to_impact(self) -> Option<SemverImpact> {
        match self {
            RuleSeverity::Major => Some(SemverImpact::Major),
            RuleSeverity::Minor => Some(SemverImpact::Minor),
            RuleSeverity::Patch => Some(SemverImpact::Patch),
            RuleSeverity::Off => None,
        }
    }
}

/// Enterprise configuration loaded from `specter.toml` or `.specter.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpecterConfig {
    /// Explicit public entry points (e.g. `["src/lib.rs"]` or `["src/index.ts"]`).
    /// When empty, Specter auto-discovers `Cargo.toml`/`src/lib.rs`, `package.json`, or `deno.json`.
    #[serde(default)]
    pub entry_points: Vec<String>,

    /// Relative path patterns to ignore (supports `*` and `**`, e.g. `"src/internal/**"`).
    #[serde(default)]
    pub ignore_paths: Vec<String>,

    /// Symbol names or logical IDs to ignore (supports `*`, e.g. `"*_internal"`, `"crate::debug::*"`).
    #[serde(default)]
    pub ignore_symbols: Vec<String>,

    /// Rule IDs to globally ignore (e.g. `["SPC011", "SPC012"]`).
    #[serde(default)]
    pub ignore_rules: Vec<String>,

    /// Fail when a `fix:` / `chore:` commit introduces a MINOR public API addition.
    #[serde(default)]
    pub strict_minor: bool,

    /// Per-rule severity overrides (e.g. `[rule_severity] SPC012 = "patch"` or `"off"`).
    #[serde(default)]
    pub rule_severity: BTreeMap<String, RuleSeverity>,
}

impl SpecterConfig {
    /// Loads `specter.toml` or `.specter.toml` from `root` if present; otherwise returns defaults.
    pub fn load_from_dir(root: &Path) -> Result<Self> {
        for candidate in ["specter.toml", ".specter.toml"] {
            let path = root.join(candidate);
            if path.is_file() {
                return Self::load_from_file(&path);
            }
        }
        Ok(Self::default())
    }

    /// Loads configuration from an explicit TOML file path.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read Specter config {}", path.display()))?;
        Self::parse_toml(&raw)
    }

    /// Parses a TOML configuration string.
    pub fn parse_toml(raw: &str) -> Result<Self> {
        toml::from_str(raw).context("Failed to parse specter.toml configuration")
    }

    pub fn is_path_ignored(&self, rel_path: &str) -> bool {
        let norm = rel_path.replace('\\', "/");
        self.ignore_paths
            .iter()
            .any(|pat| glob_match(pat.trim(), &norm))
    }

    pub fn is_symbol_ignored(&self, symbol_id: &str, symbol_name: &str) -> bool {
        self.ignore_symbols.iter().any(|pat| {
            let p = pat.trim();
            glob_match(p, symbol_id) || glob_match(p, symbol_name)
        })
    }

    pub fn is_rule_ignored(&self, rule_id: &str) -> bool {
        if self
            .ignore_rules
            .iter()
            .any(|r| r.trim().eq_ignore_ascii_case(rule_id))
        {
            return true;
        }
        self.severity_override(rule_id) == Some(RuleSeverity::Off)
    }

    pub fn severity_override(&self, rule_id: &str) -> Option<RuleSeverity> {
        self.rule_severity
            .iter()
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(rule_id))
            .map(|(_, v)| *v)
    }
}

/// Parses inline `// specter-ignore: SPC005 -- reason` pragmas on or immediately preceding
/// a 1-based `line` number in `source`.
///
/// To prevent undocumented bypasses in PRs, a non-empty reason after `--` is required.
pub fn extract_inline_suppressions(source: &str, line_1based: usize) -> Vec<String> {
    if line_1based == 0 {
        return Vec::new();
    }
    let lines: Vec<&str> = source.lines().collect();
    let idx = line_1based.saturating_sub(1);
    if idx >= lines.len() {
        return Vec::new();
    }

    let mut rules = Vec::new();

    // 1. Check trailing comment on the declaration line itself
    if let Some(comment_pos) = lines[idx].find("//") {
        parse_ignore_directive(&lines[idx][comment_pos + 2..], &mut rules);
    }

    // 2. Walk backwards over contiguous comments, attributes, decorators, and blank lines
    let mut k = idx;
    while k > 0 {
        k -= 1;
        let trimmed = lines[k].trim();
        if trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with('@') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("//") {
            parse_ignore_directive(rest, &mut rules);
            continue;
        }
        if trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.ends_with("*/") {
            let cleaned = trimmed
                .trim_start_matches("/*")
                .trim_start_matches('*')
                .trim_end_matches("*/");
            parse_ignore_directive(cleaned, &mut rules);
            continue;
        }
        break;
    }

    rules.sort();
    rules.dedup();
    rules
}

fn parse_ignore_directive(comment_body: &str, out: &mut Vec<String>) {
    let trimmed = comment_body.trim();
    let Some(pos) = trimmed.find("specter-ignore:") else {
        return;
    };
    let rest = trimmed[pos + "specter-ignore:".len()..].trim();

    // Require `-- <non-empty reason>` so suppressions are auditable in PRs
    let Some((rules_part, reason_part)) = rest.split_once("--") else {
        return;
    };
    if reason_part.trim().is_empty() {
        return;
    }

    for tok in rules_part.split([',', ' ']) {
        let rule = tok.trim();
        if rule == "*"
            || (rule.len() == 6
                && rule.starts_with("SPC")
                && rule[3..].chars().all(|c| c.is_ascii_digit()))
        {
            out.push(rule.to_ascii_uppercase());
        }
    }
}

/// Lightweight glob matcher supporting `*` (single segment/wildcard) and `**` (recursive).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p_chars: Vec<char> = pattern.chars().collect();
    let t_chars: Vec<char> = text.chars().collect();
    glob_match_rec(&p_chars, &t_chars)
}

fn glob_match_rec(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    if p.len() >= 2 && p[0] == '*' && p[1] == '*' {
        // `**` matches zero or more characters including `/`
        let rest_p = if p.len() >= 3 && p[2] == '/' {
            &p[3..]
        } else {
            &p[2..]
        };
        if glob_match_rec(rest_p, t) {
            return true;
        }
        if !t.is_empty() {
            return glob_match_rec(p, &t[1..]);
        }
        return false;
    }
    if p[0] == '*' {
        // `*` matches zero or more characters
        if glob_match_rec(&p[1..], t) {
            return true;
        }
        if !t.is_empty() {
            return glob_match_rec(p, &t[1..]);
        }
        return false;
    }
    if !t.is_empty() && (p[0] == '?' || p[0] == t[0]) {
        return glob_match_rec(&p[1..], &t[1..]);
    }
    false
}

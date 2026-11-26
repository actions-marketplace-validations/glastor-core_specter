# GLASTOR® Specter — Engineering Roadmap (0% False-Positive Precision)

> **North Star:** Zero-Compiler Polyglot AST API Contract Differ & Mathematical SemVer Gatekeeper with **0% False Positive Rate (FPR)** on safe refactorings, single static binary distribution, and sub-second CI execution.

---

## Phase 1 — Lexical Hygiene & Precision Rules (`v0.9.0`) — Completed

Eliminated the highest-frequency lexical and normalization false positives while keeping zero-compiler speed:

- [x] **Rust Lifetimes, Raw Strings & Nested Block Comments:** Accurate distinction between Rust lifetimes (`'a`, `'static`, `'_`) and char literals (`'x'`, `'\n'`), masked raw string interiors (`r#"..."#`) preserving exact line numbers, and nested `/* /* */ */` comments.
- [x] **Internal API Exclusions:** Automatic exclusion of `#[doc(hidden)]` (Rust) and JSDoc `@internal` / `@private` (TypeScript/JS) across top-level exports, impl methods, class methods, properties, and struct/interface fields.
- [x] **Rust Struct/Enum Attributes:** Full attribute stripping (`#[serde(...)]`, `#[allow(...)]`, `#[cfg_attr(...)]`) prior to public field and enum variant extraction.
- [x] **TypeScript Class Brace-Depth Tracking:** Strict member-level extraction eliminating phantom methods from nested helpers.
- [x] **Type-Only `const` Contracts:** Compares explicit type annotations (`pub const`, `export const`) instead of literal values, preventing version/constant bumps from triggering false `SPC006` (`MAJOR`).
- [x] **Canonical Type & Signature Normalizer:**
  - Positional parameter names excluded from `signature_hash`.
  - Positional lifetime (`'a` → `'0`) and generic (`T, U` → `T0, T1`) canonicalization.
  - TypeScript union sorting (`string | number` == `number | string`) and array equivalence (`Array<T>` == `T[]`).

---

## Phase 2 — True Zero-Compiler AST Engine (`v0.10.0`) — Completed

Replaced line-oriented scanning with official pure-Rust CST/AST parsers — zero `rustc` or `tsc` invocations, single static binary:

- [x] **Rust 2024 Official AST (`syn 3` + `proc-macro2` span locations):** Exact handling of `pub(crate)` / `pub(super)`, `where` clauses, nested `pub use` trees, `#[cfg(test)]` anywhere in a file, inline `pub mod`, and `#[non_exhaustive]`.
- [x] **TypeScript / JavaScript / Deno AST (`oxc_parser 0.152`):** Sub-millisecond parsing resolving exported arrow functions (`export const fn = async (...) => ...`), function expressions, destructuring, decorators, classes, interfaces, enums, and barrel re-exports.
- [x] **TypeScript Type Variance:**
  - Contravariant parameter widening (`T` → `T | U`) classified as **`MINOR`** (`OptionalMemberAdded`).
  - Covariant return narrowing (`T | U` → `T`) classified as **compatible (`PATCH`)**.
- [x] **Rust `#[non_exhaustive]` SemVer Enforcement:**
  - Adding a field/variant to an exhaustive `pub struct` / `pub enum` → **`MAJOR`**.
  - Adding a field/variant to a `#[non_exhaustive]` `pub struct` / `pub enum` → **`MINOR`**.
  - Adding `#[non_exhaustive]` to a previously exhaustive type → **`MAJOR`**.

---

## Phase 3 — Enterprise Reachability Graph & Configuration (`v0.11.0`) — Completed

Attacked the #1 false positive in monorepos and real-world libraries (internal modules & file moves behind re-exports):

- [x] **Entry-Point Auto-Discovery:**
  - **Rust:** `Cargo.toml` `[lib] path`, Cargo `[workspace]` member `*/src/lib.rs`, and `src/lib.rs`, traversing `pub mod` and resolving `pub use` (even lifting symbols out of private `mod` files).
  - **TypeScript / Deno:** `package.json` (`exports`, `module`, `main`) and `deno.json` / `deno.jsonc` (`exports`), resolving chained barrel re-exports (`export { ... } from` and `export * from`).
- [x] **Logical Symbol IDs:** Symbols are identified by their exported public logical path (`crate::Client::send`, `pkg::Client::send`, `pkg/utils::hash`) instead of physical file paths, making internal file moves 100% immune to false `SPC001`.
- [x] **Enterprise `specter.toml` / `.specter.toml` Configuration:**
  - `entry_points`, `ignore_paths` (glob `*` / `**`), `ignore_symbols`, `ignore_rules`, `strict_minor`, and `[rule_severity]` (`major` | `minor` | `patch` | `off`).
  - CLI `--config <PATH>` and `--strict-minor` flags.
- [x] **Auditable Inline Suppressions:** `// specter-ignore: SPC005 -- <reason>` (mandatory `-- <reason>` to prevent undocumented PR bypasses).

---

## Phase 4 — Golden 0% FPR Corpus & `v1.0.0` Stability — Completed

Measured and locked precision before `v1.0.0`:

- [x] **Golden 0% FPR Regression Gate (`src/golden_fpr_suite.rs`):** **105 real-world safe refactoring cases** across 12 categories (Rust & TypeScript formatting, renames, attributes, `#[doc(hidden)]`, `@internal`, file moves behind `pub use`/barrels, covariance, `specter.toml`, inline suppressions) — enforced on every `cargo test` with **0.00% FPR (105/105 PASS in `0.17s`)**.
- [x] **Shadow Mode Audit on Real Git Histories:** Audited historical checkpoints across `glastor-core` production repositories:
  - **`hyper64`** (SIMD Rust `#![no_std]`, 141 symbols, 14 files): **6/6 checkpoints = `PATCH` (0% FPR)**.
  - **`pii-veil`** (Rust workspace, 227 symbols, 31 files): Verified true-positive breaking detections (`ProxyConfig` exhaustive struct mutation, `handle_client` param type change) and surfaced Cargo `[workspace]` multi-crate reachability support (fixed immediately in `src/reachability.rs`).
  - **`vektor`** (Rust workspace, 135 symbols, 29 files): Verified true-positive exhaustive `VektorConfig` struct field additions.
  - **`specter`** (Self-audit, 64 symbols, 12 files): Verified `PublicSymbol` and `CliArgs` exhaustive struct changes cleanly caught.

---

## Post-1.0 — Polyglot Expansion (`v1.1.0+`)

Extending Specter's zero-compiler AST + reachability + 0% FPR corpus architecture to Go and Python:

### Go (`.go`) — Target `v1.1.0`
- [ ] **Pure-Rust AST Parser:** `tree-sitter-go` (zero `go` toolchain invocation, single static binary).
- [ ] **Exported Surface Rules:** Capitalized identifiers (`func`, `type ... struct`, `type ... interface`, `const`, `var`, receiver methods) while automatically ignoring `internal/` packages per Go's module visibility specification.
- [ ] **Logical Symbol IDs:** Package import path (`<module>/<pkg>::Type::Method`) rather than `.go` filename, so splitting/merging files within the same Go package is 100% immune to false `SPC001`.
- [ ] **0% FPR Golden Corpus:** +30 Go safe refactoring cases (`gofmt`, file splits within a package, `internal/` refactors, param renames, doc comments).

### Python (`.py` / `.pyi`) — Target `v1.2.0`
- [ ] **Pure-Rust AST Parser:** `ruff_python_parser` (pure Rust, sub-millisecond Python 3.13 grammar).
- [ ] **Reachability & Public Surface:** Respect `__all__` in `__init__.py` and modules, exclude `_private` leading-underscore symbols, and resolve type annotations (`def f(x: str | None = None) -> int:`) + `@overload` signatures.
- [ ] **Logical Symbol IDs:** Dotted package export path (`pkg.Client.send`) immune to internal module moves behind `__init__.py` re-exports.
- [ ] **0% FPR Golden Corpus:** +30 Python safe refactoring cases (`ruff format`, `__all__` re-exports, `_internal` refactors, union ordering `int | str` == `str | int`, docstring changes).

### Supply-Chain Attestations — Target `v1.3.0`
- [ ] **in-toto API Contract Attestations:** Export signed `ContractSnapshot` predicates for runtime contract verification with `glastor-core/medusa`.

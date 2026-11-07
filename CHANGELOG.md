# Changelog

All notable changes to **`@glastor-core/specter`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-07

### 🚀 Features
- **Zero-Compiler Polyglot AST Contract Extractor (`src/extractor.rs`)**: Sub-millisecond extraction of exported public API contracts across **Rust** (`pub fn`, `pub struct`, `pub enum`, `pub trait`, `pub type`, `pub const`) and **TypeScript/Deno** (`export function`, `export interface`, `export class`, `export enum`, `export type`, `export const`) with deterministic `SHA-256` Contract Fingerprinting.
- **Mathematical SemVer Contract Differ (`src/differ.rs`)**: Evaluates 12 structural contract rules (`SPC001`–`SPC012`) to classify changes into `MAJOR` (breaking), `MINOR` (backward-compatible feature), or `PATCH` (internal implementation refactor).
- **Trojan Commit & SemVer Guard (`src/commit_guard.rs`)**: Cross-verifies Conventional Commit messages (`fix:`, `feat:`, `feat!:`, `BREAKING CHANGE:`) against actual AST surface impact to block undeclared breaking changes.
- **Enterprise DevSecOps Telemetry (`src/report.rs`)**: Emits 14 `$GITHUB_OUTPUT` variables, rich `$GITHUB_STEP_SUMMARY` with Mermaid flowcharts, PR Sticky Comments (`<!-- glastor-specter-sticky-comment -->`), **SARIF 2.1.0** for GitHub Code Scanning, and **CycloneDX 1.5 JSON SBOM**.


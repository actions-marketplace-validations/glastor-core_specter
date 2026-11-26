# Changelog

<p align="center">
  <img src="https://img.shields.io/badge/Format-Keep%20a%20Changelog-blue.svg" alt="Keep a Changelog">
  <img src="https://img.shields.io/badge/Versioning-SemVer%202.0.0-green.svg" alt="Semantic Versioning">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License MIT">
</p>

---

## Acerca de este Changelog

Todos los cambios notables en **Specter (Zero-Compiler Polyglot AST API Contract
Differ, Trojan Breaking-Change Detector & Mathematical SemVer Gatekeeper)** son
documentados en este archivo.

Este proyecto se adhiere a:

- **Formato:** [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
- **Versionado:** [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

### Categorías de Cambios

- **Added** ✨ - Nuevas características o funcionalidades
- **Changed** 🔄 - Cambios en funcionalidades existentes
- **Fixed** 🐛 - Correcciones de errores
- **Security** 🔒 - Mejoras de seguridad y protección AppSec / Supply-Chain

---

## [Unreleased]

### 💡 Planned

- Soporte extendido de extracción de contratos públicos para Go (`.go` vía `tree-sitter-go`) y Python
  (`.py`/`.pyi` vía `ruff_python_parser`) con grafo de alcance y corpus Golden 0% FPR.
- Exportación de atestaciones in-toto de contratos de API para verificación en
  runtime con `glastor-core/medusa`.

---

## [1.0.0] - 2026-11-25

**Nombre del Release:** "Zero-Compiler Real AST (`syn` + `oxc_parser`), Enterprise Reachability Graph & 0% FPR Gate"

### ✨ Added
- **Migración a AST Real *Zero-Compiler* (`src/rust_ast.rs`, `src/ts_ast.rs`):**
  - **Rust 2024 (`syn 3` + `proc-macro2`):** Parsing oficial de gramática Rust sin invocar `rustc`, soportando `pub(crate)`, `pub(super)`, cláusulas `where`, `pub use` anidados, módulos `#[cfg(test)]` en cualquier posición, `#[doc(hidden)]`, atributos en campos (`#[serde(...)]`) y `#[non_exhaustive]`.
  - **TypeScript / JS / Deno (`oxc_parser 0.152`):** Parsing sub-milisegundo en Rust resolviendo *arrow functions* exportadas, expresiones de función, destructuring, decoradores, clases con profundidad AST real, JSDoc `@internal`/`@private` y *barrel re-exports*.
- **Grafo de Alcance (Reachability) e Identidad Lógica (`src/reachability.rs`):**
  - Auto-descubrimiento de entry points en Rust (`Cargo.toml` `[lib]`, Cargo `[workspace]` `*/src/lib.rs`, `src/lib.rs`) y TypeScript/Deno (`package.json` `exports`/`module`/`main`, `deno.json` `exports`).
  - **Logical Symbol IDs** (`crate::Client::send`, `pkg::Client::send`): mover archivos internos detrás de `pub use` o *barrels* es 100% inmune a falsos `SPC001`, y los módulos privados no re-exportados se ignoran automáticamente.
- **Configuración Enterprise (`specter.toml` / `.specter.toml`) y Supresiones Inline (`src/config.rs`):**
  - Soporte para `entry_points`, `ignore_paths`, `ignore_symbols`, `ignore_rules`, `strict_minor` y `[rule_severity]` configurable por regla (`major` | `minor` | `patch` | `off`).
  - Nuevas banderas CLI `--config <PATH>` y `--strict-minor`.
  - Supresiones inline auditables `// specter-ignore: SPC005 -- motivo` (con motivo obligatorio tras `--`).
- **Varianza Semántica en TypeScript y `#[non_exhaustive]` en Rust (`src/differ.rs`):**
  - Contravarianza en parámetros TS (`T` -> `T | U` clasificado como `MINOR`).
  - Covarianza en retornos TS (`T | U` -> `T` clasificado como compatible `PATCH`).
  - Normalización canónica de tipos (ignora nombres de parámetros posicionales, normaliza lifetimes `'0`/`'1`, genéricos `T0`/`T1`, uniones ordenadas `A | B == B | A` y `Array<T> == T[]`; `const` evaluado por tipo y no por valor).
  - Detección de `#[non_exhaustive]` en `pub struct`/`pub enum` de Rust (`MINOR` si es `#[non_exhaustive]`, `MAJOR` si es exhaustivo).
- **Suite Golden de Regresión — 0% FPR Gate (`src/golden_fpr_suite.rs`):**
  - 105 casos reales de refactorizaciones seguras en 12 categorías validados en cada `cargo test` con **0.00% de falsos positivos** (`40/40` tests en `0.17s`).
- **Roadmap Oficial ([ROADMAP.md](ROADMAP.md)):** Plan completo documentado con métricas de auditoría en *Shadow Mode* sobre `hyper64`, `pii-veil`, `vektor` y `specter`.

### 🔄 Changed
- **BREAKING CHANGE (`PublicSymbol` & `CliArgs`):** Se añadieron los campos públicos `is_non_exhaustive` y `suppressions` en `PublicSymbol`, y `config` en `CliArgs`.

---

## [0.2.1] - 2026-11-14

### ✨ Added
- **Anotaciones Nativas en GitHub Actions PRs (`::error`, `::notice`)**:
  - Emisión de comandos de flujo de trabajo de GitHub para pintar advertencias y errores inline directamente sobre las líneas de código afectadas en los Pull Requests.
- **Modo CLI Interactivo con Colores ANSI**:
  - Nuevo formateador terminal para la CLI con banderas `--format <auto|text|markdown|json>` y `--color <auto|always|never>`.
  - Muestra un diff visual estilizado con status, conteo de mutaciones y antes/después de firmas públicas.
- **Enriquecimiento de SARIF 2.1.0 para GitHub Security (Code Scanning)**:
  - Atributos `defaultConfiguration.level` en las 13 reglas (SPC001 a SPC013) para categorización y triaje nativo en la pestaña Security.

---

## [0.1.0] - 2026-11-07

**Nombre del Release:** "Initial Polyglot AST API Contract Differ, Trojan Commit
Guard & Mathematical SemVer Engine"\
**Tipo de Release:** Initial Public Release (`main`)

### ✨ Added

#### Extracción Políglota de Superficie Pública sin Compilador (`src/extractor.rs`)

- **Extractor de Contratos en Rust (`.rs`):** Detección en `< 5 ms` de `pub fn`,
  `pub async fn`, `pub const fn`, métodos públicos dentro de bloques `impl`,
  `pub struct` (y sus campos `pub`), `pub enum` (y variantes), `pub trait`,
  `pub type`, `pub const` y re-exportaciones `pub use`, ignorando
  automáticamente elementos privados, `pub(crate)` y módulos `#[cfg(test)]`.
- **Extractor de Contratos en TypeScript / Deno (`.ts`, `.tsx`, `.mts`, `.js`):**
  Detección de `export function`, `export async function`, métodos públicos de
  `export class`, `export interface`, `export enum`, `export type`,
  `export const` y _barrel re-exports_ (`export { ... } from`, `export * from`),
  rastreando parámetros opcionales (`?`), valores por defecto (`= ...`) y
  parámetros _rest_ (`...args`).
- **Extractor Git en Memoria Cero-Disco (`src/main.rs`):** Resolución de
  contratos base directamente desde referencias de Git (`--base-ref`) mediante
  `git ls-tree` y `git show` sin crear árboles de trabajo temporales en disco.
- **Huella Criptográfica Canónica (`Contract SHA-256`):** Cálculo determinista de
  hashes `SHA-256` por símbolo y para el snapshot completo del repositorio,
  inmune a cambios de formato (`cargo fmt` / `deno fmt`) o refactorizaciones
  internas de cuerpos de funciones.

#### Motor Diferencial SemVer (`SPC001`–`SPC013`) & Guardián de Commits Troyanos

- **13 Reglas Matemáticas de Contrato SemVer (`src/differ.rs`):** Clasificación
  determinista de mutaciones `MAJOR` (`SPC001` a `SPC010`, `SPC013`), adiciones
  retrocompatibles `MINOR` (`SPC011`, `SPC012`) y cambios internos `PATCH`.
- **Trojan Breaking-Change Guard (`src/commit_guard.rs`):** Verificación cruzada
  entre el encabezado/footer del _Conventional Commit_ (`!`, `BREAKING CHANGE:`)
  y el impacto real del AST, bloqueando cambios `MAJOR` disfrazados de `fix:`,
  `feat:` o `chore:`.

#### Telemetría DevSecOps: SARIF 2.1.0, CycloneDX 1.5 SBOM & GitHub Actions (`src/report.rs`)

- ** Integración Nativa con GitHub Actions (`action.yml`):** Fast-Path FinOps de
  `0s` con descarga de binarios precompilados multi-plataforma, exportación de
  14 variables en `$GITHUB_OUTPUT`, resumen enriquecido con diagramas Mermaid en
  `$GITHUB_STEP_SUMMARY` y comentarios _sticky_ idempotentes en Pull Requests
  con guía de migración automática.
- **Reportes SARIF 2.1.0 y CycloneDX 1.5 SBOM:** Generación de anotaciones para
  GitHub Security (Code Scanning) y lista de materiales de software (SBOM) de
  símbolos públicos exportados con sus firmas `SHA-256`.

### 🔒 Security

- **Hardening de Workflows y Supply Chain (`.github/workflows/audit.yml`,
  `release.yml`):** Permisos mínimos por job (`permissions: {}` global),
  compilación estática en Rust 2024 (`LTO + stripped + panic=abort`), sumas de
  verificación `SHA256SUMS.txt` y atestación criptográfica **SLSA Build
  Provenance** vía Sigstore OIDC (`actions/attest-build-provenance@v2`).
- **Licencia:** Adopción formal de la Licencia MIT.

---

## Enlaces & Recursos

- 📖 [README.md](README.md) - Documentación General y Reglas de Contrato (`SPC001`–`SPC013`)
- 🏛 [CONTRIBUTORS.md](CONTRIBUTORS.md) - Gobernanza y Sostenibilidad Técnica
- 🛡 [SECURITY.md](.github/SECURITY.md) - Política de Seguridad y Arquitectura AppSec Zero-Trust
- 📜 [LICENSE](LICENSE) - Términos de Licencia MIT
- 🏷 [CITATION.cff](CITATION.cff) - Referencia Académica y Metadatos de Software

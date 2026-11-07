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

- Soporte extendido de extracción de contratos públicos para Go (`.go`) y Python
  (`.py`).
- Exportación de atestaciones in-toto de contratos de API para verificación en
  runtime con `glastor-core/medusa`.

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
- 🏛️ [CONTRIBUTORS.md](CONTRIBUTORS.md) - Gobernanza y Sostenibilidad Técnica
- 🛡️ [SECURITY.md](.github/SECURITY.md) - Política de Seguridad y Arquitectura AppSec Zero-Trust
- 📜 [LICENSE](LICENSE) - Términos de Licencia MIT
- 🏷️ [CITATION.cff](CITATION.cff) - Referencia Académica y Metadatos de Software

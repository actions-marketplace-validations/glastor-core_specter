# 🌌 Ingeniería y Estándares de Contribución

Gracias por sumarte a la misión de construir y evolucionar **Specter**
(`glastor-core/specter`) dentro del ecosistema de
`**GLASTOR-DEV** (división de desarrollo de GLASTOR®)`. Specter es un motor
diferencial de contratos de API pública mediante AST políglota sin compilador,
detector de _Trojan Breaking Changes_ y gatekeeper matemático de SemVer en Rust
(Edition 2024) para GitHub Actions y CLI.

Valoramos la excelencia técnica, el rigor en seguridad Zero-Trust y el
compromiso con la calidad del software. Esta guía establece las directrices
operativas y de ingeniería para colaborar con máxima eficiencia (DX).

---

## 🛠 Gestión Estratégica de Incidencias

### 🐛 Reportes de Errores (Fidelidad Técnica)

Cada _issue_ debe actuar como un documento técnico verificable:

- **Executive Summary:** Resumen conciso del impacto y el alcance.
- **Protocolo de Reproducción:** Código fuente mínimo (Rust o TypeScript) y
  flags de CLI exactos para replicar el problema.
- **Análisis de Desviación:** Contraste claro entre la regla o huella obtenida y
  la esperada (`SPC001`–`SPC013`).
- **Entorno de Ejecución:**
  - Versión de Specter (`specter --version`) y Rust (`rustc --version`)
  - Sistema Operativo (Linux, macOS, Windows)
  - Modo de ejecución: CLI local o GitHub Action (`action.yml`)
- **Evidencia Técnica:** Logs de consola, trazas de error o reporte
  `specter-report.json`.

### 💡 Propuesta de Nuevos Extractores AST o Reglas de Contrato SemVer

Para proponer mejoras en el extractor políglota, en el motor diferencial o en la
telemetría DevSecOps:

1. **Definición del Escenario:** Qué lenguaje, construcción sintáctica o mutación
   de contrato público se aborda.
2. **Estrategia Técnica:** Análisis léxico/AST determinista (`< 5 ms`), sin
   invocar compiladores pesados (`rustc`/`tsc`) y preservando números de línea
   exactos para SARIF 2.1.0.
3. **Impacto en Reglas SemVer:** Clasificación matemática clara (`MAJOR`,
   `MINOR`, `PATCH`) y su código de regla correspondiente (`SPCxxx`).
4. **Cobertura de Tests:** Casos de prueba unitarios y end-to-end en
   `src/main.rs`.

---

## 💻 Setup del Entorno de Desarrollo

### Requisitos Previos

- **Rust Toolchain:** Estable con soporte para **Rust Edition 2024** (`rustup`,
  `cargo`, `rustfmt`, `clippy`).
- **Git:** 2.30+.

### 1. Clonación del Repositorio

```bash
git clone https://github.com/glastor-core/specter.git
cd specter
```

### 2. Comandos y Tareas de Verificación

Specter utiliza `cargo` como gestor estándar de compilación y pruebas:

```bash
# Verificación de formato de código con rustfmt
cargo fmt --all -- --check

# Análisis estático estricto con Clippy (cero warnings permitidos)
cargo clippy --all-targets -- -D warnings

# Ejecutar suite completa de pruebas automatizadas (Unitarias + E2E)
cargo test --verbose

# Compilar binario nativo optimizado de producción (LTO + stripped)
cargo build --release --locked

# Ejecutar auto-auditoría de contrato API sobre el propio repositorio (dogfooding)
cargo run --release -- \
  --head-dir . \
  --output-json .specter/audit.json \
  --output-sarif .specter/specter.sarif \
  --output-sbom .specter/specter.cdx.json
```

---

## 🚀 Flujo de Integración y Pull Requests

Para preservar la estabilidad de la rama principal (`main`), seguimos un flujo
riguroso:

### 1. Rama de Trabajo

Crea una rama descriptiva partiendo de `main` (incluyendo opcionalmente el ID
del ticket para trazabilidad):

```bash
git checkout -b feat/GLS-501-go-contract-extractor
# o: git checkout -b fix/ts-readonly-tuple-normalization
```

### 2. Estándares de Código

- **Rust Seguro & Dependencias Mínimas:** Uso de Rust Edition 2024 idiomático,
  sin bloques `unsafe`, manteniendo el árbol de dependencias ligero y auditable.
- **Arquitectura Modular (`src/`):**
  - `src/main.rs`: Punto de entrada CLI (`clap`), orquestador de snapshots,
    extractor de referencias Git en memoria (`git ls-tree` / `git show`) y suite
    de pruebas de integración.
  - `src/extractor.rs`: Extractor políglota sin compilador para Rust y
    TypeScript/Deno, limpiador de comentarios con preservación de líneas y
    generador de huellas criptográficas `SHA-256`.
  - `src/differ.rs`: Motor diferencial matemático de contratos públicos y
    evaluador de las reglas `SPC001`–`SPC013` (`MAJOR`, `MINOR`, `PATCH`).
  - `src/commit_guard.rs`: Parser de _Conventional Commits_ y detector de
    _Trojan Breaking Changes_.
  - `src/report.rs`: Renderizador de reportes Markdown con diagramas Mermaid,
    guías de migración automáticas, exportador a `$GITHUB_OUTPUT` /
    `$GITHUB_STEP_SUMMARY`, **SARIF 2.1.0** y **CycloneDX 1.5 SBOM**.
- **Verificación Local Obligatoria:** Asegúrate de que pasen sin errores:
  ```bash
  cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --verbose
  ```

### 3. Protocolo de Commits (Conventional Commits & Trojan Guard)

Implementamos la especificación de
[Conventional Commits](./COMMIT_CONVENTION.md), validada activamente por el
propio motor `src/commit_guard.rs` de Specter:

```bash
git commit -m "feat(extractor): support pub trait associated types in Rust"
git commit -m "feat(differ)!: tighten SPC005 parameter variance check"
```

> ⚠️ **Importante:** Si tu cambio modifica la firma de un símbolo público
> exportado en `src/` con impacto `MAJOR`, debes declararlo con `!` (ej.
> `feat(api)!: ...`) o incluir `BREAKING CHANGE:` en el footer del commit; de lo
> contrario, la auto-auditoría de Specter en CI bloqueará el PR como un _Trojan
> Breaking Change_.

### 4. Publicación y PR

Envía tu rama al repositorio remoto y abre un Pull Request hacia la rama `main`:

```bash
git push origin feat/GLS-501-go-contract-extractor
```

Completa el formulario generado por el
[PULL_REQUEST_TEMPLATE.md](./PULL_REQUEST_TEMPLATE.md) asegurando que todos los
puntos del checklist estén marcados.

---

## 📧 Canales de Comunicación y Soporte

- **GitHub Discussions:**
  [glastor-core/specter/discussions](https://github.com/glastor-core/specter/discussions)
  (consultas de arquitectura y propuestas).
- **GitHub Issues:**
  [glastor-core/specter/issues](https://github.com/glastor-core/specter/issues)
  (bugs y tareas).
- **Sitio Web Oficial:** [https://glastor.es](https://glastor.es)
- **Soporte Corporativo:** [ventas@glastor.es](mailto:ventas@glastor.es)
- **Comunicación Directa (Telegram):** [@zerhocool](https://t.me/zerhocool)

---

## Código de Conducta

Este proyecto se rige bajo nuestro [Código de Conducta](./CODE_OF_CONDUCT.md).
Fomentamos un entorno de respeto mutuo, inclusión y rigor profesional.

© 2010-2026 Andrés Antonio Cardoso — [GLASTOR®](https://glastor.es) — Todos los
derechos reservados

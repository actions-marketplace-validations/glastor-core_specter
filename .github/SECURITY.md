# 🛡️ Política de Seguridad y Arquitectura AppSec Zero-Trust (Security Policy)

En el proyecto **Specter** (`glastor-core/specter`), desarrollado por
`**GLASTOR-DEV** (división de desarrollo de GLASTOR®)`, la seguridad del
software, la inmunidad de la cadena de suministro y la protección de los
contratos de API en pipelines CI/CD son prioridades fundamentales.

---

## 📦 Versiones Soportadas

Mantenemos actualizaciones de seguridad activas para las versiones estables de
Specter en la rama `main`:

| Versión | Estado de Soporte  | Tipo de Soporte                       |
| :------ | :----------------- | :------------------------------------ |
| `0.1.x` | :white_check_mark: | Soporte activo y parches de seguridad |
| `< 0.1` | :x: No soportada   | Pre-lanzamiento / Fin de ciclo (EOL)  |

---

## 🔒 Controles AppSec y Supply-Chain Integrados

**Specter** implementa una postura **Zero-Trust** alineada con OWASP CI/CD Top
10, OpenSSF Scorecard y SLSA Build Provenance:

1. **Seguridad de Memoria en Rust (Edition 2024):** Implementado 100% en Rust
   seguro sin bloques `unsafe`, con dependencias mínimas auditadas (`anyhow`,
   `clap`, `serde`, `serde_json`, `sha2`) y perfil de compilación endurecido
   (`opt-level = 3`, `lto = "thin"`, `strip = "symbols"`, `panic = "abort"`).
2. **Inmunidad contra _Trojan Breaking Changes_ (`src/commit_guard.rs`):**
   Previene ataques o errores en la cadena de suministro donde mutaciones
   incompatibles de API (`MAJOR`: `SPC001`–`SPC010`, `SPC013`) intentan
   infiltrarse en lanzamientos `PATCH` o `MINOR` bajo commits `fix:` o `chore:`.
3. **Extracción Git en Memoria Cero-Disco (`src/main.rs`):** Al inspeccionar
   referencias base (`--base-ref`), `specter` consulta la base de objetos de Git
   mediante `Command::new("git")` con argumentos separados (sin invocación de
   shell `sh -c`), previniendo inyección de comandos y evitando escribir código
   histórico en directorios temporales.
4. **Integridad Criptográfica y Atestación SLSA (`SHA-256` & CycloneDX 1.5):**
   Cada símbolo exportado y cada snapshot de contrato se sella con `SHA-256`,
   emitiendo SBOMs en formato **CycloneDX 1.5** y binarios de release firmados
   con **SLSA Build Provenance** (`actions/attest-build-provenance@v2`).
5. **Hardening de Workflows de GitHub Actions (`.github/workflows/`):**
   Permisos globales vacíos por defecto (`permissions: {}`) e inyección segura de
   inputs y títulos de PR exclusivamente mediante variables de entorno (`env:`),
   mitigando inyecciones de script en bloques `run:`.

---

## 🚨 Reporte Responsable de Vulnerabilidades

Si descubres una vulnerabilidad de seguridad o un fallo que comprometa la
integridad de **Specter** o los pipelines que protege, te solicitamos **no abrir
un issue público**. En su lugar, activa nuestro protocolo de divulgación
coordinada:

### Opción 1: GitHub Private Vulnerability Reporting (Recomendado)

Accede directamente a la herramienta oficial de GitHub: 👉
[Reportar vulnerabilidad privada en Specter](https://github.com/glastor-core/specter/security/advisories/new)

### Opción 2: Correo Electrónico Corporativo Seguro

Envía los detalles técnicos a nuestro canal oficial de seguridad: 📧
**[ventas@glastor.es](mailto:ventas@glastor.es)**

### Información a Incluir en el Reporte

Para acelerar el triaje y la mitigación, incluye:

- Descripción clara del fallo o vector de ataque (ej. evasión del detector de
  contratos AST, bypass del _Trojan Commit Guard_, inyección en GitHub Actions).
- Pasos mínimos de reproducción o prueba de concepto (PoC).
- Impacto potencial en entornos de CI/CD o consumidores downstream.
- Código sugerido de mitigación o parche (si está disponible).

---

## ⏱️ SLA y Compromiso de Respuesta

- **Acuse de recibo:** Menos de 24 horas laborales.
- **Evaluación y confirmación:** Menos de 72 horas hábiles.
- **Publicación del parche y Advisory:** Divulgación coordinada una vez que la
  versión con la solución esté disponible en la rama `main` y en GitHub
  Releases / Marketplace.

Agradecemos profundamente el compromiso de la comunidad y los investigadores de
seguridad que colaboran en hacer de **Specter** un estándar seguro para todos.

---

© 2010-2026 Andrés Antonio Cardoso — [GLASTOR®](https://glastor.es) — Todos los
derechos reservados

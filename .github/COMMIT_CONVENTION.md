# 🏛️ Arquitectura de Mensajes de Commit (Conventional Commits)

Para escalar el desarrollo de **Specter** (`glastor-core/specter`) y garantizar
una **Software Supply Chain** transparente, este repositorio implementa una
convención estricta basada en la especificación de
[Conventional Commits v1.0.0](https://www.conventionalcommits.org/). En Specter,
esta práctica no es solo estética: el módulo `src/commit_guard.rs` audita
matemáticamente que cada mensaje de commit o título de Pull Request coincida con
el impacto real sobre el AST de la API pública (`MAJOR`, `MINOR`, `PATCH`).

## ⚙️ Especificación Técnica y Validación

Todo aporte debe superar el esquema de validación para integrarse en el flujo de
CI/CD y auto-versionado (`release.yml`) de la rama `main`:

```js
/^(revert: )?(feat|fix|polish|docs|style|refactor|perf|test|workflow|ci|chore|types|sec|security|build)(\([\w.-]+\))?!?: .{1,72}$/;
```

### Parámetros de Calidad (Linting & Trojan Commit Guard):

- **Scope (Opcional):** Define el módulo de Specter afectado entre paréntesis
  (ej. `extractor`, `differ`, `commit_guard`, `report`, `cli`, `action`).
- **Indicador de Ruptura (`!`):** Si el commit altera de forma incompatible un
  símbolo público exportado (`SPC001`–`SPC010`, `SPC013`), es **obligatorio**
  incluir `!` antes de `:` (ej. `feat(differ)!: ...`) o declarar
  `BREAKING CHANGE:` en el footer.
- **Sujeto:** Conciso y descriptivo en modo imperativo.

---

## 🏗️ Estructura del Mensaje

Adoptamos un formato de tres bloques para maximizar la legibilidad y la
compatibilidad con el motor de gobernanza SemVer:

```text
<tipo>(<scope>)[!]: <asunto>

<body>

<footer>
```

### 1. Header (Obligatorio)

| Tipo                | Impacto SemVer Declarado | ¿Aparece en Changelog? |
| :------------------ | :----------------------- | :--------------------: |
| `<tipo>!`           | 🔴 `MAJOR` (Breaking)    |         **Sí**         |
| `feat`              | 🟡 `MINOR` (Feature)     |         **Sí**         |
| `fix`               | 🟢 `PATCH` (Compatible)  |         **Sí**         |
| `perf`              | 🟢 `PATCH` (Compatible)  |         **Sí**         |
| `sec` / `security`  | 🟢 `PATCH` (Compatible)  |         **Sí**         |
| `refactor`          | 🟢 `PATCH` (Compatible)  |         **Sí**         |
| `build`             | 🟢 `PATCH` (Compatible)  |           No           |
| `docs`              | `PATCH` / Sin release    |           No           |
| `test`              | `PATCH` / Sin release    |           No           |
| `ci` / `workflow`   | `PATCH` / Sin release    |           No           |
| `chore`             | `PATCH` / Sin release    |           No           |
| `style`             | Formateo (`cargo fmt`)   |           No           |

> 🛡️ **Verificación _Trojan Breaking-Change_ (`src/commit_guard.rs`):**
> - Si el diferenciador AST detecta una mutación `MAJOR` pero el commit declara
>   `fix:`, `feat:` o `chore:` sin `!` ni `BREAKING CHANGE:`, Specter bloqueará
>   el pipeline acusando un **Trojan Breaking Change**.
> - Con `--strict-semver` activo, si se exportan nuevos símbolos públicos
>   (`SPC011` / `SPC012` → `MINOR`) bajo un commit `fix:` o `chore:` (`PATCH`),
>   Specter también señalará la discrepancia.

### 2. Body (Opcional)

Describe la motivación técnica del cambio. Contrasta la solución actual con el
comportamiento previo para facilitar la revisión de pares (Code Review).

### 3. Footer (Opcional)

Espacio crítico para metadatos de gobernanza y declaración de rupturas de
contrato:

- **Referencias:** Vincula tickets de Jira, Linear o GitHub Issues mediante
  claves: `Closes #12`, `Resolves GLS-501`.
- **Breaking Changes:** Debe iniciar con `BREAKING CHANGE:` o `BREAKING-CHANGE:`
  seguido del detalle de los símbolos afectados (Specter genera automáticamente
  una plantilla lista para copiar en el resumen del PR cuando detecta cambios
  `MAJOR`).

---

## 🔄 Reversiones (Reverts)

En caso de rollback, el mensaje debe iniciar con `revert:`, seguido del header
original. Es imperativo incluir el hash del commit afectado en el cuerpo:
`This reverts commit <hash>`.

## ✍️ Firmas y Trazabilidad (DCO)

Se fomenta el uso de trailers estándar de Git como `Co-authored-by:` para dar
crédito a colaboraciones múltiples. La firma `Signed-off-by:` garantiza el
cumplimiento con el Developer Certificate of Origin si el flujo de trabajo lo
requiere.

© 2010-2026 Andrés Antonio Cardoso — [GLASTOR®](https://glastor.es) — Todos los
derechos reservados

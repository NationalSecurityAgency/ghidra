<!-- Copyright 2026 Opcodex contributors. SPDX-License-Identifier: Apache-2.0 -->

# Opcodex v1 audit checks

2026-10-20, Asia/Calcutta. These results validate the static audit data, not the application.

Command:

```powershell
python C:\Users\pc\AppData\Local\Temp\opcodex-ui-audit-check.py
```

Result: **PASS**, exit 0.

- All 882 discovered theme icon IDs have inventory rows.
- All 592 runtime image candidate paths appear in the inventory.
- All 1,379 asset paths are unique and exist in the checkout.
- Module/format/size aggregation sums to 592 files across 97 groups.
- Theme definitions, icon references, loader calls, generated-icon sites, scale requests and color candidates point to existing source files and valid line numbers.
- Local report links resolve. CHECKS.md was created after that first link check and is included in the final document check.
- Supplemental scans record 29 ResourceManager loader calls, 143 programmatic icon sites and 28 color factory sites.

The icon reference inventory identifies 13 direct calls with complete raw raster-resource literals. The broader loader-call scan includes 14 calls beginning with a literal (potentially with concatenation) and 15 beginning with computed/variable arguments. Its `literal call` label means literal-leading syntax, not proof of a constant final argument.

Primary extraction was executed twice (directly and by the supplemental extraction); primary counts agreed. The temporary scripts remain local working tools; they are not application source or runtime dependencies.

`java -version` passed: Oracle JDK 25.0.2. `.\gradlew.bat --version` passed: Gradle 9.8.0, JVM 25.0.2, Windows 11 amd64. The wrapper download changed the Gradle cache, not upstream source.

No build, desktop launch, application test suite, visual/icon/contrast/accessibility test, platform scaling test or runtime replacement-coverage check was run. There are no replacement assets yet. Review those limitations in [AUDIT.md](AUDIT.md) before treating any later v1 implementation as verified.

Final checks:

```powershell
python C:\Users\pc\AppData\Local\Temp\opcodex-ui-audit-doc-check.py
git diff --cached --check
git diff --cached --stat
git diff --name-only
git status --short
```

Passed: report links/fences, CSV column counts and JSON totals; no staged whitespace errors; staged scope consists only of 13 new files under `docs/ui/`; no unstaged tracked-source changes. Existing application code, resources, LICENSE, NOTICE and upstream headers are unchanged.

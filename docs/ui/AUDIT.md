<!-- Copyright 2026 Opcodex contributors. SPDX-License-Identifier: Apache-2.0 -->

# Opcodex v1 desktop UI audit

Date: 2026-10-20 (Asia/Calcutta). Status: **static audit complete; awaiting owner review before design or implementation**.

## Release scope and baseline

The owner confirmed this work is the first desktop release, **Opcodex v1**. The supplied desktop brief defines the sequence: audit, approved design system, toolbar/tree pilot for review, remaining icons, light/dark themes, then UX improvements. This report does not authorize the later stages. Opcodex's product version must remain separate from the upstream engine/API version; a specific semantic version/tag has not been selected.

Project context was read from the Obsidian notes `Opcodex/AGENT_CONTEXT.md`, `SESSION_LOG.md`, `VERSION_CONTROL.md`, `README.md`, and `ARCHITECTURE.md`. The owner reports the landing page is finished and deployed at opcodex.xyz; this audit does not test that deployment. Community is the desktop core; Pro extends Community, never the reverse. No analysis, decompiler implementation, loader, processor, database, or website files were modified.

Audited checkout: `D:\opcodex`, upstream-derived commit `f70f07d07ca6284c1f26557ad19071885ed8590b`; work began on clean `master` and audit documents are on `codex/ui-audit`.

**Baseline discrepancy:** [application.properties](../../Ghidra/application.properties) identifies **Ghidra 12.3 DEV**, compiler/minimum JDK **25**, minimum Gradle **9.1**. The [wrapper](../../Ghidra/RuntimeScripts/support/gradle/gradle-wrapper.properties) selects **9.8.0**. Earlier Obsidian planning targets `Ghidra_12.1.4_build`; that is not this checkout. All counts and source findings below describe this exact development commit. Before implementing v1, resolve the release baseline and repeat the inventory if it changes. No branch reset or upstream version change was made. Opcodex v1 does not mean Ghidra version 1.

## Summary

| Measurement | Result |
|---|---:|
| Tracked files examined for the inventory scope | 20,621 |
| Image files across source, runtime, help, tests and documentation | 1,379 |
| Runtime image candidates | 592 |
| SVG/artwork source files, separately classified | 90 |
| Module theme property files | 34 |
| Unique theme property keys, all types | 1,660 |
| Unique icon theme IDs | 882 |
| Icon definitions including section overrides | 889 |
| Icon inventory rows, including aliases/dependencies/unmapped assets | 987 |
| Java theme-ID literal references | 933 |
| Direct raw-resource loader calls with literal arguments | 13 |
| Other raw-resource Java literals | 28 |
| Runtime assets without a discovered theme-ID dependency | 67 |
| Literal/derived color candidates | 218 occurrences in 38 files |

These are different populations: **882 IDs does not mean 882 distinct drawings**, and **592 runtime candidates does not mean 592 visible action icons**. Runtime resources include illustrations, strips and other non-icon artwork. Aliases and overlays reuse drawings. The all-image inventory retains excluded help/test/source artwork for traceability.

## Deliverables and method

| File | Contents |
|---|---|
| [icon-inventory.csv](icon-inventory.csv) | Required `icon id, file path, size, format, where used, module` fields, plus theme definition, section, expression, usage references and mapping status |
| [all-image-assets.csv](all-image-assets.csv) | Every tracked PNG/GIF/JPEG/BMP/ICO/ICNS/SVG/WebP candidate; measured size, format, scope, frames, transparency metadata and read status |
| [icon-counts-by-module.csv](icon-counts-by-module.csv) | Unique runtime-file counts grouped by module, format and measured size |
| [theme-definitions.csv](theme-definitions.csv) | Theme keys/values with section and source line |
| [icon-references.csv](icon-references.csv) | Production Java icon-ID and raw-path literals, source lines and context-derived usage hints |
| [resource-loader-calls.csv](resource-loader-calls.csv) | Literal and computed calls to ResourceManager image/icon loaders |
| [programmatic-icon-sites.csv](programmatic-icon-sites.csv) | Generated/composed icon constructors and direct Icon implementations requiring separate review |
| [icon-size-requests.csv](icon-size-requests.csv) | Numeric Java scaling/empty-icon calls and theme size modifiers; not a full data-flow analysis |
| [hardcoded-color-candidates.csv](hardcoded-color-candidates.csv) | Color constructors, AWT named constants and WebColors constants in production Java |
| [color-utility-candidates.csv](color-utility-candidates.csv) | Color factory calls, including computed/user-provided colors |
| [audit-counts.json](audit-counts.json) | Machine-readable measured summary |

The scan uses the tracked-file list at the audited commit. Raster metadata was read with the installed Pillow 12.1.1; SVG dimensions/viewBox were read as XML. All 1,379 asset headers/XML documents were readable; this is not a full raster pixel-decoding or appearance test. No additional library was installed. Runtime candidates are images under `Ghidra/` excluding test source sets, help, global documentation, script folders and separately classified SVG source directories. Packaging and actual visibility still require runtime verification.

Theme definitions are section-preserving lexical extracts. Alias/overlay dependency resolution takes the union of matching definitions across sections and matching resource filenames. It deliberately does not emulate classpath order or active-theme precedence. The only icon definition rows without a file dependency are the two LaF-supplied `icon.filechooser.default.file` definitions; those are native/generated references, not proven missing assets.

Java scans exclude comments and retain source lines. `where used` values are **heuristic context hints**, not a traced call graph: menu/toolbar/tree/dialog/splash are assigned only when nearby source supports a hint, otherwise `VERIFY`. A constant can serve several surfaces through distant consumers. Computed resource names, static-import aliases, generated icons, platform/native icons and external extension resources need manual/runtime follow-through. This report does not claim complete runtime coverage or prove that an unreferenced asset is unused. A snapshot of source text is included as evidence in several CSVs; upstream notices remain in the original source files.

No `graphify-out/graph.json` exists in this checkout. This audit used direct source evidence; it did not create a knowledge graph.

## Icon counts

| Format | Runtime candidate files |
|---|---:|
| PNG | 515 |
| GIF | 74 |
| JPEG | 2 |
| ICO | 1 |

No animated runtime GIF was found through frame metadata. Transparency metadata does not prove the artwork lacks a baked-in background; visual review is still required.

| Module | Runtime candidate files |
|---|---:|
| Features/Base | 277 |
| Framework/Docking | 81 |
| Debug/Debugger | 60 |
| Framework/Gui | 56 |
| Features/VersionTracking | 29 |
| Framework/Project | 29 |
| Features/FunctionGraph | 20 |
| Framework/Graph | 11 |
| Features/BSim | 8 |
| Features/ProgramDiff | 5 |
| Framework/Help | 5 |
| Features/Decompiler | 3 |
| Features/DecompilerDependent | 2 |
| Framework/SoftwareModeling | 2 |
| Features/ByteViewer | 1 |
| Features/DataGraph | 1 |
| Features/FunctionGraphDecompilerExtension | 1 |
| RuntimeScripts/support | 1 |

Common raster sizes are 16×16 (411 files), 32×32 (45), 25×17 (30), 22×22 (18), 24×24 (16), and 20×20 (3). The complete size distribution is in the JSON and grouped CSV. Several remaining assets are deliberately rectangular or large illustrations, including 440×3 strips; applying a square-icon validator to every image would be incorrect.

## Verified loading and theming architecture

Source paths below are relative to the repository; class and method names were verified in this checkout.

1. [DockingApplicationConfiguration](../../Ghidra/Framework/Docking/src/main/java/docking/framework/DockingApplicationConfiguration.java) initializes `ApplicationThemeManager`. [Gui](../../Ghidra/Framework/Gui/src/main/java/generic/theme/Gui.java) exposes `getIcon`, `getColor`, `getFont` and listeners; [GIcon](../../Ghidra/Framework/Gui/src/main/java/generic/theme/GIcon.java) and GColor provide theme-aware indirection.
2. [PropertyFileThemeDefaults](../../Ghidra/Framework/Gui/src/main/java/generic/theme/PropertyFileThemeDefaults.java) discovers module `*.theme.properties` files through `Application.findFilesByExtensionInApplication`. [ThemePropertyFileReader](../../Ghidra/Framework/Gui/src/main/java/generic/theme/ThemePropertyFileReader.java) separates `[Defaults]`, `[Dark Defaults]` and LaF-specific sections.
3. [ThemeManager.buildCurrentValues](../../Ghidra/Framework/Gui/src/main/java/generic/theme/ThemeManager.java) loads Java defaults, application light defaults, dark overrides when enabled, LaF overrides, then the active theme. A missing dark override intentionally inherits the light/default value. Theme completeness checks must evaluate effective values; raw dark/light section equality is not an upstream invariant.
4. [IconValue](../../Ghidra/Framework/Gui/src/main/java/generic/theme/IconValue.java) resolves resource paths via [ResourceManager](../../Ghidra/Framework/Gui/src/main/java/resources/ResourceManager.java). Bare filenames try `images/<filename>`, then a direct resource path and filesystem path. Paths beginning with the external-icon prefix use the user settings directory. `loadImage` caches image objects. A later overlay cannot be assumed to replace an already cached raw-path icon.
5. [IconModifier](../../Ghidra/Framework/Gui/src/main/java/generic/theme/IconModifier.java) supports size, translation, disabled state, mirror/flip, rotation and overlaid icon expressions. Retain these semantics; replacing every ID with the same generic glyph would erase important state information.
6. [ApplicationThemeManager](../../Ghidra/Framework/Gui/src/main/java/generic/theme/ApplicationThemeManager.java) discovers `DiscoverableGTheme` extension-point classes and user `.theme` files under the settings `themes` directory. [ThemeReader](../../Ghidra/Framework/Gui/src/main/java/generic/theme/ThemeReader.java) accepts `.theme` and `.theme.zip` imports. `.theme` files require `name`, `lookAndFeel` and `useDarkDefaults` metadata and do **not** allow the `[Defaults]`/`[Dark Defaults]` structure. Merely adding two module `*.theme.properties` files will not register two selectable themes.
7. [ThemeManagerPlugin](../../Ghidra/Framework/Project/src/main/java/ghidra/app/plugin/gui/ThemeManagerPlugin.java) registers **project window → Edit → Theme → Switch...**, Configure, New..., Import..., Export... and Delete.... Its annotation restricts the plugin to the project window. These captions are source-verified; a live menu was not opened.

### FlatLaf and existing themes

[Gui/build.gradle](../../Ghidra/Framework/Gui/build.gradle) declares `com.formdev:flatlaf:3.5.4`; [Module.manifest](../../Ghidra/Framework/Gui/Module.manifest) records its existing Apache License 2.0 provenance. `ApplicationThemeManager.installFlatLookAndFeels` installs Flat Light and Flat Dark. The existing [FlatLightTheme](../../Ghidra/Framework/Gui/src/main/java/generic/theme/builtin/FlatLightTheme.java) and [FlatDarkTheme](../../Ghidra/Framework/Gui/src/main/java/generic/theme/builtin/FlatDarkTheme.java) are discoverable themes. Other built-ins cover Windows, Windows Classic, macOS, GTK, Metal, Nimbus and Motif, subject to platform support.

No `flatlaf-extras` declaration or `FlatSVGIcon` integration was found in the inspected source/build files. [UrlImageIcon.createImage](../../Ghidra/Framework/Gui/src/main/java/resources/icons/UrlImageIcon.java) uses AWT Toolkit image bytes. Therefore **SVG loading/recoloring must not be assumed to work through the current resource loader**. The proposed SVG authoring → theme-specific transparent PNG export is compatible with the observed raster path. A future SVG runtime adapter would need implementation, dependency/license checking and tests; no dependency was added here.

The native default is platform-dependent: `ThemeManager.getDefaultTheme` chooses Windows on Windows, Mac on macOS and Flat Light elsewhere. Existing Flat themes are available but not universally selected by default.

### Real size requirements and branding

- [DockingUtils.scaleIconAsNeeded](../../Ghidra/Framework/Docking/src/main/java/docking/DockingUtils.java) normalizes its toolbar icon path to 16×16.
- [ToolIconURL](../../Ghidra/Framework/Docking/src/main/java/docking/util/image/ToolIconURL.java) defines small 16, medium 22 and large 24 px tool icons, with fallback scaling.
- [GTableHeaderRenderer](../../Ghidra/Framework/Docking/src/main/java/docking/widgets/table/GTableHeaderRenderer.java) scales sorting icons to 14×14 and filter decoration to 12×12.
- `project.icons.theme.properties`, `docking.theme.properties`, `base.icons.theme.properties` and `version.tracking.theme.properties` contain 8×8, 10×10 and 12×12 badges and non-square overlay canvases. Keep their intended footprint and anchor offsets. A 24 px authoring grid can serve standard glyphs; export/grid checks need explicit badges, cursors, strips, splash and native-app-icon exceptions.
- [GhidraApplicationInformationDisplayFactory](../../Ghidra/Features/Base/src/main/java/ghidra/framework/main/GhidraApplicationInformationDisplayFactory.java) requests app icons at **16, 24, 32, 40, 48, 64, 128 and 256 px** through existing `icon.base.application.*` IDs. The ICO at [RuntimeScripts/support/ghidra.ico](../../Ghidra/RuntimeScripts/support/ghidra.ico) contains these eight sizes. A desktop app icon cannot stop at 32 px. No tracked ICNS was found; macOS application-bundle integration remains **VERIFY**.
- Splash/About construction also involves [ApplicationInformationDisplayFactory](../../Ghidra/Framework/Docking/src/main/java/docking/framework/ApplicationInformationDisplayFactory.java), [SplashScreen](../../Ghidra/Framework/Docking/src/main/java/docking/framework/SplashScreen.java) and Public_Release `splash.txt`. Follow the actual branding consumers; attribution is retained separately.

## Raw paths and generated icons

All discovered direct literal loader calls are in `icon-references.csv`. Examples requiring explicit handling:

| Consumer | Raw resource | Implication |
|---|---|---|
| `Framework/Docking/.../widgets/tab/GTabPanel.java:855` | `move.png` | Custom cursor hotspot is `(8,8)`; treat as a cursor, not a toolbar glyph |
| `Features/Base/.../app/util/XReferenceUtils.java:375` | `images/ThunkFunction.gif` | Inline reference/tooltip image bypasses GIcon indirection |
| `Features/PyGhidra/.../interpreter/CancelAction.java:39` | `images/dialog-cancel.png` | Action icon loaded by path |
| `Features/PyGhidra/.../interpreter/ResetAction.java:39` | `images/reload3.png` | Action icon loaded by path |
| `Features/PyGhidra/.../interpreter/PyGhidraInterpreter.java:58` | `images/python.png` | Interpreter identity image loaded by path |
| `Debug/Debugger/.../timeoverview/TimeOverviewColorPlugin.java:174` | `images/x-office-document-template.png` | Time-overview UI path |
| Core/Developer/Examples/BSim/Miscellaneous/Utility plugin package classes | Package artwork paths | Package selection/configuration UI also needs coverage |

The resource-loader supplement includes computed arguments; a literal-only search is insufficient. The generated-icon supplement covers icon renderers/compositions without image files, including empty/close/color icons and `BrokenLinkIcon`. Swing/native LaF controls form another population. Their complete rendered appearance remains **VERIFY**.

Prefer stable theme IDs with unique Opcodex resource names and explicit light/dark mappings. Where raw calls cannot observe theme IDs, use narrowly audited changes to UI consumers or verified resource overrides; do not rely on accidental duplicate-classpath ordering. Reusing the historical ID is compatible with new artwork and does not make historical names product branding.

## Colors: confirmed findings versus candidates

The candidate list contains **218 matches in 38 production Java files**: 31 initially classified literal candidates, 24 derived/dynamic candidates and 163 palette/parser/fallback/editor candidates. These classifications are triage hints, not 218 defects. Supplementary factory calls are recorded separately.

Confirmed UI bypasses:

| Source | Finding | Later minimal treatment |
|---|---|---|
| `Framework/Project/.../main/BrokenLinkIcon.java:56` | `g.setColor(Color.red)` paints a broken-link overlay without a semantic theme ID | Introduce/use a link-error theme color while retaining the zigzag shape |
| `Features/Base/.../app/util/ToolTipUtils.java:303` | `colorString(Color.RED, ccHtml)` for unknown calling convention | Resolve a semantic error/warning foreground for both themes |

Findings that should **not** be mechanically replaced:

- [GThemeDefaults.Colors.Palette](../../Ghidra/Framework/Gui/src/main/java/generic/theme/GThemeDefaults.java) is backed by `GColor("color.palette.*")`. `Palette.RED`, `Palette.WHITE` etc. already participate in themes. Semantic names may still improve design, but these are not raw AWT colors.
- `FlatDarkUiDefaultsMapper.java:38` and `MacLookAndFeelManager.java:60` construct fixed colors while deriving **theme defaults**. They flow into the theme maps; they are not evidence of untokenized component painting.
- `ConsoleActionsCellEditor.java:47` initializes a cached color and later copies the table's selection background. Do not replace the cache with a permanent hardcoded color.
- `TokenHighlightColors` generates user/token highlights and explicitly adjusts saturation/brightness for dark mode. `IndependentColorProvider` and `GroupedVertexInfo` preserve user-chosen graph colors. These are data/annotation behaviors, not ordinary chrome defaults.
- `WebColors` is a color-name library; ColorValue/ThemeColorTree are parsers/editors. Transparent gradient endpoints, serialization colors, ANSI protocol palettes, screenshots and diagnostics need contextual treatment.

Read-only inspection of decompiler UI theme hooks is included in this audit; it does not authorize modifying decompiler code. Any later integration must respect the brief's protected analysis/decompiler/loader/processor boundary. Additional embedded HTML/CSS color strings, static-imported color constants and external plugins remain **VERIFY**; the lexical scan does not prove absence.

## Existing UX and theme hooks to preserve

- [ShowActionChooserDialogAction](../../Ghidra/Framework/Docking/src/main/java/docking/action/ShowActionChooserDialogAction.java) and [ActionChooserDialog](../../Ghidra/Framework/Docking/src/main/java/docking/actions/dialog/ActionChooserDialog.java) already provide searchable actions. [SystemKeyBindings](../../Ghidra/Framework/Generic/src/main/java/generic/util/action/SystemKeyBindings.java) binds it to **Ctrl+3** in source. Prefer evaluating and adapting this mechanism before writing a second palette. The requested Ctrl/Cmd+Shift+P binding needs conflict/platform verification.
- Default layout exists at [Public_Release/.../defaultTools/CodeBrowser.tool](../../Ghidra/Configurations/Public_Release/src/main/resources/defaultTools/CodeBrowser.tool). Export a curated fresh-profile preset; retain saved user layouts and plugin availability. Toolbar/menu cleanup should preserve discoverability and services.
- Listing/decompiler font keys already exist: `font.listing.base` in `base.listing.theme.properties`, `font.decompiler` in `decompiler.theme.properties`, both based on `font.monospaced`. Preserve configurability. Detailed Listing/decompiler/ByteViewer/FunctionGraph/Debugger palettes already have module theme definitions in the CSV.
- No OS dark-mode change listener or working “follow system appearance” option was found in the inspected theme manager/preferences/plugin paths. Native OS LaF selection is not evidence of light/dark tracking. **VERIFY** platform integration on the selected release before promising this feature; otherwise document it as deferred.
- Hit targets, keyboard focus, tooltip shortcut presentation, row padding, dialogs and empty states require a running desktop evaluation. No accessibility or contrast pass is claimed from static source inspection.

## Verification performed

| Check / exact command | Result |
|---|---|
| `git status --short`, `git branch --show-current`, `git log -1 --oneline`, `git remote -v` | Initially clean `master`, audited commit and Community remote confirmed |
| `git ls-files` plus scoped `rg` source searches | File inventory and the source paths above checked |
| `java -version` | Oracle JDK 25.0.2; compatible with this tree's declared Java minimum |
| `python -c "import PIL; print('Pillow', PIL.__version__)"` | Installed Pillow 12.1.1 |
| `.\gradlew.bat --version` | Passed; wrapper downloaded Gradle 9.8.0 into its cache; JVM 25.0.2 on Windows 11 amd64 |
| `python C:\Users\pc\AppData\Local\Temp\opcodex-ui-audit.py` | Generated primary CSV/JSON inventories from tracked source and image metadata |
| `python C:\Users\pc\AppData\Local\Temp\opcodex-ui-audit-supplement.py` | Generated loader/composition/color-factory call inventories; repeated the primary extraction |

The temporary extraction scripts are working tools, not runtime dependencies or committed product code. Inventory integrity and documentation-link checks are recorded in [CHECKS.md](CHECKS.md).

**Not run at this audit gate:** dependency bootstrap, `buildGhidra`, application launch, `unitTestReport`/integration tests, headless parity tests, dark/light desktop screenshots, icon visual review, contrast/keyboard checks, or Windows 100/125/150/200% and Linux/macOS UI checks. Wrapper version success is not a product build/test pass. No regressions have been measured. No replacement icons, design tokens, themes or UX changes were implemented; no replacement-completeness validator can pass before those exist.

## Review gate and next stage

Review this source audit and resolve the v1 upstream baseline before implementation. Then write `DESIGN_SYSTEM.md`, with explicit small-overlay/native-icon exceptions, and produce the toolbar/tree pilot for review. The remaining icons, themes and UX work follow their ordered gates. Each later changed upstream file needs its `OPCODEX:` marker and `MODIFICATIONS.md` entry; this audit changes only new documentation/data files and retains upstream files and notices intact.

Unverified runtime behavior is explicitly marked throughout this report. Opcodex v1 is the intended release; this audit is a preparatory deliverable, not a completed v1 application.

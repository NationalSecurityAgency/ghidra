# GhidrAssist

Embeds a Claude-powered AI assistant inside Ghidra.

## What it does

- **Chat panel**: a docked window where you can converse with Claude about the
  program you are reversing. Chat history is kept for the session.
- **Decompiler actions** (right-click in the Decompiler window):
  - *Explain function* — summarises what the current function does.
  - *Suggest renames* — proposes better names for variables and the function
    itself, applied via Ghidra's rename APIs after you confirm.
  - *Suggest signature* — proposes a function signature (return type + typed
    parameters).
  - *Reconstruct as C* — produces cleaner, idiomatic C source for the current
    function.
- **Export to C project**: batch-decompiles every function in the current
  program, optionally runs each through Claude for cleanup, and writes a
  directory containing one `.c` file per function, a shared `program.h`
  header, and a `Makefile` skeleton. See the honest limits below.
- **Apple binaries (Mach-O, Apple Silicon, iOS)**:
  - *What Ghidra already does on its own*: the `MachoLoader`, the
    `DyldCacheLoader`, the `AARCH64:LE:64:AppleSilicon` processor variant,
    and the Objective-C and Swift feature modules all ship with Ghidra
    out of the box. Mach-O / Apple Silicon / iOS binaries decompile with
    no help from this extension.
  - *What GhidrAssist adds on top*: when the current program is Mach-O,
    the Explain and Reconstruct prompts prepend a short preamble telling
    Claude about `objc_msgSend` dispatch, Swift mangling and metadata
    sections, Darwin AAPCS64 conventions, and the presence of pointer
    authentication on arm64e. There is also a one-click
    `Tools → GhidrAssist → Prepare Apple Binary…` action that enables the
    Objective-C and Swift analyzers on the current program and schedules
    a re-analysis. It adds no new decompilation capability; it just
    toggles analyzers that are off by default on non-Apple binaries.

## Setup

1. Install the extension from `File → Install Extensions…`, then restart
   Ghidra.
2. In the CodeBrowser tool, open `Edit → Tool Options… → GhidrAssist`.
3. Paste your Anthropic API key, pick a model (defaults to a recent Claude),
   and optionally override the API base URL (useful for proxies).
4. Open the chat panel from `Window → GhidrAssist`.

## Honest limitations

- **Not a magic decompiler.** Ghidra's SLEIGH-based decompiler handles many
  architectures but the output is a *reconstruction*, not the original source.
  Claude only cleans up that reconstruction; it does not recover information
  the compiler threw away (local names, exact types, inlined logic, macro
  definitions, …).
- **Rebuild fidelity is best-effort.** The exported C project is intended to
  be a starting point for manual porting. For non-trivial binaries it will
  not compile without edits, and even after it compiles it will not be
  bit-identical to the original. There is no current reverse-engineering
  pipeline that produces a byte-exact rebuild of arbitrary binaries.
- **The LLM can be wrong.** Treat every suggestion — especially renames and
  types — as a hypothesis to verify against the listing. Rename/retype actions
  always show a confirmation dialog before touching the program.
- **The API key leaves your machine.** The plugin calls `api.anthropic.com`
  directly over HTTPS (or the base URL you configure). The decompiled C of
  the function or functions you act on is included in the prompt. Do not use
  this on code you are not allowed to share with a third party.

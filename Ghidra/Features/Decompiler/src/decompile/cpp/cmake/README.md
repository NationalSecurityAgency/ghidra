# Standalone CMake build of the decompiler

This directory adds a CMake build for the native decompiler and SLEIGH code.
It does not change the Gradle build and it does not modify any source file.
It exists so the native code can be built, tested and linked from other
programs without a JVM, Gradle or Java on the machine.

The CMake build produces:

- `libsla.a`: SLEIGH only (disassembly, p-code translation, emulation).
  Same members as `LIBSLA_NAMES` in the `Makefile`.
- `libdecomp_archive.a`: the decompiler with SLEIGH. Same members as
  `LIBDECOMP_NAMES` in the `Makefile`, without the libbfd loader unless
  `GHIDRA_DECOMP_BFD` is on.
- `ghidra::decomp`: an interface target that links `libdecomp_archive.a`
  whole. The architecture and language capabilities (`xml`, `raw`,
  `c-language`, `java-language`) register themselves from static
  initializers; a normal archive link drops them.
- `sleigh_compiler`: the SLEIGH compiler (`slgh_compile.cc`).
- `decomp_console`: the interactive console (`consolemain.cc`, the
  `Makefile`'s `decomp_dbg`).
- `decomp_test`: the unit and data test runner (`test.cc`).
- A sleigh home: compiled `.sla` files and their support files for the
  processors in `GHIDRA_DECOMP_SPEC_PROCESSORS`.

The JVM-facing `ghidra_process.cc` and the other `GHIDRA` sources are never
compiled here. A test checks that `libdecomp_archive.a` defines no
`GhidraCapability` or `GhidraCommand` symbol.

## Build and test

From this `cpp` directory:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure
```

Requirements: CMake 3.24 or newer, a C++11 compiler, zlib development
files (or `-DGHIDRA_DECOMP_LOCAL_ZLIB=ON` to compile the bundled copy).
Ninja is recommended: the spec compilation uses a Ninja job pool so that
at most two `.sla` files compile at once. `x86-64` and `AARCH64` each take
minutes and more than 1 GB of memory.

The generated parsers (`xml.cc`, `grammar.cc`, `pcodeparse.cc`,
`slghparse.cc`, `slghscan.cc`) are the committed ones; bison and flex are
not run.

To build inside a container with no Java, run this from the root of the
Ghidra checkout:

```sh
podman run --rm -v "$PWD":/src:Z -w /src registry.fedoraproject.org/fedora:44 \
  bash -c 'dnf -y install gcc-c++ cmake ninja-build zlib-devel \
    && cmake -S Ghidra/Features/Decompiler/src/decompile/cpp -B /tmp/b -G Ninja \
    && cmake --build /tmp/b \
    && ctest --test-dir /tmp/b --output-on-failure'
```

## Options

| Option | Default | Effect |
| --- | --- | --- |
| `GHIDRA_DECOMP_LOCAL_ZLIB` | `OFF` | Compile `../zlib` with `NO_GZIP` and define `LOCAL_ZLIB` instead of linking the system zlib. |
| `GHIDRA_DECOMP_BFD` | `OFF` | Compile `bfd_arch.cc` and `loadimage_bfd.cc` and link libbfd. Needs binutils development files. |
| `GHIDRA_DECOMP_CONSOLE` | `ON` | Compile the console sources (`interface`, `ifacedecomp`, `ifaceterm`, ...). Needed by `decomp_console` and `decomp_test`. |
| `GHIDRA_DECOMP_TERMINAL` | `ON` on Unix with console | Define `__TERMINAL__` (line editing for the console). Exported: it changes the layout of `IfaceTerm`. |
| `GHIDRA_DECOMP_CPUI_DEBUG` | `OFF` | Define `CPUI_DEBUG`. Exported: it changes class layouts. |
| `GHIDRA_DECOMP_SANITIZE` | empty | Value for `-fsanitize=` on every target, for example `address,undefined`. |
| `GHIDRA_DECOMP_BUILD_TOOLS` | `ON` | Build `sleigh_compiler` and `decomp_console`. |
| `GHIDRA_DECOMP_BUILD_TESTS` | `ON` when top level | Build `decomp_test`, `sleigh_smoke`, `decomp_smoke` and register the tests. |
| `GHIDRA_DECOMP_SPEC_PROCESSORS` | `x86;ARM;AARCH64` | Processor directories whose `.slaspec` files are compiled into the sleigh home. Empty disables spec compilation and the tests that need it. |
| `GHIDRA_DECOMP_CXX_STANDARD` | `11` | C++ standard for the sources. The Gradle build uses `-std=c++11`. |
| `GHIDRA_DECOMP_INSTALL` | `ON` when top level | Generate install and export rules. |
| `GHIDRA_DECOMP_CHECK_MANIFEST` | `ON` | Compare `cmake/GhidraDecompSources.cmake` with the `Makefile` at configure time and stop on a difference. |
| `GHIDRA_DECOMP_MASTER_MAKEFILE` | empty | Path to another checkout's decompiler `Makefile`. Adds the test `manifest_matches_makefile_master`. |
| `GHIDRA_DECOMP_SLEIGH_HOME` | `<build>/sleigh-home` | Where the compiled specs go. |
| `GHIDRA_DECOMP_PROCESSORS_ROOT` | `Ghidra/Processors` of this checkout | Where the processor modules are read from. |

Compiler flags follow `buildNatives.gradle`: `-Wall -Wno-sign-compare`,
`LINUX` and `_LINUX` defined on Linux, `-O2` through the build type.
Warnings from newer compilers are left as they are.

When this directory is added to another project with `add_subdirectory`,
`GHIDRA_DECOMP_BUILD_TESTS` and `GHIDRA_DECOMP_INSTALL` default to off and
`GHIDRA_DECOMP_SLEIGH_HOME` is visible in the parent scope.

## Source manifest

`cmake/GhidraDecompSources.cmake` lists the sources by the same sets the
`Makefile` uses (`CORE`, `DECCORE`, `SLEIGH`, `GHIDRA`, `SLACOMP`,
`SPECIAL`, and `EXTRA` as every other `*.cc`).
`cmake/CheckMakefileManifest.cmake` parses the `Makefile` and compares the
sets. It runs at configure time and as the test `manifest_matches_makefile`.
When a source is added or removed upstream, the check names it under
`only-in-Makefile` or `only-in-CMake`, and the fix is a one-line edit of the
manifest. The check can also run by hand:

```sh
cmake -DMAKEFILE=$PWD/Makefile -DSOURCE_DIR=$PWD -P cmake/CheckMakefileManifest.cmake
```

## Tests

| Test | Label | What it checks |
| --- | --- | --- |
| `manifest_matches_makefile` | manifest | The source manifest equals the `Makefile` sets. |
| `manifest_matches_makefile_master` | manifest | Same against `GHIDRA_DECOMP_MASTER_MAKEFILE`, when set. |
| `decomp_unittests` | unit | `decomp_test unittests` (the `../unittests` cases). |
| `decomp_datatests` | data | `decomp_test datatests` over the `../datatests` files whose language the compiled processors provide. With the default processors, 72 of 83. |
| `sleigh_smoke_x86-64`, `sleigh_smoke_arm-thumb`, `sleigh_smoke_aarch64` | smoke | `sleigh_smoke` disassembles and translates fixed bytes with the built `.sla` files and compares with `cmake/smoke/expected/<case>.txt`. |
| `capability_linkage` | smoke, isolation | `decomp_smoke --check-capabilities`: `xml`, `raw`, `c-language`, `java-language` are registered; `bfd` only with `GHIDRA_DECOMP_BFD`. |
| `no_jvm_linkage` | isolation | No built program links `libjvm`, `libjava`, `libjli` or `libjawt` (`ldd`, `otool -L` or `readelf -d`). |
| `no_jvm_runtime` | isolation | `sleigh_smoke` runs under `env -i PATH=/usr/bin HOME=/nonexistent LANG=C`. With `strace` present, exactly one `execve` is recorded: no child process. |
| `no_ghidra_process_symbols` | isolation | `nm` finds no `GhidraCapability` or `GhidraCommand` symbol in `libdecomp_archive.a`. |

Run a subset with labels, for example `ctest --test-dir build -L smoke`.

`sleigh_smoke <sleigh-home> <case>` prints one block per instruction: the
address, mnemonic and operands, then one indented line per p-code op with
varnodes as `space[offset:size]`. The expected files were generated once
and reviewed by hand. Regenerate one with
`build/sleigh_smoke build/sleigh-home x86-64 > cmake/smoke/expected/x86-64.txt`
after a deliberate change to a spec.

## Sleigh home layout

`SleighArchitecture::scanForSleighDirectories` looks for
`Ghidra/Processors/*/data/languages` under a root. The build writes:

```
<sleigh-home>/Ghidra/Processors/<P>/data/languages/<spec>.sla
<sleigh-home>/Ghidra/Processors/<P>/data/languages/*.ldefs *.pspec *.cspec *.opinion ...
```

Only `.slaspec` files that an `.ldefs` names in a `slafile` attribute are
compiled. Per-processor compiler options come from `sleighCompileOptions` in
`Ghidra/Processors/<P>/build.gradle`, the same source the Gradle build
reads. Each spec compiles in single-file mode with an explicit output path,
so `@include` resolves against the source tree and no file is written there.

`decomp_test` and the console take this directory with `-sleighpath` or
through `SLEIGHHOME` with `-usesleighenv`.

## Install and use from another project

```sh
cmake --install build --prefix /opt/ghidra-decompiler
```

installs the archives, the programs, the headers under
`include/ghidra/decompiler`, the sleigh home under
`share/ghidra-decompiler/sleigh-home`, and a package config under
`lib/cmake/GhidraDecompiler`. A consumer:

```cmake
cmake_minimum_required(VERSION 3.24)
project(consumer CXX)
find_package(GhidraDecompiler 12 REQUIRED)
add_executable(consumer main.cc)
target_link_libraries(consumer PRIVATE ghidra::decomp)
message(STATUS "sla format ${GhidraDecompiler_SLA_FORMAT_VERSION}, specs in ${GhidraDecompiler_SLEIGH_HOME}")
```

```cpp
#include "libdecomp.hh"
int main() {
  ghidra::startDecompilerLibrary(SLEIGH_HOME);   // scans Ghidra/Processors under the root
  return ghidra::ArchitectureCapability::getCapability("xml") == nullptr;
}
```

The config file exports `GhidraDecompiler_GHIDRA_VERSION`,
`GhidraDecompiler_SLA_FORMAT_VERSION`, `GhidraDecompiler_SLEIGH_HOME`, and
`GhidraDecompiler_HAVE_BFD`, `_HAVE_CONSOLE`, `_HAVE_TERMINAL`,
`_HAVE_CPUI_DEBUG`, `_HAVE_LOCAL_ZLIB`. The compile definitions that change
class layouts (`__TERMINAL__`, `CPUI_DEBUG`, `LOCAL_ZLIB`) travel with the
targets, so a consumer sees the same layouts the archives were built with.

Link either `ghidra::sla` or `ghidra::decomp`, not both: `ghidra::decomp`
already contains every object in `ghidra::sla`.

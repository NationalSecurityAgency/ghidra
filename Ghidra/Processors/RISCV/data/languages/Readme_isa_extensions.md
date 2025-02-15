# RISCV Instruction Set Extensions

> The RISCV instruction set is relatively easy to extend with new instructions.  These extensions present Ghidra with many design and implementation challenges.

* How do combinations of these extensions map into Ghidra 'language' models?
* How do vector instructions - and vector context settings - get modeled within Ghidra?
* Are the semantics for new instructions captured in traditional pcode or in more opaque user pcode ops?
* Are the semantics designed to support decompiler legibility or emulator correctness?
* RISCV extensions include at least two 16 bit floating point formats - does Ghidra need low level support for these?
* Optimizing RISCV compilers like GCC will often optimize scalar code and simple loops into sequences of vector instructions.
  Compiler optimized loops over arrays of structures can be particularly hard to understand in Ghidra.

## Examples demonstrating RISCV ISA extensions

> Ghidra's handling of ISA extensions can be informed by the way other systems handle those instructions.

The RISCV-64 `libc.so.6` library explicitly describes the required processor extensions with the `Tag_RISCV_arch` Elf file attribute.
For the GCC 15 release the extension list looks like this:

```console
readelf -a sysroot/lib/libc.so.6|grep Tag_RISCV_arch
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0_zcd1p0"
```

That roughly translates to a supported instruction set of:

* RV64I version 2.1
* m 2.0 - integer multiplication and division
* a 2.1 - atomic instructions
* f 2.2 - single precision floating point
* d 2.2 - double precision floating point
* c 2.0 - compressed instructions
* zicsr 2.0 - privileged instructions
* zifencei 2.0 - defines the fence.i instruction for fencing instruction memory stores
* zmmul 1.0 - the muliplication subset of the m extension
* zaamo 1.0 - atomic memory operations
* zalrsc 1.0 - load-reserved/store-conditional operations
* zca 1.0 - additional compressed instructions
* zcd 1.0 - additional double precision floating point compressed instructions

These extensions are defined in https://riscv.org/technical/specifications, 
https://wiki.riscv.org/display/HOME/Recently+Ratified+Extensions,
https://wiki.riscv.org/display/HOME/Specification+Status,
and https://five-embeddev.com/riscv-isa-manual/latest/zifencei.html#.

For a broader summary of RISCV extensions, and how the kernel identifies available extensions, see https://research.redhat.com/blog/article/risc-v-extensions-whats-available-and-how-to-find-it.

Most ISA extensions are prefixed with `z`, while vendor-specific extensions are prefixed with `x`.
The `z` extensions generally have non-conflicting opcode encodings.  Vendor-specific `x` extensions *may* have overlapping
encodings.

A RISCV kernel goes into more detail on supported extensions with strings like:
    rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zihintpause2p0_zmmul1p0_zbb1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0

It is *not* obvious whether these extensions are required, supported, or simply recognized by this kernel.

This extension list includes `zbb1p0`, referencing the `zbb` version 1.0 bit processing extension.
If this extension is found on the processor at boot time, it likely invokes the Linux kernel `ALTERNATE` macro
to modify the `strcmp` kernel function to silently invoke `strcmp_zbb` instead.

>Note: this kernel example shows extension-dependent self-modifying kernel code, something to keep in mind when analyzing RISCV binaries.

### Linux kernel approach to RISCV extensions

The kernel discovers at boot time which extensions are available on each of the hardware threads (aka 'harts'), making the results available internally with
calls like `__riscv_isa_extension_available(hart_isa[cpu].isa, ext)`.  The extensions themselves are defined in `arch/riscv/include/asm/hwcap.h`.  Note that
a single processor like the Sophgo 2380 can have multiple core types, each with distinct combinations of supported or required extensions.

### binutils approach to RISCV extensions

We can compare Ghidra's ISA extension processing with that of `binutils`, since the `objdump` utility built and tested within `binutils`
performs roughly the same function as Ghidra's importer and disassembler.  If `gas` can assemble the instructions and `objdump` can read them,
then we have a decent conformance and test suite for Ghidra.

The source repository for `binutils` is https://sourceware.org/git/binutils-gdb.git, currently at release 2.44.  Within that repository the
current set of RISCV instruction encodings tested is found in `gas/testsuite/gas/riscv`.  Not all RISCV instruction extensions are found there - only those someone has
thought likely to be useful in the near future.

For example, `gas/testsuite/gas/riscv/vector-insns.s` is an 1870 line file used to test the vector instruction extensions with various operands.  We can assemble this with
a compatible `gas` utility and `-march` architecture specification, then compare the disassembly generated by `objdump` and `ghidra`.  This gives us a good start on
a Ghidra RISCV import binary testsuite, as well as a sense of which extension instructions are likely to be found in deployment anytime soon.

Binutils provides selected vendor-specific extensions, currently including:

* `x-thead` extensions from [Alibaba's](https://www.scmp.com/tech/big-tech/article/3212122/alibabas-chip-unit-t-head-steps-risc-v-development-china-pushes-open-source-architecture-face-us) cpu development initiative 
* `x-ventana` extensions from Ventana
* `xsfvcp` extensions from SI-Five
* `xcv` extensions from the [open hardware group](https://docs.openhwgroup.org/projects/cv32e40p-user-manual/en/latest/instruction_set_extensions.html)

Extension instructions can appear in deployed code without being supported by `binutils`.  This is especially true for kernel code, as vendors can use kernel macros to assemble highly
specialized instructions needed for VM memory fencing and cache coherence management.

`objdump` for RISCV generally is built to handle all known extensions in its test suite - but these extensions must be manually enabled on the command line or declared within
the ELF binary.

### Ghidra's approach to RISCV extensions

When Ghidra imports an ELF file it inspects `e_machine` and `e_flags` to find the *basic* RISCV variant.  The known variants are defined in `riscv.opinion`.
A binary for a general purpose 64 bit RISCV processor with the G profile (I, M, A, and F extensions) and the C extension will get the `RV64GC` variant as the default 'language'.
If the user enables languages other than the recommended language they will also see variants defined in `riscv.ldefs`.
This includes `RV64GC` as well as `RV64GCV_THEAD`, where `RV64GCV_THEAD` includes the roughly 10 Alibaba THead extensions supported in the `binutils` gas testsuite.  

Each variant links to a (likely shared) `slaspec` file to include base and extension instructions for that variant.  These are short files that provide `@define` and `@include` statements to access
specific files in this directory.  The general purpose 64 bit `RV64GC` variant uses the slaspec file (`riscv.lp64d.slaspec`) and includes three baseline `riscv.*.sinc` files and one place-holder `riscv.custom.sinc` file.
The THead variant `RV64GCV_THEAD` slaspec file `riscv.lp64d_thead.slaspec` is similar, except for:

* `riscv.custom.sinc` is excluded as these placeholder opcodes may conflict with the THead extension opcodes
* `riscv.xthead.sinc` is included as the `sinc` file holding the 10 current THead extensions supported by binutils
* `@define` statements enabling each of the 10 extensions, using binutils naming conventions.

Ghidra scans for `slaspec` files during its sleigh compile phase, generating a new `.sla` file for each RISCV variant found.
After compression, that means each explicit combination of supported extensions adds about 250KBytes to the Ghidra distribution.

### Gnu Compiler Suite approach to RISCV extensions

GCC can include embedded assembly instructions, passing them to the `gas` assembler.  This includes ISA extension instructions.
For example, multiple bit manipulation instruction extensions can be enabled by appending `-march=rv64i_zba_zbb_zbc_zbs` to the gcc or gas command line.
GCC can optimize generated code to use extension instructions, substituting cheaper extension instruction sequences for the nominal base instructions.
This is easy for simple bit manipulation operations and harder for the vectorization of loops.

The RISCV vector extension treatment by GCC is complex. Source code written explicitly for RISCV vector extensions uses *intrinsics* (see https://github.com/riscv-non-isa/rvv-intrinsic-doc).
These intrinsic functions capture mode and execution vector instructions.  Because there are so many modes, types, and variants in vector contexts there can be upwards of 30,000 different vector intrinsics
known to GCC.  That's too many to name explicitly in a C header file, so GCC precompiles these intrinsics directly into the riscv compiler.  Therefore `#include <riscv_vector.h>` does not itself define
any of the vector intrinsic functions, so there is no immediate way Ghidra can import a C header file of all RISCV vector intrinsics.

See https://github.com/ggerganov/whisper.cpp.git for an example of riscv vector instrinsic use, in the file `ggml_quants.c`.

>Warning: Programs that use vector instrinsic functions directly can have hard-to-debug dependencies on vector register length, exception handling, and alignment.  

## Experimental approach to Ghidra support of RISCV instruction extensions

* RISCV instruction extensions found in the main branch of the binutils gas testsuite should generally be recognized by Ghidra.  The immediate goal is to avoid the disassembler or decompiler exiting early because they
  encounter an unrecognized opcode.
* The Ghidra default RISCV variants should track the current RISCV [profiles](https://github.com/riscv/riscv-profiles/blob/main/rva23-profile.adoc).  Currently, that means we should support 64 bit extensions
  included within the rva23 64 bit profile.
* Where feasible, `binutils` and Ghidra should produce identical disassembly.  Exceptions include:
    * immediate operands can be either hex or decimal
    * compressed instructions need not be translated to their uncompressed equivalent

Deferred goals include:

* 32 bit semantics for isa extensions
* isa extensions tuned for small RISCV microcontrollers
* precise emulator support for user pcode operations
* decompiler type inference from user pcode operations
* precise 16 bit floating point support in the decompiler and emulator
* exception handling due to alignment or floating point format errors

### Testing

There is little RISCV test infrastructure currently within Ghidra.  This complicates community-driven
pull request evaluation, as we can't easily prove an absence of regressions with each new pull request.

We can start the process by adding processor-specific tests to `Ghidra/Features/Decompiler/src/decompile/unittests`
and `Ghidra/Features/Decompiler/src/decompile/datatests`.  The `unittests` directory should hold
tests to verify the supported RISCV processor/language definitions are loaded and key user pcode operations are defined.
The `datatests` directory holds binary instruction snippets to be decompiled, along with key strings as they must
appear in the decompiler view.

Basic combinations of RISCV architecture, extensions, and generated code are listed below.


| Language | Data Test | Architecture | Notes |
| ------------------ | --------- | ---------- | ----- |
| RISCV:LE:64:RV64GC | `riscv_isaext_memcpy` | rv64gcv | Minimal test of 64 bit vectorized memcpy |

Pre-commit testing should include something like:

```console
$ cd Ghidra/Features/Decompiler/src/decompile/cpp
$ make ghidra_test_dbg
$ ./ghidra_test_dbg datatests riscv_isaext_memcpy.xml

Success -- vsetvli
Success -- vle8
Success -- vse8

Total tests applied = 3
Total passing tests = 3
```

>TODO: The sleigh language `RISCV:LE:64:RV64GC` needs a better name, as it
>      includes many standard-tracked extensions beyond those explicitly named
>      by the `GC` suffix.
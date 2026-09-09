# Source manifest for the standalone CMake build of the decompiler.
#
# The lists mirror the variable blocks in ../Makefile (CORE, DECCORE, SLEIGH,
# GHIDRA, SLACOMP, SPECIAL) and the EXTRA set the Makefile computes as
# "every other *.cc".  CheckMakefileManifest.cmake compares these lists with
# the Makefile, so a source added upstream shows up as a configure error
# instead of a silent link failure.
#
# This file is included both by CMakeLists.txt and by the script-mode
# manifest check.  It must only set variables.

# CORE: used by every build.
set(GHIDRA_DECOMP_CORE_SOURCES
  xml marshal space float address pcoderaw translate opcodes globalcontext
)

# DECCORE, split so the four translation units that the Makefile's
# LIBSLA_NAMES also needs can go into the `sla` archive.
set(GHIDRA_DECOMP_LIBSLA_DECCORE_SOURCES
  loadimage memstate emulate opbehavior
)
set(GHIDRA_DECOMP_DECCORE_SOURCES
  capability architecture options graph cover block cast typeop database cpool
  comment stringmanage modelrules fspec action grammar varnode op type
  variable varmap jumptable emulateutil flow userop expression multiprecision
  funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject
  heritage prefersplit rangeutil ruleaction subflow blockaction merge double
  transform constseq bitfield coreaction condexe override dynamic crc32 prettyprint
  printlanguage printc printjava paramid signature
)

# SLEIGH: the disassembler and p-code generator.
set(GHIDRA_DECOMP_SLEIGH_SOURCES
  sleigh pcodeparse pcodecompile sleighbase slghsymbol
  slghpatexpress slghpattern semantics context slaformat compression filemanage
)

# GHIDRA: the JVM-facing process.  Listed for the manifest check only.
# Never compiled here: ghidra_process.cc installs a SIGSEGV handler that
# exits the process.
set(GHIDRA_DECOMP_GHIDRA_SOURCES
  ghidra_arch inject_ghidra ghidra_translate loadimage_ghidra
  typegrp_ghidra database_ghidra ghidra_context cpool_ghidra
  ghidra_process comment_ghidra string_ghidra signature_ghidra
)

# SLACOMP: the SLEIGH compiler.
set(GHIDRA_DECOMP_SLACOMP_SOURCES
  slgh_compile slghparse slghscan
)

# SPECIAL: programs, not library members.
set(GHIDRA_DECOMP_SPECIAL_SOURCES
  consolemain sleighexample test
)

# EXTRA, partitioned by what each translation unit needs.
# Always part of the decompiler library.
set(GHIDRA_DECOMP_EXTRA_BASE_SOURCES
  inject_sleigh libdecomp loadimage_xml raw_arch sleigh_arch xml_arch
)
# Console (command line interface) support.  decomp_console and decomp_test
# need these.
set(GHIDRA_DECOMP_EXTRA_CONSOLE_SOURCES
  callgraph ifacedecomp ifaceterm interface rulecompile testfunction unify
)
# Need <bfd.h>.
set(GHIDRA_DECOMP_EXTRA_BFD_SOURCES
  bfd_arch loadimage_bfd
)
# Console commands that also need <bfd.h> (both include loadimage_bfd.hh).
set(GHIDRA_DECOMP_EXTRA_BFD_CONSOLE_SOURCES
  analyzesigs codedata
)

# Full EXTRA set, for the manifest check.
set(GHIDRA_DECOMP_EXTRA_SOURCES
  ${GHIDRA_DECOMP_EXTRA_BASE_SOURCES}
  ${GHIDRA_DECOMP_EXTRA_CONSOLE_SOURCES}
  ${GHIDRA_DECOMP_EXTRA_BFD_SOURCES}
  ${GHIDRA_DECOMP_EXTRA_BFD_CONSOLE_SOURCES}
)

# Full DECCORE set, for the manifest check.
set(GHIDRA_DECOMP_DECCORE_ALL_SOURCES
  ${GHIDRA_DECOMP_DECCORE_SOURCES}
  ${GHIDRA_DECOMP_LIBSLA_DECCORE_SOURCES}
)

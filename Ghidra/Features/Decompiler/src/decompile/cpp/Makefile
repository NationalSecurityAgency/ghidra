# The C compiler
BFDHOME=/usr

MAKE_STATIC=
ARCH_TYPE=
ADDITIONAL_FLAGS=
SLEIGHVERSION=sleigh-2.1.0

EXTENSION_POINT=../../../../../../../ghidra.ext/Ghidra/Features/DecompilerExtensions/src/decompile/cpp
GHIDRA_BIN=../../../../../../../ghidra.bin

OS = $(shell uname -s)
CPU = $(shell uname -m)

ifeq ($(OS),Linux)
# Allow ARCH to be specified externally so we can build for 32-bit from a 64-bit Linux
ifndef ARCH
  ARCH=$(CPU)
endif
ifeq ($(ARCH),x86_64)
  ARCH_TYPE=-m64
  OSDIR=linux64
else
  ARCH_TYPE=-m32
  OSDIR=linux32
endif
endif

ifeq ($(OS),Darwin)
  MAKE_STATIC=
  ARCH_TYPE=-arch x86_64
  ADDITIONAL_FLAGS=-mmacosx-version-min=10.6 -w
  OSDIR=osx64
endif

CC=gcc
CXX=g++

# Debug flags
DBG_CXXFLAGS=-g -std=c++11 -Wall -Wno-sign-compare
#DBG_CXXFLAGS=-g -pg -Wall -Wno-sign-compare
#DBG_CXXFLAGS=-g -fprofile-arcs -ftest-coverage -Wall -Wno-sign-compare

# Optimization flags
OPT_CXXFLAGS=-O2 -std=c++11 -Wall -Wno-sign-compare

YACC=bison

# libraries
#INCLUDES=-I$(BFDHOME)/include
INCLUDES=
BFDLIB=-lbfd -lz

LNK=

# Source files
ALL_SOURCE= $(wildcard *.cc)
ALL_NAMES=$(subst .cc,,$(ALL_SOURCE))
UNITTEST_SOURCE= $(wildcard ../unittests/*.cc)
UNITTEST_NAMES=$(subst .cc,,$(UNITTEST_SOURCE))
UNITTEST_STRIP=$(subst ../unittests/,,$(UNITTEST_NAMES))

COREEXT_SOURCE= $(wildcard coreext_*.cc)
COREEXT_NAMES=$(subst .cc,,$(COREEXT_SOURCE))

GHIDRAEXT_SOURCE= $(wildcard ghidraext_*.cc)
GHIDRAEXT_NAMES=$(subst .cc,,$(GHIDRAEXT_SOURCE))

EXTERNAL_COREEXT_SOURCE= $(wildcard $(EXTENSION_POINT)/coreext_*.cc)
EXTERNAL_GHIDRAEXT_SOURCE= $(wildcard $(EXTENSION_POINT)/ghidraext_*.cc)
EXTERNAL_CONSOLEEXT_SOURCE= $(wildcard $(EXTENSION_POINT)/consoleext_*.cc)
EXTERNAL_COREEXT_NAMES=$(subst .cc,,$(notdir $(EXTERNAL_COREEXT_SOURCE)))
EXTERNAL_GHIDRAEXT_NAMES=$(subst .cc,,$(notdir $(EXTERNAL_GHIDRAEXT_SOURCE)))
EXTERNAL_CONSOLEEXT_NAMES=$(subst .cc,,$(notdir $(EXTERNAL_CONSOLEEXT_SOURCE)))

# The following macros partition all the source files, there should be no overlaps
# Some core source files used in all projects
CORE=	xml space float address pcoderaw translate opcodes globalcontext
# Additional core files for any projects that decompile
DECCORE=capability architecture options graph cover block cast typeop database cpool \
	comment stringmanage fspec action loadimage grammar varnode op \
	type variable varmap jumptable emulate emulateutil flow userop \
	funcdata funcdata_block funcdata_op funcdata_varnode pcodeinject \
	heritage prefersplit rangeutil ruleaction subflow blockaction merge double \
	transform coreaction condexe override dynamic crc32 prettyprint \
	printlanguage printc printjava memstate opbehavior paramid $(COREEXT_NAMES)
# Files used for any project that use the sleigh decoder
SLEIGH=	sleigh pcodeparse pcodecompile sleighbase slghsymbol \
	slghpatexpress slghpattern semantics context filemanage
# Additional files for the GHIDRA specific build
GHIDRA=	ghidra_arch inject_ghidra ghidra_translate loadimage_ghidra \
	typegrp_ghidra database_ghidra ghidra_context cpool_ghidra \
	ghidra_process comment_ghidra string_ghidra $(GHIDRAEXT_NAMES)
# Additional files specific to the sleigh compiler
SLACOMP=slgh_compile slghparse slghscan
# Additional special files that should not be considered part of the library
SPECIAL=consolemain sleighexample test testfunction
# Any additional modules for the command line decompiler
EXTRA= $(filter-out $(CORE) $(DECCORE) $(SLEIGH) $(GHIDRA) $(SLACOMP) $(SPECIAL),$(ALL_NAMES))

EXECS=decomp_dbg decomp_opt ghidra_test_dbg ghidra_dbg ghidra_opt sleigh_dbg sleigh_opt libdecomp_dbg.a libdecomp.a

# Possible conditional compilation flags
#     __TERMINAL__             # Turn on terminal support for console mode
#     CPUI_STATISTICS          # Turn on collection of cover and cast statistics
#     CPUI_RULECOMPILE         # Allow user defined dynamic rules

# Debug compilation flags
#     OPACTION_DEBUG           # Turns on all the action tracing facilities
#     MERGEMULTI_DEBUG         # Check for MULTIEQUAL and INDIRECT intersections
#     BLOCKCONSISTENT_DEBUG    # Check that block graph structure is consistent
#     DFSVERIFY_DEBUG          # make sure that the block ordering algorithm produces
#                                a true depth first traversal of the dominator tree
#     CPUI_DEBUG               # This is the one controlling switch for all the other debug switches

COMMANDLINE_NAMES=$(CORE) $(DECCORE) $(EXTRA) $(SLEIGH) consolemain
COMMANDLINE_DEBUG=-DCPUI_DEBUG -D__TERMINAL__
COMMANDLINE_OPT=-D__TERMINAL__

TEST_NAMES=$(CORE) $(DECCORE) $(SLEIGH) $(EXTRA) testfunction test 
TEST_DEBUG=-D__TERMINAL__

GHIDRA_NAMES=$(CORE) $(DECCORE) $(GHIDRA)
GHIDRA_NAMES_DBG=$(GHIDRA_NAMES) callgraph ifacedecomp ifaceterm interface
GHIDRA_DEBUG=-DCPUI_DEBUG
GHIDRA_OPT=

SLEIGH_NAMES=$(CORE) $(SLEIGH) $(SLACOMP)
SLEIGH_DEBUG=-DYYDEBUG
SLEIGH_OPT=

# The SLEIGH library is built with console mode objects and it
# uses the COMMANDLINE_* options
LIBSLA_NAMES=$(CORE) $(SLEIGH) loadimage sleigh memstate emulate opbehavior

# The Decompiler library is built with console mode objects and it uses the COMMANDLINE_* options
LIBDECOMP_NAMES=$(CORE) $(DECCORE) $(EXTRA) $(SLEIGH)

# object file macros
COMMANDLINE_DBG_OBJS=$(COMMANDLINE_NAMES:%=com_dbg/%.o)
COMMANDLINE_OPT_OBJS=$(COMMANDLINE_NAMES:%=com_opt/%.o)
TEST_DEBUG_OBJS=$(TEST_NAMES:%=test_dbg/%.o) $(UNITTEST_STRIP:%=test_dbg/%.o)
GHIDRA_DBG_OBJS=$(GHIDRA_NAMES_DBG:%=ghi_dbg/%.o)
GHIDRA_OPT_OBJS=$(GHIDRA_NAMES:%=ghi_opt/%.o)
SLEIGH_DBG_OBJS=$(SLEIGH_NAMES:%=sla_dbg/%.o)
SLEIGH_OPT_OBJS=$(SLEIGH_NAMES:%=sla_opt/%.o)
LIBSLA_DBG_OBJS=$(LIBSLA_NAMES:%=com_dbg/%.o)
LIBSLA_OPT_OBJS=$(LIBSLA_NAMES:%=com_opt/%.o)
LIBSLA_SOURCE=$(LIBSLA_NAMES:%=%.cc) $(LIBSLA_NAMES:%=%.hh) \
	$(SLACOMP:%=%.cc) slgh_compile.hh slghparse.hh types.h \
	partmap.hh error.hh slghparse.y pcodeparse.y xml.y slghscan.l loadimage_bfd.hh loadimage_bfd.cc
LIBDECOMP_DBG_OBJS=$(LIBDECOMP_NAMES:%=com_dbg/%.o)
LIBDECOMP_OPT_OBJS=$(LIBDECOMP_NAMES:%=com_opt/%.o)

# conditionals to determine which dependency files to build
DEPNAMES=com_dbg/depend com_opt/depend
ifeq ($(MAKECMDGOALS),install_ghidraopt)
	DEPNAMES=ghi_opt/depend
endif
ifeq ($(MAKECMDGOALS),install_ghidradbg)
	DEPNAMES=ghi_dbg/depend
endif
ifeq ($(MAKECMDGOALS),ghidra_opt)
	DEPNAMES=ghi_opt/depend
endif
ifeq ($(MAKECMDGOALS),ghidra_opt_mac)
	DEPNAMES=ghi_opt/depend
endif
ifeq ($(MAKECMDGOALS),ghidra_dbg)
	DEPNAMES=ghi_dbg/depend
endif
ifeq ($(MAKECMDGOALS),sleigh_opt)
	DEPNAMES=sla_opt/depend
endif
ifeq ($(MAKECMDGOALS),sleigh_opt_mac)
	DEPNAMES=sla_opt/depend
endif
ifeq ($(MAKECMDGOALS),sleigh_dbg)
	DEPNAMES=sla_dbg/depend
endif
ifeq ($(MAKECMDGOALS),libsla.a)
	DEPNAMES=com_opt/depend.lib_sla
endif
ifeq ($(MAKECMDGOALS),libsla_dbg.a)
	DEPNAMES=com_dbg/depend.lib_sla
endif
ifeq ($(MAKECMDGOALS),decomp_dbg)
	DEPNAMES=com_dbg/depend
endif
ifeq ($(MAKECMDGOALS),decomp_opt)
	DEPNAMES=com_opt/depend
endif
ifneq (,$(filter $(MAKECMDGOALS),ghidra_test_dbg test))
	DEPNAMES=test_dbg/depend
endif
ifeq ($(MAKECMDGOALS),reallyclean)
	DEPNAMES=
endif
ifeq ($(MAKECMDGOALS),clean)
	DEPNAMES=
endif
ifeq ($(MAKECMDGOALS),doc)
	DEPNAMES=
endif
ifeq ($(MAKECMDGOALS),tags)
	DEPNAMES=
endif
ifeq ($(MAKECMDGOALS),link_extensions)
	DEPNAMES=
endif
ifeq ($(MAKECMDGOALS),link_extensions_hard)
	DEPNAMES=
endif

com_dbg/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(COMMANDLINE_DEBUG) $< -o $@
com_opt/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(OPT_CXXFLAGS) $(ADDITIONAL_FLAGS) $(COMMANDLINE_OPT)   $< -o $@
test_dbg/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(TEST_DEBUG)        $< -o $@
test_dbg/%.o:	../unittests/%.cc
	$(CXX) -I. $(ARCH_TYPE) -c $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(TEST_DEBUG)        $< -o $@
ghi_dbg/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(GHIDRA_DEBUG)      $< -o $@
ghi_opt/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(OPT_CXXFLAGS) $(ADDITIONAL_FLAGS) $(GHIDRA_OPT)        $< -o $@
sla_dbg/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(SLEIGH_DEBUG)      $< -o $@
sla_opt/%.o:	%.cc
	$(CXX) $(ARCH_TYPE) -c $(OPT_CXXFLAGS) $(ADDITIONAL_FLAGS) $(SLEIGH_OPT)        $< -o $@

grammar.cc:	grammar.y
	$(YACC) -p cparse -o $@ $<
xml.cc:	xml.y
	$(YACC) -p xml -o $@ $<
pcodeparse.cc:	pcodeparse.y
	$(YACC) -p pcode -o $@ $<
slghparse.cc:	slghparse.y
	$(YACC) -d -o $@ $<
slghscan.cc:	slghscan.l
	$(LEX) -o$@ $<
ruleparse.cc:	ruleparse.y
	$(YACC) -p ruleparse -d -o $@ $<

slghparse.hh:	slghparse.y slghparse.cc
slghscan.cc:	slghparse.hh slgh_compile.hh
ruleparse.hh:	ruleparse.y ruleparse.cc

decomp_dbg:	$(COMMANDLINE_DBG_OBJS)
	$(CXX) $(DBG_CXXFLAGS) $(ARCH_TYPE) -o decomp_dbg $(COMMANDLINE_DBG_OBJS) $(BFDLIB) $(LNK)

decomp_opt:	$(COMMANDLINE_OPT_OBJS)
	$(CXX) $(OPT_CXXFLAGS) $(ARCH_TYPE) -o decomp_opt $(COMMANDLINE_OPT_OBJS) $(BFDLIB) $(LNK)

ghidra_test_dbg:	$(TEST_DEBUG_OBJS)
	$(CXX) $(DBG_CXXFLAGS) $(ARCH_TYPE) -o ghidra_test_dbg $(TEST_DEBUG_OBJS) $(BFDLIB) $(LNK)

test: ghidra_test_dbg
	./ghidra_test_dbg

ghidra_dbg:	$(GHIDRA_DBG_OBJS)
	$(CXX) $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(MAKE_STATIC) $(ARCH_TYPE) -o ghidra_dbg $(GHIDRA_DBG_OBJS) $(LNK)

ghidra_opt:	$(GHIDRA_OPT_OBJS)
	$(CXX) $(OPT_CXXFLAGS) $(ADDITIONAL_FLAGS) $(MAKE_STATIC) $(ARCH_TYPE)  -o ghidra_opt $(GHIDRA_OPT_OBJS) $(LNK)

sleigh_dbg:	$(SLEIGH_DBG_OBJS)
	$(CXX) $(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS) $(MAKE_STATIC) $(ARCH_TYPE) -o sleigh_dbg $(SLEIGH_DBG_OBJS) $(LNK)

sleigh_opt:	$(SLEIGH_OPT_OBJS)
	$(CXX) $(OPT_CXXFLAGS) $(ADDITIONAL_FLAGS) $(MAKE_STATIC) $(ARCH_TYPE) -o sleigh_opt $(SLEIGH_OPT_OBJS) $(LNK)

install_ghidradbg:	ghidra_dbg
	cp ghidra_dbg $(GHIDRA_BIN)/Ghidra/Features/Decompiler/os/$(OSDIR)/decompile

install_ghidraopt:	ghidra_opt
	cp ghidra_opt $(GHIDRA_BIN)/Ghidra/Features/Decompiler/os/$(OSDIR)/decompile

libsla_dbg.a:	$(LIBSLA_DBG_OBJS)
	rm -rf libsla_dbg.a
	ar qc libsla_dbg.a $(LIBSLA_DBG_OBJS)
	ranlib libsla_dbg.a

libsla.a:	$(LIBSLA_OPT_OBJS)
	rm -rf libsla.a
	ar qc libsla.a $(LIBSLA_OPT_OBJS)
	ranlib libsla.a

libdecomp_dbg.a:	$(LIBDECOMP_DBG_OBJS)
	rm -rf libdecomp_dbg.a
	ar qc libdecomp_dbg.a $(LIBDECOMP_DBG_OBJS)
	ranlib libdecomp_dbg.a

libdecomp.a:	$(LIBDECOMP_OPT_OBJS)
	rm -rf libdecomp.a
	ar qc libdecomp.a $(LIBDECOMP_OPT_OBJS)
	ranlib libdecomp.a

sleighexamp_dir:
	rm -rf $(SLEIGHVERSION)
	mkdir $(SLEIGHVERSION)
	mkdir $(SLEIGHVERSION)/src $(SLEIGHVERSION)/specfiles
	cp ../../../../../Processors/x86/data/languages/x86.sla \
	  ../../../../../Processors/x86/data/languages/x86.slaspec \
	  ../../../../../Processors/x86/data/languages/ia.sinc \
		 $(SLEIGHVERSION)/specfiles
	cp $(LIBSLA_SOURCE) Makefile Doxyfile $(SLEIGHVERSION)/src
	cp sleighexample.cc $(SLEIGHVERSION)
	grep ^-- sleighexample.cc | sed -e s/--// > $(SLEIGHVERSION)/Makefile
	grep ^-a- sleighexample.cc | sed -e s/-a-// > $(SLEIGHVERSION)/README
	sed -e s/page\ sleigh\ /mainpage\ / < $(SLEIGHVERSION)/src/sleigh.hh > $(SLEIGHVERSION)/spam
	mv $(SLEIGHVERSION)/spam $(SLEIGHVERSION)/src/sleigh.hh
	cd $(SLEIGHVERSION)/src; doxygen Doxyfile

link_extensions:
	rm -rf coreext_*.cc coreext_*.hh ghidraext_*.cc ghidraext_*.hh consoleext_*.cc consoleext_*.hh
	for i in $(EXTERNAL_COREEXT_NAMES) $(EXTERNAL_GHIDRAEXT_NAMES) $(EXTERNAL_CONSOLEEXT_NAMES); do \
		ln -s $(EXTENSION_POINT)/$$i.cc $$i.cc; \
		ln -s $(EXTENSION_POINT)/$$i.hh $$i.hh; \
	done

link_extensions_hard:
	rm -rf coreext_*.cc coreext_*.hh ghidraext_*.cc ghidraext_*.hh consoleext_*.cc consoleext_*.hh
	for i in $(EXTERNAL_COREEXT_NAMES) $(EXTERNAL_GHIDRAEXT_NAMES) $(EXTERNAL_CONSOLEEXT_NAMES); do \
		ln $(EXTENSION_POINT)/$$i.cc $$i.cc; \
		ln $(EXTENSION_POINT)/$$i.hh $$i.hh; \
	done

tags:
	etags *.c *.h *.cc *.hh

# Rules to build the different dependency files
com_dbg/depend:	$(COMMANDLINE_NAMES:%=%.cc)
	mkdir -p com_dbg 
	@set -e; rm -f $@; \
	$(CXX) -MM $(COMMANDLINE_DEBUG) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,com_dbg/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

com_opt/depend:	$(COMMANDLINE_NAMES:%=%.cc)
	mkdir -p com_opt
	@set -e; rm -f $@; \
	$(CXX) -MM $(COMMANDLINE_OPT) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,com_opt/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

test_dbg/depend:	$(TEST_NAMES:%=%.cc) $(UNITTEST_NAMES:%=%.cc)
	mkdir -p test_dbg
	@set -e; rm -f $@; \
	$(CXX) -I. -MM $(TEST_DEBUG) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,test_dbg/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

ghi_dbg/depend:	$(GHIDRA_NAMES_DBG:%=%.cc)
	mkdir -p ghi_dbg
	@set -e; rm -f $@; \
	$(CXX) -MM $(GHIDRA_DEBUG) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,ghi_dbg/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

ghi_opt/depend:	$(GHIDRA_NAMES:%=%.cc)
	mkdir -p ghi_opt 
	@set -e; rm -f $@; \
	$(CXX) -MM $(GHIDRA_OPT) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,ghi_opt/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

sla_dbg/depend:	$(SLEIGH_NAMES:%=%.cc)
	mkdir -p sla_dbg
	@set -e; rm -f $@; \
	$(CXX) -MM $(SLEIGH_DEBUG) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,sla_dbg/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

sla_opt/depend:	$(SLEIGH_NAMES:%=%.cc)
	mkdir -p sla_opt
	@set -e; rm -f $@; \
	$(CXX) -MM $(SLEIGH_OPT) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,sla_opt/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

com_opt/depend.lib_sla:	$(LIBSLA_NAMES:%=%.cc)
	mkdir -p com_opt
	@set -e; rm -f $@; \
	$(CXX) -MM $(COMMANDLINE_OPT) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,com_opt/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

com_dbg/depend.lib_sla:	$(LIBSLA_NAMES:%=%.cc)
	mkdir -p com_dbg
	@set -e; rm -f $@; \
	$(CXX) -MM $(COMMANDLINE_DEBUG) $^ > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,com_dbg/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

include $(DEPNAMES)

doc:
	doxygen Doxyfile

clean:
	rm -f com_dbg/*.o com_opt/*.o test_dbg/*.o ghi_dbg/*.o ghi_opt/*.o sla_dbg/*.o sla_opt/*.o
	rm -f *.gcov com_dbg/*.gcno com_dbg/*.gcda

resetgcov:
	rm -f *.gcov com_dbg/*.gcda

reallyclean:	clean	
	rm -rf coreext_*.cc coreext_*.hh ghidraext_*.cc ghidraext_*.hh consoleext_*.cc consoleext_*.hh
	rm -rf com_dbg com_opt test_dbg ghi_dbg ghi_opt sla_dbg sla_opt
	rm -f $(EXECS) TAGS *~


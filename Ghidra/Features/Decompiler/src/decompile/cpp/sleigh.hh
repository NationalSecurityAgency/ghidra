/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __SLEIGH__
#define __SLEIGH__

#include "sleighbase.hh"

class LoadImage;

struct RelativeRecord {
  VarnodeData *dataptr;	// Record containing relative offset
  uintb calling_index;		// Index of instruction containing relative offset
};

struct PcodeData { // Data for building one pcode instruction
  OpCode opc;
  VarnodeData *outvar;	     // Points to outvar is there is an output
  VarnodeData *invar;		// Inputs
  int4 isize;			// Number of inputs
};

class PcodeCacher { // Cached chunk of pcode, prior to emitting
  VarnodeData *poolstart;
  VarnodeData *curpool;
  VarnodeData *endpool;
  vector<PcodeData> issued;
  list<RelativeRecord> label_refs; // References to labels
  vector<uintb> labels;		// Locations of labels
  VarnodeData *expandPool(uint4 size);
public:
  PcodeCacher(void);
  ~PcodeCacher(void);
  VarnodeData *allocateVarnodes(uint4 size) {
    VarnodeData *newptr = curpool + size;
    if (newptr <= endpool) {
      VarnodeData *res = curpool;
      curpool = newptr;
      return res;
    }
    return expandPool(size);
  }
  PcodeData *allocateInstruction(void) {
    issued.emplace_back();
    PcodeData *res = &issued.back();
    res->outvar = (VarnodeData *)0;
    res->invar = (VarnodeData *)0;
    return res;
  }
  void addLabelRef(VarnodeData *ptr);
  void addLabel(uint4 id);
  void clear(void);
  void resolveRelatives(void);
  void emit(const Address &addr,PcodeEmit *emt) const;
};

class DisassemblyCache {
  ContextCache *contextcache;
  AddrSpace *constspace;
  int4 minimumreuse;		// Can call getParserContext this many times, before a ParserContext is reused
  uint4 mask;			// Size of the hashtable in form 2^n-1
  ParserContext **list;		// (circular) array of currently cached ParserContext objects
  int4 nextfree;		// Current end/beginning of circular list
  ParserContext **hashtable;	// Hashtable for looking up ParserContext via Address
  void initialize(int4 min,int4 hashsize);
  void free(void);
public:
  DisassemblyCache(ContextCache *ccache,AddrSpace *cspace,int4 cachesize,int4 windowsize);
  ~DisassemblyCache(void) { free(); }
  ParserContext *getParserContext(const Address &addr);
};

class SleighBuilder : public PcodeBuilder {
  virtual void dump( OpTpl *op );
  AddrSpace *const_space;
  AddrSpace *uniq_space;
  uintb uniquemask;
  uintb uniqueoffset;
  DisassemblyCache *discache;
  PcodeCacher *cache;
  void buildEmpty(Constructor *ct,int4 secnum);
  void generateLocation(const VarnodeTpl *vntpl,VarnodeData &vn);
  AddrSpace *generatePointer(const VarnodeTpl *vntpl,VarnodeData &vn);
  void setUniqueOffset(const Address &addr);
public:
  SleighBuilder(ParserWalker *w,DisassemblyCache *dcache,PcodeCacher *pc,AddrSpace *cspc,AddrSpace *uspc,uint4 umask);
  virtual void appendBuild(OpTpl *bld,int4 secnum);
  virtual void delaySlot(OpTpl *op);
  virtual void setLabel(OpTpl *op);
  virtual void appendCrossBuild(OpTpl *bld,int4 secnum);
};

class Sleigh : public SleighBase {
  LoadImage *loader;
  ContextDatabase *context_db;
  ContextCache *cache;
  mutable DisassemblyCache *discache;
  mutable PcodeCacher pcode_cache;
  void clearForDelete(void);
protected:
  ParserContext *obtainContext(const Address &addr,int4 state) const;
  void resolve(ParserContext &pos) const;
  void resolveHandles(ParserContext &pos) const;
public:
  Sleigh(LoadImage *ld,ContextDatabase *c_db);
  virtual ~Sleigh(void);
  void reset(LoadImage *ld,ContextDatabase *c_db);
  virtual void initialize(DocumentStorage &store);
  virtual void registerContext(const string &name,int4 sbit,int4 ebit);
  virtual void setContextDefault(const string &nm,uintm val);
  virtual void allowContextSet(bool val) const;
  virtual int4 instructionLength(const Address &baseaddr) const;
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const;
  virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const;
};

/** \page sleigh SLEIGH

  \section sleightoc Table of Contents

    - \ref sleighoverview
    - \ref sleighbuild
    - \ref sleighuse
    - \subpage sleighAPIbasic
    - \subpage sleighAPIemulate

  \b Key \b Classes
    - \ref Translate
    - \ref AssemblyEmit
    - \ref PcodeEmit
    - \ref LoadImage
    - \ref ContextDatabase

  \section sleighoverview Overview

  Welcome to \b SLEIGH, a machine language translation and
  dissassembly engine.  SLEIGH is both a processor
  specification language and the associated library and
  tools for using such a specification to generate assembly
  and to generate \b pcode, a reverse engineering Register
  Transfer Language (RTL), from binary machine instructions.
  
  SLEIGH was originally based on \b SLED, a
  \e Specification \e Language \e for \e Encoding \e and
  \e Decoding, designed by Norman Ramsey and Mary F. Fernandez,
  which performed disassembly (and assembly).  SLEIGH
  extends SLED by providing semantic descriptions (via the
  RTL) of machine instructions and other practical enhancements
  for doing real world reverse engineering. 

  SLEIGH is part of Project \b GHIDRA. It provides the core
  of the GHIDRA disassembler and the data-flow and
  decompilation analysis.  However, SLEIGH can serve as a
  standalone library for use in other applications for
  providing a generic disassembly and RTL translation interface.

  \section sleighbuild Building SLEIGH

  There are a couple of \e make targets for building the SLEIGH
  library from source.  These are:

  \code
     make libsla.a               # Build the main library

     make libsla_dbg.a           # Build the library with debug symbols
  \endcode

  The source code file \e sleighexample.cc has a complete example
  of initializing the Translate engine and using it to generate
  assembly and pcode.  The source has a hard-coded file name,
  \e x86testcode, as the example binary executable it attempts
  to decode, but this can easily be changed.  It also needs
  a SLEIGH specification file (\e .sla) to be present.

  Building the example application can be done with something
  similar to the following makefile fragment.

  \code
    # The C compiler
    CXX=g++

    # Debug flags
    DBG_CXXFLAGS=-g -Wall -Wno-sign-compare

    OPT_CXXFLAGS=-O2 -Wall -Wno-sign-compare

    # libraries
    INCLUDES=-I./src

    LNK=src/libsla_dbg.a

    sleighexample.o:      sleighexample.cc
          $(CXX) -c $(DBG_CXXFLAGS) -o sleighexample sleighexample.o $(LNK)
  
    clean:
          rm -rf *.o sleighexample
  \endcode

  \section sleighuse Using SLEIGH

  SLEIGH is a generic reverse engineering tool in the sense
  that the API is designed to be completely processor
  independent.  In order to process binary executables for a
  specific processor, The library reads in a \e
  specification \e file, which describes how instructions
  are encoded and how they are interpreted by the processor.
  An application which needs to do disassembly or generate
  \b pcode can design to the SLEIGH API once, and then the
  application will automatically support any processor for
  which there is a specification.
  
  For working with a single processor, the SLEIGH library
  needs to load a single \e compiled form of the processor
  specification, which is traditionally given a ".sla" suffix.
  Most common processors already have a ".sla" file available.
  So to use SLEIGH with these processors, the library merely
  needs to be made aware of the desired file.  This documentation
  covers the use of the SLEIGH API, assuming that this
  specification file is available.

  The ".sla" files themselves are created by running
  the \e compiler on a file written in the formal SLEIGH
  language.  These files traditionally have the suffix ".slaspec"
  For those who want to design such a specification for a new
  processor, please refer to the document, "SLEIGH: A Language
  for Rapid Processor Specification."

 */

 /**
  \page sleighAPIbasic The Basic SLEIGH Interface

  To use SLEIGH as a library within an application, there
  are basically five classes that you need to be aware of.

    - \ref sleightranslate
    - \ref sleighassememit
    - \ref sleighpcodeemit
    - \ref sleighloadimage
    - \ref sleighcontext
      
  \section sleightranslate Translate (or Sleigh)

  The core SLEIGH class is Sleigh, which is derived from the
  interface, Translate.  In order to instantiate it in your code,
  you need a LoadImage object, and a ContextDatabase object.
  The load image is responsible for retrieving instruction
  bytes, based on address, from a binary executable. The context
  database provides the library extra mode information that may
  be necessary to do the disassembly or translation.  This can
  be used, for instance, to specify that an x86 binary is running
  in 32-bit mode, or to specify that an ARM processor is running
  in THUMB mode.  Once these objects are built, the Sleigh
  object can be immediately instantiated.

  \code
  LoadImageBfd *loader;
  ContextDatabase *context;
  Translate *trans;

  // Set up the loadimage
  // Providing an executable name and architecture
  string loadimagename = "x86testcode";
  string bfdtarget= "default";

  loader = new LoadImageBfd(loadimagename,bfdtarget);
  loader->open();       // Load the executable from file

  context = new ContextInternal();   // Create a processor context

  trans = new Sleigh(loader,context);  // Instantiate the translator
  \endcode

  Once the Sleigh object is in hand, the only required
  initialization step left is to inform it of the ".sla" file.
  The file is in XML format and needs to be read in using
  SLEIGH's built-in XML parser. The following code accomplishes
  this.

  \code
  string sleighfilename = "specfiles/x86.sla";
  DocumentStorage docstorage;
  Element *sleighroot = docstorage.openDocument(sleighfilename)->getRoot();
  docstorage.registerTag(sleighroot);
  trans->initialize(docstorage);  // Initialize the translator
  \endcode

  \section sleighassememit AssemblyEmit

  In order to do disassembly, you need to derive a class from
  AssemblyEmit, and implement the method \e dump.  The library
  will call this method exactly once, for each instruction
  disassembled.

  This routine simply needs to decide how (and where) to print
  the corresponding portion of the disassembly.  For instance,

  \code
  class AssemblyRaw : public AssemblyEmit {
  public:
    virtual void dump(const Address &addr,const string &mnem,const string &body) {
      addr.printRaw(cout);
      cout << ": " << mnem << ' ' << body << endl;
    }
  };
  \endcode

  This is a minimal implementation that simply dumps the
  disassembly straight to standard out.  Once this object is
  instantiated, the Sleigh object can use it to write out
  assembly via the Translate::printAssembly() method.

  \code
  AssemblyEmit *assememit = new AssemblyRaw();

  Address addr(trans->getDefaultCodeSpace(),0x80484c0);
  int4 length;                  // Length of instruction in bytes

  length = trans->printAssembly(*assememit,addr);
  addr = addr + length;        // Advance to next instruction
  length = trans->printAssembly(*assememit,addr);
  addr = addr + length;
  length = trans->printAssembly(*assememit,addr);
  \endcode

  \section sleighpcodeemit PcodeEmit

  In order to generate a \b pcode translation of a machine
  instruction, you need to derive a class from PcodeEmit and
  implement the virtual method \e dump. This method will be
  invoked once for each \b pcode operation in the translation
  of a machine instruction.  There will likely be multiple calls
  per instruction.  Each call passes in a single \b pcode
  operation, complete with its possible varnode output, and
  all of its varnode inputs.  Here is an example of a PcodeEmit
  object that simply prints out the \b pcode.

  \code
  class PcodeRawOut : public PcodeEmit {
  public:
    virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize);
  };

  static void print_vardata(ostream &s,VarnodeData &data)

  {
    s << '(' << data.space->getName() << ',';
    data.space->printOffset(s,data.offset);
    s << ',' << dec << data.size << ')';
  }

  void PcodeRawOut::dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize)

  {
    if (outvar != (VarnodeData *)0) {     // The output is optional
      print_vardata(cout,*outvar);
      cout << " = ";
    }
    cout << get_opname(opc);
    // Possibly check for a code reference or a space reference
    for(int4 i=0;i<isize;++i) {
      cout << ' ';
      print_vardata(cout,vars[i]);
    }
    cout << endl;
  }
  \endcode

  Notice that the \e dump routine uses the built-in function
  \e get_opname to find a string version of the opcode.  Each
  varnode is defined in terms of the VarnodeData object, which
  is defined simply:

  \code
  struct VarnodeData {
    AddrSpace *space;          // The address space
    uintb offset;              // The offset within the space
    uint4 size;                // The number of bytes at that location
  };
  \endcode

  Once the PcodeEmit object is instantiated, the Sleigh object can
  use it to generate pcode, one instruction at a time, using the
  Translate::oneInstruction() const method.

  \code
  PcodeEmit *pcodeemit = new PcodeRawOut();

  Address addr(trans->getDefaultCodeSpace(),0x80484c0);
  int4 length;                   // Length of instruction in bytes

  length = trans->oneInstruction(*pcodeemit,addr);
  addr = addr + length;         // Advance to next instruction
  length = trans->oneInstruction(*pcodeemit,addr);
  addr = addr + length;
  length = trans->oneInstruction(*pcodeemit,addr);
  \endcode

  For an application to properly \e follow \e flow, while translating
  machine instructions into pcode, the emitted pcode must be
  inspected for the various branch operations.

  \section sleighloadimage LoadImage

  A LoadImage holds all the binary data from an executable file
  in the format similar to how it would exist when being executed
  by a real processor.  The interface to this from SLEIGH is
  actually very simple, although it can hide a complicated
  structure.  One method does most of the work, LoadImage::loadFill().
  It takes a byte pointer, a size, and an Address. The method
  is expected to fill in the \e ptr array with \e size bytes
  taken from the load image, corresponding to the address \e addr.
  There are two more virtual methods that are required for a
  complete implementation of LoadImage, \e getArchType and
  \e adjustVma, but these do not need to be implemented fully.

  \code
  class MyLoadImage : public LoadImage {
  public:
    MyLoadImage(const string &nm) : Loadimage(nm) {}
    virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
    virtual string getArchType(void) const { return "mytype"; }
    virtual void adjustVma(long adjust) {}
  };
  \endcode

  \section sleighcontext ContextDatabase

  The ContextDatabase needs to keep track of any possible
  context variable and its value, over different address ranges.
  In most cases, you probably don't need to override the class
  yourself, but can use the built-in class, ContextInternal.
  This provides the basic functionality required and will work
  for different architectures.  What you may need to do is
  set values for certain variables, depending on the processor
  and the environment it is running in.  For instance, for
  the x86 platform, you need to set the \e addrsize and \e opsize
  bits, to indicate the processor would be running in 32-bit
  mode.  The context variables specific to a particular processor
  are established by the SLEIGH spec.  So the variables can
  only be set \e after the spec has been loaded.

  \code
    ...
    context = new ContextInternal();
    trans = new Sleigh(loader,context);
    DocumentStorage docstorage;
    Element *root = docstorage.openDocument("specfiles/x86.sla")->getRoot();
    docstorage.registerTag(root);
    trans->initialize(docstorage);

    context->setVariableDefault("addrsize",1);  // Address size is 32-bits
    context->setVariableDefault("opsize",1);    // Operand size is 32-bits
  \endcode

  
 */
#endif

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
/// \file slgh_compile.hh
/// \brief High-level control of the sleigh compilation process
#ifndef __SLGH_COMPILE_HH__
#define __SLGH_COMPILE_HH__

#include "sleighbase.hh"
#include "pcodecompile.hh"
#include "filemanage.hh"
#include <iostream>
#include <sstream>

namespace ghidra {

using std::cout;
using std::cerr;
using std::out_of_range;

/// \brief A helper class to associate a \e named Constructor section with its symbol scope
///
/// A Constructor can contain multiple named sections of p-code.  There is a \e main
/// section associated with the constructor, but other sections are possible and can
/// be accessed through the \b crossbuild directive, which allows their operations to be
/// incorporated into nearby instructions. During parsing of a SLEIGH file, \b this class
/// associates a named section with its dedicated symbol scope.
struct RtlPair {
  ConstructTpl *section;	///< A named p-code section
  SymbolScope *scope;		///< Symbol scope associated with the section
  RtlPair(void) { section = (ConstructTpl *)0; scope = (SymbolScope *)0; }	///< Construct on empty pair
  RtlPair(ConstructTpl *sec,SymbolScope *sc) { section = sec; scope = sc; }	///< Constructor
};

/// \brief A collection of \e named p-code sections for a single Constructor
///
/// A Constructor always has a \b main section of p-code (which may be empty).
/// Alternately a Constructor may define additional \e named sections of p-code.
/// Operations in these sections are emitted using the \b crossbuild directive and
/// can be incorporated into following instructions.
///
/// Internally different sections (RtlPair) are identified by index.  A
/// SectionSymbol holds the section's name and its corresponding index.
class SectionVector {
  int4 nextindex;		///< Index of the section currently being parsed.
  RtlPair main;			///< The main section
  vector<RtlPair> named;	///< Named sections accessed by index
public:
  SectionVector(ConstructTpl *rtl,SymbolScope *scope);					///< Constructor
  ConstructTpl *getMainSection(void) const { return main.section; }			///< Get the \e main section
  ConstructTpl *getNamedSection(int4 index) const { return named[index].section; }	///< Get a \e named section by index
  RtlPair getMainPair(void) const { return main; }					///< Get the \e main section/namespace pair
  RtlPair getNamedPair(int4 i) const { return named[i]; }		///< Get a \e named section/namespace pair by index
  void setNextIndex(int4 i) { nextindex = i; }				///< Set the index of the currently parsing \e named section
  int4 getMaxId(void) const { return named.size(); }			///< Get the maximum (exclusive) named section index
  void append(ConstructTpl *rtl,SymbolScope *scope);			///< Add a new \e named section
};

/// \brief Qualities associated (via parsing) with an address space
///
/// An object of this class accumulates properties of an address space as they
/// are parsed in the \b define statement prior to formally allocating the AddrSpace object.
struct SpaceQuality {
  /// \brief The type of space being defined
  enum {
    ramtype,		///< An address space representing normal, indexed, memory
    registertype	///< An address space containing registers
  };
  string name;		///< Name of the address space
  uint4 type;		///< Type of address space, \e ramtype or \e registertype
  uint4 size;		///< Number of bytes required to index all bytes of the space
  uint4 wordsize;       ///< Number of bytes in an addressable unit of the space
  bool isdefault;	///< \b true if the new address space will be the default
  SpaceQuality(const string &nm);	///< Constructor
};

/// \brief Qualities associated (via parsing) with a token or context \b field
///
/// An object of this class accumulates properties of a field as they
/// are parsed in of a \b define \b token block prior to formally allocating the
/// TokenField or FieldContext object.
struct FieldQuality {
  string name;		///< Name of the field
  uint4 low;		///< The least significant bit of the field within the token
  uint4 high;		///< The most significant bit of the field within the token
  bool signext;		///< \b true if the field's value is signed
  bool flow;		///< \b true if the context \b flows for this field.
  bool hex;		///< \b true if the field value is displayed in hex
  FieldQuality(string *nm,uintb *l,uintb *h);	///< Constructor
};

/// \brief Subtable, pattern, and context information applied across a \b with block
///
/// The header of a \b with block is applied to all constructors in the block. It
/// attaches each constructor to a specific subtable. A pattern expression and/or a
/// a series of context changes is attached to each constructor as well.
class WithBlock {
  SubtableSymbol *ss;			///< Subtable containing each Constructor (or null for root table)
  PatternEquation *pateq;		///< Pattern to prepend to each Constructor (or null)
  vector<ContextChange *> contvec;	///< Context change to associate with each constructor (or null)
public:
  WithBlock(void) { pateq = (PatternEquation *)0; }	///< Constructor
  void set(SubtableSymbol *s, PatternEquation *pq, vector<ContextChange *> *cvec);	///< Set components of the header
  ~WithBlock(void);	///< Destructor
  static PatternEquation *collectAndPrependPattern(const list<WithBlock> &stack, PatternEquation *pateq);
  static vector<ContextChange *> *collectAndPrependContext(const list<WithBlock> &stack, vector<ContextChange *> *contvec);
  static SubtableSymbol *getCurrentSubtable(const list<WithBlock> &stack);
};

class SleighCompile;

/// \brief Derive Varnode sizes and optimize p-code in SLEIGH Constructors
///
/// This class examines p-code parsed from a SLEIGH file and performs three main tasks:
///   - Enforcing size rules in Constructor p-code,
///   - Optimizing p-code within a Constructor, and
///   - Searching for other p-code validity violations
///
/// Many p-code operators require that their input and/or output operands are all the same size
/// or have other specific size restrictions on their operands.  This class enforces those requirements.
///
/// This class performs limited optimization of p-code within a Constructor by performing COPY
/// propagation through \e temporary registers.
///
/// This class searches for unnecessary truncations and extensions, temporary varnodes that are either dead,
/// read before written, or that exceed the standard allocation size.
class ConsistencyChecker {

  /// \brief Description of how a temporary register is being used within a Constructor
  ///
  /// This counts reads and writes of the register.  If the register is read only once, the
  /// particular p-code op and input slot reading it is recorded.  If the register is written
  /// only once, the particular p-code op writing it is recorded.
  struct OptimizeRecord {
    int4 writeop;		///< Index of the (last) p-code op writing to register (or -1)
    int4 readop;		///< Index of the (last) p-code op reading the register (or -1)
    int4 inslot;		///< Input slot of p-code op reading the register (or -1)
    int4 writecount;		///< Number of times the register is written
    int4 readcount;		///< Number of times the register is read
    int4 writesection;		///< Section containing (last) p-code op writing to the register (or -2)
    int4 readsection;		///< Section containing (last) p-code op reading the register (or -2)
    mutable int4 opttype;	///< 0 = register read by a COPY, 1 = register written by a COPY (-1 otherwise)

    /// \brief Construct a record, initializing counts
    OptimizeRecord(void) {
      writeop = -1; readop = -1; inslot=-1; writecount=0; readcount=0; writesection=-2; readsection=-2; opttype=-1; }
  };
  SleighCompile *compiler;	///< Parsed form of the SLEIGH file being examined
  int4 unnecessarypcode;	///< Count of unnecessary extension/truncation operations
  int4 readnowrite;		///< Count of temporary registers that are read but not written
  int4 writenoread;		///< Count of temporary registers that are written but not read
  int4 largetemp;		///< Count of temporary registers that are too large
  bool printextwarning;		///< Set to \b true if warning emitted for each unnecessary truncation/extension
  bool printdeadwarning;	///< Set to \b true if warning emitted for each written but not read temporary
  bool printlargetempwarning;	///< Set to \b true if warning emitted for each too large temporary
  SubtableSymbol *root_symbol;	///< The root symbol table for the parsed SLEIGH file
  vector<SubtableSymbol *> postorder;	///< Subtables sorted into \e post order (dependent tables listed earlier)
  map<SubtableSymbol *,int4> sizemap;	///< Sizes associated with table \e exports
  OperandSymbol *getOperandSymbol(int4 slot,OpTpl *op,Constructor *ct);
  void printOpName(ostream &s,OpTpl *op);
  void printOpError(OpTpl *op,Constructor *ct,int4 err1,int4 err2,const string &message);
  int4 recoverSize(const ConstTpl &sizeconst,Constructor *ct);
  bool checkOpMisuse(OpTpl *op,Constructor *ct);
  bool sizeRestriction(OpTpl *op,Constructor *ct);
  bool checkConstructorSection(Constructor *ct,ConstructTpl *cttpl);
  bool hasLargeTemporary(OpTpl *op);
  bool isTemporaryAndTooBig(VarnodeTpl *vn);
  bool checkVarnodeTruncation(Constructor *ct,int4 slot,OpTpl *op,VarnodeTpl *vn,bool isbigendian);
  bool checkSectionTruncations(Constructor *ct,ConstructTpl *cttpl,bool isbigendian);
  bool checkSubtable(SubtableSymbol *sym);
  void dealWithUnnecessaryExt(OpTpl *op,Constructor *ct);
  void dealWithUnnecessaryTrunc(OpTpl *op,Constructor *ct);
  void setPostOrder(SubtableSymbol *root);

  // Optimization routines
  static void examineVn(map<uintb,OptimizeRecord> &recs,const VarnodeTpl *vn,uint4 i,int4 inslot,int4 secnum);
  static bool possibleIntersection(const VarnodeTpl *vn1,const VarnodeTpl *vn2);
  bool readWriteInterference(const VarnodeTpl *vn,const OpTpl *op,bool checkread) const;
  void optimizeGather1(Constructor *ct,map<uintb,OptimizeRecord> &recs,int4 secnum) const;
  void optimizeGather2(Constructor *ct,map<uintb,OptimizeRecord> &recs,int4 secnum) const;
  const OptimizeRecord *findValidRule(Constructor *ct,const map<uintb,OptimizeRecord> &recs) const;
  void applyOptimization(Constructor *ct,const OptimizeRecord &rec);
  void checkUnusedTemps(Constructor *ct,const map<uintb,OptimizeRecord> &recs);
  void checkLargeTemporaries(Constructor *ct,ConstructTpl *ctpl);
  void optimize(Constructor *ct);
public:
  ConsistencyChecker(SleighCompile *sleigh, SubtableSymbol *rt,bool unnecessary,bool warndead, bool warnlargetemp);
  bool testSizeRestrictions(void);		///< Test size consistency of all p-code
  bool testTruncations(void);			///< Test truncation validity of all p-code
  void testLargeTemporary(void);		///< Test for temporary Varnodes that are too large
  void optimizeAll(void);			///< Do COPY propagation optimization on all p-code
  int4 getNumUnnecessaryPcode(void) const { return unnecessarypcode; }	///< Return the number of unnecessary extensions and truncations
  int4 getNumReadNoWrite(void) const { return readnowrite; }	///< Return the number of temporaries read but not written
  int4 getNumWriteNoRead(void) const { return writenoread; }	///< Return the number of temporaries written but not read
  int4 getNumLargeTemporaries(void) const {return largetemp;}	///< Return the number of \e too large temporaries
};

/// \brief Helper function holding properties of a \e context field prior to calculating the context layout
///
/// This holds the concrete Varnode reprensenting the context field's physical storage and the
/// properties of the field itself, prior to the final ContextField being allocated.
struct FieldContext {
  VarnodeSymbol *sym;		///< The concrete Varnode representing physical storage for the field
  FieldQuality *qual;		///< Qualities of the field, as parsed
  bool operator<(const FieldContext &op2) const;	///< Sort context fields based on their least significant bit boundary
  FieldContext(VarnodeSymbol *s,FieldQuality *q) { sym=s; qual=q; }	///< Constructor
};

/// \brief A class for expanding macro directives within a p-code section
///
/// It is handed a (partial) list of p-code op templates (OpTpl).  The
/// macro directive is established with the setMacroOp() method.  Then calling
/// build() expands the macro into the list of OpTpls, providing parameter
/// substitution.  The class is derived from PcodeBuilder, where the dump() method,
/// instead of emitting raw p-code, clones the macro templates into the list
/// of OpTpls.
class MacroBuilder : public PcodeBuilder {
  SleighCompile *slgh;		///< The SLEIGH parsing object
  bool haserror;		///< Set to \b true by the build() method if there was an error
  vector<OpTpl *> &outvec;	///< The partial list of op templates to expand the macro into
  vector<HandleTpl *> params;	///< List of parameters to substitute into the macro
  bool transferOp(OpTpl *op,vector<HandleTpl *> &params);
  virtual void dump( OpTpl *op );
  void free(void);						///< Free resources used by the builder
  void reportError(const Location* loc, const string &val);	///< Report error encountered expanding the macro
public:
  MacroBuilder(SleighCompile *sl,vector<OpTpl *> &ovec,uint4 lbcnt) : PcodeBuilder(lbcnt),outvec(ovec) {
    slgh = sl; haserror = false; }					///< Constructor
  void setMacroOp(OpTpl *macroop);					///< Establish the MACRO directive to expand
  bool hasError(void) const { return haserror; }			///< Return \b true if there were errors during expansion
  virtual ~MacroBuilder(void) { free(); }
  virtual void appendBuild(OpTpl *bld,int4 secnum) { dump(bld); }
  virtual void delaySlot(OpTpl *op) { dump(op); }
  virtual void setLabel(OpTpl *op);
  virtual void appendCrossBuild(OpTpl *bld,int4 secnum) { dump(bld); }
};

/// \brief Parsing for the semantic section of Constructors
///
/// This is just the base p-code compiler for building OpTpl and VarnodeTpl.
/// Symbols, locations, and error/warning messages are tied into to the main
/// parser.
class SleighPcode : public PcodeCompile {
  SleighCompile *compiler;			///< The main SLEIGH parser
  virtual uint4 allocateTemp(void);
  virtual const Location *getLocation(SleighSymbol *sym) const;
  virtual void reportError(const Location* loc, const string &msg);
  virtual void reportWarning(const Location* loc, const string &msg);
  virtual void addSymbol(SleighSymbol *sym);
public:
  SleighPcode(void) : PcodeCompile() { compiler = (SleighCompile *)0; }	///< Constructor
  void setCompiler(SleighCompile *comp) { compiler = comp; }		///< Hook in the main parser
};

/// \brief SLEIGH specification compiling
///
/// Class for parsing SLEIGH specifications (.slaspec files) and producing the
/// \e compiled form (.sla file), which can then be loaded by a SLEIGH disassembly
/// and p-code generation engine.  This full parser contains the p-code parser SleighPcode
/// within it.  The main entry point is run_compilation(), which takes the input and output
/// file paths as parameters.  Various options and preprocessor macros can be set using the
/// various set*() methods prior to calling run_compilation.
class SleighCompile : public SleighBase {
  friend class SleighPcode;
public:
  SleighPcode pcode;			///< The p-code parsing (sub)engine
private:
  map<string,string> preproc_defines;	///< Defines for the preprocessor
  vector<FieldContext> contexttable;	///< Context field definitions (prior to defining ContextField and ContextSymbol)
  vector<ConstructTpl *> macrotable;	///< SLEIGH macro definitions
  vector<Token *> tokentable;		///< SLEIGH token definitions
  vector<SubtableSymbol *> tables;	///< SLEIGH subtables
  vector<SectionSymbol *> sections;	///< Symbols defining Constructor sections
  list<WithBlock> withstack;		///< Current stack of \b with blocks
  Constructor *curct;			///< Current Constructor being defined
  MacroSymbol *curmacro;		///< Current macro being defined
  bool contextlock;			///< If the context layout has been established yet
  vector<string> relpath;		///< Relative path (to cwd) for each filename
  vector<string> filename;		///< Stack of current files being parsed
  vector<int4> lineno;			///< Current line number for each file in stack
  map<Constructor *, Location> ctorLocationMap;		///< Map each Constructor to its defining parse location
  map<SleighSymbol *, Location> symbolLocationMap;	///< Map each symbol to its defining parse location
  int4 userop_count;			///< Number of userops defined
  bool warnunnecessarypcode;		///< \b true if we warn of unnecessary ZEXT or SEXT
  bool warndeadtemps;			///< \b true if we warn of temporaries that are written but not read
  bool lenientconflicterrors;		///< \b true if we ignore most pattern conflict errors
  bool largetemporarywarning;   	///< \b true if we warn about temporaries larger than SleighBase::MAX_UNIQUE_SIZE
  bool warnalllocalcollisions;		///< \b true if local export collisions generate individual warnings
  bool warnallnops;			///< \b true if pcode NOPs generate individual warnings
  bool failinsensitivedups;		///< \b true if case insensitive register duplicates cause error
  vector<string> noplist;		///< List of individual NOP warnings
  mutable Location currentLocCache;	///< Location for (last) request of current location
  int4 errors;				///< Number of fatal errors encountered

  const Location* getCurrentLocation(void) const;	///< Get the current file and line number being parsed
  void predefinedSymbols(void);				///< Get SLEIGHs predefined address spaces and symbols
  int4 calcContextVarLayout(int4 start,int4 sz,int4 numbits);
  void buildDecisionTrees(void);			///< Build decision trees for all subtables
  void buildPatterns(void);		///< Generate final match patterns based on parse constraint equations
  void checkConsistency(void);		///< Perform final consistency checks on the SLEIGH definitions
  static int4 findCollision(map<uintb,int4> &local2Operand,const vector<uintb> &locals,int operand);
  bool checkLocalExports(Constructor *ct);	///< Check for operands that \e might export the same local variable
  void checkLocalCollisions(void);	///< Check all Constructors for local export collisions between operands
  void checkNops(void);			///< Report on all Constructors with empty semantic sections
  void checkCaseSensitivity(void);	///< Check that register names can be treated as case insensitive
  string checkSymbols(SymbolScope *scope);	///< Make sure label symbols are both defined and used
  void addSymbol(SleighSymbol *sym);	///< Add a new symbol to the current scope
  SleighSymbol *dedupSymbolList(vector<SleighSymbol *> *symlist);	///< Deduplicate the given list of symbols
  bool expandMacros(ConstructTpl *ctpl);	///< Expand any formal SLEIGH macros in the given section of p-code

  bool finalizeSections(Constructor *big,SectionVector *vec);	///< Do final checks, expansions, and linking for p-code sections
  static VarnodeTpl *findSize(const ConstTpl &offset,const ConstructTpl *ct);
  static bool forceExportSize(ConstructTpl *ct);
  static void shiftUniqueVn(VarnodeTpl *vn,int4 sa);
  static void shiftUniqueOp(OpTpl *op,int4 sa);
  static void shiftUniqueHandle(HandleTpl *hand,int4 sa);
  static void shiftUniqueConstruct(ConstructTpl *tpl,int4 sa);
  static string formatStatusMessage(const Location* loc, const string &msg);
  void checkUniqueAllocation(void);	///< Modify temporary Varnode offsets to support \b crossbuilds
  void process(void);			///< Do all post processing on the parsed data structures
public:
  SleighCompile(void);						///< Constructor
  const Location *getLocation(Constructor* ctor) const;		///< Get the source location of the given Constructor's definition
  const Location *getLocation(SleighSymbol *sym) const;		///< Get the source location of the given symbol's definition
  void reportError(const string &msg);				///< Issue a fatal error message
  void reportError(const Location *loc, const string &msg);	///< Issue a fatal error message with a source location
  void reportWarning(const string &msg);			///< Issue a warning message
  void reportWarning(const Location *loc, const string &msg);	///< Issue a warning message with a source location
  int4 numErrors(void) const { return errors; }			///< Return the current number of fatal errors

  uint4 getUniqueAddr(void);					///< Get the next available temporary register offset

  /// \brief Set whether unnecessary truncation and extension operators generate warnings individually
  ///
  /// \param val is \b true if warnings are generated individually.  The default is \b false.
  void setUnnecessaryPcodeWarning(bool val) { warnunnecessarypcode = val; }

  /// \brief Set whether dead temporary registers generate warnings individually
  ///
  /// \param val is \b true if warnings are generated individually.  The default is \b false.
  void setDeadTempWarning(bool val) { warndeadtemps = val; }

  /// \brief Set whether named temporary registers must be defined using the \b local keyword.
  ///
  /// \param val is \b true if the \b local keyword must always be used. The default is \b false.
  void setEnforceLocalKeyWord(bool val) { pcode.setEnforceLocalKey(val); }

  /// \brief Set whether too large temporary registers generate warnings individually
  ///
  /// \param val is \b true if warnings are generated individually.  The default is \b false.
  void setLargeTemporaryWarning (bool val) {largetemporarywarning = val;}

  /// \brief Set whether indistinguishable Constructor patterns generate fatal errors
  ///
  /// \param val is \b true if no error is generated.  The default is \b true.
  void setLenientConflict(bool val) { lenientconflicterrors = val; }

  /// \brief Set whether collisions in exported locals generate warnings individually
  ///
  /// \param val is \b true if warnings are generated individually.  The default is \b false.
  void setLocalCollisionWarning(bool val) { warnalllocalcollisions = val; }

  /// \brief Set whether NOP Constructors generate warnings individually
  ///
  /// \param val is \b true if warnings are generated individually.  The default is \b false.
  void setAllNopWarning(bool val) { warnallnops = val; }

  /// \brief Set whether case insensitive duplicates of register names cause an error
  ///
  /// \param val is \b true is duplicates cause an error.
  void setInsensitiveDuplicateError(bool val) { failinsensitivedups = val; }

  // Lexer functions
  void calcContextLayout(void);				///< Calculate the internal context field layout
  string grabCurrentFilePath(void) const;		///< Get the path to the current source file
  void parseFromNewFile(const string &fname);		///< Push a new source file to the current parse stack
  void parsePreprocMacro(void);				///< Mark start of parsing for an expanded preprocessor macro
  void parseFileFinished(void);				///< Mark end of parsing for the current file or macro
  void nextLine(void) { lineno.back() += 1; }		///< Indicate parsing proceeded to the next line of the current file
  bool getPreprocValue(const string &nm,string &res) const;	///< Retrieve a given preprocessor variable
  void setPreprocValue(const string &nm,const string &value);	///< Set a given preprocessor variable
  bool undefinePreprocValue(const string &nm);		///< Remove the value associated with the given preprocessor variable

  // Parser functions
  TokenSymbol *defineToken(string *name,uintb *sz,int4 endian);
  void addTokenField(TokenSymbol *sym,FieldQuality *qual);
  bool addContextField(VarnodeSymbol *sym,FieldQuality *qual);
  void newSpace(SpaceQuality *qual);
  SectionSymbol *newSectionSymbol(const string &nm);
  void setEndian(int4 end);

  /// \brief Set instruction alignment for the SLEIGH specification
  ///
  /// \param val is the alignment value in bytes. 1 is the default indicating no alignment
  void setAlignment(int4 val) { alignment = val; }

  void defineVarnodes(SpaceSymbol *spacesym,uintb *off,uintb *size,vector<string> *names);
  void defineBitrange(string *name,VarnodeSymbol *sym,uint4 bitoffset,uint4 numb);
  void addUserOp(vector<string> *names);
  void attachValues(vector<SleighSymbol *> *symlist,vector<intb> *numlist);
  void attachNames(vector<SleighSymbol *> *symlist,vector<string> *names);
  void attachVarnodes(vector<SleighSymbol *> *symlist,vector<SleighSymbol *> *varlist);
  SubtableSymbol *newTable(string *nm);
  void newOperand(Constructor *ct,string *nm);
  PatternEquation *constrainOperand(OperandSymbol *sym,PatternExpression *patexp);
  void defineOperand(OperandSymbol *sym,PatternExpression *patexp);
  PatternEquation *defineInvisibleOperand(TripleSymbol *sym);
  void selfDefine(OperandSymbol *sym);
  ConstructTpl *setResultVarnode(ConstructTpl *ct,VarnodeTpl *vn);
  ConstructTpl *setResultStarVarnode(ConstructTpl *ct,StarQuality *star,VarnodeTpl *vn);
  bool contextMod(vector<ContextChange *> *vec,ContextSymbol *sym,PatternExpression *pe);
  void contextSet(vector<ContextChange *> *vec,TripleSymbol *sym,ContextSymbol *cvar);
  MacroSymbol *createMacro(string *name,vector<string> *param);
  void compareMacroParams(MacroSymbol *sym,const vector<ExprTree *> &param);
  vector<OpTpl *> *createMacroUse(MacroSymbol *sym,vector<ExprTree *> *param);
  SectionVector *standaloneSection(ConstructTpl *main);
  SectionVector *firstNamedSection(ConstructTpl *main,SectionSymbol *sym);
  SectionVector *nextNamedSection(SectionVector *vec,ConstructTpl *section,SectionSymbol *sym);
  SectionVector *finalNamedSection(SectionVector *vec,ConstructTpl *section);
  vector<OpTpl *> *createCrossBuild(VarnodeTpl *addr,SectionSymbol *sym);
  Constructor *createConstructor(SubtableSymbol *sym);
  bool isInRoot(Constructor *ct) const { return (root == ct->getParent()); }	///< Is the Constructor in the root table?
  void resetConstructors(void);
  void pushWith(SubtableSymbol *ss,PatternEquation *pateq,vector<ContextChange *> *contvec);
  void popWith(void);
  void buildConstructor(Constructor *big,PatternEquation *pateq,vector<ContextChange *> *contvec,SectionVector *vec);
  void buildMacro(MacroSymbol *sym,ConstructTpl *rtl);
  void recordNop(void);

  // Virtual functions (not used by the compiler)
  virtual void initialize(DocumentStorage &store) {}
  virtual int4 instructionLength(const Address &baseaddr) const { return 0; }
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const { return 0; }
  virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const { return 0; }

  void setAllOptions(const map<string,string> &defines, bool unnecessaryPcodeWarning,
		     bool lenientConflict, bool allCollisionWarning,
		     bool allNopWarning,bool deadTempWarning,bool enforceLocalKeyWord,
		     bool largeTemporaryWarning, bool caseSensitiveRegisterNames);
  int4 run_compilation(const string &filein,const string &fileout);
};

extern SleighCompile *slgh;		///< A global reference to the SLEIGH compiler accessible to the parse functions
extern int yydebug;			///< Debug state for the SLEIGH parse functions

} // End namespace ghidra
#endif

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
#include "sleighbase.hh"
#include "pcodecompile.hh"
#include "filemanage.hh"
#include <iostream>
#include <sstream>

// High-level control of the sleigh compilation process

struct RtlPair {
  ConstructTpl *section;	// A p-code section
  SymbolScope *scope;		// and its associated symbol scope
  RtlPair(void) { section = (ConstructTpl *)0; scope = (SymbolScope *)0; }
  RtlPair(ConstructTpl *sec,SymbolScope *sc) { section = sec; scope = sc; }
};

class SectionVector {
  int4 nextindex;
  RtlPair main;
  vector<RtlPair> named;
public:
  SectionVector(ConstructTpl *rtl,SymbolScope *scope);
  ConstructTpl *getMainSection(void) const { return main.section; }
  ConstructTpl *getNamedSection(int4 index) const { return named[index].section; }
  RtlPair getMainPair(void) const { return main; }
  RtlPair getNamedPair(int4 i) const { return named[i]; }
  void setNextIndex(int4 i) { nextindex = i; }
  int4 getMaxId(void) const { return named.size(); }
  void append(ConstructTpl *rtl,SymbolScope *scope);
};

struct SpaceQuality {	// Qualities of an address space
  enum {			// Class of space
    ramtype,
    registertype
  };
  string name;
  uint4 type;
  uint4 size;
  uint4 wordsize;       // number of bytes in unit of the space
  bool isdefault;
  SpaceQuality(const string &nm);
};

struct FieldQuality {
  string name;
  uint4 low,high;
  bool signext;
  bool flow;
  bool hex;
  FieldQuality(string *nm,uintb *l,uintb *h);
};

class WithBlock {
  SubtableSymbol *ss;
  PatternEquation *pateq;
  vector<ContextChange *> contvec;
public:
  WithBlock(void) { pateq = (PatternEquation *)0; }
  void set(SubtableSymbol *s, PatternEquation *pq, vector<ContextChange *> *cvec);
  ~WithBlock(void);
  static PatternEquation *collectAndPrependPattern(const list<WithBlock> &stack, PatternEquation *pateq);
  static vector<ContextChange *> *collectAndPrependContext(const list<WithBlock> &stack, vector<ContextChange *> *contvec);
  static SubtableSymbol *getCurrentSubtable(const list<WithBlock> &stack);
};

class SleighCompile;

class ConsistencyChecker {
  struct OptimizeRecord {
    int4 writeop;
    int4 readop;
    int4 inslot;
    int4 writecount;
    int4 readcount;
    int4 writesection;
    int4 readsection;
    int4 opttype;
    OptimizeRecord(void) {
      writeop = -1; readop = -1; inslot=-1; writecount=0; readcount=0; writesection=-2; readsection=-2; opttype=-1; }
  };
  SleighCompile *compiler;
  int4 unnecessarypcode;
  int4 readnowrite;
  int4 writenoread;
  int4 largetemp;
  bool printextwarning;
  bool printdeadwarning;
  bool printlargetempwarning;
  SubtableSymbol *root_symbol;
  vector<SubtableSymbol *> postorder;
  map<SubtableSymbol *,int4> sizemap; // Sizes associated with tables
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
  void setPostOrder(SubtableSymbol *root); // Establish table ordering

  // Optimization routines
  static void examineVn(map<uintb,OptimizeRecord> &recs,const VarnodeTpl *vn,uint4 i,int4 inslot,int4 secnum);
  static bool possibleIntersection(const VarnodeTpl *vn1,const VarnodeTpl *vn2);
  bool readWriteInterference(const VarnodeTpl *vn,const OpTpl *op,bool checkread) const;
  void optimizeGather1(Constructor *ct,map<uintb,OptimizeRecord> &recs,int4 secnum) const;
  void optimizeGather2(Constructor *ct,map<uintb,OptimizeRecord> &recs,int4 secnum) const;
  OptimizeRecord *findValidRule(Constructor *ct,map<uintb,OptimizeRecord> &recs) const;
  void applyOptimization(Constructor *ct,const OptimizeRecord &rec);
  void checkUnusedTemps(Constructor *ct,const map<uintb,OptimizeRecord> &recs);
  void checkLargeTemporaries(Constructor *ct);
  void optimize(Constructor *ct);
public:
  ConsistencyChecker(SleighCompile *sleigh, SubtableSymbol *rt,bool unnecessary,bool warndead, bool warnlargetemp);
  bool test(void);
  bool testTruncations(bool isbigendian);
  void optimizeAll(void);
  int4 getNumUnnecessaryPcode(void) const { return unnecessarypcode; }
  int4 getNumReadNoWrite(void) const { return readnowrite; }
  int4 getNumWriteNoRead(void) const { return writenoread; }
  int4 getNumLargeTemporaries(void) const {return largetemp;}
};

struct FieldContext {
  VarnodeSymbol *sym;
  FieldQuality *qual;
  bool operator<(const FieldContext &op2) const;
  FieldContext(VarnodeSymbol *s,FieldQuality *q) { sym=s; qual=q; }
};

class MacroBuilder : public PcodeBuilder {
  SleighCompile *slgh;
  bool haserror;
  vector<OpTpl *> &outvec;
  vector<HandleTpl *> params;
  bool transferOp(OpTpl *op,vector<HandleTpl *> &params);
  virtual void dump( OpTpl *op );
  void free(void);
  void reportError(const Location* loc, const string &val);
public:
  MacroBuilder(SleighCompile *sl,vector<OpTpl *> &ovec,uint4 lbcnt) : PcodeBuilder(lbcnt),outvec(ovec) {
    slgh = sl; haserror = false; }
  void setMacroOp(OpTpl *macroop);
  bool hasError(void) const { return haserror; }
  virtual ~MacroBuilder(void) { free(); }
  virtual void appendBuild(OpTpl *bld,int4 secnum) { dump(bld); }
  virtual void delaySlot(OpTpl *op) { dump(op); }
  virtual void setLabel(OpTpl *op);
  virtual void appendCrossBuild(OpTpl *bld,int4 secnum) { dump(bld); }
};

class SleighPcode : public PcodeCompile {
  SleighCompile *compiler;
  virtual uintb allocateTemp(void);
  virtual const Location *getLocation(SleighSymbol *sym) const;
  virtual void reportError(const Location* loc, const string &msg);
  virtual void reportWarning(const Location* loc, const string &msg);
  virtual void addSymbol(SleighSymbol *sym);
public:
  SleighPcode(void) : PcodeCompile() { compiler = (SleighCompile *)0; }
  void setCompiler(SleighCompile *comp) { compiler = comp; }
};

class SleighCompile : public SleighBase {
  friend class SleighPcode;
public:
  SleighPcode pcode;
private:
  map<string,string> preproc_defines; // Defines for the preprocessor
  vector<FieldContext> contexttable;
  vector<ConstructTpl *> macrotable;
  vector<Token *> tokentable;
  vector<SubtableSymbol *> tables;
  vector<SectionSymbol *> sections;
  list<WithBlock> withstack;
  Constructor *curct;		// Current constructor being defined
  MacroSymbol *curmacro;	// Current macro being defined
  bool contextlock;		// If the context layout has been established yet
  vector<string> relpath;	// Relative path (to cwd) for each filename
  vector<string> filename;	// Stack of current files being parsed
  vector<int4> lineno;		// Current line number for each file in stack
  map<Constructor *, Location> ctorLocationMap;	// Map constructor to its defining parse location
  map<SleighSymbol *, Location> symbolLocationMap;	// Map symbol to its defining parse location
  int4 userop_count;		// Number of userops defined
  bool warnunnecessarypcode;	// True if we warn of unnecessary ZEXT or SEXT
  bool warndeadtemps;		// True if we warn of temporaries that are written but not read
  bool lenientconflicterrors;	// True if we ignore most pattern conflict errors
  bool largetemporarywarning;   // True if we warn about temporaries larger than SleighBase::MAX_UNIQUE_SIZE
  bool warnalllocalcollisions;	// True if local export collisions generate individual warnings
  bool warnallnops;		// True if pcode NOPs generate individual warnings
  vector<string> noplist;	// List of individual NOP warnings
  mutable Location currentLocCache;	// Location for (last) request of current location
  int4 errors;

  const Location* getCurrentLocation(void) const;
  void predefinedSymbols(void);
  int4 calcContextVarLayout(int4 start,int4 sz,int4 numbits);
  void buildDecisionTrees(void);
  void buildPatterns(void);
  void checkConsistency(void);
  static int4 findCollision(map<uintb,int4> &local2Operand,const vector<uintb> &locals,int operand);
  bool checkLocalExports(Constructor *ct);
  void checkLocalCollisions(void);
  void checkNops(void);
  string checkSymbols(SymbolScope *scope);
  void addSymbol(SleighSymbol *sym);
  SleighSymbol *dedupSymbolList(vector<SleighSymbol *> *symlist);
  bool expandMacros(ConstructTpl *ctpl,const vector<ConstructTpl *> &macrotable);
  bool finalizeSections(Constructor *big,SectionVector *vec);
  static void shiftUniqueVn(VarnodeTpl *vn,int4 sa);
  static void shiftUniqueOp(OpTpl *op,int4 sa);
  static void shiftUniqueHandle(HandleTpl *hand,int4 sa);
  static void shiftUniqueConstruct(ConstructTpl *tpl,int4 sa);
  void checkUniqueAllocation(void);
public:
  SleighCompile(void);
  const Location *getLocation(Constructor* ctor) const;
  const Location *getLocation(SleighSymbol *sym) const;
  string formatStatusMessage(const Location* loc, const string &msg);
  void reportError(const string &msg);
  void reportError(const Location *loc, const string &msg);
  void reportWarning(const string &msg);
  void reportWarning(const Location *loc, const string &msg);
  int4 numErrors(void) const { return errors; }
  void reportInfo(const string &msg);
  void reportInfo(const Location *loc, const string &msg);


  uintb getUniqueAddr(void);
  void setUnnecessaryPcodeWarning(bool val) { warnunnecessarypcode = val; }
  void setDeadTempWarning(bool val) { warndeadtemps = val; }
  void setEnforceLocalKeyWord(bool val) { pcode.setEnforceLocalKey(val); }
  void setLargeTemporaryWarning (bool val) {largetemporarywarning = val;}
  void setLenientConflict(bool val) { lenientconflicterrors = val; }
  void setLocalCollisionWarning(bool val) { warnalllocalcollisions = val; }
  void setAllNopWarning(bool val) { warnallnops = val; }
  void process(void);

  // Lexer functions
  void calcContextLayout(void);
  string grabCurrentFilePath(void) const;
  void parseFromNewFile(const string &fname);
  void parsePreprocMacro(void);
  void parseFileFinished(void);
  void nextLine(void) { lineno.back() += 1; }
  bool getPreprocValue(const string &nm,string &res) const;
  void setPreprocValue(const string &nm,const string &value);
  bool undefinePreprocValue(const string &nm);

  // Parser functions
  TokenSymbol *defineToken(string *name,uintb *sz,int4 endian);
  void addTokenField(TokenSymbol *sym,FieldQuality *qual);
  bool addContextField(VarnodeSymbol *sym,FieldQuality *qual);
  void newSpace(SpaceQuality *qual);
  SectionSymbol *newSectionSymbol(const string &nm);
  void setEndian(int4 end);
  void setAlignment(int4 val) { alignment = val; }
  void defineVarnodes(SpaceSymbol *spacesym,uintb *off,uintb *size,vector<string> *names);
  void defineBitrange(string *name,VarnodeSymbol *sym,uint4 bitoffset,uint4 numb);
  void addUserOp(vector<string> *names);
  void attachValues(vector<SleighSymbol *> *symlist,vector<intb> *numlist);
  void attachNames(vector<SleighSymbol *> *symlist,vector<string> *names);
  void attachVarnodes(vector<SleighSymbol *> *symlist,vector<SleighSymbol *> *varlist);
  SubtableSymbol *newTable(string *nm);
  void newOperand(Constructor *ct,string *nm);
  VarnodeTpl *addressOf(VarnodeTpl *var,uint4 size);
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
  bool isInRoot(Constructor *ct) const { return (root == ct->getParent()); }
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
};

extern SleighCompile *slgh;
extern int yydebug;

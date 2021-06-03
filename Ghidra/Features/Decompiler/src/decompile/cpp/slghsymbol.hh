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
#ifndef __SLGHSYMBOL__
#define __SLGHSYMBOL__

#include "semantics.hh"
#include "slghpatexpress.hh"

class SleighBase;		// Forward declaration
class SleighSymbol {
  friend class SymbolTable;
public:
  enum symbol_type { space_symbol, token_symbol, userop_symbol, value_symbol, valuemap_symbol,
		     name_symbol, varnode_symbol, varnodelist_symbol, operand_symbol,
		     start_symbol, end_symbol, subtable_symbol, macro_symbol, section_symbol,
                     bitrange_symbol, context_symbol, epsilon_symbol, label_symbol,
		     dummy_symbol };
private:
  string name;
  uintm id;			// Unique id across all symbols
  uintm scopeid;		// Unique id of scope this symbol is in
public:
  SleighSymbol(void) {}		// For use with restoreXml
  SleighSymbol(const string &nm) { name = nm; id = 0; }
  virtual ~SleighSymbol(void) {}
  const string &getName(void) const { return name; }
  uintm getId(void) const { return id; }
  virtual symbol_type getType(void) const { return dummy_symbol; }
  virtual void saveXmlHeader(ostream &s) const;
  void restoreXmlHeader(const Element *el);
  virtual void saveXml(ostream &s) const {}
  virtual void restoreXml(const Element *el,SleighBase *trans) {}
};

struct SymbolCompare {
  bool operator()(const SleighSymbol *a,const SleighSymbol *b) const {
    return (a->getName() < b->getName()); }
};

typedef set<SleighSymbol *,SymbolCompare> SymbolTree;
class SymbolScope {
  friend class SymbolTable;
  SymbolScope *parent;
  SymbolTree tree;
  uintm id;
public:
  SymbolScope(SymbolScope *p,uintm i) { parent = p; id = i; }
  SymbolScope *getParent(void) const { return parent; }
  SleighSymbol *addSymbol(SleighSymbol *a);
  SleighSymbol *findSymbol(const string &nm) const;
  SymbolTree::const_iterator begin(void) const { return tree.begin(); }
  SymbolTree::const_iterator end(void) const { return tree.end(); }
  uintm getId(void) const { return id; }
  void removeSymbol(SleighSymbol *a) { tree.erase(a); }
};

class SymbolTable {
  vector<SleighSymbol *> symbollist;
  vector<SymbolScope *> table;
  SymbolScope *curscope;
  SymbolScope *skipScope(int4 i) const;
  SleighSymbol *findSymbolInternal(SymbolScope *scope,const string &nm) const;
  void renumber(void);
public:
  SymbolTable(void) { curscope = (SymbolScope *)0; }
  ~SymbolTable(void);
  SymbolScope *getCurrentScope(void) { return curscope; }
  SymbolScope *getGlobalScope(void) { return table[0]; }
  
  void setCurrentScope(SymbolScope *scope) { curscope = scope; }
  void addScope(void);		// Add new scope off of current scope, make it current
  void popScope(void);		// Make parent of current scope current
  void addGlobalSymbol(SleighSymbol *a);
  void addSymbol(SleighSymbol *a);
  SleighSymbol *findSymbol(const string &nm) const { return findSymbolInternal(curscope,nm); }
  SleighSymbol *findSymbol(const string &nm,int4 skip) const { return findSymbolInternal(skipScope(skip),nm); }
  SleighSymbol *findGlobalSymbol(const string &nm) const { return findSymbolInternal(table[0],nm); }
  SleighSymbol *findSymbol(uintm id) const { return symbollist[id]; }
  void replaceSymbol(SleighSymbol *a,SleighSymbol *b);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,SleighBase *trans);
  void restoreSymbolHeader(const Element *el);
  void purge(void);
};

class SpaceSymbol : public SleighSymbol {
  AddrSpace *space;
public:
  SpaceSymbol(AddrSpace *spc) : SleighSymbol(spc->getName()) { space = spc; }
  AddrSpace *getSpace(void) const { return space; }
  virtual symbol_type getType(void) const { return space_symbol; }
};

class TokenSymbol : public SleighSymbol {
  Token *tok;
public:
  TokenSymbol(Token *t) : SleighSymbol(t->getName()) { tok = t; }
  ~TokenSymbol(void) { delete tok; }
  Token *getToken(void) const { return tok; }
  virtual symbol_type getType(void) const { return token_symbol; }
};

class SectionSymbol : public SleighSymbol { // Named p-code sections
  int4 templateid;		// Index into the ConstructTpl array
  int4 define_count;		// Number of definitions of this named section
  int4 ref_count;		// Number of references to this named section
public:
  SectionSymbol(const string &nm,int4 id) : SleighSymbol(nm) { templateid=id; define_count=0; ref_count=0; }
  int4 getTemplateId(void) const { return templateid; }
  void incrementDefineCount(void) { define_count += 1; }
  void incrementRefCount(void) { ref_count += 1; }
  int4 getDefineCount(void) const { return define_count; }
  int4 getRefCount(void) const { return ref_count; }
  virtual symbol_type getType(void) const { return section_symbol; }
  // Not saved or restored
};

class UserOpSymbol : public SleighSymbol { // A user-defined pcode-op
  uint4 index;
public:
  UserOpSymbol(void) {}		// For use with restoreXml
  UserOpSymbol(const string &nm) : SleighSymbol(nm) { index = 0; }
  void setIndex(uint4 ind) { index = ind; }
  uint4 getIndex(void) const { return index; }
  virtual symbol_type getType(void) const { return userop_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class Constructor;		// Forward declaration
// This is the central sleigh object
class TripleSymbol : public SleighSymbol {
public:
  TripleSymbol(void) {}
  TripleSymbol(const string &nm) : SleighSymbol(nm) {}
  virtual Constructor *resolve(ParserWalker &walker) { return (Constructor *)0; }
  virtual PatternExpression *getPatternExpression(void) const=0;
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const=0;
  virtual int4 getSize(void) const { return 0; }	// Size out of context
  virtual void print(ostream &s,ParserWalker &walker) const=0;
  virtual void collectLocalValues(vector<uintb> &results) const {}
};
  
class FamilySymbol : public TripleSymbol {
public:
  FamilySymbol(void) {}
  FamilySymbol(const string &nm) : TripleSymbol(nm) {}
  virtual PatternValue *getPatternValue(void) const=0;
};

class SpecificSymbol : public TripleSymbol {
public:
  SpecificSymbol(void) {}
  SpecificSymbol(const string &nm) : TripleSymbol(nm) {}
  virtual VarnodeTpl *getVarnode(void) const=0;
};

class PatternlessSymbol : public SpecificSymbol { // Behaves like constant 0 pattern
  ConstantValue *patexp;
public:
  PatternlessSymbol(void);	// For use with restoreXml
  PatternlessSymbol(const string &nm);
  virtual ~PatternlessSymbol(void);
  virtual PatternExpression *getPatternExpression(void) const { return patexp; }
  virtual void saveXml(ostream &s) const {}
  virtual void restoreXml(const Element *el,SleighBase *trans) {}
};

class EpsilonSymbol : public PatternlessSymbol { // Another name for zero pattern/value
  AddrSpace *const_space;
public:
  EpsilonSymbol(void) {}	// For use with restoreXml
  EpsilonSymbol(const string &nm,AddrSpace *spc) : PatternlessSymbol(nm) { const_space=spc; }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return epsilon_symbol; }
  virtual VarnodeTpl *getVarnode(void) const;
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class ValueSymbol : public FamilySymbol {
protected:
  PatternValue *patval;
public:
  ValueSymbol(void) { patval = (PatternValue *)0; } // For use with restoreXml
  ValueSymbol(const string &nm,PatternValue *pv);
  virtual ~ValueSymbol(void);
  virtual PatternValue *getPatternValue(void) const { return patval; }
  virtual PatternExpression *getPatternExpression(void) const { return patval; }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return value_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class ValueMapSymbol : public ValueSymbol {
  vector<intb> valuetable;
  bool tableisfilled;
  void checkTableFill(void);
public:
  ValueMapSymbol(void) {}	// For use with restoreXml
  ValueMapSymbol(const string &nm,PatternValue *pv,const vector<intb> &vt) : ValueSymbol(nm,pv) { valuetable=vt; checkTableFill(); }
  virtual Constructor *resolve(ParserWalker &walker);
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return valuemap_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class NameSymbol : public ValueSymbol {
  vector<string> nametable;
  bool tableisfilled;
  void checkTableFill(void);
public:
  NameSymbol(void) {}		// For use with restoreXml
  NameSymbol(const string &nm,PatternValue *pv,const vector<string> &nt) : ValueSymbol(nm,pv) { nametable=nt; checkTableFill(); }
  virtual Constructor *resolve(ParserWalker &walker);
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return name_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class VarnodeSymbol : public PatternlessSymbol { // A global varnode
  VarnodeData fix;
  bool context_bits;
public:
  VarnodeSymbol(void) {}	// For use with restoreXml
  VarnodeSymbol(const string &nm,AddrSpace *base,uintb offset,int4 size);
  void markAsContext(void) { context_bits = true; }
  const VarnodeData &getFixedVarnode(void) const { return fix; }
  virtual VarnodeTpl *getVarnode(void) const;
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual int4 getSize(void) const { return fix.size; }
  virtual void print(ostream &s,ParserWalker &walker) const {
    s << getName(); }
  virtual void collectLocalValues(vector<uintb> &results) const;
  virtual symbol_type getType(void) const { return varnode_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class BitrangeSymbol : public SleighSymbol { // A smaller bitrange within a varnode
  VarnodeSymbol *varsym;	// Varnode containing the bitrange
  uint4 bitoffset;		// least significant bit of range
  uint4 numbits;		// number of bits in the range
public:
  BitrangeSymbol(void) {}	// For use with restoreXml
  BitrangeSymbol(const string &nm,VarnodeSymbol *sym,uint4 bitoff,uint4 num)
    : SleighSymbol(nm) { varsym=sym; bitoffset=bitoff; numbits=num; }
  VarnodeSymbol *getParentSymbol(void) const { return varsym; }
  uint4 getBitOffset(void) const { return bitoffset; }
  uint4 numBits(void) const { return numbits; }
  virtual symbol_type getType(void) const { return bitrange_symbol; }
};

class ContextSymbol : public ValueSymbol {
  VarnodeSymbol *vn;
  uint4 low,high;		// into a varnode
  bool flow;
public:
  ContextSymbol(void) {}	// For use with restoreXml
  ContextSymbol(const string &nm,ContextField *pate,VarnodeSymbol *v,uint4 l,uint4 h,bool flow);
  VarnodeSymbol *getVarnode(void) const { return vn; }
  uint4 getLow(void) const { return low; }
  uint4 getHigh(void) const { return high; }
  bool getFlow(void) const { return flow; }
  virtual symbol_type getType(void) const { return context_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class VarnodeListSymbol : public ValueSymbol {
  vector<VarnodeSymbol *> varnode_table;
  bool tableisfilled;
  void checkTableFill(void);
public:
  VarnodeListSymbol(void) {}	// For use with restoreXml
  VarnodeListSymbol(const string &nm,PatternValue *pv,const vector<SleighSymbol *> &vt); 
  virtual Constructor *resolve(ParserWalker &walker);
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual int4 getSize(void) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return varnodelist_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};
  
class OperandSymbol : public SpecificSymbol {
  friend class Constructor;
  friend class OperandEquation;
public:
  enum { code_address=1, offset_irrel=2, variable_len=4, marked=8 };
private:
  uint4 reloffset;		// Relative offset
  int4 offsetbase;		// Base operand to which offset is relative (-1=constructor start)
  int4 minimumlength;		// Minimum size of operand (within instruction tokens)
  int4 hand;			// Handle index
  OperandValue *localexp;
  TripleSymbol *triple;		// Defining symbol
  PatternExpression *defexp;	// OR defining expression
  uint4 flags;
  void setVariableLength(void) { flags |= variable_len; }
  bool isVariableLength(void) const { return ((flags&variable_len)!=0); }
public:
  OperandSymbol(void) {}	// For use with restoreXml
  OperandSymbol(const string &nm,int4 index,Constructor *ct);
  uint4 getRelativeOffset(void) const { return reloffset; }
  int4 getOffsetBase(void) const { return offsetbase; }
  int4 getMinimumLength(void) const { return minimumlength; }
  PatternExpression *getDefiningExpression(void) const { return defexp; }
  TripleSymbol *getDefiningSymbol(void) const { return triple; }
  int4 getIndex(void) const { return hand; }
  void defineOperand(PatternExpression *pe);
  void defineOperand(TripleSymbol *tri);
  void setCodeAddress(void) { flags |= code_address; }
  bool isCodeAddress(void) const { return ((flags&code_address)!=0); }
  void setOffsetIrrelevant(void) { flags |= offset_irrel; }
  bool isOffsetIrrelevant(void) const { return ((flags&offset_irrel)!=0); }
  void setMark(void) { flags |= marked; }
  void clearMark(void) { flags &= ~((uint4)marked); }
  bool isMarked(void) const { return ((flags&marked)!=0); }
  virtual ~OperandSymbol(void);
  virtual VarnodeTpl *getVarnode(void) const;
  virtual PatternExpression *getPatternExpression(void) const { return localexp; }
  virtual void getFixedHandle(FixedHandle &hnd,ParserWalker &walker) const;
  virtual int4 getSize(void) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual void collectLocalValues(vector<uintb> &results) const;
  virtual symbol_type getType(void) const { return operand_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class StartSymbol : public SpecificSymbol {
  AddrSpace *const_space;
  PatternExpression *patexp;
public:
  StartSymbol(void) { patexp = (PatternExpression *)0; } // For use with restoreXml
  StartSymbol(const string &nm,AddrSpace *cspc);
  virtual ~StartSymbol(void);
  virtual VarnodeTpl *getVarnode(void) const;
  virtual PatternExpression *getPatternExpression(void) const { return patexp; }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return start_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class EndSymbol : public SpecificSymbol {
  AddrSpace *const_space;
  PatternExpression *patexp;
public:
  EndSymbol(void) { patexp = (PatternExpression *)0; } // For use with restoreXml
  EndSymbol(const string &nm,AddrSpace *cspc);
  virtual ~EndSymbol(void);
  virtual VarnodeTpl *getVarnode(void) const;
  virtual PatternExpression *getPatternExpression(void) const { return patexp; }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return end_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class FlowDestSymbol : public SpecificSymbol {
  AddrSpace *const_space;
public:
  FlowDestSymbol(void) {}	// For use with restoreXml
  FlowDestSymbol(const string &nm,AddrSpace *cspc);
  virtual VarnodeTpl *getVarnode(void) const;
  virtual PatternExpression *getPatternExpression(void) const { throw SleighError("Cannot use symbol in pattern"); }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return start_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class FlowRefSymbol : public SpecificSymbol {
  AddrSpace *const_space;
public:
  FlowRefSymbol(void) {}	// For use with restoreXml
  FlowRefSymbol(const string &nm,AddrSpace *cspc);
  virtual VarnodeTpl *getVarnode(void) const;
  virtual PatternExpression *getPatternExpression(void) const { throw SleighError("Cannot use symbol in pattern"); }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const;
  virtual void print(ostream &s,ParserWalker &walker) const;
  virtual symbol_type getType(void) const { return start_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class ContextChange {		// Change to context command
public:
  virtual ~ContextChange(void) {}
  virtual void validate(void) const=0;
  virtual void saveXml(ostream &s) const=0;
  virtual void restoreXml(const Element *el,SleighBase *trans)=0;
  virtual void apply(ParserWalkerChange &walker) const=0;
  virtual ContextChange *clone(void) const=0;
};

class ContextOp : public ContextChange {
  PatternExpression *patexp;	// Expression determining value
  int4 num;			// index of word containing context variable to set
  uintm mask;			// Mask off size of variable
  int4 shift;			// Number of bits to shift value into place
public:
  ContextOp(int4 startbit,int4 endbit,PatternExpression *pe);
  ContextOp(void) {}		// For use with restoreXml
  virtual ~ContextOp(void) { PatternExpression::release(patexp); }
  virtual void validate(void) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
  virtual void apply(ParserWalkerChange &walker) const;
  virtual ContextChange *clone(void) const;
};

class ContextCommit : public ContextChange {
  TripleSymbol *sym;
  int4 num;			// Index of word containing context commit
  uintm mask;			// mask of bits in word being committed
  bool flow;			// Whether the context "flows" from the point of change
public:
  ContextCommit(void) {}	// For use with restoreXml
  ContextCommit(TripleSymbol *s,int4 sbit,int4 ebit,bool fl);
  virtual void validate(void) const {}
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
  virtual void apply(ParserWalkerChange &walker) const;
  virtual ContextChange *clone(void) const;
};

class SubtableSymbol;
class Constructor {		// This is NOT a symbol
  TokenPattern *pattern;
  SubtableSymbol *parent;
  PatternEquation *pateq;
  vector<OperandSymbol *> operands;
  vector<string> printpiece;
  vector<ContextChange *> context; // Context commands
  ConstructTpl *templ;		// The main p-code section
  vector<ConstructTpl *> namedtempl; // Other named p-code sections
  int4 minimumlength;		// Minimum length taken up by this constructor in bytes
  uintm id;			// Unique id of constructor within subtable
  int4 firstwhitespace;		// Index of first whitespace piece in -printpiece-
  int4 flowthruindex;		// if >=0 then print only a single operand no markup
  int4 lineno;
  int4 src_index;           //source file index
  mutable bool inerror;                 // An error is associated with this Constructor
  void orderOperands(void);
public:
  Constructor(void);		// For use with restoreXml
  Constructor(SubtableSymbol *p);
  ~Constructor(void);
  TokenPattern *buildPattern(ostream &s);
  TokenPattern *getPattern(void) const { return pattern; }
  void setMinimumLength(int4 l) { minimumlength = l; }
  int4 getMinimumLength(void) const { return minimumlength; }
  void setId(uintm i) { id = i; }
  uintm getId(void) const { return id; }
  void setLineno(int4 ln) { lineno = ln; }
  int4 getLineno(void) const { return lineno; }
  void setSrcIndex(int4 index) {src_index = index;}
  int4 getSrcIndex(void) {return src_index;}
  void addContext(const vector<ContextChange *> &vec) { context = vec; }
  void addOperand(OperandSymbol *sym);
  void addInvisibleOperand(OperandSymbol *sym);
  void addSyntax(const string &syn);
  void addEquation(PatternEquation *pe);
  void setMainSection(ConstructTpl *tpl) { templ = tpl; }
  void setNamedSection(ConstructTpl *tpl,int4 id);
  SubtableSymbol *getParent(void) const { return parent; }
  int4 getNumOperands(void) const { return operands.size(); }
  OperandSymbol *getOperand(int4 i) const { return operands[i]; }
  PatternEquation *getPatternEquation(void) const { return pateq; }
  ConstructTpl *getTempl(void) const { return templ; }
  ConstructTpl *getNamedTempl(int4 secnum) const;
  int4 getNumSections(void) const { return namedtempl.size(); }
  void printInfo(ostream &s) const;
  void print(ostream &s,ParserWalker &pos) const;
  void printMnemonic(ostream &s,ParserWalker &walker) const;
  void printBody(ostream &s,ParserWalker &walker) const;
  void removeTrailingSpace(void);
  void applyContext(ParserWalkerChange &walker) const {
    vector<ContextChange *>::const_iterator iter;
    for(iter=context.begin();iter!=context.end();++iter)
      (*iter)->apply(walker);
  }
  void markSubtableOperands(vector<int4> &check) const;
  void collectLocalExports(vector<uintb> &results) const;
  void setError(bool val) const { inerror = val; }
  bool isError(void) const { return inerror; }
  bool isRecursive(void) const;
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,SleighBase *trans);
};

class DecisionProperties {
  vector<pair<Constructor *, Constructor *> > identerrors;
  vector<pair<Constructor *, Constructor *> > conflicterrors;
public:
  void identicalPattern(Constructor *a,Constructor *b);
  void conflictingPattern(Constructor *a,Constructor *b);
  const vector<pair<Constructor *, Constructor *> > &getIdentErrors(void) const { return identerrors; }
  const vector<pair<Constructor *, Constructor *> > &getConflictErrors(void) const { return conflicterrors; }
};

class DecisionNode {
  vector<pair<DisjointPattern *,Constructor *> > list;
  vector<DecisionNode *> children;
  int4 num;			// Total number of patterns we distinguish
  bool contextdecision;		// True if this is decision based on context
  int4 startbit,bitsize;        // Bits in the stream on which to base the decision
  DecisionNode *parent;
  void chooseOptimalField(void);
  double getScore(int4 low,int4 size,bool context);
  int4 getNumFixed(int4 low,int4 size,bool context);
  int4 getMaximumLength(bool context);
  void consistentValues(vector<uint4> &bins,DisjointPattern *pat);
public:
  DecisionNode(void) {}		// For use with restoreXml
  DecisionNode(DecisionNode *p);
  ~DecisionNode(void);
  Constructor *resolve(ParserWalker &walker) const;
  void addConstructorPair(const DisjointPattern *pat,Constructor *ct);
  void split(DecisionProperties &props);
  void orderPatterns(DecisionProperties &props);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,DecisionNode *par,SubtableSymbol *sub);
};

class SubtableSymbol : public TripleSymbol {
  TokenPattern *pattern;
  bool beingbuilt,errors;
  vector<Constructor *> construct; // All the Constructors in this table
  DecisionNode *decisiontree;
public:
  SubtableSymbol(void) { pattern = (TokenPattern *)0; decisiontree = (DecisionNode *)0; } // For use with restoreXml
  SubtableSymbol(const string &nm);
  virtual ~SubtableSymbol(void);
  bool isBeingBuilt(void) const { return beingbuilt; }
  bool isError(void) const { return errors; }
  void addConstructor(Constructor *ct) { ct->setId(construct.size()); construct.push_back(ct); }
  void buildDecisionTree(DecisionProperties &props);
  TokenPattern *buildPattern(ostream &s);
  TokenPattern *getPattern(void) const { return pattern; }
  int4 getNumConstructors(void) const { return construct.size(); }
  Constructor *getConstructor(uintm id) const { return construct[id]; }
  virtual Constructor *resolve(ParserWalker &walker) { return decisiontree->resolve(walker); }
  virtual PatternExpression *getPatternExpression(void) const { throw SleighError("Cannot use subtable in expression"); }
  virtual void getFixedHandle(FixedHandle &hand,ParserWalker &walker) const {
    throw SleighError("Cannot use subtable in expression"); }
  virtual int4 getSize(void) const { return -1; }
  virtual void print(ostream &s,ParserWalker &walker) const {
    throw SleighError("Cannot use subtable in expression"); }
  virtual void collectLocalValues(vector<uintb> &results) const;
  virtual symbol_type getType(void) const { return subtable_symbol; }
  virtual void saveXml(ostream &s) const;
  virtual void saveXmlHeader(ostream &s) const;
  virtual void restoreXml(const Element *el,SleighBase *trans);
};

class MacroSymbol : public SleighSymbol { // A user-defined pcode-macro
  int4 index;
  ConstructTpl *construct;
  vector<OperandSymbol *> operands;
public:
  MacroSymbol(const string &nm,int4 i) : SleighSymbol(nm) { index = i; construct = (ConstructTpl *)0; }
  int4 getIndex(void) const { return index; }
  void setConstruct(ConstructTpl *ct) { construct = ct; }
  ConstructTpl *getConstruct(void) const { return construct; }
  void addOperand(OperandSymbol *sym) { operands.push_back(sym); }
  int4 getNumOperands(void) const { return operands.size(); }
  OperandSymbol *getOperand(int4 i) const { return operands[i]; }
  virtual ~MacroSymbol(void) { if (construct != (ConstructTpl *)0) delete construct; }
  virtual symbol_type getType(void) const { return macro_symbol; }
};

class LabelSymbol : public SleighSymbol { // A branch label
  uint4 index;			// Local 1 up index of label
  bool isplaced;		// Has the label been placed (not just referenced)
  uint4 refcount;		// Number of references to this label
public:
  LabelSymbol(const string &nm,uint4 i) : SleighSymbol(nm) { index = i; refcount = 0; isplaced=false; }
  uint4 getIndex(void) const { return index; }
  void incrementRefCount(void) { refcount += 1; }
  uint4 getRefCount(void) const { return refcount; }
  void setPlaced(void) { isplaced = true; }
  bool isPlaced(void) const { return isplaced; }
  virtual symbol_type getType(void) const { return label_symbol; }
};

#endif

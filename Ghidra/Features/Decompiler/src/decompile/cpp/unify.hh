/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
#ifndef __CPUI_UNIFY__
#define __CPUI_UNIFY__

#include "funcdata.hh"

class UnifyCPrinter;

class UnifyDatatype {
public:
  enum {
    op_type, var_type, const_type, block_type
  };
private:
  uint4 type;
  union {
    PcodeOp *op;
    Varnode *vn;
    uintb *cn;
    BlockBasic *bl;
  } storespot;
public:
  UnifyDatatype(void) { type = op_type; }
  UnifyDatatype(uint4 tp);
  UnifyDatatype(const UnifyDatatype &op2);
  UnifyDatatype &operator=(const UnifyDatatype &op2);
  ~UnifyDatatype(void);
  uint4 getType(void) const { return type; }
  void setOp(PcodeOp *o) { storespot.op = o; }
  PcodeOp *getOp(void) const { return storespot.op; }
  void setVarnode(Varnode *v) { storespot.vn = v; }
  Varnode *getVarnode(void) const { return storespot.vn; }
  void setBlock(BlockBasic *b) { storespot.bl = b; }
  BlockBasic *getBlock(void) const { return storespot.bl; }
  void setConstant(uintb val);
  uintb getConstant(void) const { return *storespot.cn; }
  void printVarDecl(ostream &s,int4 id,const UnifyCPrinter &cprinter) const;
  string getBaseName(void) const;
};

class UnifyState;

class RHSConstant {		// A construction that results in a constant on the right-hand side of an expression
public:
  virtual ~RHSConstant(void) {}
  virtual RHSConstant *clone(void)=0;
  virtual uintb getConstant(UnifyState &state) const=0;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const=0;
};

class ConstantNamed : public RHSConstant {
  int4 constindex;
public:
  ConstantNamed(int4 id) { constindex = id; }
  int4 getId(void) const { return constindex; }
  virtual RHSConstant *clone(void) { return new ConstantNamed(constindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantAbsolute : public RHSConstant {
  uintb val;			// The absolute value
public:
  ConstantAbsolute(uintb v) { val = v; }
  uintb getVal(void) const { return val; }
  virtual RHSConstant *clone(void) { return new ConstantAbsolute(val); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantNZMask : public RHSConstant { // A varnode's non-zero mask
  int4 varindex;
public:
  ConstantNZMask(int4 ind) { varindex = ind; }
  virtual RHSConstant *clone(void) { return new ConstantNZMask(varindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantConsumed : public RHSConstant { // A varnode's consume mask
  int4 varindex;
public:
  ConstantConsumed(int4 ind) { varindex = ind; }
  virtual RHSConstant *clone(void) { return new ConstantConsumed(varindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantOffset : public RHSConstant { // A varnode's offset
  int4 varindex;
public:
  ConstantOffset(int4 ind) { varindex = ind; }
  virtual RHSConstant *clone(void) { return new ConstantOffset(varindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantIsConstant : public RHSConstant { // TRUE if the varnode is constant
  int4 varindex;
public:
  ConstantIsConstant(int4 ind) { varindex = ind; }
  virtual RHSConstant *clone(void) { return new ConstantIsConstant(varindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantHeritageKnown : public RHSConstant { // A varnode's consume mask
  int4 varindex;
public:
  ConstantHeritageKnown(int4 ind) { varindex = ind; }
  virtual RHSConstant *clone(void) { return new ConstantHeritageKnown(varindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantVarnodeSize : public RHSConstant { // A varnode's size as an actual constant
  int4 varindex;
public:
  ConstantVarnodeSize(int4 ind) { varindex = ind; }
  virtual RHSConstant *clone(void) { return new ConstantVarnodeSize(varindex); }
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstantExpression : public RHSConstant {
  RHSConstant *expr1,*expr2;
  OpCode opc;
public:
  ConstantExpression(RHSConstant *e1,RHSConstant *e2,OpCode oc) { expr1 = e1; expr2 = e2; opc = oc; }
  virtual ~ConstantExpression(void);
  virtual RHSConstant *clone(void);
  virtual uintb getConstant(UnifyState &state) const;
  virtual void writeExpression(ostream &s,UnifyCPrinter &printstate) const;
};

class TraverseConstraint {
protected:
  int4 uniqid;
public:
  TraverseConstraint(int4 i) { uniqid = i; }
  virtual ~TraverseConstraint(void) {}
  //  int4 getId(void) const { return uniqid; }
};

class TraverseDescendState : public TraverseConstraint {
  bool onestep;			// true if first step has occurred
  list<PcodeOp *>::const_iterator iter;	// Different forward branches we could traverse
  list<PcodeOp *>::const_iterator enditer;
public:
  TraverseDescendState(int4 i) : TraverseConstraint(i) {}
  PcodeOp *getCurrentOp(void) const { return *iter; }
  void initialize(Varnode *vn) { onestep = false; iter = vn->beginDescend(); enditer = vn->endDescend(); }
  bool step(void) {
    if (onestep)
      ++iter;
    else
      onestep = true;
    return (iter!=enditer); }
};

class TraverseCountState : public TraverseConstraint {
  int4 state;
  int4 endstate;
public:
  TraverseCountState(int4 i) : TraverseConstraint(i) {}
  int4 getState(void) const { return state; }
  void initialize(int4 end) { state = -1; endstate = end; }
  bool step(void) { ++state; return (state != endstate); }
};

class TraverseGroupState : public TraverseConstraint {
  vector<TraverseConstraint *> traverselist;
  int4 currentconstraint;
  int4 state;
public:
  TraverseGroupState(int4 i) : TraverseConstraint(i) {}
  void addTraverse(TraverseConstraint *tc) { traverselist.push_back(tc); }
  TraverseConstraint *getSubTraverse(int4 slot) const { return traverselist[slot]; }
  int4 getCurrentIndex(void) const { return currentconstraint; }
  void setCurrentIndex(int4 val) { currentconstraint = val; }
  int4 getState(void) const { return state; }
  void setState(int4 val) { state = val; }
};

class UnifyConstraint {
  friend class ConstraintGroup;
protected:
  int4 uniqid;			// Unique identifier for constraint for retrieving state
  int4 maxnum;
  UnifyConstraint *copyid(const UnifyConstraint *op) { uniqid = op->uniqid; maxnum = op->maxnum; return this; }
public:
  virtual ~UnifyConstraint(void) {}
  int4 getId(void) const { return uniqid; }
  int4 getMaxNum(void) { return maxnum; }
  virtual UnifyConstraint *clone(void) const=0;
  virtual void initialize(UnifyState &state);
  virtual bool step(UnifyState &state)=0;
  virtual void buildTraverseState(UnifyState &state);
  virtual void setId(int4 &id) { uniqid = id; id += 1; }
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const {}
  virtual int4 getBaseIndex(void) const { return -1; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const=0;
  virtual bool isDummy(void) const { return false; }
  virtual void removeDummy(void) {}
};

class DummyOpConstraint : public UnifyConstraint {
  int4 opindex;
public:
  DummyOpConstraint(int4 ind) { maxnum = opindex = ind; }
  virtual UnifyConstraint *clone(void) const { return (new DummyOpConstraint(opindex))->copyid(this); }
  virtual bool step(UnifyState &state) { return true; }
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const { typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type); }
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const {}
  virtual bool isDummy(void) const { return true; }
};

class DummyVarnodeConstraint : public UnifyConstraint {
  int4 varindex;
public:
  DummyVarnodeConstraint(int4 ind) { maxnum = varindex = ind; }
  virtual UnifyConstraint *clone(void) const { return (new DummyVarnodeConstraint(varindex))->copyid(this); }
  virtual bool step(UnifyState &state) { return true; }
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const { typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type); }
  virtual int4 getBaseIndex(void) const { return varindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const {}
  virtual bool isDummy(void) const { return true; }
};

class DummyConstConstraint : public UnifyConstraint {
  int4 constindex;
public:
  DummyConstConstraint(int4 ind) { maxnum = constindex = ind; }
  virtual UnifyConstraint *clone(void) const { return (new DummyConstConstraint(constindex))->copyid(this); }
  virtual bool step(UnifyState &state) { return true; }
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const { typelist[constindex] = UnifyDatatype(UnifyDatatype::const_type); }
  virtual int4 getBaseIndex(void) const { return constindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const {}
  virtual bool isDummy(void) const { return true; }
};

class ConstraintBoolean : public UnifyConstraint { // Constant expression must evaluate to true (or false)
  bool istrue;
  RHSConstant *expr;
public:
  ConstraintBoolean(bool ist,RHSConstant *ex) { istrue = ist; expr = ex; maxnum = -1; }
  virtual ~ConstraintBoolean(void) { delete expr; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintBoolean(istrue,expr->clone()))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintVarConst : public UnifyConstraint { // Create a new varnode constant
  int4 varindex;
  RHSConstant *expr;
  RHSConstant *exprsz;
public:
  ConstraintVarConst(int4 ind,RHSConstant *ex,RHSConstant *sz) { varindex = ind; maxnum = ind; expr = ex; exprsz = sz; }
  virtual ~ConstraintVarConst(void);
  virtual UnifyConstraint *clone(void) const;
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return varindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintNamedExpression : public UnifyConstraint {
  int4 constindex;
  RHSConstant *expr;
public:
  ConstraintNamedExpression(int4 ind,RHSConstant *ex) { constindex = ind, expr=ex; maxnum = constindex; }
  virtual ~ConstraintNamedExpression(void) { delete expr; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintNamedExpression(constindex,expr->clone()))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return constindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOpCopy : public UnifyConstraint {
  int4 oldopindex;
  int4 newopindex;
public:
  ConstraintOpCopy(int4 oldind,int4 newind) { oldopindex = oldind; newopindex = newind; maxnum = (oldopindex > newopindex) ? oldopindex : newopindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOpCopy(oldopindex,newopindex))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return oldopindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOpcode : public UnifyConstraint {
  int4 opindex;
  vector<OpCode> opcodes;	// Which opcodes match
public:
  ConstraintOpcode(int4 ind,const vector<OpCode> &o) { maxnum = opindex = ind; opcodes = o; }
  const vector<OpCode> &getOpCodes(void) const { return opcodes; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOpcode(opindex,opcodes))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOpCompare : public UnifyConstraint {
  int4 op1index;
  int4 op2index;
  bool istrue;
public:
  ConstraintOpCompare(int4 op1ind,int4 op2ind,bool val) { op1index = op1ind; op2index = op2ind; istrue = val; maxnum = (op1index > op2index) ? op1index : op2index; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOpCompare(op1index,op2index,istrue))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return op1index; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOpInput : public UnifyConstraint {	// Move from op to one of its input varnodes
  int4 opindex;			// Which op
  int4 varnodeindex;		// Which input varnode
  int4 slot;			// Which slot to take
public:
  ConstraintOpInput(int4 oind,int4 vind,int4 sl) { opindex = oind; varnodeindex = vind; slot = sl; maxnum = (opindex > varnodeindex) ? opindex : varnodeindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOpInput(opindex,varnodeindex,slot))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return varnodeindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOpInputAny : public UnifyConstraint { // Move from op to ANY of its input varnodes
  int4 opindex;			// Which op
  int4 varnodeindex;		// What to label input varnode
public:
  ConstraintOpInputAny(int4 oind,int4 vind) { opindex = oind; varnodeindex = vind;  maxnum = (opindex > varnodeindex) ? opindex : varnodeindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOpInputAny(opindex,varnodeindex))->copyid(this); }
  virtual void initialize(UnifyState &state);
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return varnodeindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOpOutput : public UnifyConstraint {	// Move from op to its output varnode
  int4 opindex;			// Which op
  int4 varnodeindex;		// Label of output varnode
public:
  ConstraintOpOutput(int4 oind,int4 vind) { opindex = oind; varnodeindex = vind; maxnum = (opindex > varnodeindex) ? opindex : varnodeindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOpOutput(opindex,varnodeindex))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return varnodeindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintParamConstVal : public UnifyConstraint {
  int4 opindex;			// Which opcode
  int4 slot;			// Which slot to examine for constant
  uintb val;			// What value parameter must match
public:
  ConstraintParamConstVal(int4 oind,int4 sl,uintb v) { maxnum = opindex = oind; slot=sl; val = v; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintParamConstVal(opindex,slot,val))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintParamConst : public UnifyConstraint {
  int4 opindex;			// Which opcode
  int4 slot;			// Which slot to examine for constant
  int4 constindex;		// Which varnode is the constant
public:
  ConstraintParamConst(int4 oind,int4 sl,int4 cind) { opindex = oind; slot=sl; constindex = cind; maxnum = (opindex > constindex) ? opindex : constindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintParamConst(opindex,slot,constindex))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return constindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintVarnodeCopy : public UnifyConstraint {
  int4 oldvarindex;
  int4 newvarindex;
public:
  ConstraintVarnodeCopy(int4 oldind,int4 newind) { oldvarindex = oldind; newvarindex = newind; maxnum = (oldvarindex > newvarindex) ? oldvarindex : newvarindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintVarnodeCopy(oldvarindex,newvarindex))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return oldvarindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintVarCompare : public UnifyConstraint {
  int4 var1index;
  int4 var2index;
  bool istrue;
public:
  ConstraintVarCompare(int4 var1ind,int4 var2ind,bool val) { var1index = var1ind; var2index = var2ind; istrue = val; maxnum = (var1index > var2index) ? var1index : var2index; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintVarCompare(var1index,var2index,istrue))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return var1index; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintDef : public UnifyConstraint {
  int4 opindex;			// Where to store defining op
  int4 varindex;		// Which varnode to examine for def
public:
  ConstraintDef(int4 oind,int4 vind) { opindex = oind; varindex = vind; maxnum = (opindex > varindex) ? opindex : varindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintDef(opindex,varindex))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintDescend : public UnifyConstraint {
  int4 opindex;
  int4 varindex;
public:
  ConstraintDescend(int4 oind,int4 vind) { opindex = oind; varindex = vind; maxnum = (opindex > varindex) ? opindex : varindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintDescend(opindex,varindex))->copyid(this); }
  virtual void buildTraverseState(UnifyState &state);
  virtual void initialize(UnifyState &state);
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintLoneDescend : public UnifyConstraint {
  int4 opindex;
  int4 varindex;
public:
  ConstraintLoneDescend(int4 oind,int4 vind) { opindex = oind; varindex = vind; maxnum = (opindex > varindex) ? opindex : varindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintLoneDescend(opindex,varindex))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintOtherInput : public UnifyConstraint {
  int4 opindex;			// For a particular binary op
  int4 varindex_in;		// Given one of its input varnodes
  int4 varindex_out;		// Label the other input to op
public:
  ConstraintOtherInput(int4 oind,int4 v_in,int4 v_out) { maxnum = opindex = oind; varindex_in = v_in; varindex_out = v_out; 
    if (varindex_in > maxnum) maxnum = varindex_in; if (varindex_out > maxnum) maxnum = varindex_out; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintOtherInput(opindex,varindex_in,varindex_out))->copyid(this); }
  virtual int4 getBaseIndex(void) const { return varindex_out; }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintConstCompare : public UnifyConstraint {
  int4 const1index;		// Compare two constants resulting in a boolean
  int4 const2index;
  OpCode opc;
public:
  ConstraintConstCompare(int4 c1ind,int4 c2ind,OpCode oc) { const1index = c1ind; const2index = c2ind; opc = oc;
    maxnum = (const1index > const2index) ? const1index : const2index; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintConstCompare(const1index,const2index,opc))->copyid(this); }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual int4 getBaseIndex(void) const { return const1index; }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

// For a ConstraintGroup, the list of subconstraints must all match for the whole constraint to match.
// Constraints are tested first to last, i.e. testing for constraint n can assume that 1 thru n-1 match.
class ConstraintGroup : public UnifyConstraint {
protected:
  vector<UnifyConstraint *> constraintlist;
public:
  ConstraintGroup(void);
  virtual ~ConstraintGroup(void);
  UnifyConstraint *getConstraint(int4 slot) const { return constraintlist[slot]; }
  void addConstraint(UnifyConstraint *a);
  int4 numConstraints(void) const { return constraintlist.size(); }
  void deleteConstraint(int4 slot);
  void mergeIn(ConstraintGroup *b);
  virtual UnifyConstraint *clone(void) const;
  virtual void initialize(UnifyState &state);
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void buildTraverseState(UnifyState &state);
  virtual void setId(int4 &id);
  virtual int4 getBaseIndex(void) const { return constraintlist.back()->getBaseIndex(); }
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
  virtual void removeDummy(void);
};

// For a ConstraintOr, exactly one subconstraint needs to be true, for the whole constraint to match
// The constraints are tested sequentially, but there can be no dependency between subconstraints
class ConstraintOr : public ConstraintGroup {
public:
  virtual UnifyConstraint *clone(void) const;
  virtual void initialize(UnifyState &state);
  virtual bool step(UnifyState &state);
  virtual void buildTraverseState(UnifyState &state);
  virtual int4 getBaseIndex(void) const { return -1; } // Does not have a base
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

// Action constraints, these must always step exactly once (returning true), and do their action

class ConstraintNewOp : public UnifyConstraint {
  int4 newopindex;
  int4 oldopindex;
  bool insertafter;		// true if inserted AFTER oldop
  OpCode opc;			// new opcode
  int4 numparams;
public:
  ConstraintNewOp(int4 newind,int4 oldind,OpCode oc,bool iafter,int4 num);
  virtual UnifyConstraint *clone(void) const { return (new ConstraintNewOp(newopindex,oldopindex,opc,insertafter,numparams))->copyid(this); }
  virtual int4 getBaseIndex(void) const { return newopindex; }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintNewUniqueOut : public UnifyConstraint {
  int4 opindex;
  int4 newvarindex;
  int4 sizevarindex;		// Negative is specific size, Positive is varnode index (for size)
public:
  ConstraintNewUniqueOut(int4 oind,int4 newvarind,int4 sizeind);
  virtual UnifyConstraint *clone(void) const { return (new ConstraintNewUniqueOut(opindex,newvarindex,sizevarindex))->copyid(this); }
  virtual int4 getBaseIndex(void) const { return newvarindex; }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintSetInput : public UnifyConstraint {
  int4 opindex;
  RHSConstant *slot;
  int4 varindex;
public:
  ConstraintSetInput(int4 oind,RHSConstant *sl,int4 varind) { opindex = oind; slot=sl; varindex = varind; maxnum = (opindex > varindex) ? opindex : varindex; }
  virtual ~ConstraintSetInput(void) { delete slot; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintSetInput(opindex,slot->clone(),varindex))->copyid(this); }
  virtual int4 getBaseIndex(void) const { return varindex; }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintSetInputConstVal : public UnifyConstraint {
  int4 opindex;
  RHSConstant *slot;
  RHSConstant *val;
  RHSConstant *exprsz;
public:
  ConstraintSetInputConstVal(int4 oind,RHSConstant *sl,RHSConstant *v,RHSConstant *sz) { opindex=oind; slot=sl; val=v; exprsz = sz; maxnum = opindex; }
  virtual ~ConstraintSetInputConstVal(void);
  virtual UnifyConstraint *clone(void) const;
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintRemoveInput : public UnifyConstraint {
  int4 opindex;
  RHSConstant *slot;
public:
  ConstraintRemoveInput(int4 oind,RHSConstant *sl) { opindex = oind; slot = sl; maxnum = opindex; }
  virtual ~ConstraintRemoveInput(void) { delete slot; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintRemoveInput(opindex,slot->clone()))->copyid(this); }
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class ConstraintSetOpcode : public UnifyConstraint {
  int4 opindex;
  OpCode opc;
public:
  ConstraintSetOpcode(int4 oind,OpCode oc) { opindex = oind; opc = oc; maxnum = opindex; }
  virtual UnifyConstraint *clone(void) const { return (new ConstraintSetOpcode(opindex,opc))->copyid(this); }
  virtual int4 getBaseIndex(void) const { return opindex; }
  virtual bool step(UnifyState &state);
  virtual void collectTypes(vector<UnifyDatatype> &typelist) const;
  virtual void print(ostream &s,UnifyCPrinter &printstate) const;
};

class UnifyState {
  ConstraintGroup *container;	// containing unifyer
  vector<UnifyDatatype> storemap;
  vector<TraverseConstraint *> traverselist;
  Funcdata *fd;
public:
  UnifyState(ConstraintGroup *uni);
  ~UnifyState(void);
  int4 numTraverse(void) const { return traverselist.size(); }
  void registerTraverseConstraint(TraverseConstraint *t) { traverselist.push_back(t); }
  UnifyDatatype &data(int4 slot) { return storemap[slot]; }
  TraverseConstraint *getTraverse(int4 slot) const { return traverselist[slot]; }
  Funcdata *getFunction(void) const { return fd; }
  OpBehavior *getBehavior(OpCode opc);
  void setFunction(Funcdata *f) { fd = f; }
  void initialize(int4 id,Varnode *vn);
  void initialize(int4 id,PcodeOp *op);
};

class UnifyCPrinter {
  vector<UnifyDatatype> storemap;
  vector<string> namemap;
  int4 depth;
  int4 printingtype;		// 0 = standard rule
  string classname;		// Name of the printed class
  int4 opparam;
  vector<OpCode> opcodelist;	// List of opcodes that are recognized by rule
  void initializeBase(ConstraintGroup *g);
  void printGetOpList(ostream &s);
  void printRuleHeader(ostream &s);
  ConstraintGroup *grp;
public:
  UnifyCPrinter(void) { grp = (ConstraintGroup *)0; opparam = -1; printingtype=0; }
  int4 getDepth(void) const { return depth; }
  void incDepth(void) { depth += 1; }
  void decDepth(void) { depth -= 1; }
  void printIndent(ostream &s) const { for(int4 i=0;i<depth+1;++i) s << "  "; }
  void printAbort(ostream &s);
  void popDepth(ostream &s,int4 newdepth);
  const string &getName(int4 id) const { return namemap[id]; }
  void initializeRuleAction(ConstraintGroup *g,int4 opparam,const vector<OpCode> &olist);
  void initializeBasic(ConstraintGroup *g);
  void setClassName(const string &nm) { classname = nm; }
  void addNames(const map<string,int4> &nmmap);
  void printVarDecls(ostream &s) const;
  void print(ostream &s);
	     
};

// Rule language
// Identifiers are strict C identifiers that start with either:
//    'o'  for a pcode op
//    'v'  for a varnode
//    '#'  for a constant
//    'b'  for a basic block
//
// constraints
//    oname ( "opname" )        constrain "oname" to a given opcode
//    oname <-(1) vname         define varnode "vname" as input 1 of "oname"
//    oname <-(1) #45           make sure input 1 to "oname" is the constant value 45
//    oname <-(1) #name         define '#name' as the constant input 1 to "oname"
//    oname -> vname            define "vname" as the output varnode of op "oname"
//    vname <-   oname          define op "oname" is the op which writes "vname"
//    vname ->   oname          define op "oname" as (one of) ops that reads "vname"
//    vname ->!  oname          define op "oname" as the lone ops that reads "vname"
//    oname <- vname != vname1  define "vname" as other input to binary op "oname" besides "vname1"

//    vname1( == vname2)        verify that vname1 and vname2 are the same varnode
//    vname1( != vname2)        verify that vname1 and vname2 are not the same varnode
//    oname1( == oname2)        verify that ops are the same
//    vname1 -> vname2          define vname2 as a copy of vname1
//    oname <- vname            vname is (one of) the inputs to oname

//    statements end with ;
//    Group construct
//    (  statement
//       statement ...
//    }
//    OR construct
//    [  statement  |
//       statement ...
//    ]



//  vhi1 -> oadd1(+) ;
//  [  ( oadd1 -> vadd1 ->! oadd2(+) -> vreshi;
//       oadd1 <- vhizext1( != vhi1);
//       oadd2 <- vhizext2( != vadd1); ) |
//     ( oadd1 <- vtmpvn( != vhi1) <- oadd2(+) <-(0) vhizext1;
//       oadd2 <-(1) vhizext2;
//       oadd1 -> vreshi; ) ]
//  [  ( vhizext1 <- ozext(ZEXT);
//       vhizext2 -> vhi2;             ) |
//     ( vhizext2 <- ozext(ZEXT);
//       vhizext1 -> vhi2;             ) ]
// ozext <-(0) vzextin <- olesseq(<=) <-(0) vlessin <- oneg(*) <-(1) #-1
// [ (oneg <-(0) vtmp (== vlo1);  olesseq <-(1) vlo2; ) |
//   (oneg <-(1) vtmp (== vlo2);  oneg <-(0) vlo2; ) ]
// vlo1 -> oloadd(+) <- vtmp( != vlo1)( == vlo2);
// oloadd -> vreslo;

#endif

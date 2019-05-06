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
#ifdef CPUI_RULECOMPILE
#include "unify.hh"

UnifyDatatype::UnifyDatatype(uint4 tp)

{
  type = tp;
  switch(type) {
  case op_type:
  case var_type:
  case block_type:
    break;
  case const_type:
    storespot.cn = new uintb;
    break;
  default:
    throw LowlevelError("Bad unify datatype");
  }
}

UnifyDatatype::UnifyDatatype(const UnifyDatatype &op2)

{
  type = op2.type;
  switch(type) {
  case op_type:
  case var_type:
  case block_type:
    break;
  case const_type:
    storespot.cn = new uintb; // Copy needs its own memory
    break;
  default:
    throw LowlevelError("Bad unify datatype");
  }
}

UnifyDatatype &UnifyDatatype::operator=(const UnifyDatatype &op2)

{
  switch(type) {
  case op_type:
  case var_type:
  case block_type:
    break;
  case const_type:
    delete storespot.cn;
    break;
  default:
    throw LowlevelError("Bad unify datatype");
  }
  type = op2.type;
  switch(type) {
  case op_type:
  case var_type:
  case block_type:
    break;
  case const_type:
    storespot.cn = new uintb; // Copy needs its own memory
    break;
  default:
    throw LowlevelError("Bad unify datatype");
  }
  return *this;
}

UnifyDatatype::~UnifyDatatype(void)

{
  switch(type) {
  case op_type:
  case var_type:
  case block_type:
    break;
  case const_type:
    delete storespot.cn;
    break;
  default:
    break;
  }
}

void UnifyDatatype::setConstant(uintb val)

{
  *storespot.cn = val;
}

void UnifyDatatype::printVarDecl(ostream &s,int4 id,const UnifyCPrinter &cprinter) const

{
  cprinter.printIndent(s);
  switch(type) {
  case op_type:
    s << "PcodeOp *" << cprinter.getName(id) << ';' << endl;
    break;
  case var_type:
    s << "Varnode *" << cprinter.getName(id) << ';' << endl;
    break;
  case block_type:
    s << "BlockBasic *" << cprinter.getName(id) << ';' << endl;
    break;
  case const_type:
    s << "uintb " << cprinter.getName(id) << ';' << endl;
    break;
  default:
    throw LowlevelError("Bad unify datatype");
  }
}

string UnifyDatatype::getBaseName(void) const

{
  switch(type) {
  case op_type:
    return "op";
  case var_type:
    return "vn";
  case block_type:
    return "bl";
  case const_type:
    return "cn";
  default:
    throw LowlevelError("Bad unify datatype");
  }
}

uintb ConstantNamed::getConstant(UnifyState &state) const

{
  return state.data(constindex).getConstant();
}

void ConstantNamed::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << printstate.getName(constindex);
}

uintb ConstantAbsolute::getConstant(UnifyState &state) const

{
  return val;
}

void ConstantAbsolute::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << "(uintb)0x" << hex << val;
}

uintb ConstantNZMask::getConstant(UnifyState &state) const

{
  Varnode *vn = state.data(varindex).getVarnode();
  return vn->getNZMask();
}

void ConstantNZMask::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << printstate.getName(varindex) << "->getNZMask()";
}

uintb ConstantConsumed::getConstant(UnifyState &state) const

{
  Varnode *vn = state.data(varindex).getVarnode();
  return vn->getConsume();
}

void ConstantConsumed::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << printstate.getName(varindex) << "->getConsume()";
}

uintb ConstantOffset::getConstant(UnifyState &state) const

{
  Varnode *vn = state.data(varindex).getVarnode();
  return vn->getOffset();
}

void ConstantOffset::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << printstate.getName(varindex) << "->getOffset()";
}

uintb ConstantIsConstant::getConstant(UnifyState &state) const

{
  Varnode *vn = state.data(varindex).getVarnode();
  return vn->isConstant() ? (uintb)1 : (uintb)0;
}

void ConstantIsConstant::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << "(uintb)" << printstate.getName(varindex) << "->isConstant()";
}

uintb ConstantHeritageKnown::getConstant(UnifyState &state) const

{
  Varnode *vn = state.data(varindex).getVarnode();
  return (uintb)(vn->isHeritageKnown() ? 1 : 0);
}

void ConstantHeritageKnown::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << "(uintb)" << printstate.getName(varindex) << "->isHeritageKnown()";
}

uintb ConstantVarnodeSize::getConstant(UnifyState &state) const

{
  Varnode *vn = state.data(varindex).getVarnode();
  return (uintb)vn->getSize();	// The size is the actual value
}

void ConstantVarnodeSize::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  s << "(uintb)" << printstate.getName(varindex) << "->getSize()";
}

ConstantExpression::~ConstantExpression(void)

{
  delete expr1;
  if (expr2 != (RHSConstant *)0)
    delete expr2;
}

RHSConstant *ConstantExpression::clone(void)

{
  RHSConstant *ecopy1 = expr1->clone();
  RHSConstant *ecopy2 = (RHSConstant *)0;
  if (expr2 != (RHSConstant *)0)
    ecopy2 = expr2->clone();
  return new ConstantExpression(ecopy1,ecopy2,opc);
}

uintb ConstantExpression::getConstant(UnifyState &state) const

{
  OpBehavior *behavior = state.getBehavior(opc);
  if (behavior->isSpecial())
    throw LowlevelError("Cannot evaluate special operator in constant expression");
  uintb res;
  if (behavior->isUnary()) {
    uintb ourconst1 = expr1->getConstant(state);
    res = behavior->evaluateUnary(sizeof(uintb),sizeof(uintb),ourconst1);
  }
  else {
    uintb ourconst1 = expr1->getConstant(state);
    uintb ourconst2 = expr2->getConstant(state);
    res = behavior->evaluateBinary(sizeof(uintb),sizeof(uintb),ourconst1,ourconst2);
  }
  return res;
}

void ConstantExpression::writeExpression(ostream &s,UnifyCPrinter &printstate) const

{
  int4 type;			// 0=binary 1=unarypre 2=unarypost 3=func
  string name;			// name of operator
  switch(opc) {
  case CPUI_INT_ADD:
    type=0;
    name = " + ";
    break;
  case CPUI_INT_SUB:
    type=0;
    name = " - ";
    break;
  case CPUI_INT_AND:
    type=0;
    name = " & ";
    break;
  case CPUI_INT_OR:
    type=0;
    name = " | ";
    break;
  case CPUI_INT_XOR:
    type=0;
    name = " ^ ";
    break;
  case CPUI_INT_MULT:
    type = 0;
    name = " * ";
    break;
  case CPUI_INT_DIV:
    type = 0;
    name = " / ";
    break;
  case CPUI_INT_EQUAL:
    type = 0;
    name = " == ";
    break;
  case CPUI_INT_NOTEQUAL:
    type = 0;
    name = " != ";
    break;
    //  case CPUI_INT_SLESS:
    //  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
    type = 0;
    name = " < ";
    break;
  case CPUI_INT_LESSEQUAL:
    type = 0;
    name = " <= ";
    break;
    //  case CPUI_INT_ZEXT:
    //  case CPUI_INT_SEXT:
    //  case CPUI_INT_CARRY:
    //  case CPUI_INT_SCARRY:
    //  case CPUI_INT_SBORROW:
  case CPUI_INT_LEFT:
    type = 0;
    name = " << ";
    break;
  case CPUI_INT_RIGHT:
    type = 0;
    name = " >> ";
    break;
    //  case CPUI_INT_SRIGHT:
  default:
    throw LowlevelError("Unable to generate C for this expression element");
  }
  if (type==0) {
    s << '(';
    expr1->writeExpression(s,printstate);
    s << name;
    expr2->writeExpression(s,printstate);
    s << ')';
  }
  else if (type==1) {
    s << '(' << name;
    expr1->writeExpression(s,printstate);
    s << ')';
  }
  else if (type==2) {
    s << '(';
    expr1->writeExpression(s,printstate);
    s << name << ')';
  }
  else {
    s << name << '(';
    expr1->writeExpression(s,printstate);
    s << ')';
  }
}

void UnifyConstraint::initialize(UnifyState &state)

{				// Default initialization (with only 1 state)
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  traverse->initialize(1);	// Initialize with only one state
}

void UnifyConstraint::buildTraverseState(UnifyState &state)

{				// Build the default boolean traversal state
  if (uniqid != state.numTraverse())
    throw LowlevelError("Traverse id does not match index");
  TraverseConstraint *newt = new TraverseCountState(uniqid);
  state.registerTraverseConstraint(newt);
}

bool ConstraintBoolean::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  uintb ourconst = expr->getConstant(state);
  if (istrue)
    return (ourconst != 0);
  return (ourconst == 0);
}

void ConstraintBoolean::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (";
  expr->writeExpression(s,printstate);
  if (istrue)
    s << "== 0)";		// If false abort
  else
    s << "!= 0)";		// If true abort
  s << endl;
  printstate.printAbort(s);
}

ConstraintVarConst::~ConstraintVarConst(void)

{
  delete expr;
  if (exprsz != (RHSConstant *)0)
    delete exprsz;
}

UnifyConstraint *ConstraintVarConst::clone(void) const

{
  UnifyConstraint *res;
  RHSConstant *newexprsz = (RHSConstant *)0;
  if (exprsz != (RHSConstant *)0)
    newexprsz = exprsz->clone();
  res = (new ConstraintVarConst(varindex,expr->clone(),newexprsz))->copyid(this);
  return res;
}

bool ConstraintVarConst::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  uintb ourconst = expr->getConstant(state);
  Funcdata *fd = state.getFunction();
  int4 sz;
  if (exprsz != (RHSConstant *)0)
    sz = (int4)exprsz->getConstant(state);
  else
    sz = (int4)sizeof(uintb);
  ourconst &= calc_mask(sz);
  Varnode *vn = fd->newConstant( sz, ourconst );
  state.data(varindex).setVarnode(vn);
  return true;
}

void ConstraintVarConst::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintVarConst::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(varindex) << " = data.newConstant(";
  if (exprsz != (RHSConstant *)0)
    exprsz->writeExpression(s,printstate);
  else
    s << dec << (int4)sizeof(uintb);
  s << ',';
  expr->writeExpression(s,printstate);
  s << " & calc_mask(";
  exprsz->writeExpression(s,printstate);
  s << "));" << endl;
}

bool ConstraintNamedExpression::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  uintb ourconst = expr->getConstant(state);
  state.data(constindex).setConstant(ourconst);
  return true;
}

void ConstraintNamedExpression::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[constindex] = UnifyDatatype(UnifyDatatype::const_type);
}

void ConstraintNamedExpression::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(constindex) << " = ";
  expr->writeExpression(s,printstate);
  s << ';' << endl;
}

bool ConstraintOpCopy::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(oldopindex).getOp();
  state.data(newopindex).setOp(op);
  return true;
}

void ConstraintOpCopy::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[oldopindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[newopindex] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintOpCopy::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(newopindex) << " = " << printstate.getName(oldopindex) << ';' << endl;
}

bool ConstraintOpcode::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  for(int4 i=0;i<opcodes.size();++i)
    if (op->code() == opcodes[i]) return true;
  return false;
}

void ConstraintOpcode::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintOpcode::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (";
  if (opcodes.size()==1) {
    s << printstate.getName(opindex) << "->code() != CPUI_" << get_opname(opcodes[0]);
  }
  else {
    s << '(' << printstate.getName(opindex) << "->code() != CPUI_" << get_opname(opcodes[0]) << ')';
    for(int4 i=1;i<opcodes.size();++i) {
      s << "&&";
      s << '(' << printstate.getName(opindex) << "->code() != CPUI_" << get_opname(opcodes[i]) << ')';
    }
  }
  s << ')' << endl;
  printstate.printAbort(s);
}

bool ConstraintOpCompare::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op1 = state.data(op1index).getOp();
  PcodeOp *op2 = state.data(op2index).getOp();
  return ((op1==op2) == istrue);
}

void ConstraintOpCompare::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[op1index] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[op2index] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintOpCompare::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (" << printstate.getName(op1index);
  if (istrue)
    s << " != ";
  else
    s << " == ";
  s << printstate.getName(op2index) << ')' << endl;
  printstate.printAbort(s);
}

bool ConstraintOpInput::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = op->getIn(slot);
  state.data(varnodeindex).setVarnode(vn);
  return true;
}

void ConstraintOpInput::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varnodeindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintOpInput::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(varnodeindex) << " = " << printstate.getName(opindex);
  s << "->getIn(" << dec << slot << ");" << endl;
}

void ConstraintOpInputAny::initialize(UnifyState &state)

{				// Default initialization (with only 1 state)
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  PcodeOp *op = state.data(opindex).getOp();
  traverse->initialize(op->numInput());	// Initialize total number of inputs
}

bool ConstraintOpInputAny::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = op->getIn(traverse->getState());
  state.data(varnodeindex).setVarnode(vn);
  return true;
}

void ConstraintOpInputAny::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varnodeindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintOpInputAny::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "for(int4 i" << dec << printstate.getDepth() << "=0;i"<<printstate.getDepth()<< '<';
  s << printstate.getName(opindex) << "->numInput();++i" << printstate.getDepth() << ") {" << endl;
  printstate.incDepth();	// A permanent increase in depth
  printstate.printIndent(s);
  s << printstate.getName(varnodeindex) << " = " << printstate.getName(opindex) << "->getIn(i";
  s << (printstate.getDepth()-1) << ");" << endl;
}

bool ConstraintOpOutput::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = op->getOut();
  state.data(varnodeindex).setVarnode(vn);
  return true;
}

void ConstraintOpOutput::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varnodeindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintOpOutput::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(varnodeindex) << " = " << printstate.getName(opindex) << "->getOut();" << endl;
}

bool ConstraintParamConstVal::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = op->getIn(slot);
  if (!vn->isConstant()) return false;
  if (vn->getOffset() != (val&calc_mask(vn->getSize()))) return false;
  return true;
}

void ConstraintParamConstVal::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintParamConstVal::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (!" << printstate.getName(opindex) << "->getIn(" << dec << slot << ")->isConstant())" << endl;
  printstate.printAbort(s);
  printstate.printIndent(s);
  s << "if (" << printstate.getName(opindex) << "->getIn(" << dec << slot << ")->getOffset() != 0x";
  s << hex << val << " & calc_mask(" << printstate.getName(opindex) << "->getIn(" << dec;
  s << slot << ")->getSize()))" << endl;
  printstate.printAbort(s);
}

bool ConstraintParamConst::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = op->getIn(slot);
  if (!vn->isConstant()) return false;
  state.data(constindex).setConstant(vn->getOffset());
  return true;
}

void ConstraintParamConst::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[constindex] = UnifyDatatype(UnifyDatatype::const_type);
}

void ConstraintParamConst::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (!" << printstate.getName(opindex) << "->getIn(" << dec << slot << ")->isConstant())" << endl;
  printstate.printAbort(s);
  printstate.printIndent(s);
  s << printstate.getName(constindex) << " = ";
  s << printstate.getName(opindex) << "->getIn(" << dec << slot << ")->getOffset();" << endl;
}

bool ConstraintVarnodeCopy::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Varnode *vn = state.data(oldvarindex).getVarnode();
  state.data(newvarindex).setVarnode(vn);
  return true;
}

void ConstraintVarnodeCopy::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[oldvarindex] = UnifyDatatype(UnifyDatatype::var_type);
  typelist[newvarindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintVarnodeCopy::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(newvarindex) << " = " << printstate.getName(oldvarindex) << ';' << endl;
}

bool ConstraintVarCompare::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Varnode *vn1 = state.data(var1index).getVarnode();
  Varnode *vn2 = state.data(var2index).getVarnode();
  return ((vn1 == vn2)==istrue);
}

void ConstraintVarCompare::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[var1index] = UnifyDatatype(UnifyDatatype::var_type);
  typelist[var2index] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintVarCompare::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (" << printstate.getName(var1index);
  if (istrue)
    s << " != ";
  else
    s << " == ";
  s << printstate.getName(var2index) << ')' << endl;
  printstate.printAbort(s);
}

bool ConstraintDef::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Varnode *vn = state.data(varindex).getVarnode();
  if (!vn->isWritten()) return false;
  PcodeOp *op = vn->getDef();
  state.data(opindex).setOp(op);
  return true;
}

void ConstraintDef::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintDef::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (!" << printstate.getName(varindex) << "->isWritten())" << endl;
  printstate.printAbort(s);
  printstate.printIndent(s);
  s << printstate.getName(opindex) << " = " << printstate.getName(varindex) << "->getDef();" << endl;
}

void ConstraintDescend::buildTraverseState(UnifyState &state)

{
  if (uniqid != state.numTraverse())
    throw LowlevelError("Traverse id does not match index");
  TraverseConstraint *newt = new TraverseDescendState(uniqid);
  state.registerTraverseConstraint(newt);
}

void ConstraintDescend::initialize(UnifyState &state)

{
  TraverseDescendState *traverse = (TraverseDescendState *)state.getTraverse(uniqid);
  Varnode *vn = state.data(varindex).getVarnode();
  traverse->initialize(vn);
}

bool ConstraintDescend::step(UnifyState &state)

{
  TraverseDescendState *traverse = (TraverseDescendState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = traverse->getCurrentOp();
  state.data(opindex).setOp(op);
  return true;
}

void ConstraintDescend::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintDescend::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "list<PcodeOp *>::const_iterator iter" << dec << printstate.getDepth() << ",enditer" << printstate.getDepth() << ';' << endl;
  printstate.printIndent(s);
  s << "iter" << printstate.getDepth() << " = " << printstate.getName(varindex) << "->beginDescend();" << endl;
  printstate.printIndent(s);
  s << "enditer" << printstate.getDepth() << " = " << printstate.getName(varindex) << "->endDescend();" << endl;
  printstate.printIndent(s);
  s << "while(iter" << printstate.getDepth() << " != enditer" << printstate.getDepth() << ") {" << endl;
  printstate.incDepth();	// permanent increase in depth
  printstate.printIndent(s);
  s << printstate.getName(opindex) << " = *iter" << (printstate.getDepth()-1) << ';' << endl;
  printstate.printIndent(s);
  s << "++iter" << (printstate.getDepth()-1) << endl;
}

bool ConstraintLoneDescend::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Varnode *vn = state.data(varindex).getVarnode();
  PcodeOp *res = vn->loneDescend();
  if (res == (PcodeOp *)0) return false;
  state.data(opindex).setOp(res);
  return true;
}

void ConstraintLoneDescend::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintLoneDescend::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(opindex) << " = " << printstate.getName(varindex) << "->loneDescend();" << endl;
  printstate.printIndent(s);
  s << "if (" << printstate.getName(opindex) << " == (PcodeOp *)0)" << endl;
  printstate.printAbort(s);
}

bool ConstraintOtherInput::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = state.data(varindex_in).getVarnode();
  Varnode *res = op->getIn(1-op->getSlot(vn)); // Get the "other" input
  state.data(varindex_out).setVarnode(res);
  return true;
}

void ConstraintOtherInput::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varindex_in] = UnifyDatatype(UnifyDatatype::var_type);
  typelist[varindex_out] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintOtherInput::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(varindex_out) << " = " << printstate.getName(opindex) << "->getIn(1 - ";
  s << printstate.getName(opindex) << "->getSlot(" << printstate.getName(varindex_in) << "));" << endl;
}

bool ConstraintConstCompare::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  uintb c1 = state.data(const1index).getConstant();
  uintb c2 = state.data(const2index).getConstant();
  // This only does operations with boolean result
  OpBehavior *behavior = state.getBehavior(opc);
  uintb res = behavior->evaluateBinary(1,sizeof(uintb),c1,c2);
  return (res != 0);
}

void ConstraintConstCompare::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[const1index] = UnifyDatatype(UnifyDatatype::const_type);
  typelist[const2index] = UnifyDatatype(UnifyDatatype::const_type);
}

void ConstraintConstCompare::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "if (";
  switch(opc) {
  case CPUI_INT_EQUAL:
    s << printstate.getName(const1index) << " != " << printstate.getName(const2index);
    break;
  case CPUI_INT_NOTEQUAL:
    s << printstate.getName(const1index) << " == " << printstate.getName(const2index);
    break;
  default:
    s << "/* unimplemented constant operation */" ;
    break;
  }
  s << ')' << endl;
  printstate.printAbort(s);
}

ConstraintGroup::ConstraintGroup(void)

{
  maxnum = -1;
}

ConstraintGroup::~ConstraintGroup(void)

{
  for(uint4 i=0;i<constraintlist.size();++i)
    delete constraintlist[i];
  // We do not own the traverselist objects
}

void ConstraintGroup::addConstraint(UnifyConstraint *c)

{
  constraintlist.push_back(c);

  if (c->getMaxNum() > maxnum)
    maxnum = c->getMaxNum();
}

void ConstraintGroup::deleteConstraint(int4 slot)

{
  vector<UnifyConstraint *>::iterator iter = constraintlist.begin();
  iter = iter + slot;
  UnifyConstraint *mydel = *iter;
  constraintlist.erase(iter);
  delete mydel;
}

void ConstraintGroup::mergeIn(ConstraintGroup *b)

{ // Merge all the subconstraints from -b- into this
  for(int4 i=0;i<b->constraintlist.size();++i)
    addConstraint(b->constraintlist[i]);
  b->constraintlist.clear();	// Constraints are no longer controlled by -b-
  delete b;
}

UnifyConstraint *ConstraintGroup::clone(void) const

{
  ConstraintGroup *res = new ConstraintGroup();
  for(int4 i=0;i<constraintlist.size();++i) {
    UnifyConstraint *subconst = constraintlist[i]->clone();
    res->constraintlist.push_back(subconst);
  }
  res->copyid(this);
  return res;
}

void ConstraintGroup::initialize(UnifyState &state)

{
  TraverseGroupState *traverse = (TraverseGroupState *)state.getTraverse(uniqid);
  traverse->setState(-1);
}

bool ConstraintGroup::step(UnifyState &state)

{
  TraverseGroupState *traverse = (TraverseGroupState *)state.getTraverse(uniqid);

  UnifyConstraint *subconstraint;
  TraverseConstraint *subtraverse;
  int4 subindex;
  int4 stateint;
  int4 max = constraintlist.size();
  do {
    stateint = traverse->getState();
    if (stateint == 0) {		// Attempt a step at current constraint
      subindex = traverse->getCurrentIndex();
      subtraverse = traverse->getSubTraverse(subindex);
      subconstraint = constraintlist[subindex];
      if (subconstraint->step(state)) {
	traverse->setState(1);	// Now try a push
	subindex += 1;
	traverse->setCurrentIndex(subindex);
      }
      else {
	subindex -= 1;
	if (subindex < 0) return false;	// Popped off the top
	traverse->setCurrentIndex(subindex);
	traverse->setState(0);	// Try a step next
      }
    }
    else if (stateint == 1) {	// Push
      subindex = traverse->getCurrentIndex();
      subtraverse = traverse->getSubTraverse(subindex);
      subconstraint = constraintlist[subindex];
      subconstraint->initialize(state);
      traverse->setState(0);	// Try a step next
    }
    else {			// Very first time through
      traverse->setCurrentIndex(0);
      subindex = 0;
      subtraverse = traverse->getSubTraverse(subindex);
      subconstraint = constraintlist[subindex];
      subconstraint->initialize(state);	// Initialize the very first subcontraint
      traverse->setState(0);	// Now try a step
    }
  } while(subindex < max);
  subindex -= 1;
  traverse->setCurrentIndex(subindex);
  traverse->setState(0);	// Have full solution, do step next, to get to next solution
  return true;
}

void ConstraintGroup::collectTypes(vector<UnifyDatatype> &typelist) const

{
  for(int4 i=0;i<constraintlist.size();++i)
    constraintlist[i]->collectTypes(typelist);
}

void ConstraintGroup::buildTraverseState(UnifyState &state)

{
  if (uniqid != state.numTraverse())
    throw LowlevelError("Traverse id does not match index");
  TraverseGroupState *basetrav = new TraverseGroupState(uniqid);
  state.registerTraverseConstraint(basetrav);

  for(int4 i=0;i<constraintlist.size();++i) {
    UnifyConstraint *subconstraint = constraintlist[i];
    subconstraint->buildTraverseState(state);
    TraverseConstraint *subtraverse = state.getTraverse(subconstraint->getId());
    basetrav->addTraverse(subtraverse);
  }
}

void ConstraintGroup::setId(int4 &id)

{
  UnifyConstraint::setId(id);
  for(int4 i=0;i<constraintlist.size();++i)
    constraintlist[i]->setId(id);
}

void ConstraintGroup::print(ostream &s,UnifyCPrinter &printstate) const

{
  for(int4 i=0;i<constraintlist.size();++i)
    constraintlist[i]->print(s,printstate);
}

void ConstraintGroup::removeDummy(void)

{ // Remove any dummy constraints within us
  vector<UnifyConstraint *> newlist;

  for(int4 i=0;i<constraintlist.size();++i) {
    UnifyConstraint *cur = constraintlist[i];
    if (cur->isDummy()) {
      delete cur;
    }
    else {
      cur->removeDummy();
      newlist.push_back(cur);
    }
  }
  constraintlist = newlist;
}

UnifyConstraint *ConstraintOr::clone(void) const

{
  ConstraintOr *res = new ConstraintOr();
  for(int4 i=0;i<constraintlist.size();++i) {
    UnifyConstraint *subconst = constraintlist[i]->clone();
    res->constraintlist.push_back(subconst);
  }
  res->copyid(this);
  return res;
}

void ConstraintOr::initialize(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  traverse->initialize(constraintlist.size());
}

bool ConstraintOr::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  int4 stateind = traverse->getState();
  UnifyConstraint *cur;
  if (stateind == -1) { // First time through
    if (!traverse->step()) return false;
    stateind = traverse->getState();
    cur = getConstraint(stateind);
    cur->initialize(state);
  }
  else
    cur = getConstraint(stateind);
  for(;;) {
    if (cur->step(state)) return true;
    if (!traverse->step()) break;
    stateind = traverse->getState();
    cur = getConstraint(stateind);
    cur->initialize(state);
  }
  return false;
}

void ConstraintOr::buildTraverseState(UnifyState &state)

{
  if (uniqid != state.numTraverse())
    throw LowlevelError("Traverse id does not match index in or");
  TraverseCountState *trav = new TraverseCountState(uniqid);
  state.registerTraverseConstraint(trav);

  for(int4 i=0;i<constraintlist.size();++i) {
    UnifyConstraint *subconstraint = constraintlist[i];
    subconstraint->buildTraverseState(state);
  }
}

void ConstraintOr::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "for(i" << dec << printstate.getDepth() << "=0;i" << printstate.getDepth() << '<';
  s << (int4)constraintlist.size() << ";++i" << printstate.getDepth() << ") {" << endl;
  printstate.incDepth();	// permanent increase in depth
  for(int4 i=0;i<constraintlist.size();++i) {
    printstate.printIndent(s);
    if (i != 0)
      s << "else ";
    if (i != constraintlist.size()-1)
      s << "if (i" << printstate.getDepth()-1 << " == " << dec << i << ") ";
    s << '{' << endl;
    int4 olddepth = printstate.getDepth();
    printstate.incDepth();
    constraintlist[i]->print(s,printstate);
    printstate.popDepth(s,olddepth);
  }
}

ConstraintNewOp::ConstraintNewOp(int4 newind,int4 oldind,OpCode oc,bool iafter,int4 num)

{
  newopindex = newind;
  oldopindex = oldind;
  opc = oc;
  insertafter = iafter;
  numparams = num;
  maxnum = (newind > oldind) ? newind : oldind;
}

bool ConstraintNewOp::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Funcdata *fd = state.getFunction();
  PcodeOp *op = state.data(oldopindex).getOp();
  PcodeOp *newop = fd->newOp(numparams,op->getAddr());
  fd->opSetOpcode(newop,opc);
  if (insertafter)
    fd->opInsertAfter(newop,op);
  else
    fd->opInsertBefore(newop,op);
  return true;
}

void ConstraintNewOp::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[newopindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[oldopindex] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintNewOp::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(newopindex) << " = data.newOp(" << dec << numparams;
  s << ',' << printstate.getName(oldopindex) << "->getAddr());" << endl;
  printstate.printIndent(s);
  s << "data.opSetOpcode(" << printstate.getName(newopindex) << ",CPUI_" << get_opname(opc) << ");" << endl;
  s << "data.opInsert";
  if (insertafter)
    s << "After(";
  else
    s << "Before(";
  s << printstate.getName(newopindex) << ',' << printstate.getName(oldopindex) << ");" << endl;
}

ConstraintNewUniqueOut::ConstraintNewUniqueOut(int4 oind,int4 newvarind,int4 sizeind)

{
  opindex = oind;
  newvarindex = newvarind;
  sizevarindex = sizeind;
  maxnum = (opindex > newvarindex) ? opindex : newvarindex;
  if (sizevarindex > maxnum)
    maxnum = sizevarindex;
}

bool ConstraintNewUniqueOut::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Funcdata *fd = state.getFunction();
  PcodeOp *op = state.data(opindex).getOp();
  int4 sz;
  if (sizevarindex < 0)
    sz = -sizevarindex;		// A specific size
  else {
    Varnode *sizevn = state.data(sizevarindex).getVarnode();
    sz = sizevn->getSize();
  }
  Varnode *newvn = fd->newUniqueOut(sz,op);
  state.data(newvarindex).setVarnode(newvn);
  return true;
}

void ConstraintNewUniqueOut::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[newvarindex] = UnifyDatatype(UnifyDatatype::var_type);
  if (sizevarindex >= 0)
    typelist[sizevarindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintNewUniqueOut::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << printstate.getName(newvarindex) << " = data.newUniqueOut(";
  if (sizevarindex < 0)
    s << dec << -sizevarindex;
  else
    s << printstate.getName(sizevarindex) << "->getSize()";
  s << ',' << printstate.getName(opindex) << ");" << endl;
}

bool ConstraintSetInput::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Funcdata *fd = state.getFunction();
  PcodeOp *op = state.data(opindex).getOp();
  Varnode *vn = state.data(varindex).getVarnode();
  int4 slt = (int4)slot->getConstant(state);
  fd->opSetInput(op,vn,slt);
  return true;
}

void ConstraintSetInput::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintSetInput::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "data.opSetInput(" << printstate.getName(opindex) << ',' << printstate.getName(varindex);
  s << ',';
  slot->writeExpression(s,printstate);
  s << ");" << endl;
}

ConstraintSetInputConstVal::~ConstraintSetInputConstVal(void)

{
  delete val;
  delete slot;
  if (exprsz != (RHSConstant *)0)
    delete exprsz;
}

UnifyConstraint *ConstraintSetInputConstVal::clone(void) const

{
  RHSConstant *newexprsz = (RHSConstant *)0;
  if (exprsz != (RHSConstant *)0)
    newexprsz = exprsz->clone();
  UnifyConstraint *res;
  res = (new ConstraintSetInputConstVal(opindex,slot->clone(),val->clone(),newexprsz))->copyid(this);
  return res;
}

bool ConstraintSetInputConstVal::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Funcdata *fd = state.getFunction();
  PcodeOp *op = state.data(opindex).getOp();
  uintb ourconst = val->getConstant(state);
  int4 sz;
  if (exprsz != (RHSConstant *)0)
    sz = (int4)exprsz->getConstant(state);
  else
    sz = (int4)sizeof(uintb);
  int4 slt = (int4)slot->getConstant(state);
  fd->opSetInput(op,fd->newConstant(sz,ourconst&calc_mask(sz)),slt);
  return true;
}

void ConstraintSetInputConstVal::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
  //  typelist[varindex] = UnifyDatatype(UnifyDatatype::var_type);
}

void ConstraintSetInputConstVal::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "data.opSetInput(" << printstate.getName(opindex) << ",data.newConstant(";
  if (exprsz != (RHSConstant *)0)
    exprsz->writeExpression(s,printstate);
  else
    s << dec << (int4)sizeof(uintb);
  s << ",calc_mask(";
  if (exprsz != (RHSConstant *)0)
    exprsz->writeExpression(s,printstate);
  else
    s << dec << (int4)sizeof(uintb);
  s << ")&";
  val->writeExpression(s,printstate);
  s << "),";
  slot->writeExpression(s,printstate);
  s << ");" << endl;
}

bool ConstraintRemoveInput::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Funcdata *fd = state.getFunction();
  PcodeOp *op = state.data(opindex).getOp();
  int4 slt = (int4)slot->getConstant(state);
  fd->opRemoveInput(op,slt);
  return true;
}

void ConstraintRemoveInput::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintRemoveInput::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "data.opRemoveInput(" << printstate.getName(opindex) << ',';
  slot->writeExpression(s,printstate);
  s << ");" << endl;
}

bool ConstraintSetOpcode::step(UnifyState &state)

{
  TraverseCountState *traverse = (TraverseCountState *)state.getTraverse(uniqid);
  if (!traverse->step()) return false;
  Funcdata *fd = state.getFunction();
  PcodeOp *op = state.data(opindex).getOp();
  fd->opSetOpcode(op,opc);
  return true;
}

void ConstraintSetOpcode::collectTypes(vector<UnifyDatatype> &typelist) const

{
  typelist[opindex] = UnifyDatatype(UnifyDatatype::op_type);
}

void ConstraintSetOpcode::print(ostream &s,UnifyCPrinter &printstate) const

{
  printstate.printIndent(s);
  s << "data.opSetOpcode(" << printstate.getName(opindex) << ",CPUI_" << get_opname(opc) << ");" << endl;
}

UnifyState::UnifyState(ConstraintGroup *uni)

{
  container = uni;
  storemap.resize(container->getMaxNum()+1,UnifyDatatype());
  container->collectTypes(storemap);
  container->buildTraverseState(*this);
}

UnifyState::~UnifyState(void)

{
  for(int4 i=0;i<traverselist.size();++i)
    delete traverselist[i];
}

OpBehavior *UnifyState::getBehavior(OpCode opc)

{ // Get the behavior associated with a particular opcode
  Architecture *glb = fd->getArch();
  return glb->inst[opc]->getBehavior();
}

void UnifyState::initialize(int4 id,Varnode *vn)

{ // Enter an initial varnode (root) starting point
  storemap[id].setVarnode(vn);
}

void UnifyState::initialize(int4 id,PcodeOp *op)

{ // Enter an initial op (root) starting point
  storemap[id].setOp(op);
}

void UnifyCPrinter::initializeBase(ConstraintGroup *g)

{
  grp = g;
  depth = 0;
  namemap.clear();
  storemap.clear();
  opparam = -1;
  opcodelist.clear();
  int4 maxop = g->getMaxNum();
  storemap.resize(maxop+1,UnifyDatatype());
  
  g->collectTypes(storemap);

  for(int4 i=0;i<=maxop;++i) {
    ostringstream s;
    s << storemap[i].getBaseName() << dec << i;
    namemap.push_back(s.str());
  }
}

void UnifyCPrinter::printGetOpList(ostream &s)

{ // Print the getOpList method of the new rule
  s << "void " << classname << "::getOpList(vector<uint4> &oplist) const" << endl;
  s << endl;
  s << '{' << endl;
  for(int4 i=0;i<opcodelist.size();++i) {
    s << "  oplist.push_back(CPUI_" << get_opname(opcodelist[i]) << ");" << endl;
  }
  s << '}' << endl;
  s << endl;
}

void UnifyCPrinter::printRuleHeader(ostream &s)

{ // print the header for the applyOp method of the rule
  s << "int " << classname << "::applyOp(PcodeOp *" << namemap[opparam] << ",Funcdata &data)" << endl;
  s << endl;
  s << '{' << endl;
}

void UnifyCPrinter::printAbort(ostream &s)

{
  depth += 1;
  printIndent(s);
  if (depth >1)
    s << "continue;";
  else {
    if (printingtype == 0)
      s << "return 0;";
    else
      s << "return false;";
  }
  depth -= 1;
  s << endl;
}

void UnifyCPrinter::popDepth(ostream &s,int4 newdepth)

{
  while(depth != newdepth) {
    depth -= 1;
    printIndent(s);
    s << '}' << endl;
  }
}

void UnifyCPrinter::printVarDecls(ostream &s) const

{ // Print the variables declarations
  for(int4 i=0;i<namemap.size();++i) {
    if (i==opparam) continue;
    storemap[i].printVarDecl(s,i,*this);
  }
  if (namemap.size() != 0)
    s << endl;			// Extra blank line
}

void UnifyCPrinter::initializeRuleAction(ConstraintGroup *g,int4 opp,const vector<OpCode> &oplist)

{
  initializeBase(g);
  printingtype = 0;
  classname = "DummyRule";

  opparam = opp;
  opcodelist = oplist;
}

void UnifyCPrinter::initializeBasic(ConstraintGroup *g)

{
  initializeBase(g);
  printingtype = 1;
  opparam = -1;
}

void UnifyCPrinter::addNames(const map<string,int4> &nmmap)

{
  map<string,int4>::const_iterator iter;

  for(iter=nmmap.begin();iter!=nmmap.end();++iter) {
    int4 slot = (*iter).second;
    if (namemap.size() <= slot)
      throw LowlevelError("Name indices do not match constraint");
    namemap[slot] = (*iter).first;
  }
}

void UnifyCPrinter::print(ostream &s)

{
  if (printingtype == 0) {
    printGetOpList(s);
    s << endl;
    printRuleHeader(s);
    printVarDecls(s);
    grp->print(s,*this);
    printIndent(s);
    s << "return 1;" << endl;	// Found a complete match
    if (depth != 0) {
      popDepth(s,0);
      printIndent(s);
      s << "return 0;" << endl;	// Could never find a complete match
    }
    s << '}' << endl;
  }
  else if (printingtype == 1) {
    printVarDecls(s);
    grp->print(s,*this);
    printIndent(s);
    s << "return true;" << endl;
    if (depth != 0) {
      popDepth(s,0);
      printIndent(s);
      s << "return false;" << endl;
    }
    s << '}' << endl;
  }
}

#endif

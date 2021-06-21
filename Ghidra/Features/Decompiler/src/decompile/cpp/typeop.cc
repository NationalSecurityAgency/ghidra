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
#include "typeop.hh"
#include "funcdata.hh"
#include <cmath>

/// \param inst will hold the array of TypeOp objects, indexed on op-code
/// \param tlst is the corresponding TypeFactory for the Architecture
/// \param trans is the Translate object for floating-point formats
void TypeOp::registerInstructions(vector<TypeOp *> &inst,TypeFactory *tlst,
				  const Translate *trans)
{
  inst.insert(inst.end(),CPUI_MAX,(TypeOp *)0);

  inst[CPUI_COPY] = new TypeOpCopy(tlst);
  inst[CPUI_LOAD] = new TypeOpLoad(tlst);
  inst[CPUI_STORE] = new TypeOpStore(tlst);
  inst[CPUI_BRANCH] = new TypeOpBranch(tlst);
  inst[CPUI_CBRANCH] = new TypeOpCbranch(tlst);
  inst[CPUI_BRANCHIND] = new TypeOpBranchind(tlst);
  inst[CPUI_CALL] = new TypeOpCall(tlst);
  inst[CPUI_CALLIND] = new TypeOpCallind(tlst);
  inst[CPUI_CALLOTHER] = new TypeOpCallother(tlst);
  inst[CPUI_RETURN] = new TypeOpReturn(tlst);

  inst[CPUI_MULTIEQUAL] = new TypeOpMulti(tlst);
  inst[CPUI_INDIRECT] = new TypeOpIndirect(tlst);

  inst[CPUI_PIECE] = new TypeOpPiece(tlst);
  inst[CPUI_SUBPIECE] = new TypeOpSubpiece(tlst);
  inst[CPUI_INT_EQUAL] = new TypeOpEqual(tlst);
  inst[CPUI_INT_NOTEQUAL] = new TypeOpNotEqual(tlst);
  inst[CPUI_INT_SLESS] = new TypeOpIntSless(tlst);
  inst[CPUI_INT_SLESSEQUAL] = new TypeOpIntSlessEqual(tlst);
  inst[CPUI_INT_LESS] = new TypeOpIntLess(tlst);
  inst[CPUI_INT_LESSEQUAL] = new TypeOpIntLessEqual(tlst);
  inst[CPUI_INT_ZEXT] = new TypeOpIntZext(tlst);
  inst[CPUI_INT_SEXT] = new TypeOpIntSext(tlst);
  inst[CPUI_INT_ADD] = new TypeOpIntAdd(tlst);
  inst[CPUI_INT_SUB] = new TypeOpIntSub(tlst);
  inst[CPUI_INT_CARRY] = new TypeOpIntCarry(tlst);
  inst[CPUI_INT_SCARRY] = new TypeOpIntScarry(tlst);
  inst[CPUI_INT_SBORROW] = new TypeOpIntSborrow(tlst);
  inst[CPUI_INT_2COMP] = new TypeOpInt2Comp(tlst);
  inst[CPUI_INT_NEGATE] = new TypeOpIntNegate(tlst);
  inst[CPUI_INT_XOR] = new TypeOpIntXor(tlst);
  inst[CPUI_INT_AND] = new TypeOpIntAnd(tlst);
  inst[CPUI_INT_OR] = new TypeOpIntOr(tlst);
  inst[CPUI_INT_LEFT] = new TypeOpIntLeft(tlst);
  inst[CPUI_INT_RIGHT] = new TypeOpIntRight(tlst);
  inst[CPUI_INT_SRIGHT] = new TypeOpIntSright(tlst);
  inst[CPUI_INT_MULT] = new TypeOpIntMult(tlst);
  inst[CPUI_INT_DIV] = new TypeOpIntDiv(tlst);
  inst[CPUI_INT_SDIV] = new TypeOpIntSdiv(tlst);
  inst[CPUI_INT_REM] = new TypeOpIntRem(tlst);
  inst[CPUI_INT_SREM] = new TypeOpIntSrem(tlst);

  inst[CPUI_BOOL_NEGATE] = new TypeOpBoolNegate(tlst);
  inst[CPUI_BOOL_XOR] = new TypeOpBoolXor(tlst);
  inst[CPUI_BOOL_AND] = new TypeOpBoolAnd(tlst);
  inst[CPUI_BOOL_OR] = new TypeOpBoolOr(tlst);

  inst[CPUI_CAST] = new TypeOpCast(tlst);
  inst[CPUI_PTRADD] = new TypeOpPtradd(tlst);
  inst[CPUI_PTRSUB] = new TypeOpPtrsub(tlst);

  inst[CPUI_FLOAT_EQUAL] = new TypeOpFloatEqual(tlst,trans);
  inst[CPUI_FLOAT_NOTEQUAL] = new TypeOpFloatNotEqual(tlst,trans);
  inst[CPUI_FLOAT_LESS] = new TypeOpFloatLess(tlst,trans);
  inst[CPUI_FLOAT_LESSEQUAL] = new TypeOpFloatLessEqual(tlst,trans);
  inst[CPUI_FLOAT_NAN] = new TypeOpFloatNan(tlst,trans);

  inst[CPUI_FLOAT_ADD] = new TypeOpFloatAdd(tlst,trans);
  inst[CPUI_FLOAT_DIV] = new TypeOpFloatDiv(tlst,trans);
  inst[CPUI_FLOAT_MULT] = new TypeOpFloatMult(tlst,trans);
  inst[CPUI_FLOAT_SUB] = new TypeOpFloatSub(tlst,trans);
  inst[CPUI_FLOAT_NEG] = new TypeOpFloatNeg(tlst,trans);
  inst[CPUI_FLOAT_ABS] = new TypeOpFloatAbs(tlst,trans);
  inst[CPUI_FLOAT_SQRT] = new TypeOpFloatSqrt(tlst,trans);

  inst[CPUI_FLOAT_INT2FLOAT] = new TypeOpFloatInt2Float(tlst,trans);
  inst[CPUI_FLOAT_FLOAT2FLOAT] = new TypeOpFloatFloat2Float(tlst,trans);
  inst[CPUI_FLOAT_TRUNC] = new TypeOpFloatTrunc(tlst,trans);
  inst[CPUI_FLOAT_CEIL] = new TypeOpFloatCeil(tlst,trans);
  inst[CPUI_FLOAT_FLOOR] = new TypeOpFloatFloor(tlst,trans);
  inst[CPUI_FLOAT_ROUND] = new TypeOpFloatRound(tlst,trans);
  inst[CPUI_SEGMENTOP] = new TypeOpSegment(tlst);
  inst[CPUI_CPOOLREF] = new TypeOpCpoolref(tlst);
  inst[CPUI_NEW] = new TypeOpNew(tlst);
  inst[CPUI_INSERT] = new TypeOpInsert(tlst);
  inst[CPUI_EXTRACT] = new TypeOpExtract(tlst);
  inst[CPUI_POPCOUNT] = new TypeOpPopcount(tlst);
}

/// Change basic data-type info (signed vs unsigned) and operator names ( '>>' vs '>>>' )
/// depending on the specific language.
/// \param inst is the array of TypeOp information objects
/// \param val is set to \b true for Java operators, \b false for C operators
void TypeOp::selectJavaOperators(vector<TypeOp *> &inst,bool val)

{
  if (val) {
    inst[CPUI_INT_ZEXT]->setMetatypeIn(TYPE_UNKNOWN);
    inst[CPUI_INT_ZEXT]->setMetatypeOut(TYPE_INT);
    inst[CPUI_INT_NEGATE]->setMetatypeIn(TYPE_INT);
    inst[CPUI_INT_NEGATE]->setMetatypeOut(TYPE_INT);
    inst[CPUI_INT_XOR]->setMetatypeIn(TYPE_INT);
    inst[CPUI_INT_XOR]->setMetatypeOut(TYPE_INT);
    inst[CPUI_INT_OR]->setMetatypeIn(TYPE_INT);
    inst[CPUI_INT_OR]->setMetatypeOut(TYPE_INT);
    inst[CPUI_INT_AND]->setMetatypeIn(TYPE_INT);
    inst[CPUI_INT_AND]->setMetatypeOut(TYPE_INT);
    inst[CPUI_INT_RIGHT]->setMetatypeIn(TYPE_INT);
    inst[CPUI_INT_RIGHT]->setMetatypeOut(TYPE_INT);
    inst[CPUI_INT_RIGHT]->setSymbol(">>>");
  }
  else {
    inst[CPUI_INT_ZEXT]->setMetatypeIn(TYPE_UINT);
    inst[CPUI_INT_ZEXT]->setMetatypeOut(TYPE_UINT);
    inst[CPUI_INT_NEGATE]->setMetatypeIn(TYPE_UINT);
    inst[CPUI_INT_NEGATE]->setMetatypeOut(TYPE_UINT);
    inst[CPUI_INT_XOR]->setMetatypeIn(TYPE_UINT);
    inst[CPUI_INT_XOR]->setMetatypeOut(TYPE_UINT);
    inst[CPUI_INT_OR]->setMetatypeIn(TYPE_UINT);
    inst[CPUI_INT_OR]->setMetatypeOut(TYPE_UINT);
    inst[CPUI_INT_AND]->setMetatypeIn(TYPE_UINT);
    inst[CPUI_INT_AND]->setMetatypeOut(TYPE_UINT);
    inst[CPUI_INT_RIGHT]->setMetatypeIn(TYPE_UINT);
    inst[CPUI_INT_RIGHT]->setMetatypeOut(TYPE_UINT);
    inst[CPUI_INT_RIGHT]->setSymbol(">>");
  }
}

/// \param t is the TypeFactory used to construct data-types
/// \param opc is the op-code value the new object will represent
/// \param n is the display name that will represent the op-code
TypeOp::TypeOp(TypeFactory *t,OpCode opc,const string &n)

{
  tlst = t;
  opcode = opc;
  name = n;
  opflags = 0;
  addlflags = 0;
  behave = (OpBehavior *)0;
}

TypeOp::~TypeOp(void)

{
  if (behave != (OpBehavior *)0)
    delete behave;
}

/// \return \b true if the ordering of the inputs does not affect the output
bool TypeOp::isCommutative(void) const

{
  return ((opflags & PcodeOp::commutative)!=0);
}

/// The result should depend only on the op-code itself (and the size of the output)
/// \param op is the PcodeOp being considered
/// \return the data-type
Datatype *TypeOp::getOutputLocal(const PcodeOp *op) const

{				// Default type lookup
  return tlst->getBase(op->getOut()->getSize(),TYPE_UNKNOWN);
}

/// The result should depend only on the op-code itself (and the size of the input)
/// \param op is the PcodeOp being considered
/// \param slot is the input being considered
/// \return the data-type
Datatype *TypeOp::getInputLocal(const PcodeOp *op,int4 slot) const

{				// Default type lookup
  return tlst->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN);
}

/// Calculate the actual data-type of the output for a specific PcodeOp
/// as would be assigned by a C compiler parsing a grammar containing this op.
/// \param op is the specific PcodeOp
/// \param castStrategy is the current casting strategy
/// \return the data-type
Datatype *TypeOp::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return op->outputTypeLocal();
}

/// Calculate the actual data-type of the input to the specific PcodeOp.
/// A \b null result indicates the input data-type is the same as
/// or otherwise doesn't need a cast from the data-type of the actual input Varnode
/// \param op is the specific PcodeOp
/// \param slot is the input to consider
/// \param castStrategy is the current casting strategy
/// \return the data-type
Datatype *TypeOp::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getIn(slot);
  if (vn->isAnnotation()) return (Datatype *)0;
  Datatype *reqtype = op->inputTypeLocal(slot);
  Datatype *curtype = vn->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,false,true);
}

/// Many languages can mark an integer constant as explicitly \e unsigned. When
/// the decompiler is deciding on \e cast operations, this is one of the checks
/// it performs.  This method checks if the indicated input is an
/// integer constant that needs to be coerced (as a source token) into being unsigned.
/// If this is \b true, the input Varnode is marked for printing as explicitly \e unsigned.
/// \param op is the PcodeOp taking the value as input
/// \param slot is the input slot of the value
/// \return \b true if the Varnode gets marked for printing
bool TypeOp::markExplicitUnsigned(PcodeOp *op,int4 slot) const

{
  if ((addlflags & inherits_sign)==0) return false;
  if ((slot==1) && ((addlflags & inherits_sign_zero)!=0)) return false;
  Varnode *vn = op->getIn(slot);
  if (!vn->isConstant()) return false;
  Datatype *dt = vn->getHigh()->getType();
  type_metatype meta = dt->getMetatype();
  if ((meta != TYPE_UINT)&&(meta != TYPE_UNKNOWN)) return false;
  if (dt->isCharPrint()) return false;
  if (dt->isEnumType()) return false;
  if ((op->numInput() == 2) && ((addlflags & inherits_sign_zero)==0)) {
    Varnode *firstvn = op->getIn(1-slot);
    meta = firstvn->getHigh()->getType()->getMetatype();
    if ((meta == TYPE_UINT)||(meta == TYPE_UNKNOWN))
      return false;		// Other side of the operation will force the unsigned
  }
  // Check if type is going to get forced anyway
  Varnode *outvn = op->getOut();
  if (outvn != (Varnode *)0) {
    if (outvn->isExplicit()) return false;
    PcodeOp *lone = outvn->loneDescend();
    if (lone != (PcodeOp *)0) {
      if (!lone->inheritsSign()) return false;
    }
  }

  vn->setUnsignedPrint();
  return true;
}

Datatype *TypeOpBinary::getOutputLocal(const PcodeOp *op) const

{
  return tlst->getBase(op->getOut()->getSize(),metaout);
}

Datatype *TypeOpBinary::getInputLocal(const PcodeOp *op,int4 slot) const

{
  return tlst->getBase(op->getIn(slot)->getSize(),metain);
}

void TypeOpBinary::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  Varnode::printRaw(s,op->getIn(0));
  s << ' ' << getOperatorName(op) << ' ';
  Varnode::printRaw(s,op->getIn(1));
}

Datatype *TypeOpUnary::getOutputLocal(const PcodeOp *op) const

{
  return tlst->getBase(op->getOut()->getSize(),metaout);
}

Datatype *TypeOpUnary::getInputLocal(const PcodeOp *op,int4 slot) const

{
  return tlst->getBase(op->getIn(slot)->getSize(),metain);
}

void TypeOpUnary::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = " << getOperatorName(op) << ' ';
  Varnode::printRaw(s,op->getIn(0));
}

Datatype *TypeOpFunc::getOutputLocal(const PcodeOp *op) const

{
  return tlst->getBase(op->getOut()->getSize(),metaout);
}

Datatype *TypeOpFunc::getInputLocal(const PcodeOp *op,int4 slot) const

{
  return tlst->getBase(op->getIn(slot)->getSize(),metain);
}

void TypeOpFunc::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = " << getOperatorName(op) << '(';
  Varnode::printRaw(s,op->getIn(0));
  for(int4 i=1;i<op->numInput();++i) {
    s << ',';
    Varnode::printRaw(s,op->getIn(i));
  }
  s << ')';
}

TypeOpCopy::TypeOpCopy(TypeFactory *t) : TypeOp(t,CPUI_COPY,"copy")

{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorCopy();
}

Datatype *TypeOpCopy::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->getOut()->getHigh()->getType();	// Require input to be same type as output
  Datatype *curtype = op->getIn(0)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,false,true);
}

Datatype *TypeOpCopy::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return op->getIn(0)->getHigh()->getType();
}

void TypeOpCopy::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  Varnode::printRaw(s,op->getIn(0));
}

TypeOpLoad::TypeOpLoad(TypeFactory *t) : TypeOp(t,CPUI_LOAD,"load")

{
  opflags = PcodeOp::special | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_LOAD,false,true); // Dummy behavior
}

Datatype *TypeOpLoad::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  if (slot!=1) return (Datatype *)0;
  Datatype *reqtype = op->getOut()->getHigh()->getType();	// Cast load pointer to match output
  const Varnode *invn = op->getIn(1);
  Datatype *curtype = invn->getHigh()->getType();
  AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
  // Its possible that the input type is not a pointer to the output type
  // (or even a pointer) due to cycle trimming in the type propagation algorithms
  if (curtype->getMetatype() == TYPE_PTR)
    curtype = ((TypePointer *)curtype)->getPtrTo();
  else
    return tlst->getTypePointer(invn->getSize(),reqtype,spc->getWordSize());
  if ((curtype != reqtype)&&(curtype->getSize() == reqtype->getSize())) {
    // If we have a non-standard  in = ptr a  out = b  (a!=b)
    // We may want to postpone casting BEFORE the load in favor of casting AFTER the load
    type_metatype curmeta = curtype->getMetatype();
    if ((curmeta!=TYPE_STRUCT)&&(curmeta!=TYPE_ARRAY)&&(curmeta!=TYPE_SPACEBASE)) {
      // if the input is a pointer to a primitive type
      if ((!invn->isImplied())||(!invn->isWritten())||(invn->getDef()->code() != CPUI_CAST))
	return (Datatype *)0;	// Postpone cast to output
      // If we reach here, the input is a CAST to the wrong type
      // We fallthru (returning the proper input case) so that the bad cast can either be
      // adjusted or we recast
    }
  }
  reqtype = castStrategy->castStandard(reqtype,curtype,false,true);
  if (reqtype == (Datatype *)0) return reqtype;
  return tlst->getTypePointer(invn->getSize(),reqtype,spc->getWordSize());
}

Datatype *TypeOpLoad::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  Datatype *ct = op->getIn(1)->getHigh()->getType();
  if ((ct->getMetatype() == TYPE_PTR)&&(((TypePointer *)ct)->getPtrTo()->getSize() == op->getOut()->getSize()))
    return ((TypePointer *)ct)->getPtrTo();
  //  return TypeOp::getOutputToken(op);
  // The input to the load is not a pointer or (more likely)
  // points to something of a different size than the output
  // In this case, there will have to be a cast, so we assume
  // the cast will cause the load to produce the type matching
  // its output
  return op->getOut()->getHigh()->getType();
}

void TypeOpLoad::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = *(";
  AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
  s << spc->getName() << ',';
  Varnode::printRaw(s,op->getIn(1));
  s << ')';
}

TypeOpStore::TypeOpStore(TypeFactory *t) : TypeOp(t,CPUI_STORE,"store")

{
  opflags = PcodeOp::special | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_STORE,false,true); // Dummy behavior
}

Datatype *TypeOpStore::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  if (slot==0) return (Datatype *)0;
  const Varnode *pointerVn = op->getIn(1);
  Datatype *pointerType = pointerVn->getHigh()->getType();
  Datatype *valueType = op->getIn(2)->getHigh()->getType();
  AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
  int4 destSize;
  if (pointerType->getMetatype() == TYPE_PTR) {
    pointerType = ((TypePointer *)pointerType)->getPtrTo();
    destSize = pointerType->getSize();
  }
  else
    destSize = -1;
  if (destSize != valueType->getSize()) {
    if (slot == 1)
      return tlst->getTypePointer(pointerVn->getSize(),valueType,spc->getWordSize());
    else
      return (Datatype *)0;
  }
  if (slot == 1) {
    if (pointerVn->isWritten() && pointerVn->getDef()->code() == CPUI_CAST) {
      if (pointerVn->isImplied() && pointerVn->loneDescend() == op) {
	// CAST is already in place, test if it is casting to the right type
	Datatype *newType = tlst->getTypePointer(pointerVn->getSize(), valueType, spc->getWordSize());
	if (pointerVn->getHigh()->getType() != newType)
	  return newType;
      }
    }
    return (Datatype *)0;
  }
  // If we reach here, cast the value, not the pointer
  return castStrategy->castStandard(pointerType,valueType,false,true);
}

void TypeOpStore::printRaw(ostream &s,const PcodeOp *op)

{
  s << "*(";
  AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
  s << spc->getName() << ',';
  Varnode::printRaw(s,op->getIn(1));
  s << ") = ";
  Varnode::printRaw(s,op->getIn(2));
}

TypeOpBranch::TypeOpBranch(TypeFactory *t) : TypeOp(t,CPUI_BRANCH,"goto")

{
  opflags = (PcodeOp::special|PcodeOp::branch|PcodeOp::coderef|PcodeOp::nocollapse);
  behave = new OpBehavior(CPUI_BRANCH,false,true); // Dummy behavior
}

void TypeOpBranch::printRaw(ostream &s,const PcodeOp *op)

{
  s << name << ' ';
  Varnode::printRaw(s,op->getIn(0));
}

TypeOpCbranch::TypeOpCbranch(TypeFactory *t) : TypeOp(t,CPUI_CBRANCH,"goto")

{
  opflags = (PcodeOp::special|PcodeOp::branch|PcodeOp::coderef|PcodeOp::nocollapse);
  behave = new OpBehavior(CPUI_CBRANCH,false,true); // Dummy behavior
}

Datatype *TypeOpCbranch::getInputLocal(const PcodeOp *op,int4 slot) const

{
  Datatype *td;

  if (slot==1)
    return tlst->getBase(op->getIn(1)->getSize(),TYPE_BOOL); // Second param is bool
  td = tlst->getTypeCode();
  AddrSpace *spc = op->getIn(0)->getSpace();
  return tlst->getTypePointer(op->getIn(0)->getSize(),td,spc->getWordSize()); // First parameter is code pointer
}

void TypeOpCbranch::printRaw(ostream &s,const PcodeOp *op)

{
  s << name << ' ';
  Varnode::printRaw(s,op->getIn(0));	// Print the distant (non-fallthru) destination
  s << " if (";
  Varnode::printRaw(s,op->getIn(1));
  if (op->isBooleanFlip()^op->isFallthruTrue())
    s << " == 0)";
  else
    s << " != 0)";
}

TypeOpBranchind::TypeOpBranchind(TypeFactory *t) : TypeOp(t,CPUI_BRANCHIND,"switch")

{
  opflags = PcodeOp::special|PcodeOp::branch|PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_BRANCHIND,false,true); // Dummy behavior
}

void TypeOpBranchind::printRaw(ostream &s,const PcodeOp *op)

{
  s << name << ' ';
  Varnode::printRaw(s,op->getIn(0));
}

TypeOpCall::TypeOpCall(TypeFactory *t) : TypeOp(t,CPUI_CALL,"call")

{
  opflags = (PcodeOp::special|PcodeOp::call|PcodeOp::has_callspec|PcodeOp::coderef|PcodeOp::nocollapse);
  behave = new OpBehavior(CPUI_CALL,false,true); // Dummy behavior
}

void TypeOpCall::printRaw(ostream &s,const PcodeOp *op)

{
  if (op->getOut() != (Varnode *)0) {
    Varnode::printRaw(s,op->getOut());
    s << " = ";
  }
  s << name << ' ';
  Varnode::printRaw(s,op->getIn(0));
  if (op->numInput()>1) {
    s << '(';
    Varnode::printRaw(s,op->getIn(1));
    for(int4 i=2;i<op->numInput();++i) {
      s << ',';
      Varnode::printRaw(s,op->getIn(i));
    }
    s << ')';
  }
}

Datatype *TypeOpCall::getInputLocal(const PcodeOp *op,int4 slot) const

{
  const FuncCallSpecs *fc;
  const Varnode *vn;
  Datatype *ct;

  vn = op->getIn(0);
  if ((slot==0)||(vn->getSpace()->getType()!=IPTR_FSPEC))// Do we have a prototype to look at
    return TypeOp::getInputLocal(op,slot);
    
  // Get types of call input parameters
  fc = FuncCallSpecs::getFspecFromConst(vn->getAddr());
  // Its false to assume that the parameter symbol corresponds
  // to the varnode in the same slot, but this is easiest until
  // we get giant sized parameters working properly
  ProtoParameter *param = fc->getParam(slot - 1);
  if (param != (ProtoParameter*) 0) {
    if (param->isTypeLocked()) {
      ct = param->getType();
      if ((ct->getMetatype() != TYPE_VOID) && (ct->getSize() <= op->getIn(slot)->getSize())) // parameter may not match varnode
	return ct;
    }
    else if (param->isThisPointer()) {
      // Known "this" pointer is effectively typelocked even if the prototype as a whole isn't
      ct = param->getType();
      if (ct->getMetatype() == TYPE_PTR && ((TypePointer*) ct)->getPtrTo()->getMetatype() == TYPE_STRUCT)
	return ct;
    }
  }
  return TypeOp::getInputLocal(op,slot);
}

Datatype *TypeOpCall::getOutputLocal(const PcodeOp *op) const

{
  const FuncCallSpecs *fc;
  const Varnode *vn;
  Datatype *ct;

  vn = op->getIn(0);		// Varnode containing pointer to fspec
  if (vn->getSpace()->getType()!=IPTR_FSPEC) // Do we have a prototype to look at
    return TypeOp::getOutputLocal(op);

  fc = FuncCallSpecs::getFspecFromConst(vn->getAddr());
  if (!fc->isOutputLocked()) return TypeOp::getOutputLocal(op);
  ct = fc->getOutputType();
  if (ct->getMetatype() == TYPE_VOID) return TypeOp::getOutputLocal(op);
  return ct;
}

TypeOpCallind::TypeOpCallind(TypeFactory *t) : TypeOp(t,CPUI_CALLIND,"callind")

{
  opflags = PcodeOp::special|PcodeOp::call|PcodeOp::has_callspec|PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_CALLIND,false,true); // Dummy behavior
}

Datatype *TypeOpCallind::getInputLocal(const PcodeOp *op,int4 slot) const

{
  Datatype *td;
  const FuncCallSpecs *fc;
  Datatype *ct;

  if (slot==0) {
    td = tlst->getTypeCode();
    AddrSpace *spc = op->getAddr().getSpace();
    return tlst->getTypePointer(op->getIn(0)->getSize(),td,spc->getWordSize()); // First parameter is code pointer
  }
  fc = op->getParent()->getFuncdata()->getCallSpecs(op);
  if (fc == (const FuncCallSpecs *)0)
    return TypeOp::getInputLocal(op,slot);
  ProtoParameter *param = fc->getParam(slot-1);
  if (param != (ProtoParameter *)0) {
    if (param->isTypeLocked()) {
      ct = param->getType();
      if (ct->getMetatype() != TYPE_VOID)
	return ct;
    }
    else if (param->isThisPointer()) {
      ct = param->getType();
      if (ct->getMetatype() == TYPE_PTR && ((TypePointer *)ct)->getPtrTo()->getMetatype() == TYPE_STRUCT)
	return ct;
    }
  }
  return TypeOp::getInputLocal(op,slot);
}

Datatype *TypeOpCallind::getOutputLocal(const PcodeOp *op) const

{
  const FuncCallSpecs *fc;
  Datatype *ct;

  fc = op->getParent()->getFuncdata()->getCallSpecs(op);
  if (fc == (const FuncCallSpecs *)0)
    return TypeOp::getOutputLocal(op);
  if (!fc->isOutputLocked()) return TypeOp::getOutputLocal(op);
  ct = fc->getOutputType();
  if (ct->getMetatype()==TYPE_VOID) return TypeOp::getOutputLocal(op);
  return ct;
}

void TypeOpCallind::printRaw(ostream &s,const PcodeOp *op)

{
  if (op->getOut() != (Varnode *)0) {
    Varnode::printRaw(s,op->getOut());
    s << " = ";
  }
  s << name;
  Varnode::printRaw(s,op->getIn(0));
  if (op->numInput()>1) {
    s << '(';
    Varnode::printRaw(s,op->getIn(1));
    for(int4 i=2;i<op->numInput();++i) {
      s << ',';
      Varnode::printRaw(s,op->getIn(i));
    }
    s << ')';
  }
}

TypeOpCallother::TypeOpCallother(TypeFactory *t) : TypeOp(t,CPUI_CALLOTHER,"syscall")

{
  opflags = PcodeOp::special|PcodeOp::call|PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_CALLOTHER,false,true); // Dummy behavior
}

void TypeOpCallother::printRaw(ostream &s,const PcodeOp *op)

{
  if (op->getOut() != (Varnode *)0) {
    Varnode::printRaw(s,op->getOut());
    s << " = ";
  }
  s << getOperatorName(op);
  if (op->numInput()>1) {
    s << '(';
    Varnode::printRaw(s,op->getIn(1));
    for(int4 i=2;i<op->numInput();++i) {
      s << ',';
      Varnode::printRaw(s,op->getIn(i));
    }
    s << ')';
  }
}

string TypeOpCallother::getOperatorName(const PcodeOp *op) const

{
  const BlockBasic *bb = op->getParent();
  if (bb != (BlockBasic *)0) {
   Architecture *glb = bb->getFuncdata()->getArch();
   int4 index = op->getIn(0)->getOffset();
    UserPcodeOp *userop = glb->userops.getOp(index);
    if (userop != (UserPcodeOp *)0)
      return userop->getOperatorName(op);
  }
  ostringstream res;
  res << TypeOp::getOperatorName(op) << '[';
  op->getIn(0)->printRaw(res);
  res << ']';
  return res.str();
}

Datatype *TypeOpCallother::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (!op->doesSpecialPropagation())
    return TypeOp::getInputLocal(op,slot);
  Architecture *glb = tlst->getArch();
  VolatileWriteOp *vw_op = glb->userops.getVolatileWrite(); // Check if this a volatile write op
  if ((vw_op->getIndex() == op->getIn(0)->getOffset()) && (slot == 2)) { // And we are requesting slot 2
    const Address &addr ( op->getIn(1)->getAddr() ); // Address of volatile memory
    int4 size = op->getIn(2)->getSize(); // Size of memory being written
    uint4 vflags = 0;
    SymbolEntry *entry = glb->symboltab->getGlobalScope()->queryProperties(addr,size,op->getAddr(),vflags);
    if (entry != (SymbolEntry *)0) {
      Datatype *res = entry->getSizedType(addr,size);
      if (res != (Datatype *)0)
	return res;
    }
  }
  return TypeOp::getInputLocal(op,slot);
}

Datatype *TypeOpCallother::getOutputLocal(const PcodeOp *op) const

{
  if (!op->doesSpecialPropagation())
    return TypeOp::getOutputLocal(op);
  Architecture *glb = tlst->getArch();
  VolatileReadOp *vr_op = glb->userops.getVolatileRead(); // Check if this a volatile read op
  if (vr_op->getIndex() == op->getIn(0)->getOffset()) {
    const Address &addr ( op->getIn(1)->getAddr() ); // Address of volatile memory
    int4 size = op->getOut()->getSize(); // Size of memory being written
    uint4 vflags = 0;
    SymbolEntry *entry = glb->symboltab->getGlobalScope()->queryProperties(addr,size,op->getAddr(),vflags);
    if (entry != (SymbolEntry *)0) {
      Datatype *res = entry->getSizedType(addr,size);
      if (res != (Datatype *)0)
	return res;
    }
  }
  return TypeOp::getOutputLocal(op);
}

TypeOpReturn::TypeOpReturn(TypeFactory *t) : TypeOp(t,CPUI_RETURN,"return")

{
  opflags = PcodeOp::special|PcodeOp::returns|PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_RETURN,false,true); // Dummy behavior
}

void TypeOpReturn::printRaw(ostream &s,const PcodeOp *op)

{
  s << name;
  if (op->numInput()>=1) {
    s << '(';
    Varnode::printRaw(s,op->getIn(0));
    s << ')';
  }
  if (op->numInput()>1) {
    s << ' ';
    Varnode::printRaw(s,op->getIn(1));
    for(int4 i=2;i<op->numInput();++i) {
      s << ',';
      Varnode::printRaw(s,op->getIn(i));
    }
  }
}

Datatype *TypeOpReturn::getInputLocal(const PcodeOp *op,int4 slot) const

{
  const FuncProto *fp;
  Datatype *ct;

  if (slot==0)
    return TypeOp::getInputLocal(op,slot);

  // Get data-types of return input parameters
  const BlockBasic *bb = op->getParent();
  if (bb == (BlockBasic *)0)
    return TypeOp::getInputLocal(op,slot);

  fp = &bb->getFuncdata()->getFuncProto();	// Prototype of function we are in

  //  if (!fp->isOutputLocked()) return TypeOp::getInputLocal(op,slot);
  ct = fp->getOutputType();
  if (ct->getMetatype() == TYPE_VOID) return TypeOp::getInputLocal(op,slot);
  return ct;
}

TypeOpEqual::TypeOpEqual(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_EQUAL,"==",TYPE_BOOL,TYPE_INT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorEqual();
}

Datatype *TypeOpEqual::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->getIn(0)->getHigh()->getType();	// Input arguments should be the same type
  Datatype *othertype = op->getIn(1)->getHigh()->getType();
  if (0>othertype->typeOrder(*reqtype))
    reqtype = othertype;
  if (castStrategy->checkIntPromotionForCompare(op,slot))
    return reqtype;
  othertype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,othertype,false,false);
}

TypeOpNotEqual::TypeOpNotEqual(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_NOTEQUAL,"!=",TYPE_BOOL,TYPE_INT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorNotEqual();
}

Datatype *TypeOpNotEqual::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->getIn(0)->getHigh()->getType();	// Input arguments should be the same type
  Datatype *othertype = op->getIn(1)->getHigh()->getType();
  if (0>othertype->typeOrder(*reqtype))
    reqtype = othertype;
  if (castStrategy->checkIntPromotionForCompare(op,slot))
    return reqtype;
  othertype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,othertype,false,false);
}

TypeOpIntSless::TypeOpIntSless(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_SLESS,"<",TYPE_BOOL,TYPE_INT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntSless();
}

Datatype *TypeOpIntSless::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->inputTypeLocal(slot);
  if (castStrategy->checkIntPromotionForCompare(op,slot))
    return reqtype;
  Datatype *curtype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,true,true);
}

TypeOpIntSlessEqual::TypeOpIntSlessEqual(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_SLESSEQUAL,"<=",TYPE_BOOL,TYPE_INT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntSlessEqual();
}

Datatype *TypeOpIntSlessEqual::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->inputTypeLocal(slot);
  if (castStrategy->checkIntPromotionForCompare(op,slot))
    return reqtype;
  Datatype *curtype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,true,true);
}

TypeOpIntLess::TypeOpIntLess(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_LESS,"<",TYPE_BOOL,TYPE_UINT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntLess();
}

Datatype *TypeOpIntLess::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->inputTypeLocal(slot);
  if (castStrategy->checkIntPromotionForCompare(op,slot))
    return reqtype;
  Datatype *curtype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,true,false);
}

TypeOpIntLessEqual::TypeOpIntLessEqual(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_LESSEQUAL,"<=",TYPE_BOOL,TYPE_UINT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntLessEqual();
}

Datatype *TypeOpIntLessEqual::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->inputTypeLocal(slot);
  if (castStrategy->checkIntPromotionForCompare(op,slot))
    return reqtype;
  Datatype *curtype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,true,false);
}

TypeOpIntZext::TypeOpIntZext(TypeFactory *t)
  : TypeOpFunc(t,CPUI_INT_ZEXT,"ZEXT",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorIntZext();
}

string TypeOpIntZext::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;
  
  s << name << dec << op->getIn(0)->getSize() << op->getOut()->getSize();
  return s.str();
}

Datatype *TypeOpIntZext::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->inputTypeLocal(slot);
  if (castStrategy->checkIntPromotionForExtension(op))
    return reqtype;
  Datatype *curtype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,true,false);
}

TypeOpIntSext::TypeOpIntSext(TypeFactory *t)
  : TypeOpFunc(t,CPUI_INT_SEXT,"SEXT",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorIntSext();
}

string TypeOpIntSext::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;
  
  s << name << dec << op->getIn(0)->getSize() << op->getOut()->getSize();
  return s.str();
}

Datatype *TypeOpIntSext::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  Datatype *reqtype = op->inputTypeLocal(slot);
  if (castStrategy->checkIntPromotionForExtension(op))
    return reqtype;
  Datatype *curtype = op->getIn(slot)->getHigh()->getType();
  return castStrategy->castStandard(reqtype,curtype,true,false);
}

TypeOpIntAdd::TypeOpIntAdd(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_ADD,"+",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntAdd();
}

Datatype *TypeOpIntAdd::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);	// Use arithmetic typing rules
}

TypeOpIntSub::TypeOpIntSub(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_SUB,"-",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntSub();
}

Datatype *TypeOpIntSub::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);	// Use arithmetic typing rules
}

TypeOpIntCarry::TypeOpIntCarry(TypeFactory *t)
  : TypeOpFunc(t,CPUI_INT_CARRY,"CARRY",TYPE_BOOL,TYPE_UINT)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorIntCarry();
}

string TypeOpIntCarry::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;
  s << name << dec << op->getIn(0)->getSize();
  return s.str();
}

TypeOpIntScarry::TypeOpIntScarry(TypeFactory *t)
  : TypeOpFunc(t,CPUI_INT_SCARRY,"SCARRY",TYPE_BOOL,TYPE_INT)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorIntScarry();
}

string TypeOpIntScarry::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;
  s << name << dec << op->getIn(0)->getSize();
  return s.str();
}

TypeOpIntSborrow::TypeOpIntSborrow(TypeFactory *t)
  : TypeOpFunc(t,CPUI_INT_SBORROW,"SBORROW",TYPE_BOOL,TYPE_INT)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorIntSborrow();
}

string TypeOpIntSborrow::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;
  s << name << dec << op->getIn(0)->getSize();
  return s.str();
}

TypeOpInt2Comp::TypeOpInt2Comp(TypeFactory *t)
  : TypeOpUnary(t,CPUI_INT_2COMP,"-",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::unary;
  addlflags = inherits_sign;
  behave = new OpBehaviorInt2Comp();
}

Datatype *TypeOpInt2Comp::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);
}

TypeOpIntNegate::TypeOpIntNegate(TypeFactory *t)
  : TypeOpUnary(t,CPUI_INT_NEGATE,"~",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::unary;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntNegate();
}

Datatype *TypeOpIntNegate::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);
}

TypeOpIntXor::TypeOpIntXor(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_XOR,"^",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntXor();
}

Datatype *TypeOpIntXor::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);
}

TypeOpIntAnd::TypeOpIntAnd(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_AND,"&",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntAnd();
}

Datatype *TypeOpIntAnd::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);
}

TypeOpIntOr::TypeOpIntOr(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_OR,"|",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntOr();
}

Datatype *TypeOpIntOr::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);
}

TypeOpIntLeft::TypeOpIntLeft(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_LEFT,"<<",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign | inherits_sign_zero;
  behave = new OpBehaviorIntLeft();
}

Datatype *TypeOpIntLeft::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (slot==1)
    return tlst->getBaseNoChar(op->getIn(1)->getSize(),TYPE_INT);
  return TypeOpBinary::getInputLocal(op,slot);
}

Datatype *TypeOpIntLeft::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  Datatype *res1 = op->getIn(0)->getHigh()->getType();
  if (res1->getMetatype() == TYPE_BOOL)
    res1 = tlst->getBase(res1->getSize(),TYPE_INT);
  return res1;
}

TypeOpIntRight::TypeOpIntRight(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_RIGHT,">>",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign | inherits_sign_zero;
  behave = new OpBehaviorIntRight();
}

Datatype *TypeOpIntRight::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (slot==1)
    return tlst->getBaseNoChar(op->getIn(1)->getSize(),TYPE_INT);
  return TypeOpBinary::getInputLocal(op,slot);
}

Datatype *TypeOpIntRight::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  if (slot == 0) {
    const Varnode *vn = op->getIn(0);
    Datatype *reqtype = op->inputTypeLocal(slot);
    Datatype *curtype = vn->getHigh()->getType();
    int4 promoType = castStrategy->intPromotionType(vn);
    if (promoType != CastStrategy::NO_PROMOTION && ((promoType & CastStrategy::UNSIGNED_EXTENSION)==0))
      return reqtype;
    return castStrategy->castStandard(reqtype,curtype,true,true);
  }
  return TypeOpBinary::getInputCast(op,slot,castStrategy);
}

Datatype *TypeOpIntRight::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  Datatype *res1 = op->getIn(0)->getHigh()->getType();
  if (res1->getMetatype() == TYPE_BOOL)
    res1 = tlst->getBase(res1->getSize(),TYPE_INT);
  return res1;
}

TypeOpIntSright::TypeOpIntSright(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_SRIGHT,">>",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign | inherits_sign_zero;
  behave = new OpBehaviorIntSright();
}

void TypeOpIntSright::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  Varnode::printRaw(s,op->getIn(0));
  s << " s>> ";
  Varnode::printRaw(s,op->getIn(1));
}

Datatype *TypeOpIntSright::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  if (slot == 0) {
    const Varnode *vn = op->getIn(0);
    Datatype *reqtype = op->inputTypeLocal(slot);
    Datatype *curtype = vn->getHigh()->getType();
    int4 promoType = castStrategy->intPromotionType(vn);
    if (promoType != CastStrategy::NO_PROMOTION && ((promoType & CastStrategy::SIGNED_EXTENSION)==0))
      return reqtype;
    return castStrategy->castStandard(reqtype,curtype,true,true);
  }
  return TypeOpBinary::getInputCast(op,slot,castStrategy);
}

Datatype *TypeOpIntSright::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (slot==1)
    return tlst->getBaseNoChar(op->getIn(1)->getSize(),TYPE_INT);
  return TypeOpBinary::getInputLocal(op,slot);
}

Datatype *TypeOpIntSright::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  Datatype *res1 = op->getIn(0)->getHigh()->getType();
  if (res1->getMetatype() == TYPE_BOOL)
    res1 = tlst->getBase(res1->getSize(),TYPE_INT);
  return res1;
}

TypeOpIntMult::TypeOpIntMult(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_MULT,"*",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntMult();
}

Datatype *TypeOpIntMult::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return castStrategy->arithmeticOutputStandard(op);
}

TypeOpIntDiv::TypeOpIntDiv(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_DIV,"/",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntDiv();
}

Datatype *TypeOpIntDiv::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getIn(slot);
  Datatype *reqtype = op->inputTypeLocal(slot);
  Datatype *curtype = vn->getHigh()->getType();
  int4 promoType = castStrategy->intPromotionType(vn);
  if (promoType != CastStrategy::NO_PROMOTION && ((promoType & CastStrategy::UNSIGNED_EXTENSION)==0))
    return reqtype;
  return castStrategy->castStandard(reqtype,curtype,true,true);
}

TypeOpIntSdiv::TypeOpIntSdiv(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_SDIV,"/",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign;
  behave = new OpBehaviorIntSdiv();
}

Datatype *TypeOpIntSdiv::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getIn(slot);
  Datatype *reqtype = op->inputTypeLocal(slot);
  Datatype *curtype = vn->getHigh()->getType();
  int4 promoType = castStrategy->intPromotionType(vn);
  if (promoType != CastStrategy::NO_PROMOTION && ((promoType & CastStrategy::SIGNED_EXTENSION)==0))
    return reqtype;
  return castStrategy->castStandard(reqtype,curtype,true,true);
}

TypeOpIntRem::TypeOpIntRem(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_REM,"%",TYPE_UINT,TYPE_UINT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign | inherits_sign_zero;
  behave = new OpBehaviorIntRem();
}

Datatype *TypeOpIntRem::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getIn(slot);
  Datatype *reqtype = op->inputTypeLocal(slot);
  Datatype *curtype = vn->getHigh()->getType();
  int4 promoType = castStrategy->intPromotionType(vn);
  if (promoType != CastStrategy::NO_PROMOTION && ((promoType & CastStrategy::UNSIGNED_EXTENSION)==0))
    return reqtype;
  return castStrategy->castStandard(reqtype,curtype,true,true);
}

TypeOpIntSrem::TypeOpIntSrem(TypeFactory *t)
  : TypeOpBinary(t,CPUI_INT_SREM,"%",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::binary;
  addlflags = inherits_sign | inherits_sign_zero;
  behave = new OpBehaviorIntSrem();
}

Datatype *TypeOpIntSrem::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getIn(slot);
  Datatype *reqtype = op->inputTypeLocal(slot);
  Datatype *curtype = vn->getHigh()->getType();
  int4 promoType = castStrategy->intPromotionType(vn);
  if (promoType != CastStrategy::NO_PROMOTION && ((promoType & CastStrategy::SIGNED_EXTENSION)==0))
    return reqtype;
  return castStrategy->castStandard(reqtype,curtype,true,true);
}

TypeOpBoolNegate::TypeOpBoolNegate(TypeFactory *t)
  : TypeOpUnary(t,CPUI_BOOL_NEGATE,"!",TYPE_BOOL,TYPE_BOOL)
{
  opflags = PcodeOp::unary | PcodeOp::booloutput;
  behave = new OpBehaviorBoolNegate();
}

TypeOpBoolXor::TypeOpBoolXor(TypeFactory *t)
  : TypeOpBinary(t,CPUI_BOOL_XOR,"^^",TYPE_BOOL,TYPE_BOOL)
{
  opflags = PcodeOp::binary | PcodeOp::commutative | PcodeOp::booloutput;
  behave = new OpBehaviorBoolXor();
}

TypeOpBoolAnd::TypeOpBoolAnd(TypeFactory *t)
  : TypeOpBinary(t,CPUI_BOOL_AND,"&&",TYPE_BOOL,TYPE_BOOL)
{
  opflags = PcodeOp::binary | PcodeOp::commutative | PcodeOp::booloutput;
  behave = new OpBehaviorBoolAnd();
}

TypeOpBoolOr::TypeOpBoolOr(TypeFactory *t)
  : TypeOpBinary(t,CPUI_BOOL_OR,"||",TYPE_BOOL,TYPE_BOOL)
{
  opflags = PcodeOp::binary | PcodeOp::commutative | PcodeOp::booloutput;
  behave = new OpBehaviorBoolOr();
}

TypeOpFloatEqual::TypeOpFloatEqual(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_EQUAL,"==",TYPE_BOOL,TYPE_FLOAT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput | PcodeOp::commutative;
  behave = new OpBehaviorFloatEqual(trans);
}

TypeOpFloatNotEqual::TypeOpFloatNotEqual(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_NOTEQUAL,"!=",TYPE_BOOL,TYPE_FLOAT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput | PcodeOp::commutative;
  behave = new OpBehaviorFloatNotEqual(trans);
}

TypeOpFloatLess::TypeOpFloatLess(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_LESS,"<",TYPE_BOOL,TYPE_FLOAT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput;
  behave = new OpBehaviorFloatLess(trans);
}

TypeOpFloatLessEqual::TypeOpFloatLessEqual(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_LESSEQUAL,"<=",TYPE_BOOL,TYPE_FLOAT)
{
  opflags = PcodeOp::binary | PcodeOp::booloutput;
  behave = new OpBehaviorFloatLessEqual(trans);
}

TypeOpFloatNan::TypeOpFloatNan(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_NAN,"NAN",TYPE_BOOL,TYPE_FLOAT)
{
  opflags = PcodeOp::unary | PcodeOp::booloutput;
  behave = new OpBehaviorFloatNan(trans);
}

TypeOpFloatAdd::TypeOpFloatAdd(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_ADD,"+",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  behave = new OpBehaviorFloatAdd(trans);
}

TypeOpFloatDiv::TypeOpFloatDiv(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_DIV,"/",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorFloatDiv(trans);
}

TypeOpFloatMult::TypeOpFloatMult(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_MULT,"*",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::binary | PcodeOp::commutative;
  behave = new OpBehaviorFloatMult(trans);
}

TypeOpFloatSub::TypeOpFloatSub(TypeFactory *t,const Translate *trans)
  : TypeOpBinary(t,CPUI_FLOAT_SUB,"-",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorFloatSub(trans);
}

TypeOpFloatNeg::TypeOpFloatNeg(TypeFactory *t,const Translate *trans)
  : TypeOpUnary(t,CPUI_FLOAT_NEG,"-",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatNeg(trans);
}

TypeOpFloatAbs::TypeOpFloatAbs(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_ABS,"ABS",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatAbs(trans);
}

TypeOpFloatSqrt::TypeOpFloatSqrt(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_SQRT,"SQRT",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatSqrt(trans);
}

TypeOpFloatInt2Float::TypeOpFloatInt2Float(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_INT2FLOAT,"INT2FLOAT",TYPE_FLOAT,TYPE_INT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatInt2Float(trans);
}

TypeOpFloatFloat2Float::TypeOpFloatFloat2Float(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_FLOAT2FLOAT,"FLOAT2FLOAT",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatFloat2Float(trans);
}

TypeOpFloatTrunc::TypeOpFloatTrunc(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_TRUNC,"TRUNC",TYPE_INT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatTrunc(trans);
}

TypeOpFloatCeil::TypeOpFloatCeil(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_CEIL,"CEIL",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatCeil(trans);
}

TypeOpFloatFloor::TypeOpFloatFloor(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_FLOOR,"FLOOR",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatFloor(trans);
}

TypeOpFloatRound::TypeOpFloatRound(TypeFactory *t,const Translate *trans)
  : TypeOpFunc(t,CPUI_FLOAT_ROUND,"ROUND",TYPE_FLOAT,TYPE_FLOAT)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorFloatRound(trans);
}

TypeOpMulti::TypeOpMulti(TypeFactory *t) : TypeOp(t,CPUI_MULTIEQUAL,"?")

{
  opflags = PcodeOp::special | PcodeOp::marker|PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_MULTIEQUAL,false,true); // Dummy behavior
}

void TypeOpMulti::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  Varnode::printRaw(s,op->getIn(0));
  //  if (op->Input(0)->isWritten())
  //    s << '(' << op->Input(0)->Def()->Start() << ')';
  if (op->numInput()==1)
    s << ' ' << getOperatorName(op);
  for(int4 i=1;i<op->numInput();++i) {
    s << ' ' << getOperatorName(op) << ' ';
    Varnode::printRaw(s,op->getIn(i));
    //    if (op->Input(i)->isWritten())
    //      s << '(' << op->Input(i)->Def()->Start() << ')';
  }
}

TypeOpIndirect::TypeOpIndirect(TypeFactory *t) : TypeOp(t,CPUI_INDIRECT,"[]")

{
  opflags = PcodeOp::special | PcodeOp::marker | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_INDIRECT,false,true); // Dummy behavior
}

Datatype *TypeOpIndirect::getInputLocal(const PcodeOp *op,int4 slot) const

{
  Datatype *ct;

  if (slot==0)
    return TypeOp::getInputLocal(op,slot);
  ct = tlst->getTypeCode();
  PcodeOp *iop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
  AddrSpace *spc = iop->getAddr().getSpace();
  return tlst->getTypePointer(op->getIn(0)->getSize(),ct,spc->getWordSize()); // Second parameter is code pointer
}

void TypeOpIndirect::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  if (op->isIndirectCreation()) {
    s << "[create] ";
  }
  else {
    Varnode::printRaw(s,op->getIn(0));
    s << ' ' << getOperatorName(op) << ' ';
  }
  Varnode::printRaw(s,op->getIn(1));
}

TypeOpPiece::TypeOpPiece(TypeFactory *t)
  : TypeOpFunc(t,CPUI_PIECE,"CONCAT",TYPE_UNKNOWN,TYPE_UNKNOWN)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorPiece();
}

string TypeOpPiece::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;

  s << name << dec << op->getIn(0)->getSize() << op->getIn(1)->getSize();
  return s.str();
}

Datatype *TypeOpPiece::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getOut();
  Datatype *dt = vn->getType();
  type_metatype meta = dt->getMetatype();
  if ((meta == TYPE_INT)||(meta == TYPE_UINT))		// PIECE casts to uint or int, based on output
    return dt;
  return tlst->getBase(vn->getSize(),TYPE_UINT);	// If output is unknown or pointer, treat as cast to uint
}

TypeOpSubpiece::TypeOpSubpiece(TypeFactory *t)
  : TypeOpFunc(t,CPUI_SUBPIECE,"SUB",TYPE_UNKNOWN,TYPE_UNKNOWN)
{
  opflags = PcodeOp::binary;
  behave = new OpBehaviorSubpiece();
}

string TypeOpSubpiece::getOperatorName(const PcodeOp *op) const

{
  ostringstream s;

  s << name << dec << op->getIn(0)->getSize() << op->getOut()->getSize();
  return s.str();
}

Datatype *TypeOpSubpiece::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  const Varnode *vn = op->getOut();
  Datatype *dt = vn->getType();			// SUBPIECE prints as cast to whatever its output is
  if (dt->getMetatype() != TYPE_UNKNOWN)
    return dt;
  return tlst->getBase(vn->getSize(),TYPE_INT);	// If output is unknown, treat as cast to int
}

TypeOpCast::TypeOpCast(TypeFactory *t) : TypeOp(t,CPUI_CAST,"(cast)")

{
  opflags = PcodeOp::unary | PcodeOp::special | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_CAST,false,true); // Dummy behavior
}

void TypeOpCast::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = " << name << ' ';
  Varnode::printRaw(s,op->getIn(0));
}

TypeOpPtradd::TypeOpPtradd(TypeFactory *t) : TypeOp(t,CPUI_PTRADD,"+")

{
  opflags = PcodeOp::ternary | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_PTRADD,false); // Dummy behavior
}

Datatype *TypeOpPtradd::getInputLocal(const PcodeOp *op,int4 slot) const

{
  return tlst->getBase(op->getIn(slot)->getSize(),TYPE_INT);	// For type propagation, treat same as INT_ADD
}

Datatype *TypeOpPtradd::getOutputLocal(const PcodeOp *op) const

{
  return tlst->getBase(op->getOut()->getSize(),TYPE_INT);	// For type propagation, treat same as INT_ADD
}

Datatype *TypeOpPtradd::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return op->getIn(0)->getHigh()->getType();		// Cast to the input data-type
}

Datatype *TypeOpPtradd::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  if (slot==0) {		// The operation expects the type of the VARNODE
				// not the (possibly different) type of the HIGH
    Datatype *reqtype = op->getIn(0)->getType();
    Datatype *curtype = op->getIn(0)->getHigh()->getType();
    return castStrategy->castStandard(reqtype,curtype,false,false);
  }
  return TypeOp::getInputCast(op,slot,castStrategy);
}

void TypeOpPtradd::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  Varnode::printRaw(s,op->getIn(0));
  s << ' ' << name << ' ';
  Varnode::printRaw(s,op->getIn(1));
  s << "(*";
  Varnode::printRaw(s,op->getIn(2));
  s << ')';
}

TypeOpPtrsub::TypeOpPtrsub(TypeFactory *t) : TypeOp(t,CPUI_PTRSUB,"->")

{
				// As an operation this is really addition
				// So it should be commutative
				// But the typing information doesn't really
				// allow this to be commutative.
  opflags = PcodeOp::binary|PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_PTRSUB,false); // Dummy behavior
}

Datatype *TypeOpPtrsub::getOutputLocal(const PcodeOp *op) const

{				// Output is ptr to type of subfield
  return tlst->getBase(op->getOut()->getSize(),TYPE_INT);
}

Datatype *TypeOpPtrsub::getInputLocal(const PcodeOp *op,int4 slot) const

{
  return tlst->getBase(op->getIn(slot)->getSize(),TYPE_INT);
}

Datatype *TypeOpPtrsub::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  if (slot==0) {		// The operation expects the type of the VARNODE
				// not the (possibly different) type of the HIGH
    Datatype *reqtype = op->getIn(0)->getType();
    Datatype *curtype = op->getIn(0)->getHigh()->getType();
    return castStrategy->castStandard(reqtype,curtype,false,false);
  }
  return TypeOp::getInputCast(op,slot,castStrategy);
}

Datatype *TypeOpPtrsub::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  TypePointer *ptype = (TypePointer *)op->getIn(0)->getHigh()->getType();
  if (ptype->getMetatype() == TYPE_PTR) {
    uintb offset = AddrSpace::addressToByte(op->getIn(1)->getOffset(),ptype->getWordSize());
    Datatype *rettype = tlst->downChain(ptype,offset);
    if ((offset==0)&&(rettype != (Datatype *)0))
      return rettype;
  }
  return TypeOp::getOutputToken(op,castStrategy);
}

void TypeOpPtrsub::printRaw(ostream &s,const PcodeOp *op)

{
  Varnode::printRaw(s,op->getOut());
  s << " = ";
  Varnode::printRaw(s,op->getIn(0));
  s << ' ' << name << ' ';
  Varnode::printRaw(s,op->getIn(1));
}

TypeOpSegment::TypeOpSegment(TypeFactory *t) : TypeOp(t,CPUI_SEGMENTOP,"segmentop")

{
  opflags = PcodeOp::special | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_SEGMENTOP,false,true); // Dummy behavior
}

void TypeOpSegment::printRaw(ostream &s,const PcodeOp *op)

{
  if (op->getOut() != (Varnode *)0) {
    Varnode::printRaw(s,op->getOut());
    s << " = ";
  }
  s << getOperatorName(op);
  s << '(';
  AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
  s << spc->getName() << ',';
  Varnode::printRaw(s,op->getIn(1));
  s << ',';
  Varnode::printRaw(s,op->getIn(2));
  s << ')';
}

Datatype *TypeOpSegment::getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const

{
  return op->getIn(2)->getHigh()->getType(); // Assume type of ptr portion
}

Datatype *TypeOpSegment::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const

{
  return (Datatype *)0;		// Never need a cast for inputs
}

// Pointer to value relationship is built in the type propagation algorithm
// Datatype *TypeOpSegment::getInputLocal(const PcodeOp *op,int4 slot) const
// {
// }

TypeOpCpoolref::TypeOpCpoolref(TypeFactory *t) : TypeOp(t,CPUI_CPOOLREF,"cpoolref")

{
  cpool = t->getArch()->cpool;
  opflags = PcodeOp::special | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_CPOOLREF,false,true); // Dummy behavior
}

Datatype *TypeOpCpoolref::getOutputLocal(const PcodeOp *op) const

{
  vector<uintb> refs;
  for(int4 i=1;i<op->numInput();++i)
    refs.push_back(op->getIn(i)->getOffset());
  const CPoolRecord *rec = cpool->getRecord(refs);
  if (rec == (const CPoolRecord *)0)
    return TypeOp::getOutputLocal(op);
  if (rec->getTag() == CPoolRecord::instance_of)
    return tlst->getBase(1,TYPE_BOOL);
  return rec->getType();
}

Datatype *TypeOpCpoolref::getInputLocal(const PcodeOp *op,int4 slot) const

{
  return tlst->getBase(op->getIn(slot)->getSize(),TYPE_INT);
}

void TypeOpCpoolref::printRaw(ostream &s,const PcodeOp *op)

{
  if (op->getOut() != (Varnode *)0) {
    Varnode::printRaw(s,op->getOut());
    s << " = ";
  }
  s << getOperatorName(op);
  vector<uintb> refs;
  for(int4 i=1;i<op->numInput();++i)
    refs.push_back(op->getIn(i)->getOffset());
  const CPoolRecord *rec = cpool->getRecord(refs);
  if (rec != (const CPoolRecord *)0)
    s << '_' << rec->getToken();
  s << '(';
  Varnode::printRaw(s,op->getIn(0));
  for(int4 i=2;i<op->numInput();++i) {
    s << ',';
    Varnode::printRaw(s,op->getIn(i));
  }
  s << ')';
}

TypeOpNew::TypeOpNew(TypeFactory *t) : TypeOp(t,CPUI_NEW,"new")

{
  opflags = PcodeOp::special | PcodeOp::call | PcodeOp::nocollapse;
  behave = new OpBehavior(CPUI_NEW,false,true);		// Dummy behavior
}

void TypeOpNew::printRaw(ostream &s,const PcodeOp *op)

{
  if (op->getOut() != (Varnode *)0) {
    Varnode::printRaw(s,op->getOut());
    s << " = ";
  }
  s << getOperatorName(op);
  s << '(';
  Varnode::printRaw(s,op->getIn(0));
  for(int4 i=1;i<op->numInput();++i) {
    s << ',';
    Varnode::printRaw(s,op->getIn(i));
  }
  s << ')';
}

TypeOpInsert::TypeOpInsert(TypeFactory *t)
  : TypeOpFunc(t,CPUI_INSERT,"INSERT",TYPE_UNKNOWN,TYPE_INT)
{
  opflags = PcodeOp::ternary;
  behave = new OpBehavior(CPUI_INSERT,false);	// Dummy behavior
}

Datatype *TypeOpInsert::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (slot == 0)
    return tlst->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN);
  return TypeOpFunc::getInputLocal(op, slot);
}

TypeOpExtract::TypeOpExtract(TypeFactory *t)
  : TypeOpFunc(t,CPUI_EXTRACT,"EXTRACT",TYPE_INT,TYPE_INT)
{
  opflags = PcodeOp::ternary;
  behave = new OpBehavior(CPUI_EXTRACT,false);	// Dummy behavior
}

Datatype *TypeOpExtract::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (slot == 0)
    return tlst->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN);
  return TypeOpFunc::getInputLocal(op, slot);
}

TypeOpPopcount::TypeOpPopcount(TypeFactory *t)
  : TypeOpFunc(t,CPUI_POPCOUNT,"POPCOUNT",TYPE_INT,TYPE_UNKNOWN)
{
  opflags = PcodeOp::unary;
  behave = new OpBehaviorPopcount();
}

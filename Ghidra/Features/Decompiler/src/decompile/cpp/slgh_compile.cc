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
#include "slgh_compile.hh"
#include "filemanage.hh"
#include <csignal>

SleighCompile *slgh;		// Global pointer to sleigh object for use with parser
#ifdef YYDEBUG
extern int yydebug;		// Global debugging state for parser
#endif
extern FILE *yyin;		// Global pointer to file for lexer
extern int yyparse(void);
extern int yylex_destroy(void);

static VarnodeTpl *find_size(const ConstTpl &offset,const ConstructTpl *ct)

{				// Find a defining instance of the local variable
				// with given -offset-
  const vector<OpTpl *> &ops(ct->getOpvec());
  VarnodeTpl *vn;
  OpTpl *op;
  
  for(int4 i=0;i<ops.size();++i) {
    op = ops[i];
    vn = op->getOut();
    if ((vn!=(VarnodeTpl *)0)&&(vn->isLocalTemp())) {
      if (vn->getOffset() == offset)
	return vn;
    }
    for(int4 j=0;j<op->numInput();++j) {
      vn = op->getIn(j);
      if (vn->isLocalTemp()&&(vn->getOffset()==offset))
	return vn;
    }
  }
  return (VarnodeTpl *)0;
}

static bool force_exportsize(ConstructTpl *ct)

{				// Look for zero size temps in export statement
  HandleTpl *result = ct->getResult();
  if (result == (HandleTpl *)0) return true;

  VarnodeTpl *vt;

  if (result->getPtrSpace().isUniqueSpace()&&result->getPtrSize().isZero()) {
    vt = find_size(result->getPtrOffset(),ct);
    if (vt == (VarnodeTpl *)0) return false;
    result->setPtrSize(vt->getSize());
  }
  else if (result->getSpace().isUniqueSpace()&&result->getSize().isZero()) {
    vt = find_size(result->getPtrOffset(),ct);
    if (vt == (VarnodeTpl *)0) return false;
    result->setSize(vt->getSize());
  }
  return true;
}

SectionVector::SectionVector(ConstructTpl *rtl,SymbolScope *scope)

{
  nextindex = -1;
  main.section = rtl;
  main.scope = scope;
}

void SectionVector::append(ConstructTpl *rtl,SymbolScope *scope)

{
  while(named.size() <= nextindex)
    named.emplace_back();
  named[ nextindex ] = RtlPair(rtl,scope);
}

SpaceQuality::SpaceQuality(const string &nm)

{				// Default space qualities
  name = nm;
  type = ramtype;
  size = 0;
  wordsize = 1;
  isdefault = false;
}

FieldQuality::FieldQuality(string *nm,uintb *l,uintb *h)

{
  name = *nm;
  low = *l;
  high = *h;
  signext = false;
  flow = true;
  hex = true;
  delete nm;
  delete l;
  delete h;
}

void WithBlock::set(SubtableSymbol *s, PatternEquation *pq, vector<ContextChange *> *cvec)

{
  ss = s;
  pateq = pq;
  if (pateq != (PatternEquation *)0)
    pateq->layClaim();
  if (cvec != (vector<ContextChange *> *)0) {
    for(int4 i=0;i<cvec->size();++i)
      contvec.push_back((*cvec)[i]);	// Lay claim to -cvec-s pointers, we don't clone
    delete cvec;
  }
}

WithBlock::~WithBlock(void)

{
  if (pateq != (PatternEquation *)0)
    PatternEquation::release(pateq);
  for(int4 i=0;i<contvec.size();++i) {
    delete contvec[i];
  }
}

PatternEquation *WithBlock::collectAndPrependPattern(const list<WithBlock> &stack, PatternEquation *pateq)

{
  list<WithBlock>::const_iterator iter;
  for(iter=stack.begin();iter!=stack.end();++iter) {
    PatternEquation *witheq = (*iter).pateq;
    if (witheq != (PatternEquation *)0)
      pateq = new EquationAnd(witheq, pateq);
  }
  return pateq;
}

vector<ContextChange *> *WithBlock::collectAndPrependContext(const list<WithBlock> &stack, vector<ContextChange *> *contvec)

{ // Make new list of ContextChanges, prepending everything from stack to -contvec-, delete old contvec
  vector<ContextChange *> *res = (vector<ContextChange *> *)0;
  list<WithBlock>::const_iterator iter;
  for(iter=stack.begin();iter!=stack.end();++iter) {
    const vector<ContextChange *> &changelist( (*iter).contvec );
    if (changelist.size() == 0) continue;
    if (res == (vector<ContextChange *> *)0)
      res = new vector<ContextChange *>();
    for(int4 i=0;i<changelist.size();++i) {
      res->push_back(changelist[i]->clone());
    }
  }
  if (contvec != (vector<ContextChange *> *)0) {
    if (contvec->size() != 0) {
      if (res == (vector<ContextChange *> *)0)
	res = new vector<ContextChange *>();
      for(int4 i=0;i<contvec->size();++i)
	res->push_back((*contvec)[i]);		// lay claim to contvecs pointer
    }
    delete contvec;
  }
  return res;
}

SubtableSymbol *WithBlock::getCurrentSubtable(const list<WithBlock> &stack)

{
  list<WithBlock>::const_iterator iter;
  for(iter=stack.begin();iter!=stack.end();++iter) {
    if ((*iter).ss != (SubtableSymbol *)0)
      return (*iter).ss;
  }
  return (SubtableSymbol *)0;
}

ConsistencyChecker::ConsistencyChecker(SleighCompile *sleigh,SubtableSymbol *rt,bool un,bool warndead, bool warnlargetemp)

{
  compiler = sleigh;
  root_symbol = rt;
  unnecessarypcode = 0;
  readnowrite = 0;
  writenoread = 0;
  largetemp = 0;        ///<Number of constructors using at least one temporary varnode larger than SleighBase::MAX_UNIQUE_SIZE
  printextwarning = un;
  printdeadwarning = warndead;
  printlargetempwarning = warnlargetemp; ///< If true, prints a warning about each constructor using a temporary varnode larger than SleighBase::MAX_UNIQUE_SIZE
}

int4 ConsistencyChecker::recoverSize(const ConstTpl &sizeconst,Constructor *ct)

{
  int4 size,handindex;
  OperandSymbol *opsym;
  SubtableSymbol *tabsym;
  map<SubtableSymbol *,int4>::const_iterator iter;

  switch(sizeconst.getType()) {
  case ConstTpl::real:
    size = (int4) sizeconst.getReal();
    break;
  case ConstTpl::handle:
    handindex = sizeconst.getHandleIndex();
    opsym = ct->getOperand(handindex);
    size = opsym->getSize();
    if (size == -1) {
      tabsym = dynamic_cast<SubtableSymbol *>(opsym->getDefiningSymbol());
      if (tabsym == (SubtableSymbol *)0)
	throw SleighError("Could not recover varnode template size");
      iter = sizemap.find(tabsym);
      if (iter == sizemap.end())
	throw SleighError("Subtable out of order");
      size = (*iter).second;
    }
    break;
  default:
    throw SleighError("Bad constant type as varnode template size");
  }
  return size;
}

void ConsistencyChecker::dealWithUnnecessaryExt(OpTpl *op,Constructor *ct)

{ // Deal with detected extension (SEXT or ZEXT) where the
  // input size is the same as the output size
  if (printextwarning) {
    ostringstream msg;
    msg << "Unnecessary ";
    printOpName(msg,op);
    compiler->reportWarning(compiler->getLocation(ct), msg.str());
  }
  op->setOpcode(CPUI_COPY);	// Equivalent to copy
  unnecessarypcode += 1;
}

void ConsistencyChecker::dealWithUnnecessaryTrunc(OpTpl *op,Constructor *ct)

{
  if (printextwarning) {
    ostringstream msg;
    msg << "Unnecessary ";
    printOpName(msg,op);
    compiler->reportWarning(compiler->getLocation(ct), msg.str());
  }
  op->setOpcode(CPUI_COPY);	// Equivalent to copy
  op->removeInput(1);
  unnecessarypcode += 1;
}

bool ConsistencyChecker::checkOpMisuse(OpTpl *op,Constructor *ct)

{
  switch(op->getOpcode()) {
  case CPUI_INT_LESS:
    {
      VarnodeTpl *vn = op->getIn(1);
      if (vn->getSpace().isConstSpace() && vn->getOffset().isZero()) {
	compiler->reportWarning(compiler->getLocation(ct), "Unsigned comparison with zero is always false");
      }
    }
    break;
  default:
    break;
  }
  return true;
}

bool ConsistencyChecker::sizeRestriction(OpTpl *op,Constructor *ct)

{ // Make sure op template meets size restrictions
  // Return false and any info about mismatched sizes
  int4 vnout,vn0,vn1;
  AddrSpace *spc;

  switch(op->getOpcode()) {
  case CPUI_COPY:			// Instructions where all inputs and output are same size
  case CPUI_INT_2COMP:
  case CPUI_INT_NEGATE:
  case CPUI_FLOAT_NEG:
  case CPUI_FLOAT_ABS:
  case CPUI_FLOAT_SQRT:
  case CPUI_FLOAT_CEIL:
  case CPUI_FLOAT_FLOOR:
  case CPUI_FLOAT_ROUND:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    if (vnout == vn0) return true;
    if ((vnout==0)||(vn0==0)) return true;
    printOpError(op,ct,-1,0,"Input and output sizes must match");
    return false;
  case CPUI_INT_ADD:
  case CPUI_INT_SUB:
  case CPUI_INT_XOR:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_MULT:
  case CPUI_INT_DIV:
  case CPUI_INT_SDIV:
  case CPUI_INT_REM:
  case CPUI_INT_SREM:
  case CPUI_FLOAT_ADD:
  case CPUI_FLOAT_DIV:
  case CPUI_FLOAT_MULT:
  case CPUI_FLOAT_SUB:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    vn1 = recoverSize(op->getIn(1)->getSize(),ct);
    if (vn1 == -1) {
      printOpError(op,ct,1,1,"Using subtable with exports in expression");
      return false;
    }
    if ((vnout!=0)&&(vn0!=0)&&(vnout!=vn0)) {
      printOpError(op,ct,-1,0,"The output and all input sizes must match");
      return false;
    }
    if ((vnout!=0)&&(vn1!=0)&&(vnout!=vn1)) {
      printOpError(op,ct,-1,1,"The output and all input sizes must match");
      return false;
    }
    if ((vn0!=0)&&(vn1!=0)&&(vn0!=vn1)) {
      printOpError(op,ct,0,1,"The output and all input sizes must match");
      return false;
    }
    return true;
  case CPUI_FLOAT_NAN:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    if (vnout != 1) {
      printOpError(op,ct,-1,-1,"Output must be a boolean (size 1)");
      return false;
    }
    break;
  case CPUI_INT_EQUAL:		// Instructions with bool output, all inputs equal size
  case CPUI_INT_NOTEQUAL:
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_CARRY:
  case CPUI_INT_SCARRY:
  case CPUI_INT_SBORROW:
  case CPUI_FLOAT_EQUAL:
  case CPUI_FLOAT_NOTEQUAL:
  case CPUI_FLOAT_LESS:
  case CPUI_FLOAT_LESSEQUAL:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    if (vnout != 1) {
      printOpError(op,ct,-1,-1,"Output must be a boolean (size 1)");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    vn1 = recoverSize(op->getIn(1)->getSize(),ct);
    if (vn1 == -1) {
      printOpError(op,ct,1,1,"Using subtable with exports in expression");
      return false;
    }
    if ((vn0==0)||(vn1==0)) return true;
    if (vn0 != vn1) {
      printOpError(op,ct,0,1,"Inputs must be the same size");
      return false;
    }
    return true;
  case CPUI_BOOL_XOR:
  case CPUI_BOOL_AND:
  case CPUI_BOOL_OR:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    if (vnout != 1) {
      printOpError(op,ct,-1,-1,"Output must be a boolean (size 1)");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    if (vn0 != 1) {
      printOpError(op,ct,0,0,"Input must be a boolean (size 1)");
      return false;
    }
    return true;
  case CPUI_BOOL_NEGATE:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    if (vnout != 1) {
      printOpError(op,ct,-1,-1,"Output must be a boolean (size 1)");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    if (vn0 != 1) {
      printOpError(op,ct,0,0,"Input must be a boolean (size 1)");
      return false;
    }
    return true;
    // The shift amount does not necessarily have to be the same size
    // But the output and first parameter must be same size
  case CPUI_INT_LEFT:
  case CPUI_INT_RIGHT:
  case CPUI_INT_SRIGHT:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    if ((vnout==0)||(vn0==0)) return true;
    if (vnout != vn0) {
      printOpError(op,ct,-1,0,"Output and first input must be the same size");
      return false;
    }
    return true;
  case CPUI_INT_ZEXT:
  case CPUI_INT_SEXT:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    if ((vnout==0)||(vn0==0)) return true;
    if (vnout == vn0) {
      dealWithUnnecessaryExt(op,ct);
      return true;
    }
    else if (vnout < vn0) {
      printOpError(op,ct,-1,0,"Output size must be strictly bigger than input size");
      return false;
    }
    return true;
  case CPUI_CBRANCH:
    vn1 = recoverSize(op->getIn(1)->getSize(),ct);
    if (vn1 == -1) {
      printOpError(op,ct,1,1,"Using subtable with exports in expression");
      return false;
    }
    if (vn1 != 1) {
      printOpError(op,ct,1,1,"Input must be a boolean (size 1)");
      return false;
    }
    return true;
  case CPUI_LOAD:
  case CPUI_STORE:
    if (op->getIn(0)->getOffset().getType() != ConstTpl::spaceid)
      return true;
    spc = op->getIn(0)->getOffset().getSpace();
    vn1 = recoverSize(op->getIn(1)->getSize(),ct);
    if (vn1 == -1) {
      printOpError(op,ct,1,1,"Using subtable with exports in expression");
      return false;
    }
    if ((vn1!=0)&&(vn1 != spc->getAddrSize())) {
      printOpError(op,ct,1,1,"Pointer size must match size of space");
      return false;
    }
    return true;
  case CPUI_SUBPIECE:
    vnout = recoverSize(op->getOut()->getSize(),ct);
    if (vnout == -1) {
      printOpError(op,ct,-1,-1,"Using subtable with exports in expression");
      return false;
    }
    vn0 = recoverSize(op->getIn(0)->getSize(),ct);
    if (vn0 == -1) {
      printOpError(op,ct,0,0,"Using subtable with exports in expression");
      return false;
    }
    vn1 = op->getIn(1)->getOffset().getReal();
    if ((vnout==0)||(vn0==0)) return true;
    if ((vnout==vn0)&&(vn1==0)) { // No actual truncation is occuring
      dealWithUnnecessaryTrunc(op,ct);
      return true;
    }
    else if (vnout>=vn0) {
      printOpError(op,ct,-1,0,"Output must be strictly smaller than input");
      return false;
    }
    if (vnout>vn0-vn1) {
      printOpError(op,ct,-1,0,"Too much truncation");
      return false;
    }
    return true;
  default:
    break;
  }
  return true;
}

void ConsistencyChecker::printOpName(ostream &s,OpTpl *op)

{
  switch(op->getOpcode()) {
  case CPUI_COPY:
    s << "Copy(=)";
    break;
  case CPUI_LOAD:
    s << "Load(*)";
    break;
  case CPUI_STORE:
    s << "Store(*)";
    break;
  case CPUI_BRANCH:
    s << "Branch(goto)";
    break;
  case CPUI_CBRANCH:
    s << "Conditional branch(if)";
    break;
  case CPUI_BRANCHIND:
    s << "Indirect branch(goto[])";
    break;
  case CPUI_CALL:
    s << "Call";
    break;
  case CPUI_CALLIND:
    s << "Indirect Call";
    break;
  case CPUI_CALLOTHER:
    s << "User defined";
    break;
  case CPUI_RETURN:
    s << "Return";
    break;
  case CPUI_INT_EQUAL:
    s << "Equality(==)";
    break;
  case CPUI_INT_NOTEQUAL:
    s << "Notequal(!=)";
    break;
  case CPUI_INT_SLESS:
    s << "Signed less than(s<)";
    break;
  case CPUI_INT_SLESSEQUAL:
    s << "Signed less than or equal(s<=)";
    break;
  case CPUI_INT_LESS:
    s << "Less than(<)";
    break;
  case CPUI_INT_LESSEQUAL:
    s << "Less than or equal(<=)";
    break;
  case CPUI_INT_ZEXT:
    s << "Zero extension(zext)";
    break;
  case CPUI_INT_SEXT:
    s << "Signed extension(sext)";
    break;
  case CPUI_INT_ADD:
    s << "Addition(+)";
    break;
  case CPUI_INT_SUB:
    s << "Subtraction(-)";
    break;
  case CPUI_INT_CARRY:
    s << "Carry";
    break;
  case CPUI_INT_SCARRY:
    s << "Signed carry";
    break;
  case CPUI_INT_SBORROW:
    s << "Signed borrow";
    break;
  case CPUI_INT_2COMP:
    s << "Twos complement(-)";
    break;
  case CPUI_INT_NEGATE:
    s << "Negate(~)";
    break;
  case CPUI_INT_XOR:
    s << "Exclusive or(^)";
    break;
  case CPUI_INT_AND:
    s << "And(&)";
    break;
  case CPUI_INT_OR:
    s << "Or(|)";
    break;
  case CPUI_INT_LEFT:
    s << "Left shift(<<)";
    break;
  case CPUI_INT_RIGHT:
    s << "Right shift(>>)";
    break;
  case CPUI_INT_SRIGHT:
    s << "Signed right shift(s>>)";
    break;
  case CPUI_INT_MULT:
    s << "Multiplication(*)";
    break;
  case CPUI_INT_DIV:
    s << "Division(/)";
    break;
  case CPUI_INT_SDIV:
    s << "Signed division(s/)";
    break;
  case CPUI_INT_REM:
    s << "Remainder(%)";
    break;
  case CPUI_INT_SREM:
    s << "Signed remainder(s%)";
    break;
  case CPUI_BOOL_NEGATE:
    s << "Boolean negate(!)";
    break;
  case CPUI_BOOL_XOR:
    s << "Boolean xor(^^)";
    break;
  case CPUI_BOOL_AND:
    s << "Boolean and(&&)";
    break;
  case CPUI_BOOL_OR:
    s << "Boolean or(||)";
    break;
  case CPUI_FLOAT_EQUAL:
    s << "Float equal(f==)";
    break;
  case CPUI_FLOAT_NOTEQUAL:
    s << "Float notequal(f!=)";
    break;
  case CPUI_FLOAT_LESS:
    s << "Float less than(f<)";
    break;
  case CPUI_FLOAT_LESSEQUAL:
    s << "Float less than or equal(f<=)";
    break;
  case CPUI_FLOAT_NAN:
    s << "Not a number(nan)";
    break;
  case CPUI_FLOAT_ADD:
    s << "Float addition(f+)";
    break;
  case CPUI_FLOAT_DIV:
    s << "Float division(f/)";
    break;
  case CPUI_FLOAT_MULT:
    s << "Float multiplication(f*)";
    break;
  case CPUI_FLOAT_SUB:
    s << "Float subtractions(f-)";
    break;
  case CPUI_FLOAT_NEG:
    s << "Float minus(f-)";
    break;
  case CPUI_FLOAT_ABS:
    s << "Absolute value(abs)";
    break;
  case CPUI_FLOAT_SQRT:
    s << "Square root";
    break;
  case CPUI_FLOAT_INT2FLOAT:
    s << "Integer to float conversion(int2float)";
    break;
  case CPUI_FLOAT_FLOAT2FLOAT:
    s << "Float to float conversion(float2float)";
    break;
  case CPUI_FLOAT_TRUNC:
    s << "Float truncation(trunc)";
    break;
  case CPUI_FLOAT_CEIL:
    s << "Ceiling(ceil)";
    break;
  case CPUI_FLOAT_FLOOR:
    s << "Floor";
    break;
  case CPUI_FLOAT_ROUND:
    s << "Round";
    break;
  case CPUI_MULTIEQUAL:
    s << "Build";
    break;
  case CPUI_INDIRECT:
    s << "Delay";
    break;
  case CPUI_SUBPIECE:
    s << "Truncation(:)";
    break;
  case CPUI_SEGMENTOP:
    s << "Segment table(segment)";
    break;
  case CPUI_CPOOLREF:
    s << "Constant Pool(cpool)";
    break;
  case CPUI_NEW:
    s << "New object(newobject)";
    break;
  case CPUI_POPCOUNT:
    s << "Count bits(popcount)";
    break;
  default:
    break;
  }
}

OperandSymbol *ConsistencyChecker::getOperandSymbol(int4 slot,OpTpl *op,Constructor *ct)

{
  VarnodeTpl *vn;
  OperandSymbol *opsym;
  int4 handindex;

  if (slot == -1)
    vn = op->getOut();
  else
    vn = op->getIn(slot);
  
  switch(vn->getSize().getType()) {
  case ConstTpl::handle:
    handindex = vn->getSize().getHandleIndex();
    opsym = ct->getOperand(handindex);
    break;
  default:
    opsym = (OperandSymbol *)0;
    break;
  }
  return opsym;
}

void ConsistencyChecker::printOpError(OpTpl *op,Constructor *ct,int4 err1,int4 err2,const string &msg)

{
  SubtableSymbol *sym = ct->getParent();
  OperandSymbol *op1,*op2;

  op1 = getOperandSymbol(err1,op,ct);
  if (err2 != err1)
    op2 = getOperandSymbol(err2,op,ct);
  else
    op2 = (OperandSymbol *)0;

  ostringstream msgBuilder;

  msgBuilder << "Size restriction error in table '" << sym->getName() << "'" << endl;
  if ((op1 != (OperandSymbol *)0)&&(op2 != (OperandSymbol *)0))
    msgBuilder << "  Problem with operands '" << op1->getName() << "' and '" << op2->getName() << "'";
  else if (op1 != (OperandSymbol *)0)
    msgBuilder << "  Problem with operand 1 '" << op1->getName() << "'";
  else if (op2 != (OperandSymbol *)0)
    msgBuilder << "  Problem with operand 2 '" << op2->getName() << "'";
  else
    msgBuilder << "  Problem";
  msgBuilder << " in ";
  printOpName(msgBuilder,op);
  msgBuilder << " operator" << endl << "  " << msg;

  compiler->reportError(compiler->getLocation(ct), msgBuilder.str());
}

bool ConsistencyChecker::checkConstructorSection(Constructor *ct,ConstructTpl *cttpl)

{ // Check all the OpTpl s within the given section for consistency, return true if all tests pass
  if (cttpl == (ConstructTpl *)0)
    return true;		// Nothing to check
  vector<OpTpl *>::const_iterator iter;
  const vector<OpTpl *> &ops(cttpl->getOpvec());
  bool testresult = true;

  for(iter=ops.begin();iter!=ops.end();++iter) {
    if (!sizeRestriction(*iter,ct))
      testresult = false;
    if (!checkOpMisuse(*iter,ct))
      testresult = false;
  }
  return testresult;
}

///
/// Returns true if the output or one of the inputs of
/// op is in the unique space and larger than SleighBase::MAX_UNIQUE_SIZE
///
bool ConsistencyChecker::hasLargeTemporary(OpTpl *op){
	VarnodeTpl *out = op->getOut();
	if ((out != (VarnodeTpl *) 0x0) && isTemporaryAndTooBig(out)) {
		return true;
	}
	for (int4 i = 0; i < op->numInput(); ++i) {
	    VarnodeTpl *in = op->getIn(i);
		if (isTemporaryAndTooBig(in)) {
			return true;
		}
	}
	return false;
}

///
/// Returns true precisely when vn is in the unique space and
/// has size larger than SleighBase::MAX_UNIQUE_SIZE
///
bool ConsistencyChecker::isTemporaryAndTooBig(VarnodeTpl *vn){
	return vn->getSpace().isUniqueSpace() &&
	    (vn->getSize().getReal() > SleighBase::MAX_UNIQUE_SIZE);
	}

bool ConsistencyChecker::checkVarnodeTruncation(Constructor *ct,int4 slot,
						OpTpl *op,VarnodeTpl *vn,bool isbigendian)
{
  const ConstTpl &off( vn->getOffset() );
  if (off.getType() != ConstTpl::handle) return true;
  if (off.getSelect() != ConstTpl::v_offset_plus) return true;
  ConstTpl::const_type sztype = vn->getSize().getType();
  if ((sztype != ConstTpl::real)&&(sztype != ConstTpl::handle)) {
    printOpError(op,ct,slot,slot,"Bad truncation expression");
    return false;
  }
  int4 sz = recoverSize(off,ct); // Recover the size of the original operand
  if (sz <= 0) {
    printOpError(op,ct,slot,slot,"Could not recover size");
    return false;
  }
  bool res = vn->adjustTruncation(sz,isbigendian);
  if (!res) {
    printOpError(op,ct,slot,slot,"Truncation operator out of bounds");
    return false;
  }
  return true;
}

bool ConsistencyChecker::checkSectionTruncations(Constructor *ct,ConstructTpl *cttpl,bool isbigendian)

{ // Check all the varnodes that have an offset_plus template
  //     adjust the plus if we are bigendian
  //     make sure the truncation is valid
  vector<OpTpl *>::const_iterator iter;
  const vector<OpTpl *> &ops(cttpl->getOpvec());
  bool testresult = true;
  
  for(iter=ops.begin();iter!=ops.end();++iter) {
    OpTpl *op = *iter;
    VarnodeTpl *outvn = op->getOut();
    if (outvn != (VarnodeTpl *)0) {
      if (!checkVarnodeTruncation(ct,-1,op,outvn,isbigendian))
	testresult = false;
    }
    for(int4 i=0;i<op->numInput();++i) {
      if (!checkVarnodeTruncation(ct,i,op,op->getIn(i),isbigendian))
	testresult = false;
    }
  }
  return testresult;
}

bool ConsistencyChecker::checkSubtable(SubtableSymbol *sym)

{
  int4 tablesize = 0;
  int4 numconstruct = sym->getNumConstructors();
  Constructor *ct;
  bool testresult = true;
  bool seenemptyexport = false;
  bool seennonemptyexport = false;

  for(int4 i=0;i<numconstruct;++i) {
    ct = sym->getConstructor(i);
    if (!checkConstructorSection(ct,ct->getTempl()))
      testresult = false;
    int4 numsection = ct->getNumSections();
    for(int4 j=0;j<numsection;++j) {
      if (!checkConstructorSection(ct,ct->getNamedTempl(j)))
	testresult = false;
    }

    if (ct->getTempl() == (ConstructTpl *)0) continue;	// Unimplemented
    HandleTpl *exportres = ct->getTempl()->getResult();
    if (exportres != (HandleTpl *)0) {
      if (seenemptyexport && (!seennonemptyexport)) {
	ostringstream msg;
	msg << "Table '" << sym->getName() << "' exports inconsistently; ";
	msg << "Constructor starting at line " << dec << ct->getLineno() << " is first inconsistency";
	compiler->reportError(compiler->getLocation(ct), msg.str());
	testresult = false;
      }
      seennonemptyexport = true;
      int4 exsize = recoverSize(exportres->getSize(),ct);
      if (tablesize == 0)
	tablesize = exsize;
      if ((exsize!=0)&&(exsize != tablesize)) {
	ostringstream msg;
	msg << "Table '" << sym->getName() << "' has inconsistent export size; ";
	msg << "Constructor starting at line " << dec << ct->getLineno() << " is first conflict";
	compiler->reportError(compiler->getLocation(ct), msg.str());
	testresult = false;
      }
    }
    else {
      if (seennonemptyexport && (!seenemptyexport)) {
	ostringstream msg;
	msg << "Table '" << sym->getName() << "' exports inconsistently; ";
	msg << "Constructor starting at line " << dec << ct->getLineno() << " is first inconsistency";
	compiler->reportError(compiler->getLocation(ct), msg.str());
	testresult = false;
      }
      seenemptyexport = true;
    }
  }
  if (seennonemptyexport) {
    if (tablesize == 0) {
      compiler->reportWarning(compiler->getLocation(sym), "Table '" + sym->getName() + "' exports size 0");
    }
    sizemap[sym] = tablesize;	// Remember recovered size
  }
  else
    sizemap[sym] = -1;
  
  return testresult;
}

void ConsistencyChecker::setPostOrder(SubtableSymbol *root)

{
  postorder.clear();
  sizemap.clear();

  // Establish post-order of SubtableSymbols so that we can
  // recursively fill in sizes of varnodes which are exported
  // from constructors

  vector<SubtableSymbol *> path;
  vector<int4> state;
  vector<int4> ctstate;

  sizemap[root] = -1;		// Mark root as traversed
  path.push_back(root);
  state.push_back(0);
  ctstate.push_back(0);

  while(!path.empty()) {
    SubtableSymbol *cur = path.back();
    int4 ctind = state.back();
    if (ctind >= cur->getNumConstructors()) {
      path.pop_back(); 		// Table is fully traversed
      state.pop_back();
      ctstate.pop_back();
      postorder.push_back(cur);	// Post the traversed table
    }
    else {
      Constructor *ct = cur->getConstructor(ctind);
      int4 oper = ctstate.back();
      if (oper >= ct->getNumOperands()) {
	state.back() = ctind + 1; // Constructor fully traversed
	ctstate.back() = 0;
      }
      else {
	ctstate.back() = oper + 1;
	OperandSymbol *opsym = ct->getOperand(oper);
	SubtableSymbol *subsym = dynamic_cast<SubtableSymbol *>(opsym->getDefiningSymbol());
	if (subsym != (SubtableSymbol *)0) {
	  map<SubtableSymbol *,int4>::const_iterator iter;
	  iter = sizemap.find(subsym);
	  if (iter == sizemap.end()) { // Not traversed yet
	    sizemap[subsym] = -1; // Mark table as traversed
	    path.push_back(subsym); // Recurse
	    state.push_back(0);
	    ctstate.push_back(0);
	  }
	}
      }
    }
  }
}

bool ConsistencyChecker::possibleIntersection(const VarnodeTpl *vn1,const VarnodeTpl *vn2)

{ // Conservatively test whether vn1 and vn2 can intersect
  if (vn1->getSpace().isConstSpace()) return false;
  if (vn2->getSpace().isConstSpace()) return false;

  bool u1 = vn1->getSpace().isUniqueSpace();
  bool u2 = vn2->getSpace().isUniqueSpace();

  if (u1 != u2) return false;

  if (vn1->getSpace().getType() != ConstTpl::spaceid) return true;
  if (vn2->getSpace().getType() != ConstTpl::spaceid) return true;
  AddrSpace *spc = vn1->getSpace().getSpace();
  if (spc != vn2->getSpace().getSpace()) return false;


  if (vn2->getOffset().getType() != ConstTpl::real) return true;
  if (vn2->getSize().getType() != ConstTpl::real) return true;

  if (vn1->getOffset().getType() != ConstTpl::real) return true;
  if (vn1->getSize().getType() != ConstTpl::real) return true;

  uintb offset = vn1->getOffset().getReal();
  uintb size = vn1->getSize().getReal();

  uintb off = vn2->getOffset().getReal();
  if (off+vn2->getSize().getReal()-1 < offset) return false;
  if (off > (offset+size-1)) return false;
  return true;
}

bool ConsistencyChecker::readWriteInterference(const VarnodeTpl *vn,const OpTpl *op,bool checkread) const

{ // Does op potentially read vn
  // This is extremely conservative.  Basically any op where
  // we can't see exactly what might be written is considered
  // interference
  switch(op->getOpcode()) {
  case BUILD:
  case CROSSBUILD:
  case DELAY_SLOT:
  case MACROBUILD:
  case CPUI_LOAD:
  case CPUI_STORE:
  case CPUI_BRANCH:
  case CPUI_CBRANCH:
  case CPUI_BRANCHIND:
  case CPUI_CALL:
  case CPUI_CALLIND:
  case CPUI_CALLOTHER:
  case CPUI_RETURN:
  case LABELBUILD:		// Another value might jump in here
    return true;
  default:
    break;
  }

  if (checkread) {
    int4 numinputs = op->numInput();
    for(int4 i=0;i<numinputs;++i)
      if (possibleIntersection(vn,op->getIn(i)))
	return true;
  }

  // We always check for writes to -vn-
  const VarnodeTpl *vn2 = op->getOut();
  if (vn2 != (const VarnodeTpl *)0) {
	if (possibleIntersection(vn,vn2))
      return true;
  }
  return false;
}

void ConsistencyChecker::examineVn(map<uintb,OptimizeRecord> &recs,
				   const VarnodeTpl *vn,uint4 i,int4 inslot,int4 secnum)
{ // If varnode is a temporary,  count whether it is read or written
  if (vn == (const VarnodeTpl *)0) return;
  if (!vn->getSpace().isUniqueSpace()) return;
  if (vn->getOffset().getType() != ConstTpl::real) return;

  map<uintb,OptimizeRecord>::iterator iter;
  iter = recs.insert( pair<uint4,OptimizeRecord>(vn->getOffset().getReal(),OptimizeRecord())).first;
  if (inslot>=0) {
    (*iter).second.readop = i;
    (*iter).second.readcount += 1;
    (*iter).second.inslot = inslot;
    (*iter).second.readsection = secnum;
  }
  else {
    (*iter).second.writeop = i;
    (*iter).second.writecount += 1;
    (*iter).second.writesection = secnum;
  }
}

void ConsistencyChecker::optimizeGather1(Constructor *ct,map<uintb,OptimizeRecord> &recs,int4 secnum) const

{ // Look for reads and writes to temporaries, count how many times each temporary is read or written
  ConstructTpl *tpl;
  if (secnum < 0)
    tpl = ct->getTempl();
  else
    tpl = ct->getNamedTempl(secnum);
  if (tpl == (ConstructTpl *)0)
    return;
  const vector<OpTpl *> &ops( tpl->getOpvec() );
  for(uint4 i=0;i<ops.size();++i) {
    const OpTpl *op = ops[i];
    for(uint4 j=0;j<op->numInput();++j) {
      const VarnodeTpl *vnin = op->getIn(j);
      examineVn(recs,vnin,i,j,secnum);
    }
    const VarnodeTpl *vn = op->getOut();
    examineVn(recs,vn,i,-1,secnum);
  }
}

void ConsistencyChecker::optimizeGather2(Constructor *ct,map<uintb,OptimizeRecord> &recs,int4 secnum) const

{ // Make sure any temp used by the export is not optimized away
  ConstructTpl *tpl;
  if (secnum < 0)
    tpl = ct->getTempl();
  else
    tpl = ct->getNamedTempl(secnum);
  if (tpl == (ConstructTpl *)0)
    return;
  HandleTpl *hand = tpl->getResult();
  if (hand == (HandleTpl *)0) return;
  if (hand->getPtrSpace().isUniqueSpace()) {
    if (hand->getPtrOffset().getType() == ConstTpl::real) {
      pair<map<uintb,OptimizeRecord>::iterator,bool> res;
      uintb offset = hand->getPtrOffset().getReal();
      res = recs.insert( pair<uintb,OptimizeRecord>(offset,OptimizeRecord()));
      (*res.first).second.writeop = 0;
      (*res.first).second.readop = 0;
      (*res.first).second.writecount = 2;
      (*res.first).second.readcount = 2;
      (*res.first).second.readsection = -2;
      (*res.first).second.writesection = -2;
    }
  }
  if (hand->getSpace().isUniqueSpace()) {
    if ((hand->getPtrSpace().getType() == ConstTpl::real)&&
	(hand->getPtrOffset().getType() == ConstTpl::real)) {
      pair<map<uintb,OptimizeRecord>::iterator,bool> res;
      uintb offset = hand->getPtrOffset().getReal();
      res = recs.insert( pair<uintb,OptimizeRecord>(offset,OptimizeRecord()));
      (*res.first).second.writeop = 0;
      (*res.first).second.readop = 0;
      (*res.first).second.writecount = 2;
      (*res.first).second.readcount = 2;
      (*res.first).second.readsection = -2;
      (*res.first).second.writesection = -2;
    }
  }
}

ConsistencyChecker::OptimizeRecord *ConsistencyChecker::findValidRule(Constructor *ct,map<uintb,OptimizeRecord> &recs) const

{
  map<uintb,OptimizeRecord>::iterator iter;
  iter = recs.begin();
  while(iter != recs.end()) {
    OptimizeRecord &currec( (*iter).second );
    ++iter;
    if ((currec.writecount==1)&&(currec.readcount==1)&&(currec.readsection==currec.writesection)) {
      // Temporary must be read and written exactly once
      ConstructTpl *tpl;
      if (currec.readsection < 0)
	tpl = ct->getTempl();
      else
	tpl = ct->getNamedTempl(currec.readsection);
      const vector<OpTpl *> &ops( tpl->getOpvec() );
      const OpTpl *op = ops[ currec.readop ];
      if (currec.writeop >= currec.readop) // Read must come after write
	throw SleighError("Read of temporary before write");
      if (op->getOpcode() == CPUI_COPY) {
	bool saverecord = true;
	currec.opttype = 0;	// Read op is a COPY
	const VarnodeTpl *vn = op->getOut();
	for(int4 i=currec.writeop+1;i<currec.readop;++i) { // Check for interference between write and read
	  if (readWriteInterference(vn,ops[i],true)) {
	    saverecord = false;
	    break;
	  }
	}
	if (saverecord)
	  return &currec;
      }
      op = ops[ currec.writeop ];
      if (op->getOpcode() == CPUI_COPY) {
	bool saverecord = true;
	currec.opttype = 1;	// Write op is a COPY
	const VarnodeTpl *vn = op->getIn(0);
	for(int4 i=currec.writeop+1;i<currec.readop;++i) { // Check for interference between write and read
	  if (readWriteInterference(vn,ops[i],false)) {
	    saverecord = false;
	    break;
	  }
	}
	if (saverecord)
	  return &currec;
      }
    }
  }
  return (OptimizeRecord *)0;
}

void ConsistencyChecker::applyOptimization(Constructor *ct,const OptimizeRecord &rec)

{
  vector<int4> deleteops;
  ConstructTpl *ctempl;
  if (rec.readsection < 0)
    ctempl = ct->getTempl();
  else
    ctempl = ct->getNamedTempl(rec.readsection);
  
  if (rec.opttype == 0) { // If read op is COPY
    int4 readop = rec.readop;
    OpTpl *op = ctempl->getOpvec()[ readop ];
    VarnodeTpl *vnout = new VarnodeTpl(*op->getOut()); // Make COPY output
    ctempl->setOutput(vnout,rec.writeop); // become write output
    deleteops.push_back(readop); // and then delete the read (COPY)
  }
  else if (rec.opttype == 1) { // If write op is COPY
    int4 writeop = rec.writeop;
    OpTpl *op = ctempl->getOpvec()[ writeop ];
    VarnodeTpl *vnin = new VarnodeTpl(*op->getIn(0));	// Make COPY input
    ctempl->setInput(vnin,rec.readop,rec.inslot); // become read input
    deleteops.push_back(writeop); // and then delete the write (COPY)
  }
  ctempl->deleteOps(deleteops);
}

void ConsistencyChecker::checkUnusedTemps(Constructor *ct,const map<uintb,OptimizeRecord> &recs)

{
  map<uintb,OptimizeRecord>::const_iterator iter;
  iter = recs.begin();
  while(iter != recs.end()) {
    const OptimizeRecord &currec( (*iter).second );
    if (currec.readcount == 0) {
      if (printdeadwarning)
	compiler->reportWarning(compiler->getLocation(ct), "Temporary is written but not read");
      writenoread += 1;
    }
    else if (currec.writecount == 0) {
      compiler->reportError(compiler->getLocation(ct), "Temporary is read but not written");
      readnowrite += 1;
    }
    ++iter;
  }
}

///
/// Checks the ops in ct to see whether a varnode larger than
/// SleighBase::MAX_UNIQUE_SIZE is used.  Note that this method
/// returns after the first large varnode is found.
///
void ConsistencyChecker::checkLargeTemporaries(Constructor *ct){
	ConstructTpl *ctTpl = ct->getTempl();
    if (ctTpl == (ConstructTpl *) 0){
        return;
    }
    vector<OpTpl *> ops = ctTpl->getOpvec();
    for (vector<OpTpl *>::iterator iter = ops.begin(); iter != ops.end(); ++iter){
    	if (hasLargeTemporary(*iter)){
    		if (printlargetempwarning){
    			compiler->reportWarning(compiler->getLocation(ct), "Constructor uses temporary varnode larger than " + to_string(SleighBase::MAX_UNIQUE_SIZE) + " bytes.");
    		}
    		largetemp++;
    		return;
    	}
    }
}

void ConsistencyChecker::optimize(Constructor *ct)

{
  OptimizeRecord *currec;
  map<uintb,OptimizeRecord> recs;
  int4 numsections = ct->getNumSections();
  do {
    recs.clear();
    for(int4 i=-1;i<numsections;++i) {
      optimizeGather1(ct,recs,i);
      optimizeGather2(ct,recs,i);
    }
    currec = findValidRule(ct,recs);
    if (currec != (OptimizeRecord *)0)
      applyOptimization(ct,*currec);
  } while(currec != (OptimizeRecord *)0);
  checkUnusedTemps(ct,recs);
  checkLargeTemporaries(ct);
}

bool ConsistencyChecker::test(void)

{ // Main entry point for size consistency check
  setPostOrder(root_symbol);
  bool testresult = true;

  for(int4 i=0;i<postorder.size();++i) {
    SubtableSymbol *sym = postorder[i];
    if (!checkSubtable(sym))
      testresult = false;
  }
  return testresult;
}

bool ConsistencyChecker::testTruncations(bool isbigendian)

{
  // Now that the sizemap is calculated, we can check/adjust the offset_plus templates
  bool testresult = true;
  for(int4 i=0;i<postorder.size();++i) {
    SubtableSymbol *sym = postorder[i];
    int4 numconstruct = sym->getNumConstructors();
    Constructor *ct;
    for(int4 j=0;j<numconstruct;++j) {
      ct = sym->getConstructor(j);

      int4 numsections = ct->getNumSections();
      for(int4 k=-1;k<numsections;++k) {
	ConstructTpl *tpl;
	if (k < 0)
	  tpl = ct->getTempl();
	else
	  tpl = ct->getNamedTempl(k);
	if (tpl == (ConstructTpl *)0)
	  continue;
	if (!checkSectionTruncations(ct,tpl,isbigendian))
	  testresult = false;
      }
    }
  }
  return testresult;
}

void ConsistencyChecker::optimizeAll(void)

{
  for(int4 i=0;i<postorder.size();++i) {
    SubtableSymbol *sym = postorder[i];
    int4 numconstruct = sym->getNumConstructors();
    Constructor *ct;
    for(int4 i=0;i<numconstruct;++i) {
      ct = sym->getConstructor(i);
      optimize(ct);
    }
  }
}

bool FieldContext::operator<(const FieldContext &op2) const

{
  if (sym->getName() != op2.sym->getName())
    return (sym->getName() < op2.sym->getName());
  return (qual->low < op2.qual->low);
}

void MacroBuilder::free(void)

{
  vector<HandleTpl *>::iterator iter;

  for(iter=params.begin();iter!=params.end();++iter)
    delete *iter;

  params.clear();
}

void MacroBuilder::reportError(const Location* loc, const string &val)

{
  slgh->reportError(loc, val);
  haserror = true;
}

void MacroBuilder::setMacroOp(OpTpl *macroop)

{				// Set up parameters for a particular macro invocation
  VarnodeTpl *vn;
  HandleTpl *hand;
  free();
  for(int4 i=1;i<macroop->numInput();++i) {
    vn = macroop->getIn(i);
    hand = new HandleTpl(vn);
    params.push_back(hand);
  }
}

bool MacroBuilder::transferOp(OpTpl *op,vector<HandleTpl *> &params)

{ // Fix handle details of a macro generated OpTpl relative to its specific invocation
  // and transfer it into the output stream
  VarnodeTpl *outvn = op->getOut();
  int4 handleIndex = 0;
  int4 plus;
  bool hasrealsize = false;
  uintb realsize = 0;

  if (outvn != (VarnodeTpl *)0) {
    plus = outvn->transfer(params);
    if (plus >= 0) {
      reportError((const Location *)0, "Cannot currently assign to bitrange of macro parameter that is a temporary");
      return false;
    }
  }
  for(int4 i=0;i<op->numInput();++i) {
    VarnodeTpl *vn = op->getIn(i);
    if (vn->getOffset().getType() == ConstTpl::handle) {
      handleIndex = vn->getOffset().getHandleIndex();
      hasrealsize = (vn->getSize().getType() == ConstTpl::real);
      realsize = vn->getSize().getReal();
    }
    plus = vn->transfer(params);
    if (plus >= 0) {
      if (!hasrealsize) {
	reportError((const Location *)0, "Problem with bit range operator in macro");
	return false;
      }
      uintb newtemp = slgh->getUniqueAddr(); // Generate a new temporary location

      // Generate a SUBPIECE op that implements the offset_plus
      OpTpl *subpieceop = new OpTpl(CPUI_SUBPIECE);
      VarnodeTpl *newvn = new VarnodeTpl(ConstTpl(slgh->getUniqueSpace()),ConstTpl(ConstTpl::real,newtemp),
					 ConstTpl(ConstTpl::real,realsize));
      subpieceop->setOutput(newvn);
      HandleTpl *hand = params[handleIndex];
      VarnodeTpl *origvn = new VarnodeTpl( hand->getSpace(), hand->getPtrOffset(), hand->getSize() );
      subpieceop->addInput(origvn);
      VarnodeTpl *plusvn = new VarnodeTpl( ConstTpl(slgh->getConstantSpace()), ConstTpl(ConstTpl::real,plus),
					   ConstTpl(ConstTpl::real, 4) );
      subpieceop->addInput(plusvn);
      outvec.push_back(subpieceop);

      delete vn;		// Replace original varnode
      op->setInput(new VarnodeTpl( *newvn ), i); // with output of subpiece
    }
  }
  outvec.push_back(op);
  return true;
}

void MacroBuilder::dump(OpTpl *op)

{
  OpTpl *clone;
  VarnodeTpl *v_clone,*vn;
  
  clone = new OpTpl(op->getOpcode());
  vn = op->getOut();
  if (vn != (VarnodeTpl *)0) {
    v_clone = new VarnodeTpl(*vn);
    clone->setOutput(v_clone);
  }
  for(int4 i=0;i<op->numInput();++i) {
    vn = op->getIn(i);
    v_clone = new VarnodeTpl(*vn);
    if (v_clone->isRelative()) {
      // Adjust relative index, depending on the labelbase
      uintb val = v_clone->getOffset().getReal() + getLabelBase();
      v_clone->setRelative(val);
    }
    clone->addInput(v_clone);
  }
  if (!transferOp(clone,params))
    delete clone;
}

void MacroBuilder::setLabel(OpTpl *op)

{ // A label within a macro is local to the macro, but when
  // we expand the macro, we have to adjust the index of
  // the label, which is local to the macro, so that it fits
  // in with other labels local to the parent
  OpTpl *clone;
  VarnodeTpl *v_clone;

  clone = new OpTpl(op->getOpcode());
  v_clone = new VarnodeTpl( *op->getIn(0) ); // Clone the label index
  // Make adjustment to macro local value so that it is parent local
  uintb val = v_clone->getOffset().getReal() + getLabelBase();
  v_clone->setOffset(val);
  clone->addInput(v_clone);
  outvec.push_back(clone);
}

uintb SleighPcode::allocateTemp(void)

{
  return compiler->getUniqueAddr();
}

const Location *SleighPcode::getLocation(SleighSymbol *sym) const

{
  return compiler->getLocation(sym);
}

void SleighPcode::reportError(const Location *loc, const string &msg)

{
  return compiler->reportError(loc, msg);
}

void SleighPcode::reportWarning(const Location *loc, const string &msg)

{
  return compiler->reportWarning(loc, msg);
}

void SleighPcode::addSymbol(SleighSymbol *sym)

{
  return compiler->addSymbol(sym);
}

SleighCompile::SleighCompile(void)
  : SleighBase()
{
  pcode.setCompiler(this);
  contextlock = false;		// Context layout is not locked
  userop_count = 0;
  errors = 0;
  warnunnecessarypcode = false;
  warndeadtemps = false;
  lenientconflicterrors = true;
  warnalllocalcollisions = false;
  warnallnops = false;
  root = (SubtableSymbol *)0;
}

void SleighCompile::predefinedSymbols(void)

{ // Define the "pre" defined spaces and symbols
  // This must happen after endian has been defined
  symtab.addScope();		// Create global scope

				// Some predefined symbols
  root = new SubtableSymbol("instruction"); // Base constructors
  symtab.addSymbol(root);
  insertSpace(new ConstantSpace(this,this,"const",AddrSpace::constant_space_index));
  SpaceSymbol *spacesym = new SpaceSymbol(getConstantSpace()); // Constant space
  symtab.addSymbol(spacesym);
  OtherSpace *otherSpace = new OtherSpace(this,this,"OTHER",AddrSpace::other_space_index);
  insertSpace(otherSpace);
  spacesym = new SpaceSymbol(otherSpace);
  symtab.addSymbol(spacesym);
  insertSpace(new UniqueSpace(this,this,"unique",numSpaces(),0));
  spacesym = new SpaceSymbol(getUniqueSpace()); // Temporary register space
  symtab.addSymbol(spacesym);
  StartSymbol *startsym = new StartSymbol("inst_start",getConstantSpace());
  symtab.addSymbol(startsym);
  EndSymbol *endsym = new EndSymbol("inst_next",getConstantSpace());
  symtab.addSymbol(endsym);
  EpsilonSymbol *epsilon = new EpsilonSymbol("epsilon",getConstantSpace());
  symtab.addSymbol(epsilon);
  pcode.setConstantSpace(getConstantSpace());
  pcode.setUniqueSpace(getUniqueSpace());
}

int4 SleighCompile::calcContextVarLayout(int4 start,int4 sz,int4 numbits)

{
  VarnodeSymbol *sym = contexttable[start].sym;
  FieldQuality *qual;
  int4 i,j;
  int4 maxbits;
  
  if ((sym->getSize()) % 4 != 0)
    reportError(getCurrentLocation(), "Invalid size of context register '"+sym->getName()+"': must be a multiple of 4 bytes");
  maxbits = sym->getSize() * 8 -1;
  i = 0;
  while(i<sz) {

    qual = contexttable[i].qual;
    int4 min = qual->low;
    int4 max = qual->high;
    if ((max - min) > (8*sizeof(uintm)))
      reportError(getCurrentLocation(), "Size of bitfield '" + qual->name + "' larger than 32 bits");
    if (max > maxbits)
      reportError(getCurrentLocation(), "Scope of bitfield '" + qual->name + "' extends beyond the size of context register");
    j = i+1;
    // Find union of fields overlapping with first field
    while(j<sz) {
      qual = contexttable[j].qual;
      if (qual->low <= max) {	// We have overlap of context variables
	if (qual->high > max)
	  max = qual->high;
	// reportWarning("Local context variables overlap in "+sym->getName(),false);
      }
      else
	break;
      j = j+1;
    }

    int4 alloc = max-min+1;
    int4 startword = numbits / (8*sizeof(uintm));
    int4 endword = (numbits+alloc-1) / (8*sizeof(uintm));
    if (startword != endword)
      numbits = endword * (8*sizeof(uintm)); // Bump up to next word

    uint4 low = numbits;
    numbits += alloc;

    for(;i<j;++i) {
      qual = contexttable[i].qual;
      uint4 l = qual->low - min + low;
      uint4 h = numbits-1-(max-qual->high);
      ContextField *field = new ContextField(qual->signext,l,h);
      addSymbol(new ContextSymbol(qual->name,field,sym,qual->low,qual->high,qual->flow));
    }
    
  }
  sym->markAsContext();
  return numbits;
}

void SleighCompile::buildDecisionTrees(void)

{
  DecisionProperties props;
  root->buildDecisionTree(props);

  for(int4 i=0;i<tables.size();++i)
    tables[i]->buildDecisionTree(props);

  const vector<pair<Constructor*, Constructor*> > &ierrors( props.getIdentErrors() );
  if (ierrors.size() != 0) {
    string identMsg = "Constructor has identical pattern to constructor at ";
    for(int4 i=0;i<ierrors.size();++i) {
      errors += 1;
      const Location* locA = getLocation(ierrors[i].first);
      const Location* locB = getLocation(ierrors[i].second);
      reportError(locA, identMsg + locB->format());
      reportError(locB, identMsg + locA->format());
    }
  }

  const vector<pair<Constructor *, Constructor*> > &cerrors( props.getConflictErrors() );
  if (!lenientconflicterrors && cerrors.size() != 0) {
    string conflictMsg = "Constructor pattern cannot be distinguished from constructor at ";
    for(int4 i=0;i<cerrors.size();++i) {
      errors += 1;
      const Location* locA = getLocation(cerrors[i].first);
      const Location* locB = getLocation(cerrors[i].second);
      reportError(locA, conflictMsg + locB->format());
      reportError(locB, conflictMsg + locA->format());
    }
  }
}

void SleighCompile::buildPatterns(void)

{
  if (root == 0) {
    reportError((const Location *)0, "No patterns to match.");
    return;
  }
  ostringstream msg;
  root->buildPattern(msg);	// This should recursively hit everything
  if (root->isError()) {
    reportError(getLocation(root), msg.str());
    errors += 1;
  }
  for(int4 i=0;i<tables.size();++i) {
    if (tables[i]->isError())
      errors += 1;
    if (tables[i]->getPattern() == (TokenPattern *)0) {
      reportWarning(getLocation(tables[i]), "Unreferenced table '"+tables[i]->getName() + "'");
    }
  }
}

void SleighCompile::checkConsistency(void)

{
  ConsistencyChecker checker(this, root,warnunnecessarypcode,warndeadtemps,largetemporarywarning);

  if (!checker.test()) {
    errors += 1;
    return;
  }
  if (!checker.testTruncations(isBigEndian())) {
    errors += 1;
    return;
  }
  if ((!warnunnecessarypcode)&&(checker.getNumUnnecessaryPcode() > 0)) {
    ostringstream msg;
    msg << dec << checker.getNumUnnecessaryPcode();
    msg << " unnecessary extensions/truncations were converted to copies" << endl;
    msg << "Use -u switch to list each individually";
    reportInfo(msg.str());
  }
  checker.optimizeAll();
  if (checker.getNumReadNoWrite() > 0) {
    errors += 1;
    return;
  }
  if ((!warndeadtemps)&&(checker.getNumWriteNoRead() > 0)) {
    ostringstream msg;
    msg << dec << checker.getNumWriteNoRead();
    msg << " operations wrote to temporaries that were not read" << endl;
    msg << "Use -t switch to list each individually";
    reportInfo(msg.str());
  }
  if ((!largetemporarywarning) && (checker.getNumLargeTemporaries() > 0)) {
	ostringstream msg;
	msg << dec << checker.getNumLargeTemporaries();
	msg << " constructors contain temporaries larger than ";
	msg << SleighBase::MAX_UNIQUE_SIZE << " bytes" << endl;
	msg << "Use -o switch to list each individually.";
	reportInfo(msg.str());
  }
}

int4 SleighCompile::findCollision(map<uintb,int4> &local2Operand,const vector<uintb> &locals,int operand)

{
  for(int4 i=0;i<locals.size();++i) {
    pair<map<uintb,int4>::iterator,bool> res;
    res = local2Operand.insert(pair<uintb,int4>(locals[i],operand));
    if (!res.second) {
      int4 oldIndex = (*res.first).second;
      if (oldIndex != operand)
	return oldIndex;
    }
  }
  return -1;
}

bool SleighCompile::checkLocalExports(Constructor *ct)

{
  if (ct->getTempl() == (ConstructTpl *)0)
    return true;		// No template, collisions impossible
  if (ct->getTempl()->buildOnly())
    return true;		// Operand exports aren't manipulated, so no collision is possible
  if (ct->getNumOperands() < 2)
    return true;		// Collision can only happen with multiple operands
  bool noCollisions = true;
  map<uintb,int4> collect;
  for(int4 i=0;i<ct->getNumOperands();++i) {
    vector<uintb> newCollect;
    ct->getOperand(i)->collectLocalValues(newCollect);
    if (newCollect.empty()) continue;
    int4 collideOperand = findCollision(collect, newCollect, i);
    if (collideOperand >= 0) {
      noCollisions = false;
      if (warnalllocalcollisions) {
	reportWarning(getLocation(ct), "Possible operand collision between symbols '"
		      + ct->getOperand(collideOperand)->getName()
		      + "' and '"
		      + ct->getOperand(i)->getName() + "'");
      }
      break;	// Don't continue
    }
  }
  return noCollisions;
}

void SleighCompile::checkLocalCollisions(void)

{
  int4 collisionCount = 0;
  SubtableSymbol *sym = root; // Start with the instruction table
  int4 i = -1;
  for(;;) {
    int4 numconst = sym->getNumConstructors();
    for(int4 j=0;j<numconst;++j) {
      if (!checkLocalExports(sym->getConstructor(j)))
	collisionCount += 1;
    }
    i+=1;
    if (i>=tables.size()) break;
    sym = tables[i];
  }
  if (collisionCount > 0) {
    ostringstream msg;
    msg << dec << collisionCount << " constructors with local collisions between operands";
    if (!warnalllocalcollisions)
      msg << endl << "Use -c switch to list each individually";
    reportInfo(msg.str());
  }
}

void SleighCompile::checkNops(void)

{
  if (noplist.size() > 0) {
    if (warnallnops) {
      for(int4 i=0;i<noplist.size();++i)
	reportWarning(noplist[i]);
    }
    ostringstream msg;
    msg << dec << noplist.size() << " NOP constructors found";
    if (!warnallnops)
      msg << endl << "Use -n switch to list each individually";
    reportInfo(msg.str());
  }
}

string SleighCompile::checkSymbols(SymbolScope *scope)

{ // Make sure label symbols are used properly
  ostringstream msg;
  SymbolTree::const_iterator iter;
  for(iter=scope->begin();iter!=scope->end();++iter) {
    LabelSymbol *sym = (LabelSymbol *)*iter;
    if (sym->getType() != SleighSymbol::label_symbol) continue;
    if (sym->getRefCount() == 0)
      msg << "   Label <" << sym->getName() << "> was placed but not used" << endl;
    else if (!sym->isPlaced())
      msg << "   Label <" << sym->getName() << "> was referenced but never placed" << endl;
  }
  return msg.str();
}

void SleighCompile::addSymbol(SleighSymbol *sym)

{				// Make sure symbol table errors are caught
  try {
    symtab.addSymbol(sym);
    symbolLocationMap[sym] = *getCurrentLocation();
  }
  catch(SleighError &err) {
    reportError(err.explain);
  }
}

const Location *SleighCompile::getLocation(Constructor *ctor) const

{
  return &ctorLocationMap.at(ctor);
}

const Location *SleighCompile::getLocation(SleighSymbol *sym) const

{
  return &symbolLocationMap.at(sym);
}

const Location *SleighCompile::getCurrentLocation(void) const

{
  // Update the location cache field
  currentLocCache = Location(filename.back(), lineno.back());
  return &currentLocCache;
}

string SleighCompile::formatStatusMessage(const Location* loc, const string &msg)
{
  ostringstream s;
  if (loc != (Location*)0) {
    s << loc->format();
    s << ": ";
  }
  s << msg;
  return s.str();
}

void SleighCompile::reportError(const Location* loc, const string &msg)
{
  reportError(formatStatusMessage(loc, msg));
}

void SleighCompile::reportError(const string &msg)
{
  cerr << "ERROR   " << msg << endl;
  errors += 1;
  if (errors > 1000000) {
    cerr << "Too many errors: Aborting" << endl;
    exit(2);
  }
}

void SleighCompile::reportWarning(const Location* loc, const string &msg)
{
  reportWarning(formatStatusMessage(loc, msg));
}

void SleighCompile::reportWarning(const string &msg)

{
  cerr << "WARNING " << msg << endl;
}

void SleighCompile::reportInfo(const Location* loc, const string &msg)
{
  reportInfo(formatStatusMessage(loc, msg));
}

void SleighCompile::reportInfo(const string &msg)

{
  cerr << "INFO    " << msg << endl;
}

uintb SleighCompile::getUniqueAddr(void)

{
  uintb base = getUniqueBase();
  setUniqueBase(base + SleighBase::MAX_UNIQUE_SIZE);
  return base;
}

void SleighCompile::process(void)

{				// Do all post processing on the parsed data structures
  checkNops();
  if (getDefaultCodeSpace() == (AddrSpace *)0)
    reportError("No default space specified");
  if (errors>0) return;
  checkConsistency();
  if (errors>0) return;
  checkLocalCollisions();
  if (errors>0) return;
  buildPatterns();
  if (errors>0) return;
  buildDecisionTrees();
  if (errors>0) return;
  vector<string> errorPairs;
  buildXrefs(errorPairs);		// Make sure we can build crossrefs properly
  if (!errorPairs.empty()) {
    for(int4 i=0;i<errorPairs.size();i+=2) {
      ostringstream s;
      s << "Duplicate (offset,size) pair for registers: ";
      s << errorPairs[i] << " and " << errorPairs[i+1] << endl;
      reportError(s.str());
    }
    return;
  }
  checkUniqueAllocation();
  symtab.purge();		// Get rid of any symbols we don't plan to save
}

// Methods needed by the lexer

void SleighCompile::calcContextLayout(void)

{
  if (contextlock) return;	// Already locked
  contextlock = true;

  int4 context_offset = 0;
  int4 begin,sz;
  stable_sort(contexttable.begin(),contexttable.end());
  begin = 0;
  while(begin < contexttable.size()) { // Define the context variables
    sz = 1;
    while ((begin+sz < contexttable.size())&&(contexttable[begin+sz].sym==contexttable[begin].sym))
      sz += 1;
    context_offset = calcContextVarLayout(begin,sz,context_offset);
    begin += sz;
  } 

  //  context_size = (context_offset+8*sizeof(uintm)-1)/(8*sizeof(uintm));

  // Delete the quals
  for(int4 i=0;i<contexttable.size();++i) {
    FieldQuality *qual = contexttable[i].qual;
    delete qual;
  }

  contexttable.clear();
}

string SleighCompile::grabCurrentFilePath(void) const

{ // Get the path of the current file being parse as either an absolute path, or relative to cwd
  if (relpath.empty()) return "";
  return (relpath.back() + filename.back());
}

void SleighCompile::parseFromNewFile(const string &fname)

{
  string base,path;
  FileManage::splitPath(fname,path,base);
  filename.push_back(base);
  if (relpath.empty() || FileManage::isAbsolutePath(path))
    relpath.push_back(path);
  else {			// Relative paths from successive includes, combine
    string totalpath = relpath.back();
    totalpath += path;
    relpath.push_back(totalpath);
  }
  lineno.push_back(1);
}

void SleighCompile::parsePreprocMacro(void)

{
  filename.push_back(filename.back()+":macro");
  relpath.push_back(relpath.back());
  lineno.push_back(lineno.back());
}

void SleighCompile::parseFileFinished(void)

{
  filename.pop_back();
  relpath.pop_back();
  lineno.pop_back();
}

bool SleighCompile::getPreprocValue(const string &nm,string &res) const

{
  map<string,string>::const_iterator iter = preproc_defines.find(nm);
  if (iter == preproc_defines.end()) return false;
  res = (*iter).second;
  return true;
}

void SleighCompile::setPreprocValue(const string &nm,const string &value)

{
  preproc_defines[nm] = value;
}

bool SleighCompile::undefinePreprocValue(const string &nm)

{
  map<string,string>::iterator iter = preproc_defines.find(nm);
  if (iter==preproc_defines.end()) return false;
  preproc_defines.erase(iter);
  return true;
}

// Functions needed by the parser

TokenSymbol *SleighCompile::defineToken(string *name,uintb *sz,int4 endian)

{
  uint4 size = *sz;
  delete sz;
  if ((size&7)!=0) {
    reportError(getCurrentLocation(), "'" + *name + "': token size must be multiple of 8");
    size = (size/8)+1;
  }
  else
    size = size/8;
  bool isBig;
  if (endian ==0)
    isBig = isBigEndian();
  else
    isBig = (endian > 0);
  Token *newtoken = new Token(*name,size,isBig,tokentable.size());
  tokentable.push_back(newtoken);
  delete name;
  TokenSymbol *res = new TokenSymbol(newtoken);
  addSymbol(res);
  return res;
}

void SleighCompile::addTokenField(TokenSymbol *sym,FieldQuality *qual)

{
  TokenField *field = new TokenField(sym->getToken(),qual->signext,qual->low,qual->high);
  addSymbol(new ValueSymbol(qual->name,field));
  delete qual;
}

bool SleighCompile::addContextField(VarnodeSymbol *sym,FieldQuality *qual)

{
  if (contextlock)
    return false;		// Context layout has already been satisfied

  contexttable.push_back(FieldContext(sym,qual));
  return true;
}

void SleighCompile::newSpace(SpaceQuality *qual)

{
  if (qual->size == 0) {
    reportError(getCurrentLocation(), "Space definition '" + qual->name  + "' missing size attribute");
    delete qual;
    return;
  }

  int4 delay = (qual->type == SpaceQuality::registertype) ? 0 : 1;
  AddrSpace *spc = new AddrSpace(this,this,IPTR_PROCESSOR,qual->name,qual->size,qual->wordsize,numSpaces(),AddrSpace::hasphysical,delay);
  insertSpace(spc);
  if (qual->isdefault) {
    if (getDefaultCodeSpace() != (AddrSpace *)0)
      reportError(getCurrentLocation(), "Multiple default spaces -- '" + getDefaultCodeSpace()->getName() + "', '" + qual->name + "'");
    else {
      setDefaultCodeSpace(spc->getIndex());	// Make the flagged space the default
      pcode.setDefaultSpace(spc);
    }
  }
  delete qual;
  addSymbol( new SpaceSymbol(spc) );
}

SectionSymbol *SleighCompile::newSectionSymbol(const string &nm)

{
  SectionSymbol *sym = new SectionSymbol(nm,sections.size());
  try {
    symtab.addGlobalSymbol(sym);
  } catch(SleighError &err) {
    reportError(getCurrentLocation(), err.explain);
  }
  sections.push_back(sym);
  numSections = sections.size();
  return sym;
}

void SleighCompile::setEndian(int4 end)

{ // This MUST be called at the very beginning of the parse
  // The parser should enforce this
  setBigEndian( (end == 1) );
  predefinedSymbols();		// Set up symbols now that we know endianess
}

void SleighCompile::defineVarnodes(SpaceSymbol *spacesym,uintb *off,uintb *size,vector<string> *names)

{
  AddrSpace *spc = spacesym->getSpace();
  uintb myoff = *off;
  for(int4 i=0;i<names->size();++i) {
    if ((*names)[i] != "_")
      addSymbol( new VarnodeSymbol((*names)[i],spc,myoff,*size) );
    myoff += *size;
  }
  delete names;
  delete off;
  delete size;
}

void SleighCompile::defineBitrange(string *name,VarnodeSymbol *sym,uint4 bitoffset,uint4 numb)

{ // Define a new symbol as a subrange of bits within another symbol
  // If the ends of the range fall on byte boundaries, we
  // simply define a normal VarnodeSymbol, otherwise we create
  // a special symbol which is a place holder for the bitrange operator
  string namecopy = *name;
  delete name;
  uint4 size = 8*sym->getSize(); // Number of bits
  if (numb == 0) {
    reportError(getCurrentLocation(), "'" + namecopy + "': size of bitrange is zero");
    return;
  }
  if ((bitoffset >= size)||((bitoffset+numb)>size)) {
    reportError(getCurrentLocation(), "'" + namecopy + "': bad bitrange");
    return;
  }
  if ((bitoffset%8 == 0)&&(numb%8 == 0)) {
    // This can be reduced to an ordinary varnode definition
    AddrSpace *newspace = sym->getFixedVarnode().space;
    uintb newoffset = sym->getFixedVarnode().offset;
    int4 newsize = numb/8;
    if (isBigEndian())
      newoffset += (size-bitoffset-numb)/8;
    else
      newoffset += bitoffset/8;
    addSymbol( new VarnodeSymbol(namecopy,newspace,newoffset,newsize) );
  }
  else				// Otherwise define the special symbol
    addSymbol( new BitrangeSymbol(namecopy,sym,bitoffset,numb) );
}

void SleighCompile::addUserOp(vector<string> *names)

{
  for(int4 i=0;i<names->size();++i) {
    UserOpSymbol *sym = new UserOpSymbol((*names)[i]);
    sym->setIndex(userop_count++);
    addSymbol( sym );
  }
  delete names;
}

SleighSymbol *SleighCompile::dedupSymbolList(vector<SleighSymbol *> *symlist)

{				// Find duplicates in -symlist-, null out all but first
  SleighSymbol *res = (SleighSymbol *)0;
  for(int4 i=0;i<symlist->size();++i) {
    SleighSymbol *sym = (*symlist)[i];
    if (sym == (SleighSymbol *)0) continue;
    for(int4 j=i+1;j<symlist->size();++j) {
      if ((*symlist)[j] == sym) { // Found a duplicate
	res = sym;		// Return example duplicate for error reporting
	(*symlist)[j] = (SleighSymbol *)0; // Null out the duplicate
      }
    }
  }
  return res;
}

void SleighCompile::attachValues(vector<SleighSymbol *> *symlist,vector<intb> *numlist)

{
  SleighSymbol *dupsym = dedupSymbolList(symlist);
  if (dupsym != (SleighSymbol *)0)
    reportWarning(getCurrentLocation(), "'attach values' list contains duplicate entries: "+dupsym->getName());
  for(int4 i=0;i<symlist->size();++i) {
    ValueSymbol *sym = (ValueSymbol *)(*symlist)[i];
    if (sym == (ValueSymbol *)0) continue;
    PatternValue *patval = sym->getPatternValue();
    if (patval->maxValue() + 1 != numlist->size()) {
      reportError(getCurrentLocation(), "Attach value '" + sym->getName() + "' is wrong size for list");
    }
    symtab.replaceSymbol(sym, new ValueMapSymbol(sym->getName(),patval,*numlist));
  }
  delete numlist;
  delete symlist;
}

void SleighCompile::attachNames(vector<SleighSymbol *> *symlist,vector<string> *names)

{
  SleighSymbol *dupsym = dedupSymbolList(symlist);
  if (dupsym != (SleighSymbol *)0)
    reportWarning(getCurrentLocation(), "'attach names' list contains duplicate entries: "+dupsym->getName());
  for(int4 i=0;i<symlist->size();++i) {
    ValueSymbol *sym = (ValueSymbol *)(*symlist)[i];
    if (sym == (ValueSymbol *)0) continue;
    PatternValue *patval = sym->getPatternValue();
    if (patval->maxValue() + 1 != names->size()) {
      reportError(getCurrentLocation(), "Attach name '" + sym->getName() + "' is wrong size for list");
    }
    symtab.replaceSymbol(sym,new NameSymbol(sym->getName(),patval,*names));
  }
  delete names;
  delete symlist;
}

void SleighCompile::attachVarnodes(vector<SleighSymbol *> *symlist,vector<SleighSymbol *> *varlist)

{
  SleighSymbol *dupsym = dedupSymbolList(symlist);
  if (dupsym != (SleighSymbol *)0)
    reportWarning(getCurrentLocation(), "'attach variables' list contains duplicate entries: "+dupsym->getName());
  for(int4 i=0;i<symlist->size();++i) {
    ValueSymbol *sym = (ValueSymbol *)(*symlist)[i];
    if (sym == (ValueSymbol *)0) continue;
    PatternValue *patval = sym->getPatternValue();
    if (patval->maxValue() + 1 != varlist->size()) {
      reportError(getCurrentLocation(), "Attach varnode '" + sym->getName() + "' is wrong size for list");
    }
    int4 sz = 0;      
    for(int4 j=0;j<varlist->size();++j) {
      VarnodeSymbol *vsym = (VarnodeSymbol *)(*varlist)[j];
      if (vsym != (VarnodeSymbol *)0) {
	if (sz == 0)
	  sz = vsym->getFixedVarnode().size;
	else if (sz != vsym->getFixedVarnode().size) {
	  ostringstream msg;
	  msg << "Attach statement contains varnodes of different sizes -- "  << dec << sz << " != " << dec << vsym->getFixedVarnode().size;
	  reportError(getCurrentLocation(), msg.str());
	  break;
	}
      }
    }
    symtab.replaceSymbol(sym,new VarnodeListSymbol(sym->getName(),patval,*varlist));
  }
  delete varlist;
  delete symlist;
}

SubtableSymbol *SleighCompile::newTable(string *nm)

{
  SubtableSymbol *sym = new SubtableSymbol(*nm);
  addSymbol(sym);
  tables.push_back(sym);
  delete nm;
  return sym;
}

void SleighCompile::newOperand(Constructor *ct,string *nm)

{
  int4 index = ct->getNumOperands();
  OperandSymbol *sym = new OperandSymbol(*nm,index,ct);
  addSymbol(sym);
  ct->addOperand(sym);
  delete nm;
}

PatternEquation *SleighCompile::constrainOperand(OperandSymbol *sym,PatternExpression *patexp)

{				// Create constraint on operand
  PatternEquation *res;
  FamilySymbol *famsym = dynamic_cast<FamilySymbol *>(sym->getDefiningSymbol());
  if (famsym != (FamilySymbol *)0) { // Operand already defined as family symbol
				// This equation must be a constraint
    res = new EqualEquation(famsym->getPatternValue(),patexp);
  }
  else {			// Operand is currently undefined, so we can't constrain
    PatternExpression::release(patexp);
    res = (PatternEquation *)0;
  }
  return res;
}

void SleighCompile::defineOperand(OperandSymbol *sym,PatternExpression *patexp)

{				// Define operand in terms of PatternExpression
  try {
    sym->defineOperand(patexp);
    sym->setOffsetIrrelevant();	// If not a self-definition, the operand has no
				// pattern directly associated with it, so
				// the operand's offset is irrelevant
  }
  catch(SleighError &err) {
    reportError(getCurrentLocation(), err.explain);
    PatternExpression::release(patexp);
  }
}

PatternEquation *SleighCompile::defineInvisibleOperand(TripleSymbol *sym)

{
  int4 index = curct->getNumOperands();
  OperandSymbol *opsym = new OperandSymbol(sym->getName(),index,curct);
  addSymbol(opsym);
  curct->addInvisibleOperand(opsym);
  PatternEquation *res = new OperandEquation(opsym->getIndex());
  SleighSymbol::symbol_type tp = sym->getType();
  try {
    if ((tp==SleighSymbol::value_symbol)||(tp==SleighSymbol::context_symbol)) {
      opsym->defineOperand(sym->getPatternExpression());
    }
    else {
      opsym->defineOperand(sym);
      //      reportWarning("Defining invisible operand "+sym->getName(),true);
    }
  }
  catch(SleighError &err) {
    reportError(getCurrentLocation(), err.explain);
  }
  return res;
}

void SleighCompile::selfDefine(OperandSymbol *sym)

{				// Define operand as global symbol of same name
  TripleSymbol *glob = dynamic_cast<TripleSymbol *>(symtab.findSymbol(sym->getName(),1));
  if (glob == (TripleSymbol *)0) {
    reportError(getCurrentLocation(), "No matching global symbol '" + sym->getName() + "'");
    return;
  }
  SleighSymbol::symbol_type tp = glob->getType();
  try {
    if ((tp==SleighSymbol::value_symbol)||(tp==SleighSymbol::context_symbol)) {
      sym->defineOperand(glob->getPatternExpression());
    }
    else
      sym->defineOperand(glob);
  }
  catch(SleighError &err) {
    reportError(getCurrentLocation(), err.explain);
  }
}

ConstructTpl *SleighCompile::setResultVarnode(ConstructTpl *ct,VarnodeTpl *vn)

{				// Set constructors handle to indicate given varnode
  HandleTpl *res = new HandleTpl(vn);
  delete vn;
  ct->setResult(res);
  return ct;
}

ConstructTpl *SleighCompile::setResultStarVarnode(ConstructTpl *ct,StarQuality *star,VarnodeTpl *vn)

{				// Set constructors handle to be the value pointed
				// at by -vn-
  HandleTpl *res = new HandleTpl(star->id,ConstTpl(ConstTpl::real,star->size),vn,
				   getUniqueSpace(),getUniqueAddr());
  delete star;
  delete vn;
  ct->setResult(res);
  return ct;
}

bool SleighCompile::contextMod(vector<ContextChange *> *vec,ContextSymbol *sym,PatternExpression *pe)

{ // A temporary change to a context variable (within the parsing of a single instruction)
  // Because we are in the middle of parsing, the "inst_next" value has not been computed yet
  // So we check to make sure the value expression doesn't use this symbol
  vector<const PatternValue *> vallist;
  pe->listValues(vallist);
  for(uint4 i=0;i<vallist.size();++i)
    if (dynamic_cast<const EndInstructionValue *>(vallist[i]) != (const EndInstructionValue *)0)
      return false;
  // Otherwise we generate a "temporary" change to context instruction  (ContextOp)
  ContextField *field = (ContextField *)sym->getPatternValue();
  ContextOp *op = new ContextOp(field->getStartBit(),field->getEndBit(),pe);
  vec->push_back(op);
  return true;
}

void SleighCompile::contextSet(vector<ContextChange *> *vec,TripleSymbol *sym,
				ContextSymbol *cvar)

{ // A permanent (global) change to context.  During parsing of an instruction, this change
  // is put off until the full instruction has been parsed.  The existing value in the context
  // field is set permanently to that value starting at the address given by the address expression
  ContextField *field = (ContextField *)cvar->getPatternValue();
  ContextCommit *op = new ContextCommit(sym,field->getStartBit(),field->getEndBit(),cvar->getFlow());
  vec->push_back(op);
}

MacroSymbol *SleighCompile::createMacro(string *name,vector<string> *params)

{				// create a macro symbol (with parameter names)
  curct = (Constructor *)0;	// Not currently defining a Constructor
  curmacro = new MacroSymbol(*name,macrotable.size());
  delete name;
  addSymbol(curmacro);
  symtab.addScope();		// New scope for the body of the macro definition
  pcode.resetLabelCount();	// Macros have their own labels
  for(int4 i=0;i<params->size();++i) {
    OperandSymbol *oper = new OperandSymbol((*params)[i],i,(Constructor *)0);
    addSymbol(oper);
    curmacro->addOperand(oper);
  }
  delete params;
  return curmacro;
}

void SleighCompile::compareMacroParams(MacroSymbol *sym,const vector<ExprTree *> &param)

{ // Match up any qualities of the macro's OperandSymbols with
  // any OperandSymbol passed into the macro
  for(uint4 i=0;i<param.size();++i) {
    VarnodeTpl *outvn = param[i]->getOut();
    if (outvn == (VarnodeTpl *)0) continue;
    // Check if an OperandSymbol was passed into this macro
    if (outvn->getOffset().getType() != ConstTpl::handle) continue;
    int4 hand = outvn->getOffset().getHandleIndex();

    // The matching operands
    OperandSymbol *macroop = sym->getOperand(i);
    OperandSymbol *parentop;
    if (curct == (Constructor *)0)
      parentop = curmacro->getOperand(hand);
    else
      parentop = curct->getOperand(hand);

    // This is the only property we check right now
    if (macroop->isCodeAddress())
      parentop->setCodeAddress();
  }
}

vector<OpTpl *> *SleighCompile::createMacroUse(MacroSymbol *sym,vector<ExprTree *> *param)

{ // Create macro build directive, given symbol and parameters
  if (sym->getNumOperands() != param->size()) {
    bool tooManyParams = param->size() > sym->getNumOperands();
    string errmsg = "Invocation of macro '" + sym->getName() + "' passes too " + (tooManyParams ? "many" : "few") + " parameters";
    reportError(getCurrentLocation(), errmsg);
    return new vector<OpTpl *>;
  }
  compareMacroParams(sym,*param);
  OpTpl *op = new OpTpl(MACROBUILD);
  VarnodeTpl *idvn = new VarnodeTpl(ConstTpl(getConstantSpace()),
				      ConstTpl(ConstTpl::real,sym->getIndex()),
				      ConstTpl(ConstTpl::real,4));
  op->addInput(idvn);
  return ExprTree::appendParams(op,param);
}

SectionVector *SleighCompile::standaloneSection(ConstructTpl *main)

{ // Create SectionVector for just the main rtl section with no named sections
  SectionVector *res = new SectionVector(main,symtab.getCurrentScope());
  return res;
}

SectionVector *SleighCompile::firstNamedSection(ConstructTpl *main,SectionSymbol *sym)

{ // Start the first named p-code section after the main p-code section
  sym->incrementDefineCount();
  SymbolScope *curscope = symtab.getCurrentScope(); // This should be a Constructor scope
  SymbolScope *parscope = curscope->getParent();
  if (parscope != symtab.getGlobalScope())
    throw LowlevelError("firstNamedSection called when not in Constructor scope"); // Unrecoverable error
  symtab.addScope();		// Add new scope under the Constructor scope
  SectionVector *res = new SectionVector(main,curscope);
  res->setNextIndex(sym->getTemplateId());
  return res;
}

SectionVector *SleighCompile::nextNamedSection(SectionVector *vec,ConstructTpl *section,SectionSymbol *sym)

{ // Add additional named p-code sections
  sym->incrementDefineCount();
  SymbolScope *curscope = symtab.getCurrentScope();
  symtab.popScope();		// Pop the scope of the last named section
  SymbolScope *parscope = symtab.getCurrentScope()->getParent();
  if (parscope != symtab.getGlobalScope())
    throw LowlevelError("nextNamedSection called when not in section scope"); // Unrecoverable
  symtab.addScope();		// Add new scope under the Constructor scope (not the last section scope)
  vec->append(section,curscope); // Associate finished section
  vec->setNextIndex(sym->getTemplateId()); // Set index for the NEXT section (not been fully parsed yet)
  return vec;
}

SectionVector *SleighCompile::finalNamedSection(SectionVector *vec,ConstructTpl *section)

{ // Fill-in final named section to match the previous SectionSymbol
  vec->append(section,symtab.getCurrentScope());
  symtab.popScope();		// Pop the section scope
  return vec;
}

vector<OpTpl *> *SleighCompile::createCrossBuild(VarnodeTpl *addr,SectionSymbol *sym)

{ // Create the crossbuild directive as a pcode template
  unique_allocatemask = 1;
  vector<OpTpl *> *res = new vector<OpTpl *>();
  VarnodeTpl *sectionid = new VarnodeTpl(ConstTpl(getConstantSpace()),
                                         ConstTpl(ConstTpl::real,sym->getTemplateId()),
                                         ConstTpl(ConstTpl::real,4));
  // This is simply a single pcodeop (template), where the opcode indicates the crossbuild directive
  OpTpl *op = new OpTpl( CROSSBUILD );
  op->addInput(addr);		// The first input is the VarnodeTpl representing the address
  op->addInput(sectionid);	// The second input is the indexed representing the named pcode section to build
  res->push_back(op);
  sym->incrementRefCount();	// Keep track of the references to the section symbol
  return res;
}

Constructor *SleighCompile::createConstructor(SubtableSymbol *sym)

{
  if (sym == (SubtableSymbol *)0)
    sym = WithBlock::getCurrentSubtable(withstack);
  if (sym == (SubtableSymbol *)0)
    sym = root;
  curmacro = (MacroSymbol *)0;	// Not currently defining a macro
  curct = new Constructor(sym);
  curct->setLineno(lineno.back());
  ctorLocationMap[curct] = *getCurrentLocation();
  sym->addConstructor(curct);
  symtab.addScope();		// Make a new symbol scope for our constructor
  pcode.resetLabelCount();
  int4 index = indexer.index(ctorLocationMap[curct].getFilename());
  curct->setSrcIndex(index);
  return curct;
}

void SleighCompile::resetConstructors(void)

{				// Reset set state after a an error in previous constructor
  symtab.setCurrentScope(symtab.getGlobalScope()); // Purge any dangling local scopes
}

bool SleighCompile::expandMacros(ConstructTpl *ctpl,const vector<ConstructTpl *> &macrotable)

{
  vector<OpTpl *> newvec;
  vector<OpTpl *>::const_iterator iter;
  OpTpl *op;
  
  for(iter=ctpl->getOpvec().begin();iter!=ctpl->getOpvec().end();++iter) {
    op = *iter;
    if (op->getOpcode() == MACROBUILD) {
      MacroBuilder builder(this,newvec,ctpl->numLabels());
      int4 index = op->getIn(0)->getOffset().getReal();
      if (index >= macrotable.size())
	return false;
      builder.setMacroOp(op);
      ConstructTpl *macro_tpl = macrotable[index];
      builder.build(macro_tpl,-1);
      ctpl->setNumLabels( ctpl->numLabels() + macro_tpl->numLabels() );
      delete op;		// Throw away the place holder op
      if (builder.hasError())
	return false;
    }
    else
      newvec.push_back(op);
  }
  ctpl->setOpvec(newvec);
  return true;
}

bool SleighCompile::finalizeSections(Constructor *big,SectionVector *vec)

{ // Do all final checks, expansions, and linking for p-code sections
  vector<string> errors;

  RtlPair cur = vec->getMainPair();
  int4 i=-1;
  string sectionstring = "   Main section: ";
  int4 max = vec->getMaxId();
  for(;;) {
    string errstring;

    errstring = checkSymbols(cur.scope); // Check labels in the section's scope
    if (errstring.size()!=0) {
      errors.push_back(sectionstring + errstring);
    } else {
      if (!expandMacros(cur.section,macrotable))
	errors.push_back(sectionstring + "Could not expand macros");
      vector<int4> check;
      big->markSubtableOperands(check);
      int4 res = cur.section->fillinBuild(check,getConstantSpace());
      if (res == 1)
	errors.push_back(sectionstring + "Duplicate BUILD statements");
      if (res == 2)
	errors.push_back(sectionstring + "Unnecessary BUILD statements");
  
      if (!PcodeCompile::propagateSize(cur.section))
	errors.push_back(sectionstring + "Could not resolve at least 1 variable size");
    }
    if (i < 0) {		// These potential errors only apply to main section
      if (cur.section->getResult() != (HandleTpl *)0) {	// If there is an export statement
	if (big->getParent()==root)
	  errors.push_back("   Cannot have export statement in root constructor");
	else if (!force_exportsize(cur.section))
	  errors.push_back("   Size of export is unknown");
      }
    }
    if (cur.section->delaySlot() != 0) { // Delay slot is present in this constructor
      if (root != big->getParent()) { // it is not in a root constructor
	ostringstream msg;
	msg << "Delay slot used in non-root constructor ";
	big->printInfo(msg);
	msg << endl;
	reportWarning(getLocation(big), msg.str());
      }
      if (cur.section->delaySlot() > maxdelayslotbytes)	// Keep track of maximum delayslot parameter
	maxdelayslotbytes = cur.section->delaySlot();
    }
    do {
      i += 1;
      if (i >= max) break;
      cur = vec->getNamedPair(i);
    } while(cur.section == (ConstructTpl *)0);
      
    if (i >= max) break;
    SectionSymbol *sym = sections[i];
    sectionstring = "   " + sym->getName() + " section: ";
  }
  if (!errors.empty()) {
    ostringstream s;
    s << "in ";
    big->printInfo(s);
    reportError(getLocation(big), s.str());
    for(int4 j=0;j<errors.size();++j)
      reportError(getLocation(big), errors[j]);
    return false;
  }
  return true;
}

void SleighCompile::shiftUniqueVn(VarnodeTpl *vn,int4 sa)

{ // If the varnode is in the unique space, shift its offset up by -sa- bits
  if (vn->getSpace().isUniqueSpace() && (vn->getOffset().getType() == ConstTpl::real)) {
    uintb val = vn->getOffset().getReal();
    val <<= sa;
    vn->setOffset(val);
  }
}

void SleighCompile::shiftUniqueOp(OpTpl *op,int4 sa)

{ // Shift the offset up by -sa- bits for any varnode used by this -op- in the unique space
  VarnodeTpl *outvn = op->getOut();
  if (outvn != (VarnodeTpl *)0)
    shiftUniqueVn(outvn,sa);
  for(int4 i=0;i<op->numInput();++i)
    shiftUniqueVn(op->getIn(i),sa);
}

void SleighCompile::shiftUniqueHandle(HandleTpl *hand,int4 sa)

{ // Shift the offset up by -sa- bits, for either the dynamic or static varnode aspects that are in the unique space
  if (hand->getSpace().isUniqueSpace() && (hand->getPtrSpace().getType() == ConstTpl::real)
      && (hand->getPtrOffset().getType() == ConstTpl::real)) {
    uintb val = hand->getPtrOffset().getReal();
    val <<= sa;
    hand->setPtrOffset(val);
  }
  else if (hand->getPtrSpace().isUniqueSpace() && (hand->getPtrOffset().getType() == ConstTpl::real)) {
    uintb val = hand->getPtrOffset().getReal();
    val <<= sa;
    hand->setPtrOffset(val);
  }
  
  if (hand->getTempSpace().isUniqueSpace() && (hand->getTempOffset().getType() == ConstTpl::real)) {
    uintb val = hand->getTempOffset().getReal();
    val <<= sa;
    hand->setTempOffset(val);
  }
}

void SleighCompile::shiftUniqueConstruct(ConstructTpl *tpl,int4 sa)

{ // Shift the offset up by -sa- bits, for any varnode in the unique space associated with this template
  HandleTpl *result = tpl->getResult();
  if (result != (HandleTpl *)0)
    shiftUniqueHandle(result,sa);
  const vector<OpTpl *> &vec( tpl->getOpvec() );
  for(int4 i=0;i<vec.size();++i)
    shiftUniqueOp(vec[i],sa);
}

void SleighCompile::checkUniqueAllocation(void)

{ // With crossbuilds,  temporaries may need to survive across instructions in a packet, so here we
  // provide space in the offset of the temporary (within the unique space) so that the run-time sleigh
  // engine can alter the value to prevent collisions with other nearby instructions
  if (unique_allocatemask == 0) return;	// We don't have any crossbuild directives

  unique_allocatemask = 0xff;	// Provide 8 bits of free space
  int4 sa = 8;
  int4 secsize = sections.size(); // This is the upper bound for section numbers
  SubtableSymbol *sym = root; // Start with the instruction table
  int4 i = -1;
  for(;;) {
    int4 numconst = sym->getNumConstructors();
    for(int4 j=0;j<numconst;++j) {
      Constructor *ct = sym->getConstructor(j);
      ConstructTpl *tpl = ct->getTempl();
      if (tpl != (ConstructTpl *)0)
	shiftUniqueConstruct(tpl,sa);
      for(int4 k=0;k<secsize;++k) {
	ConstructTpl *namedtpl = ct->getNamedTempl(k);
	if (namedtpl != (ConstructTpl *)0)
	  shiftUniqueConstruct(namedtpl,sa);
      }
    }
    i+=1;
    if (i>=tables.size()) break;
    sym = tables[i];
  }
  uintm ubase = getUniqueBase(); // We have to adjust the unique base
  ubase <<= sa;
  setUniqueBase(ubase);
}

void SleighCompile::pushWith(SubtableSymbol *ss,PatternEquation *pateq,vector<ContextChange *> *contvec)

{
  withstack.emplace_back();
  withstack.back().set(ss,pateq,contvec);
}

void SleighCompile::popWith(void)

{
  withstack.pop_back();
}

void SleighCompile::buildConstructor(Constructor *big,PatternEquation *pateq,vector<ContextChange *> *contvec,SectionVector *vec)

{ // Take all the different parse pieces for a Constructor and build the Constructor object
  bool noerrors = true;
  if (vec != (SectionVector *)0) { // If the sections were implemented
    noerrors = finalizeSections(big,vec);
    if (noerrors) {		// Attach the sections to the Constructor
      big->setMainSection(vec->getMainSection());
      int4 max = vec->getMaxId();
      for(int4 i=0;i<max;++i) {
	ConstructTpl *section = vec->getNamedSection(i);
	if (section != (ConstructTpl *)0)
	  big->setNamedSection(section,i);
      }
    }
    delete vec;
  }
  if (noerrors) {
    pateq = WithBlock::collectAndPrependPattern(withstack, pateq);
    contvec = WithBlock::collectAndPrependContext(withstack, contvec);
    big->addEquation(pateq);
    big->removeTrailingSpace();
    if (contvec != (vector<ContextChange *> *)0) {
      big->addContext(*contvec);
      delete contvec;
    }
  }
  symtab.popScope();		// In all cases pop scope
}

void SleighCompile::buildMacro(MacroSymbol *sym,ConstructTpl *rtl)

{
  string errstring = checkSymbols(symtab.getCurrentScope());
  if (errstring.size() != 0) {
    reportError(getCurrentLocation(), "In definition of macro '"+sym->getName() + "': " + errstring);
    return;
  }
  if (!expandMacros(rtl,macrotable)) {
    reportError(getCurrentLocation(), "Could not expand submacro in definition of macro '" + sym->getName() + "'");
    return;
  }
  PcodeCompile::propagateSize(rtl); // Propagate size information (as much as possible)
  sym->setConstruct(rtl);
  symtab.popScope();		// Pop local variables used to define macro
  macrotable.push_back(rtl);
}

void SleighCompile::recordNop(void)

{
  string msg = formatStatusMessage(getCurrentLocation(), "NOP detected");

  noplist.push_back(msg);
}

static int4 run_compilation(const char *filein,const char *fileout,SleighCompile &compiler)

{
  compiler.parseFromNewFile(filein);
  slgh = &compiler;		// Set global pointer up for parser
  yyin = fopen(filein,"r");	// Open the file for the lexer
  if (yyin == (FILE *)0) {
    cerr << "Unable to open specfile: " << filein << endl;
    return 2;
  }

  try {
    int4 parseres = yyparse();	// Try to parse
    fclose(yyin);
    if (parseres==0)
      compiler.process();	// Do all the post-processing
    if ((parseres==0)&&(compiler.numErrors()==0)) { // If no errors
      ofstream s(fileout);
      if (!s) {
	ostringstream errs;
	errs << "Unable to open output file: " << fileout;
	throw SleighError(errs.str());
      }
      compiler.saveXml(s);	// Dump output xml
      s.close();
    }
    else {
      cerr << "No output produced" <<endl;
      return 2;
    }
    yylex_destroy();		// Make sure lexer is reset so we can parse multiple files
  } catch(LowlevelError &err) {
    cerr << "Unrecoverable error: " << err.explain << endl;
    return 2;
  }
  return 0;
}

static int4 run_xml(const char *filein,SleighCompile &compiler)

{
  ifstream s(filein);
  Document *doc;
  string specfileout;
  string specfilein;

  try {
    doc = xml_tree(s);
  }
  catch(XmlError &err) {
    cerr << "Unable to parse single input file as XML spec: " << filein << endl;
    exit(1);
  }
  s.close();

  Element *el = doc->getRoot();
  for(;;) {
    const List &list(el->getChildren());
    List::const_iterator iter;
    for(iter=list.begin();iter!=list.end();++iter) {
      el = *iter;
      if (el->getName() == "processorfile") {
	specfileout = el->getContent();
	int4 num = el->getNumAttributes();
	for(int4 i=0;i<num;++i) {
	  if (el->getAttributeName(i)=="slaspec")
	    specfilein = el->getAttributeValue(i);
	  else {
	    compiler.setPreprocValue(el->getAttributeName(i),el->getAttributeValue(i));
	  }
	}
      }
      else if (el->getName() == "language_spec")
	break;
      else if (el->getName() == "language_description")
	break;
    }
    if (iter==list.end()) break;
  }
  delete doc;

  if (specfilein.size() == 0) {
    cerr << "Input slaspec file was not specified in " << filein << endl;
    exit(1);
  }
  if (specfileout.size() == 0) {
    cerr << "Output sla file was not specified in " << filein << endl;
    exit(1);
  }
  return run_compilation(specfilein.c_str(),specfileout.c_str(),compiler);
}

static void findSlaSpecs(vector<string> &res, const string &dir, const string &suffix)

{
  FileManage::matchListDir(res, suffix, true, dir, false);
  
  vector<string> dirs;
  FileManage::directoryList(dirs, dir);
  vector<string>::const_iterator iter;
  for(iter = dirs.begin();iter!=dirs.end();++iter) {
    const string &nextdir( *iter );
    findSlaSpecs(res, nextdir,suffix);
  }
}

static void initCompiler(SleighCompile &compiler, map<string,string> &defines, bool enableUnnecessaryPcodeWarning,
			 bool disableLenientConflict, bool enableAllCollisionWarning,
			 bool enableAllNopWarning,bool enableDeadTempWarning,bool enforceLocalKeyWord, bool largeTemporaryWarning)

{
  map<string,string>::iterator iter = defines.begin();
  for (iter = defines.begin(); iter != defines.end(); iter++) {
    compiler.setPreprocValue((*iter).first, (*iter).second);
  }
  if (enableUnnecessaryPcodeWarning)
    compiler.setUnnecessaryPcodeWarning(true);
  if (disableLenientConflict)
    compiler.setLenientConflict(false);
  if (enableAllCollisionWarning)
    compiler.setLocalCollisionWarning( true );
  if (enableAllNopWarning)
    compiler.setAllNopWarning( true );
  if (enableDeadTempWarning)
    compiler.setDeadTempWarning(true);
  if (enforceLocalKeyWord)
    compiler.setEnforceLocalKeyWord(true);
  if (largeTemporaryWarning)
	  compiler.setLargeTemporaryWarning(true);
}

static void segvHandler(int sig) {
  exit(1);			// Just die - prevents OS from popping-up a dialog
}

int main(int argc,char **argv)

{
  int4 retval = 0;

  signal(SIGSEGV, &segvHandler); // Exit on SEGV errors

#ifdef YYDEBUG
  yydebug = 0;
#endif

  if (argc < 2) {
    cerr << "USAGE: sleigh [-x] [-dNAME=VALUE] inputfile [outputfile]" << endl;
    cerr << "   -a              scan for all slaspec files recursively where inputfile is a directory" << endl;
    cerr << "   -x              turns on parser debugging" << endl;
    cerr << "   -u              print warnings for unnecessary pcode instructions" << endl;
    cerr << "   -l              report pattern conflicts" << endl;
    cerr << "   -n              print warnings for all NOP constructors" << endl;
    cerr << "   -t              print warnings for dead temporaries" << endl;
    cerr << "   -e              enforce use of 'local' keyword for temporaries" << endl;
    cerr << "   -c              print warnings for all constructors with colliding operands" << endl;
    cerr << "   -o              print warnings for temporaries which are too large" << endl;
    cerr << "   -DNAME=VALUE    defines a preprocessor macro NAME with value VALUE" << endl;
    exit(2);
  }

  const string SLAEXT(".sla");	// Default sla extension
  const string SLASPECEXT(".slaspec");
  map<string,string> defines;
  bool enableUnnecessaryPcodeWarning = false;
  bool disableLenientConflict = false;
  bool enableAllCollisionWarning = false;
  bool enableAllNopWarning = false;
  bool enableDeadTempWarning = false;
  bool enforceLocalKeyWord = false;
  bool largeTemporaryWarning = false;
  
  bool compileAll = false;
  
  int4 i;
  for(i=1;i<argc;++i) {
    if (argv[i][0] != '-') break;
    if (argv[i][1] == 'a')
      compileAll = true;
    else if (argv[i][1] == 'D') {
      string preproc(argv[i]+2);
      string::size_type pos = preproc.find('=');
      if (pos == string::npos) {
	cerr << "Bad sleigh option: "<< argv[i] << endl;
	exit(1);
      }
      string name = preproc.substr(0,pos);
      string value = preproc.substr(pos+1);
      defines[name] = value;
    }
    else if (argv[i][1] == 'u')
      enableUnnecessaryPcodeWarning = true;
    else if (argv[i][1] == 'l')
      disableLenientConflict = true;
    else if (argv[i][1] == 'c')
      enableAllCollisionWarning = true;
    else if (argv[i][1] == 'n')
      enableAllNopWarning = true;
    else if (argv[i][1] == 't')
      enableDeadTempWarning = true;
    else if (argv[i][1] == 'e')
      enforceLocalKeyWord = true;
    else if (argv[i][1] == 'o')
    	largeTemporaryWarning = true;
#ifdef YYDEBUG
    else if (argv[i][1] == 'x')
      yydebug = 1;		// Debug option
#endif
    else {
      cerr << "Unknown option: " << argv[i] << endl;
      exit(1);
    }
  }
  
  if (compileAll) {
    
    if (i< argc-1) {
      cerr << "Too many parameters" << endl;
      exit(1);
    }
    const string::size_type slaspecExtLen = SLASPECEXT.length();
    
    vector<string> slaspecs;
    string dirStr = ".";
    if (i != argc)
      dirStr = argv[i];
    findSlaSpecs(slaspecs, dirStr,SLASPECEXT);
    cout << "Compiling " << dec << slaspecs.size() << " slaspec files in " << dirStr << endl;
    for(int4 j=0;j<slaspecs.size();++j) {
      string slaspec = slaspecs[j];
      cout << "Compiling (" << dec << (j+1) << " of " << dec << slaspecs.size() << ") " << slaspec << endl;
      string sla = slaspec;
      sla.replace(slaspec.length() - slaspecExtLen, slaspecExtLen, SLAEXT);
      SleighCompile compiler;
      initCompiler(compiler, defines, enableUnnecessaryPcodeWarning, 
		   disableLenientConflict, enableAllCollisionWarning, enableAllNopWarning,
		   enableDeadTempWarning, enforceLocalKeyWord,largeTemporaryWarning);
      retval = run_compilation(slaspec.c_str(),sla.c_str(),compiler);
      if (retval != 0) {
	return retval; // stop on first error
      }
    }
    
  } else { // compile single specification
    
    if (i==argc) {
      cerr << "Missing input file name" << endl;
      exit(1);
    }
    
    string fileinExamine(argv[i]);

    string::size_type extInPos = fileinExamine.find(SLASPECEXT);
    bool autoExtInSet = false;
    bool extIsSLASPECEXT = false;
    string fileinPreExt = "";
    if (extInPos == string::npos) { //No Extension Given...
      fileinPreExt = fileinExamine;
      fileinExamine.append(SLASPECEXT);
      autoExtInSet = true;
    } else {
      fileinPreExt = fileinExamine.substr(0,extInPos);
      extIsSLASPECEXT = true;
    }
    
    if (i< argc-2) {
      cerr << "Too many parameters" << endl;
      exit(1);
    }
    
    SleighCompile compiler;
    initCompiler(compiler, defines, enableUnnecessaryPcodeWarning, 
		 disableLenientConflict, enableAllCollisionWarning, enableAllNopWarning,
		 enableDeadTempWarning, enforceLocalKeyWord,largeTemporaryWarning);
    
    if (i < argc - 1) {
      string fileoutExamine(argv[i+1]);
      string::size_type extOutPos = fileoutExamine.find(SLAEXT);
      if (extOutPos == string::npos) { // No Extension Given...
	fileoutExamine.append(SLAEXT);
      }
      retval = run_compilation(fileinExamine.c_str(),fileoutExamine.c_str(),compiler);
    }else{
      //First determine whether or not to use Run_XML...
      if (autoExtInSet || extIsSLASPECEXT) { //Assumed format of at least "sleigh file" -> "sleigh file.slaspec file.sla"
	string fileoutSTR = fileinPreExt;
	fileoutSTR.append(SLAEXT);
	retval = run_compilation(fileinExamine.c_str(),fileoutSTR.c_str(),compiler);
      }else{
	retval = run_xml(fileinExamine.c_str(),compiler);
      }
      
    }
  }
  return retval;
}

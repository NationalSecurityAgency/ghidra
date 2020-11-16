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
#include "condexe.hh"

ConditionMarker::ConditionMarker(void)

{
  initop = (PcodeOp *)0;
  basevn = (Varnode *)0;
  boolvn = (Varnode *)0;
  bool2vn = (Varnode *)0;
  bool3vn = (Varnode *)0;
  binaryop = (PcodeOp *)0;
}

/// Any marks on Varnodes in the root expression are cleared
ConditionMarker::~ConditionMarker(void)

{
  basevn->clearMark();
  if (boolvn != (Varnode *)0)
    boolvn->clearMark();
  if (bool2vn != (Varnode *)0)
    bool2vn->clearMark();
  if (bool3vn != (Varnode *)0)
    bool3vn->clearMark();
  if (binaryop != (PcodeOp *)0) {
    binaryop->getIn(0)->clearMark();
    binaryop->getIn(1)->clearMark();
  }
}

/// Starting with the CBRANCH, the key Varnodes in the expression producing
/// the boolean value are marked.  BOOL_NEGATE operations are traversed, but
/// otherwise only one level of operator is walked.
/// \param op is the root CBRANCH operation
void ConditionMarker::setupInitOp(PcodeOp *op)

{
  initop = op;
  basevn = op->getIn(1);
  Varnode *curvn = basevn;
  curvn->setMark();
  if (curvn->isWritten()) {
    PcodeOp *tmp = curvn->getDef();
    if (tmp->code() == CPUI_BOOL_NEGATE) {
      boolvn = tmp->getIn(0);
      curvn = boolvn;
      curvn->setMark();
    }
  }
  if (curvn->isWritten()) {
    PcodeOp *tmp = curvn->getDef();
    if (tmp->isBoolOutput()&&(tmp->getEvalType()==PcodeOp::binary)) {
      binaryop = tmp;
      Varnode *binvn = binaryop->getIn(0);
      if (!binvn->isConstant()) {
	if (binvn->isWritten()) {
	  PcodeOp *negop = binvn->getDef();
	  if (negop->code() == CPUI_BOOL_NEGATE) {
	    if (!negop->getIn(0)->isConstant()) {
	      bool2vn = negop->getIn(0);
	      bool2vn->setMark();
	    }
	  }
	}
	binvn->setMark();
      }
      binvn = binaryop->getIn(1);
      if (!binvn->isConstant()) {
	if (binvn->isWritten()) {
	  PcodeOp *negop = binvn->getDef();
	  if (negop->code() == CPUI_BOOL_NEGATE) {
	    if (!negop->getIn(0)->isConstant()) {
	      bool3vn = negop->getIn(0);
	      bool3vn->setMark();
	    }
	  }
	}
	binvn->setMark();
      }
    }
  }
}

/// Walk the tree rooted at the given p-code op, looking for things marked in
/// the tree rooted at \b initop.  Trim everything but BOOL_NEGATE operations,
/// one MULTIEQUAL, and one binary boolean operation.  If there is a Varnode
/// in common with the root expression, this is returned, and the tree traversal
/// state holds the path from the boolean value to the common Varnode.
/// \param op is the given CBRANCH op to compare
/// \return the Varnode in common with the root expression or NULL
Varnode *ConditionMarker::findMatch(PcodeOp *op)

{
  PcodeOp *curop;
  //  FlowBlock *bl = op->getParent();
  state = 0;
  Varnode *curvn = op->getIn(1);
  multion = false;
  binon = false;

  matchflip = op->isBooleanFlip();
  
  for(;;) {
    if (curvn->isMark()) return curvn;
    bool popstate = true;
    if (curvn->isWritten()) {
      curop = curvn->getDef();
      if (curop->code() == CPUI_BOOL_NEGATE) {
	curvn = curop->getIn(0);
	if (!binon)		// Only flip if we haven't seen binop yet, as binops get compared directly
	  matchflip = !matchflip;
	popstate = false;
      }
//       else if (curop->code() == CPUI_MULTIEQUAL) {
// 	if ((curop->getParent()==bl)&&(!multion)) {
// 	  opstate[state] = curop;
// 	  slotstate[state] = 0;
// 	  flipstate[state] = matchflip;
// 	  state += 1;
// 	  curvn = curop->Input(0);
// 	  multion = true;
// 	  popstate = false;
// 	}
//       }
      else if (curop->isBoolOutput()&&(curop->getEvalType()==PcodeOp::binary)) {
	if (!binon) {
	  opstate[state] = curop;
	  slotstate[state] = 0;
	  flipstate[state] = matchflip;
	  state += 1;
	  curvn = curop->getIn(0);
	  binon = true;
	  popstate = false;
	}
      }
    }
    if (popstate) {
      while(state > 0) {
	curop = opstate[state-1];
	matchflip = flipstate[state-1];
	slotstate[state-1] += 1;
	if (slotstate[state-1] < curop->numInput()) {
	  curvn = curop->getIn(slotstate[state-1]);
	  break;
	}
	state -= 1;
	if (opstate[state]->code() == CPUI_MULTIEQUAL)
	  multion = false;
	else
	  binon = false;
      }
      if (state==0) break;
    }
  }
  return (Varnode *)0;
}

/// \brief Do the given Varnodes hold the same value, possibly as constants
///
/// \param a is the first Varnode to compare
/// \param b is the second Varnode
/// \return \b true if the Varnodes (always) hold the same value
bool ConditionMarker::varnodeSame(Varnode *a,Varnode *b)

{
  if (a == b) return true;
  if (a->isConstant() && b->isConstant())
    return (a->getOffset() == b->getOffset());
  return false;
}

/// \brief Do the given boolean Varnodes always hold complementary values
///
/// Test if they are constants, 1 and 0, or if one is the direct BOOL_NEGATE of the other.
/// \param a is the first Varnode to compare
/// \param b is the second Varnode to compare
/// \return \b true if the Varnodes (always) hold complementary values
bool ConditionMarker::varnodeComplement(Varnode *a,Varnode *b)

{
  if (a->isConstant() && b->isConstant()) {
    uintb vala = a->getOffset();
    uintb valb = b->getOffset();
    if ((vala==0)&&(valb==1)) return true;
    if ((vala==1)&&(valb==0)) return true;
    return false;
  }
  PcodeOp *negop;
  if (a->isWritten()) {
    negop = a->getDef();
    if (negop->code() == CPUI_BOOL_NEGATE)
      if (negop->getIn(0) == b)
	return true;
  }
  if (b->isWritten()) {
    negop = b->getDef();
    if (negop->code() == CPUI_BOOL_NEGATE)
      if (negop->getIn(0) == a)
	return true;
  }
  return false;
}

/// \brief Test if two operations with same opcode produce complementary boolean values
///
/// This only tests for cases where the opcode is INT_LESS or INT_SLESS and one of the
/// inputs is constant.
/// \param bin1op is the first p-code op to compare
/// \param bin2op is the second p-code op to compare
/// \return \b true if the two operations always produce complementary values
bool ConditionMarker::sameOpComplement(PcodeOp *bin1op,PcodeOp *bin2op)

{
  OpCode opcode = bin1op->code();
  if ((opcode == CPUI_INT_SLESS)||(opcode==CPUI_INT_LESS)) {
    // Basically we test for the scenario like:  x < 9   8 < x
    int4 constslot = 0;
    if (bin1op->getIn(1)->isConstant())
      constslot = 1;
    if (!bin1op->getIn(constslot)->isConstant()) return false;
    if (!bin2op->getIn(1-constslot)->isConstant()) return false;
    if (!varnodeSame(bin1op->getIn(1-constslot),bin2op->getIn(constslot))) return false;
    uintb val1 = bin1op->getIn(constslot)->getOffset();
    uintb val2 = bin2op->getIn(1-constslot)->getOffset();
    if (constslot!=0) {
      uintb tmp = val2;
      val2 = val1;
      val1 = tmp;
    }
    if (val1 + 1 != val2) return false;
    if ((val2 == 0)&&(opcode==CPUI_INT_LESS)) return false; // Corner case for unsigned
    if (opcode==CPUI_INT_SLESS) { // Corner case for signed
      int4 sz = bin1op->getIn(constslot)->getSize();
      if (signbit_negative(val2,sz) && (!signbit_negative(val1,sz)))
	return false;
    }
    return true;
  }
  return false;
}

/// \brief Check if given p-code ops are complements where one is an BOOL_AND and the other is an BOOL_OR
///
/// \param bin1op is the first PcodeOp
/// \param bin2op is the second
/// \return \b true if the p-code ops produce complementary values
bool ConditionMarker::andOrComplement(PcodeOp *bin1op,PcodeOp *bin2op)

{
  if (bin1op->code() == CPUI_BOOL_AND) {
    if (bin2op->code() != CPUI_BOOL_OR) return false;
  }
  else if (bin1op->code() == CPUI_BOOL_OR) {
    if (bin2op->code() != CPUI_BOOL_AND) return false;
  }
  else
    return false;

  // Reaching here, one is AND and one is OR
  if (varnodeComplement( bin1op->getIn(0), bin2op->getIn(0))) {
    if (varnodeComplement( bin1op->getIn(1), bin2op->getIn(1)))
      return true;
  }
  else if (varnodeComplement( bin1op->getIn(0), bin2op->getIn(1))) {
    if (varnodeComplement( bin1op->getIn(1), bin2op->getIn(0)))
      return true;
  }
  return false;
}

/// \brief Determine if the two boolean expressions always produce the same or complementary values
///
/// A common Varnode in the two expressions is given.  If the boolean expressions are
/// uncorrelated, \b false is returned, otherwise \b true is returned.  If the expressions
/// are correlated but always hold opposite values, the field \b matchflip is set to \b true.
/// \param vn is the common Varnode
/// \return \b true if the expressions are correlated
bool ConditionMarker::finalJudgement(Varnode *vn)

{
  if (initop->isBooleanFlip())
    matchflip = !matchflip;
  if ((vn == basevn)&&(!binon))	// No binary operation involved
    return true;
  if (boolvn != (Varnode *)0)
    matchflip = !matchflip;
  if ((vn == boolvn)&&(!binon)) // Negations involved
    return true;
  if ((binaryop == (PcodeOp *)0)||(!binon))
    return false;		// Conditions don't match

  // Both conditions used binary op
  PcodeOp *binary2op = (PcodeOp *)0;
  for(int4 i=0;i<state;++i) {	// Find the binary op
    binary2op = opstate[i];
    if (binary2op->isBoolOutput()) break;
  }
  // Check if the binary ops are exactly the same
  if (binaryop->code() == binary2op->code()) {
    if (varnodeSame(binaryop->getIn(0),binary2op->getIn(0)) &&
	varnodeSame(binaryop->getIn(1),binary2op->getIn(1)))
      return true;
    if (sameOpComplement(binaryop,binary2op)) {
      matchflip = !matchflip;
      return true;
    }
    return false;
  }
  // If not, check if the binary ops are complements of one another
  matchflip = !matchflip;
  if (andOrComplement(binaryop,binary2op))
    return true;
  int4 slot1 = 0;
  int4 slot2 = 0;
  bool reorder;
  if (binaryop->code() != get_booleanflip(binary2op->code(),reorder))
    return false;
  if (reorder) slot2 = 1;
  if (!varnodeSame(binaryop->getIn(slot1),binary2op->getIn(slot2)))
    return false;
  if (!varnodeSame(binaryop->getIn(1-slot1),binary2op->getIn(1-slot2)))
    return false;
  return true;
}

bool ConditionMarker::verifyCondition(PcodeOp *op,PcodeOp *initop)

{
  setupInitOp(initop);
  Varnode *matchvn = findMatch(op);
  if (matchvn == (Varnode *)0) return false;
  if (!finalJudgement(matchvn)) return false;

  // Make final determination of what MULTIEQUAL slot is used
  if (!multion)
    multislot = -1;
  else {
    for(int4 i=0;i<state;++i)
      if (opstate[i]->code()==CPUI_MULTIEQUAL) {
	multislot = slotstate[i];
	break;
      }
  }
  return true;
}

/// \brief Calculate boolean array of all address spaces that have had a heritage pass run.
///
/// Used to test if all the links out of the iblock have been calculated.
void ConditionalExecution::buildHeritageArray(void)

{
  heritageyes.clear();
  Architecture *glb = fd->getArch();
  heritageyes.resize(glb->numSpaces(),false);
  for(int4 i=0;i<glb->numSpaces();++i) {
    AddrSpace *spc = glb->getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    int4 index = spc->getIndex();
    if (!spc->isHeritaged()) continue;
    if (fd->numHeritagePasses(spc) > 0)
      heritageyes[index] = true;	// At least one pass has been performed on the space
  }
}

/// \brief Test the most basic requirements on \b iblock
///
/// The block must have 2 \b in edges and 2 \b out edges and a final CBRANCH op.
/// \return \b true if \b iblock matches basic requirements
bool ConditionalExecution::testIBlock(void)

{
  if (iblock->sizeIn() != 2) return false;
  if (iblock->sizeOut() != 2) return false;
  cbranch = iblock->lastOp();
  if (cbranch == (PcodeOp *)0) return false;
  if (cbranch->code() != CPUI_CBRANCH) return false;
  return true;
}

/// \return \b true if configuration between \b initblock and \b iblock is correct
bool ConditionalExecution::findInitPre(void)

{
  FlowBlock *tmp = iblock->getIn(prea_inslot);
  FlowBlock *last = iblock;
  while((tmp->sizeOut()==1)&&(tmp->sizeIn()==1)) {
    last = tmp;
    tmp = tmp->getIn(0);
  }
  if (tmp->sizeOut() != 2) return false;
  initblock = (BlockBasic *)tmp;
  tmp = iblock->getIn(1-prea_inslot);
  while((tmp->sizeOut()==1)&&(tmp->sizeIn()==1))
    tmp = tmp->getIn(0);
  if (tmp != initblock) return false;
  if (initblock == iblock) return false;

  init2a_true =  (initblock->getTrueOut() == last);

  return true;
}

/// The conditions must always have the same value or always have
/// complementary values.
/// \return \b true if the conditions are correlated
bool ConditionalExecution::verifySameCondition(void)

{
  PcodeOp *init_cbranch = initblock->lastOp();
  if (init_cbranch == (PcodeOp *)0) return false;
  if (init_cbranch->code() != CPUI_CBRANCH) return false;

  ConditionMarker tester;
  if (!tester.verifyCondition(cbranch,init_cbranch))
    return false;

  if (tester.getFlip())
    init2a_true = !init2a_true;
  int4 multislot = tester.getMultiSlot();
  if (multislot != -1) {
    // This is a direct split
    directsplit = true;
    posta_outslot = (multislot == prea_inslot) ? 0 : 1;
    if (init2a_true)
      posta_outslot = 1 - posta_outslot;
  }
  return true;
}

/// The given Varnode is defined by a MULTIEQUAL in \b iblock which must be removed.
/// Test if this is possible/advisable given a specific p-code op that reads the Varnode
/// \param vn is the given Varnode
/// \param op is the given PcodeOp reading the Varnode
/// \return \b false if it is not possible to move the defining op (because of the given op)
bool ConditionalExecution::testMultiRead(Varnode *vn,PcodeOp *op)

{
  if (op->getParent() == iblock) {
    if (!directsplit) {
      if (op->code() == CPUI_COPY) // The COPY is tested separately
	return true;		// If the COPY's output reads can be altered, then -vn- can be altered
      return false;
    }
  }
  if (op->code() == CPUI_RETURN) {
    if ((op->numInput() < 2)||(op->getIn(1) != vn)) return false; // Only test for flow thru to return value
    returnop.push_back(op);	// mark that CPUI_RETURN needs special handling
  }
  return true;
}

/// The given Varnode is defined by an operation in \b iblock which must be removed.
/// Test if this is possible/advisable given a specific p-code op that reads the Varnode
/// \param vn is the given Varnode
/// \param op is the given PcodeOp reading the Varnode
/// \return \b false if it is not possible to move the defining op (because of the given op)
bool ConditionalExecution::testOpRead(Varnode *vn,PcodeOp *op)

{
  if (op->getParent() == iblock) return true;
  if ((op->code() == CPUI_RETURN)&&(!directsplit)) {
    if ((op->numInput() < 2)||(op->getIn(1) != vn)) return false; // Only test for flow thru to return value
    PcodeOp *copyop = vn->getDef();
    if (copyop->code() == CPUI_COPY) {
      // Ordinarily, if -vn- is produced by a COPY we want to return false here because the propagation
      // hasn't had time to happen here.  But if the flow is into a RETURN this can't propagate, so
      // we allow this as a read that can be altered.  (We have to move the COPY)
      Varnode *invn = copyop->getIn(0);
      if (!invn->isWritten()) return false;
      PcodeOp *upop = invn->getDef();
      if ((upop->getParent() == iblock)&&(upop->code() != CPUI_MULTIEQUAL))
	return false;
      returnop.push_back(op);
      return true;
    }
  }
  return false;
}

/// \brief Prebuild a replacement MULTIEQUAL for output Varnode of the given PcodeOp in \b posta_block
///
/// The new op will hold the same data-flow as the original Varnode once a new
/// edge into \b posta_block is created.
/// \param op is the given PcodeOp
void ConditionalExecution::predefineDirectMulti(PcodeOp *op)

{
  PcodeOp *newop = fd->newOp(posta_block->sizeIn()+1,posta_block->getStart());
  Varnode *outvn = op->getOut();
  Varnode *newoutvn;
  newoutvn = fd->newVarnodeOut(outvn->getSize(),outvn->getAddr(),newop);
  fd->opSetOpcode(newop,CPUI_MULTIEQUAL);
  Varnode *vn;
  int4 inslot = iblock->getOutRevIndex(posta_outslot);
  for(int4 i=0;i<posta_block->sizeIn();++i) {
    if (i==inslot)
      vn = op->getIn(1-camethruposta_slot);
    else
      vn = newoutvn;
    fd->opSetInput(newop,vn,i);
  }
  fd->opSetInput(newop,op->getIn(camethruposta_slot),posta_block->sizeIn());
  fd->opInsertBegin(newop,posta_block);

  // Cache this new data flow holder
  replacement[posta_block->getIndex()] = newoutvn;
}

/// In the \e direct \e split case, MULTIEQUALs in the body block (\b posta_block)
/// must update their flow to account for \b iblock being removed and a new
/// block flowing into the body block.
void ConditionalExecution::adjustDirectMulti(void)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  iter = posta_block->beginOp();
  int4 inslot = iblock->getOutRevIndex(posta_outslot);
  while(iter != posta_block->endOp()) {
    op = *iter++;
    if (op->code() != CPUI_MULTIEQUAL) continue;
    Varnode *vn = op->getIn(inslot);
    if (vn->isWritten()&&(vn->getDef()->getParent() == iblock)) {
      if (vn->getDef()->code() != CPUI_MULTIEQUAL)
	throw LowlevelError("Cannot push non-trivial operation");
      // Flow that stays in iblock, comes from modified side
      fd->opSetInput(op,vn->getDef()->getIn(1-camethruposta_slot),inslot);
      // Flow from unmodified side, forms new branch
      vn = vn->getDef()->getIn(camethruposta_slot);
    }
    fd->opInsertInput(op,vn,op->numInput());
  }
}

/// \brief Create a MULTIEQUAL in the given block that will hold data-flow from the given PcodeOp
///
/// A new MULTIEQUAL is created whose inputs are the output of the given PcodeOp
/// \param op is the PcodeOp whose output will get held
/// \param bl is the block that will contain the new MULTIEQUAL
/// \return the output Varnode of the new MULTIEQUAL
Varnode *ConditionalExecution::getNewMulti(PcodeOp *op,BlockBasic *bl)

{
  PcodeOp *newop = fd->newOp(bl->sizeIn(),bl->getStart());
  Varnode *outvn = op->getOut();
  Varnode *newoutvn;
  // Using the original outvn address may cause merge conflicts
  //  newoutvn = fd->newVarnodeOut(outvn->getSize(),outvn->getAddr(),newop);
  newoutvn = fd->newUniqueOut(outvn->getSize(),newop);
  fd->opSetOpcode(newop,CPUI_MULTIEQUAL);

  // We create NEW references to outvn, these refs will get put
  // at the end of the dependency list and will get handled in
  // due course
  for(int4 i=0;i<bl->sizeIn();++i)
    fd->opSetInput(newop,outvn,i);

  fd->opInsertBegin(newop,bl);
  return newoutvn;
}

/// \brief Find a replacement Varnode for the output of the given PcodeOp that is read in the given block
///
/// The replacement Varnode must be valid for everything below (dominated) by the block.
/// If we can't find a replacement, create one (as a MULTIEQUAL) in the given
/// block (creating recursion through input blocks).  Any new Varnode created is
/// cached in the \b replacement array so it can get picked up by other calls to this function
/// for different blocks.
/// \param op is the given PcodeOp whose output we must replace
/// \param bl is the given basic block (containing a read of the Varnode)
/// \return the replacement Varnode
Varnode *ConditionalExecution::getReplacementRead(PcodeOp *op,BlockBasic *bl)

{
  map<int4,Varnode *>::const_iterator iter;
  iter = replacement.find(bl->getIndex());
  if (iter != replacement.end())
    return (*iter).second;
  BlockBasic *curbl = bl;
  // Flow must eventually come through iblock
  while(curbl->getImmedDom() != iblock) {
    curbl = (BlockBasic *)curbl->getImmedDom(); // Get immediate dominator
    if (curbl == (FlowBlock *)0)
      throw LowlevelError("Conditional execution: Could not find dominator");
  }
  iter = replacement.find(curbl->getIndex());
  if (iter != replacement.end()) {
    replacement[bl->getIndex()] = (*iter).second;
    return (*iter).second;
  }
  Varnode *res;
  if (curbl->sizeIn()==1) {
    // Since dominator is iblock, In(0) must be iblock
    // Figure what side of -iblock- we came through
    int4 slot = (curbl->getInRevIndex(0) == posta_outslot) ? camethruposta_slot : 1-camethruposta_slot;
    res = op->getIn(slot);
  }
  else
    res = getNewMulti(op,curbl);
  replacement[curbl->getIndex()] = res;
  if (curbl != bl)
    replacement[bl->getIndex()] = res;
  return res;
}

/// The data-flow for the given op is reproduced in the new control-flow configuration.
/// After completion of this method, the op can be removed.
/// \param op is the given PcodeOp
void ConditionalExecution::doReplacement(PcodeOp *op)

{
  if (op->code() == CPUI_COPY) {
    if (op->getOut()->hasNoDescend()) // Verify that this has been dealt with by fixReturnOp
      return;
    // It could be a COPY internal to iblock, we need to remove it like any other op
  }
  replacement.clear();
  if (directsplit)
    predefineDirectMulti(op);
  Varnode *vn = op->getOut();
  list<PcodeOp *>::const_iterator iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    PcodeOp *readop = *iter;
    int4 slot = readop->getSlot(vn);
    BlockBasic *bl = readop->getParent();
    Varnode *rvn;
    if (bl == iblock) {
      if (directsplit)
	fd->opSetInput(readop,op->getIn(1-camethruposta_slot),slot);	// We know op is MULTIEQUAL
      else
	fd->opUnsetInput(readop,slot);
    }
    else {
      if (readop->code() == CPUI_MULTIEQUAL) {
	BlockBasic *inbl = (BlockBasic *)bl->getIn(slot);
	if (inbl == iblock) {
	  int4 s = (bl->getInRevIndex(slot) == posta_outslot) ? camethruposta_slot : 1-camethruposta_slot;
	  rvn = op->getIn(s);
	}
	else
	  rvn = getReplacementRead(op,inbl);
      }
      else
	rvn = getReplacementRead(op,bl);
      fd->opSetInput(readop,rvn,slot);
    }
    // The last descendant is now gone
    iter = vn->beginDescend();
  }
}

/// \brief Reproduce COPY data-flow into RETURN ops affected by the removal of \b iblock
void ConditionalExecution::fixReturnOp(void)

{
  for(int4 i=0;i<returnop.size();++i) {
    PcodeOp *retop = returnop[i];
    Varnode *retvn = retop->getIn(1);
    PcodeOp *iblockop = retvn->getDef();
    Varnode *invn;
    if (iblockop->code() == CPUI_COPY)
      invn = iblockop->getIn(0); // This must either be from MULTIEQUAL or something written outside of iblock
    else
      invn = retvn;
    PcodeOp *newcopyop = fd->newOp(1,retop->getAddr());
    fd->opSetOpcode(newcopyop,CPUI_COPY);
    Varnode *outvn = fd->newVarnodeOut(retvn->getSize(),retvn->getAddr(),newcopyop); // Preserve the CPUI_RETURN storage address
    fd->opSetInput(newcopyop,invn,0);
    fd->opSetInput(retop,outvn,1);
    fd->opInsertBefore(newcopyop,retop);
  }
}

/// \param op is the PcodeOp within \b iblock to test
/// \return \b true if it is removable
bool ConditionalExecution::testRemovability(PcodeOp *op)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *readop;
  Varnode *vn;

  if (op->code() == CPUI_MULTIEQUAL) {
    vn = op->getOut();
    for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      readop = *iter;
      if (!testMultiRead(vn,readop))
	return false;
    }
  }
  else {
    if (op->isFlowBreak() || op->isCall()) return false;
    if ((op->code()==CPUI_LOAD)||(op->code()==CPUI_STORE))
      return false;
    if (op->code()==CPUI_INDIRECT) return false;

    vn = op->getOut();
    if (vn != (Varnode *)0) {
      bool hasnodescend = true;
      for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
	readop = *iter;
	if (!testOpRead(vn,readop))
	  return false;
	hasnodescend = false;
      }
      if (hasnodescend && (!heritageyes[vn->getSpace()->getIndex()]))	// Check if heritage is performed for this varnode's space
	return false;
    }
  }
  return true;
}

/// The \b iblock has been fixed. Test all control-flow conditions, and test removability
/// of all ops in the \b iblock.
/// \return \b true if the configuration can be modified
bool ConditionalExecution::verify(void)

{
  prea_inslot = 0;
  posta_outslot = 0;
  directsplit = false;

  if (!testIBlock()) return false;
  if (!findInitPre()) return false;
  if (!verifySameCondition()) return false;

  // Cache some useful values
  iblock2posta_true = (posta_outslot == 1);
  camethruposta_slot = (init2a_true==iblock2posta_true) ? prea_inslot : 1-prea_inslot;
  posta_block = (BlockBasic *)iblock->getOut(posta_outslot);
  postb_block = (BlockBasic *)iblock->getOut(1-posta_outslot);

  returnop.clear();
  list<PcodeOp *>::const_iterator iter;
  iter = iblock->endOp();
  if (iter != iblock->beginOp())
    --iter;			// Skip branch
  while(iter != iblock->beginOp()) {
    --iter;
    if (!testRemovability( *iter ))
      return false;
  }
  return true;
}

/// Set up for testing ConditionalExecution on multiple iblocks
/// \param f is the function to do testing on
ConditionalExecution::ConditionalExecution(Funcdata *f)

{
  fd = f;
  buildHeritageArray();	// Cache an array depending on the particular heritage pass
}

/// The given block is tested as a possible \b iblock. If this configuration
/// works and is not a \b directsplit, \b true is returned.
/// If the configuration works as a \b directsplit, then recursively check that
/// its \b posta_block works as an \b iblock. If it does work, keep this
/// \b iblock, otherwise revert to the \b directsplit configuration. In either
/// case return \b true.  Processing the \b directsplit first may prevent
/// posta_block from being an \b iblock.
/// \param ib is the trial \b iblock
/// \return \b true if (some) configuration is recognized and can be modified
bool ConditionalExecution::trial(BlockBasic *ib)

{
  iblock = ib;
  if (!verify()) return false;

  PcodeOp *cbranch_copy;
  BlockBasic *initblock_copy;
  BlockBasic *iblock_copy;
  int4 prea_inslot_copy;
  bool init2a_true_copy;
  bool iblock2posta_true_copy;
  int4 camethruposta_slot_copy;
  int4 posta_outslot_copy;
  BlockBasic *posta_block_copy;
  BlockBasic *postb_block_copy;
  bool directsplit_copy;

  for(;;) {
    if (!directsplit) return true;
    // Save off the data for current iblock
    cbranch_copy = cbranch;
    initblock_copy = initblock;
    iblock_copy = iblock;
    prea_inslot_copy = prea_inslot;
    init2a_true_copy = init2a_true;
    iblock2posta_true_copy = iblock2posta_true;
    camethruposta_slot_copy = camethruposta_slot;
    posta_outslot_copy = posta_outslot;
    posta_block_copy = posta_block;
    postb_block_copy = postb_block;
    directsplit_copy = directsplit;

    iblock = posta_block;
    if (!verify()) {
      cbranch = cbranch_copy;
      initblock = initblock_copy;
      iblock = iblock_copy;
      prea_inslot = prea_inslot_copy;
      init2a_true = init2a_true_copy;
      iblock2posta_true = iblock2posta_true_copy;
      camethruposta_slot = camethruposta_slot_copy;
      posta_outslot = posta_outslot_copy;
      posta_block = posta_block_copy;
      postb_block = postb_block_copy;
      directsplit = directsplit_copy;
      return true;
    }
  }
}

/// We assume the last call to verify() returned \b true
void ConditionalExecution::execute(void)

{
  list<PcodeOp *>::iterator iter;
  PcodeOp *op;

  fixReturnOp();		// Patch any data-flow thru to CPUI_RETURN
  if (!directsplit) {
    iter = iblock->beginOp();
    while(iter != iblock->endOp()) {
      op = *iter++;
      if (!op->isBranch())
	doReplacement(op);	// Remove all read refs of op
      fd->opDestroy(op);	// Then destroy op
    }
    fd->removeFromFlowSplit(iblock,(posta_outslot != camethruposta_slot));
  }
  else {
    adjustDirectMulti();
    iter = iblock->beginOp();
    while(iter != iblock->endOp()) {
      op = *iter++;
      if (op->code() == CPUI_MULTIEQUAL) { // Only adjust MULTIEQUALs
	doReplacement(op);
	fd->opDestroy(op);
      }
      // Branch stays, other operations stay
    }
    fd->switchEdge(iblock->getIn(camethruposta_slot),iblock,posta_block);
  }
}

int4 ActionConditionalExe::apply(Funcdata &data)

{
  bool changethisround;
  int4 numhits = 0;
  int4 i;

  if (data.hasUnreachableBlocks()) // Conditional execution elimination logic may not work with unreachable blocks
    return 0;
  ConditionalExecution condexe(&data);
  const BlockGraph &bblocks( data.getBasicBlocks() );

  do {
    changethisround = false;
    for(i=0;i<bblocks.getSize();++i) {
      BlockBasic *bb = (BlockBasic *)bblocks.getBlock(i);
      if (condexe.trial(bb)) {
	condexe.execute();	// Adjust dataflow
	numhits += 1;
	changethisround = true;
      }
    }
  } while(changethisround);
  count += numhits;		// Number of changes
  return 0;
}

/// \brief  Check if \b vn is produced by a 2-branch MULTIEQUAL, one side of which is a zero constant
///
/// \param vn is the given Varnode
/// \return \b true if the expression producing \b vn matches the form
bool RuleOrPredicate::MultiPredicate::discoverZeroSlot(Varnode *vn)

{
  if (!vn->isWritten()) return false;
  op = vn->getDef();
  if (op->code() != CPUI_MULTIEQUAL) return false;
  if (op->numInput() != 2) return false;
  for(zeroSlot=0;zeroSlot<2;++zeroSlot) {
    Varnode *tmpvn = op->getIn(zeroSlot);
    if (!tmpvn->isWritten()) continue;
    PcodeOp *copyop = tmpvn->getDef();
    if (copyop->code() != CPUI_COPY) continue;		// Multiequal must have CPUI_COPY input
    Varnode *zerovn = copyop->getIn(0);
    if (!zerovn->isConstant()) continue;
    if (zerovn->getOffset() != 0) continue;		// which copies #0
    otherVn = op->getIn(1-zeroSlot);			// store off varnode from other path
    if (otherVn->isFree()) return false;
    return true;
  }
  return false;
}

/// \brief Find CBRANCH operation that determines whether zero is set or not
///
/// Assuming that \b op is a 2-branch MULTIEQUAL as per discoverZeroSlot(),
/// try to find a single CBRANCH whose two \b out edges correspond to the
/// \b in edges of the MULTIEQUAL. In this case, the boolean expression
/// controlling the CBRANCH is also controlling whether zero flows into
/// the MULTIEQUAL output Varnode.
/// \return \b true if a single controlling CBRANCH is found
bool RuleOrPredicate::MultiPredicate::discoverCbranch(void)

{
  const FlowBlock *baseBlock = op->getParent();
  zeroBlock = baseBlock->getIn(zeroSlot);
  const FlowBlock *otherBlock = baseBlock->getIn(1-zeroSlot);
  if (zeroBlock->sizeOut() == 1) {
    if (zeroBlock->sizeIn() != 1) return false;
    condBlock = zeroBlock->getIn(0);
  }
  else if (zeroBlock->sizeOut() == 2)
    condBlock = zeroBlock;
  else
    return false;
  if (condBlock->sizeOut() != 2) return false;
  if (otherBlock->sizeOut() == 1) {
    if (otherBlock->sizeIn() != 1) return false;
    if (condBlock != otherBlock->getIn(0)) return false;
  }
  else if (otherBlock->sizeOut() == 2) {
    if (condBlock != otherBlock) return false;
  }
  else
    return false;
  cbranch = condBlock->lastOp();
  if (cbranch == (PcodeOp *)0) return false;
  if (cbranch->code() != CPUI_CBRANCH) return false;
  return true;
}

/// \brief Does the \b condBlock \b true outgoing edge flow to the block that sets zero
///
/// The \b zeroPathIsTrue variable is set based on the current configuration
void RuleOrPredicate::MultiPredicate::discoverPathIsTrue(void)

{
  if (condBlock->getTrueOut() == zeroBlock)
    zeroPathIsTrue = true;
  else if (condBlock->getFalseOut() == zeroBlock)
    zeroPathIsTrue = false;
  else {	// condBlock must be zeroBlock
    zeroPathIsTrue = (condBlock->getTrueOut() == op->getParent());	// True if "true" path does not override zero set
  }
}

/// \brief Verify that CBRANCH boolean expression is either (\b vn == 0) or (\b vn != 0)
///
/// Modify \b zeroPathIsTrue so that if it is \b true, then: A \b vn value equal to zero,
/// causes execution to flow to where the output of MULTIEQUAL is set to zero.
/// \param vn is the given Varnode
/// \return \b true if the boolean expression has a matching form
bool RuleOrPredicate::MultiPredicate::discoverConditionalZero(Varnode *vn)

{
  Varnode *boolvn = cbranch->getIn(1);
  if (!boolvn->isWritten()) return false;
  PcodeOp *compareop = boolvn->getDef();
  OpCode opc = compareop->code();
  if (opc == CPUI_INT_NOTEQUAL)			// Verify that CBRANCH depends on INT_NOTEQUAL
    zeroPathIsTrue = !zeroPathIsTrue;
  else if (opc != CPUI_INT_EQUAL)		// or INT_EQUAL
    return false;
  Varnode *a1 = compareop->getIn(0);
  Varnode *a2 = compareop->getIn(1);
  Varnode *zerovn;
  if (a1 == vn)			// Verify one side of compare is vn
    zerovn = a2;
  else if (a2 == vn)
    zerovn = a1;
  else
    return false;
  if (!zerovn->isConstant()) return false;
  if (zerovn->getOffset() != 0) return false;	// Verify we are comparing to zero
  if (cbranch->isBooleanFlip())
    zeroPathIsTrue = !zeroPathIsTrue;
  return true;
}

void RuleOrPredicate::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
  oplist.push_back(CPUI_INT_XOR);
}

/// \brief Check for the \e alternate form, tmp1 = (val2 == 0) ? val1 : 0;
///
/// We know we have the basic form
/// \code
///     tmp1 = cond ?  val1 : 0;
///     result = tmp1 | other;
/// \endcode
/// So we just need to check that \b other plays the role of \b val2.
/// If we match the \e alternate form, perform the simplification
/// \param vn is the candidate \b other Varnode
/// \param branch holds the basic form
/// \param op is the INT_OR p-code op
/// \param data is the function being analyzed
/// \return 1 if the form was matched and simplified, 0 otherwise
int4 RuleOrPredicate::checkSingle(Varnode *vn,MultiPredicate &branch,PcodeOp *op,Funcdata &data)

{
  if (vn->isFree()) return 0;
  if (!branch.discoverCbranch()) return 0;
  if (branch.op->getOut()->loneDescend() != op) return 0;	// Must only be one use of MULTIEQUAL, because we rewrite it
  branch.discoverPathIsTrue();
  if (!branch.discoverConditionalZero(vn)) return 0;
  if (branch.zeroPathIsTrue) return 0;		// true condition (vn == 0) must not go to zero set
  data.opSetInput(branch.op,vn,branch.zeroSlot);
  data.opRemoveInput(op,1);
  data.opSetOpcode(op,CPUI_COPY);
  data.opSetInput(op,branch.op->getOut(),0);
  return 1;
}

int4 RuleOrPredicate::applyOp(PcodeOp *op,Funcdata &data)

{
  MultiPredicate branch0;
  MultiPredicate branch1;
  bool test0 = branch0.discoverZeroSlot(op->getIn(0));
  bool test1 = branch1.discoverZeroSlot(op->getIn(1));
  if ((test0==false) && (test1==false)) return 0;
  if (!test0)		// branch1 has MULTIEQUAL form, but branch0 does not
    return checkSingle(op->getIn(0),branch1,op,data);
  else if (!test1)	// branch0 has MULTIEQUAL form, but branch1 does not
    return checkSingle(op->getIn(1),branch0,op,data);
  if (!branch0.discoverCbranch()) return 0;
  if (!branch1.discoverCbranch()) return 0;
  if (branch0.condBlock == branch1.condBlock) {
    if (branch0.zeroBlock == branch1.zeroBlock) return 0;	// zero sets must be along different paths
  }
  else {  // Make sure cbranches have shared condition and the different zero sets have complementary paths
    ConditionMarker condmarker;
    if (!condmarker.verifyCondition(branch0.cbranch,branch1.cbranch)) return 0;
    if (condmarker.getMultiSlot() != -1) return 0;
    branch0.discoverPathIsTrue();
    branch1.discoverPathIsTrue();
    bool finalBool = branch0.zeroPathIsTrue == branch1.zeroPathIsTrue;
    if (condmarker.getFlip())
      finalBool = !finalBool;
    if (finalBool) return 0;		// One path hits both zero sets, they must be on different paths
  }
  int4 order = branch0.op->compareOrder(branch1.op);
  if (order == 0) return 0;		// can this happen?
  BlockBasic *finalBlock;
  bool slot0SetsBranch0;		// True if non-zero setting of branch0 flows throw slot0
  if (order < 0) {			// branch1 happens after
    finalBlock = branch1.op->getParent();
    slot0SetsBranch0 = branch1.zeroSlot == 0;
  }
  else {				// branch0 happens after
    finalBlock = branch0.op->getParent();
    slot0SetsBranch0 = branch0.zeroSlot == 1;
  }
  PcodeOp *newMulti = data.newOp(2,finalBlock->getStart());
  data.opSetOpcode(newMulti,CPUI_MULTIEQUAL);
  if (slot0SetsBranch0) {
    data.opSetInput(newMulti,branch0.otherVn,0);
    data.opSetInput(newMulti,branch1.otherVn,1);
  }
  else {
    data.opSetInput(newMulti,branch1.otherVn,0);
    data.opSetInput(newMulti,branch0.otherVn,1);
  }
  Varnode *newvn = data.newUniqueOut(branch0.otherVn->getSize(),newMulti);
  data.opInsertBegin(newMulti,finalBlock);
  data.opRemoveInput(op,1);
  data.opSetInput(op,newvn,0);
  data.opSetOpcode(op,CPUI_COPY);
  return 1;
}

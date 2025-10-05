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

namespace ghidra {

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

  BooleanExpressionMatch tester;
  if (!tester.verifyCondition(cbranch,init_cbranch))
    return false;

  if (tester.getFlip())
    init2a_true = !init2a_true;
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
    if (op->code() == CPUI_COPY || op->code() == CPUI_SUBPIECE) // The copy-like tested separately
      return true;		// If the COPY's output reads can be altered, then -vn- can be altered
    return false;
  }
  if (op->code() == CPUI_RETURN) {
    if ((op->numInput() < 2)||(op->getIn(1) != vn)) return false; // Only test for flow thru to return value
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
  PcodeOp *writeOp = vn->getDef();
  OpCode opc = writeOp->code();
  if (opc == CPUI_COPY || opc == CPUI_SUBPIECE || opc == CPUI_INT_ADD || opc == CPUI_PTRSUB) {
    if (opc == CPUI_INT_ADD || opc == CPUI_PTRSUB) {
      if (!writeOp->getIn(1)->isConstant())
	return false;
    }
    Varnode *invn = writeOp->getIn(0);
    if (invn->isWritten()) {
      PcodeOp *upop = invn->getDef();
      if ((upop->getParent() == iblock)&&(upop->code() != CPUI_MULTIEQUAL))
	return false;
    }
    else if (invn->isFree())
      return false;
    return true;
  }
  return false;
}

/// \param inbranch is the iblock incoming branch to pullback through
/// \return the output of the previous pullback op, or null
Varnode *ConditionalExecution::findPullback(int4 inbranch)

{
  while(pullback.size() <= inbranch)
    pullback.push_back((Varnode *)0);
  return pullback[inbranch];
}

/// Create a duplicate PcodeOp outside the iblock. The first input to the PcodeOp can
/// be defined by a MULTIEQUAL in the iblock, in which case the duplicate's input will be
/// selected from the MULTIEQUAL input.  Any other inputs must be constants.
/// \param op is the PcodeOp in the iblock being replaced
/// \param inbranch is the direction to pullback from
/// \return the output Varnode of the new op
Varnode *ConditionalExecution::pullbackOp(PcodeOp *op,int4 inbranch)

{
  Varnode *invn = findPullback(inbranch);	// Look for pullback constructed for a previous read
  if (invn != (Varnode *)0)
    return invn;
  invn = op->getIn(0);
  BlockBasic *bl;
  if (invn->isWritten()) {
    PcodeOp *defOp = invn->getDef();
    if (defOp->getParent() == iblock) {
      bl = (BlockBasic *)iblock->getIn(inbranch);
      invn = defOp->getIn(inbranch);		// defOp must by MULTIEQUAL
    }
    else
      bl = (BlockBasic *)iblock->getImmedDom();
  }
  else {
    bl = (BlockBasic *)iblock->getImmedDom();
  }
  PcodeOp *newOp = fd->newOp(op->numInput(),op->getAddr());
  Varnode *origOutVn = op->getOut();
  Varnode *outVn = fd->newVarnodeOut(origOutVn->getSize(),origOutVn->getAddr(),newOp);
  fd->opSetOpcode(newOp,op->code());
  fd->opSetInput(newOp,invn,0);
  for(int4 i=1;i<op->numInput();++i)
    fd->opSetInput(newOp,op->getIn(i),i);
  fd->opInsertEnd(newOp, bl);
  pullback[inbranch] = outVn;		// Cache pullback in case there are other reads
  return outVn;
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

/// Given an op in the \b iblock and the basic block of another op that reads the output Varnode,
/// calculate the replacement Varnode for the read.
/// \param op is the given op in the \b iblock
/// \param bl is the basic block of the read
/// \return the replacement Varnode
Varnode *ConditionalExecution::resolveRead(PcodeOp *op,BlockBasic *bl)

{
  Varnode *res;
  if (bl->sizeIn()==1) {
    // Since dominator is iblock, In(0) must be iblock
    // Figure what side of -iblock- we came through
    int4 slot = (bl->getInRevIndex(0) == posta_outslot) ? camethruposta_slot : 1-camethruposta_slot;
    res = resolveIblockRead(op,slot);
  }
  else
    res = getNewMulti(op,bl);
  return res;
}

/// \param op is the \b iblock op whose output is being read
/// \param inbranch is the known direction of the reading op
/// \return the replacement Varnode to use for the read
Varnode *ConditionalExecution::resolveIblockRead(PcodeOp *op,int4 inbranch)

{
  if (op->code() == CPUI_COPY) {
    Varnode *vn = op->getIn(0);
    if (vn->isWritten()) {
      PcodeOp *defOp = vn->getDef();
      if (defOp->code() == CPUI_MULTIEQUAL && defOp->getParent() == iblock)
	op = defOp;
    }
    else
      return vn;
  }
  OpCode opc = op->code();
  if (opc == CPUI_MULTIEQUAL)
   return op->getIn(inbranch);
  else if (opc == CPUI_SUBPIECE || opc == CPUI_INT_ADD || opc == CPUI_PTRSUB) {
    return pullbackOp(op, inbranch);
  }
  throw LowlevelError("Conditional execution: Illegal op in iblock");
}

/// \brief Get the replacement Varnode for the output of a MULTIEQUAL in the \b iblock, given the op reading it
///
/// \param op is the MULTIEQUAL from \b iblock
/// \param readop is the PcodeOp reading the output Varnode
/// \param slot is the input slot being read
/// \return the Varnode to use as a replacement
Varnode *ConditionalExecution::getMultiequalRead(PcodeOp *op,PcodeOp *readop,int4 slot)

{
  BlockBasic *bl = readop->getParent();
  BlockBasic *inbl = (BlockBasic *)bl->getIn(slot);
  if (inbl != iblock)
    return getReplacementRead(op, inbl);
  int4 s = (bl->getInRevIndex(slot) == posta_outslot) ? camethruposta_slot : 1-camethruposta_slot;
  return resolveIblockRead(op,s);
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
  Varnode *res = resolveRead(op,curbl);
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
  replacement.clear();
  pullback.clear();
  Varnode *vn = op->getOut();
  list<PcodeOp *>::const_iterator iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    PcodeOp *readop = *iter;
    int4 slot = readop->getSlot(vn);
    BlockBasic *bl = readop->getParent();
    Varnode *rvn;
    if (bl == iblock) {
      fd->opUnsetInput(readop,slot);
    }
    else {
      if (readop->code() == CPUI_MULTIEQUAL) {
	rvn = getMultiequalRead(op, readop, slot);
      }
      else if (readop->code() == CPUI_RETURN) {		// Cannot replace input of RETURN directly, create COPY to hold input
	Varnode *retvn = readop->getIn(1);
	PcodeOp *newcopyop = fd->newOp(1,readop->getAddr());
	fd->opSetOpcode(newcopyop,CPUI_COPY);
	Varnode *outvn = fd->newVarnodeOut(retvn->getSize(),retvn->getAddr(),newcopyop); // Preserve the CPUI_RETURN storage address
	fd->opSetInput(readop,outvn,1);
	fd->opInsertBefore(newcopyop,readop);
	readop = newcopyop;
	slot = 0;
	rvn = getReplacementRead(op,bl);
      }
      else
	rvn = getReplacementRead(op,bl);
      fd->opSetInput(readop,rvn,slot);
    }
    // The last descendant is now gone
    iter = vn->beginDescend();
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
    if (vn->isAddrTied()) return false;
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

  if (!testIBlock()) return false;
  if (!findInitPre()) return false;
  if (!verifySameCondition()) return false;

  // Cache some useful values
  iblock2posta_true = (posta_outslot == 1);
  camethruposta_slot = (init2a_true==iblock2posta_true) ? prea_inslot : 1-prea_inslot;
  posta_block = (BlockBasic *)iblock->getOut(posta_outslot);
  postb_block = (BlockBasic *)iblock->getOut(1-posta_outslot);

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
  return true;
}

/// We assume the last call to verify() returned \b true
void ConditionalExecution::execute(void)

{
  list<PcodeOp *>::iterator iter;
  PcodeOp *op;
  bool notdone;

  iter = iblock->endOp();		// Remove ops in reverse order
  --iter;
  do {
    op = *iter;
    notdone = iter != iblock->beginOp();
    if (notdone)
      --iter;
    if (!op->isBranch())
      doReplacement(op);	// Remove all read refs of op
    fd->opDestroy(op);	// Then destroy op
  } while(notdone);
  fd->removeFromFlowSplit(iblock,(posta_outslot != camethruposta_slot));
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
    BooleanExpressionMatch condmarker;
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

} // End namespace ghidra

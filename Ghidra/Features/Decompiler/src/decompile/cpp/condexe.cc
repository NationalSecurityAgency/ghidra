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
/// Used to test if all the links out of the \b c2block have been calculated.
void ConditionalExecution::buildHeritageArray(void)

{
  heritageyes.clear();

  Architecture *glb = fd.getArch();
  heritageyes.resize(glb->numSpaces(),false);

  for(int4 i=0;i<glb->numSpaces();++i) {
    AddrSpace *spc = glb->getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    if (!spc->isHeritaged()) continue;
    if (fd.numHeritagePasses(spc) > 0)
      heritageyes[spc->getIndex()] = true;
  }
}

/// \brief Test the most basic requirements for a conditional block
///
/// The block must have 2 \b out edges and a final CBRANCH op.
/// \return \b true if the condition block matches basic requirements
bool ConditionalExecution::isCondBlock(FlowBlock *fb)

{
  if (fb->sizeOut() != 2) return false;

  PcodeOp *op = fb->lastOp();
  if (op == (PcodeOp *)0) return false;
  return op->code() == CPUI_CBRANCH;
}

// \brief Test the most basic requirements on \b c2block
///
/// The block must have at least 2 \b in edges, 2 \b out edges and a final CBRANCH op.
/// \return \b true if \b c2block matches basic requirements
bool ConditionalExecution::isCond2(void)

{
  if (c2block->sizeIn() < 2) return false;

  return isCondBlock(c2block);
}

/// \return \b true if \b c1block is exists and matches basic requirements
bool ConditionalExecution::findCond1(void)

{
  int4 in = c2block->sizeIn();
  vector<FlowBlock *> fb(in);
  for(int4 i=0;i<in;++i)
    fb[i] = c2block->getIn(i);

  c1block = (BlockBasic *)FlowBlock::findCommonBlock(fb);
  if (c1block == (BlockBasic *)0) return false;
  if (c1block == c2block) return false;

  return isCondBlock(c1block);
}

/// The conditions must always have the same value or always have
/// complementary values.
/// \return \b true if the conditions are correlated
bool ConditionalExecution::isSameCondition(void)

{
  BooleanExpressionMatch tester;
  bool same = tester.verifyCondition(c2block->lastOp(),c1block->lastOp());

  flip = tester.getFlip();

  return same;
}

/// \param op is the PcodeOp within \b c2block to test
/// \return \b true if it the PcodeOp can be duplicated
bool ConditionalExecution::canDuplicate(PcodeOp *op)

{
  Varnode *ovn = op->getOut();
  if (ovn != (Varnode *)0) {
    //if (ovn->isAddrTied()) return false;
    if (ovn->hasNoDescend() && (!heritageyes[ovn->getSpace()->getIndex()]))
      return false;
  }

  return CloneOp::canClone(op);
}

/// Set up for testing ConditionalExecution on multiple c2blocks
/// \param f is the function to do testing on
ConditionalExecution::ConditionalExecution(Funcdata &f) : fd(f)

{
  buildHeritageArray();
}

/// The given block is tested as a possible \b c2block.
/// \return \b true if flow can be modified
bool ConditionalExecution::trial(BlockBasic *bb)

{
  c2block = bb;

  if (!isCond2()) return false;
  if (!findCond1()) return false;
  if (!isSameCondition()) return false;

  const list<PcodeOp *>::const_iterator end = --c2block->endOp();
  for(list<PcodeOp *>::const_iterator iter=c2block->beginOp();iter!=end;++iter) {
    if (!canDuplicate(*iter))
      return false;
  }
  return true;
}

/// We assume the last call to verify() returned \b true
void ConditionalExecution::execute(void)

{
  // Get the flow's out index of c1block for the first flow into c2block to
  // determine how to split
  vector<int4> inset;
  int4 in = c2block->sizeIn();
  for(int4 i=0;i<in;++i) {
    const FlowBlock *fb = c2block->getIn(i);
    if (fb == c1block) {
      fb = c2block;
    } else {
      while (fb->getImmedDom() != c1block) {
        fb = fb->getImmedDom();
      }
    }

    int4 out = c1block->getOutIndex(fb);
    if (out == -1) {
      throw new LowlevelError("Dominator failed");
    }
    // Add false paths to set
    if (out == 0) {
      inset.emplace_back(i);
    }
  }

  // Remove the final branch before splitting
  fd.opDestroy(c2block->lastOp());
  BlockBasic *newbb = fd.nodeSplit(c2block,inset,flip);
  vector<pair<PcodeOp *,PcodeOp *>> ops = CloneOp::cloneBlock(c2block, newbb);

  // Rework control-flow
  InputOpCorrector icorr(fd,inset,in);
  BlockSplitOutputOpCorrector ocorr(fd,c2block,newbb);
  for(vector<pair<PcodeOp *,PcodeOp *>>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
    icorr.correct(iter->first,iter->second);
    ocorr.correct(iter->first,iter->second);
  }
}

int4 ActionConditionalExe::apply(Funcdata &data)

{
  // Conditional execution elimination logic may not work with unreachable blocks
  if (data.hasUnreachableBlocks())
    return 0;

  ConditionalExecution condexe(data);

  while (true) {
    const BlockGraph &bblocks(data.getBasicBlocks());
    int4 prev_count = count;

    for(int4 i=0;i<bblocks.getSize();++i) {
      BlockBasic *bb = (BlockBasic *)bblocks.getBlock(i);
      if (condexe.trial(bb)) {
        condexe.execute();
        count += 1;
      }
    }

    if (prev_count == count) break;
  }

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

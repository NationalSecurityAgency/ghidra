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
#include "funcdata.hh"
#include "flow.hh"

// Funcdata members pertaining directly to blocks

/// A description of each block in the current structure hierarchy is
/// printed to stream.  This is suitable for a console mode or debug view
/// of the state of control-flow structuring at any point during analysis.
/// \param s is the output stream
void Funcdata::printBlockTree(ostream &s) const

{
  if (sblocks.getSize() != 0)
    sblocks.printTree(s,0);
}

void Funcdata::clearBlocks(void)

{
  bblocks.clear();
  sblocks.clear();
}

/// Any override information is preserved.
void Funcdata::clearJumpTables(void)

{
  vector<JumpTable *> remain;
  vector<JumpTable *>::iterator iter;

  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter) {
    JumpTable *jt = *iter;
    if (jt->isOverride()) {
      jt->clear();		// Clear out any derived data
      remain.push_back(jt);	// Keep the override itself
    }
    else
      delete jt;
  }

  jumpvec = remain;
}

/// The JumpTable object is freed, and the associated BRANCHIND is no longer marked
/// as a \e switch point.
/// \param jt is the given JumpTable object
void Funcdata::removeJumpTable(JumpTable *jt)

{
  vector<JumpTable *> remain;
  vector<JumpTable *>::iterator iter;
  
  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter)
    if ((*iter) != jt)
      remain.push_back(*iter);
  PcodeOp *op = jt->getIndirectOp();
  delete jt;
  if (op != (PcodeOp *)0)
    op->getParent()->clearFlag(FlowBlock::f_switch_out);
  jumpvec = remain;
}

/// Assuming the given basic block is being removed, force any Varnode defined by
/// a MULTIEQUAL in the block to be defined in the output block instead. This is used
/// as part of the basic block removal process to patch up data-flow.
/// \param bb is the given basic block
void Funcdata::pushMultiequals(BlockBasic *bb)

{
  BlockBasic *outblock;
  PcodeOp *origop,*replaceop;
  Varnode *origvn,*replacevn;
  list<PcodeOp *>::iterator iter;
  list<PcodeOp *>::const_iterator citer;

  if (bb->sizeOut()==0) return;
  if (bb->sizeOut()>1)
    warningHeader("push_multiequal on block with multiple outputs");
  outblock = (BlockBasic *) bb->getOut(0); // Take first output block. If this is a
				// donothing block, it is the only output block
  int4 outblock_ind = bb->getOutRevIndex(0);
  for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
    origop = *iter;
    if (origop->code() != CPUI_MULTIEQUAL) continue;
    origvn = origop->getOut();
    if (origvn->hasNoDescend()) continue;
    bool needreplace = false;
    bool neednewunique = false;
    for(citer=origvn->beginDescend();citer!=origvn->endDescend();++citer) {
      PcodeOp *op = *citer;
      if ((op->code()==CPUI_MULTIEQUAL)&&(op->getParent()==outblock)) {
	bool deadEdge = true;	// Check for reference to origvn NOT thru the dead edge
	for(int4 i=0;i<op->numInput();++i) {
	  if (i == outblock_ind) continue;	// Not going thru dead edge
	  if (op->getIn(i) == origvn) {		// Reference to origvn
	    deadEdge = false;
	    break;
	  }
	}
	if (deadEdge) {
	  if ((origvn->getAddr() == op->getOut()->getAddr())&&origvn->isAddrTied())
	  // If origvn is addrtied and feeds into a MULTIEQUAL at same address in outblock
	  // Then any use of origvn beyond outblock that did not go thru this MULTIEQUAL must have
	  // propagated through some other register.  So we make the new MULTIEQUAL write to a unique register
	    neednewunique = true;
	  continue;
	}
      }
      needreplace = true;
      break;
    }
    if (!needreplace) continue;
				// Construct artificial MULTIEQUAL
    vector<Varnode *> branches;
    if (neednewunique)
      replacevn = newUnique(origvn->getSize());
    else
      replacevn = newVarnode(origvn->getSize(),origvn->getAddr());
    for(int4 i=0;i<outblock->sizeIn();++i) {
      if (outblock->getIn(i) == bb)
	branches.push_back(origvn);
      else
	branches.push_back( replacevn );

      // In this situation there are other blocks "beyond" outblock which read
      // origvn defined in bb, but there are other blocks falling into outblock
      // Assuming the only out of bb is outblock, all heritages of origvn must
      // come through outblock.  Thus any alternate ins to outblock must be
      // dominated by bb.  So the artificial MULTIEQUAL we construct must have
      // all inputs be origvn
    }
    replaceop = newOp(branches.size(),outblock->getStart());
    opSetOpcode(replaceop,CPUI_MULTIEQUAL);
    opSetOutput(replaceop,replacevn);
    opSetAllInput(replaceop,branches);
    opInsertBegin(replaceop,outblock);

    // Replace obsolete origvn with replacevn
    int4 i;
    list<PcodeOp *>::iterator titer = origvn->descend.begin();
    while(titer != origvn->descend.end()) {
      PcodeOp *op = *titer++;
      i = op->getSlot(origvn);
      // Do not replace MULTIEQUAL references in the same block
      // as replaceop.  These are patched by block_remove
      if ((op->code()==CPUI_MULTIEQUAL)&&(op->getParent()==outblock)&&(i==outblock_ind))
	continue;
      opSetInput(op,replacevn,i);
    }
  }
}

/// If the MULTIEQUAL has no inputs, presumably the basic block is unreachable, so we treat
/// the p-code op as a COPY from a new input Varnode. If there is 1 input, the MULTIEQUAL
/// is transformed directly into a COPY.
/// \param op is the given MULTIEQUAL
void Funcdata::opZeroMulti(PcodeOp *op)

{
  if (op->numInput()==0) {	// If no branches left
    opInsertInput(op,newVarnode(op->getOut()->getSize(),op->getOut()->getAddr()),0);
    setInputVarnode(op->getIn(0));	// Then this is an input
    opSetOpcode(op,CPUI_COPY);
  }
  else if (op->numInput()==1)
    opSetOpcode(op,CPUI_COPY);
}

/// \brief Remove an outgoing branch of the given basic block
///
/// MULTIEQUAL p-code ops (in other blocks) that take inputs from the outgoing branch
/// are patched appropriately.
/// \param bb is the given basic block
/// \param num is the index of the outgoing edge to remove
void Funcdata::branchRemoveInternal(BlockBasic *bb,int4 num)

{
  BlockBasic *bbout;
  list<PcodeOp *>::iterator iter;
  PcodeOp *op;
  int4 blocknum;
  
  if (bb->sizeOut() == 2)	// If there is no decision left
    opDestroy(bb->lastOp());	// Remove the branch instruction

  bbout = (BlockBasic *) bb->getOut(num);
  blocknum = bbout->getInIndex(bb);
  bblocks.removeEdge(bb,bbout); // Sever (one) connection between bb and bbout
  for(iter=bbout->beginOp();iter!=bbout->endOp();++iter) {
    op = *iter;
    if (op->code() != CPUI_MULTIEQUAL) continue;
    opRemoveInput(op,blocknum);
    opZeroMulti(op);
  }
}

/// The edge is removed from control-flow and affected MULTIEQUAL ops are adjusted.
/// \param bb is the basic block
/// \param num is the index of the out edge to remove
void Funcdata::removeBranch(BlockBasic *bb,int4 num)

{
  branchRemoveInternal(bb,num);
  structureReset();
}

/// \brief Check if given Varnode has any descendants in a dead block
///
/// Assuming a basic block is marked \e dead, return \b true if any PcodeOp reading
/// the Varnode is in the dead block.
/// \param vn is the given Varnode
/// \return \b true if the Varnode is read in the dead block
bool Funcdata::descendantsOutside(Varnode *vn)

{
  list<PcodeOp *>::const_iterator iter;

  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter)
    if (!(*iter)->getParent()->isDead()) return true;
  return false;
}

/// \brief Remove an active basic block from the function
///
/// PcodeOps in the block are deleted.  Data-flow and control-flow are otherwise
/// patched up. Most of the work is patching up MULTIEQUALs and other remaining
/// references to Varnodes flowing through the block to be removed.
///
/// If descendant Varnodes are stranded by removing the block, either an exception is
/// thrown, or optionally, the descendant Varnodes can be replaced with constants and
/// a warning is printed.
/// \param bb is the given basic block
/// \param unreachable is \b true if the caller wants a warning for stranded Varnodes
void Funcdata::blockRemoveInternal(BlockBasic *bb,bool unreachable)

{
  BlockBasic *bbout;
  Varnode *deadvn;
  PcodeOp *op,*deadop;
  list<PcodeOp *>::iterator iter;
  int4 i,j,blocknum;
  bool desc_warning;

  op = bb->lastOp();
  if ((op != (PcodeOp *)0)&&(op->code() == CPUI_BRANCHIND)) {
    JumpTable *jt = findJumpTable(op);
    if (jt != (JumpTable *)0)
      removeJumpTable(jt);
  }
  if (!unreachable) {
    pushMultiequals(bb);	// Make sure data flow is preserved

    for(i=0;i<bb->sizeOut();++i) {
      bbout = (BlockBasic *) bb->getOut(i);
      if (bbout->isDead()) continue;
      blocknum = bbout->getInIndex(bb); // Get index of bb into bbout
      for(iter=bbout->beginOp();iter!=bbout->endOp();++iter) {
	op = *iter;
	if (op->code() != CPUI_MULTIEQUAL) continue;
	deadvn = op->getIn(blocknum);
	opRemoveInput(op,blocknum);	// Remove the deleted blocks branch
	deadop = deadvn->getDef();
	if ((deadvn->isWritten())&&(deadop->code()==CPUI_MULTIEQUAL)&&(deadop->getParent()==bb)) {
	  // Append new branches
	  for(j=0;j<bb->sizeIn();++j)
	    opInsertInput(op,deadop->getIn(j),op->numInput());
	}
	else {
	  for(j=0;j<bb->sizeIn();++j)
	    opInsertInput(op,deadvn,op->numInput()); // Otherwise make copies
	}
	opZeroMulti(op);
      }
    }
  }
  bblocks.removeFromFlow(bb);

  desc_warning = false;
  iter = bb->beginOp();
  while(iter!=bb->endOp()) {	// Finally remove all the ops
    op = *iter;
    if (op->isAssignment()) {	// op still has some descendants
      deadvn = op->getOut();
      if (unreachable) {
	bool undef = descend2Undef(deadvn);
	if (undef&&(!desc_warning))  { // Mark descendants as undefined
	  warningHeader("Creating undefined varnodes in (possibly) reachable block");
	  desc_warning = true;	// Print the warning only once
	}
      }
      if (descendantsOutside(deadvn)) // If any descendants outside of bb
	throw LowlevelError("Deleting op with descendants\n");
    }
    if (op->isCall())
      deleteCallSpecs(op);
    iter++;			// Increment iterator before unlinking
    opDestroy(op);		// No longer has descendants
  }
  bblocks.removeBlock(bb);	// Remove the block altogether
}

/// The block must contain only \e marker operations (MULTIEQUAL) and possibly a single
/// unconditional branch operation. The block and its PcodeOps are completely removed from
/// the current control-flow and data-flow.  This forces a reset of the control-flow structuring
/// hierarchy.
/// \param bb is the given basic block
void Funcdata::removeDoNothingBlock(BlockBasic *bb)

{
  if (bb->sizeOut()>1)
    throw LowlevelError("Cannot delete a reachable block unless it has 1 out or less");

  bb->setDead();
  blockRemoveInternal(bb,false);
  structureReset();		// Delete any structure we had before
}

/// \brief Remove any unreachable basic blocks
///
/// A quick check for unreachable blocks can optionally be made, otherwise
/// the cached state is checked via hasUnreachableBlocks(), which is turned on
/// during analysis by calling the structureReset() method.
/// \param issuewarning is \b true if warning comments are desired
/// \param checkexistence is \b true to force an active search for unreachable blocks
/// \return \b true if unreachable blocks were actually found and removed
bool Funcdata::removeUnreachableBlocks(bool issuewarning,bool checkexistence)

{
  vector<FlowBlock *> list;
  uint4 i;

  if (checkexistence) { // Quick check for the existence of unreachable blocks
    for(i=0;i<bblocks.getSize();++i) {
      FlowBlock *blk = bblocks.getBlock(i);
      if (blk->isEntryPoint()) continue; // Don't remove starting component
      if (blk->getImmedDom() == (FlowBlock *)0) break;
    }
    if (i==bblocks.getSize()) return false;
  }
  else if (!hasUnreachableBlocks())		// Use cached check
    return false;

  // There must be at least one unreachable block if we reach here

  for(i=0;i<bblocks.getSize();++i) // Find entry point
    if (bblocks.getBlock(i)->isEntryPoint()) break;
  bblocks.collectReachable(list,bblocks.getBlock(i),true); // Collect (un)reachable blocks

  for(int4 i=0;i<list.size();++i) {
    list[i]->setDead();
    if (issuewarning) {
      ostringstream s;
      BlockBasic *bb = (BlockBasic *)list[i];
      s << "Removing unreachable block (";
      s << bb->getStart().getSpace()->getName();
      s << ',';
      bb->getStart().printRaw(s);
      s << ')';
      warningHeader(s.str());
    }
  }
  for(int4 i=0;i<list.size();++i) {
    BlockBasic *bb = (BlockBasic *)list[i];
    while(bb->sizeOut() > 0)
      branchRemoveInternal(bb,0);
  }
  for(int4 i=0;i<list.size();++i) {
    BlockBasic *bb = (BlockBasic *)list[i];
    blockRemoveInternal(bb,true);
  }
  structureReset();
  return true;
}

/// \brief Move a control-flow edge from one block to another
///
/// This is intended for eliminating switch guard artifacts. The edge
/// must be for a conditional jump and must be moved to a block hosting
/// multiple out edges for a BRANCHIND.
/// \param bb is the basic block out of which the edge to move flows
/// \param slot is the index of the (out) edge
/// \param bbnew is the basic block where the edge should get moved to
void Funcdata::pushBranch(BlockBasic *bb,int4 slot,BlockBasic *bbnew)

{
  PcodeOp *cbranch = bb->lastOp();
  if ((cbranch->code() != CPUI_CBRANCH)||(bb->sizeOut() != 2))
    throw LowlevelError("Cannot push non-conditional edge");
  PcodeOp *indop = bbnew->lastOp();
  if (indop->code() != CPUI_BRANCHIND)
    throw LowlevelError("Can only push branch into indirect jump");

  // Turn the conditional branch into a branch
  opRemoveInput(cbranch,1);	// Remove the conditional variable
  opSetOpcode(cbranch,CPUI_BRANCH);
  bblocks.moveOutEdge(bb,slot,bbnew);
  // No change needs to be made to the indirect branch
  // we assume it handles its new branch implicitly
  structureReset();
}

/// Look up the jump-table object with the matching PcodeOp address, then
/// attach the given PcodeOp to it.
/// \param op is the given BRANCHIND PcodeOp
/// \return the matching jump-table object or NULL
JumpTable *Funcdata::linkJumpTable(PcodeOp *op)

{
  vector<JumpTable *>::iterator iter;
  JumpTable *jt;

  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter) {
    jt = *iter;
    if (jt->getOpAddress() == op->getAddr()) {
      jt->setIndirectOp(op);
      return jt;
    }
  }
  return (JumpTable *)0;
}

/// Look up the jump-table object with the matching PcodeOp address
/// \param op is the given BRANCHIND PcodeOp
/// \return the matching jump-table object or NULL
JumpTable *Funcdata::findJumpTable(const PcodeOp *op) const

{
  vector<JumpTable *>::const_iterator iter;
  JumpTable *jt;

  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter) {
    jt = *iter;
    if (jt->getOpAddress() == op->getAddr()) return jt;
  }
  return (JumpTable *)0;
}

/// The given address must have a BRANCHIND op attached to it.
/// This is suitable for installing an override and must be called before
/// flow has been traced.
/// \param addr is the given Address
/// \return the new jump-table object
JumpTable *Funcdata::installJumpTable(const Address &addr)

{
  if (isProcStarted())
    throw LowlevelError("Cannot install jumptable if flow is already traced");
  for(int4 i=0;i<jumpvec.size();++i) {
    JumpTable *jt = jumpvec[i];
    if (jt->getOpAddress() == addr)
      throw LowlevelError("Trying to install over existing jumptable");
  }
  JumpTable *newjt = new JumpTable(glb,addr);
  jumpvec.push_back(newjt);
  return newjt;
}

/// \brief Recover a jump-table for a given BRANCHIND using existing flow information
///
/// A partial function (copy) is built using the flow info. Simplification is performed on the
/// partial function (using the "jumptable" strategy), then destination addresses of the
/// branch are recovered by examining the simplified data-flow. The jump-table object
/// is populated with the recovered addresses.  An integer value is returned:
///   - 0 = success
///   - 1 = normal could-not-recover failure
///   - 2 = \b likely \b thunk failure
///   - 3 = no legal flows to the BRANCHIND failure
///
/// \param jt is the jump-table object to populate
/// \param op is the BRANCHIND p-code op to analyze
/// \param flow is the existing flow information
/// \return the success/failure code
int4 Funcdata::stageJumpTable(JumpTable *jt,PcodeOp *op,FlowInfo *flow)

{
  PcodeOp *partop = (PcodeOp *)0;
  string oldactname;

  ostringstream s1;
  s1 << name << "@@jump@";
  op->getAddr().printRaw(s1);

  Funcdata partial(s1.str(),localmap->getParent(),baseaddr,(FunctionSymbol *)0);
  partial.flags |= jumptablerecovery_on; // Mark that this Funcdata object is dedicated to jumptable recovery
  partial.truncatedFlow(this,flow);

  partop = partial.findOp(op->getSeqNum());

  if ((partop==(PcodeOp *)0) ||
      (partop->code() != CPUI_BRANCHIND)||
      (partop->getAddr() != op->getAddr()))
    throw LowlevelError("Error recovering jumptable: Bad partial clone");

  oldactname = glb->allacts.getCurrentName(); // Save off old action
  glb->allacts.setCurrent("jumptable");
  try {
#ifdef OPACTION_DEBUG
    if (jtcallback != (void (*)(Funcdata &orig,Funcdata &fd))0)
      (*jtcallback)(*this,partial);  // Alternative reset/perform
    else {
#endif
    glb->allacts.getCurrent()->reset( partial );
    glb->allacts.getCurrent()->perform( partial ); // Simplify the partial function
#ifdef OPACTION_DEBUG
    }
#endif
    glb->allacts.setCurrent(oldactname); // Restore old action
    if (partop->isDead())	// Indirectop we were trying to recover was eliminated as dead code (unreachable)
      return 0;			// Return jumptable as 
    jt->setLoadCollect(flow->doesJumpRecord());
    jt->setIndirectOp(partop);
    if (jt->getStage()>0)
      jt->recoverMultistage(&partial);
    else
      jt->recoverAddresses(&partial); // Analyze partial to recover jumptable addresses
  }
  catch(JumptableNotReachableError &err) {
    glb->allacts.setCurrent(oldactname);
    return 3;
  }
  catch(JumptableThunkError &err) {
    glb->allacts.setCurrent(oldactname);
    return 2;
  }
  catch(LowlevelError &err) {
    glb->allacts.setCurrent(oldactname);
    warning(err.explain,op->getAddr());
    return 1;
  }
  return 0;
}

/// \brief Recover destinations for a BRANCHIND by analyzing nearby data and control-flow
///
/// This is the high-level entry point for jump-table/switch recovery. In short, a
/// copy of the current state of data-flow is made, simplification transformations are applied
/// to the copy, and the resulting data-flow tree is examined to enumerate possible values
/// of the input Varnode to the given BRANCHIND PcodeOp.  This information is stored in a
/// JumpTable object.
/// \param op is the given BRANCHIND PcodeOp
/// \param flow is current flow information for \b this function
/// \param failuremode will hold the final success/failure code (0=success)
/// \return the recovered JumpTable or NULL if there was no success
JumpTable *Funcdata::recoverJumpTable(PcodeOp *op,FlowInfo *flow,int4 &failuremode)

{
  JumpTable *jt;

  failuremode = 0;
  jt = linkJumpTable(op);		// Search for pre-existing jumptable
  if (jt != (JumpTable *)0) {
    if (!jt->isOverride()) {
      if (jt->getStage() != 1)
	return jt;		// Previously calculated jumptable (NOT an override and NOT incomplete)
    }
    failuremode = stageJumpTable(jt,op,flow); // Recover based on override information
    if (failuremode != 0)
      return (JumpTable *)0;
    jt->setIndirectOp(op);	// Relink table back to original op
    return jt;
  }

  if ((flags & jumptablerecovery_dont)!=0)
    return (JumpTable *)0;	// Explicitly told not to recover jumptables
  JumpTable trialjt(glb);
  failuremode = stageJumpTable(&trialjt,op,flow);
  if (failuremode != 0)
    return (JumpTable *)0;
  //  if (trialjt.is_twostage())
  //    warning("Jumptable maybe incomplete. Second-stage recovery not implemented",trialjt.Opaddress());
  jt = new JumpTable(&trialjt); // Make the jumptable permanent
  jumpvec.push_back(jt);
  jt->setIndirectOp(op);		// Relink table back to original op
  return jt;
}

/// For each jump-table, for each address, the corresponding basic block index is computed.
/// This also calculates the \e default branch for each jump-table.
/// \param flow is the flow object (mapping addresses to p-code ops)
void Funcdata::switchOverJumpTables(const FlowInfo &flow)

{
  vector<JumpTable *>::iterator iter;

  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter)
    (*iter)->switchOver(flow);
}

void Funcdata::installSwitchDefaults(void)

{
  vector<JumpTable *>::iterator iter;
  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter) {
    JumpTable *jt = *iter;
    PcodeOp *indop = jt->getIndirectOp();
    BlockBasic *ind = indop->getParent();
			 // Mark any switch blocks default edge
    if (jt->getDefaultBlock() != -1) // If a default case is present
      ind->setDefaultSwitch(jt->getDefaultBlock());
  }
}

/// For the current control-flow graph, (re)calculate the loop structure and dominance.
/// This can be called multiple times as changes are made to control-flow.
/// The structured hierarchy is also reset.
void Funcdata::structureReset(void)

{
  vector<JumpTable *>::iterator iter;
  vector<FlowBlock *> rootlist;

  flags &= ~blocks_unreachable;	// Clear any old blocks flag
  bblocks.structureLoops(rootlist);
  bblocks.calcForwardDominator(rootlist);
  if (rootlist.size() > 1)
    flags |= blocks_unreachable;
  // Check for dead jumptables
  vector<JumpTable *> alivejumps;
  for(iter=jumpvec.begin();iter!=jumpvec.end();++iter) {
    JumpTable *jt = *iter;
    PcodeOp *indop = jt->getIndirectOp();
    if (indop->isDead()) {
      warningHeader("Recovered jumptable eliminated as dead code");
      delete jt;
      continue;
    }
    alivejumps.push_back(jt);
  }
  jumpvec = alivejumps;
  sblocks.clear();		// Force structuring algorithm to start over
  //  sblocks.build_copy(bblocks);	// Make copy of the basic block control flow graph
  heritage.forceRestructure();
}

/// \brief Force a specific control-flow edge to be marked as \e unstructured
///
/// The edge is specified by a source and destination Address (of the branch).
/// The resulting control-flow structure will have a \e goto statement modeling
/// the edge.
/// \param pcop is the source Address
/// \param pcdest is the destination Address
/// \return \b true if a control-flow edge was successfully labeled
bool Funcdata::forceGoto(const Address &pcop,const Address &pcdest)

{
  FlowBlock *bl,*bl2;
  PcodeOp *op,*op2;
  int4 i,j;

  for(i=0;i<bblocks.getSize();++i) {
    bl = bblocks.getBlock(i);
    op = bl->lastOp();
    if (op == (PcodeOp *)0) continue;
    if (op->getAddr() != pcop) continue;	// Find op to mark unstructured
    for(j=0;j<bl->sizeOut();++j) {
      bl2 = bl->getOut(j);
      op2 = bl2->lastOp();
      if (op2 == (PcodeOp *)0) continue;
      if (op2->getAddr() != pcdest) continue; // Find particular branch
      bl->setGotoBranch(j);
      return true;
    }
  }
  return false;
}

/// \brief Create a new basic block for holding a merged CBRANCH
///
/// This is used by ConditionalJoin to do the low-level control-flow manipulation
/// to merge identical conditional branches. Given basic blocks containing the two
/// CBRANCH ops to merge, the new block gets one of the two out edges from each block,
/// and the remaining out edges are changed to point into the new block.
/// \param block1 is the basic block containing the first CBRANCH to merge
/// \param block2 is the basic block containing the second CBRANCH
/// \param exita is the first common exit block for the CBRANCHs
/// \param exitb is the second common exit block
/// \param fora_block1ishigh designates which edge is moved for exita
/// \param forb_block1ishigh designates which edge is moved for exitb
/// \param addr is the Address associated with (1 of the) CBRANCH ops
/// \return the new basic block
BlockBasic *Funcdata::nodeJoinCreateBlock(BlockBasic *block1,BlockBasic *block2,
					  BlockBasic *exita,BlockBasic *exitb,
					  bool fora_block1ishigh,bool forb_block1ishigh,const Address &addr)

{
  BlockBasic *newblock = bblocks.newBlockBasic(this);
  newblock->setFlag(FlowBlock::f_joined_block);
  newblock->setInitialRange(addr, addr);
  FlowBlock *swapa,*swapb;

  // Delete 2 of the original edges into exita and exitb
  if (fora_block1ishigh) {		// Remove the edge from block1
    bblocks.removeEdge(block1,exita);
    swapa = block2;
  }
  else {
    bblocks.removeEdge(block2,exita);
    swapa = block1;
  }
  if (forb_block1ishigh) {
    bblocks.removeEdge(block1,exitb);
    swapb = block2;
  }
  else {
    bblocks.removeEdge(block2,exitb);
    swapb = block1;
  }

  // Move the remaining two from block1,block2 to newblock
  bblocks.moveOutEdge(swapa,swapa->getOutIndex(exita),newblock);
  bblocks.moveOutEdge(swapb,swapb->getOutIndex(exitb),newblock);

  bblocks.addEdge(block1,newblock);
  bblocks.addEdge(block2,newblock);
  structureReset();
  return newblock;
}

/// \brief Split given basic block b along an \e in edge
///
/// A copy of the block is made, inheriting the same \e out edges but only the
/// one indicated \e in edge, which is removed from the original block.
/// Other data-flow is \b not affected.
/// \param b is the given basic block
/// \param inedge is the index of the indicated \e in edge
BlockBasic *Funcdata::nodeSplitBlockEdge(BlockBasic *b,int4 inedge)

{
  FlowBlock *a = b->getIn(inedge);
  BlockBasic *bprime;

  bprime = bblocks.newBlockBasic(this);
  bprime->setFlag(FlowBlock::f_duplicate_block);
  bprime->copyRange(b);
  bblocks.switchEdge(a,b,bprime);
  for(int4 i=0;i<b->sizeOut();++i)
    bblocks.addEdge(bprime,b->getOut(i));
  return bprime;
}

/// \brief Duplicate the given PcodeOp as part of splitting a block
///
/// Make a basic clone of the p-code op copying its basic control-flow properties
/// \param op is the given PcodeOp
/// \return the cloned op
PcodeOp *Funcdata::nodeSplitCloneOp(PcodeOp *op)

{
  PcodeOp *dup;

  if (op->isBranch()) {
    if (op->code() != CPUI_BRANCH)
      throw LowlevelError("Cannot duplicate 2-way or n-way branch in nodeplit");
    return (PcodeOp *)0;
  }
  dup = newOp(op->numInput(),op->getAddr());
  opSetOpcode(dup,op->code());
  uint4 flags = op->flags & (PcodeOp::startbasic | PcodeOp::nocollapse |
			     PcodeOp::startmark);
  dup->setFlag(flags);
  return dup;
}

/// \brief Duplicate output Varnode of the given p-code op, as part of splitting a block
///
/// Make a basic clone of the Varnode and its basic flags. The clone is created
/// as an output of a previously cloned PcodeOp.
/// \param op is the given op whose output should be cloned
/// \param newop is the cloned version
void Funcdata::nodeSplitCloneVarnode(PcodeOp *op,PcodeOp *newop)

{
  Varnode *opvn = op->getOut();
  Varnode *newvn;

  if (opvn == (Varnode *)0) return;
  newvn = newVarnodeOut(opvn->getSize(),opvn->getAddr(),newop);
  uint4 vflags = opvn->getFlags();
  vflags &= (Varnode::externref | Varnode::volatil | Varnode::incidental_copy |
	     Varnode::readonly | Varnode::persist |
	     Varnode::addrtied | Varnode::addrforce);
  newvn->setFlags(vflags);
}

/// \brief Clone all p-code ops from a block into its copy
///
/// P-code in a basic block is cloned into the split version of the block.
/// Only the output Varnodes are cloned, not the inputs.
/// \param b is the original basic block
/// \param bprime is the cloned block
void Funcdata::nodeSplitRawDuplicate(BlockBasic *b,BlockBasic *bprime)

{
  PcodeOp *b_op,*prime_op;
  list<PcodeOp *>::iterator iter;

  for(iter=b->beginOp();iter!=b->endOp();++iter) {
    b_op = *iter;
    prime_op = nodeSplitCloneOp(b_op);
    if (prime_op == (PcodeOp *)0) continue;
    nodeSplitCloneVarnode(b_op,prime_op);
    opInsertEnd(prime_op,bprime);
  }
}

/// \brief Patch Varnode inputs to p-code ops in split basic block
///
/// Map Varnodes that are inputs for PcodeOps in the original basic block to the
/// input slots of the cloned ops in the split block. Constants and code ref Varnodes
/// need to be duplicated, other Varnodes are shared between the ops. This routine
/// also pulls an input Varnode out of riginal MULTIEQUAL ops and adds it back
/// to the cloned MULTIEQUAL ops.
/// \param b is the original basic block
/// \param bprime is the split clone of the block
/// \param inedge is the incoming edge index that was split on
void Funcdata::nodeSplitInputPatch(BlockBasic *b,BlockBasic *bprime,int4 inedge)

{
  list<PcodeOp *>::iterator biter,piter;
  PcodeOp *bop,*pop;
  Varnode *bvn,*pvn;
  map<PcodeOp *,PcodeOp *> btop; // Map from b to bprime
  vector<PcodeOp *> pind;	// pop needing b input
  vector<PcodeOp *> bind;	// bop giving input
  vector<int4> pslot;		// slot within pop needing b input

  biter = b->beginOp();
  piter = bprime->beginOp();

  while(piter != bprime->endOp()) {
    bop = *biter;
    pop = *piter;
    btop[bop] = pop;		// Establish mapping
    if (bop->code() == CPUI_MULTIEQUAL) {
      pop->setNumInputs(1);	// One edge now goes into bprime
      opSetOpcode(pop,CPUI_COPY);
      opSetInput(pop,bop->getIn(inedge),0);
      opRemoveInput(bop,inedge); // One edge is removed from b
      if (bop->numInput() == 1)
	opSetOpcode(bop,CPUI_COPY);
    }
    else if (bop->code() == CPUI_INDIRECT) {
      throw LowlevelError("Can't handle INDIRECTs in nodesplit");
    }
    else if (bop->isCall()) {
      throw LowlevelError("Can't handle CALLs in nodesplit");
    }
    else {
      for(int4 i=0;i<pop->numInput();++i) {
	bvn = bop->getIn(i);
	if (bvn->isConstant())
	  pvn = newConstant(bvn->getSize(),bvn->getOffset());
	else if (bvn->isAnnotation())
	  pvn = newCodeRef(bvn->getAddr());
	else if (bvn->isFree())
	  throw LowlevelError("Can't handle free varnode in nodesplit");
	else {
	  if (bvn->isWritten()) {
	    if (bvn->getDef()->getParent() == b) {
	      pind.push_back(pop); // Need a cross reference
	      bind.push_back(bvn->getDef());
	      pslot.push_back(i);
	      continue;
	    }
	    else
	      pvn = bvn;
	  }
	  else
	    pvn = bvn;
	}
	opSetInput(pop,pvn,i);
      }
    }
    ++piter;
    ++biter;
  }

  for(int4 i=0;i<pind.size();++i) {
    pop = pind[i];
    PcodeOp *cross = btop[bind[i]];
    opSetInput(pop,cross->getOut(),pslot[i]);
  }
}

/// \brief Split control-flow into a basic block, duplicating its p-code into a new block
///
/// P-code is duplicated into another block, and control-flow is modified so that the new
/// block takes over flow from one input edge to the original block.
/// \param b is the basic block to be duplicated and split
/// \param inedge is the index of the input edge to move to the duplicate block
void Funcdata::nodeSplit(BlockBasic *b,int4 inedge)

{ // Split node b along inedge
  if (b->sizeOut() != 0)
    throw LowlevelError("Cannot (currently) nodesplit block with out flow");
  if (b->sizeIn()<=1)
    throw LowlevelError("Cannot nodesplit block with only 1 in edge");
  for(int4 i=0;i<b->sizeIn();++i) {
    if (b->getIn(i)->isMark())
      throw LowlevelError("Cannot nodesplit block with redundant in edges");
    b->setMark();
  }
  for(int4 i=0;i<b->sizeIn();++i)
    b->clearMark();

				// Create duplicate block
  BlockBasic *bprime = nodeSplitBlockEdge(b,inedge);
				// Make copy of b's ops
  nodeSplitRawDuplicate(b,bprime);
				// Patch up inputs based on split
  nodeSplitInputPatch(b,bprime,inedge);

  // We would need to patch outputs here for the more general
  // case when b has out edges
  // any references not in b to varnodes defined in b
  // need to have MULTIEQUALs defined in b's out blocks
  //   with edges coming from b and bprime
  structureReset();
}

/// \brief Remove a basic block splitting its control-flow into two distinct paths
///
/// This is used by ConditionalExecution to eliminate unnecessary control-flow joins.
/// The given block must have 2 inputs and 2 outputs, (and no operations).  The block
/// is removed, and control-flow is adjusted so that
/// In(0) flows to Out(0) and In(1) flows to Out(1), or vice versa.
/// \param bl is the given basic block
/// \param swap is \b true to force In(0)->Out(1) and In(1)->Out(0)
void Funcdata::removeFromFlowSplit(BlockBasic *bl,bool swap)

{
  if (!bl->emptyOp())
    throw LowlevelError("Can only split the flow for an empty block");
  bblocks.removeFromFlowSplit(bl,swap);
  bblocks.removeBlock(bl);
  structureReset();
}

/// \brief Switch an outgoing edge from the given \e source block to flow into another block
///
/// This does \e not adjust MULTIEQUAL data-flow.
/// \param inblock is the given \e source block
/// \param outbefore is the other side of the desired edge
/// \param outafter is the new destination block desired
void Funcdata::switchEdge(FlowBlock *inblock,BlockBasic *outbefore,FlowBlock *outafter)

{
  bblocks.switchEdge(inblock,outbefore,outafter);
  structureReset();
}

/// The given block must have a single output block, which will be removed.  The given block
/// has the p-code from the output block concatenated to its own, and it inherits the output
/// block's out edges.
/// \param bl is the given basic block
void Funcdata::spliceBlockBasic(BlockBasic *bl)

{
  BlockBasic *outbl = (BlockBasic *)0;
  if (bl->sizeOut() == 1) {
    outbl = (BlockBasic *)bl->getOut(0);
    if (outbl->sizeIn() != 1)
      outbl = (BlockBasic *)0;
  }
  if (outbl == (BlockBasic *)0)
    throw LowlevelError("Cannot splice basic blocks");
  // Remove any jump op at the end of -bl-
  if (!bl->op.empty()) {
    PcodeOp *jumpop = bl->op.back();
    if (jumpop->isBranch())
      opDestroy(jumpop);
  }
  if (!outbl->op.empty()) {
    // Check for MULTIEQUALs
    PcodeOp *firstop = outbl->op.front();
    if (firstop->code() == CPUI_MULTIEQUAL)
      throw LowlevelError("Splicing block with MULTIEQUAL");
    firstop->clearFlag(PcodeOp::startbasic);
    list<PcodeOp *>::iterator iter;
    // Move ops into -bl-
    for(iter=outbl->beginOp();iter!=outbl->endOp();++iter) {
      PcodeOp *op = *iter;
      op->setParent(bl);	// Reset ops parent to -bl-
    }
    // Move all ops from -outbl- to end of -bl-
    bl->op.splice(bl->op.end(),outbl->op,outbl->op.begin(),outbl->op.end());
    // insertiter should remain valid through splice
    bl->setOrder();		// Reset the seqnum ordering on all the ops
  }
  bl->mergeRange(outbl);	// Update the address cover
  bblocks.spliceBlock(bl);
  structureReset();
}

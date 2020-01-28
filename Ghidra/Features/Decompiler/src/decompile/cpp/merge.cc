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
#include "merge.hh"
#include "funcdata.hh"

/// This instance assumes the identity of the given Varnode and the defining index is
/// cached to facilitate quick sorting.
/// \param v is the given Varnode
void BlockVarnode::set(Varnode *v)

{
  vn = v;
  const PcodeOp *op = vn->getDef();

  if (op == (const PcodeOp *)0)
    index = 0;
  else
    index = op->getParent()->getIndex();
}

/// \brief Find the first Varnode defined in the BlockBasic of the given index
///
/// A BlockVarnode is identified from a sorted \b list. The position of the first BlockVarnode
/// in this list that has the given BlockBasic \e index is returned.
/// \param blocknum is the index of the BlockBasic to search for
/// \param list is the sorted list of BlockVarnodes
/// \return the index of the BlockVarnode within the list or -1 if no Varnode in the block is found
int4 BlockVarnode::findFront(int4 blocknum,const vector<BlockVarnode> &list)

{
  int4 min = 0;
  int4 max = list.size()-1;
  while(min < max) {
    int4 cur = (min + max)/2;
    int4 curblock = list[cur].getIndex();
    if (curblock >= blocknum)
      max = cur;
    else
      min = cur + 1;
  }
  if (min > max)
    return -1;
  if (list[min].getIndex() != blocknum)
    return -1;
  return min;
}

/// \brief Required tests to merge HighVariables that are not Cover related
///
/// This is designed to short circuit merge tests, when we know properties of the
/// two HighVariables preclude merging. For example, you can't merge HighVariables if:
///   - They are locked to different data-types
///   - They are both mapped to different address ranges
///   - One is a parameter one is a global
///
/// \param high_out is the first HighVariable to test
/// \param high_in is the second HighVariable to test
/// \return \b true if tests pass and the HighVariables are not forbidden to merge
bool Merge::mergeTestRequired(HighVariable *high_out,HighVariable *high_in)

{
  if (high_in == high_out) return true; // Already merged

  if (high_in->isTypeLock())	// If types are locked
    if (high_out->isTypeLock())	// dont merge unless
      if (high_in->getType() != high_out->getType()) return false; // both types are the same

  if (high_out->isAddrTied()) {	// Do not merge address tied input
    if (high_in->isAddrTied()) {
      if (high_in->getTiedVarnode()->getAddr() != high_out->getTiedVarnode()->getAddr())
	return false;		// with an address tied output of different address
    }
  }

  if (high_in->isInput()) {
				// Input and persist must be different vars
				// as persists inherently have their own input
    if (high_out->isPersist()) return false;
				// If we don't prevent inputs and addrtieds from
				// being merged.  Inputs can get merged with the
				// internal parts of structures on the stack
    if ((high_out->isAddrTied())&&(!high_in->isAddrTied())) return false;
  }
  else if (high_in->isExtraOut())
    return false;
  if (high_out->isInput()) {
    if (high_in->isPersist()) return false;
    if ((high_in->isAddrTied())&&(!high_out->isAddrTied())) return false;
  }
  else if (high_out->isExtraOut())
    return false;

  Symbol *symbolIn = high_in->getSymbol();
  Symbol *symbolOut = high_out->getSymbol();
  if (symbolIn != (Symbol *) 0 && symbolOut != (Symbol *) 0) {
    if (symbolIn != symbolOut)
      return false;		// Map to different symbols
    if (high_in->getSymbolOffset() != high_out->getSymbolOffset())
      return false;			// Map to different parts of same symbol
  }

  return true;
}

/// \brief Adjacency tests for merging Varnodes that are input or output to the same p-code op
///
/// All the required tests (mergeTestRequired()) are performed, and then some additional tests
/// are performed. This does not perform any Cover tests.
/// \param high_out is the \e output HighVariable to test
/// \param high_in is the \e input HighVariable to test
/// \return \b true if tests pass and the HighVariables are not forbidden to merge
bool Merge::mergeTestAdjacent(HighVariable *high_out,HighVariable *high_in)

{
  if (!mergeTestRequired(high_out,high_in)) return false;

  if (high_in->isNameLock() && high_out->isNameLock())
    return false;

  // Make sure variables have the same type
  if (high_out->getType() != high_in->getType())
    return false;
				// We want to isolate the use of illegal inputs
				// as much as possible.  See we don't do any speculative
				// merges with them, UNLESS the illegal input is only
				// used indirectly
  if (high_out->isInput()) {
    Varnode *vn = high_out->getInputVarnode();
    if (vn->isIllegalInput()&&(!vn->isIndirectOnly())) return false;
  }
  if (high_in->isInput()) {
    Varnode *vn = high_in->getInputVarnode();
    if (vn->isIllegalInput()&&(!vn->isIndirectOnly())) return false;
  }
  Symbol *symbol = high_in->getSymbol();
  if (symbol != (Symbol *)0)
    if (symbol->isIsolated())
      return false;
  symbol = high_out->getSymbol();
  if (symbol != (Symbol *)0)
    if (symbol->isIsolated())
      return false;
  return true;
}

/// \brief Speculative tests for merging HighVariables that are not Cover related
///
/// This does all the \e required and \e adjacency merge tests and then performs additional
/// tests required for \e speculative merges.
/// \param high_out is the first HighVariable to test
/// \param high_in is the second HighVariable to test
/// \return \b true if tests pass and the HighVariables are not forbidden to merge
bool Merge::mergeTestSpeculative(HighVariable *high_out,HighVariable *high_in)

{
  if (!mergeTestAdjacent(high_out,high_in)) return false;

  // Don't merge anything with a global speculatively
  if (high_out->isPersist()) return false;
  if (high_in->isPersist()) return false;
  // Don't merge anything speculatively with input
  if (high_out->isInput()) return false;
  if (high_in->isInput()) return false;
  // Don't merge anything speculatively with addrtied
  if (high_out->isAddrTied()) return false;
  if (high_in->isAddrTied()) return false;
  return true;
}

/// \brief A test if the given Varnode can ever be merged
///
/// Some Varnodes (constants, annotations, implied, spacebase) are never merged with another
/// Varnode.
/// \param vn is the Varnode to test
/// \return \b true if the Varnode is not forbidden from ever merging
bool Merge::mergeTestBasic(Varnode *vn)

{
  if (vn == (Varnode *)0) return false;
  if (!vn->hasCover()) return false;
  if (vn->isImplied()) return false;
  if (vn->isSpacebase()) return false;
  return true;
}

/// \brief Speculatively merge all HighVariables in the given list as well as possible
///
/// The variables are first sorted by the index of the earliest block in their range.
/// Then proceeding in order, an attempt is made to merge each variable with the first.
/// The attempt fails if the \e speculative test doesn't pass or if there are Cover
/// intersections, in which case that particular merge is skipped.
void Merge::mergeLinear(vector<HighVariable *> &highvec)

{
  vector<HighVariable *> highstack;
  vector<HighVariable *>::iterator initer,outiter;
  HighVariable *high;

  if (highvec.size() <= 1) return;
  for(initer=highvec.begin();initer!=highvec.end();++initer)
    updateHigh(*initer);
  sort(highvec.begin(),highvec.end(),compareHighByBlock);
  for(initer=highvec.begin();initer!=highvec.end();++initer) {
    high = *initer;
    for(outiter=highstack.begin();outiter!=highstack.end();++outiter) {
      if (mergeTestSpeculative(*outiter,high))
	if (merge(*outiter,high,true)) break;
    }
    if (outiter==highstack.end())
      highstack.push_back(high);
  }
}

/// \brief Force the merge of a ranges of Varnodes with the same size and storage address
///
/// The list of Varnodes to be merged is provided as a range in the main location sorted
/// container.  Any Cover intersection is assumed to already be \b snipped, so any problems
/// with merging cause an exception to be thrown.
/// \param startiter is the beginning of the range of Varnodes with the same storage address
/// \param enditer is the end of the range
void Merge::mergeRangeMust(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer)

{
  HighVariable *high;
  Varnode *vn;

  vn = *startiter++;
  if (!mergeTestBasic(vn)) {
    if (!vn->isSpacebase())
      throw LowlevelError("Cannot force merge of range");
  }
  high = vn->getHigh();
  for(;startiter!=enditer;++startiter) {
    vn = *startiter;
    if (vn->getHigh() == high) continue;
    if (!mergeTestBasic(vn)) {
      if (!vn->isSpacebase())
	throw LowlevelError("Cannot force merge of range");
    }
    if (!merge(high,vn->getHigh(),false))
      throw LowlevelError("Forced merge caused intersection");
  }
}

/// \brief Try to force merges of input to output for all p-code ops of a given type
///
/// For a given opcode, run through all ops in the function in block/address order and
/// try to merge each input HighVariable with the output HighVariable.  If this would
/// introduce Cover intersections, the merge is skipped.  This is generally used to try to
/// merge the input and output of COPY ops if possible.
/// \param opc is the op-code type to merge
void Merge::mergeOpcode(OpCode opc)

{
  BlockBasic *bl;
  list<PcodeOp *>::iterator iter;
  PcodeOp *op;
  Varnode *vn1,*vn2;
  const BlockGraph &bblocks(data.getBasicBlocks());

  for(int4 i=0;i<bblocks.getSize();++i) { // Do merges in linear block order
    bl = (BlockBasic *) bblocks.getBlock(i);
    for(iter=bl->beginOp();iter!=bl->endOp();++iter) {
      op = *iter;
      if (op->code() != opc) continue;
      vn1 = op->getOut();
      if (!mergeTestBasic(vn1)) continue;
      for(int4 j=0;j<op->numInput();++j) {
	vn2 = op->getIn(j);
	if (!mergeTestBasic(vn2)) continue;
	if (mergeTestRequired(vn1->getHigh(),vn2->getHigh()))
	  merge(vn1->getHigh(),vn2->getHigh(),false);	// This is a required merge
      }
    }
  }
}

/// \brief Try to merge all HighVariables in the given range that have the same data-type
///
/// HighVariables that have an instance within the given Varnode range are sorted into groups
/// based on their data-type.  Then an attempt is made to merge all the HighVariables within
/// a group. If a particular merge causes Cover intersection, it is skipped.
/// \param startiter is the start of the given range of Varnodes
/// \param enditer is the end of the given range
void Merge::mergeByDatatype(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer)

{
  vector<HighVariable *> highvec;
  list<HighVariable *> highlist;

  list<HighVariable *>::iterator hiter;
  VarnodeLocSet::const_iterator iter;
  Varnode *vn;
  HighVariable *high;
  Datatype *ct = (Datatype *)0;

  for(iter=startiter;iter!=enditer;++iter) { // Gather all the highs
    vn = *iter;
    if (vn->isFree()) continue;
    high = (*iter)->getHigh();
    if (high->isMark()) continue;	// dedup
    if (!mergeTestBasic(vn)) continue;
    high->setMark();
    highlist.push_back(high);
  }
  for(hiter=highlist.begin();hiter!=highlist.end();++hiter)
    (*hiter)->clearMark();

  while(!highlist.empty()) {
    highvec.clear();
    hiter = highlist.begin();
    high = *hiter;
    ct = high->getType();
    highvec.push_back(high);
    highlist.erase(hiter++);
    while(hiter != highlist.end()) {
      high = *hiter;
      if (ct == high->getType()) {	// Check for exact same type
	highvec.push_back(high);
	highlist.erase(hiter++);
      }
      else
	++hiter;
    }
    mergeLinear(highvec);	// Try to merge all highs of the same type
  }
}

/// \brief Allocate COPY PcodeOp designed to trim an overextended Cover
///
/// A COPY is allocated with the given input and data-type.  A \e unique space
/// output is created.
/// \param inVn is the given input Varnode for the new COPY
/// \param ct is the data-type to assign to the new unique output
/// \param addr is the address associated with the new COPY
/// \return the newly allocated COPY
PcodeOp *Merge::allocateCopyTrim(Varnode *inVn,Datatype *ct,const Address &addr)

{
  PcodeOp *copyOp = data.newOp(1,addr);
  data.opSetOpcode(copyOp,CPUI_COPY);
  Varnode *outVn = data.newUnique(inVn->getSize(),ct);
  data.opSetOutput(copyOp,outVn);
  data.opSetInput(copyOp,inVn,0);
  copyTrims.push_back(copyOp);
  return copyOp;
}

/// \brief Snip off set of \e read p-code ops for a given Varnode
///
/// The data-flow for the given Varnode is truncated by creating a COPY p-code from the Varnode
/// into a new temporary Varnode, then replacing the Varnode reads for a specific set of
/// p-code ops with the temporary.
/// \param vn is the given Varnode
/// \param markedop is the specific set of PcodeOps reading the Varnode
void Merge::snipReads(Varnode *vn,list<PcodeOp *> &markedop)

{
  if (markedop.empty()) return;

  PcodeOp *copyop,*op;
  BlockBasic *bl;
  Address pc;
  int4 slot;
  PcodeOp *afterop;

				// Figure out where copy is inserted
  if (vn->isInput()) {
    bl = (BlockBasic *) data.getBasicBlocks().getBlock(0);
    pc = bl->getStart();
    afterop = (PcodeOp *)0;
  }
  else {
    bl = vn->getDef()->getParent();
    pc = vn->getDef()->getAddr();
    if (vn->getDef()->code() == CPUI_INDIRECT) // snip must come after OP CAUSING EFFECT
				// Not the indirect op itself
      afterop = PcodeOp::getOpFromConst(vn->getDef()->getIn(1)->getAddr());
    else
      afterop = vn->getDef();
  }
  copyop = allocateCopyTrim(vn, vn->getType(), pc);
  if (afterop == (PcodeOp *)0)
    data.opInsertBegin(copyop,bl);
  else
    data.opInsertAfter(copyop,afterop);

  list<PcodeOp *>::iterator iter;
  for(iter=markedop.begin();iter!=markedop.end();++iter) {
    op = *iter;
    for(slot=0;slot<op->numInput();++slot)
      if (op->getIn(slot)==vn) break; // Find the correct slot
    data.opSetInput(op,copyop->getOut(),slot);
  }
}

/// \brief Eliminate intersections of given Varnode with other Varnodes in a list
///
/// Both the given Varnode and those in the list are assumed to be at the same storage address.
/// For any intersection, identify the PcodeOp reading the given Varnode which causes the
/// intersection and \e snip the read by inserting additional COPY ops.
/// \param vn is the given Varnode
/// \param blocksort is the list of other Varnodes sorted by their defining basic block
void Merge::eliminateIntersect(Varnode *vn,const vector<BlockVarnode> &blocksort)

{
  list<PcodeOp *> markedop;
  list<PcodeOp *>::const_iterator oiter;
  map<int4,CoverBlock>::const_iterator iter,enditer;
  Varnode *vn2;
  int4 boundtype;
  bool insertop;

  for(oiter=vn->beginDescend();oiter!=vn->endDescend();++oiter) {
    insertop = false;
    Cover single;
    single.addDefPoint(vn);
    PcodeOp *op = *oiter;
    single.addRefPoint(op,vn); // Build range for a single read
    iter = single.begin();
    enditer = single.end();
    while(iter != enditer) {
      int4 blocknum = (*iter).first;
      ++iter;
      int4 slot = BlockVarnode::findFront(blocknum,blocksort);
      if (slot == -1) continue;
      while(slot < blocksort.size()) {
	if (blocksort[slot].getIndex() != blocknum)
	  break;
	vn2 = blocksort[slot].getVarnode();
	slot += 1;
	if (vn2 == vn) continue;
	boundtype = single.containVarnodeDef(vn2);
	if (boundtype == 0) continue;
	if (boundtype == 2) {	// We have to resolve things defined at same place
	  if (vn2->getDef() == (PcodeOp *)0) {
	    if (vn->getDef() == (PcodeOp *)0) {
	      if (vn < vn2) continue; // Choose an arbitrary order if both are inputs
	    }
	    else
	      continue;
	  }
	  else {
	    if (vn->getDef() != (PcodeOp *)0) {
	      if (vn2->getDef()->getSeqNum().getOrder() < vn->getDef()->getSeqNum().getOrder())
		continue;
	    }
	  }
	}
	else if (boundtype == 3) { // intersection on the tail of the range
	  // For most operations if the READ and WRITE happen on the same op, there is really no cover
	  // intersection because the READ happens before the op and the WRITE happens after,  but
	  // if the WRITE is for an INDIRECT that is marking the READING (call) op, and the WRITE is to
	  // an address forced varnode, then because the write varnode must exist just before the op
	  // there really is an intersection.
	  if (!vn2->isAddrForce()) continue;
	  if (!vn2->isWritten()) continue;
	  PcodeOp *indop = vn2->getDef();
	  if (indop->code() != CPUI_INDIRECT) continue;
	  // The vn2 INDIRECT must be linked to the read op
	  if (op != PcodeOp::getOpFromConst(indop->getIn(1)->getAddr())) continue;
	  if (vn->copyShadow(indop->getIn(0))) continue; // If INDIRECT input shadows vn, don't consider as intersection
	}
	insertop = true;
	break;			// No need to continue iterating through varnodes in block
      }
      if (insertop) break;	// No need to continue iterating through blocks
    }
    if (insertop)
      markedop.push_back(op);
  }
  snipReads(vn,markedop);
}

/// \brief Make sure all Varnodes with the same storage address and size can be merged
///
/// The list of Varnodes to be merged is provided as a range in the main location sorted
/// container.  Any discovered intersection is \b snipped by splitting data-flow for one of
/// the Varnodes into two or more flows, which involves insert new COPY ops and temporaries.
/// \param startiter is the beginning of the range of Varnodes with the same storage address
/// \param enditer is the end of the range
void Merge::unifyAddress(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer)

{
  VarnodeLocSet::const_iterator iter;
  Varnode *vn;
  vector<Varnode *> isectlist;
  vector<BlockVarnode> blocksort;

  for(iter=startiter;iter!=enditer;++iter) {
    vn = *iter;
    isectlist.push_back(vn);
  }
  blocksort.resize(isectlist.size());
  for(int4 i=0;i<isectlist.size();++i)
    blocksort[i].set(isectlist[i]);
  stable_sort(blocksort.begin(),blocksort.end());
				// BEWARE, its possible that eliminate_intersect
				// will insert new varnodes in the original range
  for(int4 i=0;i<isectlist.size();++i)
    eliminateIntersect(isectlist[i],blocksort);
}

/// \brief Force the merge of \e address \e tried Varnodes
///
/// For each set of address tied Varnodes with the same size and storage address, merge
/// them into a single HighVariable. The merges are \e forced, so any Cover intersections must
/// be resolved by altering data-flow, which involves inserting additional COPY ops and
/// \e unique Varnodes.
void Merge::mergeAddrTied(void)

{
  bool addrtied;
  VarnodeLocSet::const_iterator startiter,enditer,iter;
  for(startiter=data.beginLoc();startiter!=data.endLoc();) {
    addrtied = false;
    enditer = data.endLoc((*startiter)->getSize(),(*startiter)->getAddr(),Varnode::written);
    for(iter=startiter;iter!=enditer;++iter) {
      if ((*iter)->isAddrTied()) {
	addrtied = true;
	break;
      }
    }
    if (addrtied) {
      unifyAddress(startiter,enditer); // unify_address may stick varnodes in our range
      enditer = data.endLoc((*startiter)->getSize(),(*startiter)->getAddr(),Varnode::written);
      mergeRangeMust(startiter,enditer);
    }
    startiter = data.endLoc((*startiter)->getSize(),(*startiter)->getAddr(),0);
  }
}

/// \brief Trim the output HighVariable of the given PcodeOp so that its Cover is tiny
///
/// The given PcodeOp is assumed to force merging so that input and output Covers shouldn't
/// intersect. The original PcodeOp output is \e moved so that it becomes the output of a new
/// COPY, disassociating the original output Varnode from the inputs.
/// \param op is the given PcodeOp
void Merge::trimOpOutput(PcodeOp *op)

{
  PcodeOp *copyop;
  Varnode *uniq,*vn;
  PcodeOp *afterop;
  
  if (op->code() == CPUI_INDIRECT)
    afterop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr()); // Insert copyop AFTER source of indirect
  else
    afterop = op;
  vn = op->getOut();
  uniq = data.newUnique(vn->getSize(),vn->getType());
  copyop = data.newOp(1,op->getAddr());
  data.opSetOutput(op,uniq);	// Output of op is now stubby uniq
  data.opSetOpcode(copyop,CPUI_COPY);
  data.opSetOutput(copyop,vn);	// Original output is bumped forward slightly
  data.opSetInput(copyop,uniq,0);
  data.opInsertAfter(copyop,afterop);
}
  
/// \brief Trim the input HighVariable of the given PcodeOp so that its Cover is tiny
///
/// The given PcodeOp is assumed to force merging so that input and output Covers shouldn't
/// intersect. A new COPY is inserted right before the given PcodeOp with a new
/// \e unique output that replaces the specified input, disassociating it from the
/// other original inputs and output.
/// \param op is the given PcodeOp
/// \param slot is the specified slot of the input Varnode to be trimmed
void Merge::trimOpInput(PcodeOp *op,int4 slot)

{
  PcodeOp *copyop;
  Varnode *vn;
  Address pc;
  
  if (op->code() == CPUI_MULTIEQUAL) {
    BlockBasic *bb = (BlockBasic *)op->getParent()->getIn(slot);
    pc = bb->getStop();
  }
  else
    pc = op->getAddr();
  vn = op->getIn(slot);
  copyop = allocateCopyTrim(vn, vn->getType(), pc);
  data.opSetInput(op,copyop->getOut(),slot);
  if (op->code() == CPUI_MULTIEQUAL)
    data.opInsertEnd(copyop,(BlockBasic *)op->getParent()->getIn(slot));
  else
    data.opInsertBefore(copyop,op);
}

/// \brief Force the merge of all input and output Varnodes for the given PcodeOp
///
/// Data-flow for specific input and output Varnodes are \e snipped until everything
/// can be merged.
/// \param op is the given PcodeOp
void Merge::mergeOp(PcodeOp *op)

{
  vector<HighVariable *> testlist;
  HighVariable *high_out;
  int4 i,nexttrim,max;

  max = (op->code() == CPUI_INDIRECT) ? 1 : op->numInput();
  high_out = op->getOut()->getHigh();
				// First try to deal with non-cover related merge
				// restrictions
  for(i=0;i<max;++i) {
    HighVariable *high_in = op->getIn(i)->getHigh();
    if (!mergeTestRequired(high_out,high_in)) {
      trimOpInput(op,i);
      continue;
    }
    for(int4 j=0;j<i;++j)
      if (!mergeTestRequired(op->getIn(j)->getHigh(),high_in)) {
	trimOpInput(op,i);
	break;
      }
  }
				// Now test if a merge violates cover restrictions
  mergeTest(high_out,testlist);
  for(i=0;i<max;++i)
    if (!mergeTest(op->getIn(i)->getHigh(),testlist)) break;

  if (i != max) {		// If there are cover restrictions
    nexttrim = 0;
    while(nexttrim < max) {
      trimOpInput(op,nexttrim); // Trim one of the branches
      testlist.clear();
				// Try the merge restriction test again
      mergeTest(high_out,testlist);
      for(i=0;i<max;++i)
	if (!mergeTest(op->getIn(i)->getHigh(),testlist)) break;
      if (i==max) break; // We successfully test merged everything
      nexttrim += 1;
    }
    if (nexttrim == max)	// One last trim we can try
      trimOpOutput(op);
  }

  for(i=0;i<max;++i) {		// Try to merge everything for real now
    if (!mergeTestRequired(op->getOut()->getHigh(),op->getIn(i)->getHigh()))
      throw LowlevelError("Non-cover related merge restriction violated, despite trims");
    if (!merge(op->getOut()->getHigh(),op->getIn(i)->getHigh(),false)) {
      ostringstream errstr;
      errstr << "Unable to force merge of op at " << op->getSeqNum();
      throw LowlevelError(errstr.str());
    }
  }
}

/// \brief Collect all instances of the given HighVariable whose Cover intersects a p-code op
///
/// Efficiently test if each instance Varnodes contains the specific p-code op in its Cover
/// and return a list of the instances that do.
/// \param vlist will hold the resulting list of intersecting instances
/// \param high is the given HighVariable
/// \param op is the specific PcodeOp to test intersection with
void Merge::collectCovering(vector<Varnode *> &vlist,HighVariable *high,PcodeOp *op)

{
  int4 blk = op->getParent()->getIndex();
  for(int4 i=0;i<high->numInstances();++i) {
    Varnode *vn = high->getInstance(i);
    if (vn->getCover()->getCoverBlock(blk).contain(op))
      vlist.push_back(vn);
  }
}

/// \brief Check for for p-code op intersections that are correctable
///
/// Given a list of Varnodes that intersect a specific PcodeOp, check that each intersection is
/// on the boundary, and if so, pass back the \e read op(s) that cause the intersection.
/// \param vlist is the given list of intersecting Varnodes
/// \param oplist will hold the boundary intersecting \e read ops
/// \param slotlist will hold the corresponding input slots of the instance
/// \param op is the specific intersecting PcodeOp
/// \return \b false if any instance in the list intersects the PcodeOp on the interior
bool Merge::collectCorrectable(const vector<Varnode *> &vlist,list<PcodeOp *> &oplist,
			       vector<int4> &slotlist,PcodeOp *op)
{
  int4 blk = op->getParent()->getIndex();
  vector<Varnode *>::const_iterator viter;
  list<PcodeOp *>::const_iterator oiter;
  Varnode *vn;
  PcodeOp *edgeop;
  int4 slot,bound;
  uintm opuindex = CoverBlock::getUIndex(op);

  for(viter=vlist.begin();viter!=vlist.end();++viter) {
    vn = *viter;
    bound = vn->getCover()->getCoverBlock(blk).boundary(op);
    if (bound == 0) return false;
    if (bound == 2) continue;	// Not defined before op (intersects with write op)
    for(oiter=vn->beginDescend();oiter!=vn->endDescend();++oiter) {
      edgeop = *oiter;
      if (CoverBlock::getUIndex(edgeop) == opuindex) { // Correctable
	oplist.push_back(edgeop);
	slot = edgeop->getSlot(vn);
	slotlist.push_back(slot);
      }
    }
  }
  return true;
}

/// \brief Snip instances of the input of an INDIRECT op that interfere with its output
///
/// Examine the input and output HighVariable for the given INDIRECT op.
/// Varnode instances of the input that intersect the output Cover are snipped by creating
/// a new COPY op from the input to a new temporary and then replacing the Varnode reads
/// with the temporary.
/// \param indop is the given INDIRECT op
void Merge::snipIndirect(PcodeOp *indop)

{
  PcodeOp *op = PcodeOp::getOpFromConst(indop->getIn(1)->getAddr()); // Indirect effect op
  vector<Varnode *> problemvn;
  list<PcodeOp *> correctable;
  vector<int4> correctslot;
				// Collect instances of output->high that are defined
				// before (and right up to) op. These need to be snipped.
  collectCovering(problemvn,indop->getOut()->getHigh(),op);
  if (problemvn.empty()) return;
				// Collect vn reads where the snip needs to be.
				// If cover properly contains op, report an error.
				// This should not be possible as that vn would have
				// to intersect with indop->output, which it is merged with.
  if (!collectCorrectable(problemvn,correctable,correctslot,op))
    throw LowlevelError("Unable to force indirect merge");

  if (correctable.empty()) return;
  Varnode *refvn = correctable.front()->getIn(correctslot[0]);
  PcodeOp *snipop,*insertop;

				// NOTE: the covers for any input to op which is
				// an instance of the output high must
				// all intersect so the varnodes must all be
				// traceable via COPY to the same root
  snipop = allocateCopyTrim(refvn, refvn->getType(), op->getAddr());
  data.opInsertBefore(snipop,op);
  list<PcodeOp *>::iterator oiter;
  int4 i,slot;
  for(oiter=correctable.begin(),i=0;i<correctslot.size();++oiter,++i) {
    insertop = *oiter;
    slot = correctslot[i];
    data.opSetInput(insertop,snipop->getOut(),slot);
  }
}

/// \brief Force the merge of all input and output Varnodes to a given INDIRECT op
///
/// Merging INDIRECTs take a little care if their output is address forced because by convention
/// the value must be present at the address BEFORE the indirect effect operation takes place.
/// \param indop is the given INDIRECT
void Merge::mergeIndirect(PcodeOp *indop)

{
  Varnode *outvn = indop->getOut();
  Varnode *invn0 = indop->getIn(0);
  if (!outvn->isAddrForce()) {	// If the output is NOT address forced
    mergeOp(indop);		// We can merge in the same way as a MULTIEQUAL
    return;
  }

  if (mergeTestRequired(outvn->getHigh(),invn0->getHigh()))
    if (merge(invn0->getHigh(),outvn->getHigh(),false)) return;
  snipIndirect(indop);		// If we cannot merge, the only thing that can go
				// wrong with an input trim, is if the output of
				// indop is involved in the input to the op causing
				// the indirect effect. So fix this

  PcodeOp *newop;

  newop = allocateCopyTrim(invn0, outvn->getType(), indop->getAddr());
  data.opSetInput(indop,newop->getOut(),0);
  data.opInsertBefore(newop,indop);
  if (!mergeTestRequired(outvn->getHigh(),indop->getIn(0)->getHigh()) ||
      (!merge(indop->getIn(0)->getHigh(),outvn->getHigh(),false))) // Try merge again
    //  if (!merge(indop->Input(0)->High(),outvn->High()))
    throw LowlevelError("Unable to merge address forced indirect");
}

/// \brief Force the merge of input and output Varnodes to MULTIEQUAL and INDIRECT ops
///
/// Run through all MULTIEQUAL and INDIRECT ops in the function. Force the merge of each
/// input Varnode with the output Varnode, doing data-flow modification if necessary to
/// resolve Cover intersections.
void Merge::mergeMarker(void)

{
  PcodeOp *op;
  list<PcodeOp *>::const_iterator iter;
  for(iter=data.beginOpAlive();iter!=data.endOpAlive();++iter) {
    op = *iter;
    if ((!op->isMarker())||op->isIndirectCreation()) continue;
    if (op->code() == CPUI_INDIRECT)
      mergeIndirect(op);
    else
      mergeOp(op);
  }
}

/// \brief Merge together Varnodes mapped to SymbolEntrys from the same Symbol
///
/// Symbols that have more than one SymbolEntry may attach to more than one Varnode.
/// These Varnodes need to be merged to properly represent a single variable.
void Merge::mergeMultiEntry(void)

{
  SymbolNameTree::const_iterator iter = data.getScopeLocal()->beginMultiEntry();
  SymbolNameTree::const_iterator enditer = data.getScopeLocal()->endMultiEntry();
  for(;iter!=enditer;++iter) {
    vector<Varnode *> mergeList;
    Symbol *symbol = *iter;
    int4 numEntries = symbol->numEntries();
    int4 mergeCount = 0;
    int4 skipCount = 0;
    int4 conflictCount = 0;
    for(int4 i=0;i<numEntries;++i) {
      int4 prevSize = mergeList.size();
      SymbolEntry *entry = symbol->getMapEntry(i);
      if (entry->getSize() != symbol->getType()->getSize())
	continue;
      data.findLinkedVarnodes(entry, mergeList);
      if (mergeList.size() == prevSize)
	skipCount += 1;		// Did not discover any Varnodes corresponding to a particular SymbolEntry
    }
    if (mergeList.empty()) continue;
    HighVariable *high = mergeList[0]->getHigh();
    updateHigh(high);
    for(int4 i=0;i<mergeList.size();++i) {
      HighVariable *newHigh = mergeList[i]->getHigh();
      if (newHigh == high) continue;		// Varnodes already merged
      updateHigh(newHigh);
      if (!mergeTestRequired(high, newHigh)) {
	symbol->setMergeProblems();
	newHigh->setUnmerged();
	conflictCount += 1;
	continue;
      }
      if (!merge(high,newHigh,false)) {		// Attempt the merge
	symbol->setMergeProblems();
	newHigh->setUnmerged();
	conflictCount += 1;
	continue;
      }
      mergeCount += 1;
    }
    if (skipCount != 0 || conflictCount !=0) {
      ostringstream s;
      s << "Unable to";
      if (mergeCount != 0)
	s << " fully";
      s << " merge symbol: " << symbol->getName();
      if (skipCount > 0)
	s << " -- Some instance varnodes not found.";
      if (conflictCount > 0)
	s << " -- Some merges are forbidden";
      data.warningHeader(s.str());
    }
  }
}

/// \brief Speculatively merge Varnodes that are input/output to the same p-code op
///
/// If a single p-code op has an input and output HighVariable that share the same data-type,
/// attempt to merge them. Each merge is speculative and is skipped if it would introduce Cover
/// intersections.
void Merge::mergeAdjacent(void)

{
  list<PcodeOp *>::const_iterator oiter;
  PcodeOp *op;
  int4 i;
  HighVariable *high_in,*high_out;
  Varnode *vn1,*vn2;
  const Datatype *ct;

  for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) {
    op = *oiter;
    if (op->isCall()) continue;
    vn1 = op->getOut();
    if (!mergeTestBasic(vn1)) continue;
    high_out = vn1->getHigh();
    ct = op->outputTypeLocal();
    for(i=0;i<op->numInput();++i) {
      if (ct != op->inputTypeLocal(i)) continue; // Only merge if types should be the same
      vn2 = op->getIn(i);
      if (!mergeTestBasic(vn2)) continue;
      if (vn1->getSize() != vn2->getSize()) continue;
      if ((vn2->getDef()==(PcodeOp *)0)&&(!vn2->isInput())) continue;
      high_in = vn2->getHigh();
      if (!mergeTestAdjacent(high_out,high_in)) continue;

      if (!intersection(high_in,high_out)) // If no interval intersection
	merge(high_out,high_in,true);
    }
  }
}

/// \brief Find instance Varnodes that copied to from outside the given HighVariable
///
/// Find all Varnodes in the HighVariable which are defined by a COPY from another
/// Varnode which is \e not part of the same HighVariable.
/// \param high is the given HighVariable
/// \param singlelist will hold the resulting list of copied instances
void Merge::findSingleCopy(HighVariable *high,vector<Varnode *> &singlelist)

{
  int4 i;
  Varnode *vn;
  PcodeOp *op;

  for(i=0;i<high->numInstances();++i) {
    vn = high->getInstance(i);
    if (!vn->isWritten()) continue;
    op = vn->getDef();
    if (op->code() != CPUI_COPY) continue; // vn must be defineed by copy
    if (op->getIn(0)->getHigh() == high) continue;	// From something NOT in same high
    singlelist.push_back(vn);
  }
}

/// \brief Compare COPY ops first by Varnode input, then by block containing the op
///
/// A sort designed to group COPY ops from the same Varnode together. Then within a group,
/// COPYs are sorted by their containing basic block (so that dominating ops come first).
/// \param op1 is the first PcodeOp being compared
/// \param op2 is the second PcodeOp being compared
/// \return \b true if the first PcodeOp should be ordered before the second
bool Merge::compareCopyByInVarnode(PcodeOp *op1,PcodeOp *op2)

{
  Varnode *inVn1 = op1->getIn(0);
  Varnode *inVn2 = op2->getIn(0);
  if (inVn1 != inVn2)		// First compare by Varnode inputs
    return (inVn1->getCreateIndex() < inVn2->getCreateIndex());
  int4 index1 = op1->getParent()->getIndex();
  int4 index2 = op2->getParent()->getIndex();
  if (index1 != index2)
    return (index1 < index2);
  return (op1->getSeqNum().getOrder() < op2->getSeqNum().getOrder());
}

/// \brief Hide \e shadow Varnodes related to the given HighVariable by consolidating COPY chains
///
/// If two Varnodes are copied from the same common ancestor then they will always contain the
/// same value and can be considered \b shadows of the same variable.  If the paths from the
/// ancestor to the two Varnodes aren't properly nested, the two Varnodes will still look like
/// distinct variables.  This routine searches for this situation, relative to a single
/// HighVariable, and alters data-flow so that copying from ancestor to first Varnode to
/// second Varnode becomes a single path. Both Varnodes then ultimately become instances of the
/// same HighVariable.
/// \param high is the given HighVariable to search near
/// \return \b true if a change was made to data-flow
bool Merge::hideShadows(HighVariable *high)

{
  vector<Varnode *> singlelist;
  Varnode *vn1,*vn2;
  int4 i,j;
  bool res = false;
  
  findSingleCopy(high,singlelist); // Find all things copied into this high
  if (singlelist.size() <= 1) return false;
  for(i=0;i<singlelist.size()-1;++i) {
    vn1 = singlelist[i];
    if (vn1 == (Varnode *)0) continue;
    for(j=i+1;j<singlelist.size();++j) {
      vn2 = singlelist[j];
      if (vn2 == (Varnode *)0) continue;
      if (!vn1->copyShadow(vn2)) continue;
      if (vn2->getCover()->containVarnodeDef(vn1)==1) {
	data.opSetInput(vn1->getDef(),vn2,0);
	res = true;
	break;
      }
      else if (vn1->getCover()->containVarnodeDef(vn2)==1) {
	data.opSetInput(vn2->getDef(),vn1,0);
	singlelist[j] = (Varnode *)0;
	res = true;
      }
    }
  }
  return res;
}

/// \brief Check if the given PcodeOp COPYs are redundant
///
/// Both the given COPYs assign to the same HighVariable. One is redundant if there is no other
/// assignment to the HighVariable between the first COPY and the second COPY.
/// The first COPY must come from a block with a smaller or equal index to the second COPY.
/// If the indices are equal, the first COPY must come before the second within the block.
/// \param high is the HighVariable being assigned to
/// \param domOp is the first COPY
/// \param subOp is the second COPY
/// \return \b true if the second COPY is redundant
bool Merge::checkCopyPair(HighVariable *high,PcodeOp *domOp,PcodeOp *subOp)

{
  FlowBlock *domBlock = domOp->getParent();
  FlowBlock *subBlock = subOp->getParent();
  if (!domBlock->dominates(subBlock))
    return false;
  Cover range;
  range.addDefPoint(domOp->getOut());
  range.addRefPoint(subOp,subOp->getIn(0));
  Varnode *inVn = domOp->getIn(0);
  // Look for high Varnodes in the range
  for(int4 i=0;i<high->numInstances();++i) {
    Varnode *vn = high->getInstance(i);
    if (!vn->isWritten()) continue;
    PcodeOp *op = vn->getDef();
    if (op->code() == CPUI_COPY) {		// If the write is not a COPY
      if (op->getIn(0) == inVn) continue;	// from the same Varnode as domOp and subOp
    }
    if (range.contain(op, 1)) {			// and if write is contained in range between domOp and subOp
      return false;				// it is intervening and subOp is not redundant
    }
  }
  return true;
}

/// \brief Try to replace a set of COPYs from the same Varnode with a single dominant COPY
///
/// All the COPY outputs must be instances of the same HighVariable (not the same Varnode).
/// Either an existing COPY dominates all the others, or a new dominating COPY is constructed.
/// The read locations of all other COPY outputs are replaced with the output of the dominating
/// COPY, if it does not cause intersections in the HighVariable's Cover. Because of
/// intersections, replacement may fail or partially succeed. Replacement only happens with
/// COPY outputs that are temporary registers. The cover of the HighVariable may be extended
/// because of a new COPY output instance.
/// \param high is the HighVariable being copied to
/// \param copy is the list of COPY ops into the HighVariable
/// \param pos is the index of the first COPY from the specific input Varnode
/// \param size is the number of COPYs (in sequence) from the same specific Varnode
void Merge::buildDominantCopy(HighVariable *high,vector<PcodeOp *> &copy,int4 pos,int4 size)

{
  vector<FlowBlock *> blockSet;
  for(int4 i=0;i<size;++i)
    blockSet.push_back(copy[pos+i]->getParent());
  BlockBasic *domBl = (BlockBasic *)FlowBlock::findCommonBlock(blockSet);
  Varnode *rootVn = copy[pos]->getIn(0);
  bool domCopyIsNew;
  PcodeOp *domCopy;
  Varnode *domVn;
  if (domBl == copy[pos]->getParent()) {
    domCopyIsNew = false;
    domCopy = copy[pos];
    domVn = domCopy->getOut();
  }
  else {
    domCopyIsNew = true;
    domCopy = data.newOp(1,domBl->getStop());
    data.opSetOpcode(domCopy, CPUI_COPY);
    domVn = data.newUnique(rootVn->getSize(), rootVn->getType());
    data.opSetOutput(domCopy,domVn);
    data.opSetInput(domCopy,rootVn,0);
    data.opInsertEnd(domCopy, domBl);
  }
  // Cover created by removing all the COPYs from rootVn
  Cover bCover;
  for(int4 i=0;i<high->numInstances();++i) {
    Varnode *vn = high->getInstance(i);
    if (vn->isWritten()) {
      PcodeOp *op = vn->getDef();
      if (op->code() == CPUI_COPY) {
	if (op->getIn(0)->copyShadow(rootVn)) continue;
      }
    }
    bCover.merge(*vn->getCover());
  }

  int4 count = size;
  for(int4 i=0;i<size;++i) {
    PcodeOp *op = copy[pos+i];
    if (op == domCopy) continue;	// No intersections from domVn already proven
    Varnode *outVn = op->getOut();
    list<PcodeOp *>::const_iterator iter;
    Cover aCover;
    aCover.addDefPoint(domVn);
    for(iter=outVn->beginDescend();iter!=outVn->endDescend();++iter)
      aCover.addRefPoint(*iter, outVn);
    if (bCover.intersect(aCover)>1) {
      count -= 1;
      op->setMark();
    }
  }

  if (count <= 1) {	// Don't bother if we only replace one COPY with another
    for (int4 i = 0; i < size; ++i)
      copy[pos + i]->setMark();
    count = 0;
    if (domCopyIsNew) {
      data.opDestroy(domCopy);
    }
  }
  // Replace all non-intersecting COPYs with read of dominating Varnode
  for(int4 i=0;i<size;++i) {
    PcodeOp *op = copy[pos+i];
    if (op->isMark())
      op->clearMark();
    else {
      Varnode *outVn = op->getOut();
      if (outVn != domVn) {
	outVn->getHigh()->remove(outVn);
	data.totalReplace(outVn, domVn);
	data.opDestroy(op);
      }
    }
  }
  if (count > 0 && domCopyIsNew) {
    high->merge(domVn->getHigh(),true);
  }
}

/// \brief Search for and mark redundant COPY ops into the given high as \e non-printing
///
/// Trimming during the merge process can insert multiple COPYs from the same source. In some
/// cases, one or more COPYs may be redundant and shouldn't be printed. This method searches
/// for redundancy among COPY ops that assign to the given HighVariable.
/// \param high is the given HighVariable
/// \param copy is the list of COPYs coming from the same source HighVariable
/// \param pos is the starting index of a set of COPYs coming from the same Varnode
/// \param size is the number of Varnodes in the set coming from the same Varnode
void Merge::markRedundantCopies(HighVariable *high,vector<PcodeOp *> &copy,int4 pos,int4 size)

{
  for (int4 i = size - 1; i > 0; --i) {
    PcodeOp *subOp = copy[pos + i];
    if (subOp->isDead()) continue;
    for (int4 j = i - 1; j >= 0; --j) {
      // Make sure earlier index provides dominant op
      PcodeOp *domOp = copy[pos + j];
      if (domOp->isDead()) continue;
      if (checkCopyPair(high, domOp, subOp)) {
	data.opMarkNonPrinting(subOp);
	break;
      }
    }
  }
}

/// \brief Determine if given Varnode is shadowed by another Varnode in the same HighVariable
///
/// \param vn is the Varnode to check for shadowing
/// \return \b true if \b vn is shadowed by another Varnode in its high-level variable
bool Merge::shadowedVarnode(const Varnode *vn)

{
  const Varnode *othervn;
  const HighVariable *high = vn->getHigh();
  int4 num,i;

  num = high->numInstances();
  for(i=0;i<num;++i) {
    othervn = high->getInstance(i);
    if (othervn == vn) continue;
    if (vn->getCover()->intersect(*othervn->getCover()) == 2) return true;
  }
  return false;
}

/// \brief  Find all the COPY ops into the given HighVariable
///
/// Collect all the COPYs whose output is the given HighVariable but
/// the input is from a different HighVariable. Returned COPYs are sorted
/// first by the input Varnode then by block order.
/// \param high is the given HighVariable
/// \param copyIns will hold the list of COPYs
/// \param filterTemps is \b true if COPYs must have a temporary output
void Merge::findAllIntoCopies(HighVariable *high,vector<PcodeOp *> &copyIns,bool filterTemps)

{
  for(int4 i=0;i<high->numInstances();++i) {
    Varnode *vn = high->getInstance(i);
    if (!vn->isWritten()) continue;
    PcodeOp *op = vn->getDef();
    if (op->code() != CPUI_COPY) continue;
    if (op->getIn(0)->getHigh() == high) continue;
    if (filterTemps && op->getOut()->getSpace()->getType() != IPTR_INTERNAL) continue;
    copyIns.push_back(op);
  }
  // Group COPYs based on the incoming Varnode then block order
  sort(copyIns.begin(),copyIns.end(),compareCopyByInVarnode);
}

/// \brief Try to replace COPYs into the given HighVariable with a single dominant COPY
///
/// Find groups of COPYs into the given HighVariable that come from a single source Varnode,
/// then try to replace them with a COPY.
/// \param high is the given HighVariable
void Merge::processHighDominantCopy(HighVariable *high)

{
  vector<PcodeOp *> copyIns;

  findAllIntoCopies(high,copyIns,true);	// Get all COPYs into this with temporary output
  if (copyIns.size() < 2) return;
  int4 pos = 0;
  while(pos < copyIns.size()) {
    // Find a group of COPYs coming from the same Varnode
    Varnode *inVn = copyIns[pos]->getIn(0);
    int4 sz = 1;
    while(pos + sz < copyIns.size()) {
      Varnode *nextVn = copyIns[pos+sz]->getIn(0);
      if (nextVn != inVn) break;
      sz += 1;
    }
    if (sz > 1)		// If there is more than one COPY in a group
      buildDominantCopy(high, copyIns, pos, sz);	// Try to construct a dominant COPY
    pos += sz;
  }
}

/// \brief Mark COPY ops into the given HighVariable that are redundant
///
/// A COPY is redundant if another COPY performs the same action and has
/// dominant control flow. The redundant COPY is not removed but is marked so that
/// it doesn't print in the final source output.
/// \param high is the given HighVariable
void Merge::processHighRedundantCopy(HighVariable *high)

{
  vector<PcodeOp *> copyIns;

  findAllIntoCopies(high,copyIns,false);
  if (copyIns.size() < 2) return;
  int4 pos = 0;
  while(pos < copyIns.size()) {
    // Find a group of COPYs coming from the same Varnode
    Varnode *inVn = copyIns[pos]->getIn(0);
    int4 sz = 1;
    while(pos + sz < copyIns.size()) {
      Varnode *nextVn = copyIns[pos+sz]->getIn(0);
      if (nextVn != inVn) break;
      sz += 1;
    }
    if (sz > 1) {	// If there is more than one COPY in a group
      markRedundantCopies(high, copyIns, pos, sz);
    }
    pos += sz;
  }
}

/// \brief Try to reduce/eliminate COPYs produced by the merge trimming process
///
/// In order to force merging of certain Varnodes, extra COPY operations may be inserted
/// to reduce their Cover ranges, and multiple COPYs from the same Varnode can be created this way.
/// This method collects sets of COPYs generated in this way that have the same input Varnode
/// and then tries to replace the COPYs with fewer or a single COPY.
void Merge::processCopyTrims(void)

{
  vector<HighVariable *> multiCopy;

  for(int4 i=0;i<copyTrims.size();++i) {
    HighVariable *high = copyTrims[i]->getOut()->getHigh();
    if (!high->hasCopyIn1()) {
      multiCopy.push_back(high);
      high->setCopyIn1();
    }
    else
      high->setCopyIn2();
  }
  copyTrims.clear();
  for(int4 i=0;i<multiCopy.size();++i) {
    HighVariable *high = multiCopy[i];
    if (high->hasCopyIn2())		// If the high has at least 2 COPYs into it
      processHighDominantCopy(high);	// Try to replace with a dominant copy
    high->clearCopyIns();
  }
}

/// \brief Mark redundant/internal COPY PcodeOps
///
/// Run through all COPY, SUBPIECE, and PIECE operations (PcodeOps that copy data) and
/// characterize those that are \e internal (copy data between storage locations representing
/// the same variable) or \e redundant (perform the same copy as an earlier operation).
/// These, as a result, are not printed in the final source code representation.
void Merge::markInternalCopies(void)

{
  vector<HighVariable *> multiCopy;
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  HighVariable *h1,*h2,*h3;
  Varnode *v1,*v2,*v3;
  int4 val;

  for(iter=data.beginOpAlive();iter!=data.endOpAlive();++iter) {
    op = *iter;
    switch(op->code()) {
    case CPUI_COPY:
      v1 = op->getOut();
      h1 = v1->getHigh();
      if (h1 == op->getIn(0)->getHigh()) {
	data.opMarkNonPrinting(op);
      }
      else {	// COPY between different HighVariables
	if (!h1->hasCopyIn1()) {	// If this is the first COPY we've seen for this high
	  h1->setCopyIn1();		// Mark it
	  multiCopy.push_back(h1);
	}
	else
	  h1->setCopyIn2();		// This is at least the second COPY we've seen
	if (v1->hasNoDescend()) {	// Don't print shadow assignments
	  if (shadowedVarnode(v1)) {
	    data.opMarkNonPrinting(op);
	  }
	}
      }
      break;
    case CPUI_PIECE:		// Check if output is built out of pieces of itself
      h1 = op->getOut()->getHigh();
      h2 = op->getIn(0)->getHigh();
      h3 = op->getIn(1)->getHigh();
      if (!h1->isAddrTied()) break;
      if (!h2->isAddrTied()) break;
      if (!h3->isAddrTied()) break;
      v1 = h1->getTiedVarnode();
      v2 = h2->getTiedVarnode();
      v3 = h3->getTiedVarnode();
      if (v3->overlap(*v1) != 0) break;
      if (v2->overlap(*v1) != v3->getSize()) break;
      data.opMarkNonPrinting(op);
      break;
    case CPUI_SUBPIECE:
      h1 = op->getOut()->getHigh();
      h2 = op->getIn(0)->getHigh();
      if (!h1->isAddrTied()) break;
      if (!h2->isAddrTied()) break;
      v1 = h1->getTiedVarnode();
      v2 = h2->getTiedVarnode();
      val = op->getIn(1)->getOffset();
      if (v1->overlap(*v2) != val) break;
      data.opMarkNonPrinting(op);
      break;
    default:
      break;
    }
  }
  for(int4 i=0;i<multiCopy.size();++i) {
    HighVariable *high = multiCopy[i];
    if (high->hasCopyIn2())
      data.getMerge().processHighRedundantCopy(high);
    high->clearCopyIns();
  }
#ifdef MERGEMULTI_DEBUG
  verifyHighCovers();
#endif
}

/// \brief Perform low-level details of merging two HighVariables if possible
///
/// This routine only fails (returning \b false) if there is a Cover intersection between
/// the two variables. Otherwise, all the Varnode instances from the second HighVariable
/// are merged into the first and its Cover is updated. The cached intersection tests are
/// also updated to reflect the merge.
/// \param high1 is the first HighVariable being merged
/// \param high2 is the second
/// \param isspeculative is \b true if the desired merge is speculative
/// \return \b true if the merge was successful
bool Merge::merge(HighVariable *high1,HighVariable *high2,bool isspeculative)

{
  if (high1 == high2) return true; // Already merged
  if (intersection(high1,high2)) return false;

				// Translate any tests for high2 into tests for high1
  vector<HighVariable *> yesinter;		// Highs that high2 intersects
  vector<HighVariable *> nointer;		// Highs that high2 does not intersect
  map<HighEdge,bool>::iterator iterfirst = highedgemap.lower_bound( HighEdge(high2,(HighVariable *)0) );
  map<HighEdge,bool>::iterator iterlast = highedgemap.lower_bound( HighEdge(high2,(HighVariable *)~((uintp)0)) );
  map<HighEdge,bool>::iterator iter;

  for(iter=iterfirst;iter!=iterlast;++iter) {
    HighVariable *b = (*iter).first.b; 
    if (b == high1) continue;
    if ((*iter).second)		// Save all high2's intersections
      yesinter.push_back(b);	// as they are still valid for the merge
    else {
      nointer.push_back(b);
      b->setMark();		// Mark that high2 did not intersect
    }
  }
				// Do a purge of all high2's tests
  if (iterfirst != iterlast) {	// Delete all the high2 tests
    --iterlast;			// Move back 1 to prevent deleting under the iterator
    for(iter=iterfirst;iter!=iterlast;++iter)
      highedgemap.erase( HighEdge( (*iter).first.b, (*iter).first.a) );
    highedgemap.erase( HighEdge( (*iter).first.b, (*iter).first.a) );
    ++iterlast;			// Restore original range (with possibly new open endpoint)
  
    highedgemap.erase(iterfirst,iterlast);
  }

  iter = highedgemap.lower_bound( HighEdge(high1,(HighVariable *)0) );
  while((iter!=highedgemap.end())&&((*iter).first.a == high1)) {
    if (!(*iter).second) {	// If test is intersection==false
      if (!(*iter).first.b->isMark()) // and there was no test with high2
	highedgemap.erase( iter++ ); // Delete the test
      else
	++iter;
    }
    else			// Keep any intersection==true tests
      ++iter;
  }
  vector<HighVariable *>::iterator titer;
  for(titer=nointer.begin();titer!=nointer.end();++titer)
    (*titer)->clearMark();
				// Reinsert high2's intersection==true tests for high1 now
  for(titer=yesinter.begin();titer!=yesinter.end();++titer) {
    highedgemap[ HighEdge(high1,*titer) ] = true;
    highedgemap[ HighEdge(*titer,high1) ] = true;
  }
  high1->merge(high2,isspeculative);		// Do the actual merge
  high1->updateCover();

  return true;
}

/// As manipulations are made, Cover information gets out of date. A \e dirty flag is used to
/// indicate a particular HighVariable Cover is out-of-date.  This routine checks the \e dirty
/// flag and updates the Cover information if it is set.
/// \param a is the HighVariable to update
/// \return \b true if the HighVariable was not originally dirty
bool Merge::updateHigh(HighVariable *a)

{
  if ((a->highflags&HighVariable::coverdirty)==0) return true;

  for(int4 i=0;i<a->numInstances();++i)
    a->getInstance(i)->updateCover();
  a->updateCover();
  purgeHigh(a);
  return false;
}

/// All tests for pairs where either the first or second HighVariable matches the given one
/// are removed.
/// \param high is the given HighVariable to purge
void Merge::purgeHigh(HighVariable *high)

{
  map<HighEdge,bool>::iterator iterfirst = highedgemap.lower_bound( HighEdge(high,(HighVariable *)0) );
  map<HighEdge,bool>::iterator iterlast = highedgemap.lower_bound( HighEdge(high,(HighVariable *)~((uintp)0)) );

  if (iterfirst == iterlast) return;
  --iterlast;			// Move back 1 to prevent deleting under the iterator
  map<HighEdge,bool>::iterator iter;
  for(iter=iterfirst;iter!=iterlast;++iter)
    highedgemap.erase( HighEdge( (*iter).first.b, (*iter).first.a) );
  highedgemap.erase( HighEdge( (*iter).first.b, (*iter).first.a) );
  ++iterlast;			// Restore original range (with possibly new open endpoint)
  
  highedgemap.erase(iterfirst,iterlast);
}

/// \brief Test the intersection of two HighVariables and cache the result
///
/// If the Covers of the two variables intersect, this routine returns \b true. To avoid
/// expensive computation on the Cover objects themselves, the test result associated with
/// the pair of HighVariables is cached.
/// \param a is the first HighVariable
/// \param b is the second HighVariable
/// \return \b true if the variables intersect
bool Merge::intersection(HighVariable *a,HighVariable *b)
  
{
  if (a==b) return false;
  bool ares = updateHigh(a);
  bool bres = updateHigh(b);
  if (ares && bres) {		// If neither high was dirty
    map<HighEdge,bool>::iterator iter = highedgemap.find( HighEdge(a,b) );
    if (iter != highedgemap.end()) // If previous test is present
      return (*iter).second;	// Use it
  }

  bool res = false;
  int4 blk;
  vector<int4> blockisect;
  a->wholecover.intersectList(blockisect,b->wholecover,2);
  for(blk=0;blk<blockisect.size();++blk) {
    if (blockIntersection(a,b,blockisect[blk])) {
      res = true;
      break;
    }
  }
  highedgemap[ HighEdge(a,b) ] = res; // Cache the result
  highedgemap[ HighEdge(b,a) ] = res;
  return res;
}

/// \brief Test if two HighVariables intersect on a given BlockBasic
///
/// Intersections are checked only on the specified block.
/// \param a is the first HighVariable
/// \param b is the second HighVariable
/// \param blk is the index of the BlockBasic on which to test intersection
/// \return \b true if an intersection occurs in the specified block
bool Merge::blockIntersection(HighVariable *a,HighVariable *b,int4 blk)

{
  vector<Varnode *> blist;

  for(int4 i=0;i<b->numInstances();++i) {
    Varnode *vn = b->getInstance(i);
    if (1<vn->getCover()->intersectByBlock(blk,a->wholecover))
      blist.push_back(vn);
  }
  for(int4 i=0;i<a->numInstances();++i) {
    Varnode *vn = a->getInstance(i);
    if (2>vn->getCover()->intersectByBlock(blk,b->wholecover)) continue;
    for(int4 j=0;j<blist.size();++j) {
      Varnode *vn2 = blist[j];
      if (1<vn2->getCover()->intersectByBlock(blk,*vn->getCover()))
	if (!vn->copyShadow(vn2))
	  return true;
    }
  }
  return false;
}

/// \brief Inflate the Cover of a given Varnode with a HighVariable
///
/// An expression involving a HighVariable can be propagated to all the read sites of the
/// output Varnode of the expression if the Varnode Cover can be \b inflated to include the
/// Cover of the HighVariable, even though the Varnode is not part of the HighVariable.
/// This routine performs the inflation, assuming an intersection test is already performed.
/// \param a is the given Varnode to inflate
/// \param high is the HighVariable to inflate with
void Merge::inflate(Varnode *a,HighVariable *high)

{
  updateHigh(a->getHigh());
  updateHigh(high);
  for(int4 i=0;i<high->numInstances();++i) {
    Varnode *b = high->getInstance(i);
    a->cover->merge(*b->cover);
  }
  a->getHigh()->coverDirty();
}

/// \brief Test if we can inflate the Cover of the given Varnode without incurring intersections
///
/// This routine tests whether an expression involving a HighVariable can be propagated to all
/// the read sites of the output Varnode of the expression. This is possible only if the
/// Varnode Cover can be \b inflated to include the Cover of the HighVariable, even though the
/// Varnode is not part of the HighVariable.
/// \param a is the given Varnode to inflate
/// \param high is the HighVariable being propagated
/// \return \b true if the Varnode can be inflated without intersection
bool Merge::inflateTest(Varnode *a,HighVariable *high)

{
  HighVariable *ahigh = a->getHigh();
  bool res = false;

  updateHigh(high);

  for(int4 i=0;i<ahigh->numInstances();++i) {
    Varnode *b = ahigh->getInstance(i);
    if (b->copyShadow(a)) continue;
    if (2==b->getCover()->intersect( high->wholecover )) {
      res = true;
      break;
    }
  }
  return res;
}

/// \brief Test for intersections between a given HighVariable and a list of other HighVariables
///
/// If there is any Cover intersection between the given HighVariable and one in the list,
/// this routine returns \b false.  Otherwise, the given HighVariable is added to the end of
/// the list and \b true is returned.
/// \param high is the given HighVariable
/// \param tmplist is the list of HighVariables to test against
/// \return \b true if there are no pairwise intersections.
bool Merge::mergeTest(HighVariable *high,vector<HighVariable *> &tmplist)

{
  if (!high->hasCover()) return false;

  for(int4 i=0;i<tmplist.size();++i) {
    HighVariable *a = tmplist[i];
    if (intersection(a,high))
      return false;
  }
  tmplist.push_back(high);
  return true;
}

#ifdef MERGEMULTI_DEBUG
/// \brief Check that all HighVariable covers are consistent
///
/// For each HighVariable make sure there are no internal intersections between
/// its instance Varnodes (unless one is a COPY shadow of the other).
void Merge::verifyHighCovers(void)

{
  VarnodeLocSet::const_iterator iter,enditer;

  enditer = data.endLoc();
  for(iter=data.beginLoc();iter!=enditer;++iter) {
    Varnode *vn = *iter;
    if (vn->hasCover()) {
      HighVariable *high = vn->getHigh();
      if (!high->hasCopyIn1()) {
	high->setCopyIn1();
	high->verifyCover();
      }
    }
  }
}
#endif

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
#include "double.hh"

SplitVarnode::SplitVarnode(int4 sz,uintb v)

{				// Construct a double precision constant
  val = v;
  wholesize = sz;
  lo = (Varnode *)0;
  hi = (Varnode *)0;
  whole = (Varnode *)0;
  defpoint = (PcodeOp *)0;
  defblock = (BlockBasic *)0;
}

void SplitVarnode::initPartial(int4 sz,uintb v)

{
  val = v;
  wholesize = sz;
  lo = (Varnode *)0;
  hi = (Varnode *)0;
  whole = (Varnode *)0;
  defpoint = (PcodeOp *)0;
  defblock = (BlockBasic *)0;
}

void SplitVarnode::initPartial(Varnode *l,Varnode *h)

{				// Construct a virtual double precision varnode
  if (h == (Varnode *)0) {	// hi is an implied zero
    wholesize = l->getSize();
    val = l->getOffset();	// Assume l is a constant
    lo = (Varnode *)0;
    hi = (Varnode *)0;
  }
  else {
    wholesize = l->getSize() + h->getSize();
    if (l->isConstant() && h->isConstant()) {
      val = h->getOffset();
      val <<= (l->getSize()*8);
      val |= l->getOffset();
      lo = (Varnode *)0;
      hi = (Varnode *)0;
    }
    else {
      lo = l;
      hi = h;
    }
  }
  whole = (Varnode *)0;
  defpoint = (PcodeOp *)0;
  defblock = (BlockBasic *)0;
}

void SplitVarnode::initAll(Varnode *w,Varnode *l,Varnode *h)

{				// A double precision varnode, with an existing whole and pieces
  wholesize = w->getSize();
  lo = l;
  hi = h;
  whole = w;
  defpoint = (PcodeOp *)0;
  defblock = (BlockBasic *)0;
}

bool SplitVarnode::inHandHi(Varnode *h)

{ // Initialize the SplitVarnode with the lo and hi, if we know that -h- is a high precision piece
  // and we know its companion low precision piece, otherwise return false
  if (!h->isPrecisHi()) return false; // Check for mark, in order to have quick -false- in most cases
  // Search for the companion
  if (h->isWritten()) {
    PcodeOp *op = h->getDef();
    // We could check for double loads here
    if (op->code() == CPUI_SUBPIECE) {
      Varnode *w = op->getIn(0);
      if (op->getIn(1)->getOffset() != (uintb)(w->getSize()-h->getSize())) return false;
      list<PcodeOp *>::const_iterator iter,enditer;
      iter = w->beginDescend();
      enditer = w->endDescend();
      while(iter != enditer) {
	PcodeOp *tmpop = *iter;
	++iter;
	if (tmpop->code() != CPUI_SUBPIECE) continue;
	Varnode *tmplo = tmpop->getOut();
	if (!tmplo->isPrecisLo()) continue;
	if (tmplo->getSize() + h->getSize() != w->getSize()) continue;
	if (tmpop->getIn(1)->getOffset() != 0) continue;
	// There could conceivably be more than one, but this shouldn't happen with CSE
	initAll(w,tmplo,h);
	return true;
      }
    }
  }
  return false;
}

bool SplitVarnode::inHandLo(Varnode *l)

{ // Initialize the SplitVarnode with the lo and hi, if we know that -l- is a low precision piece
  // and we know its companion high precision piece, otherwise return false
  if (!l->isPrecisLo()) return false; // Check for mark, in order to have quick -false- in most cases
  // Search for the companion
  if (l->isWritten()) {
    PcodeOp *op = l->getDef();
    // We could check for double loads here
    if (op->code() == CPUI_SUBPIECE) {
      Varnode *w = op->getIn(0);
      if (op->getIn(1)->getOffset() != 0) return false;
      list<PcodeOp *>::const_iterator iter,enditer;
      iter = w->beginDescend();
      enditer = w->endDescend();
      while(iter != enditer) {
	PcodeOp *tmpop = *iter;
	++iter;
	if (tmpop->code() != CPUI_SUBPIECE) continue;
	Varnode *tmphi = tmpop->getOut();
	if (!tmphi->isPrecisHi()) continue;
	if (tmphi->getSize() + l->getSize() != w->getSize()) continue;
	if (tmpop->getIn(1)->getOffset() != (uintb)l->getSize()) continue;
	// There could conceivably be more than one, but this shouldn't happen with CSE
	initAll(w,l,tmphi);
	return true;
      }
    }
  }
  return false;
}

bool SplitVarnode::inHandLoNoHi(Varnode *l)

{ // Initialize the SplitVarnode with lo and the whole it came from, if possible return true;
  // Fill in the hi if it exists, otherwise leave as null
  if (!l->isPrecisLo()) return false;
  if (!l->isWritten()) return false;
  PcodeOp *op = l->getDef();
  if (op->code() != CPUI_SUBPIECE) return false;
  if (op->getIn(1)->getOffset() != 0) return false;
  Varnode *w = op->getIn(0);

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = w->beginDescend();
  enditer = w->endDescend();
  while(iter != enditer) {
    PcodeOp *tmpop = *iter;
    ++iter;
    if (tmpop->code() != CPUI_SUBPIECE) continue;
    Varnode *tmphi = tmpop->getOut();
    if (!tmphi->isPrecisHi()) continue;
    if (tmphi->getSize() + l->getSize() != w->getSize()) continue;
    if (tmpop->getIn(1)->getOffset() != (uintb)l->getSize()) continue;
    // There could conceivably be more than one, but this shouldn't happen with CSE
    initAll(w,l,tmphi);
    return true;
  }
  initAll(w,l,(Varnode *)0);
  return true;
}

bool SplitVarnode::inHandHiOut(Varnode *h)

{ // Return true (and initialize -this-) if -h- is combined with a -lo- into an existing whole
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = h->beginDescend();
  enditer = h->endDescend();
  Varnode *lo = (Varnode *)0;
  Varnode *outvn = (Varnode *)0;
  while(iter != enditer) {
    PcodeOp *pieceop = *iter;
    ++iter;
    if (pieceop->code() != CPUI_PIECE) continue;
    if (pieceop->getIn(0) != h) continue;
    Varnode *l = pieceop->getIn(1);
    if (!l->isPrecisLo()) continue;
    if (lo != (Varnode *)0) return false; // Whole is not unique
    lo = l;
    outvn = pieceop->getOut();
  }
  if (lo != (Varnode *)0) {
    initAll(outvn,lo,h);
    return true;
  }
  return false;
}

bool SplitVarnode::inHandLoOut(Varnode *l)

{ // Return true (and initialize -this-) if -l- is combined with a -hi- into an existing whole
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = l->beginDescend();
  enditer = l->endDescend();
  Varnode *hi = (Varnode *)0;
  Varnode *outvn = (Varnode *)0;
  while(iter != enditer) {
    PcodeOp *pieceop = *iter;
    ++iter;
    if (pieceop->code() != CPUI_PIECE) continue;
    if (pieceop->getIn(1) != l) continue;
    Varnode *h = pieceop->getIn(0);
    if (!h->isPrecisHi()) continue;
    if (hi != (Varnode *)0) return false; // Whole is not unique
    hi = h;
    outvn = pieceop->getOut();
  }
  if (hi != (Varnode *)0) {
    initAll(outvn,l,hi);
    return true;
  }
  return false;
}

bool SplitVarnode::findWholeSplitToPieces(void)

{ // Find whole out of which -hi- and -lo- are split, return -true- if it is found
  if (whole == (Varnode *)0) {
    if (hi != (Varnode *)0) {
      if (!hi->isWritten()) return false;
      PcodeOp *subhi = hi->getDef();
      if (subhi->code() == CPUI_COPY) { // Go thru one level of copy, if the piece is addrtied
	Varnode *otherhi = subhi->getIn(0);
	if (!otherhi->isWritten()) return false;
	subhi = otherhi->getDef();
      }
      if (subhi->code() != CPUI_SUBPIECE) return false;
      Varnode *res = subhi->getIn(0);
      if (subhi->getIn(1)->getOffset() != wholesize - hi->getSize()) return false;
      whole = res;
    }
    if (lo != (Varnode *)0) {
      if (!lo->isWritten()) return false;
      PcodeOp *sublo = lo->getDef();
      if (sublo->code() == CPUI_COPY) { // Go thru one level of copy, if the piece is addrtied
	Varnode *otherlo = sublo->getIn(0);
	if (!otherlo->isWritten()) return false;
	sublo = otherlo->getDef();
      }
      if (sublo->code() != CPUI_SUBPIECE) return false;
      Varnode *res = sublo->getIn(0);
      if (whole == (Varnode *)0)
	whole = res;
      else if (whole != res)
	return false;		// Doesn't match between pieces
      if (sublo->getIn(1)->getOffset() != 0) return false;
    }
    if (whole==(Varnode *)0) return false;
  }

  if (whole->isWritten()) {
    defpoint = whole->getDef();
    defblock = defpoint->getParent();
  }
  else if (whole->isInput()) {
    defpoint = (PcodeOp *)0;
    defblock = (BlockBasic *)0;
  }
  return true;
}

bool SplitVarnode::findDefinitionPoint(void)

{ // Set basic block, where both -lo- and -hi- are defined, set the PcodeOp within block if possible
  if (lo == (Varnode *)0) return false;
  if (hi == (Varnode *)0) return false;
  defblock = (BlockBasic *)0;
  PcodeOp *lastop;
  if (lo->isConstant()&&hi->isConstant()) {
    defblock = (BlockBasic *)0;
    defpoint = (PcodeOp *)0;
    return true;
  }
  if (hi->isConstant()) return false; // If one but not both is constant
  if (lo->isConstant()) return false;
  if (hi->isWritten()) {
    if (!lo->isWritten()) return false;
    lastop = hi->getDef();
    defblock = lastop->getParent();
    PcodeOp *lastop2 = lo->getDef();
    BlockBasic *otherblock = lastop2->getParent();
    if (defblock != otherblock) {
      defpoint = lastop;
      FlowBlock *curbl = defblock;
      while(curbl != (FlowBlock *)0) { // Make sure defblock dominated by otherblock
	curbl = curbl->getImmedDom();
	if (curbl == otherblock) return true;
      }
      defblock = otherblock;		// Try lo as final defining location
      otherblock = lastop->getParent();
      defpoint = lastop2;
      curbl = defblock;
      while(curbl != (FlowBlock *)0) {
	curbl = curbl->getImmedDom();
	if (curbl == otherblock) return true;
      }
      defblock = (BlockBasic *)0;
      return false;		// Not defined in same basic block
    }
    if (lastop2->getSeqNum().getOrder() > lastop->getSeqNum().getOrder())
      lastop = lastop2;
    defpoint = lastop;
  }
  else if (hi->isInput()) {
    if (!lo->isInput()) {
      defblock = (BlockBasic *)0;
      return false;
    }
    defblock = (BlockBasic *)0;
    defpoint = (PcodeOp *)0;
  }
  return true;
}

PcodeOp *SplitVarnode::findEarliestSplitPoint(void)

{ // Find the earliest definition point of the lo and hi pieces
  if (!hi->isWritten()) return (PcodeOp *)0;
  if (!lo->isWritten()) return (PcodeOp *)0;
  PcodeOp *hiop = hi->getDef();
  PcodeOp *loop = lo->getDef();
  if (loop->getParent() != hiop->getParent())
    return (PcodeOp *)0;
  return (loop->getSeqNum().getOrder() < hiop->getSeqNum().getOrder()) ? loop : hiop;
}
 
bool SplitVarnode::findWholeBuiltFromPieces(void)

{
  // We want to scan here for concatenations formed out of hi <-> lo, in order to avoid
  // duplicate subexpressions.  But we need to be careful that the concatenation isn't created
  // AFTER we need it.  We assume hi and lo are defined in the same basic block (or both inputs)
  if (hi==(Varnode *)0) return false;
  if (lo==(Varnode *)0) return false;
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = lo->beginDescend();
  enditer = lo->endDescend();
  PcodeOp *res = (PcodeOp *)0;
  BlockBasic *bb;
  if (lo->isWritten())
    bb = lo->getDef()->getParent();
  else if (lo->isInput())
    bb = (BlockBasic *)0;
  else
    throw LowlevelError("Trying to find whole on free varnode");
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->code() != CPUI_PIECE) continue;
    if (op->getIn(0) != hi) continue;
    if (bb != (BlockBasic *)0) {
      if (op->getParent() != bb) continue; // Not defined in earliest block
    }
    else if (!op->getParent()->isEntryPoint())
      continue;
    if (res == (PcodeOp *)0)
      res = op;
    else {
      if (op->getSeqNum().getOrder() < res->getSeqNum().getOrder()) // Find "earliest" whole
	res = op;
    }
  }

  if (res == (PcodeOp *)0)
    whole = (Varnode *)0;
  else {
    defpoint = res;
    defblock = defpoint->getParent();
    whole = res->getOut();
  }
  return (whole!=(Varnode *)0);
}

bool SplitVarnode::isWholeFeasible(PcodeOp *existop)

{ // Does there exist, or can we construct a whole out of this split varnode that will be defined
  // before existop
  if (isConstant()) return true;
  if ((lo!=(Varnode *)0)&&(hi!=(Varnode *)0))
    if (lo->isConstant() != hi->isConstant()) return false; // Mixed constant/non-constant
  if (!findWholeSplitToPieces()) {
    if (!findWholeBuiltFromPieces()) {
      if (!findDefinitionPoint())
	return false;
    }
  }
  if (defblock == (BlockBasic *)0) return true;
  FlowBlock *curbl = existop->getParent();
  if (curbl == defblock)	// If defined in same block as -existop- check PcodeOp ordering
    return (defpoint->getSeqNum().getOrder() <= existop->getSeqNum().getOrder());
  while(curbl != (FlowBlock *)0) { // Make sure defbock dominates block containing -existop-
    curbl = curbl->getImmedDom();
    if (curbl == defblock) return true;
  }
  return false;
}

bool SplitVarnode::isWholePhiFeasible(FlowBlock *bl)

{ // This is the same as isWholeFeasible, but for MULTIEQUAL constructions where we have construct
  // a whole thats available for a particular branch
  if (isConstant()) return false;
  if (!findWholeSplitToPieces()) {
    if (!findWholeBuiltFromPieces()) {
      if (!findDefinitionPoint())
	return false;
    }
  }
  if (defblock == (BlockBasic *)0) return true;
  if (bl == defblock)	// If defined in same block
    return true;
  while(bl != (FlowBlock *)0) { // Make sure defblock dominates block containing -existop-
    bl = bl->getImmedDom();
    if (bl == defblock) return true;
  }
  return false;
}

void SplitVarnode::findCreateWhole(Funcdata &data)

{ // Find or create a whole varnode, we assume isWholeFeasible has returned true
  if (isConstant()) {
    whole = data.newConstant(wholesize,val);
    return;
  }
  else {
    if (lo != (Varnode *)0)
      lo->setPrecisLo();		// Mark the pieces
    if (hi != (Varnode *)0)
      hi->setPrecisHi();
  }

  if (whole != (Varnode *)0) return; // Already found the whole
  PcodeOp *concatop;
  Address addr;
  BlockBasic *topblock = (BlockBasic *)0;

  if (defblock != (BlockBasic *)0)
    addr = defpoint->getAddr();
  else {
    topblock = (BlockBasic *)data.getBasicBlocks().getStartBlock();
    addr = topblock->getStart();
  }
  
  concatop = data.newOp(2,addr);
  // Do we need to pick something other than a unique????
  whole = data.newUniqueOut(wholesize,concatop);
  data.opSetOpcode(concatop,CPUI_PIECE);
  data.opSetOutput(concatop,whole);
  data.opSetInput(concatop,hi,0);
  data.opSetInput(concatop,lo,1);

  if (defblock != (BlockBasic *)0)
    data.opInsertAfter(concatop,defpoint);
  else
    data.opInsertBegin(concatop,topblock);

  defpoint = concatop;
  defblock = concatop->getParent();
}

void SplitVarnode::findCreateOutputWhole(Funcdata &data)

{ // Create the actual -whole- varnode
  lo->setPrecisLo();		// Mark the pieces
  hi->setPrecisHi();
  if (whole != (Varnode *)0) return;
  whole = data.newUnique(wholesize);
}

void SplitVarnode::createJoinedWhole(Funcdata &data)

{ // Create a whole from pieces, respecting the piece addresses
  // if the pieces can be treated as a contiguous whole, use that address
  // otherwise construct a join address
  lo->setPrecisLo();
  hi->setPrecisHi();
  if (whole != (Varnode *)0) return;
  Address newaddr;
  if (!isAddrTiedContiguous(lo,hi,newaddr)) {
    newaddr = data.getArch()->constructJoinAddress(data.getArch()->translate,hi->getAddr(),hi->getSize(),
									    lo->getAddr(),lo->getSize());
  }
  whole = data.newVarnode(wholesize,newaddr);
  whole->setWriteMask();
}

void SplitVarnode::buildLoFromWhole(Funcdata &data)

{ // Assume -lo- was defined in some other way and now needs to be defined as a split from 
  // a new -whole- varnode
  PcodeOp *loop = lo->getDef();
  if (loop == (PcodeOp *)0)
    throw LowlevelError("Building low piece that was originally undefined");

  vector<Varnode *> inlist;
  inlist.push_back(whole);
  inlist.push_back(data.newConstant(4,0));
  if (loop->code() == CPUI_MULTIEQUAL) {
    // When converting the MULTIEQUAL to a SUBPIECE, we need to reinsert the op so that we don't
    // get a break in the sequence of MULTIEQUALs at the beginning of the block
    BlockBasic *bl = loop->getParent();
    data.opUninsert(loop);
    data.opSetOpcode(loop,CPUI_SUBPIECE);
    data.opSetAllInput(loop,inlist);
    data.opInsertBegin(loop,bl);
  }
  else if (loop->code() == CPUI_INDIRECT) {
    // When converting an INDIRECT to a SUBPIECE, we need to reinsert the op AFTER the affector
    PcodeOp *affector = PcodeOp::getOpFromConst(loop->getIn(1)->getAddr());
    if (!affector->isDead())
      data.opUninsert(loop);
    data.opSetOpcode(loop,CPUI_SUBPIECE);
    data.opSetAllInput(loop,inlist);
    if (!affector->isDead())
      data.opInsertAfter(loop,affector);
  }
  else {
    data.opSetOpcode(loop,CPUI_SUBPIECE);
    data.opSetAllInput(loop,inlist);
  }
}

void SplitVarnode::buildHiFromWhole(Funcdata &data)

{ // Assume -hi- was defined in some other way and now needs to be defined as a split from 
  // a new -whole- varnode
   PcodeOp *hiop = hi->getDef();
  if (hiop == (PcodeOp *)0)
    throw LowlevelError("Building low piece that was originally undefined");

  vector<Varnode *> inlist;
  inlist.push_back(whole);
  inlist.push_back(data.newConstant(4,lo->getSize()));
  if (hiop->code() == CPUI_MULTIEQUAL) {
    // When converting the MULTIEQUAL to a SUBPIECE, we need to reinsert the op so that we don't
    // get a break in the sequence of MULTIEQUALs at the beginning of the block
    BlockBasic *bl = hiop->getParent();
    data.opUninsert(hiop);
    data.opSetOpcode(hiop,CPUI_SUBPIECE);
    data.opSetAllInput(hiop,inlist);
    data.opInsertBegin(hiop,bl);
  }
  else if (hiop->code() == CPUI_INDIRECT) {
    // When converting the INDIRECT to a SUBPIECE, we need to reinsert AFTER the affector
    PcodeOp *affector = PcodeOp::getOpFromConst(hiop->getIn(1)->getAddr());
    if (!affector->isDead())
      data.opUninsert(hiop);
    data.opSetOpcode(hiop,CPUI_SUBPIECE);
    data.opSetAllInput(hiop,inlist);
    if (!affector->isDead())
      data.opInsertAfter(hiop,affector);
  }
  else {
    data.opSetOpcode(hiop,CPUI_SUBPIECE);
    data.opSetAllInput(hiop,inlist);
  }
}

// void SplitVarnode::buildHiFromLoHalf(Funcdata &data,SplitVarnode &oldin,PcodeOp *newwholeop)

// { // Only the lo half of the new logical whole is explicitly constructed, the old input high
//   // is recycled for the hi half of the output, define the new hi half as a SUBPIECE and scan
//   // through the uses of the old hi half to see which should be switch to the new hi half
//   PcodeOp *newhiop = data.newOp(2,newwholeop->getAddr());
//   data.opSetOpcode(newhiop,CPUI_SUBPIECE);
//   data.opSetOutput(newhiop,hi);	// hi was not defined previously
//   data.opSetInput(newhiop,whole,0);
//   data.opSetInput(newhiop,data.newConstant(4,lo->getSize()),1);
//   data.opInsertAfter(newhiop,newwholeop);

//   Varnode *oldhi = oldin.getHi();
//   list<PcodeOp *>::const_iterator iter,enditer;
//   iter = oldhi->beginDescend();
//   enditer = oldhi->endDescend();
//   while(iter != enditer) {
//     PcodeOp *testop = *iter;
//     ++iter;
//     int4 ord = testop->compareOrder(newhiop);
//     if (ord == 1) { 		// newhiop executes earlier than testop
//       int4 slot = testop->getSlot(oldhi);
//       data.opSetInput(testop,hi,slot);
//     }
//   }
// }

PcodeOp *SplitVarnode::findOutExist(void)

{ // Find the point at which the whole must exist
  if (findWholeBuiltFromPieces()) {
    return defpoint;
  }
  return findEarliestSplitPoint();
}

bool SplitVarnode::adjacentOffsets(Varnode *vn1,Varnode *vn2,uintb size1)

{ // Return true, if the (possibly dynamic) offset represented
  // by vn1 plus size1 produces the offset in vn2

  if (vn1->isConstant()) {
    if (!vn2->isConstant()) return false;
    return ((vn1->getOffset() + size1) == vn2->getOffset());
  }

  if (!vn2->isWritten()) return false;
  PcodeOp *op2 = vn2->getDef();
  if (op2->code() != CPUI_INT_ADD) return false;
  if (!op2->getIn(1)->isConstant()) return false;
  uintb c2 = op2->getIn(1)->getOffset();

  if (op2->getIn(0) == vn1)
    return (size1 == c2);

  if (!vn1->isWritten()) return false;
  PcodeOp *op1 = vn1->getDef();
  if (op1->code() != CPUI_INT_ADD) return false;
  if (!op1->getIn(1)->isConstant()) return false;
  uintb c1 = op1->getIn(1)->getOffset();

  if (op1->getIn(0) != op2->getIn(0)) return false;
  return ((c1 + size1) == c2);
}

bool SplitVarnode::testContiguousLoad(PcodeOp *most,PcodeOp *least,bool allowfree,PcodeOp *&first,PcodeOp *&second,AddrSpace *&spc,int4 &sizeres)

{ // Determine if -most- and -least- are contiguous loads, given that the outputs form the most and least significant
  // parts of a double precision result, sort the ops into -first- address and -second- address
  // return 'true' and the -spc- loaded from and the combined load size
  if (least->code() != CPUI_LOAD) return false;
  if (most->code() != CPUI_LOAD) return false;
  spc = Address::getSpaceFromConst(least->getIn(0)->getAddr());
  if (Address::getSpaceFromConst(most->getIn(0)->getAddr()) != spc) return false;

  if (spc->isBigEndian()) {	// Convert significance order to address order
    first = most;
    second = least;
  }
  else {
    first = least;
    second = most;
  }
  Varnode *firstptr = first->getIn(1);
  if (!allowfree)
    if (firstptr->isFree()) return false;
  sizeres = first->getOut()->getSize(); // # of bytes read by lowest address load

  // Check if the loads are adjacent to each other
  if (!adjacentOffsets(first->getIn(1),second->getIn(1),(uintb)sizeres))
    return false;
  sizeres += second->getOut()->getSize();
  return true;
}

bool SplitVarnode::isAddrTiedContiguous(Varnode *lo,Varnode *hi,Address &res)

{ // Return true if the pieces -lo- and -hi- can be melded into a contiguous storage location
  if (!lo->isAddrTied()) return false;
  if (!hi->isAddrTied()) return false;

  // Make sure there is no explicit symbol that would prevent the pieces from being joined
  SymbolEntry *entry = lo->getSymbolEntry();
  if ((entry != (SymbolEntry *)0)&&(entry->getOffset()==0)) return false;
  entry = hi->getSymbolEntry();
  if ((entry != (SymbolEntry *)0)&&(entry->getOffset()==0)) return false;
  AddrSpace *spc = lo->getSpace();
  if (spc != hi->getSpace()) return false;
  uintb looffset = lo->getOffset();
  uintb hioffset = hi->getOffset();
  if (spc->isBigEndian()) {
    if (hioffset >= looffset) return false;
    if (hioffset + hi->getSize() != looffset) return false;
    res = hi->getAddr();
  }
  else {
    if (looffset >= hioffset) return false;
    if (looffset + lo->getSize() != hioffset) return false;
    res = lo->getAddr();
  }
  return true;
}

void SplitVarnode::wholeList(Varnode *w,vector<SplitVarnode> &splitvec)

{ // Create a list of all the possible pairs that contain the same logical value as -w-
  SplitVarnode basic;

  basic.whole = w;
  basic.hi = (Varnode *)0;
  basic.lo = (Varnode *)0;
  basic.wholesize = w->getSize();
  list<PcodeOp *>::const_iterator iter,enditer;

  iter = basic.whole->beginDescend();
  enditer = basic.whole->endDescend();
  int4 res = 0;
  while(iter != enditer) {
    PcodeOp *subop = *iter;
    ++iter;
    if (subop->code() != CPUI_SUBPIECE) continue;
    Varnode *vn = subop->getOut();
    if (vn->isPrecisHi()) {
      if (subop->getIn(1)->getOffset() != basic.wholesize - vn->getSize()) continue;
      basic.hi = vn;
      res |= 2;
    }
    else if (vn->isPrecisLo()) {
      if (subop->getIn(1)->getOffset() != 0) continue;
      basic.lo = vn;
      res |= 1;
    }
  }
  if (res==0) return;

  splitvec.push_back(basic);
  findCopies(basic,splitvec);
}

void SplitVarnode::findCopies(const SplitVarnode &in,vector<SplitVarnode> &splitvec)

{ // Find copies from -in- pieces into another logical pair
  if (!in.hasBothPieces()) return;
  list<PcodeOp *>::const_iterator iter,enditer;

  iter = in.getLo()->beginDescend();
  enditer = in.getLo()->endDescend();
  while(iter != enditer) {
    PcodeOp *loop = *iter;
    ++iter;
    if (loop->code() != CPUI_COPY) continue;
    Varnode *locpy = loop->getOut();
    Address addr = locpy->getAddr(); // Calculate address of hi part
    if (addr.isBigEndian())
      addr = addr - (in.getHi()->getSize());
    else
      addr = addr + locpy->getSize();
    list<PcodeOp *>::const_iterator iter2,enditer2;
    iter2 = in.getHi()->beginDescend();
    enditer2 = in.getHi()->endDescend();
    while(iter2 != enditer2) {
      PcodeOp *hiop = *iter2;
      ++iter2;
      if (hiop->code() != CPUI_COPY) continue;
      Varnode *hicpy = hiop->getOut();
      if (hicpy->getAddr() != addr) continue;
      if (hiop->getParent() != loop->getParent()) continue;
      SplitVarnode newsplit;
      newsplit.initAll(in.getWhole(),locpy,hicpy);
      splitvec.push_back(newsplit);
    }
  }
}

void SplitVarnode::getTrueFalse(PcodeOp *boolop,bool flip,BlockBasic *&trueout,BlockBasic *&falseout)

{
  BlockBasic *parent = boolop->getParent();
  BlockBasic *trueblock = (BlockBasic *)parent->getTrueOut();
  BlockBasic *falseblock =(BlockBasic *)parent->getFalseOut();
  if (boolop->isBooleanFlip() != flip) {
    trueout = falseblock;
    falseout = trueblock;
  }
  else {
    trueout = trueblock;
    falseout = falseblock;
  }
}

bool SplitVarnode::otherwiseEmpty(PcodeOp *branchop)

{ // Return true if this block is only used to perform the branch specified by -branchop-
  BlockBasic *bl = branchop->getParent();
  if (bl->sizeIn() != 1) return false;
  PcodeOp *otherop = (PcodeOp *)0;
  Varnode *vn = branchop->getIn(1);
  if (vn->isWritten())
    otherop = vn->getDef();
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = bl->beginOp();
  enditer = bl->endOp();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op == otherop) continue;
    if (op == branchop) continue;
    return false;
  }
  return true;
}

bool SplitVarnode::verifyMultNegOne(PcodeOp *op)

{
  if (op->code() != CPUI_INT_MULT) return false;
  Varnode *in1 = op->getIn(1);
  if (!in1->isConstant()) return false;
  if (in1->getOffset() != calc_mask(in1->getSize())) return false;
  return true;
}

PcodeOp *SplitVarnode::prepareBinaryOp(SplitVarnode &out,SplitVarnode &in1,SplitVarnode &in2)

{
  PcodeOp *existop = out.findOutExist(); // Find point where output whole needs to exist
  if (existop == (PcodeOp *)0) return existop; // If we can find no such point return false;
  if (!in1.isWholeFeasible(existop)) return (PcodeOp *)0;
  if (!in2.isWholeFeasible(existop)) return (PcodeOp *)0;
  return existop;
}

void SplitVarnode::createBinaryOp(Funcdata &data,SplitVarnode &out,SplitVarnode &in1,SplitVarnode &in2,
				  PcodeOp *existop,OpCode opc)

{ // Rewrite the double precision operation (if possible) by replacing the pieces with unified varnodes
  // Make sure all the actual whole varnodes exist
  out.findCreateOutputWhole(data);
  in1.findCreateWhole(data);
  in2.findCreateWhole(data);
  if (existop->code() != CPUI_PIECE) { // If the output whole didn't previously exist
    PcodeOp *newop = data.newOp(2,existop->getAddr()); // new op which creates the output whole
    data.opSetOpcode(newop,opc);
    data.opSetOutput(newop,out.getWhole());
    data.opSetInput(newop,in1.getWhole(),0);
    data.opSetInput(newop,in2.getWhole(),1);
    data.opInsertBefore(newop,existop);
    out.buildLoFromWhole(data);
    out.buildHiFromWhole(data);
  }
  else {			// The whole previously existed
    data.opSetOpcode(existop,opc); // our new op replaces the op previously defining the output whole
    data.opSetInput(existop,in1.getWhole(),0);
    data.opSetInput(existop,in2.getWhole(),1);
  }
}

PcodeOp *SplitVarnode::prepareShiftOp(SplitVarnode &out,SplitVarnode &in)

{
  PcodeOp *existop = out.findOutExist(); // Find point where output whole needs to exist
  if (existop == (PcodeOp *)0) return existop;
  if (!in.isWholeFeasible(existop)) return (PcodeOp *)0;
  return existop;
}

void SplitVarnode::createShiftOp(Funcdata &data,SplitVarnode &out,SplitVarnode &in,Varnode *sa,
				 PcodeOp *existop,OpCode opc)

{ // Rewrite the double precision shift by replacing hi/lo pieces with unified varnodes
  out.findCreateOutputWhole(data);
  in.findCreateWhole(data);
  if (sa->isConstant())
    sa = data.newConstant(sa->getSize(),sa->getOffset());
  if (existop->code() != CPUI_PIECE) { // If the output whole didn't previously exist
    PcodeOp *newop = data.newOp(2,existop->getAddr());
    data.opSetOpcode(newop,opc);
    data.opSetOutput(newop,out.getWhole());
    data.opSetInput(newop,in.getWhole(),0);
    data.opSetInput(newop,sa,1);
    data.opInsertBefore(newop,existop);
    out.buildLoFromWhole(data);
    out.buildHiFromWhole(data);
  }
  else {			// The whole previously existed, we remake the defining op
    data.opSetOpcode(existop,opc);
    data.opSetInput(existop,in.getWhole(),0);
    data.opSetInput(existop,sa,1);
  }
}

int4 SplitVarnode::applyRuleIn(SplitVarnode &in,Funcdata &data)

{ // Try to perform one transform on a logical double precision operation that uses -in- as input
  for(int4 i=0;i<2;++i) {
    Varnode *vn;
    vn = (i==0) ? in.getHi() : in.getLo();
    if (vn == (Varnode *)0) continue;
    bool workishi = (i==0);
    list<PcodeOp *>::const_iterator iter,enditer;
    iter = vn->beginDescend();
    enditer = vn->endDescend();
    while(iter != enditer) {
      PcodeOp *workop = *iter;
      ++iter;
      switch(workop->code()) {
      case CPUI_INT_ADD:
	{
	  AddForm addform;
	  if (addform.applyRule(in,workop,workishi,data))
	    return 1;
	  SubForm subform;
	  if (subform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_AND:
	{
	  Equal3Form equal3form;
	  if (equal3form.applyRule(in,workop,workishi,data))
	    return 1;
	  LogicalForm logicalform;
	  if (logicalform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_OR:
	{
	  Equal2Form equal2form;
	  if (equal2form.applyRule(in,workop,workishi,data))
	    return 1;
	  LogicalForm logicalform;
	  if (logicalform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_XOR:
	{
	  Equal2Form equal2form;
	  if (equal2form.applyRule(in,workop,workishi,data))
	    return 1;
	  LogicalForm logicalform;
	  if (logicalform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
	{
	  LessThreeWay lessthreeway;
	  if (lessthreeway.applyRule(in,workop,workishi,data))
	    return 1;
	  Equal1Form equal1form;
	  if (equal1form.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_LESS:
      case CPUI_INT_LESSEQUAL:
	{
	  LessThreeWay lessthreeway;
	  if (lessthreeway.applyRule(in,workop,workishi,data))
	    return 1;
	  LessConstForm lessconstform;
	  if (lessconstform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_SLESS:
	{
	  LessConstForm lessconstform;
	  if (lessconstform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_SLESSEQUAL:
	{
	  LessConstForm lessconstform;
	  if (lessconstform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_LEFT:
	{
	  ShiftForm shiftform;
	  if (shiftform.applyRuleLeft(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_RIGHT:
	{
	  ShiftForm shiftform;
	  if (shiftform.applyRuleRight(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_SRIGHT:
	{
	  ShiftForm shiftform;
	  if (shiftform.applyRuleRight(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INT_MULT:
	{
	  MultForm multform;
	  if (multform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_MULTIEQUAL:
	{
	  PhiForm phiform;
	  if (phiform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      case CPUI_INDIRECT:
	{
	  IndirectForm indform;
	  if (indform.applyRule(in,workop,workishi,data))
	    return 1;
	}
	break;
      default:
	break;
      }
    }
  }
  return 0;
}

bool SplitVarnode::prepareBoolOp(SplitVarnode &in1,SplitVarnode &in2,PcodeOp *testop)

{
  if (!in1.isWholeFeasible(testop)) return false;
  if (!in2.isWholeFeasible(testop)) return false;
  return true;
}

void SplitVarnode::replaceBoolOp(Funcdata &data,PcodeOp *boolop,SplitVarnode &in1,SplitVarnode &in2,
				 OpCode opc)

{ // Rewrite the a double precision operation that results in a boolean, by replacing the input pieces
  // with unified varnodes.
  in1.findCreateWhole(data);
  in2.findCreateWhole(data);
  data.opSetOpcode(boolop,opc);
  data.opSetInput(boolop,in1.getWhole(),0);
  data.opSetInput(boolop,in2.getWhole(),1);
}

void SplitVarnode::createBoolOp(Funcdata &data,PcodeOp *cbranch,SplitVarnode &in1,SplitVarnode &in2,
				OpCode opc)

{ // Create a new boolean op which replaces the boolean taken as input by -cbranch- with a double
  // precision version.
  PcodeOp *addrop = cbranch;
  Varnode *boolvn = cbranch->getIn(1);
  if (boolvn->isWritten())
    addrop = boolvn->getDef();	// Use the address of the comparison operator
  in1.findCreateWhole(data);
  in2.findCreateWhole(data);
  PcodeOp *newop = data.newOp(2,addrop->getAddr());
  data.opSetOpcode(newop,opc);
  Varnode *newbool = data.newUniqueOut(1,newop);
  data.opSetInput(newop,in1.getWhole(),0);
  data.opSetInput(newop,in2.getWhole(),1);
  data.opInsertBefore(newop,cbranch);
  data.opSetInput(cbranch,newbool,1); // CBRANCH now determined by new compare
}

PcodeOp *SplitVarnode::preparePhiOp(SplitVarnode &out,vector<SplitVarnode> &inlist)

{
  PcodeOp *existop = out.findEarliestSplitPoint(); // Point where output whole needs to exist
  if (existop == (PcodeOp *)0) return existop;
  // existop should always be a MULTIEQUAL defining one of the pieces
  if (existop->code() != CPUI_MULTIEQUAL)
    throw LowlevelError("Trying to create phi-node double precision op with phi-node pieces");
  BlockBasic *bl = existop->getParent();
  int4 numin = inlist.size();
  for(int4 i=0;i<numin;++i)
    if (!inlist[i].isWholePhiFeasible(bl->getIn(i)))
      return (PcodeOp *)0;
  return existop;
}

void SplitVarnode::createPhiOp(Funcdata &data,SplitVarnode &out,vector<SplitVarnode> &inlist,
			       PcodeOp  *existop)

{
  // Unlike replaceBoolOp, we MUST create a newop even if the output whole already exists
  // because the MULTIEQUAL has a lot of placement constraints on it
  out.findCreateOutputWhole(data);
  int4 numin = inlist.size();
  for(int4 i=0;i<numin;++i)
    inlist[i].findCreateWhole(data);

  PcodeOp *newop = data.newOp(numin,existop->getAddr());
  data.opSetOpcode(newop,CPUI_MULTIEQUAL);
  data.opSetOutput(newop,out.getWhole());
  for(int4 i=0;i<numin;++i)
    data.opSetInput(newop,inlist[i].getWhole(),i);
  data.opInsertBefore(newop,existop);
  out.buildLoFromWhole(data);
  out.buildHiFromWhole(data);
}

bool SplitVarnode::prepareIndirectOp(SplitVarnode &in,PcodeOp *affector)

{
  // We already have the exist point, -indop-
  if (!in.isWholeFeasible(affector))
    return false;
  return true;
}

void SplitVarnode::replaceIndirectOp(Funcdata &data,SplitVarnode &out,SplitVarnode &in,PcodeOp *affector)

{ // This REPLACES the existing INDIRECTs of the pieces
  out.createJoinedWhole(data);

  in.findCreateWhole(data);
  PcodeOp *newop = data.newOp(2,affector->getAddr());
  data.opSetOpcode(newop,CPUI_INDIRECT);
  data.opSetOutput(newop,out.getWhole());
  data.opSetInput(newop,in.getWhole(),0);
  data.opSetInput(newop,data.newVarnodeIop(affector),1);
  data.opInsertBefore(newop,affector);
  out.buildLoFromWhole(data);
  out.buildHiFromWhole(data);
}

bool AddForm::checkForCarry(PcodeOp *op)

{ // If -op- matches a CARRY construction based on lo1 (i.e. CARRY(x,lo1) )
  //    set lo1 (and negconst if lo1 is a constant) to be the corresponding part of the carry
  //    and return true
  if (op->code() != CPUI_INT_ZEXT) return false;
  if (!op->getIn(0)->isWritten()) return false;
  
  PcodeOp *carryop = op->getIn(0)->getDef();
  if (carryop->code() == CPUI_INT_CARRY) { // Normal CARRY form
    if (carryop->getIn(0) == lo1)
      lo2 = carryop->getIn(1);
    else if (carryop->getIn(1) == lo1)
      lo2 = carryop->getIn(0);
    else
      return false;
    if (lo2->isConstant()) return false;
    return true;
  }
  if (carryop->code() == CPUI_INT_LESS) { // Possible CARRY
    Varnode *tmpvn = carryop->getIn(0);
    if (tmpvn->isConstant()) {
      if (carryop->getIn(1) != lo1) return false;
      negconst = tmpvn->getOffset();
      // In constant forms, the <= will get converted to a <
      // Note the lessthan to less conversion adds 1 then the 2's complement subtracts 1 and negates
      // So all we really need to do is negate
      negconst = (~negconst) & calc_mask(lo1->getSize());
      lo2 = (Varnode *)0;
      return true;
    }
    else if (tmpvn->isWritten()) {	// Calculate CARRY relative to result of loadd
      PcodeOp *loadd_op = tmpvn->getDef();	// This is the putative loadd
      if (loadd_op->code() != CPUI_INT_ADD) return false;
      Varnode *othervn;
      if (loadd_op->getIn(0)==lo1)
	othervn = loadd_op->getIn(1);
      else if (loadd_op->getIn(1)==lo1)
	othervn = loadd_op->getIn(0);
      else
	return false;			// One side of the add must be lo1
      if (othervn->isConstant()) {
	negconst = othervn->getOffset();
	lo2 = (Varnode *)0;
	Varnode *relvn = carryop->getIn(1);
	if (relvn == lo1) return true;	// Comparison can be relative to lo1
	if (!relvn->isConstant()) return false;
	if (relvn->getOffset() != negconst) return false;	// Otherwise must be relative to (constant)lo2
	return true;
      }
      else {
	lo2 = othervn;		// Other side of putative loadd must be lo2
	Varnode *compvn = carryop->getIn(1);
	if ((compvn == lo2)||(compvn == lo1))
	  return true;
      }
    }
    return false;
  }
  if (carryop->code() == CPUI_INT_NOTEQUAL) { // Possible CARRY against -1
    if (!carryop->getIn(1)->isConstant()) return false;
    if (carryop->getIn(0) != lo1) return false;
    if (carryop->getIn(1)->getOffset() != 0) return false;
    negconst = calc_mask(lo1->getSize()); // Original CARRY constant must have been -1
    lo2 = (Varnode *)0;
    return true;
  }
  return false;
}

// Given a known double precision input, look for a double precision add,
// recovering the other double input and the double output
//
// Assume hi1, lo1 is a known double precision pair, we look for
//   reshi = hi1 + hi2 + hizext             (2 variants here)
//   hizext = zext(bool)
//   {                                       (2 variants)
//     bool = (-lo1 <= lo2)     OR
//     bool = (-lo2 <= lo1)                  (multiple ways to calculate negation)
//   }
//   reslo = lo1 + lo2

bool AddForm::verify(Varnode *h,Varnode *l,PcodeOp *op)

{
  hi1 = h;
  lo1 = l;
  slot1 = op->getSlot(hi1);
  for(int4 i=0;i<3;++i) {
    if (i==0) {		// Assume we have to descend one more add
      add2 = op->getOut()->loneDescend();
      if (add2 == (PcodeOp *)0) continue;
      if (add2->code() != CPUI_INT_ADD) continue;
      reshi = add2->getOut();
      hizext1 = op->getIn(1-slot1);
      hizext2 = add2->getIn(1-add2->getSlot(op->getOut()));
    }
    else if (i==1) {		// Assume we are at the bottom most of two adds
      Varnode *tmpvn = op->getIn(1-slot1);
      if (!tmpvn->isWritten()) continue;
      add2 = tmpvn->getDef();
      if (add2->code() != CPUI_INT_ADD) continue;
      reshi = op->getOut();
      hizext1 = add2->getIn(0);
      hizext2 = add2->getIn(1);
    }
    else {			// Assume there is only one add, with second implied add by 0
      reshi = op->getOut();
      hizext1 = op->getIn(1-slot1);
      hizext2 = (Varnode *)0;
    }
    for(int4 j=0;j<2;++j) {
      if (i==2) {		// hi2 is an implied 0
	if (!hizext1->isWritten()) continue;
	zextop = hizext1->getDef();
	hi2 = (Varnode *)0;
      }
      else if (j==0) {
	if (!hizext1->isWritten()) continue;
	zextop = hizext1->getDef();
	hi2 = hizext2;
      }
      else {
	if (!hizext2->isWritten()) continue;
	zextop = hizext2->getDef();
	hi2 = hizext1;
      }
      if (!checkForCarry(zextop)) continue; // Calculate lo2 and negconst

      list<PcodeOp *>::const_iterator iter2,enditer2;
      iter2 = lo1->beginDescend();
      enditer2 = lo1->endDescend();
      while(iter2 != enditer2) {
	loadd = *iter2;
	++iter2;
	if (loadd->code() != CPUI_INT_ADD) continue;
	Varnode *tmpvn = loadd->getIn(1-loadd->getSlot(lo1));
	if (lo2 == (Varnode *)0) {
	  if (!tmpvn->isConstant()) continue;
	  if (tmpvn->getOffset() != negconst) continue;	// Must add same constant used to calculate CARRY
	  lo2 = tmpvn;
	}
	else if (lo2->isConstant()) {
	  if (!tmpvn->isConstant()) continue;
	  if (lo2->getOffset() != tmpvn->getOffset()) continue;
	}
	else if (loadd->getIn(1-loadd->getSlot(lo1)) != lo2) // Must add same value used to calculate CARRY
	  continue;
	reslo = loadd->getOut();
	return true;
      }
    }
  }
  return false;
}

bool AddForm::applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;
  if (!verify(in.getHi(),in.getLo(),op))
    return false;

  indoub.initPartial(lo2,hi2);
  outdoub.initPartial(reslo,reshi);
  existop = SplitVarnode::prepareBinaryOp(outdoub,in,indoub);
  if (existop == (PcodeOp *)0)
    return false;
  SplitVarnode::createBinaryOp(data,outdoub,in,indoub,existop,CPUI_INT_ADD);
  return true;
}

// Given a known double precision input, look for a double precision subtraction,
// recovering the other double input and the double output
//
// Assume hi1, lo1 is a known double precision pair, we look for
//   reshi = hi1 + -hi2 + - zext(lo1 < lo2)
//   reslo = lo1 + -lo2

bool SubForm::verify(Varnode *h,Varnode *l,PcodeOp *op)

{
  list<PcodeOp *>::const_iterator iter2,enditer2;
  hi1 = h;
  lo1 = l;
  slot1 = op->getSlot(hi1);
  for(int4 i=0;i<2;++i) {
    if (i==0) {		// Assume we have to descend one more add
      add2 = op->getOut()->loneDescend();
      if (add2 == (PcodeOp *)0) continue;
      if (add2->code() != CPUI_INT_ADD) continue;
      reshi = add2->getOut();
      hineg1 = op->getIn(1-slot1);
      hineg2 = add2->getIn(1-add2->getSlot(op->getOut()));
    }
    else {
      Varnode *tmpvn = op->getIn(1-slot1);
      if (!tmpvn->isWritten()) continue;
      add2 = tmpvn->getDef();
      if (add2->code() != CPUI_INT_ADD) continue;
      reshi = op->getOut();
      hineg1 = add2->getIn(0);
      hineg2 = add2->getIn(1);
    }
    if (!hineg1->isWritten()) continue;
    if (!hineg2->isWritten()) continue;
    if (!SplitVarnode::verifyMultNegOne(hineg1->getDef())) continue;
    if (!SplitVarnode::verifyMultNegOne(hineg2->getDef())) continue;
    hizext1 = hineg1->getDef()->getIn(0);
    hizext2 = hineg2->getDef()->getIn(0);
    for(int4 j=0;j<2;++j) {
      if (j==0) {
	if (!hizext1->isWritten()) continue;
	zextop = hizext1->getDef();
	hi2 = hizext2;
      }
      else {
	if (!hizext2->isWritten()) continue;
	zextop = hizext2->getDef();
	hi2 = hizext1;
      }
      if (zextop->code() != CPUI_INT_ZEXT) continue;
      if (!zextop->getIn(0)->isWritten()) continue;
      lessop = zextop->getIn(0)->getDef();
      if (lessop->code() != CPUI_INT_LESS) continue;
      if (lessop->getIn(0) != lo1) continue;
      lo2 = lessop->getIn(1);
      iter2 = lo1->beginDescend();
      enditer2 = lo1->endDescend();
      while(iter2 != enditer2) {
	loadd = *iter2;
	++iter2;
	if (loadd->code() != CPUI_INT_ADD) continue;
	Varnode *tmpvn = loadd->getIn(1-loadd->getSlot(lo1));
	if (!tmpvn->isWritten()) continue;
	negop = tmpvn->getDef();
	if (!SplitVarnode::verifyMultNegOne(negop)) continue;
	if (negop->getIn(0) != lo2) continue;
	reslo = loadd->getOut();
	return true;
      }
    }
  }
  return false;
}

bool SubForm::applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;

  if (!verify(in.getHi(),in.getLo(),op))
    return false;

  indoub.initPartial(lo2,hi2);
  outdoub.initPartial(reslo,reshi);
  existop = SplitVarnode::prepareBinaryOp(outdoub,in,indoub);
  if (existop == (PcodeOp *)0)
    return false;
  SplitVarnode::createBinaryOp(data,outdoub,in,indoub,existop,CPUI_INT_SUB);
  return true;
}

int4 LogicalForm::findHiMatch(void)

{ // Look for the op computing the most significant part of the result for which -loop- computes
  // the least significant part,  look for a known double precis out, then look for known double
  // precis in.  If the other input is constant, look for a unique op that might be computing the high,
  // Return 0 if we found an op, return -1, if we can't find an op, return -2 if no op exists
  Varnode *lo1 = in.getLo();
  Varnode *vn2 = loop->getIn( 1-loop->getSlot( lo1 ) );
  
  SplitVarnode out;
  if (out.inHandLoOut(lo1)) {	// If we already know what the double precision output looks like
    Varnode *hi = out.getHi();
    if (hi->isWritten()) {	// Just look at construction of hi precisi
      PcodeOp *maybeop = hi->getDef();
      if (maybeop->code() == loop->code()) {
	if (maybeop->getIn(0) == hi1) {
	  if (maybeop->getIn(1)->isConstant() == vn2->isConstant()) {
	    hiop = maybeop;
	    return 0;
	  }
	}
	else if (maybeop->getIn(1) == hi1) {
	  if (maybeop->getIn(0)->isConstant() == vn2->isConstant()) {
	    hiop = maybeop;
	    return 0;
	  }
	}
      }
    }
  }

  if (!vn2->isConstant()) {
    SplitVarnode in2;
    if (in2.inHandLo(vn2)) {	// If we already know what the other double precision input looks like
      list<PcodeOp *>::const_iterator iter,enditer;
      iter = in2.getHi()->beginDescend();
      enditer = in2.getHi()->endDescend();
      while(iter != enditer) {
	PcodeOp *maybeop = *iter;
	++iter;
	if (maybeop->code() == loop->code()) {
	  if ((maybeop->getIn(0) == hi1)||(maybeop->getIn(1) == hi1)) {
	    hiop = maybeop;
	    return 0;
	  }
	}
      }
    }
    return -1;
  }
  else {
    list<PcodeOp *>::const_iterator iter,enditer;
    iter = hi1->beginDescend();
    enditer = hi1->endDescend();
    int4 count = 0;
    PcodeOp *lastop = (PcodeOp *)0;
    while(iter != enditer) {
      PcodeOp *maybeop = *iter;
      ++iter;
      if (maybeop->code() == loop->code()) {
	if (maybeop->getIn(1)->isConstant()) {
	  count += 1;
	  if (count > 1) break;
	  lastop = maybeop;
	}
      }
    }
    if (count == 1) {
      hiop = lastop;
      return 0;
    }
    if (count >1)
      return -1;		// Couldn't distinguish between multiple possibilities
  }
  return -2;
}

// Given a known double precision input, look for a double precision logical operation
// recovering the other double input and the double output
//
// Assume hi1, lo1 is a known double precision pair, we look for
// reshi = hi1 & hi2
// reslo = lo1 & lo2
bool LogicalForm::verify(Varnode *h,Varnode *l,PcodeOp *lop)

{
  loop = lop;
  lo1 = l;
  hi1 = h;
  int4 res = findHiMatch();

  if (res == 0) {		// We found a matching lo presis operation
    lo2 = loop->getIn(1-loop->getSlot(lo1));
    hi2 = hiop->getIn(1-hiop->getSlot(hi1));
    if ((lo2==lo1)||(lo2==hi1)||(hi2==hi1)||(hi2==lo1)) return false; // No manipulation of itself
    if (lo2 == hi2) return false;
    return true;
  }
  return false;
}

bool LogicalForm::applyRule(SplitVarnode &i,PcodeOp *lop,bool workishi,Funcdata &data)

{
  if (workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;

  if (!verify(in.getHi(),in.getLo(),lop))
    return false;

  outdoub.initPartial(loop->getOut(),hiop->getOut());
  indoub.initPartial(lo2,hi2);
  existop = SplitVarnode::prepareBinaryOp(outdoub,in,indoub);
  if (existop == (PcodeOp *)0)
    return false;

  SplitVarnode::createBinaryOp(data,outdoub,in,indoub,existop,loop->code());
  return true;
}

// Given a known double precis input, look for double precision compares of the form
//   a == b,  a != b
//
// We look for
//     hibool = hi1 == hi2
//     lobool = lo1 == lo2
// each of the bools induces a CBRANCH
//               if (hibool) blocksecond else blockfalse
// blocksecond:  if (lobool) blocktrue else blockfalse
bool Equal1Form::applyRule(SplitVarnode &i,PcodeOp *hop,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in1 = i;

  hiop = hop;
  hi1 = in1.getHi();
  lo1 = in1.getLo();
  hi1slot = hiop->getSlot(hi1);
  hi2 = hiop->getIn(1-hi1slot);
  notequalformhi = (hiop->code() == CPUI_INT_NOTEQUAL);

  list<PcodeOp *>::const_iterator iter,enditer;
  list<PcodeOp *>::const_iterator iter2,enditer2;
  list<PcodeOp *>::const_iterator iter3,enditer3;
  iter = lo1->beginDescend();
  enditer = lo1->endDescend();
  while(iter != enditer) {
    loop = *iter;
    ++iter;
    if (loop->code() == CPUI_INT_EQUAL)
      notequalformlo = false;
    else if (loop->code() == CPUI_INT_NOTEQUAL)
      notequalformlo = true;
    else
      continue;
    lo1slot = loop->getSlot(lo1);
    lo2 = loop->getIn(1-lo1slot);

    iter2 = hiop->getOut()->beginDescend();
    enditer2 = hiop->getOut()->endDescend();
    while(iter2 != enditer2) {
      hibool = *iter2;
      ++iter2;
      iter3 = loop->getOut()->beginDescend();
      enditer3 = loop->getOut()->endDescend();
      while(iter3 != enditer3) {
	lobool = *iter3;
	++iter3;

	in2.initPartial(lo2,hi2);
	
	if ((hibool->code() == CPUI_CBRANCH)&&(lobool->code()==CPUI_CBRANCH)) {
	  // Branching form of the equal operation
	  BlockBasic *hibooltrue,*hiboolfalse;
	  BlockBasic *lobooltrue,*loboolfalse;
	  SplitVarnode::getTrueFalse(hibool,notequalformhi,hibooltrue,hiboolfalse);
	  SplitVarnode::getTrueFalse(lobool,notequalformlo,lobooltrue,loboolfalse);
	  
	  if ((hibooltrue == lobool->getParent())&&	// hi is checked first then lo
	      (hiboolfalse == loboolfalse)&&
	      SplitVarnode::otherwiseEmpty(lobool)) {
	    if (SplitVarnode::prepareBoolOp(in1,in2,hibool)) {
	      setonlow = true;
	      SplitVarnode::createBoolOp(data,hibool,in1,in2,notequalformhi ? CPUI_INT_NOTEQUAL : CPUI_INT_EQUAL);
	  // We change lobool so that it always goes to the original TRUE block
	      data.opSetInput(lobool,data.newConstant(1,notequalformlo ? 0 : 1),1);
	      return true;
	    }
	  }
	  else if ((lobooltrue == hibool->getParent())&& // lo is checked first then hi
		   (hiboolfalse == loboolfalse)&&
		   SplitVarnode::otherwiseEmpty(hibool)) {
	    if (SplitVarnode::prepareBoolOp(in1,in2,lobool)) {
	      setonlow = false;
	      SplitVarnode::createBoolOp(data,lobool,in1,in2,notequalformlo ? CPUI_INT_NOTEQUAL : CPUI_INT_EQUAL);
	      // We change hibool so that it always goes to the original TRUE block
	      data.opSetInput(hibool,data.newConstant(1,notequalformhi ? 0 : 1),1);
	      return true;
	    }
	  }
	}
      }
    }
  }
  return false;
}

bool Equal2Form::checkLoForm(void)

{ // Assuming we have equal <- or <- xor <- hi1, verify if we have the full equal form
  Varnode *orvnin = orop->getIn(1-orhislot);
  if (orvnin == lo1) {		// lo2 is an implied 0
    loxor = (PcodeOp *)0;
    lo2 = (Varnode *)0;
    return true;
  }
  if (!orvnin->isWritten()) return false;
  loxor = orvnin->getDef();
  if (loxor->code() != CPUI_INT_XOR) return false;
  if (loxor->getIn(0) == lo1) {
    lo2 = loxor->getIn(1);
    return true;
  }
  else if (loxor->getIn(1) == lo1) {
    lo2 = loxor->getIn(0);
    return true;
  }
  return false;
}

bool Equal2Form::fillOutFromOr(Funcdata &data)

{ // We have filled in either or <- xor <- hi1,  OR,  or <- hi1
  // Now try to fill in the rest of the form
  Varnode *outvn = orop->getOut();
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = outvn->beginDescend();
  enditer = outvn->endDescend();
  while(iter != enditer) {
    equalop = *iter;
    ++iter;
    if ((equalop->code() != CPUI_INT_EQUAL)&&(equalop->code() != CPUI_INT_NOTEQUAL)) continue;
    if (!equalop->getIn(1)->isConstant()) continue;
    if (equalop->getIn(1)->getOffset() != 0) continue;

    if (!checkLoForm()) continue;
    if (!replace(data)) continue;
    return true;
  }
  return false;
}

bool Equal2Form::replace(Funcdata &data)

{
  if ((hi2==(Varnode *)0)&&(lo2==(Varnode *)0)) {
    param2.initPartial(in.getSize(),0); // Double precis zero constant
    return SplitVarnode::prepareBoolOp(in,param2,equalop);
  }
  if ((hi2==(Varnode *)0)&&(lo2->isConstant())) {
    param2.initPartial(in.getSize(),lo2->getOffset());
    return SplitVarnode::prepareBoolOp(in,param2,equalop);
  }
  if ((lo2==(Varnode *)0)&&(hi2->isConstant())) {
    param2.initPartial(in.getSize(),hi2->getOffset() << 8*lo1->getSize());
    return SplitVarnode::prepareBoolOp(in,param2,equalop);
  }
  if (lo2 == (Varnode *)0) {
    // Equal to a zero extended and shifted var
    return false;
  }
  if (hi2 == (Varnode *)0) {
    // Equal to a zero extended var
    return false;
  }
  if (hi2->isConstant()&&lo2->isConstant()) {
    uintb val = hi2->getOffset();
    val <<= 8*lo1->getSize();
    val |= lo2->getOffset();
    param2.initPartial(in.getSize(),val);
    return SplitVarnode::prepareBoolOp(in,param2,equalop);
  }
  if (hi2->isConstant()||lo2->isConstant()) {
    // Some kind of mixed form
    return false;
  }
  param2.initPartial(lo2,hi2);
  return SplitVarnode::prepareBoolOp(in,param2,equalop);
}

// Given a known double precis input, look for double precision compares of the form
//   a == b,  a != b
//
// We look for
//     res = ((hi1 ^ hi2) | (lo1 ^ lo2) == 0)
//  where hi2 or lo2 may be zero, and optimized out
bool Equal2Form::applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;
  hi1 = in.getHi();
  lo1 = in.getLo();

  if (op->code() == CPUI_INT_OR) {
    orop = op;
    orhislot = op->getSlot(hi1);
    hixor = (PcodeOp *)0;
    hi2 = (Varnode *)0;
    if (fillOutFromOr(data)) {
      SplitVarnode::replaceBoolOp(data,equalop,in,param2,equalop->code());
      return true;
    }
  }
  else {			// We see an XOR
    hixor = op;
    xorhislot = hixor->getSlot(hi1);
    hi2 = hixor->getIn(1-xorhislot);
    Varnode *vn = op->getOut();
    list<PcodeOp *>::const_iterator iter,enditer;
    iter = vn->beginDescend();
    enditer = vn->endDescend();
    while(iter != enditer) {
      orop = *iter;
      ++iter;
      if (orop->code() != CPUI_INT_OR) continue;
      orhislot = orop->getSlot(vn);
      if (fillOutFromOr(data)) {
	SplitVarnode::replaceBoolOp(data,equalop,in,param2,equalop->code());
	return true;
      }
    }
  }

  return false;
}

bool Equal3Form::verify(Varnode *h,Varnode *l,PcodeOp *aop)

{
  if (aop->code() != CPUI_INT_AND) return false;
  hi = h;
  lo = l;
  andop = aop;
  int4 hislot = andop->getSlot(hi);
  if (andop->getIn(1-hislot) != lo) return false;	// hi and lo must be ANDed together
  compareop = andop->getOut()->loneDescend();
  if (compareop == (PcodeOp *)0) return false;
  if ((compareop->code()!=CPUI_INT_EQUAL)&&(compareop->code()!=CPUI_INT_NOTEQUAL))
    return false;
  uintb allonesval = calc_mask(lo->getSize());
  smallc = compareop->getIn(1);
  if (!smallc->isConstant()) return false;
  if (smallc->getOffset() != allonesval) return false;
  return true;
}

// Given a known double precis input, look for double precision compares of the form
//   a == -1,  a != -1
//
// We look for
//     hi & lo == -1
bool Equal3Form::applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;
  if (!verify(in.getHi(),in.getLo(),op))
    return false;

  SplitVarnode in2(in.getSize(),calc_mask(in.getSize()));	// Create the -1 value
  if (!SplitVarnode::prepareBoolOp(in,in2,compareop)) return false;
  SplitVarnode::replaceBoolOp(data,compareop,in,in2,compareop->code());
  return true;
}

bool LessThreeWay::mapBlocksFromLow(BlockBasic *lobl)

{ // Assuming -lobl- is the block containing the low precision test of a double precision lessthan
  // Map out all the blocks if possible, otherwise return false
  lolessbl = lobl;
  if (lolessbl->sizeIn() != 1) return false;
  if (lolessbl->sizeOut() != 2) return false;
  hieqbl = (BlockBasic *)lolessbl->getIn(0);
  if (hieqbl->sizeIn() != 1) return false;
  if (hieqbl->sizeOut() != 2) return false;
  hilessbl = (BlockBasic *)hieqbl->getIn(0);
  if (hilessbl->sizeOut() != 2) return false;
  return true;
}

bool LessThreeWay::mapOpsFromBlocks(void)

{
  lolessbool = lolessbl->lastOp();
  if (lolessbool == (PcodeOp *)0) return false;
  if (lolessbool->code() != CPUI_CBRANCH) return false;
  hieqbool = hieqbl->lastOp();
  if (hieqbool == (PcodeOp *)0) return false;
  if (hieqbool->code() != CPUI_CBRANCH) return false;
  hilessbool = hilessbl->lastOp();
  if (hilessbool == (PcodeOp *)0) return false;
  if (hilessbool->code() != CPUI_CBRANCH) return false;

  Varnode *vn;

  hiflip = false;
  equalflip = false;
  loflip = false;
  midlessform = false;
  lolessiszerocomp = false;

  vn = hieqbool->getIn(1);
  if (!vn->isWritten()) return false;
  hiequal = vn->getDef();
  switch(hiequal->code()) {
  case CPUI_INT_EQUAL:
    midlessform = false;
    break;
  case CPUI_INT_NOTEQUAL:
    midlessform = false;
    break;
  case CPUI_INT_LESS:
    midlessequal = false;
    midsigncompare = false;
    midlessform = true;
    break;
  case CPUI_INT_LESSEQUAL:
    midlessequal = true;
    midsigncompare = false;
    midlessform = true;
    break;
  case CPUI_INT_SLESS:
    midlessequal = false;
    midsigncompare = true;
    midlessform = true;
    break;
  case CPUI_INT_SLESSEQUAL:
    midlessequal = true;
    midsigncompare = true;
    midlessform = true;
    break;
  default:
    return false;
  }

  vn = lolessbool->getIn(1);
  if (!vn->isWritten()) return false;
  loless = vn->getDef();
  switch(loless->code()) {	// Only unsigned forms
  case CPUI_INT_LESS:
    lolessequalform = false;
    break;
  case CPUI_INT_LESSEQUAL:
    lolessequalform = true;
    break;
  case CPUI_INT_EQUAL:
    if (!loless->getIn(1)->isConstant()) return false;
    if (loless->getIn(1)->getOffset()!=0) return false;
    lolessiszerocomp = true;
    lolessequalform = true;
    break;
  case CPUI_INT_NOTEQUAL:
    if (!loless->getIn(1)->isConstant()) return false;
    if (loless->getIn(1)->getOffset()!=0) return false;
    lolessiszerocomp = true;
    lolessequalform = false;
    break;
  default:
    return false;
  }

  vn = hilessbool->getIn(1);
  if (!vn->isWritten()) return false;
  hiless = vn->getDef();
  switch(hiless->code()){
  case CPUI_INT_LESS:
    hilessequalform = false;
    signcompare = false;
    break;
  case CPUI_INT_LESSEQUAL:
    hilessequalform = true;
    signcompare = false;
    break;
  case CPUI_INT_SLESS:
    hilessequalform = false;
    signcompare = true;
    break;
  case CPUI_INT_SLESSEQUAL:
    hilessequalform = true;
    signcompare = true;
    break;
  default:
    return false;
  }
  return true;
}

bool LessThreeWay::checkSignedness(void)

{
  if (midlessform) {
    if (midsigncompare != signcompare) return false;
  }
  return true;
}

bool LessThreeWay::normalizeHi(void)

{
  Varnode *tmpvn;
  vnhil1 = hiless->getIn(0);
  vnhil2 = hiless->getIn(1);
  if (vnhil1->isConstant()) {	// Start with constant on the right
    hiflip = !hiflip;
    hilessequalform = !hilessequalform;
    tmpvn = vnhil1;
    vnhil1 = vnhil2;
    vnhil2 = tmpvn;
  }
  hiconstform = false;
  if (vnhil2->isConstant()) {
    hiconstform = true;
    hival = vnhil2->getOffset();
    SplitVarnode::getTrueFalse(hilessbool,hiflip,hilesstrue,hilessfalse);
    int4 inc = 1;
    if (hilessfalse != hieqbl) {	// Make sure the hiless false branch goes to the hieq block
      hiflip = !hiflip;
      hilessequalform = !hilessequalform;
      tmpvn = vnhil1;
      vnhil1 = vnhil2;
      vnhil2 = tmpvn;
      inc = -1;
    }
    if (hilessequalform) {	// Make sure to normalize lessequal to less
      hival += inc;
      hival &= calc_mask(in.getSize());
      hilessequalform = false;
    }
    hival >>= in.getLo()->getSize() * 8;
  }
  else {
    if (hilessequalform) {	// Make sure the false branch contains the equal case
      hilessequalform = false;
      hiflip = !hiflip;
      tmpvn = vnhil1;
      vnhil1 = vnhil2;
      vnhil2 = tmpvn;
    }
  }
  return true;
}

bool LessThreeWay::normalizeMid(void)

{
  Varnode *tmpvn;
  vnhie1 = hiequal->getIn(0);
  vnhie2 = hiequal->getIn(1);
  if (vnhie1->isConstant()) {	// Make sure constant is on the right
    tmpvn = vnhie1;
    vnhie1 = vnhie2;
    vnhie2 = tmpvn;
    if (midlessform) {
      equalflip = !equalflip;
      midlessequal = !midlessequal;
    }
  }
  midconstform = false;
  if (vnhie2->isConstant()) {
    if (!hiconstform) return false;	// If mid is constant, both mid and hi must be constant
    midconstform = true;
    midval = vnhie2->getOffset();
    if (vnhie2->getSize() == in.getSize()) {
      // Convert to comparison on high part
      uintb lopart = midval & calc_mask(in.getLo()->getSize());
      midval >>= in.getLo()->getSize()*8;
      if (midlessform) {
	if (midlessequal) {
	  if (lopart!=calc_mask(in.getLo()->getSize())) return false;
	}
	else {
	  if (lopart != 0) return false;
	}
      }
      else
	return false;		// Compare is forcing restriction on lo part
    }
    if (midval != hival) {	// If the mid and hi don't match
      if (!midlessform) return false;
      midval += (midlessequal) ? 1 : -1; // We may just be one off
      midval &= calc_mask(in.getLo()->getSize());
      midlessequal = !midlessequal;
      if (midval != hival) return false; // Last chance
    }
  }
  if (midlessform) {		// Normalize to EQUAL
    
    if (!midlessequal) {
      equalflip = !equalflip;
    }
  }
  else {
    if (hiequal->code() == CPUI_INT_NOTEQUAL) {
      equalflip = !equalflip;
    }
  }
  return true;
}

bool LessThreeWay::normalizeLo(void)

{ // This is basically identical to normalizeHi
  Varnode *tmpvn;
  vnlo1 = loless->getIn(0);
  vnlo2 = loless->getIn(1);
  if (lolessiszerocomp) {
    loconstform = true;
    if (lolessequalform) {	// Treat as if we see vnlo1 <= 0
      loval = 1;
      lolessequalform = false;
    }
    else {			// Treat as if we see 0 < vnlo1
      loflip = !loflip;
      loval = 1;
    }
    return true;
  }
  if (vnlo1->isConstant()) {	// Make sure constant is on the right
    loflip = !loflip;
    lolessequalform = !lolessequalform;
    tmpvn = vnlo1;
    vnlo1 = vnlo2;
    vnlo2 = tmpvn;
  }
  loconstform = false;
  if (vnlo2->isConstant()) {	// Make sure normalize lessequal to less
    loconstform = true;
    loval = vnlo2->getOffset();
    if (lolessequalform) {
      loval += 1;
      loval &= calc_mask(vnlo2->getSize());
      lolessequalform = false;
    }
  }
  else {
    if (lolessequalform) {
      lolessequalform = false;
      loflip = !loflip;
      tmpvn = vnlo1;
      vnlo1 = vnlo2;
      vnlo2 = tmpvn;
    }
  }
  return true;
}

bool LessThreeWay::checkBlockForm(void)

{
  SplitVarnode::getTrueFalse(hilessbool,hiflip,hilesstrue,hilessfalse);
  SplitVarnode::getTrueFalse(lolessbool,loflip,lolesstrue,lolessfalse);
  SplitVarnode::getTrueFalse(hieqbool,equalflip,hieqtrue,hieqfalse);
  if ((hilesstrue == lolesstrue)&&
      (hieqfalse == lolessfalse)&&
      (hilessfalse == hieqbl)&&
      (hieqtrue == lolessbl)) {
    if (SplitVarnode::otherwiseEmpty(hieqbool)&&SplitVarnode::otherwiseEmpty(lolessbool))
      return true;
  }
  //  else if ((hilessfalse == lolessfalse)&&
  //	   (hieqfalse == lolesstrue)&&
  //	   (hilesstrue == hieqbl)&&
  //	   (hieqtrue == lolessbl)) {
  //    if (SplitVarnode::otherwiseEmpty(hieqbool)&&SplitVarnode::otherwiseEmpty(lolessbool))
  //      return true;
  //  }
  return false;
}

bool LessThreeWay::checkOpForm(void)

{
  lo = in.getLo();
  hi = in.getHi();

  if (midconstform) {
    if (!hiconstform) return false;
    if (vnhie2->getSize() == in.getSize()) {
      if ((vnhie1!=vnhil1)&&(vnhie1!=vnhil2)) return false;
    }
    else {
      if (vnhie1!=in.getHi()) return false;
    }
    // normalizeMid checks that midval == hival
  }
  else {
    // hi and hi2 must appear as inputs in both -hiless- and -hiequal-
    if ((vnhil1!=vnhie1)&&(vnhil1!=vnhie2)) return false;
    if ((vnhil2!=vnhie1)&&(vnhil2!=vnhie2)) return false;
  }
  if ((hi!=(Varnode *)0)&&(hi == vnhil1)) {
    if (hiconstform) return false;
    hislot = 0;
    hi2 = vnhil2;
    if (vnlo1 != lo) { // Pieces must be on the same side
      Varnode *tmpvn = vnlo1;
      vnlo1 = vnlo2;
      vnlo2 = tmpvn;
      if (vnlo1 != lo) return false;
      loflip = !loflip;
      lolessequalform = !lolessequalform;
    }
    lo2 = vnlo2;
  }
  else if ((hi!=(Varnode *)0)&&(hi == vnhil2)) {
    if (hiconstform) return false;
    hislot = 1;
    hi2 = vnhil1;
    if (vnlo2 != lo) {
      Varnode *tmpvn = vnlo1;
      vnlo1 = vnlo2;
      vnlo2 = tmpvn;
      if (vnlo2 != lo) return false;
      loflip = !loflip;
      lolessequalform = !lolessequalform;
    }
    lo2 = vnlo1;
  }
  else if (in.getWhole() == vnhil1) {
    if (!hiconstform) return false;
    if (!loconstform) return false;
    if (vnlo1 != lo) return false;
    hislot = 0;
  }
  else if (in.getWhole() == vnhil2) { // Whole constant appears on the left
    if (!hiconstform) return false;
    if (!loconstform) return false;
    if (vnlo2 != lo) {
      loflip = !loflip;
      loval -= 1;
      loval &= calc_mask(lo->getSize());
      if (vnlo1 != lo) return false;
    }
    hislot = 1;
  }
  else
    return false;

  return true;
}

void LessThreeWay::setOpCode(void)

{ // Decide on the opcode of the final double precision compare
  if (lolessequalform != hiflip)
    finalopc = signcompare ? CPUI_INT_SLESSEQUAL : CPUI_INT_LESSEQUAL;
  else
    finalopc = signcompare ? CPUI_INT_SLESS : CPUI_INT_LESS;
  if (hiflip) {
    hislot = 1-hislot;
    hiflip = false;
  }
}

bool LessThreeWay::setBoolOp(void)

{ // Make changes to the threeway branch so that it becomes a single double precision branch
  if (hislot==0) {
    if (SplitVarnode::prepareBoolOp(in,in2,hilessbool))
      return true;
  }
  else {
    if (SplitVarnode::prepareBoolOp(in2,in,hilessbool))
      return true;
  }
  return false;
}

bool LessThreeWay::mapFromLow(PcodeOp *op)

{ // Given the less than comparison for the lo piece and an input varnode explicitly marked as isPrecisLo
  // try to map out the threeway lessthan form
  PcodeOp *loop = op->getOut()->loneDescend();
  if (loop == (PcodeOp *)0) return false;
  if (!mapBlocksFromLow(loop->getParent())) return false;
  if (!mapOpsFromBlocks()) return false;
  if (!checkSignedness()) return false;
  if (!normalizeHi()) return false;
  if (!normalizeMid()) return false;
  if (!normalizeLo()) return false;
  if (!checkOpForm()) return false;
  if (!checkBlockForm()) return false;
  return true;
}

bool LessThreeWay::testReplace(void)

{
  setOpCode();
  if (hiconstform) {
    in2.initPartial(in.getSize(),(hival<<(8*in.getLo()->getSize()))|loval);
    if (!setBoolOp()) return false;
  }
  else {
    in2.initPartial(lo2,hi2);
    if (!setBoolOp()) return false;
  }
  return true;
}

// Given a known double precis input, look for double precision less than forms, i.e.
//    a < b,   a s< b,  a <= b,   a s<= b
//
// In this form we look for three separate comparison ops
//     hiless  = hi1 LESS hi2                   where LESS is in { <, s<, <=, s<= }
//     hiequal = hi1 == hi2
//     loless  = lo1 < lo2  OR  lo1 <= lo2      where the comparison is unsigned
//
// This boolean values are either combined in the following formula:
//     resbool = hiless || (hiequal && loless)
// OR each of the three initial comparison induces a CBRANCH
//                  if (hiless)  blocktrue  else  blocksecond
//     blocksecond: if (hiequal) blockthird else  blockfalse
//     blockthird:  if (loless) blocktrue else blockfalse
bool LessThreeWay::applyRule(SplitVarnode &i,PcodeOp *loop,bool workishi,Funcdata &data)

{
  if (workishi) return false;
  if (i.getLo() == (Varnode *)0) return false; // Doesn't necessarily need the hi
  in = i;
  if (!mapFromLow(loop)) return false;
  bool res = testReplace();
  if (res) {
    if (hislot==0)
      SplitVarnode::createBoolOp(data,hilessbool,in,in2,finalopc);
    else
      SplitVarnode::createBoolOp(data,hilessbool,in2,in,finalopc);
    // We change hieqbool so that it always goes to the original FALSE block
    data.opSetInput(hieqbool,data.newConstant(1,equalflip ? 1 : 0),1);
    // The lolessbool block now becomes unreachable and is eventually removed
  }
  return res;
}

// Sometimes double precision compares only involve the high portion of the value
// The canonical example being determining whether val > 0, where we only have to
// calculate (hi > 0).  This rule takes
//    hi COMPARE #const
// and transforms it to 
//    whole COMPARE #constextend
// where #constextend is built from #const by postpending either all 0 bits or 1 bits
bool LessConstForm::applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (i.getHi()==(Varnode *)0) return false; // We don't necessarily need the lo part
  in = i;
  vn = in.getHi();
  inslot = op->getSlot(vn);
  cvn = op->getIn(1-inslot);
  int4 losize = in.getSize() - vn->getSize();

  if (!cvn->isConstant()) return false;

  signcompare = ((op->code()==CPUI_INT_SLESSEQUAL)||(op->code()==CPUI_INT_SLESS));
  hilessequalform = ((op->code()==CPUI_INT_SLESSEQUAL)||(op->code()==CPUI_INT_LESSEQUAL));

  uintb val = cvn->getOffset() << 8*losize;
  if (hilessequalform != (inslot==1))
    val |= calc_mask(losize);

  // This rule can apply and mess up less,equal rules, so we only apply it if it directly affects a branch
  PcodeOp *desc = op->getOut()->loneDescend();
  if (desc == (PcodeOp *)0) return false;
  if (desc->code() != CPUI_CBRANCH) return false;

  constin.initPartial(in.getSize(),val);

  if (inslot==0) {
    if (SplitVarnode::prepareBoolOp(in,constin,op)) {
      SplitVarnode::replaceBoolOp(data,op,in,constin,op->code());
      return true;
    }
  }
  else {
    if (SplitVarnode::prepareBoolOp(constin,in,op)) {
      SplitVarnode::replaceBoolOp(data,op,constin,in,op->code());
      return true;
    }
  }
  
  return false;
}

bool ShiftForm::mapLeft(void)

{ // Assume reshi, reslo are filled in, fill in other ops and varnodes
  if (!reslo->isWritten()) return false;
  if (!reshi->isWritten()) return false;
  loshift = reslo->getDef();
  opc = loshift->code();
  if (opc != CPUI_INT_LEFT) return false;
  orop = reshi->getDef();
  if ((orop->code() != CPUI_INT_OR)&&(orop->code() != CPUI_INT_XOR)&&(orop->code() != CPUI_INT_ADD))
    return false;
  midlo = orop->getIn(0);
  midhi = orop->getIn(1);
  if (!midlo->isWritten()) return false;
  if (!midhi->isWritten()) return false;
  if (midhi->getDef()->code() != CPUI_INT_LEFT) {
    Varnode *tmpvn = midhi;
    midhi = midlo;
    midlo = tmpvn;
  }
  midshift = midlo->getDef();
  if (midshift->code() != CPUI_INT_RIGHT) return false;	// Must be unsigned RIGHT
  hishift = midhi->getDef();
  if (hishift->code() != CPUI_INT_LEFT) return false;

  if (lo != loshift->getIn(0)) return false;
  if (hi != hishift->getIn(0)) return false;
  if (lo != midshift->getIn(0)) return false;
  salo = loshift->getIn(1);
  sahi = hishift->getIn(1);
  samid = midshift->getIn(1);
  return true;
}

bool ShiftForm::mapRight(void)

{ // Assume reshi, reslo are filled in, fill in other ops and varnodes
  if (!reslo->isWritten()) return false;
  if (!reshi->isWritten()) return false;
  hishift = reshi->getDef();
  opc = hishift->code();
  if ((opc != CPUI_INT_RIGHT)&&(opc != CPUI_INT_SRIGHT)) return false;
  orop = reslo->getDef();
  if ((orop->code() != CPUI_INT_OR)&&(orop->code() != CPUI_INT_XOR)&&(orop->code() != CPUI_INT_ADD))
    return false;
  midlo = orop->getIn(0);
  midhi = orop->getIn(1);
  if (!midlo->isWritten()) return false;
  if (!midhi->isWritten()) return false;
  if (midlo->getDef()->code() != CPUI_INT_RIGHT) { // Must be unsigned RIGHT
    Varnode *tmpvn = midhi;
    midhi = midlo;
    midlo = tmpvn;
  }
  midshift = midhi->getDef();
  if (midshift->code() != CPUI_INT_LEFT) return false;
  loshift = midlo->getDef();
  if (loshift->code() != CPUI_INT_RIGHT) return false; // Must be unsigned RIGHT

  if (lo != loshift->getIn(0)) return false;
  if (hi != hishift->getIn(0)) return false;
  if (hi != midshift->getIn(0)) return false;
  salo = loshift->getIn(1);
  sahi = hishift->getIn(1);
  samid = midshift->getIn(1);
  return true;
}

bool ShiftForm::verifyShiftAmount(void)

{ // Make sure all the shift amount varnodes are consistent
  if (!salo->isConstant()) return false;
  if (!samid->isConstant()) return false;
  if (!sahi->isConstant()) return false;
  uintb val = salo->getOffset();
  if (val != sahi->getOffset()) return false;
  if (val >= 8*lo->getSize()) return false; // If shift amount is so big, we would not use this form
  val = 8*lo->getSize() - val;
  if (samid->getOffset() != val) return false;
  return true;
}

bool ShiftForm::verifyLeft(Varnode *h,Varnode *l,PcodeOp *loop)

{
  hi = h;
  lo = l;

  loshift = loop;
  reslo = loshift->getOut();
  
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = hi->beginDescend();
  enditer = hi->endDescend();
  while(iter != enditer) {
    hishift = *iter;
    ++iter;
    if (hishift->code() != CPUI_INT_LEFT) continue;
    Varnode *outvn = hishift->getOut();
    list<PcodeOp *>::const_iterator iter2,enditer2;
    iter2 = outvn->beginDescend();
    enditer2 = outvn->endDescend();
    while(iter2 != enditer2) {
      midshift = *iter2;
      ++iter2;
      Varnode *tmpvn = midshift->getOut();
      if (tmpvn == (Varnode *)0) continue;
      reshi = tmpvn;
      if (!mapLeft()) continue;
      if (!verifyShiftAmount()) continue;
      return true;
    }
  }
  return false;
}

bool ShiftForm::verifyRight(Varnode *h,Varnode *l,PcodeOp *hiop)

{
  hi = h;
  lo = l;
  hishift = hiop;
  reshi = hiop->getOut();
  
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = lo->beginDescend();
  enditer = lo->endDescend();
  while(iter != enditer) {
    loshift = *iter;
    ++iter;
    if (loshift->code() != CPUI_INT_RIGHT) continue;
    Varnode *outvn = loshift->getOut();
    list<PcodeOp *>::const_iterator iter2,enditer2;
    iter2 = outvn->beginDescend();
    enditer2 = outvn->endDescend();
    while(iter2 != enditer2) {
      midshift = *iter2;
      ++iter2;
      Varnode *tmpvn = midshift->getOut();
      if (tmpvn == (Varnode *)0) continue;
      reslo = tmpvn;
      if (!mapRight()) continue;
      if (!verifyShiftAmount()) continue;
      return true;
    }
  }
  return false;
}

bool ShiftForm::applyRuleLeft(SplitVarnode &i,PcodeOp *loop,bool workishi,Funcdata &data)

{
  if (workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;

  if (!verifyLeft(in.getHi(),in.getLo(),loop))
    return false;

  out.initPartial(reslo,reshi);
  existop = SplitVarnode::prepareShiftOp(out,in);
  if (existop == (PcodeOp *)0)
    return false;
  SplitVarnode::createShiftOp(data,out,in,salo,existop,opc);
  return true;
}

bool ShiftForm::applyRuleRight(SplitVarnode &i,PcodeOp *hiop,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;

  if (!verifyRight(in.getHi(),in.getLo(),hiop))
    return false;

  out.initPartial(reslo,reshi);
  existop = SplitVarnode::prepareShiftOp(out,in);
  if (existop == (PcodeOp *)0)
    return false;
  SplitVarnode::createShiftOp(data,out,in,salo,existop,opc);
  return true;
}

bool MultForm::mapResHiSmallConst(Varnode *rhi)

{ // find reshi=hi1*lo2 + (tmp>>32)
  reshi = rhi;
  if (!reshi->isWritten()) return false;
  add1 = reshi->getDef();
  if (add1->code() != CPUI_INT_ADD) return false;
  Varnode *ad1,*ad2;
  ad1 = add1->getIn(0);
  ad2 = add1->getIn(1);
  if (!ad1->isWritten()) return false;
  if (!ad2->isWritten()) return false;
  multhi1 = ad1->getDef();
  if (multhi1->code() != CPUI_INT_MULT) {
    subhi = multhi1;
    multhi1 = ad2->getDef();
  }
  else
    subhi = ad2->getDef();
  if (multhi1->code() != CPUI_INT_MULT) return false;
  if (subhi->code() != CPUI_SUBPIECE) return false;
  midtmp = subhi->getIn(0);
  if (!midtmp->isWritten()) return false;
  multlo = midtmp->getDef();
  if (multlo->code() != CPUI_INT_MULT) return false;
  lo1zext = multlo->getIn(0);
  lo2zext = multlo->getIn(1);
  return true;
}
  
bool MultForm::mapResHi(Varnode *rhi)

{ // Find reshi=hi1*lo2 + hi2*lo1 + (tmp>>32)
  reshi = rhi;
  if (!reshi->isWritten()) return false;
  add1 = reshi->getDef();
  if (add1->code() != CPUI_INT_ADD) return false;
  Varnode *ad1,*ad2,*ad3;
  ad1 = add1->getIn(0);
  ad2 = add1->getIn(1);
  if (!ad1->isWritten()) return false;
  if (!ad2->isWritten()) return false;
  add2 = ad1->getDef();
  if (add2->code() == CPUI_INT_ADD) {
    ad1 = add2->getIn(0);
    ad3 = add2->getIn(1);
  }
  else {
    add2 = ad2->getDef();
    if (add2->code() != CPUI_INT_ADD) return false;
    ad2 = add2->getIn(0);
    ad3 = add2->getIn(1);
  }
  if (!ad1->isWritten()) return false;
  if (!ad2->isWritten()) return false;
  if (!ad3->isWritten()) return false;
  subhi = ad1->getDef();
  if (subhi->code() == CPUI_SUBPIECE) {
    multhi1 = ad2->getDef();
    multhi2 = ad3->getDef();
  }
  else {
    subhi = ad2->getDef();
    if (subhi->code() == CPUI_SUBPIECE) {
      multhi1 = ad1->getDef();
      multhi2 = ad3->getDef();
    }
    else {
      subhi = ad3->getDef();
      if (subhi->code() == CPUI_SUBPIECE) {
	multhi1 = ad1->getDef();
	multhi2 = ad2->getDef();
      }
      else
	return false;
    }
  }
  if (multhi1->code() != CPUI_INT_MULT) return false;
  if (multhi2->code() != CPUI_INT_MULT) return false;

  midtmp = subhi->getIn(0);
  if (!midtmp->isWritten()) return false;
  multlo = midtmp->getDef();
  if (multlo->code() != CPUI_INT_MULT) return false;
  lo1zext = multlo->getIn(0);
  lo2zext = multlo->getIn(1);
  return true;
}

bool MultForm::findLoFromInSmallConst(void)

{ // Assuming we have -multhi1-, -lo1-, and -hi1- in hand, try to label -lo2-
  Varnode *vn1 = multhi1->getIn(0);
  Varnode *vn2 = multhi1->getIn(1);
  if (vn1 == hi1)
    lo2 = vn2;
  else if (vn2 == hi1)
    lo2 = vn1;
  else
    return false;
  if (!lo2->isConstant()) return false;
  hi2 = (Varnode *)0;		// hi2 is an implied zero in this case
  return true;
}

bool MultForm::findLoFromIn(void)

{ // Assuming we have -multhi1-, -multhi2-, -lo1-, and -hi1- in hand, try to label lo2/hi2 pair
  Varnode *vn1 = multhi1->getIn(0);
  Varnode *vn2 = multhi1->getIn(1);
  if ((vn1 != lo1)&&(vn2!=lo1)) { // Try to normalize so multhi1 contains lo1
    PcodeOp *tmpop = multhi1;
    multhi1 = multhi2;
    multhi2 = tmpop;
    vn1 = multhi1->getIn(0);
    vn2 = multhi1->getIn(1);
  }
  if (vn1 == lo1)
    hi2 = vn2;
  else if (vn2 == lo1)
    hi2 = vn1;
  else
    return false;
  vn1 = multhi2->getIn(0);	// multhi2 should contain hi1 and lo2
  vn2 = multhi2->getIn(1);
  if (vn1 == hi1)
    lo2 = vn2;
  else if (vn2 == hi1)
    lo2 = vn1;
  else
    return false;

  return true;
}

bool MultForm::zextOf(Varnode *big,Varnode *small)

{ // Verify that big is (some form of) a zero extension of small
  PcodeOp *op;
  if (small->isConstant()) {
    if (!big->isConstant()) return false;
    if (big->getOffset() == small->getOffset()) return true;
    return false;
  }
  if (!big->isWritten()) return false;
  op = big->getDef();
  if (op->code() == CPUI_INT_ZEXT)
    return (op->getIn(0) == small);
  if (op->code() == CPUI_INT_AND) {
    if (!op->getIn(1)->isConstant()) return false;
    if (op->getIn(1)->getOffset() != calc_mask(small->getSize())) return false;
    Varnode *whole = op->getIn(0);
    if (!small->isWritten()) return false;
    PcodeOp *sub = small->getDef();
    if (sub->code() != CPUI_SUBPIECE) return false;
    return (sub->getIn(0) == whole);
  }
  return false;
}

bool MultForm::verifyLo(void)

{ // Given we have labelled lo1/hi1 lo2/hi2, make sure midtmp is formed properly
  // This also works for the small constant model  lo1/hi1 and lo2 const.
  if (subhi->getIn(1)->getOffset() != lo1->getSize()) return false;
  if (zextOf(lo1zext,lo1)) {
    if (zextOf(lo2zext,lo2))
      return true;
  }
  else if (zextOf(lo1zext,lo2)) {
    if (zextOf(lo2zext,lo1))
      return true;
  }
  return false;
}

bool MultForm::findResLo(void)

{ // Assuming we found -midtmp-, find potential reslo
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = midtmp->beginDescend();
  enditer = midtmp->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->code() != CPUI_SUBPIECE) continue;
    if (op->getIn(1)->getOffset() != 0) continue; // Must grab low bytes
    reslo = op->getOut();
    if (reslo->getSize() != lo1->getSize()) continue;
    return true;
  }
  // If we reach here, it may be that separate multiplies of lo1*lo2 were used for reshi and reslo
  iter = lo1->beginDescend();
  enditer = lo1->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->code() != CPUI_INT_MULT) continue;
    Varnode *vn1 = op->getIn(0);
    Varnode *vn2 = op->getIn(1);
    if (lo2->isConstant()) {
      if ((!vn1->isConstant() || (vn1->getOffset() != lo2->getOffset())) &&
	  (!vn2->isConstant() || (vn2->getOffset() != lo2->getOffset())))
	continue;
    }
    else 
      if ((op->getIn(0)!=lo2)&&(op->getIn(1)!=lo2)) continue;
    reslo = op->getOut();
    return true;
  }
  return false;
}

bool MultForm::mapFromInSmallConst(Varnode *rhi)

{
  if (!mapResHiSmallConst(rhi)) return false;
  if (!findLoFromInSmallConst()) return false;
  if (!verifyLo()) return false;
  if (!findResLo()) return false;
  return true;
}

bool MultForm::mapFromIn(Varnode *rhi)

{ // Try to do full mapping from -in- given a putative reshi
  if (!mapResHi(rhi)) return false;
  if (!findLoFromIn()) return false;
  if (!verifyLo()) return false;
  if (!findResLo()) return false;
  return true;
}

bool MultForm::replace(Funcdata &data)

{ // We have matched a double precision multiply, now transform to logical variables
  outdoub.initPartial(reslo,reshi);
  in2.initPartial(lo2,hi2);
  existop = SplitVarnode::prepareBinaryOp(outdoub,in,in2);
  if (existop == (PcodeOp *)0)
    return false;
  SplitVarnode::createBinaryOp(data,outdoub,in,in2,existop,CPUI_INT_MULT);
  return true;
}

bool MultForm::verify(Varnode *h,Varnode *l,PcodeOp *hop)

{
  hi1 = h;
  lo1 = l;
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = hop->getOut()->beginDescend();
  enditer = hop->getOut()->endDescend();
  while(iter != enditer) {
    add1 = *iter;
    ++iter;
    if (add1->code() != CPUI_INT_ADD) continue;
    list<PcodeOp *>::const_iterator iter2,enditer2;
    iter2 = add1->getOut()->beginDescend();
    enditer2 = add1->getOut()->endDescend();
    while(iter2 != enditer2) {
      add2 = *iter2;
      ++iter2;
      if (add2->code() != CPUI_INT_ADD) continue;
      if (mapFromIn(add2->getOut()))
	return true;
    }
    if (mapFromIn(add1->getOut()))
      return true;
    if (mapFromInSmallConst(add1->getOut()))
      return true;
  }
  return false;
}

bool MultForm::applyRule(SplitVarnode &i,PcodeOp *hop,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;

  if (!verify(in.getHi(),in.getLo(),hop))
    return false;

  if (replace(data)) return true;
  return false;
}

// Given a known double precis coming together with two other pieces (via phi-nodes)
// Create a double precision phi-node
bool PhiForm::verify(Varnode *h,Varnode *l,PcodeOp *hphi)

{
  hibase = h;
  lobase = l;
  hiphi = hphi;

  inslot = hiphi->getSlot(hibase);

  if (hiphi->getOut()->hasNoDescend()) return false;
  blbase = hiphi->getParent();

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = lobase->beginDescend();
  enditer = lobase->endDescend();
  while(iter != enditer) {
    lophi = *iter;
    ++iter;
    if (lophi->code() != CPUI_MULTIEQUAL) continue;
    if (lophi->getParent() != blbase) continue;
    if (lophi->getIn(inslot) != lobase) continue;
    return true;
  }
  return false;
}

bool PhiForm::applyRule(SplitVarnode &i,PcodeOp *hphi,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;

  if (!verify(in.getHi(),in.getLo(),hphi))
    return false;

  int4 numin = hiphi->numInput();
  vector<SplitVarnode> inlist;
  for(int4 i=0;i<numin;++i) {
    Varnode *vhi = hiphi->getIn(i);
    Varnode *vlo = lophi->getIn(i);
    inlist.push_back(SplitVarnode(vlo,vhi));
  }
  outvn.initPartial(lophi->getOut(),hiphi->getOut());
  existop = SplitVarnode::preparePhiOp(outvn,inlist);
  if (existop != (PcodeOp *)0) {
    SplitVarnode::createPhiOp(data,outvn,inlist,existop);
    return true;
  }
  return false;
}

bool IndirectForm::verify(Varnode *h,Varnode *l,PcodeOp *ind)

{  // Verify the basic double precision indirect form and fill out the pieces
  hi = h;
  lo = l;
  indhi = ind;
  if (indhi->getIn(1)->getSpace()->getType()!=IPTR_IOP) return false;
  affector = PcodeOp::getOpFromConst(indhi->getIn(1)->getAddr());
  if (affector->isDead()) return false;
  reshi = indhi->getOut();
  if (reshi->getSpace()->getType() == IPTR_INTERNAL) return false;		// Indirect must not be through a temporary

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = lo->beginDescend();
  enditer = lo->endDescend();
  while(iter != enditer) {
    indlo = *iter;
    ++iter;
    if (indlo->code() != CPUI_INDIRECT) continue;
    if (indlo->getIn(1)->getSpace()->getType()!=IPTR_IOP) continue;
    if (affector != PcodeOp::getOpFromConst(indlo->getIn(1)->getAddr())) continue;	// hi and lo must be affected by same op
    reslo = indlo->getOut();
    if (reslo->getSpace()->getType() == IPTR_INTERNAL) return false;		// Indirect must not be through a temporary
    return true;
  }
  return false;
}

bool IndirectForm::applyRule(SplitVarnode &i,PcodeOp *ind,bool workishi,Funcdata &data)

{
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  in = i;
  if (!verify(in.getHi(),in.getLo(),ind))
    return false;

  outvn.initPartial(reslo,reshi);

  if (!SplitVarnode::prepareIndirectOp(in,affector))
    return false;
  SplitVarnode::replaceIndirectOp(data,outvn,in,affector);
  return true;
}

void RuleDoubleIn::reset(Funcdata &data)

{
  data.setDoublePrecisRecovery(true); // Mark that we are doing double precision recovery
}

void RuleDoubleIn::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleDoubleIn::applyOp(PcodeOp *op,Funcdata &data)

{ // Try to push double precision object "down" one level from input
  Varnode *outvn = op->getOut();
  if (!outvn->isPrecisLo()) return 0;
  if (data.hasUnreachableBlocks()) return 0;

  vector<SplitVarnode> splitvec;
  SplitVarnode::wholeList(op->getIn(0),splitvec);
  if (splitvec.empty()) return 0;
  for(int4 i=0;i<splitvec.size();++i) {
    SplitVarnode &in(splitvec[i]);
    int4 res = SplitVarnode::applyRuleIn(in,data);
    if (res != 0)
      return res;
  }
  return 0;
}

PcodeOp *RuleDoubleLoad::noWriteConflict(PcodeOp *op1,PcodeOp *op2,AddrSpace *spc)

{ // Return NULL if some op between op1 and op2 could write to
  // -range-. Otherwise return pointer to latest op.
  const BlockBasic *bb = op1->getParent();

  // Force the two ops to be in the same basic block
  if (bb != op2->getParent()) return (PcodeOp *)0;
  if (op2->getSeqNum().getOrder() < op1->getSeqNum().getOrder()) {
    PcodeOp *tmp = op2;
    op2 = op1;
    op1 = tmp;
  }
  list<PcodeOp *>::iterator iter = op1->getBasicIter();
  list<PcodeOp *>::iterator enditer = op2->getBasicIter();

  ++iter;
  while(iter != enditer) {
    PcodeOp *curop = *iter;
    Varnode *outvn;
    ++iter;
    switch(curop->code()) {
    case CPUI_STORE:
      if (Address::getSpaceFromConst(curop->getIn(0)->getAddr()) == spc)
	return (PcodeOp *)0;	// Don't go any further trying to resolve alias
      break;
    case CPUI_CALL:
    case CPUI_CALLIND:
    case CPUI_CALLOTHER:
    case CPUI_RETURN:
    case CPUI_BRANCH:
    case CPUI_CBRANCH:
    case CPUI_BRANCHIND:
      return (PcodeOp *)0;
    default:
      outvn = curop->getOut();
      if (outvn != (Varnode *)0) {
	if (outvn->getSpace() == spc)
	  return (PcodeOp *)0;
      }
      break;
    }
  }
  return op2;
}

void RuleDoubleLoad::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RuleDoubleLoad::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *loadlo,*loadhi;	// Load from lowest address, highest (NOT significance)
  AddrSpace *spc;
  int4 size;

  if (!op->getIn(0)->isWritten()) return 0;
  if (!op->getIn(1)->isWritten()) return 0;
  if (!SplitVarnode::testContiguousLoad(op->getIn(0)->getDef(),op->getIn(1)->getDef(),false,loadlo,loadhi,spc,size))
    return 0;

  PcodeOp *latest = noWriteConflict(loadlo,loadhi,spc);
  if (latest == (PcodeOp *)0) return 0; // There was a conflict

  // Create new load op that combines the two smaller loads
  PcodeOp *newload = data.newOp(2,latest->getAddr());
  Varnode *vnout = data.newUniqueOut(size,newload);
  Varnode *spcvn = data.newVarnodeSpace(spc);
  data.opSetOpcode(newload,CPUI_LOAD);
  data.opSetInput(newload,spcvn,0);
  Varnode *addrvn = loadlo->getIn(1);
  if (addrvn->isConstant())
    addrvn = data.newConstant(addrvn->getSize(),addrvn->getOffset());
  data.opSetInput(newload,addrvn,1);
  // We need to guarantee that -newload- reads -addrvn- after
  // it has been defined. So insert it after the latest.
  data.opInsertAfter(newload,latest);

  // Change the concatenation to a copy from the big load
  data.opRemoveInput(op,1);
  data.opSetOpcode(op,CPUI_COPY);
  data.opSetInput(op,vnout,0);

  return 1;
}

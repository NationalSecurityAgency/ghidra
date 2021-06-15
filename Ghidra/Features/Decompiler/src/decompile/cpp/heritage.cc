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
#include "heritage.hh"
#include "funcdata.hh"
#include "prefersplit.hh"

/// Update disjoint cover making sure (addr,size) is contained in a single element
/// and return iterator to this element. Pass back \b intersect value:
///   - 0 if the only intersection is with range from the same pass
///   - 1 if there is a partial intersection with something old
///   - 2 if the range is contained in an old range
/// \param addr is the starting address of the range to add
/// \param size is the number of bytes in the range
/// \param pass is the pass number when the range was heritaged
/// \param intersect is a reference for passing back the intersect code
/// \return the iterator to the map element containing the added range
LocationMap::iterator LocationMap::add(Address addr,int4 size,int4 pass,int4 &intersect)

{
  iterator iter = themap.lower_bound(addr);
  if (iter != themap.begin())
    --iter;
  if ((iter!=themap.end())&&(-1 == addr.overlap(0,(*iter).first,(*iter).second.size)))
    ++iter;

  int4 where=0;
  intersect = 0;
  if ((iter!=themap.end())&&(-1!=(where=addr.overlap(0,(*iter).first,(*iter).second.size)))) {
    if (where+size<=(*iter).second.size) {
      intersect = ((*iter).second.pass < pass) ? 2 : 0; // Completely contained in previous element
      return iter;
    }
    addr = (*iter).first;
    size = where+size;
    if ((*iter).second.pass < pass)
      intersect = 1;			// Partial overlap with old element
    themap.erase(iter++);
  }
  while((iter!=themap.end())&&(-1!=(where=(*iter).first.overlap(0,addr,size)))) {
    if (where+(*iter).second.size>size)
      size = where+(*iter).second.size;
    if ((*iter).second.pass < pass)
      intersect = 1;
    themap.erase(iter++);
  }
  iter = themap.insert(pair<Address,SizePass>( addr, SizePass() )).first;
  (*iter).second.size = size;
  (*iter).second.pass = pass;
  return iter;
}

/// If the given address was heritaged, return (the iterator to) the SizeMap entry
/// describing the associated range and when it was heritaged.
/// \param addr is the given address
/// \return the iterator to the SizeMap entry or the end iterator is the address is unheritaged
LocationMap::iterator LocationMap::find(const Address &addr)

{
  iterator iter = themap.upper_bound(addr); // First range after address
  if (iter == themap.begin()) return themap.end();
  --iter;			// First range before or equal to address
  if (-1!=addr.overlap(0,(*iter).first,(*iter).second.size))
    return iter;
  return themap.end();
}

/// Return the pass number when the given address was heritaged, or -1 if it was not heritaged
/// \param addr is the given address
/// \return the pass number of -1
int4 LocationMap::findPass(const Address &addr) const

{
  map<Address,SizePass>::const_iterator iter = themap.upper_bound(addr); // First range after address
  if (iter == themap.begin()) return -1;
  --iter;			// First range before or equal to address
  if (-1!=addr.overlap(0,(*iter).first,(*iter).second.size))
    return (*iter).second.pass;
  return -1;
}

/// Any basic blocks currently in \b this queue are removed. Space is
/// reserved for a new set of prioritized stacks.
/// \param maxdepth is the number of stacks to allocate
void PriorityQueue::reset(int4 maxdepth) 

{
  if ((curdepth==-1)&&(maxdepth==queue.size()-1)) return; // Already reset
  queue.clear();
  queue.resize(maxdepth+1);
  curdepth = -1;
}

/// The block is pushed onto the stack of the given priority.
/// \param bl is the block being added to the queue
/// \param depth is the priority to associate with the block
void PriorityQueue::insert(FlowBlock *bl,int4 depth)

{
  queue[depth].push_back(bl);
  if (depth > curdepth)
    curdepth = depth;
}

/// The block at the top of the highest priority non-empty stack is popped
/// and returned.  This will always return a block. It shouldn't be called if the
/// queue is empty.
/// \return the highest priority block
FlowBlock *PriorityQueue::extract(void)

{
  FlowBlock *res = queue[curdepth].back();
  queue[curdepth].pop_back();
  while(queue[curdepth].empty()) {
    curdepth -= 1;
    if (curdepth <0) break;
  }
  return res;
}

/// Initialize heritage state information for a particular address space
/// \param spc is the address space
HeritageInfo::HeritageInfo(AddrSpace *spc)

{
  if (spc == (AddrSpace *)0) {
    space = (AddrSpace *)0;
    delay = 0;
    deadcodedelay = 0;
    hasCallPlaceholders = false;
  }
  else if (!spc->isHeritaged()) {
    space = (AddrSpace *)0;
    delay = spc->getDelay();
    deadcodedelay = spc->getDeadcodeDelay();
    hasCallPlaceholders = false;
  }
  else {
    space = spc;
    delay = spc->getDelay();
    deadcodedelay = spc->getDeadcodeDelay();
    hasCallPlaceholders = (spc->getType() == IPTR_SPACEBASE);
  }
  deadremoved = 0;
  warningissued = false;
  loadGuardSearch = false;
}

void HeritageInfo::reset(void)

{
  // Leave any override intact: deadcodedelay = delay;
  deadremoved = 0;
  if (space != (AddrSpace *)0)
    hasCallPlaceholders = (space->getType() == IPTR_SPACEBASE);
  warningissued = false;
  loadGuardSearch = false;
}

/// Instantiate the heritage manager for a particular function.
/// \param data is the function
Heritage::Heritage(Funcdata *data)

{
  fd = data;
  pass = 0;
  maxdepth = -1;
}

void Heritage::clearInfoList(void)

{
  vector<HeritageInfo>::iterator iter;
  for(iter=infolist.begin();iter!=infolist.end();++iter)
    (*iter).reset();
}

/// \brief Remove deprecated CPUI_MULTIEQUAL or CPUI_INDIRECT ops, preparing to re-heritage
///
/// If a previous Varnode was heritaged through a MULTIEQUAL or INDIRECT op, but now
/// a larger range containing the Varnode is being heritaged, we throw away the op,
/// letting the data-flow for the new larger range determine the data-flow for the
/// old Varnode.  The original Varnode is redefined as the output of a SUBPIECE
/// of a larger free Varnode.
/// \param remove is the list of Varnodes written by MULTIEQUAL or INDIRECT
/// \param addr is the start of the larger range
/// \param size is the size of the range
void Heritage::removeRevisitedMarkers(const vector<Varnode *> &remove,const Address &addr,int4 size)

{
  vector<Varnode *> newInputs;
  list<PcodeOp *>::iterator pos;
  for(int4 i=0;i<remove.size();++i) {
    Varnode *vn = remove[i];
    PcodeOp *op = vn->getDef();
    BlockBasic *bl = op->getParent();
    if (op->code() == CPUI_INDIRECT) {
      Varnode *iopVn = op->getIn(1);
      PcodeOp *targetOp =  PcodeOp::getOpFromConst(iopVn->getAddr());
      if (targetOp->isDead())
	pos = op->getBasicIter();
      else
	pos = targetOp->getBasicIter();
      ++pos;		// Insert SUBPIECE after target of INDIRECT
    }
    else {
      pos = op->getBasicIter();	// Insert SUBPIECE after all MULTIEQUALs in block
      ++pos;
      while(pos != bl->endOp() && (*pos)->code() == CPUI_MULTIEQUAL)
	++pos;
    }
    int4 offset = vn->overlap(addr,size);
    fd->opUninsert(op);
    newInputs.clear();
    Varnode *big = fd->newVarnode(size,addr);
    big->setActiveHeritage();
    newInputs.push_back(big);
    newInputs.push_back(fd->newConstant(4, offset));
    fd->opSetOpcode(op, CPUI_SUBPIECE);
    fd->opSetAllInput(op, newInputs);
    fd->opInsert(op, bl, pos);
    vn->setWriteMask();
  }
}

/// \brief Collect free reads, writes, and inputs in the given address range
///
/// \param addr is the starting address of the range
/// \param size is the number of bytes in the range
/// \param read will hold any read Varnodes in the range
/// \param write will hold any written Varnodes
/// \param input will hold any input Varnodes
/// \param remove will hold any PcodeOps that need to be removed
/// \return the maximum size of a write
int4 Heritage::collect(Address addr,int4 size,
		      vector<Varnode *> &read,vector<Varnode *> &write,
		      vector<Varnode *> &input,vector<Varnode *> &remove) const

{
  Varnode *vn;
  VarnodeLocSet::const_iterator viter = fd->beginLoc(addr);
  VarnodeLocSet::const_iterator enditer;
  uintb start = addr.getOffset();
  addr = addr + size;
  if (addr.getOffset() < start) {	// Wraparound
    Address tmp(addr.getSpace(),addr.getSpace()->getHighest());
    enditer = fd->endLoc(tmp);
  }
  else
    enditer = fd->beginLoc(addr);
  int4 maxsize = 0;
  while( viter != enditer ) {
    vn = *viter;
    if (!vn->isWriteMask()) {
      if (vn->isWritten()) {
	if (vn->getSize() < size && vn->getDef()->isMarker())
	  remove.push_back(vn);
	else {
	  if (vn->getSize() > maxsize) // Look for maximum write size
	    maxsize = vn->getSize();
	  write.push_back(vn);
	}
      }
      else if ((!vn->isHeritageKnown())&&(!vn->hasNoDescend()))
	read.push_back(vn);
      else if (vn->isInput())
	input.push_back(vn);
    }
    ++viter;
  }
  return maxsize;
}

/// \brief Determine if the address range is affected by the given call p-code op
///
/// We assume the op is CALL, CALLIND, CALLOTHER, or NEW and that its
/// output overlaps the given address range. We look up any effect
/// the op might have on the address range.
/// \param addr is the starting address of the range
/// \param size is the number of bytes in the range
/// \param op is the given \e call p-code op
/// \return \b true, unless the range is unaffected by the op
bool Heritage::callOpIndirectEffect(const Address &addr,int4 size,PcodeOp *op) const

{
  if ((op->code() == CPUI_CALL)||(op->code() == CPUI_CALLIND)) {
    // We should be able to get the callspec
    FuncCallSpecs *fc = fd->getCallSpecs(op);
    if (fc == (FuncCallSpecs *)0) return true;		// Assume indirect effect
    return (fc->hasEffectTranslate(addr,size) != EffectRecord::unaffected);
  }
  // If we reach here, this is a CALLOTHER, NEW
  // We assume these do not have effects on -fd- variables except for op->getOut().
  return false;
}

/// \brief Normalize the size of a read Varnode, prior to heritage
///
/// Given a Varnode being read that does not match the (larger) size
/// of the address range currently being linked, create a Varnode of
/// the correct size and define the original Varnode as a SUBPIECE.
/// \param vn is the given too small Varnode
/// \param addr is the start of the (larger) range
/// \param size is the number of bytes in the range
/// \return the new larger Varnode
Varnode *Heritage::normalizeReadSize(Varnode *vn,const Address &addr,int4 size)

{
  int4 overlap;
  Varnode *vn1,*vn2;
  PcodeOp *op,*newop;

  list<PcodeOp *>::const_iterator oiter = vn->beginDescend();
  op = *oiter++;
  if (oiter != vn->endDescend())
    throw LowlevelError("Free varnode with multiple reads");
  newop = fd->newOp(2,op->getAddr());
  fd->opSetOpcode(newop,CPUI_SUBPIECE);
  vn1 = fd->newVarnode(size,addr);
  overlap = vn->overlap(addr,size);
  vn2 = fd->newConstant(addr.getAddrSize(),(uintb)overlap);
  fd->opSetInput(newop,vn1,0);
  fd->opSetInput(newop,vn2,1);
  fd->opSetOutput(newop,vn);	// Old vn is no longer a free read
  newop->getOut()->setWriteMask();
  fd->opInsertBefore(newop,op);
  return vn1;			// But we have new free read of uniform size
}

/// \brief Normalize the size of a written Varnode, prior to heritage
///
/// Given a Varnode that is written that does not match the (larger) size
/// of the address range currently being linked, create the missing
/// pieces in the range and concatenate everything into a new Varnode
/// of the correct size.
///
/// One or more Varnode pieces are created depending
/// on how the original Varnode overlaps the given range. An expression
/// is created using PIECE ops resulting in a final Varnode.
/// \param vn is the given too small Varnode
/// \param addr is the start of the (larger) range
/// \param size is the number of bytes in the range
/// \return the newly created final Varnode
Varnode *Heritage::normalizeWriteSize(Varnode *vn,const Address &addr,int4 size)

{
  int4 overlap;
  int4 mostsigsize;
  PcodeOp *op,*newop;
  Varnode *mostvn,*leastvn,*big,*bigout,*midvn;

  mostvn = (Varnode *)0;
  op = vn->getDef();
  overlap = vn->overlap(addr,size);
  mostsigsize = size-(overlap+vn->getSize());
  if (mostsigsize != 0) {
    Address pieceaddr;
    if (addr.isBigEndian())
      pieceaddr = addr;
    else
      pieceaddr = addr + (overlap+vn->getSize());
    if (op->isCall() && callOpIndirectEffect(pieceaddr,mostsigsize,op)) {	// Does CALL have an effect on piece
      newop = fd->newIndirectCreation(op,pieceaddr,mostsigsize,false);	// Don't create a new big read if write is from a CALL
      mostvn = newop->getOut();
    }
    else {
      newop = fd->newOp(2,op->getAddr());
      mostvn = fd->newVarnodeOut(mostsigsize,pieceaddr,newop);
      big = fd->newVarnode(size,addr);	// The new read
      big->setActiveHeritage();
      fd->opSetOpcode(newop,CPUI_SUBPIECE);
      fd->opSetInput(newop,big,0);
      fd->opSetInput(newop,fd->newConstant(addr.getAddrSize(),(uintb)overlap+vn->getSize()),1);
      fd->opInsertBefore(newop,op);
    }
  }
  if (overlap != 0) {
    Address pieceaddr;
    if (addr.isBigEndian())
      pieceaddr = addr + (size-overlap);
    else
      pieceaddr = addr;
    if (op->isCall() && callOpIndirectEffect(pieceaddr,overlap,op)) {		// Unless CALL definitely has no effect on piece
      newop = fd->newIndirectCreation(op,pieceaddr,overlap,false);		// Don't create a new big read if write is from a CALL
      leastvn = newop->getOut();
    }
    else {
      newop = fd->newOp(2,op->getAddr());
      leastvn = fd->newVarnodeOut(overlap,pieceaddr,newop);
      big = fd->newVarnode(size,addr);	// The new read
      big->setActiveHeritage();
      fd->opSetOpcode(newop,CPUI_SUBPIECE);
      fd->opSetInput(newop,big,0);
      fd->opSetInput(newop,fd->newConstant(addr.getAddrSize(),0),1);
      fd->opInsertBefore(newop,op);
    }
  }
  if (overlap !=0 ) {
    newop = fd->newOp(2,op->getAddr());
    if (addr.isBigEndian())
      midvn = fd->newVarnodeOut(overlap+vn->getSize(),vn->getAddr(),newop);
    else
      midvn = fd->newVarnodeOut(overlap+vn->getSize(),addr,newop);
    fd->opSetOpcode(newop,CPUI_PIECE);
    fd->opSetInput(newop,vn,0); // Most significant part
    fd->opSetInput(newop,leastvn,1); // Least sig
    fd->opInsertAfter(newop,op);
  }
  else
    midvn = vn;
  if (mostsigsize != 0) {
    newop = fd->newOp(2,op->getAddr());
    bigout = fd->newVarnodeOut(size,addr,newop);
    fd->opSetOpcode(newop,CPUI_PIECE);
    fd->opSetInput(newop,mostvn,0);
    fd->opSetInput(newop,midvn,1);
    fd->opInsertAfter(newop,midvn->getDef());
  }
  else
    bigout = midvn;
  vn->setWriteMask();
  return bigout;		// Replace small write with big write
}

/// \brief Concatenate a list of Varnodes together at the given location
///
/// There must be at least 2 Varnodes in list, they must be in order
/// from most to least significant.  The Varnodes in the list become
/// inputs to a single expression of PIECE ops resulting in a
/// final specified Varnode
/// \param vnlist is the list of Varnodes to concatenate
/// \param insertop is the point where the expression should be inserted (before)
/// \param finalvn is the final specified output Varnode of the expression
/// \return the final unified Varnode
Varnode *Heritage::concatPieces(const vector<Varnode *> &vnlist,PcodeOp *insertop,Varnode *finalvn)

{
  Varnode *preexist = vnlist[0];
  bool isbigendian = preexist->getAddr().isBigEndian();
  Address opaddress;
  BlockBasic *bl;
  list<PcodeOp *>::iterator insertiter;

  if (insertop == (PcodeOp *)0) { // Insert at the beginning
    bl = (BlockBasic *)fd->getBasicBlocks().getStartBlock();
    insertiter = bl->beginOp();
    opaddress = fd->getAddress();
  }
  else {
    bl = insertop->getParent();
    insertiter = insertop->getBasicIter();
    opaddress = insertop->getAddr();
  }

  for(uint4 i=1;i<vnlist.size();++i) {
    Varnode *vn = vnlist[i];
    PcodeOp *newop = fd->newOp(2,opaddress);
    fd->opSetOpcode(newop,CPUI_PIECE);
    Varnode *newvn;
    if (i==vnlist.size()-1) {
      newvn = finalvn;
      fd->opSetOutput(newop,newvn);
    }
    else
      newvn = fd->newUniqueOut(preexist->getSize()+vn->getSize(),newop);
    if (isbigendian) {
      fd->opSetInput(newop,preexist,0);	// Most sig part
      fd->opSetInput(newop,vn,1); // Least sig part
    }
    else {
      fd->opSetInput(newop,vn,0);
      fd->opSetInput(newop,preexist,1);
    }
    fd->opInsert(newop,bl,insertiter);
    preexist = newvn;
  }
  return preexist;
}

/// \brief Build a set of Varnode piece expression at the given location
///
/// Given a list of small Varnodes and the address range they are a piece of,
/// construct a SUBPIECE op that defines each piece.  The truncation parameters
/// are calculated based on the overlap of the piece with the whole range,
/// and a single input Varnode is used for all SUBPIECE ops.
/// \param vnlist is the list of piece Varnodes
/// \param insertop is the point where the op expressions are inserted (before)
/// \param addr is the first address of the whole range
/// \param size is the number of bytes in the whole range
/// \param startvn is designated input Varnode
void Heritage::splitPieces(const vector<Varnode *> &vnlist,PcodeOp *insertop,
			   const Address &addr,int4 size,Varnode *startvn)

{
  Address opaddress;
  uintb baseoff;
  bool isbigendian;
  BlockBasic *bl;
  list<PcodeOp *>::iterator insertiter;

  isbigendian = addr.isBigEndian();
  if (isbigendian)
    baseoff = addr.getOffset() + size;
  else
    baseoff = addr.getOffset();
  if (insertop == (PcodeOp *)0) {
    bl = (BlockBasic *)fd->getBasicBlocks().getStartBlock();
    insertiter = bl->beginOp();
    opaddress = fd->getAddress();
  }
  else {
    bl = insertop->getParent();
    insertiter = insertop->getBasicIter();
    ++insertiter;		// Insert AFTER the write
    opaddress = insertop->getAddr();
  }

  for(uint4 i=0;i<vnlist.size();++i) {
    Varnode *vn = vnlist[i];
    PcodeOp *newop = fd->newOp(2,opaddress);
    fd->opSetOpcode(newop,CPUI_SUBPIECE);
    uintb diff;
    if (isbigendian)
      diff = baseoff - (vn->getOffset() + vn->getSize());
    else
      diff = vn->getOffset() - baseoff;
    fd->opSetInput(newop,startvn,0);
    fd->opSetInput(newop,fd->newConstant(4,diff),1);
    fd->opSetOutput(newop,vn);
    fd->opInsert(newop,bl,insertiter);
  }
}

/// \brief Find the last PcodeOps that write to specific addresses that flow to specific sites
///
/// Given a set of sites for which data-flow needs to be preserved at a specific address, find
/// the \e last ops that write to the address such that data flows to the site
/// only through \e artificial COPYs and MULTIEQUALs.  A COPY/MULTIEQUAL is artificial if all
/// of its input and output Varnodes have the same storage address.  The specific sites are
/// presented as artificial COPY ops.  The final set of ops that are not artificial will all
/// have an output Varnode that matches the specific address of a COPY sink and will need to
/// be marked address forcing. The original set of COPY sinks will be extended to all artificial
/// COPY/MULTIEQUALs encountered.  Every PcodeOp encountered will have its mark set.
/// \param copySinks is the list of sinks that we are trying to find flow to
/// \param forces is the final list of address forcing PcodeOps
void Heritage::findAddressForces(vector<PcodeOp *> &copySinks,vector<PcodeOp *> &forces)

{
  // Mark the sinks
  for(int4 i=0;i<copySinks.size();++i) {
    PcodeOp *op = copySinks[i];
    op->setMark();
  }

  // Mark everything back-reachable from a sink, trimming at non-artificial ops
  int4 pos = 0;
  while(pos < copySinks.size()) {
    PcodeOp *op = copySinks[pos];
    Address addr = op->getOut()->getAddr();	// Address being flowed to
    pos += 1;
    int4 maxIn = op->numInput();
    for(int4 i=0;i<maxIn;++i) {
      Varnode *vn = op->getIn(i);
      if (!vn->isWritten()) continue;
      if (vn->isAddrForce()) continue;		// Already marked address forced
      PcodeOp *newOp = vn->getDef();
      if (newOp->isMark()) continue;		// Already visited this op
      newOp->setMark();
      OpCode opc = newOp->code();
      bool isArtificial = false;
      if (opc == CPUI_COPY || opc == CPUI_MULTIEQUAL) {
	isArtificial = true;
	int4 maxInNew = newOp->numInput();
	for(int4 j=0;j<maxInNew;++j) {
	  Varnode *inVn = newOp->getIn(j);
	  if (addr != inVn->getAddr()) {
	    isArtificial = false;
	    break;
	  }
	}
      }
      else if (opc == CPUI_INDIRECT && newOp->isIndirectStore()) {
	// An INDIRECT can be considered artificial if it is caused by a STORE
	Varnode *inVn = newOp->getIn(0);
	if (addr == inVn->getAddr())
	  isArtificial = true;
      }
      if (isArtificial)
	copySinks.push_back(newOp);
      else
	forces.push_back(newOp);
    }
  }
}

/// \brief Eliminate a COPY sink preserving its data-flow
///
/// Given a COPY from a storage location to itself, propagate the input Varnode
/// version of the storage location to all the ops reading the output Varnode, so
/// the output no longer has any descendants. Then eliminate the COPY.
/// \param op is the given COPY sink
void Heritage::propagateCopyAway(PcodeOp *op)

{
  Varnode *inVn = op->getIn(0);
  while(inVn->isWritten()) {		// Follow any COPY chain to earliest input
    PcodeOp *nextOp = inVn->getDef();
    if (nextOp->code() != CPUI_COPY) break;
    Varnode *nextIn = nextOp->getIn(0);
    if (nextIn->getAddr() != inVn->getAddr()) break;
    inVn = nextIn;
  }
  fd->totalReplace(op->getOut(),inVn);
  fd->opDestroy(op);
}

/// \brief Mark the boundary of artificial ops introduced by load guards
///
/// Having just completed renaming, run through all new COPY sinks from load guards
/// and mark boundary Varnodes (Varnodes whose data-flow along all paths traverses only
/// COPY/INDIRECT/MULTIEQUAL ops and hits a load guard). This lets dead code removal
/// run forward from the boundary while still preserving the address force on the load guard.
void Heritage::handleNewLoadCopies(void)

{
  if (loadCopyOps.empty()) return;
  vector<PcodeOp *> forces;
  int4 copySinkSize = loadCopyOps.size();
  findAddressForces(loadCopyOps, forces);

  if (!forces.empty()) {
    RangeList loadRanges;
    for(list<LoadGuard>::const_iterator iter=loadGuard.begin();iter!=loadGuard.end();++iter) {
      const LoadGuard &guard( *iter );
      loadRanges.insertRange(guard.spc, guard.minimumOffset, guard.maximumOffset);
    }
    // Mark everything on the boundary as address forced to prevent dead-code removal
    for(int4 i=0;i<forces.size();++i) {
      PcodeOp *op = forces[i];
      Varnode *vn = op->getOut();
      if (loadRanges.inRange(vn->getAddr(), 1))	// If we are within one of the guarded ranges
	vn->setAddrForce();			// then consider the output address forced
      op->clearMark();
    }
  }

  // Eliminate or propagate away original COPY sinks
  for(int4 i=0;i<copySinkSize;++i) {
    PcodeOp *op = loadCopyOps[i];
    propagateCopyAway(op);	// Make sure load guard COPYs no longer exist
  }
  // Clear marks on remaining artificial COPYs
  for(int4 i=copySinkSize;i<loadCopyOps.size();++i) {
    PcodeOp *op = loadCopyOps[i];
    op->clearMark();
  }
  loadCopyOps.clear();		// We have handled all the load guard COPY ops
}

/// Make some determination of the range of possible values for a LOAD based
/// an partial value set analysis. This can sometimes get
///   - minimumOffset - otherwise the original constant pulled with the LOAD is used
///   - step          - the partial analysis shows step and direction
///   - maximumOffset - in rare cases
///
/// isAnalyzed is set to \b true, if full range analysis is not needed
/// \param valueSet is the calculated value set as seen by the LOAD operation
void LoadGuard::establishRange(const ValueSetRead &valueSet)

{
  const CircleRange &range( valueSet.getRange() );
  uintb rangeSize = range.getSize();
  uintb size;
  if (range.isEmpty()) {
    minimumOffset = pointerBase;
    size = 0x1000;
  }
  else if (range.isFull() || rangeSize > 0xffffff) {
    minimumOffset = pointerBase;
    size = 0x1000;
    analysisState = 1;	// Don't bother doing more analysis
  }
  else {
    step = (rangeSize == 3) ? range.getStep() : 0;	// Check for consistent step
    size = 0x1000;
    if (valueSet.isLeftStable()) {
      minimumOffset = range.getMin();
    }
    else if (valueSet.isRightStable()) {
      if (pointerBase < range.getEnd()) {
	minimumOffset = pointerBase;
	size = (range.getEnd() - pointerBase);
      }
      else {
	minimumOffset = range.getMin();
	size = rangeSize * range.getStep();
      }
    }
    else
      minimumOffset = pointerBase;
  }
  uintb max = spc->getHighest();
  if (minimumOffset > max) {
    minimumOffset = max;
    maximumOffset = minimumOffset;	// Something is seriously wrong
  }
  else {
    uintb maxSize = (max - minimumOffset) + 1;
    if (size > maxSize)
      size = maxSize;
    maximumOffset = minimumOffset + size -1;
  }
}

void LoadGuard::finalizeRange(const ValueSetRead &valueSet)

{
  analysisState = 1;		// In all cases the settings determined here are final
  const CircleRange &range( valueSet.getRange() );
  uintb rangeSize = range.getSize();
  if (rangeSize == 0x100 || rangeSize == 0x10000) {
    // These sizes likely result from the storage size of the index
    if (step == 0)	// If we didn't see signs of iteration
      rangeSize = 0;	// don't use this range
  }
  if (rangeSize > 1 && rangeSize < 0xffffff) {	// Did we converge to something reasonable
    analysisState = 2;			// Mark that we got a definitive result
    if (rangeSize > 2)
      step = range.getStep();
    minimumOffset = range.getMin();
    maximumOffset = (range.getEnd() - 1) & range.getMask();	// NOTE: Don't subtract a whole step
    if (maximumOffset < minimumOffset) {	// Values extend into what is usually stack parameters
      maximumOffset = spc->getHighest();
      analysisState = 1;	// Remove the lock as we have likely overflowed
    }
  }
  if (minimumOffset > spc->getHighest())
    minimumOffset = spc->getHighest();
  if (maximumOffset > spc->getHighest())
    maximumOffset = spc->getHighest();
}

/// Check if the address falls within the range defined by \b this
/// \param addr is the given address
/// \return \b true if the address is contained
bool LoadGuard::isGuarded(const Address &addr) const

{
  if (addr.getSpace() != spc) return false;
  if (addr.getOffset() < minimumOffset) return false;
  if (addr.getOffset() > maximumOffset) return false;
  return true;
}

/// \brief Make final determination of what range new LoadGuards are protecting
///
/// Actual LOAD operations are guarded with an initial version of the LoadGuard record.
/// Now that heritage has completed, a full analysis of each LOAD is conducted, using
/// value set analysis, to reach a conclusion about what range of stack values the
/// LOAD might actually alias.  All new LoadGuard records are updated with the analysis,
/// which then informs handling of LOAD COPYs and possible later heritage passes.
void Heritage::analyzeNewLoadGuards(void)

{
  bool nothingToDo = true;
  if (!loadGuard.empty()) {
    if (loadGuard.back().analysisState == 0)	// Check if unanalyzed
      nothingToDo = false;
  }
  if (!storeGuard.empty()) {
    if (storeGuard.back().analysisState == 0)
      nothingToDo = false;
  }
  if (nothingToDo) return;

  vector<Varnode *> sinks;
  vector<PcodeOp *> reads;
  list<LoadGuard>::iterator loadIter = loadGuard.end();
  while(loadIter != loadGuard.begin()) {
    --loadIter;
    LoadGuard &guard( *loadIter );
    if (guard.analysisState != 0) break;
    reads.push_back(guard.op);
    sinks.push_back(guard.op->getIn(1));	// The CPUI_LOAD pointer
  }
  list<LoadGuard>::iterator storeIter = storeGuard.end();
  while(storeIter != storeGuard.begin()) {
    --storeIter;
    LoadGuard &guard( *storeIter );
    if (guard.analysisState != 0) break;
    reads.push_back(guard.op);
    sinks.push_back(guard.op->getIn(1));	// The CPUI_STORE pointer
  }
  AddrSpace *stackSpc = fd->getArch()->getStackSpace();
  Varnode *stackReg = (Varnode *)0;
  if (stackSpc != (AddrSpace *)0 && stackSpc->numSpacebase() > 0)
    stackReg = fd->findSpacebaseInput(stackSpc);
  ValueSetSolver vsSolver;
  vsSolver.establishValueSets(sinks, reads, stackReg, false);
  WidenerNone widener;
  vsSolver.solve(10000,widener);
  list<LoadGuard>::iterator iter;
  bool runFullAnalysis = false;
  for(iter=loadIter;iter!=loadGuard.end(); ++iter) {
    LoadGuard &guard( *iter );
    guard.establishRange(vsSolver.getValueSetRead(guard.op->getSeqNum()));
    if (guard.analysisState == 0)
      runFullAnalysis = true;
  }
  for(iter=storeIter;iter!=storeGuard.end(); ++iter) {
    LoadGuard &guard( *iter );
    guard.establishRange(vsSolver.getValueSetRead(guard.op->getSeqNum()));
    if (guard.analysisState == 0)
      runFullAnalysis = true;
  }
  if (runFullAnalysis) {
    WidenerFull fullWidener;
    vsSolver.solve(10000, fullWidener);
    for (iter = loadIter; iter != loadGuard.end(); ++iter) {
      LoadGuard &guard(*iter);
      guard.finalizeRange(vsSolver.getValueSetRead(guard.op->getSeqNum()));
    }
    for (iter = storeIter; iter != storeGuard.end(); ++iter) {
      LoadGuard &guard(*iter);
      guard.finalizeRange(vsSolver.getValueSetRead(guard.op->getSeqNum()));
    }
  }
}

/// \brief Generate a guard record given an indexed LOAD into a stack space
///
/// Record the LOAD op and the (likely) range of addresses in the stack space that
/// might be loaded from.
/// \param node is the path element containing the constructed Address
/// \param op is the LOAD PcodeOp
/// \param spc is the stack space
void Heritage::generateLoadGuard(StackNode &node,PcodeOp *op,AddrSpace *spc)

{
  if (!op->usesSpacebasePtr()) {
    loadGuard.emplace_back();
    loadGuard.back().set(op,spc,node.offset);
    fd->opMarkSpacebasePtr(op);
  }
}

/// \brief Generate a guard record given an indexed STORE to a stack space
///
/// Record the STORE op and the (likely) range of addresses in the stack space that
/// might be stored to.
/// \param node is the path element containing the constructed Address
/// \param op is the STORE PcodeOp
/// \param spc is the stack space
void Heritage::generateStoreGuard(StackNode &node,PcodeOp *op,AddrSpace *spc)

{
  if (!op->usesSpacebasePtr()) {
    storeGuard.emplace_back();
    storeGuard.back().set(op,spc,node.offset);
    fd->opMarkSpacebasePtr(op);
  }
}

/// \brief Identify any CPUI_STORE ops that use a free pointer from a given address space
///
/// When performing heritage for stack Varnodes, data-flow around a STORE with a
/// free pointer must be guarded (with an INDIRECT) to be safe. This routine collects
/// and marks the STORE ops that trigger this guard.
/// \param spc is the given address space
/// \param freeStores will hold the list of STOREs if any
/// \return \b true if there are any new STOREs needing a guard
bool Heritage::protectFreeStores(AddrSpace *spc,vector<PcodeOp *> &freeStores)

{
  list<PcodeOp *>::const_iterator iter = fd->beginOp(CPUI_STORE);
  list<PcodeOp *>::const_iterator enditer = fd->endOp(CPUI_STORE);
  bool hasNew = false;
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->isDead()) continue;
    Varnode *vn = op->getIn(1);
    while (vn->isWritten()) {
      PcodeOp *defOp = vn->getDef();
      OpCode opc = defOp->code();
      if (opc == CPUI_COPY)
	vn = defOp->getIn(0);
      else if (opc == CPUI_INT_ADD && defOp->getIn(1)->isConstant())
	vn = defOp->getIn(0);
      else
	break;
    }
    if (vn->isFree() && vn->getSpace() == spc) {
      fd->opMarkSpacebasePtr(op);	// Mark op as spacebase STORE, even though we're not sure
      freeStores.push_back(op);
      hasNew = true;
    }
  }
  return hasNew;
}

/// \brief Trace input stack-pointer to any indexed loads
///
/// Look for expressions of the form  val = *(SP(i) + vn + \#c), where the base stack
/// pointer has an (optional) constant added to it and a non-constant index, then a
/// value is loaded from the resulting address.  The LOAD operations are added to the list
/// of ops that potentially need to be guarded during a heritage pass.  The routine can
/// checks for STOREs where the data-flow path hasn't been completed yet and returns
/// \b true if they exist, passing back a list of those that might use a pointer to the stack.
/// \param spc is the particular address space with a stackpointer (into it)
/// \param freeStores will hold the list of any STOREs that need follow-up analysis
/// \param checkFreeStores is \b true if the routine should check for free STOREs
/// \return \b true if there are incomplete STOREs
bool Heritage::discoverIndexedStackPointers(AddrSpace *spc,vector<PcodeOp *> &freeStores,bool checkFreeStores)

{
  // We need to be careful of exponential ladders, so we mark Varnodes independently of
  // the depth first path we are traversing.
  vector<Varnode *> markedVn;
  vector<StackNode> path;
  bool unknownStackStorage = false;
  for(int4 i=0;i<spc->numSpacebase();++i) {
    const VarnodeData &stackPointer(spc->getSpacebase(i));
    Varnode *spInput = fd->findVarnodeInput(stackPointer.size, stackPointer.getAddr());
    if (spInput == (Varnode *)0) continue;
    path.push_back(StackNode(spInput,0,0));
    while(!path.empty()) {
      StackNode &curNode(path.back());
      if (curNode.iter == curNode.vn->endDescend()) {
	path.pop_back();
	continue;
      }
      PcodeOp *op = *curNode.iter;
      ++curNode.iter;
      Varnode *outVn = op->getOut();
      if (outVn != (Varnode *)0 && outVn->isMark()) continue;		// Don't revisit Varnodes
      switch(op->code()) {
	case CPUI_INT_ADD:
	{
	  Varnode *otherVn = op->getIn(1-op->getSlot(curNode.vn));
	  if (otherVn->isConstant()) {
	    uintb newOffset = spc->wrapOffset(curNode.offset + otherVn->getOffset());
	    StackNode nextNode(outVn,newOffset,curNode.traversals);
	    if (nextNode.iter != nextNode.vn->endDescend()) {
	      outVn->setMark();
	      path.push_back(nextNode);
	      markedVn.push_back(outVn);
	    }
	    else if (outVn->getSpace()->getType() == IPTR_SPACEBASE)
	      unknownStackStorage = true;
	  }
	  else {
	    StackNode nextNode(outVn,curNode.offset,curNode.traversals | StackNode::nonconstant_index);
	    if (nextNode.iter != nextNode.vn->endDescend()) {
	      outVn->setMark();
	      path.push_back(nextNode);
	      markedVn.push_back(outVn);
	    }
	    else if (outVn->getSpace()->getType() == IPTR_SPACEBASE)
	      unknownStackStorage = true;
	  }
	  break;
	}
	case CPUI_INDIRECT:
	case CPUI_COPY:
	{
	  StackNode nextNode(outVn,curNode.offset,curNode.traversals);
	  if (nextNode.iter != nextNode.vn->endDescend()) {
	    outVn->setMark();
	    path.push_back(nextNode);
	    markedVn.push_back(outVn);
	  }
	  else if (outVn->getSpace()->getType() == IPTR_SPACEBASE)
	    unknownStackStorage = true;
	  break;
	}
	case CPUI_MULTIEQUAL:
	{
	  StackNode nextNode(outVn,curNode.offset,curNode.traversals | StackNode::multiequal);
	  if (nextNode.iter != nextNode.vn->endDescend()) {
	    outVn->setMark();
	    path.push_back(nextNode);
	    markedVn.push_back(outVn);
	  }
	  else if (outVn->getSpace()->getType() == IPTR_SPACEBASE)
	    unknownStackStorage = true;
	  break;
	}
	case CPUI_LOAD:
	{
	  // Note that if ANY path has one of the traversals (non-constant ADD or MULTIEQUAL), then
	  // THIS path must have one of the traversals, because the only other acceptable path elements
	  // (INDIRECT/COPY/constant ADD) have only one path through.
	  if (curNode.traversals != 0) {
	    generateLoadGuard(curNode,op,spc);
	  }
	  break;
	}
	case CPUI_STORE:
	{
	  if (op->getIn(1) == curNode.vn) {	// Make sure the STORE pointer comes from our path
	    if (curNode.traversals != 0) {
	      generateStoreGuard(curNode, op, spc);
	    }
	    else {
	      // If there were no traversals (of non-constant ADD or MULTIEQUAL) then the
	      // pointer is equal to the stackpointer plus a constant (through an indirect is possible)
	      // This will likely get resolved in the next heritage pass, but we leave the
	      // spacebaseptr mark on, so that that the indirects don't get removed
	      fd->opMarkSpacebasePtr(op);
	    }
	  }
	  break;
	}
	default:
	  break;
      }
    }
  }
  for(int4 i=0;i<markedVn.size();++i)
    markedVn[i]->clearMark();
  if (unknownStackStorage && checkFreeStores)
    return protectFreeStores(spc, freeStores);
  return false;
}

/// \brief Revisit STOREs with free pointers now that a heritage pass has completed
///
/// We regenerate STORE LoadGuard records then cross-reference with STOREs that were
/// originally free to see if they actually needed a LoadGaurd.  If not, the STORE
/// is unmarked and INDIRECTs it has caused are removed.
/// \param spc is the address space being guarded
/// \param freeStores is the list of STOREs that were marked as free
void Heritage::reprocessFreeStores(AddrSpace *spc,vector<PcodeOp *> &freeStores)

{
  for(int4 i=0;i<freeStores.size();++i)
    fd->opClearSpacebasePtr(freeStores[i]);

  discoverIndexedStackPointers(spc, freeStores, false);

  for(int4 i=0;i<freeStores.size();++i) {
    PcodeOp *op = freeStores[i];

    // If the STORE now is marked as using a spacebase ptr, then it was appropriately
    // marked to begin with, and we don't need to clean anything up
    if (op->usesSpacebasePtr()) continue;

    // If not the STORE may have triggered INDIRECTs that are unnecessary
    PcodeOp *indOp = op->previousOp();
    while(indOp != (PcodeOp *)0) {
      if (indOp->code() != CPUI_INDIRECT) break;
      Varnode *iopVn = indOp->getIn(1);
      if (iopVn->getSpace()->getType()!=IPTR_IOP) break;
      if (op != PcodeOp::getOpFromConst(iopVn->getAddr())) break;
      PcodeOp *nextOp = indOp->previousOp();
      if (indOp->getOut()->getSpace() == spc) {
	fd->totalReplace(indOp->getOut(),indOp->getIn(0));
	fd->opDestroy(indOp);		// Get rid of the INDIRECT
      }
      indOp = nextOp;
    }
  }
}

/// \brief Normalize p-code ops so that phi-node placement and renaming works
///
/// The traditional phi-node placement and renaming algorithms don't expect
/// variable pairs where there is partial overlap. For the given address range,
/// we make all the free Varnode sizes look uniform by adding PIECE and SUBPIECE
/// ops. We also add INDIRECT ops, so that we can ignore indirect effects
/// of LOAD/STORE/CALL ops.
/// \param addr is the starting address of the given range
/// \param size is the number of bytes in the given range
/// \param read is the set of Varnode values reading from the range
/// \param write is the set of written Varnodes in the range
/// \param inputvars is the set of Varnodes in the range already marked as input
void Heritage::guard(const Address &addr,int4 size,vector<Varnode *> &read,vector<Varnode *> &write,
		     vector<Varnode *> &inputvars)

{
  uint4 flags;
  Varnode *vn;
  vector<Varnode *>::iterator iter;
  bool guardneeded = true;

  for(iter=read.begin();iter!=read.end();++iter) {
    vn = *iter;
    if (vn->getSize() < size)
      *iter = vn = normalizeReadSize(vn,addr,size);
    vn->setActiveHeritage();
  }

  for(iter=write.begin();iter!=write.end();++iter) {
    vn = *iter;
    if (vn->getSize() < size)
      *iter = vn = normalizeWriteSize(vn,addr,size);
    vn->setActiveHeritage();
    if (vn->isAddrForce())
      guardneeded = false;
    else {
      if (vn->isWritten()) {
	if (vn->getDef()->code() == CPUI_INDIRECT) // Evidence of a previous guard
	  guardneeded = false;
      }
    }
  }

  if (read.empty() && write.empty() && inputvars.empty()) return;

				// This may need to be adjusted in the future
				// Basically we need to take into account the possibility
				// that the full syntax tree may form over several stages
				// so there is the possibility that we will see a new
				// free for an address that has already been guarded before
				// Because INDIRECTs for a single call or store really
				// issue simultaneously, having multiple INDIRECT guards
				// for the same address confuses the renaming algorithm
				// SO we don't guard if we think we've guarded before
  if (guardneeded) {
    flags = 0;
    // Query for generic properties of address (use empty usepoint)
    fd->getScopeLocal()->queryProperties(addr,size,Address(),flags);
    guardCalls(flags,addr,size,write);
    guardReturns(flags,addr,size,write);
    if (fd->getArch()->highPtrPossible(addr,size)) {
      guardStores(addr,size,write);
      guardLoads(flags,addr,size,write);
    }
  }
}

/// \brief Guard an address range that is larger than any single parameter
///
/// In this situation, an address range is being heritaged, but only a piece of
/// it can be a parameter for a given call. We have to construct a SUBPIECE that
/// pulls out the potential parameter.
/// \param fc is the call site potentially taking a parameter
/// \param addr is the starting address of the range
/// \param transAddr is the start of the same range from the callee's stack perspective
/// \param size is the size of the range in bytes
void Heritage::guardCallOverlappingInput(FuncCallSpecs *fc,const Address &addr,const Address &transAddr,int4 size)

{
  VarnodeData vData;

  if (fc->getBiggestContainedInputParam(transAddr, size, vData)) {
    ParamActive *active = fc->getActiveInput();
    Address truncAddr(vData.space,vData.offset);
    if (active->whichTrial(truncAddr, size) < 0) { // If not already a trial
      int4 truncateAmount = transAddr.justifiedContain(size, truncAddr, vData.size, false);
      int4 diff = (int4)(truncAddr.getOffset() - transAddr.getOffset());
      truncAddr = addr + diff;		// Convert truncated Address to caller's perspective
      PcodeOp *op = fc->getOp();
      PcodeOp *subpieceOp = fd->newOp(2,op->getAddr());
      fd->opSetOpcode(subpieceOp, CPUI_SUBPIECE);
      Varnode *wholeVn = fd->newVarnode(size,addr);
      wholeVn->setActiveHeritage();
      fd->opSetInput(subpieceOp,wholeVn,0);
      fd->opSetInput(subpieceOp,fd->newConstant(4,truncateAmount),1);
      Varnode *vn = fd->newVarnodeOut(vData.size, truncAddr, subpieceOp);
      fd->opInsertBefore(subpieceOp,op);
      active->registerTrial(truncAddr, vData.size);
      fd->opInsertInput(op, vn, op->numInput());
    }
  }
}

/// \brief Guard CALL/CALLIND ops in preparation for renaming algorithm
///
/// For the given address range, we decide what the data-flow effect is
/// across each call site in the function.  If an effect is unknown, an
/// INDIRECT op is added, prepopulating data-flow through the call.
/// Any new INDIRECT causes a new Varnode to be added to the \b write list.
/// \param flags are any boolean properties associated with the address range
/// \param addr is the first address of given range
/// \param size is the number of bytes in the range
/// \param write is the list of written Varnodes in the range (may be updated)
void Heritage::guardCalls(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write)

{
  FuncCallSpecs *fc;
  PcodeOp *indop;
  uint4 effecttype;

  bool holdind = ((flags&Varnode::addrtied)!=0);
  for(int4 i=0;i<fd->numCalls();++i) {
    fc = fd->getCallSpecs(i);
    if (fc->getOp()->isAssignment()) {
      Varnode *vn = fc->getOp()->getOut();
      if ((vn->getAddr()==addr)&&(vn->getSize()==size)) continue;
    }
    effecttype = fc->hasEffectTranslate(addr,size);
    bool possibleoutput = false;
    if (fc->isOutputActive()) {
      ParamActive *active = fc->getActiveOutput();
      if (fc->possibleOutputParam(addr,size)) {
	if (active->whichTrial(addr,size)<0) { // If not already a trial
	  active->registerTrial(addr,size);
	  effecttype = EffectRecord::killedbycall; // A potential output is always killed by call
	  possibleoutput = true;
	}
      }
    }
    if (fc->isInputActive()) {
      AddrSpace *spc = addr.getSpace();
      uintb off = addr.getOffset();
      bool tryregister = true;
      if (spc->getType() == IPTR_SPACEBASE) {
	if (fc->getSpacebaseOffset() != FuncCallSpecs::offset_unknown)
	  off = spc->wrapOffset(off - fc->getSpacebaseOffset());
	else
	  tryregister = false; // Do not attempt to register this stack loc as a trial
      }
      Address transAddr(spc,off);	// Address relative to callee's stack
      if (tryregister) {
	int4 inputCharacter = fc->characterizeAsInputParam(transAddr,size);
	if (inputCharacter == 1) {		// Call could be using this range as an input parameter
	  ParamActive *active = fc->getActiveInput();
	  if (active->whichTrial(transAddr,size)<0) { // If not already a trial
	    PcodeOp *op = fc->getOp();
	    active->registerTrial(transAddr,size);
	    Varnode *vn = fd->newVarnode(size,addr);
	    vn->setActiveHeritage();
	    fd->opInsertInput(op,vn,op->numInput());
	  }
	}
	else if (inputCharacter == 2)		// Call may be using part of this range as an input parameter
	  guardCallOverlappingInput(fc, addr, transAddr, size);
      }
    }
    // We do not guard the call if the effect is "unaffected" or "reload"
    if ((effecttype == EffectRecord::unknown_effect)||(effecttype == EffectRecord::return_address)) {
      indop = fd->newIndirectOp(fc->getOp(),addr,size,0);
      indop->getIn(0)->setActiveHeritage();
      indop->getOut()->setActiveHeritage();
      write.push_back(indop->getOut());
      if (holdind)
       	indop->getOut()->setAddrForce();
      if (effecttype == EffectRecord::return_address)
	indop->getOut()->setReturnAddress();
    }
    else if (effecttype == EffectRecord::killedbycall) {
      indop = fd->newIndirectCreation(fc->getOp(),addr,size,possibleoutput);
      indop->getOut()->setActiveHeritage();
      write.push_back(indop->getOut());
    }
  }
}

/// \brief Guard STORE ops in preparation for the renaming algorithm
///
/// Depending on the pointer, a STORE operation may affect data-flow across the
/// given address range. This method adds an INDIRECT op, prepopulating
/// data-flow across the STORE.
/// Any new INDIRECT causes a new Varnode to be added to the \b write list.
/// \param addr is the first address of the given range
/// \param size is the number of bytes in the given range
/// \param write is the list of written Varnodes in the range (may be updated)
void Heritage::guardStores(const Address &addr,int4 size,vector<Varnode *> &write)

{
  list<PcodeOp *>::const_iterator iter,iterend;
  PcodeOp *op,*indop;
  AddrSpace *spc = addr.getSpace();
  AddrSpace *container = spc->getContain();

  iterend = fd->endOp(CPUI_STORE);
  for(iter=fd->beginOp(CPUI_STORE);iter!=iterend;++iter) {
    op = *iter;
    if (op->isDead()) continue;
    AddrSpace *storeSpace = Address::getSpaceFromConst(op->getIn(0)->getAddr());
    if ((container == storeSpace && op->usesSpacebasePtr()) ||
	(spc == storeSpace)) {
      indop = fd->newIndirectOp(op,addr,size,PcodeOp::indirect_store);
      indop->getIn(0)->setActiveHeritage();
      indop->getOut()->setActiveHeritage();
      write.push_back(indop->getOut());
    }
  }
}

/// \brief Guard LOAD ops in preparation for the renaming algorithm
///
/// The op must be in the loadGuard list, which means it may pull values from an indexed
/// range on the stack.  A COPY guard is placed for the given range on any LOAD op whose
/// indexed range it intersects.
/// \param flags is boolean properties associated with the address
/// \param addr is the first address of the given range
/// \param size is the number of bytes in the given range
/// \param write is the list of written Varnodes in the range (may be updated)
void Heritage::guardLoads(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write)

{
  PcodeOp *copyop;
  list<LoadGuard>::iterator iter;

  if ((flags & Varnode::addrtied)==0) return;	// If not address tied, don't consider for index alias
  iter = loadGuard.begin();
  while(iter!=loadGuard.end()) {
    LoadGuard &guardRec(*iter);
    if (!guardRec.isValid(CPUI_LOAD)) {
      list<LoadGuard>::iterator copyIter = iter;
      ++iter;
      loadGuard.erase(copyIter);
      continue;
    }
    ++iter;
    if (guardRec.spc != addr.getSpace()) continue;
    if (addr.getOffset() < guardRec.minimumOffset) continue;
    if (addr.getOffset() > guardRec.maximumOffset) continue;
    copyop = fd->newOp(1,guardRec.op->getAddr());
    Varnode *vn = fd->newVarnodeOut(size,addr,copyop);
    vn->setActiveHeritage();
    vn->setAddrForce();
    fd->opSetOpcode(copyop,CPUI_COPY);
    Varnode *invn = fd->newVarnode(size,addr);
    invn->setActiveHeritage();
    fd->opSetInput(copyop,invn,0);
    fd->opInsertBefore(copyop,guardRec.op);
    loadCopyOps.push_back(copyop);
  }
}

/// \brief Guard global data-flow at RETURN ops in preparation for renaming
///
/// For the given global (persistent) address range, data-flow must persist up to
/// (beyond) the end of the function. This method prepopulates data-flow for the
/// range at all the RETURN ops, in order to enforce this.  Either a Varnode
/// is added as input to the RETURN (for possible return values), or a COPY
/// is inserted right before the RETURN with its output marked as
/// \b address \b forced.
/// \param flags are any boolean properties associated with the address range
/// \param addr is the first address of the given range
/// \param size is the number of bytes in the range
/// \param write is the list of written Varnodes in the range (unused)
void Heritage::guardReturns(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write)

{
  list<PcodeOp *>::const_iterator iter,iterend;
  PcodeOp *op,*copyop;

  ParamActive *active = fd->getActiveOutput();
  if (active != (ParamActive *)0) {
    if (fd->getFuncProto().possibleOutputParam(addr,size)) {
      active->registerTrial(addr,size);
      iterend = fd->endOp(CPUI_RETURN);
      for(iter=fd->beginOp(CPUI_RETURN);iter!=iterend;++iter) {
	op = *iter;
	if (op->isDead()) continue;
	if (op->getHaltType() != 0) continue; // Special halt points cannot take return values
	Varnode *invn = fd->newVarnode(size,addr);
	invn->setActiveHeritage();
	fd->opInsertInput(op,invn,op->numInput());
      }
    }
  }
  if ((flags&Varnode::persist)==0) return;
  iterend = fd->endOp(CPUI_RETURN);
  for(iter=fd->beginOp(CPUI_RETURN);iter!=iterend;++iter) {
    op = *iter;
    if (op->isDead()) continue;
    copyop = fd->newOp(1,op->getAddr());
    Varnode *vn = fd->newVarnodeOut(size,addr,copyop);
    vn->setAddrForce();
    vn->setActiveHeritage();
    fd->opSetOpcode(copyop,CPUI_COPY);
    Varnode *invn = fd->newVarnode(size,addr);
    invn->setActiveHeritage();
    fd->opSetInput(copyop,invn,0);
    fd->opInsertBefore(copyop,op);
  }
}

/// \brief Build a refinement array given an address range and a list of Varnodes
///
/// The array is a preallocated array of ints, one for each byte in the address
/// range. Each Varnode in the given list has a 1 entered in the refinement
/// array, at the position corresponding to the starting address of the Varnode
/// and at the position corresponding to the address immediately following the
/// Varnode.
/// \param refine is the refinement array
/// \param addr is the starting address of the given range
/// \param size is the number of bytes in the range
/// \param vnlist is the list of Varnodes to add to the array
void Heritage::buildRefinement(vector<int4> &refine,const Address &addr,int4 size,const vector<Varnode *> &vnlist)

{
  for(uint4 i=0;i<vnlist.size();++i) {
    Address curaddr = vnlist[i]->getAddr();
    int4 sz = vnlist[i]->getSize();
    uint4 diff = (uint4)(curaddr.getOffset() - addr.getOffset());
    refine[diff] = 1;
    refine[diff+sz] = 1;
  }
}

/// \brief Split up a Varnode by the given \e refinement
///
/// The \e refinement array is an array of integers, one for each byte in the
/// given range. Any non-zero entry is the size of a particular element of the
/// refinement starting at that corresponding byte in the range. I.e. the array
/// [4,0,0,0,4,0,0,0] indicates the address range is 8-bytes long covered by
/// two elements of length 4, starting at offsets 0 and 4 respectively.
/// The given Varnode must be contained in the address range that the
/// refinement array describes.
///
/// A new set of Varnode pieces are returned in the \b split container, where
/// the pieces form a disjoint cover of the original Varnode, and where the
/// piece boundaries match the refinement.
/// \param vn is the given Varnode to split
/// \param addr is the starting address of the range described by the refinement
/// \param refine is the refinement array
/// \param split will hold the new Varnode pieces
void Heritage::splitByRefinement(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &split)

{
  Address curaddr = vn->getAddr();
  int4 sz = vn->getSize();
  AddrSpace *spc = curaddr.getSpace();
  uint4 diff = (uint4)spc->wrapOffset(curaddr.getOffset() - addr.getOffset());
  int4 cutsz = refine[diff];
  if (sz <= cutsz) return;	// Already refined
  while(sz > 0) {
    Varnode *vn2 = fd->newVarnode(cutsz,curaddr);
    split.push_back(vn2);
    curaddr = curaddr + cutsz;
    sz -= cutsz;
    diff = (uint4)spc->wrapOffset(curaddr.getOffset() - addr.getOffset());
    cutsz = refine[diff];
    if (cutsz > sz)
      cutsz = sz;		// Final piece
  }
}

/// \brief Split up a \b free Varnode based on the given refinement
///
/// The \e refinement array is an array of integers, one for each byte in the
/// given range. Any non-zero entry is the size of a particular element of the
/// refinement starting at that corresponding byte in the range. I.e. the array
/// [4,0,0,0,4,0,0,0] indicates the address range is 8-bytes long covered by
/// two elements of length 4, starting at offsets 0 and 4 respectively.
///
/// If the Varnode overlaps the refinement, it is replaced with 2 or more
/// covering Varnodes with boundaries that are on the refinement.  A concatenation
/// expression is formed reconstructing the original value from the pieces. The
/// original Varnode is replaced, in its p-code op, with a temporary Varnode that
/// is the final output of the concatenation expression.
/// \param vn is the given Varnode to split
/// \param addr is the starting address of the address range being refined
/// \param refine is the refinement array
/// \param newvn is preallocated space for the holding the array of Varnode pieces
void Heritage::refineRead(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &newvn)

{
  newvn.clear();
  splitByRefinement(vn,addr,refine,newvn);
  if (newvn.empty()) return;
  Varnode *replacevn = fd->newUnique(vn->getSize());
  PcodeOp *op = vn->loneDescend(); // Read is free so has 1 and only 1 descend
  int4 slot = op->getSlot(vn);
  concatPieces(newvn,op,replacevn);
  fd->opSetInput(op,replacevn,slot);
  if (vn->hasNoDescend())
    fd->deleteVarnode(vn);
  else
    throw LowlevelError("Refining non-free varnode");
}

/// \brief Split up an output Varnode based on the given refinement
///
/// The \e refinement array is an array of integers, one for each byte in the
/// given range. Any non-zero entry is the size of a particular element of the
/// refinement starting at that corresponding byte in the range. I.e. the array
/// [4,0,0,0,4,0,0,0] indicates the address range is 8-bytes long covered by
/// two elements of length 4, starting at offsets 0 and 4 respectively.
///
/// If the Varnode overlaps the refinement, it is replaced with 2 or more
/// covering Varnodes with boundaries that are on the refinement.  These pieces
/// may be supplemented with additional pieces to obtain a disjoint cover of the
/// entire address range.  A defining SUBPIECE op is generated for each piece.
/// The original Varnode is replaced with a temporary Varnode.
/// \param vn is the given Varnode to split
/// \param addr is the starting address of the address range being refined
/// \param refine is the refinement array
/// \param newvn is preallocated space for the holding the array of Varnode pieces
void Heritage::refineWrite(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &newvn)

{
  newvn.clear();
  splitByRefinement(vn,addr,refine,newvn);
  if (newvn.empty()) return;
  Varnode *replacevn = fd->newUnique(vn->getSize());
  PcodeOp *def = vn->getDef();
  fd->opSetOutput(def,replacevn);
  splitPieces(newvn,def,vn->getAddr(),vn->getSize(),replacevn);
  fd->totalReplace(vn,replacevn);
  fd->deleteVarnode(vn);
}

/// \brief Split up a known input Varnode based on the given refinement
///
/// The \e refinement array is an array of integers, one for each byte in the
/// given range. Any non-zero entry is the size of a particular element of the
/// refinement starting at that corresponding byte in the range. I.e. the array
/// [4,0,0,0,4,0,0,0] indicates the address range is 8-bytes long covered by
/// two elements of length 4, starting at offsets 0 and 4 respectively.
///
/// If the Varnode overlaps the refinement, it is replaced with 2 or more
/// covering Varnodes with boundaries that are on the refinement.  These pieces
/// may be supplemented with additional pieces to obtain a disjoint cover of the
/// entire address range.  A defining SUBPIECE op is generated for each piece.
/// \param vn is the given Varnode to split
/// \param addr is the starting address of the address range being refined
/// \param refine is the refinement array
/// \param newvn is preallocated space for the holding the array of Varnode pieces
void Heritage::refineInput(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &newvn)

{
  newvn.clear();
  splitByRefinement(vn,addr,refine,newvn);
  if (newvn.empty()) return;
  splitPieces(newvn,(PcodeOp *)0,vn->getAddr(),vn->getSize(),vn);
  vn->setWriteMask();
}

/// \brief If we see 1-3 or 3-1 pieces in the partition, replace with a 4
///
/// A refinement of a 4-byte range into a 1-byte and 3-byte cover is highly likely
/// to be artificial, so we eliminate this configuration.
///
/// The \e refinement array is an array of integers, one for each byte in the
/// given range. Any non-zero entry is the size of a particular element of the
/// refinement starting at that corresponding byte in the range. I.e. the array
/// [4,0,0,0,4,0,0,0] indicates the address range is 8-bytes long covered by
/// two elements of length 4, starting at offsets 0 and 4 respectively.
/// \param refine is the refinement array
void Heritage::remove13Refinement(vector<int4> &refine)

{
  if (refine.empty()) return;
  int4 pos = 0;
  int4 lastsize = refine[pos];
  int4 cursize;

  pos += lastsize;
  while(pos < refine.size()) {
    cursize = refine[pos];
    if (cursize == 0) break;
    if (((lastsize==1)&&(cursize==3))||((lastsize==3)&&(cursize==1))) {
      refine[pos-lastsize] = 4;
      lastsize = 4;
      pos += cursize;
    }
    else {
      lastsize = cursize;
      pos += lastsize;
    }
  }
  
}

/// \brief Find the common refinement of all reads and writes in the address range
///
/// Split the reads and writes so they match the refinement.
/// \param addr is the first address in the range
/// \param size is the number of bytes in the range
/// \param readvars is all \e free Varnodes overlapping the address range
/// \param writevars is all written Varnodes overlapping the address range
/// \param inputvars is all known input Varnodes overlapping the address range
/// \return \b true if there is a non-trivial refinement
bool Heritage::refinement(const Address &addr,int4 size,const vector<Varnode *> &readvars,const vector<Varnode *> &writevars,const vector<Varnode *> &inputvars)

{
  if (size > 1024) return false;
  vector<int4> refine(size+1,0);
  buildRefinement(refine,addr,size,readvars);
  buildRefinement(refine,addr,size,writevars);
  buildRefinement(refine,addr,size,inputvars);
  int4 lastpos = 0;
  for(int4 curpos=1;curpos < size;++curpos) { // Convert boundary points to partition sizes
    if (refine[curpos] != 0) {
      refine[lastpos] = curpos - lastpos;
      lastpos = curpos;
    }
  }
  if (lastpos == 0) return false; // No non-trivial refinements
  refine[lastpos] = size-lastpos;
  remove13Refinement(refine);
  vector<Varnode *> newvn;
  for(uint4 i=0;i<readvars.size();++i)
    refineRead(readvars[i],addr,refine,newvn);
  for(uint4 i=0;i<writevars.size();++i)
    refineWrite(writevars[i],addr,refine,newvn);
  for(uint4 i=0;i<inputvars.size();++i)
    refineInput(inputvars[i],addr,refine,newvn);

  // Alter the disjoint cover (both locally and globally) to reflect our refinement
  LocationMap::iterator iter = disjoint.find(addr);
  int4 pass = (*iter).second.pass;
  disjoint.erase(iter);
  iter = globaldisjoint.find(addr);
  globaldisjoint.erase(iter);
  Address curaddr = addr;
  int4 cut = 0;
  int4 intersect;
  while(cut < size) {
    int4 sz = refine[cut];
    disjoint.add(curaddr,sz,pass,intersect);
    globaldisjoint.add(curaddr,sz,pass,intersect);
    cut += sz;
    curaddr = curaddr + sz;
  }
  return true;
}

/// \brief Make sure existing inputs for the given range fill it entirely
///
/// The method is provided any Varnodes that overlap the range and are
/// already marked as input.  If there are any holes in coverage, new
/// input Varnodes are created to cover them. A final unified Varnode
/// covering the whole range is built out of the pieces. In any event,
/// things are set up so the renaming algorithm sees only a single Varnode.
/// \param addr is the first address in the given range
/// \param size is the number of bytes in the range
/// \param input are the pre-existing inputs, given in address order
void Heritage::guardInput(const Address &addr,int4 size,vector<Varnode *> &input)

{
  if (input.empty()) return;
  // If there is only one input and it fills everything
  // it will get linked in automatically
  if ((input.size()==1)&&(input[0]->getSize() == size)) return;

  // Otherwise we need to make sure there are no holes
  int4 i = 0;
  uintb cur = addr.getOffset();	// Range that needs to be covered
  uintb end = cur + size;
  //  bool seenunspliced = false;
  Varnode *vn;
  vector<Varnode *> newinput;

  // Make sure the input range is filled
  while(cur < end) {
    if (i<input.size()) {
      vn = input[i];
      if (vn->getOffset()>cur) {
	int4 sz = vn->getOffset() - cur;
	vn = fd->newVarnode(sz,Address(addr.getSpace(),cur));
	vn = fd->setInputVarnode(vn);
	//	seenunspliced = true;
      }
      else {
	//	if (vn->hasNoDescend())
	//	  seenunspliced = true;
	i += 1;
      }
    }
    else {
      int4 sz = end-cur;
      vn = fd->newVarnode(sz,Address(addr.getSpace(),cur));
      vn = fd->setInputVarnode(vn);
      //      seenunspliced = true;
    }
    newinput.push_back(vn);
    cur += vn->getSize();
  }

  // Now we need to make sure that all the inputs get linked
  // together into a single input
  if (newinput.size()==1) return; // Will get linked in automatically
  for(uint4 i=0;i<newinput.size();++i)
    newinput[i]->setWriteMask();
//   if (!seenunspliced) {
//     // Check to see if a concatenation of inputs already exists
//     // If it existed already it would be defined at fd->getAddress()
//     // and it would have full size
//     VarnodeLocSet::const_iterator iter,enditer;
//     iter = fd->beginLoc(size,addr,fd->getAddress());
//     enditer = fd->endLoc(size,addr,fd->getAddress());
//     if (iter != enditer) return; // It already exists
//   }
  Varnode *newout = fd->newVarnode(size,addr);
  concatPieces(newinput,(PcodeOp *)0,newout)->setActiveHeritage();
}

#ifdef DFSVERIFY_DEBUG
static void verify_dfs(const vector<FlowBlock *> &list,vector<vector<FlowBlock *>> &domchild)

{
  int4 count = 0;
  vector<int4> path;

  path.push_back(0);
  if (list[0]->getIndex() != 0)
    throw LowlevelError("Initial block is not index 0");
  count += 1;
  while(!path.empty()) {
    int4 cur = path.back();
    int4 child;
    FlowBlock *bl;
    for(child=0;child<domchild[cur].size();++child) {
      bl = domchild[cur][child];
      if (bl->getIndex() == count)
	break;
    }
    if (child == domchild[cur].size())
      path.pop_back();
    else {
      path.push_back(bl->getIndex());
      count += 1;
    }
  }
  if (count != list.size())
    throw LowlevelError("dfs does not verify");
}
#endif

/// Assuming we are just about to do heritage on an address space,
/// clear any placeholder LOADs associated with it on CALLs.
/// \param info is state for the specific address space
void Heritage::clearStackPlaceholders(HeritageInfo *info)

{
  int4 numCalls = fd->numCalls();
  for(int4 i=0;i<numCalls;++i) {
    fd->getCallSpecs(i)->abortSpacebaseRelative(*fd);
  }
  info->hasCallPlaceholders = false;	// Mark that clear has taken place
}

/// \brief Perform one level of Varnode splitting to match a JoinRecord
///
/// Split all the pieces in \b lastcombo, putting them into \b nextlev in order,
/// to get closer to the representation described by the given JoinRecord.
/// \b nextlev contains the two split pieces for each Varnode in \b lastcombo.
/// If a Varnode is not split this level, an extra \b null is put into
/// \b nextlev to maintain the 2-1 mapping.
/// \param lastcombo is the list of Varnodes to split
/// \param nextlev will hold the new split Varnodes in a 2-1 ratio
/// \param joinrec is the splitting specification we are trying to match
void Heritage::splitJoinLevel(vector<Varnode *> &lastcombo,vector<Varnode *> &nextlev,JoinRecord *joinrec)

{
  int4 numpieces = joinrec->numPieces();
  int4 recnum=0;
  for(int4 i=0;i<lastcombo.size();++i) {
    Varnode *curvn = lastcombo[i];
    if (curvn->getSize() == joinrec->getPiece(recnum).size) {
      nextlev.push_back(curvn);
      nextlev.push_back((Varnode *)0);
      recnum += 1;
    }
    else {
      int4 sizeaccum = 0;
      int4 j;
      for(j=recnum;j<numpieces;++j) {
	sizeaccum += joinrec->getPiece(recnum).size;
	if (sizeaccum == curvn->getSize()) {
	  j += 1;
	  break;
	}
      }
      int4 numinhalf = (j-recnum) / 2;	// Will be at least 1
      sizeaccum = 0;
      for(int4 k=0;k<numinhalf;++k)
	sizeaccum += joinrec->getPiece(recnum+k).size;
      Varnode *mosthalf,*leasthalf;
      if (numinhalf == 1)
	mosthalf = fd->newVarnode(sizeaccum,joinrec->getPiece(recnum).space,joinrec->getPiece(recnum).offset);
      else
	mosthalf = fd->newUnique(sizeaccum);
      if ((j-recnum)==2) {
	const VarnodeData &vdata( joinrec->getPiece(recnum+1) );
	leasthalf = fd->newVarnode(vdata.size,vdata.space,vdata.offset);
      }
      else
	leasthalf = fd->newUnique(curvn->getSize() - sizeaccum);
      nextlev.push_back(mosthalf);
      nextlev.push_back(leasthalf);
      recnum = j;
    }
  }
}

/// \brief Construct pieces for a \e join-space Varnode read by an operation.
///
/// Given a splitting specification (JoinRecord) and a Varnode, build a
/// concatenation expression (out of PIECE operations) that constructs the
/// the Varnode out of the specified Varnode pieces.
/// \param vn is the \e join-space Varnode to split
/// \param joinrec is the splitting specification
void Heritage::splitJoinRead(Varnode *vn,JoinRecord *joinrec)

{
  PcodeOp *op = vn->loneDescend(); // vn isFree, so loneDescend must be non-null
  
  vector<Varnode *> lastcombo;
  vector<Varnode *> nextlev;
  lastcombo.push_back(vn);
  while(lastcombo.size() < joinrec->numPieces()) {
    nextlev.clear();
    splitJoinLevel(lastcombo,nextlev,joinrec);

    for(int4 i=0;i<lastcombo.size();++i) {
      Varnode *curvn = lastcombo[i];
      Varnode *mosthalf = nextlev[2*i];
      Varnode *leasthalf = nextlev[2*i+1];
      if (leasthalf == (Varnode *)0) continue; // Varnode didn't get split this level
      PcodeOp *concat = fd->newOp(2,op->getAddr());
      fd->opSetOpcode(concat,CPUI_PIECE);
      fd->opSetOutput(concat,curvn);
      fd->opSetInput(concat,mosthalf,0);
      fd->opSetInput(concat,leasthalf,1);
      fd->opInsertBefore(concat,op);
      mosthalf->setPrecisHi();	// Set precision flags to trigger "double precision" rules
      leasthalf->setPrecisLo();
      op = concat;		// Keep -op- as the earliest op in the concatenation construction
    }

    lastcombo.clear();
    for(int4 i=0;i<nextlev.size();++i) {
      Varnode *curvn = nextlev[i];
      if (curvn != (Varnode *)0)
	lastcombo.push_back(curvn);
    }
  }
}

/// \brief Split a written \e join-space Varnode into specified pieces
///
/// Given a splitting specification (JoinRecord) and a Varnode, build a
/// series of expressions that construct the specified Varnode pieces
/// using SUBPIECE ops.
/// \param vn is the Varnode to split
/// \param joinrec is the splitting specification
void Heritage::splitJoinWrite(Varnode *vn,JoinRecord *joinrec)

{
  PcodeOp *op = vn->getDef();	// vn cannot be free, either it has def, or it is input
  BlockBasic *bb = (BlockBasic *)fd->getBasicBlocks().getBlock(0);

  vector<Varnode *> lastcombo;
  vector<Varnode *> nextlev;
  lastcombo.push_back(vn);
  while(lastcombo.size() < joinrec->numPieces()) {
    nextlev.clear();
    splitJoinLevel(lastcombo,nextlev,joinrec);
    for(int4 i=0;i<lastcombo.size();++i) {
      Varnode *curvn = lastcombo[i];
      Varnode *mosthalf = nextlev[2*i];
      Varnode *leasthalf = nextlev[2*i+1];
      if (leasthalf == (Varnode *)0) continue; // Varnode didn't get split this level
      PcodeOp *split;
      if (vn->isInput())
	split = fd->newOp(2,bb->getStart());
      else
	split = fd->newOp(2,op->getAddr());
      fd->opSetOpcode(split,CPUI_SUBPIECE);
      fd->opSetOutput(split,mosthalf);
      fd->opSetInput(split,curvn,0);
      fd->opSetInput(split,fd->newConstant(4,leasthalf->getSize()),1);
      if (op == (PcodeOp *)0) 
	fd->opInsertBegin(split,bb);
      else
	fd->opInsertAfter(split,op);
      op = split;		// Keep -op- as the latest op in the split construction

      split = fd->newOp(2,op->getAddr());
      fd->opSetOpcode(split,CPUI_SUBPIECE);
      fd->opSetOutput(split,leasthalf);
      fd->opSetInput(split,curvn,0);
      fd->opSetInput(split,fd->newConstant(4,0),1);
      fd->opInsertAfter(split,op);
      mosthalf->setPrecisHi();	// Make sure we set the precision flags to trigger "double precision" rules
      leasthalf->setPrecisLo();
      op = split;		// Keep -op- as the latest op in the split construction
    }

    lastcombo.clear();
    for(int4 i=0;i<nextlev.size();++i) {
      Varnode *curvn = nextlev[i];
      if (curvn != (Varnode *)0)
	lastcombo.push_back(curvn);
    }
  }
}

/// \brief Create float truncation into a free lower precision \e join-space Varnode
///
/// Given a Varnode with logically lower precision, as given by a
/// float extension record (JoinRecord), create the real full-precision Varnode
/// and define the lower precision Varnode as a truncation (FLOAT2FLOAT)
/// \param vn is the lower precision \e join-space input Varnode
/// \param joinrec is the float extension record
void Heritage::floatExtensionRead(Varnode *vn,JoinRecord *joinrec)

{
  PcodeOp *op = vn->loneDescend(); // vn isFree, so loneDescend must be non-null
  PcodeOp *trunc = fd->newOp(1,op->getAddr());
  const VarnodeData &vdata( joinrec->getPiece(0) ); // Float extensions have exactly 1 piece
  Varnode *bigvn = fd->newVarnode(vdata.size,vdata.space,vdata.offset);
  fd->opSetOpcode(trunc,CPUI_FLOAT_FLOAT2FLOAT);
  fd->opSetOutput(trunc,vn);
  fd->opSetInput(trunc,bigvn,0);
  fd->opInsertBefore(trunc,op);
}

/// \brief Create float extension from a lower precision \e join-space Varnode
///
/// Given a Varnode with logically lower precision, as given by a
/// float extension record (JoinRecord), create the full precision Varnode
/// specified by the record, making it defined by an extension (FLOAT2FLOAT).
/// \param vn is the lower precision \e join-space output Varnode
/// \param joinrec is the float extension record
void Heritage::floatExtensionWrite(Varnode *vn,JoinRecord *joinrec)

{
  PcodeOp *op = vn->getDef();
  BlockBasic *bb = (BlockBasic *)fd->getBasicBlocks().getBlock(0);
  PcodeOp *ext;
  if (vn->isInput())
    ext = fd->newOp(1,bb->getStart());
  else
    ext = fd->newOp(1,op->getAddr());
  const VarnodeData &vdata( joinrec->getPiece(0) ); // Float extensions have exactly 1 piece
  fd->opSetOpcode(ext,CPUI_FLOAT_FLOAT2FLOAT);
  fd->newVarnodeOut( vdata.size, vdata.getAddr(),ext);
  fd->opSetInput( ext, vn, 0);
  if (op == (PcodeOp *)0)
    fd->opInsertBegin(ext,bb);
  else
    fd->opInsertAfter(ext,op);
}

/// \brief Split \e join-space Varnodes up into their real components
///
/// For any Varnode in the \e join-space, look up its JoinRecord and
/// split it up into the specified real components so that
/// join-space addresses play no role in the heritage process,
/// i.e. there should be no free Varnodes in the \e join-space.
void Heritage::processJoins(void)

{
  AddrSpace *joinspace = fd->getArch()->getJoinSpace();
  VarnodeLocSet::const_iterator iter,enditer;

  iter = fd->beginLoc(joinspace);
  enditer = fd->endLoc(joinspace);
  
  while(iter != enditer) {
    Varnode *vn = *iter++;
    if (vn->getSpace() != joinspace) break;	// New varnodes may get inserted before enditer
    JoinRecord *joinrec = fd->getArch()->findJoin(vn->getOffset());
    AddrSpace *piecespace = joinrec->getPiece(0).space;

    if (joinrec->getUnified().size != vn->getSize())
      throw LowlevelError("Joined varnode does not match size of record");
    if (vn->isFree()) {
      if (joinrec->isFloatExtension())
	floatExtensionRead(vn,joinrec);
      else
	splitJoinRead(vn,joinrec);
    }

    HeritageInfo *info = getInfo(piecespace);
    if (pass != info->delay) continue; // It is too soon to heritage this space
    
    if (joinrec->isFloatExtension())
      floatExtensionWrite(vn,joinrec);
    else
      splitJoinWrite(vn,joinrec);	// Only do this once for a particular varnode
  }
}

/// Assume the dominator tree is already built. Assume nodes are in dfs order.
void Heritage::buildADT(void)

{
  const BlockGraph &bblocks(fd->getBasicBlocks());
  int4 size = bblocks.getSize();
  vector<int4> a(size);
  vector<int4> b(size,0);
  vector<int4> t(size,0);
  vector<int4> z(size);
  vector<FlowBlock *> upstart,upend;	// Up edges (node pair)
  FlowBlock *x,*u,*v;
  int4 i,j,k,l;

  augment.clear();
  augment.resize(size);
  flags.clear();
  flags.resize(size,0);

  bblocks.buildDomTree(domchild);
#ifdef DFSVERIFY_DEBUG
  verify_dfs(bblocks.getList(),domchild);
#endif
  maxdepth = bblocks.buildDomDepth(depth);
  for(i=0;i<size;++i) {
    x = bblocks.getBlock(i);
    for(j=0;j<domchild[i].size();++j) {
      v = domchild[i][j];
      for(k=0;k<v->sizeIn();++k) {
	u = v->getIn(k);
	if (u != v->getImmedDom()) { // If u->v is an up-edge
	  upstart.push_back(u);	// Store edge (in dfs order)
	  upend.push_back(v);
	  b[u->getIndex()] += 1;
	  t[x->getIndex()] += 1;
	}
      }
    }
  }
  for(i=size-1;i>=0;--i) {
    k=0;
    l=0;
    for(j=0;j<domchild[i].size();++j) {
      k += a[ domchild[i][j]->getIndex() ];
      l += z[ domchild[i][j]->getIndex() ];
    }
    a[i] = b[i] - t[i] + k;
    z[i] = 1 + l;
    if ((domchild[i].size()==0)||(z[i] > a[i] + 1)) {
      flags[i] |= boundary_node; // Mark this node as a boundary node
      z[i] = 1;
    }
  }
  z[0] = -1;
  for(i=1;i<size;++i) {
    j = bblocks.getBlock(i)->getImmedDom()->getIndex();
    if ((flags[j]&boundary_node)!=0) // If j is a boundary node
      z[i] = j;
    else
      z[i] = z[j];
  }
  for(i=0;i<upstart.size();++i) {
    v = upend[i];
    j = v->getImmedDom()->getIndex();
    k = upstart[i]->getIndex();
    while(j < k) {		// while idom(v) properly dominates u
      augment[ k ].push_back(v);
      k = z[k];
    }
  }
}

/// \brief The heart of the phi-node placement algorithm
///
/// Recursively walk the dominance tree starting from a given block.
/// Calculate any children that are in the dominance frontier and add
/// them to the \b merge array.
/// \param qnode is the parent of the given block
/// \param vnode is the given block
void Heritage::visitIncr(FlowBlock *qnode,FlowBlock *vnode)

{
  int4 i,j,k;
  FlowBlock *v,*child;
  vector<FlowBlock *>::iterator iter,enditer;
  
  i = vnode->getIndex();
  j = qnode->getIndex();
  iter = augment[i].begin();
  enditer = augment[i].end();
  for(;iter!=enditer;++iter) {
    v = *iter;
    if (v->getImmedDom()->getIndex() < j) { // If idom(v) is strict ancestor of qnode
      k = v->getIndex();
      if ((flags[k]&merged_node)==0) {
	merge.push_back(v);
	flags[k] |= merged_node;
      }
      if ((flags[k]&mark_node)==0) { // If v is not marked
	flags[k] |= mark_node;	// then mark it
	pq.insert(v,depth[k]); // insert it into the queue
      }
    }
    else
      break;
  }
  if ((flags[i]&boundary_node)==0) { // If vnode is not a boundary node
    for(j=0;j<domchild[i].size();++j) {
      child = domchild[i][j];
      if ((flags[child->getIndex()]&mark_node)==0)	// If the child is not marked
	visitIncr(qnode,child);
    }
  }
}

/// \brief Calculate blocks that should contain MULTIEQUALs for one address range
///
/// This is the main entry point for the phi-node placement algorithm. It is
/// provided the normalized list of written Varnodes in this range.
/// All refinement and guarding must already be performed for the Varnodes, and
/// the dominance tree and its augmentation must already be computed.
/// After this executes, the \b merge array holds blocks that should contain
/// a MULTIEQUAL.
/// \param write is the list of written Varnodes
void Heritage::calcMultiequals(const vector<Varnode *> &write)

{
  pq.reset(maxdepth);
  merge.clear();

  int4 i,j;
  FlowBlock *bl;
				// Place write blocks into the pq
  for(i=0;i<write.size();++i) {
    bl = write[i]->getDef()->getParent(); // Get block where this write occurs
    j = bl->getIndex();
    if ((flags[j]&mark_node)!=0) continue; // Already put in
    pq.insert(bl,depth[j]);	// Insert input node into priority queue
    flags[j] |= mark_node;	// mark input node
  }
  if ((flags[0]&mark_node)==0) { // Make sure start node is in input
    pq.insert(fd->getBasicBlocks().getBlock(0),depth[0]);
    flags[0] |= mark_node;
  }

  while(!pq.empty()) {
    bl = pq.extract();		// Extract the next block
    visitIncr(bl,bl);
  }
  for(i=0;i<flags.size();++i)
    flags[i] &= ~(mark_node|merged_node); // Clear marks from nodes
}

/// \brief The heart of the renaming algorithm.
///
/// From the given block, recursively walk the dominance tree. At each
/// block, visit the PcodeOps in execution order looking for Varnodes that
/// need to be renamed.  As write Varnodes are encountered, a set of stack
/// containers, differentiated by the Varnode's address, are updated so the
/// so the current \e active Varnode is always ready for any \e free Varnode that
/// is encountered. In this was all \e free Varnodes are replaced with the
/// appropriate write Varnode or are promoted to a formal \e input Varnode.
/// \param bl is the current basic block in the dominance tree walk
/// \param varstack is the system of stacks, organized by address
void Heritage::renameRecurse(BlockBasic *bl,VariableStack &varstack)

{
  vector<Varnode *> writelist;	// List varnodes that are written in this block
  BlockBasic *subbl;
  list<PcodeOp *>::iterator oiter,suboiter;
  PcodeOp *op,*multiop;
  Varnode *vnout,*vnin,*vnnew;
  int4 i,slot;

  for(oiter=bl->beginOp();oiter!=bl->endOp();++oiter) {
    op = *oiter;
    if (op->code() != CPUI_MULTIEQUAL) {
				// First replace reads with top of stack
      for(slot=0;slot<op->numInput();++slot) {
	vnin = op->getIn(slot);
	if (vnin->isHeritageKnown()) continue; // not free
	if (!vnin->isActiveHeritage()) continue; // Not being heritaged this round
	vnin->clearActiveHeritage();
	vector<Varnode *> &stack( varstack[ vnin->getAddr() ] );
	if (stack.empty()) {
	  vnnew = fd->newVarnode(vnin->getSize(),vnin->getAddr());
	  vnnew = fd->setInputVarnode(vnnew);
	  stack.push_back(vnnew);
	}
	else
	  vnnew = stack.back();
				// INDIRECTs and their op really happen AT SAME TIME
	if (vnnew->isWritten() && (vnnew->getDef()->code()==CPUI_INDIRECT)) {
	  if (PcodeOp::getOpFromConst(vnnew->getDef()->getIn(1)->getAddr()) == op) {
	    if (stack.size()==1) {
	      vnnew = fd->newVarnode(vnin->getSize(),vnin->getAddr());
	      vnnew = fd->setInputVarnode(vnnew);
	      stack.insert(stack.begin(),vnnew);
	    }
	    else
	      vnnew = stack[stack.size()-2];
	  }
	}
	fd->opSetInput(op,vnnew,slot);
	if (vnin->hasNoDescend())
	  fd->deleteVarnode(vnin);
      }
    }
				// Then push writes onto stack
    vnout = op->getOut();
    if (vnout == (Varnode *)0) continue;
    if (!vnout->isActiveHeritage()) continue; // Not a normalized write
    vnout->clearActiveHeritage();
    varstack[ vnout->getAddr() ].push_back(vnout); // Push write onto stack
    writelist.push_back(vnout);
  }
  for(i=0;i<bl->sizeOut();++i) {
    subbl = (BlockBasic *)bl->getOut(i);
    slot = bl->getOutRevIndex(i);
    for(suboiter=subbl->beginOp();suboiter!=subbl->endOp();++suboiter) {
      multiop = *suboiter;
      if (multiop->code()!=CPUI_MULTIEQUAL) break; // For each MULTIEQUAL
      vnin = multiop->getIn(slot);
      if (!vnin->isHeritageKnown()) {
	vector<Varnode *> &stack( varstack[ vnin->getAddr() ] );
	if (stack.empty()) {
	  vnnew = fd->newVarnode(vnin->getSize(),vnin->getAddr());
	  vnnew = fd->setInputVarnode(vnnew);
	  stack.push_back(vnnew);
	}
	else
	  vnnew = stack.back();
	fd->opSetInput(multiop,vnnew,slot);
	if (vnin->hasNoDescend())
	  fd->deleteVarnode(vnin);
      }
    }
  }
				// Now we recurse to subtrees
  i = bl->getIndex();
  for(slot=0;slot<domchild[i].size();++slot)
    renameRecurse((BlockBasic *)domchild[i][slot],varstack);
				// Now we pop this blocks writes of the stack
  for(i=0;i<writelist.size();++i) {
    vnout = writelist[i];
    varstack[vnout->getAddr()].pop_back();
  }
}

/// \brief Increase the heritage delay for the given Varnode and request a restart
///
/// If applicable, look up the heritage stats for the address space for the given
/// Varnode and increment the delay.  The address space must allow an additional
/// delay and can only be incremented once.  If the increment succeeds, the
/// function is marked as having a \e restart pending.
/// \param vn is the given Varnode
void Heritage::bumpDeadcodeDelay(Varnode *vn)

{
  AddrSpace *spc = vn->getSpace();
  if ((spc->getType() != IPTR_PROCESSOR)&&(spc->getType() != IPTR_SPACEBASE))
    return;			// Not the right kind of space
  if (spc->getDelay() != spc->getDeadcodeDelay())
    return;			// there is already a global delay
  if (fd->getOverride().hasDeadcodeDelay(spc))
    return;			// A delay has already been installed
  fd->getOverride().insertDeadcodeDelay(spc,spc->getDeadcodeDelay()+1);
  fd->setRestartPending(true);
}

/// \brief Perform the renaming algorithm for the current set of address ranges
///
/// Phi-node placement must already have happened.
void Heritage::rename(void)

{
  VariableStack varstack;
  renameRecurse((BlockBasic *)fd->getBasicBlocks().getBlock(0),varstack);
  disjoint.clear();
}

/// \brief Perform phi-node placement for the current set of address ranges
///
/// Main entry point for performing the phi-node placement algorithm.
/// Assume \b disjoint is filled with all the free Varnodes to be heritaged
void Heritage::placeMultiequals(void)

{
  LocationMap::iterator iter;
  vector<Varnode *> readvars;
  vector<Varnode *> writevars;
  vector<Varnode *> inputvars;
  vector<Varnode *> removevars;
  PcodeOp *multiop;
  Varnode *vnin;
  BlockBasic *bl;
  int4 max;

  for(iter=disjoint.begin();iter!=disjoint.end();++iter) { 
    Address addr = (*iter).first;
    int4 size = (*iter).second.size;
    readvars.clear();
    writevars.clear();
    inputvars.clear();
    removevars.clear();
    max = collect(addr,size,readvars,writevars,inputvars,removevars); // Collect reads/writes
    if ((size > 4)&&(max < size)) {
      if (refinement(addr,size,readvars,writevars,inputvars)) {
	iter = disjoint.find(addr);
	size =(*iter).second.size;
	readvars.clear();
	writevars.clear();
	inputvars.clear();
	removevars.clear();
	collect(addr,size,readvars,writevars,inputvars,removevars);
      }
    }
    if (readvars.empty() && (addr.getSpace()->getType() == IPTR_INTERNAL))
      continue;
    if (!removevars.empty())
      removeRevisitedMarkers(removevars, addr, size);
    guardInput(addr,size,inputvars);
    guard(addr,size,readvars,writevars,inputvars);
    if (readvars.empty()&&writevars.empty()) continue;
    calcMultiequals(writevars); // Calculate where MULTIEQUALs go
    for(int4 i=0;i<merge.size();++i) {
      bl = (BlockBasic *) merge[i];
      multiop = fd->newOp(bl->sizeIn(),bl->getStart());
      Varnode *vnout = fd->newVarnodeOut(size,addr,multiop);
      vnout->setActiveHeritage();
      fd->opSetOpcode(multiop,CPUI_MULTIEQUAL); // Create each MULTIEQUAL
      for(int4 j=0;j<bl->sizeIn();++j) {
	vnin = fd->newVarnode(size,addr);
	fd->opSetInput(multiop,vnin,j);
      }
      fd->opInsertBegin(multiop,bl);	// Insert at beginning of block
    }
  }
  merge.clear();
}

/// This is called once to initialize \b this class in preparation for doing the
/// heritage passes.  An information structure is allocated and mapped to each
/// address space.
void Heritage::buildInfoList(void)

{
  if (!infolist.empty()) return;
  const AddrSpaceManager *manage = fd->getArch();
  infolist.reserve(manage->numSpaces());
  for(int4 i=0;i<manage->numSpaces();++i)
    infolist.emplace_back(manage->getSpace(i));
}

/// From any address space that is active for this pass, free Varnodes are collected
/// and then fully integrated into SSA form.  Reads are connected to writes, inputs
/// are identified, and phi-nodes are placed.
void Heritage::heritage(void)

{
  VarnodeLocSet::const_iterator iter,enditer;
  HeritageInfo *info;
  Varnode *vn;
  bool needwarning;
  Varnode *warnvn = (Varnode *)0;
  int4 reprocessStackCount = 0;
  AddrSpace *stackSpace = (AddrSpace *)0;
  vector<PcodeOp *> freeStores;
  PreferSplitManager splitmanage;

  if (maxdepth == -1)		// Has a restructure been forced
    buildADT();

  processJoins();
  if (pass == 0) {
    splitmanage.init(fd,&fd->getArch()->splitrecords);
    splitmanage.split();
  }
  for(int4 i=0;i<infolist.size();++i) {
    info = &infolist[i];
    if (!info->isHeritaged()) continue;
    if (pass < info->delay) continue; // It is too soon to heritage this space
    if (info->hasCallPlaceholders)
      clearStackPlaceholders(info);

    if (!info->loadGuardSearch) {
      info->loadGuardSearch = true;
      if (discoverIndexedStackPointers(info->space,freeStores,true)) {
	    reprocessStackCount += 1;
	    stackSpace = info->space;
      }
    }
    needwarning = false;
    iter = fd->beginLoc(info->space);
    enditer = fd->endLoc(info->space);

    while(iter != enditer) {
      vn = *iter++;
      if ((!vn->isWritten())&&vn->hasNoDescend()&&(!vn->isUnaffected())&&(!vn->isInput()))
	continue;
      if (vn->isWriteMask()) continue;
      int4 prev = 0;
      LocationMap::iterator liter = globaldisjoint.add(vn->getAddr(),vn->getSize(),pass,prev);
      if (prev == 0)		// All new location being heritaged, or intersecting with something new
	disjoint.add((*liter).first,(*liter).second.size,pass,prev);
      else if (prev==2) { // If completely contained in range from previous pass
	if (vn->isHeritageKnown()) continue; // Don't heritage if we don't have to 
	if (vn->hasNoDescend()) continue;
	if ((!needwarning)&&(info->deadremoved>0)) {
	  needwarning = true;
	  bumpDeadcodeDelay(vn);
	  warnvn = vn;
	}
	disjoint.add((*liter).first,(*liter).second.size,pass,prev);
      }
      else {
	if ((!needwarning)&&(info->deadremoved>0)) {
	  // TODO: We should check if this varnode is tiled by previously heritaged ranges
	  if (vn->isHeritageKnown()) continue;		// Assume that it is tiled and produced by merging
		  // In most cases, a truly new overlapping read will hit the bumpDeadcodeDelay either here or in prev==2
	  needwarning = true;
	  bumpDeadcodeDelay(vn);
	  warnvn = vn;
	}
	disjoint.add((*liter).first,(*liter).second.size,pass,prev);
      }
    }

    if (needwarning) {
      if (!info->warningissued) {
	info->warningissued = true;
	ostringstream errmsg;
	errmsg << "Heritage AFTER dead removal. Example location: ";
	warnvn->printRawNoMarkup(errmsg);
	if (!warnvn->hasNoDescend()) {
	  PcodeOp *warnop = *warnvn->beginDescend();
	  errmsg << " : ";
	  warnop->getAddr().printRaw(errmsg);
	}
	fd->warningHeader(errmsg.str());
      }
    }
  }
  placeMultiequals();
  rename();
  if (reprocessStackCount > 0)
    reprocessFreeStores(stackSpace, freeStores);
  analyzeNewLoadGuards();
  handleNewLoadCopies();
  if (pass == 0)
    splitmanage.splitAdditional();
  pass += 1;
}

/// \param op is the given PcodeOp
/// \return the associated LoadGuard or NULL
const LoadGuard *Heritage::getStoreGuard(PcodeOp *op) const

{
  list<LoadGuard>::const_iterator iter;
  for(iter=storeGuard.begin();iter!=storeGuard.end();++iter) {
    if ((*iter).op == op)
      return &(*iter);
  }
  return (const LoadGuard *)0;
}

/// \brief Get the number times heritage was performed for the given address space
///
/// A negative number indicates the number of passes to wait before the first
/// heritage will occur.
/// \param spc is the given address space
/// \return the number of heritage passes performed
int4 Heritage::numHeritagePasses(AddrSpace *spc) const

{
  const HeritageInfo *info = getInfo(spc);
  if (!info->isHeritaged())
    throw LowlevelError("Trying to calculate passes for non-heritaged space");
  return (pass - info->delay);
}

/// Record that Varnodes have been removed from the given space so that we can
/// tell if there is any new heritage \e after the dead code removal.
/// \param spc is the given address space
void Heritage::seenDeadCode(AddrSpace *spc)

{
  HeritageInfo *info = getInfo(spc);
  info->deadremoved = 1;
}

/// Linking in Varnodes can be delayed for specific address spaces (to make sure all
/// Varnodes for the space have been generated. Return the number of \e passes to
/// delay for the given space.  0 means no delay.
/// \param spc is the given address space
/// \return the number of passes heritage is delayed
int4 Heritage::getDeadCodeDelay(AddrSpace *spc) const

{
  const HeritageInfo *info = getInfo(spc);
  return info->deadcodedelay;
}

/// Set the number of heritage passes that are skipped before allowing dead code
/// removal for Varnodes in the given address space (to make sure all Varnodes have
/// been linked in before deciding what is dead).
/// \param spc is the given address space
/// \param delay is the number of passes to delay
void Heritage::setDeadCodeDelay(AddrSpace *spc,int4 delay)

{
  HeritageInfo *info = getInfo(spc);
  if (delay < info->delay)
    throw LowlevelError("Illegal deadcode delay setting");
  info->deadcodedelay = delay;
}

/// Check if the required number of passes have transpired to allow removal of dead
/// Varnodes in the given address space. If allowed, presumably no new Varnodes will
/// be generated for the space.
/// \param spc is the given address space
/// \return \b true if dead code removal is allowed
bool Heritage::deadRemovalAllowed(AddrSpace *spc) const

{
  const HeritageInfo *info = getInfo(spc);
  return (pass > info->deadcodedelay);
}

/// \brief Check if dead code removal is safe and mark that removal has happened
///
/// A convenience function combining deadRemovalAllowed() and seenDeadCode().
/// Return \b true if it is \e safe to remove dead code, and, if so, also inform
/// the system that dead code has happened for the given space.
/// \param spc is the given address space
/// \return \b true if dead code removal is allowed
bool Heritage::deadRemovalAllowedSeen(AddrSpace *spc)

{
  HeritageInfo *info = getInfo(spc);
  bool res = (pass > info->deadcodedelay);
  if (res)
    info->deadremoved = 1;
  return res;
}

/// Reset all analysis as if no heritage passes have yet taken place for the function.
/// This does not directly affect Varnodes and PcodeOps in the underlying Funcdata.
void Heritage::clear(void)

{
  disjoint.clear();
  globaldisjoint.clear();
  domchild.clear();
  augment.clear();
  flags.clear();
  depth.clear();
  merge.clear();
  clearInfoList();
  loadGuard.clear();
  storeGuard.clear();
  maxdepth = -1;
  pass = 0;
}

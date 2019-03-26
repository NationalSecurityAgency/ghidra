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
LocationMap::iterator LocationMap::find(Address addr)

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
int4 LocationMap::findPass(Address addr) const

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
  for(iter=infolist.begin();iter!=infolist.end();++iter) {
    (*iter).deadremoved = 0;
    (*iter).deadcodedelay = (*iter).delay;
    (*iter).warningissued = false;
  }
}

/// \brief Collect free reads, writes, and inputs in the given address range
///
/// \param addr is the starting address of the range
/// \param size is the number of bytes in the range
/// \param read will hold any read Varnodes in the range
/// \param write will hold any written Varnodes
/// \param input will hold any input Varnodes
/// \return the maximum size of a write
int4 Heritage::collect(Address addr,int4 size,
		      vector<Varnode *> &read,vector<Varnode *> &write,
		      vector<Varnode *> &input) const

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
	if (vn->getSize() > maxsize) // Look for maximum write size
	  maxsize = vn->getSize();
	write.push_back(vn);
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
    if (op->isCall() && callOpIndirectEffect(pieceaddr,mostsigsize,op)) {	// Unless CALL definitely has no effect on piece
      newop = fd->newIndirectCreation(op,pieceaddr,mostsigsize,false);		// Don't create a new big read if write is from a CALL
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
      //      guardLoads(flags,addr,size,write);
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
	if (fc->getStackPlaceholderSlot() < 0) { // Any stack resolution is complete (or never started)
	  if (fc->getSpacebaseOffset() != FuncCallSpecs::offset_unknown)
	    off = spc->wrapOffset(off - fc->getSpacebaseOffset());
	  else
	    tryregister = false; // Do not attempt to register this stack loc as a trial
	}
	else {			// Stack has not been resolved, so we need to abort
	  fc->abortSpacebaseRelative(*fd);
	  tryregister = false;
	}
      }
      Address taddr(spc,off);
      if (tryregister && fc->possibleInputParam(taddr,size)) {
	ParamActive *active = fc->getActiveInput();
	if (active->whichTrial(taddr,size)<0) { // If not already a trial
	  PcodeOp *op = fc->getOp();
	  active->registerTrial(taddr,size);
	  Varnode *vn = fd->newVarnode(size,addr);
	  vn->setActiveHeritage();
	  fd->opInsertInput(op,vn,op->numInput());
	}
      }
    }
    // We do not guard the call if the effect is "unaffected" or "reload"
    if ((effecttype == EffectRecord::unknown_effect)||(effecttype == EffectRecord::return_address)) {
      indop = fd->newIndirectOp(fc->getOp(),addr,size);
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

  iterend = fd->endOp(CPUI_STORE);
  for(iter=fd->beginOp(CPUI_STORE);iter!=iterend;++iter) {
    op = *iter;
    if (op->isDead()) continue;
    if (addr.getSpace()->contain(Address::getSpaceFromConst(op->getIn(0)->getAddr()))) { // Does store affect same space
      indop = fd->newIndirectOp(op,addr,size);
      indop->getIn(0)->setActiveHeritage();
      indop->getOut()->setActiveHeritage();
      write.push_back(indop->getOut());
    }
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

// void Heritage::guardLoads(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write)

// {
//   list<PcodeOp *>::const_iterator iter,iterend;
//   PcodeOp *op,*copyop;

//   iterend = fd->endOp(CPUI_LOAD);
//   for(iter=fd->beginOp(CPUI_LOAD);iter!=iterend;++iter) {
//     op = *iter;
//     if (op->isDead()) continue;
// 				// Check if load could possible read from this addr
//     if (!Address::getSpaceFromConst(op->getIn(0)->getAddr())->contain(addr.getSpace()))
//       continue;
//     copyop = fd->newOp(1,op->getAddr());
//     Varnode *vn = fd->newVarnodeOut(size,addr,copyop);
//     vn->setActiveHeritage();
//     vn->setAddrForce();
//     fd->opSetOpcode(copyop,CPUI_COPY);
//     Varnode *invn = fd->newVarnode(size,addr);
//     vn->setActiveHeritage();
//     fd->opSetInput(copyop,invn,0);
//     fd->opInsertBefore(copyop,op);
//   }
// }

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
    max = collect(addr,size,readvars,writevars,inputvars); // Collect reads/writes
    if ((size > 4)&&(max < size)) {
      if (refinement(addr,size,readvars,writevars,inputvars)) {
	iter = disjoint.find(addr);
	size =(*iter).second.size;
	readvars.clear();
	writevars.clear();
	inputvars.clear();
	collect(addr,size,readvars,writevars,inputvars);
      }
    }
    if (readvars.empty() && (addr.getSpace()->getType() == IPTR_INTERNAL))
      continue;
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
  AddrSpace *spc;
  const AddrSpaceManager *manage = fd->getArch();
  for(int4 i=0;i<manage->numSpaces();++i) {
    spc = manage->getSpace(i);
    infolist.push_back(HeritageInfo(spc,spc->getDelay(),spc->getDeadcodeDelay()));
  }
}

/// From any address space that is active for this pass, free Varnodes are collected
/// and then fully integrated into SSA form.  Reads are connected to writes, inputs
/// are identified, and phi-nodes are placed.
void Heritage::heritage(void)

{
  VarnodeLocSet::const_iterator iter,enditer;
  AddrSpace *space;
  HeritageInfo *info;
  Varnode *vn;
  bool needwarning;
  Varnode *warnvn = (Varnode *)0;
  const AddrSpaceManager *manage = fd->getArch();
  PreferSplitManager splitmanage;

  if (maxdepth == -1)		// Has a restructure been forced
    buildADT();

  processJoins();
  if (pass == 0) {
    splitmanage.init(fd,&fd->getArch()->splitrecords);
    splitmanage.split();
  }
  for(int4 i=0;i<manage->numSpaces();++i) {
    space = manage->getSpace(i);
    if (!space->isHeritaged()) continue;
    info = getInfo(space);
    if (pass < info->delay) continue; // It is too soon to heritage this space
    needwarning = false;
    iter = fd->beginLoc(space);
    enditer = fd->endLoc(space);

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
  if (pass == 0)
    splitmanage.splitAdditional();
  pass += 1;
}

/// \brief Get the number times heritage was performed for the given address space
///
/// A negative number indicates the number of passes to be wait before the first
/// heritage will occur.
/// \param spc is the given address space
/// \return the number of heritage passes performed
int4 Heritage::numHeritagePasses(AddrSpace *spc) const

{
  const HeritageInfo *info = getInfo(spc);
  if (info == (const HeritageInfo *)0)
    throw LowlevelError("Trying to calculate passes for non-heritaged space");
  return (info->delay - pass);
}

/// Record that Varnodes have been removed from the given space so that we can
/// tell if there is any new heritage \e after the dead code removal.
/// \param spc is the given address space
void Heritage::seenDeadCode(AddrSpace *spc)

{
  HeritageInfo *info = getInfo(spc);
  if (info == (HeritageInfo *)0)
    throw LowlevelError("Informed of deadcode removal for non-heritaged space");
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
  if (info == (const HeritageInfo *)0)
    throw LowlevelError("Could not get heritage delay for space: "+spc->getName());
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
  if (info == (HeritageInfo *)0)
    throw LowlevelError("Setting heritage delay for non-heritaged space");
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
  if (info == (HeritageInfo *)0)
    throw LowlevelError("Heritage query for non-heritaged space");
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
  if (info == (HeritageInfo *)0)
    throw LowlevelError("Heritage query for non-heritaged space");
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
  maxdepth = -1;
  pass = 0;
}

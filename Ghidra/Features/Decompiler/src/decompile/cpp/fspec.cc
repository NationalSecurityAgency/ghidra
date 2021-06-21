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
#include "fspec.hh"
#include "funcdata.hh"

void ParamEntry::resolveJoin(void)

{
  if (spaceid->getType() == IPTR_JOIN) 
    joinrec = spaceid->getManager()->findJoin(addressbase);
  else
    joinrec = (JoinRecord *)0;
}

/// \brief Construct entry from components
///
/// \param t is the data-type class (TYPE_UNKNOWN or TYPE_FLOAT)
/// \param grp is the group id
/// \param grpsize is the number of consecutive groups occupied
/// \param loc is the starting address of the memory range
/// \param sz is the number of bytes in the range
/// \param mnsz is the smallest size of a logical value
/// \param align is the alignment (0 means the memory range will hold one parameter exclusively)
/// \param normalstack is \b true if parameters are allocated from the front of the range
ParamEntry::ParamEntry(type_metatype t,int4 grp,int4 grpsize,const Address &loc,int4 sz,int4 mnsz,int4 align,bool normalstack)

{
  flags = 0;
  type = t;
  group = grp;
  groupsize = grpsize;
  spaceid = loc.getSpace();
  addressbase = loc.getOffset();
  size = sz;
  minsize = mnsz;
  alignment = align;
  if (alignment != 0)
    numslots = size / alignment;
  else
    numslots = 1;
  if (!normalstack)
    flags |= reverse_stack;
  resolveJoin();
}

/// This entry must properly contain the other memory range, and
/// the entry properties must be compatible.
/// \param op2 is the other entry to compare with \b this
/// \return \b true if the other entry is contained
bool ParamEntry::contains(const ParamEntry &op2) const

{
  if ((type!=TYPE_UNKNOWN)&&(op2.type != type)) return false;
  if (spaceid != op2.spaceid) return false;
  if (op2.addressbase < addressbase) return false;
  if ((op2.addressbase+op2.size-1) > (addressbase+size-1)) return false;
  if (alignment != op2.alignment) return false;
  return true;
}

/// \param addr is the starting address of the potential containing range
/// \param sz is the number of bytes in the range
/// \return \b true if the entire ParamEntry fits inside the range
bool ParamEntry::containedBy(const Address &addr,int4 sz) const

{
  if (spaceid != addr.getSpace()) return false;
  if (addressbase < addr.getOffset()) return false;
  uintb entryoff = addressbase + size-1;
  uintb rangeoff = addr.getOffset() + sz-1;
  return (entryoff <= rangeoff);
}

/// Check if the given memory range is contained in \b this.
/// If it is contained, return the endian aware offset of the containment.
/// I.e. if the least significant byte of the given range falls on the least significant
/// byte of the \b this, return 0.  If it intersects the second least significant, return 1, etc.
/// \param addr is the starting address of the given memory range
/// \param sz is the size of the given memory range in bytes
/// \return the endian aware alignment or -1 if the given range isn't contained
int4 ParamEntry::justifiedContain(const Address &addr,int4 sz) const

{
  if (joinrec != (JoinRecord *)0) {
    int4 res = 0;
    for(int4 i=joinrec->numPieces()-1;i>=0;--i) { // Move from least significant to most
      const VarnodeData &vdata(joinrec->getPiece(i));
      int4 cur = vdata.getAddr().justifiedContain(vdata.size,addr,sz,false);
      if (cur<0)
	res += vdata.size;	// We skipped this many less significant bytes
      else {
	return res + cur;
      }
    }
    return -1;			// Not contained at all
  }
  if (alignment==0) {
    // Ordinary endian containment
    Address entry(spaceid,addressbase);
    return entry.justifiedContain(size,addr,sz,((flags&force_left_justify)!=0));
  }
  if (spaceid != addr.getSpace()) return -1;
  uintb startaddr = addr.getOffset();
  if (startaddr < addressbase) return -1;
  uintb endaddr = startaddr + sz - 1;
  if (endaddr < startaddr) return -1; // Don't allow wrap around
  if (endaddr > (addressbase+size-1)) return -1;
  startaddr -= addressbase;
  endaddr -= addressbase;
  if (!isLeftJustified()) {   // For right justified (big endian), endaddr must be aligned
    int4 res = (int4)((endaddr+1) % alignment);
    if (res==0) return 0;
    return (alignment-res);
  }
  return (int4)(startaddr % alignment);
}

/// \brief Calculate the containing memory range
///
/// Pass back the VarnodeData (space,offset,size) of the parameter that would contain
/// the given memory range.  If \b this contains the range and is \e exclusive, just
/// pass back \b this memory range.  Otherwise the passed back range will depend on
/// alignment.
/// \param addr is the starting address of the given range
/// \param sz is the size of the given range in bytes
/// \param res is the reference to VarnodeData that will be passed back
/// \return \b true if the given range is contained at all
bool ParamEntry::getContainer(const Address &addr,int4 sz,VarnodeData &res) const

{
  Address endaddr = addr + (sz-1);
  if (joinrec != (JoinRecord *)0) {
    for(int4 i=joinrec->numPieces()-1;i>=0;--i) { // Move from least significant to most
      const VarnodeData &vdata(joinrec->getPiece(i));
      if ((addr.overlap(0,vdata.getAddr(),vdata.size) >=0)&&
	  (endaddr.overlap(0,vdata.getAddr(),vdata.size)>=0)) {
	res = vdata;
	return true;
      }
    }
    return false;		// Not contained at all
  }
  Address entry(spaceid,addressbase);
  if (addr.overlap(0,entry,size)<0) return false;
  if (endaddr.overlap(0,entry,size)<0) return false;
  if (alignment==0) {
    // Ordinary endian containment
    res.space = spaceid;
    res.offset = addressbase;
    res.size = size;
    return true;
  }
  uintb al = (addr.getOffset() - addressbase) % alignment;
  res.space = spaceid;
  res.offset = addr.getOffset() - al;
  res.size = (int4)(endaddr.getOffset()-res.offset) + 1;
  int4 al2 = res.size % alignment;
  if (al2 != 0)
    res.size += (alignment - al2); // Bump up size to nearest alignment
  return true;
}

/// \brief Calculate the type of \e extension to expect for the given logical value
///
/// Return:
///   - CPUI_COPY if no extensions are assumed for small values in this container
///   - CPUI_INT_SEXT indicates a sign extension
///   - CPUI_INT_ZEXT indicates a zero extension
///   - CPUI_PIECE indicates an integer extension based on type of parameter
///
///  (A CPUI_FLOAT2FLOAT=float extension is handled by heritage and JoinRecord)
/// If returning an extension operator, pass back the container being extended.
/// \param addr is the starting address of the logical value
/// \param sz is the size of the logical value in bytes
/// \param res will hold the passed back containing range
/// \return the type of extension
OpCode ParamEntry::assumedExtension(const Address &addr,int4 sz,VarnodeData &res) const

{
  if ((flags & (smallsize_zext|smallsize_sext|smallsize_inttype))==0) return CPUI_COPY;
  if (alignment != 0) {
    if (sz >= alignment)
      return CPUI_COPY;
  }
  else if (sz >= size)
    return CPUI_COPY;
  if (joinrec != (JoinRecord *)0) return CPUI_COPY;
  if (justifiedContain(addr,sz)!=0) return CPUI_COPY; // (addr,sz) is not justified properly to allow an extension
  if (alignment == 0) {	// If exclusion, take up the whole entry
    res.space = spaceid;
    res.offset = addressbase;
    res.size = size;
  }
  else {	// Otherwise take up whole alignment
    res.space = spaceid;
    int4 alignAdjust = (addr.getOffset() - addressbase) % alignment;
    res.offset = addr.getOffset() - alignAdjust;
    res.size = alignment;
  }
  if ((flags & smallsize_zext)!=0)
    return CPUI_INT_ZEXT;
  if ((flags & smallsize_inttype)!=0)
    return CPUI_PIECE;
  return CPUI_INT_SEXT;
}

/// \brief Calculate the \e slot occupied by a specific address
///
/// For \e non-exclusive entries, the memory range can be divided up into
/// \b slots, which are chunks that take up a full alignment. I.e. for an entry with
/// alignment 4, slot 0 is bytes 0-3 of the range, slot 1 is bytes 4-7, etc.
/// Assuming the given address is contained in \b this entry, and we \b skip ahead a number of bytes,
/// return the \e slot associated with that byte.
/// NOTE: its important that the given address has already been checked for containment.
/// \param addr is the given address
/// \param skip is the number of bytes to skip ahead
/// \return the slot index
int4 ParamEntry::getSlot(const Address &addr,int4 skip) const

{
  int4 res = group;
  if (alignment != 0) {
    uintb diff = addr.getOffset() + skip - addressbase;
    int4 baseslot = (int4)diff / alignment;
    if (isReverseStack())
      res += (numslots -1) - baseslot;
    else
      res += baseslot;
  }
  else if (skip != 0) {
    res += (groupsize-1);
  }
  return res;
}

/// \brief Calculate the storage address assigned when allocating a parameter of a given size
///
/// Assume \b slotnum slots have already been assigned and increment \b slotnum
/// by the number of slots used.
/// Return an invalid address if the size is too small or if there are not enough slots left.
/// \param slotnum is a reference to used slots (which will be updated)
/// \param sz is the size of the parameter to allocated
/// \return the address of the new parameter (or an invalid address)
Address ParamEntry::getAddrBySlot(int4 &slotnum,int4 sz) const

{
  Address res;			// Start with an invalid result
  int4 spaceused;
  if (sz < minsize) return res;
  if (alignment == 0) {		// If not an aligned entry (allowing multiple slots)
    if (slotnum != 0) return res; // Can only allocate slot 0
    if (sz > size) return res;	// Check on maximum size
    res = Address(spaceid,addressbase);	// Get base address of the slot
    spaceused = size;
    if (((flags & smallsize_floatext)!=0)&&(sz != size)) { // Do we have an implied floating-point extension
      AddrSpaceManager *manager = spaceid->getManager();
      res = manager->constructFloatExtensionAddress(res,size,sz);
      return res;
    }
  }
  else {
    int4 slotsused = sz / alignment; // How many slots does a -sz- byte object need
    if ( (sz % alignment) != 0)
      slotsused += 1;
    if (slotnum + slotsused > numslots)	// Check if there are enough slots left
      return res;
    spaceused = slotsused * alignment;
    int4 index;
    if (isReverseStack()) {
      index = numslots;
      index -= slotnum;
      index -= slotsused;
    } 
    else
      index = slotnum;
    res = Address(spaceid, addressbase + index * alignment);
    slotnum += slotsused;	// Inform caller of number of slots used
  }
  if (!isLeftJustified())   // Adjust for right justified (big endian)
    res = res + (spaceused - sz); 
  return res;
}

/// \brief Restore the entry from an XML stream
///
/// \param el is the root \<pentry> element
/// \param manage is a manager to resolve address space references
/// \param normalstack is \b true if the parameters should be allocated from the front of the range
void ParamEntry::restoreXml(const Element *el,const AddrSpaceManager *manage,bool normalstack)

{
  flags = 0;
  type = TYPE_UNKNOWN;
  size = minsize = -1;		// Must be filled in
  alignment = 0;		// default
  numslots = 1;
  groupsize = 1;		// default
  int4 num = el->getNumAttributes();
  
  for(int4 i=0;i<num;++i) {
    const string &attrname( el->getAttributeName(i) );
    if (attrname=="minsize") {
      istringstream i1(el->getAttributeValue(i));
      i1.unsetf(ios::dec | ios::hex | ios::oct);
      i1 >> minsize;
    }
    else if (attrname == "size") { // old style
      istringstream i2(el->getAttributeValue(i));
      i2.unsetf(ios::dec | ios::hex | ios::oct);
      i2 >> alignment;
    }
    else if (attrname == "align") { // new style
      istringstream i4(el->getAttributeValue(i));
      i4.unsetf(ios::dec | ios::hex | ios::oct);
      i4 >> alignment;
    }
    else if (attrname == "maxsize") {
      istringstream i3(el->getAttributeValue(i));
      i3.unsetf(ios::dec | ios::hex | ios::oct);
      i3 >> size;
    }
    else if (attrname == "metatype")
      type = string2metatype(el->getAttributeValue(i));
    else if (attrname == "group") { // Override the group
      istringstream i5(el->getAttributeValue(i));
      i5.unsetf(ios::dec | ios::hex | ios::oct);
      i5 >> group;
    }
    else if (attrname == "groupsize") {
      istringstream i6(el->getAttributeValue(i));
      i6.unsetf(ios::dec | ios::hex | ios::oct);
      i6 >> groupsize;
    }
    else if (attrname == "extension") {
      flags &= ~((uint4)(smallsize_zext | smallsize_sext | smallsize_inttype));
      if (el->getAttributeValue(i) == "sign")
	flags |= smallsize_sext;
      else if (el->getAttributeValue(i) == "zero")
	flags |= smallsize_zext;
      else if (el->getAttributeValue(i) == "inttype")
	flags |= smallsize_inttype;
      else if (el->getAttributeValue(i) == "float")
	flags |= smallsize_floatext;
      else if (el->getAttributeValue(i) != "none")
	throw LowlevelError("Bad extension attribute");
    }
    else
      throw LowlevelError("Unknown ParamEntry attribute: "+attrname);
  }
  if ((size==-1)||(minsize==-1))
    throw LowlevelError("ParamEntry not fully specified");
  if (alignment == size)
    alignment = 0;
  Address addr;
  addr = Address::restoreXml( *el->getChildren().begin(),manage);
  spaceid = addr.getSpace();
  addressbase = addr.getOffset();
  if (alignment != 0) {
//    if ((addressbase % alignment) != 0)
//      throw LowlevelError("Stack <pentry> address must match alignment");
    numslots = size / alignment;
  }
  if (spaceid->isReverseJustified()) {
    if (spaceid->isBigEndian())
      flags |= force_left_justify;
    else
      throw LowlevelError("No support for right justification in little endian encoding");
  }
  if (!normalstack) {
    flags |= reverse_stack;
    if (alignment != 0) {
      if ((size % alignment) != 0)
	throw LowlevelError("For positive stack growth, <pentry> size must match alignment");
    }
  }
  resolveJoin();
}

/// \brief Check if \b this entry represents a \e joined parameter and requires extra scrutiny
///
/// Return value parameter lists allow overlapping entries if one of the overlapping entries
/// is a \e joined parameter.  In this case the return value recovery logic needs to know
/// what portion(s) of the joined parameter are overlapped. This method sets flags on \b this
/// to indicate the overlap.
/// \param entry is the full parameter list to check for overlaps with \b this
void ParamEntry::extraChecks(list<ParamEntry> &entry)

{
  if (joinrec == (JoinRecord *)0) return;		// Nothing to do if not multiprecision
  if (joinrec->numPieces() != 2) return;
  const VarnodeData &highPiece(joinrec->getPiece(0));
  bool seenOnce = false;
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {	// Search for high piece, used as whole/low in another entry
    AddrSpace *spc = (*iter).getSpace();
    uintb off = (*iter).getBase();
    int4 sz = (*iter).getSize();
    if ((highPiece.offset == off)&&(highPiece.space == spc)&&(highPiece.size == sz)) {
      if (seenOnce) throw LowlevelError("Extra check hits twice");
      seenOnce = true;
      flags |= extracheck_low;				// If found, we must do extra checks on the low
    }
  }
  if (!seenOnce)
    flags |= extracheck_high;				// The default is to do extra checks on the high
}

ParamListStandard::ParamListStandard(const ParamListStandard &op2)

{
  numgroup = op2.numgroup;
  entry = op2.entry;
  spacebase = op2.spacebase;
  maxdelay = op2.maxdelay;
  pointermax = op2.pointermax;
  thisbeforeret = op2.thisbeforeret;
  nonfloatgroup = op2.nonfloatgroup;
  populateResolver();
}

ParamListStandard::~ParamListStandard(void)

{
  for(int4 i=0;i<resolverMap.size();++i) {
    ParamEntryResolver *resolver = resolverMap[i];
    if (resolver != (ParamEntryResolver *)0)
      delete resolver;
  }
}

/// Find the (first) entry containing the given memory range
/// \param loc is the starting address of the range
/// \param size is the number of bytes in the range
/// \return the pointer to the matching ParamEntry or null if no match exists
const ParamEntry *ParamListStandard::findEntry(const Address &loc,int4 size) const

{
  int4 index = loc.getSpace()->getIndex();
  if (index >= resolverMap.size())
    return (const ParamEntry *)0;
  ParamEntryResolver *resolver = resolverMap[index];
  if (resolver == (ParamEntryResolver *)0)
    return (const ParamEntry *)0;
  pair<ParamEntryResolver::const_iterator,ParamEntryResolver::const_iterator> res;
  res = resolver->find(loc.getOffset());
  while(res.first != res.second) {
    const ParamEntry *testEntry = (*res.first).getParamEntry();
    ++res.first;
    if (testEntry->getMinSize() > size) continue;
    if (testEntry->justifiedContain(loc,size)==0)	// Make sure the range is properly justified in entry
      return testEntry;
  }
  return (const ParamEntry *)0;
}

int4 ParamListStandard::characterizeAsParam(const Address &loc,int4 size) const

{
  int4 index = loc.getSpace()->getIndex();
  if (index >= resolverMap.size())
    return 0;
  ParamEntryResolver *resolver = resolverMap[index];
  if (resolver == (ParamEntryResolver *)0)
    return 0;
  pair<ParamEntryResolver::const_iterator,ParamEntryResolver::const_iterator> iterpair;
  iterpair = resolver->find(loc.getOffset());
  int4 res = 0;
  while(iterpair.first != iterpair.second) {
    const ParamEntry *testEntry = (*iterpair.first).getParamEntry();
    if (testEntry->getMinSize() <= size && testEntry->justifiedContain(loc, size)==0)
      return 1;
    if (testEntry->isExclusion() && testEntry->containedBy(loc, size))
      res = 2;
    ++iterpair.first;
  }
  if (res != 2 && iterpair.first != resolver->end()) {
    iterpair.second = resolver->find_end(loc.getOffset() + (size-1));
    while(iterpair.first != iterpair.second) {
      const ParamEntry *testEntry = (*iterpair.first).getParamEntry();
      if (testEntry->isExclusion() && testEntry->containedBy(loc, size)) {
	res = 2;
	break;
      }
      ++iterpair.first;
    }
  }
  return res;
}

/// Given the next data-type and the status of previously allocated slots,
/// select the storage location for the parameter.  The status array is
/// indexed by \e group: a positive value indicates how many \e slots have been allocated
/// from that group, and a -1 indicates the group/resource is fully consumed.
/// \param tp is the data-type of the next parameter
/// \param status is an array marking how many \e slots have already been consumed in a group
/// \return the newly assigned address for the parameter
Address ParamListStandard::assignAddress(const Datatype *tp,vector<int4> &status) const

{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    const ParamEntry &curEntry( *iter );
    int4 grp = curEntry.getGroup();
    if (status[grp]<0) continue;
    if ((curEntry.getType() != TYPE_UNKNOWN)&&
	tp->getMetatype() != curEntry.getType())
      continue;			// Wrong type

    Address res = curEntry.getAddrBySlot(status[grp],tp->getSize());
    if (res.isInvalid()) continue; // If -tp- doesn't fit an invalid address is returned
    if (curEntry.isExclusion()) {
      int4 maxgrp = grp + curEntry.getGroupSize();
      for(int4 j=grp;j<maxgrp;++j) // For an exclusion entry
	status[j] = -1;		// some number of groups are taken up
    }
    return res;
  }
  return Address();		// Return invalid address to indicated we could not assign anything
}

void ParamListStandard::assignMap(const vector<Datatype *> &proto,bool isinput,TypeFactory &typefactory,
				  vector<ParameterPieces> &res) const

{
  vector<int4> status(numgroup,0);

  if (isinput) {
    if (res.size()==2) { // Check for hidden parameters defined by the output list
      res.back().addr = assignAddress(res.back().type,status); // Reserve first param for hidden ret value
      res.back().flags |= ParameterPieces::hiddenretparm;
      if (res.back().addr.isInvalid())
	throw ParamUnassignedError("Cannot assign parameter address for " + res.back().type->getName());
    }
    for(int4 i=1;i<proto.size();++i) {
      res.emplace_back();
      if ((pointermax != 0)&&(proto[i]->getSize() > pointermax)) { // Datatype is too big
	// Assume datatype is stored elsewhere and only the pointer is passed
	AddrSpace *spc = spacebase;
	if (spc == (AddrSpace *)0)
	  spc = typefactory.getArch()->getDefaultDataSpace();
	int4 pointersize = spc->getAddrSize();
	int4 wordsize = spc->getWordSize();
	Datatype *pointertp = typefactory.getTypePointer(pointersize,proto[i],wordsize);
	res.back().addr = assignAddress(pointertp,status);
	res.back().type = pointertp;
	res.back().flags = ParameterPieces::indirectstorage;
      }
      else
	res.back().addr = assignAddress(proto[i],status);
      if (res.back().addr.isInvalid())
	throw ParamUnassignedError("Cannot assign parameter address for " + proto[i]->getName());
      res.back().type = proto[i];
      res.back().flags = 0;
    }
  }
  else {
    res.emplace_back();
    if (proto[0]->getMetatype() != TYPE_VOID) {
      res.back().addr = assignAddress(proto[0],status);
      if (res.back().addr.isInvalid())
	throw ParamUnassignedError("Cannot assign parameter address for " + proto[0]->getName());
    }
    res.back().type = proto[0];
    res.back().flags = 0;
  }
}

/// Given a set of \b trials (putative Varnode parameters) as ParamTrial objects,
/// associate each trial with a model ParamEntry within \b this list. Trials for
/// for which there are no matching entries are marked as unused. Any holes
/// in the resource list are filled with \e unreferenced trials. The trial list is sorted.
/// \param active is the set of \b trials to map and organize
void ParamListStandard::buildTrialMap(ParamActive *active) const

{
  vector<const ParamEntry *> hitlist; // List of groups for which we have a representative
  bool seenfloattrial = false;
  bool seeninttrial = false;

  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &paramtrial(active->getTrial(i));
    const ParamEntry *entrySlot = findEntry(paramtrial.getAddress(),paramtrial.getSize());
    // Note: if a trial is "definitely not used" but there is a matching entry,
    // we still include it in the map
    if (entrySlot == (const ParamEntry *)0)
      paramtrial.markNoUse();
    else {
      paramtrial.setEntry( entrySlot, 0 ); // Keep track of entry recovered for this trial

      if (entrySlot->getType() == TYPE_FLOAT)
	seenfloattrial = true;
      else
	seeninttrial = true;

      // Make sure we list that the entries group is marked
      int4 grp = entrySlot->getGroup();
      while(hitlist.size() <= grp)
	hitlist.push_back((const ParamEntry *)0);
      const ParamEntry *lastentry = hitlist[grp];
      if (lastentry == (const ParamEntry *)0)
	hitlist[grp] = entrySlot; // This is the first hit for this group
    }
  }

  // Created unreferenced (unref) ParamTrial for any group that we don't have a representive for
  // if that group occurs before one where we do have a representative

  for(int4 i=0;i<hitlist.size();++i) {
    const ParamEntry *curentry = hitlist[i];
    
    if (curentry == (const ParamEntry *)0) {
      list<ParamEntry>::const_iterator iter;
      for(iter=entry.begin();iter!=entry.end();++iter) {
	curentry = &(*iter);
	if (curentry->getGroup() == i) break; // Find first entry of the missing group
      }
      if ((!seenfloattrial)&&(curentry->getType()==TYPE_FLOAT))
	continue;		// Don't fill in unreferenced floats if we haven't seen any floats
      if ((!seeninttrial)&&(curentry->getType()!=TYPE_FLOAT))
	continue;		// Don't fill in unreferenced int if all we have seen is floats
      int4 sz = curentry->isExclusion() ? curentry->getSize() : curentry->getAlign();
      int4 nextslot = 0;
      Address addr = curentry->getAddrBySlot(nextslot,sz);
      int4 trialpos = active->getNumTrials();
      active->registerTrial(addr,sz);
      ParamTrial &paramtrial(active->getTrial(trialpos));
      paramtrial.markUnref();
      paramtrial.setEntry(curentry,0);
    }
    else if (!curentry->isExclusion()) {
      // For non-exclusion groups, we need to create a secondary hitlist to find holes within the group
      vector<int4> slotlist;
      for(int4 j=0;j<active->getNumTrials();++j) {
	ParamTrial &paramtrial(active->getTrial(j));
	if (paramtrial.getEntry() != curentry) continue;
	int4 slot = curentry->getSlot(paramtrial.getAddress(),0) - curentry->getGroup();
	int4 endslot = curentry->getSlot(paramtrial.getAddress(),paramtrial.getSize()-1) - curentry->getGroup();
	if (endslot < slot) {	// With reverse stacks, the ending address may be in an earlier slot
	  int4 tmp = slot;
	  slot = endslot;
	  endslot = tmp;
	}
	
	while(slotlist.size() <= endslot)
	  slotlist.push_back(0);
	while(slot<=endslot) {
	  slotlist[slot] = 1;
	  slot += 1;
	}
      }
      for(int4 j=0;j<slotlist.size();++j) {
	if (slotlist[j] == 0) {
	  int4 nextslot = j;	// Make copy of j, so that getAddrBySlot can change it
	  Address addr = curentry->getAddrBySlot(nextslot,curentry->getAlign());
	  int4 trialpos = active->getNumTrials();
	  active->registerTrial(addr,curentry->getAlign());
	  ParamTrial &paramtrial(active->getTrial(trialpos));
	  paramtrial.markUnref();
	  paramtrial.setEntry(curentry,0);
	}
      }
    }
  }
  active->sortTrials();
}

/// \brief Calculate the range of floating-point entries within a given set of parameter \e trials
///
/// The trials must already be mapped, which should put floating-point entries first.
/// This method calculates the range of floating-point entries and the range of general purpose
/// entries and passes them back.
/// \param active is the given set of parameter trials
/// \param floatstart will pass back the index of the first floating-point trial
/// \param floatstop will pass back the index (+1) of the last floating-point trial
/// \param start will pass back the index of the first general purpose trial
/// \param stop will pass back the index (+1) of the last general purpose trial
void ParamListStandard::separateFloat(ParamActive *active,int4 &floatstart,int4 &floatstop,int4 &start,int4 &stop) const

{
  int4 numtrials = active->getNumTrials();
  int4 i=0;
  for(;i<numtrials;++i) {
    ParamTrial &curtrial(active->getTrial(i));
    if (curtrial.getEntry()==(const ParamEntry *)0) continue;
    if (curtrial.getEntry()->getType()!=TYPE_FLOAT) break;
  }
  floatstart = 0;
  floatstop = i;
  start = i;
  stop = numtrials;
}

/// \brief Enforce exclusion rules for the given set of parameter trials
///
/// If there are more than one active trials in a single group,
/// and if that group is an exclusion group, mark all but the first trial to \e inactive.
/// \param active is the set of trials
void ParamListStandard::forceExclusionGroup(ParamActive *active) const

{
  int4 curupper = -1;
  bool exclusion = false;
  int4 numtrials = active->getNumTrials();
  for(int4 i=0;i<numtrials;++i) {
    ParamTrial &curtrial(active->getTrial(i));
    if (curtrial.isActive()) {
      int4 grp = curtrial.getEntry()->getGroup();
      exclusion = curtrial.getEntry()->isExclusion();
      if (grp <= curupper) {	// If curtrial's group falls below highest group where we have seen an active
	if (exclusion)
	  curtrial.markInactive(); // mark inactive if it is an exclusion group
      }
      else
	curupper = grp + curtrial.getEntry()->getGroupSize() - 1; // This entry covers some number of groups
    }
  }
}

/// \brief Mark every trial above the first "definitely not used" as \e inactive.
///
/// Inspection and marking only occurs within an indicated range of trials,
/// allowing floating-point and general purpose resources to be treated separately.
/// \param active is the set of trials, which must already be ordered
/// \param start is the index of the first trial in the range to consider
/// \param stop is the index (+1) of the last trial in the range to consider
void ParamListStandard::forceNoUse(ParamActive *active, int4 start, int4 stop) const

{
  bool seendefnouse = false;
  int4 curgroup = -1;
  bool exclusion = false;
  bool alldefnouse = false;
  for (int4 i = start; i < stop; ++i) {
    ParamTrial &curtrial(active->getTrial(i));
    if (curtrial.getEntry() == (const ParamEntry *) 0)
      continue;	// Already marked as not used
    int4 grp = curtrial.getEntry()->getGroup();
    exclusion = curtrial.getEntry()->isExclusion();
    if ((grp <= curgroup) && exclusion) {// If in the same exclusion group
      if (!curtrial.isDefinitelyNotUsed()) // A single element that might be used
	alldefnouse = false; // means that the whole group might be used
    }
    else { // First trial in a new group (or next element in same non-exclusion group)
      if (alldefnouse)	   // If all in the last group were defnotused
	seendefnouse = true;// then force everything afterword to be defnotused
      alldefnouse = curtrial.isDefinitelyNotUsed();
      curgroup = grp + curtrial.getEntry()->getGroupSize() - 1;
    }
    if (seendefnouse)
      curtrial.markInactive();
  }
}

/// \brief Enforce rules about chains of inactive slots.
///
/// If there is a chain of slots whose length is greater than \b maxchain,
/// where all trials are \e inactive, mark trials in any later slot as \e inactive.
/// Mark any \e inactive trials before this (that aren't in a maximal chain)
/// as active.  Inspection and marking is restricted to a given range of trials
/// to facilitate separate analysis of floating-point and general-purpose resources.
/// \param active is the set of trials, which must be sorted
/// \param maxchain is the maximum number of \e inactive trials to allow in a chain
/// \param start is the first index in the range of trials to consider
/// \param stop is the last index (+1) in the range of trials to consider
void ParamListStandard::forceInactiveChain(ParamActive *active,int4 maxchain,int4 start,int4 stop) const

{
  bool seenchain = false;
  int4 chainlength = 0;
  int4 max = -1;
  for(int4 i=start;i<stop;++i) {
    ParamTrial &trial(active->getTrial(i));
    if (trial.getEntry() == (const ParamEntry *)0) continue; // Already know not used
    if (!trial.isActive()) {
      if (trial.isUnref()&&active->isRecoverSubcall()) {
	// If there is no reference to the trial within the function, the only real possibility
	// is that a register is an input to the calling function and it is being reused (immediately)
	// to pass the input into the called function.  This really can't happen on the stack because
	// the stack relative caller offset and callee offset are different
	if (trial.getAddress().getSpace()->getType() == IPTR_SPACEBASE) // So if the parameter is on the stack
	  seenchain = true;	// Mark that we have already seen an inactive chain
      }
      if (i==start) {
	if (trial.getEntry()->getType() == TYPE_FLOAT)
	  chainlength += (active->getTrial(0).slotGroup()+1);
	else
	  chainlength += (trial.slotGroup() - nonfloatgroup + 1);
      }
      else
	chainlength += trial.slotGroup() - active->getTrial(i-1).slotGroup();
      if (chainlength > maxchain)
	seenchain = true;
    }
    else {
      chainlength = 0;
      if (!seenchain)
	max = i;
    }
    if (seenchain)
      trial.markInactive();
  }
  for(int4 i=start;i<=max;++i) { // Across the range of active trials, fill in "holes" of inactive trials
    ParamTrial &trial(active->getTrial(i));
    if (trial.isDefinitelyNotUsed()) continue;
    if (!trial.isActive())
      trial.markActive();
  }
}

void ParamListStandard::calcDelay(void)

{
  maxdelay = 0;
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    int4 delay = (*iter).getSpace()->getDelay();
    if (delay > maxdelay)
      maxdelay = delay;
  }
}

/// Enter all the ParamEntry objects into an interval map (based on address space)
void ParamListStandard::populateResolver(void)

{
  int4 maxid = -1;
  list<ParamEntry>::iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    int4 id = (*iter).getSpace()->getIndex();
    if (id > maxid)
      maxid = id;
  }
  resolverMap.resize(maxid+1, (ParamEntryResolver *)0);
  int4 position = 0;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    ParamEntry *paramEntry = &(*iter);
    int4 spaceId = paramEntry->getSpace()->getIndex();
    ParamEntryResolver *resolver = resolverMap[spaceId];
    if (resolver == (ParamEntryResolver *)0) {
      resolver = new ParamEntryResolver();
      resolverMap[spaceId] = resolver;
    }
    uintb first = paramEntry->getBase();
    uintb last = first + (paramEntry->getSize() - 1);
    ParamEntryResolver::inittype initData(position,paramEntry);
    position += 1;
    resolver->insert(initData,first,last);
  }
}

void ParamListStandard::fillinMap(ParamActive *active) const

{
  if (active->getNumTrials() == 0) return; // No trials to check

  buildTrialMap(active); // Associate varnodes with sorted list of parameter locations

  forceExclusionGroup(active);
  int4 floatstart,floatstop,start,stop;
  separateFloat(active,floatstart,floatstop,start,stop);
  forceNoUse(active,floatstart,floatstop);
  forceNoUse(active,start,stop);	    // Definitely not used -- overrides active
  forceInactiveChain(active,2,floatstart,floatstop);	// Chains of inactivity override later actives
  forceInactiveChain(active,2,start,stop);

  // Mark every active trial as used
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &paramtrial(active->getTrial(i));
    if (paramtrial.isActive())
      paramtrial.markUsed();
  }
}

bool ParamListStandard::checkJoin(const Address &hiaddr,int4 hisize,const Address &loaddr,int4 losize) const

{
  const ParamEntry *entryHi = findEntry(hiaddr,hisize);
  if (entryHi == (const ParamEntry *)0) return false;
  const ParamEntry *entryLo = findEntry(loaddr,losize);
  if (entryLo == (const ParamEntry *)0) return false;
  if (entryHi->getGroup() == entryLo->getGroup()) {
    if (entryHi->isExclusion()||entryLo->isExclusion()) return false;
    if (!hiaddr.isContiguous(hisize,loaddr,losize)) return false;
    if (((hiaddr.getOffset() - entryHi->getBase()) % entryHi->getAlign()) != 0) return false;
    if (((loaddr.getOffset() - entryLo->getBase()) % entryLo->getAlign()) != 0) return false;
    return true;
  }
  else {
    int4 sizesum = hisize + losize;
    list<ParamEntry>::const_iterator iter;
    for(iter=entry.begin();iter!=entry.end();++iter) {
      if ((*iter).getSize() < sizesum) continue;
      if ((*iter).justifiedContain(loaddr,losize)!=0) continue;
      if ((*iter).justifiedContain(hiaddr,hisize)!=losize) continue;
      return true;
    }
  }
  return false;
}

bool ParamListStandard::checkSplit(const Address &loc,int4 size,int4 splitpoint) const

{
  Address loc2 = loc + splitpoint;
  int4 size2 = size - splitpoint;
  const ParamEntry *entryNum = findEntry(loc,splitpoint);
  if (entryNum == (const ParamEntry *)0) return false;
  entryNum = findEntry(loc2,size2);
  if (entryNum == (const ParamEntry *)0) return false;
  return true;
}

bool ParamListStandard::possibleParam(const Address &loc,int4 size) const

{
  return ((const ParamEntry *)0 != findEntry(loc,size));
}

bool ParamListStandard::possibleParamWithSlot(const Address &loc,int4 size,int4 &slot,int4 &slotsize) const

{
  const ParamEntry *entryNum = findEntry(loc,size);
  if (entryNum == (const ParamEntry *)0) return false;
  slot = entryNum->getSlot(loc,0);
  if (entryNum->isExclusion()) {
    slotsize = entryNum->getGroupSize();
  }
  else {
    slotsize = ((size-1) / entryNum->getAlign()) + 1;
  }
  return true;
}

bool ParamListStandard::getBiggestContainedParam(const Address &loc,int4 size,VarnodeData &res) const

{
  int4 index = loc.getSpace()->getIndex();
  if (index >= resolverMap.size())
    return false;
  ParamEntryResolver *resolver = resolverMap[index];
  if (resolver == (ParamEntryResolver *)0)
    return false;
  Address endLoc = loc + (size-1);
  if (endLoc.getOffset() < loc.getOffset())
    return false;	// Assume there is no parameter if we see wrapping
  const ParamEntry *maxEntry = (const ParamEntry *)0;
  ParamEntryResolver::const_iterator iter = resolver->find_begin(loc.getOffset());
  ParamEntryResolver::const_iterator enditer = resolver->find_end(endLoc.getOffset());
  while(iter != enditer) {
    const ParamEntry *testEntry = (*iter).getParamEntry();
    ++iter;
    if (testEntry->containedBy(loc, size)) {
      if (maxEntry == (const ParamEntry *)0)
	maxEntry = testEntry;
      else if (testEntry->getSize() > maxEntry->getSize())
	maxEntry = testEntry;
    }
  }
  if (maxEntry != (const ParamEntry *)0) {
    if (!maxEntry->isExclusion())
      return false;
    res.space = maxEntry->getSpace();
    res.offset = maxEntry->getBase();
    res.size = maxEntry->getSize();
    return true;
  }
  return false;
}

bool ParamListStandard::unjustifiedContainer(const Address &loc,int4 size,VarnodeData &res) const

{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    if ((*iter).getMinSize() > size) continue;
    int4 just = (*iter).justifiedContain(loc,size);
    if (just < 0) continue;
    if (just == 0) return false;
    (*iter).getContainer(loc,size,res);
    return true;
  }
  return false;
}

OpCode ParamListStandard::assumedExtension(const Address &addr,int4 size,VarnodeData &res) const

{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    if ((*iter).getMinSize() > size) continue;
    OpCode ext = (*iter).assumedExtension(addr,size,res);
    if (ext != CPUI_COPY)
      return ext;
  }
  return CPUI_COPY;
}

void ParamListStandard::getRangeList(AddrSpace *spc,RangeList &res) const

{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    if ((*iter).getSpace() != spc) continue;
    uintb baseoff = (*iter).getBase();
    uintb endoff = baseoff + (*iter).getSize() - 1;
    res.insertRange(spc,baseoff,endoff);
  }
}

void ParamListStandard::restoreXml(const Element *el,const AddrSpaceManager *manage,
				   vector<EffectRecord> &effectlist,bool normalstack)

{
  int4 lastgroup = -1;
  numgroup = 0;
  spacebase = (AddrSpace *)0;
  pointermax = 0;
  thisbeforeret = false;
  bool autokilledbycall = false;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    const string &attrname( el->getAttributeName(i) );
    if (attrname == "pointermax") {
      istringstream i1(el->getAttributeValue(i));
      i1.unsetf(ios::dec | ios::hex | ios::oct);
      i1 >> pointermax;
    }
    else if (attrname == "thisbeforeretpointer") {
      thisbeforeret = xml_readbool( el->getAttributeValue(i) );
    }
    else if (attrname == "killedbycall") {
      autokilledbycall = xml_readbool( el->getAttributeValue(i) );
    }
  }
  nonfloatgroup = -1;		// We haven't seen any integer slots yet
  const List &flist(el->getChildren());
  List::const_iterator fiter;
  for(fiter=flist.begin();fiter!=flist.end();++fiter) {
    const Element *subel = *fiter;
    if (subel->getName() == "pentry") {
      entry.emplace_back(numgroup);
      entry.back().restoreXml(subel,manage,normalstack);
      if (entry.back().getType()==TYPE_FLOAT) {
	  if (nonfloatgroup >= 0)
	    throw LowlevelError("parameter list floating-point entries must come first");
      }
      else if (nonfloatgroup < 0)
	nonfloatgroup = numgroup; // First time we have seen an integer slot
      AddrSpace *spc = entry.back().getSpace();
      if (spc->getType() == IPTR_SPACEBASE)
	spacebase = spc;
      else if (autokilledbycall)	// If a register parameter AND we automatically generate killedbycall
	effectlist.push_back(EffectRecord(entry.back(),EffectRecord::killedbycall));

      int4 maxgroup = entry.back().getGroup() + entry.back().getGroupSize();
      if (maxgroup > numgroup)
	numgroup = maxgroup;
      if (entry.back().getGroup() < lastgroup)
	throw LowlevelError("pentrys must come in group order");
      lastgroup = entry.back().getGroup();
    }
  }
  calcDelay();
  populateResolver();
}

ParamList *ParamListStandard::clone(void) const

{
  ParamList *res = new ParamListStandard(*this);
  return res;
}

void ParamListStandardOut::assignMap(const vector<Datatype *> &proto,bool isinput,
				     TypeFactory &typefactory,vector<ParameterPieces> &res) const
{
  vector<int4> status(numgroup,0);

  // This is always an output list so we ignore -isinput-
  res.emplace_back();
  res.back().type = proto[0];
  res.back().flags = 0;
  if (proto[0]->getMetatype() == TYPE_VOID) {
    return;			// Leave the address as invalid
  }
  res.back().addr = assignAddress(proto[0],status);
  if (res.back().addr.isInvalid()) { // Could not assign an address (too big)
    AddrSpace *spc = spacebase;
    if (spc == (AddrSpace *)0)
      spc = typefactory.getArch()->getDefaultDataSpace();
    int4 pointersize = spc->getAddrSize();
    int4 wordsize = spc->getWordSize();
    Datatype *pointertp = typefactory.getTypePointer(pointersize, proto[0], wordsize);
    res.back().addr = assignAddress(pointertp,status);
    if (res.back().addr.isInvalid())
      throw ParamUnassignedError("Cannot assign return value as a pointer");
    res.back().type = pointertp;
    res.back().flags = ParameterPieces::indirectstorage;

    res.emplace_back();			// Add extra storage location in the input params
    res.back().type = pointertp;	// that holds a pointer to where the return value should be stored
    // leave its address invalid, to be filled in by the input list assignMap
    res.back().flags = ParameterPieces::hiddenretparm; // Mark it as special
  }
}

void ParamListStandardOut::fillinMap(ParamActive *active) const

{
  if (active->getNumTrials() == 0) return; // No trials to check
  const ParamEntry *bestentry = (const ParamEntry *)0;
  int4 bestcover = 0;
  type_metatype bestmetatype = TYPE_PTR;

  // Find entry which is best covered by the active trials
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    const ParamEntry *curentry = &(*iter);
    bool putativematch = false;
    for(int4 j=0;j<active->getNumTrials();++j) { // Evaluate all trials in terms of current ParamEntry
      ParamTrial &paramtrial(active->getTrial(j));
      if (paramtrial.isActive()) {
	int4 res = curentry->justifiedContain(paramtrial.getAddress(),paramtrial.getSize());
	if (res >= 0) {
	  paramtrial.setEntry(curentry,res);
	  putativematch = true;
	}
	else
	  paramtrial.setEntry((const ParamEntry *)0,0);
      }
      else
	paramtrial.setEntry((const ParamEntry *)0,0);
    }
    if (!putativematch) continue;
    active->sortTrials();
    // Calculate number of least justified, contiguous, bytes for this entry
    int4 offmatch = 0;
    int4 k;
    for(k=0;k<active->getNumTrials();++k) {
      ParamTrial &paramtrial(active->getTrial(k));
      if (paramtrial.getEntry() == (const ParamEntry *)0) continue;
      if (offmatch != paramtrial.getOffset()) break;
      if (((offmatch == 0)&&curentry->isParamCheckLow()) ||
	  ((offmatch != 0)&&curentry->isParamCheckHigh())) {	// If this is multi-precision
	// Do extra checks that this portion isn't created normally
	if (paramtrial.isRemFormed()) break; // Formed as a remainder of dual div/rem operation
	if (paramtrial.isIndCreateFormed()) break; // Formed indirectly by call
      }
      offmatch += paramtrial.getSize();
    }
    if (offmatch < curentry->getMinSize()) // If we didn't match enough to cover minimum size
      k = 0;				   // Don't use this entry
    // Prefer a more generic type restriction if we have it
    // prefer the larger coverage
    if ((k==active->getNumTrials())&&((curentry->getType() > bestmetatype)||(offmatch > bestcover))) {
      bestentry = curentry;
      bestcover = offmatch;
      bestmetatype = curentry->getType();
    }
  }
  if (bestentry==(const ParamEntry *)0) {
    for(int4 i=0;i<active->getNumTrials();++i)
      active->getTrial(i).markNoUse();
  }
  else {
    for(int4 i=0;i<active->getNumTrials();++i) {
      ParamTrial &paramtrial(active->getTrial(i));
      if (paramtrial.isActive()) {
	int4 res = bestentry->justifiedContain(paramtrial.getAddress(),paramtrial.getSize());
	if (res >= 0) {
	  paramtrial.markUsed(); // Only actives are ever marked used
	  paramtrial.setEntry(bestentry,res);
	}
	else {
	  paramtrial.markNoUse();
	  paramtrial.setEntry((const ParamEntry *)0,0);
	}
      }
      else {
	paramtrial.markNoUse();
	paramtrial.setEntry((const ParamEntry *)0,0);
      }
    }
    active->sortTrials();
  }
}

bool ParamListStandardOut::possibleParam(const Address &loc,int4 size) const

{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    if ((*iter).justifiedContain(loc,size)>=0)
      return true;
  }
  return false;
}

void ParamListStandardOut::restoreXml(const Element *el,const AddrSpaceManager *manage,vector<EffectRecord> &effectlist,bool normalstack)

{
  ParamListStandard::restoreXml(el,manage,effectlist,normalstack);
  // Check for double precision entries
  list<ParamEntry>::iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter)
    (*iter).extraChecks(entry);
}

ParamList *ParamListStandardOut::clone(void) const

{
  ParamList *res = new ParamListStandardOut(*this);
  return res;
}

void ParamListRegister::fillinMap(ParamActive *active) const

{
  if (active->getNumTrials() == 0) return; // No trials to check

  // Mark anything active as used
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &paramtrial(active->getTrial(i));
    const ParamEntry *entrySlot = findEntry(paramtrial.getAddress(),paramtrial.getSize());
    if (entrySlot == (const ParamEntry *)0)	// There may be no matching entry (if the model was recovered late)
      paramtrial.markNoUse();
    else {
      paramtrial.setEntry( entrySlot,0 ); // Keep track of entry recovered for this trial
      if (paramtrial.isActive())
	paramtrial.markUsed();
    }
  }
  active->sortTrials();
}

ParamList *ParamListRegister::clone(void) const

{
  ParamList *res = new ParamListRegister( *this );
  return res;
}

/// The given set of parameter entries are folded into \b this set.
/// Duplicate entries are eliminated. Containing entries subsume what
/// they contain.
/// \param op2 is the list model to fold into \b this
void ParamListMerged::foldIn(const ParamListStandard &op2)

{
  if (entry.empty()) {
    spacebase = op2.getSpacebase();
    entry = op2.getEntry();
    return;
  }
  if ((spacebase != op2.getSpacebase())&&(op2.getSpacebase() != (AddrSpace *)0))
    throw LowlevelError("Cannot merge prototype models with different stacks");

  list<ParamEntry>::const_iterator iter2;
  for(iter2=op2.getEntry().begin();iter2!=op2.getEntry().end();++iter2) {
    const ParamEntry &opentry( *iter2 );
    int4 typeint = 0;
    list<ParamEntry>::iterator iter;
    for(iter=entry.begin();iter!=entry.end();++iter) {
      if ((*iter).contains(opentry)) {
	typeint = 2;
	break;
      }
      if (opentry.contains( *iter )) {
	typeint = 1;
	break;
      }
    }
    if (typeint==2) {
      if ((*iter).getMinSize() != opentry.getMinSize())
	typeint = 0;
    }
    else if (typeint == 1) {
      if ((*iter).getMinSize() != opentry.getMinSize())
	typeint = 0;
      else
	*iter = opentry;	// Replace with the containing entry
    }
    if (typeint == 0)
      entry.push_back(opentry);
  }
}

ParamList *ParamListMerged::clone(void) const

{
  ParamList *res = new ParamListMerged(*this);
  return res;
}

/// Create a new ParamTrial based on the first bytes of the memory range.
/// \param sz is the number of bytes to include in the new trial
/// \return the new trial
ParamTrial ParamTrial::splitHi(int4 sz) const

{
  ParamTrial res(addr,sz,slot);
  res.flags = flags;
  return res;
}

/// Create a new ParamTrial based on the last bytes of the memory range.
/// \param sz is the number of bytes to include in the new trial
/// \return the new trial
ParamTrial ParamTrial::splitLo(int4 sz) const

{
  Address newaddr = addr + (size-sz);
  ParamTrial res(newaddr,sz,slot+1);
  res.flags = flags;
  return res;
}

/// A new address and size for the memory range is given, which
/// must respect the endianness of the putative parameter and
/// any existing match with the PrototypeModel
/// \param newaddr is the new address
/// \param sz is the new size
/// \return true if the trial can be shrunk to the new range
bool ParamTrial::testShrink(const Address &newaddr,int4 sz) const

{
  Address testaddr;
  if (addr.isBigEndian())
    testaddr = addr + (size - sz);
  else
    testaddr = addr;
  if (testaddr != newaddr)
    return false;
  if (entry != (const ParamEntry *)0) return false;
  //  if (entry != (const ParamEntry *)0) {
  //    int4 res = entry->justifiedContain(newaddr,sz);
  //    if (res < 0) return false;
  //  }
  return true;
}

/// Trials are sorted primarily by the \e group index assigned by the PrototypeModel.
/// Trials within the same group are sorted in address order (or its reverse)
/// \param b is the other trial to compare with \b this
/// \return \b true if \b this should be ordered before the other trial
bool ParamTrial::operator<(const ParamTrial &b) const

{
  if (entry == (const ParamEntry *)0) return false;
  if (b.entry == (const ParamEntry *)0) return true;
  int4 grpa = entry->getGroup();
  int4 grpb = b.entry->getGroup();
  if (grpa != grpb)
    return (grpa < grpb);
  if (entry != b.entry)		// Compare entry pointers directly
    return (entry < b.entry);
  if (entry->isExclusion()) {
    return (offset < b.offset);
  }
  if (addr != b.addr) {
    if (entry->isReverseStack())
      return (b.addr < addr);
    else
      return (addr < b.addr);
  }
  return (size < b.size);
}

/// \param recoversub selects whether a sub-function or the active function is being tested
ParamActive::ParamActive(bool recoversub)

{
  slotbase = 1;
  stackplaceholder = -1;
  numpasses = 0;
  maxpass = 0;
  isfullychecked = false;
  needsfinalcheck = false;
  recoversubcall = recoversub;
}

void ParamActive::clear(void)

{
  trial.clear();
  slotbase = 1;
  stackplaceholder = -1;
  numpasses = 0;
  isfullychecked = false;
}

/// A ParamTrial object is created and a slot is assigned.
/// \param addr is the starting address of the memory range
/// \param sz is the number of bytes in the range
void ParamActive::registerTrial(const Address &addr,int4 sz)

{
  trial.push_back(ParamTrial(addr,sz,slotbase));
  // It would require too much work to calculate whether a specific data location is changed
  // by a subfunction, but a fairly strong assumption is that (unless it is explicitly saved) a
  // register may change and is thus unlikely to be used as a location for passing parameters.
  // However stack locations saving a parameter across a function call is a common construction
  // Since this all a heuristic for recovering parameters, we assume this rule is always true
  // to get an efficient test
  if (addr.getSpace()->getType() != IPTR_SPACEBASE)
    trial.back().markKilledByCall();
  slotbase += 1;
}

/// The (index of) the first overlapping trial is returned.
/// \param addr is the starting address of the given range
/// \param sz is the number of bytes in the range
/// \return the index of the overlapping trial, or -1 if no trial overlaps
int4 ParamActive::whichTrial(const Address &addr,int4 sz) const

{
  for(int4 i=0;i<trial.size();++i) {
    if (addr.overlap(0,trial[i].getAddress(),trial[i].getSize())>=0) return i;
    if (sz<=1) return -1;
    Address endaddr = addr + (sz-1);
    if (endaddr.overlap(0,trial[i].getAddress(),trial[i].getSize())>=0) return i;
  }
  return -1;
}

/// Free up the stack placeholder slot, which may cause trial slots to get adjusted
void ParamActive::freePlaceholderSlot(void)

{
  for(int4 i=0;i<trial.size();++i) {
    if (trial[i].getSlot() > stackplaceholder)
      trial[i].setSlot(trial[i].getSlot() - 1);
  }
  stackplaceholder = -2;
  slotbase -= 1;
				// If we've found the placeholder, then the -next- time we
                                // analyze parameters, we will have given all locations the
                                // chance to show up, so we prevent any analysis after -next-
  maxpass = 0;
}

/// Delete any trial for which isUsed() returns \b false.
/// This is used in conjunction with setting the active Varnodes on a call, so the slot number is
/// reordered too.
void ParamActive::deleteUnusedTrials(void)

{
  vector<ParamTrial> newtrials;
  int4 slot = 1;
  
  for(int4 i=0;i<trial.size();++i) {
    ParamTrial &curtrial(trial[i]);
    if (curtrial.isUsed()) {
      curtrial.setSlot(slot);
      slot += 1;
      newtrials.push_back(curtrial);
    }
  }
  trial = newtrials;
}

/// Split the trial into two trials, where the first piece has the given size.
/// \param i is the index of the given trial
/// \param sz is the given size
void ParamActive::splitTrial(int4 i,int4 sz)

{
  if (stackplaceholder >= 0)
    throw LowlevelError("Cannot split parameter when the placeholder has not been recovered");
  vector<ParamTrial> newtrials;
  int4 slot = trial[i].getSlot();
  
  for(int4 j=0;j<i;++j) {
    newtrials.push_back(trial[j]);
    int4 oldslot = newtrials.back().getSlot();
    if (oldslot > slot)
      newtrials.back().setSlot(oldslot+1);
  }
  newtrials.push_back(trial[i].splitHi(sz));
  newtrials.push_back(trial[i].splitLo(trial[i].getSize()-sz));
  for(int4 j=i+1;j<trial.size();++j) {
    newtrials.push_back(trial[j]);
    int4 oldslot = newtrials.back().getSlot();
    if (oldslot > slot)
      newtrials.back().setSlot(oldslot+1);
  }
  slotbase += 1;
  trial = newtrials;
}

/// Join the trial at the given slot with the trial in the next slot
/// \param slot is the given slot
/// \param addr is the address of the new joined memory range
/// \param sz is the size of the new memory range
void ParamActive::joinTrial(int4 slot,const Address &addr,int4 sz)

{
  if (stackplaceholder >= 0)
    throw LowlevelError("Cannot join parameters when the placeholder has not been removed");
  vector<ParamTrial> newtrials;
  int4 sizecheck = 0;
  for(int4 i=0;i<trial.size();++i) {
    ParamTrial &curtrial( trial[i] );
    int4 curslot = curtrial.getSlot();
    if (curslot < slot)
      newtrials.push_back(curtrial);
    else if (curslot == slot) {
      sizecheck += curtrial.getSize();
      newtrials.push_back(ParamTrial(addr,sz,slot));
      newtrials.back().markUsed();
      newtrials.back().markActive();
    }
    else if (curslot == slot + 1) { // this slot is thrown out
      sizecheck += curtrial.getSize();
    }
    else {
      newtrials.push_back(curtrial);
      newtrials.back().setSlot(curslot-1);
    }
  }
  if (sizecheck != sz)
    throw LowlevelError("Size mismatch when joining parameters");
  slotbase -= 1;
  trial = newtrials;
}

/// This assumes the trials have been sorted. So \e used trials are first.
/// \return the number of formally used trials
int4 ParamActive::getNumUsed(void) const

{
  int4 count;
  for(count=0;count<trial.size();++count) {
    if (!trial[count].isUsed()) break;
  }
  return count;
}

/// Constructor for the \b fspec space.
/// There is only one such space, and it is considered
/// internal to the model, i.e. the Translate engine should never
/// generate addresses in this space.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param nm is the name of the space (always \b fspec)
/// \param ind is the index associated with the space
FspecSpace::FspecSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind)
  : AddrSpace(m,t,IPTR_FSPEC,nm,sizeof(void *),1,ind,0,1)
{
  clearFlags(heritaged|does_deadcode|big_endian);
  if (HOST_ENDIAN==1)		// Endianness always set by host
    setFlags(big_endian);
}

void FspecSpace::saveXmlAttributes(ostream &s,uintb offset) const

{
  FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset;

  if (fc->getEntryAddress().isInvalid())
    s << " space=\"fspec\"";
  else {
    AddrSpace *id = fc->getEntryAddress().getSpace();
    a_v(s,"space",id->getName()); // Just append the proper attributes
    s << ' ' << "offset=\"";
    printOffset(s,fc->getEntryAddress().getOffset());
    s << "\"";
  }
}

void FspecSpace::saveXmlAttributes(ostream &s,uintb offset,int4 size) const

{
  FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset;

  if (fc->getEntryAddress().isInvalid())
    s << " space=\"fspec\"";
  else {
    AddrSpace *id = fc->getEntryAddress().getSpace();
    a_v(s,"space",id->getName()); // Just append the proper attributes
    s << ' ' << "offset=\"";
    printOffset(s,fc->getEntryAddress().getOffset());
    s << "\"";
    a_v_i(s,"size",size);
  }
}

void FspecSpace::printRaw(ostream &s,uintb offset) const

{
  FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset;

  if (fc->getName().size() != 0)
    s << fc->getName();
  else {
    s << "func_";
    fc->getEntryAddress().printRaw(s);
  }
}

void FspecSpace::saveXml(ostream &s) const

{
  throw LowlevelError("Should never save fspec space to XML");
}

void FspecSpace::restoreXml(const Element *el)

{
  throw LowlevelError("Should never restore fspec space from XML");
}

/// The type is set to \e unknown_effect
/// \param addr is the start of the memory range
/// \param size is the number of bytes in the memory range
EffectRecord::EffectRecord(const Address &addr,int4 size)

{
  address.space = addr.getSpace();
  address.offset = addr.getOffset();
  address.size = size;
  type = unknown_effect;
}

/// \param entry is a model of the parameter storage
/// \param t is the effect type
EffectRecord::EffectRecord(const ParamEntry &entry,uint4 t)

{
  address.space = entry.getSpace();
  address.offset = entry.getBase();
  address.size = entry.getSize();
  type = t;
}

/// \param data is the memory range affected
/// \param t is the effect type
EffectRecord::EffectRecord(const VarnodeData &data,uint4 t)

{
  address = data;
  type = t;
}

/// Writes just an \<addr> tag.  The effect type is indicated by the parent tag.
/// \param s is the output stream
void EffectRecord::saveXml(ostream &s) const

{
  Address addr(address.space,address.offset);
  if ((type == unaffected)||(type == killedbycall)||(type == return_address))
    addr.saveXml(s,address.size);
  else
    throw LowlevelError("Bad EffectRecord type");
}

/// Reads an \<addr> tag to get the memory range. The effect type is inherited from the parent.
/// \param grouptype is the effect inherited from the parent
/// \param el is address element
/// \param manage is a manager to resolve address space references
void EffectRecord::restoreXml(uint4 grouptype,const Element *el,const AddrSpaceManager *manage)

{
  type = grouptype;
  address.restoreXml(el,manage);
}

void ProtoModel::defaultLocalRange(void)

{
  AddrSpace *spc = glb->getStackSpace();
  uintb first,last;

  if (stackgrowsnegative) {	// This the normal stack convention
    // Default locals are negative offsets off the stack
    last = spc->getHighest();
    if (spc->getAddrSize()>=4)
      first = last - 999999;
    else if (spc->getAddrSize()>=2)
      first = last - 9999;
    else
      first = last - 99;
    localrange.insertRange(spc,first,last);
  }
  else {			// This is the flipped stack convention
    first = 0;
    if (spc->getAddrSize()>=4)
      last = 999999;
    else if (spc->getAddrSize()>=2)
      last = 9999;
    else
      last = 99;
    localrange.insertRange(spc,first,last);
  }
}

void ProtoModel::defaultParamRange(void)

{
  AddrSpace *spc = glb->getStackSpace();
  uintb first,last;

  if (stackgrowsnegative) {	// This the normal stack convention
    // Default parameters are positive offsets off the stack
    first = 0;
    if (spc->getAddrSize()>=4)
      last = 511;
    else if (spc->getAddrSize()>=2)
      last = 255;
    else
      last = 15;
    paramrange.insertRange(spc,first,last);
  }
  else {			// This is the flipped stack convention
    last = spc->getHighest();
    if (spc->getAddrSize()>=4)
      first = last - 511;
    else if (spc->getAddrSize()>=2)
      first = last - 255;
    else
      first = last - 15;
    paramrange.insertRange(spc,first,last); // Parameters are negative offsets
  }
}

/// Generate derived ParamList objects based on a given strategy
/// \param strategy is the resource \e strategy: currently "standard" or "register"
void ProtoModel::buildParamList(const string &strategy)

{
  if ((strategy == "")||(strategy == "standard")) {
    input = new ParamListStandard();
    output = new ParamListStandardOut();
  }
  else if (strategy == "register") {
    input = new ParamListRegister();
    output = new ParamListStandardOut();
  }
  else
    throw LowlevelError("Unknown strategy type: "+strategy);
}

/// \param g is the Architecture that will own the new prototype model
ProtoModel::ProtoModel(Architecture *g)

{
  glb = g;
  input = (ParamList *)0;
  output = (ParamList *)0;
  compatModel = (const ProtoModel *)0;
  extrapop=0;
  injectUponEntry = -1;
  injectUponReturn = -1;
  stackgrowsnegative = true;	// Normal stack parameter ordering
  hasThis = false;
  isConstruct = false;
  defaultLocalRange();
  defaultParamRange();
}

/// Everything is copied from the given prototype model except the name
/// \param nm is the new name for \b this copy
/// \param op2 is the prototype model to copy
ProtoModel::ProtoModel(const string &nm,const ProtoModel &op2)

{
  glb = op2.glb;
  name = nm;
  extrapop = op2.extrapop;
  if (op2.input != (ParamList *)0)
    input = op2.input->clone();
  else
    input = (ParamList *)0;
  if (op2.output != (ParamList *)0)
    output = op2.output->clone();
  else
    output = (ParamList *)0;

  effectlist = op2.effectlist;
  likelytrash = op2.likelytrash;
  
  injectUponEntry = op2.injectUponEntry;
  injectUponReturn = op2.injectUponReturn;
  localrange = op2.localrange;
  paramrange = op2.paramrange;
  stackgrowsnegative = op2.stackgrowsnegative;
  hasThis = op2.hasThis;
  isConstruct = op2.isConstruct;
  if (name == "__thiscall")
    hasThis = true;
  compatModel = &op2;
}

ProtoModel::~ProtoModel(void)

{
  if (input != (ParamList *)0)
    delete input;
  if (output != (ParamList *)0)
    delete output;
}

/// Test whether one ProtoModel can substituted for another during FuncCallSpecs::deindirect
/// Currently this can only happen if one model is a copy of the other except for the
/// hasThis boolean property.
/// \param op2 is the other ProtoModel to compare with \b this
/// \return \b true if the two models are compatible
bool ProtoModel::isCompatible(const ProtoModel *op2) const

{
  if (this == op2 || compatModel == op2 || op2->compatModel == this)
    return true;
  return false;
}

/// \brief Calculate input and output storage locations given a function prototype
///
/// The data-types of the function prototype are passed in as an ordered list, with the
/// first data-type corresponding to the \e return \e value and all remaining
/// data-types corresponding to the input parameters.  Based on \b this model, a storage location
/// is selected for each (input and output) parameter and passed back to the caller.
/// The passed back storage locations are ordered similarly, with the output storage
/// as the first entry.  The model has the option of inserting a \e hidden return value
/// pointer in the input storage locations.
///
/// A \b void return type is indicated by the formal TYPE_VOID in the (either) list.
/// If the model can't map the specific output prototype, the caller has the option of whether
/// an exception (ParamUnassignedError) is thrown.  If they choose not to throw,
/// the unmapped return value is assumed to be \e void.
/// \param typelist is the list of data-types from the function prototype
/// \param res will hold the storage locations for each parameter
/// \param ignoreOutputError is \b true if problems assigning the output parameter are ignored
void ProtoModel::assignParameterStorage(const vector<Datatype *> &typelist,vector<ParameterPieces> &res,bool ignoreOutputError)

{
  if (ignoreOutputError) {
    try {
      output->assignMap(typelist,false,*glb->types,res);
    }
    catch(ParamUnassignedError &err) {
      res.clear();
      res.emplace_back();
      // leave address undefined
      res.back().flags = 0;
      res.back().type = glb->types->getTypeVoid();
    }
  }
  else {
    output->assignMap(typelist,false,*glb->types,res);
  }
  input->assignMap(typelist,true,*glb->types,res);
}

/// \brief Look up an effect from the given EffectRecord list
///
/// If a given memory range matches an EffectRecord, return the effect type.
/// Otherwise return EffectRecord::unknown_effect
/// \param efflist is the list of EffectRecords which must be sorted
/// \param addr is the starting address of the given memory range
/// \param size is the number of bytes in the memory range
/// \return the EffectRecord type
uint4 ProtoModel::lookupEffect(const vector<EffectRecord> &efflist,const Address &addr,int4 size)

{
  // Unique is always local to function
  if (addr.getSpace()->getType()==IPTR_INTERNAL) return EffectRecord::unaffected;

  EffectRecord cur(addr,size);

  vector<EffectRecord>::const_iterator iter;

  iter = upper_bound(efflist.begin(),efflist.end(),cur);
  // First element greater than cur  (address must be greater)
  // go back one more, and we get first el less or equal to cur
  if (iter==efflist.begin()) return EffectRecord::unknown_effect; // Can't go back one
  --iter;
  Address hit = (*iter).getAddress();
  int4 sz = (*iter).getSize();
  if (sz == 0 && (hit.getSpace() == addr.getSpace()))	// A size of zero indicates the whole space is unaffected
    return EffectRecord::unaffected;
  int4 where = addr.overlap(0,hit,sz);
  if ((where>=0)&&(where+size<=sz))
    return (*iter).getType();
  return EffectRecord::unknown_effect;
}

/// The model is searched for an EffectRecord matching the given range
/// and the effect type is returned. If there is no EffectRecord or the
/// effect generally isn't known,  EffectRecord::unknown_effect is returned.
/// \param addr is the starting address of the given memory range
/// \param size is the number of bytes in the given range
/// \return the EffectRecord type
uint4 ProtoModel::hasEffect(const Address &addr,int4 size) const

{
  return lookupEffect(effectlist,addr,size);
}

/// Read in details about \b this model from a \<prototype> tag
/// \param el is the \<prototype> element
void ProtoModel::restoreXml(const Element *el)

{
  int4 numattr = el->getNumAttributes();

  bool sawlocalrange = false;
  bool sawparamrange = false;
  bool sawretaddr = false;
  stackgrowsnegative = true;	// Default growth direction
  AddrSpace *stackspc = glb->getStackSpace();
  if (stackspc != (AddrSpace *)0)
    stackgrowsnegative = stackspc->stackGrowsNegative();	// Get growth boolean from stack space itself
  string strategystring;
  localrange.clear();
  paramrange.clear();
  extrapop = -300;
  hasThis = false;
  isConstruct = false;
  effectlist.clear();
  injectUponEntry = -1;
  injectUponReturn = -1;
  likelytrash.clear();
  for(int4 i=0;i<numattr;++i) {
    if (el->getAttributeName(i) == "name")
      name = el->getAttributeValue(i);
    else if (el->getAttributeName(i) == "extrapop") {
      if (el->getAttributeValue(i) == "unknown")
	extrapop = extrapop_unknown;
      else {
	istringstream s(el->getAttributeValue(i));
	s.unsetf(ios::dec | ios::hex | ios::oct);
	s >> extrapop;
      }
    }
    else if (el->getAttributeName(i) == "stackshift") {
      // Allow this attribute for backward compatibility
    }
    else if (el->getAttributeName(i) == "strategy") {
      strategystring = el->getAttributeValue(i);
    }
    else if (el->getAttributeName(i) == "hasthis") {
      hasThis = xml_readbool(el->getAttributeValue(i));
    }
    else if (el->getAttributeName(i) == "constructor") {
      isConstruct = xml_readbool(el->getAttributeValue(i));
    }
    else
      throw LowlevelError("Unknown prototype attribute: "+el->getAttributeName(i));
  }
  if (name == "__thiscall")
    hasThis = true;
  if (extrapop == -300)
    throw LowlevelError("Missing prototype attributes");

  buildParamList(strategystring); // Allocate input and output ParamLists
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subnode = *iter;
    if (subnode->getName() == "input") {
      input->restoreXml(subnode,glb,effectlist,stackgrowsnegative);
      if (stackspc != (AddrSpace *)0) {
	input->getRangeList(stackspc,paramrange);
	if (!paramrange.empty())
	  sawparamrange = true;
      }
    }
    else if (subnode->getName() == "output") {
      output->restoreXml(subnode,glb,effectlist,stackgrowsnegative);
    }
    else if (subnode->getName() == "unaffected") {
      const List &flist(subnode->getChildren());
      List::const_iterator fiter;
      for(fiter=flist.begin();fiter!=flist.end();++fiter) {
	effectlist.emplace_back();
	effectlist.back().restoreXml(EffectRecord::unaffected,*fiter,glb);
      }
    }
    else if (subnode->getName() == "killedbycall") {
      const List &flist(subnode->getChildren());
      List::const_iterator fiter;
      for(fiter=flist.begin();fiter!=flist.end();++fiter) {
	effectlist.emplace_back();
	effectlist.back().restoreXml(EffectRecord::killedbycall,*fiter,glb);
      }	
    }
    else if (subnode->getName() == "returnaddress") {
      const List &flist(subnode->getChildren());
      List::const_iterator fiter;
      for(fiter=flist.begin();fiter!=flist.end();++fiter) {
	effectlist.emplace_back();
	effectlist.back().restoreXml(EffectRecord::return_address,*fiter,glb);
      }
      sawretaddr = true;
    }
    else if (subnode->getName() == "localrange") {
      sawlocalrange = true;
      const List &sublist(subnode->getChildren());
      List::const_iterator subiter;
      for(subiter=sublist.begin();subiter!=sublist.end();++subiter) {
        Range range;
        range.restoreXml(*subiter,glb);
        localrange.insertRange(range.getSpace(),range.getFirst(),range.getLast());
      }
    }
    else if (subnode->getName() == "paramrange") {
      sawparamrange = true;
      const List &sublist(subnode->getChildren());
      List::const_iterator subiter;
      for(subiter=sublist.begin();subiter!=sublist.end();++subiter) {
        Range range;
        range.restoreXml(*subiter,glb);
        paramrange.insertRange(range.getSpace(),range.getFirst(),range.getLast());
      }
    }
    else if (subnode->getName() == "likelytrash") {
      const List &flist(subnode->getChildren());
      List::const_iterator fiter;
      for(fiter=flist.begin();fiter!=flist.end();++fiter) {
	likelytrash.emplace_back();
	likelytrash.back().restoreXml(*fiter,glb);
      }	
    }
    else if (subnode->getName() == "pcode") {
      if (subnode->getAttributeValue("inject") == "uponentry") {
	injectUponEntry = glb->pcodeinjectlib->restoreXmlInject("Protomodel : "+name,
								name+"@@inject_uponentry",
								InjectPayload::CALLMECHANISM_TYPE,subnode);
     }
      else {
	injectUponReturn = glb->pcodeinjectlib->restoreXmlInject("Protomodel : "+name,
								 name+"@@inject_uponreturn",
								 InjectPayload::CALLMECHANISM_TYPE,subnode);
      }
    }
    else if (subnode->getName() == "description") {
    }
    else
      throw LowlevelError("Unknown element in prototype: "+subnode->getName());
  }
  if ((!sawretaddr)&&(glb->defaultReturnAddr.space != (AddrSpace *)0)) {
    // Provide the default return address, if there isn't a specific one for the model
    effectlist.push_back(EffectRecord(glb->defaultReturnAddr,EffectRecord::return_address));
  }
  sort(effectlist.begin(),effectlist.end());
  sort(likelytrash.begin(),likelytrash.end());
  if (!sawlocalrange)
    defaultLocalRange();
  if (!sawparamrange)
    defaultParamRange();
}

/// \param isinput is set to \b true to compute scores against the input part of the model
/// \param mod is the prototype model to score against
/// \param numparam is the presumed number of trials that will constitute the score
ScoreProtoModel::ScoreProtoModel(bool isinput,const ProtoModel *mod,int4 numparam)

{
  isinputscore = isinput;
  model = mod;
  entry.reserve(numparam);
  finalscore = -1;
  mismatch = 0;
}

/// \param addr is the starting address of the trial
/// \param sz is the number of bytes in the trial
void ScoreProtoModel::addParameter(const Address &addr,int4 sz)

{
  int4 orig = entry.size();
  int4 slot,slotsize;
  bool isparam;
  if (isinputscore)
    isparam = model->possibleInputParamWithSlot(addr,sz,slot,slotsize);
  else
    isparam = model->possibleOutputParamWithSlot(addr,sz,slot,slotsize);
  if (isparam) {
    entry.emplace_back();
    entry.back().origIndex = orig;
    entry.back().slot = slot;
    entry.back().size = slotsize;
  }
  else {
    mismatch += 1;
  }
}

void ScoreProtoModel::doScore(void)

{
  sort(entry.begin(),entry.end()); // Sort our entries via slot

  int4 nextfree = 0;		// Next slot we expect to see
  int4 basescore = 0;
  int4 penalty[4];
  penalty[0] = 16;
  penalty[1] = 10;
  penalty[2] = 7;
  penalty[3] = 5;
  int4 penaltyfinal = 3;
  int4 mismatchpenalty = 20;

  for(int4 i=0;i<entry.size();++i) {
    const PEntry &p( entry[i] );
    if (p.slot > nextfree) {	// We have some kind of hole in our slot coverage
      while(nextfree < p.slot) {
	if (nextfree < 4)
	  basescore += penalty[nextfree];
	else
	  basescore += penaltyfinal;
	nextfree += 1;
      }
      nextfree += p.size;
    }
    else if (nextfree > p.slot) { // Some kind of slot duplication
      basescore += mismatchpenalty;
      if (p.slot + p.size > nextfree)
	nextfree = p.slot + p.size;
    }
    else {
      nextfree = p.slot + p.size;
    }
  }
  finalscore = basescore + mismatchpenalty * mismatch;
}

/// The EffectRecord lists are intersected. Anything in \b this that is not also in the
/// given EffectRecord list is removed.
/// \param efflist is the given EffectRecord list
void ProtoModelMerged::intersectEffects(const vector<EffectRecord> &efflist)

{
  vector<EffectRecord> newlist;

  int4 i = 0;
  int4 j = 0;
  while((i<effectlist.size())&&(j<efflist.size())) {
    const EffectRecord &eff1( effectlist[i] );
    const EffectRecord &eff2( efflist[j] );

    if (eff1 < eff2)
      i += 1;
    else if (eff2 < eff1)
      j += 1;
    else {
      newlist.push_back(eff1);
      i += 1;
      j += 1;
    }
  }
  effectlist = newlist;
}

/// The \e likely-trash locations are intersected. Anything in \b this that is not also in the
/// given \e likely-trash list is removed.
/// \param trashlist is the given \e likely-trash list
void ProtoModelMerged::intersectLikelyTrash(const vector<VarnodeData> &trashlist)

{
  vector<VarnodeData> newlist;

  int4 i=0;
  int4 j=0;
  while((i<likelytrash.size())&&(j<trashlist.size())) {
    const VarnodeData &trs1( likelytrash[i] );
    const VarnodeData &trs2( trashlist[j] );
    
    if (trs1 < trs2)
      i += 1;
    else if (trs2 < trs1)
      j += 1;
    else {
      newlist.push_back(trs1);
      i += 1;
      j += 1;
    }
  }
  likelytrash = newlist;
}

/// \param model is the new prototype model to add to the merge
void ProtoModelMerged::foldIn(ProtoModel *model)

{
  if (model->glb != glb) throw LowlevelError("Mismatched architecture");
  if ((model->input->getType() != ParamList::p_standard)&&
      (model->input->getType() != ParamList::p_register))
    throw LowlevelError("Can only resolve between standard prototype models");
  if (input == (ParamList *)0) { // First fold in
    input = new ParamListMerged();
    output = new ParamListStandardOut(*(ParamListStandardOut *)model->output);
    ((ParamListMerged *)input)->foldIn(*(ParamListStandard *)model->input); // Fold in the parameter lists
    extrapop = model->extrapop;
    effectlist = model->effectlist;
    injectUponEntry = model->injectUponEntry;
    injectUponReturn = model->injectUponReturn;
    likelytrash = model->likelytrash;
    localrange = model->localrange;
    paramrange = model->paramrange;
  }
  else {
    ((ParamListMerged *)input)->foldIn(*(ParamListStandard *)model->input);
    // We assume here that the output models are the same, but we don't check
    if (extrapop != model->extrapop)
      extrapop = ProtoModel::extrapop_unknown;
    if ((injectUponEntry != model->injectUponEntry)||(injectUponReturn != model->injectUponReturn))
      throw LowlevelError("Cannot merge prototype models with different inject ids");
    intersectEffects(model->effectlist);
    intersectLikelyTrash(model->likelytrash);
    // Take the union of the localrange and paramrange
    set<Range>::const_iterator iter;
    for(iter=model->localrange.begin();iter!=model->localrange.end();++iter)
      localrange.insertRange((*iter).getSpace(),(*iter).getFirst(),(*iter).getLast());
    for(iter=model->paramrange.begin();iter!=model->paramrange.end();++iter)
      paramrange.insertRange((*iter).getSpace(),(*iter).getFirst(),(*iter).getLast());
  }
}

/// The model that best matches the given set of input parameter trials is
/// returned. This method currently uses the ScoreProtoModel object to
/// score the different prototype models.
/// \param active is the set of parameter trials
/// \return the prototype model that scores the best
ProtoModel *ProtoModelMerged::selectModel(ParamActive *active) const

{
  int4 bestscore = 500;
  int4 bestindex = -1;
  for(int4 i=0;i<modellist.size();++i) {
    int4 numtrials = active->getNumTrials();
    ScoreProtoModel scoremodel(true,modellist[i],numtrials);
    for(int4 j=0;j<numtrials;++j) {
      ParamTrial &trial( active->getTrial(j) );
      if (trial.isActive())
	scoremodel.addParameter(trial.getAddress(),trial.getSize());
    }
    scoremodel.doScore();
    int4 score = scoremodel.getScore();
    if (score < bestscore) {
      bestscore = score;
      bestindex = i;
      if (bestscore == 0)
	break;			// Can't get any lower
    }
  }
  if (bestindex >= 0)
    return modellist[bestindex];
  throw LowlevelError("No model matches : missing default");
}

void ProtoModelMerged::restoreXml(const Element *el)

{
  name = el->getAttributeValue("name");
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) { // A tag for each merged prototype
    const Element *subel = *iter;
    ProtoModel *mymodel = glb->getModel( subel->getAttributeValue("name"));
    if (mymodel == (ProtoModel *)0)
      throw LowlevelError("Missing prototype model: "+subel->getAttributeValue("name"));
    foldIn(mymodel);
    modellist.push_back(mymodel);
  }
  ((ParamListMerged *)input)->finalize();
  ((ParamListMerged *)output)->finalize();
}

void ParameterBasic::setTypeLock(bool val)

{
  if (val) {
    flags |= ParameterPieces::typelock;
    if (type->getMetatype() == TYPE_UNKNOWN) // Check if we are locking TYPE_UNKNOWN
      flags |= ParameterPieces::sizelock;
  }
  else
    flags &= ~((uint4)(ParameterPieces::typelock|ParameterPieces::sizelock));
}

void ParameterBasic::setNameLock(bool val)

{
  if (val)
    flags |= ParameterPieces::namelock;
  else
    flags &= ~((uint4)ParameterPieces::namelock);
}

void ParameterBasic::setThisPointer(bool val)

{
  if (val)
    flags |= ParameterPieces::isthis;
  else
    flags &= ~((uint4)ParameterPieces::isthis);
}

void ParameterBasic::overrideSizeLockType(Datatype *ct)

{
  if (type->getSize() == ct->getSize()) {
    if (!isSizeTypeLocked())
      throw LowlevelError("Overriding parameter that is not size locked");
    type = ct;
    return;
  }
  throw LowlevelError("Overriding parameter with different type size");
}

void ParameterBasic::resetSizeLockType(TypeFactory *factory)

{
  if (type->getMetatype() == TYPE_UNKNOWN) return; // Nothing to do
  int4 size = type->getSize();
  type = factory->getBase(size,TYPE_UNKNOWN);
}

ProtoParameter *ParameterBasic::clone(void) const

{
  ParameterBasic *res = new ParameterBasic(name,addr,type,flags);
  return res;
}

const string &ParameterSymbol::getName(void) const 

{ 
  return sym->getName(); 
}

Datatype *ParameterSymbol::getType(void) const

{
  return sym->getType();
}

Address ParameterSymbol::getAddress(void) const

{
  return sym->getFirstWholeMap()->getAddr();
}

int4 ParameterSymbol::getSize(void) const

{
  return sym->getFirstWholeMap()->getSize();
}

bool ParameterSymbol::isTypeLocked(void) const

{
  return sym->isTypeLocked();
}

bool ParameterSymbol::isNameLocked(void) const

{
  return sym->isNameLocked();
}

bool ParameterSymbol::isSizeTypeLocked(void) const

{
  return sym->isSizeTypeLocked();
}

bool ParameterSymbol::isThisPointer(void) const

{
  return sym->isThisPointer();
}

bool ParameterSymbol::isIndirectStorage(void) const

{
  return sym->isIndirectStorage();
}

bool ParameterSymbol::isHiddenReturn(void) const

{
  return sym->isHiddenReturn();
}

bool ParameterSymbol::isNameUndefined(void) const

{
  return sym->isNameUndefined();
}

void ParameterSymbol::setTypeLock(bool val)

{
  Scope *scope = sym->getScope();
  uint4 attrs = Varnode::typelock;
  if (!sym->isNameUndefined())
    attrs |= Varnode::namelock;
  if (val)
    scope->setAttribute(sym,attrs);
  else
    scope->clearAttribute(sym,attrs);
}

void ParameterSymbol::setNameLock(bool val)

{
  Scope *scope = sym->getScope();
  if (val)
    scope->setAttribute(sym,Varnode::namelock);
  else
    scope->clearAttribute(sym,Varnode::namelock);
}

void ParameterSymbol::setThisPointer(bool val)

{
  Scope *scope = sym->getScope();
  scope->setThisPointer(sym, val);
}

void ParameterSymbol::overrideSizeLockType(Datatype *ct)

{
  sym->getScope()->overrideSizeLockType(sym,ct);
}

void ParameterSymbol::resetSizeLockType(TypeFactory *factory)

{
  sym->getScope()->resetSizeLockType(sym);
}

ProtoParameter *ParameterSymbol::clone(void) const

{
  throw LowlevelError("Should not be cloning ParameterSymbol");
}

Symbol *ParameterSymbol::getSymbol(void) const

{
  return sym;
}

/// \param sc is the function Scope that will back \b this store
/// \param usepoint is the starting address of the function (-1)
ProtoStoreSymbol::ProtoStoreSymbol(Scope *sc,const Address &usepoint)

{
  scope = sc;
  restricted_usepoint = usepoint;
  outparam = (ProtoParameter *)0;
  ParameterPieces pieces;
  pieces.type = scope->getArch()->types->getTypeVoid();
  pieces.flags = 0;
  ProtoStoreSymbol::setOutput(pieces);
}

ProtoStoreSymbol::~ProtoStoreSymbol(void)

{
  for(int4 i=0;i<inparam.size();++i) {
    ProtoParameter *param = inparam[i];
    if (param != (ProtoParameter *)0)
      delete param;
  }
  if (outparam != (ProtoParameter *)0)
    delete outparam;
}

/// Retrieve the specified ProtoParameter object, making sure it is a ParameterSymbol.
/// If it doesn't exist, or if the object in the specific slot is not a ParameterSymbol,
/// allocate an (unitialized) parameter.
/// \param i is the specified input slot
/// \return the corresponding parameter
ParameterSymbol *ProtoStoreSymbol::getSymbolBacked(int4 i)

{
  while(inparam.size() <= i)
    inparam.push_back((ProtoParameter *)0);
  ParameterSymbol *res = dynamic_cast<ParameterSymbol *>(inparam[i]);
  if (res != (ParameterSymbol *)0)
    return res;
  if (inparam[i] != (ProtoParameter *)0)
    delete inparam[i];
  res = new ParameterSymbol();
  inparam[i] = res;
  return res;
}

ProtoParameter *ProtoStoreSymbol::setInput(int4 i, const string &nm,const ParameterPieces &pieces)

{
  ParameterSymbol *res = getSymbolBacked(i);
  res->sym = scope->getCategorySymbol(0,i);
  SymbolEntry *entry;
  Address usepoint;

  bool isindirect = (pieces.flags & ParameterPieces::indirectstorage) != 0;
  bool ishidden = (pieces.flags & ParameterPieces::hiddenretparm) != 0;
  if (res->sym != (Symbol *)0) {
    entry = res->sym->getFirstWholeMap();
    if ((entry->getAddr() != pieces.addr)||(entry->getSize() != pieces.type->getSize())) {
      scope->removeSymbol(res->sym);
      res->sym = (Symbol *)0;
    }
  }
  if (res->sym == (Symbol *)0) {
    if (scope->discoverScope(pieces.addr,pieces.type->getSize(),usepoint) == (Scope *)0)
      usepoint = restricted_usepoint; 
    res->sym = scope->addSymbol(nm,pieces.type,pieces.addr,usepoint)->getSymbol();
    scope->setCategory(res->sym,0,i);
    if (isindirect || ishidden) {
      uint4 mirror = 0;
      if (isindirect)
	mirror |= Varnode::indirectstorage;
      if (ishidden)
	mirror |= Varnode::hiddenretparm;
      scope->setAttribute(res->sym,mirror);
    }
    return res;
  }
  if (res->sym->isIndirectStorage() != isindirect) {
    if (isindirect)
      scope->setAttribute(res->sym,Varnode::indirectstorage);
    else
      scope->clearAttribute(res->sym,Varnode::indirectstorage);
  }
  if (res->sym->isHiddenReturn() != ishidden) {
    if (ishidden)
      scope->setAttribute(res->sym,Varnode::hiddenretparm);
    else
      scope->clearAttribute(res->sym,Varnode::hiddenretparm);
  }
  if ((nm.size()!=0)&&(nm!=res->sym->getName()))
    scope->renameSymbol(res->sym,nm);
  if (pieces.type != res->sym->getType())
    scope->retypeSymbol(res->sym,pieces.type);
  return res;
}

void ProtoStoreSymbol::clearInput(int4 i)

{
  Symbol *sym = scope->getCategorySymbol(0,i);
  if (sym != (Symbol *)0) {
    scope->setCategory(sym,-1,0); // Remove it from category list
    scope->removeSymbol(sym);	// Remove it altogether
  }
  // Renumber any category 0 symbol with index greater than i
  int4 sz = scope->getCategorySize(0);
  for(int4 j=i+1;j<sz;++j) {
    sym = scope->getCategorySymbol(0,j);
    if (sym != (Symbol *)0)
      scope->setCategory(sym,0,j-1);
  }
}

void ProtoStoreSymbol::clearAllInputs(void)

{
  scope->clearCategory(0);
}

int4 ProtoStoreSymbol::getNumInputs(void) const

{
  return scope->getCategorySize(0);
}

ProtoParameter *ProtoStoreSymbol::getInput(int4 i)

{
  Symbol *sym = scope->getCategorySymbol(0,i);
  if (sym == (Symbol *)0)
    return (ProtoParameter *)0;
  ParameterSymbol *res = getSymbolBacked(i);
  res->sym = sym;
  return res;
}

ProtoParameter *ProtoStoreSymbol::setOutput(const ParameterPieces &piece)

{
  if (outparam != (ProtoParameter *)0)
    delete outparam;
  outparam = new ParameterBasic("",piece.addr,piece.type,piece.flags);
  return outparam;
}

void ProtoStoreSymbol::clearOutput(void)

{
  ParameterPieces pieces;
  pieces.type = scope->getArch()->types->getTypeVoid();
  pieces.flags = 0;
  setOutput(pieces);
}

ProtoParameter *ProtoStoreSymbol::getOutput(void)

{
  return outparam;
}

ProtoStore *ProtoStoreSymbol::clone(void) const

{
  ProtoStoreSymbol *res;
  res = new ProtoStoreSymbol(scope,restricted_usepoint);
  delete res->outparam;
  if (outparam != (ProtoParameter *)0)
    res->outparam = outparam->clone();
  else
    res->outparam = (ProtoParameter *)0;
  return res;
}

void ProtoStoreSymbol::saveXml(ostream &s) const

{ // Do not store anything explicitly for a symboltable backed store
  // as the symboltable will be stored separately
}

void ProtoStoreSymbol::restoreXml(const Element *el,ProtoModel *model)

{
  throw LowlevelError("Do not restore symbol-backed prototype through this interface");
}

/// \param vt is the \b void data-type used for an unspecified return value
ProtoStoreInternal::ProtoStoreInternal(Datatype *vt)

{
  voidtype = vt;
  outparam = (ProtoParameter *)0;
  ParameterPieces pieces;
  pieces.type = voidtype;
  pieces.flags = 0;
  ProtoStoreInternal::setOutput(pieces);
}

ProtoStoreInternal::~ProtoStoreInternal(void)

{
  if (outparam != (ProtoParameter *)0)
    delete outparam;
  for(int4 i=0;i<inparam.size();++i) {
    ProtoParameter *param = inparam[i];
    if (param != (ProtoParameter *)0)
      delete param;
  }
}

ProtoParameter *ProtoStoreInternal::setInput(int4 i,const string &nm,const ParameterPieces &pieces)

{
  while(inparam.size() <= i)
    inparam.push_back((ProtoParameter *)0);
  if (inparam[i] != (ProtoParameter *)0)
    delete inparam[i];
  inparam[i] = new ParameterBasic(nm,pieces.addr,pieces.type,pieces.flags);
  return inparam[i];
}

void ProtoStoreInternal::clearInput(int4 i)

{
  int4 sz = inparam.size();
  if (i>=sz) return;
  if (inparam[i] != (ProtoParameter *)0)
    delete inparam[i];
  inparam[i] = (ProtoParameter *)0;
  for(int4 j=i+1;j<sz;++j) {	// Renumber parameters with index > i
    inparam[j-1] = inparam[j];
    inparam[j] = (ProtoParameter *)0;
  }
  while(inparam.back() == (ProtoParameter *)0)
    inparam.pop_back();
}

void ProtoStoreInternal::clearAllInputs(void)

{
  for(int4 i=0;i<inparam.size();++i) {
    if (inparam[i] != (ProtoParameter *)0)
      delete inparam[i];
  }
  inparam.clear();
}

int4 ProtoStoreInternal::getNumInputs(void) const

{
  return inparam.size();
}

ProtoParameter *ProtoStoreInternal::getInput(int4 i)

{
  if (i>=inparam.size())
    return (ProtoParameter *)0;
  return inparam[i];
}

ProtoParameter *ProtoStoreInternal::setOutput(const ParameterPieces &piece)

{
  if (outparam != (ProtoParameter *)0)
    delete outparam;
  outparam = new ParameterBasic("",piece.addr,piece.type,piece.flags);
  return outparam;
}

void ProtoStoreInternal::clearOutput(void)

{
  if (outparam != (ProtoParameter *)0)
    delete outparam;
  outparam = new ParameterBasic(voidtype);
}

ProtoParameter *ProtoStoreInternal::getOutput(void)

{
  return outparam;
}

ProtoStore *ProtoStoreInternal::clone(void) const

{
  ProtoStoreInternal *res = new ProtoStoreInternal(voidtype);
  delete res->outparam;
  if (outparam != (ProtoParameter *)0)
    res->outparam = outparam->clone();
  else
    res->outparam = (ProtoParameter *)0;
  for(int4 i=0;i<inparam.size();++i) {
    ProtoParameter *param = inparam[i];
    if (param != (ProtoParameter *)0)
      param = param->clone();
    res->inparam.push_back(param);
  }
  return res;
}

void ProtoStoreInternal::saveXml(ostream &s) const

{
  s << "<internallist>\n";
  if (outparam != (ProtoParameter *)0) {
    s << "<retparam";
    if (outparam->isTypeLocked())
      a_v_b(s,"typelock",true);
    s << ">\n";
    outparam->getAddress().saveXml(s);
    outparam->getType()->saveXml(s);
    s << "</retparam>\n";
  }
  else {
    s << "<retparam>\n <addr/>\n <void/>\n</retparam>\n";
  }

  for(int4 i=0;i<inparam.size();++i) {
    ProtoParameter *param = inparam[i];
    s << "<param";
    if (param->getName().size()!=0)
      a_v(s,"name",param->getName());
    if (param->isTypeLocked())
      a_v_b(s,"typelock",true);
    if (param->isNameLocked())
      a_v_b(s,"namelock",true);
    if (param->isThisPointer())
      a_v_b(s,"thisptr",true);
    if (param->isIndirectStorage())
      a_v_b(s,"indirectstorage",true);
    if (param->isHiddenReturn())
      a_v_b(s,"hiddenretparm",true);
    s << ">\n";
    param->getAddress().saveXml(s);
    param->getType()->saveXml(s);
    s << "</param>\n";
  }
  s << "</internallist>\n";
}

void ProtoStoreInternal::restoreXml(const Element *el,ProtoModel *model)

{
  if (el->getName() != "internallist")
    throw LowlevelError("Mismatched ProtoStore tag: ProtoStoreInternal did not get <internallist>");
  Architecture *glb = model->getArch();
  const List &list(el->getChildren());
  List::const_iterator iter;
  vector<ParameterPieces> pieces;
  vector<string> namelist;
  bool addressesdetermined = true;

  pieces.push_back( ParameterPieces() ); // Push on placeholder for output pieces
  namelist.push_back("ret");
  pieces.back().type = outparam->getType();
  pieces.back().flags = 0;
  if (outparam->isTypeLocked())
    pieces.back().flags |= ParameterPieces::typelock;
  if (outparam->isIndirectStorage())
    pieces.back().flags |= ParameterPieces::indirectstorage;
  if (outparam->getAddress().isInvalid())
    addressesdetermined = false;

  for(iter=list.begin();iter!=list.end();++iter) { // This is only the input params
    const Element *subel = *iter;
    string name;
    uint4 flags = 0;
    for(int4 i=0;i<subel->getNumAttributes();++i) {
      const string &attr( subel->getAttributeName(i) );
      if (attr == "name")
	name = subel->getAttributeValue(i);
      else if (attr == "typelock") {
	if (xml_readbool(subel->getAttributeValue(i)))
	  flags |= ParameterPieces::typelock;
      }
      else if (attr == "namelock") {
	if (xml_readbool(subel->getAttributeValue(i)))
	  flags |= ParameterPieces::namelock;
      }
      else if (attr == "thisptr") {
	if (xml_readbool(subel->getAttributeValue(i)))
	  flags |= ParameterPieces::isthis;
      }
      else if (attr == "indirectstorage") {
	if (xml_readbool(subel->getAttributeValue(i)))
	  flags |= ParameterPieces::indirectstorage;
      }
      else if (attr == "hiddenretparm") {
	if (xml_readbool(subel->getAttributeValue(i)))
	  flags |= ParameterPieces::hiddenretparm;
      }
    }
    if ((flags & ParameterPieces::hiddenretparm) == 0)
      namelist.push_back(name);
    pieces.emplace_back();
    ParameterPieces &curparam( pieces.back() );
    const List &sublist(subel->getChildren());
    List::const_iterator subiter;
    subiter = sublist.begin();
    curparam.addr = Address::restoreXml(*subiter,glb);
    ++subiter;
    curparam.type = glb->types->restoreXmlType(*subiter);
    curparam.flags = flags;
    if (curparam.addr.isInvalid())
      addressesdetermined = false;
  }
  ProtoParameter *curparam;
  if (!addressesdetermined) {
    // If addresses for parameters are not provided, use
    // the model to derive them from type info
    vector<Datatype *> typelist;
    for(int4 i=0;i<pieces.size();++i) // Save off the restored types
      typelist.push_back( pieces[i].type );
    vector<ParameterPieces> addrPieces;
    model->assignParameterStorage(typelist,addrPieces,true);
    addrPieces.swap(pieces);
    uint4 k = 0;
    for(uint4 i=0;i<pieces.size();++i) {
      if ((pieces[i].flags & ParameterPieces::hiddenretparm)!=0)
	continue;	// Increment i but not k
      pieces[i].flags = addrPieces[k].flags;		// Use the original flags
      k = k + 1;
    }
    if (pieces[0].addr.isInvalid()) {	// If could not get valid storage for output
      pieces[0].flags &= ~((uint4)ParameterPieces::typelock);		// Treat as unlocked void
    }
    curparam = setOutput(pieces[0]);
    curparam->setTypeLock((pieces[0].flags & ParameterPieces::typelock)!=0);
  }
  uint4 j=1;
  for(uint4 i=1;i<pieces.size();++i) {
    if ((pieces[i].flags&ParameterPieces::hiddenretparm)!=0) {
       curparam = setInput(i-1,"rethidden",pieces[i]);
       curparam->setTypeLock((pieces[0].flags & ParameterPieces::typelock)!=0);   // Has output's typelock
       continue;    // increment i but not j
    }
    curparam = setInput(i-1,namelist[j],pieces[i]);
    curparam->setTypeLock((pieces[i].flags & ParameterPieces::typelock)!=0);
    curparam->setNameLock((pieces[i].flags & ParameterPieces::namelock)!=0);
    j = j + 1;
  }
}

/// This is called after a new prototype is established (via restoreXml or updateAllTypes)
/// It makes sure that if the ProtoModel calls for a "this" parameter, then the appropriate parameter
/// is explicitly marked as the "this".
void FuncProto::updateThisPointer(void)

{
  if (!model->hasThisPointer()) return;
  int4 numInputs = store->getNumInputs();
  if (numInputs == 0) return;
  ProtoParameter *param = store->getInput(0);
  if (param->isHiddenReturn()) {
    if (numInputs < 2) return;
    param = store->getInput(1);
  }
  param->setThisPointer(true);
}

/// Prepend the indicated number of input parameters to \b this.
/// The new parameters have a data-type of xunknown4. If they were
/// originally locked, the existing parameters are preserved.
/// \param paramshift is the number of parameters to add (must be >0)
void FuncProto::paramShift(int4 paramshift)

{
  if ((model == (ProtoModel *)0)||(store == (ProtoStore *)0))
    throw LowlevelError("Cannot parameter shift without a model");

  vector<string> nmlist;
  vector<Datatype *> typelist;
  bool isdotdotdot = false;
  TypeFactory *typefactory = model->getArch()->types;

  if (isOutputLocked())
    typelist.push_back( getOutputType() );
  else
    typelist.push_back( typefactory->getTypeVoid() );
  nmlist.push_back("");

  Datatype *extra = typefactory->getBase(4,TYPE_UNKNOWN); // The extra parameters have this type
  for(int4 i=0;i<paramshift;++i) {
    nmlist.push_back("");
    typelist.push_back(extra);
  }
  
  if (isInputLocked()) {	// Copy in the original parameter types
    int4 num = numParams();
    for(int4 i=0;i<num;++i) {
      ProtoParameter *param = getParam(i);
      nmlist.push_back(param->getName());
      typelist.push_back( param->getType() );
    }
  }
  else
    isdotdotdot = true;

  // Reassign the storage locations for this new parameter list
  vector<ParameterPieces> pieces;
  model->assignParameterStorage(typelist,pieces,false);

  delete store;

  // This routine always converts -this- to have a ProtoStoreInternal
  store = new ProtoStoreInternal(typefactory->getTypeVoid());

  store->setOutput(pieces[0]);
  uint4 j=1;
  for(uint4 i=1;i<pieces.size();++i) {
    if ((pieces[i].flags & ParameterPieces::hiddenretparm) != 0) {
       store->setInput(i-1,"rethidden",pieces[i]);
       continue;   // increment i but not j
    }
    store->setInput(j,nmlist[j],pieces[i]);
    j = j + 1;
  }
  setInputLock(true);
  setDotdotdot(isdotdotdot);
}

/// \brief If \b this has a \e merged model, pick the most likely model (from the merged set)
///
/// The given parameter trials are used to pick from among the merged ProtoModels and
/// \b this prototype is changed (specialized) to the pick
/// \param active is the set of parameter trials to evaluate with
void FuncProto::resolveModel(ParamActive *active)

{
  if (model == (ProtoModel *)0) return;
  if (!model->isMerged()) return; // Already been resolved
  ProtoModelMerged *mergemodel = (ProtoModelMerged *)model;
  ProtoModel *newmodel = mergemodel->selectModel(active);
  setModel(newmodel);
  // we don't need to remark the trials, as this is accomplished by the ParamList::fillinMap method
}

FuncProto::FuncProto(void)

{
  model = (ProtoModel *)0;
  store = (ProtoStore *)0;
  flags = 0;
  injectid = -1;
  returnBytesConsumed = 0;
}

/// \param op2 is the other function prototype to copy into \b this
void FuncProto::copy(const FuncProto &op2)

{
  model = op2.model;
  extrapop = op2.extrapop;
  flags = op2.flags;
  if (store != (ProtoStore *)0)
    delete store;
  if (op2.store != (ProtoStore *)0)
    store = op2.store->clone();
  else
    store = (ProtoStore *)0;
  effectlist = op2.effectlist;
  likelytrash = op2.likelytrash;
  injectid = op2.injectid;
}

void FuncProto::copyFlowEffects(const FuncProto &op2)

{
  flags &= ~((uint4)(is_inline|no_return));
  flags |= op2.flags & (is_inline|no_return);
  injectid = op2.injectid;
}

/// Establish a specific prototype model for \b this function prototype.
/// Some basic properties are inherited from the model, otherwise parameters
/// are unchanged.
/// \param m is the new prototype model to set
void FuncProto::setModel(ProtoModel *m)

{
  if (m != (ProtoModel *)0) {
    int4 expop = m->getExtraPop();
    // If a model previously existed don't overwrite extrapop with unknown
    if ((model == (ProtoModel *)0)||(expop != ProtoModel::extrapop_unknown))
      extrapop = expop;
    if (m->hasThisPointer())
      flags |= has_thisptr;
    if (m->isConstructor())
      flags |= is_constructor;
    model = m;
  }
  else {
    model = m;
    extrapop = ProtoModel::extrapop_unknown;
  }
  flags &= ~((uint4)unknown_model);	// Model is not "unknown" (even if null pointer is passed in)
}

/// The full function prototype is (re)set from a model, names, and data-types
/// The new input and output parameters are both assumed to be locked.
/// \param pieces is the raw collection of names and data-types
void FuncProto::setPieces(const PrototypePieces &pieces)

{
  if (pieces.model != (ProtoModel *)0)
    setModel(pieces.model);
  vector<Datatype *> typelist;
  vector<string> nmlist;
  typelist.push_back(pieces.outtype);
  nmlist.push_back("");
  for(int4 i=0;i<pieces.intypes.size();++i) {
    typelist.push_back(pieces.intypes[i]);
    nmlist.push_back(pieces.innames[i]);
  }
  updateAllTypes(nmlist,typelist,pieces.dotdotdot);
  setInputLock(true);
  setOutputLock(true);
  setModelLock(true);
}

/// Copy out the raw pieces of \b this prototype as stand-alone objects,
/// includings model, names, and data-types
/// \param pieces will hold the raw pieces
void FuncProto::getPieces(PrototypePieces &pieces) const

{
  pieces.model = model;
  if (store == (ProtoStore *)0) return;
  pieces.outtype = store->getOutput()->getType();
  int4 num = store->getNumInputs();
  for(int4 i=0;i<num;++i) {
    ProtoParameter *param = store->getInput(i);
    pieces.intypes.push_back(param->getType());
    pieces.innames.push_back(param->getName());
  }
  pieces.dotdotdot = isDotdotdot();
}

/// Input parameters are set based on an existing function Scope
/// and if there is no prototype model the default model is set.
/// Parameters that are added to \b this during analysis will automatically
/// be reflected in the symbol table.
/// This should only be called during initialization of \b this prototype.
/// \param s is the Scope to set
/// \param startpoint is a usepoint to associate with the parameters
void FuncProto::setScope(Scope *s,const Address &startpoint)

{
  store = new ProtoStoreSymbol(s,startpoint);
  if (model == (ProtoModel *)0)
    setModel(s->getArch()->defaultfp);
}

/// A prototype model is set, and any parameters added to \b this during analysis
/// will be backed internally.
/// \param m is the prototype model to set
/// \param vt is the default \e void data-type to use if the return-value remains unassigned
void FuncProto::setInternal(ProtoModel *m,Datatype *vt)

{
  store = new ProtoStoreInternal(vt);
  if (model == (ProtoModel *)0)
    setModel(m);
}

FuncProto::~FuncProto(void)

{
  if (store != (ProtoStore *)0)
    delete store;
}

bool FuncProto::isInputLocked(void) const

{
  if ((flags&voidinputlock)!=0) return true;
  if (numParams()==0) return false;
  ProtoParameter *param = getParam(0);
  if (param->isTypeLocked()) return true;
  return false;
}

/// The lock on the data-type of input parameters is set as specified.
/// A \b true value indicates that future analysis will not change the
/// number of input parameters or their data-type.  Zero parameters
/// or \e void can be locked.
/// \param val is \b true to indicate a lock, \b false for unlocked
void FuncProto::setInputLock(bool val)

{
  if (val)
    flags |= modellock;		// Locking input locks the model
  int4 num = numParams();
  if (num == 0) {
    flags = val ? (flags|voidinputlock) : (flags& ~((uint4)voidinputlock));
    return;
  }
  for(int4 i=0;i<num;++i) {
    ProtoParameter *param = getParam(i);
    param->setTypeLock(val);
  }
}

/// The lock of the data-type of the return value is set as specified.
/// A \b true value indicates that future analysis will not change the
/// presence of or the data-type of the return value. A \e void return
/// value can be locked.
/// \param val is \b true to indicate a lock, \b false for unlocked
void FuncProto::setOutputLock(bool val)

{
  if (val)
    flags |= modellock;		// Locking output locks the model
  store->getOutput()->setTypeLock(val);
}

/// Provide a hint as to how many bytes of the return value are important.
/// The smallest hint is used to inform the dead-code removal algorithm.
/// \param val is the hint (number of bytes or 0 for all bytes)
/// \return \b true if the smallest hint has changed
bool FuncProto::setReturnBytesConsumed(int4 val)

{
  if (val == 0)
    return false;
  if (returnBytesConsumed == 0 || val < returnBytesConsumed) {
    returnBytesConsumed = val;
    return true;
  }
  return false;
}

/// \brief Assuming \b this prototype is locked, calculate the \e extrapop
///
/// If \e extrapop is unknown and \b this prototype is locked, try to directly
/// calculate what the \e extrapop should be.  This is really only designed to work with
/// 32-bit x86 binaries.
void FuncProto::resolveExtraPop(void)

{
  if (!isInputLocked()) return;
  int4 numparams = numParams();
  if (isDotdotdot()) {
    if (numparams != 0)		// If this is a "standard" varargs, with fixed initial parameters
      setExtraPop(4);		// then this must be __cdecl
    return;			// otherwise we can't resolve the extrapop, as in the FARPROC prototype
  }
  int4 expop = 4;			// Extrapop is at least 4 for the return address
  for(int4 i=0;i<numparams;++i) {
    ProtoParameter *param = getParam(i);
    const Address &addr( param->getAddress() );
    if (addr.getSpace()->getType() != IPTR_SPACEBASE) continue;
    int4 cur = (int4)addr.getOffset() + param->getSize();
    cur = (cur+3)&0xffffffc;	// Must be 4-byte aligned
    if (cur > expop)
      expop = cur;
  }
  setExtraPop(expop);
}

void FuncProto::clearUnlockedInput(void)

{
  if (isInputLocked()) return;
  store->clearAllInputs();
}

void FuncProto::clearUnlockedOutput(void)

{
  ProtoParameter *outparam = getOutput();
  if (outparam->isTypeLocked()) {
    if (outparam->isSizeTypeLocked()) {
      if (model != (ProtoModel *)0)
	outparam->resetSizeLockType(getArch()->types);
    }
  }
  else
    store->clearOutput();
  returnBytesConsumed = 0;
}

void FuncProto::clearInput(void)

{
  store->clearAllInputs();
  flags &= ~((uint4)voidinputlock); // If a void was locked in clear it
}

void FuncProto::cancelInjectId(void)

{
  injectid = -1;
  flags &= ~((uint4)is_inline);
}

/// \brief Update input parameters based on Varnode trials
///
/// If the input parameters are locked, don't do anything. Otherwise,
/// given a list of Varnodes and their associated trial information,
/// create an input parameter for each trial in order, grabbing data-type
/// information from the Varnode.  Any old input parameters are cleared.
/// \param data is the function containing the trial Varnodes
/// \param triallist is the list of Varnodes
/// \param activeinput is the trial container
void FuncProto::updateInputTypes(Funcdata &data,const vector<Varnode *> &triallist,ParamActive *activeinput)

{
  if (isInputLocked()) return;	// Input is locked, do no updating
  store->clearAllInputs();
  int4 count = 0;
  int4 numtrials = activeinput->getNumTrials();
  for(int4 i=0;i<numtrials;++i) {
    ParamTrial &trial(activeinput->getTrial(i));
    if (trial.isUsed()) {
      Varnode *vn = triallist[trial.getSlot()-1];
      if (vn->isMark()) continue;
      ParameterPieces pieces;
      if (vn->isPersist()) {
	int4 sz;
	pieces.addr = data.findDisjointCover(vn, sz);
	if (sz == vn->getSize())
	  pieces.type = vn->getHigh()->getType();
	else
	  pieces.type = data.getArch()->types->getBase(sz, TYPE_UNKNOWN);
	pieces.flags = 0;
      }
      else {
	pieces.addr = trial.getAddress();
	pieces.type = vn->getHigh()->getType();
	pieces.flags = 0;
      }
      store->setInput(count,"",pieces);
      count += 1;
      vn->setMark();
    }
  }
  for(int4 i=0;i<triallist.size();++i)
    triallist[i]->clearMark();
  updateThisPointer();
}

/// \brief Update input parameters based on Varnode trials, but do not store the data-type
///
/// This is accomplished in the same way as if there were data-types but instead of
/// pulling a data-type from the Varnode, only the size is used.
/// Undefined data-types are pulled from the given TypeFactory
/// \param data is the function containing the trial Varnodes
/// \param triallist is the list of Varnodes
/// \param activeinput is the trial container
void FuncProto::updateInputNoTypes(Funcdata &data,const vector<Varnode *> &triallist,ParamActive *activeinput)
{
  if (isInputLocked()) return;	// Input is locked, do no updating
  store->clearAllInputs();
  int4 count = 0;
  int4 numtrials = activeinput->getNumTrials();
  TypeFactory *factory = data.getArch()->types;
  for(int4 i=0;i<numtrials;++i) {
    ParamTrial &trial(activeinput->getTrial(i));
    if (trial.isUsed()) {
      Varnode *vn = triallist[trial.getSlot()-1];
      if (vn->isMark()) continue;
      ParameterPieces pieces;
      if (vn->isPersist()) {
	int4 sz;
	pieces.addr = data.findDisjointCover(vn, sz);
	pieces.type = factory->getBase(sz, TYPE_UNKNOWN);
	pieces.flags = 0;
      }
      else {
	pieces.addr = trial.getAddress();
	pieces.type = factory->getBase(vn->getSize(),TYPE_UNKNOWN);
	pieces.flags = 0;
      }
      store->setInput(count,"",pieces);
      count += 1;
      vn->setMark();		// Make sure vn is used only once
    }
  }
  for(int4 i=0;i<triallist.size();++i)
    triallist[i]->clearMark();
}

/// \brief Update the return value based on Varnode trials
///
/// If the output parameter is locked, don't do anything. Otherwise,
/// given a list of (at most 1) Varnode, create a return value, grabbing
/// data-type information from the Varnode. Any old return value is removed.
/// \param triallist is the list of Varnodes
void FuncProto::updateOutputTypes(const vector<Varnode *> &triallist)

{
  ProtoParameter *outparm = getOutput();
  if (!outparm->isTypeLocked()) {
    if (triallist.empty()) {
      store->clearOutput();
      return;
    }
  }
  else if (outparm->isSizeTypeLocked()) {
    if (triallist.empty()) return;
    if ((triallist[0]->getAddr() == outparm->getAddress())&&(triallist[0]->getSize() == outparm->getSize()))
      outparm->overrideSizeLockType(triallist[0]->getHigh()->getType());
    return;
  }
  else
    return;			// Locked

  if (triallist.empty()) return;
  // If we reach here, output is not locked, not sizelocked, and there is a valid trial
  ParameterPieces pieces;
  pieces.addr = triallist[0]->getAddr();
  pieces.type = triallist[0]->getHigh()->getType();
  pieces.flags = 0;
  store->setOutput(pieces);
}

/// \brief Update the return value based on Varnode trials, but don't store the data-type
///
/// If the output parameter is locked, don't do anything. Otherwise,
/// given a list of (at most 1) Varnode, create a return value, grabbing
/// size information from the Varnode. An undefined data-type is created from the
/// given TypeFactory. Any old return value is removed.
/// \param triallist is the list of Varnodes
/// \param factory is the given TypeFactory
void FuncProto::updateOutputNoTypes(const vector<Varnode *> &triallist,TypeFactory *factory)

{
  if (isOutputLocked()) return;
  if (triallist.empty()) {
    store->clearOutput();
    return;
  }
  ParameterPieces pieces;
  pieces.type = factory->getBase(triallist[0]->getSize(),TYPE_UNKNOWN);
  pieces.addr = triallist[0]->getAddr();
  pieces.flags = 0;
  store->setOutput(pieces);
}

/// \brief Set \b this entire function prototype based on a list of names and data-types.
///
/// Prototype information is provided as separate lists of names and data-types, where
/// the first entry corresponds to the output parameter (return value) and the remaining
/// entries correspond to input parameters. Storage locations and hidden return parameters are
/// calculated, creating a complete function protototype. Existing locks are overridden.
/// \param namelist is the list of parameter names
/// \param typelist is the list of data-types
/// \param dtdtdt is \b true if the new prototype accepts variable argument lists
void FuncProto::updateAllTypes(const vector<string> &namelist,const vector<Datatype *> &typelist,
			       bool dtdtdt)

{
  setModel(model);		// This resets extrapop
  store->clearAllInputs();
  store->clearOutput();
  flags &= ~((uint4)voidinputlock);
  setDotdotdot(dtdtdt);
  
  vector<ParameterPieces> pieces;

  // Calculate what memory locations hold each type
  try {
    model->assignParameterStorage(typelist,pieces,false);
    store->setOutput(pieces[0]);
    uint4 j=1;
    for(uint4 i=1;i<pieces.size();++i) {
      if ((pieces[i].flags & ParameterPieces::hiddenretparm) != 0) {
         store->setInput(i-1,"rethidden",pieces[i]);
         continue;       // increment i but not j
      }
      store->setInput(i-1,namelist[j],pieces[i]);
      j = j + 1;
    }
  }
  catch(ParamUnassignedError &err) {
    flags |= error_inputparam;
  }
  updateThisPointer();
}

/// \brief Calculate the effect \b this has an a given storage location
///
/// For a storage location that is active before and after a call to a function
/// with \b this prototype, we determine the type of side-effect the function
/// will have on the storage.
/// \param addr is the starting address of the storage location
/// \param size is the number of bytes in the storage
/// \return the type of side-effect: EffectRecord::unaffected, EffectRecord::killedbycall, etc.
uint4 FuncProto::hasEffect(const Address &addr,int4 size) const

{
  if (effectlist.empty())
    return model->hasEffect(addr,size);

  return ProtoModel::lookupEffect(effectlist,addr,size);
}

vector<EffectRecord>::const_iterator FuncProto::effectBegin(void) const

{
  if (effectlist.empty())
    return model->effectBegin();
  return effectlist.begin();
}

vector<EffectRecord>::const_iterator FuncProto::effectEnd(void) const

{
  if (effectlist.empty())
    return model->effectEnd();
  return effectlist.end();
}

/// \return the number of individual storage locations
int4 FuncProto::numLikelyTrash(void) const

{
  if (likelytrash.empty())
    return model->numLikelyTrash();
  return likelytrash.size();
}

/// \param i is the index of the storage location
/// \return the storage location which may hold a trash value
const VarnodeData &FuncProto::getLikelyTrash(int4 i) const

{
  if (likelytrash.empty())
    return model->getLikelyTrash(i);
  return likelytrash[i];
}

/// \brief Decide whether a given storage location could be, or could hold, an input parameter
///
/// If the input is locked, check if the location overlaps one of the current parameters.
/// Otherwise, check if the location overlaps an entry in the prototype model.
/// Return:
///   - 0 if the location neither contains or is contained by a parameter storage location
///   - 1 if the location is contained by a parameter storage location
///   - 2 if the location contains a parameter storage location
/// \param addr is the starting address of the given storage location
/// \param size is the number of bytes in the storage
/// \return the characterization code
int4 FuncProto::characterizeAsInputParam(const Address &addr,int4 size) const

{
  if (!isDotdotdot()) {		// If the proto is varargs, go straight to the model
    if ((flags&voidinputlock)!=0) return 0;
    int4 num = numParams();
    if (num > 0) {
      bool locktest = false;	// Have tested against locked symbol
      int4 characterCode = 0;
      for(int4 i=0;i<num;++i) {
	ProtoParameter *param = getParam(i);
	if (!param->isTypeLocked()) continue;
	locktest = true;
	Address iaddr = param->getAddress();
	// If the parameter already exists, the varnode must be justified in the parameter relative
	// to the endianness of the space, irregardless of the forceleft flag
	if (iaddr.justifiedContain(param->getSize(),addr,size,false)==0)
	  return 1;
	if (iaddr.containedBy(param->getSize(), addr, size))
	  characterCode = 2;
      }
      if (locktest) return characterCode;
    }
  }
  return model->characterizeAsInputParam(addr, size);
}

/// \brief Decide whether a given storage location could be an input parameter
///
/// If the input is locked, check if the location matches one of the current parameters.
/// Otherwise, check if the location \e could be a parameter based on the
/// prototype model.
/// \param addr is the starting address of the given storage location
/// \param size is the number of bytes in the storage
/// \return \b false if the location is definitely not an input parameter
bool FuncProto::possibleInputParam(const Address &addr,int4 size) const

{
  if (!isDotdotdot()) {		// If the proto is varargs, go straight to the model
    if ((flags&voidinputlock)!=0) return false;
    int4 num = numParams();
    if (num > 0) {
      bool locktest = false;	// Have tested against locked symbol
      for(int4 i=0;i<num;++i) {
	ProtoParameter *param = getParam(i);
	if (!param->isTypeLocked()) continue;
	locktest = true;
	Address iaddr = param->getAddress();
	// If the parameter already exists, the varnode must be justified in the parameter relative
	// to the endianness of the space, irregardless of the forceleft flag
	if (iaddr.justifiedContain(param->getSize(),addr,size,false)==0)
	  return true;
      }
      if (locktest) return false;
    }
  }
  return model->possibleInputParam(addr,size);
}

/// \brief Decide whether a given storage location could be a return value
///
/// If the output is locked, check if the location matches the current return value.
/// Otherwise, check if the location \e could be a return value based on the
/// prototype model.
/// \param addr is the starting address of the given storage location
/// \param size is the number of bytes in the storage
/// \return \b false if the location is definitely not the return value
bool FuncProto::possibleOutputParam(const Address &addr,int4 size) const

{
  if (isOutputLocked()) {
    ProtoParameter *outparam = getOutput();
    if (outparam->getType()->getMetatype() == TYPE_VOID)
      return false;
    Address iaddr = outparam->getAddress();
    // If the output is locked, the varnode must be justified in the location relative
    // to the endianness of the space, irregardless of the forceleft flag
    if (iaddr.justifiedContain(outparam->getSize(),addr,size,false)==0)
      return true;
    return false;
  }
  return model->possibleOutputParam(addr,size);
}

/// \brief Check if the given storage location looks like an \e unjustified input parameter
///
/// The storage for a value may be contained in a normal parameter location but be
/// unjustified within that container, i.e. the least significant bytes are not being used.
/// If this is the case, pass back the full parameter location and return \b true.
/// If the input is locked, checking is againt the set parameters, otherwise the
/// check is against the prototype model.
/// \param addr is the starting address of the given storage
/// \param size is the number of bytes in the given storage
/// \param res is the full parameter storage to pass back
/// \return \b true if the given storage is unjustified within its parameter container
bool FuncProto::unjustifiedInputParam(const Address &addr,int4 size,VarnodeData &res) const

{
  if (!isDotdotdot()) {		// If the proto is varargs, go straight to the model
    if ((flags&voidinputlock)!=0) return false;
    int4 num = numParams();
    if (num > 0) {
      bool locktest = false;	// Have tested against locked symbol
      for(int4 i=0;i<num;++i) {
	ProtoParameter *param = getParam(i);
	if (!param->isTypeLocked()) continue;
	locktest = true;
	Address iaddr = param->getAddress();
	// If the parameter already exists, test if -addr- -size- is improperly contained in param
	int4 just = iaddr.justifiedContain(param->getSize(),addr,size,false);
	if (just ==0) return false; // Contained but not improperly
	if (just > 0) {
	  res.space = iaddr.getSpace();
	  res.offset = iaddr.getOffset();
	  res.size = param->getSize();
	  return true;
	}
      }
      if (locktest) return false;
    }
  }
  return model->unjustifiedInputParam(addr,size,res);
}

/// \brief Pass-back the biggest input parameter contained within the given range
///
/// \param loc is the starting address of the given range
/// \param size is the number of bytes in the range
/// \param res will hold the parameter storage description being passed back
/// \return \b true if there is at least one parameter contained in the range
bool FuncProto::getBiggestContainedInputParam(const Address &loc,int4 size,VarnodeData &res) const

{
  if (!isDotdotdot()) {		// If the proto is varargs, go straight to the model
    if ((flags&voidinputlock)!=0) return false;
    int4 num = numParams();
    if (num > 0) {
      bool locktest = false;	// Have tested against locked symbol
      res.size = 0;
      for(int4 i=0;i<num;++i) {
	ProtoParameter *param = getParam(i);
	if (!param->isTypeLocked()) continue;
	locktest = true;
	Address iaddr = param->getAddress();
	if (iaddr.containedBy(param->getSize(), loc, size)) {
	  if (param->getSize() > res.size) {
	    res.space = iaddr.getSpace();
	    res.offset = iaddr.getOffset();
	    res.size = param->getSize();
	  }
	}
      }
      if (locktest)
	return (res.size == 0);
    }
  }
  return model->getBiggestContainedInputParam(loc,size,res);
}

/// \brief Decide if \b this can be safely restricted to match another prototype
///
/// Do \b this and another given function prototype share enough of
/// their model, that if we restrict \b this to the other prototype, we know
/// we won't miss data-flow.
/// \param op2 is the other restricting prototype
/// \return \b true if the two prototypes are compatible enough to restrict
bool FuncProto::isCompatible(const FuncProto &op2) const

{
  if (!model->isCompatible(op2.model)) return false;
  if (op2.isOutputLocked()) {
    if (isOutputLocked()) {
      ProtoParameter *out1 = store->getOutput();
      ProtoParameter *out2 = op2.store->getOutput();
      if (*out1 != *out2) return false;
    }
  }
  if ((extrapop != ProtoModel::extrapop_unknown)&&
      (extrapop != op2.extrapop)) return false;
  if (isDotdotdot() != op2.isDotdotdot()) { // Mismatch in varargs
    if (op2.isDotdotdot()) {
      // If -this- is a generic prototype, then the trials
      // are still setup to recover varargs even though
      // the prototype hasn't been marked as varargs
      if (isInputLocked()) return false;
    }
    else 
      return false;
  }

  if (injectid != op2.injectid) return false;
  if ((flags&(is_inline|no_return)) != (op2.flags&(is_inline|no_return)))
    return false;
  if (effectlist.size() != op2.effectlist.size()) return false;
  for(int4 i=0;i<effectlist.size();++i)
    if (effectlist[i] != op2.effectlist[i]) return false;

  if (likelytrash.size() != op2.likelytrash.size()) return false;
  for(int4 i=0;i<likelytrash.size();++i)
    if (likelytrash[i] != op2.likelytrash[i]) return false;
  return true;
}

/// \brief Print \b this prototype as a single line of text
///
/// \param funcname is an identifier of the function using \b this prototype
/// \param s is the output stream
void FuncProto::printRaw(const string &funcname,ostream &s) const

{
  if (model != (ProtoModel *)0)
    s << model->getName() << ' ';
  else
    s << "(no model) ";
  getOutputType()->printRaw(s);
  s << ' ' << funcname << '(';
  int4 num = numParams();
  for(int4 i=0;i<num;++i) {
    if (i != 0)
      s << ',';
    getParam(i)->getType()->printRaw(s);
  }
  if (isDotdotdot()) {
    if (num!=0)
      s << ',';
    s << "...";
  }
  s << ") extrapop=" << dec << extrapop;
}

/// \brief Save \b this to an XML stream as a \<prototype> tag.
///
/// Save everything under the control of this prototype, which
/// may \e not include input parameters, as these are typically
/// controlled by the function's symbol table scope.
/// \param s is the output stream
void FuncProto::saveXml(ostream &s) const

{
  s << " <prototype";
  a_v(s,"model",model->getName());
  if (extrapop == ProtoModel::extrapop_unknown)
    a_v(s,"extrapop","unknown");
  else
    a_v_i(s,"extrapop",extrapop);
  if (isDotdotdot())
    a_v_b(s,"dotdotdot",true);
  if (isModelLocked())
    a_v_b(s,"modellock",true);
  if ((flags&voidinputlock)!=0)
    a_v_b(s,"voidlock",true);
  if (isInline())
    a_v_b(s,"inline",true);
  if (isNoReturn())
    a_v_b(s,"noreturn",true);
  if (hasCustomStorage())
    a_v_b(s,"custom",true);
  if (isConstructor())
    a_v_b(s,"constructor",true);
  if (isDestructor())
    a_v_b(s,"destructor",true);
  s << ">\n";
  ProtoParameter *outparam = store->getOutput();
  s << "  <returnsym";
  if (outparam->isTypeLocked())
    a_v_b(s,"typelock",true);
  s << ">\n   ";
  outparam->getAddress().saveXml(s,outparam->getSize());
  outparam->getType()->saveXml(s);
  s << "  </returnsym>\n";
  if (!effectlist.empty()) {
    int4 othercount = 0;
    s << "  <unaffected>\n";
    for(uint4 i=0;i<effectlist.size();++i) {
      uint4 tp = effectlist[i].getType();
      if (tp!=EffectRecord::unaffected) {
	othercount += 1;
	continue;
      }
      s << "    ";
      effectlist[i].saveXml(s);
      s << '\n';
    }
    s << "  </unaffected>\n";
    if (othercount > 0) {
      othercount = 0;
      s << "  <killedbycall>\n";
      for(uint4 i=0;i<effectlist.size();++i) {
	uint4 tp = effectlist[i].getType();
	if (tp != EffectRecord::killedbycall) {
	  othercount += 1;
	  continue;
	}
	s << "    ";
	effectlist[i].saveXml(s);
	s << '\n';
      }
      s << "  </killedbycall>\n";
    }
    if (othercount > 0) {
      s << "  <returnaddress>\n";
      for(uint4 i=0;i<effectlist.size();++i) {
	uint4 tp = effectlist[i].getType();
	if (tp != EffectRecord::return_address) continue;
	s << "    ";
	effectlist[i].saveXml(s);
	s << '\n';
      }
      s << "  </returnaddress>\n";
    }
  }
  if (!likelytrash.empty()) {
    s << "  <likelytrash>\n";
    for(uint4 i=0;i<likelytrash.size();++i) {
      s << "    <addr";
      const VarnodeData &vdata(likelytrash[i]);
      vdata.space->saveXmlAttributes(s,vdata.offset,vdata.size);
      s << "/>\n";
    }
    s << "  </likelytrash>\n";
  }
  if (injectid >= 0) {
    Architecture *glb = model->getArch();
    s << "  <inject>" << glb->pcodeinjectlib->getCallFixupName(injectid) << "</inject>\n";
  }
  store->saveXml(s);		// Store any internally backed prototyped symbols
  s << " </prototype>\n";
}

/// \brief Restore \b this from an XML stream
///
/// The backing store for the parameters must already be established using either
/// setStore() or setInternal().
/// \param el is the \<prototype> XML element
/// \param glb is the Architecture owning the prototype
void FuncProto::restoreXml(const Element *el,Architecture *glb)

{
  // Model must be set first
  if (store == (ProtoStore *)0)
    throw LowlevelError("Prototype storage must be set before restoring FuncProto");
  ProtoModel *mod = (ProtoModel *)0;
  bool seenextrapop = false;
  bool seenunknownmod = false;
  int4 readextrapop;
  int4 num = el->getNumAttributes();
  flags = 0;
  injectid = -1;
  for(int4 i=0;i<num;++i) {
    const string &attrname( el->getAttributeName(i) );
    if (attrname == "model") {
      const string &modelname( el->getAttributeValue(i) );
      if ((modelname == "default")||(modelname.size()==0))
	mod = glb->defaultfp;	// Get default model
      else if (modelname == "unknown") {
	mod = glb->defaultfp;		// Use the default
	seenunknownmod = true;
      }
      else
	mod = glb->getModel(modelname);
    }
    else if (attrname == "extrapop") {
      seenextrapop = true;
      const string &expopval( el->getAttributeValue(i) );
      if (expopval == "unknown")
	readextrapop = ProtoModel::extrapop_unknown;
      else {
	istringstream i1(expopval);
	i1.unsetf(ios::dec | ios::hex | ios::oct);
	i1 >> readextrapop;
      }
    }
    else if (attrname == "modellock") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= modellock;
    }
    else if (attrname == "dotdotdot") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= dotdotdot;
    }
    else if (attrname == "voidlock") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= voidinputlock;
    }
    else if (attrname == "inline") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= is_inline;
    }
    else if (attrname == "noreturn") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= no_return;
    }
    else if (attrname == "custom") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= custom_storage;
    }
    else if (attrname == "constructor") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= is_constructor;
    }
    else if (attrname == "destructor") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= is_destructor;
    }
  }
  if (mod != (ProtoModel *)0) // If a model was specified
    setModel(mod);		// This sets extrapop to model default
  if (seenextrapop)		// If explicitly set
    extrapop = readextrapop;
  if (seenunknownmod)
    flags |= unknown_model;

  const List &list(el->getChildren());
  List::const_iterator iter = list.begin();

  const Element *subel = (const Element *)0;
  if (iter != list.end()) {
    subel = *iter;
    ++iter;
  }
  if (subel != (const Element *)0) {
    ParameterPieces outpieces;
    bool outputlock = false;

    if (subel->getName() == "returnsym") {
      int4 num = subel->getNumAttributes();
      for(int4 i=0;i<num;++i) {
	const string &attrname( subel->getAttributeName(i) );
	if (attrname == "typelock")
	  outputlock = xml_readbool(subel->getAttributeValue(i));
      }
      const List &list2(subel->getChildren());
      List::const_iterator riter = list2.begin();
      
      int4 tmpsize;
      outpieces.addr = Address::restoreXml(*riter,glb,tmpsize);
      ++riter;
      outpieces.type = glb->types->restoreXmlType(*riter);
      outpieces.flags = 0;
    }
    else if (subel->getName() == "addr") { // Old-style specification of return (supported partially for backward compat)
      int4 tmpsize;
      outpieces.addr = Address::restoreXml(subel,glb,tmpsize);
      outpieces.type = glb->types->restoreXmlType(*iter);
      outpieces.flags = 0;
      ++iter;
    }
    else
      throw LowlevelError("Missing <returnsym> tag");

    store->setOutput(outpieces); // output may be missing storage at this point but ProtoStore should fillin
    store->getOutput()->setTypeLock(outputlock);
  }
  else
    throw LowlevelError("Missing <returnsym> tag");

  if (((flags&voidinputlock)!=0)||(isOutputLocked()))
    flags |= modellock;

  for(;iter!=list.end();++iter) {
    if ((*iter)->getName() == "unaffected") {
      const List &list2((*iter)->getChildren());
      List::const_iterator iter2 = list2.begin();
      while(iter2 != list2.end()) {
	effectlist.emplace_back();
	effectlist.back().restoreXml(EffectRecord::unaffected,*iter2,glb);
	++iter2;
      }
    }
    else if ((*iter)->getName() == "killedbycall") {
      const List &list2((*iter)->getChildren());
      List::const_iterator iter2 = list2.begin();
      while(iter2 != list2.end()) {
	effectlist.emplace_back();
	effectlist.back().restoreXml(EffectRecord::killedbycall,*iter2,glb);
	++iter2;
      }
    }
    else if ((*iter)->getName() == "returnaddress") {
      const List &list2((*iter)->getChildren());
      List::const_iterator iter2 = list2.begin();
      while(iter2 != list2.end()) {
	effectlist.emplace_back();
	effectlist.back().restoreXml(EffectRecord::return_address,*iter2,glb);
	++iter2;
      }
    }
    else if ((*iter)->getName() == "likelytrash") {
      const List &list2((*iter)->getChildren());
      List::const_iterator iter2 = list2.begin();
      while(iter2 != list2.end()) {
	likelytrash.emplace_back();
	likelytrash.back().restoreXml(*iter2,glb);
	++iter2;
      }
    }
    else if ((*iter)->getName() == "inject") {
      injectid = glb->pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE,(*iter)->getContent());
      flags |= is_inline;
    }
    else if ((*iter)->getName() == "internallist") {
      store->restoreXml(*iter,model);
    }
  }
  sort(effectlist.begin(),effectlist.end());
  sort(likelytrash.begin(),likelytrash.end());
  if (!isModelLocked()) {
    if (isInputLocked())
      flags |= modellock;
  }
  if (extrapop == ProtoModel::extrapop_unknown)
    resolveExtraPop();

  ProtoParameter *outparam = store->getOutput();
  if ((outparam->getType()->getMetatype()!=TYPE_VOID)&&outparam->getAddress().isInvalid()) {
    throw LowlevelError("<returnsym> tag must include a valid storage address");
  }
  updateThisPointer();
}

/// \brief Calculate the stack offset of \b this call site
///
/// The given Varnode must be the input to the CALL in the \e placeholder slot
/// and must be defined by a COPY from a Varnode in the stack space.
/// Calculate the offset of the stack-pointer at the point of \b this CALL,
/// relative to the incoming stack-pointer value.  This can be obtained
/// either be looking at a stack parameter, or if there is no stack parameter,
/// the stack-pointer \e placeholder can be used.
/// If the \e placeholder has no other purpose, remove it.
/// \param data is the calling function
/// \param phvn is the Varnode in the \e placeholder slot for \b this CALL
void FuncCallSpecs::resolveSpacebaseRelative(Funcdata &data,Varnode *phvn)

{
  Varnode *refvn = phvn->getDef()->getIn(0);
  AddrSpace *spacebase = refvn->getSpace();
  if (spacebase->getType() != IPTR_SPACEBASE) {
    data.warningHeader("This function may have set the stack pointer");
  }
  stackoffset = refvn->getOffset();

  if (stackPlaceholderSlot >= 0) {
    if (op->getIn(stackPlaceholderSlot) == phvn) {
      data.opRemoveInput(op,stackPlaceholderSlot);
      clearStackPlaceholderSlot();
      return;
    }
  }
  
  if (isInputLocked()) {
    // The prototype is locked and had stack parameters, we grab the relative offset from this
    // rather than from a placeholder
    int4 slot = op->getSlot(phvn)-1;
    if (slot >= numParams())
      throw LowlevelError("Stack placeholder does not line up with locked parameter");
    ProtoParameter *param = getParam(slot);
    Address addr = param->getAddress();
    if (addr.getSpace() != spacebase) {
      if (spacebase->getType() == IPTR_SPACEBASE)
	throw LowlevelError("Stack placeholder does not match locked space");
    }
    stackoffset -= addr.getOffset();
    stackoffset = spacebase->wrapOffset(stackoffset);
    return;
  }
  throw LowlevelError("Unresolved stack placeholder");
}

/// \brief Abort the attempt to recover the relative stack offset for \b this function
///
/// Any stack-pointer \e placeholder is removed.
/// \param data is the calling function
void FuncCallSpecs::abortSpacebaseRelative(Funcdata &data)

{
  if (stackPlaceholderSlot >= 0) {
    data.opRemoveInput(op,stackPlaceholderSlot);
    clearStackPlaceholderSlot();
  }
}

/// \param call_op is the representative call site within the data-flow
FuncCallSpecs::FuncCallSpecs(PcodeOp *call_op)
  : FuncProto(), activeinput(true), activeoutput(true)
{
  effective_extrapop = ProtoModel::extrapop_unknown;
  stackoffset = offset_unknown;
  stackPlaceholderSlot = -1;
  paramshift = 0;
  op = call_op;
  fd = (Funcdata *)0;
  if (call_op->code() == CPUI_CALL) {
    entryaddress = call_op->getIn(0)->getAddr();
    if (entryaddress.getSpace()->getType() == IPTR_FSPEC) {
      // op->getIn(0) was already converted to fspec pointer
      // This can happen if we are cloning an op for inlining
      FuncCallSpecs *otherfc = FuncCallSpecs::getFspecFromConst(entryaddress);
      entryaddress = otherfc->entryaddress;
    }
  }
				// If call is indirect, we leave address as invalid
  isinputactive = false;
  isoutputactive = false;
  isbadjumptable = false;
}

void FuncCallSpecs::setFuncdata(Funcdata *f)

{
  if (fd != (Funcdata *)0)
    throw LowlevelError("Setting call spec function multiple times");
  fd = f;
  if (fd != (Funcdata *)0) {
    entryaddress = fd->getAddress();
    if (fd->getName().size() != 0)
      name = fd->getName();
  }
}

/// \param newop replaces the CALL or CALLIND op in the clone
/// \return the cloned FuncCallSpecs
FuncCallSpecs *FuncCallSpecs::clone(PcodeOp *newop) const

{
  FuncCallSpecs *res = new FuncCallSpecs(newop);
  res->setFuncdata(fd);
  // This sets op, name, address, fd
  res->effective_extrapop = effective_extrapop;
  res->stackoffset = stackoffset;
  res->paramshift = paramshift;
  // We are skipping activeinput, activeoutput
  res->isbadjumptable = isbadjumptable;
  res->copy(*this);		// Copy the FuncProto portion
  return res;
}

/// Find an instance of the stack-pointer (spacebase register) that is active at the
/// point of \b this CALL, by examining the \e stack-pointer \e placeholder slot.
/// \return the stack-pointer Varnode
Varnode *FuncCallSpecs::getSpacebaseRelative(void) const

{
  if (stackPlaceholderSlot<0) return (Varnode *)0;
  Varnode *tmpvn = op->getIn(stackPlaceholderSlot);
  if (!tmpvn->isSpacebasePlaceholder()) return (Varnode *)0;
  if (!tmpvn->isWritten()) return (Varnode *)0;
  PcodeOp *loadop = tmpvn->getDef();
  if (loadop->code() != CPUI_LOAD) return (Varnode *)0;
  return loadop->getIn(1);	// The load input (ptr) is the reference we want
}

/// \brief Build a Varnode representing a specific parameter
///
/// If the Varnode holding the parameter directly as input to the CALL is available,
/// it must be provided to this method.  If it is not available, this assumes an
/// (indirect) stack Varnode is needed and builds one. If the holding Varnode is the
/// correct size it is returned, otherwise a truncated Varnode is constructed.
/// \param data is the calling function
/// \param vn is the Varnode holding the parameter (or NULL for a stack parameter)
/// \param param is the actual parameter description
/// \param stackref is the stack-pointer placeholder for \b this function
/// \return the Varnode that exactly matches the parameter
Varnode *FuncCallSpecs::buildParam(Funcdata &data,Varnode *vn,ProtoParameter *param,Varnode *stackref)

{
  if (vn == (Varnode *)0) { 	// Need to build a spacebase relative varnode
    AddrSpace *spc = param->getAddress().getSpace();
    uintb off = param->getAddress().getOffset();
    int4 sz = param->getSize();
    vn = data.opStackLoad(spc,off,sz,op,stackref,false);
    return vn;
  }
  if (vn->getSize() == param->getSize()) return vn;
  PcodeOp *newop = data.newOp(2,op->getAddr());
  data.opSetOpcode(newop,CPUI_SUBPIECE);
  Varnode *newout = data.newUniqueOut(param->getSize(),newop);
  // Its possible vn is free, in which case the SetInput would give it multiple descendants
  // See we construct a new version
  if (vn->isFree() && !vn->isConstant() && !vn->hasNoDescend())
    vn = data.newVarnode(vn->getSize(),vn->getAddr());
  data.opSetInput(newop,vn,0);
  data.opSetInput(newop,data.newConstant(4,0),1);
  data.opInsertBefore(newop,op);
  return newout;
}

/// \brief Get the index of the CALL input Varnode that matches the given parameter
///
/// This method facilitates the building of a Varnode matching the given parameter
/// from existing data-flow. Return either:
///   - 0      if the Varnode can't be built
///   - slot#  for the input Varnode to reuse
///   - -1     if the parameter needs to be built from the stack
/// \param param is the given parameter to match
/// \return the encoded slot
int4 FuncCallSpecs::transferLockedInputParam(ProtoParameter *param)

{
  int4 numtrials = activeinput.getNumTrials();
  Address startaddr = param->getAddress();
  int4 sz = param->getSize();
  Address lastaddr = startaddr + (sz-1);
  for(int4 i=0;i<numtrials;++i) {
    ParamTrial &curtrial( activeinput.getTrial(i) );
    if (startaddr < curtrial.getAddress()) continue;
    Address trialend = curtrial.getAddress() + (curtrial.getSize() - 1);
    if (trialend < lastaddr) continue;
    if (curtrial.isDefinitelyNotUsed()) return 0;	// Trial has already been stripped
    return curtrial.getSlot();
  }
  if (startaddr.getSpace()->getType() == IPTR_SPACEBASE)
    return -1;
  return 0;
}

/// Return the p-code op whose output Varnode corresponds to the given parameter (return value)
///
/// The Varnode may be attached to the base CALL or CALLIND, but it also may be
/// attached to an INDIRECT preceding the CALL. The output Varnode may not exactly match
/// the dimensions of the given parameter. We return non-null if either:
///    - The parameter contains the Varnode   (the easier case)  OR if
///    - The Varnode properly contains the parameter
/// \param param is the given paramter (return value)
/// \return the matching PcodeOp or NULL
PcodeOp *FuncCallSpecs::transferLockedOutputParam(ProtoParameter *param)

{
  Varnode *vn = op->getOut();
  if (vn != (Varnode *)0) {
    if (param->getAddress().justifiedContain(param->getSize(),vn->getAddr(),vn->getSize(),false)==0)
      return op;
    if (vn->getAddr().justifiedContain(vn->getSize(),param->getAddress(),param->getSize(),false)==0)
      return op;
    return (PcodeOp *)0;
  }
  PcodeOp *indop = op->previousOp();
  while((indop!=(PcodeOp *)0)&&(indop->code()==CPUI_INDIRECT)) {
    if (indop->isIndirectCreation()) {
      vn = indop->getOut();
      if (param->getAddress().justifiedContain(param->getSize(),vn->getAddr(),vn->getSize(),false)==0)
	return indop;
      if (vn->getAddr().justifiedContain(vn->getSize(),param->getAddress(),param->getSize(),false)==0)
	return indop;
    }
    indop = indop->previousOp();
  }
  return (PcodeOp *)0;
}

/// \brief List and/or create a Varnode for each input parameter of \b this prototype
///
/// Varnodes will be passed back in order that match current input parameters.
/// A NULL Varnode indicates a stack parameter. Varnode dimensions may not match
/// parameter dimensions exactly.
/// \param newinput will hold the resulting list of Varnodes
/// \return \b false only if the list needs to indicate stack variables and there is no stack-pointer placeholder
bool FuncCallSpecs::transferLockedInput(vector<Varnode *> &newinput)

{
  newinput.push_back(op->getIn(0)); // Always keep the call destination address
  int4 numparams = numParams();
  Varnode *stackref = (Varnode *)0;
  for(int4 i=0;i<numparams;++i) {
    int4 reuse = transferLockedInputParam(getParam(i));
    if (reuse == 0) return false;
    if (reuse > 0) 
      newinput.push_back(op->getIn(reuse));
    else {
      if (stackref == (Varnode *)0)
	stackref = getSpacebaseRelative();
      if (stackref == (Varnode *)0)
	return false;
      newinput.push_back((Varnode *)0);
    }
  }
  return true;
}

/// \brief Pass back the Varnode needed to match the output parameter (return value)
///
/// Search for the Varnode matching the current output parameter and pass
/// it back. The dimensions of the Varnode may not exactly match the return value.
/// If the return value is e void, a NULL is passed back.
/// \param newoutput will hold the passed back Varnode
/// \return \b true if the passed back value is accurate
bool FuncCallSpecs::transferLockedOutput(Varnode *&newoutput)

{
  ProtoParameter *param = getOutput();
  if (param->getType()->getMetatype() == TYPE_VOID) {
    newoutput = (Varnode *)0;
    return true;
  }
  PcodeOp *outop = transferLockedOutputParam(param);
  if (outop == (PcodeOp *)0)
    newoutput = (Varnode *)0;
  else
    newoutput = outop->getOut();
  return true;
}

/// \brief Update input Varnodes to \b this CALL to reflect the formal input parameters
///
/// The current input parameters must be locked and are presumably out of date
/// with the current state of the CALL Varnodes. These existing input Varnodes must
/// already be gathered in a list. Each Varnode is updated to reflect the parameters,
/// which may involve truncating or extending. Any active trials and stack-pointer
/// placeholder is updated, and the new Varnodes are set as the CALL input.
/// \param data is the calling function
/// \param newinput holds old input Varnodes and will hold new input Varnodes
void FuncCallSpecs::commitNewInputs(Funcdata &data,vector<Varnode *> &newinput)

{
  if (!isInputLocked()) return;
  Varnode *stackref = getSpacebaseRelative();
  Varnode *placeholder = (Varnode *)0;
  if (stackPlaceholderSlot>=0)
    placeholder = op->getIn(stackPlaceholderSlot);
  bool noplacehold = true;

  // Clear activeinput and old placeholder
  stackPlaceholderSlot = -1;
  int4 numPasses = activeinput.getNumPasses();
  activeinput.clear();

  int4 numparams = numParams();
  for(int4 i=0;i<numparams;++i) {
    ProtoParameter *param = getParam(i);
    Varnode *vn = buildParam(data,newinput[1+i],param,stackref);
    newinput[1+i] = vn;
    activeinput.registerTrial(param->getAddress(),param->getSize());
    activeinput.getTrial(i).markActive(); // Parameter is not optional
    if (noplacehold&&(param->getAddress().getSpace()->getType() == IPTR_SPACEBASE)) {
      // We have a locked stack parameter, use it to recover the stack offset
      vn->setSpacebasePlaceholder();
      noplacehold = false;	// Only set this on the first parameter
      placeholder = (Varnode *)0;	// With a locked stack param, we don't need a placeholder
    }
  }
  if (placeholder != (Varnode *)0) {		// If we still need a placeholder
    newinput.push_back(placeholder);		// Add it at end of parameters
    setStackPlaceholderSlot(newinput.size()-1);
  }
  data.opSetAllInput(op,newinput);
  if (!isDotdotdot())		// Unless we are looking for varargs
    clearActiveInput();		// turn off parameter recovery (we are locked and have all our varnodes)
  else {
    if (numPasses > 0)
      activeinput.finishPass();		// Don't totally reset the pass counter
  }
}

/// \brief Update output Varnode to \b this CALL to reflect the formal return value
///
/// The current return value must be locked and is presumably out of date
/// with the current CALL output. Unless the return value is \e void, the
/// output Varnode must exist and must be provided.
/// The Varnode is updated to reflect the return value,
/// which may involve truncating or extending. Any active trials are updated,
/// and the new Varnode is set as the CALL output.
/// \param data is the calling function
/// \param newout is the provided old output Varnode (or NULL)
void FuncCallSpecs::commitNewOutputs(Funcdata &data,Varnode *newout)

{
  if (!isOutputLocked()) return;
  activeoutput.clear();

  if (newout != (Varnode *)0) {
    ProtoParameter *param = getOutput();
    // We could conceivably truncate the output to the correct size to match the parameter
    activeoutput.registerTrial(param->getAddress(),param->getSize());
    PcodeOp *indop = newout->getDef();
    if (newout->getSize() == param->getSize()) {
      if (indop != op) {
	data.opUnsetOutput(indop);
	data.opUnlink(indop);	// We know this is an indirect creation which is no longer used
	// If we reach here, we know -op- must have no output
	data.opSetOutput(op,newout);
      }
    }
    else if (newout->getSize() < param->getSize()) {
      // We know newout is properly justified within param
      if (indop != op) {
	data.opUninsert(indop);
	data.opSetOpcode(indop,CPUI_SUBPIECE);
      }
      else {
	indop = data.newOp(2,op->getAddr());
	data.opSetOpcode(indop,CPUI_SUBPIECE);
	data.opSetOutput(indop,newout);	// Move -newout- from -op- to -indop-
      }
      Varnode *realout = data.newVarnodeOut(param->getSize(),param->getAddress(),op);
      data.opSetInput(indop,realout,0);
      data.opSetInput(indop,data.newConstant(4,0),1);
      data.opInsertAfter(indop,op);
    }
    else {			// param->getSize() < newout->getSize()
      // We know param is justified contained in newout
      VarnodeData vardata;
      // Test whether the new prototype naturally extends its output
      OpCode opc = assumedOutputExtension(param->getAddress(),param->getSize(),vardata);
      Address hiaddr = newout->getAddr();
      if (opc != CPUI_COPY) {
	// If -newout- looks like a natural extension of the true output type, create the extension op
	if (opc == CPUI_PIECE) {	// Extend based on the datatype
	  if (param->getType()->getMetatype() == TYPE_INT)
	    opc = CPUI_INT_SEXT;
	  else
	    opc = CPUI_INT_ZEXT;
	}
	if (indop != op) {
	  data.opUninsert(indop);
	  data.opRemoveInput(indop,1);
	  data.opSetOpcode(indop,opc);
	  Varnode *outvn = data.newVarnodeOut(param->getSize(),param->getAddress(),op);
	  data.opSetInput(indop,outvn,0);
	  data.opInsertAfter(indop,op);
	}
	else {
	  PcodeOp *extop = data.newOp(1,op->getAddr());
	  data.opSetOpcode(extop,opc);
	  data.opSetOutput(extop,newout);	// Move newout from -op- to -extop-
	  Varnode *outvn = data.newVarnodeOut(param->getSize(),param->getAddress(),op);
	  data.opSetInput(extop,outvn,0);
	  data.opInsertAfter(extop,op);
	}
      }
      else {	// If all else fails, concatenate in extra byte from something "indirectly created" by -op-
	int4 hisz = newout->getSize() - param->getSize();
	if (!newout->getAddr().getSpace()->isBigEndian())
	  hiaddr = hiaddr + param->getSize();
	PcodeOp *newindop = data.newIndirectCreation(op,hiaddr,hisz,true);
	if (indop != op) {
	  data.opUninsert(indop);
	  data.opSetOpcode(indop,CPUI_PIECE);
	  Varnode *outvn = data.newVarnodeOut(param->getSize(),param->getAddress(),op);
	  data.opSetInput(indop,newindop->getOut(),0);
	  data.opSetInput(indop,outvn,1);
	  data.opInsertAfter(indop,op);
	}
	else {
	  PcodeOp *concatop = data.newOp(2,op->getAddr());
	  data.opSetOpcode(concatop,CPUI_PIECE);
	  data.opSetOutput(concatop,newout); // Move newout from -op- to -concatop-
	  Varnode *outvn = data.newVarnodeOut(param->getSize(),param->getAddress(),op);
	  data.opSetInput(concatop,newindop->getOut(),0);
	  data.opSetInput(concatop,outvn,1);
	  data.opInsertAfter(concatop,op);
	}
      }
    }
  }
  clearActiveOutput();
}

void FuncCallSpecs::initActiveInput(void)

{
  isinputactive = true;
  int4 maxdelay = getMaxInputDelay();
  if (maxdelay > 0)
    maxdelay = 3;
  activeinput.setMaxPass(maxdelay);
}

/// \brief Check if adjacent parameter trials can be combined into a single logical parameter
///
/// A slot must be provided indicating the trial and the only following it.
/// \param slot1 is the first trial slot
/// \param ishislot is \b true if the first slot will be the most significant piece
/// \param vn1 is the Varnode corresponding to the first trial
/// \param vn2 is the Varnode corresponding to the second trial
/// \return \b true if the trials can be combined
bool FuncCallSpecs::checkInputJoin(int4 slot1,bool ishislot,Varnode *vn1,Varnode *vn2) const

{
  if (isInputActive()) return false;
  if (slot1 >= activeinput.getNumTrials()) return false; // Not enough params
  const ParamTrial *hislot,*loslot;
  if (ishislot) {		// slot1 looks like the high slot
    hislot = &activeinput.getTrialForInputVarnode(slot1);
    loslot = &activeinput.getTrialForInputVarnode(slot1+1);
    if (hislot->getSize() != vn1->getSize()) return false;
    if (loslot->getSize() != vn2->getSize()) return false;
  }
  else {
    loslot = &activeinput.getTrialForInputVarnode(slot1);
    hislot = &activeinput.getTrialForInputVarnode(slot1+1);
    if (loslot->getSize() != vn1->getSize()) return false;
    if (hislot->getSize() != vn2->getSize()) return false;
  }
  return FuncProto::checkInputJoin(hislot->getAddress(),hislot->getSize(),loslot->getAddress(),loslot->getSize());
}

/// \brief Join two parameter trials
///
/// We assume checkInputJoin() has returned \b true. Perform the join, replacing
/// the given adjacent trials with a single merged parameter.
/// \param slot1 is the trial slot of the first trial
/// \param ishislot is \b true if the first slot will be the most significant piece
void FuncCallSpecs::doInputJoin(int4 slot1,bool ishislot)

{
  if (isInputLocked())
    throw LowlevelError("Trying to join parameters on locked function prototype");

  const ParamTrial &trial1( activeinput.getTrialForInputVarnode(slot1) );
  const ParamTrial &trial2( activeinput.getTrialForInputVarnode(slot1+1) );

  const Address &addr1( trial1.getAddress() );
  const Address &addr2( trial2.getAddress() );
  Architecture *glb = getArch();
  Address joinaddr;
  if (ishislot)
    joinaddr = glb->constructJoinAddress(glb->translate,addr1,trial1.getSize(),addr2,trial2.getSize());
  else
    joinaddr = glb->constructJoinAddress(glb->translate,addr2,trial2.getSize(),addr1,trial1.getSize());

  activeinput.joinTrial(slot1,joinaddr,trial1.getSize()+trial2.getSize());
}

/// \brief Update \b this prototype to match a given (more specialized) prototype
///
/// This method assumes that \b this prototype is in some intermediate state during the
/// parameter recovery process and that a new definitive (locked) prototype is discovered
/// for \b this call site.  This method checks to see if \b this can be updated to match the
/// new prototype without missing any data-flow.  If so, \b this is updated, and new input
/// and output Varnodes for the CALL are passed back.
/// \param restrictedProto is the new definitive function prototype
/// \param newinput will hold the new list of input Varnodes for the CALL
/// \param newoutput will hold the new output Varnode or NULL
/// \return \b true if \b this can be fully converted
bool FuncCallSpecs::lateRestriction(const FuncProto &restrictedProto,vector<Varnode *> &newinput,Varnode *&newoutput)

{
  if (!hasModel()) {
    copy(restrictedProto);
    return true;
  }

  if (!isCompatible(restrictedProto)) return false;
  copy(restrictedProto);		// Convert ourselves to restrictedProto
  //  if (!isInputLocked()) return false;
  if (isDotdotdot() && (!isinputactive)) return false;

  // Redo all the varnode inputs (if possible)
  if (isInputLocked())
    if (!transferLockedInput(newinput)) return false;
  // Redo all the varnode outputs (if possible)
  if (isOutputLocked())
    if (!transferLockedOutput(newoutput)) return false;

  return true;
}

/// \brief Convert \b this call site from an indirect to a direct function call
///
/// This call site must be a CALLIND, and the function that it is actually calling
/// must be provided.  The method makes a determination if the current
/// state of data-flow allows converting to the prototype of the new function without
/// dropping information due to inaccurate dead-code elimination.  If conversion is
/// safe, it is performed immediately. Otherwise a \e restart directive issued to
/// force decompilation to restart from scratch (now with the direct function in hand)
/// \param data is the calling function
/// \param newfd is the Funcdata object that we know is the destination of \b this CALLIND
void FuncCallSpecs::deindirect(Funcdata &data,Funcdata *newfd)

{
  entryaddress = newfd->getAddress();
  name = newfd->getName();
  fd = newfd;

  Varnode *vn = data.newVarnodeCallSpecs(this);
  data.opSetInput(op,vn,0);
  data.opSetOpcode(op,CPUI_CALL);
  if (isOverride())	// If we are overridden at the call-site
    return;		// Don't use the discovered function prototype

  // Try our best to merge existing prototype
  // with the one we have just been handed
  vector<Varnode *> newinput;
  Varnode *newoutput;
  FuncProto &newproto( newfd->getFuncProto() );
  if ((!newproto.isNoReturn())&&(!newproto.isInline())&&
      lateRestriction(newproto,newinput,newoutput)) {
    commitNewInputs(data,newinput);
    commitNewOutputs(data,newoutput);
  }
  else {
    data.getOverride().insertIndirectOverride(op->getAddr(),entryaddress);
    data.setRestartPending(true);
  }
}

/// \brief Force a more restrictive prototype on \b this call site
///
/// A new prototype must be given, typically recovered from a function pointer
/// data-type that has been propagated to \b this call site.
/// The method makes a determination if the current
/// state of data-flow allows converting to the new prototype without
/// dropping information due to inaccurate dead-code elimination.  If conversion is
/// safe, it is performed immediately. Otherwise a \e restart directive issued to
/// force decompilation to restart from scratch (now with the new prototype in hand)
/// \param data is the calling function
/// \param fp is the new (more restrictive) function prototype
void FuncCallSpecs::forceSet(Funcdata &data,const FuncProto &fp)

{
  vector<Varnode *> newinput;
  Varnode *newoutput;
  if (lateRestriction(fp,newinput,newoutput)) {
    commitNewInputs(data,newinput);
    commitNewOutputs(data,newoutput);
  }
  else {
    // Too late to make restrictions to correct prototype
    // Add a restart override with the forcing prototype
    FuncProto *newproto = new FuncProto();
    newproto->copy(fp);
    data.getOverride().insertProtoOverride(op->getAddr(),newproto);
    data.setRestartPending(true);
  }
  // Regardless of what happened, lock the prototype so it doesn't happen again
  setInputLock(true);
  setInputErrors(fp.hasInputErrors());
  setOutputErrors(fp.hasOutputErrors());
}

/// \brief Inject any \e upon-return p-code at \b this call site
///
/// This function prototype may trigger injection of p-code immediately after
/// the CALL or CALLIND to mimic a portion of the callee that decompilation
/// of the caller otherwise wouldn't see.
/// \param data is the calling function
void FuncCallSpecs::insertPcode(Funcdata &data)

{
  int4 injectid = getInjectUponReturn();
  if (injectid < 0) return;		// Nothing to inject
  InjectPayload *payload = data.getArch()->pcodeinjectlib->getPayload(injectid);

  // do the insertion right after the callpoint
  list<PcodeOp *>::iterator iter = op->getBasicIter();
  ++iter;
  data.doLiveInject(payload,op->getAddr(),op->getParent(),iter);
}

/// Collect Varnode objects associated with each output trial
///
/// Varnodes can be attached to the CALL or CALLIND or one of the
/// preceding INDIRECTs. They are passed back in a list matching the
/// order of the trials.
/// \param trialvn holds the resulting list of Varnodes
void FuncCallSpecs::collectOutputTrialVarnodes(vector<Varnode *> &trialvn)

{
  if (op->getOut() != (Varnode *)0)
    throw LowlevelError("Output of call was determined prematurely");
  while(trialvn.size() < activeoutput.getNumTrials()) // Size of array should match number of trials
    trialvn.push_back((Varnode *)0);
  PcodeOp *indop = op->previousOp();
  while(indop != (PcodeOp *)0) {
    if (indop->code() != CPUI_INDIRECT) break;
    if (indop->isIndirectCreation()) {
      Varnode *vn = indop->getOut();
      int4 index = activeoutput.whichTrial(vn->getAddr(),vn->getSize());
      if (index >= 0) {
	trialvn[index] = vn;
	// the exact varnode may have changed, so we reset the trial
	activeoutput.getTrial(index).setAddress(vn->getAddr(),vn->getSize());
      }
    }
    indop = indop->previousOp();
  }
}

/// \brief Make final activity check on trials that might have been affected by conditional execution
///
/// The activity level a trial may change once conditional execution has been analyzed.
/// This routine (re)checks trials that might be affected by this, which may then
/// be converted to \e not \e used.
void FuncCallSpecs::finalInputCheck(void)

{
  AncestorRealistic ancestorReal;
  for(int4 i=0;i<activeinput.getNumTrials();++i) {
    ParamTrial &trial(activeinput.getTrial(i));
    if (!trial.isActive()) continue;
    if (!trial.hasCondExeEffect()) continue;
    int4 slot = trial.getSlot();
    if (!ancestorReal.execute(op,slot,&trial,false))
      trial.markNoUse();
  }
}

/// \brief Mark if input trials are being actively used
///
/// Run through each input trial and try to make a determination if the trial is \e active or not,
/// meaning basically that a write has occurred on the trial with no intervening reads between
/// the write and the call.
/// \param data is the calling function
/// \param aliascheck holds local aliasing information about the function
void FuncCallSpecs::checkInputTrialUse(Funcdata &data,AliasChecker &aliascheck)

{
  if (op->isDead())
    throw LowlevelError("Function call in dead code");

  int4 maxancestor = data.getArch()->trim_recurse_max;
  bool callee_pop = false;
  int4 extrapop = 0;
  if (hasModel()) {
    callee_pop = (getModelExtraPop() == ProtoModel::extrapop_unknown);
    if (callee_pop) {		
      extrapop = getExtraPop();
      // Tried to use getEffectiveExtraPop at one point, but it is too unreliable
      if ((extrapop==ProtoModel::extrapop_unknown)||(extrapop <=4))
	callee_pop = false;
      // If the subfunctions do their own parameter popping and
      // if the extrapop is successfully recovered this is hard evidence
      // about which trials are active
      // If the extrapop is 4, this might be a _cdecl convention, and doesn't necessarily mean
      // that there are no parameters
    }
  }

  AncestorRealistic ancestorReal;
  for(int4 i=0;i<activeinput.getNumTrials();++i) {
    ParamTrial &trial(activeinput.getTrial(i));
    if (trial.isChecked()) continue;
    int4 slot = trial.getSlot();
    Varnode *vn = op->getIn(slot);
    if (vn->getSpace()->getType() == IPTR_SPACEBASE) {
      if (aliascheck.hasLocalAlias(vn))
	trial.markNoUse();
      else if (!data.getFuncProto().getLocalRange().inRange(vn->getAddr(),1))
	trial.markNoUse();
      else if (callee_pop) {
	if ((int4)(trial.getAddress().getOffset() + (trial.getSize()-1)) < extrapop)
	  trial.markActive();
	else
	  trial.markNoUse();
      }
      else if (ancestorReal.execute(op,slot,&trial,false)) {
	if (data.ancestorOpUse(maxancestor,vn,op,trial,0))
	  trial.markActive();
	else
	  trial.markInactive();
      }
      else
	trial.markNoUse(); // Stackvar for unrealistic ancestor is definitely not a parameter
    }
    else {
      if (ancestorReal.execute(op,slot,&trial,true)) {
	if (data.ancestorOpUse(maxancestor,vn,op,trial,0)) {
	  trial.markActive();
	  if (trial.hasCondExeEffect())
	    activeinput.markNeedsFinalCheck();
	}
	else
	  trial.markInactive();
      }
      else if (vn->isInput())	// Not likely a parameter but maybe
	trial.markInactive();
      else
	trial.markNoUse();	// An ancestor is unaffected, an unusual input, or killed by a call
    }
    if (trial.isDefinitelyNotUsed())	// If definitely not used, free up the dataflow
      data.opSetInput(op,data.newConstant(vn->getSize(),0),slot);
  }
}

/// \brief Mark if output trials are being actively used
///
/// Run through each output trial and try to make a determination if the trial is \e active or not,
/// meaning basically that the first occurrence of a trial after the call is a read.
/// \param data is the calling function
/// \param trialvn will hold Varnodes corresponding to the trials
void FuncCallSpecs::checkOutputTrialUse(Funcdata &data,vector<Varnode *> &trialvn)

{
  collectOutputTrialVarnodes(trialvn);
  // The location is either used or not.  If it is used it can either be the official output
  // or a killedbycall, so whether the trial is present as a varnode (as determined by dataflow
  // and deadcode analysis) determines whether we consider the trial active or not
  for(int4 i=0;i<trialvn.size();++i) {
    ParamTrial &curtrial(activeoutput.getTrial(i));
    if (curtrial.isChecked())
      throw LowlevelError("Output trial has been checked prematurely");
    if (trialvn[i] != (Varnode *)0)
      curtrial.markActive();
    else
      curtrial.markInactive(); // don't call markNoUse, the value may be returned but not used
  }
}

/// \brief Set the final input Varnodes to \b this CALL based on ParamActive analysis
///
/// Varnodes that don't look like parameters are removed. Parameters that are unreferenced
/// are filled in. Other Varnode inputs may be truncated or extended.  This prototype
/// itself is unchanged.
/// \param data is the calling function
void FuncCallSpecs::buildInputFromTrials(Funcdata &data)

{
  AddrSpace *spc;
  uintb off;
  int4 sz;
  bool isspacebase;
  Varnode *vn;
  vector<Varnode *> newparam;
  
  newparam.push_back(op->getIn(0)); // Preserve the fspec parameter

  for(int4 i=0;i<activeinput.getNumTrials();++i) {
    const ParamTrial &paramtrial( activeinput.getTrial(i) );
    if (!paramtrial.isUsed()) continue; // Don't keep unused parameters
    sz = paramtrial.getSize();
    isspacebase = false;
    const Address &addr(paramtrial.getAddress());
    spc = addr.getSpace();
    off = addr.getOffset();
    if (spc->getType() == IPTR_SPACEBASE) {
      isspacebase = true;
      off = spc->wrapOffset(stackoffset + off);	// Translate the parameter address relative to caller's spacebase
    }
    if (paramtrial.isUnref()) {	// recovered unreferenced address as part of prototype
      vn = data.newVarnode(sz,Address(spc,off)); // We need to create the varnode
    }
    else {
      vn = op->getIn(paramtrial.getSlot()); // Where parameter is currently
      if (vn->getSize() > sz) {	// Varnode is bigger than type
	Varnode *outvn;	// Create truncate op
	PcodeOp *newop = data.newOp(2,op->getAddr());
	if (data.getArch()->translate->isBigEndian())
	  outvn = data.newVarnodeOut(sz,vn->getAddr()+(vn->getSize()-sz),newop);
	else
	  outvn = data.newVarnodeOut(sz,vn->getAddr(),newop);
	data.opSetOpcode(newop,CPUI_SUBPIECE);
	data.opSetInput(newop,vn,0);
	data.opSetInput(newop,data.newConstant(1,0),1);
	data.opInsertBefore(newop,op);
	vn = outvn;
      }
    }
    newparam.push_back(vn);
    // Mark the stack range used to pass this parameter as unmapped
    if (isspacebase)
      data.getScopeLocal()->markNotMapped(spc,off,sz,true);
  }
  data.opSetAllInput(op,newparam); // Set final parameter list
  activeinput.deleteUnusedTrials();
}

/// \brief Check if given two Varnodes are merged into a whole
///
/// If the Varnodes are merged immediately into a common whole
/// and aren't used for anything else, return the whole Varnode.
/// \param vn1 is the first given Varnode
/// \param vn2 is the second given Varnode
/// \return the combined Varnode or NULL
Varnode *FuncCallSpecs::findPreexistingWhole(Varnode *vn1,Varnode *vn2)

{
  PcodeOp *op1 = vn1->loneDescend();
  if (op1 == (PcodeOp *)0) return (Varnode *)0;
  PcodeOp *op2 = vn2->loneDescend();
  if (op2 == (PcodeOp *)0) return (Varnode *)0;
  if (op1 != op2) return (Varnode *)0;
  if (op1->code() != CPUI_PIECE) return (Varnode *)0;
  return op1->getOut();
}

/// \brief Set the final output Varnode of \b this CALL based on ParamActive analysis of trials
///
/// If it exists, the active output trial is moved to be the output Varnode of \b this CALL.
/// If there are two active trials, they are merged as a single output of the CALL.
/// Any INDIRECT ops that were holding the active trials are removed.
/// This prototype itself is unchanged.
/// \param data is the calling function
/// \param trialvn is the list of Varnodes associated with trials
void FuncCallSpecs::buildOutputFromTrials(Funcdata &data,vector<Varnode *> &trialvn)

{
  Varnode *finaloutvn;
  vector<Varnode *> finalvn;

  for(int4 i=0;i<activeoutput.getNumTrials();++i) { // Reorder the varnodes
    ParamTrial &curtrial(activeoutput.getTrial(i));
    if (!curtrial.isUsed()) break;
    Varnode *vn = trialvn[ curtrial.getSlot() - 1];
    finalvn.push_back(vn);
  }
  activeoutput.deleteUnusedTrials(); // This deletes unused, and renumbers used  (matches finalvn)
  if (activeoutput.getNumTrials()==0) return; // Nothing is a formal output

  vector<PcodeOp *> deletedops;

  if (activeoutput.getNumTrials()==1) {		// We have a single, properly justified output
    finaloutvn = finalvn[0];
    PcodeOp *indop = finaloutvn->getDef();
//     ParamTrial &curtrial(activeoutput.getTrial(0));
//     if (finaloutvn->getSize() != curtrial.getSize()) { // If the varnode does not exactly match the original trial
//       int4 res = curtrial.getEntry()->justifiedContain(finaloutvn->getAddress(),finaloutvn->getSize());
//       if (res > 0) {
// 	data.opUninsert(indop);
// 	data.opSetOpcode(indop,CPUI_SUBPIECE); // Insert a subpiece
// 	Varnode *wholevn = data.newVarnodeOut(curtrial.getSize(),curtrial.getAddress(),op);
// 	data.opSetInput(indop,wholevn,0);
// 	data.opSetInput(indop,data.newConstant(4,res),1);
// 	data.opInsertAfter(indop,op);
// 	return;
//       }
//     }
    deletedops.push_back(indop);
    data.opSetOutput(op,finaloutvn); // Move varnode to its new position as output of call
  }
  else if (activeoutput.getNumTrials()==2) {
    Varnode *hivn = finalvn[1];	// orderOutputPieces puts hi last
    Varnode *lovn = finalvn[0];
    if (data.isDoublePrecisOn()) {
      lovn->setPrecisLo();	// Mark that these varnodes are part of a larger precision whole
      hivn->setPrecisHi();
    }
    deletedops.push_back(hivn->getDef());
    deletedops.push_back(lovn->getDef());
    finaloutvn = findPreexistingWhole(hivn,lovn);
    if (finaloutvn == (Varnode *)0) {
      Address joinaddr = data.getArch()->constructJoinAddress(data.getArch()->translate,
							      hivn->getAddr(),hivn->getSize(),
							      lovn->getAddr(),lovn->getSize());
      finaloutvn = data.newVarnode(hivn->getSize()+lovn->getSize(),joinaddr);
      data.opSetOutput(op,finaloutvn);
      PcodeOp *sublo = data.newOp(2,op->getAddr());
      data.opSetOpcode(sublo,CPUI_SUBPIECE);
      data.opSetInput(sublo,finaloutvn,0);
      data.opSetInput(sublo,data.newConstant(4,0),1);
      data.opSetOutput(sublo,lovn);
      data.opInsertAfter(sublo,op);
      PcodeOp *subhi = data.newOp(2,op->getAddr());
      data.opSetOpcode(subhi,CPUI_SUBPIECE);
      data.opSetInput(subhi,finaloutvn,0);
      data.opSetInput(subhi,data.newConstant(4,lovn->getSize()),1);
      data.opSetOutput(subhi,hivn);
      data.opInsertAfter(subhi,op);
    }
    else {			// Preexisting whole
      deletedops.push_back(finaloutvn->getDef()); // Its inputs are used only in this op
      data.opSetOutput(op,finaloutvn);
    }
  }
  else
    return;

  for(int4 i=0;i<deletedops.size();++i) { // Destroy the original INDIRECT ops
    PcodeOp *dop = deletedops[i];
    Varnode *in0 = dop->getIn(0);
    Varnode *in1 = dop->getIn(1);
    data.opDestroy(dop);
    if (in0 != (Varnode *)0)
      data.deleteVarnode(in0);
    if (in1 != (Varnode *)0)
      data.deleteVarnode(in1);
  }
}

/// \brief Get the estimated number of bytes within the given parameter that are consumed
///
/// As a function is decompiled, there may hints about how many of the bytes, within the
/// storage location used to pass the parameter, are used by \b this sub-function. A non-zero
/// value means that that many least significant bytes of the storage location are used. A value
/// of zero means all bytes are presumed used.
/// \param slot is the slot of the given input parameter
/// \return the number of bytes used (or 0)
int4 FuncCallSpecs::getInputBytesConsumed(int4 slot) const

{
  if (slot >= inputConsume.size())
    return 0;
  return inputConsume[slot];
}

/// \brief Set the estimated number of bytes within the given parameter that are consumed
///
/// This provides a hint to the dead code \e consume algorithm, while examining the calling
/// function, about how the given parameter within the subfunction is used.
/// A non-zero value means that that many least significant bytes of the storage location
/// are used. A value of zero means all bytes are presumed used.
/// \param slot is the slot of the given input parameter
/// \param val is the number of bytes consumed (or 0)
/// \return \b true if there was a change in the estimate
bool FuncCallSpecs::setInputBytesConsumed(int4 slot,int4 val) const

{
  while(inputConsume.size() <= slot)
    inputConsume.push_back(0);
  int4 oldVal = inputConsume[slot];
  if (oldVal == 0 || val < oldVal)
    inputConsume[slot] = val;
  return (oldVal != val);
}

/// \brief Prepend any extra parameters if a paramshift is required
void FuncCallSpecs::paramshiftModifyStart(void)

{
  if (paramshift==0) return;
  paramShift(paramshift);
}

/// \brief Throw out any paramshift parameters
/// \param data is the calling function
/// \return \b true if a change was made
bool FuncCallSpecs::paramshiftModifyStop(Funcdata &data)

{
  if (paramshift == 0) return false;
  if (isParamshiftApplied()) return false;
  setParamshiftApplied(true);
  if (op->numInput() < paramshift + 1)
    throw LowlevelError("Paramshift mechanism is confused");
  for(int4 i=0;i<paramshift;++i) {
    // ProtoStore should have been converted to ProtoStoreInternal by paramshiftModifyStart
    data.opRemoveInput(op,1);
    removeParam(0);
  }
  return true;
}

/// \brief Calculate type of side-effect for a given storage location (with caller translation)
///
/// Stack locations should be provided from the caller's perspective.  They are automatically
/// translated to the callee's perspective before making the underlying query.
/// \param addr is the starting address of the storage location
/// \param size is the number of bytes in the storage
/// \return the effect type
uint4 FuncCallSpecs::hasEffectTranslate(const Address &addr,int4 size) const

{
  AddrSpace *spc = addr.getSpace();
  if (spc->getType() != IPTR_SPACEBASE)
    return hasEffect(addr,size);
  if (stackoffset == offset_unknown) return EffectRecord::unknown_effect;
  uintb newoff = spc->wrapOffset(addr.getOffset()-stackoffset);	// Translate to callee's spacebase point of view
  return hasEffect(Address(spc,newoff),size);
}

/// \brief Calculate the number of times an individual sub-function is called.
///
/// Provided a list of all call sites for a calling function, tally the number of calls
/// to the same sub-function.  Update the \b matchCallCount field of each FuncCallSpecs
/// \param qlst is the list of call sites (FuncCallSpecs) for the calling function
void FuncCallSpecs::countMatchingCalls(const vector<FuncCallSpecs *> &qlst)

{
  vector<FuncCallSpecs *> copyList(qlst);
  sort(copyList.begin(),copyList.end(),compareByEntryAddress);
  int4 i;
  for(i=0;i<copyList.size();++i) {
    if (!copyList[i]->entryaddress.isInvalid()) break;
    copyList[i]->matchCallCount = 1;			// Mark all invalid addresses as a singleton
  }
  if (i == copyList.size()) return;
  Address lastAddr = copyList[i]->entryaddress;
  int4 lastChange = i++;
  int4 num;
  for(;i<copyList.size();++i) {
    if (copyList[i]->entryaddress == lastAddr) continue;
    num = i - lastChange;
    for(;lastChange<i;++lastChange)
      copyList[lastChange]->matchCallCount = num;
    lastAddr = copyList[i]->entryaddress;
  }
  num = i - lastChange;
  for(;lastChange<i;++lastChange)
    copyList[lastChange]->matchCallCount = num;
}

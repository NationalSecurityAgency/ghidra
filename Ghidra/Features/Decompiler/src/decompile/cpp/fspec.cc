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

namespace ghidra {

AttributeId ATTRIB_CUSTOM = AttributeId("custom",114);
AttributeId ATTRIB_DOTDOTDOT = AttributeId("dotdotdot",115);
AttributeId ATTRIB_EXTENSION = AttributeId("extension",116);
AttributeId ATTRIB_HASTHIS = AttributeId("hasthis",117);
AttributeId ATTRIB_INLINE = AttributeId("inline",118);
AttributeId ATTRIB_KILLEDBYCALL = AttributeId("killedbycall",119);
AttributeId ATTRIB_MAXSIZE = AttributeId("maxsize",120);
AttributeId ATTRIB_MINSIZE = AttributeId("minsize",121);
AttributeId ATTRIB_MODELLOCK = AttributeId("modellock",122);
AttributeId ATTRIB_NORETURN = AttributeId("noreturn",123);
AttributeId ATTRIB_POINTERMAX = AttributeId("pointermax",124);
AttributeId ATTRIB_SEPARATEFLOAT = AttributeId("separatefloat",125);
AttributeId ATTRIB_STACKSHIFT = AttributeId("stackshift",126);
AttributeId ATTRIB_STRATEGY = AttributeId("strategy",127);
AttributeId ATTRIB_THISBEFORERETPOINTER = AttributeId("thisbeforeretpointer",128);
AttributeId ATTRIB_VOIDLOCK = AttributeId("voidlock",129);

ElementId ELEM_GROUP = ElementId("group",160);
ElementId ELEM_INTERNALLIST = ElementId("internallist",161);
ElementId ELEM_KILLEDBYCALL = ElementId("killedbycall",162);
ElementId ELEM_LIKELYTRASH = ElementId("likelytrash",163);
ElementId ELEM_LOCALRANGE = ElementId("localrange",164);
ElementId ELEM_MODEL = ElementId("model",165);
ElementId ELEM_PARAM = ElementId("param",166);
ElementId ELEM_PARAMRANGE = ElementId("paramrange",167);
ElementId ELEM_PENTRY = ElementId("pentry",168);
ElementId ELEM_PROTOTYPE = ElementId("prototype",169);
ElementId ELEM_RESOLVEPROTOTYPE = ElementId("resolveprototype",170);
ElementId ELEM_RETPARAM = ElementId("retparam",171);
ElementId ELEM_RETURNSYM = ElementId("returnsym",172);
ElementId ELEM_UNAFFECTED = ElementId("unaffected",173);
ElementId ELEM_INTERNAL_STORAGE = ElementId("internal_storage",286);

/// \brief Find a ParamEntry matching the given storage Varnode
///
/// Search through the list backward.
/// \param entryList is the list of ParamEntry to search through
/// \param vn is the storage to search for
/// \return the matching ParamEntry or null
const ParamEntry *ParamEntry::findEntryByStorage(const list<ParamEntry> &entryList,const VarnodeData &vn)

{
  list<ParamEntry>::const_reverse_iterator iter = entryList.rbegin();
  for(;iter!=entryList.rend();++iter) {
    const ParamEntry &entry(*iter);
    if (entry.spaceid == vn.space && entry.addressbase == vn.offset && entry.size == vn.size) {
      return &entry;
    }
  }
  return (const ParamEntry *)0;
}

/// Check previous ParamEntry, if it exists, and compare storage class.
/// If it is different, this is the first, and its flag gets set.
/// \param curList is the list of previous ParamEntry
void ParamEntry::resolveFirst(list<ParamEntry> &curList)

{
  list<ParamEntry>::const_iterator iter = curList.end();
  --iter;
  if (iter == curList.begin()) {
    flags |= first_storage;
    return;
  }
  --iter;
  if (type != (*iter).type) {
    flags |= first_storage;
  }
}

/// If the ParamEntry is initialized with a \e join address, cache the join record and
/// adjust the group and groupsize based on the ParamEntrys being overlapped
/// \param curList is the current list of ParamEntry
void ParamEntry::resolveJoin(list<ParamEntry> &curList)

{
  if (spaceid->getType() != IPTR_JOIN) {
    joinrec = (JoinRecord *)0;
    return;
  }
  joinrec = spaceid->getManager()->findJoin(addressbase);
  groupSet.clear();
  for(int4 i=0;i<joinrec->numPieces();++i) {
    const ParamEntry *entry = findEntryByStorage(curList, joinrec->getPiece(i));
    if (entry != (const ParamEntry *)0) {
      groupSet.insert(groupSet.end(),entry->groupSet.begin(),entry->groupSet.end());
      // For output <pentry>, if the most signifigant part overlaps with an earlier <pentry>
      // the least signifigant part is marked for extra checks, and vice versa.
      flags |= (i==0) ? extracheck_low : extracheck_high;
    }
  }
  if (groupSet.empty())
    throw LowlevelError("<pentry> join must overlap at least one previous entry");
  sort(groupSet.begin(),groupSet.end());
  flags |= overlapping;
}

/// Search for overlaps of \b this with any previous entry.  If an overlap is discovered,
/// verify the form is correct for the different ParamEntry to share \e group slots and
/// reassign \b this group.
/// \param curList is the list of previous entries
void ParamEntry::resolveOverlap(list<ParamEntry> &curList)

{
  if (joinrec != (JoinRecord *)0)
    return;		// Overlaps with join records dealt with in resolveJoin
  vector<int4> overlapSet;
  list<ParamEntry>::const_iterator iter,enditer;
  Address addr(spaceid,addressbase);
  enditer = curList.end();
  --enditer;		// The last entry is \b this ParamEntry
  for(iter=curList.begin();iter!=enditer;++iter) {
    const ParamEntry &entry(*iter);
    if (!entry.intersects(addr, size)) continue;
    if (contains(entry)) {	// If this contains the intersecting entry
      if (entry.isOverlap()) continue;	// Don't count resources (already counted overlapped entry)
      overlapSet.insert(overlapSet.end(),entry.groupSet.begin(),entry.groupSet.end());
      // For output <pentry>, if the most signifigant part overlaps with an earlier <pentry>
      // the least signifigant part is marked for extra checks, and vice versa.
      if (addressbase == entry.addressbase)
	flags |= spaceid->isBigEndian() ? extracheck_low : extracheck_high;
      else
	flags |= spaceid->isBigEndian() ? extracheck_high : extracheck_low;
    }
    else
      throw LowlevelError("Illegal overlap of <pentry> in compiler spec");
  }

  if (overlapSet.empty()) return;		// No overlaps
  sort(overlapSet.begin(),overlapSet.end());
  groupSet = overlapSet;
  flags |= overlapping;
}

/// \param op2 is the other entry to compare
/// \return \b true if the group sets associated with each ParamEntry intersect at all
bool ParamEntry::groupOverlap(const ParamEntry &op2) const

{
  int4 i = 0;
  int4 j = 0;
  int4 valThis = groupSet[i];
  int4 valOther = op2.groupSet[j];
  while(valThis != valOther) {
    if (valThis < valOther) {
      i += 1;
      if (i >= groupSet.size()) return false;
      valThis = groupSet[i];
    }
    else {
      j += 1;
      if (j >= op2.groupSet.size()) return false;
      valOther = op2.groupSet[j];
    }
  }
  return true;
}

/// This entry must properly contain the other memory range, and
/// the entry properties must be compatible.  A \e join ParamEntry can
/// subsume another \e join ParamEntry, but we expect the addressbase to be identical.
/// \param op2 is the given entry to compare with \b this
/// \return \b true if the given entry is subsumed
bool ParamEntry::subsumesDefinition(const ParamEntry &op2) const

{
  if ((type!=TYPECLASS_GENERAL)&&(op2.type != type)) return false;
  if (spaceid != op2.spaceid) return false;
  if (op2.addressbase < addressbase) return false;
  if ((op2.addressbase+op2.size-1) > (addressbase+size-1)) return false;
  if (alignment != op2.alignment) return false;
  return true;
}

/// We assume a \e join ParamEntry cannot be contained by a single contiguous memory range.
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

/// If \b this a a \e join, each piece is tested for intersection.
/// Otherwise, \b this, considered as a single memory, is tested for intersection.
/// \param addr is the starting address of the given memory range to test against
/// \param sz is the number of bytes in the given memory range
/// \return \b true if there is any kind of intersection
bool ParamEntry::intersects(const Address &addr,int4 sz) const

{
  uintb rangeend;
  if (joinrec != (JoinRecord *)0) {
    rangeend = addr.getOffset() + sz - 1;
    for(int4 i=0;i<joinrec->numPieces();++i) {
      const VarnodeData &vdata( joinrec->getPiece(i) );
      if (addr.getSpace() != vdata.space) continue;
      uintb vdataend = vdata.offset + vdata.size - 1;
      if (addr.getOffset() < vdata.offset && rangeend < vdataend)
	continue;
      if (addr.getOffset() > vdata.offset && rangeend > vdataend)
	continue;
      return true;
    }
  }
  if (spaceid != addr.getSpace()) return false;
  rangeend = addr.getOffset() + sz - 1;
  uintb thisend = addressbase + size - 1;
  if (addr.getOffset() < addressbase && rangeend < thisend)
    return false;
  if (addr.getOffset() > addressbase && rangeend > thisend)
    return false;
  return true;
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

/// Test that \b this, as one or more memory ranges, contains the other ParamEntry's memory range.
/// A \e join ParamEntry cannot be contained by another entry, but it can contain an entry in one
/// of its pieces.
/// \param op2 is the given ParamEntry to test for containment
/// \return \b true if the given ParamEntry is contained
bool ParamEntry::contains(const ParamEntry &op2) const

{
  if (op2.joinrec != (JoinRecord *)0) return false;	// Assume a join entry cannot be contained
  if (joinrec == (JoinRecord *)0) {
    Address addr(spaceid,addressbase);
    return op2.containedBy(addr, size);
  }
  for(int4 i=0;i<joinrec->numPieces();++i) {
    const VarnodeData &vdata(joinrec->getPiece(i));
    Address addr = vdata.getAddr();
    if (op2.containedBy(addr,vdata.size))
      return true;
  }
  return false;
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
  int4 res = groupSet[0];
  if (alignment != 0) {
    uintb diff = addr.getOffset() + skip - addressbase;
    int4 baseslot = (int4)diff / alignment;
    if (isReverseStack())
      res += (numslots -1) - baseslot;
    else
      res += baseslot;
  }
  else if (skip != 0) {
    res = groupSet.back();
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
/// \param typeAlign is the required byte alignment for the parameter
/// \return the address of the new parameter (or an invalid address)
Address ParamEntry::getAddrBySlot(int4 &slotnum,int4 sz,int4 typeAlign) const

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
    if (typeAlign > alignment) {
      int4 tmp = (slotnum * alignment) % typeAlign;
      if (tmp != 0)
	slotnum += (typeAlign - tmp) / alignment;	// Waste slots to achieve typeAlign
    }
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

/// \brief Decode a \<pentry> element into \b this object
///
/// \param decoder is the stream decoder
/// \param normalstack is \b true if the parameters should be allocated from the front of the range
/// \param grouped is \b true if \b this will be grouped with other entries
/// \param curList is the list of ParamEntry defined up to this point
void ParamEntry::decode(Decoder &decoder,bool normalstack,bool grouped,list<ParamEntry> &curList)

{
  flags = 0;
  type = TYPECLASS_GENERAL;
  size = minsize = -1;		// Must be filled in
  alignment = 0;		// default
  numslots = 1;

  uint4 elemId = decoder.openElement(ELEM_PENTRY);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_MINSIZE) {
      minsize = decoder.readSignedInteger();
    }
    else if (attribId == ATTRIB_SIZE) { // old style
      alignment = decoder.readSignedInteger();
    }
    else if (attribId == ATTRIB_ALIGN) { // new style
      alignment = decoder.readSignedInteger();
    }
    else if (attribId == ATTRIB_MAXSIZE) {
      size = decoder.readSignedInteger();
    }
    else if (attribId == ATTRIB_STORAGE || attribId == ATTRIB_METATYPE)
      type = string2typeclass(decoder.readString());
    else if (attribId == ATTRIB_EXTENSION) {
      flags &= ~((uint4)(smallsize_zext | smallsize_sext | smallsize_inttype));
      string ext = decoder.readString();
      if (ext == "sign")
	flags |= smallsize_sext;
      else if (ext == "zero")
	flags |= smallsize_zext;
      else if (ext == "inttype")
	flags |= smallsize_inttype;
      else if (ext == "float")
	flags |= smallsize_floatext;
      else if (ext != "none")
	throw LowlevelError("Bad extension attribute");
    }
    else
      throw LowlevelError("Unknown <pentry> attribute");
  }
  if ((size==-1)||(minsize==-1))
    throw LowlevelError("ParamEntry not fully specified");
  if (alignment == size)
    alignment = 0;
  Address addr;
  addr = Address::decode(decoder);
  decoder.closeElement(elemId);
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
  if (grouped)
    flags |= is_grouped;
  resolveFirst(curList);
  resolveJoin(curList);
  resolveOverlap(curList);
}

/// Entries within a group must be distinguishable by size or by type.
/// Throw an exception if the entries aren't distinguishable
/// \param entry1 is the first ParamEntry to compare
/// \param entry2 is the second ParamEntry to compare
void ParamEntry::orderWithinGroup(const ParamEntry &entry1,const ParamEntry &entry2)

{
  if (entry2.minsize > entry1.size || entry1.minsize > entry2.size)
    return;
  if (entry1.type != entry2.type) {
    if (entry1.type == TYPECLASS_GENERAL) {
      throw LowlevelError("<pentry> tags with a specific type must come before the general type");
    }
    return;
  }
  throw LowlevelError("<pentry> tags within a group must be distinguished by size or type");
}

ParamListStandard::ParamListStandard(const ParamListStandard &op2)

{
  numgroup = op2.numgroup;
  entry = op2.entry;
  spacebase = op2.spacebase;
  maxdelay = op2.maxdelay;
  thisbeforeret = op2.thisbeforeret;
  resourceStart = op2.resourceStart;
  for(list<ModelRule>::const_iterator iter=op2.modelRules.begin();iter!=op2.modelRules.end();++iter) {
    modelRules.emplace_back(*iter,&op2);
  }
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

/// The entry must have a unique group.
/// If no matching entry is found, the \b end iterator is returned.
/// \param type is the storage class
/// \return the first matching iterator
list<ParamEntry>::const_iterator ParamListStandard::getFirstIter(type_class type) const

{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    const ParamEntry &curEntry( *iter );
    if (curEntry.getType() == type && curEntry.getAllGroups().size() == 1)
      return iter;
  }
  return iter;
}

/// If the stack entry is not present, null is returned
/// \return the stack entry or null
const ParamEntry *ParamListStandard::getStackEntry(void) const

{
  list<ParamEntry>::const_iterator iter = entry.end();
  if (iter != entry.begin()) {
    --iter;		// Stack entry necessarily must be the last entry
    const ParamEntry &curEntry( *iter );
    if (!curEntry.isExclusion() && curEntry.getSpace()->getType() == IPTR_SPACEBASE) {
      return &(*iter);
    }
  }
  return (const ParamEntry *)0;
}

/// Find the (first) entry containing the given memory range
/// \param loc is the starting address of the range
/// \param size is the number of bytes in the range
/// \param just is \b true if the search enforces a justified match
/// \return the pointer to the matching ParamEntry or null if no match exists
const ParamEntry *ParamListStandard::findEntry(const Address &loc,int4 size,bool just) const

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
    if (!just || testEntry->justifiedContain(loc,size)==0)	// Make sure the range is properly justified in entry
      return testEntry;
  }
  return (const ParamEntry *)0;
}

int4 ParamListStandard::characterizeAsParam(const Address &loc,int4 size) const

{
  int4 index = loc.getSpace()->getIndex();
  if (index >= resolverMap.size())
    return ParamEntry::no_containment;
  ParamEntryResolver *resolver = resolverMap[index];
  if (resolver == (ParamEntryResolver *)0)
    return ParamEntry::no_containment;
  pair<ParamEntryResolver::const_iterator,ParamEntryResolver::const_iterator> iterpair;
  iterpair = resolver->find(loc.getOffset());
  bool resContains = false;
  bool resContainedBy = false;
  while(iterpair.first != iterpair.second) {
    const ParamEntry *testEntry = (*iterpair.first).getParamEntry();
    int4 off = testEntry->justifiedContain(loc, size);
    if (off == 0)
      return ParamEntry::contains_justified;
    else if (off > 0)
      resContains = true;
    if (testEntry->isExclusion() && testEntry->containedBy(loc, size))
      resContainedBy = true;
    ++iterpair.first;
  }
  if (resContains) return ParamEntry::contains_unjustified;
  if (resContainedBy) return ParamEntry::contained_by;
  if (iterpair.first != resolver->end()) {
    iterpair.second = resolver->find_end(loc.getOffset() + (size-1));
    while(iterpair.first != iterpair.second) {
      const ParamEntry *testEntry = (*iterpair.first).getParamEntry();
      if (testEntry->isExclusion() && testEntry->containedBy(loc, size)) {
	return ParamEntry::contained_by;
      }
      ++iterpair.first;
    }
  }
  return ParamEntry::no_containment;
}

/// \brief Assign storage for given parameter class, using the fallback assignment algorithm
///
/// Given a resource list, a data-type, and the status of previously allocated slots,
/// select the storage location for the parameter.  The status array is
/// indexed by \e group: a positive value indicates how many \e slots have been allocated
/// from that group, and a -1 indicates the group/resource is fully consumed.
/// If an Address can be assigned to the parameter, it and other details are passed back in the
/// ParameterPieces object and the \e success code is returned.  Otherwise, the \e fail code is returned.
/// \param resource is the resource list to allocate from
/// \param tp is the data-type of the parameter
/// \param matchExact is \b false if TYPECLASS_GENERAL is considered a match for any storage class
/// \param status is an array marking how many \e slots have already been consumed in a group
/// \param param will hold the address of the newly assigned parameter
/// \return either \e success or \e fail
uint4 ParamListStandard::assignAddressFallback(type_class resource,Datatype *tp,bool matchExact,
					       vector<int4> &status,ParameterPieces &param) const
{
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    const ParamEntry &curEntry( *iter );
    int4 grp = curEntry.getGroup();
    if (status[grp]<0) continue;
    if (resource != curEntry.getType()) {
      if (matchExact || curEntry.getType() != TYPECLASS_GENERAL)
	continue;			// Wrong type
    }

    param.addr = curEntry.getAddrBySlot(status[grp],tp->getAlignSize(),tp->getAlignment());
    if (param.addr.isInvalid()) continue; // If -tp- doesn't fit an invalid address is returned
    if (curEntry.isExclusion()) {
      const vector<int4> &groupSet(curEntry.getAllGroups());
      for(int4 j=0;j<groupSet.size();++j) 	// For an exclusion entry
	status[groupSet[j]] = -1;		// some number of groups are taken up
    }
    param.type = tp;
    param.flags = 0;
    return AssignAction::success;
  }
  return AssignAction::fail;	// Unable to make an assignment
}

/// \brief Fill in the Address and other details for the given parameter
///
/// Attempt to apply a ModelRule first. If these do not succeed, use the fallback assignment algorithm.
/// \param dt is the data-type assigned to the parameter
/// \param proto is the description of the function prototype
/// \param pos is the position of the parameter to assign (pos=-1 for output, pos >=0 for input)
/// \param tlist is the data-type factory for (possibly) transforming the parameter's data-type
/// \param status is the consumed resource status array
/// \param res is parameter description to be filled in
/// \return the response code
uint4 ParamListStandard::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
				       vector<int4> &status,ParameterPieces &res) const

{
  for(list<ModelRule>::const_iterator iter=modelRules.begin();iter!=modelRules.end();++iter) {
    uint4 responseCode = (*iter).assignAddress(dt, proto, pos, tlist, status, res);
    if (responseCode != AssignAction::fail)
      return responseCode;
  }
  type_class store = metatype2typeclass(dt->getMetatype());
  return assignAddressFallback(store,dt,false,status,res);
}

void ParamListStandard::assignMap(const PrototypePieces &proto,TypeFactory &typefactory,vector<ParameterPieces> &res) const

{
  vector<int4> status(numgroup,0);

  if (res.size() == 2) {	// Check for hidden parameters defined by the output list
    Datatype *dt = res.back().type;
    type_class store;
    if ((res.back().flags & ParameterPieces::hiddenretparm) != 0)
      store = TYPECLASS_HIDDENRET;
    else
      store = metatype2typeclass(dt->getMetatype());
    // Reserve first param for hidden return pointer
    if (assignAddressFallback(store,dt,false,status,res.back()) == AssignAction::fail)
      throw ParamUnassignedError("Cannot assign parameter address for " + res.back().type->getName());
    res.back().flags |= ParameterPieces::hiddenretparm;
  }
  for(int4 i=0;i<proto.intypes.size();++i) {
    res.emplace_back();
    Datatype *dt = proto.intypes[i];
    uint4 responseCode = assignAddress(dt,proto,i,typefactory,status,res.back());
    if (responseCode == AssignAction::fail || responseCode == AssignAction::no_assignment)
      throw ParamUnassignedError("Cannot assign parameter address for " + dt->getName());
  }
}

/// From among the ParamEntrys matching the given \e group, return the one that best matches
/// the given \e metatype attribute. If there are no ParamEntrys in the group, null is returned.
/// \param grp is the given \e group number
/// \param prefType is the preferred \e storage \e class attribute to match
const ParamEntry *ParamListStandard::selectUnreferenceEntry(int4 grp,type_class prefType) const

{
  int4 bestScore = -1;
  const ParamEntry *bestEntry = (const ParamEntry *)0;
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    const ParamEntry *curEntry = &(*iter);
    if (curEntry->getGroup() != grp) continue;
    int4 curScore;
    if (curEntry->getType() == prefType)
      curScore = 2;
    else if (prefType == TYPECLASS_GENERAL)
      curScore = 1;
    else
      curScore = 0;
    if (curScore > bestScore) {
      bestScore = curScore;
      bestEntry = curEntry;
    }
  }
  return bestEntry;
}

/// Given a set of \b trials (putative Varnode parameters) as ParamTrial objects,
/// associate each trial with a model ParamEntry within \b this list. Trials for
/// for which there are no matching entries are marked as unused. Any holes
/// in the resource list are filled with \e unreferenced trials. The trial list is sorted.
/// \param active is the set of \b trials to map and organize
void ParamListStandard::buildTrialMap(ParamActive *active) const

{
  vector<const ParamEntry *> hitlist; // List of groups for which we have a representative
  int4 floatCount = 0;
  int4 intCount = 0;

  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &paramtrial(active->getTrial(i));
    const ParamEntry *entrySlot = findEntry(paramtrial.getAddress(),paramtrial.getSize(),true);
    // Note: if a trial is "definitely not used" but there is a matching entry,
    // we still include it in the map
    if (entrySlot == (const ParamEntry *)0)
      paramtrial.markNoUse();
    else {
      paramtrial.setEntry( entrySlot, 0 ); // Keep track of entry recovered for this trial

      if (paramtrial.isActive()) {
	if (entrySlot->getType() == TYPECLASS_FLOAT)
	  floatCount += 1;
	else
	  intCount += 1;
      }

      // Make sure we list that the entries group is marked
      int4 grp = entrySlot->getGroup();
      while(hitlist.size() <= grp)
	hitlist.push_back((const ParamEntry *)0);
      const ParamEntry *lastentry = hitlist[grp];
      if (lastentry == (const ParamEntry *)0)
	hitlist[grp] = entrySlot; // This is the first hit for this group
    }
  }

  // Created unreferenced (unref) ParamTrial for any group that we don't have a representative for
  // if that group occurs before one where we do have a representative

  for(int4 i=0;i<hitlist.size();++i) {
    const ParamEntry *curentry = hitlist[i];

    if (curentry == (const ParamEntry *)0) {
      curentry = selectUnreferenceEntry(i, (floatCount > intCount) ? TYPECLASS_FLOAT : TYPECLASS_GENERAL);
      if (curentry == (const ParamEntry *)0)
	continue;
      int4 sz = curentry->isExclusion() ? curentry->getSize() : curentry->getAlign();
      int4 nextslot = 0;
      Address addr = curentry->getAddrBySlot(nextslot,sz,1);
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
	  Address addr = curentry->getAddrBySlot(nextslot,curentry->getAlign(),1);
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

/// \brief Calculate the range of trials in each resource sections
///
/// The trials must already be mapped, which should put them in group order.  The sections
/// split at the groups given by \b resourceStart.  We pass back the starting index for
/// each range of trials.
/// \param active is the given set of parameter trials
/// \param trialStart will hold the starting index for each range of trials
void ParamListStandard::separateSections(ParamActive *active,vector<int4> &trialStart) const

{
  int4 numtrials = active->getNumTrials();
  int4 currentTrial = 0;
  int4 nextGroup = resourceStart[1];
  int4 nextSection = 2;
  trialStart.push_back(currentTrial);
  for(;currentTrial<numtrials;++currentTrial) {
    ParamTrial &curtrial(active->getTrial(currentTrial));
    if (curtrial.getEntry()==(const ParamEntry *)0) continue;
    if (curtrial.getEntry()->getGroup() >= nextGroup) {
      if (nextSection > resourceStart.size())
	throw LowlevelError("Missing next resource start");
      nextGroup = resourceStart[nextSection];
      nextSection += 1;
      trialStart.push_back(currentTrial);
    }
  }
  trialStart.push_back(numtrials);
}

/// \brief Mark all the trials within the indicated groups as \e not \e used, except for one specified index
///
/// Only one trial within an exclusion group can have active use, mark all others as unused.
/// \param active is the set of trials, which must be sorted on group
/// \param activeTrial is the index of the trial whose groups are to be considered active
/// \param trialStart is the index of the first trial to mark
void ParamListStandard::markGroupNoUse(ParamActive *active,int4 activeTrial,int4 trialStart)

{
  int4 numTrials = active->getNumTrials();
  const ParamEntry *activeEntry = active->getTrial(activeTrial).getEntry();
  for(int4 i=trialStart;i<numTrials;++i) {		// Mark entries intersecting the group set as definitely not used
    if (i == activeTrial) continue;			// The trial NOT to mark
    ParamTrial &othertrial(active->getTrial(i));
    if (othertrial.isDefinitelyNotUsed()) continue;
    if (!othertrial.getEntry()->groupOverlap(*activeEntry)) break;
    othertrial.markNoUse();
  }
}

/// \brief From among multiple \e inactive trials, select the most likely to be active and mark others as not used
///
/// There can be at most one \e inactive trial in an exclusion group for the fill algorithms to work.
/// Score all the trials and pick the one that is the most likely to actually be an active param.
/// Mark all the others as definitely not used.
/// \param active is the sorted set of trials
/// \param group is the group number
/// \param groupStart is the index of the first trial in the group
/// \param prefType is a preferred entry to type to use in scoring
void ParamListStandard::markBestInactive(ParamActive *active,int4 group,int4 groupStart,type_class prefType)

{
  int4 numTrials = active->getNumTrials();
  int4 bestTrial = -1;
  int4 bestScore = -1;
  for(int4 i=groupStart;i<numTrials;++i) {
    ParamTrial &trial(active->getTrial(i));
    if (trial.isDefinitelyNotUsed()) continue;
    const ParamEntry *entry = trial.getEntry();
    int4 grp = entry->getGroup();
    if (grp != group) break;
    if (entry->getAllGroups().size() > 1) continue;	// Covering multiple slots automatically give low score
    int4 score = 0;
    if (trial.hasAncestorRealistic()) {
      score += 5;
      if (trial.hasAncestorSolid())
	score += 5;
    }
    if (entry->getType() == prefType)
      score += 1;
    if (score > bestScore) {
      bestScore = score;
      bestTrial = i;
    }
  }
  if (bestTrial >= 0)
    markGroupNoUse(active, bestTrial, groupStart);
}

/// \brief Enforce exclusion rules for the given set of parameter trials
///
/// If there are more than one active trials in a single group,
/// and if that group is an exclusion group, mark all but the first trial to \e defnouse.
/// \param active is the set of trials
void ParamListStandard::forceExclusionGroup(ParamActive *active)

{
  int4 numTrials = active->getNumTrials();
  int4 curGroup = -1;
  int4 groupStart = -1;
  int4 inactiveCount = 0;
  for(int4 i=0;i<numTrials;++i) {
    ParamTrial &curtrial(active->getTrial(i));
    if (curtrial.isDefinitelyNotUsed() || !curtrial.getEntry()->isExclusion())
         continue;
    int4 grp = curtrial.getEntry()->getGroup();
    if (grp != curGroup) {
      if (inactiveCount > 1)
	markBestInactive(active, curGroup, groupStart, TYPECLASS_GENERAL);
      curGroup = grp;
      groupStart = i;
      inactiveCount = 0;
    }
    if (curtrial.isActive()) {
      markGroupNoUse(active, i, groupStart);
    }
    else {
      inactiveCount += 1;
    }
  }
  if (inactiveCount > 1)
    markBestInactive(active, curGroup, groupStart, TYPECLASS_GENERAL);
}

/// \brief Mark every trial above the first "definitely not used" as \e inactive.
///
/// Inspection and marking only occurs within an indicated range of trials,
/// allowing floating-point and general purpose resources to be treated separately.
/// \param active is the set of trials, which must already be ordered
/// \param start is the index of the first trial in the range to consider
/// \param stop is the index (+1) of the last trial in the range to consider
void ParamListStandard::forceNoUse(ParamActive *active, int4 start, int4 stop)

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
	seendefnouse = true;// then force everything afterward to be defnotused
      alldefnouse = curtrial.isDefinitelyNotUsed();
      curgroup = grp;
    }
    if (seendefnouse)
      curtrial.markInactive();
  }
}

/// \brief Enforce rules about chains of inactive slots.
///
/// If there is a chain of slots whose length is greater than \b maxchain,
/// where all trials are \e inactive, mark trials in any later slot as \e inactive.
/// Mark any \e inactive trials before this (that aren't in a maximal chain) as active.
/// The parameter entries in the model may be split up into different resource sections,
/// as in floating-point vs general purpose.  This method must be called on a single
/// section at a time. The \b start and \b stop indices describe the range of trials
/// in the particular section.
/// \param active is the set of trials, which must be sorted
/// \param maxchain is the maximum number of \e inactive trials to allow in a chain
/// \param start is the first index in the range of trials to consider
/// \param stop is the last index (+1) in the range of trials to consider
/// \param groupstart is the smallest group id in the particular section
void ParamListStandard::forceInactiveChain(ParamActive *active,int4 maxchain,int4 start,int4 stop,int4 groupstart)

{
  bool seenchain = false;
  int4 chainlength = 0;
  int4 max = -1;
  for(int4 i=start;i<stop;++i) {
    ParamTrial &trial(active->getTrial(i));
    if (trial.isDefinitelyNotUsed()) continue; // Already know not used
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
	chainlength += (trial.slotGroup() - groupstart + 1);
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

/// \brief Internal method for adding a single address range to the ParamEntryResolvers
///
/// Specify the contiguous address range, the ParamEntry to map to it, and a position recording
/// the order in which ranges are added.
/// \param spc is address space of the memory range
/// \param first is the starting offset of the memory range
/// \param last is the ending offset of the memory range
/// \param paramEntry is the ParamEntry to associate with the memory range
/// \param position is the ordering position
void ParamListStandard::addResolverRange(AddrSpace *spc,uintb first,uintb last,ParamEntry *paramEntry,int4 position)

{
  int4 index = spc->getIndex();
  while(resolverMap.size() <= index) {
    resolverMap.push_back((ParamEntryResolver *)0);
  }
  ParamEntryResolver *resolver = resolverMap[index];
  if (resolver == (ParamEntryResolver *)0) {
    resolver = new ParamEntryResolver();
    resolverMap[spc->getIndex()] = resolver;
  }
  ParamEntryResolver::inittype initData(position,paramEntry);
  resolver->insert(initData,first,last);
}

/// Enter all the ParamEntry objects into an interval map (based on address space)
void ParamListStandard::populateResolver(void)

{
  list<ParamEntry>::iterator iter;
  int4 position = 0;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    ParamEntry *paramEntry = &(*iter);
    AddrSpace *spc = paramEntry->getSpace();
    if (spc->getType() == IPTR_JOIN) {
      JoinRecord *joinRec = paramEntry->getJoinRecord();
      for(int4 i=0;i<joinRec->numPieces();++i) {
	// Individual pieces making up the join are mapped to the ParamEntry
        const VarnodeData &vData(joinRec->getPiece(i));
        uintb last = vData.offset + (vData.size - 1);
        addResolverRange(vData.space,vData.offset,last,paramEntry,position);
        position += 1;
      }
    }
    else {
      uintb first = paramEntry->getBase();
      uintb last = first + (paramEntry->getSize() - 1);
      addResolverRange(spc,first,last,paramEntry,position);
      position += 1;
    }
  }
}

/// \brief Parse a \<pentry> element and add it to \b this list
///
/// \param decoder is the stream decoder
/// \param effectlist holds any passed back effect records
/// \param groupid is the group to which the new ParamEntry is assigned
/// \param normalstack is \b true if the parameters should be allocated from the front of the range
/// \param autokill is \b true if parameters are automatically added to the killedbycall list
/// \param splitFloat is \b true if floating-point parameters are in their own resource section
/// \param grouped is \b true if the new ParamEntry is grouped with other entries
void ParamListStandard::parsePentry(Decoder &decoder,vector<EffectRecord> &effectlist,
				    int4 groupid,bool normalstack,bool autokill,bool splitFloat,bool grouped)
{
  type_class lastClass = TYPECLASS_CLASS4;
  if (!entry.empty()) {
    lastClass = entry.back().isGrouped() ? TYPECLASS_GENERAL : entry.back().getType();
  }
  entry.emplace_back(groupid);
  entry.back().decode(decoder,normalstack,grouped,entry);
  if (splitFloat) {
    type_class currentClass = grouped ? TYPECLASS_GENERAL : entry.back().getType();
    if (lastClass != currentClass) {
      if (lastClass < currentClass)
	throw LowlevelError("parameter list entries must be ordered by storage class");
      resourceStart.push_back(groupid);
    }
  }
  AddrSpace *spc = entry.back().getSpace();
  if (spc->getType() == IPTR_SPACEBASE)
    spacebase = spc;
  else if (autokill)	// If a register parameter AND we automatically generate killedbycall
    effectlist.push_back(EffectRecord(entry.back(),EffectRecord::killedbycall));

  int4 maxgroup = entry.back().getAllGroups().back() + 1;
  if (maxgroup > numgroup)
    numgroup = maxgroup;
}

/// \brief Parse a sequence of \<pentry> elements that are allocated as a group
///
/// All ParamEntry objects will share the same \b group id.
/// \param decoder is the stream decoder
/// \param effectlist holds any passed back effect records
/// \param groupid is the group to which all ParamEntry elements are assigned
/// \param normalstack is \b true if the parameters should be allocated from the front of the range
/// \param autokill is \b true if parameters are automatically added to the killedbycall list
/// \param splitFloat is \b true if floating-point parameters are in their own resource section
void ParamListStandard::parseGroup(Decoder &decoder,vector<EffectRecord> &effectlist,
				   int4 groupid,bool normalstack,bool autokill,bool splitFloat)
{
  int4 basegroup = numgroup;
  ParamEntry *previous1 = (ParamEntry *)0;
  ParamEntry *previous2 = (ParamEntry *)0;
  uint4 elemId = decoder.openElement(ELEM_GROUP);
  while(decoder.peekElement() != 0) {
    parsePentry(decoder, effectlist, basegroup, normalstack, autokill, splitFloat, true);
    ParamEntry &pentry( entry.back() );
    if (pentry.getSpace()->getType() == IPTR_JOIN)
      throw LowlevelError("<pentry> in the join space not allowed in <group> tag");
    if (previous1 != (ParamEntry *)0) {
      ParamEntry::orderWithinGroup(*previous1,pentry);
      if (previous2 != (ParamEntry *)0)
	ParamEntry::orderWithinGroup(*previous2,pentry);
    }
    previous2 = previous1;
    previous1 = &pentry;
  }
  decoder.closeElement(elemId);
}

void ParamListStandard::fillinMap(ParamActive *active) const

{
  if (active->getNumTrials() == 0) return; // No trials to check
  if (entry.empty())
    throw LowlevelError("Cannot derive parameter storage for prototype model without parameter entries");

  buildTrialMap(active); // Associate varnodes with sorted list of parameter locations

  forceExclusionGroup(active);
  vector<int4> trialStart;
  separateSections(active,trialStart);
  int4 numSection = trialStart.size() - 1;
  for(int4 i=0;i<numSection;++i) {
    // Definitely not used -- overrides active
    forceNoUse(active,trialStart[i],trialStart[i+1]);
  }
  for(int4 i=0;i<numSection;++i) {
    // Chains of inactivity override later actives
    forceInactiveChain(active,2,trialStart[i],trialStart[i+1],resourceStart[i]);
  }

  // Mark every active trial as used
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &paramtrial(active->getTrial(i));
    if (paramtrial.isActive())
      paramtrial.markUsed();
  }
}

bool ParamListStandard::checkJoin(const Address &hiaddr,int4 hisize,const Address &loaddr,int4 losize) const

{
  const ParamEntry *entryHi = findEntry(hiaddr,hisize,true);
  if (entryHi == (const ParamEntry *)0) return false;
  const ParamEntry *entryLo = findEntry(loaddr,losize,true);
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
  const ParamEntry *entryNum = findEntry(loc,splitpoint,true);
  if (entryNum == (const ParamEntry *)0) return false;
  entryNum = findEntry(loc2,size2,true);
  if (entryNum == (const ParamEntry *)0) return false;
  return true;
}

bool ParamListStandard::possibleParam(const Address &loc,int4 size) const

{
  return ((const ParamEntry *)0 != findEntry(loc,size,true));
}

bool ParamListStandard::possibleParamWithSlot(const Address &loc,int4 size,int4 &slot,int4 &slotsize) const

{
  const ParamEntry *entryNum = findEntry(loc,size,true);
  if (entryNum == (const ParamEntry *)0) return false;
  slot = entryNum->getSlot(loc,0);
  if (entryNum->isExclusion()) {
    slotsize = entryNum->getAllGroups().size();
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

void ParamListStandard::decode(Decoder &decoder,vector<EffectRecord> &effectlist,bool normalstack)

{
  numgroup = 0;
  spacebase = (AddrSpace *)0;
  int4 pointermax = 0;
  thisbeforeret = false;
  bool splitFloat = true;		// True if we should split FLOAT entries into their own resource section
  bool autokilledbycall = false;
  uint4 elemId = decoder.openElement();
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_POINTERMAX) {
      pointermax = decoder.readSignedInteger();
    }
    else if (attribId == ATTRIB_THISBEFORERETPOINTER) {
      thisbeforeret = decoder.readBool();
    }
    else if (attribId == ATTRIB_KILLEDBYCALL) {
      autokilledbycall = decoder.readBool();
    }
    else if (attribId == ATTRIB_SEPARATEFLOAT) {
      splitFloat = decoder.readBool();
    }
  }
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_PENTRY) {
      parsePentry(decoder, effectlist, numgroup, normalstack, autokilledbycall, splitFloat, false);
    }
    else if (subId == ELEM_GROUP) {
      parseGroup(decoder, effectlist, numgroup, normalstack, autokilledbycall, splitFloat);
    }
    else if (subId == ELEM_RULE) {
      break;
    }
  }
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_RULE) {
      modelRules.emplace_back();
      modelRules.back().decode(decoder, this);
    }
    else {
      throw LowlevelError("<pentry> and <group> elements must come before any <modelrule>");
    }
  }
  decoder.closeElement(elemId);
  resourceStart.push_back(numgroup);
  calcDelay();
  populateResolver();
  if (pointermax > 0) {	// Add a ModelRule at the end that converts too big data-types to pointers
    SizeRestrictedFilter typeFilter(pointermax+1,0);
    ConvertToPointer action(this);
    modelRules.emplace_back(typeFilter,action,this);
  }
}

ParamList *ParamListStandard::clone(void) const

{
  ParamList *res = new ParamListStandard(*this);
  return res;
}

void ParamListRegisterOut::assignMap(const PrototypePieces &proto,TypeFactory &typefactory,vector<ParameterPieces> &res) const

{
  vector<int4> status(numgroup,0);
  res.emplace_back();
  if (proto.outtype->getMetatype() != TYPE_VOID) {
    assignAddress(proto.outtype,proto,-1,typefactory,status,res.back());
    if (res.back().addr.isInvalid())
      throw ParamUnassignedError("Cannot assign parameter address for " + proto.outtype->getName());
  }
  else {
    res.back().type = proto.outtype;
    res.back().flags = 0;
  }
}

ParamList *ParamListRegisterOut::clone(void) const

{
  ParamList *res = new ParamListRegisterOut(*this);
  return res;
}

void ParamListRegister::fillinMap(ParamActive *active) const

{
  if (active->getNumTrials() == 0) return; // No trials to check

  // Mark anything active as used
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &paramtrial(active->getTrial(i));
    const ParamEntry *entrySlot = findEntry(paramtrial.getAddress(),paramtrial.getSize(),true);
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

void ParamListStandardOut::assignMap(const PrototypePieces &proto,TypeFactory &typefactory,vector<ParameterPieces> &res) const

{
  vector<int4> status(numgroup,0);

  res.emplace_back();
  if (proto.outtype->getMetatype() == TYPE_VOID) {
    res.back().type = proto.outtype;
    res.back().flags = 0;
    return;			// Leave the address as invalid
  }
  uint4 responseCode = assignAddress(proto.outtype,proto,-1,typefactory,status,res.back());

  if (responseCode == AssignAction::fail)
    responseCode = AssignAction::hiddenret_ptrparam;	// Invoke default hidden return input assignment action

  if (responseCode == AssignAction::hiddenret_ptrparam || responseCode == AssignAction::hiddenret_specialreg ||
      responseCode == AssignAction::hiddenret_specialreg_void) { // Could not assign an address (too big)
    AddrSpace *spc = spacebase;
    if (spc == (AddrSpace *)0)
      spc = typefactory.getArch()->getDefaultDataSpace();
    int4 pointersize = spc->getAddrSize();
    int4 wordsize = spc->getWordSize();
    Datatype *pointertp = typefactory.getTypePointer(pointersize, proto.outtype, wordsize);
    if (responseCode == AssignAction::hiddenret_specialreg_void) {
      res.back().type = typefactory.getTypeVoid();
    }
    else {
      if (assignAddressFallback(TYPECLASS_PTR,pointertp,false,status,res.back()) == AssignAction::fail)
	throw ParamUnassignedError("Cannot assign return value as a pointer");
    }
    res.back().flags = ParameterPieces::indirectstorage;

    res.emplace_back();			// Add extra storage location in the input params
    res.back().type = pointertp;	// that holds a pointer to where the return value should be stored
    // leave its address invalid, to be filled in by the input list assignMap
    // Encode whether or not hidden return should be drawn from TYPECLASS_HIDDENRET
    bool isSpecial = (responseCode == AssignAction::hiddenret_specialreg ||
	responseCode == AssignAction::hiddenret_specialreg_void);
    res.back().flags = isSpecial ? ParameterPieces::hiddenretparm : 0;
  }
}

void ParamListStandardOut::initialize(void)

{
  useFillinFallback = true;
  list<ModelRule>::const_iterator iter;
  for(iter=modelRules.begin();iter!=modelRules.end();++iter) {
    if ((*iter).canAffectFillinOutput()) {
      useFillinFallback = false;
      break;
    }
  }
}

/// \brief Find the return value storage using the older \e fallback method
///
/// Given the active set of trial locations that might hold (pieces of) the return value, calculate
/// the best matching ParamEntry from \b this ParamList and mark all the trials that are contained
/// in the ParamEntry as \e used.  If \b firstOnly is \b true, the ParamList is assumed to contain
/// partial storage locations that might get used for return values split storage.  In this case,
/// only the first ParamEntry in a storage class is allowed to match.
/// \param active is the set of active trials
/// \param firstOnly is \b true if only the first entry in a storage class can match
void ParamListStandardOut::fillinMapFallback(ParamActive *active,bool firstOnly) const

{
  const ParamEntry *bestentry = (const ParamEntry *)0;
  int4 bestcover = 0;
  type_class bestclass = TYPECLASS_PTR;

  // Find entry which is best covered by the active trials
  list<ParamEntry>::const_iterator iter;
  for(iter=entry.begin();iter!=entry.end();++iter) {
    const ParamEntry *curentry = &(*iter);
    if (firstOnly && !curentry->isFirstInClass() && curentry->isExclusion() && curentry->getAllGroups().size() == 1) {
      continue;	// This is not the first entry in the storage class
    }
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
    if ((k==active->getNumTrials())&&((curentry->getType() < bestclass)||(offmatch > bestcover))) {
      bestentry = curentry;
      bestcover = offmatch;
      bestclass = curentry->getType();
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

void ParamListStandardOut::fillinMap(ParamActive *active) const

{
  if (active->getNumTrials() == 0) return; // No trials to check
  if (useFillinFallback) {
    fillinMapFallback(active,false);
    return;
  }
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &trial(active->getTrial(i));
    trial.setEntry((const ParamEntry *)0, 0);
    if (!trial.isActive()) continue;
    const ParamEntry *entry = findEntry(trial.getAddress(),trial.getSize(),false);
    if (entry == (const ParamEntry *)0) {
      trial.markNoUse();
      continue;
    }
    int4 res = entry->justifiedContain(trial.getAddress(),trial.getSize());
    if ((trial.isRemFormed() || trial.isIndCreateFormed()) && !entry->isFirstInClass()) {
      trial.markNoUse();
      continue;
    }
    trial.setEntry(entry,res);
  }
  active->sortTrials();
  list<ModelRule>::const_iterator iter;
  for(iter=modelRules.begin();iter!=modelRules.end();++iter) {
    if ((*iter).fillinOutputMap(active)) {
      for(int4 i=0;i<active->getNumTrials();++i) {
	ParamTrial &trial(active->getTrial(i));
	if (trial.isActive()) {
	  trial.markUsed();
	}
	else {
	  trial.markNoUse();
	  trial.setEntry((const ParamEntry *)0,0);
	}
      }
      return;
    }
  }
  fillinMapFallback(active, true);
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

void ParamListStandardOut::decode(Decoder &decoder,vector<EffectRecord> &effectlist,bool normalstack)

{
  ParamListStandard::decode(decoder,effectlist,normalstack);
  initialize();
}

ParamList *ParamListStandardOut::clone(void) const

{
  ParamList *res = new ParamListStandardOut( *this );
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
      if ((*iter).subsumesDefinition(opentry)) {
	typeint = 2;
	break;
      }
      if (opentry.subsumesDefinition( *iter )) {
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

/// Sort by fixed position then by ParamTrial::operator<
/// \param a trial
/// \param b trial
/// \return \b true if \b a should be ordered before \b b
bool ParamTrial::fixedPositionCompare(const ParamTrial &a, const ParamTrial &b)

{
	if (a.fixedPosition == -1 && b.fixedPosition == -1){
		return a < b;
	}
	if (a.fixedPosition == -1){
		return false;
	}
	if (b.fixedPosition == -1){
		return true;
	}
	return a.fixedPosition < b.fixedPosition;
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

const string FspecSpace::NAME = "fspec";

/// Constructor for the \b fspec space.
/// There is only one such space, and it is considered
/// internal to the model, i.e. the Translate engine should never
/// generate addresses in this space.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param ind is the index associated with the space
FspecSpace::FspecSpace(AddrSpaceManager *m,const Translate *t,int4 ind)
  : AddrSpace(m,t,IPTR_FSPEC,NAME,false,sizeof(void *),1,ind,0,1,1)
{
  clearFlags(heritaged|does_deadcode|big_endian);
  if (HOST_ENDIAN==1)		// Endianness always set by host
    setFlags(big_endian);
}

void FspecSpace::encodeAttributes(Encoder &encoder,uintb offset) const

{
  FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset;

  if (fc->getEntryAddress().isInvalid())
    encoder.writeString(ATTRIB_SPACE, "fspec");
  else {
    AddrSpace *id = fc->getEntryAddress().getSpace();
    encoder.writeSpace(ATTRIB_SPACE, id);
    encoder.writeUnsignedInteger(ATTRIB_OFFSET, fc->getEntryAddress().getOffset());
  }
}

void FspecSpace::encodeAttributes(Encoder &encoder,uintb offset,int4 size) const

{
  FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset;

  if (fc->getEntryAddress().isInvalid())
    encoder.writeString(ATTRIB_SPACE, "fspec");
  else {
    AddrSpace *id = fc->getEntryAddress().getSpace();
    encoder.writeSpace(ATTRIB_SPACE, id);
    encoder.writeUnsignedInteger(ATTRIB_OFFSET, fc->getEntryAddress().getOffset());
    encoder.writeSignedInteger(ATTRIB_SIZE, size);
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

void FspecSpace::decode(Decoder &decoder)

{
  throw LowlevelError("Should never decode fspec space from stream");
}

/// Swap any data-type and flags, but leave the storage address intact.
/// This assumes the two parameters are the same size.
/// \param op is the other parameter to swap with \b this.
void ParameterPieces::swapMarkup(ParameterPieces &op)

{
  uint4 tmpFlags = flags;
  Datatype *tmpType = type;
  flags = op.flags;
  type = op.type;
  op.flags = tmpFlags;
  op.type = tmpType;
}

/// The type is set to \e unknown_effect
/// \param addr is the start of the memory range
/// \param size is the number of bytes in the memory range
EffectRecord::EffectRecord(const Address &addr,int4 size)

{
  range.space = addr.getSpace();
  range.offset = addr.getOffset();
  range.size = size;
  type = unknown_effect;
}

/// \param entry is a model of the parameter storage
/// \param t is the effect type
EffectRecord::EffectRecord(const ParamEntry &entry,uint4 t)

{
  range.space = entry.getSpace();
  range.offset = entry.getBase();
  range.size = entry.getSize();
  type = t;
}

/// \param data is the memory range affected
/// \param t is the effect type
EffectRecord::EffectRecord(const VarnodeData &data,uint4 t)

{
  range = data;
  type = t;
}

/// Encode just an \<addr> element.  The effect type is indicated by the parent element.
/// \param encoder is the stream encoder
void EffectRecord::encode(Encoder &encoder) const

{
  Address addr(range.space,range.offset);
  if ((type == unaffected)||(type == killedbycall)||(type == return_address))
    addr.encode(encoder,range.size);
  else
    throw LowlevelError("Bad EffectRecord type");
}

/// Parse an \<addr> element to get the memory range. The effect type is inherited from the parent.
/// \param grouptype is the effect inherited from the parent
/// \param decoder is the stream decoder
void EffectRecord::decode(uint4 grouptype,Decoder &decoder)

{
  type = grouptype;
  range.decode(decoder);
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
    output = new ParamListRegisterOut();
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
  isPrinted = true;
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
  isPrinted = true;		// Don't inherit. Always print unless setPrintInDecl called explicitly
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
  internalstorage = op2.internalstorage;

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
/// The data-types of the function prototype are passed in. Based on \b this model, a
/// location is selected for each (input and output) parameter and passed back to the
/// caller.  The passed back storage locations are ordered with the output storage
/// as the first entry, followed by the input storage locations.  The model has the option
/// of inserting a \e hidden return value pointer in the input storage locations.
///
/// A \b void return type is indicated by the formal TYPE_VOID.
/// If the model can't map the specific output prototype, the caller has the option of whether
/// an exception (ParamUnassignedError) is thrown.  If they choose not to throw,
/// the unmapped return value is assumed to be \e void.
/// \param proto is the data-types associated with the function prototype
/// \param res will hold the storage locations for each parameter
/// \param ignoreOutputError is \b true if problems assigning the output parameter are ignored
void ProtoModel::assignParameterStorage(const PrototypePieces &proto,vector<ParameterPieces> &res,bool ignoreOutputError)

{
  if (ignoreOutputError) {
    try {
      output->assignMap(proto,*glb->types,res);
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
    output->assignMap(proto,*glb->types,res);
  }
  input->assignMap(proto,*glb->types,res);

  if (hasThis && res.size() > 1) {
    int4 thisIndex = 1;
    if ((res[1].flags & ParameterPieces::hiddenretparm) != 0 && res.size() > 2) {
      if (input->isThisBeforeRetPointer()) {
					// pointer has been bumped by auto-return-storage
	res[1].swapMarkup(res[2]);	// must swap markup for slots 1 and 2
      }
      else {
	thisIndex = 2;
      }
    }
    res[thisIndex].flags |= ParameterPieces::isthis;
  }
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

  iter = upper_bound(efflist.begin(),efflist.end(),cur,EffectRecord::compareByAddress);
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

/// \brief Look up a particular EffectRecord from a given list by its Address and size
///
/// The index of the matching EffectRecord from the given list is returned.  Only the first
/// \e listSize elements are examined, which much be sorted by Address.
/// If no matching range exists, a negative number is returned.
///   - -1 if the Address and size don't overlap any other EffectRecord
///   - -2 if there is overlap with another EffectRecord
///
/// \param efflist is the given list
/// \param listSize is the number of records in the list to search through
/// \param addr is the starting Address of the record to find
/// \param size is the size of the record to find
/// \return the index of the matching record or a negative number
int4 ProtoModel::lookupRecord(const vector<EffectRecord> &efflist,int4 listSize,
			      const Address &addr,int4 size)
{
  if (listSize == 0) return -1;
  EffectRecord cur(addr,size);

  vector<EffectRecord>::const_iterator begiter = efflist.begin();
  vector<EffectRecord>::const_iterator enditer = begiter + listSize;
  vector<EffectRecord>::const_iterator iter;

  iter = upper_bound(begiter,enditer,cur,EffectRecord::compareByAddress);
  // First element greater than cur  (address must be greater)
  // go back one more, and we get first el less or equal to cur
  if (iter==efflist.begin()) {
    Address closeAddr = (*iter).getAddress();
    return (closeAddr.overlap(0,addr,size) < 0) ? -1 : -2;
  }
  --iter;
  Address closeAddr =(*iter).getAddress();
  int4 sz = (*iter).getSize();
  if (addr == closeAddr && size == sz)
    return iter - begiter;
  return (addr.overlap(0,closeAddr,sz) < 0) ? -1 : -2;
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

/// Parse details about \b this model from a \<prototype> element
/// \param decoder is the stream decoder
void ProtoModel::decode(Decoder &decoder)

{
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
  isPrinted = true;
  effectlist.clear();
  injectUponEntry = -1;
  injectUponReturn = -1;
  likelytrash.clear();
  internalstorage.clear();
  uint4 elemId = decoder.openElement(ELEM_PROTOTYPE);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_NAME)
      name = decoder.readString();
    else if (attribId == ATTRIB_EXTRAPOP) {
      extrapop = decoder.readSignedIntegerExpectString("unknown", extrapop_unknown);
    }
    else if (attribId == ATTRIB_STACKSHIFT) {
      // Allow this attribute for backward compatibility
    }
    else if (attribId == ATTRIB_STRATEGY) {
      strategystring = decoder.readString();
    }
    else if (attribId == ATTRIB_HASTHIS) {
      hasThis = decoder.readBool();
    }
    else if (attribId == ATTRIB_CONSTRUCTOR) {
      isConstruct = decoder.readBool();
    }
    else
      throw LowlevelError("Unknown prototype attribute");
  }
  if (name == "__thiscall")
    hasThis = true;
  if (extrapop == -300)
    throw LowlevelError("Missing prototype attributes");

  buildParamList(strategystring); // Allocate input and output ParamLists
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_INPUT) {
      input->decode(decoder,effectlist,stackgrowsnegative);
      if (stackspc != (AddrSpace *)0) {
	input->getRangeList(stackspc,paramrange);
	if (!paramrange.empty())
	  sawparamrange = true;
      }
    }
    else if (subId == ELEM_OUTPUT) {
      output->decode(decoder,effectlist,stackgrowsnegative);
    }
    else if (subId == ELEM_UNAFFECTED) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	effectlist.emplace_back();
	effectlist.back().decode(EffectRecord::unaffected,decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_KILLEDBYCALL) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	effectlist.emplace_back();
	effectlist.back().decode(EffectRecord::killedbycall,decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_RETURNADDRESS) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	effectlist.emplace_back();
	effectlist.back().decode(EffectRecord::return_address,decoder);
      }
      decoder.closeElement(subId);
      sawretaddr = true;
    }
    else if (subId == ELEM_LOCALRANGE) {
      sawlocalrange = true;
      decoder.openElement();
      while(decoder.peekElement() != 0) {
        Range range;
        range.decode(decoder);
        localrange.insertRange(range.getSpace(),range.getFirst(),range.getLast());
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_PARAMRANGE) {
      sawparamrange = true;
      decoder.openElement();
      while(decoder.peekElement() != 0) {
        Range range;
        range.decode(decoder);
        paramrange.insertRange(range.getSpace(),range.getFirst(),range.getLast());
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_LIKELYTRASH) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	likelytrash.emplace_back();
	likelytrash.back().decode(decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_INTERNAL_STORAGE) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	internalstorage.emplace_back();
	internalstorage.back().decode(decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_PCODE) {
      int4 injectId = glb->pcodeinjectlib->decodeInject("Protomodel : "+name, name,
							InjectPayload::CALLMECHANISM_TYPE,decoder);
      InjectPayload *payload = glb->pcodeinjectlib->getPayload(injectId);
      if (payload->getName().find("uponentry") != string::npos)
	injectUponEntry = injectId;
      else
	injectUponReturn = injectId;
    }
    else
      throw LowlevelError("Unknown element in prototype");
  }
  decoder.closeElement(elemId);
  if ((!sawretaddr)&&(glb->defaultReturnAddr.space != (AddrSpace *)0)) {
    // Provide the default return address, if there isn't a specific one for the model
    effectlist.push_back(EffectRecord(glb->defaultReturnAddr,EffectRecord::return_address));
  }
  sort(effectlist.begin(),effectlist.end(),EffectRecord::compareByAddress);
  sort(likelytrash.begin(),likelytrash.end());
  sort(internalstorage.begin(),internalstorage.end());
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

    if (EffectRecord::compareByAddress(eff1, eff2))
      i += 1;
    else if (EffectRecord::compareByAddress(eff2, eff1))
      j += 1;
    else {
      if (eff1 == eff2)
	newlist.push_back(eff1);
      i += 1;
      j += 1;
    }
  }
  effectlist.swap(newlist);
}

/// The intersection of two containers of register Varnodes is calculated, and the result is
/// placed in the first container, replacing the original contents.  The containers must already be sorted.
/// \param regList1 is the first container
/// \param regList2 is the second container
void ProtoModelMerged::intersectRegisters(vector<VarnodeData> &regList1,const vector<VarnodeData> &regList2)

{
  vector<VarnodeData> newlist;

  int4 i=0;
  int4 j=0;
  while((i<regList1.size())&&(j<regList2.size())) {
    const VarnodeData &trs1( regList1[i] );
    const VarnodeData &trs2( regList2[j] );

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
  regList1.swap(newlist);
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
    intersectRegisters(likelytrash,model->likelytrash);
    intersectRegisters(internalstorage,model->internalstorage);
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

void ProtoModelMerged::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_RESOLVEPROTOTYPE);
  name = decoder.readString(ATTRIB_NAME);
  for(;;) { // A tag for each merged prototype
    uint4 subId = decoder.openElement();
    if (subId != ELEM_MODEL) break;
    string modelName = decoder.readString(ATTRIB_NAME);
    ProtoModel *mymodel = glb->getModel( modelName );
    if (mymodel == (ProtoModel *)0)
      throw LowlevelError("Missing prototype model: "+modelName);
    decoder.closeElement(subId);
    foldIn(mymodel);
    modellist.push_back(mymodel);
  }
  decoder.closeElement(elemId);
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
/// allocate an (uninitialized) parameter.
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
  res->sym = scope->getCategorySymbol(Symbol::function_parameter,i);
  SymbolEntry *entry;
  Address usepoint;

  bool isindirect = (pieces.flags & ParameterPieces::indirectstorage) != 0;
  bool ishidden = (pieces.flags & ParameterPieces::hiddenretparm) != 0;
  bool istypelock = (pieces.flags & ParameterPieces::typelock) != 0;
  bool isnamelock = (pieces.flags & ParameterPieces::namelock) != 0;
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
    scope->setCategory(res->sym,Symbol::function_parameter,i);
    if (isindirect || ishidden || istypelock || isnamelock) {
      uint4 mirror = 0;
      if (isindirect)
	mirror |= Varnode::indirectstorage;
      if (ishidden)
	mirror |= Varnode::hiddenretparm;
      if (istypelock)
	mirror |= Varnode::typelock;
      if (isnamelock)
	mirror |= Varnode::namelock;
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
  if (res->sym->isTypeLocked() != istypelock) {
    if (istypelock)
      scope->setAttribute(res->sym,Varnode::typelock);
    else
      scope->clearAttribute(res->sym,Varnode::typelock);
  }
  if (res->sym->isNameLocked() != isnamelock) {
    if (isnamelock)
      scope->setAttribute(res->sym,Varnode::namelock);
    else
      scope->clearAttribute(res->sym,Varnode::namelock);
  }
  if ((nm.size()!=0)&&(nm!=res->sym->getName()))
    scope->renameSymbol(res->sym,nm);
  if (pieces.type != res->sym->getType())
    scope->retypeSymbol(res->sym,pieces.type);
  return res;
}

void ProtoStoreSymbol::clearInput(int4 i)

{
  Symbol *sym = scope->getCategorySymbol(Symbol::function_parameter,i);
  if (sym != (Symbol *)0) {
    scope->setCategory(sym,Symbol::no_category,0); // Remove it from category list
    scope->removeSymbol(sym);	// Remove it altogether
  }
  // Renumber any category 0 symbol with index greater than i
  int4 sz = scope->getCategorySize(Symbol::function_parameter);
  for(int4 j=i+1;j<sz;++j) {
    sym = scope->getCategorySymbol(Symbol::function_parameter,j);
    if (sym != (Symbol *)0)
      scope->setCategory(sym,Symbol::function_parameter,j-1);
  }
}

void ProtoStoreSymbol::clearAllInputs(void)

{
  scope->clearCategory(0);
}

int4 ProtoStoreSymbol::getNumInputs(void) const

{
  return scope->getCategorySize(Symbol::function_parameter);
}

ProtoParameter *ProtoStoreSymbol::getInput(int4 i)

{
  Symbol *sym = scope->getCategorySymbol(Symbol::function_parameter,i);
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

void ProtoStoreSymbol::encode(Encoder &encoder) const

{ // Do not store anything explicitly for a symboltable backed store
  // as the symboltable will be stored separately
}

void ProtoStoreSymbol::decode(Decoder &decoder,ProtoModel *model)

{
  throw LowlevelError("Do not decode symbol-backed prototype through this interface");
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

void ProtoStoreInternal::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_INTERNALLIST);
  if (outparam != (ProtoParameter *)0) {
    encoder.openElement(ELEM_RETPARAM);
    if (outparam->isTypeLocked())
      encoder.writeBool(ATTRIB_TYPELOCK,true);
    outparam->getAddress().encode(encoder);
    outparam->getType()->encodeRef(encoder);
    encoder.closeElement(ELEM_RETPARAM);
  }
  else {
    encoder.openElement(ELEM_RETPARAM);
    encoder.openElement(ELEM_ADDR);
    encoder.closeElement(ELEM_ADDR);
    encoder.openElement(ELEM_VOID);
    encoder.closeElement(ELEM_VOID);
    encoder.closeElement(ELEM_RETPARAM);
  }

  for(int4 i=0;i<inparam.size();++i) {
    ProtoParameter *param = inparam[i];
    encoder.openElement(ELEM_PARAM);
    if (param->getName().size()!=0)
      encoder.writeString(ATTRIB_NAME,param->getName());
    if (param->isTypeLocked())
      encoder.writeBool(ATTRIB_TYPELOCK, true);
    if (param->isNameLocked())
      encoder.writeBool(ATTRIB_NAMELOCK, true);
    if (param->isThisPointer())
      encoder.writeBool(ATTRIB_THISPTR, true);
    if (param->isIndirectStorage())
      encoder.writeBool(ATTRIB_INDIRECTSTORAGE, true);
    if (param->isHiddenReturn())
      encoder.writeBool(ATTRIB_HIDDENRETPARM, true);
    param->getAddress().encode(encoder);
    param->getType()->encodeRef(encoder);
    encoder.closeElement(ELEM_PARAM);
  }
  encoder.closeElement(ELEM_INTERNALLIST);
}

void ProtoStoreInternal::decode(Decoder &decoder,ProtoModel *model)

{
  Architecture *glb = model->getArch();
  vector<ParameterPieces> pieces;
  PrototypePieces proto;
  proto.model = model;
  proto.firstVarArgSlot = -1;
  bool addressesdetermined = true;

  pieces.emplace_back(); // Push on placeholder for output pieces
  pieces.back().type = outparam->getType();
  pieces.back().flags = 0;
  if (outparam->isTypeLocked())
    pieces.back().flags |= ParameterPieces::typelock;
  if (outparam->isIndirectStorage())
    pieces.back().flags |= ParameterPieces::indirectstorage;
  if (outparam->getAddress().isInvalid())
    addressesdetermined = false;

  uint4 elemId = decoder.openElement(ELEM_INTERNALLIST);
  uint4 firstId = decoder.getNextAttributeId();
  if (firstId == ATTRIB_FIRST) {
    proto.firstVarArgSlot = decoder.readSignedInteger();
  }
  for(;;) { // This is only the input params
    uint4 subId = decoder.openElement();		// <retparam> or <param>
    if (subId == 0) break;
    string name;
    uint4 flags = 0;
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_NAME)
	name = decoder.readString();
      else if (attribId == ATTRIB_TYPELOCK) {
	if (decoder.readBool())
	  flags |= ParameterPieces::typelock;
      }
      else if (attribId == ATTRIB_NAMELOCK) {
	if (decoder.readBool())
	  flags |= ParameterPieces::namelock;
      }
      else if (attribId == ATTRIB_THISPTR) {
	if (decoder.readBool())
	  flags |= ParameterPieces::isthis;
      }
      else if (attribId == ATTRIB_INDIRECTSTORAGE) {
	if (decoder.readBool())
	  flags |= ParameterPieces::indirectstorage;
      }
      else if (attribId == ATTRIB_HIDDENRETPARM) {
	if (decoder.readBool())
	  flags |= ParameterPieces::hiddenretparm;
      }
    }
    if ((flags & ParameterPieces::hiddenretparm) == 0)
      proto.innames.push_back(name);
    pieces.emplace_back();
    ParameterPieces &curparam( pieces.back() );
    curparam.addr = Address::decode(decoder);
    curparam.type = glb->types->decodeType(decoder);
    curparam.flags = flags;
    if (curparam.addr.isInvalid())
      addressesdetermined = false;
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
  ProtoParameter *curparam;
  if (!addressesdetermined) {
    // If addresses for parameters are not provided, use
    // the model to derive them from type info
    proto.outtype = pieces[0].type;
    for(int4 i=1;i<pieces.size();++i) // Save off the decoded types
      proto.intypes.push_back( pieces[i].type );
    vector<ParameterPieces> addrPieces;
    model->assignParameterStorage(proto,addrPieces,true);
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
  uint4 j=0;
  for(uint4 i=1;i<pieces.size();++i) {
    if ((pieces[i].flags&ParameterPieces::hiddenretparm)!=0) {
       curparam = setInput(i-1,"rethidden",pieces[i]);
       curparam->setTypeLock((pieces[0].flags & ParameterPieces::typelock)!=0);   // Has output's typelock
       continue;    // increment i but not j
    }
    curparam = setInput(i-1,proto.innames[j],pieces[i]);
    curparam->setTypeLock((pieces[i].flags & ParameterPieces::typelock)!=0);
    curparam->setNameLock((pieces[i].flags & ParameterPieces::namelock)!=0);
    j = j + 1;
  }
}

/// This is called after a new prototype is established (via decode or updateAllTypes)
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

/// If the \e effectlist for \b this is non-empty, it contains the complete set of
/// EffectRecords.  Save just those that override the underlying list from ProtoModel
/// \param encoder is the stream encoder
void FuncProto::encodeEffect(Encoder &encoder) const

{
  if (effectlist.empty()) return;
  vector<const EffectRecord *> unaffectedList;
  vector<const EffectRecord *> killedByCallList;
  const EffectRecord *retAddr = (const EffectRecord *)0;
  for(vector<EffectRecord>::const_iterator iter=effectlist.begin();iter!=effectlist.end();++iter) {
    const EffectRecord &curRecord( *iter );
    uint4 type = model->hasEffect(curRecord.getAddress(), curRecord.getSize());
    if (type == curRecord.getType()) continue;
    if (curRecord.getType() == EffectRecord::unaffected)
      unaffectedList.push_back(&curRecord);
    else if (curRecord.getType() == EffectRecord::killedbycall)
      killedByCallList.push_back(&curRecord);
    else if (curRecord.getType() == EffectRecord::return_address)
      retAddr = &curRecord;
  }
  if (!unaffectedList.empty()) {
    encoder.openElement(ELEM_UNAFFECTED);
    for(int4 i=0;i<unaffectedList.size();++i) {
      unaffectedList[i]->encode(encoder);
    }
    encoder.closeElement(ELEM_UNAFFECTED);
  }
  if (!killedByCallList.empty()) {
    encoder.openElement(ELEM_KILLEDBYCALL);
    for(int4 i=0;i<killedByCallList.size();++i) {
      killedByCallList[i]->encode(encoder);
    }
    encoder.closeElement(ELEM_KILLEDBYCALL);
  }
  if (retAddr != (const EffectRecord *)0) {
    encoder.openElement(ELEM_RETURNADDRESS);
    retAddr->encode(encoder);
    encoder.closeElement(ELEM_RETURNADDRESS);
  }
}

/// If the \b likelytrash list is not empty it overrides the underlying ProtoModel's list.
/// Encode any VarnodeData that does not appear in the ProtoModel to the stream.
/// \param encoder is the stream encoder
void FuncProto::encodeLikelyTrash(Encoder &encoder) const

{
  if (likelytrash.empty()) return;
  vector<VarnodeData>::const_iterator iter1,iter2;
  iter1 = model->trashBegin();
  iter2 = model->trashEnd();
  encoder.openElement(ELEM_LIKELYTRASH);
  for(vector<VarnodeData>::const_iterator iter=likelytrash.begin();iter!=likelytrash.end();++iter) {
    const VarnodeData &cur(*iter);
    if (binary_search(iter1,iter2,cur)) continue;	// Already exists in ProtoModel
    encoder.openElement(ELEM_ADDR);
    cur.space->encodeAttributes(encoder,cur.offset,cur.size);
    encoder.closeElement(ELEM_ADDR);
  }
  encoder.closeElement(ELEM_LIKELYTRASH);
}

/// EffectRecords read into \e effectlist by decode() override the list from ProtoModel.
/// If this list is not empty, set up \e effectlist as a complete override containing
/// all EffectRecords from ProtoModel plus all the overrides.
void FuncProto::decodeEffect(void)

{
  if (effectlist.empty()) return;
  vector<EffectRecord> tmpList;
  tmpList.swap(effectlist);
  for(vector<EffectRecord>::const_iterator iter=model->effectBegin();iter!=model->effectEnd();++iter) {
    effectlist.push_back(*iter);
  }
  bool hasNew = false;
  int4 listSize = effectlist.size();
  for(vector<EffectRecord>::const_iterator iter=tmpList.begin();iter!=tmpList.end();++iter) {
    const EffectRecord &curRecord( *iter );
    int4 off = ProtoModel::lookupRecord(effectlist, listSize, curRecord.getAddress(), curRecord.getSize());
    if (off == -2)
      throw LowlevelError("Partial overlap of prototype override with existing effects");
    else if (off >= 0) {
      // Found matching record, change its type
      effectlist[off] = curRecord;
    }
    else {
      effectlist.push_back(curRecord);
      hasNew = true;
    }
  }
  if (hasNew)
    sort(effectlist.begin(),effectlist.end(),EffectRecord::compareByAddress);
}

/// VarnodeData read into \e likelytrash by decode() are additional registers over
/// what is already in ProtoModel.  Make \e likelytrash in \b this a complete list by
/// merging in everything from ProtoModel.
void FuncProto::decodeLikelyTrash(void)

{
  if (likelytrash.empty()) return;
  vector<VarnodeData> tmpList;
  tmpList.swap(likelytrash);
  vector<VarnodeData>::const_iterator iter1,iter2;
  iter1 = model->trashBegin();
  iter2 = model->trashEnd();
  for(vector<VarnodeData>::const_iterator iter=iter1;iter!=iter2;++iter)
    likelytrash.push_back(*iter);
  for(vector<VarnodeData>::const_iterator iter=tmpList.begin();iter!=tmpList.end();++iter) {
    if (!binary_search(iter1,iter2,*iter))
      likelytrash.push_back(*iter);		// Add in the new register
  }
  sort(likelytrash.begin(),likelytrash.end());
}

/// Prepend the indicated number of input parameters to \b this.
/// The new parameters have a data-type of xunknown4. If they were
/// originally locked, the existing parameters are preserved.
/// \param paramshift is the number of parameters to add (must be >0)
void FuncProto::paramShift(int4 paramshift)

{
  if ((model == (ProtoModel *)0)||(store == (ProtoStore *)0))
    throw LowlevelError("Cannot parameter shift without a model");

  PrototypePieces proto;
  proto.model = model;
  proto.firstVarArgSlot = -1;
  TypeFactory *typefactory = model->getArch()->types;

  if (isOutputLocked())
    proto.outtype = getOutputType();
  else
    proto.outtype = typefactory->getTypeVoid();

  Datatype *extra = typefactory->getBase(4,TYPE_UNKNOWN); // The extra parameters have this type
  for(int4 i=0;i<paramshift;++i) {
    proto.innames.push_back("");
    proto.intypes.push_back(extra);
  }

  if (isInputLocked()) {	// Copy in the original parameter types
    int4 num = numParams();
    for(int4 i=0;i<num;++i) {
      ProtoParameter *param = getParam(i);
      proto.innames.push_back(param->getName());
      proto.intypes.push_back( param->getType() );
    }
  }
  else
    proto.firstVarArgSlot = paramshift;

  // Reassign the storage locations for this new parameter list
  vector<ParameterPieces> pieces;
  model->assignParameterStorage(proto,pieces,false);

  delete store;

  // This routine always converts -this- to have a ProtoStoreInternal
  store = new ProtoStoreInternal(typefactory->getTypeVoid());

  store->setOutput(pieces[0]);
  uint4 j=0;
  for(uint4 i=1;i<pieces.size();++i) {
    if ((pieces[i].flags & ParameterPieces::hiddenretparm) != 0) {
       store->setInput(i-1,"rethidden",pieces[i]);
       continue;   // increment i but not j
    }
    store->setInput(j,proto.innames[j],pieces[i]);
    j = j + 1;
  }
  setInputLock(true);
  setDotdotdot(proto.firstVarArgSlot >= 0);
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
    if (m->isAutoKillByCall())
      flags |= auto_killbycall;
    model = m;
  }
  else {
    model = m;
    extrapop = ProtoModel::extrapop_unknown;
  }
}

/// The full function prototype is (re)set from a model, names, and data-types
/// The new input and output parameters are both assumed to be locked.
/// \param pieces is the raw collection of names and data-types
void FuncProto::setPieces(const PrototypePieces &pieces)

{
  if (pieces.model != (ProtoModel *)0)
    setModel(pieces.model);
  updateAllTypes(pieces);
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
  pieces.firstVarArgSlot = isDotdotdot() ? num : -1;
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

/// Set the id directly.
/// \param id is the new id
void FuncProto::setInjectId(int4 id)

{
  if (id < 0)
    cancelInjectId();
  else {
    injectid = id;
    flags |= is_inline;
  }
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
/// \param proto is the list of names, data-types, and other attributes
void FuncProto::updateAllTypes(const PrototypePieces &proto)

{
  setModel(model);		// This resets extrapop
  store->clearAllInputs();
  store->clearOutput();
  flags &= ~((uint4)voidinputlock);
  setDotdotdot(proto.firstVarArgSlot >= 0);

  vector<ParameterPieces> pieces;

  // Calculate what memory locations hold each type
  try {
    model->assignParameterStorage(proto,pieces,false);
    store->setOutput(pieces[0]);
    uint4 j=0;
    for(uint4 i=1;i<pieces.size();++i) {
      if ((pieces[i].flags & ParameterPieces::hiddenretparm) != 0) {
         store->setInput(i-1,"rethidden",pieces[i]);
         continue;       // increment i but not j
      }
      string nm = (j >= proto.innames.size()) ? "" : proto.innames[j];
      store->setInput(i-1,nm,pieces[i]);
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

/// \return the iterator to the start of the list
vector<VarnodeData>::const_iterator FuncProto::trashBegin(void) const

{
  if (likelytrash.empty())
    return model->trashBegin();
  return likelytrash.begin();
}

/// \return the iterator to the end of the list
vector<VarnodeData>::const_iterator FuncProto::trashEnd(void) const

{
  if (likelytrash.empty())
    return model->trashEnd();
  return likelytrash.end();
}

/// \brief Decide whether a given storage location could be, or could hold, an input parameter
///
/// If the input is locked, check if the location overlaps one of the current parameters.
/// Otherwise, check if the location overlaps an entry in the prototype model.
/// Return:
///   - no_containment - there is no containment between the range and any input parameter
///   - contains_unjustified - at least one parameter contains the range
///   - contains_justified - at least one parameter contains this range as its least significant bytes
///   - contained_by - no parameter contains this range, but the range contains at least one parameter
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
      bool resContains = false;
      bool resContainedBy = false;
      for(int4 i=0;i<num;++i) {
	ProtoParameter *param = getParam(i);
	if (!param->isTypeLocked()) continue;
	locktest = true;
	Address iaddr = param->getAddress();
	// If the parameter already exists, the varnode must be justified in the parameter relative
	// to the endianness of the space, irregardless of the forceleft flag
	int4 off = iaddr.justifiedContain(param->getSize(), addr, size, false);
	if (off == 0)
	  return ParamEntry::contains_justified;
	else if (off > 0)
	  resContains = true;
	if (iaddr.containedBy(param->getSize(), addr, size))
	  resContainedBy = true;
      }
      if (locktest) {
	if (resContains) return ParamEntry::contains_unjustified;
	if (resContainedBy) return ParamEntry::contained_by;
	return ParamEntry::no_containment;
      }
    }
  }
  return model->characterizeAsInputParam(addr, size);
}

/// \brief Decide whether a given storage location could be, or could hold, the return value
///
/// If the output is locked, check if the location overlaps the current return storage.
/// Otherwise, check if the location overlaps an entry in the prototype model.
/// Return:
///   - no_containment - there is no containment between the range and any output storage
///   - contains_unjustified - at least one output storage contains the range
///   - contains_justified - at least one output storage contains this range as its least significant bytes
///   - contained_by - no output storage contains this range, but the range contains at least one output storage
/// \param addr is the starting address of the given storage location
/// \param size is the number of bytes in the storage
/// \return the characterization code
int4 FuncProto::characterizeAsOutput(const Address &addr,int4 size) const

{
  if (isOutputLocked()) {
    ProtoParameter *outparam = getOutput();
    if (outparam->getType()->getMetatype() == TYPE_VOID)
      return ParamEntry::no_containment;
    Address iaddr = outparam->getAddress();
    // If the output is locked, the varnode must be justified in the location relative
    // to the endianness of the space, irregardless of the forceleft flag
    int4 off = iaddr.justifiedContain(outparam->getSize(),addr,size,false);
    if (off == 0)
      return ParamEntry::contains_justified;
    else if (off > 0)
      return ParamEntry::contains_unjustified;
    if (iaddr.containedBy(outparam->getSize(),addr,size))
      return ParamEntry::contained_by;
    return ParamEntry::no_containment;
  }
  return model->characterizeAsOutput(addr, size);
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

/// \param loc is the starting address of the given range
/// \param size is the number of bytes in the range
/// \param res will hold the output storage description being passed back
/// \return \b true if there is at least one possible output contained in the range
bool FuncProto::getBiggestContainedOutput(const Address &loc,int4 size,VarnodeData &res) const

{
  if (isOutputLocked()) {
    ProtoParameter *outparam = getOutput();
    if (outparam->getType()->getMetatype() == TYPE_VOID)
      return false;
    Address iaddr = outparam->getAddress();
    if (iaddr.containedBy(outparam->getSize(), loc, size)) {
      res.space = iaddr.getSpace();
      res.offset = iaddr.getOffset();
      res.size = outparam->getSize();
      return true;
    }
    return false;
  }
  return model->getBiggestContainedOutput(loc,size,res);
}

/// A likely pointer data-type for "this" pointer is passed in, which can be pointer to void. As the
/// storage of "this" may depend on the full prototype, if the prototype is not already locked in, we
/// assume the prototype returns void and takes the given data-type as the single input parameter.
/// \param dt is the given input data-type
/// \return the starting address of storage for the "this" pointer
Address FuncProto::getThisPointerStorage(Datatype *dt)

{
  if (!model->hasThisPointer())
    return Address();
  PrototypePieces proto;
  proto.model = model;
  proto.firstVarArgSlot = -1;
  proto.outtype = getOutputType();
  proto.intypes.push_back(dt);
  vector<ParameterPieces> res;
  model->assignParameterStorage(proto, res, true);
  for(int4 i=1;i<res.size();++i) {
    if ((res[i].flags & ParameterPieces::hiddenretparm) != 0) continue;
    return res[i].addr;
  }
  return Address();
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

/// This assumes the storage location has already been determined to be contained
/// in standard return value location.
/// \return \b true if the location should be considered killed by call
bool FuncProto::isAutoKillByCall(void) const

{
  if ((flags & auto_killbycall)!=0)
    return true;		// The ProtoModel always does killbycall
  if (isOutputLocked())
    return true;		// A locked output location is killbycall by definition
  return false;
}

/// \brief Encode \b this to a stream as a \<prototype> element.
///
/// Save everything under the control of this prototype, which
/// may \e not include input parameters, as these are typically
/// controlled by the function's symbol table scope.
/// \param encoder is the stream encoder
void FuncProto::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_PROTOTYPE);
  encoder.writeString(ATTRIB_MODEL, model->getName());
  if (extrapop == ProtoModel::extrapop_unknown)
    encoder.writeString(ATTRIB_EXTRAPOP, "unknown");
  else
    encoder.writeSignedInteger(ATTRIB_EXTRAPOP, extrapop);
  if (isDotdotdot())
    encoder.writeBool(ATTRIB_DOTDOTDOT, true);
  if (isModelLocked())
    encoder.writeBool(ATTRIB_MODELLOCK, true);
  if ((flags&voidinputlock)!=0)
    encoder.writeBool(ATTRIB_VOIDLOCK, true);
  if (isInline())
    encoder.writeBool(ATTRIB_INLINE, true);
  if (isNoReturn())
    encoder.writeBool(ATTRIB_NORETURN, true);
  if (hasCustomStorage())
    encoder.writeBool(ATTRIB_CUSTOM, true);
  if (isConstructor())
    encoder.writeBool(ATTRIB_CONSTRUCTOR, true);
  if (isDestructor())
    encoder.writeBool(ATTRIB_DESTRUCTOR, true);
  ProtoParameter *outparam = store->getOutput();
  encoder.openElement(ELEM_RETURNSYM);
  if (outparam->isTypeLocked())
    encoder.writeBool(ATTRIB_TYPELOCK, true);
  outparam->getAddress().encode(encoder,outparam->getSize());
  outparam->getType()->encodeRef(encoder);
  encoder.closeElement(ELEM_RETURNSYM);
  encodeEffect(encoder);
  encodeLikelyTrash(encoder);
  if (injectid >= 0) {
    Architecture *glb = model->getArch();
    encoder.openElement(ELEM_INJECT);
    encoder.writeString(ATTRIB_CONTENT, glb->pcodeinjectlib->getCallFixupName(injectid));
    encoder.closeElement(ELEM_INJECT);
  }
  store->encode(encoder);		// Store any internally backed prototyped symbols
  encoder.closeElement(ELEM_PROTOTYPE);
}

/// \brief Restore \b this from a \<prototype> element in the given stream
///
/// The backing store for the parameters must already be established using either
/// setStore() or setInternal().
/// \param decoder is the given stream decoder
/// \param glb is the Architecture owning the prototype
void FuncProto::decode(Decoder &decoder,Architecture *glb)

{
  // Model must be set first
  if (store == (ProtoStore *)0)
    throw LowlevelError("Prototype storage must be set before restoring FuncProto");
  ProtoModel *mod = (ProtoModel *)0;
  bool seenextrapop = false;
  int4 readextrapop;
  flags = 0;
  injectid = -1;
  uint4 elemId = decoder.openElement(ELEM_PROTOTYPE);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_MODEL) {
      string modelname = decoder.readString();
      if (modelname.size()==0 || modelname == "default")
	mod = glb->defaultfp;	// Use the default model
      else {
	mod = glb->getModel(modelname);
	if (mod == (ProtoModel *)0)	// Model name is unrecognized
	  mod = glb->createUnknownModel(modelname);	// Create model with placeholder behavior
      }
    }
    else if (attribId == ATTRIB_EXTRAPOP) {
      seenextrapop = true;
      readextrapop = decoder.readSignedIntegerExpectString("unknown", ProtoModel::extrapop_unknown);
    }
    else if (attribId == ATTRIB_MODELLOCK) {
      if (decoder.readBool())
	flags |= modellock;
    }
    else if (attribId == ATTRIB_DOTDOTDOT) {
      if (decoder.readBool())
	flags |= dotdotdot;
    }
    else if (attribId == ATTRIB_VOIDLOCK) {
      if (decoder.readBool())
	flags |= voidinputlock;
    }
    else if (attribId == ATTRIB_INLINE) {
      if (decoder.readBool())
	flags |= is_inline;
    }
    else if (attribId == ATTRIB_NORETURN) {
      if (decoder.readBool())
	flags |= no_return;
    }
    else if (attribId == ATTRIB_CUSTOM) {
      if (decoder.readBool())
	flags |= custom_storage;
    }
    else if (attribId == ATTRIB_CONSTRUCTOR) {
      if (decoder.readBool())
	flags |= is_constructor;
    }
    else if (attribId == ATTRIB_DESTRUCTOR) {
      if (decoder.readBool())
	flags |= is_destructor;
    }
  }
  if (mod != (ProtoModel *)0) // If a model was specified
    setModel(mod);		// This sets extrapop to model default
  if (seenextrapop)		// If explicitly set
    extrapop = readextrapop;

  uint4 subId = decoder.peekElement();
  if (subId != 0) {
    ParameterPieces outpieces;
    bool outputlock = false;

    if (subId == ELEM_RETURNSYM) {
      decoder.openElement();
      for(;;) {
	uint4 attribId = decoder.getNextAttributeId();
	if (attribId == 0) break;
	if (attribId == ATTRIB_TYPELOCK)
	  outputlock = decoder.readBool();
      }
      int4 tmpsize;
      outpieces.addr = Address::decode(decoder,tmpsize);
      outpieces.type = glb->types->decodeType(decoder);
      outpieces.flags = 0;
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_ADDR) { // Old-style specification of return (supported partially for backward compat)
      int4 tmpsize;
      outpieces.addr = Address::decode(decoder,tmpsize);
      outpieces.type = glb->types->decodeType(decoder);
      outpieces.flags = 0;
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

  for(;;) {
    subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_UNAFFECTED) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	effectlist.emplace_back();
	effectlist.back().decode(EffectRecord::unaffected,decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_KILLEDBYCALL) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	effectlist.emplace_back();
	effectlist.back().decode(EffectRecord::killedbycall,decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_RETURNADDRESS) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	effectlist.emplace_back();
	effectlist.back().decode(EffectRecord::return_address,decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_LIKELYTRASH) {
      decoder.openElement();
      while(decoder.peekElement() != 0) {
	likelytrash.emplace_back();
	likelytrash.back().decode(decoder);
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_INJECT) {
      decoder.openElement();
      string injectString = decoder.readString(ATTRIB_CONTENT);
      injectid = glb->pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE,injectString);
      flags |= is_inline;
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_INTERNALLIST) {
      store->decode(decoder,model);
    }
  }
  decoder.closeElement(elemId);
  decodeEffect();
  decodeLikelyTrash();
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

/// \brief Add a an input parameter that will resolve to the current stack offset for \b this call site
///
/// A LOAD from a free reference to the \e spacebase pointer of the given AddrSpace is created and
/// its output is added as a parameter to the call.  Later the LOAD should resolve to a COPY from
/// a Varnode in the AddrSpace, whose offset is then the current offset.
/// \param data is the function where the LOAD is created
/// \param spacebase is the given (stack) AddrSpace
void FuncCallSpecs::createPlaceholder(Funcdata &data,AddrSpace *spacebase)

{
  int4 slot = op->numInput();
  Varnode *loadval = data.opStackLoad(spacebase,0,1,op,(Varnode *)0,false);
  data.opInsertInput(op,loadval,slot);
  setStackPlaceholderSlot(slot);
  loadval->setSpacebasePlaceholder();
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
      abortSpacebaseRelative(data);
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
    Varnode *vn = op->getIn(stackPlaceholderSlot);
    data.opRemoveInput(op,stackPlaceholderSlot);
    clearStackPlaceholderSlot();
    // Remove the op producing the placeholder as well
    if (vn->hasNoDescend() && vn->getSpace()->getType() == IPTR_INTERNAL && vn->isWritten())
      data.opDestroy(vn->getDef());
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
  isstackoutputlock = false;
}

void FuncCallSpecs::setFuncdata(Funcdata *f)

{
  if (fd != (Funcdata *)0)
    throw LowlevelError("Setting call spec function multiple times");
  fd = f;
  if (fd != (Funcdata *)0) {
    entryaddress = fd->getAddress();
    if (fd->getDisplayName().size() != 0)
      name = fd->getDisplayName();
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

/// \brief Return any outputs of \b this CALL that contain or are contained by the given return value parameter
///
/// The output Varnodes may be attached to the base CALL or CALLIND, but also may be
/// attached to an INDIRECT preceding the CALL. The output Varnodes may not exactly match
/// the dimensions of the given parameter. We pass back a Varnode if either:
///    - The parameter contains the Varnode   (the easier case)  OR if
///    - The Varnode properly contains the parameter
/// \param param is the given paramter (return value)
/// \param newoutput will hold any overlapping output Varnodes
/// \return the matching PcodeOp or NULL
void FuncCallSpecs::transferLockedOutputParam(ProtoParameter *param,vector<Varnode *> &newoutput)

{
  Varnode *vn = op->getOut();
  if (vn != (Varnode *)0) {
    if (param->getAddress().justifiedContain(param->getSize(),vn->getAddr(),vn->getSize(),false)>=0)
      newoutput.push_back(vn);
    else if (vn->getAddr().justifiedContain(vn->getSize(),param->getAddress(),param->getSize(),false)>=0)
      newoutput.push_back(vn);
  }
  PcodeOp *indop = op->previousOp();
  while((indop!=(PcodeOp *)0)&&(indop->code()==CPUI_INDIRECT)) {
    if (indop->isIndirectCreation()) {
      vn = indop->getOut();
      if (param->getAddress().justifiedContain(param->getSize(),vn->getAddr(),vn->getSize(),false)>=0)
	newoutput.push_back(vn);
      else if (vn->getAddr().justifiedContain(vn->getSize(),param->getAddress(),param->getSize(),false)>=0)
	newoutput.push_back(vn);
    }
    indop = indop->previousOp();
  }
}

/// \brief List and/or create a Varnode for each input parameter of matching a source prototype
///
/// Varnodes are taken for current trials associated with \b this call spec.
/// Varnodes will be passed back in the order that they match the source input parameters.
/// A NULL Varnode indicates a stack parameter. Varnode dimensions may not match
/// parameter dimensions exactly.
/// \param newinput will hold the resulting list of Varnodes
/// \param source is the source prototype
/// \return \b false only if the list needs to indicate stack variables and there is no stack-pointer placeholder
bool FuncCallSpecs::transferLockedInput(vector<Varnode *> &newinput,const FuncProto &source)

{
  newinput.push_back(op->getIn(0)); // Always keep the call destination address
  int4 numparams = source.numParams();
  Varnode *stackref = (Varnode *)0;
  for(int4 i=0;i<numparams;++i) {
    int4 reuse = transferLockedInputParam(source.getParam(i));
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

/// \brief Pass back the Varnode needed to match the output parameter (return value) of a source prototype
///
/// Search for the Varnode matching the output parameter and pass
/// it back. The dimensions of the Varnode may not exactly match the return value.
/// If the return value is \e void, a NULL is passed back.
/// \param newoutput will hold the passed back Varnode
/// \param source is the source prototype
/// \return \b true if the passed back value is accurate
bool FuncCallSpecs::transferLockedOutput(vector<Varnode *> &newoutput,const FuncProto &source)

{
  ProtoParameter *param = source.getOutput();
  if (param->getType()->getMetatype() == TYPE_VOID) {
    return true;
  }
  transferLockedOutputParam(param,newoutput);
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
/// The current return value must be locked and is presumably out of date with the current CALL output.
/// Unless the return value is \e void, the output Varnode must exist and must be provided.
/// The Varnode is created/updated to reflect the return value and is set as the CALL output.
/// Any other intersecting outputs are updated to be either truncations or extensions of this.
/// Any active trials are updated,
/// \param data is the calling function
/// \param newoutput is the list of intersecting outputs
void FuncCallSpecs::commitNewOutputs(Funcdata &data,vector<Varnode *> &newoutput)

{
  if (!isOutputLocked()) return;
  activeoutput.clear();

  if (!newoutput.empty()) {
    ProtoParameter *param = getOutput();
    // We could conceivably truncate the output to the correct size to match the parameter
    activeoutput.registerTrial(param->getAddress(),param->getSize());
    if (param->getSize() == 1 && param->getType()->getMetatype() == TYPE_BOOL && data.isTypeRecoveryOn())
      data.opMarkCalculatedBool(op);
    Varnode *exactMatch = (Varnode *)0;
    for(int4 i=0;i<newoutput.size();++i) {
      if (newoutput[i]->getSize() == param->getSize()) {
	exactMatch = newoutput[i];
	break;
      }
    }
    Varnode *realOut;
    PcodeOp *indOp;
    if (exactMatch != (Varnode *)0) {
      // If we have a Varnode that exactly matches param, make sure it is the output of the CALL
      indOp = exactMatch->getDef();
      if (op != indOp) {
	// If we reach here, we know -op- must have no output
	data.opSetOutput(op,exactMatch);
	data.opUnlink(indOp);	// We know this is an indirect creation which is no longer used
      }
      realOut = exactMatch;
    }
    else {
      // Otherwise, we create a Varnode matching param
      data.opUnsetOutput(op);
      realOut = data.newVarnodeOut(param->getSize(),param->getAddress(),op);
    }

    for(int4 i=0;i<newoutput.size();++i) {
      Varnode *oldOut = newoutput[i];
      if (oldOut == exactMatch) continue;
      indOp = oldOut->getDef();
      if (indOp == op)
	indOp = (PcodeOp *)0;
      if (oldOut->getSize() < param->getSize()) {
	if (indOp != (PcodeOp *)0) {
	  data.opUninsert(indOp);
	  data.opSetOpcode(indOp,CPUI_SUBPIECE);
	}
	else {
	  indOp = data.newOp(2,op->getAddr());
	  data.opSetOpcode(indOp,CPUI_SUBPIECE);
	  data.opSetOutput(indOp,oldOut);	// Move oldOut from op to indOp
	}
	int4 overlap = oldOut->overlap(realOut->getAddr(),realOut->getSize());
	data.opSetInput(indOp,realOut,0);
	data.opSetInput(indOp,data.newConstant(4,(uintb)overlap),1);
	data.opInsertAfter(indOp,op);
      }
      else if (param->getSize() < oldOut->getSize()) {
	int4 overlap = oldOut->getAddr().justifiedContain(oldOut->getSize(), param->getAddress(), param->getSize(), false);
	VarnodeData vardata;
	// Test whether the new prototype naturally extends its output
	OpCode opc = assumedOutputExtension(param->getAddress(),param->getSize(),vardata);
	if (opc != CPUI_COPY && overlap == 0) {
	  // If oldOut looks like a natural extension of the true output type, create the extension op
	  if (opc == CPUI_PIECE) {	// Extend based on the data-type
	    if (param->getType()->getMetatype() == TYPE_INT)
	      opc = CPUI_INT_SEXT;
	    else
	      opc = CPUI_INT_ZEXT;
	  }
	  if (indOp != (PcodeOp *)0) {
	    data.opUninsert(indOp);
	    data.opRemoveInput(indOp,1);
	    data.opSetOpcode(indOp,opc);
	    data.opSetInput(indOp,realOut,0);
	    data.opInsertAfter(indOp,op);
	  }
	  else {
	    PcodeOp *extop = data.newOp(1,op->getAddr());
	    data.opSetOpcode(extop,opc);
	    data.opSetOutput(extop,oldOut);	// Move newout from -op- to -extop-
	    data.opSetInput(extop,realOut,0);
	    data.opInsertAfter(extop,op);
	  }
	}
	else {	// If all else fails, concatenate in extra byte from something "indirectly created" by -op-
	  if (indOp != (PcodeOp *)0) {
	    data.opUnlink(indOp);
	  }
	  int4 mostSigSize = oldOut->getSize() - overlap - realOut->getSize();
	  PcodeOp *lastOp = op;
	  if (overlap != 0) {		// We need to append less significant bytes to realOut for this oldOut
	    Address loAddr = oldOut->getAddr();
	    if (loAddr.isBigEndian())
	      loAddr = loAddr + (oldOut->getSize() - overlap);
	    PcodeOp *newIndOp = data.newIndirectCreation(op,loAddr,overlap,true);
	    PcodeOp *concatOp = data.newOp(2,op->getAddr());
	    data.opSetOpcode(concatOp,CPUI_PIECE);
	    data.opSetInput(concatOp,realOut,0); // Most significant part
	    data.opSetInput(concatOp,newIndOp->getOut(),1); // Least sig
	    data.opInsertAfter(concatOp,op);
	    if (mostSigSize != 0) {
	      if (loAddr.isBigEndian())
		data.newVarnodeOut(overlap+realOut->getSize(),realOut->getAddr(),concatOp);
	      else
		data.newVarnodeOut(overlap+realOut->getSize(),loAddr,concatOp);
	    }
	    lastOp = concatOp;
	  }
	  if (mostSigSize != 0) {	// We need to append more significant bytes to realOut for this oldOut
	    Address hiAddr = oldOut->getAddr();
	    if (!hiAddr.isBigEndian())
	      hiAddr = hiAddr + (realOut->getSize() + overlap);
	    PcodeOp *newIndOp = data.newIndirectCreation(op,hiAddr,mostSigSize,true);
	    PcodeOp *concatOp = data.newOp(2,op->getAddr());
	    data.opSetOpcode(concatOp,CPUI_PIECE);
	    data.opSetInput(concatOp,newIndOp->getOut(),0);
	    data.opSetInput(concatOp,lastOp->getOut(),1);
	    data.opInsertAfter(concatOp,lastOp);
	    lastOp = concatOp;
	  }
	  data.opSetOutput(lastOp,oldOut);	// We have completed the redefinition of this oldOut
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
bool FuncCallSpecs::lateRestriction(const FuncProto &restrictedProto,vector<Varnode *> &newinput,
				    vector<Varnode *> &newoutput)

{
  if (!hasModel()) {
    copy(restrictedProto);
    return true;
  }

  if (!isCompatible(restrictedProto)) return false;
  if (restrictedProto.isDotdotdot() && (!isinputactive)) return false;

  if (restrictedProto.isInputLocked()) {
    if (!transferLockedInput(newinput,restrictedProto))		// Redo all the varnode inputs (if possible)
      return false;
  }
  if (restrictedProto.isOutputLocked()) {
    if (!transferLockedOutput(newoutput,restrictedProto))	// Redo all the varnode outputs (if possible)
      return false;
  }
  copy(restrictedProto);		// Convert ourselves to restrictedProto

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
  name = newfd->getDisplayName();
  fd = newfd;

  Varnode *vn = data.newVarnodeCallSpecs(this);
  data.opSetInput(op,vn,0);
  data.opSetOpcode(op,CPUI_CALL);

  data.getOverride().insertIndirectOverride(op->getAddr(),entryaddress);

  // Try our best to merge existing prototype
  // with the one we have just been handed
  vector<Varnode *> newinput;
  vector<Varnode *> newoutput;
  FuncProto &newproto( newfd->getFuncProto() );
  if ((!newproto.isNoReturn())&&(!newproto.isInline())) {
    if (isOverride())	// If we are overridden at the call-site
      return;		// Don't use the discovered function prototype

    if (lateRestriction(newproto,newinput,newoutput)) {
      commitNewInputs(data,newinput);
      commitNewOutputs(data,newoutput);
      return;	// We have successfully updated the prototype, don't restart
    }
  }
  data.setRestartPending(true);
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
  vector<Varnode *> newoutput;

  // Copy the recovered prototype into the override manager so that
  // future restarts don't have to rediscover it
  FuncProto *newproto = new FuncProto();
  newproto->copy(fp);
  data.getOverride().insertProtoOverride(op->getAddr(),newproto);
  if (lateRestriction(fp,newinput,newoutput)) {
    commitNewInputs(data,newinput);
    commitNewOutputs(data,newoutput);
  }
  else {
    // Too late to make restrictions to correct prototype
    // Force a restart
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
  int4 id = getInjectUponReturn();
  if (id < 0) return;		// Nothing to inject
  InjectPayload *payload = data.getArch()->pcodeinjectlib->getPayload(id);

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
  int4 expop = 0;
  if (hasModel()) {
    callee_pop = (getModelExtraPop() == ProtoModel::extrapop_unknown);
    if (callee_pop) {
      expop = getExtraPop();
      // Tried to use getEffectiveExtraPop at one point, but it is too unreliable
      if ((expop==ProtoModel::extrapop_unknown)||(expop <=4))
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
	if ((int4)(trial.getAddress().getOffset() + (trial.getSize()-1)) < expop)
	  trial.markActive();
	else
	  trial.markNoUse();
      }
      else if (ancestorReal.execute(op,slot,&trial,false)) {
	if (data.ancestorOpUse(maxancestor,vn,op,trial,0,0))
	  trial.markActive();
	else
	  trial.markInactive();
      }
      else
	trial.markNoUse(); // Stackvar for unrealistic ancestor is definitely not a parameter
    }
    else {
      if (ancestorReal.execute(op,slot,&trial,true)) {
	if (data.ancestorOpUse(maxancestor,vn,op,trial,0,0)) {
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

  if (isDotdotdot() && isInputLocked()){
      //if varargs, move the fixed args to the beginning of the list in order
	  //preserve relative order of variable args
	  activeinput.sortFixedPosition();
  }

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
  if (oldVal == 0 || val < oldVal) {	// Only let the value get smaller
    inputConsume[slot] = val;
    return true;
  }
  return false;
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

} // End namespace ghidra

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
#include "address.hh"
#include "translate.hh"

namespace ghidra {

AttributeId ATTRIB_FIRST = AttributeId("first",27);
AttributeId ATTRIB_LAST = AttributeId("last",28);
AttributeId ATTRIB_UNIQ = AttributeId("uniq",29);

ElementId ELEM_ADDR = ElementId("addr",11);
ElementId ELEM_RANGE = ElementId("range",12);
ElementId ELEM_RANGELIST = ElementId("rangelist",13);
ElementId ELEM_REGISTER = ElementId("register",14);
ElementId ELEM_SEQNUM = ElementId("seqnum",15);
ElementId ELEM_VARNODE = ElementId("varnode",16);

ostream &operator<<(ostream &s,const SeqNum &sq)

{
  sq.pc.printRaw(s);
  s << ':' << sq.uniq;
  return s;
}

/// This allows an Address to be written to a stream using
/// the standard '<<' operator.  This is a wrapper for the
/// printRaw method and is intended for debugging and console
/// mode uses.
/// \param s is the stream being written to
/// \param addr is the Address to write
/// \return the output stream
ostream &operator<<(ostream &s,const Address &addr)

{
  addr.printRaw(s);
  return s;
}

SeqNum::SeqNum(Address::mach_extreme ex) : pc(ex)

{
  uniq = (ex == Address::m_minimal) ? 0 : ~((uintm)0);
}

void SeqNum::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_SEQNUM);
  pc.getSpace()->encodeAttributes(encoder,pc.getOffset());
  encoder.writeUnsignedInteger(ATTRIB_UNIQ, uniq);
  encoder.closeElement(ELEM_SEQNUM);
}

SeqNum SeqNum::decode(Decoder &decoder)

{
  uintm uniq = ~((uintm)0);
  uint4 elemId = decoder.openElement(ELEM_SEQNUM);
  Address pc = Address::decode(decoder); // Recover address
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_UNIQ) {
      uniq = decoder.readUnsignedInteger();
      break;
    }
  }
  decoder.closeElement(elemId);
  return SeqNum(pc,uniq);
}

/// Some data structures sort on an Address, and it is convenient
/// to be able to create an Address that is either bigger than
/// or smaller than all other Addresses.
/// \param ex is either \e m_minimal or \e m_maximal
Address::Address(mach_extreme ex)

{
  if (ex == m_minimal) {
    base = (AddrSpace *)0;
    offset = 0;
  }
  else {
    base = (AddrSpace *) ~((uintp)0);
    offset = ~((uintb)0);
  }
}

/// Return \b true if the range starting at \b this extending the given number of bytes
/// is contained by the second given range.
/// \param sz is the given number of bytes in \b this range
/// \param op2 is the start of the second given range
/// \param sz2 is the number of bytes in the second given range
/// \return \b true if the second given range contains \b this range
bool Address::containedBy(int4 sz,const Address &op2,int4 sz2) const

{
  if (base != op2.base) return false;
  if (op2.offset > offset) return false;
  uintb off1 = offset + (sz-1);
  uintb off2 = op2.offset + (sz2-1);
  return (off2 >= off1);
}

/// Return -1 if (\e op2,\e sz2) is not properly contained in (\e this,\e sz).
/// If it is contained, return the endian aware offset of (\e op2,\e sz2) 
/// I.e. if the least significant byte of the \e op2 range falls on the least significant
/// byte of the \e this range, return 0.  If it intersects the second least significant, return 1, etc.
/// The -forceleft- toggle causes the check to be made against the left (lowest address) side
/// of the container, regardless of the endianness.  I.e. it forces a little endian interpretation.
/// \param sz is the size of \e this range
/// \param op2 is the address of the second range
/// \param sz2 is the size of the second range
/// \param forceleft is \b true if containments is forced to be on the left even for big endian
/// \return the endian aware offset, or -1
int4 Address::justifiedContain(int4 sz,const Address &op2,int4 sz2,bool forceleft) const

{ if (base != op2.base) return -1;
  if (op2.offset < offset) return -1;
  uintb off1 = offset + (sz-1);
  uintb off2 = op2.offset + (sz2-1);
  if (off2 > off1) return -1;
  if (base->isBigEndian()&&(!forceleft)) {
    return (int4)(off1 - off2);
  }
  return (int4)(op2.offset - offset);
}

/// If \e this + \e skip falls in the range
/// \e op to \e op + \e size, then a non-negative integer is
/// returned indicating where in the interval it falls. I.e.
/// if \e this + \e skip == \e op, then 0 is returned. Otherwise
/// -1 is returned.
/// \param skip is an adjust to \e this address
/// \param op is the start of the range to check
/// \param size is the size of the range
/// \return an integer indicating how overlap occurs
int4 Address::overlap(int4 skip,const Address &op,int4 size) const

{
  uintb dist;

  if (base != op.base) return -1; // Must be in same address space to overlap
  if (base->getType()==IPTR_CONSTANT) return -1; // Must not be constants

  dist = base->wrapOffset(offset+skip-op.offset);

  if (dist >= size) return -1; // but must fall before op+size
  return (int4) dist;
}

/// Does the location \e this, \e sz form a contiguous region to \e loaddr, \e losz,
/// where \e this forms the most significant piece of the logical whole
/// \param sz is the size of \e this hi region
/// \param loaddr is the starting address of the low region
/// \param losz is the size of the low region
/// \return \b true if the pieces form a contiguous whole
bool Address::isContiguous(int4 sz,const Address &loaddr,int4 losz) const

{
  if (base != loaddr.base) return false;
  if (base->isBigEndian()) {
    uintb nextoff = base->wrapOffset(offset+sz);
    if (nextoff == loaddr.offset) return true;
  }
  else {
    uintb nextoff = base->wrapOffset(loaddr.offset+losz);
    if (nextoff == offset) return true;
  }
  return false;
}

/// If \b this is (originally) a \e join address, reevaluate it in terms of its new
/// \e offset and \e size, changing the space and offset if necessary.
/// \param size is the new size in bytes of the underlying object
void Address::renormalize(int4 size) {
  if (base->getType() == IPTR_JOIN)
    base->getManager()->renormalizeJoinAddress(*this,size);
}

/// This is usually used to decode an address from an \b \<addr\>
/// element, but any element can be used if it has the appropriate attributes
///    - \e space indicates the address space of the tag
///    - \e offset indicates the offset within the space
///
/// or a \e name attribute can be used to recover an address
/// based on a register name.
/// \param decoder is the stream decoder
/// \return the resulting Address
Address Address::decode(Decoder &decoder)

{
  VarnodeData var;

  var.decode(decoder);
  return Address(var.space,var.offset);
}

/// This is usually used to decode an address from an \b \<addr\>
/// element, but any element can be used if it has the appropriate attributes
///    - \e space indicates the address space of the tag
///    - \e offset indicates the offset within the space
///    - \e size indicates the size of an address range
///
/// or a \e name attribute can be used to recover an address
/// and size based on a register name. If a size is recovered
/// it is stored in \e size reference.
/// \param decoder is the stream decoder
/// \param size is the reference to any recovered size
/// \return the resulting Address
Address Address::decode(Decoder &decoder,int4 &size)

{
  VarnodeData var;

  var.decode(decoder);
  size = var.size;
  return Address(var.space,var.offset);
}

Range::Range(const RangeProperties &properties,const AddrSpaceManager *manage)

{
  if (properties.isRegister) {
    const Translate *trans = manage->getDefaultCodeSpace()->getTrans();
    const VarnodeData &point(trans->getRegister(properties.spaceName));
    spc = point.space;
    first = point.offset;
    last = (first-1) + point.size;
    return;
  }
  spc = manage->getSpaceByName(properties.spaceName);
  if (spc == (AddrSpace *)0)
    throw LowlevelError("Undefined space: "+properties.spaceName);

  if (spc == (AddrSpace *)0)
    throw LowlevelError("No address space indicated in range tag");
  first = properties.first;
  last = properties.last;
  if (!properties.seenLast) {
    last = spc->getHighest();
  }
  if (first > spc->getHighest() || last > spc->getHighest() || last < first)
    throw LowlevelError("Illegal range tag");
}

/// Get the last address +1, updating the space, or returning
/// the extremal address if necessary
/// \param manage is used to fetch the next address space
Address Range::getLastAddrOpen(const AddrSpaceManager *manage) const

{
  AddrSpace *curspc = spc;
  uintb curlast = last;
  if (curlast == curspc->getHighest()) {
    curspc = manage->getNextSpaceInOrder(curspc);
    curlast = 0;
  }
  else
    curlast += 1;
  if (curspc == (AddrSpace *)0)
    return Address(Address::m_maximal);
  return Address(curspc,curlast);
}

/// Output a description of this Range like:  ram: 7f-9c
/// \param s is the output stream
void Range::printBounds(ostream &s) const

{
  s << spc->getName() << ": ";
  s << hex << first << '-' << last;
}

/// Encode \b this to a stream as a \<range> element.
/// \param encoder is the stream encoder
void Range::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_RANGE);
  encoder.writeSpace(ATTRIB_SPACE, spc);
  encoder.writeUnsignedInteger(ATTRIB_FIRST, first);
  encoder.writeUnsignedInteger(ATTRIB_LAST, last);
  encoder.closeElement(ELEM_RANGE);
}

/// Reconstruct this object from a \<range> or \<register> element
/// \param decoder is the stream decoder
void Range::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement();
  if (elemId != ELEM_RANGE && elemId != ELEM_REGISTER)
    throw DecoderError("Expecting <range> or <register> element");
  decodeFromAttributes(decoder);
  decoder.closeElement(elemId);
}

/// Reconstruct from attributes that may not be part of a \<range> element.
/// \param decoder is the stream decoder
void Range::decodeFromAttributes(Decoder &decoder)

{
  spc = (AddrSpace *)0;
  bool seenLast = false;
  first = 0;
  last = 0;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_SPACE) {
      spc = decoder.readSpace();
    }
    else if (attribId == ATTRIB_FIRST) {
      first = decoder.readUnsignedInteger();
    }
    else if (attribId == ATTRIB_LAST) {
      last = decoder.readUnsignedInteger();
      seenLast = true;
    }
    else if (attribId == ATTRIB_NAME) {
      const Translate *trans = decoder.getAddrSpaceManager()->getDefaultCodeSpace()->getTrans();
      const VarnodeData &point(trans->getRegister(decoder.readString()));
      spc = point.space;
      first = point.offset;
      last = (first-1) + point.size;
      return;		// There should be no (space,first,last) attributes
    }
  }
  if (spc == (AddrSpace *)0)
    throw LowlevelError("No address space indicated in range tag");
  if (!seenLast) {
    last = spc->getHighest();
  }
  if (first > spc->getHighest() || last > spc->getHighest() || last < first)
    throw LowlevelError("Illegal range tag");
}

void RangeProperties::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement();
  if (elemId != ELEM_RANGE && elemId != ELEM_REGISTER)
    throw DecoderError("Expecting <range> or <register> element");
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_SPACE)
      spaceName = decoder.readString();
    else if (attribId == ATTRIB_FIRST)
      first = decoder.readUnsignedInteger();
    else if (attribId == ATTRIB_LAST) {
      last = decoder.readUnsignedInteger();
      seenLast = true;
    }
    else if (attribId == ATTRIB_NAME) {
      spaceName = decoder.readString();
      isRegister = true;
    }
  }
  decoder.closeElement(elemId);
}

/// Insert a new Range merging as appropriate to maintain the disjoint cover
/// \param spc is the address space containing the new range
/// \param first is the offset of the first byte in the new range
/// \param last is the offset of the last byte in the new range
void RangeList::insertRange(AddrSpace *spc,uintb first,uintb last)

{
  set<Range>::iterator iter1,iter2;

  // we must have iter1.first > first
  iter1 = tree.upper_bound(Range(spc,first,first));

  // Set iter1 to first range with range.last >=first
  // It is either current iter1 or the one before
  if (iter1 != tree.begin()) {
    --iter1;
    if (((*iter1).spc!=spc)||((*iter1).last < first))
      ++iter1;
  }

  // Set iter2 to first range with range.first > last
  iter2 = tree.upper_bound(Range(spc,last,last));
  
  while(iter1!=iter2) {
    if ((*iter1).first < first)
      first = (*iter1).first;
    if ((*iter1).last > last)
      last = (*iter1).last;
    tree.erase(iter1++);
  }
  tree.insert(Range(spc,first,last));
}

/// Remove/narrow/split existing Range objects to eliminate the indicated addresses
/// while still maintaining a disjoint cover.
/// \param spc is the address space of the address range to remove
/// \param first is the offset of the first byte of the range
/// \param last is the offset of the last byte of the range
void RangeList::removeRange(AddrSpace *spc,uintb first,uintb last)

{				// remove a range
  set<Range>::iterator iter1,iter2;

  if (tree.empty()) return;	// Nothing to do

  // we must have iter1.first > first
  iter1 = tree.upper_bound(Range(spc,first,first));

  // Set iter1 to first range with range.last >=first
  // It is either current iter1 or the one before
  if (iter1 != tree.begin()) {
    --iter1;
    if (((*iter1).spc!=spc)||((*iter1).last < first))
      ++iter1;
  }

  // Set iter2 to first range with range.first > last
  iter2 = tree.upper_bound(Range(spc,last,last));
  
  while(iter1!=iter2) {
    uintb a,b;

    a = (*iter1).first;
    b = (*iter1).last;
    tree.erase(iter1++);
    if (a <first)
      tree.insert(Range(spc,a,first-1));
    if (b > last)
      tree.insert(Range(spc,last+1,b));
  }
}

void RangeList::merge(const RangeList &op2)

{ // Merge -op2- into this rangelist
  set<Range>::const_iterator iter1,iter2;
  iter1 = op2.tree.begin();
  iter2 = op2.tree.end();
  while(iter1 != iter2) {
    const Range &range( *iter1 );
    ++iter1;
    insertRange(range.spc, range.first, range.last);
  }
}

/// Make sure indicated range of addresses is \e contained in \b this RangeList
/// \param addr is the first Address in the target range
/// \param size is the number of bytes in the target range
/// \return \b true is the range is fully contained by this RangeList
bool RangeList::inRange(const Address &addr,int4 size) const

{
  set<Range>::const_iterator iter;

  if (addr.isInvalid()) return true; // We don't really care
  if (tree.empty()) return false;

  // iter = first range with its first > addr
  iter = tree.upper_bound(Range(addr.getSpace(),addr.getOffset(),addr.getOffset()));
  if (iter == tree.begin()) return false;
  // Set iter to last range with range.first <= addr
  --iter;
  //  if (iter == tree.end())   // iter can't be end if non-empty
  //    return false;
  if ((*iter).spc != addr.getSpace()) return false;
  if ((*iter).last >= addr.getOffset()+size-1)
    return true;
  return false;
}

/// If \b this RangeList contains the specific address (spaceid,offset), return it
/// \return the containing Range or NULL
const Range *RangeList::getRange(AddrSpace *spaceid,uintb offset) const

{
  if (tree.empty()) return (const Range *)0;

  // iter = first range with its first > offset
  set<Range>::const_iterator iter = tree.upper_bound(Range(spaceid,offset,offset));
  if (iter == tree.begin()) return (const Range *)0;
  // Set iter to last range with range.first <= offset
  --iter;
  if ((*iter).spc != spaceid) return (const Range *)0;
  if ((*iter).last >= offset)
    return &(*iter);
  return (const Range *)0;
}

/// Return the size of the biggest contiguous sequence of addresses in
/// \b this RangeList which contain the given address
/// \param addr is the given address
/// \param maxsize is the large range to consider before giving up
/// \return the size (in bytes) of the biggest range
uintb RangeList::longestFit(const Address &addr,uintb maxsize) const

{
  set<Range>::const_iterator iter;

  if (addr.isInvalid()) return 0;
  if (tree.empty()) return 0;

  // iter = first range with its first > addr
  uintb offset = addr.getOffset();
  iter = tree.upper_bound(Range(addr.getSpace(),offset,offset));
  if (iter == tree.begin()) return 0;
  // Set iter to last range with range.first <= addr
  --iter;
  uintb sizeres = 0;
  if ((*iter).last < offset) return sizeres;
  do {
    if ((*iter).spc != addr.getSpace()) break;
    if ((*iter).first > offset) break;
    sizeres += ((*iter).last + 1 - offset); // Size extends to end of range
    offset = (*iter).last + 1;	// Try to chain on the next range
    if (sizeres >= maxsize) break; // Don't bother if past maxsize
    ++iter;			// Next range in the chain
  } while(iter != tree.end());
  return sizeres;
}

/// \return the first contiguous range of addresses or NULL if empty
const Range *RangeList::getFirstRange(void) const

{
  if (tree.empty()) return (const Range *)0;
  return &(*tree.begin());
}

/// \return the last contiguous range of addresses or NULL if empty
const Range *RangeList::getLastRange(void) const

{
  if (tree.empty()) return (const Range *)0;
  set<Range>::const_iterator iter = tree.end();
  --iter;
  return &(*iter);
}

/// Treating offsets with their high-bits set as coming \e before
/// offset where the high-bit is clear, return the last/latest contiguous
/// Range within the given address space
/// \param spaceid is the given address space
/// \return indicated Range or NULL if empty
const Range *RangeList::getLastSignedRange(AddrSpace *spaceid) const

{
  uintb midway = spaceid->getHighest() / 2;		// Maximal signed value
  Range range(spaceid,midway,midway);
  set<Range>::const_iterator iter = tree.upper_bound(range);	// First element greater than -range- (should be MOST negative)

  if (iter!=tree.begin()) {
    --iter;
    if ((*iter).getSpace() == spaceid)
      return &(*iter);
  }

  // If there were no "positive" ranges, search for biggest negative range
  range = Range(spaceid,spaceid->getHighest(),spaceid->getHighest());
  iter = tree.upper_bound(range);
  if (iter != tree.begin()) {
    --iter;
    if ((*iter).getSpace() == spaceid)
      return &(*iter);
  }
  return (const Range *)0;
}

/// Print a one line description of each disjoint Range making up \b this RangeList
/// \param s is the output stream
void RangeList::printBounds(ostream &s) const

{
  if (tree.empty())
    s << "all" << endl;
  else {
    set<Range>::const_iterator iter;
    for(iter=tree.begin();iter!=tree.end();++iter) {
      (*iter).printBounds(s);
      s << endl;
    }
  }
}

/// Encode \b this as a \<rangelist> element
/// \param encoder is the stream encoder
void RangeList::encode(Encoder &encoder) const

{
  set<Range>::const_iterator iter;

  encoder.openElement(ELEM_RANGELIST);
  for(iter=tree.begin();iter!=tree.end();++iter) {
    (*iter).encode(encoder);
  }
  encoder.closeElement(ELEM_RANGELIST);
}

/// Recover each individual disjoint Range for \b this RangeList.
/// \param decoder is the stream decoder
void RangeList::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_RANGELIST);
  while(decoder.peekElement() != 0) {
    Range range;
    range.decode(decoder);
    tree.insert(range);
  }
  decoder.closeElement(elemId);
}

#ifdef UINTB4
uintb uintbmasks[9] = { 0, 0xff, 0xffff, 0xffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
#else
uintb uintbmasks[9] = { 0, 0xff, 0xffff, 0xffffff, 0xffffffff, 0xffffffffffLL,
			0xffffffffffffLL, 0xffffffffffffffLL, 0xffffffffffffffffLL };
#endif

/// Treat the given \b val as a constant of \b size bytes
/// \param val is the given value
/// \param size is the size in bytes
/// \return \b true if the constant (as sized) has its sign bit set
bool signbit_negative(uintb val,int4 size)

{				// Return true if signbit is set (negative)
  uintb mask = 0x80;
  mask <<= 8*(size-1);
  return ((val&mask) != 0);
}

/// Treat the given \b in as a constant of \b size bytes.
/// Negate this constant keeping the upper bytes zero.
/// \param in is the given value
/// \param size is the size in bytes
/// \return the negation of the sized constant
uintb uintb_negate(uintb in,int4 size)

{				// Invert bits
  return ((~in)&calc_mask(size));
}

/// Take the first \b sizein bytes of the given \b in and sign-extend
/// this to \b sizeout bytes, keeping any more significant bytes zero
/// \param in is the given value
/// \param sizein is the size to treat that value as an input
/// \param sizeout is the size to sign-extend the value to
/// \return the sign-extended value
uintb sign_extend(uintb in,int4 sizein,int4 sizeout)

{
  sizein = (sizein < sizeof(uintb)) ? sizein : sizeof(uintb);
  sizeout = (sizeout < sizeof(uintb)) ? sizeout : sizeof(uintb);
  intb sval = in;
  sval <<= (sizeof(intb) - sizein) * 8;
  uintb res = (uintb)(sval >> (sizeout - sizein) * 8);
  res >>= (sizeof(uintb) - sizeout)*8;
  return res;
}

/// Swap the least significant \b size bytes in \b val
/// \param val is a reference to the value to swap
/// \param size is the number of bytes to swap
void byte_swap(intb &val,int4 size)

{
  intb res = 0;
  while(size>0) {
    res <<= 8;
    res |= (val&0xff);
    val >>= 8;
    size -= 1;
  }
  val = res;
}

/// Swap the least significant \b size bytes in \b val
/// \param val is the value to swap
/// \param size is the number of bytes to swap
/// \return the swapped value
uintb byte_swap(uintb val,int4 size)

{
  uintb res=0;
  while(size>0) {
    res <<= 8;
    res |= (val&0xff);
    val >>= 8;
    size -= 1;
  }
  return res;
}

/// The least significant bit is index 0.
/// \param val is the given value
/// \return the index of the least significant set bit, or -1 if none are set
int4 leastsigbit_set(uintb val)

{
  if (val==0) return -1;
  int4 res = 0;
  int4 sz = 4*sizeof(uintb);
  uintb mask = ~((uintb)0);
  do {
    mask >>= sz;
    if ((mask&val)==0) {
      res += sz;
      val >>= sz;
    }
    sz >>= 1;
  } while(sz!=0);
  return res;
}

/// The least significant bit is index 0.
/// \param val is the given value
/// \return the index of the most significant set bit, or -1 if none are set
int4 mostsigbit_set(uintb val)

{
  if (val==0) return -1;
  int4 res = 8*sizeof(uintb)-1;
  int4 sz = 4*sizeof(uintb);
  uintb mask = ~((uintb)0);
  do {
    mask <<= sz;
    if ((mask&val)==0) {
      res -= sz;
      val <<= sz;
    }
    sz >>= 1;
  } while(sz != 0);
  return res;
}

/// Count the number (population) bits set.
/// \param val is the given value
/// \return the number of one bits
int4 popcount(uintb val)

{
  val = (val & 0x5555555555555555L) + ((val >> 1) & 0x5555555555555555L);
  val = (val & 0x3333333333333333L) + ((val >> 2) & 0x3333333333333333L);
  val = (val & 0x0f0f0f0f0f0f0f0fL) + ((val >> 4) & 0x0f0f0f0f0f0f0f0fL);
  val = (val & 0x00ff00ff00ff00ffL) + ((val >> 8) & 0x00ff00ff00ff00ffL);
  val = (val & 0x0000ffff0000ffffL) + ((val >> 16) & 0x0000ffff0000ffffL);
  int4 res = (int4)(val & 0xff);
  res += (int4)((val >> 32) & 0xff);
  return res;
}

/// Count the number of more significant zero bits before the most significant
/// one bit in the representation of the given value;
/// \param val is the given value
/// \return the number of zero bits
int4 count_leading_zeros(uintb val)

{
  if (val == 0)
    return 8*sizeof(uintb);
  uintb mask = ~((uintb)0);
  int4 maskSize = 4*sizeof(uintb);
  mask &= (mask << maskSize);
  int4 bit = 0;

  do {
    if ((mask & val)==0) {
      bit += maskSize;
      maskSize >>= 1;
      mask |= (mask >> maskSize);
    }
    else {
      maskSize >>= 1;
      mask &= (mask << maskSize);
    }
  } while(maskSize != 0);
  return bit;
}

/// Return smallest number of form 2^n-1, bigger or equal to the given value
/// \param val is the given value
/// \return the mask
uintb coveringmask(uintb val)

{
  uintb res = val;
  int4 sz = 1;
  while(sz < 8*sizeof(uintb)) {
    res = res | (res>>sz);
    sz <<= 1;
  }
  return res;
}

/// Treat \b val as a constant of size \b sz.
/// Scanning across the bits of \b val return the number of transitions (from 0->1 or 1->0)
/// If there are 2 or less transitions, this is an indication of a bit flag or a mask
/// \param val is the given value
/// \param sz is the size to treat the value as
/// \return the number of transitions
int4 bit_transitions(uintb val,int4 sz)

{
  int4 res = 0;
  int4 last = val & 1;
  int4 cur;
  for(int4 i=1;i<8*sz;++i) {
    val >>= 1;
    cur = val & 1;
    if (cur != last) {
      res += 1;
      last = cur;
    }
    if (val==0) break;
  }
  return res;
}

} // End namespace ghidra

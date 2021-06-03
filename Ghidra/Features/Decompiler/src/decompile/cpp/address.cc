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

void SeqNum::saveXml(ostream &s) const

{
  s << "<seqnum";
  pc.getSpace()->saveXmlAttributes(s,pc.getOffset());
  a_v_u(s,"uniq",uniq);
  s << "/>";
}

SeqNum SeqNum::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  uintm uniq = ~((uintm)0);
  Address pc = Address::restoreXml(el,manage); // Recover address
  for(int4 i=0;i<el->getNumAttributes();++i)
    if (el->getAttributeName(i) == "uniq") {
      istringstream s2(el->getAttributeValue(i)); // Recover unique (if present)
      s2.unsetf(ios::dec | ios::hex | ios::oct);
      s2 >> uniq;
      break;
    }
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

/// \deprecated Convert this to the most basic physical address.
/// This routine is only present for backward compatibility
/// with SLED
void Address::toPhysical(void)

{ AddrSpace *phys = base->getContain();
  if ((phys != (AddrSpace *)0)&&(base->getType()==IPTR_SPACEBASE))
     base = phys;
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
/// \e offset and \e siz, changing the space and offset if necessary.
/// \param size is the new size in bytes of the underlying object
void Address::renormalize(int4 size) {
  if (base->getType() == IPTR_JOIN)
    base->getManager()->renormalizeJoinAddress(*this,size);
}

/// This is usually used to build an address from an \b \<addr\>
/// tag, but it can be used to create an address from any tag
/// with the appropriate attributes
///    - \e space indicates the address space of the tag
///    - \e offset indicates the offset within the space
///
/// or a \e name attribute can be used to recover an address
/// based on a register name.
/// \param el is the parsed tag
/// \param manage is the address space manager for the program
/// \return the resulting Address
Address Address::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  VarnodeData var;

  var.restoreXml(el,manage);
  return Address(var.space,var.offset);
}

/// This is usually used to build an address from an \b \<addr\>
/// tag, but it can be used to create an address from any tag
/// with the appropriate attributes
///    - \e space indicates the address space of the tag
///    - \e offset indicates the offset within the space
///    - \e size indicates the size of an address range
///
/// or a \e name attribute can be used to recover an address
/// and size based on a register name. If a size is recovered
/// it is stored in \e size reference.
/// \param el is the parsed tag
/// \param manage is the address space manager for the program
/// \param size is the reference to any recovered size
/// \return the resulting Address
Address Address::restoreXml(const Element *el,const AddrSpaceManager *manage,int4 &size)

{
  VarnodeData var;

  var.restoreXml(el,manage);
  size = var.size;
  return Address(var.space,var.offset);
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

/// Write this object to a stream as a \<range> tag.
/// \param s is the output stream
void Range::saveXml(ostream &s) const

{
  s << "<range";
  a_v(s,"space",spc->getName());
  a_v_u(s,"first",first);
  a_v_u(s,"last",last);
  s << "/>\n";
}

/// Reconstruct this object from an XML \<range> element
/// \param el is the XML element
/// \param manage is the space manage for recovering AddrSpace objects
void Range::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  spc = (AddrSpace *)0;
  first = 0;
  last = ~((uintb)0);
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i) == "space") {
      spc = manage->getSpaceByName(el->getAttributeValue(i));
      if (spc == (AddrSpace *)0)
        throw LowlevelError("Undefined space: "+el->getAttributeValue(i));
    }
    else if (el->getAttributeName(i) == "first") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> first;
    }
    else if (el->getAttributeName(i) == "last") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> last;
    }
    else if (el->getAttributeName(i) == "name") {
      const Translate *trans = manage->getDefaultCodeSpace()->getTrans();
      const VarnodeData &point(trans->getRegister(el->getAttributeValue(i)));
      spc = point.space;
      first = point.offset;
      last = (first-1) + point.size;
      break;		// There should be no (space,first,last) attributes
    }
  }
  if (spc == (AddrSpace *)0)
	  throw LowlevelError("No address space indicated in range tag");
  last = spc->wrapOffset(last);
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

/// Serialize this object to an XML \<rangelist> tag
/// \param s is the output stream
void RangeList::saveXml(ostream &s) const

{
  set<Range>::const_iterator iter;

  s << "<rangelist>\n";
  for(iter=tree.begin();iter!=tree.end();++iter) {
    (*iter).saveXml(s);
  }
  s << "</rangelist>\n";
}

/// Recover each individual disjoint Range for \b this RangeList as encoded
/// in a \<rangelist> tag.
/// \param el is the XML element
/// \param manage is manager for retrieving address spaces
void RangeList::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    Range range;
    range.restoreXml(subel,manage);
    tree.insert(range);
  }
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
  int4 signbit;
  uintb mask;

  signbit = sizein*8 - 1;
  in &= calc_mask(sizein);
  if (sizein >= sizeout) return in;
  if ((in>>signbit) != 0) {
    mask = calc_mask(sizeout);
    uintb tmp = mask << signbit; // Split shift into two pieces
    tmp = (tmp<<1) & mask;	// In case, everything is shifted out
    in |= tmp;
  }
  return in;
}

/// Sign extend \b val starting at \b bit
/// \param val is a reference to the value to be sign-extended
/// \param bit is the index of the bit to extend from (0=least significant bit)
void sign_extend(intb &val,int4 bit)

{
  intb mask = 0;
  mask = (~mask)<<bit;
  if (((val>>bit)&1)!=0)
    val |= mask;
  else
    val &= (~mask);
}

/// Zero extend \b val starting at \b bit
/// \param val is a reference to the value to be zero extended
/// \param bit is the index of the bit to extend from (0=least significant bit)
void zero_extend(intb &val,int4 bit)

{
  intb mask = 0;
  mask = (~mask)<<bit;
  mask <<= 1;
  val &= (~mask);
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

/// \brief Multiply 2 unsigned 64-bit values, producing a 128-bit value
///
/// TODO: Remove once we import a full multiprecision library.
/// \param res points to the result array (2 uint8 pieces)
/// \param x is the first 64-bit value
/// \param y is the second 64-bit value
void mult64to128(uint8 *res,uint8 x,uint8 y)

{
  uint8 f = x & 0xffffffff;
  uint8 e = x >> 32;
  uint8 d = y & 0xffffffff;
  uint8 c = y >> 32;
  uint8 fd = f * d;
  uint8 fc = f * c;
  uint8 ed = e * d;
  uint8 ec = e * c;
  uint8 tmp = (fd >> 32) + (fc & 0xffffffff) + (ed & 0xffffffff);
  res[1] = (tmp>>32) + (fc>>32) + (ed>>32) + ec;
  res[0] = (tmp<<32) + (fd & 0xffffffff);
}

/// \brief Subtract (in-place) a 128-bit value from a base 128-value
///
/// The base value is altered in place.
/// TODO: Remove once we import a full multiprecision library.
/// \param a is the base 128-bit value being subtracted from in-place
/// \param b is the other 128-bit value being subtracted
void unsignedSubtract128(uint8 *a,uint8 *b)

{
  bool borrow = (a[0] < b[0]);
  a[0] -= b[0];
  a[1] -= b[1];
  if (borrow)
    a[1] -= 1;
}

/// \brief Compare two unsigned 128-bit values
///
/// TODO: Remove once we import a full multiprecision library.
/// Given a first and second value, return -1, 0, or 1 depending on whether the first value
/// is \e less, \e equal, or \e greater than the second value.
/// \param a is the first 128-bit value (as an array of 2 uint8 elements)
/// \param b is the second 128-bit value
/// \return the comparison code
int4 unsignedCompare128(uint8 *a,uint8 *b)

{
  if (a[1] != b[1])
    return (a[1] < b[1]) ? -1 : 1;
  if (a[0] != b[0])
    return (a[0] < b[0]) ? -1 : 1;
  return 0;
}

/// \brief Unsigned division of a power of 2 (upto 2^127) by a 64-bit divisor
///
/// The result must be less than 2^64. The remainder is calculated.
/// \param n is the power of 2 for the numerand
/// \param divisor is the 64-bit divisor
/// \param q is the passed back 64-bit quotient
/// \param r is the passed back 64-bit remainder
/// \return 0 if successful, 1 if result is too big, 2 if divide by 0
int4 power2Divide(int4 n,uint8 divisor,uint8 &q,uint8 &r)

{
  if (divisor == 0) return 2;
  uint8 power = 1;
  if (n < 64) {
    power <<= n;
    q = power / divisor;
    r = power % divisor;
    return 0;
  }
  // Divide numerand and divisor by 2^(n-63) to get approximation of result
  uint8 y = divisor >> (n-64);	// Most of the way on divisor
  if (y == 0) return 1;		// Check if result will be too big
  y >>= 1;			// Divide divisor by final bit
  power <<= 63;
  uint8 max;
  if (y == 0) {
    max = 0;
    max -= 1;			// Could be maximal
    // Check if divisor is a power of 2
    if ((((uint8)1) << (n-64)) == divisor)
      return 1;
  }
  else
    max = power / y + 1;
  uint8 min = power / (y+1);
  if (min != 0)
    min -= 1;
  uint8 fullpower[2];
  fullpower[1] = ((uint8)1)<<(n-64);
  fullpower[0] = 0;
  uint8 mult[2];
  mult[0] = 0;
  mult[1] = 0;
  uint8 tmpq = 0;
  while(max > min+1) {
    tmpq = max + min;
    if (tmpq < min) {
      tmpq = (tmpq>>1) + 0x8000000000000000L;
    }
    else
      tmpq >>= 1;
    mult64to128(mult,divisor,tmpq);
    if (unsignedCompare128(fullpower,mult) < 0)
      max = tmpq-1;
    else
      min = tmpq;
  }
  // min is now our putative quotient
  if (tmpq != min)
    mult64to128(mult,divisor,min);
  unsignedSubtract128(fullpower,mult); // Calculate remainder
  // min might be 1 too small
  if (fullpower[1] != 0 || fullpower[0] >= divisor) {
    q = min + 1;
    r = fullpower[0] - divisor;
  }
  else {
    q = min;
    r = fullpower[0];
  }
  return 0;
}

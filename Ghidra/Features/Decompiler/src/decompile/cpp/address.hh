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
/// \file address.hh
/// \brief Classes for specifying addresses and other low-level constants
///
///  All addresses are absolute and there are are no registers in CPUI. However,
///  all addresses are prefixed with an "immutable" pointer, which can
///  specify a separate RAM space, a register space, an i/o space etc. Thus
///  a translation from a real machine language will typically simulate registers
///  by placing them in their own space, separate from RAM. Indirection
///  (i.e. pointers) must be simulated through the LOAD and STORE ops.

#ifndef __CPUI_ADDR__
#define __CPUI_ADDR__

#include "space.hh"

class AddrSpaceManager;

/// \brief A low-level machine address for labelling bytes and data.
///
/// All data that can be manipulated within the processor reverse
/// engineering model can be labelled with an Address. It is
/// simply an address space (AddrSpace) and an offset within that
/// space.  Note that processor registers are typically modelled
/// by creating a dedicated address space for them, as distinct
/// from RAM say, and then specifying certain addresses within the
/// register space that correspond to particular registers. However,
/// an arbitrary address could refer to anything,
/// RAM, ROM, cpu register, data segment, coprocessor, stack,
/// nvram, etc.
/// An Address represents an offset \e only, not an offset and length
class Address {
protected:
  AddrSpace *base;		///< Pointer to our address space
  uintb offset;			///< Offset (in bytes)
public:
  /// An enum for specifying extremal addresses
  enum mach_extreme {
    m_minimal,			///< Smallest possible address
    m_maximal			///< Biggest possible address
  };
  Address(mach_extreme ex);	///< Initialize an extremal address
  Address(void);		///< Create an invalid address
  Address(AddrSpace *id,uintb off); ///< Construct an address with a space/offset pair
  Address(const Address &op2);	///< A copy constructor

  bool isInvalid(void) const;  ///< Is the address invalid?
  int4 getAddrSize(void) const; ///< Get the number of bytes in the address
  bool isBigEndian(void) const;	///< Is data at this address big endian encoded
  void printRaw(ostream &s) const; ///< Write a raw version of the address to a stream
  int4 read(const string &s); ///< Read in the address from a string
  AddrSpace *getSpace(void) const; ///< Get the address space
  uintb getOffset(void) const;  ///< Get the address offset
  void toPhysical(void);       ///< Convert this to a physical address
  char getShortcut(void) const;	///< Get the shortcut character for the address space
  Address &operator=(const Address &op2); ///< Copy an address
  bool operator==(const Address &op2) const; ///< Compare two addresses for equality
  bool operator!=(const Address &op2) const; ///< Compare two addresses for inequality
  bool operator<(const Address &op2) const; ///< Compare two addresses via their natural ordering
  bool operator<=(const Address &op2) const; ///< Compare two addresses via their natural ordering
  Address operator+(int4 off) const; ///< Increment address by a number of bytes
  Address operator-(int4 off) const; ///< Decrement address by a number of bytes
  friend ostream &operator<<(ostream &s,const Address &addr);  ///< Write out an address to stream
  bool containedBy(int4 sz,const Address &op2,int4 sz2) const;	///< Determine if \e op2 range contains \b this range
  int4 justifiedContain(int4 sz,const Address &op2,int4 sz2,bool forceleft) const; ///< Determine if \e op2 is the least significant part of \e this.
  int4 overlap(int4 skip,const Address &op,int4 size) const; ///< Determine how two address ranges overlap
  bool isContiguous(int4 sz,const Address &loaddr,int4 losz) const; ///< Does \e this form a contigous range with \e loaddr
  bool isConstant(void) const; ///< Is this a \e constant \e value
  void renormalize(int4 size);	///< Make sure there is a backing JoinRecord if \b this is in the \e join space
  bool isJoin(void) const;	///< Is this a \e join \e value
  void saveXml(ostream &s) const; ///< Save this to a stream as an XML tag
  void saveXml(ostream &s,int4 size) const; ///< Save this and a size to a stream as an XML tag

  /// Restore an address from parsed XML
  static Address restoreXml(const Element *el,const AddrSpaceManager *manage);

  /// Restore an address and size from parsed XML
  static Address restoreXml(const Element *el,const AddrSpaceManager *manage,int4 &size);

  /// Recover an encoded address space from an address
  static AddrSpace *getSpaceFromConst(const Address &addr);
};

/// \brief A class for uniquely labelling and comparing PcodeOps
///
/// Different PcodeOps generated by a single machine instruction
/// can only be labelled with a single Address. But PcodeOps
/// must be distinguishable and compared for execution order.
/// A SeqNum extends the address for a PcodeOp to include:
///   - A fixed \e time field, which is set at the time the PcodeOp
///     is created. The \e time field guarantees a unique SeqNum
///     for the life of the PcodeOp. 
///   - An \e order field, which is guaranteed to be comparable
///     for the execution order of the PcodeOp within its basic
///     block.  The \e order field also provides uniqueness but
///     may change over time if the syntax tree is manipulated.
class SeqNum {
  Address pc;		  ///< Program counter at start of instruction
  uintm uniq;		  ///< Number to guarantee uniqueness
  uintm order;		  ///< Number for order comparisons within a block
public:
  SeqNum(void) {}	  ///< Create an invalid sequence number
  SeqNum(Address::mach_extreme ex); ///< Create an extremal sequence number

  /// Create a sequence number with a specific \e time field
  SeqNum(const Address &a,uintm b) : pc(a) { uniq = b; }

  /// Copy a sequence number
  SeqNum(const SeqNum &op2) : pc(op2.pc) { uniq = op2.uniq; }

  /// Get the address portion of a sequence number
  const Address &getAddr(void) const { return pc; }

  /// Get the \e time field of a sequence number
  uintm getTime(void) const { return uniq; }
  
  /// Get the \e order field of a sequence number
  uintm getOrder(void) const { return order; }

  /// Set the \e order field of a sequence number
  void setOrder(uintm ord) { order = ord; }

  /// Compare two sequence numbers for equality
  bool operator==(const SeqNum &op2) const { return (uniq == op2.uniq); }

  /// Compare two sequence numbers for inequality
  bool operator!=(const SeqNum &op2) const { return (uniq != op2.uniq); }

  /// Compare two sequence numbers with their natural order
  bool operator<(const SeqNum &op2) const {
    if (pc == op2.pc)
      return (uniq < op2.uniq);
    return (pc < op2.pc);
  }

  /// Save a SeqNum to a stream as an XML tag
  void saveXml(ostream &s) const;

  /// Restore a SeqNum from parsed XML
  static SeqNum restoreXml(const Element *el,const AddrSpaceManager *manage);

  /// Write out a SeqNum to a stream
  friend ostream &operator<<(ostream &s,const SeqNum &sq);
};

/// \brief A contiguous range of bytes in some address space
class Range {
  friend class RangeList;
  AddrSpace *spc;		///< Space containing range
  uintb first;			///< Offset of first byte in \b this Range
  uintb last;			///< Offset of last byte in \b this Range
public:
  /// \brief Construct a Range from offsets
  ///
  /// Offsets must expressed in \e bytes as opposed to addressable \e words
  /// \param s is the address space containing the range
  /// \param f is the offset of the first byte in the range
  /// \param l is the offset of the last byte in the range
  Range(AddrSpace *s,uintb f,uintb l) {
    spc = s; first = f; last = l; }
  Range(void) {}					///< Constructor for use with restoreXml
  AddrSpace *getSpace(void) const { return spc; }	///< Get the address space containing \b this Range
  uintb getFirst(void) const { return first; }		///< Get the offset of the first byte in \b this Range
  uintb getLast(void) const { return last; }		///< Get the offset of the last byte in \b this Range
  Address getFirstAddr(void) const { return Address(spc,first); }	///< Get the address of the first byte
  Address getLastAddr(void) const { return Address(spc,last); }		///< Get the address of the last byte
  Address getLastAddrOpen(const AddrSpaceManager *manage) const;	///< Get address of first byte after \b this
  bool contains(const Address &addr) const;		///< Determine if the address is in \b this Range

  /// \brief Sorting operator for Ranges
  ///
  /// Compare based on address space, then the starting offset
  /// \param op2 is the Range to compare with \b this
  /// \return \b true if \b this comes before op2
  bool operator<(const Range &op2) const {
    if (spc->getIndex() != op2.spc->getIndex())
      return (spc->getIndex() < op2.spc->getIndex());
    return (first < op2.first); }
  void printBounds(ostream &s) const;			///< Print \b this Range to a stream
  void saveXml(ostream &s) const;			///< Save \b this Range to an XML stream
  void restoreXml(const Element *el,const AddrSpaceManager *manage);	///< Restore \b this from XML stream
};

/// \brief A disjoint set of Ranges, possibly across multiple address spaces
///
/// This is a container for addresses. It maintains a disjoint list of Ranges
/// that cover all the addresses in the container.  Ranges can be inserted
/// and removed, but overlapping/adjacent ranges will get merged.
class RangeList {
  set<Range> tree;			///< The sorted list of Range objects
public:
  RangeList(const RangeList &op2) { tree = op2.tree; }		///< Copy constructor
  RangeList(void) {}						///< Construct an empty container
  void clear(void) { tree.clear(); }				///< Clear \b this container to empty
  bool empty(void) const { return tree.empty(); }		///< Return \b true if \b this is empty
  set<Range>::const_iterator begin(void) const { return tree.begin(); }	///< Get iterator to beginning Range
  set<Range>::const_iterator end(void) const { return tree.end(); }	///< Get iterator to ending Range
  int4 numRanges(void) const { return tree.size(); }		///< Return the number of Range objects in container
  const Range *getFirstRange(void) const;			///< Get the first Range
  const Range *getLastRange(void) const;			///< Get the last Range
  const Range *getLastSignedRange(AddrSpace *spaceid) const;	///< Get the last Range viewing offsets as signed
  const Range *getRange(AddrSpace *spaceid,uintb offset) const;	///< Get Range containing the given byte
  void insertRange(AddrSpace *spc,uintb first,uintb last);	///< Insert a range of addresses
  void removeRange(AddrSpace *spc,uintb first,uintb last);	///< Remove a range of addresses
  void merge(const RangeList &op2);				///< Merge another RangeList into \b this
  bool inRange(const Address &addr,int4 size) const;		///< Check containment an address range
  uintb longestFit(const Address &addr,uintb maxsize) const;	///< Find size of biggest Range containing given address
  void printBounds(ostream &s) const;				///< Print a description of \b this RangeList to stream
  void saveXml(ostream &s) const;				///< Write \b this RangeList to an XML stream
  void restoreXml(const Element *el,const AddrSpaceManager *manage);	///< Restore \b this RangeList from an XML stream
};

/// Precalculated masks indexed by size
extern uintb uintbmasks[];

// Inline functions

/// An invalid address is possible in some circumstances.
/// This deliberately constructs an invalid address
inline Address::Address(void) {
  base = (AddrSpace *)0;
}

/// This is the basic Address constructor
/// \param id is the space containing the address
/// \param off is the offset of the address
inline Address::Address(AddrSpace *id,uintb off) {
  base=id; offset=off;
}

/// This is a standard copy constructor, copying the
/// address space and the offset
/// \param op2 is the Address to copy
inline Address::Address(const Address &op2) {
  base = op2.base;
  offset = op2.offset;
}

/// Determine if this is an invalid address. This only
/// detects \e deliberate invalid addresses.
/// \return \b true if the address is invalid
inline bool Address::isInvalid(void) const {
  return (base == (AddrSpace *)0);
}

/// Get the number of bytes needed to encode the \e offset
/// for this address.
/// \return the number of bytes in the encoding
inline int4 Address::getAddrSize(void) const {
  return base->getAddrSize();
}

/// Determine if data stored at this address is big endian encoded.
/// \return \b true if the address is big endian
inline bool Address::isBigEndian(void) const {
  return base->isBigEndian();
}

/// Write a short-hand or debug version of this address to a
/// stream.
/// \param s is the stream being written
inline void Address::printRaw(ostream &s) const {
  if (base == (AddrSpace *)0) {
    s << "invalid_addr";
    return;
  }
  base->printRaw(s,offset);
}

/// Convert a string into an address. The string format can be
/// tailored for the particular address space.
/// \param s is the string to parse
/// \return any size associated with the parsed string
inline int4 Address::read(const string &s) {
  int4 sz; offset=base->read(s,sz); return sz;
}

/// Get the address space associated with this address.
/// \return the AddressSpace pointer, or \b NULL if invalid
inline AddrSpace *Address::getSpace(void) const {
  return base;
}

/// Get the offset of the address as an integer.
/// \return the offset integer
inline uintb Address::getOffset(void) const {
  return offset;
}

/// Each address has a shortcut character associated with it
/// for use with the read and printRaw methods.
/// \return the shortcut char
inline char Address::getShortcut(void) const {
  return base->getShortcut();
}

/// This is a standard assignment operator, copying the
/// address space pointer and the offset
/// \param op2 is the Address being assigned
/// \return a reference to altered address
inline Address &Address::operator=(const Address &op2)

{
  base = op2.base;
  offset = op2.offset;
  return *this;
}

/// Check if two addresses are equal. I.e. if their address
/// space and offset are the same.
/// \param op2 is the address to compare to \e this
/// \return \b true if the addresses are the same
inline bool Address::operator==(const Address &op2) const { 
  return ((base==op2.base)&&(offset==op2.offset));
}

/// Check if two addresses are not equal.  I.e. if either their
/// address space or offset are different.
/// \param op2 is the address to compare to \e this
/// \return \b true if the addresses are different
inline bool Address::operator!=(const Address &op2) const {
  return !(*this==op2);
}

/// Do an ordering comparison of two addresses.  Addresses are
/// sorted first on space, then on offset.  So two addresses in
/// the same space compare naturally based on their offset, but
/// addresses in different spaces also compare. Different spaces
/// are ordered by their index.
/// \param op2 is the address to compare to
/// \return \b true if \e this comes before \e op2
inline bool Address::operator<(const Address &op2) const {
  if (base != op2.base)  {
    if (base == (AddrSpace *)0) {
      return true;
    }
    else if (base == (AddrSpace *) ~((uintp)0)) {
      return false;
    }
    else if (op2.base == (AddrSpace *)0) {
      return false;
    }
    else if (op2.base == (AddrSpace *) ~((uintp)0)) {
      return true;
    }
    return (base->getIndex() < op2.base->getIndex());
  }
  if (offset != op2.offset) return (offset < op2.offset);
  return false;
}

/// Do an ordering comparison of two addresses.
/// \param op2 is the address to compare to
/// \return \b true if \e this comes before or is equal to \e op2
inline bool Address::operator<=(const Address &op2) const {
  if (base != op2.base)  {
    if (base == (AddrSpace *)0) {
      return true;
    }
    else if (base == (AddrSpace *) ~((uintp)0)) {
      return false;
    }
    else if (op2.base == (AddrSpace *)0) {
      return false;
    }
    else if (op2.base == (AddrSpace *) ~((uintp)0)) {
      return true;
    }
    return (base->getIndex() < op2.base->getIndex());
  }
  if (offset != op2.offset) return (offset < op2.offset);
  return true;
}

/// Add an integer value to the offset portion of the address.
/// The addition takes into account the \e size of the address
/// space, and the Address will wrap around if necessary.
/// \param off is the number to add to the offset
/// \return the new incremented address
inline Address Address::operator+(int4 off) const {
  return Address(base,base->wrapOffset(offset+off));
}

/// Subtract an integer value from the offset portion of the
/// address.  The subtraction takes into account the \e size of
/// the address space, and the Address will wrap around if
/// necessary.
/// \param off is the number to subtract from the offset
/// \return the new decremented address
inline Address Address::operator-(int4 off) const {
  return Address(base,base->wrapOffset(offset-off));
}

/// Determine if this address is from the \e constant \e space.
/// All constant values are represented as an offset into
/// the \e constant \e space.
/// \return \b true if this address represents a constant
inline bool Address::isConstant(void) const {
  return (base->getType() == IPTR_CONSTANT);
}

/// Determine if this address represents a set of joined memory locations.
/// \return \b true if this address represents a join
inline bool Address::isJoin(void) const {
  return (base->getType() == IPTR_JOIN);
}

/// Save an \b \<addr\> tag corresponding to this address to a
/// stream.  The exact format is determined by the address space,
/// but this generally has a \e space and an \e offset attribute.
/// \param s is the stream being written to
inline void Address::saveXml(ostream &s) const {
  s << "<addr";
  if (base!=(AddrSpace *)0)
    base->saveXmlAttributes(s,offset);
  s << "/>";
}

/// Save an \b \<addr\> tag corresponding to this address to a
/// stream.  The tag will also include an extra \e size attribute
/// so that it can describe an entire memory range.
/// \param s is the stream being written to
/// \param size is the number of bytes in the range
inline void Address::saveXml(ostream &s,int4 size) const {
  s << "<addr";
  if (base!=(AddrSpace *)0)
    base->saveXmlAttributes(s,offset,size);
  s << "/>";
}

/// In \b LOAD and \b STORE instructions, the particular address
/// space being read/written is encoded as a constant input parameter
/// to the instruction.  Internally, this constant is the actual
/// pointer to the AddrSpace.  This function allows the encoded pointer
/// to be recovered from the address it is encoded in.
/// \param addr is the Address encoding the pointer
/// \return the AddrSpace pointer
inline AddrSpace *Address::getSpaceFromConst(const Address &addr) {
  return (AddrSpace *)(uintp)addr.offset;
}

/// \param addr is the Address to test for containment
/// \return \b true if addr is in \b this Range
inline bool Range::contains(const Address &addr) const {
  if (spc != addr.getSpace()) return false;
  if (first > addr.getOffset()) return false;
  if (last < addr.getOffset()) return false;
  return true;
}

/// \param size is the desired size in bytes
/// \return a value appropriate for masking off the first \e size bytes
inline uintb calc_mask(int4 size) { return uintbmasks[(size<8)? size : 8]; }

/// Perform a CPUI_INT_RIGHT on the given val
/// \param val is the value to shift
/// \param sa is the number of bits to shift
/// \return the shifted value
inline uintb pcode_right(uintb val,int4 sa) {
  if (sa >= 8*sizeof(uintb)) return 0;
  return val >> sa;
}

/// Perform a CPUI_INT_LEFT on the given val
/// \param val is the value to shift
/// \param sa is the number of bits to shift
/// \return the shifted value
inline uintb pcode_left(uintb val,int4 sa) {
  if (sa >= 8*sizeof(uintb)) return 0;
  return val << sa;
}

/// \brief Calculate smallest mask that covers the given value
///
/// Calculcate a mask that covers either the least significant byte, uint2, uint4, or uint8,
/// whatever is smallest.
/// \param val is the given value
/// \return the minimal mask
inline uintb minimalmask(uintb val)

{
  if (val > 0xffffffff)
    return ~((uintb)0);
  if (val > 0xffff)
    return 0xffffffff;
  if (val > 0xff)
    return 0xffff;
  return 0xff;
}

extern bool signbit_negative(uintb val,int4 size);	///< Return true if the sign-bit is set
extern uintb calc_mask(int4 size);			///< Calculate a mask for a given byte size
extern uintb uintb_negate(uintb in,int4 size);		///< Negate the \e sized value
extern uintb sign_extend(uintb in,int4 sizein,int4 sizeout);	///< Sign-extend a value between two byte sizes

extern void sign_extend(intb &val,int4 bit); 		///< Sign extend above given bit
extern void zero_extend(intb &val,int4 bit);		///< Clear all bits above given bit
extern void byte_swap(intb &val,int4 size);		///< Swap bytes in the given value

extern uintb byte_swap(uintb val,int4 size);		///< Return the given value with bytes swapped
extern int4 leastsigbit_set(uintb val);			///< Return index of least significant bit set in given value
extern int4 mostsigbit_set(uintb val);			///< Return index of most significant bit set in given value
extern int4 popcount(uintb val);			///< Return the number of one bits in the given value
extern int4 count_leading_zeros(uintb val);		///< Return the number of leading zero bits in the given value

extern uintb coveringmask(uintb val);			///< Return a mask that \e covers the given value
extern int4 bit_transitions(uintb val,int4 sz);		///< Calculate the number of bit transitions in the sized value

extern void mult64to128(uint8 *res,uint8 x,uint8 y);
extern void unsignedSubtract128(uint8 *a,uint8 *b);
extern int4 unsignedCompare128(uint8 *a,uint8 *b);
extern int4 power2Divide(int4 n,uint8 divisor,uint8 &q,uint8 &r);

#endif

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
/// \file space.hh
/// \brief Classes for describing address spaces

#ifndef __SPACE_HH__
#define __SPACE_HH__

#include "error.hh"
#include "marshal.hh"

namespace ghidra {

/// \brief Fundemental address space types
///
/// Every address space must be one of the following core types
enum spacetype {
  IPTR_CONSTANT = 0,	       ///< Special space to represent constants
  IPTR_PROCESSOR = 1,	       ///< Normal spaces modelled by processor
  IPTR_SPACEBASE = 2,	       ///< addresses = offsets off of base register
  IPTR_INTERNAL = 3,	       ///< Internally managed temporary space
  IPTR_FSPEC = 4,	       ///< Special internal FuncCallSpecs reference
  IPTR_IOP = 5,                ///< Special internal PcodeOp reference
  IPTR_JOIN = 6		       ///< Special virtual space to represent split variables
};

class AddrSpace;
class AddrSpaceManager;
struct VarnodeData;
class Translate;

extern AttributeId ATTRIB_BASE;		///< Marshaling attribute "base"
extern AttributeId ATTRIB_DEADCODEDELAY;	///< Marshaling attribute "deadcodedelay"
extern AttributeId ATTRIB_DELAY;	///< Marshaling attribute "delay"
extern AttributeId ATTRIB_LOGICALSIZE;	///< Marshaling attribute "logicalsize"
extern AttributeId ATTRIB_PHYSICAL;	///< Marshaling attribute "physical"
extern AttributeId ATTRIB_PIECE;	///< Marshaling attribute "piece"

/// \brief A region where processor data is stored
///
/// An AddrSpace (Address Space) is an arbitrary sequence of
/// bytes where a processor can store data. As is usual with
/// most processors' concept of RAM, an integer offset
/// paired with an AddrSpace forms the address (See Address)
/// of a byte.  The \e size of an AddrSpace indicates the number
/// of bytes that can be separately addressed and is usually
/// described by the number of bytes needed to encode the biggest
/// offset.  I.e. a \e 4-byte address space means that there are
/// offsets ranging from 0x00000000 to 0xffffffff within the space
/// for a total of 2^32 addressable bytes within the space.
/// There can be multiple address spaces, and it is typical to have spaces
///     - \b ram        Modeling the main processor address bus
///     - \b register   Modeling a processors registers
///
/// The processor specification can set up any address spaces it
/// needs in an arbitrary manner, but \e all data manipulated by
/// the processor, which the specification hopes to model, must
/// be contained in some address space, including RAM, ROM,
/// general registers, special registers, i/o ports, etc.
///
/// The analysis engine also uses additional address spaces to
/// model special concepts.  These include
///     - \b const        There is a \e constant address space for
///                       modeling constant values in p-code expressions
///                       (See ConstantSpace)
///     - \b unique       There is always a \e unique address space used
///                       as a pool for temporary registers. (See UniqueSpace)
///
class AddrSpace {
  friend class AddrSpaceManager; // Space container
public:
  enum {
    big_endian = 1,		///< Space is big endian if set, little endian otherwise
    heritaged = 2,		///< This space is heritaged
    does_deadcode = 4,		///< Dead-code analysis is done on this space
    programspecific = 8,        ///< Space is specific to a particular loadimage
    reverse_justification = 16, ///< Justification within aligned word is opposite of endianness
    formal_stackspace = 0x20,	///< Space attached to the formal \b stack \b pointer
    overlay = 0x40,		///< This space is an overlay of another space
    overlaybase = 0x80,		///< This is the base space for overlay space(s)
    truncated = 0x100,		///< Space is truncated from its original size, expect pointers larger than this size
    hasphysical = 0x200,	///< Has physical memory associated with it
    is_otherspace = 0x400,	///< Quick check for the OtherSpace derived class
    has_nearpointers = 0x800	///< Does there exist near pointers into this space
  };
private:
  spacetype type;		///< Type of space (PROCESSOR, CONSTANT, INTERNAL, ...)
  AddrSpaceManager *manage;     ///< Manager for processor using this space
  const Translate *trans;	///< Processor translator (for register names etc) for this space
  int4 refcount;		///< Number of managers using this space
  uint4 flags;			///< Attributes of the space
  uintb highest;	        ///< Highest (byte) offset into this space
  uintb pointerLowerBound;	///< Offset below which we don't search for pointers
  uintb pointerUpperBound;	///< Offset above which we don't search for pointers
  char shortcut;		///< Shortcut character for printing
protected:
  string name;			///< Name of this space
  uint4 addressSize;		///< Size of an address into this space in bytes
  uint4 wordsize;		///< Size of unit being addressed (1=byte)
  int4 minimumPointerSize;	///< Smallest size of a pointer into \b this space (in bytes)
  int4 index;			///< An integer identifier for the space
  int4 delay;			///< Delay in heritaging this space
  int4 deadcodedelay;		///< Delay before deadcode removal is allowed on this space
  void calcScaleMask(void);	///< Calculate scale and mask
  void setFlags(uint4 fl);	///< Set a cached attribute
  void clearFlags(uint4 fl);	///< Clear a cached attribute
  void saveBasicAttributes(ostream &s) const; ///< Write the XML attributes of this space
  void decodeBasicAttributes(Decoder &decoder);	///< Read attributes for \b this space from an open XML element
  void truncateSpace(uint4 newsize);
public:
  AddrSpace(AddrSpaceManager *m,const Translate *t,spacetype tp,const string &nm,uint4 size,uint4 ws,int4 ind,uint4 fl,int4 dl);
  AddrSpace(AddrSpaceManager *m,const Translate *t,spacetype tp); ///< For use with decode
  virtual ~AddrSpace(void) {}	///< The address space destructor
  const string &getName(void) const; ///< Get the name
  AddrSpaceManager *getManager(void) const; ///< Get the space manager
  const Translate *getTrans(void) const; ///< Get the processor translator
  spacetype getType(void) const; ///< Get the type of space
  int4 getDelay(void) const;     ///< Get number of heritage passes being delayed
  int4 getDeadcodeDelay(void) const; ///< Get number of passes before deadcode removal is allowed
  int4 getIndex(void) const;	///< Get the integer identifier
  uint4 getWordSize(void) const; ///< Get the addressable unit size
  uint4 getAddrSize(void) const; ///< Get the size of the space
  uintb getHighest(void) const;  ///< Get the highest byte-scaled address
  uintb getPointerLowerBound(void) const;	///< Get lower bound for assuming an offset is a pointer
  uintb getPointerUpperBound(void) const;	///< Get upper bound for assuming an offset is a pointer
  int4 getMinimumPtrSize(void) const;	///< Get the minimum pointer size for \b this space
  uintb wrapOffset(uintb off) const; ///< Wrap -off- to the offset that fits into this space
  char getShortcut(void) const; ///< Get the shortcut character
  bool isHeritaged(void) const;	///< Return \b true if dataflow has been traced
  bool doesDeadcode(void) const; ///< Return \b true if dead code analysis should be done on this space
  bool hasPhysical(void) const;  ///< Return \b true if data is physically stored in this
  bool isBigEndian(void) const;  ///< Return \b true if values in this space are big endian
  bool isReverseJustified(void) const;  ///< Return \b true if alignment justification does not match endianness
  bool isFormalStackSpace(void) const;	///< Return \b true if \b this is attached to the formal \b stack \b pointer
  bool isOverlay(void) const;  ///< Return \b true if this is an overlay space
  bool isOverlayBase(void) const; ///< Return \b true if other spaces overlay this space
  bool isOtherSpace(void) const;	///< Return \b true if \b this is the \e other address space
  bool isTruncated(void) const; ///< Return \b true if this space is truncated from its original size
  bool hasNearPointers(void) const;	///< Return \b true if \e near (truncated) pointers into \b this space are possible
  void printOffset(ostream &s,uintb offset) const;  ///< Write an address offset to a stream

  virtual int4 numSpacebase(void) const;	///< Number of base registers associated with this space
  virtual const VarnodeData &getSpacebase(int4 i) const;	///< Get a base register that creates this virtual space
  virtual const VarnodeData &getSpacebaseFull(int4 i) const;	///< Return original spacebase register before truncation
  virtual bool stackGrowsNegative(void) const;		///< Return \b true if a stack in this space grows negative
  virtual AddrSpace *getContain(void) const;  ///< Return this space's containing space (if any)
  virtual int4 overlapJoin(uintb offset,int4 size,AddrSpace *pointSpace,uintb pointOff,int4 pointSkip) const;
  virtual void encodeAttributes(Encoder &encoder,uintb offset) const;  ///< Encode address attributes to a stream
  virtual void encodeAttributes(Encoder &encoder,uintb offset,int4 size) const;   ///< Encode an address and size attributes to a stream
  virtual uintb decodeAttributes(Decoder &decoder,uint4 &size) const;   ///< Recover an offset and size
  virtual void printRaw(ostream &s,uintb offset) const;  ///< Write an address in this space to a stream
  virtual uintb read(const string &s,int4 &size) const;  ///< Read in an address (and possible size) from a string
  virtual void saveXml(ostream &s) const; ///< Write the details of this space as XML
  virtual void decode(Decoder &decoder); ///< Recover the details of this space from XML

  static uintb addressToByte(uintb val,uint4 ws); ///< Scale from addressable units to byte units
  static uintb byteToAddress(uintb val,uint4 ws); ///< Scale from byte units to addressable units
  static int8 addressToByteInt(int8 val,uint4 ws); ///< Scale int4 from addressable units to byte units
  static int8 byteToAddressInt(int8 val,uint4 ws); ///< Scale int4 from byte units to addressable units
  static bool compareByIndex(const AddrSpace *a,const AddrSpace *b);	///< Compare two spaces by their index
};

/// \brief Special AddrSpace for representing constants during analysis.
///
/// The underlying RTL (See PcodeOp) represents all data in terms of
/// an Address, which is made up of an AddrSpace and offset pair.
/// In order to represent constants in the semantics of the RTL,
/// there is a special \e constant address space.  An \e offset
/// within the address space encodes the actual constant represented
/// by the pair.  I.e. the pair (\b const,4) represents the constant
/// \b 4 within the RTL.  The \e size of the ConstantSpace has
/// no meaning, as we always want to be able to represent an arbitrarily
/// large constant.  In practice, the size of a constant is limited
/// by the offset field of an Address.
class ConstantSpace : public AddrSpace {
public:
  ConstantSpace(AddrSpaceManager *m,const Translate *t); ///< Only constructor
  virtual int4 overlapJoin(uintb offset,int4 size,AddrSpace *pointSpace,uintb pointOff,int4 pointSkip) const;
  virtual void printRaw(ostream &s,uintb offset) const;
  virtual void saveXml(ostream &s) const;
  virtual void decode(Decoder &decoder);
  static const string NAME;		///< Reserved name for the address space
  static const int4 INDEX;		///< Reserved index for constant space
};

/// \brief Special AddrSpace for special/user-defined address spaces
class OtherSpace : public AddrSpace {
public:
  OtherSpace(AddrSpaceManager *m, const Translate *t, int4 ind);	///< Constructor
  OtherSpace(AddrSpaceManager *m, const Translate *t);	///< For use with decode
  virtual void printRaw(ostream &s, uintb offset) const;
  virtual void saveXml(ostream &s) const;
  static const string NAME;		///< Reserved name for the address space
  static const int4 INDEX;		///< Reserved index for the other space
};

/// \brief The pool of temporary storage registers
///
/// It is convenient both for modelling processor instructions
/// in an RTL and for later transforming of the RTL to have a pool
/// of temporary registers that can hold data but that aren't a
/// formal part of the state of the processor. The UniqueSpace
/// provides a specific location for this pool.  The analysis
/// engine always creates exactly one of these spaces named
/// \b unique.  
class UniqueSpace : public AddrSpace {
public:
  UniqueSpace(AddrSpaceManager *m,const Translate *t,int4 ind,uint4 fl);	///< Constructor
  UniqueSpace(AddrSpaceManager *m,const Translate *t);	///< For use with decode
  virtual void saveXml(ostream &s) const;
  static const string NAME;		///< Reserved name for the unique space
  static const uint4 SIZE;		///< Fixed size (in bytes) for unique space offsets
};

/// \brief The pool of logically joined variables
///
/// Some logical variables are split across non-contiguous regions of memory. This space
/// creates a virtual place for these logical variables to exist.  Any memory location within this
/// space is backed by 2 or more memory locations in other spaces that physically hold the pieces
/// of the logical value. The database controlling symbols is responsible for keeping track of
/// mapping the logical address in this space to its physical pieces.  Offsets into this space do not
/// have an absolute meaning, the database may vary what offset is assigned to what set of pieces.
class JoinSpace : public AddrSpace {
  static const int4 MAX_PIECES = 64;	///< Maximum number of pieces that can be marshaled in one \e join address
public:
  JoinSpace(AddrSpaceManager *m,const Translate *t,int4 ind);
  virtual int4 overlapJoin(uintb offset,int4 size,AddrSpace *pointSpace,uintb pointOff,int4 pointSkip) const;
  virtual void encodeAttributes(Encoder &encoder,uintb offset) const;
  virtual void encodeAttributes(Encoder &encoder,uintb offset,int4 size) const;
  virtual uintb decodeAttributes(Decoder &decoder,uint4 &size) const;
  virtual void printRaw(ostream &s,uintb offset) const;
  virtual uintb read(const string &s,int4 &size) const;
  virtual void saveXml(ostream &s) const;
  virtual void decode(Decoder &decoder);
  static const string NAME;		///< Reserved name for the join space
};

/// \brief An overlay space.
///
/// A different code and data layout that occupies the same memory as another address space.
/// Some compilers use this concept to increase the logical size of a program without increasing
/// its physical memory requirements.  An overlay space allows the same physical location to contain
/// different code and be labeled with different symbols, depending on context.
/// From the point of view of reverse engineering, the different code and symbols are viewed
/// as a logically distinct space.
class OverlaySpace : public AddrSpace {
  AddrSpace *baseSpace;		///< Space being overlayed
public:
  OverlaySpace(AddrSpaceManager *m,const Translate *t);	///< Constructor
  virtual AddrSpace *getContain(void) const { return baseSpace; }
  virtual void saveXml(ostream &s) const;
  virtual void decode(Decoder &decoder);
};

/// An internal method for derived classes to set space attributes
/// \param fl is the set of attributes to be set
inline void AddrSpace::setFlags(uint4 fl) {
  flags |= fl;
}

/// An internal method for derived classes to clear space attibutes
/// \param fl is the set of attributes to clear
inline void AddrSpace::clearFlags(uint4 fl) {
  flags &= ~fl;
}

/// Every address space has a (unique) name, which is referred
/// to especially in configuration files via XML.
/// \return the name of this space
inline const string &AddrSpace::getName(void) const {
  return name;
}

/// Every address space is associated with a manager of (all possible) spaces.
/// This method recovers the address space manager object.
/// \return a pointer to the address space manager
inline AddrSpaceManager *AddrSpace::getManager(void) const {
  return manage;
}

/// Every address space is associated with a processor which may have additional objects
/// like registers etc. associated with it. This method returns a pointer to that processor
/// translator
/// \return a pointer to the Translate object
inline const Translate *AddrSpace::getTrans(void) const {
  return trans;
}

///
/// Return the defining type for this address space.
///   - IPTR_CONSTANT for the constant space
///   - IPTR_PROCESSOR for a normal space
///   - IPTR_INTERNAL for the temporary register space
///   - IPTR_FSPEC for special FuncCallSpecs references
///   - IPTR_IOP for special PcodeOp references
/// \return the basic type of this space
inline spacetype AddrSpace::getType(void) const {
  return type;
}

/// If the heritage algorithms need to trace dataflow
/// within this space, the algorithms can delay tracing this
/// space in order to let indirect references into the space
/// resolve themselves.  This method indicates the number of
/// rounds of dataflow analysis that should be skipped for this
/// space to let this resolution happen
/// \return the number of rounds to skip heritage
inline int4 AddrSpace::getDelay(void) const {
  return delay;
}

/// The point at which deadcode removal is performed on varnodes within
/// a space can be set to skip some number of heritage passes, in case
/// not all the varnodes are created within a single pass. This method
/// gives the number of rounds that should be skipped before deadcode
/// elimination begins
/// \return the number of rounds to skip deadcode removal
inline int4 AddrSpace::getDeadcodeDelay(void) const {
  return deadcodedelay;
}

/// Each address space has an associated index that can be used
/// as an integer encoding of the space.
/// \return the unique index
inline int4 AddrSpace::getIndex(void) const {
  return index;
}

/// This method indicates the number of bytes contained in an
/// \e addressable \e unit of this space.  This is almost always
/// 1, but can be any other small integer.
/// \return the number of bytes in a unit
inline uint4 AddrSpace::getWordSize(void) const {
  return wordsize;
}

/// Return the number of bytes needed to represent an offset
/// into this space.  A space with 2^32 bytes has an address
/// size of 4, for instance.
/// \return the size of an address
inline uint4 AddrSpace::getAddrSize(void) const {
  return addressSize;
}

/// Get the highest (byte) offset possible for this space
/// \return the offset
inline uintb AddrSpace::getHighest(void) const {
  return highest;
}

/// Constant offsets are tested against \b this lower bound as a quick filter before
/// attempting to lookup symbols.
/// \return the minimum offset that will be inferred as a pointer
inline uintb AddrSpace::getPointerLowerBound(void) const {
  return pointerLowerBound;
}

/// Constant offsets are tested against \b this upper bound as a quick filter before
/// attempting to lookup symbols.
/// \return the maximum offset that will be inferred as a pointer
inline uintb AddrSpace::getPointerUpperBound(void) const {
  return pointerUpperBound;
}

/// A value of 0 means the size must match exactly. If the space is truncated, or
/// if there exists near pointers, this value may be non-zero.
inline int4 AddrSpace::getMinimumPtrSize(void) const {
  return minimumPointerSize;
}

/// Calculate \e off modulo the size of this address space in
/// order to construct the offset "equivalent" to \e off that
/// fits properly into this space
/// \param off is the offset requested
/// \return the wrapped offset
inline uintb AddrSpace::wrapOffset(uintb off) const {
  if (off <= highest)		// Comparison is unsigned
    return off;
  intb mod = (intb)(highest+1);
  intb res = (intb)off % mod;	// remainder is signed
  if (res<0)			// Remainder may be negative
    res += mod;			// Adding mod guarantees res is in (0,mod)
  return (uintb)res;
}

/// Return a unique short cut character that is associated
/// with this space.  The shortcut character can be used by
/// the read method to quickly specify the space of an address.
/// \return the shortcut character
inline char AddrSpace::getShortcut(void) const {
  return shortcut;
}

/// During analysis, memory locations in most spaces need to
/// have their data-flow traced.  This method returns \b true
/// for these spaces.  For some of the special spaces, like
/// the \e constant space, tracing data flow makes no sense,
/// and this routine will return \b false.
/// \return \b true if this space's data-flow is analyzed
inline bool AddrSpace::isHeritaged(void) const {
  return ((flags & heritaged)!=0);
}

/// Most memory locations should have dead-code analysis performed,
/// and this routine will return \b true.
/// For certain special spaces like the \e constant space, dead-code
/// analysis doesn't make sense, and this routine returns \b false.
inline bool AddrSpace::doesDeadcode(void) const {
  return ((flags & does_deadcode)!=0);
}

/// This routine returns \b true, if, like most spaces, the space
/// has actual read/writeable bytes associated with it.
/// Some spaces, like the \e constant space, do not.
/// \return \b true if the space has physical data in it.
inline bool AddrSpace::hasPhysical(void) const {
  return ((flags & hasphysical) !=0);
}

/// If integer values stored in this space are encoded in this
/// space using the big endian format, then return \b true.
/// \return \b true if the space is big endian
inline bool AddrSpace::isBigEndian(void) const {
  return ((flags&big_endian)!=0);
}

/// Certain architectures or compilers specify an alignment for accessing words within the space
/// The space required for a variable must be rounded up to the alignment. For variables smaller
/// than the alignment, there is the issue of how the variable is "justified" within the aligned
/// word. Usually the justification depends on the endianness of the space, for certain weird
/// cases the justification may be the opposite of the endianness.
inline bool AddrSpace::isReverseJustified(void) const {
  return ((flags&reverse_justification)!=0);
}

/// Currently an architecture can declare only one formal stack pointer.
inline bool AddrSpace::isFormalStackSpace(void) const {
  return ((flags&formal_stackspace)!=0);
}

inline bool AddrSpace::isOverlay(void) const {
  return ((flags&overlay)!=0);
}

inline bool AddrSpace::isOverlayBase(void) const {
  return ((flags&overlaybase)!=0);
}

inline bool AddrSpace::isOtherSpace(void) const {
  return ((flags&is_otherspace)!=0);
}

/// If this method returns \b true, the logical form of this space is truncated from its actual size
/// Pointers may refer to this original size put the most significant bytes are ignored
inline bool AddrSpace::isTruncated(void) const {
  return ((flags&truncated)!=0);
}

inline bool AddrSpace::hasNearPointers(void) const {
  return ((flags&has_nearpointers)!=0);
}

/// Some spaces are "virtual", like the stack spaces, where addresses are really relative to a
/// base pointer stored in a register, like the stackpointer.  This routine will return non-zero
/// if \b this space is virtual and there is 1 (or more) associated pointer registers
/// \return the number of base registers associated with this space
inline int4 AddrSpace::numSpacebase(void) const {
  return 0;
}

/// For virtual spaces, like the stack space, this routine returns the location information for
/// a base register of the space.  This routine will throw an exception if the register does not exist
/// \param i is the index of the base register starting at
/// \return the VarnodeData that describes the register
inline const VarnodeData &AddrSpace::getSpacebase(int4 i) const {
  throw LowlevelError(name+" space is not virtual and has no associated base register");
}

/// If a stack pointer is truncated to fit the stack space, we may need to know the
/// extent of the original register
/// \param i is the index of the base register
/// \return the original register before truncation
inline const VarnodeData &AddrSpace::getSpacebaseFull(int4 i) const {
  throw LowlevelError(name+" has no truncated registers");
}

/// For stack (or other spacebase) spaces, this routine returns \b true if the space can viewed as a stack
/// and a \b push operation causes the spacebase pointer to be decreased (grow negative)
/// \return \b true if stacks grow in negative direction.
inline bool AddrSpace::stackGrowsNegative(void) const {
  return true;
}

/// If this space is virtual, then
/// this routine returns the containing address space, otherwise
/// it returns NULL.
/// \return a pointer to the containing space or NULL
inline AddrSpace *AddrSpace::getContain(void) const {
  return (AddrSpace *)0;
}

/// Given an offset into an address space based on the addressable unit size (wordsize),
/// convert it into a byte relative offset
/// \param val is the offset to convert
/// \param ws is the number of bytes in the addressable word
/// \return the scaled offset
inline uintb AddrSpace::addressToByte(uintb val,uint4 ws) {
  return val*ws;
}

/// Given an offset in an address space based on bytes, convert it
/// into an offset relative to the addressable unit of the space (wordsize)
/// \param val is the offset to convert
/// \param ws is the number of bytes in the addressable word
/// \return the scaled offset
inline uintb AddrSpace::byteToAddress(uintb val,uint4 ws) {
  return val/ws;
}

/// Given an int8 offset into an address space based on the addressable unit size (wordsize),
/// convert it into a byte relative offset
/// \param val is the offset to convert
/// \param ws is the number of bytes in the addressable word
/// \return the scaled offset
inline int8 AddrSpace::addressToByteInt(int8 val,uint4 ws) {
  return val*ws;
}

/// Given an int8 offset in an address space based on bytes, convert it
/// into an offset relative to the addressable unit of the space (wordsize)
/// \param val is the offset to convert
/// \param ws is the number of bytes in the addressable word
/// \return the scaled offset
inline int8 AddrSpace::byteToAddressInt(int8 val,uint4 ws) {
  return val/ws;
}

/// For sorting a sequence of address spaces.
/// \param a is the first space
/// \param b is the second space
/// \return \b true if the first space should come before the second
inline bool AddrSpace::compareByIndex(const AddrSpace *a,const AddrSpace *b) {
  return (a->index < b->index);
}

} // End namespace ghidra
#endif

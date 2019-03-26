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
/// \file memstate.hh
/// \brief Classes for keeping track of memory state during emulation

#ifndef __CPUI_MEMSTATE__
#define __CPUI_MEMSTATE__

#include "pcoderaw.hh"
#include "loadimage.hh"

/// \brief Memory storage/state for a single AddressSpace
///
/// Class for setting and getting memory values within a space
/// The basic API is to get/set arrays of byte values via offset within the space.
/// Helper functions getValue and setValue easily retrieve/store integers
/// of various sizes from memory, using the endianness encoding specified by the space.
/// Accesses through the public interface, are automatically broken down into
/// \b word accesses, through the private insert/find methods, and \b page
/// accesses through getPage/setPage.  So these are the virtual methods that need
/// to be overridden in the derived classes.

class MemoryBank {
  friend class MemoryPageOverlay;
  friend class MemoryHashOverlay;
  int4 wordsize;		///< Number of bytes in an aligned word access
  int4 pagesize;		///< Number of bytes in an aligned page access
  AddrSpace *space;		///< The address space associated with this memory
protected:
  virtual void insert(uintb addr,uintb val)=0; ///< Insert a word in memory bank at an aligned location
  virtual uintb find(uintb addr) const=0; ///< Retrieve a word from memory bank at an aligned location
  virtual void getPage(uintb addr,uint1 *res,int4 skip,int4 size) const; ///< Retrieve data from a memory \e page 
  virtual void setPage(uintb addr,const uint1 *val,int4 skip,int4 size); ///< Write data into a memory page
public:
  MemoryBank(AddrSpace *spc,int4 ws,int4 ps); ///< Generic constructor for a memory bank
  virtual ~MemoryBank(void) {}
  int4 getWordSize(void) const;	///< Get the number of bytes in a word for this memory bank
  int4 getPageSize(void) const;	///< Get the number of bytes in a page for this memory bank
  AddrSpace *getSpace(void) const; ///< Get the address space associated with this memory bank
  
  void setValue(uintb offset,int4 size,uintb val); ///< Set the value of a (small) range of bytes
  uintb getValue(uintb offset,int4 size) const; ///< Retrieve the value encoded in a (small) range of bytes
  void setChunk(uintb offset,int4 size,const uint1 *val); ///< Set values of an arbitrary sequence of bytes
  void getChunk(uintb offset,int4 size,uint1 *res) const; ///< Retrieve an arbitrary sequence of bytes
  static uintb constructValue(const uint1 *ptr,int4 size,bool bigendian); ///< Decode bytes to value
  static void deconstructValue(uint1 *ptr,uintb val,int4 size,bool bigendian); ///< Encode value to bytes
};

/// A MemoryBank is instantiated with a \e natural word size. Requests for arbitrary byte ranges
/// may be broken down into units of this size.
/// \return the number of bytes in a \e word.
inline int4 MemoryBank::getWordSize(void) const

{
  return wordsize;
}

/// A MemoryBank is instantiated with a \e natural page size. Requests for large chunks of data
/// may be broken down into units of this size.
/// \return the number of bytes in a \e page.
inline int4 MemoryBank::getPageSize(void) const

{
  return pagesize;
}

/// A MemoryBank is a contiguous sequence of bytes associated with a particular address space.
/// \return the AddressSpace associated with this bank.
inline AddrSpace *MemoryBank::getSpace(void) const

{
  return space;
}

/// \brief A kind of MemoryBank which retrieves its data from an underlying LoadImage
///
/// Any bytes requested on the bank which lie in the LoadImage are retrieved from
/// the LoadImage.  Other addresses in the space are filled in with zero.
/// This bank cannot be written to.
class MemoryImage : public MemoryBank {
  LoadImage *loader;		///< The underlying LoadImage
protected:
  virtual void insert(uintb addr,uintb val) {
    throw LowlevelError("Writing to read-only MemoryBank"); } ///< Exception is thrown for write attempts
  virtual uintb find(uintb addr) const;	///< Overridden find method
  virtual void getPage(uintb addr,uint1 *res,int4 skip,int4 size) const; ///< Overridded getPage method
public:
  MemoryImage(AddrSpace *spc,int4 ws,int4 ps,LoadImage *ld); ///< Constructor for a loadimage memorybank
};

/// \brief Memory bank that overlays some other memory bank, using a "copy on write" behavior.
///
/// Pages are copied from the underlying object only when there is
/// a write. The underlying access routines are overridden to make optimal use
/// of this page implementation.  The underlying memory bank can be a \b null pointer
/// in which case, this memory bank behaves as if it were initially filled with zeros.
class MemoryPageOverlay : public MemoryBank {
  MemoryBank *underlie;		///< Underlying memory object
  map<uintb,uint1 *> page;	///< Overlayed pages
protected:
  virtual void insert(uintb addr,uintb val); ///< Overridden aligned word insert
  virtual uintb find(uintb addr) const;	///< Overridden aligned word find
  virtual void getPage(uintb addr,uint1 *res,int4 skip,int4 size) const; ///< Overridden getPage
  virtual void setPage(uintb addr,const uint1 *val,int4 skip,int4 size); ///< Overridden setPage
public:
  MemoryPageOverlay(AddrSpace *spc,int4 ws,int4 ps,MemoryBank *ul); ///< Constructor for page overlay
  virtual ~MemoryPageOverlay(void);
};

/// \brief A memory bank that implements reads and writes using a hash table.
///
/// The initial state of the
/// bank is taken from an \e underlying memory bank or is all zero, if this bank is initialized with
/// a \b null pointer.  This implementation will not be very efficient for accessing entire pages.
class MemoryHashOverlay : public MemoryBank {
  MemoryBank *underlie;		///< Underlying memory bank
  int4 alignshift;		///< How many LSBs are thrown away from address when doing hash table lookup
  uintb collideskip;		///< How many slots to skip after a hashtable collision
  vector<uintb> address;	///< The hashtable addresses
  vector<uintb> value;		///< The hashtable values
protected:
  virtual void insert(uintb addr,uintb val); ///< Overridden aligned word insert
  virtual uintb find(uintb addr) const;	///< Overridden aligned word find
public:
  MemoryHashOverlay(AddrSpace *spc,int4 ws,int4 ps,int4 hashsize,MemoryBank *ul); ///< Constructor for hash overlay
};

class Translate;		// Forward declaration

/// \brief All storage/state for a pcode machine
///
/// Every piece of information in a pcode machine is representable as a triple
/// (AddrSpace,offset,size).  This class allows getting and setting
/// of all state information of this form.
class MemoryState {
protected:
  Translate *trans;		///< Architecture information about memory spaces
  vector<MemoryBank *> memspace; ///< Memory banks associated with each address space
public:
  MemoryState(Translate *t);	///< A constructor for MemoryState
  ~MemoryState(void) {}
  Translate *getTranslate(void) const; ///< Get the Translate object
  void setMemoryBank(MemoryBank *bank);	///< Map a memory bank into the state
  MemoryBank *getMemoryBank(AddrSpace *spc) const; ///< Get a memory bank associated with a particular space
  void setValue(AddrSpace *spc,uintb off,int4 size,uintb cval); ///< Set a value on the memory state
  uintb getValue(AddrSpace *spc,uintb off,int4 size) const; ///< Retrieve a memory value from the memory state
  void setValue(const string &nm,uintb cval); ///< Set a value on a named register in the memory state
  uintb getValue(const string &nm) const; ///< Retrieve a value from a named register in the memory state
  void setValue(const VarnodeData *vn,uintb cval); ///< Set value on a given \b varnode
  uintb getValue(const VarnodeData *vn) const; ///< Get a value from a \b varnode
  void getChunk(uint1 *res,AddrSpace *spc,uintb off,int4 size) const; ///< Get a chunk of data from memory state
  void setChunk(const uint1 *val,AddrSpace *spc,uintb off,int4 size); ///< Set a chunk of data from memory state
};

/// The MemoryState needs a Translate object in order to be able to convert register names
/// into varnodes
/// \param t is the translator
inline MemoryState::MemoryState(Translate *t)

{
  trans = t;
}

/// Retrieve the actual pcode translator being used by this machine state
/// \return a pointer to the Translate object
inline Translate *MemoryState::getTranslate(void) const

{
  return trans;
}

/// A convenience method for setting a value directly on a varnode rather than
/// breaking out the components
/// \param vn is a pointer to the varnode to be written
/// \param cval is the value to write into the varnode
inline void MemoryState::setValue(const VarnodeData *vn,uintb cval)

{
  setValue(vn->space,vn->offset,vn->size,cval);
}

/// A convenience method for reading a value directly from a varnode rather
/// than querying for the offset and space
/// \param vn is a pointer to the varnode to be read
/// \return the value read from the varnode
inline uintb MemoryState::getValue(const VarnodeData *vn) const

{
  return getValue(vn->space,vn->offset,vn->size);
}

 #endif

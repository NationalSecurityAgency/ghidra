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
#ifndef __GLOBALCONTEXT_HH__
#define __GLOBALCONTEXT_HH__

/// \file globalcontext.hh
/// \brief Utilities for getting address-based context to the disassembler and decompiler

#include "pcoderaw.hh"
#include "partmap.hh"

namespace ghidra {

extern ElementId ELEM_CONTEXT_DATA;	///< Marshaling element \<context_data>
extern ElementId ELEM_CONTEXT_POINTS;	///< Marshaling element \<context_points>
extern ElementId ELEM_CONTEXT_POINTSET;	///< Marshaling element \<context_pointset>
extern ElementId ELEM_CONTEXT_SET;	///< Marshaling element \<context_set>
extern ElementId ELEM_SET;		///< Marshaling element \<set>
extern ElementId ELEM_TRACKED_POINTSET;	///< Marshaling element \<tracked_pointset>
extern ElementId ELEM_TRACKED_SET;	///< Marshaling element \<tracked_set>

/// \brief Description of a context variable within the disassembly context \e blob
///
/// Disassembly context is stored as individual (integer) values packed into a sequence of words. This class
/// represents the info for encoding or decoding a single value within this sequence.  A value is
/// a contiguous range of bits within one context word. Size can range from 1 bit up to the size of a word.
class ContextBitRange {
  int4 word;		///< Index of word containing this context value
  int4 startbit;	///< Starting bit of the value within its word (0=most significant bit 1=least significant)
  int4 endbit;		///< Ending bit of the value within its word
  int4 shift;		///< Right-shift amount to apply when unpacking this value from its word
  uintm mask;		///< Mask to apply (after shifting) when unpacking this value from its word
public:
  ContextBitRange(void) { }	///< Construct an undefined bit range
  ContextBitRange(int4 sbit,int4 ebit);		///< Construct a context value given an absolute bit range
  int4 getShift(void) const { return shift; }	///< Return the shift-amount for \b this value
  uintm getMask(void) const { return mask; }	///< Return the mask for \b this value
  int4 getWord(void) const { return word; }	///< Return the word index for \b this value

  /// \brief Set \b this value within a given context blob
  ///
  /// \param vec is the given context blob to alter (as an array of uintm words)
  /// \param val is the integer value to set
  void setValue(uintm *vec,uintm val) const {
    uintm newval = vec[word];
    newval &= ~(mask<<shift);
    newval |= ((val & mask)<<shift);
    vec[word] = newval;
  }

  /// \brief Retrieve \b this value from a given context blob
  ///
  /// \param vec is the given context blob (as an array of uintm words)
  /// \return the recovered integer value
  uintm getValue(const uintm *vec) const {
    return ((vec[word]>>shift)&mask);
  }
};

/// \brief A tracked register (Varnode) and the value it contains
///
/// This is the object returned when querying for tracked registers,
/// via ContextDatabase::getTrackedSet().  It holds the storage details of the register and
/// the actual value it holds at the point of the query.
struct TrackedContext {
  VarnodeData loc;	///< Storage details of the register being tracked
  uintb val;		///< The value of the register
  void decode(Decoder &decoder);			///< Decode \b this from a stream
  void encode(Encoder &encoder) const;			///< Encode \b this to a stream
};
typedef vector<TrackedContext> TrackedSet;		///< A set of tracked registers and their values (at one code point)

/// \brief An interface to a database of disassembly/decompiler \b context information
///
/// \b Context \b information is a set of named variables that hold concrete values at specific
/// addresses in the target executable being analyzed. A variable can hold different values at
/// different addresses, but a specific value at a specific address never changes. Analysis recovers
/// these values over time, populating this database, and querying this database lets analysis
/// provides concrete values for memory locations in context.
///
/// Context variables come in two flavors:
///  - \b Low-level \b context \b variables:
///      These can affect instruction decoding. These can be as small as a single bit and need to
///      be defined in the Sleigh specification (so that Sleigh knows how they effect disassembly).
///      These variables are not mapped to normal memory locations with an address space and offset
///      (although they often have a corresponding embedding into a normal memory location).
///      The model to keep in mind is a control register with specialized bit-fields within it.
///  - \b High-level \b tracked \b variables:
///      These are normal memory locations that are to be treated as constants across some range of
///      code. These are normally registers that are being tracked by the compiler outside the
///      domain of normal local and global variables. They have a specific value established by
///      the compiler coming into a function but are not supposed to be interpreted as a high-level
///      variable. Typical examples are the direction flag (for \e string instructions) and segment
///      registers. All tracked variables are interpreted as a constant value at the start of a
///      function, although the memory location can be recycled for other calculations later in the
///      function.
///
/// Low-level context variables can be queried and set by name -- getVariable(), setVariable(),
/// setVariableRegion() -- but the disassembler accesses all the variables at an address as a group
/// via getContext(), setContextChangePoint(), setContextRegion().  In this setting, all the values
/// are packed together in an array of words, a context \e blob (See ContextBitRange).
///
/// Tracked variables are also queried as a group via getTrackedSet() and createSet().  These return
/// a list of TrackedContext objects.
class ContextDatabase {
protected:
  static void encodeTracked(Encoder &encoder,const Address &addr,const TrackedSet &vec);
  static void decodeTracked(Decoder &decoder,TrackedSet &vec);

  /// \brief Retrieve the context variable description object by name
  ///
  /// If the variable doesn't exist an exception is thrown.
  /// \param nm is the name of the context value
  /// \return the ContextBitRange object matching the name
  virtual ContextBitRange &getVariable(const string &nm)=0;

  /// \brief Retrieve the context variable description object by name
  ///
  /// If the variable doesn't exist an exception is thrown.
  /// \param nm is the name of the context value
  /// \return the ContextBitRange object matching the name
  virtual const ContextBitRange &getVariable(const string &nm) const=0;

  /// \brief Grab the context blob(s) for the given address range, marking bits that will be set
  ///
  /// This is an internal routine for obtaining the actual memory regions holding context values
  /// for the address range.  This also informs the system which bits are getting set. A split is forced
  /// at the first address, and at least one memory region is passed back. The second address can be
  /// invalid in which case the memory region passed back is valid from the first address to whatever
  /// the next split point is.
  /// \param res will hold pointers to memory regions for the given range
  /// \param addr1 is the starting address of the range
  /// \param addr2 is (1 past) the last address of the range or is invalid
  /// \param num is the word index for the context value that will be set
  /// \param mask is a mask of the value being set (within its word)
  virtual void getRegionForSet(vector<uintm *> &res,const Address &addr1,
			       const Address &addr2,int4 num,uintm mask)=0;

  /// \brief Grab the context blob(s) starting at the given address up to the first point of change
  ///
  /// This is an internal routine for obtaining the actual memory regions holding context values
  /// starting at the given address.  A specific context value is specified, and all memory regions
  /// are returned up to the first address where that particular context value changes.
  /// \param res will hold pointers to memory regions being passed back
  /// \param addr is the starting address of the regions to fetch
  /// \param num is the word index for the specific context value being set
  /// \param mask is a mask of the context value being set (within its word)
  virtual void getRegionToChangePoint(vector<uintm *> &res,const Address &addr,int4 num,uintm mask)=0;

  /// \brief Retrieve the memory region holding all default context values
  ///
  /// This fetches the active memory holding the default context values on top of which all other context
  /// values are overlaid.
  /// \return the memory region holding all the default context values
  virtual uintm *getDefaultValue(void)=0;

  /// \brief Retrieve the memory region holding all default context values
  ///
  /// This fetches the active memory holding the default context values on top of which all other context
  /// values are overlaid.
  /// \return the memory region holding all the default context values
  virtual const uintm *getDefaultValue(void) const=0;
public:
  virtual ~ContextDatabase() {}			///< Destructor

  /// \brief Retrieve the number of words (uintm) in a context \e blob
  ///
  /// \return the number of words
  virtual int4 getContextSize(void) const=0;

  /// \brief Register a new named context variable (as a bit range) with the database
  ///
  /// A new variable is registered by providing a name and the range of bits the value will occupy
  /// within the context blob.  The full blob size is automatically increased if necessary.  The variable
  /// must be contained within a single word, and all variables must be registered before any values can
  /// be set.
  /// \param nm is the name of the new variable
  /// \param sbit is the position of the variable's most significant bit within the blob
  /// \param ebit is the position of the variable's least significant bit within the blob
  virtual void registerVariable(const string &nm,int4 sbit,int4 ebit)=0;

  /// \brief Get the context blob of values associated with a given address
  ///
  /// \param addr is the given address
  /// \return the memory region holding the context values for the address
  virtual const uintm *getContext(const Address &addr) const=0;

  /// \brief Get the context blob of values associated with a given address and its bounding offsets
  ///
  /// In addition to the memory region, the range of addresses for which the region is valid
  /// is passed back as offsets into the address space.
  /// \param addr is the given address
  /// \param first will hold the starting offset of the valid range
  /// \param last will hold the ending offset of the valid range
  /// \return the memory region holding the context values for the address
  virtual const uintm *getContext(const Address &addr,uintb &first,uintb &last) const=0;

  /// \brief Get the set of default values for all tracked registers
  ///
  /// \return the list of TrackedContext objects
  virtual TrackedSet &getTrackedDefault(void)=0;

  /// \brief Get the set of tracked register values associated with the given address
  ///
  /// \param addr is the given address
  /// \return the list of TrackedContext objects
  virtual const TrackedSet &getTrackedSet(const Address &addr) const=0;

  /// \brief Create a tracked register set that is valid over the given range
  ///
  /// This really should be an internal routine.  The created set is empty, old values are blown
  /// away.  If old/default values are to be preserved, they must be copied back in.
  /// \param addr1 is the starting address of the given range
  /// \param addr2 is (1 past) the ending address of the given range
  /// \return the empty set of tracked register values
  virtual TrackedSet &createSet(const Address &addr1,const Address &addr2)=0;

  /// \brief Encode the entire database to a stream
  ///
  /// \param encoder is the stream encoder
  virtual void encode(Encoder &encoder) const=0;

  /// \brief Restore the state of \b this database object from the given stream decoder
  ///
  /// \param decoder is the given stream decoder
  virtual void decode(Decoder &decoder)=0;

  /// \brief Add initial context state from elements in the compiler/processor specifications
  ///
  /// Parse a \<context_data> element from the given stream decoder from either the compiler
  /// or processor specification file for the architecture, initializing this database.
  /// \param decoder is the given stream decoder
  virtual void decodeFromSpec(Decoder &decoder)=0;

  void setVariableDefault(const string &nm,uintm val);	///< Provide a default value for a context variable
  uintm getDefaultValue(const string &nm) const;	///< Retrieve the default value for a context variable
  void setVariable(const string &nm,const Address &addr,uintm value);	///< Set a context value at the given address
  uintm getVariable(const string &nm,const Address &addr) const;	///< Retrieve a context value at the given address
  void setContextChangePoint(const Address &addr,int4 num,uintm mask,uintm value);
  void setContextRegion(const Address &addr1,const Address &addr2,int4 num,uintm mask,uintm value);
  void setVariableRegion(const string &nm,const Address &begad,
			 const Address &endad,uintm value);
  uintb getTrackedValue(const VarnodeData &mem,const Address &point) const;
};

/// \brief An in-memory implementation of the ContextDatabase interface
///
/// Context blobs are held in a partition map on addresses.  Any address within the map
/// indicates a \e split point, where the value of a context variable was explicitly changed.
/// Sets of tracked registers are held in a separate partition map.
class ContextInternal : public ContextDatabase {

  /// \brief A context blob, holding context values across some range of code addresses
  ///
  /// This is an internal object that allocates the actual "array of words" for a context blob.
  /// An associated mask array holds 1-bits for context variables that were explicitly set for the
  /// specific split point.
  struct FreeArray {
    uintm *array;		///< The "array of words" holding context variable values
    uintm *mask;		///< The mask array indicating which variables are explicitly set
    int4 size;			///< The number of words in the array
    FreeArray(void) { size=0; array = (uintm *)0; mask = (uintm *)0; }	///< Construct an empty context blob
    ~FreeArray(void) { if (size!=0) { delete [] array; delete [] mask; } }	///< Destructor
    void reset(int4 sz);	///< Resize the context blob, preserving old values
    FreeArray &operator=(const FreeArray &op2);	///< Assignment operator
  };

  int4 size;			///< Number of words in a context blob (for this architecture)
  map<string,ContextBitRange> variables;		///< Map from context variable name to description object
  partmap<Address,FreeArray> database;			///< Partition map of context blobs (FreeArray)
  partmap<Address,TrackedSet> trackbase;		///< Partition map of tracked register sets
  void encodeContext(Encoder &encoder,const Address &addr,const uintm *vec) const;
  void decodeContext(Decoder &decoder,const Address &addr1,const Address &addr2);
  virtual ContextBitRange &getVariable(const string &nm);
  virtual const ContextBitRange &getVariable(const string &nm) const;
  virtual void getRegionForSet(vector<uintm *> &res,const Address &addr1,
			       const Address &addr2,int4 num,uintm mask);
  virtual void getRegionToChangePoint(vector<uintm *> &res,const Address &addr,int4 num,uintm mask);
  virtual uintm *getDefaultValue(void) { return database.defaultValue().array; }
  virtual const uintm *getDefaultValue(void) const { return database.defaultValue().array; }
public:
  ContextInternal(void) { size = 0; }
  virtual ~ContextInternal(void) {}
  virtual int4 getContextSize(void) const { return size; }
  virtual void registerVariable(const string &nm,int4 sbit,int4 ebit);

  virtual const uintm *getContext(const Address &addr) const { return database.getValue(addr).array; }
  virtual const uintm *getContext(const Address &addr,uintb &first,uintb &last) const;

  virtual TrackedSet &getTrackedDefault(void) { return trackbase.defaultValue(); }
  virtual const TrackedSet &getTrackedSet(const Address &addr) const { return trackbase.getValue(addr); }
  virtual TrackedSet &createSet(const Address &addr1,const Address &addr2);

  virtual void encode(Encoder &encoder) const;
  virtual void decode(Decoder &decoder);
  virtual void decodeFromSpec(Decoder &decoder);
};

/// \brief A helper class for caching the active context blob to minimize database lookups
///
/// This merely caches the last retrieved context blob ("array of words") and the range of
/// addresses over which the blob is valid.  It encapsulates the ContextDatabase itself and
/// exposes a minimal interface (getContext() and setContext()).
class ContextCache {
  ContextDatabase *database;		///< The encapsulated context database
  bool allowset;			///< If set to \b false, and setContext() call is dropped
  mutable AddrSpace *curspace;		///< Address space of the current valid range
  mutable uintb first;			///< Starting offset of the current valid range
  mutable uintb last;			///< Ending offset of the current valid range
  mutable const uintm *context;		///< The current cached context blob
public:
  ContextCache(ContextDatabase *db);	///< Construct given a context database
  ContextDatabase *getDatabase(void) const { return database; }		///< Retrieve the encapsulated database object
  void allowSet(bool val) { allowset = val; }		///< Toggle whether setContext() calls are ignored
  void getContext(const Address &addr,uintm *buf) const;	///< Retrieve the context blob for the given address
  void setContext(const Address &addr,int4 num,uintm mask,uintm value);
  void setContext(const Address &addr1,const Address &addr2,int4 num,uintm mask,uintm value);
};

} // End namespace ghidra
#endif

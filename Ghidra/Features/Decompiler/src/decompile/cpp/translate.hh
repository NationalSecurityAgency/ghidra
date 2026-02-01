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
/// \file translate.hh
/// \brief Classes for disassembly and pcode generation
///
/// Classes for keeping track of spaces and registers (for a single architecture).

#ifndef __TRANSLATE_HH__
#define __TRANSLATE_HH__

#include "pcoderaw.hh"
#include "float.hh"

namespace ghidra {

extern AttributeId ATTRIB_CODE;		///< Marshaling attribute "code"
extern AttributeId ATTRIB_CONTAIN;	///< Marshaling attribute "contain"
extern AttributeId ATTRIB_DEFAULTSPACE;	///< Marshaling attribute "defaultspace"
extern AttributeId ATTRIB_UNIQBASE;	///< Marshaling attribute "uniqbase"

extern ElementId ELEM_OP;		///< Marshaling element \<op>
extern ElementId ELEM_SLEIGH;		///< Marshaling element \<sleigh>
extern ElementId ELEM_SPACE;		///< Marshaling element \<space>
extern ElementId ELEM_SPACEID;		///< Marshaling element \<spaceid>
extern ElementId ELEM_SPACES;		///< Marshaling element \<spaces>
extern ElementId ELEM_SPACE_BASE;	///< Marshaling element \<space_base>
extern ElementId ELEM_SPACE_OTHER;	///< Marshaling element \<space_other>
extern ElementId ELEM_SPACE_OVERLAY;	///< Marshaling element \<space_overlay>
extern ElementId ELEM_SPACE_UNIQUE;	///< Marshaling element \<space_unique>
extern ElementId ELEM_TRUNCATE_SPACE;	///< Marshaling element \<truncate_space>

// Some errors specific to the translation unit

/// \brief Exception for encountering unimplemented pcode
///
/// This error is thrown when a particular machine instruction
/// cannot be translated into pcode. This particular error
/// means that the particular instruction being decoded was valid,
/// but the system doesn't know how to represent it in pcode.
struct UnimplError : public LowlevelError {
  int4 instruction_length;	///< Number of bytes in the unimplemented instruction
  /// \brief Constructor
  ///
  /// \param s is a more verbose description of the error
  /// \param l is the length (in bytes) of the unimplemented instruction
  UnimplError(const string &s,int4 l) : LowlevelError(s) { instruction_length = l; }
};

/// \brief Exception for bad instruction data
///
/// This error is thrown when the system cannot decode data
/// for a particular instruction.  This usually means that the
/// data is not really a machine instruction, but may indicate
/// that the system is unaware of the particular instruction.
struct BadDataError : public LowlevelError {
  /// \brief Constructor
  ///
  /// \param s is a more verbose description of the error
  BadDataError(const string &s) : LowlevelError(s) {}
};

class Translate;

/// \brief Object for describing how a space should be truncated
///
/// This can turn up in various XML configuration files and essentially acts
/// as a command to override the size of an address space as defined by the architecture
class TruncationTag {
  string spaceName;	///< Name of space to be truncated
  uint4 size;		///< Size truncated addresses into the space
public:
  void decode(Decoder &decoder);				///< Restore \b this from a stream
  const string &getName(void) const { return spaceName; }	///< Get name of address space being truncated
  uint4 getSize(void) const { return size; }			///< Size (of pointers) for new truncated space
};

/// \brief Abstract class for emitting pcode to an application
///
/// Translation engines pass back the generated pcode for an
/// instruction to the application using this class.
class PcodeEmit {
public:
  virtual ~PcodeEmit(void) {}	///< Virtual destructor

  /// \brief The main pcode emit method.
  ///
  /// A single pcode instruction is returned to the application
  /// via this method.  Particular applications override it
  /// to tailor how the operations are used.
  /// \param addr is the Address of the machine instruction
  /// \param opc is the opcode of the particular pcode instruction
  /// \param outvar if not \e null is a pointer to data about the
  ///               output varnode
  /// \param vars is a pointer to an array of VarnodeData for each
  ///             input varnode
  /// \param isize is the number of input varnodes
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize)=0;

  /// Emit pcode directly from an \<op> element
  void decodeOp(const Address &addr,Decoder &decoder);
};

/// \brief Abstract class for emitting disassembly to an application
///
/// Translation engines pass back the disassembly character data
/// for decoded machine instructions to an application using this class.
class AssemblyEmit {
public:
  virtual ~AssemblyEmit(void) {} ///< Virtual destructor

  /// \brief The main disassembly emitting method.
  ///
  /// The disassembly strings for a single machine instruction
  /// are passed back to an application through this method.
  /// Particular applications can tailor the use of the disassembly
  /// by overriding this method.
  /// \param addr is the Address of the machine instruction
  /// \param mnem is the decoded instruction mnemonic
  /// \param body is the decode body (or operands) of the instruction
  virtual void dump(const Address &addr,const string &mnem,const string &body)=0;
};

/// \brief Abstract class for converting native constants to addresses
///
/// This class is used if there is a special calculation to get from a constant embedded
/// in the code being analyzed to the actual Address being referred to.  This is used especially
/// in the case of a segmented architecture, where "near" pointers must be extended to a full address
/// with implied segment information.
class AddressResolver {
public:
  virtual ~AddressResolver(void) {} ///> Virtual destructor

  /// \brief The main resolver method.
  ///
  /// Given a native constant in a specific context, resolve what address is being referred to.
  /// The constant can be a partially encoded pointer, in which case the full pointer encoding
  /// is recovered as well as the address.  Whether or not a pointer is partially encoded or not
  /// is determined by the \e sz parameter, indicating the number of bytes in the pointer. A value
  /// of -1 here indicates that the pointer is known to be a full encoding.
  /// \param val is constant to be resolved to an address
  /// \param sz is the size of \e val in context (or -1).
  /// \param point is the address at which this constant is being used
  /// \param fullEncoding is used to hold the full pointer encoding if \b val is a partial encoding
  /// \return the resolved Address
  virtual Address resolve(uintb val,int4 sz,const Address &point,uintb &fullEncoding)=0;
};

/// \brief A virtual space \e stack space
///
/// In a lot of analysis situations it is convenient to extend
/// the notion of an address space to mean bytes that are indexed
/// relative to some base register.  The canonical example of this
/// is the \b stack space, which models the concept of local
/// variables stored on the stack.  An address of (\b stack, 8)
/// might model the address of a function parameter on the stack
/// for instance, and (\b stack, 0xfffffff4) might be the address
/// of a local variable.  A space like this is inherently \e virtual
/// and contained within whatever space is being indexed into.
class SpacebaseSpace : public AddrSpace {
  friend class AddrSpaceManager;
  AddrSpace *contain;		///< Containing space
  bool hasbaseregister;		///< true if a base register has been attached
  bool isNegativeStack;		///< true if stack grows in negative direction
  VarnodeData baseloc;		///< location data of the base register
  VarnodeData baseOrig;		///< Original base register before any truncation
  void setBaseRegister(const VarnodeData &data,int4 origSize,bool stackGrowth); ///< Set the base register at time space is created
public:
  SpacebaseSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind,int4 sz,AddrSpace *base,int4 dl,bool isFormal);
  SpacebaseSpace(AddrSpaceManager *m,const Translate *t); ///< For use with decode
  virtual int4 numSpacebase(void) const;
  virtual const VarnodeData &getSpacebase(int4 i) const;
  virtual const VarnodeData &getSpacebaseFull(int4 i) const;
  virtual bool stackGrowsNegative(void) const { return isNegativeStack; }
  virtual AddrSpace *getContain(void) const { return contain; } ///< Return containing space
  virtual void decode(Decoder &decoder);
};

/// \brief A record describing how logical values are split
/// 
/// The decompiler can describe a logical value that is stored split across multiple
/// physical memory locations.  This record describes such a split. The pieces must be listed
/// from \e most \e significant to \e least \e significant.
class JoinRecord {
  friend class AddrSpaceManager;
  vector<VarnodeData> pieces;	///< All the physical pieces of the symbol, most significant to least
  VarnodeData unified; ///< Special entry representing entire symbol in one chunk
public:
  int4 numPieces(void) const { return pieces.size(); }	///< Get number of pieces in this record
  bool isFloatExtension(void) const { return (pieces.size() == 1); }	///< Does this record extend a float varnode
  const VarnodeData &getPiece(int4 i) const { return pieces[i]; }	///< Get the i-th piece
  const VarnodeData &getUnified(void) const { return unified; }		///< Get the Varnode whole
  Address getEquivalentAddress(uintb offset,int4 &pos) const;	///< Given offset in \e join space, get equivalent address of piece
  bool operator<(const JoinRecord &op2) const; ///< Compare records lexigraphically by pieces
  static void mergeSequence(vector<VarnodeData> &seq,const Translate *trans);	///< Merge any contiguous ranges in a sequence
};

/// \brief Comparator for JoinRecord objects
struct JoinRecordCompare {
  bool operator()(const JoinRecord *a,const JoinRecord *b) const {
    return *a < *b; }		///< Compare to JoinRecords using their built-in comparison
};

/// \brief A manager for different address spaces
///
/// Allow creation, lookup by name, lookup by shortcut, lookup by name, and iteration
/// over address spaces
class AddrSpaceManager {
  vector<AddrSpace *> baselist; ///< Every space we know about for this architecture
  vector<AddressResolver *> resolvelist; ///< Special constant resolvers
  map<string,AddrSpace *> name2Space;	///< Map from name -> space
  map<int4,AddrSpace *> shortcut2Space;	///< Map from shortcut -> space
  AddrSpace *constantspace;	///< Quick reference to constant space
  AddrSpace *defaultcodespace;	///< Default space where code lives, generally main RAM
  AddrSpace *defaultdataspace;	///< Default space where data lives
  AddrSpace *iopspace;		///< Space for internal pcode op pointers
  AddrSpace *fspecspace;	///< Space for internal callspec pointers
  AddrSpace *joinspace;		///< Space for unifying split variables
  AddrSpace *stackspace;	///< Stack space associated with processor
  AddrSpace *uniqspace;		///< Temporary space associated with processor
  uintb joinallocate;		///< Next offset to be allocated in join space
  set<JoinRecord *,JoinRecordCompare> splitset;	///< Different splits that have been defined in join space
  vector<JoinRecord *> splitlist; ///< JoinRecords indexed by join address
protected:
  AddrSpace *decodeSpace(Decoder &decoder,const Translate *trans); ///< Add a space to the model based an on XML tag
  void decodeSpaces(Decoder &decoder,const Translate *trans); ///< Restore address spaces in the model from a stream
  void setDefaultCodeSpace(int4 index); ///< Set the default address space (for code)
  void setDefaultDataSpace(int4 index);	///< Set the default address space for data
  void setReverseJustified(AddrSpace *spc); ///< Set reverse justified property on this space
  void assignShortcut(AddrSpace *spc);	///< Select a shortcut character for a new space
  void markNearPointers(AddrSpace *spc,int4 size);	///< Mark that given space can be accessed with near pointers
  void insertSpace(AddrSpace *spc); ///< Add a new address space to the model
  void copySpaces(const AddrSpaceManager *op2);	///< Copy spaces from another manager
  void addSpacebasePointer(SpacebaseSpace *basespace,const VarnodeData &ptrdata,int4 truncSize,bool stackGrowth); ///< Set the base register of a spacebase space
  void insertResolver(AddrSpace *spc,AddressResolver *rsolv); ///< Override the base resolver for a space
  void setInferPtrBounds(const Range &range);		///< Set the range of addresses that can be inferred as pointers
  JoinRecord *findJoinInternal(uintb offset) const; ///< Find JoinRecord for \e offset in the join space
public:
  AddrSpaceManager(void);	///< Construct an empty address space manager
  virtual ~AddrSpaceManager(void); ///< Destroy the manager
  int4 getDefaultSize(void) const; ///< Get size of addresses for the default space
  AddrSpace *getSpaceByName(const string &nm) const; ///< Get address space by name
  AddrSpace *getSpaceByShortcut(char sc) const;	///< Get address space from its shortcut
  AddrSpace *getIopSpace(void) const; ///< Get the internal pcode op space
  AddrSpace *getFspecSpace(void) const; ///< Get the internal callspec space
  AddrSpace *getJoinSpace(void) const; ///< Get the joining space
  AddrSpace *getStackSpace(void) const; ///< Get the stack space for this processor
  AddrSpace *getUniqueSpace(void) const; ///< Get the temporary register space for this processor
  AddrSpace *getDefaultCodeSpace(void) const; ///< Get the default address space of this processor
  AddrSpace *getDefaultDataSpace(void) const; ///< Get the default address space where data is stored
  AddrSpace *getConstantSpace(void) const; ///< Get the constant space
  Address getConstant(uintb val) const; ///< Get a constant encoded as an Address
  Address createConstFromSpace(AddrSpace *spc) const; ///< Create a constant address encoding an address space
  Address resolveConstant(AddrSpace *spc,uintb val,int4 sz,const Address &point,uintb &fullEncoding) const;
  int4 numSpaces(void) const; ///< Get the number of address spaces for this processor
  AddrSpace *getSpace(int4 i) const; ///< Get an address space via its index
  AddrSpace *getNextSpaceInOrder(AddrSpace *spc) const; ///< Get the next \e contiguous address space
  JoinRecord *findAddJoin(const vector<VarnodeData> &pieces,uint4 logicalsize); ///< Get (or create) JoinRecord for \e pieces
  JoinRecord *findJoin(uintb offset) const; ///< Find JoinRecord for \e offset in the join space
  void setDeadcodeDelay(AddrSpace *spc,int4 delaydelta); ///< Set the deadcodedelay for a specific space
  void truncateSpace(const TruncationTag &tag);	///< Mark a space as truncated from its original size

  /// \brief Build a logically lower precision storage location for a bigger floating point register
  Address constructFloatExtensionAddress(const Address &realaddr,int4 realsize,int4 logicalsize);

  /// \brief Build a logical whole from register pairs
  Address constructJoinAddress(const Translate *translate,const Address &hiaddr,int4 hisz,const Address &loaddr,int4 losz);

  /// \brief Make sure a possibly offset \e join address has a proper JoinRecord
  void renormalizeJoinAddress(Address &addr,int4 size);

  /// \brief Parse a string with just an \e address \e space name and a hex offset
  Address parseAddressSimple(const string &val);
};

/// \brief The interface to a translation engine for a processor.
///
/// This interface performs translations of instruction data
/// for a particular processor.  It has two main functions
///     - Disassemble single machine instructions
///     - %Translate single machine instructions into \e pcode.
///
/// It is also the repository for information about the exact
/// configuration of the reverse engineering model associated
/// with the processor. In particular, it knows about all the
/// address spaces, registers, and spacebases for the processor.
class Translate : public AddrSpaceManager {
public:
  /// Tagged addresses in the \e unique address space
  enum UniqueLayout {
    RUNTIME_BOOLEAN_INVERT=0,		///< Location of the runtime temporary for boolean inversion
    RUNTIME_RETURN_LOCATION=0x80,	///< Location of the runtime temporary storing the return value
    RUNTIME_BITRANGE_EA=0x100,		///< Location of the runtime temporary for storing an effective address
    INJECT=0x200,			///< Range of temporaries for use in compiling p-code snippets
    ANALYSIS=0x10000000			///< Range of temporaries for use during decompiler analysis
  };
private:
  bool target_isbigendian;	///< \b true if the general endianness of the process is big endian
  uint4 unique_base;		///< Starting offset into unique space
protected:
  int4 alignment;      ///< Byte modulo on which instructions are aligned
  vector<FloatFormat> floatformats; ///< Floating point formats utilized by the processor

  void setBigEndian(bool val);	///< Set general endianness to \b big if val is \b true
  void setUniqueBase(uint4 val); ///< Set the base offset for new temporary registers
public:
  Translate(void); 		///< Constructor for the translator
  void setDefaultFloatFormats(void); ///< If no explicit float formats, set up default formats
  bool isBigEndian(void) const; ///< Is the processor big endian?
  const FloatFormat *getFloatFormat(int4 size) const; ///< Get format for a particular floating point encoding
  int4 getAlignment(void) const; ///< Get the instruction alignment for the processor
  uint4 getUniqueBase(void) const; ///< Get the base offset for new temporary registers
  uint4 getUniqueStart(UniqueLayout layout) const;	///< Get a tagged address within the \e unique space

  /// \brief Initialize the translator given XML configuration documents
  ///
  /// A translator gets initialized once, possibly using XML documents
  /// to configure it.
  /// \param store is a set of configuration documents
  virtual void initialize(DocumentStorage &store)=0;

  /// \brief Add a new context variable to the model for this processor
  ///
  /// Add the name of a context register used by the processor and
  /// how that register is packed into the context state. This
  /// information is used by a ContextDatabase to associate names
  /// with context information and to pack context into a single
  /// state variable for the translation engine.
  /// \param name is the name of the new context variable
  /// \param sbit is the first bit of the variable in the packed state
  /// \param ebit is the last bit of the variable in the packed state
  virtual void registerContext(const string &name,int4 sbit,int4 ebit) {}

  /// \brief Set the default value for a particular context variable
  ///
  /// Set the value to be returned for a context variable when
  /// there are no explicit address ranges specifying a value
  /// for the variable.
  /// \param name is the name of the context variable
  /// \param val is the value to be considered default
  virtual void setContextDefault(const string &name,uintm val) {}

  /// \brief Toggle whether disassembly is allowed to affect context
  ///
  /// By default the disassembly/pcode translation engine can change
  /// the global context, thereby affecting later disassembly.  Context
  /// may be getting determined by something other than control flow in,
  /// the disassembly, in which case this function can turn off changes
  /// made by the disassembly
  /// \param val is \b true to allow context changes, \b false prevents changes
  virtual void allowContextSet(bool val) const {}

  /// \brief Get a register as VarnodeData given its name
  ///
  /// Retrieve the location and size of a register given its name
  /// \param nm is the name of the register
  /// \return the VarnodeData for the register
  virtual const VarnodeData &getRegister(const string &nm) const=0;

  /// \brief Get the name of the smallest containing register given a location and size
  ///
  /// Generic references to locations in a \e register space are translated into the
  /// register \e name.  If a containing register isn't found, an empty string is returned.
  /// \param base is the address space containing the location
  /// \param off is the offset of the location
  /// \param size is the size of the location
  /// \return the name of the register, or an empty string
  virtual string getRegisterName(AddrSpace *base,uintb off,int4 size) const=0;

  /// \brief Get the name of a register with an exact location and size
  ///
  /// If a register exists with the given location and size, return the name of the register.
  /// Otherwise return the empty string.
  /// \param base is the address space containing the location
  /// \param off is the offset of the location
  /// \param size is the size of the location
  /// \return the name of the register, or an empty string
  virtual string getExactRegisterName(AddrSpace *base,uintb off,int4 size) const=0;

  /// \brief Get a list of all register names and the corresponding location
  ///
  /// Most processors have a list of named registers and possibly other memory locations
  /// that are specific to it.  This function populates a map from the location information
  /// to the name, for every named location known by the translator
  /// \param reglist is the map which will be populated by the call
  virtual void getAllRegisters(map<VarnodeData,string> &reglist) const=0;

  /// \brief Get a list of all \e user-defined pcode ops
  ///
  /// The pcode model allows processors to define new pcode
  /// instructions that are specific to that processor. These
  /// \e user-defined instructions are all identified by a name
  /// and an index.  This method returns a list of these ops
  /// in index order.
  /// \param res is the resulting vector of user op names
  virtual void getUserOpNames(vector<string> &res) const=0;

  /// \brief Get the length of a machine instruction
  ///
  /// This method decodes an instruction at a specific address
  /// just enough to find the number of bytes it uses within the
  /// instruction stream.
  /// \param baseaddr is the Address of the instruction
  /// \return the number of bytes in the instruction
  virtual int4 instructionLength(const Address &baseaddr) const=0;

  /// \brief Transform a single machine instruction into pcode
  ///
  /// This is the main interface to the pcode translation engine.
  /// The \e dump method in the \e emit object is invoked exactly
  /// once for each pcode operation in the translation for the
  /// machine instruction at the given address.
  /// This routine can throw either
  ///     - UnimplError or
  ///     - BadDataError
  ///
  /// \param emit is the tailored pcode emitting object
  /// \param baseaddr is the Address of the machine instruction
  /// \return the number of bytes in the machine instruction
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const=0;

  /// \brief Disassemble a single machine instruction
  ///
  /// This is the main interface to the disassembler for the
  /// processor.  It disassembles a single instruction and
  /// returns the result to the application via the \e dump
  /// method in the \e emit object.
  /// \param emit is the disassembly emitting object
  /// \param baseaddr is the address of the machine instruction to disassemble
  virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const=0;
};

/// Return the size of addresses for the processor's official
/// default space. This space is usually the main RAM databus.
/// \return the size of an address in bytes
inline int4 AddrSpaceManager::getDefaultSize(void) const {
  return defaultcodespace->getAddrSize();
}

/// There is a special address space reserved for encoding pointers
/// to pcode operations as addresses.  This allows a direct pointer
/// to be \e hidden within an operation, when manipulating pcode
/// internally. (See IopSpace)
/// \return a pointer to the address space
inline AddrSpace *AddrSpaceManager::getIopSpace(void) const {
  return iopspace;
}

/// There is a special address space reserved for encoding pointers
/// to the FuncCallSpecs object as addresses. This allows direct
/// pointers to be \e hidden within an operation, when manipulating
/// pcode internally. (See FspecSpace)
/// \return a pointer to the address space
inline AddrSpace *AddrSpaceManager::getFspecSpace(void) const {
  return fspecspace;
}

/// There is a special address space reserved for providing a 
/// logical contiguous memory location for variables that are
/// really split between two physical locations.  This allows the
/// the decompiler to work with the logical value. (See JoinSpace)
/// \return a pointer to the address space
inline AddrSpace *AddrSpaceManager::getJoinSpace(void) const {
  return joinspace;
}

/// Most processors have registers and instructions that are
/// reserved for implementing a stack. In the pcode translation,
/// these are translated into locations and operations on a
/// dedicated \b stack address space. (See SpacebaseSpace)
/// \return a pointer to the \b stack space
inline AddrSpace *AddrSpaceManager::getStackSpace(void) const {
  return stackspace;
}

/// Both the pcode translation process and the simplification
/// process need access to a pool of temporary registers that
/// can be used for moving data around without affecting the
/// address spaces used to formally model the processor's RAM
/// and registers.  These temporary locations are all allocated
/// from a dedicated address space, referred to as the \b unique
/// space. (See UniqueSpace)
/// \return a pointer to the \b unique space
inline AddrSpace *AddrSpaceManager::getUniqueSpace(void) const {
  return uniqspace;
}

/// Most processors have a main address bus, on which the bulk
/// of the processor's RAM is mapped. This matches SLEIGH's notion
/// of the \e default space. For Harvard architectures, this is the
/// space where code exists (as opposed to data).
/// \return a pointer to the \e default code space
inline AddrSpace *AddrSpaceManager::getDefaultCodeSpace(void) const {
  return defaultcodespace;
}

/// Return the default address space for holding data. For most processors, this
/// is just the main RAM space and is the same as the default \e code space.
/// For Harvard architectures, this is the space where data is stored
/// (as opposed to code).
/// \return a pointer to the \e default data space
inline AddrSpace *AddrSpaceManager::getDefaultDataSpace(void) const {
  return defaultdataspace;
}

/// Pcode represents constant values within an operation as
/// offsets within a special \e constant address space. 
/// (See ConstantSpace)
/// \return a pointer to the \b constant space
inline AddrSpace *AddrSpaceManager::getConstantSpace(void) const {
  return constantspace;
}

/// This routine encodes a specific value as a \e constant
/// address. I.e. the address space of the resulting Address
/// will be the \b constant space, and the offset will be the
/// value.
/// \param val is the constant value to encode
/// \return the \e constant address
inline Address AddrSpaceManager::getConstant(uintb val) const {
  return Address(constantspace,val);
}

/// This routine is used to encode a pointer to an address space
/// as a \e constant Address, for use in \b LOAD and \b STORE
/// operations.  This is used internally and is slightly more
/// efficient than storing the formal index of the space
/// param spc is the space pointer to be encoded
/// \return the encoded Address
inline Address AddrSpaceManager::createConstFromSpace(AddrSpace *spc) const {
  return Address(constantspace,(uintb)(uintp)spc);
}

/// This returns the total number of address spaces used by the
/// processor, including all special spaces, like the \b constant
/// space and the \b iop space. 
/// \return the number of spaces
inline int4 AddrSpaceManager::numSpaces(void) const {
  return baselist.size();
}

/// This retrieves a specific address space via its formal index.
/// All spaces have an index, and in conjunction with the numSpaces
/// method, this method can be used to iterate over all spaces.
/// \param i is the index of the address space
/// \return a pointer to the desired space
inline AddrSpace *AddrSpaceManager::getSpace(int4 i) const {
  return baselist[i];
}

/// Although endianness is usually specified on the space, most languages set an endianness
/// across the entire processor.  This routine sets the endianness to \b big if the -val-
/// is passed in as \b true. Otherwise, the endianness is set to \b small.
/// \param val is \b true if the endianness should be set to \b big
inline void Translate::setBigEndian(bool val) {
  target_isbigendian = val; 
}

/// The \e unique address space, for allocating temporary registers,
/// is used for both registers needed by the pcode translation
/// engine and, later, by the simplification engine.  This routine
/// sets the boundary of the portion of the space allocated
/// for the pcode engine, and sets the base offset where registers
/// created by the simplification process can start being allocated.
/// \param val is the boundary offset
inline void Translate::setUniqueBase(uint4 val) {
  if (val>unique_base) unique_base = val;
}

/// Processors can usually be described as using a big endian
/// encoding or a little endian encoding. This routine returns
/// \b true if the processor globally uses big endian encoding.
/// \return \b true if big endian
inline bool Translate::isBigEndian(void) const {
  return target_isbigendian;
}

/// If machine instructions need to have a specific alignment
/// for this processor, this routine returns it. I.e. a return
/// value of 4, means that the address of all instructions
/// must be a multiple of 4. If there is no
/// specific alignment requirement, this routine returns 1.
/// \return the instruction alignment
inline int4 Translate::getAlignment(void) const {
  return alignment;
}

/// Return the first offset within the \e unique space after the range statically reserved by Translate.
/// This is generally the starting offset where dynamic temporary registers can start to be allocated.
/// \return the first allocatable offset
inline uint4 Translate::getUniqueBase(void) const {
  return unique_base;
}

/// Regions of the \e unique space are reserved for specific uses. We select the start of a specific
/// region based on the given tag.
/// \param layout is the given tag
/// \return the absolute offset into the \e unique space
inline uint4 Translate::getUniqueStart(UniqueLayout layout) const {
  return (layout != ANALYSIS) ? layout + unique_base : layout;
}

} // End namespace ghidra
#endif

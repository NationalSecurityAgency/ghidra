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
/// \file varnode.hh
/// \brief The Varnode and VarnodeBank classes
#ifndef __CPUI_VARNODE__
#define __CPUI_VARNODE__

#include "pcoderaw.hh"
#include "cover.hh"

class HighVariable;

class Varnode;		// Forward declaration
class VarnodeBank;
class Merge;
class Funcdata;
class SymbolEntry;
class ValueSet;

/// \brief Compare two Varnode pointers by location then definition
struct VarnodeCompareLocDef {
  bool operator()(const Varnode *a,const Varnode *b) const;	///< Functional comparison operator
};

/// \brief Compare two Varnode pointers by definition then location
struct VarnodeCompareDefLoc {
  bool operator()(const Varnode *a,const Varnode *b) const;	///< Functional comparison operator
};

/// A set of Varnodes sorted by location (then by definition)
typedef set<Varnode *,VarnodeCompareLocDef> VarnodeLocSet;

/// A set of Varnodes sorted by definition (then location)
typedef set<Varnode *,VarnodeCompareDefLoc> VarnodeDefSet;

/// \brief A low-level variable or contiguous set of bytes described by an Address and a size
///
/// A Varnode is the fundemental \e variable in the p-code language model.  A Varnode
/// represents anything that holds data, including registers, stack locations,
/// global RAM locations, and constants.  It is described most simply as a storage
/// location for some number of bytes, and is identified by
///    - an Address  (an AddrSpace and an offset into that space) and
///    - a size in bytes
///
/// In its raw form, the Varnode is referred to as \b free, and this pair uniquely identifies
/// the Varnode, as determined by its comparison operators.  In terms of the
/// Static Single Assignment (SSA) form for the decompiler analysis, the Varnode class also
/// represents a node in the tree. In this case the Varnode is not free, and
/// each individual write to a storage location, as per SSA form, creates a unique Varnode, which
/// is represented by a separate instance, so there may be multiple Varnode instances
/// with the same Address and size. 
class Varnode {
public:
  /// There are a large number of boolean attributes that can be placed on a Varnode.
  /// Some are calculated and maintained by the friend classes Funcdata and VarnodeBank, 
  /// and others can be set and cleared publicly by separate subsystems.
  enum varnode_flags {
    mark = 0x01,	///< Prevents infinite loops
    constant = 0x02,	///< The varnode is constant
    annotation = 0x04,	///< This varnode is an annotation and has no dataflow
    input = 0x08,		///< This varnode has no ancestor
    written = 0x10,	///< This varnode has a defining op (def is nonzero)
    insert = 0x20,	///< This varnode has been inserted in a tree
				///< This means the varnode is the output of an op \e or
				///< The output is a constant \e or the output is an input
    implied = 0x40,	///< This varnode is a temporary variable
    explict = 0x80,	///< This varnode \e CANNOT be a temporary variable
    
    typelock = 0x100,	///< The Dataype of the Varnode is locked
    namelock = 0x200,	///< The Name of the Varnode is locked
    nolocalalias = 0x400,	///< There are no aliases pointing to this varnode
    volatil = 0x800,	///< This varnode's value is volatile
    
    externref = 0x1000,	///< Varnode address is specially mapped by the loader
    readonly = 0x2000,	///< Varnode is stored at a readonly location
    persist = 0x4000,	///< Persists after (and before) function
    addrtied = 0x8000,	///< High-level variable is tied to address
    unaffected = 0x10000,	///< Input which is unaffected by the function
    spacebase = 0x20000,	///< This is a base register for an address space
    indirectonly = 0x40000, ///< If all uses of illegalinput varnode are inputs to INDIRECT
    directwrite = 0x80000, ///< (could be) Directly affected by a valid input
    addrforce = 0x100000, ///< Varnode is used to force variable into an address
    
    mapped = 0x200000, ///< Varnode has a database entry associated with it
    indirect_creation = 0x400000, ///< The value in this Varnode is created indirectly
    return_address = 0x800000, ///< Is the varnode storage for a return address
    coverdirty = 0x1000000, ///< Cover is not upto date
    precislo = 0x2000000,	///< Is this Varnode the low part of a double precision value
    precishi = 0x4000000,	///< Is this Varnode the high part of a double precision value
    indirectstorage = 0x8000000, ///< Is this Varnode storing a pointer to the actual symbol
    hiddenretparm = 0x10000000,	 ///< Does this varnode point to the return value storage location
    incidental_copy = 0x20000000, ///< Do copies of this varnode happen as a side-effect
    autolive_hold = 0x40000000	///< Temporarily block dead-code removal of \b this
  };
  /// Additional boolean properties on a Varnode
  enum addl_flags {
    activeheritage = 0x01,	///< The varnode is actively being heritaged
    writemask = 0x02,           ///< Should not be considered a write in heritage calculation
    vacconsume = 0x04,		///< Vacuous consume
    lisconsume = 0x08,		///< In consume worklist
    ptrcheck = 0x10,	        ///< The Varnode value is \e NOT a pointer
    ptrflow = 0x20,             ///< If this varnode flows to or from a pointer
    unsignedprint = 0x40,	///< Constant that must be explicitly printed as unsigned
    stack_store = 0x80,		///< Created by an explicit STORE
    locked_input = 0x100,	///< Input that exists even if its unused
    spacebase_placeholder = 0x200 ///< This varnode is inserted artificially to track a register
				///< value at a specific point in the code
  };
private:
  mutable uint4 flags;		///< The collection of boolean attributes for this Varnode
  int4 size;			///< Size of the Varnode in bytes
  uint4 create_index;		///< A unique one-up index assigned to Varnode at its creation
  int2 mergegroup;		///< Which group of forced merges does this Varnode belong to
  uint2 addlflags;		///< Additional flags
  Address loc;			///< Storage location (or constant value) of the Varnode

				// Heritage fields
  PcodeOp *def;			///< The defining operation of this Varnode
  HighVariable *high;		///< High-level variable of which this is an instantiation
  SymbolEntry *mapentry;	///< cached SymbolEntry associated with Varnode
  Datatype *type;		///< Datatype associated with this varnode
  VarnodeLocSet::iterator lociter;	///< Iterator into VarnodeBank sorted by location
  VarnodeDefSet::iterator defiter;	///< Iterator into VarnodeBank sorted by definition
  list<PcodeOp *> descend;		///< List of every op using this varnode as input
  mutable Cover *cover;		///< Addresses covered by the def->use of this Varnode
  mutable union {
    Datatype *dataType;		///< Temporary data-type associated with \b this for use in type propagate algorithm
    ValueSet *valueSet;		///< Value set associated with \b this when performing Value Set Analysis
  } temp;			///< Temporary storage for analysis algorithms
  uintb consumed;		///< What parts of this varnode are used
  uintb nzm;			///< Which bits do we know are zero
  friend class VarnodeBank;
  friend class Merge;
  friend class Funcdata;
  void updateCover(void) const;	///< Internal function for update coverage information
  void calcCover(void) const;	///< Turn on the Cover object for this Varnode
  void clearCover(void) const; ///< Turn off any coverage information
  void setFlags(uint4 fl) const; ///< Internal method for setting boolean attributes
  void clearFlags(uint4 fl) const; ///< Internal method for clearing boolean attributes
  void setUnaffected(void) { setFlags(Varnode::unaffected); } ///< Mark Varnode as \e unaffected
  // These functions should be only private things used by VarnodeBank
  void setInput(void) { setFlags(Varnode::input|Varnode::coverdirty); }	///< Mark Varnode as \e input
  void setDef(PcodeOp *op);	///< Set the defining PcodeOp of this Varnode
  bool setSymbolProperties(SymbolEntry *entry);	///< Set properties from the given Symbol to \b this Varnode
  void setSymbolEntry(SymbolEntry *entry);	///< Attach a Symbol to \b this Varnode
  void setSymbolReference(SymbolEntry *entry,int4 off);	///< Attach a Symbol reference to \b this
  void addDescend(PcodeOp *op);	///< Add a descendant (reading) PcodeOp to this Varnode's list
  void eraseDescend(PcodeOp *op); ///< Erase a descendant (reading) PcodeOp from this Varnode's list
  void destroyDescend(void);	///< Clear all descendant (reading) PcodeOps
public:
  // only to be used by HighVariable
  void setHigh(HighVariable *tv,int2 mg) { high = tv; mergegroup = mg; } ///< Set the HighVariable owning this Varnode

  const Address &getAddr(void) const { return (const Address &) loc; } ///< Get the storage Address
  AddrSpace *getSpace(void) const { return loc.getSpace(); } ///< Get the AddrSpace storing this Varnode
  uintb getOffset(void) const { return loc.getOffset(); } ///< Get the offset (within its AddrSpace) where this is stored
  int4 getSize(void) const { return size; } ///< Get the number of bytes this Varnode stores
  int2 getMergeGroup(void) const { return mergegroup; }	///< Get the \e forced \e merge group of this Varnode
  PcodeOp *getDef(void) { return def; }	///< Get the defining PcodeOp of this Varnode
  const PcodeOp *getDef(void) const { return (const PcodeOp *) def; } ///< Get the defining PcodeOp
  HighVariable *getHigh(void) const; ///< Get the high-level variable associated with this Varnode
  SymbolEntry *getSymbolEntry(void) const { return mapentry; } ///< Get symbol and scope information associated with this Varnode
  uint4 getFlags(void) const { return flags; } ///< Get all the boolean attributes
  Datatype *getType(void) const { return type; } ///< Get the Datatype associated with this Varnode
  void setTempType(Datatype *t) const { temp.dataType = t; }	///< Set the temporary Datatype
  Datatype *getTempType(void) const { return temp.dataType; } ///< Get the temporary Datatype (used during type propagation)
  void setValueSet(ValueSet *v) const { temp.valueSet = v; }	///< Set the temporary ValueSet record
  ValueSet *getValueSet(void) const { return temp.valueSet; }	///< Get the temporary ValueSet record
  uint4 getCreateIndex(void) const { return create_index; } ///< Get the creation index
  Cover *getCover(void) const { updateCover(); return cover; } ///< Get Varnode coverage information
  list<PcodeOp *>::const_iterator beginDescend(void) const { return descend.begin(); } ///< Get iterator to list of syntax tree descendants (reads)
  list<PcodeOp *>::const_iterator endDescend(void) const { return descend.end(); } ///< Get the end iterator to list of descendants
  uintb getConsume(void) const { return consumed; } ///< Get mask of consumed bits
  void setConsume(uintb val) { consumed = val; } ///< Set the mask of consumed bits (used by dead-code algorithm)
  bool isConsumeList(void) const { return ((addlflags&Varnode::lisconsume)!=0); } ///< Get marker used by dead-code algorithm
  bool isConsumeVacuous(void) const { return ((addlflags&Varnode::vacconsume)!=0); } ///< Get marker used by dead-code algorithm
  void setConsumeList(void) { addlflags |= Varnode::lisconsume; } ///< Set marker used by dead-code algorithm
  void setConsumeVacuous(void) { addlflags |= Varnode::vacconsume; } ///< Set marker used by dead-code algorithm
  void clearConsumeList(void) { addlflags &= ~Varnode::lisconsume; } ///< Clear marker used by dead-code algorithm
  void clearConsumeVacuous(void) { addlflags &= ~Varnode::vacconsume; } ///< Clear marker used by dead-code algorithm
  PcodeOp *loneDescend(void) const; ///< Return unique reading PcodeOp, or \b null if there are zero or more than 1
  Address getUsePoint(const Funcdata &fd) const; ///< Get Address when this Varnode first comes into scope
  int4 printRawNoMarkup(ostream &s) const; ///< Print a simple identifier for the Varnode
  void printRaw(ostream &s) const; ///< Print a simple identifier plus additional info identifying Varnode with SSA form
  void printCover(ostream &s) const; ///< Print raw coverage info about the Varnode
  void printInfo(ostream &s) const; ///< Print raw attribute info about the Varnode
  Varnode(int4 s,const Address &m,Datatype *dt);	///< Construct a \e free Varnode
  bool operator<(const Varnode &op2) const; ///< Comparison operator on Varnode
  bool operator==(const Varnode &op2) const; ///< Equality operator
  bool operator!=(const Varnode &op2) const { return !operator==(op2); } ///< Inequality operator
  ~Varnode(void);		///< Destructor
  bool intersects(const Varnode &op) const; ///< Return \b true if the storage locations intersect
  bool intersects(const Address &op2loc,int4 op2size) const; ///< Check intersection against an Address range
  int4 contains(const Varnode &op) const; ///< Return info about the containment of \e op in \b this
  int4 characterizeOverlap(const Varnode &op) const; ///< Return 0, 1, or 2 for "no overlap", "partial overlap", "identical storage"
  int4 overlap(const Varnode &op) const;	///< Return relative point of overlap between two Varnodes
  int4 overlap(const Address &op2loc,int4 op2size) const;	///< Return relative point of overlap with Address range
  uintb getNZMask(void) const { return nzm; } ///< Get the mask of bits within \b this that are known to be zero
  int4 termOrder(const Varnode *op) const; ///< Compare two Varnodes based on their term order
  void printRawHeritage(ostream &s,int4 depth) const; ///< Print a simple SSA subtree rooted at \b this
  bool isAnnotation(void) const { return ((flags&Varnode::annotation)!=0); } ///< Is \b this an annotation?
  bool isImplied(void) const { return ((flags&Varnode::implied)!=0); } ///< Is \b this an implied variable?
  bool isExplicit(void) const { return ((flags&Varnode::explict)!=0); }	///< Is \b this an explicitly printed variable?
  bool isConstant(void) const { return ((flags&Varnode::constant)!=0); } ///< Is \b this a constant?
  bool isFree(void) const { return ((flags&(Varnode::written|Varnode::input))==0); } ///< Is \b this free, not in SSA form?
  bool isInput(void) const { return ((flags&Varnode::input)!=0); } ///< Is \b this an SSA input node?
  bool isIllegalInput(void) const { return ((flags&(Varnode::input|Varnode::directwrite))==Varnode::input); } ///< Is \b this an abnormal input to the function?
  bool isIndirectOnly(void) const { return ((flags&Varnode::indirectonly)!=0); } ///< Is \b this read only by INDIRECT operations?
  bool isExternalRef(void) const { return ((flags&Varnode::externref)!=0); } ///< Is \b this storage location mapped by the loader to an external location?
  bool hasActionProperty(void) const { return ((flags&(Varnode::readonly|Varnode::volatil))!=0); } ///< Will this Varnode be replaced dynamically?
  bool isReadOnly(void) const { return ((flags&Varnode::readonly)!=0); } ///< Is \b this a read-only storage location?
  bool isVolatile(void) const { return ((flags&Varnode::volatil)!=0); }	///< Is \b this a volatile storage location?
  bool isPersist(void) const { return ((flags&Varnode::persist)!=0); } ///< Does \b this storage location persist beyond the end of the function?
  bool isDirectWrite(void) const { return ((flags&Varnode::directwrite)!=0); } ///< Is \b this value affected by a legitimate function input

  /// Are all Varnodes at this storage location components of the same high-level variable?
  bool isAddrTied(void) const { return ((flags&(Varnode::addrtied|Varnode::insert))==(Varnode::addrtied|Varnode::insert)); }
  bool isAddrForce(void) const { return ((flags&Varnode::addrforce)!=0); } ///< Is \b this value forced into a particular storage location?
  bool isAutoLive(void) const { return ((flags&(Varnode::addrforce|Varnode::autolive_hold))!=0); } ///< Is \b this varnode exempt from dead-code removal?
  bool isAutoLiveHold(void) const { return ((flags&Varnode::autolive_hold)!=0); }	///< Is there a temporary hold on dead-code removal?
  bool isMapped(void) const { return ((flags&Varnode::mapped)!=0); } ///< Is there or should be formal symbol information associated with \b this?
  bool isUnaffected(void) const { return ((flags&Varnode::unaffected)!=0); } ///< Is \b this a value that is supposed to be preserved across the function?
  bool isSpacebase(void) const { return ((flags&Varnode::spacebase)!=0); } ///< Is this location used to store the base point for a virtual address space?
  bool isReturnAddress(void) const { return ((flags&Varnode::return_address)!=0); } ///< Is this storage for a calls return address?
  bool isPtrCheck(void) const { return ((addlflags&Varnode::ptrcheck)!=0); } ///< Has \b this been checked as a constant pointer to a mapped symbol?
  bool isPtrFlow(void) const { return ((addlflags&Varnode::ptrflow)!=0); } ///< Does this varnode flow to or from a known pointer
  bool isSpacebasePlaceholder(void) const { return ((addlflags&Varnode::spacebase_placeholder)!=0); } ///< Is \b this used specifically to track stackpointer values?
  bool hasNoLocalAlias(void) const { return ((flags&Varnode::nolocalalias)!=0); } ///< Are there (not) any local pointers that might affect \b this?
  bool isMark(void) const { return ((flags&Varnode::mark)!=0); } ///< Has \b this been visited by the current algorithm?
  bool isActiveHeritage(void) const { return ((addlflags&Varnode::activeheritage)!=0); } ///< Is \b this currently being traced by the Heritage algorithm?
  bool isStackStore(void) const { return ((addlflags&Varnode::stack_store)!=0); } ///< Was this originally produced by an explicit STORE
  bool isLockedInput(void) const { return ((addlflags&Varnode::locked_input)!=0); }	///< Is always an input, even if unused

  /// Is \b this just a special placeholder representing INDIRECT creation?
  bool isIndirectZero(void) const { return ((flags&(Varnode::indirect_creation|Varnode::constant))==(Varnode::indirect_creation|Varnode::constant)); }

  /// Is this Varnode \b created indirectly by a CALL operation?
  bool isExtraOut(void) const { return ((flags&(Varnode::indirect_creation|Varnode::addrtied))==Varnode::indirect_creation); }
  bool isPrecisLo(void) const { return ((flags&Varnode::precislo)!=0); } ///< Is \b this the low portion of a double precision value?
  bool isPrecisHi(void) const { return ((flags&Varnode::precishi)!=0); } ///< Is \b this the high portion of a double precision value?
  bool isIncidentalCopy(void) const { return ((flags&Varnode::incidental_copy)!=0); } ///< Does this varnode get copied as a side-effect
  bool isWriteMask(void) const { return ((addlflags&Varnode::writemask)!=0); } ///< Is \b this (not) considered a true write location when calculating SSA form?
  bool isUnsignedPrint(void) const { return ((addlflags&Varnode::unsignedprint)!=0); } ///< Must \b this be printed as unsigned
  bool isWritten(void) const { return ((flags&Varnode::written)!=0); }   ///< Does \b this have a defining write operation?

  /// Does \b this have Cover information?
  bool hasCover(void) const {
    return ((flags&(Varnode::constant|Varnode::annotation|Varnode::insert))==Varnode::insert); }
  bool hasNoDescend(void) const { return descend.empty(); } ///< Return \b true if nothing reads this Varnode

  /// Return \b true if \b this is a constant with value \b val
  bool constantMatch(uintb val) const {
    if (!isConstant()) return false;
    return (loc.getOffset() == val);
  }

  int4 isConstantExtended(uintb &val) const; ///< Is \b this an (extended) constant
  /// Return \b true if this Varnode is linked into the SSA tree
  bool isHeritageKnown(void) const { return ((flags&(Varnode::insert|Varnode::constant|Varnode::annotation))!=0); }
  bool isTypeLock(void) const { return ((flags&Varnode::typelock)!=0); } ///< Does \b this have a locked Datatype?
  bool isNameLock(void) const { return ((flags&Varnode::namelock)!=0); } ///< Does \b this have a locked name?
  void setActiveHeritage(void) { addlflags |= Varnode::activeheritage; } ///< Mark \b this as currently being linked into the SSA tree
  void clearActiveHeritage(void) { addlflags &= ~Varnode::activeheritage; }	///< Mark \b this as not (actively) being linked into the SSA tree
  void setMark(void) const { flags |= Varnode::mark; } ///< Mark this Varnode for breadcrumb algorithms
  void clearMark(void) const { flags &= ~Varnode::mark; } ///< Clear the mark on this Varnode
  void setDirectWrite(void) { flags |= Varnode::directwrite; } ///< Mark \b this as directly affected by a legal input
  void clearDirectWrite(void) { flags &= ~Varnode::directwrite; } ///< Mark \b this as not directly affected by a legal input
  void setAddrForce(void) { setFlags(Varnode::addrforce); } ///< Mark as forcing a value into \b this particular storage location
  void clearAddrForce(void) { clearFlags(Varnode::addrforce); }	///< Clear the forcing attribute
  void setImplied(void) { setFlags(Varnode::implied); }	///< Mark \b this as an \e implied variable in the final C source
  void clearImplied(void) { clearFlags(Varnode::implied); } ///< Clear the \e implied mark on this Varnode
  void setExplicit(void) { setFlags(Varnode::explict); } ///< Mark \b this as an \e explicit variable in the final C source
  void clearExplicit(void) { clearFlags(Varnode::explict); } ///< Clear the \e explicit mark on this Varnode
  void setReturnAddress(void) { flags |= Varnode::return_address; } ///< Mark as storage location for a return address
  void clearReturnAddress(void) { flags &= ~Varnode::return_address; } ///< Clear return address attribute
  void setPtrCheck(void) { addlflags |= Varnode::ptrcheck; } ///< Set \b this as checked for a constant symbol reference
  void clearPtrCheck(void) { addlflags &= ~Varnode::ptrcheck; } ///< Clear the pointer check mark on this Varnode
  void setPtrFlow(void) { addlflags |= Varnode::ptrflow; } ///< Set \b this as flowing to or from pointer
  void clearPtrFlow(void) { addlflags &= ~Varnode::ptrflow; } ///< Indicate that this varnode is not flowing to or from pointer
  void setSpacebasePlaceholder(void) { addlflags |= Varnode::spacebase_placeholder; } ///< Mark \b this as a special Varnode for tracking stackpointer values
  void clearSpacebasePlaceholder(void) { addlflags &= ~Varnode::spacebase_placeholder; } ///< Clear the stackpointer tracking mark
  void setPrecisLo(void) { setFlags(Varnode::precislo); } ///< Mark \b this as the low portion of a double precision value
  void clearPrecisLo(void) { clearFlags(Varnode::precislo); } ///< Clear the mark indicating a double precision portion
  void setPrecisHi(void) { setFlags(Varnode::precishi); } ///< Mark \b this as the high portion of a double precision value
  void clearPrecisHi(void) { clearFlags(Varnode::precishi); } ///< Clear the mark indicating a double precision portion
  void setWriteMask(void) { addlflags |= Varnode::writemask; } ///< Mark \b this as not a true \e write when computing SSA form
  void clearWriteMask(void) { addlflags &= ~Varnode::writemask; } ///< Clear the mark indicating \b this is not a true write
  void setAutoLiveHold(void) { flags |= Varnode::autolive_hold; }	///< Place temporary hold on dead code removal
  void clearAutoLiveHold(void) { flags &= ~Varnode::autolive_hold; }	///< Clear temporary hold on dead code removal
  void setUnsignedPrint(void) { addlflags |= Varnode::unsignedprint; } ///< Force \b this to be printed as unsigned
  bool updateType(Datatype *ct,bool lock,bool override); ///< (Possibly) set the Datatype given various restrictions
  void setStackStore(void) { addlflags |= Varnode::stack_store; } ///< Mark as produced by explicit CPUI_STORE
  void setLockedInput(void) { addlflags |= Varnode::locked_input; }	///< Mark as existing input, even if unused
  void copySymbol(const Varnode *vn); ///< Copy symbol info from \b vn
  void copySymbolIfValid(const Varnode *vn);	///< Copy symbol info from \b vn if constant value matches
  Datatype *getLocalType(void) const; ///< Calculate type of Varnode based on local information
  bool copyShadow(const Varnode *op2) const; ///< Are \b this and \b op2 copied from the same source?
  void saveXml(ostream &s) const; ///< Save a description of \b this as an XML tag
  static bool comparePointers(const Varnode *a,const Varnode *b) { return (*a < *b); }	///< Compare Varnodes as pointers
  static void printRaw(ostream &s,const Varnode *vn);	///< Print raw info about a Varnode to stream
  //  static Varnode *restoreXml(const Element *el,Funcdata &fd,bool coderef);
};

/// \brief A container for Varnode objects from a specific function
///
/// The API allows the creation, deletion, search, and iteration of
/// Varnode objects from one function.  The class maintains two ordering
/// for efficiency:
///    - Sorting based on storage location (\b loc)
///    - Sorting based on point of definition (\b def)
/// The class maintains a \e last \e offset counter for allocation
/// temporary Varnode objects in the \e unique space. Constants are created
/// by passing a constant address to the create() method.
class VarnodeBank {
  AddrSpaceManager *manage;	///< Underlying address space manager
  AddrSpace *uniq_space;	///< Space to allocate unique varnodes from
  uintm uniqbase;		///< Base for unique addresses
  uintm uniqid;			///< Counter for generating unique offsets
  uint4 create_index;		///< Number of varnodes created
  VarnodeLocSet loc_tree;	///< Varnodes sorted by location then def
  VarnodeDefSet def_tree;	///< Varnodes sorted by def then location
  mutable Varnode searchvn;	///< Template varnode for searching trees
  Varnode *xref(Varnode *vn);	///< Insert a Varnode into the sorted lists
public:
  VarnodeBank(AddrSpaceManager *m,AddrSpace *uspace,uintm ubase);	///< Construct the container
  void clear(void);						///< Clear out all Varnodes and reset counters
  ~VarnodeBank(void) { clear(); }				///< Destructor
  int4 numVarnodes(void) const { return loc_tree.size(); }	///< Get number of Varnodes \b this contains
  Varnode *create(int4 s,const Address &m,Datatype *ct);	///< Create a \e free Varnode object
  Varnode *createDef(int4 s,const Address &m,Datatype *ct,PcodeOp *op);	///< Create a Varnode as the output of a PcodeOp
  Varnode *createUnique(int4 s,Datatype *ct);			///< Create a temporary varnode
  Varnode *createDefUnique(int4 s,Datatype *ct,PcodeOp *op);	///< Create a temporary Varnode as output of a PcodeOp
  void destroy(Varnode *vn);					///< Remove a Varnode from the container
  Varnode *setInput(Varnode *vn);				///< Mark a Varnode as an input to the function
  Varnode *setDef(Varnode *vn,PcodeOp *op);			///< Change Varnode to be defined by the given PcodeOp
  void makeFree(Varnode *vn);					///< Convert a Varnode to be \e free
  void replace(Varnode *oldvn,Varnode *newvn);			///< Replace every read of one Varnode with another
  Varnode *find(int4 s,const Address &loc,const Address &pc,uintm uniq=~((uintm)0)) const;	///< Find a Varnode
  Varnode *findInput(int4 s,const Address &loc) const;		///< Find an input Varnode
  Varnode *findCoveredInput(int4 s,const Address &loc) const;	///< Find an input Varnode contained within this range
  Varnode *findCoveringInput(int4 s,const Address &loc) const;	///< Find an input Varnode covering a range
  uint4 getCreateIndex(void) const { return create_index; }	///< Get the next creation index to be assigned
  VarnodeLocSet::const_iterator beginLoc(void) const { return loc_tree.begin(); }	///< Beginning of location list
  VarnodeLocSet::const_iterator endLoc(void) const { return loc_tree.end(); }		///< End of location list
  VarnodeLocSet::const_iterator beginLoc(AddrSpace *spaceid) const;
  VarnodeLocSet::const_iterator endLoc(AddrSpace *spaceid) const;
  VarnodeLocSet::const_iterator beginLoc(const Address &addr) const;
  VarnodeLocSet::const_iterator endLoc(const Address &addr) const;
  VarnodeLocSet::const_iterator beginLoc(int4 s,const Address &addr) const;
  VarnodeLocSet::const_iterator endLoc(int4 s,const Address &addr) const;
  VarnodeLocSet::const_iterator beginLoc(int4 s,const Address &addr,uint4 fl) const;
  VarnodeLocSet::const_iterator endLoc(int4 s,const Address &addr,uint4 fl) const;
  VarnodeLocSet::const_iterator beginLoc(int4 s,const Address &addr,const Address &pc,uintm uniq) const;
  VarnodeLocSet::const_iterator endLoc(int4 s,const Address &addr,const Address &pc,uintm uniq) const;
  VarnodeDefSet::const_iterator beginDef(void) const { return def_tree.begin(); }	///< Beginning of Varnodes sorted by definition
  VarnodeDefSet::const_iterator endDef(void) const { return def_tree.end(); }	///< End of Varnodes sorted by definition
  VarnodeDefSet::const_iterator beginDef(uint4 fl) const;
  VarnodeDefSet::const_iterator endDef(uint4 fl) const;
  VarnodeDefSet::const_iterator beginDef(uint4 fl,const Address &addr) const;
  VarnodeDefSet::const_iterator endDef(uint4 fl,const Address &addr) const;
#ifdef VARBANK_DEBUG
  void verifyIntegrity(void) const;		///< Verify the integrity of the container
#endif
};

/// \brief Node for a forward traversal of a Varnode expression
struct TraverseNode {
  const Varnode *vn;		///< Varnode at the point of traversal
  uint4 flags;			///< Flags associated with the node
  TraverseNode(const Varnode *v,uint4 f) { vn = v; flags = f; }		///< Constructor
};

bool contiguous_test(Varnode *vn1,Varnode *vn2);	///< Test if Varnodes are pieces of a whole
Varnode *findContiguousWhole(Funcdata &data,Varnode *vn1,
				  Varnode *vn2);	///< Retrieve the whole Varnode given pieces
#endif

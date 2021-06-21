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
/// \file fspec.hh
/// \brief Definitions for specifying functions prototypes

#ifndef __CPUI_FSPEC__
#define __CPUI_FSPEC__

#include "op.hh"
#include "rangemap.hh"

class JoinRecord;

/// \brief Exception thrown when a prototype can't be modeled properly
struct ParamUnassignedError : public LowlevelError {
  ParamUnassignedError(const string &s) : LowlevelError(s) {}	///< Constructor
};

/// \brief A contiguous range of memory that can be used to pass parameters
///
/// This range can be used to pass a single parameter (isExclusion() == \b true).  This
/// is intended to model a parameter passed in a register.  The logical value does not
/// have to fill the entire range.  The size in bytes can range from a minimum, getMinSize(),
/// to the whole range, getSize(). Justification and extension of the logical value within
/// the range can be specified.
///
/// Alternately the range can be used as a resource for multiple parameters
/// (isExclusion() == \b false).  In this case, the parameters are allocated sequentially
/// (usually) starting from the front of the range.  The amount of space consumed by each
/// parameter is dictated by an \e alignment setting in bytes.
///
/// A ParamEntry can be associated with a particular class of data-types. Usually:
///   - TYPE_UNKNOWN   for general purpose parameters
///   - TYPE_FLOAT     for dedicated floating-point registers
class ParamEntry {
public:
  enum {
    force_left_justify = 1,	///< Big endian values are left justified within their slot
    reverse_stack = 2,		///< Slots (for \e non-exlusion entries) are allocated in reverse order
    smallsize_zext = 4,		///< Assume values that are below the max \b size are zero extended into this container
    smallsize_sext = 8,		///< Assume values that are below the max \b size are sign extended into this container
//    is_big_endian = 16,		///< Set if this value should be treated as big endian
    smallsize_inttype = 32,	///< Assume values that are below the max \b size are sign OR zero extended based on integer type
    smallsize_floatext = 64,	///< Assume values smaller than max \b size are floating-point extended to full size
    extracheck_high = 128,	///< Perform extra checks during parameter recovery on most sig portion of the double
    extracheck_low = 256	///< Perform extra checks during parameter recovery on least sig portion of the double
  };
private:
  uint4 flags;			///< Boolean properties of the parameter
  type_metatype type;		///< Data-type class that this entry must match
  int4 group;			///< Group of (mutually exclusive) entries that this entry belongs to
  int4 groupsize;		///< The number of consecutive groups taken by the entry
  AddrSpace *spaceid;		///< Address space containing the range
  uintb addressbase;		///< Starting offset of the range
  int4 size;			///< Size of the range in bytes
  int4 minsize;			///< Minimum bytes allowed for the logical value
  int4 alignment;		///< How much alignment (0 means only 1 logical value is allowed)
  int4 numslots;		///< (Maximum) number of slots that can store separate parameters
  JoinRecord *joinrec;		///< Non-null if this is logical variable from joined pieces
  void resolveJoin(void); 	///< If the ParamEntry is initialized with a \e join address, cache the join record

  /// \brief Is the logical value left-justified within its container
  bool isLeftJustified(void) const { return (((flags&force_left_justify)!=0)||(!spaceid->isBigEndian())); }
public:
  ParamEntry(int4 grp) { group=grp; }			///< Constructor for use with restoreXml
  ParamEntry(type_metatype t,int4 grp,int4 grpsize,const Address &loc,int4 sz,int4 mnsz,int4 align,bool normalstack);
  int4 getGroup(void) const { return group; }		///< Get the group id \b this belongs to
  int4 getGroupSize(void) const { return groupsize; }	///< Get the number of groups occupied by \b this
  int4 getSize(void) const { return size; }		///< Get the size of the memory range in bytes.
  int4 getMinSize(void) const { return minsize; }	///< Get the minimum size of a logical value contained in \b this
  int4 getAlign(void) const { return alignment; }	///< Get the alignment of \b this entry
  type_metatype getType(void) const { return type; }	///< Get the data-type class associated with \b this
  bool isExclusion(void) const { return (alignment==0); }	///< Return \b true if this holds a single parameter exclusively
  bool isReverseStack(void) const { return ((flags & reverse_stack)!=0); }	///< Return \b true if parameters are allocated in reverse order
  bool contains(const ParamEntry &op2) const;		///< Does \b this contain the indicated entry.
  bool containedBy(const Address &addr,int4 sz) const;	///< Is this entry contained by the given range
  int4 justifiedContain(const Address &addr,int4 sz) const;	///< Calculate endian aware containment
  bool getContainer(const Address &addr,int4 sz,VarnodeData &res) const;
  OpCode assumedExtension(const Address &addr,int4 sz,VarnodeData &res) const;
  int4 getSlot(const Address &addr,int4 skip) const;
  AddrSpace *getSpace(void) const { return spaceid; }	///< Get the address space containing \b this entry
  uintb getBase(void) const { return addressbase; }	///< Get the starting offset of \b this entry
  Address getAddrBySlot(int4 &slot,int4 sz) const;
  void restoreXml(const Element *el,const AddrSpaceManager *manage,bool normalstack);
  void extraChecks(list<ParamEntry> &entry);
  bool isParamCheckHigh(void) const { return ((flags & extracheck_high)!=0); }	///< Return \b true if there is a high overlap
  bool isParamCheckLow(void) const { return ((flags & extracheck_low)!=0); }	///< Return \b true if there is a low overlap
};

/// \brief Class for storing ParamEntry objects in an interval range (rangemap)
class ParamEntryRange {
  uintb first;		///< Starting offset of the ParamEntry's range
  uintb last;		///< Ending offset of the ParamEntry's range
  int4 position;	///< Position of the ParamEntry within the entire prototype list
  ParamEntry *entry;	///< Pointer to the actual ParamEntry

  /// \brief Helper class for initializing ParamEntryRange in a range map
  class InitData {
    friend class ParamEntryRange;
    int4 position;	///< Position (within the full list) being assigned to the ParamEntryRange
    ParamEntry *entry;	///< Underlying ParamEntry being assigned to the ParamEntryRange
  public:
    InitData(int4 pos,ParamEntry *e) { position = pos; entry = e; }	///< Constructor
  };

  /// \brief Helper class for subsorting on position
  class SubsortPosition {
    int4 position;	///< The position value
  public:
    SubsortPosition(void) {}					///< Constructor for use with rangemap
    SubsortPosition(int4 pos) { position = pos; }		///< Construct given position
    SubsortPosition(bool val) { position = val ? 1000000 : 0; }	///< Constructor minimal/maximal subsort
    bool operator<(const SubsortPosition &op2) { return position < op2.position; }	///< Compare operation
  };
public:
  typedef uintb linetype;		///< The linear element for a rangemap
  typedef SubsortPosition subsorttype;	///< The sub-sort object for a rangemap
  typedef InitData inittype;		///< Initialization data for a ScopeMapper

  ParamEntryRange(const inittype &data,uintb f,uintb l) {
    first = f; last = l; position = data.position; entry = data.entry; }	///< Initialize the range
  uintb getFirst(void) const { return first; }	///< Get the first address in the range
  uintb getLast(void) const { return last; }		///< Get the last address in the range
  subsorttype getSubsort(void) const { return SubsortPosition(position); }	///< Get the sub-subsort object
  ParamEntry *getParamEntry(void) const { return entry; }	///< Get pointer to actual ParamEntry
};
typedef rangemap<ParamEntryRange> ParamEntryResolver;	///< A map from offset to ParamEntry

/// \brief A register or memory register that may be used to pass a parameter or return value
///
/// The parameter recovery utilities (see ParamActive) use this to denote a putative
/// parameter passing storage location. It is made up of the address and size of the memory range,
/// a set of properties about the use of the range (as a parameter) in context, and a link to
/// the matching part of the PrototypeModel.
///
/// Data-flow for the putative parameter is held directly by a Varnode.  To quickly map to the
/// Varnode (which may or may not exist at points during the ParamTrial lifetime), the concept
/// of \b slot is used.  ParamTrials are assigned a \e slot, starting at 1.  For sub-function parameters,
/// this represents the actual input index of the Varnode in the corresponding CALL or CALLIND op.
/// For parameters, this gives the position within the list of possible input Varnodes in address order.
/// The \e slot ordering varies over the course of analysis and is unlikely to match
/// the final parameter ordering.  The ParamTrial comparator sorts the trials in final parameter ordering.
class ParamTrial {
public:
  enum {
    checked = 1,		///< Trial has been checked
    used = 2,			///< Trial is definitely used  (final verdict)
    defnouse = 4,		///< Trial is definitely not used
    active = 8,			///< Trial looks active (hint that it is used)
    unref = 16,			///< There is no direct reference to this parameter trial
    killedbycall = 32,		///< Data in this location is unlikely to flow thru a func and still be a param
    rem_formed = 64,		///< The trial is built out of a remainder operation
    indcreate_formed = 128,	///< The trial is built out of an indirect creation
    condexe_effect = 256	///< This trial may be affected by conditional execution
  };
private:
  uint4 flags;			///< Boolean properties of the trial
  Address addr;			///< Starting address of the memory range
  int4 size;			///< Number of bytes in the memory range
  int4 slot;			///< Slot assigned to this trial
  const ParamEntry *entry;	///< PrototypeModel entry matching this trial
  int4 offset;			///< "justified" offset into entry
public:
  /// \brief Construct from components
  ParamTrial(const Address &ad,int4 sz,int4 sl) { addr = ad; size = sz; slot = sl; flags=0; entry=(ParamEntry *)0; offset=-1; }
  const Address &getAddress(void) const { return addr; }	///< Get the starting address of \b this trial
  int4 getSize(void) const { return size; }			///< Get the number of bytes in \b this trial
  int4 getSlot(void) const { return slot; }			///< Get the \e slot associated with \b this trial
  void setSlot(int4 val) { slot = val; }			///< Set the \e slot associated with \b this trial
  const ParamEntry *getEntry(void) const { return entry; }	///< Get the model entry associated with \b this trial
  int4 getOffset(void) const { return offset; }			///< Get the offset associated with \b this trial
  void setEntry(const ParamEntry *ent,int4 off) { entry=ent; offset=off; }	///< Set the model entry for this trial
  void markUsed(void) { flags |= used; }			///< Mark the trial as a formal parameter
  void markActive(void) { flags |= (active|checked); }		///< Mark that trial is actively used (in data-flow)
  void markInactive(void) { flags &= ~((uint4)active); flags |= checked; }	///< Mark that trial is not actively used
  void markNoUse(void) { flags &= ~((uint4)(active|used)); flags |= (checked|defnouse); }	///< Mark trial as definitely \e not a parameter
  void markUnref(void) { flags |= (unref|checked); slot = -1; }	///< Mark that \b this trial has no Varnode representative
  void markKilledByCall(void) { flags |= killedbycall; }	///< Mark that \b this storage is \e killed-by-call
  bool isChecked(void) const { return ((flags & checked)!=0); }	///< Has \b this trial been checked
  bool isActive(void) const { return ((flags & active)!=0); }	///< Is \b this trial actively used in data-flow
  bool isDefinitelyNotUsed(void) const { return ((flags & defnouse)!=0); }	///< Is \b this trial as definitely not a parameter
  bool isUsed(void) const { return ((flags & used)!=0); }	///< Is \b this trial as a formal parameter
  bool isUnref(void) const { return ((flags & unref)!=0); }	///< Does \b this trial not have a Varnode representative
  bool isKilledByCall(void) const { return ((flags & killedbycall)!=0); }	///< Is \b this storage \e killed-by-call
  void setRemFormed(void) { flags |= rem_formed; }		///< Mark that \b this is formed by a INT_REM operation
  bool isRemFormed(void) const { return ((flags & rem_formed)!=0); }	///< Is \b this formed by a INT_REM operation
  void setIndCreateFormed(void) { flags |= indcreate_formed; }	///< Mark \b this trial as formed by \e indirect \e creation
  bool isIndCreateFormed(void) const { return ((flags & indcreate_formed)!=0); }	///< Is \b this trial formed by \e indirect \e creation
  void setCondExeEffect(void) { flags |= condexe_effect; }	///< Mark \b this trial as possibly affected by conditional execution
  bool hasCondExeEffect(void) const { return ((flags & condexe_effect)!=0); }	///< Is \b this trial possibly affected by conditional execution
  int4 slotGroup(void) const { return entry->getSlot(addr,size-1); }	///< Get position of \b this within its parameter \e group
  void setAddress(const Address &ad,int4 sz) { addr=ad; size=sz; }	///< Reset the memory range of \b this trial
  ParamTrial splitHi(int4 sz) const;			///< Create a trial representing the first part of \b this
  ParamTrial splitLo(int4 sz) const;			///< Create a trial representing the last part of \b this
  bool testShrink(const Address &newaddr,int4 sz) const;	///< Test if \b this trial can be made smaller
  bool operator<(const ParamTrial &b) const;		///< Sort trials in formal parameter order
};

/// \brief Container class for ParamTrial objects
///
/// The parameter analysis algorithms use this class to maintain the collection
/// of parameter trials being actively considered for a given function. It holds the
/// ParamTrial objects and other information about the current state of analysis.
///
/// Trials are maintained in two stages, \e before parameter decisions have been made and \e after.
/// Before, trials are in input index order relative to the CALL or CALLIND op for a sub-function, or
/// they are in address order for input Varnodes to the active function.
/// After, the trials are put into formal parameter order, as dictated by the PrototypeModel.
class ParamActive {
  vector<ParamTrial> trial;	///< The list of parameter trials
  int4 slotbase;		///< Slot where next parameter will go
  int4 stackplaceholder;	///< Which call input slot holds the stack placeholder
  int4 numpasses;		///< Number of attempts at evaluating parameters
  int4 maxpass;			///< Number of passes before we assume we have seen all params
  bool isfullychecked;		///< True if all trials are fully examined (and no new trials are expected)
  bool needsfinalcheck;		///< Should a final pass be made on trials (to take into account control-flow changes)
  bool recoversubcall;		///< True if \b this is being used to recover prototypes of a sub-function call
public:
  ParamActive(bool recoversub);	///< Constructor an empty container
  void clear(void);		///< Reset to an empty container
  void registerTrial(const Address &addr,int4 sz);		///< Add a new trial to the container
  int4 getNumTrials(void) const { return trial.size(); }	///< Get the number of trials in \b this container
  ParamTrial &getTrial(int4 i) { return trial[i]; }		///< Get the i-th trial
  const ParamTrial &getTrialForInputVarnode(int4 slot) const;	///< Get trial corresponding to the given input Varnode
  int4 whichTrial(const Address &addr,int4 sz) const;		///< Get the trial overlapping with the given memory range
  bool needsFinalCheck(void) const { return needsfinalcheck; }	///< Is a final check required
  void markNeedsFinalCheck(void) { needsfinalcheck = true; }	///< Mark that a final check is required
  bool isRecoverSubcall(void) const { return recoversubcall; }	///< Are these trials for a call to a sub-function
  bool isFullyChecked(void) const { return isfullychecked; }	///< Are all trials checked with no new trials expected
  void markFullyChecked(void) { isfullychecked = true; }	///< Mark that all trials are checked
  void setPlaceholderSlot(void) { stackplaceholder = slotbase; slotbase += 1; }	///< Establish a stack placedholder slot
  void freePlaceholderSlot(void);				///< Free the stack placeholder slot
  int4 getNumPasses(void) const { return numpasses; }		///< How many trial analysis passes were performed
  int4 getMaxPass(void) const { return maxpass; }		///< What is the maximum number of passes
  void setMaxPass(int4 val) { maxpass = val; }			///< Set the maximum number of passes
  void finishPass(void) { numpasses += 1; }			///< Mark that an analysis pass has completed
  void sortTrials(void) { sort(trial.begin(),trial.end()); }	///< Sort the trials in formal parameter order
  void deleteUnusedTrials(void);				///< Remove trials that were found not to be parameters
  void splitTrial(int4 i,int4 sz);				///< Split the given trial in two
  void joinTrial(int4 slot,const Address &addr,int4 sz);	///< Join adjacent parameter trials
  int4 getNumUsed(void) const;					///< Get number of trials marked as formal parameters

  /// \brief Test if the given trial can be shrunk to the given range
  ///
  /// \param i is the index of the given trial
  /// \param addr is the new address
  /// \param sz is the new size
  /// \return true if the trial can be shrunk to the new range
  bool testShrink(int4 i,const Address &addr,int4 sz) const { return trial[i].testShrink(addr,sz); }

  /// \brief Shrink the given trial to a new given range
  ///
  /// \param i is the index of the given trial
  /// \param addr is the new range's starting address
  /// \param sz is the new range's size in bytes
  void shrink(int4 i,const Address &addr,int4 sz) { trial[i].setAddress(addr,sz); }
};

/// \brief A special space for encoding FuncCallSpecs
///
/// It is efficient and convenient to store the main subfunction
/// object (FuncCallSpecs) in the pcode operation which is actually making the
/// call. This address space allows a FuncCallSpecs to be encoded
/// as an address which replaces the formally encoded address of
/// the function being called, when manipulating the operation
/// internally.  The space stored in the encoded address is
/// this special \b fspec space, and the offset is the actual
/// value of the pointer
class FspecSpace : public AddrSpace {
public:
  FspecSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind);	///< Constructor
  virtual void saveXmlAttributes(ostream &s,uintb offset) const;
  virtual void saveXmlAttributes(ostream &s,uintb offset,int4 size) const;
  virtual void printRaw(ostream &s,uintb offset) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
};

/// \brief Basic elements of a parameter: address, data-type, properties
struct ParameterPieces {
  enum {
    isthis = 1,		///< Parameter is "this" pointer
    hiddenretparm = 2,	///< Parameter is hidden pointer to return value, mirrors Varnode::hiddenretparm
    indirectstorage = 4,	///< Parameter is indirect pointer to true parameter, mirrors Varnode::indirectstorage
    namelock = 8,	///< Parameter's name is locked, mirrors Varnode::namelock
    typelock = 16,	///< Parameter's data-type is locked, mirrors Varnode::typelock
    sizelock = 32	///< Size of the parameter is locked (but not the data-type)
  };
  Address addr;			///< Storage address of the parameter
  Datatype *type;		///< The datatype of the parameter
  uint4 flags;			///< additional attributes of the parameter
};

/// \brief Description of the indirect effect a sub-function has on a memory range
///
/// This object applies only to the specific memory range, which is seen from the
/// point of view of the calling function as a particular
/// sub-function gets called. The main enumeration below lists the possible effects.
class EffectRecord {
public:
  enum {
    unaffected = 1,	///< The sub-function does not change the value at all
    killedbycall = 2,	///< The memory is changed and is completely unrelated to its original value
    return_address = 3,	///< The memory is being used to store the return address
    unknown_effect = 4	///< An unknown effect (indicates the absence of an EffectRecord)
  };
private:
  VarnodeData address;		///< The memory range affected
  uint4 type;			///< The type of effect
public:
  EffectRecord(void) {}		///< Constructor for use with restoreXml()
  EffectRecord(const EffectRecord &op2) { address = op2.address; type = op2.type; }	///< Copy constructor
  EffectRecord(const Address &addr,int4 size);		///< Construct a memory range with an unknown effect
  EffectRecord(const ParamEntry &entry,uint4 t);	///< Construct an effect on a parameter storage location
  EffectRecord(const VarnodeData &addr,uint4 t);	///< Construct an effect on a memory range
  uint4 getType(void) const { return type; }		///< Get the type of effect
  Address getAddress(void) const { return Address(address.space,address.offset); }	///< Get the starting address of the affected range
  int4 getSize(void) const { return address.size; }	///< Get the size of the affected range
  bool operator<(const EffectRecord &op2) const;	///< Comparator for EffectRecords
  bool operator==(const EffectRecord &op2) const;	///< Equality operator
  bool operator!=(const EffectRecord &op2) const;	///< Inequality operator
  void saveXml(ostream &s) const;			///< Save the record to an XML stream
  void restoreXml(uint4 grouptype,const Element *el,const AddrSpaceManager *manage);	///< Restore the record from an XML stream
};

/// A group of ParamEntry objects that form a complete set for passing
/// parameters in one direction (either input or output). The main tasks this class must
/// perform are:
///   - possibleParam() Quick test if a Varnode could ever be a parameter with this prototype
///   - fillinMap()   Select trials completing prototype, given analysis info
///   - assignMap()   Derive slot->address map, given a list of types
///   - checkJoin()   Can two parameters be considered/converted into a single logical parameter
class ParamList {
public:
  enum {
    p_standard,		///< Standard input parameter model
    p_standard_out,	///< Standard output (return value) model
    p_register,		///< Unordered parameter passing locations model
    p_merged		///< A merged model (multiple models merged together)
  };
  virtual ~ParamList(void) {}			///< Destructor
  virtual uint4 getType(void) const=0;		///< Get the type of parameter list

  /// \brief Given list of data-types, map the list positions to storage locations
  ///
  /// If we know the function prototype, recover how parameters are actually stored using the model.
  /// \param proto is the ordered list of data-types
  /// \param isinput is \b true for the input prototype, \b false for output prototype
  /// \param typefactory is the TypeFactory (for constructing pointers)
  /// \param res will contain the storage locations corresponding to the datatypes
  virtual void assignMap(const vector<Datatype *> &proto,bool isinput,
			 TypeFactory &typefactory,vector<ParameterPieces> &res) const=0;

  /// \brief Given an unordered list of storage locations, calculate a function prototype
  ///
  /// A list of input (or output) trials is given, which may have holes, invalid inputs etc.  Decide
  /// on the formal ordered parameter list. Trials within the ParamActive are added, removed, or
  /// reordered as needed.
  /// \param active is the given list of trials
  virtual void fillinMap(ParamActive *active) const=0;

  /// \brief Check if the given two storage locations can represent a single logical parameter
  ///
  /// Within the conventions of this model, do the two (hi/lo) locations represent
  /// consecutive parameter locations that can be replaced by a single logical parameter.
  /// \param hiaddr is the address of the most significant part of the value
  /// \param hisize is the size of the most significant part in bytes
  /// \param loaddr is the address of the least significant part of the value
  /// \param losize is the size of the least significant part in bytes
  /// \return \b true if the two pieces can be joined
  virtual bool checkJoin(const Address &hiaddr,int4 hisize,const Address &loaddr,int4 losize) const=0;

  /// \brief Check if it makes sense to split a single storage location into two parameters
  ///
  /// A storage location and split point is provided, implying two new storage locations. Does
  /// \b this model allow these locations to be considered parameters.
  /// \param loc is the starting address of provided storage location
  /// \param size is the size of the location in bytes
  /// \param splitpoint is the number of bytes to consider in the first (in address order) piece
  /// \return \b true if the storage location can be split
  virtual bool checkSplit(const Address &loc,int4 size,int4 splitpoint) const=0;

  /// \brief Characterize whether the given range overlaps parameter storage
  ///
  /// Does the range naturally fit inside a potential parameter entry from this list or does
  /// it contain a parameter entry. Return one of three values indicating this characterization:
  ///   - 0 means there is no intersection between the range and any parameter in this list
  ///   - 1 means that at least one parameter contains the range in a properly justified manner
  ///   - 2 means no parameter contains the range, but the range contains at least one ParamEntry
  /// \param loc is the starting address of the given range
  /// \param size is the number of bytes in the given range
  /// \return the characterization code
  virtual int4 characterizeAsParam(const Address &loc,int4 size) const=0;

  /// \brief Does the given storage location make sense as a parameter
  ///
  /// Within \b this model, decide if the storage location can be considered a parameter.
  /// \param loc is the starting address of the storage location
  /// \param size is the number of bytes in the storage location
  /// \return \b true if the location can be a parameter
  virtual bool possibleParam(const Address &loc,int4 size) const=0;

  /// \brief Pass-back the slot and slot size for the given storage location as a parameter
  ///
  /// This checks if the given storage location acts as a parameter in \b this model and
  /// passes back the number of slots that it occupies.
  /// \param loc is the starting address of the storage location
  /// \param size is the number of bytes in the storage location
  /// \param slot if the \e slot number to pass back
  /// \param slotsize is the number of consumed slots to pass back
  /// \return \b true if the location can be a parameter
  virtual bool possibleParamWithSlot(const Address &loc,int4 size,int4 &slot,int4 &slotsize) const=0;

  /// \brief Pass-back the biggest parameter contained within the given range
  ///
  /// \param loc is the starting address of the given range
  /// \param size is the number of bytes in the range
  /// \param res will hold the parameter storage description being passed back
  /// \return \b true if there is at least one parameter contained in the range
  virtual bool getBiggestContainedParam(const Address &loc,int4 size,VarnodeData &res) const=0;

  /// \brief Check if the given storage location looks like an \e unjustified parameter
  ///
  /// The storage for a value may be contained in a normal parameter location but be
  /// unjustified within that container, i.e. the least significant bytes are not being used.
  /// If this is the case, pass back the full parameter location and return \b true.
  /// \param loc is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the full parameter storage to pass back
  /// \return \b true if the given storage is unjustified within its parameter container
  virtual bool unjustifiedContainer(const Address &loc,int4 size,VarnodeData &res) const=0;

  /// \brief Get the type of extension and containing parameter for the given storage
  ///
  /// If the given storage is properly contained within a normal parameter and the model
  /// typically extends a small value into the full container, pass back the full container
  /// and the type of extension.
  /// \param addr is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the parameter storage to pass back
  /// \return the extension operator (INT_ZEXT INT_SEXT) or INT_COPY if there is no extension.
  /// INT_PIECE indicates the extension is determined by the specific prototype.
  virtual OpCode assumedExtension(const Address &addr,int4 size,VarnodeData &res) const=0;

  /// \brief Get the address space associated with any stack based parameters in \b this list.
  ///
  /// \return the stack address space, if \b this models parameters passed on the stack, NULL otherwise
  virtual AddrSpace *getSpacebase(void) const=0;

  /// \brief For a given address space, collect all the parameter locations within that space
  ///
  /// Pass back the memory ranges for any parameter that is stored in the given address space.
  /// \param spc is the given address space
  /// \param res will hold the set of matching memory ranges
  virtual void getRangeList(AddrSpace *spc,RangeList &res) const=0;

  /// \brief Return the maximum heritage delay across all possible parameters
  ///
  /// Depending on the address space, data-flow for a parameter may not be available until
  /// extra transform passes have completed. This method returns the number of passes
  /// that must occur before we can guarantee that all parameters have data-flow info.
  /// \return the maximum number of passes across all parameters in \b this model
  virtual int4 getMaxDelay(void) const=0;

  /// \brief Restore the model from an XML stream
  ///
  /// \param el is the root \<input> or \<output> element
  /// \param manage is used to resolve references to address spaces
  /// \param effectlist is a container collecting EffectRecords across all parameters
  /// \param normalstack is \b true if parameters are pushed on the stack in the normal order
  virtual void restoreXml(const Element *el,const AddrSpaceManager *manage,vector<EffectRecord> &effectlist,bool normalstack)=0;

  virtual ParamList *clone(void) const=0;	///< Clone this parameter list model
};

/// \brief A standard model for parameters as an ordered list of storage resources
///
/// This is a configurable model for passing (input) parameters as a list to a function.
/// The model allows 1 or more resource lists based on data-type, either TYPE_UNKNOWN for
/// general purpose or TYPE_FLOAT for floating-point registers. Within a resource list,
/// any number of parameters can be used but they must come starting at the beginning of
/// the list with no \e holes (skipped resources). A resource list can include (at the end)
/// \e stack parameters that are allocated based on an alignment.  Optionally, the model supports
/// converting data-types larger than a specified size to pointers within the parameter list.
class ParamListStandard : public ParamList {
protected:
  int4 numgroup;			///< Number of \e groups in this parameter convention
  int4 maxdelay;			///< Maximum heritage delay across all parameters
  int4 pointermax; 			///< If non-zero, maximum size of a data-type before converting to a pointer
  bool thisbeforeret;			///< Does a \b this parameter come before a hidden return parameter
  int4 nonfloatgroup;			///< Group of first entry which is not marked float
  list<ParamEntry> entry;		///< The ordered list of parameter entries
  vector<ParamEntryResolver *> resolverMap;	///< Map from space id to resolver
  AddrSpace *spacebase;			///< Address space containing relative offset parameters
  const ParamEntry *findEntry(const Address &loc,int4 size) const;	///< Given storage location find matching ParamEntry
  Address assignAddress(const Datatype *tp,vector<int4> &status) const;	///< Assign storage for given parameter data-type
  void buildTrialMap(ParamActive *active) const;	///< Build map from parameter trials to model ParamEntrys
  void separateFloat(ParamActive *active,int4 &floatstart,int4 &floatstop,int4 &start,int4 &stop) const;
  void forceExclusionGroup(ParamActive *active) const;
  void forceNoUse(ParamActive *active,int4 start,int4 stop) const;
  void forceInactiveChain(ParamActive *active,int4 maxchain,int4 start,int4 stop) const;
  void calcDelay(void);		///< Calculate the maximum heritage delay for any potential parameter in this list
  void populateResolver(void);	///< Build the ParamEntry resolver maps
public:
  ParamListStandard(void) {}						///< Construct for use with restoreXml()
  ParamListStandard(const ParamListStandard &op2);			///< Copy constructor
  virtual ~ParamListStandard(void);
  const list<ParamEntry> &getEntry(void) const { return entry; }	///< Get the list of parameter entries
  virtual uint4 getType(void) const { return p_standard; }
  virtual void assignMap(const vector<Datatype *> &proto,bool isinput,
			 TypeFactory &typefactory,vector<ParameterPieces> &res) const;
  virtual void fillinMap(ParamActive *active) const;
  virtual bool checkJoin(const Address &hiaddr,int4 hisize,const Address &loaddr,int4 losize) const;
  virtual bool checkSplit(const Address &loc,int4 size,int4 splitpoint) const;
  virtual int4 characterizeAsParam(const Address &loc,int4 size) const;
  virtual bool possibleParam(const Address &loc,int4 size) const;
  virtual bool possibleParamWithSlot(const Address &loc,int4 size,int4 &slot,int4 &slotsize) const;
  virtual bool getBiggestContainedParam(const Address &loc,int4 size,VarnodeData &res) const;
  virtual bool unjustifiedContainer(const Address &loc,int4 size,VarnodeData &res) const;
  virtual OpCode assumedExtension(const Address &addr,int4 size,VarnodeData &res) const;
  virtual AddrSpace *getSpacebase(void) const { return spacebase; }
  virtual void getRangeList(AddrSpace *spc,RangeList &res) const;
  virtual int4 getMaxDelay(void) const { return maxdelay; }
  virtual void restoreXml(const Element *el,const AddrSpaceManager *manage,vector<EffectRecord> &effectlist,bool normalstack);
  virtual ParamList *clone(void) const;
};

/// \brief A standard model for passing back return values from a function
///
/// This models a resource list of potential storage locations for a return value,
/// at most 1 of which will be chosen for a given function. Order only matters in that the
/// first ParamEntry that fits is used. If no entry fits, the return value is
/// converted to a pointer data-type, storage allocation is attempted again, and the
/// return value is marked as a \e hidden return parameter to inform the input model.
class ParamListStandardOut : public ParamListStandard {
public:
  ParamListStandardOut(void) : ParamListStandard() {}		///< Constructor
  ParamListStandardOut(const ParamListStandardOut &op2) : ParamListStandard(op2) {}	///< Copy constructor
  virtual uint4 getType(void) const { return p_standard_out; }
  virtual void assignMap(const vector<Datatype *> &proto,bool isinput,
			 TypeFactory &typefactory,vector<ParameterPieces> &res) const;
  virtual void fillinMap(ParamActive *active) const;
  virtual bool possibleParam(const Address &loc,int4 size) const;
  virtual void restoreXml(const Element *el,const AddrSpaceManager *manage,vector<EffectRecord> &effectlist,bool normalstack);
  virtual ParamList *clone(void) const;
};

/// \brief An unstructured model for passing input parameters to a function.
///
/// This is the \b register model, meaning a collection of registers, any of which
/// can be used to pass a parameter.  This is nearly identical to ParamListStandard, but
/// rules banning \e holes are not enforced, any subset of the resource list can be used.
/// This makes sense for executables where parameters follow no conventions or only loose
/// conventions. The assignMap() method may make less sense in this scenario.
class ParamListRegister : public ParamListStandard {
public:
  ParamListRegister(void) : ParamListStandard() {}	///< Constructor for use with restoreXml()
  ParamListRegister(const ParamListRegister &op2) : ParamListStandard(op2) {}	///< Copy constructor
  virtual uint4 getType(void) const { return p_register; }
  virtual void fillinMap(ParamActive *active) const;
  virtual ParamList *clone(void) const;
};

/// \brief A union of other input parameter passing models
///
/// This model is viewed as a union of a constituent set of resource lists.
/// This allows initial data-flow analysis to proceed when the exact model
/// isn't known.  The assignMap() and fillinMap() methods are disabled for
/// instances of this class. The controlling prototype model (ProtoModelMerged)
/// decides from among the constituent ParamList models before these routines
/// need to be invoked.
class ParamListMerged : public ParamListStandard {
public:
  ParamListMerged(void) : ParamListStandard() {}			///< Constructor for use with restoreXml
  ParamListMerged(const ParamListMerged &op2) : ParamListStandard(op2) {}	///< Copy constructor
  void foldIn(const ParamListStandard &op2);				///< Add another model to the union
  void finalize(void) { populateResolver(); }				///< Fold-ins are finished, finalize \b this
  virtual uint4 getType(void) const { return p_merged; }
  virtual void assignMap(const vector<Datatype *> &proto,bool isinput,
			 TypeFactory &typefactory,vector<ParameterPieces> &res) const {
    throw LowlevelError("Cannot assign prototype before model has been resolved"); }
  virtual void fillinMap(ParamActive *active) const {
    throw LowlevelError("Cannot determine prototype before model has been resolved"); }
  virtual ParamList *clone(void) const;
};

/// \brief A \b prototype \b model: a model for passing parameters between functions
///
/// This encompasses both input parameters and return values. It attempts to
/// describe the ABI, Application Binary Interface, of the processor or compiler.
/// Any number of function prototypes (FuncProto) can be implemented under a
/// \b prototype \b model, which represents a static rule set the compiler uses
/// to decide:
///   - Storage locations for input parameters
///   - Storage locations for return values
///   - Expected side-effects of a function on other (non-parameter) registers and storage locations
///   - Behavior of the stack and the stack pointer across function calls
///
/// Major analysis concerns are:
///   - Recovering function prototypes from data-flow information: deriveInputMap() and deriveOutputMap()
///   - Calculating parameter storage locations given a function prototype: assignParameterStorage()
///   - Behavior of data-flow around call sites
///
/// A prototype model supports the concept of \b extrapop, which is defined as the change in
/// value of the stack pointer (or the number of bytes popped from the stack) across a call.
/// This value is calculated starting from the point of the p-code CALL or CALLIND op, when the
/// stack parameters have already been pushed by the calling function. So \e extrapop only reflects
/// changes made by the callee.
class ProtoModel {
  friend class ProtoModelMerged;
  Architecture *glb;		///< The Architecture owning this prototype model
  string name;			///< Name of the model
  int4 extrapop;		///< Extra bytes popped from stack
  ParamList *input;		///< Resource model for input parameters
  ParamList *output;		///< Resource model for output parameters
  const ProtoModel *compatModel;	///< The model \b this is a copy of
  vector<EffectRecord> effectlist; ///< List of side-effects
  vector<VarnodeData> likelytrash;	///< Storage locations potentially carrying \e trash values
  int4 injectUponEntry;		///< Id of injection to perform at beginning of function (-1 means not used)
  int4 injectUponReturn;	///< Id of injection to perform after a call to this function (-1 means not used)
  RangeList localrange;		///< Memory range(s) of space-based locals
  RangeList paramrange;		///< Memory range(s) of space-based parameters
  bool stackgrowsnegative;	///< True if stack parameters have (normal) low address to high address ordering
  bool hasThis;			///< True if this model has a \b this parameter (auto-parameter)
  bool isConstruct;		///< True if this model is a constructor for a particular object
  void defaultLocalRange(void);	///< Set the default stack range used for local variables
  void defaultParamRange(void);	///< Set the default stack range used for input parameters
  void buildParamList(const string &strategy);	 ///< Establish the main resource lists for input and output parameters.
public:
  enum {
    extrapop_unknown = 0x8000	///< Reserved extrapop value meaning the function's \e extrapop is unknown
  };
  ProtoModel(Architecture *g);	///< Constructor for use with restoreXml()
  ProtoModel(const string &nm,const ProtoModel &op2);	///< Copy constructor changing the name
  virtual ~ProtoModel(void);				///< Destructor
  const string &getName(void) const { return name; }	///< Get the name of the prototype model
  Architecture *getArch(void) const { return glb; }	///< Get the owning Architecture
  uint4 hasEffect(const Address &addr,int4 size) const;	///< Determine side-effect of \b this on the given memory range
  int4 getExtraPop(void) const { return extrapop; }	///< Get the stack-pointer \e extrapop for \b this model
  void setExtraPop(int4 ep) { extrapop = ep; }		///< Set the stack-pointer \e extrapop
  int4 getInjectUponEntry(void) const { return injectUponEntry; }	///< Get the inject \e uponentry id
  int4 getInjectUponReturn(void) const { return injectUponReturn; }	///< Get the inject \e uponreturn id
  bool isCompatible(const ProtoModel *op2) const;	///< Return \b true if other given model can be substituted for \b this

  /// \brief Given a list of input \e trials, derive the most likely input prototype
  ///
  /// Trials are sorted and marked as \e used or not.
  /// \param active is the collection of Varnode input trials
  void deriveInputMap(ParamActive *active) const {
    input->fillinMap(active); }

  /// \brief Given a list of output \e trials, derive the most likely output prototype
  ///
  /// One trial (at most) is marked \e used and moved to the front of the list
  /// \param active is the collection of output trials
  void deriveOutputMap(ParamActive *active) const {
    output->fillinMap(active); }

  void assignParameterStorage(const vector<Datatype *> &typelist,vector<ParameterPieces> &res,bool ignoreOutputError);

  /// \brief Check if the given two input storage locations can represent a single logical parameter
  ///
  /// Within the conventions of this model, do the two (hi/lo) locations represent
  /// consecutive input parameter locations that can be replaced by a single logical parameter.
  /// \param hiaddr is the address of the most significant part of the value
  /// \param hisize is the size of the most significant part in bytes
  /// \param loaddr is the address of the least significant part of the value
  /// \param losize is the size of the least significant part in bytes
  /// \return \b true if the two pieces can be joined
  bool checkInputJoin(const Address &hiaddr,int4 hisize,const Address &loaddr,int4 losize) const {
    return input->checkJoin(hiaddr,hisize,loaddr,losize); }

  /// \brief Check if the given two output storage locations can represent a single logical return value
  ///
  /// Within the conventions of this model, do the two (hi/lo) locations represent
  /// consecutive locations that can be replaced by a single logical return value.
  /// \param hiaddr is the address of the most significant part of the value
  /// \param hisize is the size of the most significant part in bytes
  /// \param loaddr is the address of the least significant part of the value
  /// \param losize is the size of the least significant part in bytes
  /// \return \b true if the two pieces can be joined
  bool checkOutputJoin(const Address &hiaddr,int4 hisize,const Address &loaddr,int4 losize) const {
    return output->checkJoin(hiaddr,hisize,loaddr,losize); }

  /// \brief Check if it makes sense to split a single storage location into two input parameters
  ///
  /// A storage location and split point is provided, implying two new storage locations. Does
  /// \b this model allow these locations to be considered separate parameters.
  /// \param loc is the starting address of provided storage location
  /// \param size is the size of the location in bytes
  /// \param splitpoint is the number of bytes to consider in the first (in address order) piece
  /// \return \b true if the storage location can be split
  bool checkInputSplit(const Address &loc,int4 size,int4 splitpoint) const {
    return input->checkSplit(loc,size,splitpoint); }

  const RangeList &getLocalRange(void) const { return localrange; }	///< Get the range of (possible) local stack variables
  const RangeList &getParamRange(void) const { return paramrange; }	///< Get the range of (possible) stack parameters
  vector<EffectRecord>::const_iterator effectBegin(void) const { return effectlist.begin(); }	///< Get an iterator to the first EffectRecord
  vector<EffectRecord>::const_iterator effectEnd(void) const { return effectlist.end(); }	///< Get an iterator to the last EffectRecord
  int4 numLikelyTrash(void) const { return likelytrash.size(); }	///< Get the number of \e likelytrash locations
  const VarnodeData &getLikelyTrash(int4 i) const { return likelytrash[i]; }	///< Get the i-th \e likelytrashh location

  /// \brief Characterize whether the given range overlaps parameter storage
  ///
  /// Does the range naturally fit inside a potential parameter entry from this model or does
  /// it contain a parameter entry. Return one of three values indicating this characterization:
  ///   - 0 means there is no intersection between the range and any ParamEntry
  ///   - 1 means that at least one ParamEntry contains the range in a properly justified manner
  ///   - 2 means no ParamEntry contains the range, but the range contains at least one ParamEntry
  /// \param loc is the starting address of the given range
  /// \param size is the number of bytes in the given range
  /// \return the characterization code
  int4 characterizeAsInputParam(const Address &loc,int4 size) const {
    return input->characterizeAsParam(loc, size);
  }

  /// \brief Does the given storage location make sense as an input parameter
  ///
  /// Within \b this model, decide if the storage location can be considered an input parameter.
  /// \param loc is the starting address of the storage location
  /// \param size is the number of bytes in the storage location
  /// \return \b true if the location can be a parameter
  bool possibleInputParam(const Address &loc,int4 size) const {
    return input->possibleParam(loc,size); }

  /// \brief Does the given storage location make sense as a return value
  ///
  /// Within \b this model, decide if the storage location can be considered an output parameter.
  /// \param loc is the starting address of the storage location
  /// \param size is the number of bytes in the storage location
  /// \return \b true if the location can be a parameter
  bool possibleOutputParam(const Address &loc,int4 size) const {
    return output->possibleParam(loc,size); }

  /// \brief Pass-back the slot and slot size for the given storage location as an input parameter
  ///
  /// This checks if the given storage location acts as an input parameter in \b this model and
  /// passes back the number of slots that it occupies.
  /// \param loc is the starting address of the storage location
  /// \param size is the number of bytes in the storage location
  /// \param slot if the \e slot number to pass back
  /// \param slotsize is the number of consumed slots to pass back
  /// \return \b true if the location can be a parameter
  bool possibleInputParamWithSlot(const Address &loc,int4 size,int4 &slot,int4 &slotsize) const {
    return input->possibleParamWithSlot(loc,size,slot,slotsize); }

  /// \brief Pass-back the slot and slot size for the given storage location as a return value
  ///
  /// This checks if the given storage location acts as an output parameter in \b this model and
  /// passes back the number of slots that it occupies.
  /// \param loc is the starting address of the storage location
  /// \param size is the number of bytes in the storage location
  /// \param slot if the \e slot number to pass back
  /// \param slotsize is the number of consumed slots to pass back
  /// \return \b true if the location can be a parameter
  bool possibleOutputParamWithSlot(const Address &loc,int4 size,int4 &slot,int4 &slotsize) const {
    return output->possibleParamWithSlot(loc,size,slot,slotsize); }

  /// \brief Check if the given storage location looks like an \e unjustified input parameter
  ///
  /// The storage for a value may be contained in a normal parameter location but be
  /// unjustified within that container, i.e. the least significant bytes are not being used.
  /// If this is the case, pass back the full parameter location and return \b true.
  /// \param loc is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the full parameter storage to pass back
  /// \return \b true if the given storage is unjustified within its parameter container
  bool unjustifiedInputParam(const Address &loc,int4 size,VarnodeData &res) const {
    return input->unjustifiedContainer(loc,size,res); }

  /// \brief Get the type of extension and containing input parameter for the given storage
  ///
  /// If the given storage is properly contained within a normal parameter and the model
  /// typically extends a small value into the full container, pass back the full container
  /// and the type of extension.
  /// \param addr is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the parameter storage to pass back
  /// \return the extension operator (INT_ZEXT INT_SEXT) or INT_COPY if there is no extension.
  /// INT_PIECE indicates the extension is determined by the specific prototype.
  OpCode assumedInputExtension(const Address &addr,int4 size,VarnodeData &res) const {
    return input->assumedExtension(addr,size,res); }

  /// \brief Get the type of extension and containing return value location for the given storage
  ///
  /// If the given storage is properly contained within a normal return value location and the model
  /// typically extends a small value into the full container, pass back the full container
  /// and the type of extension.
  /// \param addr is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the parameter storage to pass back
  /// \return the extension operator (INT_ZEXT INT_SEXT) or INT_COPY if there is no extension.
  /// INT_PIECE indicates the extension is determined by the specific prototype.
  OpCode assumedOutputExtension(const Address &addr,int4 size,VarnodeData &res) const {
    return output->assumedExtension(addr,size,res); }

  /// \brief Pass-back the biggest input parameter contained within the given range
  ///
  /// \param loc is the starting address of the given range
  /// \param size is the number of bytes in the range
  /// \param res will hold the parameter storage description being passed back
  /// \return \b true if there is at least one parameter contained in the range
  bool getBiggestContainedInputParam(const Address &loc,int4 size,VarnodeData &res) const {
    return input->getBiggestContainedParam(loc, size, res);
  }

  AddrSpace *getSpacebase(void) const { return input->getSpacebase(); }	///< Get the stack space associated with \b this model
  bool isStackGrowsNegative(void) const { return stackgrowsnegative; }	///< Return \b true if the stack \e grows toward smaller addresses
  bool hasThisPointer(void) const { return hasThis; }			///< Is \b this a model for (non-static) class methods
  bool isConstructor(void) const { return isConstruct; }		///< Is \b this model for class constructors

  /// \brief Return the maximum heritage delay across all possible input parameters
  ///
  /// Depending on the address space, data-flow for a parameter may not be available until
  /// extra transform passes have completed. This method returns the number of passes
  /// that must occur before we can guarantee that all parameters have data-flow info.
  /// \return the maximum number of passes across all input parameters in \b this model
  int4 getMaxInputDelay(void) const { return input->getMaxDelay(); }

  /// \brief Return the maximum heritage delay across all possible return values
  ///
  /// Depending on the address space, data-flow for a parameter may not be available until
  /// extra transform passes have completed. This method returns the number of passes
  /// that must occur before we can guarantee that any return value has data-flow info.
  /// \return the maximum number of passes across all output parameters in \b this model
  int4 getMaxOutputDelay(void) const { return output->getMaxDelay(); }

  virtual bool isMerged(void) const { return false; }	///< Is \b this a merged prototype model
  virtual void restoreXml(const Element *el);		///< Restore \b this model from an XML stream
  static uint4 lookupEffect(const vector<EffectRecord> &efflist,const Address &addr,int4 size);
};

/// \brief Class for calculating "goodness of fit" of parameter trials against a prototype model
///
/// The class is instantiated with a prototype model (ProtoModel). A set of Varnode parameter trials
/// are registered by calling addParameter() for each trial.  Then calling doScore() computes a score
/// that evaluates how well the set of registered trials fit the prototype model.  A lower score
/// indicates a better fit.
class ScoreProtoModel {
  /// \brief A record mapping trials to parameter entries in the prototype model
  class PEntry {
  public:
    int4 origIndex;		///< Original index of trial
    int4 slot;			///< Matching slot within the resource list
    int4 size;			///< Number of slots occupied
    /// \brief Compare PEntry objects by slot
    ///
    /// \param op2 is the PEntry to compare \b this to
    /// \return \b true if \b this should be ordered before the other PEntry
    bool operator<(const PEntry &op2) const { return (slot < op2.slot); }
  };
  bool isinputscore;		///< True if scoring against input parameters, \b false for outputs
  vector<PEntry> entry;		///< Map of parameter entries corresponding to trials
  const ProtoModel *model;	///< Prototype model to score against
  int4 finalscore;		///< The final fitness score
  int4 mismatch;		///< Number of trials that don't fit the prototype model at all
public:
  ScoreProtoModel(bool isinput,const ProtoModel *mod,int4 numparam);	///< Constructor
  void addParameter(const Address &addr,int4 sz);			///< Register a trial to be scored
  void doScore(void);							///< Compute the fitness score
  int4 getScore(void) const { return finalscore; }			///< Get the fitness score
  int4 getNumMismatch(void) const { return mismatch; }			///< Get the number of mismatched trials
};

/// \brief A prototype model made by merging together other models
///
/// This model serves as a placeholder for multiple models, when the exact model
/// hasn't been immediately determined. At the time of active parameter recovery
/// the correct model is selected for the given set of trials
/// from among the constituent prototype models used to build \b this,
/// by calling the method selectModel().
/// Up to this time, \b this serves as a merged form of the models
/// so that all potential parameter trials will be included in the analysis.  The parameter recovery
/// for the output part of the model is currently limited, so the constituent models must all share
/// the same output model, and this part is \e not currently merged.
class ProtoModelMerged : public ProtoModel {
  vector<ProtoModel *> modellist;					///< Constituent models being merged
  void intersectEffects(const vector<EffectRecord> &efflist);		///< Fold EffectRecords into \b this model
  void intersectLikelyTrash(const vector<VarnodeData> &trashlist);	///< Fold \e likelytrash locations into \b this model
public:
  ProtoModelMerged(Architecture *g) : ProtoModel(g) {}			///< Constructor
  virtual ~ProtoModelMerged(void) {}					///< Destructor
  int4 numModels(void) const { return modellist.size(); }		///< Get the number of constituent models
  ProtoModel *getModel(int4 i) const { return modellist[i]; }		///< Get the i-th model
  void foldIn(ProtoModel *model);					///< Fold-in an additional prototype model
  ProtoModel *selectModel(ParamActive *active) const;			///< Select the best model given a set of trials
  virtual bool isMerged(void) const { return true; }
  virtual void restoreXml(const Element *el);
};

class Symbol;
class AliasChecker;

/// \brief A function parameter viewed as a name, data-type, and storage address
///
/// This is the base class, with derived classes determining what is backing up
/// the information, whether is it a formal Symbol or just internal storage.
/// Both input parameters and return values can be represented with this object.
class ProtoParameter {
public:
  ProtoParameter(void) {}				///< Constructor
  virtual ~ProtoParameter(void) {}			///< Destructor
  virtual const string &getName(void) const=0;		///< Get the name of the parameter ("" for return value)
  virtual Datatype *getType(void) const=0;		///< Get the data-type associate with \b this
  virtual Address getAddress(void) const=0;		///< Get the storage address for \b this parameter
  virtual int4 getSize(void) const=0;			///< Get the number of bytes occupied by \b this parameter
  virtual bool isTypeLocked(void) const=0;		///< Is the parameter data-type locked
  virtual bool isNameLocked(void) const=0;		///< Is the parameter name locked
  virtual bool isSizeTypeLocked(void) const=0;		///< Is the size of the parameter locked
  virtual bool isThisPointer(void) const=0;		///< Is \b this the "this" pointer for a class method
  virtual bool isIndirectStorage(void) const=0;		///< Is \b this really a pointer to the true parameter
  virtual bool isHiddenReturn(void) const=0;		///< Is \b this a pointer to storage for a return value
  virtual bool isNameUndefined(void) const=0;		///< Is the name of \b this parameter undefined
  virtual void setTypeLock(bool val)=0;			///< Toggle the lock on the data-type
  virtual void setNameLock(bool val)=0;			///< Toggle the lock on the name
  virtual void setThisPointer(bool val)=0;		///< Toggle whether \b this is the "this" pointer for a class method

  /// \brief Change (override) the data-type of a \e size-locked parameter.
  ///
  /// The original parameter must have a \e type-lock and TYPE_UNKNOWN data-type.
  /// The \e size-lock is preserved and \b this can be cleared back to its TYPE_UNKNOWN state.
  /// \param ct is the overriding data-type
  virtual void overrideSizeLockType(Datatype *ct)=0;

  /// \brief Clear \b this parameter's data-type preserving any \e size-lock
  ///
  /// The data-type is converted to a TYPE_UNKNOWN of the same size
  /// \param factory is the TypeFactory that will construct the unknown data-type
  virtual void resetSizeLockType(TypeFactory *factory)=0;

  virtual ProtoParameter *clone(void) const=0;		///< Clone the parameter

  /// \brief Retrieve the formal Symbol associated with \b this parameter
  ///
  /// If there is no backing symbol an exception is thrown
  /// \return the backing Symbol object
  virtual Symbol *getSymbol(void) const=0;

  /// \brief Compare storage location and data-type for equality
  ///
  /// \param op2 is the parameter to compare with \b this
  /// \return \b true if the parameters share a data-type and storage location
  bool operator==(const ProtoParameter &op2) const {
    if (getAddress() != op2.getAddress()) return false;
    if (getType() != op2.getType()) return false;
    return true;
  }

  /// \brief Compare storage location and data-type for inequality
  ///
  /// \param op2 is the parameter to compare with \b this
  /// \return \b true if the parameters do not share a data-type and storage location
  bool operator!=(const ProtoParameter &op2) const {
    return !(*this==op2); }
};

/// \brief A stand-alone parameter with no backing symbol
///
/// Name, data-type, and storage location is stored internally to the object.
/// This is suitable for return values, function pointer prototypes, or functions
/// that haven't been fully analyzed.
class ParameterBasic : public ProtoParameter {
  string name;			///< The name of the parameter, "" for undefined or return value parameters
  Address addr;			///< Storage address of the parameter
  Datatype *type;		///< Data-type of the parameter
  uint4 flags;			///< Lock and other properties from ParameterPieces flags
public:
  ParameterBasic(const string &nm,const Address &ad,Datatype *tp,uint4 fl) {
    name = nm; addr = ad; type = tp; flags=fl; }		///< Construct from components
  ParameterBasic(Datatype *tp) {
    type = tp; flags = 0; }			///< Construct a \e void parameter
  virtual const string &getName(void) const { return name; }
  virtual Datatype *getType(void) const { return type; }
  virtual Address getAddress(void) const { return addr; }
  virtual int4 getSize(void) const { return type->getSize(); }
  virtual bool isTypeLocked(void) const { return ((flags&ParameterPieces::typelock)!=0); }
  virtual bool isNameLocked(void) const { return ((flags&ParameterPieces::namelock)!=0); }
  virtual bool isSizeTypeLocked(void) const { return ((flags&ParameterPieces::sizelock)!=0); }
  virtual bool isThisPointer(void) const { return ((flags&ParameterPieces::isthis)!=0); }
  virtual bool isIndirectStorage(void) const { return ((flags&ParameterPieces::indirectstorage)!=0); }
  virtual bool isHiddenReturn(void) const { return ((flags&ParameterPieces::hiddenretparm)!=0); }
  virtual bool isNameUndefined(void) const { return (name.size()==0); }
  virtual void setTypeLock(bool val);
  virtual void setNameLock(bool val);
  virtual void setThisPointer(bool val);
  virtual void overrideSizeLockType(Datatype *ct);
  virtual void resetSizeLockType(TypeFactory *factory);
  virtual ProtoParameter *clone(void) const;
  virtual Symbol *getSymbol(void) const { throw LowlevelError("Parameter is not a real symbol"); }
};

/// \brief A collection parameter descriptions making up a function prototype
///
/// A unified interface for accessing descriptions of individual
/// parameters in a function prototype. Both input parameters and return values
/// are described.
class ProtoStore {
public:
  virtual ~ProtoStore(void) {}		///< Constructor

  /// \brief Establish name, data-type, storage of a specific input parameter
  ///
  /// This either allocates a new parameter or replaces the existing one at the
  /// specified input slot.  If there is a backing symbol table, a Symbol is
  /// created or modified.
  /// \param i is the specified input slot
  /// \param nm is the (optional) name of the parameter
  /// \param pieces holds the raw storage address and data-type to set
  /// \return the new/modified ProtoParameter
  virtual ProtoParameter *setInput(int4 i,const string &nm,const ParameterPieces &pieces)=0;

  /// \brief Clear the input parameter at the specified slot
  ///
  /// The parameter is excised, any following parameters are shifted to fill its spot.
  /// If there is a backing Symbol, it is removed from the SymbolTable
  /// \param i is the specified parameter slot to remove
  virtual void clearInput(int4 i)=0;

  virtual void clearAllInputs(void)=0;			///< Clear all input parameters (and any backing symbols)
  virtual int4 getNumInputs(void) const=0;		///< Get the number of input parameters for \b this prototype
  virtual ProtoParameter *getInput(int4 i)=0;		///< Get the i-th input parameter (or NULL if it doesn't exist)

  /// \brief Establish the data-type and storage of the return value
  ///
  /// This either allocates a new parameter or replaces the existing one.
  /// A \e void return value can be specified with an \e invalid address and TYPE_VOID data-type.
  /// \param piece holds the raw storage address and data-type to set
  /// \return the new/modified ProtoParameter
  virtual ProtoParameter *setOutput(const ParameterPieces &piece)=0;

  virtual void clearOutput(void)=0;			///< Clear the return value to TYPE_VOID
  virtual ProtoParameter *getOutput(void)=0;		///< Get the return-value description
  virtual ProtoStore *clone(void) const=0;		///< Clone the entire collection of parameter descriptions

  /// \brief Save any parameters that are not backed by symbols to an XML stream
  ///
  /// Symbols are stored elsewhere, so symbol backed parameters are not serialized.
  /// If there are any internal parameters an \<internallist> tag is emitted.
  /// \param s is the output stream
  virtual void saveXml(ostream &s) const=0;

  /// \brief Restore any internal parameter descriptions from an XML stream
  ///
  /// \param el is a root \<internallist> element containing \<param> and \<retparam> sub-tags.
  /// \param model is prototype model for determining storage for unassigned parameters
  virtual void restoreXml(const Element *el,ProtoModel *model)=0;
};

/// \brief A parameter with a formal backing Symbol
///
/// Input parameters generally have a symbol associated with them.
/// This class holds a reference to the Symbol object and pulls the relevant
/// parameter information off of it.
class ParameterSymbol : public ProtoParameter {
  friend class ProtoStoreSymbol;
  Symbol *sym;		///< Backing Symbol for \b this parameter
public:
  ParameterSymbol(void) { sym = (Symbol *)0; }		///< Constructor
  virtual const string &getName(void) const;
  virtual Datatype *getType(void) const;
  virtual Address getAddress(void) const;
  virtual int4 getSize(void) const;
  virtual bool isTypeLocked(void) const;
  virtual bool isNameLocked(void) const;
  virtual bool isSizeTypeLocked(void) const;
  virtual bool isThisPointer(void) const;
  virtual bool isIndirectStorage(void) const;
  virtual bool isHiddenReturn(void) const;
  virtual bool isNameUndefined(void) const;
  virtual void setTypeLock(bool val);
  virtual void setNameLock(bool val);
  virtual void setThisPointer(bool val);
  virtual void overrideSizeLockType(Datatype *ct);
  virtual void resetSizeLockType(TypeFactory *factory);
  virtual ProtoParameter *clone(void) const;
  virtual Symbol *getSymbol(void) const;
};

/// \brief A collection of parameter descriptions backed by Symbol information
///
/// Input parameters are determined by symbols a function Scope
/// (category 0).  Information about the return-value is stored internally.
/// ProtoParameter objects are constructed on the fly as requested and cached.
class ProtoStoreSymbol : public ProtoStore {
  Scope *scope;				///< Backing Scope for input parameters
  Address restricted_usepoint;		///< A usepoint reference for storage locations (usually function entry -1)
  vector<ProtoParameter *> inparam;	///< Cache of allocated input parameters
  ProtoParameter *outparam;		///< The return-value parameter
  ParameterSymbol *getSymbolBacked(int4 i);	///< Fetch or allocate the parameter for the indicated slot
public:
  ProtoStoreSymbol(Scope *sc,const Address &usepoint);	///< Constructor
  virtual ~ProtoStoreSymbol(void);
  virtual ProtoParameter *setInput(int4 i,const string &nm,const ParameterPieces &pieces);
  virtual void clearInput(int4 i);
  virtual void clearAllInputs(void);
  virtual int4 getNumInputs(void) const;
  virtual ProtoParameter *getInput(int4 i);
  virtual ProtoParameter *setOutput(const ParameterPieces &piece);
  virtual void clearOutput(void);
  virtual ProtoParameter *getOutput(void);
  virtual ProtoStore *clone(void) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,ProtoModel *model);
};

/// \brief A collection of parameter descriptions without backing symbols
///
/// Parameter descriptions are stored internally to the object and are not
/// mirrored by a symbol table.
class ProtoStoreInternal : public ProtoStore {
  Datatype *voidtype;			///< Cached reference to the \b void data-type
  vector<ProtoParameter *> inparam;	///< Descriptions of input parameters
  ProtoParameter *outparam;		///< Description of the return value
public:
  ProtoStoreInternal(Datatype *vt);	///< Constructor
  virtual ~ProtoStoreInternal(void);
  virtual ProtoParameter *setInput(int4 i,const string &nm,const ParameterPieces &pieces);
  virtual void clearInput(int4 i);
  virtual void clearAllInputs(void);
  virtual int4 getNumInputs(void) const;
  virtual ProtoParameter *getInput(int4 i);
  virtual ProtoParameter *setOutput(const ParameterPieces &piece);
  virtual void clearOutput(void);
  virtual ProtoParameter *getOutput(void);
  virtual ProtoStore *clone(void) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,ProtoModel *model);
};

/// \brief Raw components of a function prototype (obtained from parsing source code)
struct PrototypePieces {
  ProtoModel *model;		///< (Optional) model on which prototype is based
  string name;			///< Identifier (function name) associated with prototype
  Datatype *outtype;		///< Return data-type
  vector<Datatype *> intypes;	///< Input data-types
  vector<string> innames;	///< Identifiers for input types
  bool dotdotdot;		///< True if prototype takes variable arguments
};

/// \brief A \b function \b prototype
///
/// A description of the parameters and return value for a specific function.
/// Parameter descriptions include both source code features like \e name and \e data-type
/// but also give the storage location. Storage follows a specific parameter passing convention
/// (ProtoModel), although individual parameters may be customized.  The prototype describes
/// numerous properties related to calling the specific function:
///   - Side-effects on non-parameter storage locations (like save registers)
///   - P-code injection associated with the function (uponentry, uponreturn, callfixup)
///   - Additional bytes (\b extrapop) popped from the stack by the function
///   - Method flags (thiscall, is_constructor, is_destructor)
class FuncProto {
  enum {
    dotdotdot = 1,		///< Set if \b this prototype takes variable arguments (varargs)
    voidinputlock = 2,		///< Set if \b this prototype takes no inputs and is locked
    modellock = 4,		///< Set if the PrototypeModel is locked for \b this prototype
    is_inline = 8,		///< Should \b this be inlined (within calling function) by decompiler
    no_return = 16,		///< Function does not return
    paramshift_applied = 32,	///< paramshift parameters have been added and removed
    error_inputparam = 64,	///< Set if the input parameters are not properly represented
    error_outputparam = 128,	///< Set if the return value(s) are not properly represented
    custom_storage = 256,	///< Parameter storage is custom (not derived from ProtoModel)
    unknown_model = 512,	///< Set if the PrototypeModel isn't known
    is_constructor = 0x400,	///< Function is an (object-oriented) constructor
    is_destructor = 0x800,	///< Function is an (object-oriented) destructor
    has_thisptr= 0x1000,	///< Function is a method with a 'this' pointer as an argument
    is_override = 0x2000	///< Set if \b this prototype is created to override a single call site
  };
  ProtoModel *model;		///< Model of for \b this prototype
  ProtoStore *store;		///< Storage interface for parameters
  int4 extrapop;		///< Extra bytes popped from stack
  uint4 flags;			///< Boolean properties of the function prototype
  vector<EffectRecord> effectlist;	///< Side-effects associated with non-parameter storage locations
  vector<VarnodeData> likelytrash;	///< Locations that may contain \e trash values
  int4 injectid;		///< (If non-negative) id of p-code snippet that should replace this function
  int4 returnBytesConsumed;	///< Number of bytes of return value that are consumed by callers (0 = all bytes)
  void updateThisPointer(void);	///< Make sure any "this" parameter is properly marked
protected:
  void paramShift(int4 paramshift);	///< Add parameters to the front of the input parameter list
  bool isParamshiftApplied(void) const { return ((flags&paramshift_applied)!=0); }	///< Has a parameter shift been applied
  /// \brief Toggle whether a parameter shift has been applied
  void setParamshiftApplied(bool val) { flags = val ? (flags|paramshift_applied) : (flags & ~((uint4)paramshift_applied)); }
public:
  FuncProto(void);		///< Constructor
  ~FuncProto(void);		///< Destructor
  Architecture *getArch(void) const { return model->getArch(); }	///< Get the Architecture owning \b this
  void copy(const FuncProto &op2);					///< Copy another function prototype
  void copyFlowEffects(const FuncProto &op2);	 			///< Copy properties that affect data-flow
  void getPieces(PrototypePieces &pieces) const;			///< Get the raw pieces of the prototype
  void setPieces(const PrototypePieces &pieces);			///< Set \b this prototype based on raw pieces
  void setScope(Scope *s,const Address &startpoint);			///< Set a backing symbol Scope for \b this
  void setInternal(ProtoModel *m,Datatype *vt);				///< Set internal backing storage for \b this
  void setModel(ProtoModel *m);						///< Set the prototype model for \b this
  bool hasModel(void) const { return (model != (ProtoModel *)0); }	///< Does \b this prototype have a model

  bool hasMatchingModel(const FuncProto *op2) const { return (model == op2->model); }	///< Does \b this have a matching model
  bool hasMatchingModel(const ProtoModel *op2) const { return (model == op2); }	///< Does \b this use the given model
  const string &getModelName(void) const { return model->getName(); }	///< Get the prototype model name
  int4 getModelExtraPop(void) const { return model->getExtraPop(); }	///< Get the \e extrapop of the prototype model

  bool isInputLocked(void) const;					///< Are input data-types locked
  bool isOutputLocked(void) const { return store->getOutput()->isTypeLocked(); }	///< Is the output data-type locked
  bool isModelLocked(void) const { return ((flags&modellock)!=0); }	///< Is the prototype model for \b this locked
  bool isUnknownModel(void) const { return ((flags&unknown_model)!=0); }	///< Is prototype model officially "unknown"
  bool hasCustomStorage(void) const { return ((flags&custom_storage)!=0); }	///< Is \b this a "custom" function prototype
  void setInputLock(bool val);				///< Toggle the data-type lock on input parameters
  void setOutputLock(bool val);				///< Toggle the data-type lock on the return value

  /// \brief Toggle the lock on the prototype model for \b this.
  ///
  /// The prototype model can be locked while still leaving parameters unlocked. Parameter
  /// recovery will follow the rules of the locked model.
  /// \param val is \b true to indicate a lock, \b false for unlocked
  void setModelLock(bool val) { flags = val ? (flags|modellock) : (flags & ~((uint4)modellock)); }

  bool isInline(void) const { return ((flags & is_inline)!=0); }	///< Does this function get \e in-lined during decompilation.

  /// \brief Toggle the \e in-line setting for functions with \b this prototype
  ///
  /// In-lining can be based on a \e call-fixup, or the full body of the function can be in-lined.
  /// \param val is \b true if in-lining should be performed.
  void setInline(bool val) { flags = val ? (flags|is_inline) : (flags & ~((uint4)is_inline)); }

  /// \brief Get the injection id associated with \b this.
  ///
  /// A non-negative id indicates a \e call-fixup is used to in-line function's with \b this prototype.
  /// \return the id value corresponding to the specific call-fixup or -1 if there is no call-fixup
  int4 getInjectId(void) const { return injectid; }

  /// \brief Get an estimate of the number of bytes consumed by callers of \b this prototype.
  ///
  /// A value of 0 means \e all possible bytes of the storage location are consumed.
  /// \return the number of bytes or 0
  int4 getReturnBytesConsumed(void) const { return returnBytesConsumed; }

  bool setReturnBytesConsumed(int4 val);	///< Set the number of bytes consumed by callers of \b this

  /// \brief Does a function with \b this prototype never return
  bool isNoReturn(void) const { return ((flags & no_return)!=0); }

  /// \brief Toggle the \e no-return setting for functions with \b this prototype
  ///
  /// \param val is \b true to treat the function as never returning
  void setNoReturn(bool val) { flags = val ? (flags|no_return) : (flags & ~((uint4)no_return)); }

  /// \brief Is \b this a prototype for a class method, taking a \e this pointer.
  bool hasThisPointer(void) const { return ((flags & has_thisptr)!=0); }

  /// \brief Is \b this prototype for a class constructor method
  bool isConstructor(void) const { return ((flags & is_constructor)!=0); }

  /// \brief Toggle whether \b this prototype is a \e constructor method
  ///
  /// \param val is \b true if \b this is a constructor, \b false otherwise
  void setConstructor(bool val) { flags = val ? (flags|is_constructor) : (flags & ~((uint4)is_constructor)); }

  /// \brief Is \b this prototype for a class destructor method
  bool isDestructor(void) const { return ((flags & is_destructor)!=0); }

  /// \brief Toggle whether \b this prototype is a \e destructor method
  ///
  /// \param val is \b true if \b this is a destructor
  void setDestructor(bool val) { flags = val ? (flags|is_destructor) : (flags & ~((uint4)is_destructor)); }

  /// \brief Has \b this prototype been marked as having an incorrect input parameter descriptions
  bool hasInputErrors(void) const { return ((flags&error_inputparam)!=0); }

  /// \brief Has \b this prototype been marked as having an incorrect return value description
  bool hasOutputErrors(void) const { return ((flags&error_outputparam)!=0); }

  /// \brief Toggle the input error setting for \b this prototype
  ///
  /// \param val is \b true if input parameters should be marked as in error
  void setInputErrors(bool val) { flags = val ? (flags|error_inputparam) : (flags & ~((uint4)error_inputparam)); }

  /// \brief Toggle the output error setting for \b this prototype
  ///
  /// \param val is \b true if return value should be marked as in error
  void setOutputErrors(bool val) { flags = val ? (flags|error_outputparam) : (flags & ~((uint4)error_outputparam)); }

  int4 getExtraPop(void) const { return extrapop; }		///< Get the general \e extrapop setting for \b this prototype
  void setExtraPop(int4 ep) { extrapop = ep; }			///< Set the general \e extrapop for \b this prototype
  int4 getInjectUponEntry(void) const { return model->getInjectUponEntry(); }	///< Get any \e upon-entry injection id (or -1)
  int4 getInjectUponReturn(void) const { return model->getInjectUponReturn(); }	///< Get any \e upon-return injection id (or -1)
  void resolveExtraPop(void);

  void clearUnlockedInput(void);		///< Clear input parameters that have not been locked
  void clearUnlockedOutput(void);		///< Clear the return value if it has not been locked
  void clearInput(void);			///< Clear all input parameters regardless of lock
  void cancelInjectId(void);			///< Turn-off any in-lining for this function

  void resolveModel(ParamActive *active);

  /// \brief Given a list of input \e trials, derive the most likely inputs for \b this prototype
  ///
  /// Trials are sorted and marked as \e used or not.
  /// \param active is the collection of Varnode input trials
  void deriveInputMap(ParamActive *active) const {
    model->deriveInputMap(active); }

  /// \brief Given a list of output \e trials, derive the most likely return value for \b this prototype
  ///
  /// One trial (at most) is marked \e used and moved to the front of the list
  /// \param active is the collection of output trials
  void deriveOutputMap(ParamActive *active) const {
    model->deriveOutputMap(active); }

  /// \brief Check if the given two input storage locations can represent a single logical parameter
  ///
  /// For \b this prototype, do the two (hi/lo) locations represent
  /// consecutive input parameter locations that can be replaced by a single logical parameter.
  /// \param hiaddr is the address of the most significant part of the value
  /// \param hisz is the size of the most significant part in bytes
  /// \param loaddr is the address of the least significant part of the value
  /// \param losz is the size of the least significant part in bytes
  /// \return \b true if the two pieces can be joined
  bool checkInputJoin(const Address &hiaddr,int4 hisz,const Address &loaddr,int4 losz) const {
    return model->checkInputJoin(hiaddr,hisz,loaddr,losz); }

  /// \brief Check if it makes sense to split a single storage location into two input parameters
  ///
  /// A storage location and split point is provided, implying two new storage locations. Does
  /// \b this prototype allow these locations to be considered separate parameters.
  /// \param loc is the starting address of provided storage location
  /// \param size is the size of the location in bytes
  /// \param splitpoint is the number of bytes to consider in the first (in address order) piece
  /// \return \b true if the storage location can be split
  bool checkInputSplit(const Address &loc,int4 size,int4 splitpoint) const {
    return model->checkInputSplit(loc,size,splitpoint); }

  void updateInputTypes(Funcdata &data,const vector<Varnode *> &triallist,ParamActive *activeinput);
  void updateInputNoTypes(Funcdata &data,const vector<Varnode *> &triallist,ParamActive *activeinput);
  void updateOutputTypes(const vector<Varnode *> &triallist);
  void updateOutputNoTypes(const vector<Varnode *> &triallist,TypeFactory *factory);
  void updateAllTypes(const vector<string> &namelist,const vector<Datatype *> &typelist,bool dtdtdt);
  ProtoParameter *getParam(int4 i) const { return store->getInput(i); }	///< Get the i-th input parameter
  void removeParam(int4 i) { store->clearInput(i); }		///< Remove the i-th input parameter
  int4 numParams(void) const { return store->getNumInputs(); }	///< Get the number of input parameters
  ProtoParameter *getOutput(void) const { return store->getOutput(); }	///< Get the return value
  Datatype *getOutputType(void) const { return store->getOutput()->getType(); }	///< Get the return value data-type
  const RangeList &getLocalRange(void) const { return model->getLocalRange(); }	///< Get the range of potential local stack variables
  const RangeList &getParamRange(void) const { return model->getParamRange(); }	///< Get the range of potential stack parameters
  bool isStackGrowsNegative(void) const { return model->isStackGrowsNegative(); }	///< Return \b true if the stack grows toward smaller addresses
  bool isDotdotdot(void) const { return ((flags&dotdotdot)!=0); }	///< Return \b true if \b this takes a variable number of arguments
  void setDotdotdot(bool val) { flags = val ? (flags|dotdotdot) : (flags & ~((uint4)dotdotdot)); }	///< Toggle whether \b this takes variable arguments
  bool isOverride(void) const { return ((flags&is_override)!=0); }	///< Return \b true if \b this is a call site override
  void setOverride(bool val) { flags = val ? (flags|is_override) : (flags & ~((uint4)is_override)); }	///< Toggle whether \b this is a call site override
  uint4 hasEffect(const Address &addr,int4 size) const;
  vector<EffectRecord>::const_iterator effectBegin(void) const;	///< Get iterator to front of EffectRecord list
  vector<EffectRecord>::const_iterator effectEnd(void) const;	///< Get iterator to end of EffectRecord list
  int4 numLikelyTrash(void) const;				///< Get the number of \e likely-trash locations
  const VarnodeData &getLikelyTrash(int4 i) const;		///< Get the i-th \e likely-trash location
  int4 characterizeAsInputParam(const Address &addr,int4 size) const;
  bool possibleInputParam(const Address &addr,int4 size) const;
  bool possibleOutputParam(const Address &addr,int4 size) const;

  /// \brief Return the maximum heritage delay across all possible input parameters
  ///
  /// Depending on the address space, data-flow for a parameter may not be available until
  /// extra transform passes have completed. This method returns the number of passes
  /// that must occur before we can guarantee that all parameters have data-flow info.
  /// \return the maximum number of passes across all input parameters in \b this prototype
  int4 getMaxInputDelay(void) const { return model->getMaxInputDelay(); }

  /// \brief Return the maximum heritage delay across all possible return values
  ///
  /// Depending on the address space, data-flow for a parameter may not be available until
  /// extra transform passes have completed. This method returns the number of passes
  /// that must occur before we can guarantee that any return value has data-flow info.
  /// \return the maximum number of passes across all output parameters in \b this prototype
  int4 getMaxOutputDelay(void) const { return model->getMaxOutputDelay(); }

  bool unjustifiedInputParam(const Address &addr,int4 size,VarnodeData &res) const;

  /// \brief Get the type of extension and containing input parameter for the given storage
  ///
  /// If the given storage is properly contained within a normal parameter and the model
  /// typically extends a small value into the full container, pass back the full container
  /// and the type of extension.
  /// \param addr is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the parameter storage to pass back
  /// \return the extension operator (INT_ZEXT INT_SEXT) or INT_COPY if there is no extension.
  /// INT_PIECE indicates the extension is determined by the specific prototype.
  OpCode assumedInputExtension(const Address &addr,int4 size,VarnodeData &res) const {
    return model->assumedInputExtension(addr,size,res); }

  /// \brief Get the type of extension and containing return value location for the given storage
  ///
  /// If the given storage is properly contained within a normal return value location and the model
  /// typically extends a small value into the full container, pass back the full container
  /// and the type of extension.
  /// \param addr is the starting address of the given storage
  /// \param size is the number of bytes in the given storage
  /// \param res is the parameter storage to pass back
  /// \return the extension operator (INT_ZEXT INT_SEXT) or INT_COPY if there is no extension.
  /// INT_PIECE indicates the extension is determined by the specific prototype.
  OpCode assumedOutputExtension(const Address &addr,int4 size,VarnodeData &res) const {
    return model->assumedOutputExtension(addr,size,res); }

  /// \brief Pass-back the biggest potential input parameter contained within the given range
  bool getBiggestContainedInputParam(const Address &loc,int4 size,VarnodeData &res) const;

  bool isCompatible(const FuncProto &op2) const;
  AddrSpace *getSpacebase(void) const { return model->getSpacebase(); }		///< Get the \e stack address space
  void printRaw(const string &funcname,ostream &s) const;

  /// \brief Get the comparable properties of \b this prototype
  ///
  /// Get properties not including locking, error, and inlining flags.
  /// \return the active set of flags for \b this prototype
  uint4 getComparableFlags(void) const { return (flags & (dotdotdot | is_constructor | is_destructor | has_thisptr )); }

  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,Architecture *glb);
};

class Funcdata;

/// \brief A class for analyzing parameters to a sub-function call
///
/// This can be viewed as a function prototype that evolves over the course of
/// analysis. It derives off of FuncProto and includes facilities for analyzing
/// data-flow for parameter information. This is the high-level object managing
/// the examination of data-flow to recover a working prototype (ParamActive),
/// holding a stack-pointer placeholder to facilitate stack analysis, and deciding
/// on the working \e extrapop for the CALL.
///
/// A \b stack-pointer \b placeholder is a temporary Varnode in the input operands
/// of the CALL or CALLIND that is defined by a LOAD from the stack-pointer. By examining
/// the pointer, the exact value of the stack-pointer (relative to its incoming value) can
/// be computed at the point of the CALL.  The temporary can arise naturally if stack
/// parameters are a possibility, otherwise a placeholder temporary is artificially
/// inserted into the CALL input.  At the time heritage of the stack space is computed,
/// the placeholder is examined to read off the active stack-pointer offset for the CALL
/// and the placeholder is removed.
class FuncCallSpecs : public FuncProto {
  PcodeOp *op;			///< Pointer to CALL or CALLIND instruction
  string name;			///< Name of function if present
  Address entryaddress;		///< First executing address of function
  Funcdata *fd;			///< The Funcdata object for the called functon (if known)
  int4 effective_extrapop;	///< Working extrapop for the CALL
  uintb stackoffset;		///< Relative offset of stack-pointer at time of this call
  int4 stackPlaceholderSlot;	///< Slot containing temporary stack tracing placeholder (-1 means unused)
  int4 paramshift;		///< Number of input parameters to ignore before prototype
  int4 matchCallCount;		///< Number of calls to this sub-function within the calling function
  ParamActive activeinput;	///< Info for recovering input parameters
  ParamActive activeoutput;	///< Info for recovering output parameters
  mutable vector<int4> inputConsume;	///< Number of bytes consumed by sub-function, for each input parameter
  bool isinputactive; 		///< Are we actively trying to recover input parameters
  bool isoutputactive;		///< Are we actively trying to recover output parameters
  bool isbadjumptable;		///< Was the call originally a jump-table we couldn't recover
  Varnode *getSpacebaseRelative(void) const;	///< Get the active stack-pointer Varnode at \b this call site
  Varnode *buildParam(Funcdata &data,Varnode *vn,ProtoParameter *param,Varnode *stackref);
  int4 transferLockedInputParam(ProtoParameter *param);
  PcodeOp *transferLockedOutputParam(ProtoParameter *param);
  bool transferLockedInput(vector<Varnode *> &newinput);
  bool transferLockedOutput(Varnode *&newoutput);
  void commitNewInputs(Funcdata &data,vector<Varnode *> &newinput);
  void commitNewOutputs(Funcdata &data,Varnode *newout);
  void collectOutputTrialVarnodes(vector<Varnode *> &trialvn);
public:
  enum {
    offset_unknown = 0xBADBEEF					///< "Magic" stack offset indicating the offset is unknown
  };
  FuncCallSpecs(PcodeOp *call_op);					///< Construct based on CALL or CALLIND
  void setAddress(const Address &addr) { entryaddress = addr; }	///< Set (override) the callee's entry address
  PcodeOp *getOp(void) const { return op; }			///< Get the CALL or CALLIND corresponding to \b this
  Funcdata *getFuncdata(void) const { return fd; }		///< Get the Funcdata object associated with the called function
  void setFuncdata(Funcdata *f);				///< Set the Funcdata object associated with the called function
  FuncCallSpecs *clone(PcodeOp *newop) const;			///< Clone \b this given the mirrored p-code CALL
  const string &getName(void) const { return name; }		///< Get the function name associated with the callee
  const Address &getEntryAddress(void) const { return entryaddress; }	///< Get the entry address of the callee
  void setEffectiveExtraPop(int4 epop) { effective_extrapop = epop; }	///< Set the specific \e extrapop associate with \b this call site
  int4 getEffectiveExtraPop(void) const { return effective_extrapop; }	///< Get the specific \e extrapop associate with \b this call site
  uintb getSpacebaseOffset(void) const { return stackoffset; }	///< Get the stack-pointer relative offset at the point of \b this call site
  void setParamshift(int4 val) { paramshift = val; }		///< Set a parameter shift for this call site
  int4 getParamshift(void) const { return paramshift; }		///< Get the parameter shift for this call site
  int4 getMatchCallCount(void) const { return matchCallCount; }	///< Get the number of calls the caller makes to \b this sub-function
  int4 getStackPlaceholderSlot(void) const { return stackPlaceholderSlot; }	///< Get the slot of the stack-pointer placeholder
  void setStackPlaceholderSlot(int4 slot) { stackPlaceholderSlot = slot;
      if (isinputactive) activeinput.setPlaceholderSlot(); }	///< Set the slot of the stack-pointer placeholder
  void clearStackPlaceholderSlot(void) {
    stackPlaceholderSlot = -1; if (isinputactive) activeinput.freePlaceholderSlot(); }	///< Release the stack-pointer placeholder

  void initActiveInput(void);			 ///< Turn on analysis recovering input parameters
  void clearActiveInput(void) { isinputactive = false; }	///< Turn off analysis recovering input parameters
  void initActiveOutput(void) { isoutputactive = true; }	///< Turn on analysis recovering the return value
  void clearActiveOutput(void) { isoutputactive = false; }	///< Turn off analysis recovering the return value
  bool isInputActive(void) const { return isinputactive; }	///< Return \b true if input parameter recovery analysis is active
  bool isOutputActive(void) const { return isoutputactive; }	///< Return \b true if return value recovery analysis is active
  void setBadJumpTable(bool val) { isbadjumptable = val; }	///< Toggle whether \b call site looked like an indirect jump
  bool isBadJumpTable(void) const { return isbadjumptable; }	///< Return \b true if \b this call site looked like an indirect jump
  ParamActive *getActiveInput(void) { return &activeinput; }	///< Get the analysis object for input parameter recovery
  ParamActive *getActiveOutput(void) { return &activeoutput; }	///< Get the analysis object for return value recovery

  bool checkInputJoin(int4 slot1,bool ishislot,Varnode *vn1,Varnode *vn2) const;
  void doInputJoin(int4 slot1,bool ishislot);
  bool lateRestriction(const FuncProto &restrictedProto,vector<Varnode *> &newinput,Varnode *&newoutput);
  void deindirect(Funcdata &data,Funcdata *newfd);
  void forceSet(Funcdata &data,const FuncProto &fp);
  void insertPcode(Funcdata &data);
  void resolveSpacebaseRelative(Funcdata &data,Varnode *phvn);
  void abortSpacebaseRelative(Funcdata &data);
  void finalInputCheck(void);
  void checkInputTrialUse(Funcdata &data,AliasChecker &aliascheck);
  void checkOutputTrialUse(Funcdata &data,vector<Varnode *> &trialvn);
  void buildInputFromTrials(Funcdata &data);
  void buildOutputFromTrials(Funcdata &data,vector<Varnode *> &trialvn);
  int4 getInputBytesConsumed(int4 slot) const;
  bool setInputBytesConsumed(int4 slot,int4 val) const;
  void paramshiftModifyStart(void);
  bool paramshiftModifyStop(Funcdata &data);
  uint4 hasEffectTranslate(const Address &addr,int4 size) const;
  static Varnode *findPreexistingWhole(Varnode *vn1,Varnode *vn2);

  /// \brief Convert FspecSpace addresses to the underlying FuncCallSpecs object
  ///
  /// \param addr is the given \e fspec address
  /// \return the FuncCallSpecs object
  static FuncCallSpecs *getFspecFromConst(const Address &addr) { return (FuncCallSpecs *)(uintp)addr.getOffset(); }

  /// \brief Compare FuncCallSpecs by function entry address
  ///
  /// \param a is the first FuncCallSpecs to compare
  /// \param b is the second to compare
  /// \return \b true if the first should be ordered before the second
  static bool compareByEntryAddress(const FuncCallSpecs *a,const FuncCallSpecs *b) { return a->entryaddress < b->entryaddress; }
  static void countMatchingCalls(const vector<FuncCallSpecs *> &qlst);
};

/// Return the trial associated with the input Varnode to the associated p-code CALL or CALLIND.
/// We take into account the call address parameter (subtract 1) and if the index occurs \e after the
/// index holding the stackpointer placeholder, we subtract an additional 1.
/// \param slot is the input index of the input Varnode
/// \return the corresponding parameter trial
inline const ParamTrial &ParamActive::getTrialForInputVarnode(int4 slot) const

{
  slot -= ((stackplaceholder<0)||(slot<stackplaceholder)) ? 1 : 2;
  return trial[slot];
}

/// Sort on the memory range, then the effect type
/// \param op2 is the other record to compare with \b this
/// \return \b true if \b this should be ordered before the other record
inline bool EffectRecord::operator<(const EffectRecord &op2) const

{
  if (address < op2.address) return true;
  if (address != op2.address) return false;
  return (type < op2.type);
}

inline bool EffectRecord::operator==(const EffectRecord &op2) const

{
  if (address != op2.address) return false;
  return (type == op2.type);
}

inline bool EffectRecord::operator!=(const EffectRecord &op2) const

{
  if (address != op2.address) return true;
  return (type != op2.type);
}

#endif

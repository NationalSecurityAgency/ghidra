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
#ifndef __FUNCDATA_HH__
#define __FUNCDATA_HH__

/// \file funcdata.hh
/// \brief Utilities for processing data structures associated with a single function

#include "architecture.hh"
#include "override.hh"
#include "heritage.hh"
#include "merge.hh"
#include "dynamic.hh"
#include "unionresolve.hh"

namespace ghidra {

class FlowInfo;

extern AttributeId ATTRIB_NOCODE;	///< Marshaling attribute "nocode"

extern ElementId ELEM_AST;		///< Marshaling element \<ast>
extern ElementId ELEM_FUNCTION;		///< Marshaling element \<function>
extern ElementId ELEM_HIGHLIST;		///< Marshaling element \<highlist>
extern ElementId ELEM_JUMPTABLELIST;	///< Marshaling element \<jumptablelist>
extern ElementId ELEM_VARNODES;		///< Marshaling element \<varnodes>

/// \brief Container for data structures associated with a single function
///
/// This class holds the primary data structures for decompiling a function. In particular it holds
/// control-flow, data-flow, and prototype information, plus class instances to help with constructing
/// SSA form, structure control-flow, recover jump-tables, recover parameters, and merge Varnodes. In
/// most cases it acts as the main API for querying and accessing these structures.
///
/// Some important groups of public methods include:
///    - PcodeOp manipulation (mostly starting with 'op')
///    - PcodeOp search and traversal ('beginOp*' and 'endOp*')
///    - Varnode creation ('new*' methods)
///    - Varnode search and traversal ('beginLoc' 'endLoc' 'beginDef' and 'endDef')
///    - Basic block access and block structuring
///    - Access to subfunction prototypes
///    - Access to jump-tables (within the body of the function)
class Funcdata {
  enum {
    highlevel_on = 1,		///< Set if Varnodes have HighVariables assigned
    blocks_generated = 2,	///< Set if Basic blocks have been generated
    blocks_unreachable = 4,	///< Set if at least one basic block is currently unreachable
    processing_started = 8,	///< Set if processing has started
    processing_complete = 0x10,	///< Set if processing completed
    typerecovery_on = 0x20,	///< Set if data-type analysis will be performed
    typerecovery_start = 0x40,	///< Set if data-type recovery is started
    no_code = 0x80,		///< Set if there is no code available for this function
    jumptablerecovery_on = 0x100,	///< Set if \b this Funcdata object is dedicated to jump-table recovery
    jumptablerecovery_dont = 0x200, 	///< Don't try to recover jump-tables, always truncate
    restart_pending = 0x400,	///< Analysis must be restarted (because of new override info)
    unimplemented_present = 0x800,	///< Set if function contains unimplemented instructions
    baddata_present = 0x1000,	///< Set if function flowed into bad data
    double_precis_on = 0x2000,	///< Set if we are performing double precision recovery
    typerecovery_exceeded= 0x4000	///< Set if data-type propagation passes reached maximum
  };
  uint4 flags;			///< Boolean properties associated with \b this function
  uint4 clean_up_index;		///< Creation index of first Varnode created after start of cleanup
  uint4 high_level_index;	///< Creation index of first Varnode created after HighVariables are created
  uint4 cast_phase_index;	///< Creation index of first Varnode created after ActionSetCasts
  uint4 minLanedSize;		///< Minimum Varnode size to check as LanedRegister
  int4 size;			///< Number of bytes of binary data in function body
  Architecture *glb;		///< Global configuration data
  FunctionSymbol *functionSymbol;	///< The symbol representing \b this function
  string name;			///< Name of function
  string displayName;		///< Name to display in output
  Address baseaddr;		///< Starting code address of binary data
  FuncProto funcp;		///< Prototype of this function
  ScopeLocal *localmap;		///< Local variables (symbols in the function scope)

  vector<FuncCallSpecs *> qlst;	///< List of calls this function makes
  vector<JumpTable *> jumpvec;	///< List of jump-tables for this function

  VarnodeBank vbank;		///< Container of Varnode objects for \b this function
  PcodeOpBank obank;		///< Container of PcodeOp objects for \b this function
  BlockGraph bblocks;		///< Unstructured basic blocks
  BlockGraph sblocks;		///< Structured block hierarchy (on top of basic blocks)
  Heritage heritage;		///< Manager for maintaining SSA form
  Merge covermerge;		///< Variable range intersection algorithms
  ParamActive *activeoutput;	///< Data for assessing which parameters are passed to \b this function
  Override localoverride;	///< Overrides of data-flow, prototypes, etc. that are local to \b this function
  map<VarnodeData,const LanedRegister *> lanedMap;	///< Current storage locations which may be laned registers
  map<ResolveEdge,ResolvedUnion> unionMap;	///< A map from data-flow edges to the resolved field of TypeUnion being accessed

				// Low level Varnode functions
  void setVarnodeProperties(Varnode *vn) const;	///< Look-up boolean properties and data-type information
  HighVariable *assignHigh(Varnode *vn);	///< Assign a new HighVariable to a Varnode
  Symbol *handleSymbolConflict(SymbolEntry *entry,Varnode *vn);	///< Handle two variables with matching storage
  bool syncVarnodesWithSymbol(VarnodeLocSet::const_iterator &iter,uint4 fl,Datatype *ct);
  bool descend2Undef(Varnode *vn);		///< Transform all reads of the given Varnode to a special \b undefined constant

  void splitUses(Varnode *vn);			///< Make all reads of the given Varnode unique
  Varnode *cloneVarnode(const Varnode *vn);	///< Clone a Varnode (between copies of the function)
  void destroyVarnode(Varnode *vn);		///< Delete the given Varnode from \b this function
  void coverVarnodes(SymbolEntry *entry,vector<Varnode *> &list);
  bool applyUnionFacet(SymbolEntry *entry,DynamicHash &dhash);
				// Low level op functions
  void opZeroMulti(PcodeOp *op);		///< Transform trivial CPUI_MULTIEQUAL to CPUI_COPY
				// Low level block functions
  void blockRemoveInternal(BlockBasic *bb,bool unreachable);
  void branchRemoveInternal(BlockBasic *bb,int4 num);
  void pushMultiequals(BlockBasic *bb);		///< Push MULTIEQUAL Varnodes of the given block into the output block
  void clearBlocks(void);			///< Clear all basic blocks
  void structureReset(void);			///< Calculate initial basic block structures (after a control-flow change)
  JumpTable::RecoveryMode stageJumpTable(Funcdata &partial,JumpTable *jt,PcodeOp *op,FlowInfo *flow);
  void switchOverJumpTables(const FlowInfo &flow);	///< Convert jump-table addresses to basic block indices
  void clearJumpTables(void);			///< Clear any jump-table information
  BlockBasic *nodeSplitBlockEdge(BlockBasic *b,int4 inedge);

  void sortCallSpecs(void);			///< Sort calls using a dominance based order
  void deleteCallSpecs(PcodeOp *op);		///< Remove the specification for a particular call
  void clearCallSpecs(void);			///< Remove all call specifications
  void issueDatatypeWarnings(void);		///< Add warning headers for any data-types that have been modified

  static bool descendantsOutside(Varnode *vn);
  static void encodeVarnode(Encoder &encoder,VarnodeLocSet::const_iterator iter,VarnodeLocSet::const_iterator enditer);
  static bool checkIndirectUse(Varnode *vn);
  static PcodeOp *findPrimaryBranch(PcodeOpTree::const_iterator iter,PcodeOpTree::const_iterator enditer,
				    bool findbranch,bool findcall,bool findreturn);
public:
  Funcdata(const string &nm,const string &disp,Scope *conf,const Address &addr,FunctionSymbol *sym,int4 sz=0);	///< Constructor
  ~Funcdata(void);							///< Destructor
  const string &getName(void) const { return name; }			///< Get the function's local symbol name
  const string &getDisplayName(void) const { return displayName; }	///< Get the name to display in output
  const Address &getAddress(void) const { return baseaddr; }		///< Get the entry point address
  int4 getSize(void) const { return size; }				///< Get the function body size in bytes
  Architecture *getArch(void) const { return glb; }			///< Get the program/architecture owning \b this function
  FunctionSymbol *getSymbol(void) const { return functionSymbol; }	///< Return the symbol associated with \b this function
  bool isHighOn(void) const { return ((flags&highlevel_on)!=0); }	///< Are high-level variables assigned to Varnodes
  bool isProcStarted(void) const { return ((flags&processing_started)!=0); }	///< Has processing of the function started
  bool isProcComplete(void) const { return ((flags&processing_complete)!=0); }	///< Is processing of the function complete
  bool hasUnreachableBlocks(void) const { return ((flags&blocks_unreachable)!=0); }	///< Did this function exhibit unreachable code
  bool isTypeRecoveryOn(void) const { return ((flags&typerecovery_on)!=0); }	///< Will data-type analysis be performed
  bool hasTypeRecoveryStarted(void) const { return ((flags&typerecovery_start)!=0); }	///< Has data-type recovery processes started
  bool isTypeRecoveryExceeded(void) const { return ((flags&typerecovery_exceeded)!=0); }	///< Has maximum propagation passes been reached
  bool hasNoCode(void) const { return ((flags & no_code)!=0); }		///< Return \b true if \b this function has no code body
  void setNoCode(bool val) { if (val) flags |= no_code; else flags &= ~no_code; }	///< Toggle whether \b this has a body
  void setLanedRegGenerated(void) { minLanedSize = 1000000; }	///< Mark that laned registers have been collected

  /// \brief Toggle whether \b this is being used for jump-table recovery
  ///
  /// \param val is \b true to indicate a jump-table is being recovered
  void setJumptableRecovery(bool val) { if (val) flags &= ~jumptablerecovery_dont; else flags |= jumptablerecovery_dont; }

  bool isJumptableRecoveryOn(void) const { return ((flags & jumptablerecovery_on)!=0); }	///< Is \b this used for jump-table recovery

  /// \brief Toggle whether double precision analysis is used
  ///
  /// \param val is \b true if double precision analysis is enabled
  void setDoublePrecisRecovery(bool val) { if (val) flags |= double_precis_on; else flags &= ~double_precis_on; }

  bool isDoublePrecisOn(void) const { return ((flags & double_precis_on)!=0); }	///< Is double precision analysis enabled
  bool hasNoStructBlocks(void) const { return (sblocks.getSize() == 0); }	///< Return \b true if no block structuring was performed
  void clear(void);						///< Clear out old disassembly
  void warning(const string &txt,const Address &ad) const;	///< Add a warning comment in the function body
  void warningHeader(const string &txt) const;			///< Add a warning comment as part of the function header
  void startProcessing(void);					///< Start processing for this function
  void stopProcessing(void);					///< Mark that processing has completed for this function
  bool startTypeRecovery(void);					///< Mark that data-type analysis has started

  /// \brief Toggle whether data-type recovery will be performed on \b this function
  ///
  /// \param val is \b true if data-type analysis is enabled
  void setTypeRecovery(bool val) { flags = val ? (flags | typerecovery_on) : (flags & ~typerecovery_on); }
  void setTypeRecoveryExceeded(void) { flags |= typerecovery_exceeded; }	///< Mark propagation passes have reached maximum
  void startCastPhase(void) { cast_phase_index = vbank.getCreateIndex(); }	///< Start the \b cast insertion phase
  uint4 getCastPhaseIndex(void) const { return cast_phase_index; }	///< Get creation index at the start of \b cast insertion
  uint4 getHighLevelIndex(void) const { return high_level_index; }	///< Get creation index at the start of HighVariable creation
  void startCleanUp(void) { clean_up_index = vbank.getCreateIndex(); }	///< Start \e clean-up phase
  uint4 getCleanUpIndex(void) const { return clean_up_index; }	///< Get creation index at the start of \b clean-up phase

  void followFlow(const Address &baddr,const Address &eadddr);
  void truncatedFlow(const Funcdata *fd,const FlowInfo *flow);
  int4 inlineFlow(Funcdata *inlinefd,FlowInfo &flow,PcodeOp *callop);
  void overrideFlow(const Address &addr,uint4 type);
  void doLiveInject(InjectPayload *payload,const Address &addr,BlockBasic *bl,list<PcodeOp *>::iterator pos);
  
  void printRaw(ostream &s) const;			///< Print raw p-code op descriptions to a stream
  void printVarnodeTree(ostream &s) const;		///< Print a description of all Varnodes to a stream
  void printBlockTree(ostream &s) const;		///< Print a description of control-flow structuring to a stream
  void printLocalRange(ostream &s) const;		///< Print description of memory ranges associated with local scopes
  void encode(Encoder &encoder,uint8 id,bool savetree) const;	///< Encode a description of \b this function to stream
  uint8 decode(Decoder &decoder);			///< Restore the state of \b this function from a stream
  void encodeJumpTable(Encoder &encoder) const;		///< Encode a description of jump-tables to stream
  void decodeJumpTable(Decoder &decoder);		///< Decode jump-tables from a stream
  void encodeTree(Encoder &encoder) const;		///< Encode a description of the p-code tree to stream
  void encodeHigh(Encoder &encoder) const;		///< Encode a description of all HighVariables to stream

  Override &getOverride(void) { return localoverride; }	///< Get the Override object for \b this function

  /// \brief Toggle whether analysis needs to be restarted for \b this function
  ///
  /// \param val is \b true if a reset is required
  void setRestartPending(bool val) { flags = val ? (flags|restart_pending) : (flags & ~((uint4)restart_pending)); }

  /// \brief Does \b this function need to restart its analysis
  ///
  /// \return \b true if analysis should be restarted
  bool hasRestartPending(void) const { return ((flags&restart_pending)!=0); }

  /// \brief Does \b this function have instructions marked as \e unimplemented
  ///
  /// \return \b true if the function's body contains at least one unimplemented instruction
  bool hasUnimplemented(void) const { return ((flags&unimplemented_present)!=0); }

  bool hasBadData(void) const { return ((flags&baddata_present)!=0); }	///< Does \b this function flow into bad data
  void spacebase(void);				///< Mark registers that map to a virtual address space
  Varnode *newSpacebasePtr(AddrSpace *id);	///< Construct a new \e spacebase register for a given address space
  Varnode *findSpacebaseInput(AddrSpace *id) const;
  Varnode *constructSpacebaseInput(AddrSpace *id);
  Varnode *constructConstSpacebase(AddrSpace *id);
  void spacebaseConstant(PcodeOp *op,int4 slot,SymbolEntry *entry,const Address &rampoint,uintb origval,int4 origsize);

  int4 getHeritagePass(void) const { return heritage.getPass(); }	///< Get overall count of heritage passes

  /// \brief Get the number of heritage passes performed for the given address space
  ///
  /// \param spc is the address space
  /// \return the number of passes performed
  int4 numHeritagePasses(AddrSpace *spc) { return heritage.numHeritagePasses(spc); }

  /// \brief Mark that dead Varnodes have been seen in a specific address space
  ///
  /// \param spc is the address space to mark
  void seenDeadcode(AddrSpace *spc) { heritage.seenDeadCode(spc); }

  /// \brief Set a delay before removing dead code for a specific address space
  ///
  /// \param spc is the specific address space
  /// \param delay is the number of passes to delay
  void setDeadCodeDelay(AddrSpace *spc,int4 delay) { heritage.setDeadCodeDelay(spc,delay); }

  /// \brief Check if dead code removal is allowed for a specific address space
  ///
  /// \param spc is the specific address space
  /// \return \b true if dead code removal is allowed
  bool deadRemovalAllowed(AddrSpace *spc) const { return heritage.deadRemovalAllowed(spc); }

  /// \brief Check if dead Varnodes have been removed for a specific address space
  ///
  /// \param spc is the specific address space
  /// \return \b true if dead code removal has happened in the space
  bool deadRemovalAllowedSeen(AddrSpace *spc) { return heritage.deadRemovalAllowedSeen(spc); }

  /// \brief Check if a specific Varnode has been linked in fully to the syntax tree (SSA)
  ///
  /// \param vn is the specific Varnode
  /// \return \b true if the Varnode is fully linked
  bool isHeritaged(Varnode *vn) { return (heritage.heritagePass(vn->getAddr())>=0); }

  const list<LoadGuard> &getLoadGuards(void) const { return heritage.getLoadGuards(); }		///< Get the list of guarded LOADs
  const list<LoadGuard> &getStoreGuards(void) const { return heritage.getStoreGuards(); }	///< Get the list of guarded STOREs
  const LoadGuard *getStoreGuard(PcodeOp *op) const { return heritage.getStoreGuard(op); }	///< Get LoadGuard associated with STORE op

  // Function prototype and call specification routines
  int4 numCalls(void) const { return qlst.size(); }	///< Get the number of calls made by \b this function
  FuncCallSpecs *getCallSpecs(int4 i) const { return qlst[i]; }	///< Get the i-th call specification
  FuncCallSpecs *getCallSpecs(const PcodeOp *op) const;	///< Get the call specification associated with a CALL op
  int4 fillinExtrapop(void);			///< Recover and return the \e extrapop for this function

  // Varnode routines
  int4 numVarnodes(void) const { return vbank.numVarnodes(); }	///< Get the total number of Varnodes
  Varnode *newVarnodeOut(int4 s,const Address &m,PcodeOp *op);	///< Create a new output Varnode
  Varnode *newUniqueOut(int4 s,PcodeOp *op);			///< Create a new \e temporary output Varnode
  Varnode *newVarnode(int4 s,const Address &m,Datatype *ct=(Datatype *)0);
  Varnode *newConstant(int4 s,uintb constant_val);		///< Create a new \e constant Varnode
  Varnode *newVarnode(int4 s,AddrSpace *base,uintb off);	///< Create a new Varnode given an address space and offset
  Varnode *newVarnodeIop(PcodeOp *op);				///< Create a PcodeOp \e annotation Varnode
  Varnode *newVarnodeSpace(AddrSpace *spc);			///< Create a constant Varnode referring to an address space
  Varnode *newVarnodeCallSpecs(FuncCallSpecs *fc);		///< Create a call specification \e annotation Varnode
  Varnode *newUnique(int4 s,Datatype *ct=(Datatype *)0);	///< Create a new \e temporary Varnode
  Varnode *newCodeRef(const Address &m);			///< Create a code address \e annotation Varnode
  Varnode *setInputVarnode(Varnode *vn);			///< Mark a Varnode as an input to the function
  void combineInputVarnodes(Varnode *vnHi,Varnode *vnLo);	///< Combine two contiguous input Varnodes into one
  Varnode *newExtendedConstant(int4 s,uint8 *val,PcodeOp *op);	///< Create extended precision constant
  void adjustInputVarnodes(const Address &addr,int4 sz);
  void deleteVarnode(Varnode *vn) { vbank.destroy(vn); }	///< Delete the given varnode

  Address findDisjointCover(Varnode *vn,int4 &sz);	///< Find range covering given Varnode and any intersecting Varnodes

  /// \brief Find the first input Varnode covered by the given range
  ///
  /// \param s is the size of the range in bytes
  /// \param loc is the starting address of the range
  /// \return the matching Varnode or NULL
  Varnode *findCoveredInput(int4 s,const Address &loc) const { return vbank.findCoveredInput(s,loc); }

  /// \brief Find the input Varnode that contains the given range
  ///
  /// \param s is the size of the range in bytes
  /// \param loc is the starting address of the range
  /// \return the matching Varnode or NULL
  Varnode *findCoveringInput(int4 s,const Address &loc) const { return vbank.findCoveringInput(s,loc); }

  /// \brief Find the input Varnode with the given size and storage address
  ///
  /// \param s is the size in bytes
  /// \param loc is the storage address
  /// \return the matching Varnode or NULL
  Varnode *findVarnodeInput(int4 s,const Address &loc) const { return vbank.findInput(s,loc); }

  /// \brief Find a defined Varnode via its storage address and its definition address
  ///
  /// \param s is the size in bytes
  /// \param loc is the storage address
  /// \param pc is the address where the Varnode is defined
  /// \param uniq is an (optional) sequence number to match
  /// \return the matching Varnode or NULL
  Varnode *findVarnodeWritten(int4 s,const Address &loc,const Address &pc,uintm uniq=~((uintm)0)) const {
    return vbank.find(s,loc,pc,uniq); }

  /// \brief Start of all Varnodes sorted by storage
  VarnodeLocSet::const_iterator beginLoc(void) const { return vbank.beginLoc(); }

  /// \brief End of all Varnodes sorted by storage
  VarnodeLocSet::const_iterator endLoc(void) const { return vbank.endLoc(); }

  /// \brief Start of Varnodes stored in a given address space
  VarnodeLocSet::const_iterator beginLoc(AddrSpace *spaceid) const { return vbank.beginLoc(spaceid); }

  /// \brief End of Varnodes stored in a given address space
  VarnodeLocSet::const_iterator endLoc(AddrSpace *spaceid) const { return vbank.endLoc(spaceid); }

  /// \brief Start of Varnodes at a storage address
  VarnodeLocSet::const_iterator beginLoc(const Address &addr) const { return vbank.beginLoc(addr); }

  /// \brief End of Varnodes at a storage address
  VarnodeLocSet::const_iterator endLoc(const Address &addr) const { return vbank.endLoc(addr); }

  /// \brief Start of Varnodes with given storage
  VarnodeLocSet::const_iterator beginLoc(int4 s,const Address &addr) const { return vbank.beginLoc(s,addr); }

  /// \brief End of Varnodes with given storage
  VarnodeLocSet::const_iterator endLoc(int4 s,const Address &addr) const { return vbank.endLoc(s,addr); }

  /// \brief Start of Varnodes matching storage and properties
  VarnodeLocSet::const_iterator beginLoc(int4 s,const Address &addr,uint4 fl) const { return vbank.beginLoc(s,addr,fl); }

  /// \brief End of Varnodes matching storage and properties
  VarnodeLocSet::const_iterator endLoc(int4 s,const Address &addr,uint4 fl) const { return vbank.endLoc(s,addr,fl); }

  /// \brief Start of Varnodes matching storage and definition address
  VarnodeLocSet::const_iterator beginLoc(int4 s,const Address &addr,const Address &pc,uintm uniq=~((uintm)0)) const {
    return vbank.beginLoc(s,addr,pc,uniq); }

  /// \brief End of Varnodes matching storage and definition address
  VarnodeLocSet::const_iterator endLoc(int4 s,const Address &addr,const Address &pc,uintm uniq=~((uintm)0)) const {
    return vbank.endLoc(s,addr,pc,uniq); }

  /// \brief Given start, return maximal range of overlapping Varnodes
  uint4 overlapLoc(VarnodeLocSet::const_iterator iter,vector<VarnodeLocSet::const_iterator> &bounds) const {
    return vbank.overlapLoc(iter,bounds); }

  /// \brief Start of all Varnodes sorted by definition address
  VarnodeDefSet::const_iterator beginDef(void) const { return vbank.beginDef(); }

  /// \brief End of all Varnodes sorted by definition address
  VarnodeDefSet::const_iterator endDef(void) const { return vbank.endDef(); }

  /// \brief Start of Varnodes with a given definition property
  VarnodeDefSet::const_iterator beginDef(uint4 fl) const { return vbank.beginDef(fl); }

  /// \brief End of Varnodes with a given definition property
  VarnodeDefSet::const_iterator endDef(uint4 fl) const { return vbank.endDef(fl); }

  /// \brief Start of (input or free) Varnodes at a given storage address
  VarnodeDefSet::const_iterator beginDef(uint4 fl,const Address &addr) const { return vbank.beginDef(fl,addr); }

  /// \brief End of (input or free) Varnodes at a given storage address
  VarnodeDefSet::const_iterator endDef(uint4 fl,const Address &addr) const { return vbank.endDef(fl,addr); }

  void checkForLanedRegister(int4 sz,const Address &addr);	///< Check for a potential laned register
  map<VarnodeData,const LanedRegister *>::const_iterator beginLaneAccess(void) const { return lanedMap.begin(); }	///< Beginning iterator over laned accesses
  map<VarnodeData,const LanedRegister *>::const_iterator endLaneAccess(void) const { return lanedMap.end(); }	///< Ending iterator over laned accesses
  void clearLanedAccessMap(void) { lanedMap.clear(); }	///< Clear records from the laned access list

  HighVariable *findHigh(const string &nm) const;	///< Find a high-level variable by name
  void mapGlobals(void);			///< Make sure there is a Symbol entry for all global Varnodes
  void prepareThisPointer(void);		///< Prepare for recovery of the "this" pointer
  bool checkCallDoubleUse(const PcodeOp *opmatch,const PcodeOp *op,const Varnode *vn,uint4 fl,const ParamTrial &trial) const;
  bool onlyOpUse(const Varnode *invn,const PcodeOp *opmatch,const ParamTrial &trial,uint4 mainFlags) const;
  bool ancestorOpUse(int4 maxlevel,const Varnode *invn,const PcodeOp *op,ParamTrial &trial,int4 offset,uint4 mainFlags) const;
  bool syncVarnodesWithSymbols(const ScopeLocal *lm,bool updateDatatypes,bool unmappedAliasCheck);
  void transferVarnodeProperties(Varnode *vn,Varnode *newVn,int4 lsbOffset);
  bool fillinReadOnly(Varnode *vn);		///< Replace the given Varnode with its (constant) value in the load image
  bool replaceVolatile(Varnode *vn);		///< Replace accesses of the given Varnode with \e volatile operations
  void markIndirectOnly(void);			///< Mark \e illegal \e input Varnodes used only in INDIRECTs
  void totalReplace(Varnode *vn,Varnode *newvn);
  void totalReplaceConstant(Varnode *vn,uintb val);
  ScopeLocal *getScopeLocal(void) { return localmap; }		///< Get the local function scope
  const ScopeLocal *getScopeLocal(void) const { return localmap; }	///< Get the local function scope
  FuncProto &getFuncProto(void) { return funcp; }		///< Get the function's prototype object
  const FuncProto &getFuncProto(void) const { return funcp; }	///< Get the function's prototype object
  void initActiveOutput(void);					///< Initialize \e return prototype recovery analysis
  /// \brief Clear any analysis of the function's \e return prototype
  void clearActiveOutput(void) {
    if (activeoutput != (ParamActive *)0) delete activeoutput;
    activeoutput = (ParamActive *)0;
  }
  ParamActive *getActiveOutput(void) const { return activeoutput; }	///< Get the \e return prototype recovery object
  void setHighLevel(void);					///< Turn on HighVariable objects for all Varnodes
  void clearDeadVarnodes(void);					///< Delete any dead Varnodes
  void calcNZMask(void);					///< Calculate \e non-zero masks for all Varnodes
  void clearDeadOps(void) { obank.destroyDead(); }		///< Delete any dead PcodeOps
  void remapVarnode(Varnode *vn,Symbol *sym,const Address &usepoint);
  void remapDynamicVarnode(Varnode *vn,Symbol *sym,const Address &usepoint,uint8 hash);
  void linkProtoPartial(Varnode *vn);				///< Find or create Symbol and a partial mapping
  Symbol *linkSymbol(Varnode *vn);				///< Find or create Symbol associated with given Varnode
  Symbol *linkSymbolReference(Varnode *vn);			///< Discover and attach Symbol to a constant reference
  Varnode *findLinkedVarnode(SymbolEntry *entry) const;	///< Find a Varnode matching the given Symbol mapping
  void findLinkedVarnodes(SymbolEntry *entry,vector<Varnode *> &res) const;	///< Find Varnodes that map to the given SymbolEntry
  void buildDynamicSymbol(Varnode *vn);				///< Build a \e dynamic Symbol associated with the given Varnode
  bool testForReturnAddress(Varnode *vn);	///< Test if the given Varnode is (derived from) the return address
  bool attemptDynamicMapping(SymbolEntry *entry,DynamicHash &dhash);
  bool attemptDynamicMappingLate(SymbolEntry *entry,DynamicHash &dhash);
  Merge &getMerge(void) { return covermerge; }			///< Get the Merge object for \b this function
  Varnode *getInternalString(const uint1 *buf,int4 size,Datatype *ptrType,PcodeOp *readOp);

  // op routines
  PcodeOp *newOp(int4 inputs,const Address &pc);		/// Allocate a new PcodeOp with Address
  PcodeOp *newOp(int4 inputs,const SeqNum &sq);			/// Allocate a new PcodeOp with sequence number
  PcodeOp *newOpBefore(PcodeOp *follow,OpCode opc,Varnode *in1,Varnode *in2,Varnode *in3=(Varnode *)0);
  PcodeOp *cloneOp(const PcodeOp *op,const SeqNum &seq);	/// Clone a PcodeOp into \b this function
  PcodeOp *getFirstReturnOp(void) const;			/// Find a representative CPUI_RETURN op for \b this function
  PcodeOp *newIndirectOp(PcodeOp *indeffect,const Address &addr,int4 sz,uint4 extraFlags);
  PcodeOp *newIndirectCreation(PcodeOp *indeffect,const Address &addr,int4 sz,bool possibleout);
  void markIndirectCreation(PcodeOp *indop,bool possibleOutput);	///< Convert CPUI_INDIRECT into an \e indirect \e creation
  void markReturnCopy(PcodeOp *op) { op->flags |= PcodeOp::return_copy; }	///< Mark COPY as returning a global value
  PcodeOp *findOp(const SeqNum &sq) { return obank.findOp(sq); }	///< Find PcodeOp with given sequence number
  void opInsertBefore(PcodeOp *op,PcodeOp *follow);		///< Insert given PcodeOp before a specific op
  void opInsertAfter(PcodeOp *op,PcodeOp *prev);		///< Insert given PcodeOp after a specific op
  void opInsertBegin(PcodeOp *op,BlockBasic *bl);		///< Insert given PcodeOp at the beginning of a basic block
  void opInsertEnd(PcodeOp *op,BlockBasic *bl);			///< Insert given PcodeOp at the end of a basic block

  /// \brief Moved given PcodeOp to specified point in the \e dead list
  void opDeadInsertAfter(PcodeOp *op,PcodeOp *prev) { obank.insertAfterDead(op,prev); }

  void opHeritage(void) { heritage.heritage(); }		///< Perform an entire heritage pass linking Varnode reads to writes
  void opSetOpcode(PcodeOp *op,OpCode opc);			///< Set the op-code for a specific PcodeOp
  void opMarkHalt(PcodeOp *op,uint4 flag);			///< Mark given CPUI_RETURN op as a \e special halt
  void opSetOutput(PcodeOp *op,Varnode *vn);			///< Set a specific output Varnode for the given PcodeOp
  void opUnsetOutput(PcodeOp *op);				///< Remove output Varnode from the given PcodeOp
  void opSetInput(PcodeOp *op,Varnode *vn,int4 slot);		///< Set a specific input operand for the given PcodeOp
  void opSwapInput(PcodeOp *op,int4 slot1,int4 slot2);		///< Swap two input operands in the given PcodeOp
  void opUnsetInput(PcodeOp *op,int4 slot);			///< Clear an input operand slot for the given PcodeOp
  void opInsert(PcodeOp *op,BlockBasic *bl,list<PcodeOp *>::iterator iter);
  void opUninsert(PcodeOp *op);					///< Remove the given PcodeOp from its basic block
  void opUnlink(PcodeOp *op);					///< Unset inputs/output and remove given PcodeOP from its basic block
  void opDestroy(PcodeOp *op);					///< Remove given PcodeOp and destroy its Varnode operands
  void opDestroyRecursive(PcodeOp *op,vector<PcodeOp *> &scratch);	///< Remove a PcodeOp and recursively remove ops producing its inputs
  void opDestroyRaw(PcodeOp *op);				///< Remove the given \e raw PcodeOp
  void opDeadAndGone(PcodeOp *op) { obank.destroy(op); }	///< Free resources for the given \e dead PcodeOp
  void opSetAllInput(PcodeOp *op,const vector<Varnode *> &vvec);	///< Set all input Varnodes for the given PcodeOp simultaneously
  void opRemoveInput(PcodeOp *op,int4 slot);			///< Remove a specific input slot for the given PcodeOp
  void opInsertInput(PcodeOp *op,Varnode *vn,int4 slot);	///< Insert a new Varnode into the operand list for the given PcodeOp
  void opMarkStartBasic(PcodeOp *op) { op->setFlag(PcodeOp::startbasic); }	///< Mark PcodeOp as starting a basic block
  void opMarkStartInstruction(PcodeOp *op) { op->setFlag(PcodeOp::startmark); }	///< Mark PcodeOp as starting its instruction
  void opMarkNonPrinting(PcodeOp *op) { op->setFlag(PcodeOp::nonprinting); }	///< Mark PcodeOp as not being printed
  void opMarkSpecialPrint(PcodeOp *op) { op->setAdditionalFlag(PcodeOp::special_print); }	///< Mark PcodeOp as needing special printing
  void opMarkNoCollapse(PcodeOp *op) { op->setFlag(PcodeOp::nocollapse); }	///< Mark PcodeOp as not collapsible
  void opMarkCpoolTransformed(PcodeOp *op) { op->setAdditionalFlag(PcodeOp::is_cpool_transformed); }	///< Mark cpool record was visited
  void opMarkCalculatedBool(PcodeOp *op) { op->setFlag(PcodeOp::calculated_bool); }	///< Mark PcodeOp as having boolean output
  void opMarkSpacebasePtr(PcodeOp *op) { op->setFlag(PcodeOp::spacebase_ptr); }	///< Mark PcodeOp as LOAD/STORE from spacebase ptr
  void opClearSpacebasePtr(PcodeOp *op) { op->clearFlag(PcodeOp::spacebase_ptr); }	///< Unmark PcodeOp as using spacebase ptr
  void opFlipCondition(PcodeOp *op) { op->flipFlag(PcodeOp::boolean_flip); }	///< Flip output condition of given CBRANCH
  PcodeOp *target(const Address &addr) const { return obank.target(addr); }	///< Look up a PcodeOp by an instruction Address
  Varnode *createStackRef(AddrSpace *spc,uintb off,PcodeOp *op,Varnode *stackptr,bool insertafter);
  Varnode *opStackLoad(AddrSpace *spc,uintb off,uint4 sz,PcodeOp *op,Varnode *stackptr,bool insertafter);
  PcodeOp *opStackStore(AddrSpace *spc,uintb off,PcodeOp *op,bool insertafter);
  Varnode *opBoolNegate(Varnode *vn,PcodeOp *op,bool insertafter);
  void opUndoPtradd(PcodeOp *op,bool finalize);	///< Convert a CPUI_PTRADD back into a CPUI_INT_ADD
  static int4 opFlipInPlaceTest(PcodeOp *op,vector<PcodeOp *> &fliplist);
  void opFlipInPlaceExecute(vector<PcodeOp *> &fliplist);

  /// \brief Start of PcodeOp objects with the given op-code
  list<PcodeOp *>::const_iterator beginOp(OpCode opc) const { return obank.begin(opc); }

  /// \brief End of PcodeOp objects with the given op-code
  list<PcodeOp *>::const_iterator endOp(OpCode opc) const { return obank.end(opc); }

  /// \brief Start of PcodeOp objects in the \e alive list
  list<PcodeOp *>::const_iterator beginOpAlive(void) const { return obank.beginAlive(); }

  /// \brief End of PcodeOp objects in the \e alive list
  list<PcodeOp *>::const_iterator endOpAlive(void) const { return obank.endAlive(); }

  /// \brief Start of PcodeOp objects in the \e dead list
  list<PcodeOp *>::const_iterator beginOpDead(void) const { return obank.beginDead(); }

  /// \brief End of PcodeOp objects in the \e dead list
  list<PcodeOp *>::const_iterator endOpDead(void) const { return obank.endDead(); }

  /// \brief Start of all (alive) PcodeOp objects sorted by sequence number
  PcodeOpTree::const_iterator beginOpAll(void) const { return obank.beginAll(); }

  /// \brief End of all (alive) PcodeOp objects sorted by sequence number
  PcodeOpTree::const_iterator endOpAll(void) const { return obank.endAll(); }

  /// \brief Start of all (alive) PcodeOp objects attached to a specific Address
  PcodeOpTree::const_iterator beginOp(const Address &addr) const { return obank.begin(addr); }

  /// \brief End of all (alive) PcodeOp objects attached to a specific Address
  PcodeOpTree::const_iterator endOp(const Address &addr) const { return obank.end(addr); }

  bool moveRespectingCover(PcodeOp *op,PcodeOp *lastOp);	///< Move given op past \e lastOp respecting covers if possible

  const ResolvedUnion *getUnionField(const Datatype *parent,const PcodeOp *op,int4 slot) const;
  bool setUnionField(const Datatype *parent,const PcodeOp *op,int4 slot,const ResolvedUnion &resolve);
  void forceFacingType(Datatype *parent,int4 fieldNum,PcodeOp *op,int4 slot);
  int4 inheritResolution(Datatype *parent,const PcodeOp *op,int4 slot,PcodeOp *oldOp,int4 oldSlot);

  // Jumptable routines
  JumpTable *linkJumpTable(PcodeOp *op);		///< Link jump-table with a given BRANCHIND
  JumpTable *findJumpTable(const PcodeOp *op) const;	///< Find a jump-table associated with a given BRANCHIND
  JumpTable *installJumpTable(const Address &addr);	///< Install a new jump-table for the given Address
  JumpTable *recoverJumpTable(Funcdata &partial,PcodeOp *op,FlowInfo *flow,JumpTable::RecoveryMode &mode);
  JumpTable::RecoveryMode earlyJumpTableFail(PcodeOp *op);	///< Try to determine, early, if jump-table analysis will fail
  int4 numJumpTables(void) const { return jumpvec.size(); }	///< Get the number of jump-tables for \b this function
  JumpTable *getJumpTable(int4 i) { return jumpvec[i]; }	///< Get the i-th jump-table
  void removeJumpTable(JumpTable *jt);			///< Remove/delete the given jump-table

  // Block routines
  BlockGraph &getStructure(void) { return sblocks; } 	///< Get the current control-flow structuring hierarchy
  const BlockGraph &getStructure(void) const { return sblocks; }	///< Get the current control-flow structuring hierarchy
  const BlockGraph &getBasicBlocks(void) const { return bblocks; }	///< Get the basic blocks container

  /// \brief Set the initial ownership range for the given basic block
  ///
  /// \param bb is the given basic block
  /// \param beg is the beginning Address of the owned code range
  /// \param end is the ending Address of the owned code range
  void setBasicBlockRange(BlockBasic *bb,const Address &beg,const Address &end) { bb->setInitialRange(beg, end); }

  void removeDoNothingBlock(BlockBasic *bb);	///< Remove a basic block from control-flow that performs no operations
  bool removeUnreachableBlocks(bool issuewarning,bool checkexistence);
  void pushBranch(BlockBasic *bb,int4 slot,BlockBasic *bbnew);
  void removeBranch(BlockBasic *bb,int4 num);	///< Remove the indicated branch from a basic block
  BlockBasic *nodeJoinCreateBlock(BlockBasic *block1,BlockBasic *block2,BlockBasic *exita,BlockBasic *exitb,
				  bool fora_block1ishigh,bool forb_block1ishigh,const Address &addr);
  void nodeSplit(BlockBasic *b,int4 inedge);
  bool forceGoto(const Address &pcop,const Address &pcdest);
  void removeFromFlowSplit(BlockBasic *bl,bool swap);
  void switchEdge(FlowBlock *inblock,BlockBasic *outbefore,FlowBlock *outafter);
  void spliceBlockBasic(BlockBasic *bl);	///< Merge the given basic block with the block it flows into
  void installSwitchDefaults(void);		///< Make sure default switch cases are properly labeled
  bool replaceLessequal(PcodeOp *op);		///< Replace INT_LESSEQUAL and INT_SLESSEQUAL expressions
  bool distributeIntMultAdd(PcodeOp *op);	///< Distribute constant coefficient to additive input
  bool collapseIntMultMult(Varnode *vn);	///< Collapse constant coefficients for two chained CPUI_INT_MULT
  Varnode *buildCopyTemp(Varnode *vn,PcodeOp *point);	///< Create a COPY of given Varnode in a temporary register

  static PcodeOp *cseFindInBlock(PcodeOp *op,Varnode *vn,BlockBasic *bl,PcodeOp *earliest);
  PcodeOp *cseElimination(PcodeOp *op1,PcodeOp *op2);
  void cseEliminateList(vector< pair<uintm,PcodeOp *> > &list,vector<Varnode *> &outlist);
  static bool compareCallspecs(const FuncCallSpecs *a,const FuncCallSpecs *b);

#ifdef OPACTION_DEBUG
  void (*jtcallback)(Funcdata &orig,Funcdata &fd);	///< Hook point debugging the jump-table simplification process
  vector<PcodeOp *> modify_list;		///< List of modified ops
  vector<string> modify_before;			///< List of "before" strings for modified ops
  int4 opactdbg_count;				///< Number of debug statements printed
  int4 opactdbg_breakcount;			///< Which debug to break on
  bool opactdbg_on;				///< Are we currently doing op action debugs
  bool opactdbg_active;				///< \b true if current op mods should be recorded
  bool opactdbg_breakon;			///< Has a breakpoint been hit
  vector<Address> opactdbg_pclow;		///< Lower bounds on the PC register
  vector<Address> opactdbg_pchigh;		///< Upper bounds on the PC register
  vector<uintm> opactdbg_uqlow;			///< Lower bounds on the unique register
  vector<uintm> opactdbg_uqhigh;		///< Upper bounds on the unique register
  void enableJTCallback(void (*jtcb)(Funcdata &orig,Funcdata &fd)) { jtcallback = jtcb; }	///< Enable a debug callback
  void disableJTCallback(void) { jtcallback = (void (*)(Funcdata &orig,Funcdata &fd))0; }	///< Disable debug callback
  void debugActivate(void) { if (opactdbg_on) opactdbg_active=true; }	///< Turn on recording
  void debugDeactivate(void) { opactdbg_active = false; }		///< Turn off recording
  void debugModCheck(PcodeOp *op);		///< Cache \e before state of the given PcodeOp
  void debugModClear(void);			///< Abandon printing debug for current action
  void debugModPrint(const string &actionname);	///< Print before and after strings for PcodeOps modified by given action
  bool debugBreak(void) const { return opactdbg_on&&opactdbg_breakon; }	///< Has a breakpoint been hit
  int4 debugSize(void) const { return opactdbg_pclow.size(); }	///< Number of code ranges being debug traced
  void debugEnable(void) { opactdbg_on = true; opactdbg_count = 0; }	///< Turn on debugging
  void debugDisable(void) { opactdbg_on = false; }	///< Turn off debugging
  void debugClear(void) {
    opactdbg_pclow.clear(); opactdbg_pchigh.clear(); opactdbg_uqlow.clear(); opactdbg_uqhigh.clear(); }	///< Clear debugging ranges
  bool debugCheckRange(PcodeOp *op);		///< Check if the given PcodeOp is being debug traced
  void debugSetRange(const Address &pclow,const Address &pchigh,
			 uintm uqlow=~((uintm)0),uintm uqhigh=~((uintm)0));	///< Add a new memory range to the debug trace
  void debugHandleBreak(void) { opactdbg_breakon = false; }		///< Mark a breakpoint as handled
  void debugSetBreak(int4 count) { opactdbg_breakcount = count; }	///< Break on a specific trace hit count
  void debugPrintRange(int4 i) const;		///< Print the i-th debug trace range
#endif
};

/// \brief A p-code emitter for building PcodeOp objects
///
/// The emitter is attached to a specific Funcdata object.  Any p-code generated (by FlowInfo typically)
/// will be instantiated as PcodeOp and Varnode objects and placed in the Funcdata \e dead list.
class PcodeEmitFd : public PcodeEmit {
  Funcdata *fd;			///< The Funcdata container to emit to
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize);
public:
  void setFuncdata(Funcdata *f) { fd = f; }	///< Establish the container for \b this emitter
};

/// \brief Control the cloning of PcodeOps from within a basic block into another block
///
/// Used for splitting control-flow at a merge point.  Can duplicate either a whole basic block, or an expression
/// subset within a basic block.
class CloneBlockOps {
  /// \brief Helper class for pairing a p-code op with its clone
  struct ClonePair {
    PcodeOp *cloneOp;		///< New cloned op
    PcodeOp *origOp;		///< Original op that was cloned
    ClonePair(PcodeOp *c,PcodeOp *o) { cloneOp = c; origOp = o; }	///< Constructor
  };
  Funcdata &data;		///< Function containing ops to clone
  vector<ClonePair> cloneList;	///< List of cloned ops
  map<PcodeOp *,PcodeOp *> origToClone;	///< Map from original p-code op to its clone
  PcodeOp *buildOpClone(PcodeOp *op);	///< Produce a skeleton copy of the given PcodeOp
  void buildVarnodeOutput(PcodeOp *origOp,PcodeOp *cloneOp);	///< Clone the output Varnode of the given op onto its clone
  void patchInputs(int4 inedge);				///< Set the input Varnodes of all cloned ops
public:
  CloneBlockOps(Funcdata &fd) : data(fd) {}	///< Constructor
  void cloneBlock(BlockBasic *b,BlockBasic *bprime,int4 inedge);	///< Clone all p-code ops from a block into its copy
  Varnode *cloneExpression(vector<PcodeOp *> &ops,PcodeOp *followOp);	///< Clone p-code ops in an expression
};

/// \brief Helper class for determining if Varnodes can trace their value from a legitimate source
///
/// Try to determine if a Varnode (expressed as a particular input to a CALL, CALLIND, or RETURN op)
/// makes sense as parameter passing (or return value) storage by examining the Varnode's ancestors.
/// If it has ancestors that are \e unaffected, \e abnormal inputs, or \e killedbycall, then this is a sign
/// that the Varnode doesn't make a good parameter.
class AncestorRealistic {
  /// \brief Node in a depth first traversal of ancestors
  class State {
  public:
    enum {
      seen_solid0 = 1,		///< Indicates a \e solid movement into the Varnode occurred on at least one path to MULTIEQUAL
      seen_solid1 = 2,		///< Indicates a \e solid movement into anything other than slot 0 occurred.
      seen_kill = 4		///< Indicates the Varnode is killed by a call on at least path to MULTIEQUAL
    };
    PcodeOp *op;		///< Operation along the path to the Varnode
    int4 slot;			///< vn = op->getIn(slot)
    uint4 flags;		///< Boolean properties of the node
    int4 offset;		///< Offset of the (eventual) trial value, within a possibly larger register

    /// \brief Constructor given a Varnode read
    ///
    /// \param o is the PcodeOp reading the Varnode
    /// \param s is the input slot
    State(PcodeOp *o,int4 s) {
      op = o;
      slot = s;
      flags = 0;
      offset = 0;
    }

    /// \brief Constructor from old state pulled back through a CPUI_SUBPIECE
    ///
    /// Data ultimately in SUBPIECE output is copied from a non-zero offset within the input Varnode. Note this offset
    /// \param o is the CPUI_SUBPIECE
    /// \param oldState is the old state being pulled back from
    State(PcodeOp *o,const State &oldState) {
      op = o;
      slot = 0;
      flags = 0;
      offset = oldState.offset + (int4)op->getIn(1)->getOffset();
    }
    int4 getSolidSlot(void) const { return ((flags & seen_solid0)!=0) ? 0 : 1; }	///< Get slot associated with \e solid movement
    void markSolid(int4 s) { flags |= (s==0) ? seen_solid0 : seen_solid1; }		///< Mark given slot as having \e solid movement
    void markKill(void) { flags |= seen_kill; }						///< Mark \e killedbycall seen
    bool seenSolid(void) const { return ((flags & (seen_solid0|seen_solid1))!=0); }	///< Has \e solid movement been seen
    bool seenKill(void) const { return ((flags & seen_kill)!=0); }			///< Has \e killedbycall been seen
  };
  /// \brief Enumerations for state of depth first traversal
  enum {
    enter_node,		///< Extending path into new Varnode
    pop_success,	///< Backtracking, from path that contained a reasonable ancestor
    pop_solid,		///< Backtracking, from path with successful, solid, movement, via COPY, LOAD, or other arith/logical
    pop_fail,		///< Backtracking, from path with a bad ancestor
    pop_failkill	///< Backtracking, from path with a bad ancestor, specifically killedbycall
  };
  ParamTrial *trial;			///< Current trial being analyzed for suitability
  vector<State> stateStack;		///< Holds the depth-first traversal stack
  vector<const Varnode *> markedVn;	///< Holds visited Varnodes to properly trim cycles
  int4 multiDepth;			///< Number of MULTIEQUAL ops along current traversal path
  bool allowFailingPath;		///< True if we allow and test for failing paths due to conditional execution

  /// \brief Mark given Varnode is visited by the traversal
  ///
  /// \param vn is the given Varnode
  void mark(Varnode *vn) {
    markedVn.push_back(vn);
    vn->setMark();
  }

  int4 enterNode(void);				///< Traverse into a new Varnode
  int4 uponPop(int4 command);			///< Pop a Varnode from the traversal stack
  bool checkConditionalExe(State &state);	///< Check if current Varnode produced by conditional flow
public:
  bool execute(PcodeOp *op,int4 slot,ParamTrial *t,bool allowFail);
};

} // End namespace ghidra
#endif

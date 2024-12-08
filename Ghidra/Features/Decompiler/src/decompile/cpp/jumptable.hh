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
/// \file jumptable.hh
/// \brief Classes to support jump-tables and their recovery

#ifndef __JUMPTABLE_HH__
#define __JUMPTABLE_HH__

#include "emulateutil.hh"
#include "rangeutil.hh"

namespace ghidra {

class EmulateFunction;

extern AttributeId ATTRIB_LABEL;	///< Marshaling attribute "label"
extern AttributeId ATTRIB_NUM;		///< Marshaling attribute "num"

extern ElementId ELEM_BASICOVERRIDE;	///< Marshaling element \<basicoverride>
extern ElementId ELEM_DEST;		///< Marshaling element \<dest>
extern ElementId ELEM_JUMPTABLE;	///< Marshaling element \<jumptable>
extern ElementId ELEM_LOADTABLE;	///< Marshaling element \<loadtable>
extern ElementId ELEM_NORMADDR;		///< Marshaling element \<normaddr>
extern ElementId ELEM_NORMHASH;		///< Marshaling element \<normhash>
extern ElementId ELEM_STARTVAL;		///< Marshaling element \<startval>

/// \brief Exception thrown for a thunk mechanism that looks like a jump-table
struct JumptableThunkError : public LowlevelError {
  JumptableThunkError(const string &s) : LowlevelError(s) {}	///< Construct with an explanatory string
};

/// \brief A description where and how data was loaded from memory
///
/// This is a generic table description, giving the starting address
/// of the table, the size of an entry, and number of entries.
class LoadTable {
  friend class EmulateFunction;
  Address addr;			///< Starting address of table
  int4 size;			///< Size of table entry
  int4 num;			///< Number of entries in table;
public:
  LoadTable(void) {}		// Constructor for use with decode
  LoadTable(const Address &ad,int4 sz) { addr = ad, size = sz; num = 1; }	///< Constructor for a single entry table
  LoadTable(const Address &ad,int4 sz,int4 nm) { addr = ad; size = sz; num = nm; }	///< Construct a full table
  bool operator<(const LoadTable &op2) const { return (addr < op2.addr); }	///< Compare \b this with another table by address
  void encode(Encoder &encoder) const;				///< Encode a description of \b this as an \<loadtable> element
  void decode(Decoder &decoder);				///< Decode \b this table from a \<loadtable> element
  static void collapseTable(vector<LoadTable> &table);		///< Collapse a sequence of table descriptions
};

/// \brief All paths from a (putative) switch variable to the CPUI_BRANCHIND
///
/// This is a container for intersecting paths during the construction of a
/// JumpModel.  It contains every PcodeOp from some starting Varnode through
/// all paths to a specific BRANCHIND.  The paths can split and rejoin. This also
/// keeps track of Varnodes that are present on \e all paths, as these are the
/// potential switch variables for the model.
class PathMeld {

  /// \brief A PcodeOp in the path set associated with the last Varnode in the intersection
  ///
  /// This links a PcodeOp to the point where the flow path to it split from common path
  struct RootedOp {
    PcodeOp *op;	///< An op in the container
    int4 rootVn;	///< The index, within commonVn, of the Varnode at the split point
    RootedOp(PcodeOp *o,int4 root) { op = o; rootVn = root; }	///< Constructor
  };
  vector<Varnode *> commonVn;		///< Varnodes in common with all paths
  vector<RootedOp> opMeld;		///< All the ops for the melded paths
  void internalIntersect(vector<int4> &parentMap);
  int4 meldOps(const vector<PcodeOpNode> &path,int4 cutOff,const vector<int4> &parentMap);
  void truncatePaths(int4 cutPoint);
public:
  void set(const PathMeld &op2);	///< Copy paths from another container
  void set(const vector<PcodeOpNode> &path);	///< Initialize \b this to be a single path
  void set(PcodeOp *op,Varnode *vn);	///< Initialize \b this container to a single node "path"
  void append(const PathMeld &op2);	///< Append a new set of paths to \b this set of paths
  void clear(void);			///< Clear \b this to be an empty container
  void meld(vector<PcodeOpNode> &path);	///< Meld a new path into \b this container
  void markPaths(bool val,int4 startVarnode);			///< Mark PcodeOps paths from the given start
  int4 numCommonVarnode(void) const { return commonVn.size(); }	///< Return the number of Varnodes common to all paths
  int4 numOps(void) const { return opMeld.size(); }		///< Return the number of PcodeOps across all paths
  Varnode *getVarnode(int4 i) const { return commonVn[i]; }	///< Get the i-th common Varnode
  Varnode *getOpParent(int4 i) const { return commonVn[ opMeld[i].rootVn ]; }	///< Get the split-point for the i-th PcodeOp
  PcodeOp *getOp(int4 i) const { return opMeld[i].op; }		///< Get the i-th PcodeOp
  PcodeOp *getEarliestOp(int4 pos) const;		///< Find \e earliest PcodeOp that has a specific common Varnode as input
  bool empty(void) const { return commonVn.empty(); }	///< Return \b true if \b this container holds no paths
};

/// \brief A light-weight emulator to calculate switch targets from switch variables
///
/// We assume we only have to store memory state for individual Varnodes and that dynamic
/// LOADs are resolved from the LoadImage. BRANCH and CBRANCH emulation will fail, there can
/// only be one execution path, although there can be multiple data-flow paths.
class EmulateFunction : public EmulatePcodeOp {
  Funcdata *fd;				///< The function being emulated
  map<Varnode *,uintb> varnodeMap;	///< Light-weight memory state based on Varnodes
  vector<LoadTable> *loadpoints;	///< The set of collected LOAD records (if non-null)
  virtual void executeLoad(void);
  virtual void executeBranch(void);
  virtual void executeBranchind(void);
  virtual void executeCall(void);
  virtual void executeCallind(void);
  virtual void executeCallother(void);
  virtual void fallthruOp(void);
public:
  EmulateFunction(Funcdata *f);		///< Constructor
  void setLoadCollect(vector<LoadTable> *val) { loadpoints = val; }	///< Set where/if we collect LOAD information
  virtual void setExecuteAddress(const Address &addr);
  virtual uintb getVarnodeValue(Varnode *vn) const;
  virtual void setVarnodeValue(Varnode *vn,uintb val);
  uintb emulatePath(uintb val,const PathMeld &pathMeld,PcodeOp *startop,Varnode *startvn);
};

class FlowInfo;
class JumpTable;

/// \brief A (putative) switch variable Varnode and a constraint imposed by a CBRANCH
///
/// The record constrains a specific Varnode.  If the associated CBRANCH is followed
/// along the path that reaches the switch's BRANCHIND, then we have an explicit
/// description of the possible values the Varnode can hold.
class GuardRecord {
  PcodeOp *cbranch;		///< PcodeOp CBRANCH the branches around the switch
  PcodeOp *readOp;		///< The immediate PcodeOp causing the restriction
  Varnode *vn;			///< The Varnode being restricted
  Varnode *baseVn;		///< Value being (quasi)copied to the Varnode
  int4 indpath;			///< Specific CBRANCH path going to the switch
  int4 bitsPreserved;		///< Number of bits copied (all other bits are zero)
  CircleRange range;		///< Range of values causing the CBRANCH to take the path to the switch
  bool unrolled;		///< \b true if guarding CBRANCH is duplicated across multiple blocks
public:
  GuardRecord(PcodeOp *bOp,PcodeOp *rOp,int4 path,const CircleRange &rng,Varnode *v,bool unr=false);	///< Constructor
  bool isUnrolled(void) const { return unrolled; }	///< Is \b this guard duplicated across multiple blocks
  PcodeOp *getBranch(void) const { return cbranch; }	///< Get the CBRANCH associated with \b this guard
  PcodeOp *getReadOp(void) const { return readOp; }	///< Get the PcodeOp immediately causing the restriction
  int4 getPath(void) const { return indpath; }		///< Get the specific path index going towards the switch
  const CircleRange &getRange(void) const { return range; }	///< Get the range of values causing the switch path to be taken
  void clear(void) { cbranch = (PcodeOp *)0; }		///< Mark \b this guard as unused
  int4 valueMatch(Varnode *vn2,Varnode *baseVn2,int4 bitsPreserved2) const;
  static int4 oneOffMatch(PcodeOp *op1,PcodeOp *op2);
  static Varnode *quasiCopy(Varnode *vn,int4 &bitsPreserved);
};

/// \brief An iterator over values a switch variable can take
///
/// This iterator is intended to provide the start value for emulation
/// of a jump-table model to obtain the associated jump-table destination.
/// Each value can be associated with a starting Varnode and PcodeOp in
/// the function being emulated, via getStartVarnode() and getStartOp().
class JumpValues {
public:
  virtual ~JumpValues(void) {}
  virtual void truncate(int4 nm)=0;	///< Truncate the number of values to the given number
  virtual uintb getSize(void) const=0;	///< Return the number of values the variables can take
  virtual bool contains(uintb val) const=0;	///< Return \b true if the given value is in the set of possible values

  /// \brief Initialize \b this for iterating over the set of possible values
  ///
  /// \return \b true if there are any values to iterate over
  virtual bool initializeForReading(void) const=0;

  virtual bool next(void) const=0;		///< Advance the iterator, return \b true if there is another value
  virtual uintb getValue(void) const=0;		///< Get the current value
  virtual Varnode *getStartVarnode(void) const=0;	///< Get the Varnode associated with the current value
  virtual PcodeOp *getStartOp(void) const=0;		///< Get the PcodeOp associated with the current value
  virtual bool isReversible(void) const=0;	///< Return \b true if the current value can be reversed to get a label
  virtual JumpValues *clone(void) const=0;	///< Clone \b this iterator
  static const uint8 NO_LABEL;			///< Jump-table label reserved to indicate \e no \e label
};

/// \brief single entry switch variable that can take a range of values
class JumpValuesRange : public JumpValues {
protected:
  CircleRange range;		///< Acceptable range of values for the normalized switch variable
  Varnode *normqvn;		///< Varnode representing the normalized switch variable
  PcodeOp *startop;		///< First PcodeOp in the jump-table calculation
  mutable uintb curval;		///< The current value pointed to be the iterator
public:
  void setRange(const CircleRange &rng) { range = rng; }	///< Set the range of values explicitly
  void setStartVn(Varnode *vn) { normqvn = vn; }		///< Set the normalized switch Varnode explicitly
  void setStartOp(PcodeOp *op) { startop = op; }		///< Set the starting PcodeOp explicitly
  virtual void truncate(int4 nm);
  virtual uintb getSize(void) const;
  virtual bool contains(uintb val) const;
  virtual bool initializeForReading(void) const;
  virtual bool next(void) const;
  virtual uintb getValue(void) const;
  virtual Varnode *getStartVarnode(void) const;
  virtual PcodeOp *getStartOp(void) const;
  virtual bool isReversible(void) const { return true; }
  virtual JumpValues *clone(void) const;
};

/// \brief A jump-table starting range with two possible execution paths
///
/// This extends the basic JumpValuesRange having a single entry switch variable and
/// adds a second entry point that takes only a single value. This value comes last in the iteration.
class JumpValuesRangeDefault : public JumpValuesRange {
  uintb extravalue;		///< The extra value
  Varnode *extravn;		///< The starting Varnode associated with the extra value
  PcodeOp *extraop;		///< The starting PcodeOp associated with the extra value
  mutable bool lastvalue;	///< \b true if the extra value has been visited by the iterator
public:
  void setExtraValue(uintb val) { extravalue = val; }	///< Set the extra value explicitly
  void setDefaultVn(Varnode *vn) { extravn = vn; }	///< Set the associated start Varnode
  void setDefaultOp(PcodeOp *op) { extraop = op; }	///< Set the associated start PcodeOp
  virtual uintb getSize(void) const;
  virtual bool contains(uintb val) const;
  virtual bool initializeForReading(void) const;
  virtual bool next(void) const;
  virtual Varnode *getStartVarnode(void) const;
  virtual PcodeOp *getStartOp(void) const;
  virtual bool isReversible(void) const { return !lastvalue; }	// The -extravalue- is not reversible
  virtual JumpValues *clone(void) const;
};

/// \brief A jump-table execution model
///
/// This class holds details of the model and recovers these details in various stages.
/// The model concepts include:
///   - Address Table, the set of destination addresses the jump-table can produce.
///   - Normalized Switch Variable, the Varnode with the most restricted set of values used
///       by the model to produce the destination addresses.
///   - Unnormalized Switch Variable, the Varnode being switched on, as seen in the decompiler output.
///   - Case labels, switch variable values associated with specific destination addresses.
///   - Guards, CBRANCH ops that enforce the normalized switch variable's value range.
class JumpModel {
protected:
  JumpTable *jumptable;		///< The jump-table that is building \b this model
public:
  JumpModel(JumpTable *jt) { jumptable = jt; }	///< Construct given a parent jump-table
  virtual ~JumpModel(void) {}			///< Destructor
  virtual bool isOverride(void) const=0;	///< Return \b true if \b this model was manually overridden
  virtual int4 getTableSize(void) const=0;	///< Return the number of entries in the address table

  /// \brief Attempt to recover details of the model, given a specific BRANCHIND
  ///
  /// This generally recovers the normalized switch variable and any guards.
  /// \param fd is the function containing the switch
  /// \param indop is the given BRANCHIND
  /// \param matchsize is the expected number of address table entries to recover, or 0 for no expectation
  /// \param maxtablesize is maximum number of address table entries to allow in the model
  /// \return \b true if details of the model were successfully recovered
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)=0;

  /// \brief Construct the explicit list of target addresses (the Address Table) from \b this model
  ///
  /// The addresses produced all come from the BRANCHIND and may not be deduped. Alternate guard
  /// destinations are not yet included.
  /// \param fd is the function containing the switch
  /// \param indop is the root BRANCHIND of the switch
  /// \param addresstable will hold the list of Addresses
  /// \param loadpoints if non-null will hold LOAD table information used by the model
  /// \param loadcounts if non-null will hold number of LOADs per switch value
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			      vector<LoadTable> *loadpoints,vector<int4> *loadcounts) const=0;

  /// \brief Recover the unnormalized switch variable
  ///
  /// The normalized switch variable must already be recovered. The amount of normalization between
  /// the two switch variables can be restricted.
  /// \param maxaddsub is a restriction on arithmetic operations
  /// \param maxleftright is a restriction on shift operations
  /// \param maxext is a restriction on extension operations
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)=0;

  /// \brief Recover \e case labels associated with the Address table
  ///
  /// The unnormalized switch variable must already be recovered.  Values that the normalized
  /// switch value can hold or walked back to obtain the value that the unnormalized switch
  /// variable would hold. Labels are returned in the order provided by normalized switch
  /// variable iterator JumpValues.
  /// \param fd is the function containing the switch
  /// \param addresstable is the address table (used to label code blocks with bad or missing labels)
  /// \param label will hold recovered labels in JumpValues order
  /// \param orig is the JumpModel to use for the JumpValues iterator
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const=0;

  /// \brief Do normalization of the given switch specific to \b this model.
  ///
  /// The PcodeOp machinery is removed so it looks like the CPUI_BRANCHIND simply takes the
  /// switch variable as an input Varnode and automatically interprets its values to reach
  /// the correct destination.
  /// \param fd is the function containing the switch
  /// \param indop is the given switch as a CPUI_BRANCHIND
  /// \return the Varnode holding the final unnormalized switch variable
  virtual Varnode *foldInNormalization(Funcdata *fd,PcodeOp *indop)=0;

  /// \brief Eliminate any \e guard code involved in computing the switch destination
  ///
  /// We now think of the BRANCHIND as encompassing any guard function.
  /// \param fd is the function containing the switch
  /// \param jump is the JumpTable owning \b this model.
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump)=0;

  /// \brief Perform a sanity check on recovered addresses
  ///
  /// Individual addresses are checked against the function or its program to determine
  /// if they are reasonable. This method can optionally remove addresses from the table.
  /// If it does so, the underlying model is changed to reflect the removal.
  /// Passing in \b loadcounts indicates that LOAD addresses were collected in \b loadpoints,
  /// which may need to have elements removed as well.
  /// \param fd is the function containing the switch
  /// \param indop is the root BRANCHIND of the switch
  /// \param addresstable is the list of recovered Addresses, which may be modified
  /// \param loadpoints are any LOAD addresses associated with the table
  /// \param loadcounts (if non-null) associates each switch value with the count of LOADs used
  /// \return \b true if there are (at least some) reasonable addresses in the table
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			   vector<LoadTable> &loadpoints,vector<int4> *loadcounts)=0;

  virtual JumpModel *clone(JumpTable *jt) const=0;	///< Clone \b this model

  /// \brief Clear any non-permanent aspects of the model
  virtual void clear(void) {}

  /// \brief Encode \b this model to a stream
  ///
  /// \param encoder is the stream encoder
  virtual void encode(Encoder &encoder) const {}

  /// \brief Decode \b this model from a stream
  ///
  /// \param decoder is the stream decoder
  virtual void decode(Decoder &decoder) {}
};

/// \brief A trivial jump-table model, where the BRANCHIND input Varnode is the switch variable
///
/// This class treats the input Varnode to the BRANCHIND as the switch variable, and recovers
/// its possible values from the existing block structure. This is used when the flow following
/// fork recovers destination addresses, but the switch normalization action is unable to recover
/// the model.
class JumpModelTrivial : public JumpModel {
  uint4 size;			///< Number of addresses in the table as reported by the JumpTable
public:
  JumpModelTrivial(JumpTable *jt) : JumpModel(jt) { size = 0; }	///< Construct given a parent JumpTable
  virtual bool isOverride(void) const { return false; }
  virtual int4 getTableSize(void) const { return size; }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			      vector<LoadTable> *loadpoints,vector<int4> *loadcounts) const;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext) {}
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  virtual Varnode *foldInNormalization(Funcdata *fd,PcodeOp *indop) { return (Varnode *)0; }
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump) { return false; }
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			   vector<LoadTable> &loadpoints,vector<int4> *loadcounts) { return true; }
  virtual JumpModel *clone(JumpTable *jt) const;
};

/// \brief The basic switch model
///
/// This is the most common model:
///   - A straight-line calculation from switch variable to BRANCHIND
///   - The switch variable is bounded by one or more \e guards that branch around the BRANCHIND
///   - The unnormalized switch variable is recovered from the normalized variable through some basic transforms
class JumpBasic : public JumpModel {
protected:
  JumpValuesRange *jrange;		///< Range of values for the (normalized) switch variable
  PathMeld pathMeld;			///< Set of PcodeOps and Varnodes producing the final target addresses
  vector<GuardRecord> selectguards;	///< Any guards associated with \b model
  int4 varnodeIndex;			///< Position of the normalized switch Varnode within PathMeld
  Varnode *normalvn;			///< Normalized switch Varnode
  Varnode *switchvn;			///< Unnormalized switch Varnode
  static bool isprune(Varnode *vn);	///< Do we prune in here in our depth-first search for the normalized switch variable
  static bool ispoint(Varnode *vn);	///< Is it possible for the given Varnode to be a switch variable?
  static int4 getStride(Varnode *vn);	///< Get the step/stride associated with the Varnode
  static uintb backup2Switch(Funcdata *fd,uintb output,Varnode *outvn,Varnode *invn);
  static uintb getMaxValue(Varnode *vn);	///< Get maximum value associated with the given Varnode
  void findDeterminingVarnodes(PcodeOp *op,int4 slot);
  void analyzeGuards(BlockBasic *bl,int4 pathout);
  void calcRange(Varnode *vn,CircleRange &rng) const;
  void findSmallestNormal(uint4 matchsize);
  void findNormalized(Funcdata *fd,BlockBasic *rootbl,int4 pathout,uint4 matchsize,uint4 maxtablesize);
  void markFoldableGuards();
  void markModel(bool val);		///< Mark (or unmark) all PcodeOps involved in the model
  bool flowsOnlyToModel(Varnode *vn,PcodeOp *trailOp);	///< Check if the given Varnode flows to anything other than \b this model
  bool checkCommonCbranch(vector<Varnode *> &varArray,BlockBasic *bl);	///< Check that all incoming blocks end with a CBRANCH
  void checkUnrolledGuard(BlockBasic *bl,int4 maxpullback,bool usenzmask);

  /// \brief Eliminate the given guard to \b this switch
  ///
  /// We \e disarm the guard instructions by making the guard condition
  /// always \b false.  If the simplification removes the unusable branches,
  /// we are left with only one path through the switch.
  /// \param fd is the function containing the switch
  /// \param guard is a description of the particular guard mechanism
  /// \param jump is the JumpTable owning \b this model
  /// \return \b true if a change was made to data-flow
  virtual bool foldInOneGuard(Funcdata *fd,GuardRecord &guard,JumpTable *jump);
public:
  JumpBasic(JumpTable *jt) : JumpModel(jt) { jrange = (JumpValuesRange *)0; }	///< Construct given a parent JumpTable
  const PathMeld &getPathMeld(void) const { return pathMeld; }		///< Get the possible of paths to the switch
  const JumpValuesRange *getValueRange(void) const { return jrange; }	///< Get the normalized value iterator
  virtual ~JumpBasic(void);
  virtual bool isOverride(void) const { return false; }
  virtual int4 getTableSize(void) const { return jrange->getSize(); }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			      vector<LoadTable> *loadpoints,vector<int4> *loadcounts) const;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext);
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  virtual Varnode *foldInNormalization(Funcdata *fd,PcodeOp *indop);
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump);
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			   vector<LoadTable> &loadpoints,vector<int4> *loadcounts);
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void);
};

/// \brief A basic jump-table model with an added default address path
///
/// This model expects two paths to the switch, 1 from a default value, 1 from the other values that hit the switch
/// If A is the guarding control-flow block, C is the block setting the default value, and S the switch block itself,
/// We expect one of the following situations:
///   - A -> C or S  and  C -> S
///   - A -> C or D  and  C -> S  D -> S
///   - C -> S and S -> A   A -> S or "out of loop", i.e. S is in a loop, and the guard block doubles as the loop condition
///
/// This builds on the analysis performed for JumpBasic, which fails because there are too many paths
/// to the BRANCHIND, preventing the guards from being interpreted properly.  This class expects to reuse
/// the PathMeld calculation from JumpBasic.
class JumpBasic2 : public JumpBasic {
  Varnode *extravn;		///< The extra Varnode holding the default value
  PathMeld origPathMeld;	///< The set of paths that produce non-default addresses
  bool checkNormalDominance(void) const;
  virtual bool foldInOneGuard(Funcdata *fd,GuardRecord &guard,JumpTable *jump);
public:
  JumpBasic2(JumpTable *jt) : JumpBasic(jt) {}	///< Constructor
  void initializeStart(const PathMeld &pMeld);	///< Pass in the prior PathMeld calculation
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext);
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void);
};

/// \brief A basic jump-table model incorporating manual override information
///
/// The list of potential target addresses produced by the BRANCHIND is not recovered by \b this
/// model, but must provided explicitly via setAddresses().
/// The model tries to repurpose some of the analysis that JumpBasic does to recover the switch variable.
/// But it will revert to the trivial model if it can't find a suitable switch variable.
class JumpBasicOverride : public JumpBasic {
  set<Address> adset;		///< Absolute address table (manually specified)
  vector<uintb> values;		///< Normalized switch variable values associated with addresses
  vector<Address> addrtable;	///< Address associated with each value
  uintb startingvalue;		///< Possible start for guessing values that match addresses
  Address normaddress;		///< Dynamic info for recovering normalized switch variable
  uint8 hash;			///< if (hash==0) there is no normalized switch (use trivial model)
  bool istrivial;		///< \b true if we use a trivial value model
  int4 findStartOp(Varnode *vn);
  int4 trialNorm(Funcdata *fd,Varnode *trialvn,uint4 tolerance);
  void setupTrivial(void);
  Varnode *findLikelyNorm(void);
  void clearCopySpecific(void);
public:
  JumpBasicOverride(JumpTable *jt);		///< Constructor
  void setAddresses(const vector<Address> &adtable);	///< Manually set the address table for \b this model
  void setNorm(const Address &addr,uintb h) { normaddress = addr; hash = h; }	///< Set the normalized switch variable
  void setStartingValue(uintb val) { startingvalue = val; }		///< Set the starting value for the normalized range
  virtual bool isOverride(void) const { return true; }
  virtual int4 getTableSize(void) const { return addrtable.size(); }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			      vector<LoadTable> *loadpoints,vector<int4> *loadcounts) const;
  // findUnnormalized inherited from JumpBasic
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  // foldInNormalization inherited from JumpBasic
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump) { return false; }
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			   vector<LoadTable> &loadpoints,vector<int4> *loadcounts) { return true; }
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void);
  virtual void encode(Encoder &encoder) const;
  virtual void decode(Decoder &decoder);
};

class JumpAssistOp;

/// \brief A jump-table model assisted by pseudo-op directives in the code
///
/// This model looks for a special \e jumpassist pseudo-op near the branch site, which contains
/// p-code models describing how to parse a jump-table for case labels and addresses.
/// It views the switch table calculation as a two-stage process:
///    - case2index:    convert the switchvar to an index into a table
///    - index2address: convert the index to an address
///
/// The pseudo-op holds:
///    - the table address, size (number of indices)
///    - exemplar p-code for inverting the case2index part of the calculation
///    - exemplar p-code for calculating index2address
class JumpAssisted : public JumpModel {
  PcodeOp *assistOp;		///< The \e jumpassist PcodeOp
  JumpAssistOp *userop;		///< The \e jumpassist p-code models
  int4 sizeIndices;		///< Total number of indices in the table (not including the defaultaddress)
  Varnode *switchvn;		///< The switch variable
public:
  JumpAssisted(JumpTable *jt) : JumpModel(jt) { assistOp = (PcodeOp *)0; switchvn = (Varnode *)0; sizeIndices=0; }	///< Constructor
//  virtual ~JumpAssisted(void);
  virtual bool isOverride(void) const { return false; }
  virtual int4 getTableSize(void) const { return sizeIndices+1; }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			      vector<LoadTable> *loadpoints,vector<int4> *loadcounts) const;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext) {}
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  virtual Varnode *foldInNormalization(Funcdata *fd,PcodeOp *indop);
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump);
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,
			   vector<LoadTable> &loadpoints,vector<int4> *loadcounts) { return true; }
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void) { assistOp = (PcodeOp *)0; switchvn = (Varnode *)0; }
};

/// \brief A map from values to control-flow targets within a function
///
/// A JumpTable is attached to a specific CPUI_BRANCHIND and encapsulates all the information necessary
/// to model the indirect jump as a \e switch statement. It knows how to map from specific switch variable
/// values to the destination \e case block and how to label the value.  The table also establishes a
/// \e default target which is either
///   - the \e default case of the switch or
///   - the exit point of the switch
class JumpTable {
public:
  /// \brief Recovery status for a specific JumpTable
  enum RecoveryMode {
    success = 0,		///< JumpTable is fully recovered
    fail_normal = 1,		///< Normal failure to recover
    fail_thunk = 2,		///< Likely \b thunk
    fail_return = 3,  		///< Likely \b return operation
    fail_callother = 4		///< Address formed by CALLOTHER
  };
private:
  /// \brief An address table index and its corresponding out-edge
  struct IndexPair {
    int4 blockPosition;				///< Out-edge index for the basic-block
    int4 addressIndex;				///< Index of address targeting the basic-block
    IndexPair(int4 pos,int4 index) { blockPosition = pos; addressIndex = index; }	///< Constructor
    bool operator<(const IndexPair &op2) const;	///< Compare by position then by index
    static bool compareByPosition(const IndexPair &op1,const IndexPair &op2);	///< Compare just by position
  };
  Architecture *glb;		///< Architecture under which this jump-table operates
  JumpModel *jmodel;		///< Current model of how the jump table is implemented in code
  JumpModel *origmodel;		///< Initial jump table model, which may be incomplete
  vector<Address> addresstable; ///< Raw addresses in the jump-table
  vector<IndexPair> block2addr;	///< Map from basic-blocks to address table index
  vector<uintb> label;		///< The case label for each explicit target
  vector<LoadTable> loadpoints;	///< Any recovered in-memory data for the jump-table
  Address opaddress;		///< Absolute address of the BRANCHIND jump
  PcodeOp *indirect;		///< CPUI_BRANCHIND linked to \b this jump-table
  uintb switchVarConsume;	///< Bits of the switch variable being consumed
  int4 defaultBlock;		///< The out-edge corresponding to the \e default switch destination (-1 = undefined)
  int4 lastBlock;		///< Block out-edge corresponding to last entry in the address table
  uint4 maxaddsub;		///< Maximum ADDs or SUBs to normalize
  uint4 maxleftright;		///< Maximum shifts to normalize
  uint4 maxext;			///< Maximum extensions to normalize
  bool partialTable;		///< Set to \b true if \b this table is incomplete and needs additional recovery steps
  bool collectloads;		///< Set to \b true if information about in-memory model data is/should be collected
  bool defaultIsFolded;		///< The \e default block is the target of a folded CBRANCH (and cannot have a label)
  void saveModel(void);		///< Save off current model (if any) and prepare for instantiating a new model
  void restoreSavedModel(void);	///< Restore any saved model as the current model
  void clearSavedModel(void);	///< Clear any saved model
  void recoverModel(Funcdata *fd);	///< Attempt recovery of the jump-table model
  void trivialSwitchOver(void);	///< Switch \b this table over to a trivial model
  void sanityCheck(Funcdata *fd,vector<int4> *loadpoints);	///< Perform sanity check on recovered address targets
  int4 block2Position(const FlowBlock *bl) const;	///< Convert a basic-block to an out-edge index from the switch.
  static bool isReachable(PcodeOp *op);	///< Check if the given PcodeOp still seems reachable in its function
public:
  JumpTable(Architecture *g,Address ad=Address());	///< Constructor
  JumpTable(const JumpTable *op2);			///< Copy constructor
  ~JumpTable(void);					///< Destructor
  bool isRecovered(void) const { return !addresstable.empty(); }	///< Return \b true if a model has been recovered
  bool isLabelled(void) const { return !label.empty(); }		///< Return \b true if \e case labels are computed
  bool isOverride(void) const;				///< Return \b true if \b this table was manually overridden
  bool isPartial(void) const { return partialTable; }	///< Return \b true if \b this is a partial table needing more recovery
  void markComplete(void) { partialTable = false; }	///< Mark whatever is recovered so far as the complete table
  int4 numEntries(void) const { return addresstable.size(); }	///< Return the size of the address table for \b this jump-table
  uintb getSwitchVarConsume(void) const { return switchVarConsume; }	///< Get bits of switch variable consumed by \b this table
  int4 getDefaultBlock(void) const { return defaultBlock; }	///< Get the out-edge corresponding to the \e default switch destination
  const Address &getOpAddress(void) const { return opaddress; }	///< Get the address of the BRANCHIND for the switch
  PcodeOp *getIndirectOp(void) const { return indirect; }	///< Get the BRANCHIND PcodeOp
  void setIndirectOp(PcodeOp *ind) { opaddress = ind->getAddr(); indirect = ind; }	///< Set the BRANCHIND PcodeOp
  void setNormMax(uint4 maddsub,uint4 mleftright,uint4 mext) {
    maxaddsub = maddsub; maxleftright = mleftright; maxext = mext; }	///< Set the switch variable normalization model restrictions
  void setOverride(const vector<Address> &addrtable,const Address &naddr,uintb h,uintb sv);
  int4 numIndicesByBlock(const FlowBlock *bl) const;
  int4 getIndexByBlock(const FlowBlock *bl,int4 i) const;
  Address getAddressByIndex(int4 i) const { return addresstable[i]; }	///< Get the i-th address table entry
  void setLastAsDefault(void);		///< Set the \e default jump-table target to be the last address in the table
  void setDefaultBlock(int4 bl) { defaultBlock = bl; }		///< Set out-edge of the switch destination considered to be \e default
  void setLoadCollect(bool val) { collectloads = val; }		///< Set whether LOAD records should be collected
  void setFoldedDefault(void) { defaultIsFolded = true; }	///< Mark that the \e default block is a folded CBRANCH target
  bool hasFoldedDefault(void) const { return defaultIsFolded; }	///< Return \b true if the \e default block is a folded CBRANCH target
  void addBlockToSwitch(BlockBasic *bl,uintb lab);		///< Force a given basic-block to be a switch destination
  void switchOver(const FlowInfo &flow);				///< Convert absolute addresses to block indices
  uintb getLabelByIndex(int4 index) const { return label[index]; }	///< Given a \e case index, get its label
  void foldInNormalization(Funcdata *fd);		///< Hide the normalization code for the switch
  bool foldInGuards(Funcdata *fd) { return jmodel->foldInGuards(fd,this); }	///< Hide any guard code for \b this switch
  void recoverAddresses(Funcdata *fd);		///< Recover the raw jump-table addresses (the address table)
  void recoverMultistage(Funcdata *fd);		///< Recover jump-table addresses keeping track of a possible previous stage
  void matchModel(Funcdata *fd);		///< Try to match JumpTable model to the existing function
  void recoverLabels(Funcdata *fd);		///< Recover the case labels for \b this jump-table
  bool checkForMultistage(Funcdata *fd);	///< Check if this jump-table requires an additional recovery stage
  void clear(void);				///< Clear instance specific data for \b this jump-table
  void encode(Encoder &encoder) const;		///< Encode \b this jump-table as a \<jumptable> element
  void decode(Decoder &decoder);		///< Decode \b this jump-table from a \<jumptable> element
};

/// \param op2 is the other IndexPair to compare with \b this
/// \return \b true if \b this is ordered before the other IndexPair
inline bool JumpTable::IndexPair::operator<(const IndexPair &op2) const

{
  if (blockPosition != op2.blockPosition) return (blockPosition < op2.blockPosition);
  return (addressIndex < op2.addressIndex);
}

/// \param op1 is the first IndexPair to compare
/// \param op2 is the second IndexPair to compare
/// \return \b true if op1 is ordered before op2
inline bool JumpTable::IndexPair::compareByPosition(const IndexPair &op1,const IndexPair &op2)

{
  return (op1.blockPosition < op2.blockPosition);
}

} // End namespace ghidra
#endif

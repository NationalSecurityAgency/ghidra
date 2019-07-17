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
// Abstract jump table, we do not specify how addresses are encoded in table

#ifndef __CPUI_JUMPTABLE__
#define __CPUI_JUMPTABLE__

#include "emulateutil.hh"
#include "rangeutil.hh"

class EmulateFunction;

struct JumptableThunkError : public LowlevelError { // Thunk that looks like a jumptable
  /// Initialize the error with an explanatory string
  JumptableThunkError(const string &s) : LowlevelError(s) {}
};

struct JumptableNotReachableError : public LowlevelError { // There are no legal flows to the switch
  JumptableNotReachableError(const string &s) : LowlevelError(s) {}
};

class LoadTable {
  friend class EmulateFunction;
  Address addr;		// Starting address of table
  int4 size;			// Size of table entry
  int4 num;			// Number of entries in table;
public:
  LoadTable(void) {}		// For use with restoreXml
  LoadTable(const Address &ad,int4 sz) { addr = ad, size = sz; num = 1; }
  LoadTable(const Address &ad,int4 sz,int4 nm) { addr = ad; size = sz; num = nm; }
  bool operator<(const LoadTable &op2) const { return (addr < op2.addr); }
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,Architecture *glb);
  static void collapseTable(vector<LoadTable> &table);
};

class PathMeld {
  struct RootedOp {
    PcodeOp *op;
    int4 rootVn;
    RootedOp(PcodeOp *o,int4 root) { op = o; rootVn = root; }
  };
  vector<Varnode *> commonVn;		// Varnodes in common with all paths
  vector<RootedOp> opMeld;		// All the ops for the melded paths
  void internalIntersect(vector<int4> &parentMap);
  int4 meldOps(const vector<PcodeOp *> &path,int4 cutOff,const vector<int4> &parentMap);
  void truncatePaths(int4 cutPoint);
public:
  void set(const PathMeld &op2);
  void set(const vector<PcodeOp *> &path,const vector<int4> &slot);
  void set(PcodeOp *op,Varnode *vn);
  void append(const PathMeld &op2);
  void clear(void);
  void meld(vector<PcodeOp *> &path,vector<int4> &slot);
  int4 numCommonVarnode(void) const { return commonVn.size(); }
  int4 numOps(void) const { return opMeld.size(); }
  Varnode *getVarnode(int4 i) const { return commonVn[i]; }
  Varnode *getOpParent(int4 i) const { return commonVn[ opMeld[i].rootVn ]; }
  PcodeOp *getOp(int4 i) const { return opMeld[i].op; }
  PcodeOp *getEarliestOp(int4 pos) const;
  bool empty(void) const { return commonVn.empty(); }
};

class EmulateFunction : public EmulatePcodeOp {
  Funcdata *fd;
  map<Varnode *,uintb> varnodeMap;	// Lightweight memory state based on Varnodes
  bool collectloads;
  vector<LoadTable> loadpoints;
  virtual void executeLoad(void);
  virtual void executeBranch(void);
  virtual void executeBranchind(void);
  virtual void executeCall(void);
  virtual void executeCallind(void);
  virtual void executeCallother(void);
  virtual void fallthruOp(void);
public:
  EmulateFunction(Funcdata *f);
  void setLoadCollect(bool val) { collectloads = val; }
  virtual void setExecuteAddress(const Address &addr);
  virtual uintb getVarnodeValue(Varnode *vn) const;
  virtual void setVarnodeValue(Varnode *vn,uintb val);
  uintb emulatePath(uintb val,const PathMeld &pathMeld,PcodeOp *startop,Varnode *startvn);
  void collectLoadPoints(vector<LoadTable> &res) const;
};

class FlowInfo;
class JumpTable;

class GuardRecord {
  PcodeOp *cbranch;		// instruction branching around switch
  int4 indpath;			// branch going to switch
  CircleRange range;		// range of values which goto switch
  Varnode *vn;			// Varnode being restricted
  Varnode *baseVn;		// Value being (quasi)copied to vn
  int4 bitsPreserved;		// Number of bits copied (all other bits are zero)
public:
  GuardRecord(PcodeOp *op,int4 path,const CircleRange &rng,Varnode *v);
  PcodeOp *getBranch(void) const { return cbranch; }
  int4 getPath(void) const { return indpath; }
  const CircleRange &getRange(void) const { return range; }
  bool isClear(void) const { return (cbranch == (PcodeOp *)0); }
  void clear(void) { cbranch = (PcodeOp *)0; }
  int4 valueMatch(Varnode *vn2,Varnode *baseVn2,int4 bitsPreserved2) const;
  static int4 oneOffMatch(PcodeOp *op1,PcodeOp *op2);
  static Varnode *quasiCopy(Varnode *vn,int4 &bitsPreserved,bool noWholeValue);
};

// This class represents a set of switch variables, and the values that they can take
class JumpValues {
public:
  virtual ~JumpValues(void) {}
  virtual void truncate(int4 nm)=0;
  virtual uintb getSize(void) const=0;
  virtual bool contains(uintb val) const=0;
  virtual bool initializeForReading(void) const=0;
  virtual bool next(void) const=0;
  virtual uintb getValue(void) const=0;
  virtual Varnode *getStartVarnode(void) const=0;
  virtual PcodeOp *getStartOp(void) const=0;
  virtual bool isReversible(void) const=0;	// Can the current value be reversed to get a label
  virtual JumpValues *clone(void) const=0;
};

// This class implements a single entry switch variable that can take a range of values
class JumpValuesRange : public JumpValues {
protected:
  CircleRange range;		// Acceptable range of values for normalvn
  Varnode *normqvn;
  PcodeOp *startop;
  mutable uintb curval;
public:
  void setRange(const CircleRange &rng) { range = rng; }
  void setStartVn(Varnode *vn) { normqvn = vn; }
  void setStartOp(PcodeOp *op) { startop = op; }
  virtual void truncate(int4 nm);		///< Truncate the number of values to the given number
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

// This class extends having a single entry switch variable with range and
// adds a second entry point that takes only a single value
class JumpValuesRangeDefault : public JumpValuesRange { // Range like model1, but with extra default value
  uintb extravalue;
  Varnode *extravn;
  PcodeOp *extraop;
  mutable bool lastvalue;
public:
  void setExtraValue(uintb val) { extravalue = val; }
  void setDefaultVn(Varnode *vn) { extravn = vn; }
  void setDefaultOp(PcodeOp *op) { extraop = op; }
  virtual uintb getSize(void) const;
  virtual bool contains(uintb val) const;
  virtual bool initializeForReading(void) const;
  virtual bool next(void) const;
  virtual Varnode *getStartVarnode(void) const;
  virtual PcodeOp *getStartOp(void) const;
  virtual bool isReversible(void) const { return !lastvalue; }	// The -extravalue- is not reversible
  virtual JumpValues *clone(void) const;
};

// This class represents the entire recovery process, recognizing the model, tracing
// from the switch entry to the address, and folding in guards
class JumpModel {
protected:
  JumpTable *jumptable;		// The jumptable that is building this model
public:
  JumpModel(JumpTable *jt) { jumptable = jt; }
  virtual ~JumpModel(void) {}
  virtual bool isOverride(void) const=0;
  virtual int4 getTableSize(void) const=0;
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)=0;
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const=0;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)=0;
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const=0;
  virtual void foldInNormalization(Funcdata *fd,PcodeOp *indop)=0;
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump)=0;
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable)=0;
  virtual JumpModel *clone(JumpTable *jt) const=0;
  virtual void clear(void) {};	// Clear any non-permanent aspects of the model
  virtual void saveXml(ostream &s) const {} // For use with override models
  virtual void restoreXml(const Element *el,Architecture *glb) {} // For use with override models
};

// This class treats the branch indirection variable as the switch variable, and recovers
// its possible values from the existing block structure
class JumpModelTrivial : public JumpModel {
  uint4 size;
public:
  JumpModelTrivial(JumpTable *jt) : JumpModel(jt) { size = 0; }
  virtual bool isOverride(void) const { return false; }
  virtual int4 getTableSize(void) const { return size; }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext) {}
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  virtual void foldInNormalization(Funcdata *fd,PcodeOp *indop) {}
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump) { return false; }
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable) { return true; }
  virtual JumpModel *clone(JumpTable *jt) const;
};

// This is the basic switch model.  In brief
//   1) Straight-line calculation from switch variable to BRANCHIND
//   2) Switch variable is bounded by one or more "guards" that branch around the BRANCHIND
//   3) Recover unnormalized switch from bounded switch, through some basic transforms
class JumpBasic : public JumpModel {
protected:
  JumpValuesRange *jrange;
  PathMeld pathMeld;			// Set of PcodeOps and Varnodes producing the final switch addresses
  vector<GuardRecord> selectguards;
  int4 varnodeIndex;			// Position of the normalized switch varnode within PathMeld
  Varnode *normalvn;			// The normalized switch varnode
  Varnode *switchvn;			// The unnormalized switch varnode
  static bool isprune(Varnode *vn);
  static bool ispoint(Varnode *vn);
  static int4 getStride(Varnode *vn);	///< Get the step/stride associated with the Varnode
  static uintb backup2Switch(Funcdata *fd,uintb output,Varnode *outvn,Varnode *invn);
  void findDeterminingVarnodes(PcodeOp *op,int4 slot);
  void analyzeGuards(BlockBasic *bl,int4 pathout);
  void calcRange(Varnode *vn,CircleRange &rng) const;
  void findSmallestNormal(uint4 matchsize);
  void findNormalized(Funcdata *fd,BlockBasic *rootbl,int4 pathout,uint4 matchsize,uint4 maxtablesize);
  void markFoldableGuards();
  virtual bool foldInOneGuard(Funcdata *fd,GuardRecord &guard,JumpTable *jump);
public:
  JumpBasic(JumpTable *jt) : JumpModel(jt) { jrange = (JumpValuesRange *)0; }
  const PathMeld &getPathMeld(void) const { return pathMeld; }
  const JumpValuesRange *getValueRange(void) const { return jrange; }
  virtual ~JumpBasic(void);
  virtual bool isOverride(void) const { return false; }
  virtual int4 getTableSize(void) const { return jrange->getSize(); }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext);
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  virtual void foldInNormalization(Funcdata *fd,PcodeOp *indop);
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump);
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable);
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void);
};

// This model expects two paths to the switch, 1 from a default value, 1 from the other values that hit the switch
// If A is the guarding control-flow block, C is the block setting the default value, and S the switch block itself,
// We expect one of the following situations:
//    A -> C or S  and  C -> S
//    A -> C or D  and  C -> S  D -> S
//    C -> S and S -> A   A -> S or "out of loop", i.e. S is in a loop, and the guard block doubles as the loop condition
class JumpBasic2 : public JumpBasic {
  Varnode *extravn;
  PathMeld origPathMeld;
  bool checkNormalDominance(void) const;
  virtual bool foldInOneGuard(Funcdata *fd,GuardRecord &guard,JumpTable *jump);
public:
  JumpBasic2(JumpTable *jt) : JumpBasic(jt) {}
  void initializeStart(const PathMeld &pathMeld);
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext);
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void);
};

// This is the basic model for manually specifying the list of addresses the switch goes to
// It tries to repurpose some of the analysis that JumpBasic does to recover what the switch variable
// is, but will revert to the trivial model if it can't find a suitable switch variable
class JumpBasicOverride : public JumpBasic {
  set<Address> adset;	// Absolute address table (manually specified)
  vector<uintb> values;		// Normalized switch variable values associated with addresses
  vector<Address> addrtable;	// Address associated with each value
  uintb startingvalue;		// Possible start for guessing values that match addresses
  Address normaddress;		// Dynamic info for recovering normalized switch variable
  uint8 hash;			// if (hash==0) there is no normalized switch (use trivial model)
  bool istrivial;		// true if we use a trivial value model
  int4 findStartOp(Varnode *vn);
  int4 trialNorm(Funcdata *fd,Varnode *trialvn,uint4 tolerance);
  void setupTrivial(void);
  Varnode *findLikelyNorm(void);
  void clearCopySpecific(void);
public:
  JumpBasicOverride(JumpTable *jt);
  void setAddresses(const vector<Address> &adtable);
  void setNorm(const Address &addr,uintb h) { normaddress = addr; hash = h; }
  void setStartingValue(uintb val) { startingvalue = val; }
  virtual bool isOverride(void) const { return true; }
  virtual int4 getTableSize(void) const { return addrtable.size(); }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const;
  // findUnnormalized inherited from JumpBasic
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  // foldInNormalization inherited from JumpBasic
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump) { return false; }
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable) { return true; }
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void);
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Architecture *glb);
};

class JumpAssistOp;

// This model looks for a special "jumpassist" pseudo-op near the branch site, which contains
// p-code models describing how to parse a jump-table for case labels and addresses.
// It views the switch table calculation as a two-stage process:
//    case2index:    convert the switchvar to an index into a table
//    index2address: convert the index to an address
// The pseudo-op holds:
//    the table address, size (number of indices)
//    exemplar p-code for inverting the case2index part of the calculation
//    exemplar p-code for calculating index2address
class JumpAssisted : public JumpModel {
  PcodeOp *assistOp;
  JumpAssistOp *userop;
  int4 sizeIndices;		// Total number of indices in the table (not including the defaultaddress)
  Varnode *switchvn;		// The switch variable
public:
  JumpAssisted(JumpTable *jt) : JumpModel(jt) { assistOp = (PcodeOp *)0; switchvn = (Varnode *)0; sizeIndices=0; }
//  virtual ~JumpAssisted(void);
  virtual bool isOverride(void) const { return false; }
  virtual int4 getTableSize(void) const { return sizeIndices+1; }
  virtual bool recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize);
  virtual void buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const;
  virtual void findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext) {}
  virtual void buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const;
  virtual void foldInNormalization(Funcdata *fd,PcodeOp *indop);
  virtual bool foldInGuards(Funcdata *fd,JumpTable *jump);
  virtual bool sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable) { return true; }
  virtual JumpModel *clone(JumpTable *jt) const;
  virtual void clear(void) { assistOp = (PcodeOp *)0; switchvn = (Varnode *)0; }
};

class JumpTable {
  Architecture *glb;	// Architecture under which this jumptable operates
  JumpModel *jmodel,*origmodel;
  vector<Address> addresstable; // Raw addresses in the jumptable
  vector<uint4> blocktable;	// Addresses converted to basic blocks
  vector<uintb> label;
  vector<LoadTable> loadpoints;
  Address opaddress;		// Absolute address of op
  PcodeOp *indirect;		// INDIRECT op referring to this jump table
  uint4 mostcommon;		// Most common position in table
  uint4 maxtablesize;		// Maximum table size we allow to be built (sanity check)
  uint4 maxaddsub;		// Maximum ADDs or SUBs to normalize
  uint4 maxleftright;		// Maximum shifts to normalize
  uint4 maxext;			// Maximum extensions to normalize
  int4 recoverystage;		// 0=no stages, 1=needs additional stage, 2=complete
  bool collectloads;
  void recoverModel(Funcdata *fd);
  void trivialSwitchOver(void);
  void sanityCheck(Funcdata *fd);
  uint4 block2Position(const FlowBlock *bl) const;
  static bool isReachable(PcodeOp *op);
public:
  JumpTable(Architecture *g,Address ad=Address());
  JumpTable(const JumpTable *op2);
  ~JumpTable(void);
  bool isSwitchedOver(void) const { return !blocktable.empty(); }
  bool isRecovered(void) const { return !addresstable.empty(); }
  bool isLabelled(void) const { return !label.empty(); }
  bool isOverride(void) const;
  bool isPossibleMultistage(void) const { return (addresstable.size()==1); }
  int4 getStage(void) const { return recoverystage; }
  int4 numEntries(void) const { return addresstable.size(); }
  int4 getMostCommon(void) const { return mostcommon; }
  const Address &getOpAddress(void) const { return opaddress; }
  PcodeOp *getIndirectOp(void) const { return indirect; }
  void setIndirectOp(PcodeOp *ind) { opaddress = ind->getAddr(); indirect = ind; }
  void setMaxTableSize(uint4 val) { maxtablesize = val; }
  void setNormMax(uint4 maddsub,uint4 mleftright,uint4 mext) {
    maxaddsub = maddsub; maxleftright = mleftright; maxext = mext; }
  void setOverride(const vector<Address> &addrtable,const Address &naddr,uintb h,uintb sv);
  int4 numIndicesByBlock(const FlowBlock *bl) const;
  int4 getIndexByBlock(const FlowBlock *bl,int4 i) const;
  Address getAddressByIndex(int4 index) const { return addresstable[index]; }
  void setMostCommonIndex(uint4 tableind);
  void setMostCommonBlock(uint4 bl) { mostcommon = bl; }
  void setLoadCollect(bool val) { collectloads = val; }
  void addBlockToSwitch(BlockBasic *bl,uintb lab);
  void switchOver(const FlowInfo &flow);
  uintb getLabelByIndex(int4 index) const { return label[index]; }
  void foldInNormalization(Funcdata *fd) { jmodel->foldInNormalization(fd,indirect); }
  bool foldInGuards(Funcdata *fd) { return jmodel->foldInGuards(fd,this); }
  void recoverAddresses(Funcdata *fd);
  void recoverMultistage(Funcdata *fd);
  bool recoverLabels(Funcdata *fd);
  bool checkForMultistage(Funcdata *fd);
  void clear(void);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el);
};  

#endif

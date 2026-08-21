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
#ifndef __DOUBLE_HH__
#define __DOUBLE_HH__

#include "ruleaction.hh"
#include "funcdata.hh"

namespace ghidra {

/// \brief A logical value whose storage is split between two Varnodes
///
/// This is usually a pair of Varnodes \b lo and \b hi holding the least and
/// most significant part of the logical value respectively.  Its possible for
/// the logical value to be a constant, in which case \b lo and \b hi are set to
/// null and \b val holds the actual constant.
/// Its also possible for \b hi to be null by itself, indicating that most signficant
/// part of the variable is zero, and the logical variable is the zero extension of \b lo.
class SplitVarnode {
  Varnode *lo;			///< Least significant piece of the double precision object
  Varnode *hi;			///< Most significant piece of the double precision object
  Varnode *whole;		///< A representative of the whole object
  PcodeOp *defpoint; 		///< Operation at which both \b lo and \b hi are defined
  BlockBasic *defblock;		///< Block in which both \b lo and \b hi are defined
  uintb val;			///< Value of a double precision constant
  int4 wholesize;		///< Size in bytes of the (virtual) whole
  bool findWholeSplitToPieces(void);	///< Find whole out of which \b hi and \b lo are split
  bool findDefinitionPoint(void);	///< Find the earliest PcodeOp where both \b lo and \b hi are defined
  bool findWholeBuiltFromPieces(void);	///< Find whole Varnode formed as a CPUI_PIECE of \b hi and \b lo
public:
  SplitVarnode(void) {}			///< Construct an uninitialized SplitVarnode
  SplitVarnode(int4 sz,uintb v);	///< Construct a double precision constant
  SplitVarnode(Varnode *l,Varnode *h) { initPartial(l->getSize()+h->getSize(),l,h); }	///< Construct from \b lo and \b hi piece
  void initAll(Varnode *w,Varnode *l,Varnode *h);	///< Construct given Varnode pieces and a known \b whole Varnode
  void initPartial(int4 sz,uintb v);	///< (Re)initialize \b this SplitVarnode as a constant
  void initPartial(int4 sz,Varnode *l,Varnode *h);	///< (Re)initialize \b this SplitVarnode given Varnode pieces
  bool inHandHi(Varnode *h);		///< Try to initialize given just the most significant piece split from whole
  bool inHandLo(Varnode *l);		///< Try to initialize given just the least significant piece split from whole
  bool inHandLoNoHi(Varnode *l);	///< Try to initialize given just the least significant piece (other piece may be zero)
  bool inHandHiOut(Varnode *h);		///< Try to initialize given just the most significant piece concatenated into whole
  bool inHandLoOut(Varnode *l);		///< Try to initialize given just the least significant piece concatenated into whole
  bool isConstant(void) const { return (lo == (Varnode *)0); }	///< Return \b true if \b this is a constant
  bool hasBothPieces(void) const { return ((hi!=(Varnode *)0)&&(lo!=(Varnode *)0)); }	///< Return \b true if both pieces are initialized
  int4 getSize(void) const { return wholesize; }	///< Get the size of \b this SplitVarnode as a whole in bytes
  Varnode *getLo(void) const { return lo; }		///< Get the least significant Varnode piece
  Varnode *getHi(void) const { return hi; }		///< Get the most significant Varnode piece
  Varnode *getWhole(void) const { return whole; }	///< Get the Varnode representing \b this as a whole
  PcodeOp *getDefPoint(void) const { return defpoint; }	///< Get the(final) defining PcodeOp of \b this
  BlockBasic *getDefBlock(void) const { return defblock; }	///< Get the defining basic block of \b this
  uintb getValue(void) const { return val; }		///< Get the value of \b this, assuming it is a constant
  bool isWholeFeasible(PcodeOp *existop);	///< Does a whole Varnode already exist or can it be created before the given PcodeOp
  bool isWholePhiFeasible(FlowBlock *bl);	///< Does a whole Varnode already exist or can it be created before the given basic block
  void findCreateWhole(Funcdata &data);		///< Create a \b whole Varnode for \b this, if it doesn't already exist
  void findCreateOutputWhole(Funcdata &data);	///< Create a \b whole Varnode that will be a PcodeOp output
  void createJoinedWhole(Funcdata &data);	///< Create a \b whole Varnode from pieces, respecting piece storage
  void buildLoFromWhole(Funcdata &data);	///< Rebuild the least significant piece as a CPUI_SUBPIECE of the \b whole
  void buildHiFromWhole(Funcdata &data);	///< Rebuild the most significant piece as a CPUI_SUBPIECE of the \b whole
  PcodeOp *findEarliestSplitPoint(void);	///< Find the earliest definition point of the \b lo and \b hi pieces
  PcodeOp *findOutExist(void);			///< Find the point at which the output \b whole must exist
  bool exceedsConstPrecision(void) const;	///< Check if \b this is a constant that exceeds precision limits
  static bool adjacentOffsets(Varnode *vn1,Varnode *vn2,uintb size1);
  static bool testContiguousPointers(PcodeOp *most,PcodeOp *least,PcodeOp *&first,PcodeOp *&second,AddrSpace *&spc);
  static bool isAddrTiedContiguous(Varnode *lo,Varnode *hi,Address &res);
  static void wholeList(Varnode *w,vector<SplitVarnode> &splitvec);
  static void findCopies(const SplitVarnode &in,vector<SplitVarnode> &splitvec);
  static void getTrueFalse(PcodeOp *boolop,bool flip,BlockBasic *&trueout,BlockBasic *&falseout);
  static bool otherwiseEmpty(PcodeOp *branchop);
  static bool verifyMultNegOne(PcodeOp *op);
  static PcodeOp *prepareBinaryOp(SplitVarnode &out,SplitVarnode &in1,SplitVarnode &in2);
  static void createBinaryOp(Funcdata &data,SplitVarnode &out,SplitVarnode &in1,SplitVarnode &in2,
			     PcodeOp *existop,OpCode opc);
  static PcodeOp *prepareShiftOp(SplitVarnode &out,SplitVarnode &in);
  static void createShiftOp(Funcdata &data,SplitVarnode &out,SplitVarnode &in,Varnode *sa,
			    PcodeOp *existop,OpCode opc);
  static void replaceBoolOp(Funcdata &data,PcodeOp *boolop,SplitVarnode &in1,SplitVarnode &in2,
			    OpCode opc);
  static bool prepareBoolOp(SplitVarnode &in1,SplitVarnode &in2,PcodeOp *testop);
  static void createBoolOp(Funcdata &data,PcodeOp *cbranch,SplitVarnode &in1,SplitVarnode &in2,
			   OpCode opc);
  static PcodeOp *preparePhiOp(SplitVarnode &out,vector<SplitVarnode> &inlist);
  static void createPhiOp(Funcdata &data,SplitVarnode &out,vector<SplitVarnode> &inlist,
			  PcodeOp *existop);
  static bool prepareIndirectOp(SplitVarnode &in,PcodeOp *affector);
  static void replaceIndirectOp(Funcdata &data,SplitVarnode &out,SplitVarnode &in,PcodeOp *affector);
  static void replaceCopyForce(Funcdata &data,const Address &addr,SplitVarnode &in,PcodeOp *copylo,PcodeOp *copyhi);
  static int4 applyRuleIn(SplitVarnode &in,Funcdata &data);
};

class AddForm {
  SplitVarnode in;
  Varnode *hi1,*hi2,*lo1,*lo2;
  Varnode *reshi,*reslo;
  PcodeOp *zextop,*loadd,*add2;
  Varnode *hizext1,*hizext2;
  int4 slot1;
  uintb negconst;
  PcodeOp *existop;
  SplitVarnode indoub;
  SplitVarnode outdoub;
  bool checkForCarry(PcodeOp *op);
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *op);
  bool applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data);
};

class SubForm {
  SplitVarnode in;
  Varnode *hi1,*hi2,*lo1,*lo2;
  Varnode *reshi,*reslo;
  PcodeOp *zextop,*lessop,*negop,*loadd,*add2;
  Varnode *hineg1,*hineg2;
  Varnode *hizext1,*hizext2;
  int4 slot1;
  PcodeOp *existop;
  SplitVarnode indoub;
  SplitVarnode outdoub;
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *op);
  bool applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data);
};

class LogicalForm {
  SplitVarnode in;
  PcodeOp *loop,*hiop;
  Varnode *hi1,*hi2,*lo1,*lo2;
  PcodeOp *existop;
  SplitVarnode indoub;
  SplitVarnode outdoub;
  int4 findHiMatch(void);
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *lop);
  bool applyRule(SplitVarnode &i,PcodeOp *lop,bool workishi,Funcdata &data);
};

class Equal1Form {
  SplitVarnode in1;
  SplitVarnode in2;
  PcodeOp *loop,*hiop;
  PcodeOp *hibool,*lobool;
  Varnode *hi1,*lo1,*hi2,*lo2;
  int4 hi1slot,lo1slot;
  bool notequalformhi,notequalformlo;
  bool setonlow;
public:
  bool applyRule(SplitVarnode &i,PcodeOp *hop,bool workishi,Funcdata &data);
};

class Equal2Form {
  SplitVarnode in;
  Varnode *hi1,*hi2,*lo1,*lo2;
  PcodeOp *boolAndOr;
  SplitVarnode param2;
  bool replace(Funcdata &data);
public:
  bool applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data);
};

class Equal3Form {
  SplitVarnode in;
  Varnode *hi,*lo;
  PcodeOp *andop;
  PcodeOp *compareop;
  Varnode *smallc;
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *aop);
  bool applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data);
};

class LessThreeWay {
  SplitVarnode in;
  SplitVarnode in2;
  BlockBasic *hilessbl,*lolessbl,*hieqbl;
  BlockBasic *hilesstrue,*hilessfalse;
  BlockBasic *hieqtrue,*hieqfalse;
  BlockBasic *lolesstrue,*lolessfalse;
  PcodeOp *hilessbool,*lolessbool,*hieqbool;
  PcodeOp *hiless,*hiequal,*loless;
  Varnode *vnhil1,*vnhil2,*vnhie1,*vnhie2;
  Varnode *vnlo1,*vnlo2;
  Varnode *hi,*lo,*hi2,*lo2;
  int4 hislot;
  bool hiflip,equalflip,loflip;
  bool lolessiszerocomp;
  bool lolessequalform,hilessequalform,signcompare;
  bool midlessform,midlessequal,midsigncompare;
  bool hiconstform,midconstform,loconstform;
  uintb hival,midval,loval;
  OpCode finalopc;
  bool mapBlocksFromLow(BlockBasic *lobl);
  bool mapOpsFromBlocks(void);
  bool checkSignedness(void);
  bool normalizeHi(void);
  bool normalizeMid(void);
  bool normalizeLo(void);
  bool checkBlockForm(void);
  bool checkOpForm(void);
  void setOpCode(void);
  bool setBoolOp(void);
  bool mapFromLow(PcodeOp *op);
  bool testReplace(void);
public:
  bool applyRule(SplitVarnode &i,PcodeOp *loop,bool workishi,Funcdata &data);
};

class LessConstForm {
  SplitVarnode in;
  Varnode *vn,*cvn;
  int4 inslot;
  bool signcompare,hilessequalform;
  SplitVarnode constin;
public:
  bool applyRule(SplitVarnode &i,PcodeOp *op,bool workishi,Funcdata &data);
};

class ShiftForm {
  SplitVarnode in;
  OpCode opc;			// Basic operation
  PcodeOp *loshift,*midshift,*hishift;
  PcodeOp *orop;
  Varnode *lo,*hi,*midlo,*midhi;
  Varnode *salo,*sahi,*samid;
  Varnode *reslo,*reshi;
  SplitVarnode out;
  PcodeOp *existop;
  bool verifyShiftAmount(void);
  bool mapLeft(void);
  bool mapRight(void);
public:
  bool verifyLeft(Varnode *h,Varnode *l,PcodeOp *loop);
  bool verifyRight(Varnode *h,Varnode *l,PcodeOp *hiop);
  bool applyRuleLeft(SplitVarnode &i,PcodeOp *loop,bool workishi,Funcdata &data);
  bool applyRuleRight(SplitVarnode &i,PcodeOp *hiop,bool workishi,Funcdata &data);
};

class MultForm {
  SplitVarnode in;
  PcodeOp *add1,*add2;
  PcodeOp *subhi;
  PcodeOp *multlo,*multhi1,*multhi2;
  Varnode *midtmp,*lo1zext,*lo2zext;
  Varnode *hi1,*lo1,*hi2,*lo2;
  Varnode *reslo,*reshi;
  SplitVarnode outdoub;
  SplitVarnode in2;
  PcodeOp *existop;
  bool zextOf(Varnode *big,Varnode *small);
  bool mapResHi(Varnode *rhi);
  bool mapResHiSmallConst(Varnode *rhi);
  bool findLoFromIn(void);
  bool findLoFromInSmallConst(void);
  bool verifyLo(void);
  bool findResLo(void);
  bool mapFromIn(Varnode *rhi);
  bool mapFromInSmallConst(Varnode *rhi);
  bool replace(Funcdata &data);
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *hop);
  bool applyRule(SplitVarnode &i,PcodeOp *hop,bool workishi,Funcdata &data);
};

class PhiForm {
  SplitVarnode in;
  SplitVarnode outvn;
  int4 inslot;
  Varnode *hibase,*lobase;
  BlockBasic *blbase;
  PcodeOp *lophi,*hiphi;
  PcodeOp *existop;
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *hphi);
  bool applyRule(SplitVarnode &i,PcodeOp *hphi,bool workishi,Funcdata &data);
};

class IndirectForm {
  SplitVarnode in;
  SplitVarnode outvn;
  Varnode *lo,*hi;
  Varnode *reslo,*reshi;
  PcodeOp *affector;			// Single op affecting both lo and hi
  PcodeOp *indhi,*indlo;		// Two partial CPUI_INDIRECT ops
public:
  bool verify(Varnode *h,Varnode *l,PcodeOp *ihi);
  bool applyRule(SplitVarnode &i,PcodeOp *ind,bool workishi,Funcdata &data);
};

/// \brief Collapse two COPYs into contiguous address forced Varnodes
///
/// The inputs must be pieces of a logical whole and outputs must be address forced with no descendants.
/// Take into account special form of COPYs holding global variables upto/past a RETURN.
class CopyForceForm {
  SplitVarnode in;			///< Incoming pieces to COPY
  Varnode *reslo;			///< Least significant result of global COPY
  Varnode *reshi;			///< Most significant result of global COPY
  PcodeOp *copylo;			///< Partial COPY of least significant piece
  PcodeOp *copyhi;			///< Partial COPY of most significant piece
  Address addrOut;			///< Storage address
public:
  bool verify(Varnode *h,Varnode *l,Varnode *w,PcodeOp *cpy);		///< Make sure the COPYs have the correct form
  bool applyRule(SplitVarnode &i,PcodeOp *cpy,bool workishi,Funcdata &data);	/// Verify and then collapse COPYs
};

/// \brief Simply a double precision operation, pushing down one level, starting from a marked double precision input.
///
/// This rule starts by trying to find a pair of Varnodes that are SUBPIECE from a whole,
/// are marked as double precision, and that are then used in some double precision operation.
/// The various operation \e forms are overlayed on the data-flow until a matching one is found.  The
/// pieces of the double precision operation are then transformed into a single logical operation on the whole.
class RuleDoubleIn : public Rule {
  int4 attemptMarking(Varnode *vn,PcodeOp *subpieceOp);
public:
  RuleDoubleIn(const string &g) : Rule(g, 0, "doublein") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleIn(getGroup());
  }
  virtual void reset(Funcdata &data);
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Simplify a double precision operation, pulling back one level, starting from inputs to a PIECE operation
class RuleDoubleOut : public Rule {
  int4 attemptMarking(Varnode *vnhi,Varnode *vnlo,PcodeOp *pieceOp);
public:
  RuleDoubleOut(const string &g) : Rule(g, 0, "doubleout") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleOut(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Collapse contiguous loads: `x = CONCAT44(*(ptr+4),*ptr)  =>  x = *ptr`
class RuleDoubleLoad : public Rule {
public:
  RuleDoubleLoad(const string &g) : Rule( g, 0, "doubleload") {}
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleLoad(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static PcodeOp *noWriteConflict(PcodeOp *op1,PcodeOp *op2,AddrSpace *spc,vector<PcodeOp *> *indirects);
};

/// \brief Collapse contiguous stores:  `*ptr = SUB(x,0); *(ptr + 4) = SUB(x,4)  =>  *ptr = x`
class RuleDoubleStore : public Rule {
public:
  RuleDoubleStore(const string &g) : Rule( g, 0, "doublestore") {}
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleStore(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static bool testIndirectUse(PcodeOp *op1,PcodeOp *op2,const vector<PcodeOp *> &indirects);
  static void reassignIndirects(Funcdata &data,PcodeOp *newStore,const vector<PcodeOp *> &indirects);
};

} // End namespace ghidra
#endif

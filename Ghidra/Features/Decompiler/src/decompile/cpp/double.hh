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
#ifndef __CPUI_DOUBLE__
#define __CPUI_DOUBLE__

#include "ruleaction.hh"
#include "funcdata.hh"

class SplitVarnode {
  Varnode *lo;			// Least significant piece of the double precision object
  Varnode *hi;			// Most significant piece of the double precision object
  Varnode *whole;	       // A representative of the whole object
  PcodeOp *defpoint; // Operation at which both -lo- and -hi- are defined
  BlockBasic *defblock;	// Block in which bot -lo- and -hi- are defined
  uintb val;			// Value of a double precision constant
  int4 wholesize;	       // Size in bytes of the (virtual) whole
  bool findWholeSplitToPieces(void);
  bool findDefinitionPoint(void);
  bool findWholeBuiltFromPieces(void);
public:
  SplitVarnode(void) {}		// For use with inHandHi
  SplitVarnode(int4 sz,uintb v); // Initialize a double precision constant
  SplitVarnode(Varnode *l,Varnode *h) { initPartial(l,h); }
  void initAll(Varnode *w,Varnode *l,Varnode *h);
  void initPartial(int4 sz,uintb v);
  void initPartial(Varnode *l,Varnode *h);
  bool inHandHi(Varnode *h);
  bool inHandLo(Varnode *l);
  bool inHandLoNoHi(Varnode *l);
  bool inHandHiOut(Varnode *h);
  bool inHandLoOut(Varnode *h);
  bool isConstant(void) const { return (lo == (Varnode *)0); }
  bool hasBothPieces(void) const { return ((hi!=(Varnode *)0)&&(lo!=(Varnode *)0)); }
  int4 getSize(void) const { return wholesize; }
  Varnode *getLo(void) const { return lo; }
  Varnode *getHi(void) const { return hi; }
  Varnode *getWhole(void) const { return whole; }
  PcodeOp *getDefPoint(void) const { return defpoint; }
  BlockBasic *getDefBlock(void) const { return defblock; }
  uintb getValue(void) const { return val; }
  bool isWholeFeasible(PcodeOp *existop);
  bool isWholePhiFeasible(FlowBlock *bl);
  void findCreateWhole(Funcdata &data);
  void findCreateOutputWhole(Funcdata &data);
  void createJoinedWhole(Funcdata &data);
  void buildLoFromWhole(Funcdata &data);
  void buildHiFromWhole(Funcdata &data);
  PcodeOp *findEarliestSplitPoint(void);
  PcodeOp *findOutExist(void);
  static bool adjacentOffsets(Varnode *vn1,Varnode *vn2,uintb size1);
  static bool testContiguousLoad(PcodeOp *most,PcodeOp *least,bool allowfree,PcodeOp *&first,PcodeOp *&second,AddrSpace *&spc,int4 &sizeres);
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
  PcodeOp *equalop,*orop;
  PcodeOp *hixor,*loxor;
  int4 orhislot,xorhislot;
  SplitVarnode param2;
  bool checkLoForm(void);
  bool fillOutFromOr(Funcdata &data);
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

class RuleDoubleIn : public Rule {
public:
  RuleDoubleIn(const string &g) : Rule(g, 0, "doublein") {}
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleIn(getGroup());
  }
  virtual void reset(Funcdata &data);
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleDoubleLoad : public Rule {
public:
  RuleDoubleLoad(const string &g) : Rule( g, 0, "doubleload") {}
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleLoad(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static PcodeOp *noWriteConflict(PcodeOp *op1,PcodeOp *op2,AddrSpace *spc);
};

#endif

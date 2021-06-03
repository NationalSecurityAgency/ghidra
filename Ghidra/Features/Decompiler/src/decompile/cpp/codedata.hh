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
#ifndef __CPUI_CODEDATA__
#define __CPUI_CODEDATA__

#include "ifacedecomp.hh"

class IfaceCodeDataCapability : public IfaceCapability {
  static IfaceCodeDataCapability ifaceCodeDataCapability;	// Singleton instance
  IfaceCodeDataCapability(void);	// Singleton
  IfaceCodeDataCapability(const IfaceCodeDataCapability &op2);	// Not implemented
  IfaceCodeDataCapability &operator=(const IfaceCodeDataCapability &op2);	// Not implemented
public:
  virtual void registerCommands(IfaceStatus *status);
};

class CodeDataAnalysis;		// Forward declaration

class CodeUnit {
public:
  enum {
    fallthru = 1,
    jump = 2,
    call = 4,
    notcode = 8,
    hit_by_fallthru = 16,
    hit_by_jump = 32,
    hit_by_call = 64,
    errantstart = 128,
    targethit = 256,
    thunkhit = 512
  };
  uint4 flags;
  int4 size;
};

struct DisassemblyResult {
  bool success;
  int4 length;
  uint4 flags;
  Address jumpaddress;
  uintb targethit;
};


class DisassemblyEngine : public PcodeEmit {
  const Translate *trans;
  vector<Address> jumpaddr;
  set<uintb> targetoffsets;
  OpCode lastop;
  bool hascall;
  bool hitsaddress;
  uintb targethit;
public:
  void init(const Translate *t);
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize);
  void disassemble(const Address &addr,DisassemblyResult &res);
  void addTarget(const Address &addr) { targetoffsets.insert( addr.getOffset() ); }
};

class TargetHit {
public:
  Address funcstart;		// Starting address of function making target call
  Address codeaddr;		// Address of instruction refering to target call
  Address thunkaddr;		// The target call
  uint4 mask;			// Mask associated with this target
  TargetHit(const Address &func,const Address &code,const Address &thunk,uint4 m) :
    funcstart(func), codeaddr(code), thunkaddr(thunk) { mask = m; }
  bool operator<(const TargetHit &op2) const { return (funcstart < op2.funcstart); }
};

struct TargetFeature {
  string name;			// Name of the target function
  uint4 featuremask;		// id of this target for ORing into a mask
};

struct AddrLink {
  Address a;
  Address b;
  AddrLink(Address i) { a = i; b=Address(); }
  AddrLink(Address i,Address j) { a=i; b=j; }
  bool operator<(const AddrLink &op2) const {
    if (a != op2.a) return (a < op2.a);
    return (b < op2.b);
  }
};

class CodeDataAnalysis : public IfaceData {
public:
  int4 alignment;		// Alignment of instructions
  Architecture *glb;
  DisassemblyEngine disengine;
  RangeList modelhits;
  map<Address,CodeUnit> codeunit;
  map<AddrLink,uint4> fromto_crossref;
  map<AddrLink,uint4> tofrom_crossref;
  list<map<Address,CodeUnit>::iterator> taintlist;
  list<Address> unlinkedstarts;
  list<TargetHit> targethits;
  map<Address,TargetFeature> targets;
  virtual ~CodeDataAnalysis(void) {}
  void init(Architecture *g);
  void pushTaintAddress(const Address &addr);
  void processTaint(void);
  Address commitCodeVec(const Address &addr,vector<CodeUnit> &codevec,map<AddrLink,uint4> &fromto_vec);
  void clearHitBy(void);
  void clearCrossRefs(const Address &addr,const Address &endaddr);
  void clearCodeUnits(const Address &addr,const Address &endaddr);
  void addTarget(const string &nm,const Address &addr,uint4 mask);
  int4 getNumTargets(void) const { return targets.size(); }
  Address disassembleBlock(const Address &addr,const Address &endaddr);
  void disassembleRange(const Range &range);
  void disassembleRangeList(const RangeList &rangelist);
  void findNotCodeUnits(void);
  void markFallthruHits(void);
  void markCrossHits(void);
  void addTargetHit(const Address &codeaddr,uintb targethit);
  void resolveThunkHit(const Address &codeaddr,uintb targethit);
  void findUnlinked(void);
  bool checkErrantStart(map<Address,CodeUnit>::iterator iter);
  bool repairJump(const Address &addr,int4 max);
  void findOffCut(void);
  Address findFunctionStart(const Address &addr) const;
  const list<TargetHit> &getTargetHits(void) const { return targethits; }
  void dumpModelHits(ostream &s) const;
  void dumpCrossRefs(ostream &s) const;
  void dumpFunctionStarts(ostream &s) const;
  void dumpUnlinked(ostream &s) const;
  void dumpTargetHits(ostream &s) const;
  void runModel(void);
};

class IfaceCodeDataCommand : public IfaceCommand {
protected:
  IfaceStatus *status;
  IfaceDecompData *dcp;
  CodeDataAnalysis *codedata;
public:
  virtual void setData(IfaceStatus *root,IfaceData *data);
  virtual string getModule(void) const { return "codedata"; }
  virtual IfaceData *createData(void) { return new CodeDataAnalysis(); }
};

class IfcCodeDataInit : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataTarget : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataRun : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataDumpModelHits : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataDumpCrossRefs : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataDumpStarts : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataDumpUnlinked : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

class IfcCodeDataDumpTargetHits : public IfaceCodeDataCommand {
public:
  virtual void execute(istream &s);
};

#endif

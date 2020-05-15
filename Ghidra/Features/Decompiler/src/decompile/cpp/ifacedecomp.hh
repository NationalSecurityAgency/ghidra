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
// Interface to the decompilation routines

#ifndef __IFACE_DECOMP__
#define __IFACE_DECOMP__

#include "ifaceterm.hh"
#include "graph.hh"
#include "grammar.hh"
#include "callgraph.hh"
#include "paramid.hh"
#ifdef CPUI_RULECOMPILE
#include "rulecompile.hh"
#endif

class IfaceDecompCapability : public IfaceCapability {
  static IfaceDecompCapability ifaceDecompCapability;		// Singleton instance
  IfaceDecompCapability(void);	// Singleton
  IfaceDecompCapability(const IfaceDecompCapability &op2);	// Not implemented
  IfaceDecompCapability &operator=(const IfaceDecompCapability &op2);	// Not implemented
public:
  virtual void registerCommands(IfaceStatus *status);
};

class IfaceDecompData : public IfaceData {
public:
  Funcdata *fd;		// Current function data
  Architecture *conf;
  CallGraph *cgraph;

  map<Funcdata*,PrototypePieces> prototypePieces;
  void storePrototypePieces( Funcdata *fd_in, PrototypePieces pp_in ) { prototypePieces.insert(pair<Funcdata*,PrototypePieces>(fd_in,pp_in)); }
  PrototypePieces findPrototypePieces( Funcdata *fd_in ) { return (*prototypePieces.find(fd_in)).second; }

#ifdef CPUI_RULECOMPILE
  string experimental_file;	// File containing experimental rules
#endif
#ifdef OPACTION_DEBUG
  bool jumptabledebug;
#endif
  IfaceDecompData(void);
  virtual ~IfaceDecompData(void);
  void allocateCallGraph(void);
  void abortFunction(ostream &s);
  void clearArchitecture(void);
};

class IfaceAssemblyEmit : public AssemblyEmit {
  int4 mnemonicpad;		// How much to pad the mnemonic
  ostream *s;
public:
  IfaceAssemblyEmit(ostream *val,int4 mp) { s = val; mnemonicpad=mp; }
  virtual void dump(const Address &addr,const string &mnem,const string &body) {
    addr.printRaw(*s);
    *s << ": " << mnem;
    for(int4 i=mnem.size();i<mnemonicpad;++i) *s << ' ';
    *s << body << endl;
  }
};

extern void execute(IfaceStatus *status,IfaceDecompData *dcp);
extern void mainloop(IfaceStatus *status);

class IfaceDecompCommand : public IfaceCommand {
protected:
  IfaceStatus *status;
  IfaceDecompData *dcp;
  void iterateScopesRecursive(Scope *scope);
  void iterateFunctionsAddrOrder(Scope *scope);
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) { status = root; dcp = (IfaceDecompData *)data; }
  virtual string getModule(void) const { return "decompile"; }
  virtual IfaceData *createData(void) { return new IfaceDecompData(); }
  virtual void iterationCallback(Funcdata *fd) {}
  void iterateFunctionsAddrOrder(void);
  void iterateFunctionsLeafOrder(void);
};

class IfcSource : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcOption : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcParseLine : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcParseFile : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcAdjustVma : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcFuncload : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcAddrrangeLoad : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCleararch : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcReadSymbols : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcMapaddress : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcMaphash : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcMapfunction : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcMapexternalref : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcMaplabel : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintdisasm : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcDump : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcDumpbinary : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcDecompile : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintLanguage : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintCXml : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintCFlat : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintCStruct : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintCGlobals : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintCTypes : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcProduceC : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcProducePrototypes : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcListaction : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcListOverride : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcListprototypes : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcSetcontextrange : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcSettrackedrange : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcBreakstart : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcBreakaction : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcBreakjump : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintTree : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintBlocktree : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintSpaces : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintHigh : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcParamIDAnalysis : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};
class IfcPrintParamMeasures : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};
class IfcPrintParamMeasuresXml : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcRename : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcRetype : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcRemove : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintVarnode : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintCover : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcVarnodehighCover : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintExtrapop : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcVarnodeCover : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcNameVarnode : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTypeVarnode : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcForceHex : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcForceDec : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcForcegoto : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcProtooverride : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcJumpOverride : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcFlowOverride : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcDeadcodedelay : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGlobalAdd : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGlobalRemove : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGlobalify : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGlobalRegisters : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintInputs : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintInputsAll : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcLockPrototype : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcUnlockPrototype : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintLocalrange : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintMap : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcContinue : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintRaw : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGraphDataflow : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGraphControlflow : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcGraphDom : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCommentInstr : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcDuplicateHash : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcCallGraphDump : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCallGraphBuild : public IfaceDecompCommand {
protected:
  bool quick;
public:
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcCallGraphBuildQuick : public IfcCallGraphBuild {
  virtual void execute(istream &s);
};

class IfcCallGraphLoad : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCallGraphList : public IfaceDecompCommand {
protected:
  bool quick;
public:
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcComment : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCallFixup : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCallOtherFixup : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCountPcode : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintActionstats : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcResetActionstats : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcVolatile : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcReadonly : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPreferSplit : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcStructureBlocks : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcAnalyzeRange : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

#ifdef CPUI_RULECOMPILE
class IfcParseRule : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};
#endif

class IfcExperimentalRules : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

#ifdef OPACTION_DEBUG
class IfcDebugAction : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTraceBreak : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTraceAddress : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTraceEnable : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTraceDisable : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTraceClear : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcTraceList : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

#endif

#endif

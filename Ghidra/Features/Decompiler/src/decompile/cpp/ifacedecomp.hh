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
/// \file ifacedecomp.hh
/// \brief Console interface commands for the decompiler engine

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

/// \brief Interface capability point for all decompiler commands
class IfaceDecompCapability : public IfaceCapability {
  static IfaceDecompCapability ifaceDecompCapability;		///< Singleton instance
  IfaceDecompCapability(void);					///< Singleton constructor
  IfaceDecompCapability(const IfaceDecompCapability &op2);	///< Not implemented
  IfaceDecompCapability &operator=(const IfaceDecompCapability &op2);	///< Not implemented
public:
  virtual void registerCommands(IfaceStatus *status);
};

/// \brief Common data shared by decompiler commands
class IfaceDecompData : public IfaceData {
public:
  Funcdata *fd;		///< Current function active in the console
  Architecture *conf;	///< Current architecture/program active in the console
  CallGraph *cgraph;	///< Call-graph information for the program

  map<Funcdata*,PrototypePieces> prototypePieces;
  void storePrototypePieces( Funcdata *fd_in, PrototypePieces pp_in ) { prototypePieces.insert(pair<Funcdata*,PrototypePieces>(fd_in,pp_in)); }
  PrototypePieces findPrototypePieces( Funcdata *fd_in ) { return (*prototypePieces.find(fd_in)).second; }

#ifdef CPUI_RULECOMPILE
  string experimental_file;	// File containing experimental rules
#endif
#ifdef OPACTION_DEBUG
  bool jumptabledebug;
#endif
  IfaceDecompData(void);		///< Constructor
  virtual ~IfaceDecompData(void);
  void allocateCallGraph(void);		///< Allocate the call-graph object
  void abortFunction(ostream &s);	///< Clear references to current function
  void clearArchitecture(void);		///< Free all resources for the current architecture/program
  void followFlow(ostream &s,int4 size);
  Varnode *readVarnode(istream &s);	///< Read a varnode from the given stream
};

/// \brief Disassembly emitter that prints to a console stream
///
/// An instruction is printed to a stream simply, as an address
/// followed by the mnemonic and then column aligned operands.
class IfaceAssemblyEmit : public AssemblyEmit {
  int4 mnemonicpad;		///< How much to pad the mnemonic
  ostream *s;			///< The current stream to write to
public:
  IfaceAssemblyEmit(ostream *val,int4 mp) { s = val; mnemonicpad=mp; }	///< Constructor
  virtual void dump(const Address &addr,const string &mnem,const string &body) {
    addr.printRaw(*s);
    *s << ": " << mnem;
    for(int4 i=mnem.size();i<mnemonicpad;++i) *s << ' ';
    *s << body << endl;
  }
};

extern void execute(IfaceStatus *status,IfaceDecompData *dcp);	///< Execute one command for the console
extern void mainloop(IfaceStatus *status);			///< Execute commands as they become available

/// \brief Root class for all decompiler specific commands
///
/// Commands share the data object IfaceDecompData and are capable of
/// iterating over all functions in the program/architecture.
class IfaceDecompCommand : public IfaceCommand {
protected:
  IfaceStatus *status;			///< The console owning \b this command
  IfaceDecompData *dcp;			///< Data common to decompiler commands
  void iterateScopesRecursive(Scope *scope);	///< Iterate recursively over all functions in given scope
  void iterateFunctionsAddrOrder(Scope *scope);	///< Iterate over all functions in a given scope
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) { status = root; dcp = (IfaceDecompData *)data; }
  virtual string getModule(void) const { return "decompile"; }
  virtual IfaceData *createData(void) { return new IfaceDecompData(); }

  /// \brief Perform the per-function aspect of \b this command.
  ///
  /// \param fd is the particular function to operate on
  virtual void iterationCallback(Funcdata *fd) {}

  void iterateFunctionsAddrOrder(void);		///< Iterate command over all functions in all scopes
  void iterateFunctionsLeafOrder(void);		///< Iterate command over all functions in a call-graph traversal
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

class IfcPrintParamMeasures : public IfaceDecompCommand {
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
  static bool nonTrivialUse(Varnode *vn);		///< Check for non-trivial use of given Varnode
  static int4 checkRestore(Varnode *vn);		///< Check if a Varnode is \e restored to its original input value
  static bool findRestore(Varnode *vn,Funcdata *fd);	///< Check if storage is \e restored
  static void print(Funcdata *fd,ostream &s);		///< Print information about function inputs
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
  static void check(Funcdata *fd,ostream &s);		///< Check for duplicate hashes in given function

};

class IfcCallGraphDump : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcCallGraphBuild : public IfaceDecompCommand {
protected:
  bool quick;		///< Set to \b true if a quick analysis is desired
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
  static void readPcodeSnippet(istream &s,string &name,string &outname,vector<string> &inname,
			       string &pcodestring);
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

class IfcExperimentalRules : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};
#endif

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

class IfcBreakjump : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

#endif

#endif

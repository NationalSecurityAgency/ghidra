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
/// \file coreaction.hh
/// \brief Core decompilation actions which are indepedent of any particular architecture
///
/// These are the internal actions.
/// They are guaranteed to not to invalidate covers.
/// (if they do they must check the covers themselves)


#ifndef __COREACTION_HH__
#define __COREACTION_HH__

#include "ruleaction.hh"
#include "blockaction.hh"
#include "funcdata.hh"

namespace ghidra {

/// \brief Gather raw p-code for a function.
class ActionStart : public Action {
public:
  ActionStart(const string &g) : Action(0,"start",g) {}		///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionStart(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.startProcessing(); return 0; }
};

/// \brief Do any post-processing after decompilation
class ActionStop : public Action {
public:
  ActionStop(const string &g) : Action(0,"stop",g) {}		///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionStop(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.stopProcessing(); return 0; }
};

/// \brief Start clean up after main transform phase
class ActionStartCleanUp : public Action {
public:
  ActionStartCleanUp(const string &g) : Action(0,"startcleanup",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionStartCleanUp(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.startCleanUp(); return 0; }
};

/// \brief Allow type recovery to start happening
///
/// The presence of \b this Action causes the function to be marked that data-type analysis
/// will be performed.  Then when \b this action is applied during analysis, the function is marked
/// that data-type analysis has started.
class ActionStartTypes : public Action {
public:
  ActionStartTypes(const string &g) : Action(0,"starttypes",g) {}	///< Constructor
  virtual void reset(Funcdata &data) { data.setTypeRecovery(true); }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionStartTypes(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (data.startTypeRecovery()) count+=1;
    return 0;
  }
};

/// \brief Analyze change to the stack pointer across sub-function calls.
class ActionStackPtrFlow : public Action {
  AddrSpace *stackspace;		///< Stack space associated with stack-pointer register
  bool analysis_finished;		///< True if analysis already performed
  static void analyzeExtraPop(Funcdata &data,AddrSpace *stackspace,int4 spcbase);
  static bool isStackRelative(Varnode *spcbasein,Varnode *vn,uintb &constval);
  static bool adjustLoad(Funcdata &data,PcodeOp *loadop,PcodeOp *storeop);
  static int4 repair(Funcdata &data,AddrSpace *id,Varnode *spcbasein,PcodeOp *loadop,uintb constz);
  static int4 checkClog(Funcdata &data,AddrSpace *id,int4 spcbase);
public:
  ActionStackPtrFlow(const string &g,AddrSpace *ss) : Action(0,"stackptrflow",g) { stackspace = ss; }	///<Constructor
  virtual void reset(Funcdata &data) { analysis_finished = false; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionStackPtrFlow(getGroup(),stackspace);
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Find Varnodes with a vectorized lane scheme and attempt to split the lanes
///
/// The Architecture lists (vector) registers that may be used to perform parallelized operations
/// on \b lanes within the register. This action looks for these registers as Varnodes, determines
/// if a particular lane scheme makes sense in terms of the function's data-flow, and then
/// rewrites the data-flow so that the lanes become explicit Varnodes.
class ActionLaneDivide : public Action {
  void collectLaneSizes(Varnode *vn,const LanedRegister &allowedLanes,LanedRegister &checkLanes);
  bool processVarnode(Funcdata &data,Varnode *vn,const LanedRegister &lanedRegister,int4 mode);
public:
  ActionLaneDivide(const string &g) : Action(rule_onceperfunc,"lanedivide",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionLaneDivide(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Make sure pointers into segmented spaces have the correct form.
///
/// Convert user-defined ops defined as segment p-code ops by a cspec tag into the internal CPUI_SEGMENTOP
class ActionSegmentize : public Action {
  int4 localcount;			///< Number of times this Action has been performed on the function
public:
  ActionSegmentize(const string &g) : Action(0,"segmentize",g) {}	///< Constructor
  virtual void reset(Funcdata &data) { localcount = 0; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionSegmentize(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Apply any overridden forced gotos
class ActionForceGoto : public Action {
public:
  ActionForceGoto(const string &g) : Action(0,"forcegoto",g) {}		///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionForceGoto(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

// \brief Perform common subexpression elimination
// class ActionCse : public Action {
// public:
//   ActionCse(const string &g) : Action(0,"cse",g) {}			///< Constructor
//   virtual Action *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Action *)0;
//     return new ActionCse(getGroup());
//   }
//   virtual int4 apply(Funcdata &data);
// };

/// \brief Perform Common Sub-expression Elimination on CPUI_MULTIEQUAL ops
class ActionMultiCse : public Action {
  static bool preferredOutput(Varnode *out1,Varnode *out2);	///< Which of two outputs is preferred
  static PcodeOp *findMatch(BlockBasic *bl,PcodeOp *target,Varnode *in);	///< Find match to CPUI_MULTIEQUAL
  bool processBlock(Funcdata &data,BlockBasic *bl);		///< Search a block for equivalent CPUI_MULTIEQUAL
public:
  ActionMultiCse(const string &g) : Action(0,"multicse",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMultiCse(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Check for one CPUI_MULTIEQUAL input set defining more than one Varnode
class ActionShadowVar : public Action {
public:
  ActionShadowVar(const string &g) : Action(0,"shadowvar",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionShadowVar(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Check for constants, with pointer type, that correspond to global symbols
class ActionConstantPtr : public Action {
  int4 localcount;		///< Number of passes made for this function
  static AddrSpace *searchForSpaceAttribute(Varnode *vn,PcodeOp *op);
  static AddrSpace *selectInferSpace(Varnode *vn,PcodeOp *op,const vector<AddrSpace *> &spaceList);
  static bool checkCopy(PcodeOp *op,Funcdata &data);
  static SymbolEntry *isPointer(AddrSpace *spc,Varnode *vn,PcodeOp *op,int4 slot,
				Address &rampoint,uintb &fullEncoding,Funcdata &data);
public:
  ActionConstantPtr(const string &g) : Action(0,"constantptr",g) {}	///< Constructor
  virtual void reset(Funcdata &data) { localcount = 0; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionConstantPtr(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Eliminate locally constant indirect calls
class ActionDeindirect : public Action {
public:
  ActionDeindirect(const string &g) : Action(0,"deindirect",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDeindirect(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Transform based on Varnode properties, such as \e read-only and \e volatile
///
/// This performs various transforms that are based on Varnode properties.
///   - Read-only Varnodes are converted to the underlying constant
///   - Volatile Varnodes are converted read/write functions
///   - Varnodes whose values are not consumed are replaced with constant 0 Varnodes
class ActionVarnodeProps : public Action {
public:
  ActionVarnodeProps(const string &g) : Action(0,"varnodeprops",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionVarnodeProps(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Mark Varnodes built out of \e legal parameters
///
/// Label a varnode with the \b directwrite attribute if:
/// that varnode can trace at least part of its data-flow ancestry to legal inputs,
/// where \b legal inputs include:  globals, spacebase registers, and normal function parameters.
/// The directwrite attribute is set on these inputs initially and then propagated
/// to other varnodes through all other ops except CPUI_INDIRECT. The attribute propagates
/// through CPUI_INDIRECT depending on the setting of -propagateIndirect-.
/// For normal decompilation, propagation through CPUI_INDIRECTs is important for stack and other
/// high-level addrtied variables that need to hold their value over ranges where they are not
/// accessed directly. But propagation adds unnecessary clutter for normalization style analysis.
class ActionDirectWrite : public Action {
  bool propagateIndirect;			///< Propagate thru CPUI_INDIRECT ops
public:
  ActionDirectWrite(const string &g,bool prop) : Action(0,"directwrite",g) { propagateIndirect=prop; }	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDirectWrite(getGroup(),propagateIndirect);
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Search for input Varnodes that have been officially provided constant values.
///
/// This class injects p-code at the beginning of the function if there is an official \e uponentry
/// injection specified for the prototype model or if there are \e tracked registers for which the
/// user has provided a constant value for.
class ActionConstbase : public Action {
public:
  ActionConstbase(const string &g) : Action(0,"constbase",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionConstbase(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Mark Varnode objects that hold stack-pointer values and set-up special data-type
class ActionSpacebase : public Action {
public:
  ActionSpacebase(const string &g) : Action(0,"spacebase",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionSpacebase(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.spacebase(); return 0; }
};

/// \brief Build Static Single Assignment (SSA) representation for function
class ActionHeritage : public Action {
public:
  ActionHeritage(const string &g) : Action(0,"heritage",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionHeritage(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.opHeritage(); return 0; }
};

/// \brief Calculate the non-zero mask property on all Varnode objects.
class ActionNonzeroMask : public Action {
public:
  ActionNonzeroMask(const string &g) : Action(0,"nonzeromask",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionNonzeroMask(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.calcNZMask(); return 0; }
};

/// \brief Fill-in CPUI_CAST p-code ops as required by the casting strategy
///
/// Setting the casts is complicated by type inference and
/// implied variables.  By the time this Action is run, the
/// type inference algorithm has labeled every Varnode with what
/// it thinks the type should be.  This casting algorithm tries
/// to get the code to legally match this inference result by
/// adding casts.  Following the data flow, it tries the best it
/// can to get each token to match the inferred type.  For
/// implied variables, the type is completely determined by the
/// syntax of the output language, so implied casts won't work in this case.
/// For most of these cases, the algorithm just changes the type
/// to that dictated by syntax and gets back on track at the
/// next explicit variable in the flow. It tries to avoid losing
/// pointer types however because any CPUI_PTRADD \b mst have a pointer
/// input. In this case, it casts to the necessary pointer type
/// immediately.
class ActionSetCasts : public Action {
  static void checkPointerIssues(PcodeOp *op,Varnode *vn,Funcdata &data);
  static bool testStructOffset0(Datatype *reqtype,Datatype *curtype,CastStrategy *castStrategy);
  static bool tryResolutionAdjustment(PcodeOp *op,int4 slot,Funcdata &data);
  static bool isOpIdentical(Datatype *ct1,Datatype *ct2);
  static int4 resolveUnion(PcodeOp *op,int4 slot,Funcdata &data);
  static int4 castOutput(PcodeOp *op,Funcdata &data,CastStrategy *castStrategy);
  static int4 castInput(PcodeOp *op,int4 slot,Funcdata &data,CastStrategy *castStrategy);
  static PcodeOp *insertPtrsubZero(PcodeOp *op,int4 slot,Datatype *ct,Funcdata &data);
public:
  ActionSetCasts(const string &g) : Action(rule_onceperfunc,"setcasts",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionSetCasts(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Assign initial high-level HighVariable objects to each Varnode
class ActionAssignHigh : public Action {
public:
  ActionAssignHigh(const string &g) : Action(rule_onceperfunc,"assignhigh",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionAssignHigh(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.setHighLevel(); return 0; }
};

/// \brief Mark illegal Varnode inputs used only in CPUI_INDIRECT ops
class ActionMarkIndirectOnly : public Action {
public:
  ActionMarkIndirectOnly(const string &g) : Action(rule_onceperfunc, "markindirectonly",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMarkIndirectOnly(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.markIndirectOnly(); return 0; }
};

/// \brief Make \e required Varnode merges as dictated by CPUI_MULTIEQUAL, CPUI_INDIRECT, and \e addrtied property
class ActionMergeRequired : public Action {
public:
  ActionMergeRequired(const string &g) : Action(rule_onceperfunc,"mergerequired",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMergeRequired(getGroup());
  }
  virtual int4 apply(Funcdata &data) { 
    data.getMerge().mergeAddrTied(); data.getMerge().groupPartials(); data.getMerge().mergeMarker(); return 0; }
};

/// \brief Try to merge an op's input Varnode to its output, if they are at the same storage location.
class ActionMergeAdjacent : public Action {
public:
  ActionMergeAdjacent(const string &g) : Action(rule_onceperfunc,"mergeadjacent",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMergeAdjacent(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.getMerge().mergeAdjacent(); return 0; }
};

/// \brief Try to merge the input and output Varnodes of a CPUI_COPY op
class ActionMergeCopy : public Action {
public:
  ActionMergeCopy(const string &g) : Action(rule_onceperfunc,"mergecopy",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMergeCopy(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.getMerge().mergeOpcode(CPUI_COPY); return 0; }
};

/// \brief Try to merge Varnodes specified by Symbols with multiple SymbolEntrys
class ActionMergeMultiEntry : public Action {
public:
  ActionMergeMultiEntry(const string &g) : Action(rule_onceperfunc,"mergemultientry",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMergeMultiEntry(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.getMerge().mergeMultiEntry(); return 0; }
};

/// \brief Try to merge Varnodes of the same type (if they don't hold different values at the same time)
class ActionMergeType : public Action {
public:
  ActionMergeType(const string &g) : Action(rule_onceperfunc,"mergetype",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMergeType(getGroup());
  }
  virtual int4 apply(Funcdata &data) { 
    data.getMerge().mergeByDatatype(data.beginLoc(),data.endLoc()); return 0; }
};

/// \brief Find \b explicit Varnodes: Varnodes that have an explicit token representing them in the output
///
/// In the final output of the syntax tree as source code, all variables are characterized as either
///    - \b explicit, having a specific identifier in the source code, or
///    - \b implied, an intermediate result of an expression with no specific identifier
///
/// This Action does preliminary scanning of Varnodes to determine which should be explicit
/// in the final output.  Basically, if there is symbol information associated, the possibility
/// of aliasing, or if there are too many reads of a Varnode, it should be considered explicit.
class ActionMarkExplicit : public Action {
  /// This class holds a single entry in a stack used to traverse Varnode expressions
  struct OpStackElement {
    Varnode *vn;		///< The Varnode at this particular point in the path
    int4 slot;			///< The slot of the first input Varnode to traverse in this subexpression
    int4 slotback;		///< The slot(+1) of the last input Varnode to traverse in this subexpression
    OpStackElement(Varnode *v);	///< Constructor
  };
  static int4 baseExplicit(Varnode *vn,int4 maxref);	///< Make initial determination if a Varnode should be \e explicit
  static int4 multipleInteraction(vector<Varnode *> &multlist);	///< Find multiple descendant chains
  static void processMultiplier(Varnode *vn,int4 max);	///< For a given multi-descendant Varnode, decide if it should be explicit
  static void checkNewToConstructor(Funcdata &data,Varnode *vn);	///< Set special properties on output of CPUI_NEW
public:
  ActionMarkExplicit(const string &g) : Action(rule_onceperfunc,"markexplicit",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMarkExplicit(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Mark all the \e implied Varnode objects, which will have no explicit token in the output
class ActionMarkImplied : public Action {
  /// This class holds a single entry in a stack used to forward traverse Varnode expressions
  struct DescTreeElement {
    Varnode *vn;				///< The Varnode at this particular point in the path
    list<PcodeOp *>::const_iterator desciter;	///< The current edge being traversed
    DescTreeElement(Varnode *v) {
      vn = v; desciter = v->beginDescend(); }	///< Constructor
  };
  static bool isPossibleAliasStep(Varnode *vn1,Varnode *vn2);	///< Check for additive relationship
  static bool isPossibleAlias(Varnode *vn1,Varnode *vn2,int4 depth);	///< Check for possible duplicate value
  static bool checkImpliedCover(Funcdata &data,Varnode *vn);	///< Check for cover violation if Varnode is implied
public:
  ActionMarkImplied(const string &g) : Action(rule_onceperfunc,"markimplied",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMarkImplied(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Choose names for all high-level variables (HighVariables)
class ActionNameVars : public Action {
  /// This class is a record in a database used to store and lookup potential names
  struct OpRecommend {
    Datatype *ct;		///< The data-type associated with a name
    string namerec;		///< A possible name for a variable
  };
  static void makeRec(ProtoParameter *param,Varnode *vn,map<HighVariable *,OpRecommend> &recmap);
  static void lookForBadJumpTables(Funcdata &data);	///< Mark the switch variable for bad jump-tables
  static void lookForFuncParamNames(Funcdata &data,const vector<Varnode *> &varlist);
  static void linkSpacebaseSymbol(Varnode *vn,Funcdata &data,vector<Varnode *> &namerec);
  static void linkSymbols(Funcdata &data,vector<Varnode *> &namerec);
public:
  ActionNameVars(const string &g) : Action(rule_onceperfunc,"namevars",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionNameVars(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Remove unreachable blocks
class ActionUnreachable : public Action {
public:
  ActionUnreachable(const string &g) : Action(0,"unreachable",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionUnreachable(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Remove blocks that do nothing
class ActionDoNothing : public Action {
public:
  ActionDoNothing(const string &g) : Action(rule_repeatapply,"donothing",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDoNothing(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Get rid of \b redundant branches: duplicate edges between the same input and output block
class ActionRedundBranch : public Action {
public:
  ActionRedundBranch(const string &g) : Action(0,"redundbranch",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionRedundBranch(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Remove conditional branches if the condition is constant
class ActionDeterminedBranch : public Action {
public:
  ActionDeterminedBranch(const string &g) : Action(0,"determinedbranch",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDeterminedBranch(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Dead code removal.  Eliminate \e dead p-code ops
///
/// This is a very fine grained algorithm, it detects usage
/// of individual bits within the Varnode, not just use of the
/// Varnode itself.  Each Varnode has a \e consumed word, which
/// indicates if a bit in the Varnode is being used, and it has
/// two flags layed out as follows:
///    - Varnode::lisconsume = varnode is in the working list
///    - Varnode::vacconsume = vacuously used bit
///            there is a path from the varnode through assignment
///            op outputs down to a varnode that is used
///
/// The algorithm works by back propagating the \e consumed value
/// up from the output of the op to its inputs, starting with
/// a set of seed Varnodes which are marked as completely used
/// (function inputs, branch conditions, ...) For each propagation
/// the particular op being passed through can transform the
/// "bit usage" vector of the output to obtain the input.
class ActionDeadCode : public Action {
  static void pushConsumed(uintb val,Varnode *vn,vector<Varnode *> &worklist);
  static void propagateConsumed(vector<Varnode *> &worklist);
  static bool neverConsumed(Varnode *vn,Funcdata &data);
  static void markConsumedParameters(FuncCallSpecs *fc,vector<Varnode *> &worklist);
  static uintb gatherConsumedReturn(Funcdata &data);
  static bool lastChanceLoad(Funcdata &data,vector<Varnode *> &worklist);
public:
  ActionDeadCode(const string &g) : Action(0,"deadcode",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDeadCode(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Propagate conditional constants
class ActionConditionalConst : public Action {
  static void clearMarks(const vector<PcodeOp *> &opList);
  static void collectReachable(Varnode *vn,vector<PcodeOpNode> &phiNodeEdges,vector<PcodeOp *> &reachable);
  static bool flowToAlternatePath(PcodeOp *op);
  static bool flowTogether(const vector<PcodeOpNode> &edges,int4 i,vector<int4> &result);
  static Varnode *placeCopy(PcodeOp *op,BlockBasic *bl,Varnode *constVn,Funcdata &data);
  static void placeMultipleConstants(vector<PcodeOpNode> &phiNodeEdges,vector<int4> &marks,Varnode *constVn,Funcdata &data);
  void handlePhiNodes(Varnode *varVn,Varnode *constVn,vector<PcodeOpNode> &phiNodeEdges,Funcdata &data);
  void propagateConstant(Varnode *varVn,Varnode *constVn,FlowBlock *constBlock,bool useMultiequal,Funcdata &data);
public:
  ActionConditionalConst(const string &g) : Action(0,"condconst",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionConditionalConst(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Normalize jump-table construction.
///
/// This involves folding switch variable normalization and the \b guard instructions into
/// the \b switch action. The case labels are also calculated based on the normalization.
class ActionSwitchNorm : public Action {
public:
  ActionSwitchNorm(const string &g) : Action(0,"switchnorm",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionSwitchNorm(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Prepare function prototypes for "normalize" simplification.
///
/// The "normalize" simplification style has the fundamental requirement that the input parameter
/// types must not be locked, as locking can cause changes in the data-flow that "normalize" is
/// trying to normalize, because:
///   1)  The decompiler views locking as useful aliasing information
///   2)  Locking forces varnodes to exist up-front, which can affect subflow analysis
///   3)  ... probably other differences
///
/// This action removes any input symbols on the function, locked or otherwise,
/// Similarly there should be no lock on the output and no lock on the prototype model
class ActionNormalizeSetup : public Action {
public:
  ActionNormalizeSetup(const string &g) : Action(rule_onceperfunc,"normalizesetup",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionNormalizeSetup(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Lay down locked input and output data-type information.
///
/// Build forced input/output Varnodes and extend them as appropriate.
/// Set types on output forced Varnodes (input types are set automatically by the database).
/// Initialize output recovery process.
class ActionPrototypeTypes: public Action {
public:
  void extendInput(Funcdata &data,Varnode *invn,ProtoParameter *param,BlockBasic *topbl);
  ActionPrototypeTypes(const string &g) : Action(rule_onceperfunc,"prototypetypes",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionPrototypeTypes(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Find a prototype for each sub-function
///
/// This loads prototype information, if it exists for each sub-function. If no explicit
/// prototype exists, a default is selected.  If the prototype model specifies
/// \e uponreturn injection, the p-code is injected at this time.
class ActionDefaultParams : public Action {
public:
  ActionDefaultParams(const string &g) : Action(rule_onceperfunc,"defaultparams",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDefaultParams(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Define formal link between stack-pointer values before and after sub-function calls.
///
/// Change to the stack-pointer across a sub-function is called \b extrapop. This class
/// makes sure there is p-code relationship between the Varnode coming into a sub-function
/// and the Varnode coming out.  If the \e extrapop is known, the p-code will be
/// a CPUI_COPY or CPUI_ADD. If it is unknown, a CPUI_INDIRECT will be inserted that gets
/// filled in by ActionStackPtrFlow.
class ActionExtraPopSetup : public Action {
  AddrSpace *stackspace;		///< The stack space to analyze
public:
  ActionExtraPopSetup(const string &g,AddrSpace *ss) : Action(rule_onceperfunc,"extrapopsetup",g) { stackspace = ss; }	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionExtraPopSetup(getGroup(),stackspace);
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Prepare for data-flow analysis of function parameters
///
/// If exact prototypes are known for sub-functions, insert the appropriate
/// Varnodes to match the parameters. If not known, prepare the sub-function for
/// the parameter recovery process.
class ActionFuncLink : public Action {
  friend class ActionFuncLinkOutOnly;
  static void funcLinkInput(FuncCallSpecs *fc,Funcdata &data);
  static void funcLinkOutput(FuncCallSpecs *fc,Funcdata &data);
public:
  ActionFuncLink(const string &g) : Action(rule_onceperfunc,"funclink",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionFuncLink(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Prepare for data-flow analysis of function parameters, when recovery isn't required.
///
/// If the "protorecovery" action group is not enabled, this
/// Action probably should be. It sets up only the potential
/// sub-function outputs (not the inputs) otherwise local uses of
/// the output registers may be incorrectly heritaged, screwing
/// up the local analysis (i.e. for jump-tables) even though we
/// don't care about the function inputs.
class ActionFuncLinkOutOnly : public Action {
public:
  ActionFuncLinkOutOnly(const string &g) : Action(rule_onceperfunc,"funclink_outonly",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionFuncLinkOutOnly(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Deal with situations that look like double precision parameters
///
/// Check each sub-function for parameter concatenation situations:
///    - if the sub-function is in the middle of parameter recovery, check if the CONCAT
///         is an artifact of the heritage process and arbitrarily grouping parameters together.
///    - if the CONCAT is correct, producing a locked double precision parameter, make
///         sure the pieces are properly labeled.
class ActionParamDouble : public Action {
public:
  ActionParamDouble(const string &g) : Action(0, "paramdouble",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionParamDouble(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Determine active parameters to sub-functions
///
/// This is the final stage of the parameter recovery process, when
/// a prototype for a sub-function is not explicitly known. Putative input Varnode
/// parameters are collected by the Heritage process.  This class determines
/// which of these Varnodes are being used as parameters.
/// This needs to be called \b after ActionHeritage and \b after ActionDirectWrite
/// but \b before any simplification or copy propagation has been performed.
class ActionActiveParam : public Action {
public:
  ActionActiveParam(const string &g) : Action( 0, "activeparam",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionActiveParam(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Determine which sub-functions have active output Varnodes
///
/// This is analogous to ActionActiveParam but for sub-function return values.
class ActionActiveReturn : public Action {
public:
  ActionActiveReturn(const string &g) : Action( 0, "activereturn",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionActiveReturn(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

// \brief If there are any sub-function calls with \e paramshifts, add the shifted parameters.
// class ActionParamShiftStart : public Action {
// public:
//   ActionParamShiftStart(const string &g) : Action( rule_onceperfunc, "paramshiftstart",g) {}	///< Constructor
//   virtual Action *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Action *)0;
//     return new ActionParamShiftStart(getGroup());
//   }
//   virtual int4 apply(Funcdata &data);
// };

// \brief If there are any sub-function calls with \e paramshifts, remove the shifted parameters.
// class ActionParamShiftStop : public Action {
//   bool paramshiftsleft;
// public:
//   ActionParamShiftStop(const string &g) : Action( 0, "paramshiftstop",g) {}	///< Constructor
//   virtual void reset(Funcdata &data) { paramshiftsleft = true; }
//   virtual Action *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Action *)0;
//     return new ActionParamShiftStop(getGroup());
//   }
//   virtual int4 apply(Funcdata &data);
// };

/// \brief Determine data-flow holding the \e return \e value of the function.
class ActionReturnRecovery : public Action {
  static void buildReturnOutput(ParamActive *active,PcodeOp *retop,Funcdata &data);
public:
  ActionReturnRecovery(const string &g) : Action( 0, "returnrecovery",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionReturnRecovery(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Restrict possible range of local variables
///
/// Mark what we know of parameters and unaffected stores
/// so that they cannot be treated as local variables.
class ActionRestrictLocal : public Action {
public:
  ActionRestrictLocal(const string &g) : Action(0,"restrictlocal",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionRestrictLocal(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Get rid of registers with trash values.
///
/// Register locations called \b likely \b trash are read as a side-effect of some instruction
/// the compiler was using.  The canonical example in x86 code is the
///     PUSH ECX
/// which compilers use to create space on the stack without caring about what's in ECX.
/// Even though the decompiler can see that the read ECX value is never getting used directly
/// by the function, because the value is getting copied to the stack, the decompiler frequently
/// can't tell if the value has been aliased across sub-function calls. By marking the ECX register
/// as \b likely \ trash the decompiler will assume that, unless there is a direct read of the
/// incoming ECX, none of subfunctions alias the stack location where ECX was stored.  This
/// allows the spurious references to the register to be removed.
class ActionLikelyTrash : public Action {
  static uint4 countMarks(PcodeOp *op);
  static bool traceTrash(Varnode *vn,vector<PcodeOp *> &indlist);
public:
  ActionLikelyTrash(const string &g) : Action(0,"likelytrash",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionLikelyTrash(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Create symbols that map out the local stack-frame for the function.
///
/// This produces on intermediate view of symbols on the stack.
class ActionRestructureVarnode : public Action {
  int4 numpass;			///< Number of passes performed for this function
  static bool isDelayedConstant(Varnode *vn);		///< Determine if given Varnode is or will be a constant
  static void protectSwitchPathIndirects(PcodeOp *op);	///< Protect path to the given switch from INDIRECT collapse
  static void protectSwitchPaths(Funcdata &data);	///< Look for switches and protect path of switch variable
public:
  ActionRestructureVarnode(const string &g) : Action(0,"restructure_varnode",g) {}	///< Constructor
  virtual void reset(Funcdata &data) { numpass = 0; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionRestructureVarnode(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Do final synchronization of symbols in the local scope with Varnodes
///
/// Push data-types from the last local scope restructuring onto Varnodes
class ActionMappedLocalSync : public Action {
public:
  ActionMappedLocalSync(const string &g) : Action(0,"mapped_local_sync",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMappedLocalSync(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Create symbols for any discovered global variables in the function.
class ActionMapGlobals : public Action {
public:
  ActionMapGlobals(const string &g) : Action(rule_onceperfunc,"mapglobals",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionMapGlobals(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.mapGlobals(); return 0; }
};

/// \brief Calculate the prototype for the function.
///
/// If the prototype wasn't originally known, the discovered input Varnodes are analyzed
/// to determine a prototype based on the prototype model.
class ActionInputPrototype : public Action {
public:
  ActionInputPrototype(const string &g) : Action(rule_onceperfunc,"inputprototype",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionInputPrototype(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Set the (already) recovered output data-type as a formal part of the prototype
class ActionOutputPrototype : public Action {
public:
  ActionOutputPrototype(const string &g) : Action(rule_onceperfunc,"outputprototype",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionOutputPrototype(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Adjust improperly justified parameters
///
/// Scan through all inputs, find Varnodes that look like improperly justified input parameters
/// create a new full input, and change the old partial input to be formed as a CPUI_SUBPIECE of the
/// full input
class ActionUnjustifiedParams : public Action {
public:
  ActionUnjustifiedParams(const string &g) : Action(0,"unjustparams",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionUnjustifiedParams(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Infer and propagate data-types.
///
/// Atomic data-types are ordered from \e most specified to \e least specified.
/// This is extended rescursively to an ordering on composite data-types via Datatype::typeOrder().
/// A local data-type is calculated for each Varnode by looking at the data-types
/// expected by the PcodeOps it is directly involved in (as input or output).
/// Every Varnode has 1 chance to propagate its information throughout the graph
/// along COPY,LOAD,STORE,ADD,MULTIEQUAL,and INDIRECT edges. The propagation is
/// done with a depth first search along propagating edges.  If the propagated
/// data-type is the same, less than, or if the varnode had been propagated through
/// already, that branch is trimmed.  Every edge can theoretically get traversed
/// once, i.e. the search allows the type to propagate through a looping edge,
/// but immediately truncates.
/// This is probably quadratic in the worst case, if each Varnode has a higher
/// type and propagates it to the entire graph.  But it is linear in practice,
/// because there are generally only two or three levels of type, so only one
/// or two Varnodes are likely to propagate widely within a component, and
/// the others get truncated immediately.  An initial sort on the data-type level
/// of the Varnodes, so that the highest-level types are propagated first,
/// would probably fix the worst-case, but this seems unnecessary.
/// Complications:
/// TYPE_SPACEBASE is a problem because we have to make sure that it doesn't
/// propagate.
/// Also, offsets off of pointers to TYPE_SPACEBASE look up the data-type in the
/// local map. Then ActionRestructure uses data-type information recovered by
/// this algorithm to reconstruct the local map.  This causes a feedback loop
/// which allows type information recovered about mapped Varnodes to be propagated
/// to pointer Varnodes which point to the mapped object.  Unfortunately under
/// rare circumstances, this feedback-loop does not converge for some reason.
/// Rather than hunt this down, I've put an arbitrary iteration limit on
/// the data-type propagation algorithm, which reports a warning if the limit is
/// reached and then aborts additional propagation so that decompiling can terminate.
class ActionInferTypes : public Action {
#ifdef TYPEPROP_DEBUG
  static void propagationDebug(Architecture *glb,Varnode *vn,const Datatype *newtype,PcodeOp *op,int4 slot,Varnode *ptralias);
#endif
  int4 localcount;					///< Number of passes performed for this function
  static void buildLocaltypes(Funcdata &data);		///< Assign initial data-type based on local info
  static bool writeBack(Funcdata &data);		///< Commit the final propagated data-types to Varnodes
  static bool propagateTypeEdge(TypeFactory *typegrp,PcodeOp *op,int4 inslot,int4 outslot);
  static void propagateOneType(TypeFactory *typegrp,Varnode *vn);
  static void propagateRef(Funcdata &data,Varnode *vn,const Address &addr);
  static void propagateSpacebaseRef(Funcdata &data,Varnode *spcvn);
  static PcodeOp *canonicalReturnOp(Funcdata &data);
  static void propagateAcrossReturns(Funcdata &data);
public:
  ActionInferTypes(const string &g) : Action(0,"infertypes",g) {}	///< Constructor
  virtual void reset(Funcdata &data) { localcount = 0; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionInferTypes(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Locate \e shadow Varnodes and adjust them so they are hidden
///
/// A \b shadow Varnode is an internal copy of another Varnode that a compiler
/// produces but that really isn't a separate variable.  In practice, a Varnode
/// and its shadow get grouped into the same HighVariable, then without this
/// Action the decompiler output shows duplicate COPY statements. This Action
/// alters the defining op of the shadow so that the duplicate statement doesn't print.
class ActionHideShadow : public Action {
public:
  ActionHideShadow(const string &g) : Action(rule_onceperfunc,"hideshadow",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionHideShadow(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Replace COPYs from the same source with a single dominant COPY
class ActionDominantCopy : public Action {
public:
  ActionDominantCopy(const string &g) : Action(rule_onceperfunc,"dominantcopy",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDominantCopy(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.getMerge().processCopyTrims(); return 0; }
};

/// \brief Mark COPY operations between Varnodes representing the object as \e non-printing
class ActionCopyMarker : public Action {
public:
  ActionCopyMarker(const string &g) : Action(rule_onceperfunc,"copymarker",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionCopyMarker(getGroup());
  }
  virtual int4 apply(Funcdata &data) { data.getMerge().markInternalCopies(); return 0; }
};

/// \brief Attach \e dynamically mapped symbols to Varnodes in time for data-type propagation
class ActionDynamicMapping : public Action {
public:
  ActionDynamicMapping(const string &g) : Action(0,"dynamicmapping",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDynamicMapping(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Make final attachments of \e dynamically mapped symbols to Varnodes
class ActionDynamicSymbols : public Action {
public:
  ActionDynamicSymbols(const string &g) : Action(rule_onceperfunc,"dynamicsymbols",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionDynamicSymbols(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Add warnings for prototypes that aren't modeled properly
class ActionPrototypeWarnings : public Action {
public:
  ActionPrototypeWarnings(const string &g) : Action(rule_onceperfunc,"prototypewarnings",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionPrototypeWarnings(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Check for constants getting written to the stack from \e internal \e storage registers
///
/// The constant is internal to the compiler and its storage location on the stack should not be addressable.
class ActionInternalStorage : public Action {
public:
  ActionInternalStorage(const string &g) : Action(rule_onceperfunc,"internalstorage",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionInternalStorage(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief A class that holds a data-type traversal state during type propagation
///
/// For a given Varnode, this class iterates all the possible edges its
/// data-type might propagate through.
class PropagationState {
public:
  Varnode *vn;					///< The root Varnode
  list<PcodeOp *>::const_iterator iter;		///< Iterator to current descendant being enumerated
  PcodeOp *op;					///< The current descendant or the defining PcodeOp
  int4 inslot;					///< Slot holding Varnode for descendant PcodeOp
  int4 slot;					///< Current edge relative to current PcodeOp
  PropagationState(Varnode *v);			///< Constructor
  void step(void);				///< Advance to the next propagation edge
  bool valid(void) const { return (op != (PcodeOp *)0); }	///< Return \b true if there are edges left to iterate
};

/// Class representing a \e term in an additive expression
class AdditiveEdge {
  PcodeOp *op;			///< Lone descendant reading the term
  int4 slot;			///< The input slot of the term
  Varnode *vn;			///< The term Varnode
  PcodeOp *mult;		///< The (optional) multiplier being applied to the term
public:
  AdditiveEdge(PcodeOp *o,int4 s,PcodeOp *m) { op = o; slot = s; vn = op->getIn(slot); mult=m; }	///< Constructor
  PcodeOp *getMultiplier(void) const { return mult; }	///< Get the multiplier PcodeOp
  PcodeOp *getOp(void) const { return op; }		///< Get the component PcodeOp adding in the term
  int4 getSlot(void) const { return slot; }		///< Get the slot reading the term
  Varnode *getVarnode(void) const { return vn; }	///< Get the Varnode term
};

/// \brief A class for ordering Varnode terms in an additive expression.
///
/// Given the final PcodeOp in a data-flow expression that sums 2 or more
/// Varnode \e terms, this class collects all the terms then allows
/// sorting of the terms to facilitate constant collapse and factoring simplifications.
class TermOrder {
  PcodeOp *root;			///< The final PcodeOp in the expression
  vector<AdditiveEdge> terms;		///< Collected terms
  vector<AdditiveEdge *> sorter;		///< An array of references to terms for quick sorting
  static bool additiveCompare(const AdditiveEdge *op1,const AdditiveEdge *op2);
public:
  TermOrder(PcodeOp *rt) { root = rt; }	///< Construct given root PcodeOp
  int4 getSize(void) const { return terms.size(); }	///< Get the number of terms in the expression
  void collect(void);			///< Collect all the terms in the expression
  void sortTerms(void);			///< Sort the terms using additiveCompare()
  const vector<AdditiveEdge *> &getSort(void) { return sorter; }	///< Get the sorted list of references
};

/// \brief A comparison operator for ordering terms in a sum
///
/// This is based on Varnode::termOrder which groups constants terms and
/// ignores multiplicative coefficients.
/// \param op1 is the first term to compare
/// \param op2 is the second term
/// \return \b true if the first term is less than the second
inline bool TermOrder::additiveCompare(const AdditiveEdge *op1,const AdditiveEdge *op2) {
    return (-1 == op1->getVarnode()->termOrder(op2->getVarnode())); }

} // End namespace ghidra
#endif

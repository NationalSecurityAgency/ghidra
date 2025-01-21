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
/// \file subflow.hh
/// \brief Classes for reducing/splitting Varnodes containing smaller logical values
#ifndef __SUBFLOW_HH__
#define __SUBFLOW_HH__

#include "ruleaction.hh"
#include "transform.hh"

namespace ghidra {

/// \brief Class for shrinking big Varnodes carrying smaller logical values
///
/// Given a root within the syntax tree and dimensions
/// of a logical variable, this class traces the flow of this
/// logical variable through its containing Varnodes.  It then
/// creates a subgraph of this flow, where there is a correspondence
/// between nodes in the subgraph and nodes in the original graph
/// containing the logical variable.  When doReplacement is called,
/// this subgraph is duplicated as a new separate piece within the
/// syntax tree.  Ops are replaced to reflect the manipulation of
/// of the logical variable, rather than the containing variable.
/// Operations in the original graph which pluck out the logical
/// variable from the containing variable, are replaced with copies
/// from the corresponding node in the new section of the graph,
/// which frequently causes the operations on the original container
/// Varnodes to becomes dead code.
class SubvariableFlow {
  class ReplaceOp;
  /// \brief Placeholder node for Varnode holding a smaller logical value
  class ReplaceVarnode {
    friend class SubvariableFlow;
    Varnode *vn;		///< Varnode being shrunk
    Varnode *replacement;	///< The new smaller Varnode
    uintb mask;			///< Bits making up the logical sub-variable
    uintb val;			///< Value of constant (when vn==NULL)
    ReplaceOp *def;		///< Defining op for new Varnode
  };

  /// \brief Placeholder node for PcodeOp operating on smaller logical values
  class ReplaceOp {
    friend class SubvariableFlow;
    PcodeOp *op;		///< op getting paralleled
    PcodeOp *replacement;	///< The new op
    OpCode opc;			///< Opcode of the new op
    int4 numparams;		///< Number of parameters in (new) op
    ReplaceVarnode *output;	///< Varnode output
    vector<ReplaceVarnode *> input; ///< Varnode inputs
  };

  /// \brief Operation with a new logical value as (part of) input, but output Varnode is unchanged
  class PatchRecord {
    friend class SubvariableFlow;
    /// The possible types of patches on ops being performed
    enum patchtype {
      copy_patch,		///< Turn op into a COPY of the logical value
      compare_patch,		///< Turn compare op inputs into logical values
      parameter_patch,		///< Convert a CALL/CALLIND/RETURN/BRANCHIND parameter into logical value
      extension_patch,		///< Convert op into something that copies/extends logical value, adding zero bits
      push_patch,		///< Convert an operator output to the logical value
      int2float_patch		///< Zero extend logical value into FLOAT_INT2FLOAT operator
    };
    patchtype type;		///< The type of \b this patch
    PcodeOp *patchOp;		///< Op being affected
    ReplaceVarnode *in1;	///< The logical variable input
    ReplaceVarnode *in2;	///< (optional second parameter)
    int4 slot;			///< slot being affected or other parameter
  };

  int4 flowsize;		///< Size of the logical data-flow in bytes
  int4 bitsize;			///< Number of bits in logical variable
  bool returnsTraversed;	///< Have we tried to flow logical value across CPUI_RETURNs
  bool aggressive;		///< Do we "know" initial seed point must be a sub variable
  bool sextrestrictions;	///< Check for logical variables that are always sign extended into their container
  Funcdata *fd;			///< Containing function
  map<Varnode *,ReplaceVarnode> varmap;	///< Map from original Varnodes to the overlaying subgraph nodes
  list<ReplaceVarnode> newvarlist;	///< Storage for subgraph variable nodes
  list<ReplaceOp> oplist;		///< Storage for subgraph op nodes
  list<PatchRecord> patchlist;	///< Operations getting patched (but with no flow thru)
  vector<ReplaceVarnode *> worklist;	///< Subgraph variable nodes still needing to be traced
  int4 pullcount;		///< Number of instructions pulling out the logical value
  static int4 doesOrSet(PcodeOp *orop,uintb mask);
  static int4 doesAndClear(PcodeOp *andop,uintb mask);
  Address getReplacementAddress(ReplaceVarnode *rvn) const;
  ReplaceVarnode *setReplacement(Varnode *vn,uintb mask,bool &inworklist);
  ReplaceOp *createOp(OpCode opc,int4 numparam,ReplaceVarnode *outrvn);
  ReplaceOp *createOpDown(OpCode opc,int4 numparam,PcodeOp *op,ReplaceVarnode *inrvn,int4 slot);
  bool tryCallPull(PcodeOp *op,ReplaceVarnode *rvn,int4 slot);
  bool tryReturnPull(PcodeOp *op,ReplaceVarnode *rvn,int4 slot);
  bool tryCallReturnPush(PcodeOp *op,ReplaceVarnode *rvn);
  bool trySwitchPull(PcodeOp *op,ReplaceVarnode *rvn);
  bool tryInt2FloatPull(PcodeOp *op,ReplaceVarnode *rvn);
  bool traceForward(ReplaceVarnode *rvn);	///< Trace the logical data-flow forward for the given subgraph variable
  bool traceBackward(ReplaceVarnode *rvn);	///< Trace the logical data-flow backward for the given subgraph variable
  bool traceForwardSext(ReplaceVarnode *rvn);	///< Trace logical data-flow forward assuming sign-extensions
  bool traceBackwardSext(ReplaceVarnode *rvn);	///< Trace logical data-flow backward assuming sign-extensions
  bool createLink(ReplaceOp *rop,uintb mask,int4 slot,Varnode *vn);
  bool createCompareBridge(PcodeOp *op,ReplaceVarnode *inrvn,int4 slot,Varnode *othervn);
  void addPush(PcodeOp *pushOp,ReplaceVarnode *rvn);
  void addTerminalPatch(PcodeOp *pullop,ReplaceVarnode *rvn);
  void addTerminalPatchSameOp(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot);
  void addBooleanPatch(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot);
  void addSuggestedPatch(ReplaceVarnode *rvn,PcodeOp *pushop,int4 sa);
  void addComparePatch(ReplaceVarnode *in1,ReplaceVarnode *in2,PcodeOp *op);
  ReplaceVarnode *addConstant(ReplaceOp *rop,uintb mask,uint4 slot,Varnode *constvn);
  ReplaceVarnode *addNewConstant(ReplaceOp *rop,uint4 slot,uintb val);
  void createNewOut(ReplaceOp *rop,uintb mask);
  void replaceInput(ReplaceVarnode *rvn);
  bool useSameAddress(ReplaceVarnode *rvn);
  Varnode *getReplaceVarnode(ReplaceVarnode *rvn);
  bool processNextWork(void);		///< Extend the subgraph from the next node in the worklist
public:
  SubvariableFlow(Funcdata *f,Varnode *root,uintb mask,bool aggr,bool sext,bool big);	///< Constructor
  bool doTrace(void);			///< Trace logical value through data-flow, constructing transform
  void doReplacement(void);		///< Perform the discovered transform, making logical values explicit
};

/// \brief Perform SubVariableFlow analysis triggered by INT_AND
class RuleSubvarAnd : public Rule {
public:
  RuleSubvarAnd(const string &g) : Rule( g, 0, "subvar_and") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarAnd(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Perform SubVariableFlow analysis triggered by SUBPIECE
class RuleSubvarSubpiece : public Rule {
public:
  RuleSubvarSubpiece(const string &g) : Rule( g, 0, "subvar_subpiece") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarSubpiece(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Perform SubvariableFlow analysis triggered by testing of a single bit
///
/// Given a comparison (INT_EQUAL or INT_NOTEEQUAL_ to a constant,
/// check that input has only 1 bit that can possibly be non-zero
/// and that the constant is testing this.  This then triggers
/// the full SubvariableFlow analysis.
class RuleSubvarCompZero : public Rule {
public:
  RuleSubvarCompZero(const string &g) : Rule( g, 0, "subvar_compzero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarCompZero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Perform SubvariableFlow analysis triggered by INT_RIGHT
///
/// If the INT_RIGHT input has only 1 bit that can possibly be non-zero
/// and it is getting shifted into the least significant bit position,
/// trigger the full SubvariableFlow analysis.
class RuleSubvarShift : public Rule {
public:
  RuleSubvarShift(const string &g) : Rule( g, 0, "subvar_shift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Perform SubvariableFlow analysis triggered by INT_ZEXT
class RuleSubvarZext : public Rule {
public:
  RuleSubvarZext(const string &g) : Rule( g, 0, "subvar_zext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Perform SubvariableFlow analysis triggered by INT_SEXT
class RuleSubvarSext : public Rule {
  int4 isaggressive;			///< Is it guaranteed the root is a sub-variable needing to be trimmed
public:
  RuleSubvarSext(const string &g) : Rule( g, 0, "subvar_sext") { isaggressive = false; }	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarSext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  virtual void reset(Funcdata &data);
};

/// \brief Class for splitting up Varnodes that hold 2 logical variables
///
/// Starting from a \e root Varnode provided to the constructor, \b this class looks for data-flow
/// that consistently holds 2 logical values in a single Varnode. If doTrace() returns \b true,
/// a consistent view has been created and invoking apply() will split all Varnodes  and PcodeOps
/// involved in the data-flow into their logical pieces.
class SplitFlow : public TransformManager {
  LaneDescription laneDescription;	///< Description of how to split Varnodes
  vector<TransformVar *> worklist;	///< Pending work list of Varnodes to push the split through
  TransformVar *setReplacement(Varnode *vn);
  bool addOp(PcodeOp *op,TransformVar *rvn,int4 slot);
  bool traceForward(TransformVar *rvn);
  bool traceBackward(TransformVar *rvn);
  bool processNextWork(void);		///< Process the next logical value on the worklist
public:
  SplitFlow(Funcdata *f,Varnode *root,int4 lowSize);	///< Constructor
  bool doTrace(void);			///< Trace split through data-flow, constructing transform
};

/// \brief Try to detect and split artificially joined Varnodes
///
/// Look for SUBPIECE coming from a PIECE that has come through INDIRECTs and/or MULTIEQUAL
/// Then: check if the input to SUBPIECE can be viewed as two independent pieces
/// If so:  split the pieces into independent data-flows
class RuleSplitFlow : public Rule {
public:
  RuleSplitFlow(const string &g) : Rule( g, 0, "splitflow") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSplitFlow(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Split a p-code COPY, LOAD, or STORE op based on underlying composite data-type
///
/// During the cleanup phase, if a COPY, LOAD, or STORE occurs on a partial structure or array
/// (TypePartialStruct), try to break it up into multiple operations that each act on logical component
/// of the structure or array.
class SplitDatatype {
  /// \brief A helper class describing a pair of matching data-types for the split
  ///
  /// Data-types being copied simultaneously are split up into these matching pairs.
  class Component {
    friend class SplitDatatype;
    Datatype *inType;		///< Data-type coming into the logical COPY operation
    Datatype *outType;		///< Data-type coming out of the logical COPY operation
    int4 offset;		///< Offset of this logical piece within the whole
  public:
    Component(Datatype *in,Datatype *out,int4 off) { inType=in; outType=out; offset=off; }	///< Constructor
  };
  /// \brief A helper class describing the pointer being passed to a LOAD or STORE
  ///
  /// It makes distinction between the immediate pointer to the LOAD or STORE and a \e root pointer
  /// to the main structure or array, which the immediate pointer may be at an offset from.
  class RootPointer {
    friend class SplitDatatype;
    PcodeOp *loadStore;			///< LOAD or STORE op
    TypePointer *ptrType;		///< Base pointer data-type of LOAD or STORE
    Varnode *firstPointer;		///< Direct pointer input for LOAD or STORE
    Varnode *pointer;			///< The root pointer
    int4 baseOffset;			///< Offset of the LOAD or STORE relative to root pointer
    bool backUpPointer(Datatype *impliedBase);		///< Follow flow of \b pointer back thru INT_ADD or PTRSUB
  public:
    bool find(PcodeOp *op,Datatype *valueType);	///< Locate root pointer for underlying LOAD or STORE
    void duplicateToTemp(Funcdata &data,PcodeOp *followOp);	///< COPY the root varnode into a temp register
    void freePointerChain(Funcdata &data);	///< Remove unused pointer calculations
  };
  Funcdata &data;			///< The containing function
  TypeFactory *types;			///< The data-type container
  vector<Component> dataTypePieces;	///< Sequence of all data-type pairs being copied
  bool splitStructures;			///< Whether or not structures should be split
  bool splitArrays;			///< Whether or not arrays should be split
  bool isLoadStore;			///< True if trying to split LOAD or STORE
  Datatype *getComponent(Datatype *ct,int4 offset,bool &isHole);
  int4 categorizeDatatype(Datatype *ct);	///< Categorize if and how data-type should be split
  bool testDatatypeCompatibility(Datatype *inBase,Datatype *outBase,bool inConstant);
  bool testCopyConstraints(PcodeOp *copyOp);
  bool generateConstants(Varnode *vn,vector<Varnode *> &inVarnodes);
  void buildInConstants(Varnode *rootVn,vector<Varnode *> &inVarnodes,bool bigEndian);
  void buildInSubpieces(Varnode *rootVn,PcodeOp *followOp,vector<Varnode *> &inVarnodes);
  void buildOutVarnodes(Varnode *rootVn,vector<Varnode *> &outVarnodes);
  void buildOutConcats(Varnode *rootVn,PcodeOp *previousOp,vector<Varnode *> &outVarnodes);
  void buildPointers(Varnode *rootVn,TypePointer *ptrType,int4 baseOffset,PcodeOp *followOp,
		     vector<Varnode *> &ptrVarnodes,bool isInput);
  static bool isArithmeticInput(Varnode *vn);	///< Is \b this the input to an arithmetic operation
  static bool isArithmeticOutput(Varnode *vn);	///< Is \b this defined by an arithmetic operation
public:
  SplitDatatype(Funcdata &func);			///< Constructor
  bool splitCopy(PcodeOp *copyOp,Datatype *inType,Datatype *outType);	///< Split a COPY operation
  bool splitLoad(PcodeOp *loadOp,Datatype *inType);	///< Split a LOAD operation
  bool splitStore(PcodeOp *storeOp,Datatype *outType);	///< Split a STORE operation
  static Datatype *getValueDatatype(PcodeOp *loadStore,int4 size,TypeFactory *tlst);
};

/// \brief Split COPY ops based on TypePartialStruct
///
/// If more than one logical component of a structure or array is copied at once,
/// rewrite the COPY operator as multiple COPYs.
class RuleSplitCopy : public Rule {
public:
  RuleSplitCopy(const string &g) : Rule( g, 0, "splitcopy") {}		///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSplitCopy(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Split LOAD ops based on TypePartialStruct
///
/// If more than one logical component of a structure or array is loaded at once,
/// rewrite the LOAD operator as multiple LOADs.
class RuleSplitLoad : public Rule {
public:
  RuleSplitLoad(const string &g) : Rule( g, 0, "splitload") {}		///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSplitLoad(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Split STORE ops based on TypePartialStruct
///
/// If more than one logical component of a structure or array is stored at once,
/// rewrite the STORE operator as multiple STOREs.
class RuleSplitStore : public Rule {
public:
  RuleSplitStore(const string &g) : Rule( g, 0, "splitstore") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSplitStore(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Simplify join and break apart based on data-types
///
/// Simplify expressions like:
///  - `sub( concat(V,W), 0)  =>  W`
///  - `sub( concat(V,W), c)  =>  V`
///
/// preserving the data-types and removing the SUBPIECE and PIECE operations that are discarded.
class RuleDumptyHumpLate : public Rule {
public:
  RuleDumptyHumpLate(const string &g) : Rule( g, 0, "dumptyhumplate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDumptyHumpLate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Class for tracing changes of precision in floating point variables
///
/// It follows the flow of a logical lower precision value stored in higher precision locations
/// and then rewrites the data-flow in terms of the lower precision, eliminating the
/// precision conversions.
class SubfloatFlow : public TransformManager {
  /// \brief Internal state for walking floating-point data-flow and computing precision
  class State {
  public:
    PcodeOp *op;		///< Operation being traversed
    int4 slot;			///< Input edge being traversed
    int4 maxPrecision;		///< Maximum precision traversed through inputs so far
    State(PcodeOp *o) {
      op = o; slot = 0; maxPrecision = 0; }	///< Constructor
    /// \brief Accumulate precision coming in from an input Varnode to \b this node
    void incorporateInputSize(int4 sz) { maxPrecision = (maxPrecision < sz) ? sz : maxPrecision; }
  };
  int4 precision;		///< Number of bytes of precision in the logical flow
  int4 terminatorCount;		///< Number of terminating nodes reachable via the root
  const FloatFormat *format;	///< The floating-point format of the logical value
  vector<TransformVar *> worklist;	///< Current list of placeholders that still need to be traced
  map<PcodeOp *,int4> maxPrecisionMap;	///< Maximum precision flowing into a particular floating-point op
  int4 maxPrecision(Varnode *vn);	///< Calculate maximum floating-point precision reaching a given Varnode
  bool exceedsPrecision(PcodeOp *op);	///< Determine if the given op exceeds our \b precision
  TransformVar *setReplacement(Varnode *vn);
  bool traceForward(TransformVar *rvn);
  bool traceBackward(TransformVar *rvn);
  bool processNextWork(void);
public:
  SubfloatFlow(Funcdata *f,Varnode *root,int4 prec);
  virtual bool preserveAddress(Varnode *vn,int4 bitSize,int4 lsbOffset) const;
  bool doTrace(void);		///< Trace logical value as far as possible
};

/// \brief Perform SubfloatFlow analysis triggered by FLOAT_FLOAT2FLOAT
class RuleSubfloatConvert : public Rule {
public:
  RuleSubfloatConvert(const string &g) : Rule( g, 0, "subfloat_convert") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubfloatConvert(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Class for splitting data-flow on \e laned registers
///
/// From a root Varnode and a description of its \e lanes, trace data-flow as far as
/// possible through the function, propagating each lane, using the doTrace() method.  Then
/// using the apply() method, data-flow can be split, making each lane in every traced
/// register into an explicit Varnode
class LaneDivide : public TransformManager {
  /// \brief Description of a large Varnode that needs to be traced (in the worklist)
  class WorkNode {
    friend class LaneDivide;
    TransformVar *lanes;	///< Lane placeholders for underyling Varnode
    int4 numLanes;	///< Number of lanes in the particular Varnode
    int4 skipLanes;	///< Number of lanes to skip in the global description
  };

  LaneDescription description;	///< Global description of lanes that need to be split
  vector<WorkNode> workList;	///< List of Varnodes still left to trace
  bool allowSubpieceTerminator;	///< \b true if we allow lanes to be cast (via SUBPIECE) to a smaller integer size

  TransformVar *setReplacement(Varnode *vn,int4 numLanes,int4 skipLanes);
  void buildUnaryOp(OpCode opc,PcodeOp *op,TransformVar *inVars,TransformVar *outVars,int4 numLanes);
  void buildBinaryOp(OpCode opc,PcodeOp *op,TransformVar *in0Vars,TransformVar *in1Vars,TransformVar *outVars,int4 numLanes);
  bool buildPiece(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool buildMultiequal(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool buildIndirect(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool buildStore(PcodeOp *op,int4 numLanes,int4 skipLanes);
  bool buildLoad(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool buildRightShift(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool buildLeftShift(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool buildZext(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes);
  bool traceForward(TransformVar *rvn,int4 numLanes,int4 skipLanes);
  bool traceBackward(TransformVar *rvn,int4 numLanes,int4 skipLanes);
  bool processNextWork(void);		///< Process the next Varnode on the work list
public:
  LaneDivide(Funcdata *f,Varnode *root,const LaneDescription &desc,bool allowDowncast);	///< Constructor
  bool doTrace(void);		///< Trace lanes as far as possible from the root Varnode
};

} // End namespace ghidra
#endif

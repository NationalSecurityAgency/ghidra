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
#ifndef __SUBVARIABLE_FLOW__
#define __SUBVARIABLE_FLOW__

#include "funcdata.hh"

// Structures for splitting big varnodes carrying smaller logical
// variables.  Given a root within the syntax tree and dimensions
// of a logical variable, this class traces the flow of this
// logical variable through its containing varnodes.  It then
// creates a subgraph of this flow, where there is a correspondence
// between nodes in the subgraph and nodes in the original graph
// containing the logical variable.  When doReplacement is called,
// this subgraph is duplicated as a new separate piece within the
// syntax tree.  Ops are replaced to reflect the manipulation of
// of the logical variable, rather than the containing variable.
// Operations in the original graph which pluck out the logical
// variable from the containing variable, are replaced with copies
// from the corresponding node in the new section of the graph,
// which frequently causes the operations on the original container
// varnodes to becomes deadcode.

class SubvariableFlow {
  class ReplaceOp;
  class ReplaceVarnode {
    friend class SubvariableFlow;
    Varnode *vn;		// Varnode being split
    Varnode *replacement;	// The new subvariable varnode
    uintb mask;			// Bits of the logical subvariable
    uintb val;			// Value of constant (vn==NULL)
    ReplaceOp *def;		// Defining op for new varnode
  };
  
  class ReplaceOp {
    friend class SubvariableFlow;
    PcodeOp *op;		// op getting paralleled
    PcodeOp *replacement;	// The new op
    OpCode opc;		// type of new op
    int4 numparams;
    ReplaceVarnode *output;	// varnode output
    vector<ReplaceVarnode *> input; // varnode inputs
  };
  
  class PatchRecord {		// Operation where logical value is part of input, but output remains as is
    friend class SubvariableFlow;
    int4 type;			// 0=COPY 1=compare 2=call 3=AND/SHIFT
    PcodeOp *pullop;		// Op being affected
    ReplaceVarnode *in1;	// The logical variable input
    ReplaceVarnode *in2;	// (optional second parameter)
    int4 slot;			// slot being affected or other parameter
  };

  int4 flowsize;			// Size of the data-flow
  int4 bitsize;			// Number of bits in logical variable
  bool returnsTraversed;	// Have we tried to flow logical value across CPUI_RETURNs
  bool aggressive;		// Do we "know" initial seed point must be a sub variable
  bool sextrestrictions;	// Check for logical variables that are always sign extended into their container
  Funcdata *fd;
  map<Varnode *,ReplaceVarnode> varmap;
  list<ReplaceVarnode> newvarlist;
  list<ReplaceOp> oplist;
  list<PatchRecord> patchlist;	// Operations getting patched (but no flow thru)
  vector<ReplaceVarnode *> worklist;
  int4 pullcount;		// Number of instructions pulling out the logical value
  static int4 doesOrSet(PcodeOp *orop,uintb mask);
  static int4 doesAndClear(PcodeOp *andop,uintb mask);
  Address getReplacementAddress(ReplaceVarnode *rvn) const;
  ReplaceVarnode *setReplacement(Varnode *vn,uintb mask,bool &inworklist);
  ReplaceOp *createOp(OpCode opc,int4 numparam,ReplaceVarnode *outrvn);
  ReplaceOp *createOpDown(OpCode opc,int4 numparam,PcodeOp *op,ReplaceVarnode *inrvn,int4 slot);
  void patchIndirect(PcodeOp *newop,PcodeOp *oldop,ReplaceVarnode *out);
  bool tryCallPull(PcodeOp *op,ReplaceVarnode *rvn,int4 slot);
  bool tryReturnPull(PcodeOp *op,ReplaceVarnode *rvn,int4 slot);
  bool tryCallReturnPull(PcodeOp *op,ReplaceVarnode *rvn);
  bool traceForward(ReplaceVarnode *rvn);
  bool traceBackward(ReplaceVarnode *rvn);
  bool traceForwardSext(ReplaceVarnode *rvn);
  bool traceBackwardSext(ReplaceVarnode *rvn);
  bool createLink(ReplaceOp *rop,uintb mask,int4 slot,Varnode *vn);
  bool createCompareBridge(PcodeOp *op,ReplaceVarnode *inrvn,int4 slot,Varnode *othervn);
  void addTerminalPatch(PcodeOp *pullop,ReplaceVarnode *rvn);
  void addTerminalPatchSameOp(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot);
  void addBooleanPatch(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot);
  void addSuggestedPatch(ReplaceVarnode *rvn,PcodeOp *pushop,int4 sa);
  void addComparePatch(ReplaceVarnode *in1,ReplaceVarnode *in2,PcodeOp *op);
  ReplaceVarnode *addConstant(ReplaceOp *rop,uintb mask,uint4 slot,uintb val);
  void createNewOut(ReplaceOp *rop,uintb mask);
  void replaceInput(ReplaceVarnode *rvn);
  bool useSameAddress(ReplaceVarnode *rvn);
  Varnode *getReplaceVarnode(ReplaceVarnode *rvn);
  bool processNextWork(void);
public:
  SubvariableFlow(Funcdata *f,Varnode *root,uintb mask,bool aggr,bool sext);
  bool doTrace(void);
  void doReplacement(void);
};

// Class for splitting up varnodes that hold 2 logical variables
class SplitFlow {
  class ReplaceVarnode {
    friend class SplitFlow;
    Varnode *vn;		// Varnode being split
    Varnode *replaceLo;		// Replacement holding least significant part of original
    Varnode *replaceHi;		// Replacement holding most significant part
    bool defTraversed;		// Has the defining op been traversed
  public:
    ReplaceVarnode(void);
  };
  class ReplaceOp {
    friend class SplitFlow;
    PcodeOp *op;		// Original op being split
    OpCode opcode;			// Replacement opcode
    PcodeOp *loOp;		// Replacement for least sig part
    PcodeOp *hiOp;		// Replacement for most sig part
    int4 numParams;
    bool doDelete;		// Original operation should be deleted
    bool isLogicalInput;	// Op is putting a logical value into the whole, as opposed to pulling one out
    ReplaceVarnode *output;	// Output varnode(s) if needed
  public:
    ReplaceOp(bool isLogic,PcodeOp *o,OpCode opc,int4 num);
  };
  int4 concatSize;		// Size of combined logicals
  int4 loSize;			// Size of logical piece in least sig part of combined
  int4 hiSize;			// Size of logical piece in most sig part of combined
  Funcdata *fd;
  map<Varnode *,ReplaceVarnode> varmap;
  list<ReplaceOp> oplist;
  vector<ReplaceVarnode *> worklist;
  void assignReplaceOp(bool isLogicalInput,PcodeOp *op,OpCode opc,int4 numParam,ReplaceVarnode *outrvn);
  void assignLogicalPieces(ReplaceVarnode *rvn);
  void buildReplaceOutputs(ReplaceOp *rop);
  void replacePiece(ReplaceOp *rop);
  void replaceZext(ReplaceOp *rop);
  void replaceLeftInput(ReplaceOp *rop);
  void replaceLeftTerminal(ReplaceOp *rop);
  void replaceOp(ReplaceOp *rop);
  ReplaceVarnode *setReplacement(Varnode *vn,bool &inworklist);
  bool addOpOutput(PcodeOp *op);
  bool addOpInputs(PcodeOp *op,ReplaceVarnode *outrvn,int4 numParam);
  bool traceForward(ReplaceVarnode *rvn);
  bool traceBackward(ReplaceVarnode *rvn);
  bool processNextWork(void);
public:
  SplitFlow(Funcdata *f,Varnode *root,int4 lowSize);
  void doReplacement(void);
  bool doTrace(void);
};

// Structures for tracing floating point variables if they are
// stored at points in a higher precision encoding.  This is nearly identical
// in spirit to the SubvariableFlow class, but it performs on floating point
// variables contained in higher precision storage, rather than integers stored
// as a subfield of a bigger integer

// This the floating point version of SubvariablFlow, it follows the flow of a logical lower
// precision value stored in higher precision locations
class SubfloatFlow {
  class ReplaceOp;
  class ReplaceVarnode {
    friend class SubfloatFlow;
    Varnode *vn;		// Varnode being split
    Varnode *replacement;	// The new subvariable varnode
    ReplaceOp *def;		// Defining op for new varnode
  };
  
  class ReplaceOp {
    friend class SubfloatFlow;
    PcodeOp *op;		// op getting paralleled
    PcodeOp *replacement;	// The new op
    OpCode opc;		// type of new op
    int4 numparams;
    ReplaceVarnode *output;	// varnode output
    vector<ReplaceVarnode *> input; // varnode inputs
  };
  
  class PulloutRecord {		// Node where logical variable is getting pulled out into a real varnode
    friend class SubfloatFlow;
    OpCode opc;			// (possibly) new opcode
    PcodeOp *pullop;		// Op producing the real output
    ReplaceVarnode *input;	// The logical variable input
  };

  class CompareRecord {
    friend class SubfloatFlow;
    ReplaceVarnode *in1;
    ReplaceVarnode *in2;
    PcodeOp *compop;
  };

  int4 precision;		// Number of bytes of precision in the logical flow
  Funcdata *fd;
  const FloatFormat *format;
  map<Varnode *,ReplaceVarnode> varmap;
  list<ReplaceVarnode> newvarlist;
  list<ReplaceOp> oplist;
  list<PulloutRecord> pulllist;
  list<CompareRecord> complist;
  vector<ReplaceVarnode *> worklist;
  ReplaceVarnode *setReplacement(Varnode *vn,bool &inworklist);
  ReplaceVarnode *setReplacementNoFlow(Varnode *vn);
  ReplaceOp *createOp(OpCode opc,int4 numparam,ReplaceVarnode *outrvn);
  ReplaceOp *createOpDown(OpCode opc,int4 numparam,PcodeOp *op,ReplaceVarnode *inrvn,int4 slot);
  bool traceForward(ReplaceVarnode *rvn);
  bool traceBackward(ReplaceVarnode *rvn);
  bool createLink(ReplaceOp *rop,int4 slot,Varnode *vn);
  void addtopulllist(PcodeOp *pullop,ReplaceVarnode *rvn);
  bool addtopushlist(PcodeOp *pushop,ReplaceVarnode *rvn);
  void addtocomplist(ReplaceVarnode *in1,ReplaceVarnode *in2,PcodeOp *op);
  ReplaceVarnode *addConstant(Varnode *vn);
  void replaceInput(ReplaceVarnode *rvn);
  Varnode *getReplaceVarnode(ReplaceVarnode *rvn);
  bool processNextWork(void);
public:
  SubfloatFlow(Funcdata *f,Varnode *root,int4 prec);
  bool doTrace(void);
  void doReplacement(void);
};

#endif

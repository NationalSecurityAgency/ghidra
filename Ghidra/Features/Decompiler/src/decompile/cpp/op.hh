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
/// \file op.hh
/// \brief The PcodeOp and PcodeOpBank classes
#ifndef __OP_HH__
#define __OP_HH__

#include "typeop.hh"

namespace ghidra {

extern ElementId ELEM_IOP;		///< Marshaling element \<iop>
extern ElementId ELEM_UNIMPL;		///< Marshaling element \<unimpl>

/// \brief Space for storing internal PcodeOp pointers as addresses
///
/// It is convenient and efficient to replace the formally encoded
/// branch target addresses with a pointer to the actual PcodeOp
/// being branched to.  This special \b iop space allows a PcodeOp
/// pointer to be encoded as an address so it can be stored as
/// part of an input varnode, in place of the target address, in
/// a \e branching operation.  The pointer is encoded as an offset
/// within the \b fspec space.
class IopSpace : public AddrSpace {
public:
  IopSpace(AddrSpaceManager *m,const Translate *t,int4 ind);
  virtual void encodeAttributes(Encoder &encoder,uintb offset) const { encoder.writeString(ATTRIB_SPACE, "iop"); }
  virtual void encodeAttributes(Encoder &encoder,uintb offset,int4 size) const { encoder.writeString(ATTRIB_SPACE, "iop"); }
  virtual void printRaw(ostream &s,uintb offset) const;
  virtual void decode(Decoder &decoder);
  static const string NAME;			///< Reserved name for the iop space
};

/// \brief Lowest level operation of the \b p-code language
///
/// The philosophy here is to have only one version of any type of operation,
/// and to be completely explicit about all effects.
/// All operations except the control flow operations have exactly one
/// explicit output. Any given operation can have multiple inputs, but all
/// are listed explicitly.
///
/// Input and output size for an operation are specified explicitly. All
/// inputs must be of the same size. 
/// Except for the above restrictions, input and output can be any size
/// in bytes. 
///
/// P-code can be either big or little endian, this is determined
/// by the language being translated from

class PcodeOp {
  friend class BlockBasic; // Just insert_before, insert_after, setOrder
  friend class Funcdata;
  friend class CloneBlockOps;
  friend class PcodeOpBank;
  friend class VarnodeBank;    // Only uses setInput
public:
  /// Boolean attributes (flags) that can be placed on a PcodeOp. Even though this enum is public, these are
  /// all set and read internally, although many are read publicly via \e get or \e is methods.
  enum {
    startbasic = 1,	    ///< This instruction starts a basic block
    branch = 2,		    ///< This instruction is a branch
    call = 4,		    ///< This instruction calls a subroutine
    returns = 0x8,	    ///< This instruction returns to caller
    nocollapse = 0x10,	    ///< This op cannot be collapsed further
    dead = 0x20,	    ///< This operation is dead
    marker = 0x40,          ///< special placeholder op (multiequal or indirect)
			    ///< or CPUI_COPY between different copies
			    ///< of same variable
    booloutput = 0x80,		///< Boolean operation
    boolean_flip = 0x100,	///< Set if condition must be false to take branch
    fallthru_true = 0x200,	///< Set if fallthru happens on true condition
    indirect_source = 0x400,	///< Op is source of (one or more) CPUI_INDIRECTs
    coderef = 0x800,		///< The first parameter to this op is a coderef
    startmark = 0x1000,		///< This op is the first in its instruction
    mark = 0x2000,		///< Used by many algorithms that need to detect loops or avoid repeats
    commutative = 0x4000,	///< Order of input parameters does not matter
    unary = 0x8000,		///< Evaluate as unary expression
    binary = 0x10000,		///< Evaluate as binary expression
    special = 0x20000,		///< Cannot be evaluated (without special processing)
    ternary = 0x40000,		///< Evaluate as ternary operator (or higher)
    return_copy = 0x80000,	///< Special form of COPY op for holding global values to (past) the end of the function
    nonprinting = 0x100000,	///< Op should not be directly printed as source
    halt = 0x200000,		///< instruction causes processor or process to halt
    badinstruction = 0x400000,	///< placeholder for bad instruction data
    unimplemented = 0x800000,	///< placeholder for unimplemented instruction
    noreturn = 0x1000000,	///< placeholder for previous call that doesn't exit
    missing = 0x2000000,	///< ops at this address were not generated
    spacebase_ptr = 0x4000000,	///< Loads or stores from a dynamic pointer into a spacebase
    indirect_creation = 0x8000000,  ///< Output varnode is created by indirect effect
    calculated_bool = 0x10000000, ///< Output has been determined to be a 1-bit boolean value
    has_callspec = 0x20000000,	///< Op has a call specification associated with it
    ptrflow = 0x40000000,	///< Op consumes or produces a ptr
    indirect_store = 0x80000000	///< CPUI_INDIRECT is caused by CPUI_STORE
  };
  enum {
    special_prop = 1,		///< Does some special form of datatype propagation
    special_print = 2,		///< Op is marked for special printing
    modified = 4,		///< This op has been modified by the current action
    warning = 8,		///< Warning has been generated for this op
    incidental_copy = 0x10,	///< Treat this as \e incidental for parameter recovery algorithms
    is_cpool_transformed = 0x20, ///< Have we checked for cpool transforms
    stop_type_propagation = 0x40,	///< Stop data-type propagation into output from descendants
    hold_output = 0x80,		///< Output varnode (of call) should not be removed if it is unread
    concat_root = 0x100,	///< Output of \b this is root of a CONCAT tree
    no_indirect_collapse = 0x200,	///< Do not collapse \b this INDIRECT (via RuleIndirectCollapse)
    store_unmapped = 0x400	///< If STORE collapses to a stack Varnode, force it to be unmapped
  };
private:
  TypeOp *opcode;		///< Pointer to class providing behavioral details of the operation
  mutable uint4 flags;		///< Collection of boolean attributes on this op
  mutable uint4 addlflags;	///< Additional boolean attributes for this op
  SeqNum start;	                ///< What instruction address is this attached to
  BlockBasic *parent;	        ///< Basic block in which this op is contained
  list<PcodeOp *>::iterator basiciter;	///< Iterator within basic block
  list<PcodeOp *>::iterator insertiter;	///< Position in alive/dead list
  list<PcodeOp *>::iterator codeiter;	///< Position in opcode list
  Varnode *output;		///< The one possible output Varnode of this op
  vector<Varnode *> inrefs;	///< The ordered list of input Varnodes for this op

  // Only used by Funcdata
  void setOpcode(TypeOp *t_op);	///< Set the opcode for this PcodeOp
  void setOutput(Varnode *vn) { output = vn; } ///< Set the output Varnode of this op
  void clearInput(int4 slot) { inrefs[slot] = (Varnode *)0; } ///< Clear a specific input Varnode to \e null
  void setInput(Varnode *vn,int4 slot) { inrefs[slot] = vn; } ///< Set a specific input Varnode
  void setFlag(uint4 fl) { flags |= fl; } ///< Set specific boolean attribute(s) on this op
  void clearFlag(uint4 fl) { flags &= ~fl; } ///< Clear specific boolean attribute(s)
  void setAdditionalFlag(uint4 fl) { addlflags |= fl; } ///< Set specific boolean attribute
  void clearAdditionalFlag(uint4 fl) { addlflags &= ~fl; } ///< Clear specific boolean atribute
  void flipFlag(uint4 fl) { flags ^= fl; } ///< Flip the setting of specific boolean attribute(s)
  void setNumInputs(int4 num);	///< Make sure this op has \b num inputs
  void removeInput(int4 slot);	///< Eliminate a specific input Varnode
  void insertInput(int4 slot);	///< Make room for a new input Varnode at a specific position
  void setOrder(uintm ord) { start.setOrder(ord); } ///< Order this op within the ops for a single instruction
  void setParent(BlockBasic *p) { parent = p; }	///< Set the parent basic block of this op
  void setBasicIter(list<PcodeOp *>::iterator iter) { basiciter = iter; } ///< Store the iterator into this op's basic block

public:
  PcodeOp(int4 s,const SeqNum &sq); ///< Construct an unattached PcodeOp
  ~PcodeOp(void) {}		///< Destructor
  int4 numInput(void) const { return inrefs.size(); } ///< Get the number of inputs to this op
  Varnode *getOut(void) { return output; } ///< Get the output Varnode of this op or \e null
  const Varnode *getOut(void) const { return (const Varnode *) output; } ///< Get the output Varnode of this op or \e null
  Varnode *getIn(int4 slot) { return inrefs[slot]; } ///< Get a specific input Varnode to this op
  const Varnode *getIn(int4 slot) const { return (const Varnode *) inrefs[slot]; } ///< Get a specific input Varnode to this op
  const BlockBasic *getParent(void) const { return (const BlockBasic *) parent; } ///< Get the parent basic block
  BlockBasic *getParent(void) { return parent; } ///< Get the parent basic block
  const Address &getAddr(void) const { return start.getAddr(); } ///< Get the instruction address associated with this op
  uintm getTime(void) const { return start.getTime(); }	///< Get the time index indicating when this op was created
  const SeqNum &getSeqNum(void) const { return start; }	///< Get the sequence number associated with this op
  list<PcodeOp *>::iterator getInsertIter(void) const { return insertiter; } ///< Get position within alive/dead list
  list<PcodeOp *>::iterator getBasicIter(void) const { return basiciter; } ///< Get position within basic block
  /// \brief Get the slot number of the indicated input varnode
  int4 getSlot(const Varnode *vn) const { int4 i,n; n=inrefs.size(); for(i=0;i<n;++i) if (inrefs[i]==vn) break; return i; }
  int4 getRepeatSlot(const Varnode *vn,int4 firstSlot,list<PcodeOp *>::const_iterator iter) const;
  /// \brief Get the evaluation type of this op
  uint4 getEvalType(void) const { return (flags&(PcodeOp::unary|PcodeOp::binary|PcodeOp::special|PcodeOp::ternary)); }
  /// \brief Get type which indicates unusual halt in control-flow
  uint4 getHaltType(void) const { return (flags&(PcodeOp::halt|PcodeOp::badinstruction|PcodeOp::unimplemented|
					      PcodeOp::noreturn|PcodeOp::missing)); }
  bool isDead(void) const { return ((flags&PcodeOp::dead)!=0); } ///< Return \b true if this op is dead
  bool isAssignment(void) const { return (output!=(Varnode *)0); } ///< Return \b true is this op has an output
  bool isCall(void) const { return ((flags&PcodeOp::call)!=0); } ///< Return \b true if this op indicates call semantics
  /// \brief Return \b true if this op acts as call but does not have a full specification
  bool isCallWithoutSpec(void) const { return ((flags&(PcodeOp::call|PcodeOp::has_callspec))==PcodeOp::call); }
  bool isMarker(void) const { return ((flags&PcodeOp::marker)!=0); } ///< Return \b true is a special SSA form op
  bool isIndirectCreation(void) const { return ((flags&PcodeOp::indirect_creation)!=0); } ///< Return \b true if op creates a varnode indirectly
  bool isIndirectStore(void) const { return ((flags&PcodeOp::indirect_store)!=0); }	///< Return \b true if \b this INDIRECT is caused by STORE
  /// \brief Return \b true if this op is not directly represented in C output
  bool notPrinted(void) const { return ((flags&(PcodeOp::marker|PcodeOp::nonprinting|PcodeOp::noreturn))!=0); }
  /// \brief Return \b true if this op produces a boolean output
  bool isBoolOutput(void) const { return ((flags&PcodeOp::booloutput)!=0); }
  bool isBranch(void) const { return ((flags&PcodeOp::branch)!=0); } ///< Return \b true if this op is a branch
  /// \brief Return \b true if this op is a call or branch
  bool isCallOrBranch(void) const { return ((flags&(PcodeOp::branch|PcodeOp::call))!=0); }
  /// \brief Return \b true if this op breaks fall-thru flow
  bool isFlowBreak(void) const { return ((flags&(PcodeOp::branch|PcodeOp::returns))!=0); }
  /// \brief Return \b true if this op flips the true/false meaning of its control-flow branching
  bool isBooleanFlip(void) const { return ((flags&PcodeOp::boolean_flip)!=0); }
  /// \brief Return \b true if the fall-thru branch is taken when the boolean input is true
  bool isFallthruTrue(void) const { return ((flags&PcodeOp::fallthru_true)!=0); }
  bool isCodeRef(void) const { return ((flags&PcodeOp::coderef)!=0); } ///< Return \b true if the first input is a code reference
  bool isInstructionStart(void) const { return ((flags&PcodeOp::startmark)!=0); } ///< Return \b true if this starts an instruction
  bool isBlockStart(void) const { return ((flags&PcodeOp::startbasic)!=0); } ///< Return \b true if this starts a basic block
  bool isModified(void) const { return ((addlflags&PcodeOp::modified)!=0); } ///< Return \b true if this is modified by the current action
  bool isMark(void) const { return ((flags&PcodeOp::mark)!=0); } ///< Return \b true if this op has been marked
  void setMark(void) const { flags |= PcodeOp::mark; } ///< Set the mark on this op
  bool isWarning(void) const { return ((addlflags&PcodeOp::warning)!=0); } ///< Return \b true if a warning has been generated for this op
  void clearMark(void) const { flags &= ~PcodeOp::mark; } ///< Clear any mark on this op
  bool isIndirectSource(void) const { return ((flags&PcodeOp::indirect_source)!=0); } ///< Return \b true if this causes an INDIRECT
  void setIndirectSource(void) { flags |= PcodeOp::indirect_source; } ///< Mark this op as source of INDIRECT
  void clearIndirectSource(void) { flags &= ~PcodeOp::indirect_source; } ///< Clear INDIRECT source flag
  bool isPtrFlow(void) const { return ((flags&PcodeOp::ptrflow)!=0); } ///< Return \b true if this produces/consumes ptrs
  void setPtrFlow(void) { flags |= PcodeOp::ptrflow; } ///< Mark this op as consuming/producing ptrs
  bool doesSpecialPropagation(void) const { return ((addlflags&PcodeOp::special_prop)!=0); } ///< Return \b true if this does datatype propagation
  bool doesSpecialPrinting(void) const { return ((addlflags&PcodeOp::special_print)!=0); } ///< Return \b true if this needs to special printing
  bool isIncidentalCopy(void) const { return ((addlflags&PcodeOp::incidental_copy)!=0); } ///< Return \b true if \b this COPY is \e incidental
  /// \brief Return \b true if output is 1-bit boolean
  bool isCalculatedBool(void) const { return ((flags&(PcodeOp::calculated_bool|PcodeOp::booloutput))!=0); }
  /// \brief Return \b true if we have already examined this cpool
  bool isCpoolTransformed(void) const { return ((addlflags&PcodeOp::is_cpool_transformed)!=0); }
  bool isCollapsible(void) const; ///< Return \b true if this can be collapsed to a COPY of a constant
  bool stopsTypePropagation(void) const { return ((addlflags&stop_type_propagation)!=0); }	///< Is data-type propagation from below stopped
  void setStopTypePropagation(void) { addlflags |= stop_type_propagation; }	///< Stop data-type propagation from below
  void clearStopTypePropagation(void) { addlflags &= ~stop_type_propagation; }	///< Allow data-type propagation from below
  bool holdOutput(void) const { return ((addlflags&hold_output)!=0); }	///< If \b true, do not remove output as dead code
  void setHoldOutput(void) { addlflags |= hold_output; }	///< Prevent output from being removed as dead code
  bool isPartialRoot(void) const { return ((addlflags&concat_root)!=0); }	///< Output is root of CONCAT tree
  void setPartialRoot(void) { addlflags |= concat_root; }	///< Mark \b this as root of CONCAT tree
  bool isReturnCopy(void) const { return ((flags&return_copy)!=0); }	///< Is \b this a \e return form COPY
  bool noIndirectCollapse(void) const { return ((addlflags & no_indirect_collapse)!=0); }	///< Check if INDIRECT collapse is possible
  void setNoIndirectCollapse(void) { addlflags |= no_indirect_collapse; }	///< Prevent collapse of INDIRECT
  bool isStoreUnmapped(void) const { return ((addlflags & store_unmapped)!=0); }	///< Is STORE location supposed to be unmapped
  void setStoreUnmapped(void) const { addlflags |= store_unmapped; }	///< Mark that STORE location should be unmapped
  /// \brief Return \b true if this LOADs or STOREs from a dynamic \e spacebase pointer
  bool usesSpacebasePtr(void) const { return ((flags&PcodeOp::spacebase_ptr)!=0); }
  uintm getCseHash(void) const;	///< Return hash indicating possibility of common subexpression elimination
  bool isCseMatch(const PcodeOp *op) const; ///< Return \b true if this and \e op represent common subexpressions
  bool isMoveable(const PcodeOp *point) const;	///< Can \b this be moved to after \e point, without disturbing data-flow
  TypeOp *getOpcode(void) const { return opcode; } ///< Get the opcode for this op
  OpCode code(void) const { return opcode->getOpcode(); } ///< Get the opcode id (enum) for this op
  bool isCommutative(void) const { return ((flags & PcodeOp::commutative)!=0); } ///< Return \b true if inputs commute
  uintb collapse(bool &markedInput) const;	///< Calculate the constant output produced by this op
  void collapseConstantSymbol(Varnode *newConst) const;	///< Propagate constant symbol from inputs to given output
  PcodeOp *nextOp(void) const;	///< Return the next op in the control-flow from this or \e null
  PcodeOp *previousOp(void) const; ///< Return the previous op within this op's basic block or \e null
  PcodeOp *target(void) const;	///< Return starting op for instruction associated with this op
  uintb getNZMaskLocal(bool cliploop) const; ///< Calculate known zero bits for output to this op
  int4 compareOrder(const PcodeOp *bop) const; ///< Compare the control-flow order of this and \e bop
  void printRaw(ostream &s) const { opcode->printRaw(s,this); }	///< Print raw info about this op to stream
  const string &getOpName(void) const { return opcode->getName(); } ///< Return the name of this op
  void printDebug(ostream &s) const; ///< Print debug description of this op to stream
  void encode(Encoder &encoder) const; ///< Encode a description of \b this op to stream

  /// \brief Retrieve the PcodeOp encoded as the address \e addr
  static PcodeOp *getOpFromConst(const Address &addr) { return (PcodeOp *)(uintp)addr.getOffset(); }

  Datatype *outputTypeLocal(void) const { return opcode->getOutputLocal(this); } ///< Calculate the local output type
  Datatype *inputTypeLocal(int4 slot) const { return opcode->getInputLocal(this,slot); }	///< Calculate the local input type
};

/// \brief An edge in a data-flow path or graph
///
/// A minimal node for traversing expressions in the data-flow
struct PcodeOpNode {
  PcodeOp *op;		///< The p-code end-point of the edge
  int4 slot;		///< Slot indicating the input Varnode end-point of the edge
  PcodeOpNode(void) { op = (PcodeOp *)0; slot = 0; }	///< Unused constructor
  PcodeOpNode(PcodeOp *o,int4 s) { op = o; slot = s; }	///< Constructor
  bool operator<(const PcodeOpNode &op2) const;		///< Simple comparator for putting edges in a sorted container
  static bool compareByHigh(const PcodeOpNode &a,const PcodeOpNode &b);	///< Compare Varnodes by their HighVariable
};

/// \brief A node in a tree structure of CPUI_PIECE operations
///
/// If a group of Varnodes are concatenated into a larger structure, this object is used to explicitly gather
/// the PcodeOps (and Varnodes) in the data-flow and view them as a unit. In a properly formed tree, for each
/// CPUI_PIECE operation, the addresses of the input Varnodes and the output Varnode align according to the
/// concatenation. Internal Varnodes can have only one descendant, but the leaf and the root Varnodes
/// can each have multiple descendants
class PieceNode {
  PcodeOp *pieceOp;	///< CPUI_PIECE operation combining this particular Varnode piece
  int4 slot;		///< The particular slot of this Varnode within CPUI_PIECE
  int4 typeOffset;	///< Byte offset into structure/array
  bool leaf;		///< \b true if this is a leaf of the tree structure
public:
  PieceNode(PcodeOp *op,int4 sl,int4 off,bool l) { pieceOp=op; slot=sl; typeOffset=off; leaf = l; }	///< Constructor
  bool isLeaf(void) const { return leaf; }		///< Return \b true if \b this node is a leaf of the tree structure
  int4 getTypeOffset(void) const { return typeOffset; }	///< Get the byte offset of \b this node into the data-type
  int4 getSlot(void) const { return slot; }	///< Get the input slot associated with \b this node
  PcodeOp *getOp(void) const { return pieceOp; }	///< Get the PcodeOp reading \b this piece
  Varnode *getVarnode(void) const { return pieceOp->getIn(slot); }	///< Get the Varnode representing \b this piece
  static bool isLeaf(Varnode *rootVn,Varnode *vn,int4 typeOffset);
  static Varnode *findRoot(Varnode *vn);
  static void gatherPieces(vector<PieceNode> &stack,Varnode *rootVn,PcodeOp *op,int4 baseOffset,int4 rootOffset);
};

/// A map from sequence number (SeqNum) to PcodeOp
typedef map<SeqNum,PcodeOp *> PcodeOpTree;

/// \brief Container class for PcodeOps associated with a single function
///
/// The PcodeOp objects are maintained under multiple different sorting criteria to
/// facilitate quick access in various situations. The main sort (PcodeOpTree) is by
/// sequence number (SeqNum). PcodeOps are also grouped into \e alive and \e dead lists
/// to distinguish between raw p-code ops and those that are fully linked into control-flow.
/// Several lists group PcodeOps with important op-codes (like STORE and RETURN).
class PcodeOpBank {
  PcodeOpTree optree;			///< The main sequence number sort
  list<PcodeOp *> deadlist;		///< List of \e dead PcodeOps
  list<PcodeOp *> alivelist;		///< List of \e alive PcodeOps
  list<PcodeOp *> storelist;		///< List of STORE PcodeOps
  list<PcodeOp *> loadlist;		///< list of LOAD PcodeOps
  list<PcodeOp *> returnlist;		///< List of RETURN PcodeOps
  list<PcodeOp *> useroplist;		///< List of user-defined PcodeOps
  list<PcodeOp *> deadandgone;		///< List of retired PcodeOps
  uintm uniqid;				///< Counter for producing unique id's for each op
  void addToCodeList(PcodeOp *op);	///< Add given PcodeOp to specific op-code list
  void removeFromCodeList(PcodeOp *op);	///< Remove given PcodeOp from specific op-code list
  void clearCodeLists(void);		///< Clear all op-code specific lists
public:
  void clear(void);					///< Clear all PcodeOps from \b this container
  PcodeOpBank(void) { uniqid = 0; }			///< Constructor
  ~PcodeOpBank(void) { clear(); }			///< Destructor
  void setUniqId(uintm val) { uniqid = val; }		///< Set the unique id counter
  uintm getUniqId(void) const { return uniqid; }	///< Get the next unique id
  PcodeOp *create(int4 inputs,const Address &pc);	///< Create a PcodeOp with at a given Address
  PcodeOp *create(int4 inputs,const SeqNum &sq);	///< Create a PcodeOp with a given sequence number
  void destroy(PcodeOp *op);				///< Destroy/retire the given PcodeOp
  void destroyDead(void);				///< Destroy/retire all PcodeOps in the \e dead list
  void changeOpcode(PcodeOp *op,TypeOp *newopc);	///< Change the op-code for the given PcodeOp
  void markAlive(PcodeOp *op);				///< Mark the given PcodeOp as \e alive
  void markDead(PcodeOp *op);				///< Mark the given PcodeOp as \e dead
  void insertAfterDead(PcodeOp *op,PcodeOp *prev);	///< Insert the given PcodeOp after a point in the \e dead list
  void moveSequenceDead(PcodeOp *firstop,PcodeOp *lastop,PcodeOp *prev);
  void markIncidentalCopy(PcodeOp *firstop,PcodeOp *lastop);	///< Mark any COPY ops in the given range as \e incidental
  bool empty(void) const { return optree.empty(); }	///< Return \b true if there are no PcodeOps in \b this container
  PcodeOp *target(const Address &addr) const;		///< Find the first executing PcodeOp for a target address
  PcodeOp *findOp(const SeqNum &num) const;		///< Find a PcodeOp by sequence number
  PcodeOp *fallthru(const PcodeOp *op) const;		///< Find the PcodeOp considered a \e fallthru of the given PcodeOp

  /// \brief Start of all PcodeOps in sequence number order
  PcodeOpTree::const_iterator beginAll(void) const { return optree.begin(); }

  /// \brief End of all PcodeOps in sequence number order
  PcodeOpTree::const_iterator endAll(void) const { return optree.end(); }

  /// \brief Start of all PcodeOps at one Address
  PcodeOpTree::const_iterator begin(const Address &addr) const;

  /// \brief End of all PcodeOps at one Address
  PcodeOpTree::const_iterator end(const Address &addr) const;

  /// \brief Start of all PcodeOps marked as \e alive
  list<PcodeOp *>::const_iterator beginAlive(void) const { return alivelist.begin(); }

  /// \brief End of all PcodeOps marked as \e alive
  list<PcodeOp *>::const_iterator endAlive(void) const { return alivelist.end(); }

  /// \brief Start of all PcodeOps marked as \e dead
  list<PcodeOp *>::const_iterator beginDead(void) const { return deadlist.begin(); }

  /// \brief End of all PcodeOps marked as \e dead
  list<PcodeOp *>::const_iterator endDead(void) const { return deadlist.end(); }

  /// \brief Start of all PcodeOps sharing the given op-code
  list<PcodeOp *>::const_iterator begin(OpCode opc) const;

  /// \brief End of all PcodeOps sharing the given op-code
  list<PcodeOp *>::const_iterator end(OpCode opc) const;
};

extern int4 functionalEqualityLevel(Varnode *vn1,Varnode *vn2,Varnode **res1,Varnode **res2);
extern bool functionalEquality(Varnode *vn1,Varnode *vn2);
extern bool functionalDifference(Varnode *vn1,Varnode *vn2,int4 depth);

/// \brief Static methods for determining if two boolean expressions are the \b same or \b complementary
///
/// Traverse (upto a specific depth) the two boolean expressions consisting of BOOL_AND, BOOL_OR, and
/// BOOL_XOR operations.  Leaf operators in the expression can be other operators with boolean output (INT_LESS,
/// INT_SLESS, etc.).
class BooleanMatch {
  static bool sameOpComplement(PcodeOp *bin1op, PcodeOp *bin2op);
  static bool varnodeSame(Varnode *a,Varnode *b);
public:
  enum {
    same = 1,			///< Pair always hold the same value
    complementary = 2,		///< Pair always hold complementary values
    uncorrelated = 3		///< Pair values are uncorrelated
  };
  static int4 evaluate(Varnode *vn1,Varnode *vn2,int4 depth);
};

/// Compare PcodeOps (as pointers) first, then slot
/// \param op2 is the other edge to compare with \b this
/// \return true if \b this should come before the other PcodeOp
inline bool PcodeOpNode::operator<(const PcodeOpNode &op2) const

{
  if (op != op2.op)
    return (op->getSeqNum().getTime() < op2.op->getSeqNum().getTime());
  if (slot != op2.slot)
    return (slot < op2.slot);
  return false;
}

/// Allow a sorting that groups together input Varnodes with the same HighVariable
/// \param a is the first Varnode to compare
/// \param b is the second Varnode to compare
/// \return true is \b a should come before \b b
inline bool PcodeOpNode::compareByHigh(const PcodeOpNode &a, const PcodeOpNode &b)

{
  return a.op->getIn(a.slot)->getHigh() < b.op->getIn(b.slot)->getHigh();
}

} // End namespace ghidra
#endif

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
/// \file block.hh
/// \brief Classes related to \e basic \e blocks and control-flow structuring

#ifndef __BLOCK_HH__
#define __BLOCK_HH__

#include "jumptable.hh"

namespace ghidra {

class BlockBasic;		// Forward declarations
class BlockList;
class BlockCopy;
class BlockGoto;
class BlockMultiGoto;
class BlockCondition;
class BlockIf;
class BlockWhileDo;
class BlockDoWhile;
class BlockInfLoop;
class BlockSwitch;
class PrintLanguage;
class BlockMap;

extern AttributeId ATTRIB_ALTINDEX;	///< Marshaling attribute "altindex"
extern AttributeId ATTRIB_DEPTH;	///< Marshaling attribute "depth"
extern AttributeId ATTRIB_END;		///< Marshaling attribute "end"
extern AttributeId ATTRIB_OPCODE;	///< Marshaling attribute "opcode"
extern AttributeId ATTRIB_REV;		///< Marshaling attribute "rev"

extern ElementId ELEM_BHEAD;		///< Marshaling element \<bhead>
extern ElementId ELEM_BLOCK;		///< Marshaling element \<block>
extern ElementId ELEM_BLOCKEDGE;	///< Marshaling element \<blockedge>
extern ElementId ELEM_EDGE;		///< Marshaling element \<edge>

/// \brief A control-flow edge between blocks (FlowBlock)
///
/// The edge is owned by the source block and can have FlowBlock::edge_flags
/// labels applied to it.  The \b point indicates the FlowBlock at the other end
/// from the source block. NOTE: The control-flow direction of the edge can
/// only be determined from context, whether the edge is in the incoming or outgoing edge list.
struct BlockEdge {
  uint4 label;			///< Label of the edge
  FlowBlock *point;		///< Other end of the edge
  int4 reverse_index;		///< Index for edge coming other way
  BlockEdge(void) {}		///< Constructor for use with decode
  BlockEdge(FlowBlock *pt,uint4 lab,int4 rev) { label=lab; point=pt; reverse_index = rev; }	///< Constructor
  void encode(Encoder &encoder) const;	///< Encode \b this edge to a stream
  void decode(Decoder &decoder,BlockMap &resolver);	///< Restore \b this edge from a stream
};

/// \brief Description of a control-flow block containing PcodeOps
///
/// This is the base class for basic blocks (BlockBasic) and the
/// hierarchical description of \e structured code.  At all levels,
/// these can be viewed as a block of code (PcodeOp objects) with
/// other blocks flowing into and out of it.
class FlowBlock {
  friend class BlockGraph;
public:
  /// \brief The possible block types
  enum block_type {
    t_plain, t_basic, t_graph, t_copy, t_goto, t_multigoto, t_ls,
    t_condition, t_if, t_whiledo, t_dowhile, t_switch, t_infloop
  };
  /// \brief Boolean properties of blocks
  ///
  /// The first four flags describe attributes of the blocks primary exiting edges
  /// The f_interior_* flags do not necessarily apply to these edges. They are used
  /// with the block structure and hierarchy algorithms where unstructured jumps
  /// are removed from the list of primary edges. These flags keep track only of
  /// the existence of unstructured edges, even though they aren't listed
  enum block_flags {
    f_goto_goto = 1,		///< (Block ends in) non-structured branch
    f_break_goto = 2,		///< Block ends with a break;
    f_continue_goto = 4,	///< Block ends with a continue;
    f_switch_out = 0x10,	///< Output is decided by switch
    f_unstructured_targ = 0x20,	///< Block is destination of unstructured goto
    f_mark = 0x80,		///< Generic way to mark a block
    f_mark2 = 0x100,		///< A secondary mark
    f_entry_point = 0x200,	///< Official entry point of the function
    f_interior_gotoout = 0x400,	///< The block has an unstructured jump out of interior
    f_interior_gotoin = 0x800,	///< Block is target of unstructured jump to its interior
    f_label_bumpup = 0x1000,	///< Any label printed higher up in hierarchy
    f_donothing_loop = 0x2000,	///< Block does nothing in infinite loop (halt)
    f_dead = 0x4000,		///< Block is in process of being deleted
    f_whiledo_overflow = 0x8000,///< Set if the conditional block of a whiledo is too big to print as while(cond) { ...
    f_flip_path = 0x10000,      ///< If true, out edges have been flipped since last time path was traced
    f_joined_block = 0x20000,	///< Block is a merged form of original basic blocks
    f_duplicate_block = 0x40000	///< Block is a duplicated version of an original basic block
  };
  /// \brief Boolean properties on edges
  enum edge_flags {
    f_goto_edge = 1,		///< Edge is unstructured
    f_loop_edge = 2,		///< Edge completes a loop, removing these edges gives you a DAG
    f_defaultswitch_edge = 4,	///< This is default edge from switchblock
    f_irreducible = 8,          ///< Edge which must be removed to make graph reducible
    f_tree_edge = 0x10,		///< An edge in the spanning tree
    f_forward_edge = 0x20,	///< An edge that jumps forward in the spanning tree
    f_cross_edge = 0x40,	///< An edge that crosses subtrees in the spanning tree
    f_back_edge = 0x80,		///< Within (reducible) graph, a back edge defining a loop
    f_loop_exit_edge = 0x100	///< Edge exits the body of a loop
  };
private:
  uint4 flags;			///< Collection of block_flags
  FlowBlock *parent;		///< The parent block to which \b this belongs
  FlowBlock *immed_dom;		///< Immediate dominating block
  FlowBlock *copymap;		///< Back reference to a BlockCopy of \b this
  int4 index;			///< Reference index for this block (reverse post order)
  int4 visitcount;		///< A count of visits of this node for various algorithms
  int4 numdesc;			///< Number of descendants of this block in spanning tree (+1)
  vector<BlockEdge> intothis;	///< Blocks which (can) fall into this block
  vector<BlockEdge> outofthis;	///< Blocks into which this block (can) fall
				// If there are two possible outputs as the
				// result of a conditional branch
				// the first block in outofthis should be
				// the result of the condition being false
  static void replaceEdgeMap(vector<BlockEdge> &vec);	///< Update block references in edges with copy map
  void addInEdge(FlowBlock *b,uint4 lab);	///< Add an edge coming into \b this
  void decodeNextInEdge(Decoder &decoder,BlockMap &resolver);	///< Decode the next input edge from stream
  void halfDeleteInEdge(int4 slot);		///< Delete the \e in half of an edge, correcting indices
  void halfDeleteOutEdge(int4 slot);		///< Delete the \e out half of an edge, correcting indices
  void removeInEdge(int4 slot);			///< Remove an incoming edge
  void removeOutEdge(int4 slot);		///< Remove an outgoing edge
  void replaceInEdge(int4 num,FlowBlock *b);	///< Make an incoming edge flow from a given block
  void replaceOutEdge(int4 num,FlowBlock *b);	///< Make an outgoing edge flow to a given block
  void replaceEdgesThru(int4 in,int4 out);	///< Remove \b this from flow between two blocks
  void swapEdges(void);				///< Swap the first and second \e out edges
  void setOutEdgeFlag(int4 i,uint4 lab);	///< Apply an \e out edge label
  void clearOutEdgeFlag(int4 i,uint4 lab);	///< Remove an \e out edge label
  void eliminateInDups(FlowBlock *bl);		///< Eliminate duplicate \e in edges from given block
  void eliminateOutDups(FlowBlock *bl);		///< Eliminate duplicate \e out edges to given block
  static void findDups(const vector<BlockEdge> &ref,vector<FlowBlock *> &duplist);
  void dedup(void);				///< Eliminate duplicate edges
  void replaceUsingMap(void);			///< Update references to other blocks using getCopyMap()
#ifdef BLOCKCONSISTENT_DEBUG
  void checkEdges(void);			///< Check the consistency of edge references
#endif
protected:
  void setFlag(uint4 fl) { flags |= fl; }	///< Set a boolean property
  void clearFlag(uint4 fl) { flags &= ~fl; }	///< Clear a boolean property
public:
  FlowBlock(void);				///< Construct a block with no edges
  virtual ~FlowBlock(void) {}			///< Destructor
  int4 getIndex(void) const { return index; }	///< Get the index assigned to \b this block
  FlowBlock *getParent(void) { return parent; }	///< Get the parent FlowBlock of \b this
  FlowBlock *getImmedDom(void) const { return immed_dom; }	///< Get the immediate dominator FlowBlock
  FlowBlock *getCopyMap(void) const { return copymap; }		///< Get the mapped FlowBlock
  const FlowBlock *getParent(void) const { return (const FlowBlock *) parent; }	///< Get the parent FlowBlock of \b this
  uint4 getFlags(void) const { return flags; }			///< Get the block_flags properties

  /// \brief Get the starting address of code in \b this FlowBlock
  ///
  /// If \b this is a basic block, the first address of (the original) instructions in the block
  /// is returned.  Otherwise, an \e invalid address is returned.
  /// \return the starting address or an \e invalid address
  virtual Address getStart(void) const { return Address(); }

  /// \brief Get the ending address of code in \b this FlowBlock
  ///
  /// If \b this is a basic block, the last address of (the original) instructions in the block
  /// is returned.  Otherwise, an \e invalid address is returned.
  /// \return the starting address or an \e invalid address
  virtual Address getStop(void) const { return Address(); }

  /// \brief Get the FlowBlock type of \b this
  ///
  /// \return one of the enumerated block types
  virtual block_type getType(void) const { return t_plain; }

  /// \brief Get the i-th component block
  ///
  /// \param i is the index of the component block
  /// \return the specified component block
  virtual FlowBlock *subBlock(int4 i) const { return (FlowBlock *)0; }

  /// \brief Mark target blocks of any unstructured edges
  virtual void markUnstructured(void) {}

  virtual void markLabelBumpUp(bool bump);	///< Let hierarchical blocks steal labels of their (first) components

  /// \brief Mark unstructured edges that should be \e breaks
  ///
  /// \param curexit is the index of the (fall-thru) exit block for \b this block, or -1 for no fall-thru
  /// \param curloopexit is the index of the exit block of the containing loop, or -1 for no containing loop
  virtual void scopeBreak(int4 curexit,int4 curloopexit) {}

  virtual void printHeader(ostream &s) const;		///< Print a simple description of \b this to stream
  virtual void printTree(ostream &s,int4 level) const;	///< Print tree structure of any blocks owned by \b this

  /// \brief Print raw instructions contained in \b this FlowBlock
  ///
  /// A text representation of the control-flow and instructions contained in \b this block is
  /// emitted to the given stream.
  /// \param s is the given stream to write to
  virtual void printRaw(ostream &s) const {}

  virtual void emit(PrintLanguage *lng) const;	///<Emit the instructions in \b this FlowBlock as structured code

  /// \brief Get the leaf block from which \b this block exits
  ///
  /// This will be the only basic block with (structured) edges out of \b this block.
  /// \return the specific exiting block or null if there isn't a unique block
  virtual const FlowBlock *getExitLeaf(void) const { return (const FlowBlock *)0; }

  /// \brief Get the first PcodeOp executed by \b this FlowBlock
  ///
  /// If there are no PcodeOps in the block, null is returned.
  /// \return the first PcodeOp or null
  virtual PcodeOp *firstOp(void) const { return (PcodeOp *)0; }

  /// \brief Get the last PcodeOp executed by \b this FlowBlock
  ///
  /// If \b this has a unique last PcodeOp, it is returned.
  /// \return the last PcodeOp or null
  virtual PcodeOp *lastOp(void) const { return (PcodeOp *)0; }

  virtual bool negateCondition(bool toporbottom);	///< Flip the condition computed by \b this
  virtual bool preferComplement(Funcdata &data);	///< Rearrange \b this hierarchy to simplify boolean expressions
  virtual FlowBlock *getSplitPoint(void);		///< Get the leaf splitting block
  virtual int4 flipInPlaceTest(vector<PcodeOp *> &fliplist) const;
  virtual void flipInPlaceExecute(void);

  /// \brief Is \b this too complex to be a condition (BlockCondition)
  ///
  /// \return \b false if the whole block can be emitted as a conditional clause
  virtual bool isComplex(void) const { return true; }

  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;

  /// \brief Do any structure driven final transforms
  ///
  /// \param data is the function to transform
  virtual void finalTransform(Funcdata &data) {}

  /// \brief Make any final configurations necessary to emit the block
  ///
  /// \param data is the function to finalize
  virtual void finalizePrinting(Funcdata &data) const {}

  virtual void encodeHeader(Encoder &encoder) const;	///< Encode basic information as attributes
  virtual void decodeHeader(Decoder &decoder);		///< Decode basic information from element attributes

  /// \brief Encode detail about \b this block and its components to a stream
  ///
  /// \param encoder is the stream encoder
  virtual void encodeBody(Encoder &encoder) const {}

  /// \brief Restore details about \b this FlowBlock from an element stream
  ///
  /// \param decoder is the stream decoder
  virtual void decodeBody(Decoder &decoder) {}

  void encodeEdges(Encoder &encoder) const;		///< Encode edge information to a stream
  void decodeEdges(Decoder &decoder,BlockMap &resolver);
  void encode(Encoder &encoder) const;			///< Encode \b this to a stream
  void decode(Decoder &decoder,BlockMap &resolver);	///< Decode \b this from a stream
  const FlowBlock *nextInFlow(void) const;		///< Return next block to be executed in flow
  void setVisitCount(int4 i) { visitcount = i; }	///< Set the number of times this block has been visited
  int4 getVisitCount(void) const { return visitcount; }	///< Get the count of visits
  void setGotoBranch(int4 i);				///< Mark a \e goto branch
  void setDefaultSwitch(int4 pos);			///< Mark an edge as the switch default
  bool isMark(void) const { return ((flags&f_mark)!=0); }	///< Return \b true if \b this block has been marked
  void setMark(void) { flags |= f_mark; }			///< Mark \b this block
  void clearMark(void) { flags &= ~f_mark; }			///< Clear any mark on \b this block
  void setDonothingLoop(void) { flags |= f_donothing_loop; }	///< Label \b this as a \e do \e nothing loop
  void setDead(void) { flags |= f_dead; }			///< Label \b this as dead
  bool hasSpecialLabel(void) const { return ((flags&(f_joined_block|f_duplicate_block))!=0); }	///< Return \b true if \b this uses a different label
  bool isJoined(void) const { return ((flags&f_joined_block)!=0); }		///< Return \b true if \b this is a \e joined basic block
  bool isDuplicated(void) const { return ((flags&f_duplicate_block)!=0); }	///< Return \b true if \b this is a \e duplicated block
  void setLoopExit(int4 i) { setOutEdgeFlag(i,f_loop_exit_edge); }	///< Label the edge exiting \b this as a loop
  void clearLoopExit(int4 i) { clearOutEdgeFlag(i,f_loop_exit_edge); }	///< Clear the loop exit edge
  void setBackEdge(int4 i) { setOutEdgeFlag(i,f_back_edge); }		///< Label the \e back edge of a loop
  bool getFlipPath(void) const { return ((flags & f_flip_path)!=0); }	///< Have out edges been flipped
  bool isJumpTarget(void) const;		///< Return \b true if non-fallthru jump flows into \b this
  FlowBlock *getFalseOut(void) const { return outofthis[0].point; }	///< Get the \b false output FlowBlock
  FlowBlock *getTrueOut(void) const { return outofthis[1].point; }	///< Get the \b true output FlowBlock
  FlowBlock *getOut(int4 i) { return outofthis[i].point; }		///< Get the i-th output FlowBlock
  const FlowBlock *getOut(int4 i) const { return (const FlowBlock *) outofthis[i].point; }	///< Get i-th output FlowBlock
  int4 getOutRevIndex(int4 i) const { return outofthis[i].reverse_index; }	///< Get the input index of the i-th output FlowBlock
  FlowBlock *getIn(int4 i) { return intothis[i].point; }		///< Get the i-th input FlowBlock
  const FlowBlock *getIn(int4 i) const { return (const FlowBlock *) intothis[i].point; }	///< Get the i-th input FlowBlock
  int4 getInRevIndex(int4 i) const { return intothis[i].reverse_index; }	///< Get the output index of the i-th input FlowBlock
  const FlowBlock *getFrontLeaf(void) const;				///< Get the first leaf FlowBlock
  FlowBlock *getFrontLeaf(void);					///< Get the first leaf FlowBlock
  int4 calcDepth(const FlowBlock *leaf) const;		///< Get the depth of the given component FlowBlock
  bool dominates(const FlowBlock *subBlock) const;	///< Does \b this block dominate the given block
  bool restrictedByConditional(const FlowBlock *cond) const;
  int4 sizeOut(void) const { return outofthis.size(); }	///< Get the number of out edges
  int4 sizeIn(void) const { return intothis.size(); }	///< Get the number of in edges
  bool hasLoopIn(void) const;				///< Is there a looping edge coming into \b this block
  bool hasLoopOut(void) const;				///< Is there a looping edge going out of \b this block
  bool isLoopIn(int4 i) const { return ((intothis[i].label & f_loop_edge)!=0); }	///< Is the i-th incoming edge a \e loop edge
  bool isLoopOut(int4 i) const { return ((outofthis[i].label & f_loop_edge)!=0); }	///< Is the i-th outgoing edge a \e loop edge
  int4 getInIndex(const FlowBlock *bl) const;		///< Get the incoming edge index for the given FlowBlock
  int4 getOutIndex(const FlowBlock *bl) const;		///< Get the outgoing edge index for the given FlowBlock
  bool isDefaultBranch(int4 i) const { return ((outofthis[i].label & f_defaultswitch_edge)!=0); }	///< Is the i-th out edge the switch default edge
  bool isLabelBumpUp(void) const { return ((flags & f_label_bumpup)!=0); }	///< Are labels for \b this printed by the parent
  bool isUnstructuredTarget(void) const { return ((flags & f_unstructured_targ)!=0); }	///< Is \b this the target of an unstructured goto
  bool isInteriorGotoTarget(void) const { return ((flags & f_interior_gotoin)!=0); }	///< Is there an unstructured goto to \b this block's interior
  bool hasInteriorGoto(void) const { return ((flags & f_interior_gotoout)!=0); }	///< Is there an unstructured goto out of \b this block's interior
  bool isEntryPoint(void) const { return ((flags&f_entry_point)!=0); }			///< Is the entry point of the function
  bool isSwitchOut(void) const { return ((flags&f_switch_out)!=0); }			///< Is \b this a switch block
  bool isDonothingLoop(void) const { return ((flags&f_donothing_loop)!=0); }		///< Is \b this a \e do \e nothing block
  bool isDead(void) const { return ((flags & f_dead)!=0); }				///< Is \b this block dead
  bool isTreeEdgeIn(int4 i) const { return ((intothis[i].label & f_tree_edge)!=0); }	///< Is the i-th incoming edge part of the spanning tree
  bool isBackEdgeIn(int4 i) const { return ((intothis[i].label & f_back_edge)!=0); }	///< Is the i-th incoming edge a \e back edge
  bool isBackEdgeOut(int4 i) const { return ((outofthis[i].label & f_back_edge)!=0); }	///< Is the i-th outgoing edge a \e back edge
  bool isIrreducibleOut(int4 i) const { return ((outofthis[i].label & f_irreducible)!=0); }	///< Is the i-th outgoing edge an irreducible edge
  bool isIrreducibleIn(int4 i) const { return ((intothis[i].label & f_irreducible)!=0); }	///< Is the i-th incoming edge an irreducible edge

  /// \brief Can \b this and the i-th output be merged into a BlockIf or BlockList
  bool isDecisionOut(int4 i) const { return ((outofthis[i].label & (f_irreducible|f_back_edge|f_goto_edge))==0); }

  /// \brief Can \b this and the i-th input be merged into a BlockIf or BlockList
  bool isDecisionIn(int4 i) const { return ((intothis[i].label & (f_irreducible|f_back_edge|f_goto_edge))==0); }

  /// \brief Is the i-th outgoing edge part of the DAG sub-graph
  bool isLoopDAGOut(int4 i) const { return ((outofthis[i].label & (f_irreducible|f_back_edge|f_loop_exit_edge|f_goto_edge))==0); }

  /// \brief Is the i-th incoming edge part of the DAG sub-graph
  bool isLoopDAGIn(int4 i) const { return ((intothis[i].label & (f_irreducible|f_back_edge|f_loop_exit_edge|f_goto_edge))==0); }
  bool isGotoIn(int4 i) const { return ((intothis[i].label & (f_irreducible|f_goto_edge))!=0); }	///< Is the i-th incoming edge unstructured
  bool isGotoOut(int4 i) const { return ((outofthis[i].label & (f_irreducible|f_goto_edge))!=0); }	///< Is the i-th outgoing edge unstructured
  JumpTable *getJumptable(void) const;	///< Get the JumpTable associated \b this block
  static block_type nameToType(const string &name);	///< Get the block_type associated with a name string
  static string typeToName(block_type bt);		///< Get the name string associated with a block_type
  static bool compareBlockIndex(const FlowBlock *bl1,const FlowBlock *bl2);	///< Compare FlowBlock by index
  static bool compareFinalOrder(const FlowBlock *bl1,const FlowBlock *bl2);	///< Final FlowBlock comparison
  static FlowBlock *findCommonBlock(FlowBlock *bl1,FlowBlock *bl2);	///< Find the common dominator of two FlowBlocks
  static FlowBlock *findCommonBlock(const vector<FlowBlock *> &blockSet);	///< Find common dominator of multiple FlowBlocks
  static FlowBlock *findCondition(FlowBlock *bl1,int4 edge1,FlowBlock *bl2,int4 edge2,int4 &slot1);
};

/// \brief A control-flow block built out of sub-components
///
/// This is the core class for building a hierarchy of control-flow blocks.
/// A set of control-flow blocks can be grouped together and viewed as a single block,
/// with its own input and output blocks.
/// All the code structuring elements (BlockList, BlockIf, BlockWhileDo, etc.) derive from this.
class BlockGraph : public FlowBlock {
  vector<FlowBlock *> list;     	///< List of FlowBlock components within \b this super-block
  void addBlock(FlowBlock *bl);		///< Add a component FlowBlock
  void forceOutputNum(int4 i);		///< Force number of outputs
  void selfIdentify(void);		///< Inherit our edges from the edges of our components
  void identifyInternal(BlockGraph *ident,const vector<FlowBlock *> &nodes);
  void clearEdgeFlags(uint4 fl);	///< Clear a set of properties from all edges in the graph
  static FlowBlock *createVirtualRoot(const vector<FlowBlock *> &rootlist);
  void findSpanningTree(vector<FlowBlock *> &preorder,vector<FlowBlock *> &rootlist);
  bool findIrreducible(const vector<FlowBlock *> &preorder,int4 &irreduciblecount);
  void forceFalseEdge(const FlowBlock *out0);	///< Force the \e false out edge to go to the given FlowBlock
protected:
  void swapBlocks(int4 i,int4 j);	///< Swap the positions two component FlowBlocks
  static void markCopyBlock(FlowBlock *bl,uint4 fl);	///< Set properties on the first leaf FlowBlock
public:
  void clear(void);					///< Clear all component FlowBlock objects
  virtual ~BlockGraph(void) { clear(); }		///< Destructor
  const vector<FlowBlock *> &getList(void) const { return list; }	///< Get the list of component FlowBlock objects
  int4 getSize(void) const { return list.size(); }	///< Get the number of components
  FlowBlock *getBlock(int4 i) const { return list[i]; }	///< Get the i-th component
  virtual block_type getType(void) const { return t_graph; }
  virtual FlowBlock *subBlock(int4 i) const { return list[i]; }
  virtual void markUnstructured(void);
  virtual void markLabelBumpUp(bool bump);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printTree(ostream &s,int4 level) const;
  virtual void printRaw(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockGraph(this); }
  virtual PcodeOp *firstOp(void) const;
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void finalTransform(Funcdata &data);
  virtual void finalizePrinting(Funcdata &data) const;
  virtual void encodeBody(Encoder &encoder) const;
  virtual void decodeBody(Decoder &decoder);
  void decode(Decoder &decoder);				///< Decode \b this BlockGraph from a stream
  void addEdge(FlowBlock *begin,FlowBlock *end);		///< Add a directed edge between component FlowBlocks
  void addLoopEdge(FlowBlock *begin,int4 outindex);		///< Mark a given edge as a \e loop edge
  void removeEdge(FlowBlock *begin,FlowBlock *end);		///< Remove an edge between component FlowBlocks
  void switchEdge(FlowBlock *in,FlowBlock *outbefore,FlowBlock *outafter);	///< Move an edge from one out FlowBlock to another
  void moveOutEdge(FlowBlock *blold,int4 slot,FlowBlock *blnew);	///< Move indicated \e out edge to a new FlowBlock
  void removeBlock(FlowBlock *bl);				///< Remove a FlowBlock from \b this BlockGraph
  void removeFromFlow(FlowBlock *bl);				///< Remove given FlowBlock preserving flow in \b this
  void removeFromFlowSplit(FlowBlock *bl,bool flipflow);	///< Remove FlowBlock splitting flow between input and output edges
  void spliceBlock(FlowBlock *bl);		///< Splice given FlowBlock together with its output
  void setStartBlock(FlowBlock *bl);		///< Set the entry point FlowBlock for \b this graph
  FlowBlock *getStartBlock(void) const;		///< Get the entry point FlowBlock
				// Factory functions
  FlowBlock *newBlock(void);							///< Build a new plain FlowBlock
  BlockBasic *newBlockBasic(Funcdata *fd);					///< Build a new BlockBasic

				// Factory (identify) routines
  BlockCopy *newBlockCopy(FlowBlock *bl);					///< Build a new BlockCopy
  BlockGoto *newBlockGoto(FlowBlock *bl);					///< Build a new BlockGoto
  BlockMultiGoto *newBlockMultiGoto(FlowBlock *bl,int4 outedge);		///< Build a new BlockMultiGoto
  BlockList *newBlockList(const vector<FlowBlock *> &nodes);			///< Build a new BlockList
  BlockCondition *newBlockCondition(FlowBlock *b1,FlowBlock *b2);		///< Build a new BlockCondition
  BlockIf *newBlockIfGoto(FlowBlock *cond);					///< Build a new BlockIfGoto
  BlockIf *newBlockIf(FlowBlock *cond,FlowBlock *tc);				///< Build a new BlockIf
  BlockIf *newBlockIfElse(FlowBlock *cond,FlowBlock *tc,FlowBlock *fc);		///< Build a new BlockIfElse
  BlockWhileDo *newBlockWhileDo(FlowBlock *cond,FlowBlock *cl);			///< Build a new BlockWhileDo
  BlockDoWhile *newBlockDoWhile(FlowBlock *condcl);				///< Build a new BlockDoWhile
  BlockInfLoop *newBlockInfLoop(FlowBlock *body);				///< Build a new BlockInfLoop
  BlockSwitch *newBlockSwitch(const vector<FlowBlock *> &cs,bool hasExit);	///< Build a new BlockSwitch

  void orderBlocks(void) {	///< Sort blocks using the final ordering
    if (list.size()!=1) sort(list.begin(),list.end(),compareFinalOrder); }
  void buildCopy(const BlockGraph &graph);					///< Build a copy of a BlockGraph
  void clearVisitCount(void);							///< Clear the visit count in all node FlowBlocks
  void calcForwardDominator(const vector<FlowBlock *> &rootlist);		///< Calculate forward dominators
  void buildDomTree(vector<vector<FlowBlock *> > &child) const;			///< Build the dominator tree
  int4 buildDomDepth(vector<int4> &depth) const;				///< Calculate dominator depths
  void buildDomSubTree(vector<FlowBlock *> &res,FlowBlock *root) const;		///< Collect nodes from a dominator sub-tree
  void calcLoop(void);								///< Calculate loop edges
  void collectReachable(vector<FlowBlock *> &res,FlowBlock *bl,bool un) const;	///< Collect reachable/unreachable FlowBlocks from a given start FlowBlock
  void structureLoops(vector<FlowBlock *> &rootlist);				///< Label loop edges
#ifdef BLOCKCONSISTENT_DEBUG
  bool isConsistent(void) const;						///< Check consistency of \b this BlockGraph
#endif
};

/// \brief A basic block for p-code operations.
///
/// A \b basic \b block is a maximal sequence of p-code operations (PcodeOp) that,
/// within the context of a function, always execute starting with the first
/// operation in sequence through in order to the last operation.  Any decision points in the
/// control flow of a function manifest as branching operations (BRANCH, CBRANCH, BRANCHIND)
/// that necessarily occur as the last operation in a basic block.
///
/// Every Funcdata object implements the control-flow graph of the underlying function using
/// BlockBasic objects as the underlying nodes of the graph.  The decompiler structures code
/// by making a copy of this graph and then overlaying a hierarchy of structured nodes on top of it.
///
/// The block also keeps track of the original range of addresses of instructions constituting the block.
/// As decompiler transformations progress, the set of addresses associated with the current set of
/// PcodeOps my migrate away from this original range.
class BlockBasic: public FlowBlock {
  friend class Funcdata;				// Only uses private functions
  list<PcodeOp *> op;					///< The sequence of p-code operations
  Funcdata *data;					///< The function of which this block is a part
  RangeList cover;					///< Original range of addresses covered by this basic block
  void insert(list<PcodeOp *>::iterator iter,PcodeOp *inst);	///< Insert p-code operation at a given position
  void setInitialRange(const Address &beg,const Address &end);	///< Set the initial address range of the block
  void copyRange(const BlockBasic *bb) { cover = bb->cover; }	///< Copy address ranges from another basic block
  void mergeRange(const BlockBasic *bb) { cover.merge(bb->cover); }	///< Merge address ranges from another basic block
  void setOrder(void);					///< Reset the \b SeqNum::order field for all PcodeOp objects in this block
  void removeOp(PcodeOp *inst);				///< Remove PcodeOp from \b this basic block
public:
  BlockBasic(Funcdata *fd) { data = fd; }		///< Construct given the underlying function
  Funcdata *getFuncdata(void) { return data; }		///< Return the underlying Funcdata object
  const Funcdata *getFuncdata(void) const { return (const Funcdata *)data; }	///< Return the underlying Funcdata object
  bool contains(const Address &addr) const { return cover.inRange(addr, 1); }	///< Determine if the given address is contained in the original range
  Address getEntryAddr(void) const;			///< Get the address of the (original) first operation to execute
  virtual Address getStart(void) const;
  virtual Address getStop(void) const;
  virtual block_type getType(void) const { return t_basic; }
  virtual FlowBlock *subBlock(int4 i) const { return (FlowBlock *)0; }
  virtual void encodeBody(Encoder &encoder) const;
  virtual void decodeBody(Decoder &decoder);
  virtual void printHeader(ostream &s) const;
  virtual void printRaw(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockBasic(this); }
  virtual const FlowBlock *getExitLeaf(void) const { return this; }
  virtual PcodeOp *firstOp(void) const;
  virtual PcodeOp *lastOp(void) const;
  virtual bool negateCondition(bool toporbottom);
  virtual FlowBlock *getSplitPoint(void);
  virtual int4 flipInPlaceTest(vector<PcodeOp *> &fliplist) const;
  virtual void flipInPlaceExecute(void);
  virtual bool isComplex(void) const;
  bool unblockedMulti(int4 outslot) const;		///< Check if \b this block can be removed without introducing inconsistencies
  bool hasOnlyMarkers(void) const;		///< Does \b this block contain only MULTIEQUAL and INDIRECT ops
  bool isDoNothing(void) const;			///< Should \b this block should be removed
  list<PcodeOp *>::iterator beginOp(void) { return op.begin(); }	///< Return an iterator to the beginning of the PcodeOps
  list<PcodeOp *>::iterator endOp(void) { return op.end(); }		///< Return an iterator to the end of the PcodeOps
  list<PcodeOp *>::const_iterator beginOp(void) const { return op.begin(); }	///< Return an iterator to the beginning of the PcodeOps
  list<PcodeOp *>::const_iterator endOp(void) const { return op.end(); }	///< Return an iterator to the end of the PcodeOps
  bool emptyOp(void) const { return op.empty(); }		///< Return \b true if \b block contains no operations
  bool noInterveningStatement(void) const;
  PcodeOp *findMultiequal(const vector<Varnode *> &varArray);		///< Find MULTIEQUAL with given inputs
  PcodeOp *earliestUse(Varnode *vn);
  static bool liftVerifyUnroll(vector<Varnode *> &varArray,int4 slot);	///< Verify given Varnodes are defined with same PcodeOp
};

/// \brief This class is used to mirror the BlockBasic objects in the fixed control-flow graph for a function
///
/// The decompiler does control-flow structuring by making an initial copy of the control-flow graph,
/// then iteratively collapsing nodes (in the copy) into \e structured nodes.  So an instance of this
/// class acts as the mirror of an original basic block within the copy of the graph.  During the
/// structuring process, an instance will start with an exact mirror of its underlying basic block's edges,
/// but as the algorithm proceeds, edges may get replaced as neighboring basic blocks get collapsed, and
/// eventually the instance will get collapsed itself and become a component of one of the \e structured
/// block objects (BlockIf, BlockDoWhile, etc). The block that incorporates the BlockCopy as a component
/// is accessible through getParent().
class BlockCopy : public FlowBlock {
  FlowBlock *copy;			///< The block being mirrored by \b this (usually a BlockBasic)
public:
  BlockCopy(FlowBlock *bl) { copy = bl; }	///< Construct given the block to copy
  virtual FlowBlock *subBlock(int4 i) const { return copy; }
  virtual block_type getType(void) const { return t_copy; }
  virtual void printHeader(ostream &s) const;
  virtual void printTree(ostream &s,int4 level) const;
  virtual void printRaw(ostream &s) const { copy->printRaw(s); }
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockCopy(this); }
  virtual const FlowBlock *getExitLeaf(void) const { return this; }
  virtual PcodeOp *firstOp(void) const { return copy->firstOp(); }
  virtual PcodeOp *lastOp(void) const { return copy->lastOp(); }
  virtual bool negateCondition(bool toporbottom) { bool res = copy->negateCondition(true); FlowBlock::negateCondition(toporbottom); return res; }
  virtual FlowBlock *getSplitPoint(void) { return copy->getSplitPoint(); }
  virtual bool isComplex(void) const { return copy->isComplex(); }
  virtual void encodeHeader(Encoder &encoder) const;
};

/// \brief A block that terminates with an unstructured (goto) branch to another block
///
/// The \e goto must be an unconditional branch.  The instance keeps track of the target block and
/// will emit the branch as some form of formal branch statement (goto, break, continue).
/// From the point of view of control-flow structuring, this block has \e no output edges. The
/// algorithm handles edges it can't structure by encapsulating it in the BlockGoto class and
/// otherwise removing the edge from the structured view of the graph.
class BlockGoto : public BlockGraph {
  FlowBlock *gototarget;			///< The target block of the unstructured branch
  uint4 gototype;				///< The type of unstructured branch (f_goto_goto, f_break_goto, etc.)
public:
  BlockGoto(FlowBlock *bl) { gototarget = bl; gototype = f_goto_goto; }	///< Construct given target block
  FlowBlock *getGotoTarget(void) const { return gototarget; }		///< Get the target block of the goto
  uint4 getGotoType(void) const { return gototype; }			///< Get the type of unstructured branch
  bool gotoPrints(void) const;						///< Should a formal goto statement be emitted
  virtual block_type getType(void) const { return t_goto; }
  virtual void markUnstructured(void);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void printRaw(ostream &s) const { getBlock(0)->printRaw(s); }
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockGoto(this); }
  virtual const FlowBlock *getExitLeaf(void) const { return getBlock(0)->getExitLeaf(); }
  virtual PcodeOp *lastOp(void) const { return getBlock(0)->lastOp(); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void encodeBody(Encoder &encoder) const;
};

/// \brief A block with multiple edges out, at least one of which is an unstructured (goto) branch.
///
/// An instance of this class is used to mirror a basic block with multiple out edges at the point
/// where one of the edges can't be structured.  The instance keeps track of this edge but otherwise
/// presents a view to the structuring algorithm as if the edge didn't exist.  If at a later point,
/// more edges can't be structured, the one instance can hold this information as well.
class BlockMultiGoto : public BlockGraph {
  vector<FlowBlock *> gotoedges; 		///< List of goto targets from this block
  bool defaultswitch;				///< True if one of the unstructured edges is the formal switch \e default edge
public:
  BlockMultiGoto(FlowBlock *bl) { defaultswitch = false; }	///< Construct given the underlying multi-exit block
  void setDefaultGoto(void) { defaultswitch = true; }		///< Mark that this block holds an unstructured switch default
  bool hasDefaultGoto(void) const { return defaultswitch; }	///< Does this block hold an unstructured switch default edge
  void addEdge(FlowBlock *bl) { gotoedges.push_back(bl); }	///< Mark the edge from \b this to the given FlowBlock as unstructured
  int4 numGotos(void) const { return gotoedges.size(); }	///< Get the number of unstructured edges
  FlowBlock *getGoto(int4 i) const { return gotoedges[i]; }	///< Get the target FlowBlock along the i-th unstructured edge
  
  virtual block_type getType(void) const { return t_multigoto; }
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void printRaw(ostream &s) const { getBlock(0)->printRaw(s); }
  virtual void emit(PrintLanguage *lng) const { getBlock(0)->emit(lng); }
  virtual const FlowBlock *getExitLeaf(void) const { return getBlock(0)->getExitLeaf(); }
  virtual PcodeOp *lastOp(void) const { return getBlock(0)->lastOp(); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void encodeBody(Encoder &encoder) const;
};

/// \brief A series of blocks that execute in sequence.
///
/// When structuring control-flow, an instance of this class represents blocks
/// that execute in sequence and fall-thru to each other. In general, the component
/// blocks may not be basic blocks and can have their own sub-structures.
class BlockList : public BlockGraph {
public:
  virtual block_type getType(void) const { return t_ls; }
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockLs(this); }
  virtual const FlowBlock *getExitLeaf(void) const;
  virtual PcodeOp *lastOp(void) const;
  virtual bool negateCondition(bool toporbottom);
  virtual FlowBlock *getSplitPoint(void);
};

/// \brief Two conditional blocks combined into one conditional using BOOL_AND or BOOL_OR
///
/// This class is used to construct full conditional expressions.  An instance glues together
/// two components, each with two outgoing edges. Of the four edges, 1 must go between the two
/// components, and 2 must go to the same exit block, so there will be exactly 2 distinct exit
/// blocks in total.  The new condition can be interpreted as either:
///   -  If condition one \b and condition two, goto exit 0, otherwise goto exit 1.
///   -  If condition one \b or condition two, goto exit 1, otherwise goto exit 0.
///
/// depending on the boolean operation setting for the condition
class BlockCondition : public BlockGraph {
  OpCode opc;		///< Type of boolean operation
public:
  BlockCondition(OpCode c) { opc = c; }		///< Construct given the boolean operation
  OpCode getOpcode(void) const { return opc; }	///< Get the boolean operation
  virtual block_type getType(void) const { return t_condition; }
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockCondition(this); }
  virtual bool negateCondition(bool toporbottom);
  virtual FlowBlock *getSplitPoint(void) { return this; }
  virtual int4 flipInPlaceTest(vector<PcodeOp *> &fliplist) const;
  virtual void flipInPlaceExecute(void);
  virtual PcodeOp *lastOp(void) const;
  virtual bool isComplex(void) const { return getBlock(0)->isComplex(); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void encodeHeader(Encoder &encoder) const;
};

/// \brief A basic "if" block
///
/// This represents a formal "if" structure in code, with a expression for the condition, and
/// one or two bodies of the conditionally executed code. An instance has one, two, or three components.
/// One component is always the \e conditional block.  If there is a second component, it is
/// the block of code executed when the condition is true.  If there is a third component, it
/// is the "else" block, executed when the condition is false.
///
/// If there is only one component, this represents the case where the conditionally executed
/// branch is unstructured.  This is generally emitted where the conditionally executed body
/// is the single \e goto statement.
///
/// A BlockIf will always have at most one (structured) exit edge. With one component, one of the edges of
/// the conditional component is unstructured. With two components, one of the conditional block
/// edges flows to the body block, and the body's out edge and the remaining conditional block out
/// edge flow to the same exit block. With three components, the one conditional edge flows to the
/// \e true body block, the other conditional edge flows to the \e false body block, and outgoing
/// edges from the body blocks, if they exist, flow to the same exit block.
class BlockIf : public BlockGraph {
  uint4 gototype;			///< The type of unstructured edge (if present)
  FlowBlock *gototarget;		///< The target FlowBlock of the unstructured edge (if present)
public:
  BlockIf(void) { gototype = f_goto_goto; gototarget = (FlowBlock *)0; }	///< Constructor
  void setGotoTarget(FlowBlock *bl) { gototarget = bl; }		///< Mark the target of the unstructured edge
  FlowBlock *getGotoTarget(void) const { return gototarget; }		///< Get the target of the unstructured edge
  uint4 getGotoType(void) const { return gototype; }			///< Get the type of unstructured edge
  virtual block_type getType(void) const { return t_if; }
  virtual void markUnstructured(void);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockIf(this); }
  virtual bool preferComplement(Funcdata &data);
  virtual const FlowBlock *getExitLeaf(void) const;
  virtual PcodeOp *lastOp(void) const;
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void encodeBody(Encoder &encoder) const;
};  

/// \brief A loop structure where the condition is checked at the top.
///
/// This has exactly two components: one conditional block which evaluates when the
/// loop terminates, and one body block.  The conditional block has two outgoing edges,
/// one to the body block and one to the exit block.  The body block has one outgoing edge
/// back to the conditional block.  The BlockWhileDo instance has exactly one outgoing edge.
///
/// Overflow syntax refers to the situation where there is a proper BlockWhileDo structure but
/// the conditional block is too long or complicated to emit as a single conditional expression.
/// An alternate `while(true) { }` form is used instead.
///
/// If an iterator op is provided, the block will be printed using \e for loop syntax,
/// `for(i=0;i<10;++i)` where an \e initializer statement and \e iterator statement are
/// printed alongside the \e condition statement.  Otherwise, \e while loop syntax is used
/// `while(i<10)`
class BlockWhileDo : public BlockGraph {
  mutable PcodeOp *initializeOp;	///< Statement used as \e for loop initializer
  mutable PcodeOp *iterateOp;		///< Statement used as \e for loop iterator
  mutable PcodeOp *loopDef;		///< MULTIEQUAL merging loop variable
  void findLoopVariable(PcodeOp *cbranch,BlockBasic *head,BlockBasic *tail,PcodeOp *lastOp);	///< Find a \e loop \e variable
  PcodeOp *findInitializer(BlockBasic *head,int4 slot) const;			///< Find the for-loop initializer op
  PcodeOp *testTerminal(Funcdata &data,int4 slot) const;	///< Test that given statement is terminal and explicit
  bool testIterateForm(void) const;	///< Return \b false if the iterate statement is of an unacceptable form
public:
  BlockWhileDo(void) { initializeOp = (PcodeOp *)0; iterateOp = (PcodeOp *)0; loopDef = (PcodeOp *)0; }	///< Constructor
  PcodeOp *getInitializeOp(void) const { return initializeOp; }	///< Get root of initialize statement or null
  PcodeOp *getIterateOp(void) const { return iterateOp; }	///< Get root of iterate statement or null
  bool hasOverflowSyntax(void) const { return ((getFlags() & f_whiledo_overflow)!=0); }	///< Does \b this require overflow syntax
  void setOverflowSyntax(void) { setFlag(f_whiledo_overflow); }		///< Set that \b this requires overflow syntax
  virtual block_type getType(void) const { return t_whiledo; }
  virtual void markLabelBumpUp(bool bump);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockWhileDo(this); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void finalTransform(Funcdata &data);
  virtual void finalizePrinting(Funcdata &data) const;
};

/// \brief A loop structure where the condition is checked at the bottom.
///
/// This has exactly one component with two outgoing edges: one edge flows to itself,
/// the other flows to the exit block. The BlockDoWhile instance has exactly one outgoing edge.
class BlockDoWhile : public BlockGraph {
public:
  virtual block_type getType(void) const { return t_dowhile; }
  virtual void markLabelBumpUp(bool bump);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockDoWhile(this); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
};

/// \brief An infinite loop structure
///
/// This has exactly one component with one outgoing edge that flows into itself.
/// The BlockInfLoop instance has zero outgoing edges.
class BlockInfLoop : public BlockGraph {
public:
  virtual block_type getType(void) const { return t_infloop; }
  virtual void markLabelBumpUp(bool bump);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockInfLoop(this); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
};

/// \brief A structured \e switch construction
///
/// This always has at least one component, the first, that executes the \e switch statement
/// itself and has multiple outgoing edges. Each edge flows either to a formal exit block, or
/// to another \e case component. All additional components are \b case components, which have
/// either zero or one outgoing edge. If there is an edge, it flows either to another case
/// component or to the formal exit block.  The BlockSwitch instance has zero or one outgoing edges.
class BlockSwitch : public BlockGraph {
  JumpTable *jump;		///< Jump table associated with this switch
  /// \brief A class for annotating and sorting the individual cases of the switch
  struct CaseOrder {
    FlowBlock *block;		///< The structured \e case block
    const FlowBlock *basicblock;	///< The first basic-block to execute within the \e case block
    uintb label;		///< The \e label for this case, as an untyped constant
    int4 depth;			///< How deep in a fall-thru chain we are
    int4 chain;			///< Who we immediately chain to, expressed as caseblocks index, -1 for no chaining
    int4 outindex;		///< Index coming out of switch to this case
    uint4 gototype;		///< (If non-zero) What type of unstructured \e case is this?
    bool isexit;		///< Does this case flow to the \e exit block
    bool isdefault;		///< True if this is formal \e default case for the switch
    static bool compare(const CaseOrder &a,const CaseOrder &b);	///< Compare two cases
  };
  mutable vector<CaseOrder> caseblocks; ///< Blocks associated with switch cases
  void addCase(FlowBlock *switchbl,FlowBlock *bl,uint4 gt);	///< Add a new \e case to this switch
public:
  BlockSwitch(FlowBlock *ind);		///< Construct given the multi-exit root block
  void grabCaseBasic(FlowBlock *switchbl,const vector<FlowBlock *> &cs);	///< Build annotated CaseOrder objects
  FlowBlock *getSwitchBlock(void) const { return getBlock(0); }		///< Get the root switch component
  int4 getNumCaseBlocks(void) const { return caseblocks.size(); }	///< Get the number of cases
  FlowBlock *getCaseBlock(int4 i) const { return caseblocks[i].block; }	///< Get the i-th \e case FlowBlock

  /// \brief Get the number of labels associated with one \e case block
  ///
  /// \param i is the index of the \e case block
  /// \return the number of labels put on the associated block
  int4 getNumLabels(int4 i) const { return jump->numIndicesByBlock(caseblocks[i].basicblock); }

  /// \brief Get a specific label associated with a \e case block
  ///
  /// \param i is the index of the \e case block
  /// \param j is the index of the specific label
  /// \return the label as an untyped constant
  uintb getLabel(int4 i,int4 j) const { return jump->getLabelByIndex(jump->getIndexByBlock(caseblocks[i].basicblock,j)); }

  bool isDefaultCase(int4 i) const { return caseblocks[i].isdefault; }	///< Is the i-th \e case the \e default case
  uint4 getGotoType(int4 i) const { return caseblocks[i].gototype; }	///< Get the edge type for the i-th \e case block
  bool isExit(int4 i) const { return caseblocks[i].isexit; }		///< Does the i-th \e case block exit the switch?
  const Datatype *getSwitchType(void) const;				///< Get the data-type of the switch variable
  virtual block_type getType(void) const { return t_switch; }
  virtual void markUnstructured(void);
  virtual void scopeBreak(int4 curexit,int4 curloopexit);
  virtual void printHeader(ostream &s) const;
  virtual void emit(PrintLanguage *lng) const { lng->emitBlockSwitch(this); }
  virtual FlowBlock *nextFlowAfter(const FlowBlock *bl) const;
  virtual void finalizePrinting(Funcdata &data) const;
};

/// \brief Helper class for resolving cross-references while deserializing BlockGraph objects
///
/// FlowBlock objects are serialized with their associated \b index value and edges are serialized
/// with the indices of the FlowBlock end-points.  During deserialization, this class maintains a
/// list of FlowBlock objects sorted by index and then looks up the FlowBlock matching a given
/// index as edges specify them.
class BlockMap {
  vector<FlowBlock *> sortlist;		///< The list of deserialized FlowBlock objects
  FlowBlock *resolveBlock(FlowBlock::block_type bt);	///< Construct a FlowBlock of the given type
  static FlowBlock *findBlock(const vector<FlowBlock *> &list,int4 ind);	///< Locate a FlowBlock with a given index
public:
  void sortList(void);					///< Sort the list of FlowBlock objects

  /// \brief Find the FlowBlock matching the given index
  ///
  /// \param index is the given index
  /// \return the FlowBlock matching the index
  FlowBlock *findLevelBlock(int4 index) const { return findBlock(sortlist,index); }
  FlowBlock *createBlock(const string &name);		///< Create a FlowBlock of the named type
};

/// This is the main entry point, at the control-flow level, for printing structured code.
/// \param lng is the PrintLanguage that provides details of the high-level language being printed
inline void FlowBlock::emit(PrintLanguage *lng) const

{
}

/// For the instructions in this block, decide if the control-flow structure
/// can be rearranged so that boolean expressions come out more naturally.
/// \param data is the function to analyze
/// \return \b true if a change was made
inline bool FlowBlock::preferComplement(Funcdata &data)

{
  return false;
}

/// If \b this block ends with a conditional branch, return the
/// deepest component block that performs the split.  This component needs
/// to be able to perform flipInPlaceTest() and flipInPlaceExecute()
/// \return the component FlowBlock or NULL if this doesn't end in a conditional branch
inline FlowBlock *FlowBlock::getSplitPoint(void)

{
  return (FlowBlock *)0;
}

/// \brief Test normalizing the conditional branch in \b this
///
/// Find the set of PcodeOp objects that need to be adjusted to flip
/// the condition \b this FlowBlock calculates.
///
/// Return:
///   - 0 if the flip would normalize the condition
///   - 1 if the flip doesn't affect normalization of the condition
///   - 2 if the flip produces an unnormalized condition
/// \param fliplist will contain the PcodeOps that need to be adjusted
/// \return 0 if the condition will be normalized, 1 or 2 otherwise
inline int4 FlowBlock::flipInPlaceTest(vector<PcodeOp *> &fliplist) const

{
  return 2;	// By default a block will not normalize
}

/// \brief Perform the flip to normalize conditional branch executed by \b this block
///
/// This reverses the outgoing edge order in the right basic blocks, but does not
/// modify the instructions directly.
inline void FlowBlock::flipInPlaceExecute(void)

{
}

/// \brief Get the leaf FlowBlock that will execute after the given FlowBlock
///
/// Within the hierarchy of \b this FlowBlock, assume the given FlowBlock
/// will fall-thru in its execution at some point. Return the first
/// leaf block (BlockBasic or BlockCopy) that will execute after the given
/// FlowBlock completes, assuming this is a unique block.
/// \param bl is the given FlowBlock
/// \return the next FlowBlock to execute or NULL
inline FlowBlock *FlowBlock::nextFlowAfter(const FlowBlock *bl) const

{
  return (FlowBlock *)0;
}

/// \param bl1 is the first FlowBlock to compare
/// \param bl2 is the second FlowBlock to compare
/// \return true if the first comes before the second
inline bool FlowBlock::compareBlockIndex(const FlowBlock *bl1,const FlowBlock *bl2)

{
  return (bl1->getIndex() < bl2->getIndex());
}

/// Cases are compared by their label
/// \param a is the first case to compare
/// \param b is the second
/// \return \b true if the first comes before the second
inline bool BlockSwitch::CaseOrder::compare(const CaseOrder &a,const CaseOrder &b)

{
  if (a.label != b.label)
    return (a.label < b.label);
  return (a.depth < b.depth);
}

} // End namespace ghidra
#endif

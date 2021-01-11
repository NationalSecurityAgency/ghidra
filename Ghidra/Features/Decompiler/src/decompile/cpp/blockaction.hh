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
#ifndef __BLOCK_ACTION__
#define __BLOCK_ACTION__

/// \file blockaction.hh
/// \brief Actions and classes associated with transforming and structuring the control-flow graph

#include "action.hh"

/// \brief Class for holding an edge while the underlying graph is being manipulated
///
/// The original FlowBlock nodes that define the end-points of the edge may get
/// collapsed, but the edge may still exist between higher level components.
/// The edge can still be retrieved via the getCurrentEdge() method.
class FloatingEdge {
  FlowBlock *top;		///< Starting FlowBlock of the edge
  FlowBlock *bottom;		///< Ending FlowBlock of the edge
public:
  FloatingEdge(FlowBlock *t,FlowBlock *b) { top = t; bottom = b; }	///< Construct given end points
  FlowBlock *getTop(void) const { return top; }			///< Get the starting FlowBlock
  FlowBlock *getBottom(void) const { return bottom; }		///< Get the ending FlowBlock
  FlowBlock *getCurrentEdge(int4 &outedge,FlowBlock *graph);	///< Get the current form of the edge
};

/// \brief A description of the body of a loop.
///
/// Following Tarjan, assuming there are no \e irreducible edges, a loop body is defined
/// by the \e head (or entry-point) and 1 or more tails, which each have a \e back \e edge into
/// the head.
class LoopBody {
  FlowBlock *head;		///< head of the loop
  vector<FlowBlock *> tails;	///< (Possibly multiple) nodes with back edge returning to the head
  int4 depth;			///< Nested depth of this loop
  int4 uniquecount;		///< Total number of unique head and tail nodes
  FlowBlock *exitblock;		///< Official exit block from loop, or NULL
  list<FloatingEdge> exitedges;	///< Edges that exit to the formal exit block
  LoopBody *immed_container;	///< Immediately containing loop body, or NULL
  void extendToContainer(const LoopBody &container,vector<FlowBlock *> &body) const;
public:
  LoopBody(FlowBlock *h) { head=h; immed_container = (LoopBody *)0; depth=0; }	///< Construct with a loop head
  FlowBlock *getHead(void) const { return head; }			///< Return the head FlowBlock of the loop
  FlowBlock *getCurrentBounds(FlowBlock **top,FlowBlock *graph);	///< Return current loop bounds (\b head and \b bottom).
  void addTail(FlowBlock *bl) { tails.push_back(bl); }			///< Add a \e tail to the loop
  FlowBlock *getExitBlock(void) const { return exitblock; }		///< Get the exit FlowBlock or NULL
  void findBase(vector<FlowBlock *> &body);				///< Mark the body FlowBlocks of \b this loop
  void extend(vector<FlowBlock *> &body) const;				///< Extend body (to blocks that never exit)
  void findExit(const vector<FlowBlock *> &body);			///< Choose the exit block for \b this loop
  void orderTails(void);						///< Find preferred \b tail
  void labelExitEdges(const vector<FlowBlock *> &body);			///< Label edges that exit the loop
  void labelContainments(const vector<FlowBlock *> &body,const vector<LoopBody *> &looporder);
  void emitLikelyEdges(list<FloatingEdge> &likely,FlowBlock *graph);	///< Collect likely \e unstructured edges
  void setExitMarks(FlowBlock *graph);					///< Mark all the exits to this loop
  void clearExitMarks(FlowBlock *graph);				///< Clear the mark on all the exits to this loop
  bool operator<(const LoopBody &op2) const { return (depth > op2.depth); }	///< Order loop bodies by depth
  static void mergeIdenticalHeads(vector<LoopBody *> &looporder);	///< Merge loop bodies that share the same \e head
  static bool compare_ends(LoopBody *a,LoopBody *b);			///< Compare the \b head then \b tail
  static int4 compare_head(LoopBody *a,FlowBlock *looptop);		///< Compare just the \b head
  static LoopBody *find(FlowBlock *looptop,const vector<LoopBody *> &looporder);	///< Find a LoopBody
  static void clearMarks(vector<FlowBlock *> &body);			///< Clear the body marks
};

/// \brief Algorithm for selecting unstructured edges based an Directed Acyclic Graphs (DAG)
///
/// With the exception of the back edges in loops, structured code tends to form a DAG.
/// Within the DAG, all building blocks of structured code have a single node entry point
/// and (at most) one exit block. Given root points, this class traces edges with this kind of
/// structure.  Paths can recursively split at any point, starting a new \e active BranchPoint, but
/// the BranchPoint can't be \e retired until all paths emanating from its start either terminate
/// or come back together at the same FlowBlock node. Once a BranchPoint is retired, all the edges
/// traversed from the start FlowBlock to the end FlowBlock are likely structurable. After pushing
/// the traces as far as possible and retiring as much as possible, any \e active edge left
/// is a candidate for an unstructured branch.
///
/// Ultimately this produces a list of \e likely \e gotos, which is used whenever the structuring
/// algorithm (ActionBlockStructure) gets stuck.
///
/// The tracing can be restricted to a \e loopbody by setting the top FlowBlock of the loop as
/// the root, and the loop exit block as the finish block.  Additionally, any edges that
/// exit the loop should be marked using LoopBody::setExitMarks().
class TraceDAG {

  struct BlockTrace;

  /// A node in the control-flow graph with multiple outgoing edges in the DAG. Ideally, all
  /// these paths eventually merge at the same node.
  struct BranchPoint {
    BranchPoint *parent;	///< The parent BranchPoint along which \b this is only one path
    int4 pathout;		///< Index (of the out edge from the parent) of the path along which \b this lies
    FlowBlock *top;		///< FlowBlock that embodies the branch point
    vector<BlockTrace *> paths;	///< BlockTrace for each possible path out of \b this BlockPoint
    int4 depth;			///< Depth of BranchPoints from the root
    bool ismark;		///< Possible mark
    void createTraces(void);	///< Given the BlockTrace objects, given a new BranchPoint
  public:
    void markPath(void);	///< Mark a path from \b this up to the root BranchPoint
    int4 distance(BranchPoint *op2);	///< Calculate distance between two BranchPoints
    FlowBlock *getPathStart(int4 i);	///< Get the start of the i-th BlockTrace
    BranchPoint(void);		///< Create the (unique) root branch point
    BranchPoint(BlockTrace *parenttrace);	///< Construct given a parent BlockTrace
    ~BranchPoint(void);		///< BranchPoint owns its BlockTraces
  };

  /// \brief A trace of a single path out of a BranchPoint
  ///
  /// Once a BranchPoint is retired with 1 outgoing edge, the multiple paths coming out of
  /// the BranchPoint are considered a single path for the parent BlockTrace.
  struct BlockTrace {
    enum {
      f_active = 1,		///< This BlockTrace is \e active.
      f_terminal = 2		///< All paths from this point exit (without merging back to parent)
    };
    uint4 flags;		///< Properties of the BlockTrace
    BranchPoint *top;		///< Parent BranchPoint for which this is a path
    int4 pathout;		///< Index of the out-edge for this path (relative to the parent BranchPoint)
    FlowBlock *bottom;		///< Current node being traversed along 1 path from decision point
    FlowBlock *destnode;	///< Next FlowBlock node \b this BlockTrace will try to push into
    int4 edgelump;		///< If >1, edge to \b destnode is "virtual" representing multiple edges coming together
    list<BlockTrace *>::iterator activeiter; ///< Position of \b this in the active trace list
    BranchPoint *derivedbp;	///< BranchPoint blocker \b this traces into
  public:
    BlockTrace(BranchPoint *t,int4 po,int4 eo);		///< Construct given a parent BranchPoint and path index
    BlockTrace(BranchPoint *root,int4 po,FlowBlock *bl);	///< Construct a root BlockTrace
    bool isActive(void) const { return ((flags & f_active)!=0); }	///< Return \b true if \b this is active
    bool isTerminal(void) const { return ((flags & f_terminal)!=0); }	///< Return \b true is \b this terminates
  };

  /// \brief Record for scoring a BlockTrace for suitability as an unstructured branch
  ///
  /// This class holds various metrics about BlockTraces that are used to sort them.
  struct BadEdgeScore {
    FlowBlock *exitproto;	///< Putative exit block for the BlockTrace
    BlockTrace *trace;		///< The active BlockTrace being considered
    int4 distance;		///< Minimum distance crossed by \b this and any other BlockTrace sharing same exit block
    int4 terminal;		///< 1 if BlockTrace destination has no exit, 0 otherwise
    int4 siblingedge;		///< Number of active BlockTraces with same BranchPoint and exit as \b this
    bool compareFinal(const BadEdgeScore &op2) const;	///< Compare BadEdgeScore for unstructured suitability
    bool operator<(const BadEdgeScore &op2) const;	///< Compare for grouping
  };

  list<FloatingEdge> &likelygoto;	///< A reference to the list of likely goto edges being produced
  vector<FlowBlock *> rootlist;		///< List of root FlowBlocks to trace from
  vector<BranchPoint *> branchlist;	///< Current set of BranchPoints that have been traced
  int4 activecount;			///< Number of active BlockTrace objects
  int4 missedactivecount;		///< Current number of active BlockTraces that can't be pushed further
  list<BlockTrace *> activetrace;	///< The list of \e active BlockTrace objects
  list<BlockTrace *>::iterator current_activeiter;	///< The current \e active BlockTrace being pushed
  FlowBlock *finishblock;		///< Designated exit block for the DAG (or null)
  void removeTrace(BlockTrace *trace);	///< Remove the indicated BlockTrace
  void processExitConflict(list<BadEdgeScore>::iterator start,list<BadEdgeScore>::iterator end);
  BlockTrace *selectBadEdge(void);	///< Select the the most likely unstructured edge from active BlockTraces
  void insertActive(BlockTrace *trace);	///< Move a BlockTrace into the \e active category
  void removeActive(BlockTrace *trace);	///< Remove a BlockTrace from the \e active category
  bool checkOpen(BlockTrace *trace);	///< Check if we can push the given BlockTrace into its next node
  list<BlockTrace *>::iterator openBranch(BlockTrace *parent);	///< Open a new BranchPoint along a given BlockTrace
  bool checkRetirement(BlockTrace *trace,FlowBlock *&exitblock);	///< Check if a given BlockTrace can be retired
  list<BlockTrace *>::iterator retireBranch(BranchPoint *bp,FlowBlock *exitblock);
  void clearVisitCount(void);		/// Clear the \b visitcount field of any FlowBlock we have modified
public:
  TraceDAG(list<FloatingEdge> &lg);	///< Construct given the container for likely unstructured edges
  ~TraceDAG(void);			///< Destructor
  void addRoot(FlowBlock *root) { rootlist.push_back(root); }	///< Add a root FlowBlock to the trace
  void initialize(void);		///< Create the initial BranchPoint and BlockTrace objects
  void pushBranches(void);		///< Push the trace through, removing edges as necessary
  void setFinishBlock(FlowBlock *bl) { finishblock = bl; }	///< Mark an exit point not to trace beyond
};

/// \brief Build a code structure from a control-flow graph (BlockGraph).
///
/// This class manages the main control-flow structuring algorithm for the decompiler.
/// In short:
///    - Start with a control-flow graph of basic blocks.
///    - Repeatedly apply:
///       - Search for sub-graphs matching specific code structure elements.
///       - Note the structure element and collapse the component nodes to a single node.
///    - If the process gets stuck, remove appropriate edges, marking them as unstructured.
class CollapseStructure {
  bool finaltrace;				///< Have we a made search for unstructured edges in the final DAG
  bool likelylistfull;				///< Have we generated a \e likely \e goto list for the current innermost loop
  list<FloatingEdge> likelygoto;		///< The current \e likely \e goto list
  list<FloatingEdge>::iterator likelyiter;	///< Iterator to the next most \e likely \e goto edge
  list<LoopBody> loopbody;			///< The list of loop bodies for this control-flow graph
  list<LoopBody>::iterator loopbodyiter;	///< Current (innermost) loop being structured
  BlockGraph &graph;				///< The control-flow graph
  int4 dataflow_changecount;			///< Number of data-flow changes made during structuring
  bool checkSwitchSkips(FlowBlock *switchbl,FlowBlock *exitblock);
  void onlyReachableFromRoot(FlowBlock *root,vector<FlowBlock *> &body);
  int4 markExitsAsGotos(vector<FlowBlock *> &body);	///< Mark edges exiting the body as \e unstructured gotos
  bool clipExtraRoots(void);			///< Mark edges between root components as \e unstructured gotos
  void labelLoops(vector<LoopBody *> &looporder);	///< Identify all the loops in this graph
  void orderLoopBodies(void);			///< Identify and label all loop structure for this graph
  bool updateLoopBody(void);			///< Find likely \e unstructured edges within the innermost loop body
  FlowBlock *selectGoto(void);			///< Select an edge to mark as  \e unstructured
  bool ruleBlockGoto(FlowBlock *bl);		///< Attempt to apply the BlockGoto structure
  bool ruleBlockCat(FlowBlock *bl);		///< Attempt to apply a BlockList structure
  bool ruleBlockOr(FlowBlock *bl);		///< Attempt to apply a BlockCondition structure
  bool ruleBlockProperIf(FlowBlock *bl);	///< Attempt to apply a 2 component form of BlockIf
  bool ruleBlockIfElse(FlowBlock *bl);		///< Attempt to apply a 3 component form of BlockIf
  bool ruleBlockIfNoExit(FlowBlock *bl);	///< Attempt to apply BlockIf where the body does not exit
  bool ruleBlockWhileDo(FlowBlock *bl);		///< Attempt to apply the BlockWhileDo structure
  bool ruleBlockDoWhile(FlowBlock *bl);		///< Attempt to apply the BlockDoWhile structure
  bool ruleBlockInfLoop(FlowBlock *bl);		///< Attempt to apply the BlockInfLoop structure
  bool ruleBlockSwitch(FlowBlock *bl);		///< Attempt to apply the BlockSwitch structure
  bool ruleCaseFallthru(FlowBlock *bl);		///< Attempt to one switch case falling through to another
  int4 collapseInternal(FlowBlock *targetbl);	///< The main collapsing loop
  void collapseConditions(void);		///< Simplify conditionals
public:
  CollapseStructure(BlockGraph &g);		///< Construct given a control-flow graph
  int4 getChangeCount(void) const { return dataflow_changecount; }	///< Get number of data-flow changes
  void collapseAll(void);			///< Run the whole algorithm
};

/// \brief Discover and eliminate \e split conditions
///
/// A \b split condition is when a conditional expression, resulting in a CBRANCH,
/// is duplicated across two blocks that would otherwise merge.
/// Instead of a single conditional in a merged block,
/// there are two copies of the conditional, two splitting blocks and no direct merge.
class ConditionalJoin {
  /// \brief A pair of Varnode objects that have been split (and should be merged)
  struct MergePair {
    Varnode *side1;		///< Varnode coming from block1
    Varnode *side2;		///< Varnode coming from block2
    MergePair(Varnode *s1,Varnode *s2) { side1 = s1; side2 = s2; }	///< Construct from Varnode objects
    bool operator<(const MergePair &op2) const;				///< Lexicographic comparator
  };
  Funcdata &data;			///< The function being analyzed
  BlockBasic *block1;			///< Side 1 of the (putative) split
  BlockBasic *block2;			///< Side 2 of the (putative) split
  BlockBasic *exita;			///< First (common) exit point
  BlockBasic *exitb;			///< Second (common) exit point
  int4 a_in1;				///< In edge of \b exita coming from \b block1
  int4 a_in2;				///< In edge of \b exita coming from \b block2
  int4 b_in1;				///< In edge of \b exitb coming from \b block1
  int4 b_in2;				///< In edge of \b exitb coming from \b block2
  PcodeOp *cbranch1;			///< CBRANCH at bottom of \b block1
  PcodeOp *cbranch2;			///< CBRANCH at bottom of \b block2
  BlockBasic *joinblock;		///< The new joined condition block
  map<MergePair,Varnode *> mergeneed;	///< Map from the MergePair of Varnodes to the merged Varnode
  bool findDups(void);			///< Search for duplicate conditional expressions
  void checkExitBlock(BlockBasic *exit,int4 in1,int4 in2);
  void cutDownMultiequals(BlockBasic *exit,int4 in1,int4 in2);
  void setupMultiequals(void);		///< Join the Varnodes in the new \b joinblock
  void moveCbranch(void);	 	//< Move one of the duplicated CBRANCHs into the new \b joinblock
public:
  ConditionalJoin(Funcdata &fd) : data(fd) { }	///< Constructor
  bool match(BlockBasic *b1,BlockBasic *b2);	///< Test blocks for the merge condition
  void execute(void);				///< Execute the merge
  void clear(void);				///< Clear for a new test
};

/// \brief Give each control-flow structure an opportunity to make a final transform
///
/// This is currently used to set up \e for loops via BlockWhileDo
class ActionStructureTransform : public Action {
public:
  ActionStructureTransform(const string &g) : Action(0,"structuretransform",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionStructureTransform(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Flip conditional control-flow so that \e preferred comparison operators are used
///
/// This is used as an alternative to the standard algorithm that structures control-flow, when
/// normalization of the data-flow is important but structured source code doesn't need to be emitted.
class ActionNormalizeBranches : public Action {
public:
  ActionNormalizeBranches(const string &g) : Action(0,"normalizebranches",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionNormalizeBranches(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief  Attempt to normalize symmetric block structures.
///
/// This is used in conjunction with the action ActionBlockStructure
/// to make the most natural choice, when there is a choice in how code is structured.
/// This uses the preferComplement() method on structured FlowBlocks to choose between symmetric
/// structurings, such as an if/else where the \b true and \b false blocks can be swapped.
class ActionPreferComplement : public Action {
public:
  ActionPreferComplement(const string &g) : Action(0,"prefercomplement",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionPreferComplement(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Structure control-flow using standard high-level code constructs.
class ActionBlockStructure : public Action {
public:
  ActionBlockStructure(const string &g) : Action(0,"blockstructure",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionBlockStructure(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Perform final organization of the control-flow structure
///
/// Label unstructured edges, order switch cases, and order disjoint components of the control-flow
class ActionFinalStructure : public Action {
public:
  ActionFinalStructure(const string &g) : Action(0,"finalstructure",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionFinalStructure(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Split the epilog code of the function
///
/// Introduce RETURN operations corresponding to individual branches flowing to the epilog.
class ActionReturnSplit : public Action {
  static void gatherReturnGotos(FlowBlock *parent,vector<FlowBlock *> &vec);
  static bool isSplittable(BlockBasic *b);		///< Determine if a RETURN block can be split
public:
  ActionReturnSplit(const string &g) : Action(0,"returnsplit",g) {}		///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionReturnSplit(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief  Look for conditional branch expressions that have been split and rejoin them
class ActionNodeJoin : public Action {
public:
  ActionNodeJoin(const string &g) : Action(0,"nodejoin",g) {}			///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionNodeJoin(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

#endif

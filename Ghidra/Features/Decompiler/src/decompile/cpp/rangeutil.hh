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
/// \file rangeutil.hh
/// \brief Documentation for the CircleRange class
#ifndef __RANGEUTIL__
#define __RANGEUTIL__

#include "op.hh"

/// \brief A class for manipulating integer value ranges.
///
/// The idea is to have a representation of common sets of
/// values that a varnode might take on in analysis so that
/// the representation can be manipulated symbolically to
/// some extent.  The representation is a circular range
/// (determined by a half-open interval [left,right)), over
/// the integers mod 2^n,  where mask = 2^n-1.
/// The range can support a step, if some of the
/// least significant bits of the mask are set to zero.
///
/// The class then can
///   - Generate ranges based on a pcode condition:
///      -    x < 2      =>   left=0  right=2  mask=sizeof(x)
///      -    5 >= x     =>   left=5  right=0  mask=sizeof(x)
///
///   - Intersect and union ranges, if the result is another range
///   - Pull-back a range through a transformation operation
///   - Iterate
///
///   \code
///     val = range.getMin();
///     do {
///     } while(range.getNext(val));
///   \endcode
class CircleRange {
  uintb left;			///< Left boundary of the open range [left,right)
  uintb right;			///< Right boundary of the open range [left,right)
  uintb mask;			///< Bit mask defining the size (modulus) and stop of the range
  bool isempty;			///< \b true if set is empty
  int4 step;			///< Explicit step size
  static const char arrange[];	///< Map from raw overlaps to normalized overlap code
  void normalize(void);		///< Normalize the representation of full sets
  void complement(void);	///< Set \b this to the complement of itself
  bool convertToBoolean(void);	///< Convert \b this to boolean.
  static bool newStride(uintb mask,int4 step,int4 oldStep,uint4 rem,uintb &myleft,uintb &myright);
  static bool newDomain(uintb newMask,int4 newStep,uintb &myleft,uintb &myright);
  static char encodeRangeOverlaps(uintb op1left,uintb op1right,uintb op2left,uintb op2right);	///< Calculate overlap code
public:
  CircleRange(void) { isempty=true; }		///< Construct an empty range
  CircleRange(uintb lft,uintb rgt,int4 size,int4 stp);	///< Construct given specific boundaries.
  CircleRange(bool val);			///< Construct a boolean range
  CircleRange(uintb val,int4 size);		///< Construct range with single value
  void setRange(uintb lft,uintb rgt,int4 size,int4 step);	///< Set directly to a specific range
  void setRange(uintb val,int4 size);		///< Set range with a single value
  void setFull(int4 size);			///< Set a completely full range
  bool isEmpty(void) const { return isempty; }	///< Return \b true if \b this range is empty
  bool isFull(void) const { return ((!isempty) && (step == 1) && (left == right)); }	///< Return \b true if \b this contains all possible values
  bool isSingle(void) const { return (!isempty) && (right == ((left + step)& mask)); }	///< Return \b true if \b this contains single value
  uintb getMin(void) const { return left; }	///< Get the left boundary of the range
  uintb getMax(void) const { return (right-step)&mask; }	///< Get the right-most integer contained in the range
  uintb getEnd(void) const { return right; }	///< Get the right boundary of the range
  uintb getMask(void) const { return mask; }	///< Get the mask
  uintb getSize(void) const;			///< Get the size of this range
  int4 getStep(void) const { return step; }	///< Get the step for \b this range
  int4 getMaxInfo(void) const;			///< Get maximum information content of range
  bool operator==(const CircleRange &op2) const;	///< Equals operator
  bool getNext(uintb &val) const { val = (val+step)&mask; return (val!=right); }	///< Advance an integer within the range
  bool contains(const CircleRange &op2) const;	///< Check containment of another range in \b this.
  bool contains(uintb val) const;		///< Check containment of a specific integer.
  int4 intersect(const CircleRange &op2);	///< Intersect \b this with another range
  bool setNZMask(uintb nzmask,int4 size);	///< Set the range based on a putative mask.
  int4 circleUnion(const CircleRange &op2);	///< Union two ranges.
  bool minimalContainer(const CircleRange &op2,int4 maxStep);	///< Construct minimal range that contains both \b this and another range
  int4 invert(void);				///< Convert to complementary range
  void setStride(int4 newStep,uintb rem);	///< Set a new step on \b this range.
  bool pullBackUnary(OpCode opc,int4 inSize,int4 outSize);	///< Pull-back \b this through the given unary operator
  bool pullBackBinary(OpCode opc,uintb val,int4 slot,int4 inSize,int4 outSize);	///< Pull-back \b this thru binary operator
  Varnode *pullBack(PcodeOp *op,Varnode **constMarkup,bool usenzmask);	///< Pull-back \b this range through given PcodeOp.
  bool pushForwardUnary(OpCode opc,const CircleRange &in1,int4 inSize,int4 outSize);	///< Push-forward thru given unary operator
  bool pushForwardBinary(OpCode opc,const CircleRange &in1,const CircleRange &in2,int4 inSize,int4 outSize,int4 maxStep);
  bool pushForwardTrinary(OpCode opc,const CircleRange &in1,const CircleRange &in2,const CircleRange &in3,
			  int4 inSize,int4 outSize,int4 maxStep);
  void widen(const CircleRange &op2,bool leftIsStable);	///< Widen the unstable bound to match containing range
  int4 translate2Op(OpCode &opc,uintb &c,int4 &cslot) const;	///< Translate range to a comparison op
  void printRaw(ostream &s) const;		///< Write a text representation of \b this to stream
};

class Partition;		// Forward declaration
class Widener;			// Forward declaration

/// \brief A range of values attached to a Varnode within a data-flow subsystem
///
/// This class acts as both the set of values for the Varnode and as a node in a
/// sub-graph overlaying the full data-flow of the function containing the Varnode.
/// The values are stored in the CircleRange field and can be interpreted either as
/// absolute values (if \b typeCode is 0) or as values relative to a stack pointer
/// or some other register (if \b typeCode is non-zero).
class ValueSet {
public:
  static const int4 MAX_STEP;	///< Maximum step inferred for a value set
  /// \brief An external that can be applied to a ValueSet
  ///
  /// An Equation is attached to a particular ValueSet and its underlying Varnode
  /// providing additional restriction on the ValueSet of an input parameter of the
  /// operation producing the Varnode.
  class Equation {
    friend class ValueSet;
    int4 slot;			///< The input parameter slot to which the constraint is attached
    int4 typeCode;		///< The constraint characteristic 0=absolute 1=relative to a spacebase register
    CircleRange range;		///< The range constraint
  public:
    Equation(int4 s,int4 tc,const CircleRange &rng) { slot=s; typeCode = tc; range = rng; }	///< Constructor
  };
private:
  friend class ValueSetSolver;
  int4 typeCode;	///< 0=pure constant 1=stack relative
  int4 numParams;	///< Number of input parameters to defining operation
  int4 count;		///< Depth first numbering / widening count
  OpCode opCode;	///< Op-code defining Varnode
  bool leftIsStable;	///< Set to \b true if left boundary of range didn't change (last iteration)
  bool rightIsStable;	///< Set to \b true if right boundary of range didn't change (last iteration)
  Varnode *vn;		///< Varnode whose set this represents
  CircleRange range;	///< Range of values or offsets in this set
  vector<Equation> equations;	///< Any equations associated with this value set
  Partition *partHead;	///< If Varnode is a component head, pointer to corresponding Partition
  ValueSet *next;	///< Next ValueSet to iterate
  bool doesEquationApply(int4 num,int4 slot) const;	///< Does the indicated equation apply for the given input slot
  void setFull(void) { range.setFull(vn->getSize()); typeCode = 0; }	///< Mark value set as possibly containing any value
  void setVarnode(Varnode *v,int4 tCode);	///< Attach \b this to given Varnode and set initial values
  void addEquation(int4 slot,int4 type,const CircleRange &constraint);	///< Insert an equation restricting \b this value set
  void addLandmark(int4 type,const CircleRange &constraint) { addEquation(numParams,type,constraint); }	///< Add a widening landmark
  bool computeTypeCode(void);	///< Figure out if \b this value set is absolute or relative
  bool iterate(Widener &widener);	///< Regenerate \b this value set from operator inputs
public:
  int4 getCount(void) const { return count; }		///< Get the current iteration count
  const CircleRange *getLandMark(void) const;		///< Get any \e landmark range
  int4 getTypeCode(void) const { return typeCode; }	///< Return '0' for normal constant, '1' for spacebase relative
  Varnode *getVarnode(void) const { return vn; }	///< Get the Varnode attached to \b this ValueSet
  const CircleRange &getRange(void) const { return range; }	///< Get the actual range of values
  bool isLeftStable(void) const { return leftIsStable; }	///< Return \b true if the left boundary hasn't been changing
  bool isRightStable(void) const { return rightIsStable; }	///< Return \b true if the right boundary hasn't been changing
  void printRaw(ostream &s) const;		///< Write a text description of \b to the given stream
};

/// \brief A range of nodes (within the weak topological ordering) that are iterated together
class Partition {
  friend class ValueSetSolver;
  ValueSet *startNode;		///< Starting node of component
  ValueSet *stopNode;		///< Ending node of component
  bool isDirty;			///< Set to \b true if a node in \b this component has changed this iteration
public:
  Partition(void) {
    startNode = (ValueSet *)0; stopNode = (ValueSet *)0; isDirty = false;
  }				///< Construct empty partition
};

/// \brief A special form of ValueSet associated with the \e read \e point of a Varnode
///
/// When a Varnode is read, it may have a more restricted range at the point of the read
/// compared to the full scope. This class officially stores the value set at the point
/// of the read (specified by PcodeOp and slot).  It is computed as a final step after
/// the main iteration has completed.
class ValueSetRead {
  friend class ValueSetSolver;
  int4 typeCode;	///< 0=pure constant 1=stack relative
  int4 slot;		///< The slot being read
  PcodeOp *op;		///< The PcodeOp at the point of the value set read
  CircleRange range;	///< Range of values or offsets in this set
  CircleRange equationConstraint;	///< Constraint associated with the equation
  int4 equationTypeCode;	///< Type code of the associated equation
  bool leftIsStable;	///< Set to \b true if left boundary of range didn't change (last iteration)
  bool rightIsStable;	///< Set to \b true if right boundary of range didn't change (last iteration)
  void setPcodeOp(PcodeOp *o,int4 slt);	///< Establish \e read this value set corresponds to
  void addEquation(int4 slt,int4 type,const CircleRange &constraint);	///< Insert an equation restricting \b this value set
public:
  int4 getTypeCode(void) const { return typeCode; }	///< Return '0' for normal constant, '1' for spacebase relative
  const CircleRange &getRange(void) const { return range; }	///< Get the actual range of values
  bool isLeftStable(void) const { return leftIsStable; }	///< Return \b true if the left boundary hasn't been changing
  bool isRightStable(void) const { return rightIsStable; }	///< Return \b true if the right boundary hasn't been changing
  void compute(void);			///< Compute \b this value set
  void printRaw(ostream &s) const;	///< Write a text description of \b to the given stream
};

/// \brief Class holding a particular widening strategy for the ValueSetSolver iteration algorithm
///
/// This obects gets to decide when a value set gets \e frozen (checkFreeze()), meaning the set
/// doesn't change for the remaining iteration steps. It also gets to decide when and by how much
/// value sets get artificially increased in size to accelerate reaching their stable state (doWidening()).
class Widener {
public:
  virtual ~Widener(void) {}	///< Destructor

  /// \brief Upon entering a fresh partition, determine how the given ValueSet count should be reset
  ///
  /// \param valueSet is the given value set
  /// \return the value of the iteration counter to reset to
  virtual int4 determineIterationReset(const ValueSet &valueSet)=0;

  /// \brief Check if the given value set has been frozen for the remainder of the iteration process
  ///
  /// \param valueSet is the given value set
  /// \return \b true if the valueSet will no longer change
  virtual bool checkFreeze(const ValueSet &valueSet)=0;

  /// \brief For an iteration that isn't stabilizing attempt to widen the given ValueSet
  ///
  /// Change the given range based on its previous iteration so that it stabilizes more
  /// rapidly on future iterations.
  /// \param valueSet is the given value set
  /// \param range is the previous form of the given range (and storage for the widening result)
  /// \param newRange is the current iteration of the given range
  /// \return \b true if widening succeeded
  virtual bool doWidening(const ValueSet &valueSet,CircleRange &range,const CircleRange &newRange)=0;
};

/// \brief Class for doing normal widening
///
/// Widening is attempted at a specific iteration. If a landmark is available, it is used
/// to do a controlled widening, holding the stable range boundary constant. Otherwise a
/// full range is produced.  At a later iteration, a full range is produced automatically.
class WidenerFull : public Widener {
  int4 widenIteration;		///< The iteration at which widening is attempted
  int4 fullIteration;		///< The iteration at which a full range is produced
public:
  WidenerFull(void) { widenIteration = 2; fullIteration = 5; }	///< Constructor with default iterations
  WidenerFull(int4 wide,int4 full) { widenIteration = wide; fullIteration = full; }	///< Constructor specifying iterations
  virtual int4 determineIterationReset(const ValueSet &valueSet);
  virtual bool checkFreeze(const ValueSet &valueSet);
  virtual bool doWidening(const ValueSet &valueSet,CircleRange &range,const CircleRange &newRange);
};

/// \brief Class for freezing value sets at a specific iteration (to accelerate convergence)
///
/// The value sets don't reach a true stable state but instead lock in a description of the
/// first few values that \e reach a given Varnode. The ValueSetSolver does normal iteration,
/// but individual ValueSets \e freeze after a specific number of iterations (3 by default),
/// instead of growing to a true stable state. This gives evidence of iteration in the underlying
/// code, showing the initial value and frequently the step size.
class WidenerNone : public Widener {
  int4 freezeIteration;		///< The iteration at which all change ceases
public:
  WidenerNone(void) { freezeIteration = 3; }
  virtual int4 determineIterationReset(const ValueSet &valueSet);
  virtual bool checkFreeze(const ValueSet &valueSet);
  virtual bool doWidening(const ValueSet &valueSet,CircleRange &range,const CircleRange &newRange);
};

/// \brief Class that determines a ValueSet for each Varnode in a data-flow system
///
/// This class uses \e value \e set \e analysis to calculate (an overestimation of)
/// the range of values that can reach each Varnode.  The system is formed by providing
/// a set of Varnodes for which the range is desired (the sinks) via establishValueSets().
/// This creates a system of Varnodes (within the single function) that can flow to the sinks.
/// Running the method solve() does the analysis, and the caller can examine the results
/// by examining the ValueSet attached to any of the Varnodes in the system (via Varnode::getValueSet()).
/// The ValueSetSolver::solve() starts with minimal value sets and does iteration steps by pushing
/// them through the PcodeOps until stability is reached. A Widener object is passed to solve()
/// which selects the specific strategy for accelerating convergence.
class ValueSetSolver {
  /// \brief An iterator over out-bound edges for a single ValueSet node in a data-flow system
  ///
  /// This is a helper class for walking a collection of ValueSets as a graph.
  /// Mostly the graph mirrors the data-flow of the Varnodes underlying the ValueSets, but
  /// there is support for a simulated root node. This class acts as an iterator over the outgoing
  /// edges of a particular ValueSet in the graph.
  class ValueSetEdge {
    const vector<ValueSet *> *rootEdges;		///< The list of nodes attached to the simulated root node (or NULL)
    int4 rootPos;					///< The iterator position for the simulated root node
    Varnode *vn;					///< The Varnode attached to a normal ValueSet node (or NULL)
    list<PcodeOp *>::const_iterator iter;		///< The iterator position for a normal ValueSet node
  public:
    ValueSetEdge(ValueSet *node,const vector<ValueSet *> &roots);
    ValueSet *getNext(void);
  };

  list<ValueSet> valueNodes;		///< Storage for all the current value sets
  map<SeqNum,ValueSetRead> readNodes;	///< Additional, after iteration, add-on value sets
  Partition orderPartition;		///< Value sets in iteration order
  list<Partition> recordStorage;	///< Storage for the Partitions establishing components
  vector<ValueSet *> rootNodes;		///< Values treated as inputs
  vector<ValueSet *> nodeStack;		///< Stack used to generate the topological ordering
  int4 depthFirstIndex;			///< (Global) depth first numbering for topological ordering
  int4 numIterations;			///< Count of individual ValueSet iterations
  int4 maxIterations;			///< Maximum number of iterations before forcing termination
  void newValueSet(Varnode *vn,int4 tCode);		///< Allocate storage for a new ValueSet
  static void partitionPrepend(ValueSet *vertex,Partition &part);	///< Prepend a vertex to a partition
  static void partitionPrepend(const Partition &head,Partition &part);	///< Prepend full Partition to given Partition
  void partitionSurround(Partition &part);				///< Create a full partition component
  void component(ValueSet *vertex,Partition &part);		///< Generate a partition component given its head
  int4 visit(ValueSet *vertex,Partition &part);			///< Recursively walk the data-flow graph finding partitions
  void establishTopologicalOrder(void);				///< Find the optimal order for iterating through the ValueSets
  void generateTrueEquation(Varnode *vn,PcodeOp *op,int4 slot,int4 type,const CircleRange &range);
  void generateFalseEquation(Varnode *vn,PcodeOp *op,int4 slot,int4 type,const CircleRange &range);
  void applyConstraints(Varnode *vn,int4 type,const CircleRange &range,PcodeOp *cbranch);
  void constraintsFromPath(int4 type,CircleRange &lift,Varnode *startVn,Varnode *endVn,PcodeOp *cbranch);
  void constraintsFromCBranch(PcodeOp *cbranch);		///< Generate constraints arising from the given branch
  void generateConstraints(const vector<Varnode *> &worklist,const vector<PcodeOp *> &reads);	///< Generate constraints given a system of Varnodes
  bool checkRelativeConstant(Varnode *vn,int4 &typeCode,uintb &value) const;	///< Check if the given Varnode is a \e relative constant
  void generateRelativeConstraint(PcodeOp *compOp,PcodeOp *cbranch);	///< Try to find a \e relative constraint
public:
  void establishValueSets(const vector<Varnode *> &sinks,const vector<PcodeOp *> &reads,Varnode *stackReg,bool indirectAsCopy);
  int4 getNumIterations(void) const { return numIterations; }	///< Get the current number of iterations
  void solve(int4 max,Widener &widener);			///< Iterate the ValueSet system until it stabilizes
  list<ValueSet>::const_iterator beginValueSets(void) const { return valueNodes.begin(); }	///< Start of all ValueSets in the system
  list<ValueSet>::const_iterator endValueSets(void) const { return valueNodes.end(); }	///< End of all ValueSets in the system
  map<SeqNum,ValueSetRead>::const_iterator beginValueSetReads(void) const { return readNodes.begin(); }	///< Start of ValueSetReads
  map<SeqNum,ValueSetRead>::const_iterator endValueSetReads(void) const { return readNodes.end(); }	///< End of ValueSetReads
  const ValueSetRead &getValueSetRead(const SeqNum &seq) { return (*readNodes.find(seq)).second; }	///< Get ValueSetRead by SeqNum
#ifdef CPUI_DEBUG
  void dumpValueSets(ostream &s) const;
#endif
};

/// \param op2 is the range to compare \b this to
/// \return \b true if the two ranges are equal
inline bool CircleRange::operator==(const CircleRange &op2) const

{
  if (isempty != op2.isempty) return false;
  if (isempty) return true;
  return (left == op2.left) && (right == op2.right) && (mask == op2.mask) && (step == op2.step);
}

/// If two ranges are labeled [l , r) and  [op2.l, op2.r), the
/// overlap of the ranges can be characterized by listing the four boundary
/// values  in order, as the circle is traversed in a clock-wise direction.  This characterization can be
/// further normalized by starting the list at op2.l, unless op2.l is contained in the range [l, r).
/// In which case, the list should start with l.  You get the following 6 categories
///    - a  = (l r op2.l op2.r)
///    - b  = (l op2.l r op2.r)
///    - c  = (l op2.l op2.r r)
///    - d  = (op2.l l r op2.r)
///    - e  = (op2.l l op2.r r)
///    - f  = (op2.l op2.r l r)
///    - g  = (l op2.r op2.l r)
///
/// Given 2 ranges, this method calculates the category code for the overlap.
/// \param op1left is left boundary of the first range
/// \param op1right is the right boundary of the first range
/// \param op2left is the left boundary of the second range
/// \param op2right is the right boundary of the second range
/// \return the character code of the normalized overlap category
inline char CircleRange::encodeRangeOverlaps(uintb op1left, uintb op1right, uintb op2left, uintb op2right)

{
  int4 val = (op1left <= op1right) ? 0x20 : 0;
  val |= (op1left <= op2left) ? 0x10 : 0;
  val |= (op1left <= op2right) ? 0x8 : 0;
  val |= (op1right <= op2left) ? 4 : 0;
  val |= (op1right <= op2right) ? 2 : 0;
  val |= (op2left <= op2right) ? 1 : 0;
  return arrange[val];
}

/// Perform basic checks that the selected Equation exists and applies
/// to the indicated input slot.
/// \param num is the index selecting an Equation
/// \param slot is the indicated slot
/// \return \b true if the Equation exists and applies
inline bool ValueSet::doesEquationApply(int4 num,int4 slot) const

{
  if (num < equations.size()) {
    if (equations[num].slot == slot) {
      if (equations[num].typeCode == typeCode)
	return true;
    }
  }
  return false;
}

/// \param vertex is the node that will be prepended
/// \param part is the Partition being modified
inline void ValueSetSolver::partitionPrepend(ValueSet *vertex,Partition &part)

{
  vertex->next = part.startNode;	// Attach new vertex to beginning of list
  part.startNode = vertex;		// Change the first value set to be the new vertex
  if (part.stopNode == (ValueSet *)0)
    part.stopNode = vertex;
}

/// \param head is the partition to be prepended
/// \param part is the given partition being modified (prepended to)
inline void ValueSetSolver::partitionPrepend(const Partition &head,Partition &part)

{
  head.stopNode->next = part.startNode;
  part.startNode = head.startNode;
  if (part.stopNode == (ValueSet *)0)
    part.stopNode = head.stopNode;
}

#endif

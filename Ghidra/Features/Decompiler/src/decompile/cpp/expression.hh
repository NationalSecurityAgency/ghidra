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
/// \file expression.hh
/// \brief Classes to collect, analyze, and match expressions within p-code data-flow
#ifndef __EXPRESSION_HH__
#define __EXPRESSION_HH__

#include "op.hh"

namespace ghidra {

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

/// \brief Node for a forward traversal of a Varnode expression
struct TraverseNode {
  enum {
    actionalt = 1,	///< Alternate path traverses a solid action or \e non-incidental COPY
    indirect = 2,	///< Main path traverses an INDIRECT
    indirectalt = 4,	///< Alternate path traverses an INDIRECT
    lsb_truncated = 8,	///< Least significant byte(s) of original value have been truncated
    concat_high = 0x10	///< Original value has been concatented as \e most significant portion
  };
  const Varnode *vn;		///< Varnode at the point of traversal
  uint4 flags;			///< Flags associated with the node
  TraverseNode(const Varnode *v,uint4 f) { vn = v; flags = f; }		///< Constructor
  static bool isAlternatePathValid(const Varnode *vn,uint4 flags);
};

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

/// \brief A helper class for describing the similarity of the boolean condition between 2 CBRANCH operations
///
/// This class determines if two CBRANCHs share the same condition.  It also determines if the conditions
/// are complements of each other, and/or they are shared along only one path.
class BooleanExpressionMatch {
  static const int4 maxDepth;	///< Maximum depth to trace a boolean expression
  bool matchflip;		///< True if the compared CBRANCH keys on the opposite boolean value of the root
public:
  bool verifyCondition(PcodeOp *op, PcodeOp *iop);	///< Perform the correlation test on two CBRANCH operations
  int4 getMultiSlot(void) const { return -1; }	///< Get the MULTIEQUAL slot in the critical path
  bool getFlip(void) const { return matchflip; }	///< Return \b true if the expressions are anti-correlated
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

/// \brief Class for lightweight matching of two additive expressions
///
/// Collect (up to 2) terms along with any constants and coefficients.
//// Determine if two expressions are equivalent.
class AddExpression {
  /// \brief A term in the expression
  class Term {
    Varnode *vn;	///< The Varnode representing the term
    uintb coeff;	///< Multiplicative coefficient
  public:
    Term(void) {}	///< Uninitialized constructor
    Term(Varnode *v,uintb c) { vn = v; coeff = c; }	///< Constructor
    bool isEquivalent(const Term &op2) const;		///< Compare two terms for functional equivalence
  };
  uintb constval;		///< Collected constants in the expression
  int4 numTerms;		///< Number of terms
  Term terms[2];		///< Terms making up the expression
  void add(Varnode *vn,uintb coeff) { if (numTerms < 2) terms[numTerms++] = Term(vn,coeff); }	///< Add a term to the expression
  void gather(Varnode *vn,uintb coeff,int4 depth);	///< Gather terms in the expression from a root point
public:
  AddExpression(void) { constval = 0; numTerms = 0; }	///< Construct an empty expression
  void gatherTwoTermsSubtract(Varnode *a,Varnode *b);	///< Walk expression given two roots being subtracted from one another
  void gatherTwoTermsAdd(Varnode *a,Varnode *b);	///< Walk expression given two roots being added to each other
  void gatherTwoTermsRoot(Varnode *root);		///< Gather up to 2 terms given root Varnode
  bool isEquivalent(const AddExpression &op2) const;	///< Determine if 2 expressions are equivalent
};

/// \brief A comparison operator for ordering terms in a sum
///
/// This is based on Varnode::termOrder which groups constants terms and
/// ignores multiplicative coefficients.
/// \param op1 is the first term to compare
/// \param op2 is the second term
/// \return \b true if the first term is less than the second
inline bool TermOrder::additiveCompare(const AdditiveEdge *op1,const AdditiveEdge *op2) {
  return (-1 == op1->getVarnode()->termOrder(op2->getVarnode()));
}

extern int4 functionalEqualityLevel(Varnode *vn1,Varnode *vn2,Varnode **res1,Varnode **res2);
extern bool functionalEquality(Varnode *vn1,Varnode *vn2);
extern bool functionalDifference(Varnode *vn1,Varnode *vn2,int4 depth);

}  // End namespace ghidra
#endif

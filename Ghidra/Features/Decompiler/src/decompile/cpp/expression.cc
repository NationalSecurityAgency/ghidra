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
#include "expression.hh"

namespace ghidra {

/// \brief Return \b true if the alternate path looks more valid than the main path.
///
/// Two different paths from a common Varnode each terminate at a CALL, CALLIND, or RETURN.
/// Evaluate which path most likely represents actual parameter/return value passing,
/// based on traversal information about each path.
/// \param vn is the Varnode terminating the \e alternate path
/// \param flags indicates traversals for both paths
/// \return \b true if the alternate path is preferred
bool TraverseNode::isAlternatePathValid(const Varnode *vn,uint4 flags)

{
  if ((flags & (indirect | indirectalt)) == indirect)
    // If main path traversed an INDIRECT but the alternate did not
    return true;	// Main path traversed INDIRECT, alternate did not
  if ((flags & (indirect | indirectalt)) == indirectalt)
    return false;	// Alternate path traversed INDIRECT, main did not
  if ((flags & actionalt) != 0)
    return true;	// Alternate path traversed a dedicated COPY
  if (vn->loneDescend() == (PcodeOp*)0) return false;
  const PcodeOp *op = vn->getDef();
  if (op == (PcodeOp*)0) return true;
  while(op->isIncidentalCopy() && op->code() == CPUI_COPY) {	// Skip any incidental COPY
    vn = op->getIn(0);
    if (vn->loneDescend() == (PcodeOp *)0) return false;
    op = vn->getDef();
    if (op == (PcodeOp *)0) return true;
  }
  return !op->isMarker();	// MULTIEQUAL or INDIRECT indicates multiple values
}

/// \brief Test if two operations with same opcode produce complementary boolean values
///
/// This only tests for cases where the opcode is INT_LESS or INT_SLESS and one of the
/// inputs is constant.
/// \param bin1op is the first p-code op to compare
/// \param bin2op is the second p-code op to compare
/// \return \b true if the two operations always produce complementary values
bool BooleanMatch::sameOpComplement(PcodeOp *bin1op,PcodeOp *bin2op)

{
  OpCode opcode = bin1op->code();
  if ((opcode == CPUI_INT_SLESS)||(opcode==CPUI_INT_LESS)) {
    // Basically we test for the scenario like:  x < 9   8 < x
    int4 constslot = 0;
    if (bin1op->getIn(1)->isConstant())
      constslot = 1;
    if (!bin1op->getIn(constslot)->isConstant()) return false;
    if (!bin2op->getIn(1-constslot)->isConstant()) return false;
    if (!varnodeSame(bin1op->getIn(1-constslot),bin2op->getIn(constslot))) return false;
    uintb val1 = bin1op->getIn(constslot)->getOffset();
    uintb val2 = bin2op->getIn(1-constslot)->getOffset();
    if (constslot!=0) {
      uintb tmp = val2;
      val2 = val1;
      val1 = tmp;
    }
    if (val1 + 1 != val2) return false;
    if ((val2 == 0)&&(opcode==CPUI_INT_LESS)) return false; // Corner case for unsigned
    if (opcode==CPUI_INT_SLESS) { // Corner case for signed
      int4 sz = bin1op->getIn(constslot)->getSize();
      if (signbit_negative(val2,sz) && (!signbit_negative(val1,sz)))
	return false;
    }
    return true;
  }
  return false;
}

/// \brief Do the given Varnodes hold the same value, possibly as constants
///
/// \param a is the first Varnode to compare
/// \param b is the second Varnode
/// \return \b true if the Varnodes (always) hold the same value
bool BooleanMatch::varnodeSame(Varnode *a,Varnode *b)

{
  if (a == b) return true;
  if (a->isConstant() && b->isConstant())
    return (a->getOffset() == b->getOffset());
  return false;
}

/// \brief Determine if two boolean Varnodes hold related values
///
/// The values may be the \e same, or opposite of each other (\e complementary).
/// Otherwise the values are \e uncorrelated.  The trees constructing each Varnode
/// are examined up to a maximum \b depth.  If this is exceeded \e uncorrelated is returned.
/// \param vn1 is the first boolean Varnode
/// \param vn2 is the second boolean Varnode
/// \param depth is the maximum depth to traverse in the evaluation
/// \return the correlation class
int4 BooleanMatch::evaluate(Varnode *vn1,Varnode *vn2,int4 depth)

{
  if (vn1 == vn2) return same;
  PcodeOp *op1,*op2;
  OpCode opc1,opc2;
  if (vn1->isWritten()) {
    op1 = vn1->getDef();
    opc1 = op1->code();
    if (opc1 == CPUI_BOOL_NEGATE) {
      int res = evaluate(op1->getIn(0),vn2,depth);
      if (res == same)		// Flip same <-> complementary result
	res = complementary;
      else if (res == complementary)
	res = same;
      return res;
    }
  }
  else {
    op1 = (PcodeOp *)0;			// Don't give up before checking if op2 is BOOL_NEGATE
    opc1 = CPUI_MAX;
  }
  if (vn2->isWritten()) {
    op2 = vn2->getDef();
    opc2 = op2->code();
    if (opc2 == CPUI_BOOL_NEGATE) {
      int4 res = evaluate(vn1,op2->getIn(0),depth);
      if (res == same)		// Flip same <-> complementary result
	res = complementary;
      else if (res == complementary)
	res = same;
      return res;
    }
  }
  else
    return uncorrelated;
  if (op1 == (PcodeOp *)0)
    return uncorrelated;
  if (!op1->isBoolOutput() || !op2->isBoolOutput())
    return uncorrelated;
  if (depth != 0 && (opc1 == CPUI_BOOL_AND || opc1 == CPUI_BOOL_OR || opc1 == CPUI_BOOL_XOR)) {
    if (opc2 == CPUI_BOOL_AND || opc2 == CPUI_BOOL_OR || opc2 == CPUI_BOOL_XOR) {
      if (opc1 == opc2 || (opc1 == CPUI_BOOL_AND && opc2 == CPUI_BOOL_OR) || (opc1 == CPUI_BOOL_OR && opc2 == CPUI_BOOL_AND)) {
	int4 pair1 = evaluate(op1->getIn(0),op2->getIn(0),depth-1);
	int4 pair2;
	if (pair1 == uncorrelated) {
	  pair1 = evaluate(op1->getIn(0),op2->getIn(1),depth-1);	// Try other possible pairing (commutative op)
	  if (pair1 == uncorrelated)
	    return uncorrelated;
	  pair2 = evaluate(op1->getIn(1),op2->getIn(0),depth-1);
	}
	else {
	  pair2 = evaluate(op1->getIn(1),op2->getIn(1),depth-1);
	}
	if (pair2 == uncorrelated)
	  return uncorrelated;
	if (opc1 == opc2) {
	  if (pair1 == same && pair2 == same)
	    return same;
	  else if (opc1 == CPUI_BOOL_XOR) {
	    if (pair1 == complementary && pair2 == complementary)
	      return same;
	    return complementary;
	  }
	}
	else {		// Must be CPUI_BOOL_AND and CPUI_BOOL_OR
	  if (pair1 == complementary && pair2 == complementary)
	    return complementary;		// De Morgan's Law
	}
      }
    }
  }
  else {
    // Two boolean output ops, compare them directly
    if (opc1 == opc2) {
      bool sameOp = true;
      int numInputs = op1->numInput();
      for (int i = 0; i < numInputs; ++i){
          if (!varnodeSame(op1->getIn(i),op2->getIn(i))){
              sameOp = false;
              break;
          }
      }
      if (sameOp){
        return same;
      }
      if (sameOpComplement(op1,op2)) {
	return complementary;
      }
      return uncorrelated;
    }
    // Check if the binary ops are complements of one another
    int4 slot1 = 0;
    int4 slot2 = 0;
    bool reorder;
    if (opc1 != get_booleanflip(opc2,reorder))
      return uncorrelated;
    if (reorder) slot2 = 1;
    if (!varnodeSame(op1->getIn(slot1),op2->getIn(slot2)))
      return uncorrelated;
    if (!varnodeSame(op1->getIn(1-slot1),op2->getIn(1-slot2)))
      return uncorrelated;
    return complementary;
  }
  return uncorrelated;
}

const int4 BooleanExpressionMatch::maxDepth = 1;

bool BooleanExpressionMatch::verifyCondition(PcodeOp *op, PcodeOp *iop)

{
  int4 res = BooleanMatch::evaluate(op->getIn(1), iop->getIn(1), maxDepth);
  if (res == BooleanMatch::uncorrelated)
    return false;
  matchflip = (res == BooleanMatch::complementary);
  if (op->isBooleanFlip())
    matchflip = !matchflip;
  if (iop->isBooleanFlip())
    matchflip = !matchflip;
  return true;
}

/// Assuming root->getOut() is the root of an expression formed with the
/// CPUI_INT_ADD op, collect all the Varnode \e terms of the expression.
void TermOrder::collect(void)

{
  Varnode *curvn;
  PcodeOp *curop;
  PcodeOp *subop,*multop;

  vector<PcodeOp *> opstack;	// Depth first traversal path
  vector<PcodeOp *> multstack;

  opstack.push_back(root);
  multstack.push_back((PcodeOp *)0);

  while(!opstack.empty()) {
    curop = opstack.back();
    multop = multstack.back();
    opstack.pop_back();
    multstack.pop_back();
    for(int4 i=0;i<curop->numInput();++i) {
      curvn = curop->getIn(i);	// curvn is a node of the subtree IF
      if (!curvn->isWritten()) { // curvn is not defined by another operation
	terms.emplace_back(curop,i,multop);
	continue;
      }
      if (curvn->loneDescend() == (PcodeOp *)0) { // curvn has more then one use
	terms.emplace_back(curop,i,multop);
	continue;
      }
      subop = curvn->getDef();
      if (subop->code() != CPUI_INT_ADD) { // or if curvn is defined with some other type of op
	if ((subop->code()==CPUI_INT_MULT)&&(subop->getIn(1)->isConstant())) {
	  PcodeOp *addop = subop->getIn(0)->getDef();
	  if ((addop!=(PcodeOp *)0)&&(addop->code()==CPUI_INT_ADD)) {
	    if (addop->getOut()->loneDescend()!=(PcodeOp *)0) {
	      opstack.push_back(addop);
	      multstack.push_back(subop);
	      continue;
	    }
	  }
	}
	terms.emplace_back(curop,i,multop);
	continue;
      }
      opstack.push_back(subop);
      multstack.push_back(multop);
    }
  }
}

void TermOrder::sortTerms(void)

{
  sorter.reserve(terms.size());
  for(vector<AdditiveEdge>::iterator iter=terms.begin();iter!=terms.end();++iter)
    sorter.push_back( &(*iter) );

  sort(sorter.begin(),sorter.end(),additiveCompare);
}

/// The value \b true is returned if it can be proven that two terms add the same value to their
/// respective expressions.
/// \param op2 is the other term to compare with \b this
/// \return \b true if the terms are equivalent
bool AddExpression::Term::isEquivalent(const Term &op2) const

{
  if (coeff != op2.coeff) return false;
  return functionalEquality(vn,op2.vn);
}

/// The value \b true is returned if it can be proven that the expressions always produce the same value.
/// \param op2 is the other expression to compare with \b this
/// \return \b true if the expressions are equivalent
bool AddExpression::isEquivalent(const AddExpression &op2) const

{
  if (constval != op2.constval)
    return false;
  if (numTerms != op2.numTerms) return false;
  if (numTerms == 1) {
    if (terms[0].isEquivalent(op2.terms[0]))
      return true;
  }
  else if (numTerms == 2) {
    if (terms[0].isEquivalent(op2.terms[0]) && terms[1].isEquivalent(op2.terms[1]))
      return true;
    if (terms[0].isEquivalent(op2.terms[1]) && terms[1].isEquivalent(op2.terms[0]))
      return true;
  }
  return false;
}

/// Recursively collect terms, up to the given depth.  INT_ADD either contributes to the constant sum, or
/// it is recursively walked.  Term coefficients are collected from INT_MULT with a constant.
/// \param vn is the root of the (sub)expression
/// \param coeff is the current multiplicative coefficient of the subexpression
/// \param depth is the current depth
void AddExpression::gather(Varnode *vn,uintb coeff,int4 depth)

{
  if (vn->isConstant()) {
    constval = constval + coeff * vn->getOffset();
    constval &= calc_mask(vn->getSize());
    return;
  }
  if (vn->isWritten()) {
    PcodeOp *op = vn->getDef();
    if (op->code() == CPUI_INT_ADD) {
      if (!op->getIn(1)->isConstant())
	depth -= 1;
      if (depth >= 0) {
	gather(op->getIn(0),coeff,depth);
	gather(op->getIn(1),coeff,depth);
	return;
      }
    }
    else if (op->code() == CPUI_INT_MULT) {
      if (op->getIn(1)->isConstant()) {
	coeff = coeff * op->getIn(1)->getOffset();
	coeff &= calc_mask(vn->getSize());
	gather(op->getIn(0),coeff,depth);
	return;
      }
    }
  }
  add(vn,coeff);
  return;
}

/// Gather up to two non-constant additive terms, given two root Varnodes that are being subtracted.
/// \param a is the first root
/// \param b is the second root being subtracted from the first
void AddExpression::gatherTwoTermsSubtract(Varnode *a,Varnode *b)

{
  int4 depth = (a->isConstant() || b->isConstant()) ? 1 : 0;
  gather(a,(uintb)1,depth);
  gather(b,calc_mask(b->getSize()),depth);
}

/// Gather up to two non-constant additive terms, given two root Varnodes being added
/// \param a is the first root
/// \param b is the second root being added to the first
void AddExpression::gatherTwoTermsAdd(Varnode *a,Varnode *b)

{
  int4 depth = (a->isConstant() || b->isConstant()) ? 1 : 0;
  gather(a,(uintb)1,depth);
  gather(b,(uintb)1,depth);
}

/// Gather up to two non-constant additive terms in the expression at the given root.
/// \param root is the root Varnode
void AddExpression::gatherTwoTermsRoot(Varnode *root)

{
  gather(root,(uintb)1,1);
}

/// \brief Perform basic comparison of two given Varnodes
///
/// Return
///   - 0 if \b vn1 and \b vn2 must hold same value
///   - -1 if they definitely don't hold same value
///   - 1 if the same value depends on ops writing to \b vn1 and \b vn2
/// \param vn1 is the first Varnode to compare
/// \param vn2 is the second
/// \return a code -1, 0, or 1
static int4 functionalEqualityLevel0(Varnode *vn1,Varnode *vn2)

{
  if (vn1==vn2) return 0;
  if (vn1->getSize() != vn2->getSize()) return -1;
  if (vn1->isConstant()) {
    if (vn2->isConstant()) {
      return (vn1->getOffset() == vn2->getOffset()) ? 0 : -1;
    }
    return -1;
  }
  if (vn1->isFree() || vn2->isFree()) return -1;
  return 1;
}

/// \brief Try to determine if \b vn1 and \b vn2 contain the same value
///
/// Return:
///    -  -1, if they do \b not, or if it can't be immediately verified
///    -   0, if they \b do hold the same value
///    -  >0, if the result is contingent on additional varnode pairs having the same value
/// In the last case, the varnode pairs are returned as (res1[i],res2[i]),
/// where the return value is the number of pairs.
/// \param vn1 is the first Varnode to compare
/// \param vn2 is the second Varnode
/// \param res1 is a reference to the first returned Varnode
/// \param res2 is a reference to the second returned Varnode
/// \return the result of the comparison
int4 functionalEqualityLevel(Varnode *vn1,Varnode *vn2,Varnode **res1,Varnode **res2)

{
  int4 testval = functionalEqualityLevel0(vn1,vn2);
  if (testval != 1)
    return testval;
  if (!vn1->isWritten() || !vn2->isWritten()) {
    return -1;		// Did not find at least one level of match
  }
  PcodeOp *op1 = vn1->getDef();
  PcodeOp *op2 = vn2->getDef();
  OpCode opc = op1->code();

  if (opc != op2->code()) return -1;

  int4 num = op1->numInput();
  if (num != op2->numInput()) return -1;
  if (op1->isMarker()) return -1;
  if (op2->isCall()) return -1;
  if (opc == CPUI_LOAD) {
				// FIXME: We assume two loads produce the same
				// result if the address is the same and the loads
				// occur in the same instruction
    if (op1->getAddr() != op2->getAddr()) return -1;
  }
  if (num >= 3) {
    if (opc != CPUI_PTRADD) return -1; // If this is a PTRADD
    if (op1->getIn(2)->getOffset() != op2->getIn(2)->getOffset()) return -1; // Make sure the elsize constant is equal
    num = 2;			// Otherwise treat as having 2 inputs
  }
  for(int4 i=0;i<num;++i) {
    res1[i] = op1->getIn(i);
    res2[i] = op2->getIn(i);
  }

  testval = functionalEqualityLevel0(res1[0],res2[0]);
  if (testval == 0) {	      	// A match locks in this comparison ordering
    if (num==1) return 0;
    testval = functionalEqualityLevel0(res1[1],res2[1]);
    if (testval==0) return 0;
    if (testval < 0) return -1;
    res1[0] = res1[1];		// Match is contingent on second pair
    res2[0] = res2[1];
    return 1;
  }
  if (num == 1) return testval;
  int4 testval2 = functionalEqualityLevel0(res1[1],res2[1]);
  if (testval2 == 0) {		// A match locks in this comparison ordering
    return testval;
  }
  int4 unmatchsize;
  if ((testval==1)&&(testval2==1))
    unmatchsize = 2;
  else
    unmatchsize = -1;

  if (!op1->isCommutative()) return unmatchsize;
  // unmatchsize must be 2 or -1 here on a commutative operator,
  // try flipping
  int4 comm1 = functionalEqualityLevel0(res1[0],res2[1]);
  int4 comm2 = functionalEqualityLevel0(res1[1],res2[0]);
  if ((comm1==0) && (comm2==0))
    return 0;
  if ((comm1<0)||(comm2<0))
    return unmatchsize;
  if (comm1==0)	{		// AND (comm2==1)
    res1[0] = res1[1];		// Left over unmatch is res1[1] and res2[0]
    return 1;
  }
  if (comm2==0) {		// AND (comm1==1)
    res2[0] = res2[1];		// Left over unmatch is res1[0] and res2[1]
    return 1;
  }
  // If we reach here (comm1==1) AND (comm2==1)
  if (unmatchsize == 2)		// If the original ordering wasn't impossible
    return 2;			// Prefer the original ordering
  Varnode *tmpvn = res2[0];	// Otherwise swap the ordering
  res2[0] = res2[1];
  res2[1] = tmpvn;
  return 2;
}

/// \brief Determine if two Varnodes hold the same value
///
/// Only return \b true if it can be immediately determined they are equivalent
/// \param vn1 is the first Varnode
/// \param vn2 is the second Varnode
/// \return true if they are provably equal
bool functionalEquality(Varnode *vn1,Varnode *vn2)

{
  Varnode *buf1[2];
  Varnode *buf2[2];
  return (functionalEqualityLevel(vn1,vn2,buf1,buf2)==0);
}

/// \brief Return true if vn1 and vn2 are verifiably different values
///
/// This is actually a rather speculative test
/// \param vn1 is the first Varnode to compare
/// \param vn2 is the second Varnode
/// \param depth is the maximum level to recurse while testing
/// \return \b true if they are different
bool functionalDifference(Varnode *vn1,Varnode *vn2,int4 depth)

{
  PcodeOp *op1,*op2;
  int4 i,num;

  if (vn1 == vn2) return false;
  if ((!vn1->isWritten())||(!vn2->isWritten())) {
    if (vn1->isConstant() && vn2->isConstant())
      return !(vn1->getAddr()==vn2->getAddr());
    if (vn1->isInput()&&vn2->isInput()) return false; // Might be the same
    if (vn1->isFree()||vn2->isFree()) return false; // Might be the same
    return true;
  }
  op1 = vn1->getDef();
  op2 = vn2->getDef();
  if (op1->code() != op2->code()) return true;
  num = op1->numInput();
  if (num != op2->numInput()) return true;
  if (depth==0) return true;	// Different as far as we can tell
  depth -= 1;
  for(i=0;i<num;++i)
    if (functionalDifference(op1->getIn(i),op2->getIn(i),depth))
      return true;
  return false;
}

} // End namespace ghidra

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
/// \file condexe.hh
/// \brief Classes for simplifying control-flow with shared conditional expressions
#ifndef __CONDEXE_HH__
#define __CONDEXE_HH__

#include "funcdata.hh"

namespace ghidra {

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

/// \brief A class for simplifying a series of conditionally executed statements.
///
/// This class tries to perform transformations like the following:
/// \code
///    if (a) {           if (a) {
///       BODY1
///    }          ==>       BODY1
///    if (a) {             BODY2
///       BODY2
///    }                  }
/// \endcode
/// Other similar configurations where two CBRANCHs are based on
/// the same condition are handled.  The main variation, referred to as a
/// \b directsplit in the code looks like:
/// \code
///  if (a) {                      if (a && new_boolean()) {
///     a = new_boolean();
///  }                      ==>      BODY1
///  if (a) {
///     BODY1
///  }                             }
/// \endcode
/// The value of 'a' doesn't need to be reevaluated if it is false.
///
/// In the first scenario, there is a block where two flows come
/// together but don't need to, as the evaluation of the boolean
/// is redundant.  This block is the \b iblock.  The original
/// evaluation of the boolean occurs in \b initblock.  There are
/// two paths from here to \b iblock, called the \b prea path and \b preb path,
/// either of which may contain additional 1in/1out blocks.
/// There are also two paths out of \b iblock, \b posta, and \b postb.
/// The ConditionalExecution class determines if the CBRANCH in
/// \b iblock is redundant by determining if the boolean value is
/// either the same as, or the complement of, the boolean value
/// in \b initblock.  If the CBRANCH is redundant, \b iblock is
/// removed, linking \b prea to \b posta and \b preb to \b postb (or vice versa
/// depending on whether the booleans are complements of each other).
/// If \b iblock is to be removed, modifications to data-flow made
/// by \b iblock must be preserved.  For MULTIEQUALs in \b iblock,
/// reads are examined to see if they came from the \b posta path,
/// or the \b postb path, then the are replaced by the MULTIEQUAL
/// slot corresponding to the matching \b prea or \b preb branch. If
/// \b posta and \b postb merge at an \b exitblock, the MULTIEQUAL must
/// be pushed into the \b exitblock and reads which can't be
/// attributed to the \b posta or \b postb path are replaced by the
/// \b exitblock MULTIEQUAL.
///
/// In theory, other operations performed in \b iblock could be
/// pushed into \b exitblock if they are not read in the \b posta
/// or \b postb paths, but currently
/// non MULTIEQUAL operations in \b iblock terminate the action.
///
/// In the second scenario, the boolean evaluated in \b initblock
/// remains unmodified along only one of the two paths out, \b prea
/// or \b reb.  The boolean in \b iblock (modulo complementing) will
/// evaluate in the same way. We define \b posta as the path out of
/// \b iblock that will be followed by this unmodified path. The
/// transform that needs to be made is to have the unmodified path
/// out of \b initblock flow immediately into the \b posta path without
/// having to reevalute the condition in \b iblock.  \b iblock is not
/// removed because flow from the "modified" path may also flow
/// into \b posta, depending on how the boolean was modified.
/// Adjustments to data-flow are similar to the first scenario but
/// slightly more complicated.  The first block along the \b posta
/// path is referred to as the \b posta_block, this block will
/// have a new block flowing into it.
class ConditionalExecution {
  Funcdata *fd;			///< Function being analyzed
  PcodeOp *cbranch;		///< CBRANCH in iblock
  BlockBasic *initblock;	///< The initial block computing the boolean value
  BlockBasic *iblock;		///< The block where flow is (unnecessarily) coming together
  int4 prea_inslot;	    	///< iblock->In(prea_inslot) = pre a path
  bool init2a_true; 		///< Does \b true branch (in terms of iblock) go to path pre a
  bool iblock2posta_true;	///< Does \b true branch go to path post a
  int4 camethruposta_slot;	///< init or pre slot to use, for data-flow thru post
  int4 posta_outslot;		///< The \b out edge from iblock to posta
  BlockBasic *posta_block;	///< First block in posta path
  BlockBasic *postb_block;	///< First block in postb path
  bool directsplit;		///< True if this the \e direct \e split variation
  map<int4,Varnode *> replacement;	///< Map from block to replacement Varnode for (current) Varnode
  vector<PcodeOp *> returnop;	///< RETURN ops that have flow coming out of the iblock
  vector<bool> heritageyes;	///< Boolean array indexed by address space indicating whether the space is heritaged

  void buildHeritageArray(void);
  bool testIBlock(void);
  bool findInitPre(void);			///< Find \b initblock, based on \b iblock
  bool verifySameCondition(void);		///< Verify that \b initblock and \b iblock branch on the same condition
  bool testOpRead(Varnode *vn,PcodeOp *op);	///< Can we move the (non MULTIEQUAL) defining p-code of the given Varnode
  bool testMultiRead(Varnode *vn,PcodeOp *op);	///< Can we mave the MULTIEQUAL defining p-code of the given Varnode
  bool testRemovability(PcodeOp *op);		///< Test if the given PcodeOp can be removed from \b iblock
  void predefineDirectMulti(PcodeOp *op);
  void adjustDirectMulti(void);			///< Update inputs to any MULTIEQUAL in the direct block
  Varnode *getNewMulti(PcodeOp *op,BlockBasic *bl);
  Varnode *getReplacementRead(PcodeOp *op,BlockBasic *bl);
  void doReplacement(PcodeOp *op);		///< Replace the data-flow for the given PcodeOp in \b iblock
  void fixReturnOp(void);
  bool verify(void);				///< Verify that we have a removable \b iblock
public:
  ConditionalExecution(Funcdata *f);		///< Constructor
  bool trial(BlockBasic *ib);			///< Test for a modifiable configuration around the given block
  void execute(void);				///< Eliminate the unnecessary path join at \b iblock
};

/// \brief Search for and remove various forms of redundant CBRANCH operations
///
/// This action wraps the analysis performed by ConditionalExecution to simplify control-flow
/// that repeatedly branches on the same (or slightly modified) boolean expression.
class ActionConditionalExe : public Action {
public:
  ActionConditionalExe(const string &g) : Action(0,"conditionalexe",g) {}	///< Constructor
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ActionConditionalExe(getGroup());
  }
  virtual int4 apply(Funcdata &data);
};

/// \brief Simplify predication constructions involving the INT_OR operator
///
/// In this form of predication, two variables are set based on a condition and then ORed together.
/// Both variables may be set to zero, or to some other value, based on the condition
/// and the zero values are such that at least one of the variables is zero.
/// \code
///     tmp1 = cond ? val1 : 0;
///     tmp2 = cond ?  0 : val2;
///     result = tmp1 | tmp2;
/// \endcode
/// The RuleOrPredicate simplifies this to
/// \code
///     if (cond) result = val1; else result = val2;
/// \endcode
/// or to be precise
/// \code
///     newtmp = val1 ? val2;			// Using a new MULTIEQUAL
///     result = newtmp;
/// \endcode
/// In an alternate form we have
/// \code
///     tmp1 = (val2 == 0) ? val1 : 0
///     result = tmp1 | val2;
/// \endcode
/// again, one of val1 or val2 must be zero, so this gets replaced with
/// \code
///     tmp1 = val1 ? val2
///     result = tmp1
/// \endcode
class RuleOrPredicate : public Rule {
  /// \brief A helper class to mark up predicated INT_OR expressions
  struct MultiPredicate {
    PcodeOp *op;		///< Base MULTIEQUAL op
    int4 zeroSlot;		///< Input slot containing path that sets zero
    const FlowBlock *zeroBlock;	///< Final block in path that sets zero
    const FlowBlock *condBlock;	///< Conditional block determining if zero is set or not
    PcodeOp *cbranch;		///< CBRANCH determining if zero is set
    Varnode *otherVn;		///< Other (non-zero) Varnode getting set on other path
    bool zeroPathIsTrue;	///< True if path to zero set is the \b true path out of condBlock
    bool discoverZeroSlot(Varnode *vn);
    bool discoverCbranch(void);
    void discoverPathIsTrue(void);
    bool discoverConditionalZero(Varnode *vn);
  };
  int4 checkSingle(Varnode *vn,MultiPredicate &branch,PcodeOp *op,Funcdata &data);
public:
  RuleOrPredicate(const string &g) : Rule(g, 0, "orpredicate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleOrPredicate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

} // End namespace ghidra
#endif

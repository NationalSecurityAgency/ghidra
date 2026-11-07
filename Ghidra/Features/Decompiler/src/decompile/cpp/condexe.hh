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
class ConditionalExecution {
  Funcdata &fd; ///< Function being analyzed

  vector<bool> heritageyes;

  BlockBasic *c1block; ///< The initial block computing the boolean value
  BlockBasic *c2block; ///< The block where flow is (unnecessarily) coming together
  bool flip;

  void buildHeritageArray(void);
  static bool isCondBlock(FlowBlock *fb);
  bool isCond2(void); ///< Basic \b c2block requirements
  bool findCond1(void); ///< Find \b c1block, based on \b c2block
  bool isSameCondition(void); ///< Verify that \b c1block and \b c2block branch on the same condition
  bool canDuplicate(PcodeOp *op); ///< Test if the given PcodeOp can be cloned from \b c2block
public:
  ConditionalExecution(Funcdata &f); ///< Constructor
  bool trial(BlockBasic *bb); ///< Test for a modifiable configuration around the given block
  void execute(void); ///< Eliminate the unnecessary path join at \b iblock
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

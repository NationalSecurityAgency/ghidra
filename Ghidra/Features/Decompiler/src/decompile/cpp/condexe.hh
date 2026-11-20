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
/// or:
/// \code
///    if (a) {           if (a) {
///       BODY1             BODY1
///    }          ==>     }
///    if (!a) {          else
///       BODY2             BODY2
///    }                  }
/// \endcode
///
/// There is a block where two flows come together but don't need to,
/// as the evaluation of the boolean is redundant.  This block is the
/// \b c2block.  The original evaluation of the boolean occurs in the
/// \b c1block. The \b true and \b false edges out of \b c1block are
/// connected to the corresponding out edge of \b c2block separated by
/// the contents of \b c2block.
///
/// For the first transformation above:
/// \code
///   +---------+             +---------+
///   | c1block |             | c1block |
///   +---------+             +---------+
///     |!a   |a                |!a   |a
///     |     |                 |     +-------+
///     |   +-------+           |             |
///     |   | BODY1 |           |         +-------+
///     |   +-------+           |         | BODY1 |
///     |     |                 |         +-------+
///     |     |                 |             |
///   +---------+         +-----------+ +-----------+
///   | c2block |     ==> | c2block.1 | | c2block.2 |
///   +---------+         +-----------+ +-----------+
///     |!a   |a                |             |
///     |     |                 |         +-------+
///     |   +-------+           |         | BODY2 |
///     |   | BODY2 |           |         +-------+
///     |   +-------+           |             |
///     |     |                 |     +-------+
///     |     |                 |     |
///   +---------+             +---------+
///   |   out   |             |   out   |
///   +---------+             +---------+
/// \endcode
///
/// This transformation requires adjustments to output Varnodes that
/// descend into \b c2block.1 and \b c2block.2, and those created by
/// the \b c2block. More specifically, any MULTIEQUAL into \b c2block
/// will transform into a COPY - in \b c2block.1 and \b c1block.2 -
/// containing the corresponding Varnode from the original in edge.
/// These, along with the created output Varnodes, are propagated down
/// their respective edges. For Varnodes with descendants in \b out
/// (and beyond), the two paths are recombined with a MULTIEQUAL.
///
/// It is important to reduce unnecessary duplication of PcodeOps. To
/// this effect, attempts are made to pull-back PcodeOps from
/// \b c2block to \b c1block before the split occurs. It would
/// also be possible to push-back PcodeOps into \b out as-well.
class ConditionalExecution {
  Funcdata &fd; ///< Function being analyzed

  const vector<bool> heritageyes;

  BlockBasic *c1block; ///< The initial block computing the boolean value
  BlockBasic *c2block; ///< The block where flow is (unnecessarily) coming together
  bool flip;

  static const vector<bool> buildHeritageArray(Funcdata &f);
  static bool isCondBlock(FlowBlock *fb); ///< Commond conditional block requirements

  bool isCond2(void); ///< Basic \b c2block requirements
  bool findCond1(void); ///< Find \b c1block, based on \b c2block
  bool isSameCondition(void); ///< Verify that \b c1block and \b c2block branch on the same condition
  bool canDuplicate(const PcodeOp *op); ///< Test if the given PcodeOp can be cloned from \b c2block
public:
  ConditionalExecution(Funcdata &f) : fd(f),heritageyes(buildHeritageArray(f)) { }

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

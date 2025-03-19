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
/// \file ruleaction.hh
/// \brief This is the basic set of transformation Rule objects.
///
/// Each Rule triggers on
/// a specific localized data-flow configuration. They are generally applied
/// simultaneously from a pool (see ActionPool) and can interact with each other
/// to produce an emergent transformation. The Rules are applied repeatedly until
/// no Rule can make any additional transformations.

#ifndef __RULEACTION_HH__
#define __RULEACTION_HH__

#include "action.hh"

namespace ghidra {

/// \brief Structure for sorting out pointer expression trees
///
/// Given a base pointer of known data-type and an additive expression involving
/// the pointer, group the terms of the expression into:
///   - A constant multiple of the base data-type
///   - Non-constant multiples of the base data-type
///   - An constant offset to a sub-component of the base data-type
///   - An remaining terms
///
/// The \e multiple terms are rewritten using a CPUI_PTRADD. The constant offset
/// is rewritten using a CPUI_PTRSUB.  Other terms are added back in.  Analysis may cause
/// multiplication (CPUI_INT_MULT) by a constant to be distributed to its CPUI_INT_ADD input.
class AddTreeState {
  Funcdata &data;		///< The function containing the expression
  PcodeOp *baseOp;		///< Base of the ADD tree
  Varnode *ptr;			///< The pointer varnode
  const TypePointer *ct;	///< The pointer data-type
  const Datatype *baseType;	///< The base data-type being pointed at
  const TypePointerRel *pRelType;	///< A copy of \b ct, if it is a relative pointer
  int4 ptrsize;			///< Size of the pointer
  int4 size;			///< Size of data-type being pointed to (in address units) or 0 for open ended pointer
  int4 baseSlot;		///< Slot of the ADD tree base that is holding the pointer
  uint4 biggestNonMultCoeff;	///< Biggest coefficient that is not a multiple
  uint8 ptrmask;		///< Mask for modulo calculations in ptr space
  uint8 offset;			///< Number of bytes we dig into the base data-type
  uint8 correct;		///< Number of bytes being double counted
  vector<Varnode *> multiple;	///< Varnodes which are multiples of size
  vector<intb> coeff;		///< Associated constant multiple
  vector<Varnode *> nonmult;	///< Varnodes which are not multiples
  PcodeOp *distributeOp;	///< A CPUI_INT_MULT op that needs to be distributed
  uint8 multsum;		///< Sum of multiple constants
  uint8 nonmultsum;		///< Sum of non-multiple constants
  bool preventDistribution;	///< Do not distribute "multiply by constant" operation
  bool isDistributeUsed;	///< Are terms produced by distributing used
  bool isSubtype;		///< Is there a sub-type (using CPUI_PTRSUB)
  bool valid;			///< Set to \b true if the whole expression can be transformed
  bool isDegenerate;		///< Set to \b true if pointer to unitsize or smaller
  bool hasMatchingSubType(int8 off,uint4 arrayHint,int8 *newoff) const;
  bool checkMultTerm(Varnode *vn,PcodeOp *op,uint8 treeCoeff);	///< Accumulate details of INT_MULT term and continue traversal if appropriate
  bool checkTerm(Varnode *vn,uint8 treeCoeff);			///< Accumulate details of given term and continue tree traversal
  bool spanAddTree(PcodeOp *op,uint8 treeCoeff);		///< Walk the given sub-tree accumulating details
  void calcSubtype(void);		///< Calculate final sub-type offset
  void assignPropagatedType(PcodeOp *op);	///< Assign a data-type propagated through the given PcodeOp
  Varnode *buildMultiples(void);	///< Build part of tree that is multiple of base size
  Varnode *buildExtra(void);		///< Build part of tree not accounted for by multiples or \e offset
  bool buildDegenerate(void);		///< Transform ADD into degenerate PTRADD
  void buildTree(void);			///< Build the transformed ADD tree
  void clear(void);			///< Reset for a new ADD tree traversal
public:
  AddTreeState(Funcdata &d,PcodeOp *op,int4 slot);	///< Construct given root of ADD tree and pointer
  bool apply(void);		///< Attempt to transform the pointer expression
  bool initAlternateForm(void);		///< Prepare analysis if there is an alternate form of the base pointer
};

class RuleEarlyRemoval : public Rule {
public:
  RuleEarlyRemoval(const string &g) : Rule(g, 0, "earlyremoval") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleEarlyRemoval(getGroup());
  }
  // This rule applies to all ops
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
// class RuleAddrForceRelease : public Rule {
// public:
//   RuleAddrForceRelease(const string &g) : Rule(g, 0, "addrforcerelease") {}	///< Constructor
//   virtual void getOpList(vector<uint4> &oplist) const;
//   virtual int4 applyOp(PcodeOp *op,Funcdata &data);
// };
class RuleCollectTerms : public Rule {
  static Varnode *getMultCoeff(Varnode *vn,uintb &coef);	///< Get the multiplicative coefficient
public:
  RuleCollectTerms(const string &g) : Rule(g, 0, "collect_terms") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleCollectTerms(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSelectCse : public Rule {
public:
  RuleSelectCse(const string &g) : Rule(g,0,"selectcse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSelectCse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePiece2Zext : public Rule {
public:
  RulePiece2Zext(const string &g) : Rule(g, 0, "piece2zext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePiece2Zext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePiece2Sext : public Rule {
public:
  RulePiece2Sext(const string &g) : Rule(g, 0, "piece2sext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePiece2Sext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBxor2NotEqual : public Rule {
public:
  RuleBxor2NotEqual(const string &g) : Rule(g, 0, "bxor2notequal") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBxor2NotEqual(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleOrMask : public Rule {
public:
  RuleOrMask(const string &g) : Rule(g, 0, "ormask") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleOrMask(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleAndMask : public Rule {
public:
  RuleAndMask(const string &g) : Rule(g, 0, "andmask") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndMask(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleOrConsume : public Rule {
public:
  RuleOrConsume(const string &g) : Rule(g, 0, "orconsume") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleOrConsume(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleOrCollapse : public Rule {
public:
  RuleOrCollapse(const string &g) : Rule(g, 0, "orcollapse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleOrCollapse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleAndOrLump : public Rule {
public:
  RuleAndOrLump(const string &g) : Rule(g, 0, "andorlump") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndOrLump(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleNegateIdentity : public Rule {
public:
  RuleNegateIdentity(const string &g) : Rule(g, 0, "negateidentity") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleNegateIdentity(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleShiftBitops : public Rule {
public:
  RuleShiftBitops(const string &g) : Rule(g, 0, "shiftbitops") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleShiftBitops(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleRightShiftAnd : public Rule {
public:
  RuleRightShiftAnd(const string &g) : Rule(g, 0, "rightshiftand") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleRightShiftAnd(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleIntLessEqual : public Rule {
public:
  RuleIntLessEqual(const string &g) : Rule(g, 0, "intlessequal") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleIntLessEqual(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleEquality : public Rule {
public:
  RuleEquality(const string &g) : Rule(g, 0, "equality") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleEquality(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
// Reversible rules
class RuleTermOrder : public Rule {
public:
  RuleTermOrder(const string &g) : Rule(g, 0, "termorder") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleTermOrder(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePullsubMulti : public Rule {
public:
  RulePullsubMulti(const string &g) : Rule(g, 0, "pullsub_multi") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePullsubMulti(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static void minMaxUse(Varnode *vn,int4 &maxByte,int4 &minByte);
  static void replaceDescendants(Varnode *origVn,Varnode *newVn,int4 maxByte,int4 minByte,Funcdata &data);
  static bool acceptableSize(int4 size);
  static Varnode *buildSubpiece(Varnode *basevn,uint4 outsize,uint4 shift,Funcdata &data);
  static Varnode *findSubpiece(Varnode *basevn,uint4 outsize,uint4 shift);
};
class RulePullsubIndirect : public Rule {
public:
  RulePullsubIndirect(const string &g) : Rule(g, 0, "pullsub_indirect") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePullsubIndirect(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePushMulti : public Rule {
  static PcodeOp *findSubstitute(Varnode *in1,Varnode *in2,BlockBasic *bb,PcodeOp *earliest);
public:
  RulePushMulti(const string &g) : Rule(g, 0, "push_multi") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePushMulti(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleNotDistribute : public Rule {
public:
  RuleNotDistribute(const string &g) : Rule(g, 0, "notdistribute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleNotDistribute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleHighOrderAnd : public Rule {
public:
  RuleHighOrderAnd(const string &g) : Rule(g, 0, "highorderand") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleHighOrderAnd(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleAndDistribute : public Rule {
public:
  RuleAndDistribute(const string &g) : Rule(g, 0, "anddistribute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndDistribute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleLessOne : public Rule {
public:
  RuleLessOne(const string &g) : Rule(g, 0, "lessone") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLessOne(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleRangeMeld : public Rule {
public:
  RuleRangeMeld(const string &g) : Rule(g, 0, "rangemeld") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleRangeMeld(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};  
class RuleFloatRange : public Rule {
public:
  RuleFloatRange(const string &g) : Rule(g, 0, "floatrange") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleFloatRange(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};  
class RuleAndCommute : public Rule {
public:
  RuleAndCommute(const string &g) : Rule(g, 0, "andcommute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndCommute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};  
class RuleAndPiece : public Rule {
public:
  RuleAndPiece(const string &g) : Rule(g, 0, "andpiece") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndPiece(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};  
class RuleAndZext : public Rule {
public:
  RuleAndZext(const string &g) : Rule(g, 0, "andzext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleAndCompare : public Rule {
public:
  RuleAndCompare(const string &g) : Rule(g, 0, "andcompare") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAndCompare(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleDoubleSub : public Rule {
public:
  RuleDoubleSub(const string &g) : Rule(g, 0, "doublesub") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleSub(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};  
class RuleDoubleShift : public Rule {
public:
  RuleDoubleShift(const string &g) : Rule(g, 0, "doubleshift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleDoubleArithShift : public Rule {
public:
  RuleDoubleArithShift(const string &g) : Rule(g, 0, "doublearithshift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDoubleArithShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleConcatShift : public Rule {
public:
  RuleConcatShift(const string &g) : Rule(g, 0, "concatshift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleConcatShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleLeftRight : public Rule {
public:
  RuleLeftRight(const string &g) : Rule(g, 0, "leftright") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLeftRight(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleShiftCompare : public Rule {
public:
  RuleShiftCompare(const string &g) : Rule(g, 0, "shiftcompare") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleShiftCompare(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
// class RuleShiftLess : public Rule {
// public:
//   RuleShiftLess(const string &g) : Rule(g, 0, "shiftless") {}	///< Constructor
//   virtual Rule *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Rule *)0;
//     return new RuleShiftLess(getGroup());
//   }
//   virtual void getOpList(vector<uint4> &oplist) const;
//   virtual int4 applyOp(PcodeOp *op,Funcdata &data);
// };
class RuleLessEqual : public Rule {
public:
  RuleLessEqual(const string &g) : Rule(g, 0, "lessequal") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLessEqual(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleLessNotEqual : public Rule {
public:
  RuleLessNotEqual(const string &g) : Rule(g, 0, "lessnotequal") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLessNotEqual(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleTrivialArith : public Rule {
public:
  RuleTrivialArith(const string &g) : Rule(g, 0, "trivialarith") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleTrivialArith(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleTrivialBool : public Rule {
public:
  RuleTrivialBool(const string &g) : Rule(g, 0, "trivialbool") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleTrivialBool(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleZextEliminate : public Rule {
public:
  RuleZextEliminate(const string &g) : Rule(g, 0, "zexteliminate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleZextEliminate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSlessToLess : public Rule {
public:
  RuleSlessToLess(const string &g) : Rule(g, 0, "slesstoless") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSlessToLess(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleZextSless : public Rule {
public:
  RuleZextSless(const string &g) : Rule(g, 0, "zextsless") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleZextSless(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBitUndistribute : public Rule {
public:
  RuleBitUndistribute(const string &g) : Rule(g, 0, "bitundistribute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBitUndistribute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBooleanUndistribute : public Rule {
  static bool isMatch(Varnode *leftVn,Varnode *rightVn,bool &rightFlip);
public:
  RuleBooleanUndistribute(const string &g) : Rule(g, 0, "booleanundistribute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBooleanUndistribute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBooleanDedup : public Rule {
  static bool isMatch(Varnode *leftVn,Varnode *rightVn,bool &isFlip);
public:
  RuleBooleanDedup(const string &g) : Rule(g, 0, "booleandedup") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBooleanDedup(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBooleanNegate : public Rule {
public:
  RuleBooleanNegate(const string &g) : Rule(g, 0, "booleannegate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBooleanNegate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBoolZext : public Rule {
public:
  RuleBoolZext(const string &g) : Rule(g, 0, "boolzext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBoolZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleLogic2Bool : public Rule {
public:
  RuleLogic2Bool(const string &g) : Rule(g, 0, "logic2bool") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLogic2Bool(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleIndirectCollapse : public Rule {
public:
  RuleIndirectCollapse(const string &g) : Rule(g, 0, "indirectcollapse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleIndirectCollapse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleMultiCollapse : public Rule {
public:
  RuleMultiCollapse(const string &g) : Rule(g, 0, "multicollapse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleMultiCollapse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSborrow : public Rule {
public:
  RuleSborrow(const string &g) : Rule(g, 0, "sborrow") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSborrow(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleTrivialShift : public Rule {
public:
  RuleTrivialShift(const string &g) : Rule(g, 0, "trivialshift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleTrivialShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSignShift : public Rule {
public:
  RuleSignShift(const string &g) : Rule(g, 0, "signshift") {}		///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleTestSign : public Rule {
  void findComparisons(Varnode *vn,vector<PcodeOp *> &res);
public:
  RuleTestSign(const string &g) : Rule(g, 0, "testsign") {}		///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleTestSign(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleIdentityEl : public Rule {
public:
  RuleIdentityEl(const string &g) : Rule(g, 0, "identityel") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleIdentityEl(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleShift2Mult : public Rule {
public:
  RuleShift2Mult(const string &g) : Rule(g, 0, "shift2mult") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleShift2Mult(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleShiftPiece : public Rule {
public:
  RuleShiftPiece(const string &g) : Rule(g, 0, "shiftpiece") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleShiftPiece(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleCollapseConstants : public Rule {
public:
  RuleCollapseConstants(const string &g) : Rule(g, 0, "collapseconstants") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleCollapseConstants(getGroup());
  }
  // applies to all opcodes
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleTransformCpool : public Rule {
public:
  RuleTransformCpool(const string &g) : Rule(g, 0, "transformcpool") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleTransformCpool(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePropagateCopy : public Rule {
public:
  RulePropagateCopy(const string &g) : Rule(g, 0, "propagatecopy") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePropagateCopy(getGroup());
  }
  // applies to all opcodes
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class Rule2Comp2Mult : public Rule {
public:
  Rule2Comp2Mult(const string &g) : Rule(g,0,"2comp2mult") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new Rule2Comp2Mult(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleCarryElim : public Rule {
public:
  RuleCarryElim(const string &g) : Rule(g, 0, "carryelim") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleCarryElim(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSub2Add : public Rule {
public:
  RuleSub2Add(const string &g) : Rule(g, 0, "sub2add") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSub2Add(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleXorCollapse : public Rule {
public:
  RuleXorCollapse(const string &g) : Rule(g, 0, "xorcollapse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleXorCollapse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleAddMultCollapse : public Rule {
public:
  RuleAddMultCollapse(const string &g) : Rule(g, 0, "addmultcollapse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAddMultCollapse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
// class RuleUndistribute : public Rule {
// public:
//   RuleUndistribute(const string &g) : Rule(g, 0, "undistribute") {}	///< Constructor
//   virtual Rule *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Rule *)0;
//     return new RuleUndistribute(Group());
//   }
//   virtual void getOpList(vector<uint4> &oplist) const;
//   virtual int4 applyOp(PcodeOp *op,Funcdata &data);
// };
class RuleLoadVarnode : public Rule {
  friend class RuleStoreVarnode;
  static AddrSpace *correctSpacebase(Architecture *glb,Varnode *vn,AddrSpace *spc);
  static AddrSpace *vnSpacebase(Architecture *glb,Varnode *vn,uintb &val,AddrSpace *spc);
  static AddrSpace *checkSpacebase(Architecture *glb,PcodeOp *op,uintb &offoff);
public:
  RuleLoadVarnode(const string &g) : Rule(g, 0, "loadvarnode") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLoadVarnode(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleStoreVarnode : public Rule {
public:
  RuleStoreVarnode(const string &g) : Rule(g, 0, "storevarnode") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleStoreVarnode(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
// class RuleShadowVar : public Rule {
// public:
//   RuleShadowVar(const string &g) : Rule(g, 0, "shadowvar") {}	///< Constructor
//   virtual Rule *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Rule *)0;
//     return new RuleShadowVar(getGroup());
//   }
//   virtual void getOpList(vector<uint4> &oplist) const;
//   virtual int4 applyOp(PcodeOp *op,Funcdata &data);
// };
class RuleSubExtComm : public Rule {
public:
  RuleSubExtComm(const string &g) : Rule(g,0,"subextcomm") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubExtComm(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSubCommute : public Rule {
public:
  RuleSubCommute(const string &g) : Rule(g, 0, "subcommute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubCommute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static Varnode *shortenExtension(PcodeOp *extOp,int4 maxSize,Funcdata &data);
  static bool cancelExtensions(PcodeOp *longform,PcodeOp *subOp,Varnode *ext0In,Varnode *ext1In,Funcdata &data);
};
class RuleConcatCommute : public Rule {
public:
  RuleConcatCommute(const string &g) : Rule(g, 0, "concatcommute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleConcatCommute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
// class RuleIndirectConcat : public Rule {
// public:
//   RuleIndirectConcat(const string &g) : Rule(g, 0, "indirectconcat") {}	///< Constructor
//   virtual Rule *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Rule *)0;
//     return new RuleIndirectConcat(getGroup());
//   }
//   virtual void getOpList(vector<uint4> &oplist) const;
//   virtual int4 applyOp(PcodeOp *op,Funcdata &data);
// };
class RuleConcatZext : public Rule {
public:
  RuleConcatZext(const string &g) : Rule(g, 0, "concatzext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleConcatZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleZextCommute : public Rule {
public:
  RuleZextCommute(const string &g) : Rule(g, 0, "zextcommute") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleZextCommute(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleZextShiftZext : public Rule {
public:
  RuleZextShiftZext(const string &g) : Rule(g, 0, "zextshiftzext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleZextShiftZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleShiftAnd : public Rule {
public:
  RuleShiftAnd(const string &g) : Rule(g, 0, "shiftand") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleShiftAnd(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleConcatZero : public Rule {
public:
  RuleConcatZero(const string &g) : Rule(g, 0, "concatzero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleConcatZero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleConcatLeftShift : public Rule {
public:
  RuleConcatLeftShift(const string &g) : Rule(g, 0, "concatleftshift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleConcatLeftShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSubZext : public Rule {
public:
  RuleSubZext(const string &g) : Rule(g, 0, "subzext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSubCancel : public Rule {
public:
  RuleSubCancel(const string &g) : Rule(g, 0, "subcancel") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubCancel(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleShiftSub : public Rule {
public:
  RuleShiftSub(const string &g) : Rule(g, 0, "shiftsub") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleShiftSub(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleHumptyDumpty : public Rule {
public:
  RuleHumptyDumpty(const string &g) : Rule(g, 0, "humptydumpty") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleHumptyDumpty(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleDumptyHump : public Rule {
public:
  RuleDumptyHump(const string &g) : Rule(g, 0, "dumptyhump") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDumptyHump(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleHumptyOr : public Rule {
public:
  RuleHumptyOr(const string &g) : Rule(g, 0, "humptyor") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleHumptyOr(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSwitchSingle : public Rule {
public:
  RuleSwitchSingle(const string &g) : Rule(g,0,"switchsingle") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSwitchSingle(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleCondNegate : public Rule {
public:
  RuleCondNegate(const string &g) : Rule(g, 0, "condnegate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleCondNegate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleBoolNegate : public Rule {
public:
  RuleBoolNegate(const string &g) : Rule(g, 0, "boolnegate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBoolNegate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleLess2Zero : public Rule {
public:
  RuleLess2Zero(const string &g) : Rule(g, 0, "less2zero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLess2Zero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleLessEqual2Zero : public Rule {
public:
  RuleLessEqual2Zero(const string &g) : Rule(g, 0, "lessequal2zero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLessEqual2Zero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleSLess2Zero : public Rule {
  static Varnode *getHiBit(PcodeOp *op);
public:
  RuleSLess2Zero(const string &g) : Rule(g, 0, "sless2zero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSLess2Zero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleEqual2Zero : public Rule {
public:
  RuleEqual2Zero(const string &g) : Rule(g, 0, "equal2zero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleEqual2Zero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RuleEqual2Constant : public Rule {
public:
  RuleEqual2Constant(const string &g) : Rule(g, 0, "equal2constant") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleEqual2Constant(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePtrArith : public Rule {
  static bool verifyPreferredPointer(PcodeOp *op,int4 slot);
public:
  RulePtrArith(const string &g) : Rule(g, 0, "ptrarith") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePtrArith(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static int4 evaluatePointerExpression(PcodeOp *op,int4 slot);
};
class RuleStructOffset0 : public Rule {
public:
  RuleStructOffset0(const string &g) : Rule(g, 0, "structoffset0") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleStructOffset0(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePushPtr : public Rule {
  static Varnode *buildVarnodeOut(Varnode *vn,PcodeOp *op,Funcdata &data);
  static void collectDuplicateNeeds(vector<PcodeOp *> &reslist,Varnode *vn);
public:
  RulePushPtr(const string &g) : Rule(g, 0, "pushptr") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePushPtr(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static void duplicateNeed(PcodeOp *op,Funcdata &data);
};
class RulePtraddUndo : public Rule {
public:
  RulePtraddUndo(const string &g) : Rule(g, 0, "ptraddundo") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePtraddUndo(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};
class RulePtrsubUndo : public Rule {
  static const int4 DEPTH_LIMIT;	///< The maximum depth of the additive expression to check
  static int8 getConstOffsetBack(Varnode *vn,int8 &multiplier,int4 maxLevel);
  static int8 getExtraOffset(PcodeOp *op,int8 &multiplier);
  static int8 removeLocalAdds(Varnode *vn,Funcdata &data);
  static int8 removeLocalAddRecurse(PcodeOp *op,int4 slot,int4 maxLevel,Funcdata &data);
public:
  RulePtrsubUndo(const string &g) : Rule(g, 0, "ptrsubundo") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePtrsubUndo(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

// Cleanup rules
class RuleMultNegOne : public Rule {
public:
  RuleMultNegOne(const string &g) : Rule( g, 0, "multnegone") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleMultNegOne(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleAddUnsigned : public Rule {
public:
  RuleAddUnsigned(const string &g) : Rule( g, 0, "addunsigned") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleAddUnsigned(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class Rule2Comp2Sub : public Rule {
public:
  Rule2Comp2Sub(const string &g) : Rule( g, 0, "2comp2sub") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new Rule2Comp2Sub(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSubRight : public Rule {
public:
  RuleSubRight(const string &g) : Rule( g, 0, "subright") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubRight(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RulePtrsubCharConstant : public Rule {
  bool pushConstFurther(Funcdata &data,TypePointer *outtype,PcodeOp *op,int4 slot,uintb val);
public:
  RulePtrsubCharConstant(const string &g) : Rule( g, 0, "ptrsubcharconstant") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePtrsubCharConstant(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleExtensionPush : public Rule {
public:
  RuleExtensionPush(const string &g) : Rule( g, 0, "extensionpush") {}		///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleExtensionPush(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RulePieceStructure : public Rule {
  /// \brief Markup for Varnodes pieced together into structure/array
  static Datatype *determineDatatype(Varnode *vn,int4 &baseOffset);
  static bool spanningRange(Datatype *ct,int4 off,int4 size);
  static bool convertZextToPiece(PcodeOp *zext,Datatype *structuredType,int4 offset,Funcdata &data);
  static bool findReplaceZext(vector<PieceNode> &stack,Datatype *structuredType,Funcdata &data);
  static bool separateSymbol(Varnode *root,Varnode *leaf);
public:
  RulePieceStructure(const string &g) : Rule( g, 0, "piecestructure") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePieceStructure(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSubNormal : public Rule {
public:
  RuleSubNormal(const string &g) : Rule( g, 0, "subnormal") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubNormal(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

// class RuleRightShiftSub : public Rule {
// public:
//   RuleRightShiftSub(const string &g) : Rule( g, 0, "rightshiftsub") {}	///< Constructor
//   virtual Rule *clone(const ActionGroupList &grouplist) const {
//     if (!grouplist.contains(getGroup())) return (Rule *)0;
//     return new RuleRightShiftSub(Group());
//   }
//   virtual void getOpList(vector<uint4> &oplist) const;
//   virtual int4 applyOp(PcodeOp *op,Funcdata &data);
// };

class RulePositiveDiv : public Rule {
public:
  RulePositiveDiv(const string &g) : Rule( g, 0, "positivediv") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePositiveDiv(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleDivTermAdd : public Rule {
public:
  RuleDivTermAdd(const string &g) : Rule( g, 0, "divtermadd") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDivTermAdd(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static PcodeOp *findSubshift(PcodeOp *op,int4 &n,OpCode &shiftopc);
};

class RuleDivTermAdd2 : public Rule {
public:
  RuleDivTermAdd2(const string &g) : Rule( g, 0, "divtermadd2") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDivTermAdd2(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleDivOpt : public Rule {
  static uintb calcDivisor(uintb n,uint8 *y,int4 xsize);		///< Calculate the divisor
  static void moveSignBitExtraction(Varnode *firstVn,Varnode *replaceVn,Funcdata &data);
  static bool checkFormOverlap(PcodeOp *op);	///< If form rooted at given PcodeOp is superseded by an overlapping form
public:
  RuleDivOpt(const string &g) : Rule( g, 0, "divopt") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDivOpt(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static Varnode *findForm(PcodeOp *op,int4 &n,uint8 *y,int4 &xsize,OpCode &extopc);
};

class RuleSignDiv2 : public Rule {
public:
  RuleSignDiv2(const string &g) : Rule( g, 0, "signdiv2") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignDiv2(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleDivChain : public Rule {
public:
  RuleDivChain(const string &g) : Rule( g, 0, "divchain") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleDivChain(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSignForm : public Rule {
public:
  RuleSignForm(const string &g) : Rule( g, 0, "signform") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignForm(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSignForm2 : public Rule {
public:
  RuleSignForm2(const string &g) : Rule( g, 0, "signform2") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignForm2(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSignNearMult : public Rule {
public:
  RuleSignNearMult(const string &g) : Rule( g, 0, "signnearmult") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignNearMult(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleModOpt: public Rule {
public:
  RuleModOpt(const string &g) : Rule( g, 0, "modopt") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleModOpt(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSignMod2nOpt : public Rule {
public:
  RuleSignMod2nOpt(const string &g) : Rule( g, 0, "signmod2nopt") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignMod2nOpt(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static Varnode *checkSignExtraction(Varnode *outVn);
};

class RuleSignMod2Opt : public Rule {
public:
  RuleSignMod2Opt(const string &g) : Rule( g, 0, "signmod2opt") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignMod2Opt(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSignMod2nOpt2 : public Rule {
  static Varnode *checkMultiequalForm(PcodeOp *op,uintb npow);
  static Varnode *checkSignExtForm(PcodeOp *op);
public:
  RuleSignMod2nOpt2(const string &g) : Rule( g, 0, "signmod2nopt2") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSignMod2nOpt2(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSegment : public Rule {
public:
  RuleSegment(const string &g) : Rule( g, 0, "segment") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSegment(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RulePtrFlow : public Rule {
  Architecture *glb;			///< The address space manager
  bool hasTruncations;			///< \b true if this architecture needs truncated pointers
  bool trialSetPtrFlow(PcodeOp *op);
  bool propagateFlowToDef(Varnode *vn);
  bool propagateFlowToReads(Varnode *vn);
  Varnode *truncatePointer(AddrSpace *spc,PcodeOp *op,Varnode *vn,int4 slot,Funcdata &data);
public:
  RulePtrFlow(const string &g,Architecture *conf);	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePtrFlow(getGroup(),glb);
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleNegateNegate : public Rule {
public:
  RuleNegateNegate(const string &g) : Rule( g, 0, "negatenegate") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleNegateNegate(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleConditionalMove : public Rule {
  static Varnode *checkBoolean(Varnode *vn);			///< Check for boolean expression
  static bool gatherExpression(Varnode *vn,vector<PcodeOp *> &ops,FlowBlock *root,FlowBlock *branch);
  static Varnode *constructBool(Varnode *vn,PcodeOp *insertop,vector<PcodeOp *> &ops,Funcdata &data);
  /// \brief Sort PcodeOps based only on order within a basic block
  static bool compareOp(PcodeOp *op0,PcodeOp *op1) { return op0->getSeqNum().getOrder() < op1->getSeqNum().getOrder(); }
public:
  RuleConditionalMove(const string &g) : Rule( g, 0, "conditionalmove") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleConditionalMove(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleFloatCast : public Rule {
public:
  RuleFloatCast(const string &g) : Rule( g, 0, "floatcast") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleFloatCast(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleIgnoreNan : public Rule {
  static bool checkBackForCompare(Varnode *floatVar,Varnode *root);
  static bool isAnotherNan(Varnode *vn);
  static Varnode *testForComparison(Varnode *floatVar,PcodeOp *op,int4 slot,OpCode matchCode,int4 &count,Funcdata &data);
public:
  RuleIgnoreNan(const string &g) : Rule( g, 0, "ignorenan") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleIgnoreNan(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleUnsigned2Float : public Rule {
public:
  RuleUnsigned2Float(const string &g) : Rule( g, 0, "unsigned2float") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleUnsigned2Float(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleInt2FloatCollapse : public Rule {
public:
  RuleInt2FloatCollapse(const string &g) : Rule( g, 0, "int2floatcollapse") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleInt2FloatCollapse(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleFuncPtrEncoding : public Rule {
public:
  RuleFuncPtrEncoding(const string &g) : Rule( g, 0, "funcptrencoding") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleFuncPtrEncoding(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleThreeWayCompare : public Rule {
public:
  RuleThreeWayCompare(const string &g) : Rule( g, 0, "threewaycomp") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleThreeWayCompare(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static PcodeOp *detectThreeWay(PcodeOp *op,bool &isPartial);
  static int4 testCompareEquivalence(PcodeOp *lessop,PcodeOp *lessequalop);
};

class RulePopcountBoolXor : public Rule {
public:
  RulePopcountBoolXor(const string &g) : Rule( g, 0, "popcountboolxor") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePopcountBoolXor(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static Varnode *getBooleanResult(Varnode *vn,int4 bitPos,int4 &constRes);
};

class RulePiecePathology : public Rule {
  static bool isPathology(Varnode *vn,Funcdata &data);
  static int4 tracePathologyForward(PcodeOp *op,Funcdata &data);
public:
  RulePiecePathology(const string &g) : Rule( g, 0, "piecepathology") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePiecePathology(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleXorSwap : public Rule {
public:
  RuleXorSwap(const string &g) : Rule(g,0,"xorswap") {}		///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleXorSwap(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleLzcountShiftBool : public Rule {
public:
  RuleLzcountShiftBool(const string &g) : Rule( g, 0, "lzcountshiftbool") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleLzcountShiftBool(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleFloatSign : public Rule {
public:
  RuleFloatSign(const string &g) : Rule( g, 0, "floatsign") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleFloatSign(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleFloatSignCleanup : public Rule {
public:
  RuleFloatSignCleanup(const string &g) : Rule( g, 0, "floatsigncleanup") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleFloatSignCleanup(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleOrCompare : public Rule {
public:
  RuleOrCompare(const string &g) : Rule( g, 0, "orcompare") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleOrCompare(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleExpandLoad : public Rule {
  static bool checkAndComparison(Varnode *vn);
  static void modifyAndComparison(Funcdata &data,Varnode *oldVn,Varnode *newVn,Datatype *dt,int4 offset);
public:
  RuleExpandLoad(const string &g) : Rule( g, 0, "expandload") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleExpandLoad(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

} // End namespace ghidra
#endif

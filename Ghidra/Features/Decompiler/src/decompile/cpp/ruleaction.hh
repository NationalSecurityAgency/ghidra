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

#ifndef __RULE_ACTION__
#define __RULE_ACTION__

#include "action.hh"

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
  int4 ptrsize;			///< Size of the pointer
  int4 size;			///< Size of data-type being pointed to (in address units) or 0 for open ended pointer
  uintb ptrmask;		///< Mask for modulo calculations in ptr space
  uintb offset;			///< Number of bytes we dig into the base data-type
  uintb correct;		///< Number of bytes being double counted
  vector<Varnode *> multiple;	///< Varnodes which are multiples of size
  vector<intb> coeff;		///< Associated constant multiple
  vector<Varnode *> nonmult;	///< Varnodes which are not multiples
  PcodeOp *distributeOp;	///< A CPUI_INT_MULT op that needs to be distributed
  uintb multsum;		///< Sum of multiple constants
  uintb nonmultsum;		///< Sum of non-multiple constants
  bool preventDistribution;	///< Do not distribute "multiply by constant" operation
  bool isDistributeUsed;	///< Are terms produced by distributing used
  bool isSubtype;		///< Is there a sub-type (using CPUI_PTRSUB)
  bool valid;			///< Set to \b true if the whole expression can be transformed
  uint4 findArrayHint(void) const;	///< Look for evidence of an array in a sub-component
  bool hasMatchingSubType(uintb off,uint4 arrayHint,uintb *newoff) const;
  bool checkMultTerm(Varnode *vn,PcodeOp *op, uintb treeCoeff);	///< Accumulate details of INT_MULT term and continue traversal if appropriate
  bool checkTerm(Varnode *vn, uintb treeCoeff);			///< Accumulate details of given term and continue tree traversal
  bool spanAddTree(PcodeOp *op, uintb treeCoeff);		///< Walk the given sub-tree accumulating details
  void calcSubtype(void);		///< Calculate final sub-type offset
  Varnode *buildMultiples(void);	///< Build part of tree that is multiple of base size
  Varnode *buildExtra(void);		///< Build part of tree not accounted for by multiples or \e offset
  void buildTree(void);			///< Build the transformed ADD tree
  void clear(void);			///< Reset for a new ADD tree traversal
public:
  AddTreeState(Funcdata &d,PcodeOp *op,int4 slot);	///< Construct given root of ADD tree and pointer
  bool apply(void);		///< Attempt to transform the pointer expression
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
class RuleEmbed : public Rule {
public:
  RuleEmbed(const string &g) : Rule(g, 0, "embed") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleEmbed(getGroup());
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
  static bool verifyAddTreeBottom(PcodeOp *op,int4 slot);
public:
  RulePtrArith(const string &g) : Rule(g, 0, "ptrarith") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePtrArith(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
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
public:
  RulePushPtr(const string &g) : Rule(g, 0, "pushptr") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePushPtr(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
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
  static uintb calcDivisor(uintb n,uint8 y,int4 xsize);		///< Calculate the divisor
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
  static Varnode *findForm(PcodeOp *op,int4 &n,uintb &y,int4 &xsize,OpCode &extopc);
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

class RuleSubvarAnd : public Rule {
public:
  RuleSubvarAnd(const string &g) : Rule( g, 0, "subvar_and") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarAnd(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSubvarSubpiece : public Rule {
public:
  RuleSubvarSubpiece(const string &g) : Rule( g, 0, "subvar_subpiece") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarSubpiece(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSplitFlow : public Rule {
public:
  RuleSplitFlow(const string &g) : Rule( g, 0, "splitflow") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSplitFlow(getGroup());
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

class RuleSubvarCompZero : public Rule {
public:
  RuleSubvarCompZero(const string &g) : Rule( g, 0, "subvar_compzero") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarCompZero(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSubvarShift : public Rule {
public:
  RuleSubvarShift(const string &g) : Rule( g, 0, "subvar_shift") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarShift(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSubvarZext : public Rule {
public:
  RuleSubvarZext(const string &g) : Rule( g, 0, "subvar_zext") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarZext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleSubvarSext : public Rule {
  int4 isaggressive;			///< Is it guaranteed the root is a sub-variable needing to be trimmed
public:
  RuleSubvarSext(const string &g) : Rule( g, 0, "subvar_sext") { isaggressive = false; }	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubvarSext(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  virtual void reset(Funcdata &data);
};

class RuleSubfloatConvert : public Rule {
public:
  RuleSubfloatConvert(const string &g) : Rule( g, 0, "subfloat_convert") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSubfloatConvert(getGroup());
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
  /// \brief Class for categorizing and rebuilding a boolean expression
  class BoolExpress {
    int4 optype;		///< 0=constant 1=unary 2=binary
    OpCode opc;			///< OpCode constructing the boolean value
    PcodeOp *op;		///< PcodeOp constructing the boolean value
    uintb val;			///< Value (if boolean is constant)
    Varnode *in0;		///< First input
    Varnode *in1;		///< Second input
    bool mustreconstruct; 	///< Must make a copy of final boolean operation
  public:
    bool isConstant(void) const { return (optype==0); }	///< Return \b true if boolean is a constant
    uintb getVal(void) const { return val; }		///< Get the constant boolean value
    bool initialize(Varnode *vn);			///< Initialize based on output Varnode
    bool evaluatePropagation(FlowBlock *root,FlowBlock *branch);	///< Can this expression be propagated
    Varnode *constructBool(PcodeOp *insertop,Funcdata &data);	///< Construct the expression after the merge
  };
  static Varnode *constructNegate(Varnode *vn,PcodeOp *op,Funcdata &data);
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
public:
  RuleIgnoreNan(const string &g) : Rule( g, 0, "ignorenan") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleIgnoreNan(getGroup());
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

#endif

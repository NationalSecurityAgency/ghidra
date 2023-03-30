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
#ifndef __UNIONRESOLVE_HH__
#define __UNIONRESOLVE_HH__

#include "op.hh"

namespace ghidra {

/// \brief A data-type \e resolved from an associated TypeUnion or TypeStruct
///
/// A \b parent refers to either:
///   1) A union
///   2) A structure that is an effective union (1 field filling the entire structure) OR
///   3) A pointer to a union/structure
///
/// This object represents a data-type that is resolved via analysis from the \b parent data-type.
/// The resolved data-type can be either:
///   1) A specific field of the parent (if the parent is not a pointer)
///   2) A pointer to a specific field of the underlying union/structure (if the parent is a pointer)
///   3) The parent data-type itself (either a pointer or not)
/// The \b fieldNum (if non-negative) selects a particular field of the underlying union/structure.
/// If the parent is a pointer, the resolution is a pointer to the field.
/// If the parent is not a pointer, the resolution is the field itself.
/// A \b fieldNum of -1 indicates that the parent data-type itself is the resolution.
class ResolvedUnion {
  friend class ScoreUnionFields;
  Datatype *resolve;		///< The resolved data-type
  Datatype *baseType;		///< Union or Structure being resolved
  int4 fieldNum;		///< Index of field referenced by \b resolve
  bool lock;			///< If \b true, resolution cannot be overridden
public:
  ResolvedUnion(Datatype *parent);		///< Construct a data-type that resolves to itself
  ResolvedUnion(Datatype *parent,int4 fldNum,TypeFactory &typegrp);	///< Construct a reference to a field
  Datatype *getDatatype(void) const { return resolve; }		///< Get the resolved data-type
  Datatype *getBase(void) const { return baseType; }		///< Get the union or structure being referenced
  int4 getFieldNum(void) const { return fieldNum; }		///< Get the index of the resolved field or -1
  bool isLocked(void) const { return lock; }	///< Is \b this locked against overrides
  void setLock(bool val) { lock = val; }	///< Set whether \b this resolution is locked against overrides
};

/// \brief A data-flow edge to which a resolved data-type can be assigned
///
/// The edge is associated with the specific data-type that needs to be resolved,
/// which is typically a union or a pointer to a union.  The edge collapses different
/// kinds of pointers to the same base union.
class ResolveEdge {
  uint8 typeId;			///< Id of base data-type being resolved
  uintm opTime;			///< Id of PcodeOp edge
  int4 encoding;		///< Encoding of the slot and pointer-ness
public:
  ResolveEdge(const Datatype *parent,const PcodeOp *op,int4 slot);	///< Construct from components
  bool operator<(const ResolveEdge &op2) const;			///< Compare two edges
};

/// \brief Analyze data-flow to resolve which field of a union data-type is being accessed
///
/// A Varnode with a data-type that is either a union, a pointer to union, or a part of a union, can
/// be accessed in multiple ways.  Each individual read (or write) of the Varnode may be accessing either
/// a specific field of the union or accessing the union as a whole.  The particular access may not be
/// explicitly known but can sometimes be inferred from data-flow near the Varnode.  This class scores
/// all the possible fields of a data-type involving a union for a specific Varnode.
///
/// Because the answer may be different for different accesses, the Varnode must be specified as an
/// access \e edge, a PcodeOp and a \b slot.  A slot >= 0 indicates the index of a Varnode that is being read
/// by the PcodeOp, a slot == -1 indicates the output Varnode being written by the PcodeOp.
///
/// The result of scoring is returned as a ResolvedUnion record.
class ScoreUnionFields {
  /// \brief A trial data-type fitted to a specific place in the data-flow
  class Trial {
    friend class ScoreUnionFields;
    /// \brief An enumerator to distinguish how an individual trial follows data-flow
    enum dir_type {
      fit_down,			///< Only push the fit down \e with the data-flow
      fit_up			///< Only push the fit up \e against the data-flow
    };
    Varnode *vn;		///< The Varnode we are testing for data-type fit
    PcodeOp *op;		///< The PcodeOp reading the Varnode (or null)
    int4 inslot;		///< The slot reading the Varnode (or -1)
    dir_type direction;		///< Direction to push fit.  0=down 1=up
    bool array;			///< Field can be accessed as an array
    Datatype *fitType;		///< The putative data-type of the Varnode
    int4 scoreIndex;		///< The original field being scored by \b this trial
  public:
    /// \brief Construct a downward trial for a Varnode
    ///
    /// \param o is the PcodeOp reading the Varnode
    /// \param slot is the input slot being read
    /// \param ct is the trial data-type to fit
    /// \param index is the scoring index
    /// \param isArray is \b true if the data-type to fit is a pointer to an array
   Trial(PcodeOp *o,int4 slot,Datatype *ct,int4 index,bool isArray) {
      op = o; inslot = slot; direction = fit_down; fitType = ct; scoreIndex = index; vn = o->getIn(slot); array=isArray; }

    /// \brief Construct an upward trial for a Varnode
    ///
    /// \param v is the Varnode to fit
    /// \param ct is the trial data-type to fit
    /// \param index is the scoring index
    /// \param isArray is \b true if the data-type to fit is a pointer to an array
    Trial(Varnode *v,Datatype *ct,int4 index,bool isArray) {
      vn = v; op = (PcodeOp *)0; inslot=-1; direction = fit_up; fitType = ct; scoreIndex = index; array=isArray; }
  };

  /// \brief A mark accumulated when a given Varnode is visited with a specific field index
  class VisitMark {
    Varnode *vn;		///< Varnode reached by trial field
    int4 index;			///< Index of the trial field
  public:
    VisitMark(Varnode *v,int4 i) { vn = v; index = i; }	///< Constructor

    /// \brief Compare two VisitMarks for use in a set container
    ///
    /// \param op2 is the other VisitMark being compared with \b this
    /// \return \b true if \b this should be ordered before \b op2
    bool operator<(const VisitMark &op2) const {
      if (vn != op2.vn)
	return (vn < op2.vn);
      return (index < op2.index);
    }
  };
  TypeFactory &typegrp;		///< The factory containing data-types
  vector<int4> scores;		///< Score for each field, indexed by fieldNum + 1 (whole union is index=0)
  vector<Datatype *> fields;	///< Field corresponding to each score
  set<VisitMark> visited;	///< Places that have already been visited
  list<Trial> trialCurrent;	///< Current trials being pushed
  list<Trial> trialNext;	///< Next set of trials
  ResolvedUnion result;		///< The best result
  int4 trialCount;		///< Number of trials evaluated so far
  static const int4 maxPasses;	///< Maximum number of levels to score through
  static const int4 threshold;	///< Threshold of trials over which to cancel additional passes
  static const int4 maxTrials;		///< Maximum number of trials to evaluate
  bool testArrayArithmetic(PcodeOp *op,int4 inslot);	///< Check if given PcodeOp is operating on array with union elements
  bool testSimpleCases(PcodeOp *op,int4 inslot,Datatype *parent);	///< Preliminary checks before doing full scoring
  int4 scoreLockedType(Datatype *ct,Datatype *lockType);	///< Score trial data-type against a locked data-type
  int4 scoreParameter(Datatype *ct,const PcodeOp *callOp,int4 paramSlot);	///< Score trial data-type against a parameter
  int4 scoreReturnType(Datatype *ct,const PcodeOp *callOp);	///< Score trial data-type against return data-type of function
  Datatype *derefPointer(Datatype *ct,Varnode *vn,int4 &score);	///< Score trial data-type as a pointer to LOAD/STORE
  void newTrialsDown(Varnode *vn,Datatype *ct,int4 scoreIndex,bool isArray);	///< Create new trials based an reads of given Varnode
  void newTrials(PcodeOp *op,int4 slot,Datatype *ct,int4 scoreIndex,bool isArray);	///< Create new trials based on given input slot
  void scoreTrialDown(const Trial &trial,bool lastLevel);	///< Try to fit the given trial following data-flow down
  void scoreTrialUp(const Trial &trial,bool lastLevel);		///< Try to fit the given trial following data-flow up
  Datatype *scoreTruncation(Datatype *ct,Varnode *vn,int4 offset,int4 scoreIndex);	///< Score a truncation in the data-flow
  void scoreConstantFit(const Trial &trial);	///< Score trial data-type against a constant
  void runOneLevel(bool lastPass);	///< Score all the current trials
  void computeBestIndex(void);		///< Assuming scoring is complete, compute the best index
  void run(void);	///< Calculate best fitting field
public:
  ScoreUnionFields(TypeFactory &tgrp,Datatype *parentType,PcodeOp *op,int4 slot);
  ScoreUnionFields(TypeFactory &tgrp,TypeUnion *unionType,int4 offset,PcodeOp *op);
  ScoreUnionFields(TypeFactory &tgrp,TypeUnion *unionType,int4 offset,PcodeOp *op,int4 slot);
  const ResolvedUnion &getResult(void) const { return result; }		///< Get the resulting best field resolution
};

/// Compare based on the data-type, the \b slot, and the PcodeOp's unique id.
/// \param op2 is the other edge to compare with \b this
/// \return \b true if \b this should be ordered before the other edge
inline bool ResolveEdge::operator<(const ResolveEdge &op2) const

{
  if (typeId != op2.typeId)
    return (typeId < op2.typeId);
  if (encoding != op2.encoding)
    return (encoding < op2.encoding);
  return (opTime < op2.opTime);
}

} // End namespace ghidra
#endif

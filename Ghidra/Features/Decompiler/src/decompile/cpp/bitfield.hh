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
/// \file bitfield.hh
/// \brief Classes for transforming bitfield expressions

#ifndef __BITFIELD_HH__
#define __BITFIELD_HH__

#include "ruleaction.hh"

namespace ghidra {

/// \brief Description of the bitfields covered by a Varnode
class BitFieldNodeState {
public:
  BitRange bitsUsed;	///< Bits being used from \b this Varnode
  BitRange bitsField;	///< Bits from bit-field being followed
  Varnode *node;	///< Varnode holding bitfields
  const TypeBitField *field;	///< Bit-field being followed
  int4 origLeastSigBit;	///< Original position of least significant bit
  bool isSignExtended;	///< Bitfield has been sign-extended into node
  BitFieldNodeState(const BitRange &used,Varnode *vn,const TypeBitField *fld);	///< Constructor to follow a field
  BitFieldNodeState(const BitRange &used,Varnode *vn,int4 leastSig,int4 numBits);	///< Constructor for a hole
  BitFieldNodeState(const BitFieldNodeState &copy,const BitRange &newField,Varnode *vn,bool sgnExt);	///< Copy constructor with new \b bitsField
  /// \brief Can the current Varnode be treated as the isolated bitfield
  bool isFieldAligned(void) const { return (bitsField.leastSigBit == 0 && bitsField.numBits == bitsUsed.numBits); }
  /// \brief Return \b true if the signedness of the field matches the extension used to extract it
  bool doesSignExtensionMatch(void) const { return isSignExtended == (field->type->getMetatype() == TYPE_INT); }
};

/// \brief Class for transforming bitfield expressions
///
/// For both insertion and extraction, establish the bitfields that need to be traced.
class BitFieldTransform {
protected:
  Funcdata *func;			///< The containing function
  TypeStruct *parentStruct;		///< Structure owning the bitfields
  list<BitFieldNodeState> workList;	///< Fields that are being followed
  int4 initialOffset;			///< Byte offset into parent structure
  int4 containerSize;			///< Size of Varnode containing bitfields
  bool isBigEndian;			///< Endianness associated with bitfields
  void establishFields(Varnode *vn,bool followHoles);	///< Build worklist for each bitfield overlapped by given Varnode
  Datatype *buildPartialType(void);	///< Build the (partial) data-type associated with the root bitfield container
  static bool findOverwrite(Varnode *vn,BlockBasic *bl,const BitRange &range);
public:
  BitFieldTransform(Funcdata *f,Datatype *dt,int4 off);	///< Constructor setting up basic info about bitfield data-type
};

/// \brief Class that converts bitfield insertion expressions into explicit INSERT operations
///
/// The doTrace() method traces backward from a root Varnode that contains bitfields to find points that
/// can be treated as a value written to an individual bitfield, creating an InsertRecord at each point.
/// If all bits of the Varnode are accounted for, the apply() method transforms expressions based on any InsertRecord.
class BitFieldInsertTransform : public BitFieldTransform {
  /// \brief Info about a Varnode that can be treated as a write to a single bitfield
  class InsertRecord {
    friend class BitFieldInsertTransform;
    Varnode *vn;	///< Value being inserted (or null)
    uintb constVal;	///< Constant value being inserted
    Datatype *dt;	///< Data-type associated with value
    int4 pos;		///< Position being inserted to
    int4 numBits;	///< Number of bits being inserted
    int4 shiftAmount;	///< Amount that value needs to be right shifted
  public:
    InsertRecord(Varnode *v,Datatype *d,int4 p,int4 sz,int4 sa) { vn = v; dt = d; constVal = 0; pos = p; numBits = sz; shiftAmount = sa; }	///< Constructor for Varnode
    InsertRecord(uintb val,Datatype *d,int4 p,int4 sz) { vn = (Varnode *)0; dt = d; constVal = val; pos = p; numBits = sz; shiftAmount = 0; }	///< Constructor for constant
  };
  PcodeOp *finalWriteOp;		///< STORE to bitfields or op outputing to bitfields
  Varnode *originalValue;		///< Value prior to insertion
  Varnode *mappedVn;			///< Bitfield container written to
  list<InsertRecord> insertList;	///< Insertion actions
  bool verifyLoadStoreOriginalValue(uintb mask) const;		///< Test for other STORE ops interfering with the \e original \e value
  bool verifyMappedOriginalValue(uintb mask) const;		///< Test for other ops interfering with the mapped \e original \e value
  uintb constructOriginalValueMask(void) const;			///< Calculate mask where 1 bits represent all the bits being preserved
  bool verifyOriginalValueBits(void) const;			///< Do final check that unINSERTed bits come from the \e original \e value
  bool isOverwrittenPartial(const BitFieldNodeState &state);	///< Is given state a partial field that is overwritten later
  bool checkPulledOriginalValue(BitFieldNodeState &state);	///< Is this an original value defined by ZPULL or SPULL
  bool checkOriginalBase(Varnode *vn);			///< Check if the given Varnode is the original LOAD or mapped value
  bool isOriginalValue(BitFieldNodeState &state);	///< Is the given Varnode a (partial) copy of the original value being INSERTed into
  bool addConstantWrite(BitFieldNodeState &state);	///< Create InsertRecord writing a constant into the field
  bool addZeroOut(BitFieldNodeState &state);		///< Create InsertRecord writing 0 into the field
  void addFieldWrite(BitFieldNodeState &state);		///< Create InsertRecord writing Varnode into the field
  bool handleAndBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through INT_AND with a mask
  bool handleOrBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through one branch of INT_OR
  bool handleAddBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through one branch of INT_AND
  bool handleLeftBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through INT_LEFT by a constant
  bool handleRightBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through INT_SRIGHT by a constant
  bool handleZextBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through INT_ZEXT
  bool handleMultBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through INT_MULT
  bool handleSubpieceBack(BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield back through SUBPIECE
  bool testCallOriginal(BitFieldNodeState &state,PcodeOp *op);	///< Test if a call is producing the \e original \e value
  bool processBackward(BitFieldNodeState &state);		///< Follow field back, creating an InsertRecord if possible
  PcodeOp *setInsertInputs(PcodeOp *op,const InsertRecord &rec);	///< Fill-in INSERT inputs based on given InsertRecord
  void addFieldShift(PcodeOp *insertOp,const InsertRecord &rec);	///< Create any shift p-code op specified by given InsertRecord
  bool foldLoad(PcodeOp *loadOp) const;			///< Try to mark LOAD as part of INSERT
  void foldPtrsub(PcodeOp *loadOp) const;		///< Try to mark PTRSUB as part of INSERT
  void checkRedundancy(const InsertRecord &rec);	///< Check if value is getting INSERTed twice and remove second
public:
  BitFieldInsertTransform(Funcdata *f,PcodeOp *op,Datatype *dt,int4 off);	///< Construct from a terminating op
  bool doTrace(void);		 			///< Trace bitfields backward from the terminating op
  void apply(void);					///< Transform recovered expressions into INSERT operations
};

/// \brief Class that converts bitfield pull expressions into explicit ZPULL and SPULL operations
///
/// The doTrace() method traces forward from a root Varnode that contains bitfields to find points where
/// an individual bitfield has been fully isolated, creating an PullRecord at each point.
/// If all bits of the Varnode are accounted for, the apply() method transforms expressions based on any PullRecord.
class BitFieldPullTransform : public BitFieldTransform {
  /// \brief During final transformation, this is the state maintained between processing individual PullRecords
  class TransformState {
    friend class BitFieldPullTransform;
    vector<PcodeOp *> deadScratch;	///< Scratch space for opDestroyRecursive method
    Datatype *partialType;		///< Partial data-type of the root container
    int4 count;				///< Number of PullRecords processed
  };
  /// \brief Info about a single read by a PcodeOp that can be treated as a \e pull of 1 or more bitfields
  class PullRecord {
    enum {
      normal = 0,			///< A single field pull
      equal = 1,			///< Pull for INT_EQUAL or INT_NOTEQUAL
      aborted = 2			///< Code to indicate that the pull for the entire PcodeOp should be aborted
    };
    friend class BitFieldPullTransform;
    Varnode *readVn;			///< Varnode holding pulled value
    PcodeOp *readOp;			///< Op reading the pulled value, or null if readVn itself is redefined
    Datatype *dt;			///< Data-type associated with the pulled value
    int4 type;				///< Type of pull
    int4 pos;				///< Bit position of field being pulled
    int4 numBits;			///< Number of bits in field being pulled
    int4 leftShift;			///< Amount final field is left shifted
    uintb mask;				///< Mask representing the bitfield within the Varnode
  public:
    PullRecord(const BitFieldNodeState &state,PcodeOp *op);	///< Construct pull record for a specific PcodeOp read
    PullRecord(const BitFieldNodeState &state,PcodeOp *op,uintb val);	///< Construct record for a pull into an INT_EQUAL or INT_NOTEQUAL
    PullRecord(PcodeOp *op);					///< Construct record representing an abort
    bool operator<(const PullRecord &op2) const;		///< Compare records
  };
  Varnode *root;			///< Value being pulled from
  PcodeOp *loadOp;			///< LOAD op producing root (if non-null)
  list<PullRecord> pullList;		///< Pull actions
  static bool testConsumed(Varnode *vn,const BitRange &bitField);	///< Test if all consumed bits are in the given bitfield
  void handleLeftForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through INT_LEFT
  void handleRightForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through INT_RIGHT
  void handleAndForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through INT_AND
  void handleExtForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through INT_ZEXT
  void handleMultForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through INT_MULT
  void handleSubpieceForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through SUBPIECE
  void handleInsertForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward into INSERT
  void handleLessForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield forward through INT_LESS, INT_SLESS
  void handleLeastSigOp(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield into INT_ADD, INT_MULT, INT_OR, INT_XOR
  void handleEqualForward(const BitFieldNodeState &state,PcodeOp *op);	///< Follow bitfield into INT_EQUAL or INT_NOTEQUAL
  void processForward(BitFieldNodeState &state);			///< Follow bitfield forward one level through all its descendants
  list<PullRecord>::iterator testCompareGroup(list<PullRecord>::iterator iter);
  void applyRecord(PullRecord &rec,TransformState &state);		///< Perform transform corresponding to the given PullRecord
  void applyCompareRecord(const PullRecord &rec);			///< Perform transform on an INT_EQUAL or INT_NOTEQUAL
  bool foldLoad(PcodeOp *loadOp) const;					///< Try to mark LOAD as part of ZPULL or SPULL
  void foldPtrsub(PcodeOp *loadOp) const;				///< Try to mark PTRSUB as part of ZPULL or SPULL
public:
  BitFieldPullTransform(Funcdata *f,Varnode *r,Datatype *dt,int4 off);	///< Construct from Varnode containing bitfields
  bool doTrace(void);					///< Trace bitfields from \b root to points where they are pulled
  void apply(void);					///< Transform recovered expressions into ZPULL or SPULL operations
};

/// \brief Collapse bitfield insertion ending in a CPUI_STORE
class RuleBitFieldStore : public Rule {
public:
  RuleBitFieldStore(const string &g) : Rule( g, 0, "bitfield_store") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBitFieldStore(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Collapse bitfield insertion ending in a write to a mapped Varnode
class RuleBitFieldOut : public Rule {
public:
  RuleBitFieldOut(const string &g) : Rule( g, 0, "bitfield_out") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBitFieldOut(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Collapse bitfield pulls starting with a CPUI_LOAD
class RuleBitFieldLoad : public Rule {
public:
  RuleBitFieldLoad(const string &g) : Rule( g, 0, "bitfield_load") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBitFieldLoad(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Collapse bitfield pulls starting with mapped Varnodes
class RuleBitFieldIn : public Rule {
public:
  RuleBitFieldIn(const string &g) : Rule( g, 0, "bitfield_in") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleBitFieldIn(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Simplify expressions explicitly using ZPULL and SPULL p-code ops
class RulePullAbsorb : public Rule {
  int4 absorbRight(Funcdata &data,PcodeOp *rightOp,PcodeOp *pullOp);
  int4 absorbRightAndCompZero(Funcdata &data,PcodeOp *rightOp,PcodeOp *andOp,PcodeOp *pullOp);
  int4 absorbLeft(Funcdata &data,PcodeOp *leftOp,PcodeOp *pullOp);
  int4 absorbLeftRight(Funcdata &data,PcodeOp *rightOp,PcodeOp *leftOp,PcodeOp *pullOp);
  int4 absorbLeftAnd(Funcdata &data,PcodeOp *andOp,PcodeOp *leftOp,PcodeOp *pullOp);
  int4 absorbAnd(Funcdata &data,PcodeOp *andOp,PcodeOp *pullOp);
  int4 absorbCompare(Funcdata &data,PcodeOp *compOp,PcodeOp *leftOp,PcodeOp *pullOp);
  int4 absorbExt(Funcdata &data,PcodeOp *extOp,PcodeOp *pullOp);
  int4 absorbSubpiece(Funcdata &data,PcodeOp *subOp,PcodeOp *pullOp);
  int4 absorbCompZero(Funcdata &data,PcodeOp *compOp,PcodeOp *pullOp);
public:
  RulePullAbsorb(const string &g) : Rule( g, 0, "pull_absorb") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RulePullAbsorb(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Simplify expressions explicitly using the INSERT p-code op
class RuleInsertAbsorb : public Rule {
  static Varnode *leftShiftVarnode(Varnode *vn,int4 sa);	///< Test if a Varnode is left-shifted by the given amount
  int4 absorbAnd(Funcdata &data,PcodeOp *andOp,PcodeOp *insertOp);
  int4 absorbRightLeft(Funcdata &data,PcodeOp *nextOp,PcodeOp *rightOp,PcodeOp *insertOp);
  int4 absorbShiftAdd(Funcdata &data,PcodeOp *rightOp,PcodeOp *addOp,PcodeOp *insertOp);
  int4 absorbNestedAnd(Funcdata &data,PcodeOp *baseOp,PcodeOp *insertOp);
public:
  RuleInsertAbsorb(const string &g) : Rule( g, 0, "insert_absorb") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleInsertAbsorb(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

} // End namespace ghidra
#endif

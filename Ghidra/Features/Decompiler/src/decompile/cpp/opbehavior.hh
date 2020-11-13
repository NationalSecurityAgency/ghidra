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
/// \file opbehavior.hh
/// \brief Classes for describing the behavior of individual p-code operations
#ifndef __CPUI_OPBEHAVIOR__
#define __CPUI_OPBEHAVIOR__

#include "error.hh"
#include "opcodes.hh"

class Translate;		// Forward declaration

/// This exception is thrown when emulation evaluation of an operator fails for some reason.
/// This can be thrown for either forward or reverse emulation
struct EvaluationError : public LowlevelError {
  EvaluationError(const string &s) : LowlevelError(s) {} ///< Initialize the error with an explanatory string
};

/// \brief Class encapsulating the action/behavior of specific pcode opcodes
///
/// At the lowest level, a pcode op is one of a small set of opcodes that
/// operate on varnodes (address space, offset, size). Classes derived from
/// this base class encapsulate this basic behavior for each possible opcode.
/// These classes describe the most basic behaviors and include:
///    * uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb int2)
///    * uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1)
///    * uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in)
///    * uintb recoverInputUnary(int4 sizeout,uintb out,int4 sizein)
class OpBehavior {
  OpCode opcode;		///< the internal enumeration for pcode types
  bool isunary;			///< true= use unary interfaces,  false = use binary
  bool isspecial;		///< Is op not a normal unary or binary op
public:
  OpBehavior(OpCode opc,bool isun); ///< A behavior constructor

  OpBehavior(OpCode opc,bool isun,bool isspec);	///< A special behavior constructor

  virtual ~OpBehavior(void) {}

  /// \brief Get the opcode for this pcode operation
  OpCode getOpcode(void) const;

  /// \brief Check if this is a special operator
  bool isSpecial(void) const;

  /// \brief Check if operator is unary
  bool isUnary(void) const;

  /// \brief Emulate the unary op-code on an input value
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
  
  /// \brief Emulate the binary op-code on input values
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  
  /// \brief Reverse the binary op-code operation, recovering an input value
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
  
  /// \brief Reverse the unary op-code operation, recovering the input value
  virtual uintb recoverInputUnary(int4 sizeout,uintb out,int4 sizein) const;

  static void registerInstructions(vector<OpBehavior *> &inst,const Translate *trans); ///< Build all pcode behaviors
};

/// This kind of OpBehavior is associated with a particular opcode and is either unary or binary
/// \param opc is the opcode of the behavior
/// \param isun is \b true if the behavior is unary, \b false if binary
inline OpBehavior::OpBehavior(OpCode opc,bool isun)

{
  opcode = opc;
  isunary = isun;
  isspecial = false;
}

/// This kind of OpBehavior can be set to \b special, if it neither unary or binary.
/// \param opc is the opcode of the behavior
/// \param isun is \b true if the behavior is unary
/// \param isspec is \b true if the behavior is neither unary or binary
inline OpBehavior::OpBehavior(OpCode opc,bool isun,bool isspec)

{
  opcode = opc;
  isunary = isun;
  isspecial = isspec;
}

/// There is an internal enumeration value for each type of pcode operation.
/// This routine returns that value.
/// \return the opcode value
inline OpCode OpBehavior::getOpcode(void) const {
  return opcode;
}

/// If this function returns false, the operation is a normal unary or binary operation
/// which can be evaluated calling evaluateBinary() or evaluateUnary().
/// Otherwise, the operation requires special handling to emulate properly
inline bool OpBehavior::isSpecial(void) const {
  return isspecial;
}

/// The operated can either be evaluated as unary or binary
/// \return \b true if the operator is unary
inline bool OpBehavior::isUnary(void) const {
  return isunary;
}

// A class for each opcode

/// CPUI_COPY behavior
class OpBehaviorCopy : public OpBehavior {
public:
  OpBehaviorCopy(void) : OpBehavior(CPUI_COPY,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
  virtual uintb recoverInputUnary(int4 sizeout,uintb out,int4 sizein) const;
};

/// CPUI_INT_EQUAL behavior
class OpBehaviorEqual : public OpBehavior {
public:
  OpBehaviorEqual(void) : OpBehavior(CPUI_INT_EQUAL,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_NOTEQUAL behavior
class OpBehaviorNotEqual : public OpBehavior {
public:
  OpBehaviorNotEqual(void) : OpBehavior(CPUI_INT_NOTEQUAL,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_SLESS behavior
class OpBehaviorIntSless : public OpBehavior {
public:
  OpBehaviorIntSless(void) : OpBehavior(CPUI_INT_SLESS,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_SLESSEQUAL behavior
class OpBehaviorIntSlessEqual : public OpBehavior {
public:
  OpBehaviorIntSlessEqual(void) : OpBehavior(CPUI_INT_SLESSEQUAL,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_LESS behavior
class OpBehaviorIntLess : public OpBehavior {
public:
  OpBehaviorIntLess(void) : OpBehavior(CPUI_INT_LESS,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_LESSEQUAL behavior
class OpBehaviorIntLessEqual : public OpBehavior {
public:
  OpBehaviorIntLessEqual(void): OpBehavior(CPUI_INT_LESSEQUAL,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_ZEXT behavior
class OpBehaviorIntZext : public OpBehavior {
public:
  OpBehaviorIntZext(void): OpBehavior(CPUI_INT_ZEXT,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
  virtual uintb recoverInputUnary(int4 sizeout,uintb out,int4 sizein) const;
};

/// CPUI_INT_SEXT behavior
class OpBehaviorIntSext : public OpBehavior {
public:
  OpBehaviorIntSext(void): OpBehavior(CPUI_INT_SEXT,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
  virtual uintb recoverInputUnary(int4 sizeout,uintb out,int4 sizein) const;
};

/// CPUI_INT_ADD behavior
class OpBehaviorIntAdd : public OpBehavior {
public:
  OpBehaviorIntAdd(void): OpBehavior(CPUI_INT_ADD,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
};

/// CPUI_INT_SUB behavior
class OpBehaviorIntSub : public OpBehavior {
public:
  OpBehaviorIntSub(void): OpBehavior(CPUI_INT_SUB,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
};

/// CPUI_INT_CARRY behavior
class OpBehaviorIntCarry : public OpBehavior {
public:
  OpBehaviorIntCarry(void): OpBehavior(CPUI_INT_CARRY,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_SCARRY behavior
class OpBehaviorIntScarry : public OpBehavior {
public:
  OpBehaviorIntScarry(void): OpBehavior(CPUI_INT_SCARRY,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_SBORROW behavior
class OpBehaviorIntSborrow : public OpBehavior {
public:
  OpBehaviorIntSborrow(void): OpBehavior(CPUI_INT_SBORROW,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_2COMP behavior
class OpBehaviorInt2Comp : public OpBehavior {
public:
  OpBehaviorInt2Comp(void): OpBehavior(CPUI_INT_2COMP,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_INT_NEGATE behavior
class OpBehaviorIntNegate : public OpBehavior {
public:
  OpBehaviorIntNegate(void): OpBehavior(CPUI_INT_NEGATE,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_INT_XOR behavior
class OpBehaviorIntXor : public OpBehavior {
public:
  OpBehaviorIntXor(void): OpBehavior(CPUI_INT_XOR,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_AND behavior
class OpBehaviorIntAnd : public OpBehavior {
public:
  OpBehaviorIntAnd(void): OpBehavior(CPUI_INT_AND,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_OR behavior
class OpBehaviorIntOr : public OpBehavior {
public:
  OpBehaviorIntOr(void): OpBehavior(CPUI_INT_OR,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_LEFT behavior
class OpBehaviorIntLeft : public OpBehavior {
public:
  OpBehaviorIntLeft(void): OpBehavior(CPUI_INT_LEFT,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
};

/// CPUI_INT_RIGHT behavior
class OpBehaviorIntRight : public OpBehavior {
public:
  OpBehaviorIntRight(void): OpBehavior(CPUI_INT_RIGHT,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
};

/// CPUI_INT_SRIGHT behavior
class OpBehaviorIntSright : public OpBehavior {
public:
  OpBehaviorIntSright(void): OpBehavior(CPUI_INT_SRIGHT,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
};

/// CPUI_INT_MULT behavior
class OpBehaviorIntMult : public OpBehavior {
public:
  OpBehaviorIntMult(void): OpBehavior(CPUI_INT_MULT,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_DIV behavior
class OpBehaviorIntDiv : public OpBehavior {
public:
  OpBehaviorIntDiv(void): OpBehavior(CPUI_INT_DIV,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_SDIV behavior
class OpBehaviorIntSdiv : public OpBehavior {
public:
  OpBehaviorIntSdiv(void): OpBehavior(CPUI_INT_SDIV,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_REM behavior
class OpBehaviorIntRem : public OpBehavior {
public:
  OpBehaviorIntRem(void): OpBehavior(CPUI_INT_REM,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_INT_SREM behavior
class OpBehaviorIntSrem : public OpBehavior {
public:
  OpBehaviorIntSrem(void): OpBehavior(CPUI_INT_SREM,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_BOOL_NEGATE behavior
class OpBehaviorBoolNegate : public OpBehavior {
public:
  OpBehaviorBoolNegate(void): OpBehavior(CPUI_BOOL_NEGATE,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_BOOL_XOR behavior
class OpBehaviorBoolXor : public OpBehavior {
public:
  OpBehaviorBoolXor(void): OpBehavior(CPUI_BOOL_XOR,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_BOOL_AND behavior
class OpBehaviorBoolAnd : public OpBehavior {
public:
  OpBehaviorBoolAnd(void): OpBehavior(CPUI_BOOL_AND,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_BOOL_OR behavior
class OpBehaviorBoolOr : public OpBehavior {
public:
  OpBehaviorBoolOr(void): OpBehavior(CPUI_BOOL_OR,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_EQUAL behavior
class OpBehaviorFloatEqual : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatEqual(const Translate *trans): OpBehavior(CPUI_FLOAT_EQUAL,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_NOTEQUAL behavior
class OpBehaviorFloatNotEqual : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatNotEqual(const Translate *trans): OpBehavior(CPUI_FLOAT_NOTEQUAL,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_LESS behavior
class OpBehaviorFloatLess : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatLess(const Translate *trans) : OpBehavior(CPUI_FLOAT_LESS,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_LESSEQUAL behavior
class OpBehaviorFloatLessEqual : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatLessEqual(const Translate *trans) : OpBehavior(CPUI_FLOAT_LESSEQUAL,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_NAN behavior
class OpBehaviorFloatNan : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatNan(const Translate *trans) : OpBehavior(CPUI_FLOAT_NAN,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_ADD behavior
class OpBehaviorFloatAdd : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatAdd(const Translate *trans) : OpBehavior(CPUI_FLOAT_ADD,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_DIV behavior
class OpBehaviorFloatDiv : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatDiv(const Translate *trans) : OpBehavior(CPUI_FLOAT_DIV,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_MULT behavior
class OpBehaviorFloatMult : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatMult(const Translate *trans) : OpBehavior(CPUI_FLOAT_MULT,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_SUB behavior
class OpBehaviorFloatSub : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatSub(const Translate *trans) : OpBehavior(CPUI_FLOAT_SUB,false) { translate = trans; }	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_FLOAT_NEG behavior
class OpBehaviorFloatNeg : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatNeg(const Translate *trans) : OpBehavior(CPUI_FLOAT_NEG,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_ABS behavior
class OpBehaviorFloatAbs : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatAbs(const Translate *trans) : OpBehavior(CPUI_FLOAT_ABS,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_SQRT behavior
class OpBehaviorFloatSqrt : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatSqrt(const Translate *trans) : OpBehavior(CPUI_FLOAT_SQRT,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_INT2FLOAT behavior
class OpBehaviorFloatInt2Float : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatInt2Float(const Translate *trans) : OpBehavior(CPUI_FLOAT_INT2FLOAT,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_FLOAT2FLOAT behavior
class OpBehaviorFloatFloat2Float : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatFloat2Float(const Translate *trans) : OpBehavior(CPUI_FLOAT_FLOAT2FLOAT,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_TRUNC behavior
class OpBehaviorFloatTrunc : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatTrunc(const Translate *trans) : OpBehavior(CPUI_FLOAT_TRUNC,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_CEIL behavior
class OpBehaviorFloatCeil : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatCeil(const Translate *trans) : OpBehavior(CPUI_FLOAT_CEIL,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_FLOOR behavior
class OpBehaviorFloatFloor : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatFloor(const Translate *trans) : OpBehavior(CPUI_FLOAT_FLOOR,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_FLOAT_ROUND behavior
class OpBehaviorFloatRound : public OpBehavior {
  const Translate *translate;	///< Translate object for recovering float format
public:
  OpBehaviorFloatRound(const Translate *trans) : OpBehavior(CPUI_FLOAT_ROUND,true) { translate = trans; }	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

/// CPUI_PIECE behavior
class OpBehaviorPiece : public OpBehavior {
public:
  OpBehaviorPiece(void) : OpBehavior(CPUI_PIECE,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_SUBPIECE behavior
class OpBehaviorSubpiece : public OpBehavior {
public:
  OpBehaviorSubpiece(void) : OpBehavior(CPUI_SUBPIECE,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
};

/// CPUI_POPCOUNT behavior
class OpBehaviorPopcount : public OpBehavior {
public:
  OpBehaviorPopcount(void) : OpBehavior(CPUI_POPCOUNT,true) {}	///< Constructor
  virtual uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const;
};

#endif

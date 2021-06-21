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
/// \file typeop.hh
/// \brief Data-type and behavior information associated with specific p-code op-codes.

#ifndef __CPUI_TYPEOP__
#define __CPUI_TYPEOP__

#include "cpool.hh"
#include "variable.hh"
#include "opbehavior.hh"
#include "printlanguage.hh"

class PcodeOp;
class Translate;

/// \brief Associate data-type and behavior information with a specific p-code op-code.
///
/// This holds all information about a p-code op-code. The main PcodeOp object holds this
/// as a representative of the op-code.  The evaluate* methods can be used to let the op-code
/// act on constant input values. The getOutput* and getInput* methods are used to obtain
/// data-type information that is specific to the op-code. This also holds other PcodeOp
/// boolean properties that are set in common for the op-code.
class TypeOp {
public:
  enum {
    inherits_sign = 1,		///< Operator token inherits signedness from its inputs
    inherits_sign_zero = 2	///< Only inherits sign from first operand, not the second
  };
protected:
  TypeFactory *tlst;		///< Pointer to data-type factory
  OpCode opcode;		///< The op-code value
  uint4 opflags;		///< Cached pcode-op properties for this op-code
  uint4 addlflags;		///< Additional properties
  string name;			///< Symbol denoting this operation
  OpBehavior *behave;		///< Object for emulating the behavior of the op-code
  virtual void setMetatypeIn(type_metatype val) {}	///< Set the data-type associated with inputs to this opcode
  virtual void setMetatypeOut(type_metatype val) {}	///< Set the data-type associated with outputs of this opcode
  virtual void setSymbol(const string &nm) { name = nm; }	///< Set the display symbol associated with the op-code
public:
  TypeOp(TypeFactory *t,OpCode opc,const string &n);	///< Constructor
  virtual ~TypeOp(void);				///< Destructor
  const string &getName(void) const { return name; }	///< Get the display name of the op-code
  OpCode getOpcode(void) const { return opcode; }	///< Get the op-code value
  uint4 getFlags(void) const { return opflags; }	///< Get the properties associated with the op-code
  OpBehavior *getBehavior(void) const { return behave; }	///< Get the behavior associated with the op-code
  bool markExplicitUnsigned(PcodeOp *op,int4 slot) const;	///< Check if a constant input should be explicitly labeled as \e unsigned

  /// \brief Emulate the unary op-code on an input value
  ///
  /// \param sizeout is the size of the output in bytes
  /// \param sizein is the size of the input in bytes
  /// \param in1 is the input value
  /// \return the output value
  uintb evaluateUnary(int4 sizeout,int4 sizein,uintb in1) const {
    return behave->evaluateUnary(sizeout,sizein,in1); }

  /// \brief Emulate the binary op-code on an input value
  ///
  /// \param sizeout is the size of the output in bytes
  /// \param sizein is the size of the inputs in bytes
  /// \param in1 is the first input value
  /// \param in2 is the second input value
  /// \return the output value
  uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const {
    return behave->evaluateBinary(sizeout,sizein,in1,in2); }

  /// \brief Reverse the binary op-code operation, recovering a constant input value
  ///
  /// If the output value and one of the input values is known, recover the value
  /// of the other input.
  /// \param slot is the input slot to recover
  /// \param sizeout is the size of the output in bytes
  /// \param out is the output value
  /// \param sizein is the size of the inputs in bytes
  /// \param in is the known input value
  /// \return the input value corresponding to the \b slot
  uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const {
    return behave->recoverInputBinary(slot,sizeout,out,sizein,in); }

  /// \brief Reverse the unary op-code operation, recovering a constant input value
  ///
  /// If the output value is known, recover the input value.
  /// \param sizeout is the size of the output in bytes
  /// \param out is the output value
  /// \param sizein is the size of the input in bytes
  /// \return the input value
  uintb recoverInputUnary(int4 sizeout,uintb out,int4 sizein) const {
    return behave->recoverInputUnary(sizeout,out,sizein); }

  bool isCommutative(void) const;		///< Return \b true if this op-code is commutative

  /// \brief Return \b true if the op-code inherits it signedness from its inputs
  bool inheritsSign(void) const { return ((addlflags & inherits_sign)!=0); }

  /// \brief Find the minimal (or suggested) data-type of an output to \b this op-code
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;

  /// \brief Find the minimal (or suggested) data-type of an input to \b this op-code
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;

  /// \brief Find the data-type of the output that would be assigned by a compiler
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;

  /// \brief Find the data-type of the input to a specific PcodeOp
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;

  /// \brief Push the specific PcodeOp to the emitter's RPN stack
  ///
  /// Given a specific language and PcodeOp, emit the expression rooted at the operation.
  /// \param lng is the PrintLanguage to emit
  /// \param op is the specific PcodeOp
  /// \param readOp is the PcodeOp consuming the output (or null)
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const=0;

  /// \brief Print (for debugging purposes) \b this specific PcodeOp to the stream
  ///
  /// \param s is the output stream
  /// \param op is the specific PcodeOp to print
  virtual void printRaw(ostream &s,const PcodeOp *op)=0;

  /// \brief Get the name of the op-code as it should be displayed in context.
  ///
  /// Depending on the context, the same op-code may get displayed in different ways.
  /// \param op is the PcodeOp context
  /// \return the display token
  virtual string getOperatorName(const PcodeOp *op) const { return name; }

  /// \brief Build a map from op-code value to the TypeOp information objects
  static void registerInstructions(vector<TypeOp *> &inst,TypeFactory *tlst,
				   const Translate *trans);

  /// \brief Toggle Java specific aspects of the op-code information
  static void selectJavaOperators(vector<TypeOp *> &inst,bool val);
};

// Major classes of operations

/// \brief A generic binary operator: two inputs and one output
///
/// All binary op-codes have a single data-type for input values
/// and a data-type for the output value
class TypeOpBinary : public TypeOp {
  type_metatype metaout;	///< The metatype of the output
  type_metatype metain;		///< The metatype of the inputs
  virtual void setMetatypeIn(type_metatype val) { metain = val; }
  virtual void setMetatypeOut(type_metatype val) { metaout = val; }
public:
  TypeOpBinary(TypeFactory *t,OpCode opc,const string &n,type_metatype mout,type_metatype min)
    : TypeOp(t,opc,n) { metaout = mout; metain = min; }	///< Constructor
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief A generic unary operator: one input and one output
///
/// All unary op-codes have data-type for the input value and a
/// data-type for the output value
class TypeOpUnary : public TypeOp {
  type_metatype metaout;	///< The metatype of the output
  type_metatype metain;		///< The metatype of the input
  virtual void setMetatypeIn(type_metatype val) { metain = val; }
  virtual void setMetatypeOut(type_metatype val) { metaout = val; }
public:
  TypeOpUnary(TypeFactory *t,OpCode opc,const string &n,type_metatype mout,type_metatype min)
    : TypeOp(t,opc,n) { metaout = mout; metain = min; }	///< Constructor
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief A generic functional operator.
///
/// The operator takes one or more inputs (with the same data-type by default)
/// and produces one output with  specific data-type
class TypeOpFunc : public TypeOp {
  type_metatype metaout;	///< The metatype of the output
  type_metatype metain;		///< The metatype of the inputs
  virtual void setMetatypeIn(type_metatype val) { metain = val; }
  virtual void setMetatypeOut(type_metatype val) { metaout = val; }
public:
  TypeOpFunc(TypeFactory *t,OpCode opc,const string &n,type_metatype mout,type_metatype min)
    : TypeOp(t,opc,n) { metaout = mout; metain = min; }		///< Constructor
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

// A class for each op-code

/// \brief Information about the COPY op-code
class TypeOpCopy : public TypeOp {
public:
  TypeOpCopy(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCopy(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the LOAD op-code
class TypeOpLoad : public TypeOp {
public:
  TypeOpLoad(TypeFactory *t);			///< Constructor
  //  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opLoad(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the STORE op-code
class TypeOpStore : public TypeOp {
public:
  TypeOpStore(TypeFactory *t);			///< Constructor
  //  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opStore(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the BRANCH op-code
class TypeOpBranch : public TypeOp {
public:
  TypeOpBranch(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opBranch(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the CBRANCH op-code
class TypeOpCbranch : public TypeOp {
public:
  TypeOpCbranch(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCbranch(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the BRANCHIND op-code
class TypeOpBranchind : public TypeOp {
public:
  TypeOpBranchind(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opBranchind(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the CALL op-code
class TypeOpCall : public TypeOp {
public:
  TypeOpCall(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCall(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
};

/// \brief Information about the CALLIND op-code
class TypeOpCallind : public TypeOp {
public:
  TypeOpCallind(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCallind(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
};

/// \brief Information about the CALLOTHER op-code (user defined p-code operations)
class TypeOpCallother : public TypeOp {
public:
  TypeOpCallother(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCallother(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
};

/// \brief Information about the RETURN op-code
class TypeOpReturn : public TypeOp {
public:
  TypeOpReturn(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opReturn(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
};

/// \brief Information about the INT_EQUAL op-code
class TypeOpEqual : public TypeOpBinary {
public:
  TypeOpEqual(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntEqual(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_NOTEQUAL op-code
class TypeOpNotEqual : public TypeOpBinary {
public:
  TypeOpNotEqual(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntNotEqual(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SLESS op-code
class TypeOpIntSless : public TypeOpBinary {
public:
  TypeOpIntSless(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSless(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SLESSEQUAL op-code
class TypeOpIntSlessEqual : public TypeOpBinary {
public:
  TypeOpIntSlessEqual(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSlessEqual(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_LESS op-code
class TypeOpIntLess : public TypeOpBinary {
public:
  TypeOpIntLess(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntLess(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_LESSEQUAL op-code
class TypeOpIntLessEqual : public TypeOpBinary {
public:
  TypeOpIntLessEqual(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntLessEqual(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_ZEXT op-code
class TypeOpIntZext : public TypeOpFunc {
public:
  TypeOpIntZext(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntZext(op,readOp); }
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SEXT op-code
class TypeOpIntSext : public TypeOpFunc {
public:
  TypeOpIntSext(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSext(op,readOp); }
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_ADD op-code
class TypeOpIntAdd : public TypeOpBinary {
public:
  TypeOpIntAdd(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntAdd(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SUB op-code
class TypeOpIntSub : public TypeOpBinary {
public:
  TypeOpIntSub(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSub(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_CARRY op-code
class TypeOpIntCarry : public TypeOpFunc {
public:
  TypeOpIntCarry(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntCarry(op); }
  virtual string getOperatorName(const PcodeOp *op) const;
};

/// \brief Information about the INT_SCARRY op-code
class TypeOpIntScarry : public TypeOpFunc {
public:
  TypeOpIntScarry(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntScarry(op); }
  virtual string getOperatorName(const PcodeOp *op) const;
};

/// \brief Information about the INT_SBORROW op-code
class TypeOpIntSborrow : public TypeOpFunc {
public:
  TypeOpIntSborrow(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSborrow(op); }
  virtual string getOperatorName(const PcodeOp *op) const;
};

/// \brief Information about the INT_2COMP op-code
class TypeOpInt2Comp : public TypeOpUnary {
public:
  TypeOpInt2Comp(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opInt2Comp(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_NEGATE op-code
class TypeOpIntNegate : public TypeOpUnary {
public:
  TypeOpIntNegate(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntNegate(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_XOR op-code
class TypeOpIntXor : public TypeOpBinary {
public:
  TypeOpIntXor(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntXor(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_AND op-code
class TypeOpIntAnd : public TypeOpBinary {
public:
  TypeOpIntAnd(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntAnd(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_OR op-code
class TypeOpIntOr : public TypeOpBinary {
public:
  TypeOpIntOr(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntOr(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_LEFT op-code
class TypeOpIntLeft : public TypeOpBinary {
public:
  TypeOpIntLeft(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntLeft(op); }
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_RIGHT op-code
class TypeOpIntRight : public TypeOpBinary {
public:
  TypeOpIntRight(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntRight(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SRIGHT op-code
class TypeOpIntSright : public TypeOpBinary {
public:
  TypeOpIntSright(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSright(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_MULT op-code
class TypeOpIntMult : public TypeOpBinary {
public:
  TypeOpIntMult(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntMult(op); }
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_DIV op-code
class TypeOpIntDiv : public TypeOpBinary {
public:
  TypeOpIntDiv(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntDiv(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SDIV op-code
class TypeOpIntSdiv : public TypeOpBinary {
public:
  TypeOpIntSdiv(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSdiv(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_REM op-code
class TypeOpIntRem : public TypeOpBinary {
public:
  TypeOpIntRem(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntRem(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the INT_SREM op-code
class TypeOpIntSrem : public TypeOpBinary {
public:
  TypeOpIntSrem(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIntSrem(op); }
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
};

/// \brief Information about the BOOL_NEGATE op-code
class TypeOpBoolNegate : public TypeOpUnary {
public:
  TypeOpBoolNegate(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opBoolNegate(op); }
};
  
/// \brief Information about the BOOL_XOR op-code
class TypeOpBoolXor : public TypeOpBinary {
public:
  TypeOpBoolXor(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opBoolXor(op); }
};
  
/// \brief Information about the BOOL_AND op-code
class TypeOpBoolAnd : public TypeOpBinary {
public:
  TypeOpBoolAnd(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opBoolAnd(op); }
};
  
/// \brief Information about the BOOL_OR op-code
class TypeOpBoolOr : public TypeOpBinary {
public:
  TypeOpBoolOr(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opBoolOr(op); }
};
  
/// \brief Information about the FLOAT_EQUAL op-code
class TypeOpFloatEqual : public TypeOpBinary {
public:
  TypeOpFloatEqual(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatEqual(op); }
};
  
/// \brief Information about the FLOAT_NOTEQUAL op-code
class TypeOpFloatNotEqual : public TypeOpBinary {
public:
  TypeOpFloatNotEqual(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatNotEqual(op); }
};
  
/// \brief Information about the FLOAT_LESS op-code
class TypeOpFloatLess : public TypeOpBinary {
public:
  TypeOpFloatLess(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatLess(op); }
};
  
/// \brief Information about the FLOAT_LESSEQUAL op-code
class TypeOpFloatLessEqual : public TypeOpBinary {
public:
  TypeOpFloatLessEqual(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatLessEqual(op); }
};
  
/// \brief Information about the FLOAT_NAN op-code
class TypeOpFloatNan : public TypeOpFunc {
public:
  TypeOpFloatNan(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatNan(op); }
};

/// \brief Information about the FLOAT_ADD op-code
class TypeOpFloatAdd : public TypeOpBinary {
public:
  TypeOpFloatAdd(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatAdd(op); }
};
  
/// \brief Information about the FLOAT_DIV op-code
class TypeOpFloatDiv : public TypeOpBinary {
public:
  TypeOpFloatDiv(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatDiv(op); }
};

/// \brief Information about the FLOAT_MULT op-code
class TypeOpFloatMult : public TypeOpBinary {
public:
  TypeOpFloatMult(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatMult(op); }
};
  
/// \brief Information about the FLOAT_SUB op-code
class TypeOpFloatSub : public TypeOpBinary {
public:
  TypeOpFloatSub(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatSub(op); }
};
  
/// \brief Information about the FLOAT_NEG op-code
class TypeOpFloatNeg : public TypeOpUnary {
public:
  TypeOpFloatNeg(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatNeg(op); }
};

/// \brief Information about the FLOAT_ABS op-code
class TypeOpFloatAbs : public TypeOpFunc {
public:
  TypeOpFloatAbs(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatAbs(op); }
};

/// \brief Information about the FLOAT_SQRT op-code
class TypeOpFloatSqrt : public TypeOpFunc {
public:
  TypeOpFloatSqrt(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatSqrt(op); }
};

/// \brief Information about the FLOAT_INT2FLOAT op-code
class TypeOpFloatInt2Float : public TypeOpFunc {
public:
  TypeOpFloatInt2Float(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatInt2Float(op); }
};

/// \brief Information about the FLOAT_FLOAT2FLOAT op-code
class TypeOpFloatFloat2Float : public TypeOpFunc {
public:
  TypeOpFloatFloat2Float(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatFloat2Float(op); }
};

/// \brief Information about the FLOAT_TRUNC op-code
class TypeOpFloatTrunc : public TypeOpFunc {
public:
  TypeOpFloatTrunc(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatTrunc(op); }
};

/// \brief Information about the FLOAT_CEIL op-code
class TypeOpFloatCeil : public TypeOpFunc {
public:
  TypeOpFloatCeil(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatCeil(op); }
};

/// \brief Information about the FLOAT_FLOOR op-code
class TypeOpFloatFloor : public TypeOpFunc {
public:
  TypeOpFloatFloor(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatFloor(op); }
};

/// \brief Information about the FLOAT_ROUND op-code
class TypeOpFloatRound : public TypeOpFunc {
public:
  TypeOpFloatRound(TypeFactory *t,const Translate *trans);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opFloatRound(op); }
};

/// \brief Information about the MULTIEQUAL op-code
class TypeOpMulti : public TypeOp {
public:
  TypeOpMulti(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opMultiequal(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the INDIRECT op-code
class TypeOpIndirect : public TypeOp {
public:
  TypeOpIndirect(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opIndirect(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the PIECE op-code
class TypeOpPiece : public TypeOpFunc {
public:
  TypeOpPiece(TypeFactory *t);			///< Constructor
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opPiece(op); }
};

/// \brief Information about the SUBPIECE op-code
class TypeOpSubpiece : public TypeOpFunc {
public:
  TypeOpSubpiece(TypeFactory *t);			///< Constructor
  //  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  //  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opSubpiece(op); }
};

/// \brief Information about the CAST op-code
class TypeOpCast : public TypeOp {
public:
  TypeOpCast(TypeFactory *t);			///< Constructor
				// We don't care what types are cast
				// So no input and output requirements
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCast(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};
  
/// \brief Information about the PTRADD op-code
class TypeOpPtradd : public TypeOp {
public:
  TypeOpPtradd(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opPtradd(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the PTRSUB op-code
class TypeOpPtrsub : public TypeOp {
public:
  TypeOpPtrsub(TypeFactory *t);			///< Constructor
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opPtrsub(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the SEGMENTOP op-code
///
/// The segment operator is a placeholder for address mappings
/// (i.e. from virtual to physical) that a compiler (or processor)
/// may generate as part of its memory model. Typically this is
/// of little concern to the high-level code, so this scheme allows
/// the decompiler to track it but ignore it where appropriate,
/// such as in type propagation and printing high-level expressions
class TypeOpSegment : public TypeOp {
public:
  TypeOpSegment(TypeFactory *t);			///< Constructor
  //  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  //  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const;
  virtual Datatype *getOutputToken(const PcodeOp *op,CastStrategy *castStrategy) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opSegmentOp(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the CPOOLREF op-code
class TypeOpCpoolref : public TypeOp {
  ConstantPool *cpool;					///< The constant pool container
public:
  TypeOpCpoolref(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const { return (Datatype *)0; }  // Never needs casting
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opCpoolRefOp(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the NEW op-code
class TypeOpNew : public TypeOp {
public:
  TypeOpNew(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const { return (Datatype *)0; }  // Never needs casting
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opNewOp(op); }
  virtual void printRaw(ostream &s,const PcodeOp *op);
};

/// \brief Information about the INSERT op-code
class TypeOpInsert : public TypeOpFunc {
public:
  TypeOpInsert(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opInsertOp(op); }
};

/// \brief Information about the EXTRACT op-code
class TypeOpExtract : public TypeOpFunc {
public:
  TypeOpExtract(TypeFactory *t);			///< Constructor
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opExtractOp(op); }
};

/// \brief Information about the POPCOUNT op-code
class TypeOpPopcount : public TypeOpFunc {
public:
  TypeOpPopcount(TypeFactory *t);			///< Constructor
  virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const { lng->opPopcountOp(op); }
};

#endif

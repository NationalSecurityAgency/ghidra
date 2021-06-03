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
/// \file cast.hh
/// \brief API and specific strategies for applying type casts

#ifndef __CPUI_CAST__
#define __CPUI_CAST__

#include "type.hh"

class Varnode;
class PcodeOp;

/// \brief A strategy for applying type casts
///
/// A \e cast operation in C or other languages masks a variety of possible low-level conversions,
/// such as extensions, truncations, integer to floating-point, etc. On top of this, languages allow
/// many of these types of operations to be \e implied in the source code, with no explicit token
/// representing the conversion.  Conversions happen automatically for things like \e integer \e promotion,
/// between different sizes (of integers), and between signed and unsigned data-type variants.
///
/// This class is the API for making four kinds of decisions:
///   - Do we need a cast operator for a given assignment
///   - Does the given conversion operation need to be represented as a cast
///   - Does the given extension or comparison match with the expected level of integer promotion
///   - What data-type is produced by a particular integer arithmetic operation
class CastStrategy {
public:
  /// \brief Types of integer promotion
  ///
  /// For many languages, small integers are automatically \e promoted to a standard size. The decompiler
  /// describes how an expression is or will be affected by integer promotion, using these codes
  enum IntPromotionCode {
    NO_PROMOTION = -1,			///< There is no integer promotion
    UNKNOWN_PROMOTION = 0,		///< The type of integer promotion cannot be determined
    UNSIGNED_EXTENSION = 1,		///< The value is promoted using unsigned extension
    SIGNED_EXTENSION = 2,		///< The value is promoted using signed extension
    EITHER_EXTENSION = 3		///< The value is promoted using either signed or unsigned extension
  };
protected:
  TypeFactory *tlst;			///< Type factory associated with the Architecture
  int4 promoteSize;			///< Size of \b int data-type, (size that integers get promoted to)
public:
  CastStrategy(void) {}			///< Constructor
  void setTypeFactory(TypeFactory *t);	///< Establish the data-type factory
  virtual ~CastStrategy(void) {}	///< Destructor

  /// \brief Decide on integer promotion by examining just local properties of the given Varnode
  ///
  /// \param vn is the given Varnode
  /// \return an IntPromotionCode (excluding NO_PROMOTION)
  virtual int4 localExtensionType(const Varnode *vn) const=0;

  /// \brief Calculate the integer promotion code of a given Varnode
  ///
  /// Recursively examine the expression defining the Varnode as necessary
  /// \param vn is the given Varnode
  /// \return the IntPromotionCode
  virtual int4 intPromotionType(const Varnode *vn) const=0;

  /// \brief Check if integer promotion forces a cast for the given comparison op and slot
  ///
  /// Compute to what level the given slot has seen integer promotion and if
  /// a cast is required before the comparison operator makes sense.
  /// \param op is the given comparison operator
  /// \param slot is the input slot being tested
  /// \return \b true if a cast is required before comparing
  virtual bool checkIntPromotionForCompare(const PcodeOp *op,int4 slot) const=0;

  /// \brief Check if integer promotion forces a cast for the input to the given extension.
  ///
  /// Compute to what level the given slot has seen integer promotion and if
  /// a cast is required before the extension operator makes sense.
  /// \param op is the given extension operator INT_ZEXT or INT_SEXT
  /// \return \b true if a cast is required before extending
  virtual bool checkIntPromotionForExtension(const PcodeOp *op) const=0;


  /// \brief Is the given ZEXT/SEXT cast implied by the expression its in?
  ///
  /// We've already determined that the given ZEXT or SEXT op can be viewed as a natural \e cast operation.
  /// Determine if the cast is implied by the expression its and doesn't need to be printed.
  /// \param op is the given ZEXT or SEXT PcodeOp
  /// \param readOp is the PcodeOp consuming the output of the extensions (or null)
  /// \return \b true if the op as a cast does not need to be printed
  virtual bool isExtensionCastImplied(const PcodeOp *op,const PcodeOp *readOp) const=0;

  /// \brief Does there need to be a visible cast between the given data-types
  ///
  /// The cast is from a \e current data-type to an \e expected data-type. NULL is returned
  /// if no cast is required, otherwise the data-type to cast to (usually the expected data-type)
  /// is returned.
  /// \param reqtype is the \e expected data-type
  /// \param curtype is the \e current data-type
  /// \param care_uint_int is \b true if we care about a change in signedness
  /// \param care_ptr_uint is \b true if we care about conversions between pointers and unsigned values
  /// \return NULL to indicate no cast, or the data-type to cast to
  virtual Datatype *castStandard(Datatype *reqtype,Datatype *curtype,bool care_uint_int,bool care_ptr_uint) const=0;

  /// \brief What is the output data-type produced by the given integer arithmetic operation
  ///
  /// \param op is the given operation
  /// \return the output data-type
  virtual Datatype *arithmeticOutputStandard(const PcodeOp *op)=0;

  /// \brief Is truncating an input data-type, producing an output data-type, considered a cast
  ///
  /// Data-types must be provided from the input and output of a SUBPIECE operation.
  /// \param outtype is the output data-type
  /// \param intype is the input data-type
  /// \param offset is number of bytes truncated by the SUBPIECE
  /// \return \b true if the SUBPIECE should be represented as a cast
  virtual bool isSubpieceCast(Datatype *outtype,Datatype *intype,uint4 offset) const=0;

  /// \brief Is the given data-type truncation considered a cast, given endianess concerns.
  ///
  /// This is equivalent to isSubpieceCast() but where the truncation is accomplished by pulling
  /// bytes directly out of memory.  We assume the input data-type is layed down in memory, and
  /// we pull the output value starting at a given byte offset.
  /// \param outtype is the output data-type
  /// \param intype is the input data-type
  /// \param offset is the given byte offset (into the input memory)
  /// \param isbigend is \b true if the address space holding the memory is big endian.
  /// \return \b true if the truncation should be represented as a cast
  virtual bool isSubpieceCastEndian(Datatype *outtype,Datatype *intype,uint4 offset,bool isbigend) const=0;

  /// \brief Is sign-extending an input data-type, producing an output data-type, considered a cast
  ///
  /// Data-types must be provided from the input and output of an INT_SEXT operation.
  /// \param outtype is the output data-type
  /// \param intype is the input data-type
  /// \return \b true if the INT_SEXT should be represented as a cast
  virtual bool isSextCast(Datatype *outtype,Datatype *intype) const=0;

  /// \brief Is zero-extending an input data-type, producing an output data-type, considered a cast
  ///
  /// Data-types must be provided from the input and output of an INT_ZEXT operation.
  /// \param outtype is the output data-type
  /// \param intype is the input data-type
  /// \return \b true if the INT_ZEXT should be represented as a cast
  virtual bool isZextCast(Datatype *outtype,Datatype *intype) const=0;
};

/// \brief Casting strategies that are specific to the C language
class CastStrategyC : public CastStrategy {
public:
  virtual int4 localExtensionType(const Varnode *vn) const;
  virtual int4 intPromotionType(const Varnode *vn) const;
  virtual bool checkIntPromotionForCompare(const PcodeOp *op,int4 slot) const;
  virtual bool checkIntPromotionForExtension(const PcodeOp *op) const;
  virtual bool isExtensionCastImplied(const PcodeOp *op,const PcodeOp *readOp) const;
  virtual Datatype *castStandard(Datatype *reqtype,Datatype *curtype,bool care_uint_int,bool care_ptr_uint) const;
  virtual Datatype *arithmeticOutputStandard(const PcodeOp *op);
  virtual bool isSubpieceCast(Datatype *outtype,Datatype *intype,uint4 offset) const;
  virtual bool isSubpieceCastEndian(Datatype *outtype,Datatype *intype,uint4 offset,bool isbigend) const;
  virtual bool isSextCast(Datatype *outtype,Datatype *intype) const;
  virtual bool isZextCast(Datatype *outtype,Datatype *intype) const;
};

/// \brief Casting strategies that are specific to the Java language
///
/// This is nearly identical to the strategy for C, but there is some change to account
/// for the way object references are encoded as pointer data-types within the
/// decompiler's data-type system.
class CastStrategyJava : public CastStrategyC {
public:
  virtual Datatype *castStandard(Datatype *reqtype,Datatype *curtype,bool care_uint_int,bool care_ptr_uint) const;
  virtual bool isZextCast(Datatype *outtype,Datatype *intype) const;
};

#endif

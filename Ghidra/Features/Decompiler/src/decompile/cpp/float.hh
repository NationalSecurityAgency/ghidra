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
/// \file float.hh
/// \brief Support for decoding different floating-point formats

#ifndef __FLOAT_HH__
#define __FLOAT_HH__

#include "xml.hh"

namespace ghidra {

/// \brief Encoding information for a single floating-point format
///
/// This class supports manipulation of a single floating-point encoding.
/// An encoding can be converted to and from the host format and
/// convenience methods allow p-code floating-point operations to be
/// performed on natively encoded operands.  This follows the IEEE754 standards.
class FloatFormat {
public:
  /// \brief The various classes of floating-point encodings
  enum floatclass {
    normalized = 0,		///< A normal floating-point number
    infinity = 1,		///< An encoding representing an infinite value
    zero = 2,			///< An encoding of the value zero
    nan = 3,			///< An invalid encoding, Not-a-Number
    denormalized = 4		///< A denormalized encoding (for very small values)
  };
private:
  int4 size;			///< Size of float in bytes (this format)
  int4 signbit_pos;		///< Bit position of sign bit
  int4 frac_pos;		///< (lowest) bit position of fractional part
  int4 frac_size;		///< Number of bits in fractional part
  int4 exp_pos;			///< (lowest) bit position of exponent
  int4 exp_size;		///< Number of bits in exponent
  int4 bias;			///< What to add to real exponent to get encoding
  int4 maxexponent;		///< Maximum possible exponent
  int4 decimal_precision;	///< Number of decimal digits of precision
  bool jbitimplied;		///< Set to \b true if integer bit of 1 is assumed
  static double createFloat(bool sign,uintb signif,int4 exp);	 ///< Create a double given sign, fractional, and exponent
  static floatclass extractExpSig(double x,bool *sgn,uintb *signif,int4 *exp);
  static bool roundToNearestEven(uintb &signif, int4 lowbitpos);
  uintb setFractionalCode(uintb x,uintb code) const;		///< Set the fractional part of an encoded value
  uintb setSign(uintb x,bool sign) const;			///< Set the sign bit of an encoded value
  uintb setExponentCode(uintb x,uintb code) const;		///< Set the exponent of an encoded value
  uintb getZeroEncoding(bool sgn) const;			///< Get an encoded zero value
  uintb getInfinityEncoding(bool sgn) const;			///< Get an encoded infinite value
  uintb getNaNEncoding(bool sgn) const;				///< Get an encoded NaN value
  void calcPrecision(void);					///< Calculate the decimal precision of this format
public:
  FloatFormat(void) {}	///< Construct for use with restoreXml()
  FloatFormat(int4 sz);	///< Construct default IEEE 754 standard settings
  int4 getSize(void) const { return size; }			///< Get the size of the encoding in bytes
  double getHostFloat(uintb encoding,floatclass *type) const;	///< Convert an encoding into host's double
  uintb getEncoding(double host) const;				///< Convert host's double into \b this encoding
  int4 getDecimalPrecision(void) const { return decimal_precision; }	///< Get number of digits of precision
  uintb convertEncoding(uintb encoding,const FloatFormat *formin) const;	///< Convert between two different formats

  uintb extractFractionalCode(uintb x) const;			///< Extract the fractional part of the encoding
  bool extractSign(uintb x) const;				///< Extract the sign bit from the encoding
  int4 extractExponentCode(uintb x) const;			///< Extract the exponent from the encoding

  // Operations on floating point values

  uintb opEqual(uintb a,uintb b) const;			///< Equality comparison (==)
  uintb opNotEqual(uintb a,uintb b) const;		///< Inequality comparison (!=)
  uintb opLess(uintb a,uintb b) const;			///< Less-than comparison (<)
  uintb opLessEqual(uintb a,uintb b) const;		///< Less-than-or-equal comparison (<=)
  uintb opNan(uintb a) const;				///< Test if Not-a-Number (NaN)
  uintb opAdd(uintb a,uintb b) const;			///< Addition (+)
  uintb opDiv(uintb a,uintb b) const;			///< Division (/)
  uintb opMult(uintb a,uintb b) const;			///< Multiplication (*)
  uintb opSub(uintb a,uintb b) const;			///< Subtraction (-)
  uintb opNeg(uintb a) const;				///< Unary negate
  uintb opAbs(uintb a) const;				///< Absolute value (abs)
  uintb opSqrt(uintb a) const;				///< Square root (sqrt)
  uintb opTrunc(uintb a,int4 sizeout) const;		///< Convert floating-point to integer
  uintb opCeil(uintb a) const;				///< Ceiling (ceil)
  uintb opFloor(uintb a) const;				///< Floor (floor)
  uintb opRound(uintb a) const;				///< Round
  uintb opInt2Float(uintb a,int4 sizein) const;		///< Convert integer to floating-point
  uintb opFloat2Float(uintb a,const FloatFormat &outformat) const;	///< Convert between floating-point precisions

  void saveXml(ostream &s) const;			///< Save the format to an XML stream
  void restoreXml(const Element *el);			///< Restore the format from XML
};

} // End namespace ghidra
#endif

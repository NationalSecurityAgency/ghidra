/* ###
 * IP: GHIDRA
 * NOTE: uses some windows and sparc specific floating point definitions
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
#include "float.hh"
#include "address.hh"

#include <cmath>
#include <limits>

namespace ghidra {

using std::ldexp;
using std::frexp;
using std::signbit;
using std::sqrt;
using std::floor;
using std::ceil;
using std::round;
using std::fabs;

/// Set format for a given encoding size according to IEEE 754 standards
/// \param sz is the size of the encoding in bytes
FloatFormat::FloatFormat(int4 sz)

{
  size = sz;

  if (size == 4) {
    signbit_pos = 31;
    exp_pos = 23;
    exp_size = 8;
    frac_pos = 0;
    frac_size = 23;
    bias = 127;
    jbitimplied = true;
  }
  else if (size == 8) {
    signbit_pos = 63;
    exp_pos = 52;
    exp_size = 11;
    frac_pos = 0;
    frac_size = 52;
    bias = 1023;
    jbitimplied = true;
  }
  maxexponent = (1<<exp_size)-1;
  calcPrecision();
}

/// \param sign is set to \b true if the value should be negative
/// \param signif is the fractional part
/// \param exp is the exponent
/// \return the constructed floating-point value
double FloatFormat::createFloat(bool sign,uintb signif,int4 exp)

{
  signif >>= 1;		      // Throw away 1 bit of precision we will
				// lose anyway, to make sure highbit is 0
  int4 precis = 8*sizeof(uintb) - 1;   // fullword - 1 we threw away
  double res = (double)signif;
  int4 expchange = exp - precis + 1; // change in exponent is precis
				// -1 integer bit
  res = ldexp(res,expchange);
  if (sign)
    res = res * -1.0;
  return res;
}

/// \brief Extract the sign, fractional, and exponent from a given floating-point value
///
/// \param x is the given value
/// \param sgn passes back the sign
/// \param signif passes back the fractional part
/// \param exp passes back the exponent
/// \return the floating-point class of the value
FloatFormat::floatclass FloatFormat::extractExpSig(double x,bool *sgn,uintb *signif,int4 *exp)

{
  int4 e;

  *sgn = signbit(x);
  if (x == 0.0) return zero;
  if (std::isinf(x)) return infinity;
  if (std::isnan(x)) return nan;
  if (*sgn)
    x = -x;
  double norm = frexp(x,&e);  // norm is between 1/2 and 1
  norm = ldexp(norm,8*sizeof(uintb)-1); // norm between 2^62 and 2^63
					   
  *signif = (uintb)norm;    // Convert to normalized integer
  *signif <<= 1;

  e -= 1;    // Consider normalization between 1 and 2  
  *exp = e;
  return normalized;
}

/// \param x is an encoded floating-point value
/// \return the fraction part of the value aligned to the top of the word
uintb FloatFormat::extractFractionalCode(uintb x) const

{
  x >>= frac_pos;		// Eliminate bits below
  x <<= 8*sizeof(uintb) - frac_size; // Align with top of word
  return x;
}

/// \param x is an encoded floating-point value
/// \return the sign bit
bool FloatFormat::extractSign(uintb x) const

{
  x >>= signbit_pos;
  return ((x&1)!=0);
}

/// \param x is an encoded floating-point value
/// \return the (signed) exponent
int4 FloatFormat::extractExponentCode(uintb x) const

{
  x >>= exp_pos;
  uintb mask = 1;
  mask = (mask<<exp_size) - 1;
  return (int4)(x & mask);
}

/// \param x is an encoded value (with fraction part set to zero)
/// \param code is the new fractional value to set
/// \return the encoded value with the fractional filled in
uintb FloatFormat::setFractionalCode(uintb x,uintb code) const

{
  // Align with bottom of word, also drops bits of precision
  // we don't have room for
  code >>= 8*sizeof(uintb) - frac_size;
  code <<= frac_pos;		// Move bits into position;
  x |= code;
  return x;
}

/// \param x is an encoded value (with sign set to zero)
/// \param sign is the sign bit to set
/// \return the encoded value with the sign bit set
uintb FloatFormat::setSign(uintb x,bool sign) const

{
  if (!sign) return x;		// Assume bit is already zero
  uintb mask = 1;
  mask <<= signbit_pos;
  x |= mask;			// Stick in the bit
  return x;
}

/// \param x is an encoded value (with exponent set to zero)
/// \param code is the exponent to set
/// \return the encoded value with the new exponent
uintb FloatFormat::setExponentCode(uintb x,uintb code) const

{
  code <<= exp_pos;		// Move bits into position
  x |= code;
  return x;
}

/// \param sgn is set to \b true for negative zero, \b false for positive
/// \return the encoded zero
uintb FloatFormat::getZeroEncoding(bool sgn) const

{
  uintb res = 0;
  // Use IEEE 754 standard for zero encoding
  res = setFractionalCode(res,0);
  res = setExponentCode(res,0);
  return setSign(res,sgn);
}

/// \param sgn is set to \b true for negative infinity, \b false for positive
/// \return the encoded infinity
uintb FloatFormat::getInfinityEncoding(bool sgn) const

{
  uintb res = 0;
  // Use IEEE 754 standard for infinity encoding
  res = setFractionalCode(res,0);
  res = setExponentCode(res,(uintb)maxexponent);
  return setSign(res,sgn);
}

/// \param sgn is set to \b true for negative NaN, \b false for positive
/// \return the encoded NaN
uintb FloatFormat::getNaNEncoding(bool sgn) const

{
  uintb res = 0;
  // Use IEEE 754 standard for NaN encoding
  uintb mask = 1;
  mask <<= 8*sizeof(uintb)-1;	// Create "quiet" NaN
  res = setFractionalCode(res,mask);
  res = setExponentCode(res,(uintb)maxexponent);
  return setSign(res,sgn);
}

void FloatFormat::calcPrecision(void)

{
  float val = frac_size * 0.30103;
  decimal_precision = (int4)floor(val + 0.5);
}

/// \param encoding is the encoding value
/// \param type points to the floating-point class, which is passed back
/// \return the equivalent double value
double FloatFormat::getHostFloat(uintb encoding,floatclass *type) const

{
  bool sgn = extractSign(encoding);
  uintb frac = extractFractionalCode(encoding);
  int4 exp = extractExponentCode(encoding);
  bool normal = true;

  if (exp == 0) {
    if ( frac == 0 ) {		// Floating point zero
      *type = zero;
      return sgn ? -0.0 : +0.0;
    }
    *type = denormalized;
    // Number is denormalized
    normal = false;
  }
  else if (exp == maxexponent) {
    if ( frac == 0 ) {		// Floating point infinity
      *type = infinity;
      double infinity = std::numeric_limits<double>::infinity();
      return sgn ? -infinity : +infinity;
    }
    *type = nan;
    // encoding is "Not a Number" NaN
    double nan = std::numeric_limits<double>::quiet_NaN();
    return sgn ? -nan : +nan; // Sign is usually ignored
  }
  else
    *type = normalized;

  // Get "true" exponent and fractional
  exp -= bias;
  if (normal && jbitimplied) {
    frac >>= 1;			// Make room for 1 jbit
    uintb highbit = 1;
    highbit <<= 8*sizeof(uintb)-1;
    frac |= highbit;		// Stick bit in at top
  }
  return createFloat(sgn,frac,exp);
}

/// \brief Round a floating point value to the nearest even
///
/// \param signif the significant bits of a floating point value
/// \param lowbitpos the position in signif of the floating point
/// \return true if we rounded up

bool FloatFormat::roundToNearestEven(uintb &signif, int4 lowbitpos)

{
  uintb lowbitmask = (lowbitpos < 8 * sizeof(uintb)) ? ((uintb)1 << lowbitpos) : 0;
  uintb midbitmask = (uintb)1 << (lowbitpos - 1);
  uintb epsmask = midbitmask - 1;
  bool odd = (signif & lowbitmask) != 0;
  if ((signif & midbitmask) != 0 && ((signif & epsmask) != 0 || odd)) {
    signif += midbitmask;
    return true;
  }
  return false;
}


/// \param host is the double value to convert
/// \return the equivalent encoded value
uintb FloatFormat::getEncoding(double host) const

{
  floatclass type;
  bool sgn;
  uintb signif;
  int4 exp;

  type = extractExpSig(host, &sgn, &signif, &exp);
  if (type == zero)
    return getZeroEncoding(sgn);
  else if (type == infinity)
    return getInfinityEncoding(sgn);
  else if (type == nan)
    return getNaNEncoding(sgn);

  // convert exponent and fractional to their encodings
  exp += bias;

  if (exp < -frac_size)	// Exponent is too small to represent
    return getZeroEncoding(sgn); // TODO handle round to non-zero

  if (exp < 1) {	// Must be denormalized
    if (roundToNearestEven(signif, 8 * sizeof(uintb) - frac_size - exp)) {
      // TODO handle round to normal case
      if ((signif >> (8 * sizeof(uintb) - 1)) == 0) {
	signif = (uintb)1 << (8 * sizeof(uintb) - 1);
	exp += 1;
      }
    }
    uintb res = getZeroEncoding(sgn);
    return setFractionalCode(res, signif >> (-exp));
  }

  if (roundToNearestEven(signif, 8 * sizeof(uintb) - frac_size - 1)) {
    // if high bit is clear, then the add overflowed. Increase exp and set
    // signif to 1.
    if ((signif >> (8 * sizeof(uintb) - 1)) == 0) {
      signif = (uintb)1 << (8 * sizeof(uintb) - 1);
      exp += 1;
    }
  }

  if (exp >= maxexponent)	// Exponent is too big to represent
    return getInfinityEncoding(sgn);

  if (jbitimplied && (exp != 0))
    signif <<= 1;		// Cut off top bit (which should be 1)

  uintb res = 0;
  res = setFractionalCode(res, signif);
  res = setExponentCode(res, (uintb)exp);
  return setSign(res, sgn);
}


/// \param encoding is the value in the \e other FloatFormat
/// \param formin is the \e other FloatFormat
/// \return the equivalent value in \b this FloatFormat
uintb FloatFormat::convertEncoding(uintb encoding,
				   const FloatFormat *formin) const

{
  bool sgn = formin->extractSign(encoding);
  uintb signif = formin->extractFractionalCode(encoding);
  int4 exp = formin->extractExponentCode(encoding);

  if (exp == formin->maxexponent) { // NaN or INFINITY encoding
    exp = maxexponent;
    if (signif != 0)
      return getNaNEncoding(sgn);
    else
      return getInfinityEncoding(sgn);
  }

  if (exp == 0) { // incoming is subnormal
    if (signif == 0)
      return getZeroEncoding(sgn);

    // normalize
    int4 lz = count_leading_zeros(signif);
    signif <<= lz;
    exp = -formin->bias - lz;
  }
  else { // incoming is normal
    exp -= formin->bias;
    if (jbitimplied)
      signif = ((uintb)1 << (8 * sizeof(uintb) - 1)) | (signif >> 1);
  }

  exp += bias;

  if (exp < -frac_size)	// Exponent is too small to represent
    return getZeroEncoding(sgn); // TODO handle round to non-zero

  if (exp < 1) {	// Must be denormalized
    if (roundToNearestEven(signif, 8 * sizeof(uintb) - frac_size - exp)) {
      // TODO handle carry to normal case
      if ((signif >> (8 * sizeof(uintb) - 1)) == 0) {
	signif = (uintb)1 << (8 * sizeof(uintb) - 1);
	exp += 1;
      }
    }
    uintb res = getZeroEncoding(sgn);
    return setFractionalCode(res, signif >> (-exp));
  }

  if (roundToNearestEven(signif, 8 * sizeof(uintb) - frac_size - 1)) {
    // if high bit is clear, then the add overflowed. Increase exp and set
    // signif to 1.
    if ((signif >> (8 * sizeof(uintb) - 1)) == 0) {
      signif = (uintb)1 << (8 * sizeof(uintb) - 1);
      exp += 1;
    }
  }

  if (exp >= maxexponent)	// Exponent is too big to represent
    return getInfinityEncoding(sgn);

  if (jbitimplied && (exp != 0))
    signif <<= 1;		// Cut off top bit (which should be 1)

  uintb res = 0;
  res = setFractionalCode(res, signif);
  res = setExponentCode(res, (uintb)exp);
  return setSign(res, sgn);
}

// Currently we emulate floating point operations on the target
// By converting the encoding to the host's encoding and then
// performing the operation using the host's floating point unit
// then the host's encoding is converted back to the targets encoding

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a == b)
uintb FloatFormat::opEqual(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  uintb res = (val1 == val2) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a != b)
uintb FloatFormat::opNotEqual(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  uintb res = (val1 != val2) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a < b)
uintb FloatFormat::opLess(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  uintb res = (val1 < val2) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a <= b)
uintb FloatFormat::opLessEqual(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  uintb res = (val1 <= val2) ? 1 : 0;
  return res;
}

/// \param a is an encoded floating-point value
/// \return \b true if a is Not-a-Number
uintb FloatFormat::opNan(uintb a) const

{
  floatclass type;
  getHostFloat(a,&type);
  uintb res = (type == FloatFormat::nan) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a + b
uintb FloatFormat::opAdd(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  return getEncoding(val1 + val2);
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a / b
uintb FloatFormat::opDiv(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  return getEncoding(val1 / val2);
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a * b
uintb FloatFormat::opMult(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  return getEncoding(val1 * val2);
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a - b
uintb FloatFormat::opSub(uintb a,uintb b) const

{
  floatclass type;
  double val1 = getHostFloat(a,&type);
  double val2 = getHostFloat(b,&type);
  return getEncoding(val1 - val2);
}

/// \param a is an encoded floating-point value
/// \return -a
uintb FloatFormat::opNeg(uintb a) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  return getEncoding(-val);
}

/// \param a is an encoded floating-point value
/// \return abs(a)
uintb FloatFormat::opAbs(uintb a) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  return getEncoding(fabs(val));
}

/// \param a is an encoded floating-point value
/// \return sqrt(a)
uintb FloatFormat::opSqrt(uintb a) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  return getEncoding(sqrt(val));
}

/// \param a is a signed integer value
/// \param sizein is the number of bytes in the integer encoding
/// \return a converted to an encoded floating-point value
uintb FloatFormat::opInt2Float(uintb a,int4 sizein) const

{
  intb ival = sign_extend(a,8*sizein-1);
  double val = (double) ival;	// Convert integer to float
  return getEncoding(val);
}

/// \param a is an encoded floating-point value
/// \param outformat is the desired output FloatFormat
/// \return a converted to the output FloatFormat
uintb FloatFormat::opFloat2Float(uintb a,const FloatFormat &outformat) const

{
  return outformat.convertEncoding(a, this);
}

/// \param a is an encoded floating-point value
/// \param sizeout is the desired encoding size of the output
/// \return an integer encoding of a
uintb FloatFormat::opTrunc(uintb a,int4 sizeout) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  intb ival = (intb) val;	// Convert to integer
  uintb res = (uintb) ival;	// Convert to unsigned
  res &= calc_mask(sizeout);	// Truncate to proper size
  return res;
}

/// \param a is an encoded floating-point value
/// \return ceil(a)
uintb FloatFormat::opCeil(uintb a) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  return getEncoding(ceil(val));
}

/// \param a is an encoded floating-point value
/// \return floor(a)
uintb FloatFormat::opFloor(uintb a) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  return getEncoding(floor(val));
}

/// \param a is an encoded floating-point value
/// \return round(a)
uintb FloatFormat::opRound(uintb a) const

{
  floatclass type;
  double val = getHostFloat(a,&type);
  // return getEncoding(floor(val+.5)); // round half up
  return getEncoding(round(val)); // round half away from zero
}

/// Write the format out to a \<floatformat> XML tag.
/// \param s is the output stream
void FloatFormat::saveXml(ostream &s) const

{
  s << "<floatformat";
  a_v_i(s,"size",size);
  a_v_i(s,"signpos",signbit_pos);
  a_v_i(s,"fracpos",frac_pos);
  a_v_i(s,"fracsize",frac_size);
  a_v_i(s,"exppos",exp_pos);
  a_v_i(s,"expsize",exp_size);
  a_v_i(s,"bias",bias);
  a_v_b(s,"jbitimplied",jbitimplied);
  s << "/>\n";
}

/// Restore \b object from a \<floatformat> XML tag
/// \param el is the element
void FloatFormat::restoreXml(const Element *el)

{
  {
    istringstream s(el->getAttributeValue("size"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> size;
  }
  {
    istringstream s(el->getAttributeValue("signpos"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> signbit_pos;
  }
  {
    istringstream s(el->getAttributeValue("fracpos"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> frac_pos;
  }
  {
    istringstream s(el->getAttributeValue("fracsize"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> frac_size;
  }
  {
    istringstream s(el->getAttributeValue("exppos"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> exp_pos;
  }
  {
    istringstream s(el->getAttributeValue("expsize"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> exp_size;
  }
  {
    istringstream s(el->getAttributeValue("bias"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> bias;
  }
  jbitimplied = xml_readbool(el->getAttributeValue("jbitimplied"));
  maxexponent = (1<<exp_size)-1;
  calcPrecision();
}

} // End namespace ghidra

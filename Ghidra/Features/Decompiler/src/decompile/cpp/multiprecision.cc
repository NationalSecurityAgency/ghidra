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
#include "multiprecision.hh"

namespace ghidra {

extern int4 count_leading_zeros(uintb val);		///< Return the number of leading zero bits in the given value

/// \brief Multi-precision logical left shift by a constant amount
///
/// \b in and \b out arrays are specified and can point to the same storage.
/// \param num is the number 64-bit words in the extended precision integers
/// \param in is the 128-bit value to shift
/// \param out is the container for the 128-bit result
/// \param sa is the number of bits to shift
static void leftshift(int4 num,uint8 *in,uint8 *out,int4 sa)

{
  int4 inIndex = num - 1 - sa / 64;
  sa = sa % 64;
  int4 outIndex = num - 1;
  if (sa == 0) {
    for(;inIndex>=0;--inIndex) {
      out[outIndex--] = in[inIndex];
    }
    for(;outIndex>=0;--outIndex) {
      out[outIndex] = 0;
    }
  }
  else {
    for(;inIndex>0;--inIndex) {
      out[outIndex--] = (in[inIndex] << sa) | (in[inIndex-1] >> (64-sa));
    }
    out[outIndex--] = in[0] << sa;
    for(;outIndex>=0;--outIndex) {
      out[outIndex] = 0;
    }
  }
}

/// \param in is the 128-bit input (as 2 64-bit words)
/// \param out will hold the 128-bit result
/// \param sa is the number of bits to shift
void leftshift128(uint8 *in,uint8 *out,int4 sa)

{
  leftshift(2,in,out,sa);
}

/// \brief Compare two multi-precision unsigned integers
///
/// -1, 0, or 1 is returned depending on if the first integer is less than, equal to, or greater than
/// the second integer.
/// \param num is the number 64-bit words in the extended precision integers
/// \param in1 is the first integer to compare
/// \param in2 is the second integer to compare
/// \return -1, 0, or 1
static inline int4 ucompare(int4 num,uint8 *in1,uint8 *in2)

{
  for(int4 i=num-1;i>=0;--i) {
    if (in1[i] != in2[i])
      return (in1[i] < in2[i]) ? -1 : 1;
  }
  return 0;
}

/// \param in1 is the first 128-bit value (as 2 64-bit words) to compare
/// \param in2 is the second 128-bit value
/// \return \b true if the first value is less than the second value
bool uless128(uint8 *in1,uint8 *in2)

{
  return ucompare(2,in1,in2) < 0;
}

/// \param in1 is the first 128-bit value (as 2 64-bit words) to compare
/// \param in2 is the second 128-bit value
/// \return \b true if the first value is less than or equal to the second value
bool ulessequal128(uint8 *in1,uint8 *in2)

{
  return ucompare(2,in1,in2) <= 0;
}

/// \brief Multi-precision add operation
///
/// \param num is the number 64-bit words in the extended precision integers
/// \param in1 is the first integer
/// \param in2 is the integer added to the first
/// \param out is where the add result is stored
static inline void add(int4 num,uint8 *in1,uint8 *in2,uint8 *out)

{
  uint8 carry = 0;
  for(int4 i=0;i<num;++i) {
    uint8 tmp = in2[i] + carry;
    uint8 tmp2 = in1[i] + tmp;
    out[i] = tmp2;
    carry = (tmp < in2[i] || tmp2 < tmp) ? 1 : 0;
  }
}

/// \param in1 is the first 128-bit value (as 2 64-bit words) to add
/// \param in2 is the second 128-bit value to add
/// \param out will hold the 128-bit result
void add128(uint8 *in1,uint8 *in2,uint8 *out)

{
  add(2,in1,in2,out);
}

/// \brief Multi-precision subtract operation
///
/// \param num is the number 64-bit words in the extended precision integers
/// \param in1 is the first integer
/// \param in2 is the integer subtracted from the first
/// \param out is where the subtraction result is stored
static inline void subtract(int4 num,uint8 *in1,uint8 *in2,uint8 *out)

{
  uint8 borrow = 0;
  for(int4 i=0;i<num;++i) {
    uint8 tmp = in2[i] + borrow;
    borrow = (tmp < in2[i] || in1[i] < tmp) ? 1: 0;
    out[i] = in1[i] - tmp;
  }
}

/// \param in1 is the first 128-bit value (as 2 64-bit words)
/// \param in2 is the second 128-bit value to subtract
/// \param out will hold the 128-bit result
void subtract128(uint8 *in1,uint8 *in2,uint8 *out)

{
  subtract(2,in1,in2,out);
}

/// \brief Split an array of 64-bit words into an array of 32-bit words
///
/// The arrays must already be allocated.  The least significant half of each 64-bit word is put
/// into the 32-bit word array first.  The index of the most significant non-zero 32-bit word is
/// calculated and returned as the \e effective size of the resulting array.
/// \param num is the number of 64-bit words to split
/// \param val is the array of 64-bit words
/// \param res is the array that will hold the 32-bit words
/// \return the effective size of the 32-bit word array
static int4 split64_32(int4 num,uint8 *val,uint4 *res)

{
  int4 m = 0;
  for(int4 i=0;i<num;++i) {
    uint4 hi = val[i] >> 32;
    uint4 lo = val[i] & 0xffffffff;
    if (hi != 0)
      m = i*2 + 2;
    else if (lo != 0)
      m = i*2 + 1;
    res[i*2] = lo;
    res[i*2+1] = hi;
  }
  return m;
}

/// \brief Pack an array of 32-bit words into an array of 64-bit words
///
/// The arrays must already be allocated.  The 64-bit word array is padded out with zeroes if
/// the specified size exceeds the provided number of 32-bit words.
/// \param num is the number of 64-bit words in the resulting array
/// \param max is the number of 32-bit words to pack
/// \param out is the array of 64-bit words
/// \param in is the array of 32-bit words
static void pack32_64(int4 num,int4 max,uint8 *out,uint4 *in)

{
  int4 j = num * 2 - 1;
  for(int4 i=num-1;i>=0;--i) {
    uint8 val;
    val = (j<max) ? in[j] : 0;
    val <<= 32;
    j -= 1;
    if (j < max)
      val |= in[j];
    j -= 1;
    out[i] = val;
  }
}

/// \brief Logical shift left for an extended integer in 32-bit word arrays
///
/// \param arr is the array of 32-bit words
/// \param size is the number of words in the array
/// \param sa is the number of bits to shift
static void shift_left(uint4 *arr,int4 size,int4 sa)

{
  if (sa == 0) return;
  for (int4 i = size - 1; i > 0; --i)
    arr[i] = (arr[i] << sa) | (arr[i-1] >> (32-sa));
  arr[0] = arr[0] << sa;
}

/// \brief Logical shift right for an extended integer in 32-bit word arrays
///
/// \param arr is the array of 32-bit words
/// \param size is the number of words in the array
/// \param sa is the number of bits to shift
static void shift_right(uint4 *arr,int4 size,int4 sa)

{
  if (sa == 0) return;
  for(int4 i=0;i<size-1;++i)
    arr[i] = (arr[i] >> sa) | (arr[i+1] << (32-sa));
  arr[size-1] = arr[size -1] >> sa;
}

/// \brief Knuth's algorithm d, for integer division
///
/// The numerator and denominator, expressed in 32-bit \e digits, are provided.
/// The algorithm calculates the quotient and the remainder is left in the array originally
/// containing the numerator.
/// \param m is the number of 32-bit digits in the numerator
/// \param n is the number of 32-bit digits in the denominator
/// \param u is the numerator and will hold the remainder
/// \param v is the denominator
/// \param q will hold the final quotient
static void knuth_algorithm_d(int4 m,int4 n,uint4 *u,uint4 *v,uint4 *q)

{
  int4 s = count_leading_zeros(v[n-1]) - 8*(sizeof(uintb)-sizeof(uint4));
  shift_left(v,n,s);
  shift_left(u,m,s);

  for(int4 j=m-n-1;j>=0;--j) {
    uint8 tmp = ((uint8)u[n+j] << 32) + u[n-1+j];
    uint8 qhat = tmp / v[n-1];
    uint8 rhat = tmp % v[n-1];
    do {
      if (qhat <= 0xffffffff && qhat * v[n-2] <= (rhat << 32) + u[n-2+j])
	break;
      qhat -= 1;
      rhat += v[n-1];
    } while(rhat <= 0xffffffff);

    uint8 carry = 0;
    int8 t;
    for (int4 i=0;i<n;++i) {
      tmp = qhat*v[i];
      t = u[i+j] - carry - (tmp & 0xffffffff);
      u[i+j] = t;
      carry = (tmp >> 32) - (t >> 32);
    }
    t = u[j+n] - carry;
    u[j+n] = t;

    q[j] = qhat;
    if (t < 0) {
      q[j] -= 1;
      carry = 0;
      for(int4 i=0;i<n;++i) {
	tmp = u[i+j] + (v[i] + carry);
	u[i+j] = tmp;
	carry = tmp >> 32;
      }
      u[j+n] += carry;
    }
  }
  shift_right(u,m,s);
}

/// \param numer holds the 2 64-bit words of the numerator
/// \param denom holds the 2 words of the denominator
/// \param quotient_res will hold the 2 words of the quotient
/// \param remainder_res will hold the 2 words of the remainder
void udiv128(uint8 *numer,uint8 *denom,uint8 *quotient_res,uint8 *remainder_res)

{
  if (numer[1] == 0 && denom[1] == 0) {
    quotient_res[0] = numer[0] / denom[0];
    quotient_res[1] = 0;
    remainder_res[0] = numer[0] % denom[0];
    remainder_res[1] = 0;
    return;
  }
  uint4 v[4];
  uint4 u[5];	// Array needs one more entry for normalization overflow
  uint4 q[4];
  int4 n = split64_32(2,denom,v);
  if (n == 0) {
    throw LowlevelError("divide by 0");
  }
  int4 m = split64_32(2,numer,u);
  if ( m < n || ( (n==m) && u[n-1] < v[n-1])) {
				// denominator is smaller than the numerator, quotient is 0
    quotient_res[0] = 0;
    quotient_res[1] = 0;
    remainder_res[0] = numer[0];
    remainder_res[1] = numer[1];
    return;
  }
  u[m] = 0;
  m += 1;			// Extend u array by 1 to account for normalization
  if (n == 1) {
    uint4 d = v[0];
    uint4 rem = 0;
    for(int4 i=m-1;i>=0;--i) {
      uint8 tmp = ((uint8)rem << 32) + u[i];
      q[i] = tmp / d;
      u[i] = 0;
      rem = tmp % d;
    }
    u[0] = rem;			// Last carry is final remainder
  }
  else {
    knuth_algorithm_d(m,n,u,v,q);
  }
  pack32_64(2,m-n,quotient_res,q);
  pack32_64(2,m-1,remainder_res,u);
}

} // End namespace ghidra

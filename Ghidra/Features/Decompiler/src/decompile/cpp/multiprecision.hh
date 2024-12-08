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
/// \file multiprecision.hh
/// \brief Multi-precision integers
#ifndef __CPUI_MULTIPRECISION__
#define __CPUI_MULTIPRECISION__

#include "error.hh"

namespace ghidra {

extern void leftshift128(uint8 *in,uint8 *out,int4 sa);		///< 128-bit INT_LEFT operation with constant shift amount
extern bool uless128(uint8 *in1,uint8 *in2);			///< 128-bit INT_LESS operation
extern bool ulessequal128(uint8 *in1,uint8 *in2);		///< 128-bit INT_LESSEQUAL operation
extern void udiv128(uint8 *numer,uint8 *denom,uint8 *quotient_res,uint8 *remainder_res);	///< 128-bit INT_DIV
extern void add128(uint8 *in1,uint8 *in2,uint8 *out);		///< 128-bit INT_ADD operation
extern void subtract128(uint8 *in1,uint8 *in2,uint8 *out);	///< 128-bit INT_SUB operation

/// \brief Set a 128-bit value (2 64-bit words) from a 64-bit value
///
/// \param res will hold the 128-bit value
/// \param val is the 64-bit value to set from
inline void set_u128(uint8 *res,uint8 val) {
  res[0] = val;
  res[1] = 0;
}

} // End namespace ghidra
#endif

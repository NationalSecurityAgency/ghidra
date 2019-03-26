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
/// \file crc32.hh
/// \brief Table and function for computing a CRC32

#ifndef __CRC32__
#define __CRC32__

#include "types.h"

extern uint4 crc32tab[];	///< Table for quickly computing a 32-bit Cyclic Redundacy Check (CRC)

/// \brief Feed 8 bits into a CRC register
///
/// \param reg is the current state of the CRC register
/// \param val holds 8 bits (least significant) to feed in
/// \return the new value of the register
inline uint4 crc_update(uint4 reg,uint4 val) {
  return crc32tab[(reg ^ val)&0xff] ^ (reg>>8); }

#endif

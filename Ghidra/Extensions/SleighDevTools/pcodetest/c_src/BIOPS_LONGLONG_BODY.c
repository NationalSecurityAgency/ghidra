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
#include "pcode_test.h"

#ifdef HAS_LONGLONG
i8 pcode_i8_complexLogic(i8 a, i8 b, i8 c, i8 d, i8 e, i8 f)
{
	i8 ret = 0;

	if (a > b && b > c || d < e && f < e) {
		ret += 1;
	}
	if (a != b || a != c && d != e || f != e) {
		ret += 2;
	}
	if (a && b && c || d && e && f) {
		ret += 4;
	}
	if (a || b || c && d || e || f) {
		ret += 8;
	}
	return ret;
}

u8 pcode_u8_complexLogic(u8 a, u8 b, u8 c, u8 d, u8 e, u8 f)
{
	u8 ret = 0;

	if (a > b && b > c || d < e && f < e) {
		ret += 1;
	}
	if (a != b || a != c && d != e || f != e) {
		ret += 2;
	}
	if (a && b && c || d && e && f) {
		ret += 4;
	}
	if (a || b || c && d || e || f) {
		ret += 8;
	}
	return ret;
}

i8 biopCmpi8i8(i8 lhs, i8 rhs)
{
	if (lhs < 0)
		lhs += 2;
	if (lhs > 0)
		lhs += 4;
	if (lhs == 0)
		lhs += 8;
	if (lhs != rhs)
		lhs += 16;
	return lhs;
}

u8 biopCmpu8u8(u8 lhs, u8 rhs)
{
	if (lhs < rhs)
		lhs += 2;
	if (lhs > rhs)
		lhs += 4;
	if (lhs == 0)
		lhs += 8;
	if (lhs != rhs)
		lhs += 16;
	return lhs;
}

i8 biopNei8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs != rhs;
	return z;
}

u8 biopAndu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs & rhs;
	return z;
}

i8 biopAndi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs & rhs;
	return z;
}

u8 biopOru8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs | rhs;
	return z;
}

u8 biopXOru8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs ^ rhs;
	return z;
}

i8 biopOri8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs | rhs;
	return z;
}

u8 biopLogicOru8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs || rhs;
	return z;
}

i8 biopXOri8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs ^ rhs;
	return z;
}

i8 biopRemainderi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs % rhs;
	return z;
}

i8 biopLogicOri8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs || rhs;
	return z;
}

u8 biopLogicAndu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs && rhs;
	return z;
}

i8 biopDividi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs / rhs;
	return z;
}

u8 biopDividu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs / rhs;
	return z;
}

i8 biopLogicAndi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs && rhs;
	return z;
}

u8 unopNotu8(u8 lhs)
{
	u8 z;

	z = !lhs;
	return z;
}

i8 unopNoti8(i8 lhs)
{
	i8 z;

	z = !lhs;
	return z;
}

u8 unopPlusu8(u8 lhs)
{
	u8 z;

	z = +lhs;
	return z;
}

i8 unopNegativei8(i8 lhs)
{
	i8 z;

	z = -lhs;
	return z;
}

i8 unopPlusi8(i8 lhs)
{
	i8 z;

	z = +lhs;
	return z;
}

u8 biopMultu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs * rhs;
	return z;
}

i8 biopMulti8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs * rhs;
	return z;
}

u8 biopSubu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs - rhs;
	return z;
}

i8 biopSubi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs - rhs;
	return z;
}

u8 biopAddu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs + rhs;
	return z;
}

u8 biopShtLftu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs << rhs;
	return z;
}

i8 biopAddi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs + rhs;
	return z;
}

u8 biopShtRhtu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs >> rhs;
	return z;
}

i8 biopShtLfti8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs << rhs;
	return z;
}

i8 biopShtRhti8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs >> rhs;
	return z;
}

u8 biopGtu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs > rhs;
	return z;
}

i8 biopGti8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs > rhs;
	return z;
}

u8 biopGeu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs >= rhs;
	return z;
}

i8 biopGei8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs >= rhs;
	return z;
}

u8 biopLtu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs < rhs;
	return z;
}

u8 biopLeu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs <= rhs;
	return z;
}

i8 biopLti8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs < rhs;
	return z;
}

u8 biopEqu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs == rhs;
	return z;
}

i8 biopLei8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs <= rhs;
	return z;
}

i8 biopEqi8i8(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs == rhs;
	return z;
}

u8 biopNeu8u8(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs != rhs;
	return z;
}

#endif /* #ifdef HAS_LONGLONG */

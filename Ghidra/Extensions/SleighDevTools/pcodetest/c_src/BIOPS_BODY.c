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

u1 pcode_u1_complexLogic(u1 a, u1 b, u1 c, u1 d, u1 e, u1 f)
{
	u1 ret = 0;

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

u2 pcode_u2_complexLogic(u2 a, u2 b, u2 c, u2 d, u2 e, u2 f)
{
	u2 ret = 0;

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

u4 pcode_u4_complexLogic(u4 a, u4 b, u4 c, u4 d, u4 e, u4 f)
{
	u4 ret = 0;

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

i1 pcode_i1_complexLogic(i1 a, i1 b, i1 c, i1 d, i1 e, i1 f)
{
	i1 ret = 0;

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

i2 pcode_i2_complexLogic(i2 a, i2 b, i2 c, i2 d, i2 e, i2 f)
{
	i2 ret = 0;

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

i4 pcode_i4_complexLogic(i4 a, i4 b, i4 c, i4 d, i4 e, i4 f)
{
	i4 ret = 0;

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

u1 biopCmpu1u1(u1 lhs, u1 rhs)
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

u2 biopCmpu2u2(u2 lhs, u2 rhs)
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

u4 biopCmpu4u4(u4 lhs, u4 rhs)
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

i1 biopCmpi1i1(i1 lhs, i1 rhs)
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

i2 biopCmpi2i2(i2 lhs, i2 rhs)
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

i4 biopCmpi4i4(i4 lhs, i4 rhs)
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

i4 biopAndi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs & rhs;
	return z;
}

i1 biopLei1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs <= rhs;
	return z;
}

u4 biopLogicAndu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs && rhs;
	return z;
}

u2 biopGtu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs > rhs;
	return z;
}

i1 biopEqi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs == rhs;
	return z;
}

i4 biopOri4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs | rhs;
	return z;
}

u4 unopNotu4(u4 lhs)
{
	u4 z;

	z = !lhs;
	return z;
}

u1 unopPlusu1(u1 lhs)
{
	u1 z;

	z = +lhs;
	return z;
}

u2 biopGeu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs >= rhs;
	return z;
}

i1 biopNei1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs != rhs;
	return z;
}

i4 biopXOri4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs ^ rhs;
	return z;
}

i4 biopDividi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs / rhs;
	return z;
}

i4 biopRemainderi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs % rhs;
	return z;
}

u2 biopLtu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs < rhs;
	return z;
}

i1 biopAndi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs & rhs;
	return z;
}

i4 biopLogicOri4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs || rhs;
	return z;
}

u4 unopPlusu4(u4 lhs)
{
	u4 z;

	z = +lhs;
	return z;
}

u2 biopLeu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs <= rhs;
	return z;
}

i4 biopLogicAndi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs && rhs;
	return z;
}

i1 biopOri1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs | rhs;
	return z;
}

i2 biopRemainderi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs % rhs;
	return z;
}

i2 biopMulti2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs * rhs;
	return z;
}

u2 biopEqu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs == rhs;
	return z;
}

i2 biopDividi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs / rhs;
	return z;
}

i4 unopNoti4(i4 lhs)
{
	i4 z;

	z = !lhs;
	return z;
}

u2 biopNeu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs != rhs;
	return z;
}

i1 biopLogicOri1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs || rhs;
	return z;
}

i1 biopXOri1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs ^ rhs;
	return z;
}

i1 biopRemainderi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs % rhs;
	return z;
}

i2 biopSubi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs - rhs;
	return z;
}

i1 biopDividi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs / rhs;
	return z;
}

i4 unopNegativei4(i4 lhs)
{
	i4 z;

	z = -lhs;
	return z;
}

i2 biopAddi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs + rhs;
	return z;
}

u2 biopAndu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs & rhs;
	return z;
}

i1 biopLogicAndi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs && rhs;
	return z;
}

i4 unopPlusi4(i4 lhs)
{
	i4 z;

	z = +lhs;
	return z;
}

i2 biopShtLfti2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs << rhs;
	return z;
}

u2 biopOru2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs | rhs;
	return z;
}

i1 unopNoti1(i1 lhs)
{
	i1 z;

	z = !lhs;
	return z;
}

u4 biopMultu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs * rhs;
	return z;
}

i2 biopShtRhti2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs >> rhs;
	return z;
}

u2 biopXOru2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs ^ rhs;
	return z;
}

u4 biopSubu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs - rhs;
	return z;
}

i1 unopNegativei1(i1 lhs)
{
	i1 z;

	z = -lhs;
	return z;
}

i2 biopGti2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs > rhs;
	return z;
}

u2 biopLogicOru2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs || rhs;
	return z;
}

u4 biopAddu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs + rhs;
	return z;
}

i1 unopPlusi1(i1 lhs)
{
	i1 z;

	z = +lhs;
	return z;
}

i2 biopGei2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs >= rhs;
	return z;
}

u2 biopLogicAndu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs && rhs;
	return z;
}

u1 biopMultu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs * rhs;
	return z;
}

u1 biopGtu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs > rhs;
	return z;
}

u4 biopShtLftu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs << rhs;
	return z;
}

i2 biopOri2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs | rhs;
	return z;
}

i2 biopLti2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs < rhs;
	return z;
}

i4 biopMulti4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs * rhs;
	return z;
}

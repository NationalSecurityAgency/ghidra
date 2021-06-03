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
i8 i8_complexLogic(i8 a, i8 b, i8 c, i8 d, i8 e, i8 f)
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

u8 u8_complexLogic(u8 a, u8 b, u8 c, u8 d, u8 e, u8 f)
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

i8 i8_compareLogic(i8 lhs, i8 rhs)
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

u8 u8_compareLogic(u8 lhs, u8 rhs)
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
/* Comparison operators */
u8 u8_greaterThan(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs > rhs;
	return z;
}

u8 u8_greaterThanEquals(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs >= rhs;
	return z;
}

u8 u8_lessThan(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs < rhs;
	return z;
}

u8 u8_lessThanEquals(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs <= rhs;
	return z;
}

u8 u8_equals(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs == rhs;
	return z;
}

u8 u8_notEquals(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs != rhs;
	return z;
}

i8 i8_greaterThan(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs > rhs;
	return z;
}

i8 i8_greaterThanEquals(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs >= rhs;
	return z;
}

i8 i8_lessThan(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs < rhs;
	return z;
}

i8 i8_lessThanEquals(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs <= rhs;
	return z;
}

i8 i8_equals(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs == rhs;
	return z;
}

i8 i8_notEquals(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs != rhs;
	return z;
}

/* Bitwise operators */
u8 u8_bitwiseAnd(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs & rhs;
	return z;
}

u8 u8_bitwiseOr(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs | rhs;
	return z;
}

u8 u8_bitwiseXor(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs ^ rhs;
	return z;
}

i8 i8_bitwiseAnd(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs & rhs;
	return z;
}

i8 i8_bitwiseOr(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs | rhs;
	return z;
}

i8 i8_bitwiseXor(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs ^ rhs;
	return z;
}

/* Logical operators */
u8 u8_logicalAnd(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs && rhs;
	return z;
}

u8 u8_logicalOr(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs || rhs;
	return z;
}

u8 u8_logicalNot(u8 lhs)
{
	u8 z;

	z = !lhs;
	return z;
}

i8 i8_logicalAnd(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs && rhs;
	return z;
}

i8 i8_logicalOr(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs || rhs;
	return z;
}

i8 i8_logicalNot(i8 lhs)
{
	i8 z;

	z = !lhs;
	return z;
}

/* Shift operators */
u8 u8_shiftLeft(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs << rhs;
	return z;
}

u8 u8_shiftRight(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs >> rhs;
	return z;
}

i8 i8_shiftLeft(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs << rhs;
	return z;
}

i8 i8_shiftRight(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs >> rhs;
	return z;
}

/* Arithmetic operators */
u8 u8_unaryPlus(u8 lhs)
{
	u8 z;

	z = +lhs;
	return z;
}

u8 u8_addition(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs + rhs;
	return z;
}

u8 u8_subtract(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs - rhs;
	return z;
}

u8 u8_multiply(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs * rhs;
	return z;
}

u8 u8_divide(u8 lhs, u8 rhs)
{
	u8 z;

	z = lhs / rhs;
	return z;
}


i8 i8_unaryMinus(i8 lhs)
{
	i8 z;

	z = -lhs;
	return z;
}

i8 i8_unaryPlus(i8 lhs)
{
	i8 z;

	z = +lhs;
	return z;
}

i8 i8_addition(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs + rhs;
	return z;
}

i8 i8_subtract(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs - rhs;
	return z;
}

i8 i8_multiply(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs * rhs;
	return z;
}

i8 i8_divide(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs / rhs;
	return z;
}

i8 i8_remainder(i8 lhs, i8 rhs)
{
	i8 z;

	z = lhs % rhs;
	return z;
}


#endif /* #ifdef HAS_LONGLONG */

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

u4 u4_complexLogic(u4 a, u4 b, u4 c, u4 d, u4 e, u4 f)
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

i4 i4_complexLogic(i4 a, i4 b, i4 c, i4 d, i4 e, i4 f)
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

u4 u4_compareLogic(u4 lhs, u4 rhs)
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

i4 i4_compareLogic(i4 lhs, i4 rhs)
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
/* Comparison operators */
u4 u4_greaterThan(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs > rhs;
	return z;
}

u4 u4_greaterThanEquals(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs >= rhs;
	return z;
}

u4 u4_lessThan(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs < rhs;
	return z;
}

u4 u4_lessThanEquals(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs <= rhs;
	return z;
}

u4 u4_equals(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs == rhs;
	return z;
}

u4 u4_notEquals(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs != rhs;
	return z;
}

i4 i4_greaterThan(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs > rhs;
	return z;
}

i4 i4_greaterThanEquals(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs >= rhs;
	return z;
}

i4 i4_lessThan(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs < rhs;
	return z;
}

i4 i4_lessThanEquals(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs <= rhs;
	return z;
}

i4 i4_equals(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs == rhs;
	return z;
}

i4 i4_notEquals(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs != rhs;
	return z;
}

/* Bitwise operators */
u4 u4_bitwiseAnd(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs & rhs;
	return z;
}

u4 u4_bitwiseOr(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs | rhs;
	return z;
}

u4 u4_bitwiseXor(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs ^ rhs;
	return z;
}

i4 i4_bitwiseAnd(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs & rhs;
	return z;
}

i4 i4_bitwiseOr(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs | rhs;
	return z;
}

i4 i4_bitwiseXor(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs ^ rhs;
	return z;
}

/* Logical operators */
u4 u4_logicalAnd(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs && rhs;
	return z;
}

u4 u4_logicalOr(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs || rhs;
	return z;
}

u4 u4_logicalNot(u4 lhs)
{
	u4 z;

	z = !lhs;
	return z;
}

i4 i4_logicalAnd(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs && rhs;
	return z;
}

i4 i4_logicalOr(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs || rhs;
	return z;
}

i4 i4_logicalNot(i4 lhs)
{
	i4 z;

	z = !lhs;
	return z;
}

/* Shift operators */
u4 u4_shiftLeft(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs << rhs;
	return z;
}

u4 u4_shiftRight(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs >> rhs;
	return z;
}

i4 i4_shiftLeft(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs << rhs;
	return z;
}

i4 i4_shiftRight(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs >> rhs;
	return z;
}

/* Arithmetic operators */
u4 u4_unaryPlus(u4 lhs)
{
	u4 z;

	z = +lhs;
	return z;
}

u4 u4_addition(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs + rhs;
	return z;
}

u4 u4_subtract(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs - rhs;
	return z;
}

u4 u4_multiply(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs * rhs;
	return z;
}

u4 u4_divide(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs / rhs;
	return z;
}

u4 u4_remainder(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs % rhs;
	return z;
}

i4 i4_unaryMinus(i4 lhs)
{
	i4 z;

	z = -lhs;
	return z;
}

i4 i4_unaryPlus(i4 lhs)
{
	i4 z;

	z = +lhs;
	return z;
}

i4 i4_addition(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs + rhs;
	return z;
}

i4 i4_subtract(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs - rhs;
	return z;
}

i4 i4_multiply(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs * rhs;
	return z;
}

i4 i4_divide(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs / rhs;
	return z;
}

i4 i4_remainder(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs % rhs;
	return z;
}


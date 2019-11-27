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

u2 u2_complexLogic(u2 a, u2 b, u2 c, u2 d, u2 e, u2 f)
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

i2 i2_complexLogic(i2 a, i2 b, i2 c, i2 d, i2 e, i2 f)
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

u2 u2_compareLogic(u2 lhs, u2 rhs)
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

i2 i2_compareLogic(i2 lhs, i2 rhs)
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
u2 u2_greaterThan(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs > rhs;
	return z;
}

u2 u2_greaterThanEquals(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs >= rhs;
	return z;
}

u2 u2_lessThan(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs < rhs;
	return z;
}

u2 u2_lessThanEquals(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs <= rhs;
	return z;
}

u2 u2_equals(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs == rhs;
	return z;
}

u2 u2_notEquals(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs != rhs;
	return z;
}

i2 i2_greaterThan(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs > rhs;
	return z;
}

i2 i2_greaterThanEquals(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs >= rhs;
	return z;
}

i2 i2_lessThan(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs < rhs;
	return z;
}

i2 i2_lessThanEquals(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs <= rhs;
	return z;
}

i2 i2_equals(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs == rhs;
	return z;
}

i2 i2_notEquals(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs != rhs;
	return z;
}

/* Bitwise operators */
u2 u2_bitwiseAnd(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs & rhs;
	return z;
}

u2 u2_bitwiseOr(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs | rhs;
	return z;
}

u2 u2_bitwiseXor(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs ^ rhs;
	return z;
}

i2 i2_bitwiseAnd(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs & rhs;
	return z;
}

i2 i2_bitwiseOr(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs | rhs;
	return z;
}

i2 i2_bitwiseXor(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs ^ rhs;
	return z;
}

/* Logical operators */
u2 u2_logicalAnd(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs && rhs;
	return z;
}

u2 u2_logicalOr(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs || rhs;
	return z;
}

u2 u2_logicalNot(u2 lhs)
{
	u2 z;

	z = !lhs;
	return z;
}

i2 i2_logicalAnd(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs && rhs;
	return z;
}

i2 i2_logicalOr(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs || rhs;
	return z;
}

i2 i2_logicalNot(i2 lhs)
{
	i2 z;

	z = !lhs;
	return z;
}

/* Shift operators */
u2 u2_shiftLeft(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs << rhs;
	return z;
}

u2 u2_shiftRight(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs >> rhs;
	return z;
}

i2 i2_shiftRight(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs >> rhs;
	return z;
}

i2 i2_shiftLeft(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs << rhs;
	return z;
}

/* Arithmetic operators */
u2 u2_unaryPlus(u2 lhs)
{
	u2 z;

	z = +lhs;
	return z;
}

u2 u2_addition(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs + rhs;
	return z;
}

u2 u2_subtract(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs - rhs;
	return z;
}

u2 u2_multiply(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs * rhs;
	return z;
}

i2 u2_divide(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs / rhs;
	return z;
}

u2 u2_remainder(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs % rhs;
	return z;
}

i2 i2_unaryMinus(i2 lhs)
{
	i2 z;

	z = -lhs;
	return z;
}

i2 i2_unaryPlus(i2 lhs)
{
	i2 z;

	z = +lhs;
	return z;
}

i2 i2_addition(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs + rhs;
	return z;
}

i2 i2_subtract(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs - rhs;
	return z;
}

i2 i2_multiply(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs * rhs;
	return z;
}

i2 i2_divide(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs / rhs;
	return z;
}

i2 i2_remainder(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs % rhs;
	return z;
}



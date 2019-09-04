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

u1 u1_complexLogic(u1 a, u1 b, u1 c, u1 d, u1 e, u1 f)
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

i1 i1_complexLogic(i1 a, i1 b, i1 c, i1 d, i1 e, i1 f)
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

u1 u1_compareLogic(u1 lhs, u1 rhs)
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

i1 i1_compareLogic(i1 lhs, i1 rhs)
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
u1 u1_greaterThan(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs > rhs;
	return z;
}

u1 u1_greaterThanEquals(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs >= rhs;
	return z;
}

u1 u1_lessThan(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs < rhs;
	return z;
}

u1 u1_lessThanEquals(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs <= rhs;
	return z;
}

u1 u1_equals(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs == rhs;
	return z;
}

u1 u1_notEquals(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs != rhs;
	return z;
}

i1 i1_greaterThan(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs > rhs;
	return z;
}

i1 i1_greaterThanEquals(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs >= rhs;
	return z;
}

i1 i1_lessThan(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs < rhs;
	return z;
}

i1 i1_lessThanEquals(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs <= rhs;
	return z;
}

i1 i1_equals(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs == rhs;
	return z;
}

i1 i1_notEquals(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs != rhs;
	return z;
}

/* Bitwise operators */
u1 u1_bitwiseAnd(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs & rhs;
	return z;
}


u1 u1_bitwiseOr(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs | rhs;
	return z;
}

u1 u1_bitwiseXor(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs ^ rhs;
	return z;
}

i1 i1_bitwiseAnd(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs & rhs;
	return z;
}

i1 i1_bitwiseOr(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs | rhs;
	return z;
}

i1 i1_bitwiseXor(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs ^ rhs;
	return z;
}

/* Logical operators */
u1 u1_logicalAnd(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs && rhs;
	return z;
}

u1 u1_logicalOr(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs || rhs;
	return z;
}

u1 u1_logicalNot(u1 lhs)
{
	u1 z;

	z = !lhs;
	return z;
}

i1 i1_logicalAnd(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs && rhs;
	return z;
}

i1 i1_logicalOr(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs || rhs;
	return z;
}

i1 i1_logicalNot(i1 lhs)
{
	i1 z;

	z = !lhs;
	return z;
}

/* Shift operators */
u1 u1_shiftLeft(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs << rhs;
	return z;
}

u1 u1_shiftRight(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs >> rhs;
	return z;
}

i1 i1_shiftLeft(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs << rhs;
	return z;
}

i1 i1_shiftRight(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs >> rhs;
	return z;
}

/* Arithmetic operators */
u1 u1_unaryPlus(u1 lhs)
{
	u1 z;

	z = +lhs;
	return z;
}

u1 u1_addition(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs + rhs;
	return z;
}

u1 u1_subtract(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs - rhs;
	return z;
}

u1 u1_multiply(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs * rhs;
	return z;
}

i1 u1_divide(u1 lhs, u1 rhs)
{
	i1 z;

	z = lhs / rhs;
	return z;
}

u1 u1_remainder(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs % rhs;
	return z;
}

i1 i1_unaryMinus(i1 lhs)
{
	i1 z;

	z = -lhs;
	return z;
}

i1 i1_unaryPlus(i1 lhs)
{
	i1 z;

	z = +lhs;
	return z;
}

i1 i1_addition(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs + rhs;
	return z;
}

i1 i1_subtract(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs - rhs;
	return z;
}

i1 i1_multiply(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs * rhs;
	return z;
}

i1 i1_divide(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs / rhs;
	return z;
}

i1 i1_remainder(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs % rhs;
	return z;
}



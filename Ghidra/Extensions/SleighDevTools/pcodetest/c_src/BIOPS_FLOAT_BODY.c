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

#ifdef HAS_FLOAT
f4 f4_compareLogic(f4 lhs, f4 rhs)
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

f8 f8_compareLogic(f8 lhs, f8 rhs)
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
f4 f4_greaterThan(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs > rhs;
	return z;
}

f4 f4_greaterThanEquals(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs >= rhs;
	return z;
}

f4 f4_lessThan(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs < rhs;
	return z;
}

f4 f4_lessThanEquals(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs <= rhs;
	return z;
}

f4 f4_equals(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs == rhs;
	return z;
}

f4 f4_notEquals(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs != rhs;
	return z;
}

/* Logical operators */
f4 f4_logicalAnd(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs && rhs;
	return z;
}

f4 f4_logicalOr(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs || rhs;
	return z;
}

f4 f4_logicalNot(f4 lhs)
{
	f4 z;

	z = !lhs;
	return z;
}

/* Arithmetic operators */
f4 f4_unaryMinus(f4 lhs)
{
	f4 z;

	z = -lhs;
	return z;
}

f4 f4_unaryPlus(f4 lhs)
{
	f4 z;

	z = +lhs;
	return z;
}

f4 f4_addition(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs + rhs;
	return z;
}

f4 f4_subtract(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs - rhs;
	return z;
}

f4 f4_multiply(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs * rhs;
	return z;
}

#endif /* #ifdef HAS_FLOAT */

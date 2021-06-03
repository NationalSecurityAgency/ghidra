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
#ifdef HAS_DOUBLE

/* Comparison operators */
f8 f8_greaterThan(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs > rhs;
	return z;
}

f8 f8_greaterThanEquals(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs >= rhs;
	return z;
}

f8 f8_lessThan(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs < rhs;
	return z;
}

f8 f8_lessThanEquals(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs <= rhs;
	return z;
}

f8 f8_equals(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs == rhs;
	return z;
}

f8 f8_notEquals(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs != rhs;
	return z;
}

/* Bitwise operators */

/* Logical operators */
f8 f8_logicalAnd(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs && rhs;
	return z;
}

f8 f8_logicalOr(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs || rhs;
	return z;
}

f8 f8_logicalNot(f8 lhs)
{
	f8 z;

	z = !lhs;
	return z;
}

/* Arithmetic operators */
f8 f8_unaryMinus(f8 lhs)
{
	f8 z;

	z = -lhs;
	return z;
}

f8 f8_unaryPlus(f8 lhs)
{
	f8 z;

	z = +lhs;
	return z;
}

f8 f8_addition(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs + rhs;
	return z;
}

f8 f8_subtract(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs - rhs;
	return z;
}

f8 f8_multiply(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs * rhs;
	return z;
}

#endif /* #ifdef HAS_DOUBLE */

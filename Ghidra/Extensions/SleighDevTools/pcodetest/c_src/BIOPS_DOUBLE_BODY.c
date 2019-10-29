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
f8 biopEqf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs == rhs;
	return z;
}

f8 biopNef8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs != rhs;
	return z;
}

f8 biopLogicOrf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs || rhs;
	return z;
}

f8 biopLogicAndf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs && rhs;
	return z;
}

f8 unopNotf8(f8 lhs)
{
	f8 z;

	z = !lhs;
	return z;
}

f8 unopNegativef8(f8 lhs)
{
	f8 z;

	z = -lhs;
	return z;
}

f8 unopPlusf8(f8 lhs)
{
	f8 z;

	z = +lhs;
	return z;
}

f8 biopMultf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs * rhs;
	return z;
}

f8 biopSubf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs - rhs;
	return z;
}

f8 biopAddf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs + rhs;
	return z;
}

f8 biopGtf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs > rhs;
	return z;
}

f8 biopGef8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs >= rhs;
	return z;
}

f8 biopLtf8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs < rhs;
	return z;
}

f8 biopLef8f8(f8 lhs, f8 rhs)
{
	f8 z;

	z = lhs <= rhs;
	return z;
}

#endif /* #ifdef HAS_DOUBLE */

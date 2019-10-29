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
f4 biopCmpf4f4(f4 lhs, f4 rhs)
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

f8 biopCmpf8f8(f8 lhs, f8 rhs)
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

f4 biopLtf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs < rhs;
	return z;
}

f4 biopLef4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs <= rhs;
	return z;
}

f4 biopEqf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs == rhs;
	return z;
}

f4 biopNef4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs != rhs;
	return z;
}

f4 biopLogicOrf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs || rhs;
	return z;
}

f4 biopLogicAndf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs && rhs;
	return z;
}

f4 unopNotf4(f4 lhs)
{
	f4 z;

	z = !lhs;
	return z;
}

f4 unopNegativef4(f4 lhs)
{
	f4 z;

	z = -lhs;
	return z;
}

f4 unopPlusf4(f4 lhs)
{
	f4 z;

	z = +lhs;
	return z;
}

f4 biopMultf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs * rhs;
	return z;
}

f4 biopSubf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs - rhs;
	return z;
}

f4 biopAddf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs + rhs;
	return z;
}

f4 biopGtf4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs > rhs;
	return z;
}

f4 biopGef4f4(f4 lhs, f4 rhs)
{
	f4 z;

	z = lhs >= rhs;
	return z;
}

#endif /* #ifdef HAS_FLOAT */

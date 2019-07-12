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

u2 unopNotu2(u2 lhs)
{
	u2 z;

	z = !lhs;
	return z;
}

u1 biopSubu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs - rhs;
	return z;
}

u1 biopGeu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs >= rhs;
	return z;
}

u4 biopShtRhtu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs >> rhs;
	return z;
}

i2 biopXOri2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs ^ rhs;
	return z;
}

i2 biopLei2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs <= rhs;
	return z;
}

i4 biopSubi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs - rhs;
	return z;
}

u1 biopAddu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs + rhs;
	return z;
}

u1 biopLtu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs < rhs;
	return z;
}

u4 biopGtu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs > rhs;
	return z;
}

i2 biopLogicOri2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs || rhs;
	return z;
}

i2 biopEqi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs == rhs;
	return z;
}

u2 unopPlusu2(u2 lhs)
{
	u2 z;

	z = +lhs;
	return z;
}

i4 biopAddi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs + rhs;
	return z;
}

u4 biopGeu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs >= rhs;
	return z;
}

u1 biopShtLftu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs << rhs;
	return z;
}

u1 biopLeu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs <= rhs;
	return z;
}

i2 biopLogicAndi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs && rhs;
	return z;
}

i2 biopNei2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs != rhs;
	return z;
}

i1 biopMulti1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs * rhs;
	return z;
}

i4 biopShtLfti4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs << rhs;
	return z;
}

u4 biopLtu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs < rhs;
	return z;
}

u1 biopShtRhtu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs >> rhs;
	return z;
}

u1 biopEqu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs == rhs;
	return z;
}

i2 unopNoti2(i2 lhs)
{
	i2 z;

	z = !lhs;
	return z;
}

i2 biopAndi2i2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs & rhs;
	return z;
}

i1 biopSubi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs - rhs;
	return z;
}

u1 biopNeu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs != rhs;
	return z;
}

i4 biopShtRhti4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs >> rhs;
	return z;
}

u4 biopLeu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs <= rhs;
	return z;
}

i2 unopNegativei2(i2 lhs)
{
	i2 z;

	z = -lhs;
	return z;
}

i4 biopGti4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs > rhs;
	return z;
}

i1 biopAddi1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs + rhs;
	return z;
}

u1 biopAndu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs & rhs;
	return z;
}

u4 biopEqu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs == rhs;
	return z;
}

i2 unopPlusi2(i2 lhs)
{
	i2 z;

	z = +lhs;
	return z;
}

i4 biopGei4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs >= rhs;
	return z;
}

i1 biopShtLfti1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs << rhs;
	return z;
}

u1 biopOru1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs | rhs;
	return z;
}

u4 biopNeu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs != rhs;
	return z;
}

u2 biopMultu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs * rhs;
	return z;
}

i1 biopShtRhti1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs >> rhs;
	return z;
}

i4 biopLti4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs < rhs;
	return z;
}

u4 biopAndu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs & rhs;
	return z;
}

u1 biopXOru1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs ^ rhs;
	return z;
}

u2 biopSubu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs - rhs;
	return z;
}

i1 biopGti1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs > rhs;
	return z;
}

i4 biopLei4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs <= rhs;
	return z;
}

u4 biopOru4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs | rhs;
	return z;
}

u1 biopLogicOru1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs || rhs;
	return z;
}

u2 biopAddu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs + rhs;
	return z;
}

i1 biopGei1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs >= rhs;
	return z;
}

u1 biopLogicAndu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs && rhs;
	return z;
}

i4 biopEqi4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs == rhs;
	return z;
}

u4 biopXOru4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs ^ rhs;
	return z;
}

u2 biopShtLftu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs << rhs;
	return z;
}

i4 biopNei4i4(i4 lhs, i4 rhs)
{
	i4 z;

	z = lhs != rhs;
	return z;
}

i1 biopLti1i1(i1 lhs, i1 rhs)
{
	i1 z;

	z = lhs < rhs;
	return z;
}

u1 unopNotu1(u1 lhs)
{
	u1 z;

	z = !lhs;
	return z;
}

u4 biopLogicOru4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs || rhs;
	return z;
}

u2 biopShtRhtu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs >> rhs;
	return z;
}

i1 biopDividu1u1(u1 lhs, u1 rhs)
{
	i1 z;

	z = lhs / rhs;
	return z;
}

i2 biopDividu2u2(i2 lhs, i2 rhs)
{
	i2 z;

	z = lhs / rhs;
	return z;
}

u4 biopDividu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs / rhs;
	return z;
}

u1 biopRemainderu1u1(u1 lhs, u1 rhs)
{
	u1 z;

	z = lhs % rhs;
	return z;
}

u2 biopRemainderu2u2(u2 lhs, u2 rhs)
{
	u2 z;

	z = lhs % rhs;
	return z;
}

u4 biopRemainderu4u4(u4 lhs, u4 rhs)
{
	u4 z;

	z = lhs % rhs;
	return z;
}

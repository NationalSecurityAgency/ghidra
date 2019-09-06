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

#define PARAMS(typ,a,b,c) (( (-((typ) (a))) * ((typ) (b)) ) + ((typ) (c)))

i4 pcode_PP2_1_OrderingIntShortChar(i4 i, i2 s, i1 c)
{
	return PARAMS(i4, i, s, c);
}

i4 pcode_PP2_2_OrderingShortIntChar(i2 s, i4 i, i1 c)
{
	return PARAMS(i4, s, i, c);
}

i4 pcode_PP2_3_OrderingIntCharShort(i4 i, i1 c, i2 s)
{
	return PARAMS(i4, i, c, s);
}

i4 pcode_PP2_4_OrderingShortCharInt(i2 s, i1 c, i4 i)
{
	return PARAMS(i4, s, c, i);
}

i4 pcode_PP2_5_OrderingCharShortInt(i1 c, i2 s, i4 i)
{
	return PARAMS(i4, c, s, i);
}

i4 pcode_PP2_6_OrderingCharIntShort(i1 c, i4 i, i2 s)
{
	return PARAMS(i4, c, i, s);
}

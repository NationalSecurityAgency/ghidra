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

i4 pcode_PP1_12_InferPointerArgumentInt(i4 * arg1)
{
	return (-7) >> (*arg1);
}

i2 pcode_PP1_13_InferPointerArgumentShort(i2 * arg1)
{
	return (-7) >> (*arg1);
}

i1 pcode_PP1_14_InferPointerArgumentChar(i1 * arg1)
{
	return (-7) >> (*arg1);
}

#ifdef HAS_LONGLONG
u8 pcode_PP1_15_InferPointerArgumentUnsignedLongLong(u8 * arg1)
{
	return (-7) >> (*arg1);
}
#endif /* #ifdef HAS_LONGLONG */

u4 pcode_PP1_16_InferPointerArgumentUnsignedInt(u4 * arg1)
{
	return (-7) >> (*arg1);
}

u2 pcode_PP1_17_InferPointerArgumentUnsignedShort(u2 * arg1)
{
	return (-7) >> (*arg1);
}

u1 pcode_PP1_18_InferPointerArgumentUnsignedChar(u1 * arg1)
{
	return (-7) >> (*arg1);
}

#ifdef HAS_FLOAT
f4 pcode_PP1_19_InferPointerArgumentFloat(f4 * arg1)
{
	return (-7) + (*arg1);
}
#endif

#ifdef HAS_DOUBLE
f8 pcode_PP1_20_InferPointerArgumentDouble(f8 * arg1)
{
	return (-7) + (*arg1);
}
#endif

#ifdef HAS_LONGLONG
i8 pcode_PP1_1_InferArgumentLongLong(i8 * arg1)
{
	return (-7) >> *arg1;
}
#endif /* #ifdef HAS_LONGLONG */

i4 pcode_PP1_2_InferArgumentInt(i4 arg1)
{
	return (-7) >> arg1;
}

i2 pcode_PP1_3_InferArgumentShort(i2 arg1)
{
	return (-7) >> arg1;
}

i1 pcode_PP1_4_InferArgumentChar(i1 arg1)
{
	return (-7) >> arg1;
}

#ifdef HAS_LONGLONG
u8 pcode_PP1_5_InferArgumentUnsignedLongLong(u8 arg1)
{
	return (-7) >> arg1;
}
#endif /* #ifdef HAS_LONGLONG */

u4 pcode_PP1_6_InferArgumentUnsignedInt(u4 arg1)
{
	return (-7) >> arg1;
}

u2 pcode_PP1_7_InferArgumentUnsignedShort(u2 arg1)
{
	return (-7) >> arg1;
}

u1 pcode_PP1_8_InferArgumentUnsignedChar(u1 arg1)
{
	return (-7) >> arg1;
}

#ifdef HAS_FLOAT
f4 pcode_PP1_9_InferArgumentFloat(f4 arg1)
{
	return ((f4) - 7) + arg1;
}
#endif

#ifdef HAS_DOUBLE
f8 pcode_PP1_10_InferArgumentDouble(f8 arg1)
{
	return ((f8) - 7) + arg1;
}
#endif

#ifdef HAS_LONGLONG
i8 pcode_PP1_11_InferPointerArgumentLongLong(i8 * arg1)
{
	return (-7) >> (*arg1);
}
#endif /* #ifdef HAS_LONGLONG */

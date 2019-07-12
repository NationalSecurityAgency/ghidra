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

#define GET_BIT(typ, arg, bit) (arg & (((typ)1) << bit))
#define SET_BIT(typ, arg, bit) (arg | (((typ)1) << bit))
#define CLR_BIT(typ, arg, bit) (arg & (~(((typ)1) << bit)))
#define TGL_BIT(typ, arg, bit) (arg ^ (((typ)1) << bit))

#ifdef HAS_LONGLONG
i8 pcode_BM1_GetBitLongLong(i8 arg, u4 bit)
{
	return GET_BIT(i8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

i4 pcode_BM2_GetBitInt(i4 arg, u4 bit)
{
	return GET_BIT(i4, arg, bit);
}

i2 pcode_BM3_GetBitShort(i2 arg, u4 bit)
{
	return GET_BIT(i2, arg, bit);
}

i1 pcode_BM4_GetBitChar(i1 arg, u4 bit)
{
	return GET_BIT(i1, arg, bit);
}

#ifdef HAS_LONGLONG
u8 pcode_BM5_GetBitUnsignedLongLong(u8 arg, u8 bit)
{
	return GET_BIT(u8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

u4 pcode_BM6_GetBitUnsignedInt(u4 arg, u4 bit)
{
	return GET_BIT(u4, arg, bit);
}

u2 pcode_BM7_GetBitUnsignedShort(u2 arg, u4 bit)
{
	return GET_BIT(u2, arg, bit);
}

u1 pcode_BM8_GetBitUnsignedChar(u1 arg, u4 bit)
{
	return GET_BIT(u1, arg, bit);
}

#ifdef HAS_LONGLONG
i8 pcode_BM9_SetBitLongLong(i8 arg, u4 bit)
{
	return SET_BIT(i8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

i4 pcode_BM10_SetBitInt(i4 arg, u4 bit)
{
	return SET_BIT(i4, arg, bit);
}

i2 pcode_BM11_SetBitShort(i2 arg, i2 bit)
{
	return SET_BIT(i2, arg, bit);
}

i1 pcode_BM12_SetBitChar(i1 arg, u1 bit)
{
	return SET_BIT(i1, arg, bit);
}

#ifdef HAS_LONGLONG
u8 pcode_BM12_SetBitUnsignedLongLong(u8 arg, u8 bit)
{
	return SET_BIT(u8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_LONGLONG
u8 pcode_BM13_SetLowBitUnsignedLongLong(u8 arg, u8 bit)
{
	return SET_BIT(u8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

u4 pcode_BM14_SetBitUnsignedInt(u4 arg, u4 bit)
{
	return SET_BIT(u4, arg, bit);
}

u2 pcode_BM15_SetBitUnsignedShort(u2 arg, u4 bit)
{
	return SET_BIT(u2, arg, bit);
}

u1 pcode_BM16_SetBitUnsignedChar(u1 arg, u1 bit)
{
	return SET_BIT(u1, arg, bit);
}

#ifdef HAS_LONGLONG
i8 pcode_BM17_ClearBitLongLong(i8 arg, i8 bit)
{
	return CLR_BIT(i8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

i4 pcode_BM18_ClearBitInt(i4 arg, i4 bit)
{
	return CLR_BIT(i4, arg, bit);
}

i2 pcode_BM19_ClearBitShort(i2 arg, i2 bit)
{
	return CLR_BIT(i2, arg, bit);
}

i1 pcode_BM20_ClearBitChar(i1 arg, u1 bit)
{
	return CLR_BIT(i1, arg, bit);
}

#ifdef HAS_LONGLONG
u8 pcode_BM21_ClearBitUnsignedLongLong(u8 arg, u8 bit)
{
	return CLR_BIT(u8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

u4 pcode_BM22_ClearBitUnsignedInt(u4 arg, u4 bit)
{
	return CLR_BIT(u4, arg, bit);
}

u2 pcode_BM23_ClearBitUnsignedShort(u2 arg, u2 bit)
{
	return CLR_BIT(u2, arg, bit);
}

u1 pcode_BM24_ClearBitUnsignedChar(u1 arg, u1 bit)
{
	return CLR_BIT(u1, arg, bit);
}

#ifdef HAS_LONGLONG
i8 pcode_BM25_ToggleBitLongLong(i8 arg, u4 bit)
{
	return TGL_BIT(i8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

i4 pcode_BM26_ToggleBitInt(i4 arg, i4 bit)
{
	return TGL_BIT(i4, arg, bit);
}

i2 pcode_BM27_ToggleBitShort(i2 arg, i2 bit)
{
	return TGL_BIT(i2, arg, bit);
}

i1 pcode_BM28_ToggleBitChar(i1 arg, u4 bit)
{
	return TGL_BIT(i1, arg, bit);
}

#ifdef HAS_LONGLONG
u8 pcode_BM29_ToggleBitUnsignedLongLong(u8 arg, u4 bit)
{
	return TGL_BIT(u8, arg, bit);
}
#endif /* #ifdef HAS_LONGLONG */

u4 pcode_BM30_ToggleBitUnsignedInt(u4 arg, u4 bit)
{
	return TGL_BIT(u4, arg, bit);
}

u2 pcode_BM31_ToggleBitUnsignedShort(u2 arg, u4 bit)
{
	return TGL_BIT(u2, arg, bit);
}

u1 pcode_BM32_ToggleBitUnsignedChar(u1 arg, u1 bit)
{
	return TGL_BIT(u1, arg, bit);
}

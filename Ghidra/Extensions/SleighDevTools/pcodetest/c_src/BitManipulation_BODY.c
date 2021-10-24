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

#if 0
u1 is_big_endian(void)
{
    // Not all tests need to go into something like this, but enough
    // use as a test to use big endian values or little
    // this could be better supported by pcodetest in general
    // there is a value in the the structs but not sure how to ref
    const union {
        u4 i;
        u1 c[4];
    } e = { 0x01000000 };

    return e.c[0];
}
#endif
#if 0
u1 is_order_lo(void)
{
    // The bit order may be reading hi to lo or lo to hi
    // return true if flipped
    u1bits x;
    x.z = 0x3f;
    x.y.w2 = 1;
    return x.z == 0x3f;
}
#endif

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

u1 pcode_u1_SumBits(u1 arg)
{
    u1bits a;
    a.z = arg;
    u1 sum =
	a.x.b0  + a.x.b1  + a.x.b2  + a.x.b3  +
	a.x.b4  + a.x.b5  + a.x.b6  + a.x.b7;
    return sum;
}

u2 pcode_u2_SumBits(u2 arg)
{
    u2bits a;
    a.z = arg;
    u2 sum =
	a.x.b0  + a.x.b1  + a.x.b2  + a.x.b3  +
	a.x.b4  + a.x.b5  + a.x.b6  + a.x.b7  +
	a.x.b8  + a.x.b9  + a.x.b10 + a.x.b11 +
	a.x.b12 + a.x.b13 + a.x.b14 + a.x.b15;
    return sum;
}

u4 pcode_u4_SumBits(u4 arg)
{
    u4bits a;
    a.z = arg;
    u4 sum =
	a.x.b0  + a.x.b1  + a.x.b2  + a.x.b3  +
	a.x.b4  + a.x.b5  + a.x.b6  + a.x.b7  +
	a.x.b8  + a.x.b9  + a.x.b10 + a.x.b11 +
	a.x.b12 + a.x.b13 + a.x.b14 + a.x.b15 +
	a.x.b16 + a.x.b17 + a.x.b18 + a.x.b19 +
	a.x.b20 + a.x.b21 + a.x.b22 + a.x.b23 +
	a.x.b24 + a.x.b25 + a.x.b26 + a.x.b27 +
	a.x.b28 + a.x.b29 + a.x.b30 + a.x.b31;
    return sum;
}

#ifdef HAS_LONGLONG
u8 pcode_u8_SumBits(u8 arg)
{
    u8bits a;
    a.z = arg;
    u8 sum =
	a.x.b0  + a.x.b1  + a.x.b2  + a.x.b3  +
	a.x.b4  + a.x.b5  + a.x.b6  + a.x.b7  +
	a.x.b8  + a.x.b9  + a.x.b10 + a.x.b11 +
	a.x.b12 + a.x.b13 + a.x.b14 + a.x.b15 +
	a.x.b16 + a.x.b17 + a.x.b18 + a.x.b19 +
	a.x.b20 + a.x.b21 + a.x.b22 + a.x.b23 +
	a.x.b24 + a.x.b25 + a.x.b26 + a.x.b27 +
	a.x.b28 + a.x.b29 + a.x.b30 + a.x.b31 +
	a.x.b32 + a.x.b33 + a.x.b34 + a.x.b35 +
	a.x.b36 + a.x.b37 + a.x.b38 + a.x.b39 +
	a.x.b40 + a.x.b41 + a.x.b42 + a.x.b43 +
	a.x.b44 + a.x.b45 + a.x.b46 + a.x.b47 +
	a.x.b48 + a.x.b49 + a.x.b50 + a.x.b51 +
	a.x.b52 + a.x.b53 + a.x.b54 + a.x.b55 +
	a.x.b56 + a.x.b57 + a.x.b58 + a.x.b59 +
	a.x.b60 + a.x.b61 + a.x.b62 + a.x.b63;
    return sum;
}
#endif


#define BITFIELDS(typ)				\
    typ pcode_##typ##_SetBitsfield(typ arg)	\
    {						\
	typ##bits a;				\
	a.z = 0;				\
	a.y.w1 = arg;				\
	return a.z;				\
    }						\
    typ pcode_##typ##_GetBitsfield(typ arg)	\
    {						\
	typ##bits a;				\
	a.z = arg;				\
	return a.y.w1;				\
    }						\
    typ pcode_##typ##_SetBitfield(typ arg)	\
    {						\
	typ##bits a;				\
	a.z = 0;				\
	a.y.w2 = arg;				\
	return a.z;				\
    }						\
    typ pcode_##typ##_GetBitfield(typ arg)	\
    {						\
	typ##bits a;				\
	a.z = 0;				\
	a.z = arg;				\
	return a.y.w2;				\
    }						\
    typ pcode_##typ##_SetHigh(typ arg)		\
    {						\
	typ##bits a;				\
	a.z = arg;				\
	a.y.w2 = 1;				\
	return a.z;				\
    }						\
    typ pcode_##typ##_SetLow(typ arg)		\
    {						\
	typ##bits a;				\
	a.z = arg;				\
	a.y.w2 = 0;				\
	return a.z;				\
    }

BITFIELDS(u1)
BITFIELDS(u2)
BITFIELDS(u4)
#ifdef HAS_LONGLONG
BITFIELDS(u8)
#endif

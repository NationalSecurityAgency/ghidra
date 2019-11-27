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
#include "big_struct.h"

#ifdef HAS_DOUBLE
f8 pcode_P30_GetDecrementedDouble(f8 * ptr)
{
	return *--ptr;
}
#endif /* #ifdef HAS_DOUBLE */

u1 *pcode_P58_UnionGetAddressOfUnsignedChar(big_union_type *ptr, i4 index)
{
	return (u1 *) & (*(ptr + index)).uc;
}

#ifdef HAS_FLOAT
f4 *pcode_P9_GetAddressOfFloat(f4 * ptr, i4 index)
{
	return ptr + index;
}
#endif /* #ifdef HAS_FLOAT */

#ifdef HAS_FLOAT
f4 *pcode_P59_UnionGetAddressOfFloat(big_union_type *ptr, i4 index)
{
	return (f4 *) & (*(ptr + index)).f;
}
#endif /* #ifdef HAS_FLOAT */

#ifdef HAS_DOUBLE
f8 *pcode_P10_GetAddressOfDouble(f8 * ptr, i4 index)
{
	return ptr + index;
}
#endif /* #ifdef HAS_DOUBLE */

#ifdef HAS_LONGLONG
void pcode_P31_ModifyContentsOfLongLong(i8 * ptr, i4 index, i8 value)
{
	*(ptr + index) = value;
}
#endif /* #ifdef HAS_LONGLONG */

i4 pcode_P32_ModifyContentsOfInt(i4 * ptr, i4 index, i4 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}

i2 pcode_P33_ModifyContentsOfShort(i2 * ptr, i4 index, i2 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}

#ifdef HAS_DOUBLE
f8 *pcode_P60_UnionGetAddressOfDouble(big_union_type *ptr, i4 index)
{
	return (f8 *) & (*(ptr + index)).d;
}
#endif /* #ifdef HAS_DOUBLE */

#ifdef HAS_LONGLONG
i8 pcode_P11_GetIncrementedLongLong(i8 * ptr)
{
	ptr++;
	return *ptr;
}
#endif /* #ifdef HAS_LONGLONG */

i1 pcode_P34_ModifyContentsOfChar(i1 * ptr, i4 index, i1 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}

i4 pcode_P12_GetIncrementedInt(i4 * ptr)
{
	ptr++;
	return *ptr;
}

i2 pcode_P13_GetIncrementedShort(i2 * ptr)
{
	ptr++;
	return *ptr;
}

u4 pcode_P36_ModifyContentsOfUnsignedInt(u4 * ptr, i4 index, u4 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}

#ifdef HAS_LONGLONG
u8 pcode_P35_ModifyContentsOfUnsignedLongLong(u8 * ptr, i4 index, u8 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}
#endif /* #ifdef HAS_LONGLONG */

i1 pcode_P14_GetIncrementedChar(i1 * ptr)
{
	ptr++;
	return *ptr;
}

u2 pcode_P37_ModifyContentsOfUnsignedShort(u2 * ptr, i4 index, u2 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}

#ifdef HAS_LONGLONG
i8 *pcode_P61_GetIndexOfLongLong(i8 * base_ptr, i8 * el_ptr)
{
	return (i8 *) (el_ptr - base_ptr);
}
#endif /* #ifdef HAS_LONGLONG */

u1 pcode_P38_ModifyContentsOfUnsignedChar(u1 * ptr, i4 index, u1 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}

#ifdef HAS_LONGLONG
u8 pcode_P15_GetIncrementedUnsignedLongLong(u8 * ptr)
{
	ptr++;
	return *ptr;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_FLOAT
f4 pcode_P39_ModifyContentsOfFloat(f4 * ptr, i4 index, f4 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}
#endif /* #ifdef HAS_FLOAT */

i4 pcode_P63_GetIndexOfShort(i2 * base_ptr, i2 * el_ptr)
{
	return el_ptr - base_ptr;
}

i4 pcode_P62_GetIndexOfInt(i4 * base_ptr, i4 * el_ptr)
{
	return el_ptr - base_ptr;
}

u2 pcode_P17_GetIncrementedUnsignedShort(u2 * ptr)
{
	ptr++;
	return *ptr;
}

u4 pcode_P16_GetIncrementedUnsignedInt(u4 * ptr)
{
	++ptr;
	return *ptr;
}

i4 pcode_P64_GetIndexOfChar(i1 * base_ptr, i1 * el_ptr)
{
	return el_ptr - base_ptr;
}

u1 pcode_P18_GetIncrementedUnsignedChar(u1 * ptr)
{
	++ptr;
	return *ptr;
}

#ifdef HAS_DOUBLE
f8 pcode_P40_ModifyContentsOfDouble(f8 * ptr, i4 index, f8 value)
{
	*(ptr + index) = value;
	return *(ptr + index);
}
#endif /* #ifdef HAS_DOUBLE */

#ifdef HAS_LONGLONG
i8 *pcode_P41_StructGetAddressOfLongLong(big_struct_type *ptr, i4 index)
{
	return (i8 *) & (*(ptr + index)).ll;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_LONGLONG
i4 pcode_P65_GetIndexOfUnsignedLongLong(u8 * base_ptr, u8 * el_ptr)
{
	return el_ptr - base_ptr;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_FLOAT
f4 pcode_P19_GetIncrementedFloat(f4 * ptr)
{
	ptr++;
	return *ptr;
}
#endif /* #ifdef HAS_FLOAT */

i4 *pcode_P42_StructGetAddressOfInt(big_struct_type *ptr, i4 index)
{
	return (i4 *) & (*(ptr + index)).i;
}

i2 *pcode_P43_StructGetAddressOfShort(big_struct_type *ptr, i4 index)
{
	return (i2 *) & (*(ptr + index)).s;
}

i4 pcode_P66_GetIndexOfUnsignedInt(u4 * base_ptr, u4 * el_ptr)
{
	return el_ptr - base_ptr;
}

i1 *pcode_P44_StructGetAddressOfChar(big_struct_type *ptr, i4 index)
{
	return (i1 *) & (*(ptr + index)).c;
}

i4 pcode_P67_GetIndexOfUnsignedShort(u2 * base_ptr, u2 * el_ptr)
{
	return el_ptr - base_ptr;
}

#ifdef HAS_DOUBLE
f8 pcode_P20_GetIncrementedDouble(f8 * ptr)
{
	ptr++;
	return *ptr;
}
#endif /* #ifdef HAS_DOUBLE */

i4 pcode_P68_GetIndexOfUnsignedChar(u1 * base_ptr, u1 * el_ptr)
{
	return el_ptr - base_ptr;
}

#ifdef HAS_LONGLONG
u8 *pcode_P45_StructGetAddressOfUnsignedLongLong(big_struct_type *ptr, i4 index)
{
	return (u8 *) & (*(ptr + index)).ull;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_FLOAT
i4 pcode_P69_GetIndexOfFloat(f4 * base_ptr, f4 * el_ptr)
{
	return el_ptr - base_ptr;
}
#endif /* #ifdef HAS_FLOAT */

#ifdef HAS_LONGLONG
i8 pcode_P21_GetDecrementedLongLong(i8 * ptr)
{
	return *--ptr;
}
#endif /* #ifdef HAS_LONGLONG */

u2 *pcode_P47_StructGetAddressOfUnsignedShort(big_struct_type *ptr, i4 index)
{
	return (u2 *) & (*(ptr + index)).us;
}

u4 *pcode_P46_StructGetAddressOfUnsignedInt(big_struct_type *ptr, i4 index)
{
	return (u4 *) & (*(ptr + index)).ui;
}

i4 pcode_P22_GetDecrementedInt(i4 * ptr)
{
	return *--ptr;
}

u1 *pcode_P48_StructGetAddressOfUnsignedChar(big_struct_type *ptr, i4 index)
{
	return (u1 *) & (*(ptr + index)).uc;
}

#ifdef HAS_DOUBLE
i4 pcode_P70_GetIndexOfDouble(f8 * base_ptr, f8 * el_ptr)
{
	return el_ptr - base_ptr;
}
#endif /* #ifdef HAS_DOUBLE */

i2 pcode_P23_GetDecrementedShort(i2 * ptr)
{
	return *--ptr;
}

#ifdef HAS_LONGLONG
i8 *pcode_P51_UnionGetAddressOfLongLong(big_union_type *ptr, i4 index)
{
	return (i8 *) & (*(ptr + index)).ll;
}
#endif /* #ifdef HAS_LONGLONG */

i1 pcode_P24_GetDecrementedChar(i1 * ptr)
{
	return *--ptr;
}

#ifdef HAS_LONGLONG
i8 *pcode_P1_GetAddressOfLongLong(i8 * ptr, i4 index)
{
	return ptr + index;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_FLOAT
f4 *pcode_P49_StructGetAddressOfFloat(big_struct_type *ptr, i4 index)
{
	return (f4 *) & (*(ptr + index)).f;
}
#endif /* #ifdef HAS_FLOAT */

i4 *pcode_P2_GetAddressOfInt(i4 * ptr, i4 index)
{
	return ptr + index;
}

#ifdef HAS_LONGLONG
u8 pcode_P25_GetDecrementedUnsignedLongLong(u8 * ptr)
{
	return *--ptr;
}
#endif /* #ifdef HAS_LONGLONG */

i4 *pcode_P52_UnionGetAddressOfInt(big_union_type *ptr, i4 index)
{
	return (i4 *) & (*(ptr + index)).i;
}

i2 *pcode_P3_GetAddressOfShort(i2 * ptr, i4 index)
{
	return ptr + index;
}

u4 pcode_P26_GetDecrementedUnsignedInt(u4 * ptr)
{
	return *--ptr;
}

i2 *pcode_P53_UnionGetAddressOfShort(big_union_type *ptr, i4 index)
{
	return (i2 *) & (*(ptr + index)).s;
}

i1 *pcode_P4_GetAddressOfChar(i1 * ptr, i4 index)
{
	return ptr + index;
}

u2 pcode_P27_GetDecrementedUnsignedShort(u2 * ptr)
{
	return *--ptr;
}

i1 *pcode_P54_UnionGetAddressOfChar(big_union_type *ptr, i4 index)
{
	return (i1 *) & (*(ptr + index)).c;
}

u1 pcode_P28_GetDecrementedUnsignedChar(u1 * ptr)
{
	return *--ptr;
}

#ifdef HAS_DOUBLE
f8 *pcode_P50_StructGetAddressOfDouble(big_struct_type *ptr, i4 index)
{
	return (f8 *) & (*(ptr + index)).d;
}
#endif /* #ifdef HAS_DOUBLE */

#ifdef HAS_LONGLONG
u8 *pcode_P55_UnionGetAddressOfUnsignedLongLong(big_union_type *ptr, i4 index)
{
	return (u8 *) & (*(ptr + index)).ull;
}
#endif /* #ifdef HAS_LONGLONG */

u4 *pcode_P6_GetAddressOfUnsignedInt(u4 * ptr, i4 index)
{
	return ptr + index;
}

#ifdef HAS_LONGLONG
u8 *pcode_P5_GetAddressOfUnsignedLongLong(u8 * ptr, i4 index)
{
	return ptr + index;
}
#endif /* #ifdef HAS_LONGLONG */

u2 *pcode_P7_GetAddressOfUnsignedShort(u2 * ptr, i4 index)
{
	return ptr + index;
}

#ifdef HAS_FLOAT
f4 pcode_P29_GetDecrementedFloat(f4 * ptr)
{
	return *--ptr;
}
#endif /* #ifdef HAS_FLOAT */

u1 *pcode_P8_GetAddressOfUnsignedChar(u1 * ptr, i4 index)
{
	return ptr + index;
}

u4 *pcode_P56_UnionGetAddressOfUnsignedInt(big_union_type *ptr, i4 index)
{
	return (u4 *) & (*(ptr + index)).ui;
}

u2 *pcode_P57_UnionGetAddressOfUnsignedShort(big_union_type *ptr, i4 index)
{
	return (u2 *) & (*(ptr + index)).us;
}

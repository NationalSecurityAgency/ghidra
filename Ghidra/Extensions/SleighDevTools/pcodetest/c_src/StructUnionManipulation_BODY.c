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

void bs_init(big_struct_type * bs)
{
#ifdef HAS_LONGLONG
	bs->ull = 1;
	bs->ll = 1;
#endif
	bs->i = 1;
	bs->s = 1;
	bs->c = 1;
	bs->ui = 1;
	bs->us = 1;
	bs->uc = 1;
#ifdef HAS_FLOAT
	bs->f = 1;
#endif
#ifdef HAS_DOUBLE
	bs->d = 1;
#endif
	bs->b = bs;
}

u4 pcode_SUM28_BigStructPtrAccessUnsignedInt(big_struct_type *arg)
{
	u4 local_var;

	local_var = (u4) 7;
	return arg->ui + local_var;
}

#ifdef HAS_FLOAT
big_union_type pcode_SUM64_BigUnionModifyFloat(big_union_type arg, f4 field)
{
	arg.f = field;
	return arg;
}
#endif /* #ifdef HAS_FLOAT */

u2 pcode_SUM29_BigStructPtrAccessUnsignedShort(big_struct_type *arg)
{
	u2 local_var;

	local_var = (u2) 7;
	return arg->us + local_var;
}

#ifdef HAS_DOUBLE
big_union_type pcode_SUM65_BigUnionModifyDouble(big_union_type arg, f8 field)
{
	arg.d = field;
	return arg;
}
#endif /* #ifdef HAS_DOUBLE */

u1 pcode_SUM30_BigStructPtrAccessUnsignedChar(big_struct_type *arg)
{
	u1 local_var;

	local_var = (u1) 7;
	return arg->uc + local_var;
}

big_union_type pcode_SUM66_BigUnionModifyBig_union_type_ptr(big_union_type arg, big_union_type *field)
{
	arg.b = field;
	return arg;
}

#ifdef HAS_FLOAT
f4 pcode_SUM31_BigStructPtrAccessFloat(big_struct_type *arg)
{
	f4 local_var;

	local_var = (f4) 7;
	return arg->f + local_var;
}
#endif

#ifdef HAS_DOUBLE
f8 pcode_SUM32_BigStructPtrAccessDouble(big_struct_type *arg)
{
	f8 local_var;

	local_var = (f8) 7;
	return arg->d + local_var;
}
#endif

#ifdef HAS_LONGLONG
void pcode_SUM67_BigStructPtrModifyLongLong(big_struct_type *arg, i8 field)
{
	arg->ll = field;
}
#endif /* #ifdef HAS_LONGLONG */

void pcode_SUM68_BigStructPtrModifyInt(big_struct_type *arg, i4 field)
{
	arg->i = field;
}

big_struct_type *pcode_SUM33_BigStructPtrAccessBig_struct_type_ptr(big_struct_type *arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg->b + local_var;
}

void pcode_SUM69_BigStructPtrModifyShort(big_struct_type *arg, i2 field)
{
	arg->s = field;
}

void pcode_SUM81_BigUnionPtrModifyChar(big_union_type *arg, i1 field)
{
	arg->c = field;
}

#ifdef HAS_LONGLONG
void pcode_SUM71_BigStructPtrModifyUnsignedLongLong(big_struct_type *arg, u8 field)
{
	arg->ull = field;
}
#endif /* #ifdef HAS_LONGLONG */

void pcode_SUM70_BigStructPtrModifyChar(big_struct_type *arg, i1 field)
{
	arg->c = field;
}

#ifdef HAS_LONGLONG
i8 pcode_SUM34_BigUnionPtrAccessLongLong(big_union_type *arg)
{
	i8 local_var;

	local_var = (i8) 7;
	return arg->ll + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_LONGLONG
void pcode_SUM82_BigUnionPtrModifyUnsignedLongLong(big_union_type *arg, u8 field)
{
	arg->ull = field;
}
#endif /* #ifdef HAS_LONGLONG */

void pcode_SUM72_BigStructPtrModifyUnsignedInt(big_struct_type *arg, u4 field)
{
	arg->ui = field;
}

i4 pcode_SUM35_BigUnionPtrAccessInt(big_union_type *arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg->i + local_var;
}

void pcode_SUM73_BigStructPtrModifyUnsignedShort(big_struct_type *arg, u2 field)
{
	arg->us = field;
}

#ifdef HAS_LONGLONG
i8 pcode_SUM1_BigStructAccessLongLong(big_struct_type arg)
{
	i8 local_var;

	local_var = (i8) 7;
	return arg.ll + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

i2 pcode_SUM36_BigUnionPtrAccessShort(big_union_type *arg)
{
	i2 local_var;

	local_var = (i2) 7;
	return arg->s + local_var;
}

void pcode_SUM85_BigUnionPtrModifyUnsignedChar(big_union_type *arg, u1 field)
{
	arg->uc = field;
}

void pcode_SUM74_BigStructPtrModifyUnsignedChar(big_struct_type *arg, u1 field)
{
	arg->uc = field;
}

i4 pcode_SUM2_BigStructAccessInt(big_struct_type arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg.i + local_var;
}

i1 pcode_SUM37_BigUnionPtrAccessChar(big_union_type *arg)
{
	i1 local_var;

	local_var = (i1) 7;
	return arg->c + local_var;
}

#ifdef HAS_FLOAT
void pcode_SUM86_BigUnionPtrModifyFloat(big_union_type *arg, f4 field)
{
	arg->f = field;
}

#endif /* #ifdef HAS_FLOAT */

#ifdef HAS_FLOAT
void pcode_SUM75_BigStructPtrModifyFloat(big_struct_type *arg, f4 field)
{
	arg->f = field;
}
#endif /* #ifdef HAS_FLOAT */

i2 pcode_SUM3_BigStructAccessShort(big_struct_type arg)
{
	i2 local_var;

	local_var = (i2) 7;
	return arg.s + local_var;
}

#ifdef HAS_LONGLONG
u8 pcode_SUM38_BigUnionPtrAccessUnsignedLongLong(big_union_type *arg)
{
	u8 local_var;

	local_var = (u8) 7;
	return arg->ull + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_DOUBLE
void pcode_SUM87_BigUnionPtrModifyDouble(big_union_type *arg, f8 field)
{
	arg->d = field;
}
#endif /* #ifdef HAS_DOUBLE */

#ifdef HAS_DOUBLE
void pcode_SUM76_BigStructPtrModifyDouble(big_struct_type *arg, f8 field)
{
	arg->d = field;
}

#endif /* #ifdef HAS_DOUBLE */

i1 pcode_SUM4_BigStructAccessChar(big_struct_type arg)
{
	i1 local_var;

	local_var = (i1) 7;
	return arg.c + local_var;
}

u4 pcode_SUM39_BigUnionPtrAccessUnsignedInt(big_union_type *arg)
{
	u4 local_var;

	local_var = (u4) 7;
	return arg->ui + local_var;
}

void pcode_SUM88_BigUnionPtrModifyBig_union_type_ptr(big_union_type *arg, big_union_type *field)
{
	arg->b = field;
}

void pcode_SUM77_BigStructPtrModifyBig_struct_type_ptr(big_struct_type *arg, big_struct_type *field)
{
	arg->b = field;
}

u2 pcode_SUM40_BigUnionPtrAccessUnsignedShort(big_union_type *arg)
{
	u2 local_var;

	local_var = (u2) 7;
	return arg->us + local_var;
}

#ifdef HAS_LONGLONG
void pcode_SUM78_BigUnionPtrModifyLongLong(big_union_type *arg, i8 field)
{
	arg->ll = field;
}
#endif /* #ifdef HAS_LONGLONG */

#ifdef HAS_LONGLONG
u8 pcode_SUM5_BigStructAccessUnsignedLongLong(big_struct_type arg)
{
	u8 local_var;

	local_var = (u8) 7;
	return arg.ull + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

u1 pcode_SUM41_BigUnionPtrAccessUnsignedChar(big_union_type *arg)
{
	u1 local_var;

	local_var = (u1) 7;
	return arg->uc + local_var;
}

void pcode_SUM79_BigUnionPtrModifyInt(big_union_type *arg, i4 field)
{
	arg->i = field;
}

u4 pcode_SUM6_BigStructAccessUnsignedInt(big_struct_type arg)
{
	u4 local_var;

	local_var = (u4) 7;
	return arg.ui + local_var;
}

void pcode_SUM80_BigUnionPtrModifyShort(big_union_type *arg, i2 field)
{
	arg->s = field;
}

u1 pcode_SUM8_BigStructAccessUnsignedChar(big_struct_type arg)
{
	u1 local_var;

	local_var = (u1) 7;
	return arg.uc + local_var;
}

u2 pcode_SUM7_BigStructAccessUnsignedShort(big_struct_type arg)
{
	u2 local_var;

	local_var = (u2) 7;
	return arg.us + local_var;
}

#ifdef HAS_FLOAT
f4 pcode_SUM42_BigUnionPtrAccessFloat(big_union_type *arg)
{
	f4 local_var;

	local_var = (f4) 7;
	return arg->f + local_var;
}
#endif

#ifdef HAS_DOUBLE
f8 pcode_SUM43_BigUnionPtrAccessDouble(big_union_type *arg)
{
	f8 local_var;

	local_var = (f8) 7;
	return arg->d + local_var;
}
#endif

#ifdef HAS_FLOAT
f4 pcode_SUM9_BigStructAccessFloat(big_struct_type arg)
{
	f4 local_var;

	local_var = (f4) 7;
	return arg.f + local_var;
}
#endif

big_union_type *pcode_SUM44_BigUnionPtrAccessBig_union_type_ptr(big_union_type *arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg->b + local_var;
}

#ifdef HAS_DOUBLE
f8 pcode_SUM10_BigStructAccessDouble(big_struct_type arg)
{
	f8 local_var;

	local_var = (f8) 7;
	return arg.d + local_var;
}
#endif

big_struct_type *pcode_SUM11_BigStructAccessBig_struct_type_ptr(big_struct_type arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg.b + local_var;
}

big_struct_type pcode_SUM46_BigStructModifyInt(big_struct_type arg, i4 field)
{
	arg.i = field;
	return arg;
}

#ifdef HAS_LONGLONG
big_struct_type pcode_SUM45_BigStructModifyLongLong(big_struct_type arg, i8 field)
{
	arg.ll = field;
	return arg;
}
#endif /* #ifdef HAS_LONGLONG */

big_struct_type pcode_SUM47_BigStructModifyShort(big_struct_type arg, i2 field)
{
	arg.s = field;
	return arg;
}

#ifdef HAS_LONGLONG
i8 pcode_SUM12_BigUnionAccessLongLong(big_union_type arg)
{
	i8 local_var;

	local_var = (i8) 7;
	return arg.ll + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

big_struct_type pcode_SUM48_BigStructModifyChar(big_struct_type arg, i1 field)
{
	arg.c = field;
	return arg;
}

i4 pcode_SUM13_BigUnionAccessInt(big_union_type arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg.i + local_var;
}

i2 pcode_SUM14_BigUnionAccessShort(big_union_type arg)
{
	i2 local_var;

	local_var = (i2) 7;
	return arg.s + local_var;
}

#ifdef HAS_LONGLONG
big_struct_type pcode_SUM49_BigStructModifyUnsignedLongLong(big_struct_type arg, u8 field)
{
	arg.ull = field;
	return arg;
}
#endif /* #ifdef HAS_LONGLONG */

i1 pcode_SUM15_BigUnionAccessChar(big_union_type arg)
{
	i1 local_var;

	local_var = (i1) 7;
	return arg.c + local_var;
}

big_struct_type pcode_SUM50_BigStructModifyUnsignedInt(big_struct_type arg, u4 field)
{
	arg.ui = field;
	return arg;
}

#ifdef HAS_LONGLONG
u8 pcode_SUM16_BigUnionAccessUnsignedLongLong(big_union_type arg)
{
	u8 local_var;

	local_var = (u8) 7;
	return arg.ull + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

big_struct_type pcode_SUM51_BigStructModifyUnsignedShort(big_struct_type arg, u2 field)
{
	arg.us = field;
	return arg;
}

u4 pcode_SUM17_BigUnionAccessUnsignedInt(big_union_type arg)
{
	u4 local_var;

	local_var = (u4) 7;
	return arg.ui + local_var;
}

big_struct_type pcode_SUM52_BigStructModifyUnsignedChar(big_struct_type arg, u1 field)
{
	arg.uc = field;
	return arg;
}

u2 pcode_SUM18_BigUnionAccessUnsignedShort(big_union_type arg)
{
	u2 local_var;

	local_var = (u2) 7;
	return arg.us + local_var;
}

u1 pcode_SUM19_BigUnionAccessUnsignedChar(big_union_type arg)
{
	u1 local_var;

	local_var = (u1) 7;
	return arg.uc + local_var;
}

#ifdef HAS_DOUBLE
big_struct_type pcode_SUM54_BigStructModifyDouble(big_struct_type arg, f8 field)
{
	arg.d = field;
	return arg;
}
#endif /* #ifdef HAS_DOUBLE */

#ifdef HAS_FLOAT
big_struct_type pcode_SUM53_BigStructModifyFloat(big_struct_type arg, f4 field)
{
	arg.f = field;
	return arg;
}
#endif /* #ifdef HAS_FLOAT */

big_struct_type pcode_SUM55_BigStructModifyBig_struct_type_ptr(big_struct_type arg, big_struct_type *field)
{
	arg.b = field;
	return arg;
}

#ifdef HAS_FLOAT
f4 pcode_SUM20_BigUnionAccessFloat(big_union_type arg)
{
	f4 local_var;

	local_var = (f4) 7;
	return arg.f + local_var;
}
#endif

#ifdef HAS_DOUBLE
f8 pcode_SUM21_BigUnionAccessDouble(big_union_type arg)
{
	f8 local_var;

	local_var = (f8) 7;
	return arg.d + local_var;
}
#endif

#ifdef HAS_LONGLONG
big_union_type pcode_SUM56_BigUnionModifyLongLong(big_union_type arg, i8 field)
{
	arg.ll = field;
	return arg;
}

#endif /* #ifdef HAS_LONGLONG */

big_union_type *pcode_SUM22_BigUnionAccessBig_union_type_ptr(big_union_type arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg.b + local_var;
}

big_union_type pcode_SUM57_BigUnionModifyInt(big_union_type arg, i4 field)
{
	arg.i = field;
	return arg;
}

#ifdef HAS_LONGLONG
i8 pcode_SUM23_BigStructPtrAccessLongLong(big_struct_type *arg)
{
	i8 local_var;

	local_var = (i8) 7;
	return arg->ll + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

big_union_type pcode_SUM58_BigUnionModifyShort(big_union_type arg, i2 field)
{
	arg.s = field;
	return arg;
}

i4 pcode_SUM24_BigStructPtrAccessInt(big_struct_type *arg)
{
	i4 local_var;

	local_var = (i4) 7;
	return arg->i + local_var;
}

big_union_type pcode_SUM59_BigUnionModifyChar(big_union_type arg, i1 field)
{
	arg.c = field;
	return arg;
}

i2 pcode_SUM25_BigStructPtrAccessShort(big_struct_type *arg)
{
	i2 local_var;

	local_var = (i2) 7;
	return arg->s + local_var;
}

i1 pcode_SUM26_BigStructPtrAccessChar(big_struct_type *arg)
{
	i1 local_var;

	local_var = (i1) 7;
	return arg->c + local_var;
}

big_union_type pcode_SUM63_BigUnionModifyUnsignedChar(big_union_type arg, u1 field)
{
	arg.uc = field;
	return arg;
}

big_union_type pcode_SUM62_BigUnionModifyUnsignedShort(big_union_type arg, u2 field)
{
	arg.us = field;
	return arg;
}

#ifdef HAS_LONGLONG
u8 pcode_SUM27_BigStructPtrAccessUnsignedLongLong(big_struct_type *arg)
{
	u8 local_var;

	local_var = (u8) 7;
	return arg->ull + local_var;
}
#endif /* #ifdef HAS_LONGLONG */

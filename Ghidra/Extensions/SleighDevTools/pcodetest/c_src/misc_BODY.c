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

static i4 int_expectedValue;
static i4 int_actualValue;

static i4 breakPointHere(void)
{
	return 1;
}

i4 recursionTestLevel(i4 level, u1 * array, i4 len)
{
	i4 i, ret = 0;
	u1 localArray[128];

	for (i = 0; i < sizeof(localArray); i++) {
		localArray[i] = (8 * level) + i;
	}

	if (level < 4 && (ret = recursionTestLevel(level + 1, localArray, len))) {
		return 1;
	}
	/* verify array integrity */
	for (i = 0; i < sizeof(localArray); i++) {
		if (localArray[i] != ((8 * level) + i)) {
			return ret + 1;
		}
	}
	/* verify array integrity */
	for (i = 0; i < sizeof(localArray); i++) {
		if (array[i] != ((8 * (level - 1)) + i)) {
			return ret + 1;
		}
	}
	return ret;
}

i2 nalign_i2(i2 in)
{
	char buffer[128];

	*(i2 *) (buffer + 1) = in;
	in += *(i2 *) (buffer + 1);
	*(i2 *) (buffer + 2) = in;
	in += *(i2 *) (buffer + 2);
	*(i2 *) (buffer + 3) = in;
	in += *(i2 *) (buffer + 3);
	*(i2 *) (buffer + 4) = in;
	in += *(i2 *) (buffer + 4);
	return in;
}

i4 nalign_i4(i4 in)
{
	char buffer[128];

	*(i4 *) (buffer + 1) = in;
	in += *(i4 *) (buffer + 1);
	*(i4 *) (buffer + 2) = in;
	in += *(i4 *) (buffer + 2);
	*(i4 *) (buffer + 3) = in;
	in += *(i4 *) (buffer + 3);
	*(i4 *) (buffer + 4) = in;
	in += *(i4 *) (buffer + 4);
	return in;
}

#ifdef HAS_LONGLONG
i8 nalign_i8(i8 in)
{
	char buffer[128];
	*(i8 *) (buffer + 1) = in;
	in += *(i8 *) (buffer + 1);
	*(i8 *) (buffer + 2) = in;
	in += *(i8 *) (buffer + 2);
	*(i8 *) (buffer + 3) = in;
	in += *(i8 *) (buffer + 3);
	*(i8 *) (buffer + 4) = in;
	in += *(i8 *) (buffer + 4);
	return in;
}
#endif /* #ifdef HAS_LONGLONG */

i4 nalign_struct(big_struct_type * in)
{
	i4 ret = 0;
	char buffer[128];

	in->i = 0x5;
	if (in->i != 0x5)
		ret++;
	in->s = 0x6;
	if (in->s != 0x6)
		ret++;
	in->c = 0x7;
	if (in->c != 0x7)
		ret++;
#ifdef HAS_LONGLONG
	in->ll = 0x8;
	if (in->ll != 0x8)
		ret++;
#endif
	return ret;
}

u4 pcode_memset(u1 *lhs, u1 val, u4 len)
{
	memset(lhs, val, (size_t) len);
	return *(u4 *) lhs;
}

void *pcode_memcpy(u1 * lhs, u1 * rhs, u4 len)
{
	return memcpy(lhs, rhs, (size_t) len);
}

u4 pcode_memcmp_u4(u4 lhs, u4 rhs)
{
	return (u4) (memcmp(&lhs, &rhs, 4) == 0 ? 0 : 1);
}

u4 pcode_memcmp_n(u1 * lhs, u1 * rhs, u4 len)
{
	return (u4) (memcmp(lhs, rhs, (size_t) len) == 0 ? 0 : 1);
}

#if defined(HAS_FLOAT) && defined(HAS_DOUBLE) && defined(HAS_LONGLONG)

/* Almost equal here means a difference between f1 and f2 that is less
 * than 1% of f2. Naturally, f2 != 0. Implement it without calling
 * fabs, which would cast everything to double anyway.
 */

static int FLOAT_ALMOST_EQUAL(double f1, double f2)
{
	double d = (f1 >= f2 ? f1 - f2 : f2 - f1);
	double m = (f2 >= 0.0 ? f2 : -f2) * 0.01;
	return d < m;
}

i4 pcode_conversions(int argc)
{
	i1 u1buff[8];
	u2 u2buff[8];
	u4 u4buff[8];
	u8 u8buff[8];
	f4 f4buff[8];
	f8 f8buff[8];
	u8 ret = 0;
	i4 i = 0;

	f4 f4_1 = argc;
	f4 f4_2 = 4.0 - f4_1;
	if (f4_2 != 4.0)
		return 101;

	f4 f4_3 = f4_1 + 5.0;
	if (f4_3 != 5.0)
		return 102;

	f8 f8_1 = argc;
	f8 f8_2 = 4.0 - f8_1;
	if (f8_2 != 4.0)
		return 103;

	f8 f8_3 = f8_1 + 5.0;
	if (f8_3 != 5.0)
		return 104;

	for (i = 0; i < 8; i++) {
		u1buff[i] = 0;
		u2buff[i] = 0;
		u4buff[i] = 0;
		u8buff[i] = 0;
		f4buff[i] = 0;
		f8buff[i] = 0;
	}
	u8buff[0] = 0x0FFFFFFFFFFFFFFFULL;

	u4buff[0] = u8buff[0] + argc;

	u2buff[0] = u8buff[0] + argc;
	u2buff[1] = u4buff[0] + argc;

	u1buff[0] = u8buff[0] + argc;
	u1buff[1] = u4buff[0] + argc;
	u1buff[2] = u2buff[0] + argc;

	if (u1buff[0] != (i1) 0xff || u1buff[1] != (i1) 0xff || u1buff[2] != (i1) 0xff || u2buff[0] != 0xffff || u2buff[1] != 0xffff || u4buff[0] != 0xffffffff || u8buff[0] != 0x0fffffffffffffffULL)
		return 1;

	f4buff[0] = 1.0 + argc;
	if (!FLOAT_ALMOST_EQUAL(f4buff[0], 1.0))
		return 21;

	f4buff[0] = u8buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f4buff[0], 1.152921504606846976e+18))
		return 2;

	f4buff[1] = u4buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f4buff[1], 4.294967296e+09))
		return 3;

	f4buff[2] = u2buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f4buff[2], 6.5535e+04))
		return 4;

	f4buff[3] = u1buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f4buff[3], -1.0e+00))
		return 5;

	f8buff[0] = u8buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f8buff[0], 1.152921504606846976e+18))
		return 6;

	f8buff[1] = u4buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f8buff[1], 4.294967295e+09))
		return 7;
	f8buff[2] = u2buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f8buff[2], 6.5535e+04))
		return 8;

	f8buff[3] = u1buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f8buff[3], -1.0e+00))
		return 9;

	f8buff[4] = f4buff[0] + argc;
	if (!FLOAT_ALMOST_EQUAL(f8buff[4], 1.152921504606846976e+18))
		return 10;

	f8 tmpf8 = f8buff[4] + f8buff[3] - f8buff[2] + f8buff[1] - f8buff[0]
		+ f4buff[4] + f4buff[3] - f4buff[2] + f4buff[1] - f4buff[0];

	if (!FLOAT_ALMOST_EQUAL(tmpf8, -1.15292149601704345600e+18))
		return 11;

	u8 retll = u1buff[0] + u1buff[1] - u1buff[2] + u4buff[0] + u8buff[0];

	if (retll != 0x10000000fffffffdULL)
		return 12;

	return 0;		// OK
}
#endif /* #if defined(HAS_FLOAT) && defined(HAS_DOUBLE) && defined(HAS_LONGLONG) */

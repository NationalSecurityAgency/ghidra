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


u2 pcode_bswap_u2(u2 x)
{
    u2 y;
    y = __builtin_bswap16(x);
    return y;
}

u4 pcode_bswap_u4(u4 x)
{
    u4 y;
    y = __builtin_bswap32(x);
    return y;
}

#ifdef HAS_LONGLONG
u8 pcode_bswap_u8(u8 x)
{
    u8 y;
    y = __builtin_bswap64(x);
    return y;
}
#endif

i2 pcode_bswap_i2(i2 x)
{
    i2 y;
    y = __builtin_bswap16(x);
    return y;
}

i4 pcode_bswap_i4(i4 x)
{
    i4 y;
    y = __builtin_bswap32(x);
    return y;
}

#ifdef HAS_LONGLONG
i8 pcode_bswap_i8(i8 x)
{
    i8 y;
    y = __builtin_bswap64(x);
    return y;
}
#endif

// compare exchange if x===y -> z, else -> x
#define PCODE_LOAD_STORE(typ)						\
    typ pcode_atomic_load_store_##typ(typ x)				\
    {									\
	typ a = 0;							\
	__atomic_store_n(&a, x, __ATOMIC_SEQ_CST);			\
	x = __atomic_load_n(&a, __ATOMIC_SEQ_CST);			\
	return x;							\
    }

#define PCODE_ATOMICS(typ)						\
    typ pcode_atomic_exchange_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	a = __atomic_exchange_n(&a, y, __ATOMIC_ACQ_REL);		\
	return a;							\
    }									\
    typ pcode_atomic_compare_exchange_##typ(typ x, typ y, typ z)	\
    {									\
	typ a = x;							\
	typ b = y;							\
	if (__atomic_compare_exchange_n(&a, &b, z, 0,			\
				      __ATOMIC_ACQ_REL,			\
				      __ATOMIC_ACQUIRE))		\
	    return a;							\
	return b;							\
    }									\
    typ pcode_atomic_add_fetch_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_add_fetch(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_sub_fetch_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_sub_fetch(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_and_fetch_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_and_fetch(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_xor_fetch_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_xor_fetch(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_or_fetch_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_or_fetch(&a, y, __ATOMIC_ACQ_REL);			\
	return b;							\
    }									\
    typ pcode_atomic_nand_fetch_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_nand_fetch(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_fetch_add_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_fetch_add(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_fetch_sub_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_fetch_sub(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_fetch_and_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_fetch_and(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_fetch_xor_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_fetch_xor(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }									\
    typ pcode_atomic_fetch_or_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_fetch_or(&a, y, __ATOMIC_ACQ_REL);			\
	return b;							\
    }									\
    typ pcode_atomic_fetch_nand_##typ(typ x, typ y)			\
    {									\
	typ a = x;							\
	typ b;								\
	b = __atomic_fetch_nand(&a, y, __ATOMIC_ACQ_REL);		\
	return b;							\
    }



PCODE_LOAD_STORE(u1)
PCODE_LOAD_STORE(i1)
PCODE_LOAD_STORE(u2)
PCODE_LOAD_STORE(i2)
PCODE_LOAD_STORE(u4)
PCODE_LOAD_STORE(i4)

PCODE_ATOMICS(u4)
PCODE_ATOMICS(i4)

#ifdef HAS_LONGLONG
PCODE_LOAD_STORE(u8)
PCODE_LOAD_STORE(i8)
PCODE_ATOMICS(u8)
PCODE_ATOMICS(i8)
#endif


#define PCODE_OVERFLOW(typ)				\
    typ pcode_add_overflow_##typ(typ x, typ y)		\
    {							\
	typ a;						\
	a = (typ)__builtin_add_overflow_p(x, y, a);	\
	return a;					\
    }							\
    typ pcode_sub_overflow_##typ(typ x, typ y)		\
    {							\
	typ a;						\
	a = (typ)__builtin_sub_overflow_p(x, y, a);	\
	return a;					\
    }							\
    typ pcode_mul_overflow_##typ(typ x, typ y)		\
    {							\
	typ a;						\
	a = (typ)__builtin_mul_overflow_p(x, y, a);	\
	return a;					\
    }

PCODE_OVERFLOW(u1)
PCODE_OVERFLOW(u2)
PCODE_OVERFLOW(u4)
PCODE_OVERFLOW(i1)
PCODE_OVERFLOW(i2)
PCODE_OVERFLOW(i4)
#ifdef HAS_LONGLONG
PCODE_OVERFLOW(u8)
PCODE_OVERFLOW(i8)
#endif

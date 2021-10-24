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
#ifndef PCODE_TEST_H
#define PCODE_TEST_H

#include "types.h"

#define TEST void
#define MAIN void

#ifdef HAS_GNU_ATTRIBUTES
#define NOINLINE __attribute__ ((__noinline__))
#define PACKED_STRUCTURE __attribute__((__packed__))
#else
#define NOINLINE
#define PACKED_STRUCTURE
#endif

typedef i4 (*testFuncPtr)(void);

typedef struct PACKED_STRUCTURE FunctionInfo
{
	char *name;			/* Name of function, used in pcode test reporting */
	testFuncPtr func;		/* Pointer to function */
	i4 numTest;			/* Number of expected tests */
} FunctionInfo;

typedef struct PACKED_STRUCTURE TestInfo
{
	char id[8];			/* id constains a "Magic Number" which will allow us to find this in a binary */
	u4 ptrSz;			/* how many bytes in a pointer? */
	u4 byteOrder;			/* value 0x01020304 used to detect endianess */
	void *onPass;			/* address of breakOnPass function, (where it goes on test pass) */
	void *onError;		/* address of breakOnError function, (where it goes on test failure) */
	void *onDone;		/* address of breakOnDone function, (where it goes when all test done) */
	u4 numpass;			/* How many test passed */
	u4 numfail;			/* How many test failed */
	u4 lastTestPos;			/* Last test index number */
	u4 lastErrorLine;		/* Line number of last error. */
	char *lastErrorFile;		/* File name of last error. */
	char *lastFunc;			/* Last function ran. */
	void *sprintf5;			/* Our embedded sprintf function */
	void *sprintf5buffer;		/* Buffer where our embedded sprintf write to */
	u4 sprintf5Enabled;		/* Turn on off our embedded sprintf */
	char *compilerVersion;		/* Compiler version info (gcc specific) */
	char *name;			/* Test binary name */
	char *ccflags;			/* Flags used to compile this */
	char *buildDate;		/* when this was  compiled */
	FunctionInfo *funcTable;	/* a function table */
} TestInfo;

typedef struct PACKED_STRUCTURE GroupInfo
{
	char id[8];			/* id constains a "Magic Number" which will allow us to find this in a binary */
	FunctionInfo *funcTable;	/* Table of test functions in this group */
} GroupInfo;

void noteTestMain(const char *file, int line, const char *func);
void assertI1(const char *file, int line, const char *func, i1 val, i1 expected);
void assertI2(const char *file, int line, const char *func, i2 val, i2 expected);
void assertI4(const char *file, int line, const char *func, i4 val, i4 expected);
#ifdef HAS_LONGLONG
void assertI8(const char *file, int line, const char *func, i8 val, i8 expected);
#endif
void assertU1(const char *file, int line, const char *func, u1 val, u1 expected);
void assertU2(const char *file, int line, const char *func, u2 val, u2 expected);
void assertU4(const char *file, int line, const char *func, u4 val, u4 expected);
#ifdef HAS_LONGLONG
void assertU8(const char *file, int line, const char *func, u8 val, u8 expected);
#endif
#ifdef HAS_FLOAT
void assertF4(const char *file, int line, const char *func, f4 val, f4 expected);
#endif
#ifdef HAS_DOUBLE
void assertF8(const char *file, int line, const char *func, f8 val, f8 expected);
#endif
NOINLINE i4 breakOnDone(const char *file, int line, const char *func);
// NOINLINE void TestInfo_register(void);	/* Register a TestInfo */
NOINLINE void TestInfo_reset(void);
NOINLINE i4 breakOnSubDone(const char *file, int line, const char *func);

#define ASSERTI1(val, exp)  assertI1(__FILE__, __LINE__, 0, val, exp);
#define ASSERTI2(val, exp)  assertI2(__FILE__, __LINE__, 0, val, exp);
#define ASSERTI4(val, exp)  assertI4(__FILE__, __LINE__, 0, val, exp);
#define ASSERTI8(val, exp)  assertI8(__FILE__, __LINE__, 0, val, exp);
#define ASSERTU1(val, exp)  assertU1(__FILE__, __LINE__, 0, val, exp);
#define ASSERTU2(val, exp)  assertU2(__FILE__, __LINE__, 0, val, exp);
#define ASSERTU4(val, exp)  assertU4(__FILE__, __LINE__, 0, val, exp);
#define ASSERTU8(val, exp)  assertU8(__FILE__, __LINE__, 0, val, exp);
#define ASSERTF4(val, exp)  assertF4(__FILE__, __LINE__, 0, val, exp);
#define ASSERTF8(val, exp)  assertF8(__FILE__, __LINE__, 0, val, exp);



/**
 * Macros for basic operations for a type.  Tries to shift values when possible
 * to other registers to hopefully exercise more more SLEIGH code paths and
 * corner cases based on specific register usage.
 * TODO  `-fno-ipa-sra` would be nice for the dummy argument, not sure how to
 *       get around that w/o or if it is even worth the dummy argument.
 */

#ifndef PCODE_COMPLEX_LOGIC
#define PCODE_COMPLEX_LOGIC(typ)			\
typ typ##_complexLogic(					\
			typ a,				\
			typ b,				\
			typ c,				\
			typ d,				\
			typ e,				\
			typ f)				\
{							\
	typ ret = 0;					\
							\
	if (a > b && b > c || d < e && f < e)		\
		ret += 1;				\
	if (a != b || a != c && d != e || f != e)	\
		ret += 2;				\
	if (a && b && c || d && e && f)			\
		ret += 4;				\
	if (a || b || c && d || e || f)			\
		ret += 8;				\
	return ret;					\
}
#endif
#ifndef PCODE_COMPARE_LOGIC
#define PCODE_COMPARE_LOGIC(typ)	\
typ typ##_compareLogic(			\
			typ lhs,	\
			typ rhs)	\
{					\
	if (lhs == 0)			\
		lhs += 1;		\
	if (lhs < rhs)			\
		lhs += 2;		\
	if (lhs > rhs)			\
		lhs += 4;		\
	if (lhs != rhs)			\
		lhs += 8;		\
	if (lhs == rhs)			\
		lhs += 16;		\
	return lhs;			\
}
#endif
#ifndef PCODE_SUBTRACT
#define PCODE_SUBTRACT(typ)					\
    static __attribute__((noinline))				\
    typ typ##_subtract0(					\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs - rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_subtract1(					\
			__attribute__((unused))typ dummy,	\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs - rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_subtract2(					\
			typ rhs,				\
			typ lhs)				\
    {								\
	typ z;							\
	z = lhs - rhs;						\
	return z;						\
    }								\
    typ typ##_subtract(						\
		       typ lhs,					\
		       typ rhs)					\
    {								\
	return typ##_subtract0(lhs,rhs) &			\
	    typ##_subtract1(0,lhs,rhs) &			\
	    typ##_subtract2(rhs, lhs);				\
								\
    }
#endif
#ifndef PCODE_SUBTRACT_FLOAT
#define PCODE_SUBTRACT_FLOAT(typ)				\
    typ typ##_subtract(typ lhs, typ rhs)			\
    {								\
	return lhs - rhs;					\
    }
#endif
#ifndef PCODE_ADDITION
#define PCODE_ADDITION(typ)					\
    static __attribute__((noinline))				\
    typ typ##_addition0(					\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs + rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_addition1(					\
			__attribute__((unused))typ dummy,	\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs + rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_addition2(					\
			typ rhs,				\
			typ lhs)				\
    {								\
	typ z;							\
	z = lhs + rhs;						\
	return z;						\
    }								\
    typ typ##_addition(						\
		       typ lhs,					\
		       typ rhs)					\
    {								\
	return typ##_addition0(lhs, rhs) &			\
	    typ##_addition1(0, lhs, rhs) &			\
	    typ##_addition2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_ADDITION_FLOAT
#define PCODE_ADDITION_FLOAT(typ)				\
    typ typ##_addition(typ lhs, typ rhs)			\
    {								\
	return lhs + rhs;					\
    }
#endif
#ifndef PCODE_BITWISE_AND
#define PCODE_BITWISE_AND(typ)					\
    static __attribute__((noinline))				\
    typ typ##_bitwiseAnd0(					\
			  typ lhs,				\
			  typ rhs)				\
    {								\
	typ z;							\
	z = lhs & rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_bitwiseAnd1(					\
			  __attribute__((unused))typ dummy,	\
			  typ lhs,				\
			  typ rhs)				\
    {								\
	typ z;							\
	z = lhs & rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_bitwiseAnd2(					\
			  typ rhs,				\
			  typ lhs)				\
    {								\
	typ z;							\
	z = lhs & rhs;						\
	return z;						\
    }								\
    typ typ##_bitwiseAnd(					\
			 typ lhs,				\
			 typ rhs)				\
    {								\
	return typ##_bitwiseAnd0(lhs, rhs) &			\
	    typ##_bitwiseAnd1(0, lhs, rhs) &			\
	    typ##_bitwiseAnd2(rhs, lhs);			\
    }
#endif
#ifndef PCODE_BITWISE_AND_FLOAT
#define PCODE_BITWISE_AND_FLOAT(typ)				\
    typ typ##_bitwiseAnd(typ lhs, typ rhs)			\
    {								\
	return lhs & rhs;					\
    }
#endif
#ifndef PCODE_BITWISE_OR
#define PCODE_BITWISE_OR(typ)					\
    static __attribute__((noinline))				\
    typ typ##_bitwiseOr0(					\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs | rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_bitwiseOr1(					\
			__attribute__((unused))typ dummy,	\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs | rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_bitwiseOr2(					\
			typ rhs,				\
			typ lhs)				\
    {								\
	typ z;							\
	z = lhs | rhs;						\
	return z;						\
    }								\
    typ typ##_bitwiseOr(					\
			typ lhs,				\
			typ rhs)				\
    {								\
	return typ##_bitwiseOr0(lhs, rhs) &			\
	    typ##_bitwiseOr1(0, lhs, rhs) &			\
	    typ##_bitwiseOr2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_BITWISE_OR_FLOAT
#define PCODE_BITWISE_OR_FLOAT(typ)				\
    typ typ##_bitwiseOr(typ lhs, typ rhs)			\
    {								\
	return lhs | rhs;					\
    }
#endif
#ifndef PCODE_LOGICAL_AND
#define PCODE_LOGICAL_AND(typ)					\
    static __attribute__((noinline))				\
    typ typ##_logicalAnd0(					\
			 typ lhs,				\
			 typ rhs)				\
    {								\
	typ z;							\
	z = lhs && rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_logicalAnd1(					\
			 __attribute__((unused))typ dummy,	\
			 typ lhs,				\
			 typ rhs)				\
    {								\
	typ z;							\
	z = lhs && rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_logicalAnd2(					\
			 typ rhs,				\
			 typ lhs)				\
    {								\
	typ z;							\
	z = lhs && rhs;						\
	return z;						\
    }								\
    typ typ##_logicalAnd(					\
			 typ lhs,				\
			 typ rhs)				\
    {								\
	return typ##_logicalAnd0(lhs, rhs) &			\
	    typ##_logicalAnd1(0, lhs, rhs) &			\
	    typ##_logicalAnd2(rhs, lhs);			\
    }
#endif
#ifndef PCODE_LOGICAL_AND_FLOAT
#define PCODE_LOGICAL_AND_FLOAT(typ)					\
    typ typ##_logicalAnd(typ lhs, typ rhs)			\
    {								\
	return lhs && rhs;					\
    }
#endif
#ifndef PCODE_LOGICAL_OR
#define PCODE_LOGICAL_OR(typ)					\
    static __attribute__((noinline))				\
    typ typ##_logicalOr0(					\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs || rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_logicalOr1(					\
			__attribute__((unused))typ dummy,	\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs || rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_logicalOr2(					\
			typ rhs,				\
			typ lhs)				\
    {								\
	typ z;							\
	z = lhs || rhs;						\
	return z;						\
    }								\
    typ typ##_logicalOr(						\
		       typ lhs,					\
		       typ rhs)					\
    {								\
	return typ##_logicalOr0(lhs, rhs) &			\
	    typ##_logicalOr1(0, lhs, rhs) &			\
	    typ##_logicalOr2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_LOGICAL_OR_FLOAT
#define PCODE_LOGICAL_OR_FLOAT(typ)				\
    typ typ##_logicalOr(typ lhs, typ rhs)			\
    {								\
	return lhs || rhs;					\
    }
#endif
#ifndef PCODE_LESSTHANEQUALS
#define PCODE_LESSTHANEQUALS(typ)				\
    static __attribute__((noinline))				\
    typ typ##_lessThanEquals0(					\
			      typ lhs,				\
			      typ rhs)				\
    {								\
	typ z;							\
	z = lhs <= rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_lessThanEquals1(					\
			      __attribute__((unused))typ dummy,	\
			      typ lhs,				\
			      typ rhs)				\
    {								\
	typ z;							\
	z = lhs <= rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_lessThanEquals2(					\
			      typ rhs,				\
			      typ lhs)				\
    {								\
	typ z;							\
	z = lhs <= rhs;						\
	return z;						\
    }								\
    typ typ##_lessThanEquals(					\
			     typ lhs,				\
			     typ rhs)				\
    {								\
	return typ##_lessThanEquals0(lhs, rhs) &		\
	    typ##_lessThanEquals1(0, lhs, rhs) &		\
	    typ##_lessThanEquals2(rhs, lhs);			\
    }
#endif
#ifndef PCODE_LESSTHANEQUALS_FLOAT
#define PCODE_LESSTHANEQUALS_FLOAT(typ)				\
    typ typ##_lessThanEquals(typ lhs, typ rhs)			\
    {								\
	return lhs <= rhs;					\
    }
#endif
#ifndef PCODE_LESSTHAN
#define PCODE_LESSTHAN(typ)					\
    static __attribute__((noinline))				\
    typ typ##_lessThan0(					\
			typ lhs,				\
			typ rhs)				\
    {								\
	typ z;							\
	z = lhs < rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_lessThan1(					\
			__attribute__((unused))typ dummy,	\
			typ lhs,				\
			typ rhs)				\
    {								\
        typ z;							\
	z = lhs < rhs;						\
	return z;						\
    }								\
    static __attribute__((noinline))				\
    typ typ##_lessThan2(					\
			typ rhs,				\
			typ lhs)				\
    {								\
	typ z;							\
	z = lhs < rhs;						\
	return z;						\
    }								\
    typ typ##_lessThan(						\
		       typ lhs,					\
		       typ rhs)					\
    {								\
	return typ##_lessThan0(lhs, rhs) &			\
	    typ##_lessThan1(0, lhs, rhs) &			\
	    typ##_lessThan2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_LESSTHAN_FLOAT
#define PCODE_LESSTHAN_FLOAT(typ)				\
    typ typ##_lessThan(typ lhs, typ rhs)				\
    {								\
	return (typ)(lhs < rhs);					\
    }
#endif
#ifndef PCODE_GREATERTHANEQUALS
#define PCODE_GREATERTHANEQUALS(typ)					\
    static __attribute__((noinline))					\
    typ typ##_greaterThanEquals0(					\
				 typ lhs,				\
				 typ rhs)				\
    {									\
	typ z;								\
	z = lhs >= rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_greaterThanEquals1(					\
				 __attribute__((unused))typ dummy,	\
				 typ lhs,				\
				 typ rhs)				\
    {									\
	typ z;								\
	z = lhs >= rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_greaterThanEquals2(					\
				 typ rhs,				\
				 typ lhs)				\
    {									\
	typ z;								\
	z = lhs >= rhs;							\
	return z;							\
    }									\
    typ typ##_greaterThanEquals(					\
				typ lhs,				\
				typ rhs)				\
    {									\
	return typ##_greaterThanEquals0(lhs, rhs) &			\
	    typ##_greaterThanEquals1(0, lhs, rhs) &			\
	    typ##_greaterThanEquals2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_GREATERTHANEQUALS_FLOAT
#define PCODE_GREATERTHANEQUALS_FLOAT(typ)				\
    typ typ##_greaterThanEquals(typ lhs, typ rhs)			\
    {									\
	return lhs >= rhs;						\
    }
#endif
#ifndef PCODE_GREATERTHAN
#define PCODE_GREATERTHAN(typ)						\
    static __attribute__((noinline))					\
    typ typ##_greaterThan0(						\
			   typ lhs,					\
			   typ rhs)					\
    {									\
	typ z;								\
	z = lhs > rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_greaterThan1(						\
			   __attribute__((unused))typ dummy,		\
			   typ lhs,					\
			   typ rhs)					\
    {									\
	typ z;								\
	z = lhs > rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_greaterThan2(						\
			   typ rhs,					\
			   typ lhs)					\
    {									\
	typ z;								\
	z = lhs > rhs;							\
	return z;							\
    }									\
    typ typ##_greaterThan(						\
			  typ lhs,					\
			  typ rhs)					\
    {									\
	return typ##_greaterThan0(lhs, rhs) &				\
	    typ##_greaterThan1(0, lhs, rhs) &				\
	    typ##_greaterThan2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_GREATERTHAN_FLOAT
#define PCODE_GREATERTHAN_FLOAT(typ)					\
    typ typ##_greaterThan(typ lhs, typ rhs)				\
    {									\
	return lhs > rhs;						\
    }
#endif
#ifndef PCODE_EQUALS
#define PCODE_EQUALS(typ)						\
    static __attribute__((noinline))					\
    typ typ##_equals0(							\
		      typ lhs,						\
		      typ rhs)						\
    {									\
	typ z;								\
	z = lhs == rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_equals1(							\
		      __attribute__((unused))typ dummy,			\
		      typ lhs,						\
		      typ rhs)						\
    {									\
	typ z;								\
	z = lhs == rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_equals2(							\
		      typ rhs,						\
		      typ lhs)						\
    {									\
	typ z;								\
	z = lhs == rhs;							\
	return z;							\
    }									\
    typ typ##_equals(							\
		     typ lhs,						\
		     typ rhs)						\
    {									\
	return typ##_equals0(lhs, rhs) &				\
	    typ##_equals1(0, lhs, rhs) &				\
	    typ##_equals2(rhs, lhs);					\
    }
#endif
#ifndef PCODE_EQUALS_FLOAT
#define PCODE_EQUALS_FLOAT(typ)						\
    typ typ##_equals(typ lhs, typ rhs)					\
    {									\
	return lhs == rhs;						\
    }
#endif
#ifndef PCODE_NOTEQUALS
#define PCODE_NOTEQUALS(typ)						\
    static __attribute__((noinline))					\
    typ typ##_notEquals0(						\
			typ lhs,					\
			typ rhs)					\
    {									\
        typ z;								\
	z = lhs != rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_notEquals1(						\
			__attribute__((unused))typ dummy,		\
			typ lhs,					\
			typ rhs)					\
    {									\
	typ z;								\
	z = lhs != rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_notEquals2(						\
			typ rhs,					\
			typ lhs)					\
    {									\
	typ z;								\
	z = lhs != rhs;							\
	return z;							\
    }									\
    typ typ##_notEquals(						\
			typ lhs,					\
			typ rhs)					\
    {									\
	return typ##_notEquals0(lhs, rhs) &				\
	    typ##_notEquals1(0, lhs, rhs) &				\
	    typ##_notEquals2(rhs, lhs);					\
    }
#endif
#ifndef PCODE_NOTEQUALS_FLOAT
#define PCODE_NOTEQUALS_FLOAT(typ)					\
    typ typ##_notEquals(typ lhs, typ rhs)				\
    {									\
	return lhs != rhs;						\
    }
#endif
#ifndef PCODE_XOR
#define PCODE_XOR(typ)							\
    static __attribute__((noinline))					\
    typ typ##_bitwiseXor0(						\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	typ z;								\
	z = lhs ^ rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_bitwiseXor1(						\
			 __attribute__((unused))typ dummy,		\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	typ z;								\
	z = lhs ^ rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_bitwiseXor2(						\
			 typ rhs,					\
			 typ lhs)					\
    {									\
	typ z;								\
	z = lhs ^ rhs;							\
	return z;							\
    }									\
    typ typ##_bitwiseXor(						\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	return typ##_bitwiseXor0(lhs, rhs) &				\
	    typ##_bitwiseXor1(0, lhs, rhs) &				\
	    typ##_bitwiseXor2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_XOR_FLOAT
#define PCODE_XOR_FLOAT(typ)						\
    typ typ##_bitwiseXor(typ lhs, typ rhs)				\
    {									\
	return lhs ^ rhs;						\
    }
#endif
#ifndef PCODE_SHIFTLEFT
#define PCODE_SHIFTLEFT(typ)						\
    static __attribute__((noinline))					\
    typ typ##_shiftLeft0(						\
			typ lhs,					\
			typ rhs)					\
    {									\
	typ z;								\
	z = lhs << rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_shiftLeft1(						\
			__attribute__((unused))typ dummy,		\
			typ lhs,					\
			typ rhs)					\
    {									\
	typ z;								\
	z = lhs << rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_shiftLeft2(						\
			typ rhs,					\
			typ lhs)					\
    {									\
	typ z;								\
	z = lhs << rhs;							\
	return z;							\
    }									\
    typ typ##_shiftLeft(						\
			typ lhs,					\
			typ rhs)					\
    {									\
	return typ##_shiftLeft0(lhs, rhs) &				\
	    typ##_shiftLeft1(0, lhs, rhs) &				\
	    typ##_shiftLeft2(rhs, lhs);					\
    }
#endif
#ifndef PCODE_SHIFTLEFT_FLOAT
#define PCODE_SHIFTLEFT_FLOAT(typ)					\
    typ typ##_shiftLeft(typ lhs, typ rhs)				\
    {									\
	return lhs << rhs;						\
    }
#endif
#ifndef PCODE_SHIFTRIGHT
#define PCODE_SHIFTRIGHT(typ)						\
    static __attribute__((noinline))					\
    typ typ##_shiftRight0(						\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	typ z;								\
	z = lhs >> rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_shiftRight1(						\
			 __attribute__((unused))typ dummy,		\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	typ z;								\
	z = lhs >> rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_shiftRight2(						\
			 typ rhs,					\
			 typ lhs)					\
    {									\
	typ z;								\
	z = lhs >> rhs;							\
	return z;							\
    }									\
    typ typ##_shiftRight(						\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	return typ##_shiftRight0(lhs, rhs) &				\
	    typ##_shiftRight1(0, lhs, rhs) &				\
	    typ##_shiftRight2(rhs, lhs);				\
    }
#endif
#ifndef PCODE_SHIFTRIGHT_FLOAT
#define PCODE_SHIFTRIGHT_FLOAT(typ)					\
    typ typ##_shiftRight(typ lhs, typ rhs)				\
    {									\
	return lhs >> rhs;						\
    }
#endif
#ifndef PCODE_LOGICAL_NOT
#define PCODE_LOGICAL_NOT(typ)						\
    static __attribute__((noinline))					\
    typ typ##_logicalNot0(typ a)					\
    {									\
	typ z;								\
	z = !a;								\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_logicalNot1(__attribute__((unused))typ dummy,		\
			  typ a)					\
    {									\
	typ z;								\
	z = !a;								\
	return z;							\
    }									\
    typ typ##_logicalNot(typ a)						\
    {									\
	return typ##_logicalNot0(a) &					\
	    typ##_logicalNot1(0, a);					\
    }
#endif
#ifndef PCODE_LOGICAL_NOT_FLOAT
#define PCODE_LOGICAL_NOT_FLOAT(typ)					\
    typ typ##_logicalNot(typ a)						\
    {									\
	return !a;							\
    }
#endif
#ifndef PCODE_UNARY_PLUS
#define PCODE_UNARY_PLUS(typ)						\
    static __attribute__((noinline))					\
    typ typ##_unaryPlus0(typ a)						\
    {									\
	typ z;								\
	z = +a;								\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_unaryPlus1(__attribute__((unused))typ dummy,		\
			 typ a)						\
    {									\
	typ z;								\
	z = +a;								\
	return z;							\
    }									\
    typ typ##_unaryPlus(typ a)						\
    {									\
	return typ##_unaryPlus0(a) &					\
	    typ##_unaryPlus1(0, a);					\
    }
#endif
#ifndef PCODE_UNARY_PLUS_FLOAT
#define PCODE_UNARY_PLUS_FLOAT(typ)					\
    typ typ##_unaryPlus(typ a)						\
    {									\
	return +a;							\
    }
#endif
#ifndef PCODE_UNARY_MINUS
#define PCODE_UNARY_MINUS(typ)						\
    static __attribute__((noinline))					\
    typ typ##_unaryMinus0(typ a)					\
    {									\
	typ z;								\
	z = -a;								\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_unaryMinus1(__attribute__((unused))typ dummy,		\
			  typ a)					\
    {									\
	typ z;								\
	z = -a;								\
	return z;							\
    }									\
    typ typ##_unaryMinus(typ a)						\
    {									\
	return typ##_unaryMinus0(a) &					\
	    typ##_unaryMinus1(0, a);					\
    }
#endif
#ifndef PCODE_UNARY_MINUS_FLOAT
#define PCODE_UNARY_MINUS_FLOAT(typ)					\
    typ typ##_unaryMinus(typ a)						\
    {									\
	return -a;							\
    }
#endif
#ifndef PCODE_DIV
#define PCODE_DIV(typ)							\
    static __attribute__((noinline))					\
    typ typ##_divide0(							\
		      typ lhs,						\
		      typ rhs)						\
    {									\
	typ z;								\
	z = lhs / rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_divide1(							\
		      __attribute__((unused))typ dummy,			\
		      typ lhs,						\
		      typ rhs)						\
    {									\
	typ z;								\
	z = lhs / rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_divide2(							\
		      typ rhs,						\
		      typ lhs)						\
    {									\
	typ z;								\
	z = lhs / rhs;							\
	return z;							\
    }									\
    typ typ##_divide(							\
		     typ lhs,						\
		     typ rhs)						\
    {									\
	return typ##_divide0(lhs, rhs) &				\
	    typ##_divide1(0, lhs, rhs) &				\
	    typ##_divide2(rhs, lhs);					\
    }
#endif
#ifndef PCODE_DIV_FLOAT
#define PCODE_DIV_FLOAT(typ)						\
    typ typ##_divide(typ lhs, typ rhs)					\
    {									\
	return lhs / rhs;						\
    }
#endif
#ifndef PCODE_REM
#define PCODE_REM(typ)							\
    static __attribute__((noinline))					\
    typ typ##_remainder0(						\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	typ z;								\
	z = lhs % rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_remainder1(						\
			 __attribute__((unused))typ dummy,		\
			 typ lhs,					\
			 typ rhs)					\
    {									\
	typ z;								\
	z = lhs % rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_remainder2(						\
			 typ rhs,					\
			 typ lhs)					\
    {									\
	typ z;								\
	z = lhs % rhs;							\
	return z;							\
    }									\
    typ typ##_remainder(						\
			typ lhs,					\
			typ rhs)					\
    {									\
	return typ##_remainder0(lhs, rhs) &				\
	    typ##_remainder1(0, lhs, rhs) &				\
	    typ##_remainder2(rhs, lhs);					\
    }
#endif
#ifndef PCODE_REM_FLOAT
#define PCODE_REM_FLOAT(typ)						\
    typ typ##_remainder(typ lhs, typ rhs)				\
    {									\
	return lhs % rhs;						\
    }
#endif
#ifndef PCODE_MUL
#define PCODE_MUL(typ)							\
    static __attribute__((noinline))					\
    typ typ##_multiply0(						\
			typ lhs,					\
			typ rhs)					\
    {									\
	typ z;								\
	z = lhs * rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_multiply1(						\
			__attribute__((unused))typ dummy,		\
			typ lhs,					\
			typ rhs)					\
    {									\
	typ z;								\
	z = lhs * rhs;							\
	return z;							\
    }									\
    static __attribute__((noinline))					\
    typ typ##_multiply2(						\
			typ rhs,					\
			typ lhs)					\
    {									\
	typ z;								\
	z = lhs * rhs;							\
	return z;							\
    }									\
    typ typ##_multiply(							\
		       typ lhs,						\
		       typ rhs)						\
    {									\
	return typ##_multiply0(lhs, rhs) &				\
	    typ##_multiply1(0, lhs, rhs) &				\
	    typ##_multiply2(rhs, lhs);					\
    }
#endif
#ifndef PCODE_MUL_FLOAT
#define PCODE_MUL_FLOAT(typ)						\
    typ typ##_multiply(typ lhs, typ rhs)				\
    {									\
	return lhs * rhs;						\
    }
#endif
#ifndef PCODE_CONVERT
#define PCODE_CONVERT(typ, typ0)					\
    static __attribute__((noinline))					\
    typ0 typ##_to_##typ0##_convert0(typ a)				\
    {									\
	typ x = a;							\
	typ0 y = (typ0)x;						\
	return y;							\
    }									\
    static __attribute__((noinline))					\
    typ0 typ##_to_##typ0##_convert1(__attribute__((unused))typ dummy,	\
				    typ a)				\
    {									\
	typ x = a;							\
	typ0 y = (typ0)x;						\
	return y;							\
    }									\
    typ0 typ##_to_##typ0##_convert(typ a)				\
    {									\
	return typ##_to_##typ0##_convert0(a) &				\
	    typ##_to_##typ0##_convert1(0, a);				\
    }
#endif
#ifndef PCODE_CONVERT_FLOAT
#define PCODE_CONVERT_FLOAT(typ, typ0)					\
    typ0 typ##_to_##typ0##_convert(typ a)				\
    {									\
        return (typ0)a;							\
    }
#endif
#endif /* PCODE_TEST_H */

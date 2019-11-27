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

#endif /* PCODE_TEST_H */


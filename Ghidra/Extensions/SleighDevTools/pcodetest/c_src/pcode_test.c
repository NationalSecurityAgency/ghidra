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

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

NOINLINE i4 breakOnPass(void);
NOINLINE i4 breakOnError(void);
void nosprintf5() { }			/* sprintf5 function was removed, but java is still looking for it. */

FunctionInfo mainFunctionInfoTable[] = {
#ifdef HAS_FLOAT
	{"assertF4", (testFuncPtr) assertF4, 0},
#endif
#ifdef HAS_DOUBLE
	{"assertF8", (testFuncPtr) assertF8, 0},
#endif
	{"assertI1", (testFuncPtr) assertI1, 0},
	{"assertI2", (testFuncPtr) assertI2, 0},
	{"assertI4", (testFuncPtr) assertI4, 0},
#ifdef HAS_LONGLONG
	{"assertI8", (testFuncPtr) assertI8, 0},
#endif
	{"assertU1", (testFuncPtr) assertU1, 0},
	{"assertU2", (testFuncPtr) assertU2, 0},
	{"assertU4", (testFuncPtr) assertU4, 0},
#ifdef HAS_LONGLONG
	{"assertU8", (testFuncPtr) assertU8, 0},
#endif
	{"breakOnDone", (testFuncPtr) breakOnDone, 0},
	{"breakOnError", (testFuncPtr) breakOnError, 0},
	{"breakOnPass", (testFuncPtr) breakOnPass, 0},
	{"breakOnSubDone", (testFuncPtr) breakOnSubDone, 0},
	{"noteTestMain", (testFuncPtr) noteTestMain, 0},
	{0, 0, 0},
};

static TestInfo MainInfo = {
	{'A', 'b', 'C', 'd', 'E', 'F', 'g', 'H'},
	sizeof(i1 *),			/* ptrSz */
	0x01020304,			/* byteOrder */
	breakOnPass,			/* onPass function ptr */
	breakOnError,			/* onError function ptr */
	breakOnDone,			/* onDone function ptr */
	0,				/* numpass */
	0,				/* numfail  */
	0,				/* lastTestPos */
	0,				/* lastErrorLine */
	"none",				/* lastErrorFile */
	"none",				/* lasFunc */
	nosprintf5,			/* sprintf5 function ptr */
	0,				/* sprintf5 buffer */
	0,				/* sprintf5 enabled flag */
	__VERSION__,			/* compiler version */
	TOSTRING(NAME),			/* value of name symbol */
	TOSTRING(THECCFLAGS),		/* value of THECCFLAGS symbol */
	"BUILDDATE: " __DATE__,		/* build date */
	mainFunctionInfoTable,		/* function table */
};

NOINLINE void TestInfo_reset(void)
{
	MainInfo.numpass = 0;
	MainInfo.numfail = 0;
	MainInfo.lastTestPos = 0;
	MainInfo.lastErrorFile = "none";
	MainInfo.lastFunc = "none";
}

/* Injected call when a test is done */

NOINLINE i4 breakOnDone(const char *file, int line, const char *func)
{
	return 0;
}

/* Called from assert when a test passes */

NOINLINE i4 breakOnPass(void)
{
	MainInfo.numpass++;
	return 0;
}

/* Called from assert when a test fails */

NOINLINE i4 breakOnError(void)
{
	MainInfo.numfail++;
	return 0;
}

/* Injected call when a subtest is done */

NOINLINE i4 breakOnSubDone(const char *file, int line, const char *func)
{
	return 0;
}

/* Injected at start of a test to record file position */

void noteTestMain(const char *file, int line, const char *func)
{
	MainInfo.lastFunc = (char *) func;
	MainInfo.lastTestPos = line;
}

#if defined(BUILD_EXE)
#define DO_PRINT_INT(ok)	print_int(file, line, MainInfo.lastFunc, expected, val, (ok) ? "OK" : "ERROR");
#define DO_PRINT_LONG(ok)	print_long(file, line, MainInfo.lastFunc, expected, val, (ok) ? "OK" : "ERROR");
/* for ARM platform, and possibly others, printf does not properly handle long long args */
#define DO_PRINT_LONGLONG(ok)	print_long(file, line, MainInfo.lastFunc, (long) expected, (long) val, (ok) ? "OK" : "ERROR");
#define DO_PRINT_UINT(ok)	print_uint(file, line, MainInfo.lastFunc, expected, val, (ok) ? "OK" : "ERROR");
#define DO_PRINT_ULONG(ok)	print_ulong(file, line, MainInfo.lastFunc, expected, val, (ok) ? "OK" : "ERROR");
#define DO_PRINT_ULONGLONG(ok)	print_ulong(file, line, MainInfo.lastFunc, (long) expected, (long) val, (ok) ? "OK" : "ERROR");
#define DO_PRINT_FLOAT(ok)	print_float(file, line, MainInfo.lastFunc, expected, val, (ok) ? "OK" : "ERROR");
#else
#define DO_PRINT_INT(ok)
#define DO_PRINT_LONG(ok)
#define DO_PRINT_LONGLONG(ok)
#define DO_PRINT_UINT(ok)
#define DO_PRINT_ULONG(ok)
#define DO_PRINT_ULONGLONG(ok)
#define DO_PRINT_FLOAT(ok)
#endif

/* The remaining functions are asserts. Assert functions perform
 * comparison of expected and actual values, record location of
 * errors, and call breakOnPass or breakOnError.
 */

void assertI1(const char *file, int line, const char *func, i1 val, i1 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_INT(val == expected);
}

void assertI2(const char *file, int line, const char *func, i2 val, i2 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_INT(val == expected);
}

void assertI4(const char *file, int line, const char *func, i4 val, i4 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_INT(val == expected);
}

#ifdef HAS_LONGLONG
void assertI8(const char *file, int line, const char *func, i8 val, i8 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_LONGLONG(val == expected);
}
#endif

void assertU1(const char *file, int line, const char *func, u1 val, u1 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_UINT(val == expected);
}

void assertU2(const char *file, int line, const char *func, u2 val, u2 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_UINT(val == expected);
}

void assertU4(const char *file, int line, const char *func, u4 val, u4 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_UINT(val == expected);
}

#ifdef HAS_LONGLONG
void assertU8(const char *file, int line, const char *func, u8 val, u8 expected)
{
	if (val == expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_ULONGLONG(val == expected);
}
#endif

#ifdef HAS_FLOAT
void assertF4(const char *file, int line, const char *func, f4 val, f4 expected)
{
	u4 u4Val = *(u4 *) & val;
	u4 u4Expected = *(u4 *) & expected;

	/* Mask off last byte from value and expected */
	u4Val &= 0xFFFFFF00;
	u4Expected &= 0xFFFFFF00;

	/* Should fail if diff in sign/exponent/or more than (0xFF * eplison) */
	if (u4Val == u4Expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_FLOAT(u4Val == u4Expected);
}
#endif

#ifdef HAS_DOUBLE
void assertF8(const char *file, int line, const char *func, f8 val, f8 expected)
{
	u8 u8Val = *(u8 *) & val;
	u8 u8Expected = *(u8 *) & expected;

	/* Mask off last 2 bytes from value and expected */
	u8Val &= 0xFFFFFFFFFFFF0000ULL;
	u8Expected &= 0xFFFFFFFFFFFF0000ULL;

	/* Should fail if diff in sign/exponent/or more than (0xFFFF * eplison) */
	if (u8Val == u8Expected) {
		breakOnPass();
	} else {
		MainInfo.lastErrorLine = line;
		MainInfo.lastErrorFile = (char *) file;
		breakOnError();
	}
	MainInfo.lastTestPos = line;
	DO_PRINT_FLOAT(u8Val == u8Expected);
}
#endif


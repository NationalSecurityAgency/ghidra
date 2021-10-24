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
#if defined(__GNUC__) && !defined(__llvm__)

#define HAS_GNU_ATTRIBUTES      1
#define FUNCNAME __FUNCTION__
#define NO_OPTIMIZE __attribute__((optimize("O0")))

#elif defined(__llvm__)

#define HAS_GNU_ATTRIBUTES      1
#define FUNCNAME __FUNCTION__
#define NO_OPTIMIZE __attribute__((optimize("O0")))

#elif defined(__SDCC)

#define FUNCNAME __func__
#define NO_OPTIMIZE
#define __VERSION__  "version"

#else

#ifndef __VERSION__
#define __VERSION__  "version"
#endif

#define FUNCNAME __FUNCTION__
#define NO_OPTIMIZE
#endif

/* Make the default to have float double and long long types defined
 */

#define HAS_FLOAT    1
#define HAS_DOUBLE   1
#define HAS_LONGLONG 1

#ifdef HAS_FLOAT_OVERRIDE
#undef HAS_FLOAT
#endif

#ifdef HAS_DOUBLE_OVERRIDE
#undef HAS_DOUBLE
#endif

#ifdef HAS_LONGLONG_OVERRIDE
#undef HAS_LONGLONG
#endif

/* Define some standard types, these are defined to be the same on
 * different platforms and compilers
 */

#if defined(_MSV_VER)
#define IS_COMPILER_MSVC 1
#elif defined(__TI_COMPILER_VERSION__)
#define IS_COMPILER_CODECOMPOSERSTUDIO 1
#elif defined(__GNUC__) && !defined(__INT8_TYPE__) && !defined(__llvm__)
#define IS_COMPILER_PRE48_GCC
#elif defined(__GNUC__) && defined(__INT8_TYPE__) && !defined(__llvm__)
#define IS_COMPILER_POST48_GCC
#elif defined(__llvm__)
#if !defined(__INT8_TYPE__)
#define IS_COMPILER_PRE48_GCC
#else
#define IS_COMPILER_LLVM
#endif
#else /* defined(MSV_VER) */
#define IS_COMPILER_UNKNOWN
#endif

#if defined(IS_COMPILER_UNKNOWN) || defined(IS_COMPILER_PRE48_GCC)

/* Catch specific platforms */
#ifdef __AVR_ARCH__		/* defined(IS_COMPILER_UNKNOWN) || defined(IS_COMPILER_PRE48_GCC) && defined(__AVR_ARCH__) */
typedef unsigned char u1;
typedef signed char i1;
typedef unsigned short u2;
typedef signed short i2;
typedef unsigned long u4;
typedef signed long i4;
typedef long long i8;
typedef unsigned long long u8;
typedef float f4;
#ifdef HAS_DOUBLE
#endif
typedef i4 size_t;
#elif __AVR32__
typedef unsigned char u1;
typedef signed char i1;
typedef unsigned short u2;
typedef signed short i2;
typedef unsigned int u4;
typedef signed int i4;
#ifdef HAS_LONGLONG
typedef long long i8;
typedef unsigned long long u8;
#endif
#ifdef HAS_FLOAT
typedef float f4;
#endif
#ifdef HAS_DOUBLE
typedef double f8;
#endif

typedef __SIZE_TYPE__ size_t;
#else /* defined(IS_COMPILER_UNKNOWN) || defined(IS_COMPILER_PRE48_GCC) && !defined(__AVR_ARCH__) */
/* This is for non-GNU non CodeComposerStudio generic case. */
typedef unsigned char u1;
typedef signed char i1;
typedef unsigned short u2;
typedef signed short i2;
#ifdef INT4_IS_LONG
typedef unsigned long u4;
typedef signed long i4;
#else
typedef unsigned int u4;
typedef signed int i4;
#endif
#ifdef HAS_LONGLONG
typedef long long i8;
typedef unsigned long long u8;
#endif
#ifdef HAS_FLOAT
typedef float f4;
#endif
#ifdef HAS_DOUBLE
#ifdef dsPIC30
typedef long double f8;
#else
typedef double f8;
#endif
#endif

#ifdef HAS_LONGLONG
typedef i8 size_t;
#else
typedef i4 size_t;
#endif
#endif

#endif /* #if defined(IS_COMPILER_UNKNOWN) || defined(IS_COMPILER_PRE48_GCC) */

/* For CodeComposerStudio */
#if defined(IS_COMPILER_CODECOMPOSERSTUDIO)

#if defined(__MSP430__)		/*  defined(IS_COMPILER_CODECOMPOSERSTUDIO) && defined(__MSP430__)   */

typedef unsigned char u1;
typedef signed char i1;
typedef unsigned short u2;
typedef signed short i2;
typedef unsigned long u4;
typedef signed long i4;

#undef HAS_FLOAT
#undef HAS_DOUBLE
#undef HAS_LONGLONG
#undef HAS_GNU_ATTRIBUTES

typedef unsigned int size_t;

#endif /* #if defined(__MSP430__) */

#endif /* #if defined(IS_COMPILER_CODECOMPOSERSTUDIO) */

/* For GNU compilers */
/* Modern GNU compilers > 4.7 have size macros to uses to give us definitions. */

#if defined(IS_COMPILER_POST48_GCC)

typedef __SIZE_TYPE__ size_t;

typedef __INT8_TYPE__ i1;
typedef __INT16_TYPE__ i2;
typedef __INT32_TYPE__ i4;
#if defined(__INT64_TYPE__)
#ifdef HAS_LONGLONG
typedef __INT64_TYPE__ i8;
#endif
#endif

typedef __UINT8_TYPE__ u1;
typedef __UINT16_TYPE__ u2;
typedef __UINT32_TYPE__ u4;
#if defined(__UINT64_TYPE__)
#ifdef HAS_LONGLONG
typedef __UINT64_TYPE__ u8;
#endif
#endif

#ifdef __SIZEOF_FLOAT__
#ifdef HAS_FLOAT
typedef float f4;
#endif
#endif

#ifdef __SIZEOF_DOUBLE__
#ifdef HAS_DOUBLE
typedef double f8;
#endif
#endif

#define TYPES_ARE_DEFINED       1
#endif /* #if defined(IS_COMPILER_POST48_GCC) */

/* Microsoft VisualC++ compiler */
#if defined(IS_COMPILER_MSVC)

/* ARM on Visual C++ */
#if defined(_M_ARM_FP)		/* defined(IS_COMPILER_MSVC) && defined(_M_ARM_FP) */
typedef unsigned char u1;
typedef signed char i1;
typedef unsigned short u2;
typedef signed short i2;
typedef unsigned long u4;
typedef signed long i4;

#undef HAS_FLOAT
#undef HAS_DOUBLE
#undef HAS_LONGLONG
#undef HAS_GNU_ATTRIBUTES

typedef unsigned int size_t;

#endif /* #if defined(IS_COMPILER_MSVC) */

#endif /* #if defined(_M_ARM_FP) */

#ifdef IS_COMPILER_LLVM
typedef unsigned char u1;
typedef signed char i1;
typedef unsigned short u2;
typedef signed short i2;
typedef unsigned __INT32_TYPE__ u4;
typedef signed __INT32_TYPE__ i4;
#ifdef __INT64_TYPE__
typedef unsigned long long u8;
typedef signed long long i8;
#define HAS_LONGLONG
#else
#undef  HAS_LONGLONG
#endif /* LONGLONG */
#ifdef __SIZEOF_FLOAT__
typedef float f4;
#define HAS_FLOAT
#else
#undef HAS_FLOAT
#endif /* FLOAT */
#ifdef __SIZEOF_DOUBLE__
typedef double f8;
#define HAS_DOUBLE
#else
#undef HAS_DOUBLE
#endif /* DOUBLE */

/* __is_identifier __has_feature */
#ifdef __has_feature		/* LLVM clang magic (see clang docs) */
#pragma message "has __has_feature"
#if __has_feature(size_t)
#pragma message "has size_t"
#else
#pragma message "define size_t"
#if    __SIZEOF_SIZE_T__ == 8
typedef u8 size_t;
#elif __SIZEOF_SIZE_T__== 4
typedef u4 size_t;
#elif __SIZEOF_SIZE_T__ == 2
typedef u2 size_t;
#elif __SIZEOF_SIZE_T__ == 1
typedef i1 size_t;
#endif
#endif
#else
#pragma message "has NOT __has_feature"
#endif /* #ifdef __has_feature */

#endif /* #ifdef IS_COMPILER_LLVM */

/* Simulated limit.h */
#define U1_MAX                   0xFF
#define U1_MIN                   0
#define U2_MAX                   0xFFFF
#define U2_MIN                   0
#define U4_MAX                   0xFFFFFFFFU
#define U4_MIN                   0
#define U8_MAX                   0xFFFFFFFFFFFFFFFFULL
#define U8_MIN                   0
#define I1_MAX                   0x7F
#define I1_MIN                   (-128)
#define I2_MAX                   0x7FFF
#define I2_MIN                   (-32768)
#define I4_MAX                   0x7FFFFFFF
#define I4_MIN                   (-I4_MAX - 1)
#define I8_MAX                   9223372036854775807LL
#define I8_MIN                   (-I8_MAX - 1LL)

/* made up useful defines */
#define U1_MSB   0x80
#define U2_MSB   0x8000
#define U21_MSB  0xff80
#define U4_MSB   0x80000000
#define U41_MSB  0xffffff80
#define U42_MSB  0xffff8000
#define U8_MSB   0x8000000000000000
#define U81_MSB  0xffffffffffffff80
#define U82_MSB  0xffffffffffff8000
#define U84_MSB  0xffffffff80000000
#define U1_MAGIC 0x11
#define U2_MAGIC 0x1211
#define U4_MAGIC 0x14131211
#define U8_MAGIC 0x1817161514131211
#define U1_55    0x55
#define U1_56    0x56
#define U1_AA    0xAA
#define U1_AB    0xAB
#define U2_55    0x5555
#define U2_56    0x5556
#define U2_AA    0xAAAA
#define U2_AB    0xAAAB
#define U21_AB   0xFFAB
#define U21_56   0xFF56
#define U4_55    0x55555555
#define U4_56    0x55555556
#define U4_AA    0xAAAAAAAA
#define U4_AB    0xAAAAAAAB
#define U41_56   0xFFFFFF56
#define U41_AB   0xFFFFFFAB
#define U42_56   0xFFFF5556
#define U42_AB   0xFFFFAAAB
#define U8_55    0x5555555555555555
#define U8_56    0x5555555555555556
#define U8_AA    0xAAAAAAAAAAAAAAAA
#define U8_AB    0xAAAAAAAAAAAAAAAB
#define U81_AB   0xFFFFFFFFFFFFFFAB
#define U82_AB   0xFFFFFFFFFFFFAAAB
#define U84_AB   0xFFFFFFFFAAAAAAAB
#define U81_56   0xFFFFFFFFFFFFFF56
#define U82_56   0xFFFFFFFFFFFF5556



/* Simulate float.h assumes IEEE standard format and 4 8 10 byte formats (FLT_, DBL_, LDBL_) (FLT_ maps to F4, DBL_ maps to F8) */
#define DBL_MAX                  ((double)1.79769313486231570814527423731704357e+308L)
#define DBL_MIN                  ((double)2.22507385850720138309023271733240406e-308L)

#define LDBL_MAX                 ((long double)1.18973149535723176502126385303097021e+4932L)
#define LDBL_MIN                 ((long double)3.36210314311209350626267781732175260e-4932L)

#define FLT_MAX                  ((float)3.40282346638528859811704183484516925e+38F)
#define FLT_MIN                  ((float)1.17549435082228750796873653722224568e-38F)

#define PI_SHORT 3.14
#define M_PI     ((float)3.14159265358979323846)
#define M_PIl    ((double)3.141592653589793238462643383279502884L)


#ifdef HAS_LIBC
#include <stdio.h>
#endif

#ifdef BUILD_EXE
#ifndef HAS_LIBC
void write(int fd, char *buf, int count);
void exit(int stat);
#endif
void print_int(char *file, int line, char *func, int expected, int val, char *ok);
void print_long(char *file, int line, char *func, long expected, long val, char *ok);
void print_uint(char *file, int line, char *func, unsigned int expected, unsigned int val, char *ok);
void print_ulong(char *file, int line, char *func, unsigned long expected, unsigned long val, char *ok);
void print_float(char *file, int line, char *func, float expected, float val, char *ok);
void print_val(char *name, int val);
#endif


/**
 *  @attn  This is extremely unportable for endianess
 *
 *  Any checks that use `y` should be careful, there is no real good
 *  way to do bitfield access with endianess correctly here it looks like.
 */

typedef union u1bits {
    struct {
	u1 b0:1;
	u1 b1:1;
	u1 b2:1;
	u1 b3:1;
	u1 b4:1;
	u1 b5:1;
	u1 b6:1;
	u1 b7:1;
    } x;
    struct {
	u1 w0:2;
	u1 w1:4;
	u1 w2:1;
    } y;
    u1 z;
} u1bits;
typedef union u2bits {
    struct {
	u2 b0:1;
	u2 b1:1;
	u2 b2:1;
	u2 b3:1;
	u2 b4:1;
	u2 b5:1;
	u2 b6:1;
	u2 b7:1;
	u2 b8:1;
	u2 b9:1;
	u2 b10:1;
	u2 b11:1;
	u2 b12:1;
	u2 b13:1;
	u2 b14:1;
	u2 b15:1;
    } x;
    struct {
	u2 w0:4;
	u2 w1:8;
	u2 w2:1;
    } y;
    u2 z;
} u2bits;
typedef union u4bits {
    struct {
	u4 b0:1;
	u4 b1:1;
	u4 b2:1;
	u4 b3:1;
	u4 b4:1;
	u4 b5:1;
	u4 b6:1;
	u4 b7:1;
	u4 b8:1;
	u4 b9:1;
	u4 b10:1;
	u4 b11:1;
	u4 b12:1;
	u4 b13:1;
	u4 b14:1;
	u4 b15:1;
	u4 b16:1;
	u4 b17:1;
	u4 b18:1;
	u4 b19:1;
	u4 b20:1;
	u4 b21:1;
	u4 b22:1;
	u4 b23:1;
	u4 b24:1;
	u4 b25:1;
	u4 b26:1;
	u4 b27:1;
	u4 b28:1;
	u4 b29:1;
	u4 b30:1;
	u4 b31:1;
    } x;
    struct {
	u4 w0:8;
	u4 w1:16;
	u4 w2:1;
    } y;
    u4 z;
} u4bits;
#ifdef HAS_LONGLONG
typedef union u8bits {
    struct {
	u8 b0:1;
	u8 b1:1;
	u8 b2:1;
	u8 b3:1;
	u8 b4:1;
	u8 b5:1;
	u8 b6:1;
	u8 b7:1;
	u8 b8:1;
	u8 b9:1;
	u8 b10:1;
	u8 b11:1;
	u8 b12:1;
	u8 b13:1;
	u8 b14:1;
	u8 b15:1;
	u8 b16:1;
	u8 b17:1;
	u8 b18:1;
	u8 b19:1;
	u8 b20:1;
	u8 b21:1;
	u8 b22:1;
	u8 b23:1;
	u8 b24:1;
	u8 b25:1;
	u8 b26:1;
	u8 b27:1;
	u8 b28:1;
	u8 b29:1;
	u8 b30:1;
	u8 b31:1;
	u8 b32:1;
	u8 b33:1;
	u8 b34:1;
	u8 b35:1;
	u8 b36:1;
	u8 b37:1;
	u8 b38:1;
	u8 b39:1;
	u8 b40:1;
	u8 b41:1;
	u8 b42:1;
	u8 b43:1;
	u8 b44:1;
	u8 b45:1;
	u8 b46:1;
	u8 b47:1;
	u8 b48:1;
	u8 b49:1;
	u8 b50:1;
	u8 b51:1;
	u8 b52:1;
	u8 b53:1;
	u8 b54:1;
	u8 b55:1;
	u8 b56:1;
	u8 b57:1;
	u8 b58:1;
	u8 b59:1;
	u8 b60:1;
	u8 b61:1;
	u8 b62:1;
	u8 b63:1;
    } x;
    struct {
	u8 w0:16;
	u8 w1:32;
	u8 w2:1;
    } y;
    u8 z;
} u8bits;
#endif

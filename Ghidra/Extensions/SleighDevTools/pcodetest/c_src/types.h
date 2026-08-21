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

#if defined(U1)
typedef U1 u1;
#else
#if defined(__UINT8_TYPE__)
typedef __UINT8_TYPE__ u1;
#else
typedef unsigned char u1;
#endif
#endif

#if defined(I1)
typedef I1 i1;
#else
#if defined(__INT8_TYPE__)
typedef __INT8_TYPE__ i1;
#else
typedef signed char i1;
#endif
#endif

#if defined(U2)
typedef U2 u2;
#else
#if defined(__UINT16_TYPE__)
typedef __UINT16_TYPE__ u2;
#else
typedef unsigned short u2;
#endif
#endif

#if defined(I2)
typedef I2 i2;
#else
#if defined(__INT16_TYPE__)
typedef __INT16_TYPE__ i2;
#else
typedef signed short i2;
#endif
#endif

#if defined(U4)
typedef U4 u4;
#else
#if defined(__UINT32_TYPE__)
typedef __UINT32_TYPE__ u4;
#else
typedef unsigned long u4;
#endif
#endif

#if defined(I4)
typedef I4 i4;
#else
#if defined(__INT32_TYPE__)
typedef __INT32_TYPE__ i4;
#else
typedef signed long i4;
#endif
#endif

#if defined(U8)
typedef U8 u8;
#else
#if defined(__UINT64_TYPE__)
typedef __UINT64_TYPE__ u8;
#else
typedef unsigned long long u8;
#endif
#endif

#if defined(I8)
typedef I8 i8;
#else
#if defined(__INT64_TYPE__)
typedef __INT64_TYPE__ i8;
#else
typedef signed long long i8;
#endif
#endif

#if defined(F4)
typedef F4 f4;
#else
typedef float f4;
#endif

#if defined(F8)
typedef F8 f8;
#else
typedef double f8;
#endif

#if defined(F16)
typedef F16 f16;
#else
typedef long double f16;
#endif


#if defined(__SIZE_TYPE__)
typedef __SIZE_TYPE__ size_t;
#else

#ifdef IS_COMPILER_LLVM

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

#else

#if defined(HAS_LONGLONG)
typedef u8 size_t;
#else
typedef u4 size_t;
#endif /* HAS_LONGLONG */
#endif /* #ifdef IS_COMPILER_LLVM */
#endif /* defined(__SIZE_TYPE__) */


/* For CodeComposerStudio */
#if defined(IS_COMPILER_CODECOMPOSERSTUDIO) || defined(IS_COMPILER_MSVC)

#undef HAS_GNU_ATTRIBUTES

#endif /* #if defined(IS_COMPILER_CODECOMPOSERSTUDIO) || defined(IS_COMPILER_MSVC) */




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

/* Simulate float.h assumes IEEE standard format and 4 8 10 byte formats (FLT_, DBL_, LDBL_) (FLT_ maps to F4, DBL_ maps to F8) */

#define DBL_DIG                  15
#define DBL_EPSILON              2.2204460492503131e-16
#define DBL_MANT_DIG             53
#define DBL_MAX_10_EXP           308
#define DBL_MAX                  1.7976931348623157e+308

#define DBL_MAX_EXP              1024
#define DBL_MIN_10_EXP           (-307)
#define DBL_MIN                  2.2250738585072014e-308
#define DBL_MIN_EXP              (-1021)

#define LDBL_DIG                 18
#define LDBL_EPSILON             1.08420217248550443401e-19L
#define LDBL_MANT_DIG            64
#define LDBL_MAX_10_EXP          4932
#define LDBL_MAX_EXP             16384

#define LDBL_MAX                 1.18973149535723176502e+4932L
#define LDBL_MIN_10_EXP          (-4931)
#define LDBL_MIN_EXP             (-16381)
#define LDBL_MIN                 3.36210314311209350626e-4932L

#define FLT_DIG                  6
#define FLT_EPSILON              1.19209290e-7F
#define FLT_MANT_DIG             24
#define FLT_MAX_10_EXP           38
#define FLT_MAX_EXP              128

#define FLT_MAX                  3.40282347e+38F
#define FLT_MIN_10_EXP           (-37)
#define FLT_MIN_EXP              (-125)
#define FLT_MIN                  1.17549435e-38F
#define FLT_RADIX                2

#define FLT_ROUNDS               1

#define PI_SHORT 3.14

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

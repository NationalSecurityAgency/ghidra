/* ###
 * IP: GHIDRA
 * NOTE: Decompiler specific flags, refers to sparc,linux,windows,i386,apple,alpha,powerpc
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
/* typedefs for getting specific word sizes */

/* Defines for the "preferred" intm size, where this is not determined by the */
/* algorithm being coded. I.e. the code works without change using */
/* maximum wordsize when compiled on 64 OR 32 machines */

/* uintp is intended to be an unsigned integer that is the same size as a pointer */

#ifndef __MYTYPES__
#define __MYTYPES__

#if defined( __sparc )
#define HOST_ENDIAN 1
#if defined( __sparcv9 )
typedef unsigned long uintm;
typedef long intm;
typedef unsigned long uint8;
typedef long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint8 uintp;
#else
typedef unsigned int uintm;
typedef int intm;

typedef unsigned long long uint8;
typedef long long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint4 uintp;

#endif /* __sparcv9 */
#endif /* __sparc */

/* Alpha defines */
#if defined (__digital__) && defined (__unix__)
typedef unsigned long uintm;
typedef long intm;
typedef unsigned long uint8;
typedef long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint8 uintp;
#endif

#if defined (__linux__) && defined (__i386__)
#define HOST_ENDIAN 0
typedef unsigned long uintm;
typedef long intm;
typedef unsigned long long uint8;
typedef long long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint4 uintp;
#endif

#if defined (__linux__) && defined (__x86_64__)
#define HOST_ENDIAN 0
typedef unsigned int uintm;
typedef int intm;
typedef unsigned long uint8;
typedef long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint8 uintp;
#endif

#if defined(_WINDOWS)

#if defined(_WIN64)

#define HOST_ENDIAN 0
typedef unsigned int uintm;
typedef int intm;
typedef unsigned long long uint8;
typedef long long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint8 uintp;

#else // _WIN32 assumed

#define HOST_ENDIAN 0
typedef unsigned long uintm;
typedef long intm;
typedef unsigned long long uint8;
typedef long long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint4 uintp;
#endif // _WIN32

#endif // _WINDOWS

#if defined( __APPLE_CC__) && defined( __ppc__)
#define HOST_ENDIAN 1
typedef unsigned long uintm;
typedef long intm;
typedef unsigned long uint8;
typedef long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint4 uintp;
#endif

#if defined( __APPLE_CC__) && defined( __i386__)
#define HOST_ENDIAN 0
typedef unsigned long uintm;
typedef long intm;
typedef unsigned long long uint8;
typedef long long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint4 uintp;
#endif

#if defined (__APPLE_CC__) && defined (__x86_64__)
#define HOST_ENDIAN 0
typedef unsigned int uintm;
typedef int intm;
typedef unsigned long uint8;
typedef long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint8 uintp;
#endif

#if defined (__APPLE_CC__) && defined (__aarch64__)
#define HOST_ENDIAN 0
typedef unsigned int uintm;
typedef int intm;
typedef unsigned long uint8;
typedef long int8;
typedef unsigned int uint4;
typedef int int4;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned char uint1;
typedef char int1;
typedef uint8 uintp;
#endif

#if defined(_WINDOWS)
#pragma warning (disable:4312)
#pragma warning (disable:4311)
#pragma warning (disable:4267)
#pragma warning (disable:4018)
#pragma warning (disable:4244)

/*
 The windows standard template library list implementation seems to have a philosophical difference with
 the standard regarding the validity of iterators pointing to objects that are moved between containers
 (via the splice method) These defines turn off the validity checks
 (These have been moved to the VC project spec)
 */
//#define _SECURE_SCL 0
//#define _HAS_ITERATOR_DEBUGGING 0
#endif

/* In order to have a little more flexibility in integer precision vs efficiency,
  we subdivide the integer types into three classes:

  Small integers:   Integers that never come close to overflowing their (machine word)
                    precision. We will always use int4 or uint4 (or smaller) for
                    these so that the precision is explicitly given.

  Machine word integers:   These integers exactly match the largest precision that
                           will fit in a general purpose register.  They should be
                           used exclusively by in implementations of larger
                           precision objects.  Use intm or uintm

  Big integers: These are intended to be arbitrary precison integers. However
                for efficiency, these will always be implemented as fixed precision.
                So for coding purposes, these should be interpreted as fixed
                precision integers that store as big a number as you would ever need.
*/

/* Specify that unsigned big ints are coded with 8 bytes */
#define UINTB8

typedef int8 intb;		/* This is a signed big integer */
//#include "integer.hh"
#ifdef UINTB8
typedef uint8 uintb;		/* This is an unsigned big integer */
#else
typedef uint4 uintb;
#endif

/*

Other compilation flags

CPUI_DEBUG        --    This is the ONE debug switch that should be passed in
                        from the compiler, all others are controlled below
*/

#ifdef CPUI_DEBUG
# define OPACTION_DEBUG
# define PRETTY_DEBUG
//# define __REMOTE_SOCKET__
//# define TYPEPROP_DEBUG
//# define DFSVERIFY_DEBUG
//# define BLOCKCONSISTENT_DEBUG
//# define MERGEMULTI_DEBUG
//# define VARBANK_DEBUG
#endif

#endif

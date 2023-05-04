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
 
 /* test define symbols of length 1 */
 #ifdef a
 #undef a
 #endif


 /* definition coming from -D, should evaluate to true */
 #if FROM_ARG_VALUE
 #define DID_ARG_VALUE 1
 #endif
 
 #if FROM_ARG_DEF
 #define DID_ARG_DEF 1
 #endif
 
 #if FROM_ARG_EMPTY
 #define DID_ARG_EMPTY 1
 #endif
 
 #if defined(FROM_ARG_VALUE)
 #define DID_ARG_ISDEF_VALUE 1
 #endif
 
 #if defined(FROM_ARG_DEF)
 #define DID_ARG_ISDEF_DEF 1
 #endif
 
 #if defined(FROM_ARG_EMPTY)
 #define DID_ARG_ISDEF_EMPTY 1
 #endif
 
 
 
 /* Defined checks from file */
 #define FROM_FILE_VALUE 300
 #define FROM_FILE_EMPTY ""
 #define FROM_FILE_DEF
 
 #if FROM_FILE_VALUE
 #define DID_FILE_VALUE 1
 #endif
 
 #if FROM_FILE_EMPTY
 #define DID_FILE_EMPTY 1
 #endif
 
 #if FROM_FILE_DEF
 #define DID_FILE_DEF 1
 #endif

 #if defined(FROM_FILE_VALUE)
 #define DID_FILE_ISDEF_VALUE 1
 #endif
 
 #if defined(FROM_FILE_EMPTY)
 #define DID_FILE_ISDEF_EMPTY 1
 #endif
 
 #if defined(FROM_FILE_DEF)
 #define DID_FILE_ISDEF_DEF 1
 #endif

#include <multinclude.h> /* include once */

#include "multinclude.h" /* include twice */

#include "multinclude.h"

#include "multinclude.h"

#define __DEFINED_INCLUDE <defined.h>

#include __DEFINED_INCLUDE /* THIS SHOULD BE IGNORED <> */

#define __TEXT(quote)  quote

#define TEXT(quote)  __TEXT(quote)
 
 #define SEPERATORC  TEXT(',')
 
 #define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
 
 #define ZeroMemory  RtlZeroMemory
 

#define foo    ZeroMemory(&Filter->gf_group, sizeof(Filter->gf_group));

int foo;
 
 
#pragma once

#define PTYPE 4

#define TYPE2               2   /* 2 */
#define TYPE3               3   /* 3 */
#define TYPE4               4   /* 4 */
#define TYPE5               5   /* 5 */
#define TYPE6               6   /* 6 */

#ifndef P1
#define P1                                                   \
  (PTYPE == TYPE3 ||                               \
   PTYPE == TYPE4 ||                                    \
   PTYPE == TYPE5 )
#endif


#ifndef P2
#define P2                                                \
  (PTYPE == TYPE5 ||                                    \
   PTYPE == TYPE6)
#endif

#ifndef P3
#define P3                                                 \
  (PTYPE == TYPE1 ||                                     \
   PTYPE == TYPE5 )
#endif

#define PPTYPE(Partition) (Partition)

#if PPTYPE(P1 | P2 | P3)
#define DID_EXPANSION 1
#else
#define DID_EXPANSION 0
#endif


#ifndef _CRTIMP
    #define _VCRT_DEFINED_CRTIMP
    #if defined CRTDLL && defined _CRTBLD
        #define _CRTIMP __declspec(dllexport)
    #else
        #ifdef _DLL
            #define _CRTIMP __declspec(dllimport)
        #else /* this is an else comment that goes to the next line
                #define and this should be ignored */
            #define _CRTIMP
        #endif /* this is a endif comment that goes to the next line
                #define and this should be ignored */
    #endif
#endif    /* this is a comment that goes to the next line
             #endif and this should be ignored */

#define ONEFISH 1
#define TWOFISH 2

#if (ONEFISH + TWOFISH + REDFISH + BLUEFISH) > 2
#error "Too many fish"
#define TOO_MANY_FISH 0
int TooManyFish;
#else
int NotEnoughFish;
#endif

#define TEST1 one

#if defined(TEST1) + \
   defined(TEST2) + \
   defined(TEST3) > 1
#error "Two or more defined, only one allowed of TEST1, TEST2, TEST3
#define TEST_FAILED 1
int TEST_FAILED;
#endif

#if !defined(__GNUC__) || __GNUC__ < 4
#warning "Unsupported compiler detected"
#endif

#if defined(else)  // end comment
#error Cannot redefine C keywords
#else  STUPIDCOMMENT IS IGNORED
#define ElseNotDefined TRUE
#endif  /* !_SYS_UNISTD_H_ */

#define O_M 0xffff0000 // test commment
#define N_V 0x60010001  // test comment

#if 0 /* comment
         */
# define DefineNameSlash           ?? * /
# define DefineMacroSlash(aba)          aba ?? * /
#endif

#define K 0x06010000

/**
 ** Test Various define value simplification to Enum
 **/
#define DefVal1 (((ULONG_PTR)((WORD)(32516))))

#define DefVal2 (((long) K + 0xf1))
#define DefVal3 ((long ) ((long) N_V & 0x21234) | (( ULONG ) 1))

#define DefVal4 ((long ) (0x1 << (1 + 2 | 4)))

#define DefVal5 (0xFF000000 & (~(0x01000000 | 0x02000000 | 0x04000000)))

#define DefVal6 ((0x000F0000L)|(0x00100000L)|0x3)

#define DefVal7 0x40000000UL

#define DefVal8 ((3 << 13)|(3 << 9)|4)

#define DefVal9 ((0x7fff & ~(((1 << 4) - 1))))

#define DefVal10 ((0x7fff) * 900L / 1000)

#define DefVal_1L	1L
#define DefVal_2l	2l
#define DefVal_3U	3U 
#define DefVal_4u	4u
#define DefVal_5UL	5UL
#define DefVal_6ul	6ul
#define DefVal_7lu	7lu
#define DefVal_8llu	8llu
#define DefVal_9ull	9ull
#define DefVal_10ll	10ll

#define DefVal_P_1L (1L)
#define DefVal_P_2l (2l)
#define DefVal_P_3U (3U )
#define DefVal_P_4u ( 4u)
#define DefVal_P_5UL ( 5UL )
#define DefVal_P_6ul (6ul)
#define DefVal_P_7lu ( 7lu )
#define DefVal_P_8llu ( 8llu )
#define DefVal_P_9ull ( 9ull )
#define DefVal_P_10ll ( 10ll )

#define BIGNUM 64 * 16 + 16

#define ImOctal 01234567


#define BYTE_LEN_1   0x1
#define BYTE_LEN_8   0x8
#define BYTE_LEN_1F   0x1F
#define BYTE_LEN_FF   0xFF
#define BYTE_LEN_1FF   0x1FF
#define BYTE_LEN_7FFF   0x7FFF
#define BYTE_LEN_10000   0x10000
#define BYTE_LEN_1000000 0x1000000
#define BYTE_LEN_100000000   0x100000000
#define BYTE_LEN_10000000000   0x10000000000
#define BYTE_LEN_1000000000000   0x1000000000000
#define BYTE_LEN_100000000000000   0x100000000000000
#define BYTE_LEN_neg1   -1

/**
 ** Test for recursive definitions, Should not cause an infinite loop
 **/
#define AVERSION enum AVERSION
AVERSION
{
    AVERSION_5 = 1,  // version 5
    AVERSION_6,      // version 6
    AVERSION_7,      // version 7
    AVERSION_8,      // version 9
};

#define Group(a,b)

#define _In Group(_In,a)

int doit(_In int a);



/**
 ** test concat operator
 **/
 
#if (N_V >= K) // [
int ntver_gt_nt2k(int a, int b);
#endif

#if ((O_M & N_V) == K)
#error VM setting conflicts with N_V setting
#endif

// make a symbol
#define $$doit(x, y) x ## y
#define $doit(x, y) $$doit(x, y)
#define $dosym(x) $doit(x, __cnt__)


#define __mode(x)												\
      __declspec("marker(\"" #x "\")")								\
      __inline void $dosym(__dud_)(void){}

__mode(Why);

#define _fpf(t)    __declspec("fp("f", " #t ")")
#define _fpc(t)   __declspec("fp(\"c\", " #t ")")
#define _fpl(typ)    extern int __declspec("fp(\"l\", " #typ ")") __ifpl##typ;

_fpl(bob)

#define BUILD_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }

BUILD_GUID(LIBID_ADO20,0x##00000200,0x##0000,
                 0x##0010,0x##80,0x##00,0x##00,
                 0x##AA,0x##00,0x##6D,0x##2E,0x##A4)


#define ___POSIX_C_DEPRECATED_STARTING_199506L

#define __POSIX_C_DEPRECATED(ver) ___POSIX_C_DEPRECATED_STARTING_##ver

int      chroot(const char *) __POSIX_C_DEPRECATED(199506L);


/**
 ** Test for correct macro expansion truth evaluation in #if constructs
 **/
#define A 0x2
#define B 0x1

#define FAMILY_APP (B | A)

#define FAMILY FAMILY_APP

#define FUNC(v) ((FAMILY & v) == v)

#if FUNC(A)
#define isDefineOnValue 1
#endif




#define MEMORY_OBJECT_INFO_MAX      (1024)
typedef int     *mem_info_t;
typedef int      mem_flavor_t;
typedef int      mem_info_data_t[MEMORY_OBJECT_INFO_MAX];


#define PERF_INFO   11
#define ATTR_INFO   14
#define BEHAVE_INFO 15


#define MEMORY_OBJECT_BEHAVE_INFO_COUNT ((mach_msg_type_number_t)       \
                (sizeof(memory_object_behave_info_data_t)/sizeof(int)))

#define invalid_memory_object_flavor(f)                                 \
        (f != ATTR_INFO &&                           \
         f != PERF_INFO &&                         \
         f != OLD_BEHAVE_INFO &&                        \
         f != BEHAVE_INFO &&                            \
         f != OLD_ATTR_INFO)


#define GET_IT(flags)      \
        ((((unsigned int)(flags)) >> 24) & 0xFF)

#define SET_MEM(ca, flags)     \
        ((flags) = ((((unsigned int)(ca)) << 24) \
                        & 0xFF000000) | ((flags) & 0xFFFFFF));


struct p_info {
        unsigned int    dummy[2];      /* dummy funcs */
};


typedef struct p_info    p_info_t;
typedef p_info_t         *p_info_array_t;
typedef p_info_array_t   p_list_ptr_t;

typedef uint32_t        p_offset_t;   /* offset */
typedef uint32_t        p_size_t;     /* size */


#	define LDP(protos)	protos

#define LDP_CONST  /* no const */

ldp LDP((
        LDP *ld,
        LDP_CONST char *dn, /* usually NULL */
        LDP_CONST char *saslMechanism,
        LDPControl **sCont,

        /* controls */
        ungiend flag,
        LDP_UNDEP *proc,
        void *defaults,

        /* result */
        LDPValue *result,

        /* installed */
        const char **rm,
        int *id ));

#define SPECHSZ 64
#if     ((SPECHSZ&(SPECHSZ-1)) == 0)
#define SPECHASH(d)  (((d>>21)+(d))&(SPECHSZ-1))
#else
#define SPECHASH(d)  (((unsigned)((d>>21)+(d)))%SPECHSZ)
#endif



#if -_LARGEFILE64_SOURCE - -1 == 1
#  undef _LARGEFILE64_SOURCE
#endif

/**
 ** Multi line define
 **/
#define __MISMATCH_TAGS_PUSH                                            \
        _Pragma("clang diagnostic push")                                \
        _Pragma("clang diagnostic ignored \"-Wmismatched-tags\"")

/**
 ** Protected from macro expansion
 **/
 
 #define stdin  (&__iob[0])
#define stdout (&__iob[1])

int __filbuf(FILE * /*stream*/);

#define getc(p) \
    (--((p)->__icnt) >= 0 ? *((p)->__ptr)++ : __filbuf(p))
#ifndef __cplusplus
int (getc)(FILE * /*stream*/);
#endif

#define getchar() getc(stdin)
#ifndef __cplusplus
int (getchar)(void);
#endif


/**
 ** Vararg defined
 **/
 #  define SETIT(value, [attributes])


#define eprintf(format, ...) fprintf (stderr, format, __VA_ARGS__)

#define EPRINTF_VARARGS eprintf ("%s:%d: ", input_file, lineno)

#define vprintf(format, ...) \
  fprintf (stderr, format __VA_OPT__(,) __VA_ARGS__)
  
#define VPRINTF_NO_ARGS vprintf ("no args!\n")
#define VPRINTF_ARGS vprintf ("%s!\n", "I have args")


#if defined(__has_include)
#if __has_include(<gethostuuid_private.h>)
int does_has_include_found();
#else
int does_has_include_not_found();
#endif
#else
int does_not_has_include();
#endif

#if (defined(__MINGW32__) || defined(_MSC_VER)) && \
    defined(__has_include_next) && __has_include_next(<float.h>)
#  include_next <float.h>
#endif

#if 0
#define NEWLINETEST1 0 // uh oh
#else
#define NEWLINETEST1 1 // strange
#endif

#define NEWLINETEST2 2 /* Comment with */
/* linefeed */
#define NEWLINETEST3 3

// Should be blank line below
#define AVALUE 1
// Should be blank line above

// 5 blank lines below
#if 0
#define BVALUE 0
#else
#define BVALUE 2
#endif
// 5 blank lines above

// test single quoted qoutes
#define BEGINC  QUOTED('"')
#define TEST_QUOTED_QUOTE    QUOTED('"')

#define TEST_MULTILINE_TEXT(t) multi_line_worked(t)

A = TEST_MULTILINE_TEXT("One Line")

B = TEST_MULTILINE_TEXT("Some text first line"
               "More text second line") 

#define DUAL_MULTILINE(A, B) dual_line_worked(A,B)
       
C = DUAL_MULTILINE(1, OneLine("Caution: One Line"))

D = DUAL_MULTILINE(2, "Caution: First line"
                                      " second line"
                                      " third line"
                                      " fourth line")
                                                                 
theEnd();

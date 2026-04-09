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
/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the type names.  */
#define YYSTYPE         SLEIGHSTYPE
/* Substitute the variable and function names.  */
#define yyparse         sleighparse
#define yylex           sleighlex
#define yyerror         sleigherror
#define yydebug         sleighdebug
#define yynerrs         sleighnerrs
#define yylval          sleighlval
#define yychar          sleighchar

/* First part of user prologue.  */

#include "slgh_compile.hh"

extern FILE *sleighin;
extern int sleighlex(void);

namespace ghidra {

extern SleighCompile *slgh;
extern int4 actionon;
extern int sleighdebug;
extern int sleigherror(const char *str );


# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "slghparse.hh"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_OP_BOOL_OR = 3,                 /* OP_BOOL_OR  */
  YYSYMBOL_OP_BOOL_AND = 4,                /* OP_BOOL_AND  */
  YYSYMBOL_OP_BOOL_XOR = 5,                /* OP_BOOL_XOR  */
  YYSYMBOL_6_ = 6,                         /* '|'  */
  YYSYMBOL_OP_OR = 7,                      /* OP_OR  */
  YYSYMBOL_8_ = 8,                         /* ';'  */
  YYSYMBOL_9_ = 9,                         /* '^'  */
  YYSYMBOL_OP_XOR = 10,                    /* OP_XOR  */
  YYSYMBOL_11_ = 11,                       /* '&'  */
  YYSYMBOL_OP_AND = 12,                    /* OP_AND  */
  YYSYMBOL_OP_EQUAL = 13,                  /* OP_EQUAL  */
  YYSYMBOL_OP_NOTEQUAL = 14,               /* OP_NOTEQUAL  */
  YYSYMBOL_OP_FEQUAL = 15,                 /* OP_FEQUAL  */
  YYSYMBOL_OP_FNOTEQUAL = 16,              /* OP_FNOTEQUAL  */
  YYSYMBOL_17_ = 17,                       /* '<'  */
  YYSYMBOL_18_ = 18,                       /* '>'  */
  YYSYMBOL_OP_GREATEQUAL = 19,             /* OP_GREATEQUAL  */
  YYSYMBOL_OP_LESSEQUAL = 20,              /* OP_LESSEQUAL  */
  YYSYMBOL_OP_SLESS = 21,                  /* OP_SLESS  */
  YYSYMBOL_OP_SGREATEQUAL = 22,            /* OP_SGREATEQUAL  */
  YYSYMBOL_OP_SLESSEQUAL = 23,             /* OP_SLESSEQUAL  */
  YYSYMBOL_OP_SGREAT = 24,                 /* OP_SGREAT  */
  YYSYMBOL_OP_FLESS = 25,                  /* OP_FLESS  */
  YYSYMBOL_OP_FGREAT = 26,                 /* OP_FGREAT  */
  YYSYMBOL_OP_FLESSEQUAL = 27,             /* OP_FLESSEQUAL  */
  YYSYMBOL_OP_FGREATEQUAL = 28,            /* OP_FGREATEQUAL  */
  YYSYMBOL_OP_LEFT = 29,                   /* OP_LEFT  */
  YYSYMBOL_OP_RIGHT = 30,                  /* OP_RIGHT  */
  YYSYMBOL_OP_SRIGHT = 31,                 /* OP_SRIGHT  */
  YYSYMBOL_32_ = 32,                       /* '+'  */
  YYSYMBOL_33_ = 33,                       /* '-'  */
  YYSYMBOL_OP_FADD = 34,                   /* OP_FADD  */
  YYSYMBOL_OP_FSUB = 35,                   /* OP_FSUB  */
  YYSYMBOL_36_ = 36,                       /* '*'  */
  YYSYMBOL_37_ = 37,                       /* '/'  */
  YYSYMBOL_38_ = 38,                       /* '%'  */
  YYSYMBOL_OP_SDIV = 39,                   /* OP_SDIV  */
  YYSYMBOL_OP_SREM = 40,                   /* OP_SREM  */
  YYSYMBOL_OP_FMULT = 41,                  /* OP_FMULT  */
  YYSYMBOL_OP_FDIV = 42,                   /* OP_FDIV  */
  YYSYMBOL_43_ = 43,                       /* '!'  */
  YYSYMBOL_44_ = 44,                       /* '~'  */
  YYSYMBOL_OP_ZEXT = 45,                   /* OP_ZEXT  */
  YYSYMBOL_OP_CARRY = 46,                  /* OP_CARRY  */
  YYSYMBOL_OP_BORROW = 47,                 /* OP_BORROW  */
  YYSYMBOL_OP_SEXT = 48,                   /* OP_SEXT  */
  YYSYMBOL_OP_SCARRY = 49,                 /* OP_SCARRY  */
  YYSYMBOL_OP_SBORROW = 50,                /* OP_SBORROW  */
  YYSYMBOL_OP_NAN = 51,                    /* OP_NAN  */
  YYSYMBOL_OP_ABS = 52,                    /* OP_ABS  */
  YYSYMBOL_OP_SQRT = 53,                   /* OP_SQRT  */
  YYSYMBOL_OP_CEIL = 54,                   /* OP_CEIL  */
  YYSYMBOL_OP_FLOOR = 55,                  /* OP_FLOOR  */
  YYSYMBOL_OP_ROUND = 56,                  /* OP_ROUND  */
  YYSYMBOL_OP_INT2FLOAT = 57,              /* OP_INT2FLOAT  */
  YYSYMBOL_OP_FLOAT2FLOAT = 58,            /* OP_FLOAT2FLOAT  */
  YYSYMBOL_OP_TRUNC = 59,                  /* OP_TRUNC  */
  YYSYMBOL_OP_CPOOLREF = 60,               /* OP_CPOOLREF  */
  YYSYMBOL_OP_NEW = 61,                    /* OP_NEW  */
  YYSYMBOL_OP_POPCOUNT = 62,               /* OP_POPCOUNT  */
  YYSYMBOL_OP_LZCOUNT = 63,                /* OP_LZCOUNT  */
  YYSYMBOL_OP_BITREV = 64,                 /* OP_BITREV  */
  YYSYMBOL_OP_TZCOUNT = 65,                /* OP_TZCOUNT  */
  YYSYMBOL_BADINTEGER = 66,                /* BADINTEGER  */
  YYSYMBOL_GOTO_KEY = 67,                  /* GOTO_KEY  */
  YYSYMBOL_CALL_KEY = 68,                  /* CALL_KEY  */
  YYSYMBOL_RETURN_KEY = 69,                /* RETURN_KEY  */
  YYSYMBOL_IF_KEY = 70,                    /* IF_KEY  */
  YYSYMBOL_DEFINE_KEY = 71,                /* DEFINE_KEY  */
  YYSYMBOL_ATTACH_KEY = 72,                /* ATTACH_KEY  */
  YYSYMBOL_MACRO_KEY = 73,                 /* MACRO_KEY  */
  YYSYMBOL_SPACE_KEY = 74,                 /* SPACE_KEY  */
  YYSYMBOL_TYPE_KEY = 75,                  /* TYPE_KEY  */
  YYSYMBOL_RAM_KEY = 76,                   /* RAM_KEY  */
  YYSYMBOL_DEFAULT_KEY = 77,               /* DEFAULT_KEY  */
  YYSYMBOL_REGISTER_KEY = 78,              /* REGISTER_KEY  */
  YYSYMBOL_ENDIAN_KEY = 79,                /* ENDIAN_KEY  */
  YYSYMBOL_WITH_KEY = 80,                  /* WITH_KEY  */
  YYSYMBOL_ALIGN_KEY = 81,                 /* ALIGN_KEY  */
  YYSYMBOL_OP_UNIMPL = 82,                 /* OP_UNIMPL  */
  YYSYMBOL_TOKEN_KEY = 83,                 /* TOKEN_KEY  */
  YYSYMBOL_SIGNED_KEY = 84,                /* SIGNED_KEY  */
  YYSYMBOL_NOFLOW_KEY = 85,                /* NOFLOW_KEY  */
  YYSYMBOL_HEX_KEY = 86,                   /* HEX_KEY  */
  YYSYMBOL_DEC_KEY = 87,                   /* DEC_KEY  */
  YYSYMBOL_BIG_KEY = 88,                   /* BIG_KEY  */
  YYSYMBOL_LITTLE_KEY = 89,                /* LITTLE_KEY  */
  YYSYMBOL_SIZE_KEY = 90,                  /* SIZE_KEY  */
  YYSYMBOL_WORDSIZE_KEY = 91,              /* WORDSIZE_KEY  */
  YYSYMBOL_OFFSET_KEY = 92,                /* OFFSET_KEY  */
  YYSYMBOL_NAMES_KEY = 93,                 /* NAMES_KEY  */
  YYSYMBOL_VALUES_KEY = 94,                /* VALUES_KEY  */
  YYSYMBOL_VARIABLES_KEY = 95,             /* VARIABLES_KEY  */
  YYSYMBOL_PCODEOP_KEY = 96,               /* PCODEOP_KEY  */
  YYSYMBOL_IS_KEY = 97,                    /* IS_KEY  */
  YYSYMBOL_LOCAL_KEY = 98,                 /* LOCAL_KEY  */
  YYSYMBOL_DELAYSLOT_KEY = 99,             /* DELAYSLOT_KEY  */
  YYSYMBOL_CROSSBUILD_KEY = 100,           /* CROSSBUILD_KEY  */
  YYSYMBOL_EXPORT_KEY = 101,               /* EXPORT_KEY  */
  YYSYMBOL_BUILD_KEY = 102,                /* BUILD_KEY  */
  YYSYMBOL_CONTEXT_KEY = 103,              /* CONTEXT_KEY  */
  YYSYMBOL_ELLIPSIS_KEY = 104,             /* ELLIPSIS_KEY  */
  YYSYMBOL_GLOBALSET_KEY = 105,            /* GLOBALSET_KEY  */
  YYSYMBOL_BITRANGE_KEY = 106,             /* BITRANGE_KEY  */
  YYSYMBOL_CHAR = 107,                     /* CHAR  */
  YYSYMBOL_INTEGER = 108,                  /* INTEGER  */
  YYSYMBOL_INTB = 109,                     /* INTB  */
  YYSYMBOL_STRING = 110,                   /* STRING  */
  YYSYMBOL_SYMBOLSTRING = 111,             /* SYMBOLSTRING  */
  YYSYMBOL_SPACESYM = 112,                 /* SPACESYM  */
  YYSYMBOL_SECTIONSYM = 113,               /* SECTIONSYM  */
  YYSYMBOL_TOKENSYM = 114,                 /* TOKENSYM  */
  YYSYMBOL_USEROPSYM = 115,                /* USEROPSYM  */
  YYSYMBOL_VALUESYM = 116,                 /* VALUESYM  */
  YYSYMBOL_VALUEMAPSYM = 117,              /* VALUEMAPSYM  */
  YYSYMBOL_CONTEXTSYM = 118,               /* CONTEXTSYM  */
  YYSYMBOL_NAMESYM = 119,                  /* NAMESYM  */
  YYSYMBOL_VARSYM = 120,                   /* VARSYM  */
  YYSYMBOL_BITSYM = 121,                   /* BITSYM  */
  YYSYMBOL_SPECSYM = 122,                  /* SPECSYM  */
  YYSYMBOL_VARLISTSYM = 123,               /* VARLISTSYM  */
  YYSYMBOL_OPERANDSYM = 124,               /* OPERANDSYM  */
  YYSYMBOL_JUMPSYM = 125,                  /* JUMPSYM  */
  YYSYMBOL_MACROSYM = 126,                 /* MACROSYM  */
  YYSYMBOL_LABELSYM = 127,                 /* LABELSYM  */
  YYSYMBOL_SUBTABLESYM = 128,              /* SUBTABLESYM  */
  YYSYMBOL_129_ = 129,                     /* '}'  */
  YYSYMBOL_130_ = 130,                     /* '='  */
  YYSYMBOL_131_ = 131,                     /* '('  */
  YYSYMBOL_132_ = 132,                     /* ')'  */
  YYSYMBOL_133_ = 133,                     /* ','  */
  YYSYMBOL_134_ = 134,                     /* '['  */
  YYSYMBOL_135_ = 135,                     /* ']'  */
  YYSYMBOL_136_ = 136,                     /* '{'  */
  YYSYMBOL_137_ = 137,                     /* ':'  */
  YYSYMBOL_138_ = 138,                     /* ' '  */
  YYSYMBOL_YYACCEPT = 139,                 /* $accept  */
  YYSYMBOL_spec = 140,                     /* spec  */
  YYSYMBOL_definition = 141,               /* definition  */
  YYSYMBOL_constructorlike = 142,          /* constructorlike  */
  YYSYMBOL_endiandef = 143,                /* endiandef  */
  YYSYMBOL_aligndef = 144,                 /* aligndef  */
  YYSYMBOL_tokendef = 145,                 /* tokendef  */
  YYSYMBOL_tokenprop = 146,                /* tokenprop  */
  YYSYMBOL_contextdef = 147,               /* contextdef  */
  YYSYMBOL_contextprop = 148,              /* contextprop  */
  YYSYMBOL_fielddef = 149,                 /* fielddef  */
  YYSYMBOL_contextfielddef = 150,          /* contextfielddef  */
  YYSYMBOL_spacedef = 151,                 /* spacedef  */
  YYSYMBOL_spaceprop = 152,                /* spaceprop  */
  YYSYMBOL_varnodedef = 153,               /* varnodedef  */
  YYSYMBOL_bitrangedef = 154,              /* bitrangedef  */
  YYSYMBOL_bitrangelist = 155,             /* bitrangelist  */
  YYSYMBOL_bitrangesingle = 156,           /* bitrangesingle  */
  YYSYMBOL_pcodeopdef = 157,               /* pcodeopdef  */
  YYSYMBOL_valueattach = 158,              /* valueattach  */
  YYSYMBOL_nameattach = 159,               /* nameattach  */
  YYSYMBOL_varattach = 160,                /* varattach  */
  YYSYMBOL_macrodef = 161,                 /* macrodef  */
  YYSYMBOL_withblockstart = 162,           /* withblockstart  */
  YYSYMBOL_withblockmid = 163,             /* withblockmid  */
  YYSYMBOL_withblock = 164,                /* withblock  */
  YYSYMBOL_id_or_nil = 165,                /* id_or_nil  */
  YYSYMBOL_bitpat_or_nil = 166,            /* bitpat_or_nil  */
  YYSYMBOL_macrostart = 167,               /* macrostart  */
  YYSYMBOL_rtlbody = 168,                  /* rtlbody  */
  YYSYMBOL_constructor = 169,              /* constructor  */
  YYSYMBOL_constructprint = 170,           /* constructprint  */
  YYSYMBOL_subtablestart = 171,            /* subtablestart  */
  YYSYMBOL_pexpression = 172,              /* pexpression  */
  YYSYMBOL_pequation = 173,                /* pequation  */
  YYSYMBOL_elleq = 174,                    /* elleq  */
  YYSYMBOL_ellrt = 175,                    /* ellrt  */
  YYSYMBOL_atomic = 176,                   /* atomic  */
  YYSYMBOL_constraint = 177,               /* constraint  */
  YYSYMBOL_contextblock = 178,             /* contextblock  */
  YYSYMBOL_contextlist = 179,              /* contextlist  */
  YYSYMBOL_section_def = 180,              /* section_def  */
  YYSYMBOL_rtlfirstsection = 181,          /* rtlfirstsection  */
  YYSYMBOL_rtlcontinue = 182,              /* rtlcontinue  */
  YYSYMBOL_rtl = 183,                      /* rtl  */
  YYSYMBOL_rtlmid = 184,                   /* rtlmid  */
  YYSYMBOL_statement = 185,                /* statement  */
  YYSYMBOL_expr = 186,                     /* expr  */
  YYSYMBOL_sizedstar = 187,                /* sizedstar  */
  YYSYMBOL_jumpdest = 188,                 /* jumpdest  */
  YYSYMBOL_varnode = 189,                  /* varnode  */
  YYSYMBOL_integervarnode = 190,           /* integervarnode  */
  YYSYMBOL_lhsvarnode = 191,               /* lhsvarnode  */
  YYSYMBOL_label = 192,                    /* label  */
  YYSYMBOL_exportvarnode = 193,            /* exportvarnode  */
  YYSYMBOL_familysymbol = 194,             /* familysymbol  */
  YYSYMBOL_specificsymbol = 195,           /* specificsymbol  */
  YYSYMBOL_charstring = 196,               /* charstring  */
  YYSYMBOL_intblist = 197,                 /* intblist  */
  YYSYMBOL_intbpart = 198,                 /* intbpart  */
  YYSYMBOL_stringlist = 199,               /* stringlist  */
  YYSYMBOL_stringpart = 200,               /* stringpart  */
  YYSYMBOL_anystringlist = 201,            /* anystringlist  */
  YYSYMBOL_anystringpart = 202,            /* anystringpart  */
  YYSYMBOL_valuelist = 203,                /* valuelist  */
  YYSYMBOL_valuepart = 204,                /* valuepart  */
  YYSYMBOL_varlist = 205,                  /* varlist  */
  YYSYMBOL_varpart = 206,                  /* varpart  */
  YYSYMBOL_paramlist = 207,                /* paramlist  */
  YYSYMBOL_oplist = 208,                   /* oplist  */
  YYSYMBOL_anysymbol = 209                 /* anysymbol  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined SLEIGHSTYPE_IS_TRIVIAL && SLEIGHSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  5
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   2719

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  139
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  71
/* YYNRULES -- Number of rules.  */
#define YYNRULES  338
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  722

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   370


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,   138,    43,     2,     2,     2,    38,    11,     2,
     131,   132,    36,    32,   133,    33,     2,    37,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   137,     8,
      17,   130,    18,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   134,     2,   135,     9,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   136,     6,   129,    44,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     7,    10,    12,    13,    14,    15,    16,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    34,    35,    39,    40,    41,    42,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    73,    74,    75,    76,    77,
      78,    79,    80,    81,    82,    83,    84,    85,    86,    87,
      88,    89,    90,    91,    92,    93,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,   107,
     108,   109,   110,   111,   112,   113,   114,   115,   116,   117,
     118,   119,   120,   121,   122,   123,   124,   125,   126,   127,
     128
};

#if SLEIGHDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   155,   155,   156,   157,   158,   160,   161,   162,   163,
     164,   165,   166,   167,   168,   169,   171,   172,   173,   174,
     176,   177,   179,   181,   183,   184,   185,   186,   187,   189,
     191,   192,   195,   196,   197,   198,   199,   201,   202,   203,
     204,   205,   206,   208,   210,   211,   212,   213,   214,   215,
     216,   218,   220,   222,   224,   225,   227,   230,   232,   234,
     236,   238,   241,   243,   244,   245,   247,   249,   250,   251,
     254,   255,   258,   260,   261,   262,   264,   265,   267,   268,
     269,   270,   271,   272,   273,   274,   275,   277,   278,   279,
     280,   282,   284,   287,   288,   289,   290,   291,   292,   293,
     294,   295,   296,   297,   298,   299,   301,   302,   303,   304,
     306,   307,   309,   310,   312,   313,   315,   316,   317,   318,
     319,   320,   321,   324,   325,   326,   327,   329,   330,   332,
     333,   334,   335,   336,   337,   339,   340,   342,   344,   345,
     347,   348,   349,   350,   351,   353,   354,   355,   356,   358,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,   378,
     379,   380,   381,   382,   384,   385,   386,   387,   388,   389,
     390,   391,   392,   393,   394,   395,   396,   397,   398,   399,
     400,   401,   402,   403,   404,   405,   406,   407,   408,   409,
     410,   411,   412,   413,   414,   415,   416,   417,   418,   419,
     420,   421,   422,   423,   424,   425,   426,   427,   428,   429,
     430,   431,   432,   433,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   454,   455,   456,   457,   459,   460,   461,
     462,   463,   464,   465,   467,   468,   469,   470,   472,   473,
     474,   475,   476,   478,   479,   480,   482,   483,   485,   486,
     487,   488,   489,   490,   492,   493,   494,   495,   496,   498,
     499,   500,   501,   503,   504,   506,   507,   508,   510,   511,
     512,   514,   515,   516,   519,   520,   522,   523,   524,   526,
     528,   529,   530,   531,   533,   534,   535,   537,   538,   539,
     540,   541,   543,   544,   546,   547,   549,   550,   553,   554,
     555,   557,   558,   559,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,   571,   572,   573,   574,   575
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if SLEIGHDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "OP_BOOL_OR",
  "OP_BOOL_AND", "OP_BOOL_XOR", "'|'", "OP_OR", "';'", "'^'", "OP_XOR",
  "'&'", "OP_AND", "OP_EQUAL", "OP_NOTEQUAL", "OP_FEQUAL", "OP_FNOTEQUAL",
  "'<'", "'>'", "OP_GREATEQUAL", "OP_LESSEQUAL", "OP_SLESS",
  "OP_SGREATEQUAL", "OP_SLESSEQUAL", "OP_SGREAT", "OP_FLESS", "OP_FGREAT",
  "OP_FLESSEQUAL", "OP_FGREATEQUAL", "OP_LEFT", "OP_RIGHT", "OP_SRIGHT",
  "'+'", "'-'", "OP_FADD", "OP_FSUB", "'*'", "'/'", "'%'", "OP_SDIV",
  "OP_SREM", "OP_FMULT", "OP_FDIV", "'!'", "'~'", "OP_ZEXT", "OP_CARRY",
  "OP_BORROW", "OP_SEXT", "OP_SCARRY", "OP_SBORROW", "OP_NAN", "OP_ABS",
  "OP_SQRT", "OP_CEIL", "OP_FLOOR", "OP_ROUND", "OP_INT2FLOAT",
  "OP_FLOAT2FLOAT", "OP_TRUNC", "OP_CPOOLREF", "OP_NEW", "OP_POPCOUNT",
  "OP_LZCOUNT", "OP_BITREV", "OP_TZCOUNT", "BADINTEGER", "GOTO_KEY",
  "CALL_KEY", "RETURN_KEY", "IF_KEY", "DEFINE_KEY", "ATTACH_KEY",
  "MACRO_KEY", "SPACE_KEY", "TYPE_KEY", "RAM_KEY", "DEFAULT_KEY",
  "REGISTER_KEY", "ENDIAN_KEY", "WITH_KEY", "ALIGN_KEY", "OP_UNIMPL",
  "TOKEN_KEY", "SIGNED_KEY", "NOFLOW_KEY", "HEX_KEY", "DEC_KEY", "BIG_KEY",
  "LITTLE_KEY", "SIZE_KEY", "WORDSIZE_KEY", "OFFSET_KEY", "NAMES_KEY",
  "VALUES_KEY", "VARIABLES_KEY", "PCODEOP_KEY", "IS_KEY", "LOCAL_KEY",
  "DELAYSLOT_KEY", "CROSSBUILD_KEY", "EXPORT_KEY", "BUILD_KEY",
  "CONTEXT_KEY", "ELLIPSIS_KEY", "GLOBALSET_KEY", "BITRANGE_KEY", "CHAR",
  "INTEGER", "INTB", "STRING", "SYMBOLSTRING", "SPACESYM", "SECTIONSYM",
  "TOKENSYM", "USEROPSYM", "VALUESYM", "VALUEMAPSYM", "CONTEXTSYM",
  "NAMESYM", "VARSYM", "BITSYM", "SPECSYM", "VARLISTSYM", "OPERANDSYM",
  "JUMPSYM", "MACROSYM", "LABELSYM", "SUBTABLESYM", "'}'", "'='", "'('",
  "')'", "','", "'['", "']'", "'{'", "':'", "' '", "$accept", "spec",
  "definition", "constructorlike", "endiandef", "aligndef", "tokendef",
  "tokenprop", "contextdef", "contextprop", "fielddef", "contextfielddef",
  "spacedef", "spaceprop", "varnodedef", "bitrangedef", "bitrangelist",
  "bitrangesingle", "pcodeopdef", "valueattach", "nameattach", "varattach",
  "macrodef", "withblockstart", "withblockmid", "withblock", "id_or_nil",
  "bitpat_or_nil", "macrostart", "rtlbody", "constructor",
  "constructprint", "subtablestart", "pexpression", "pequation", "elleq",
  "ellrt", "atomic", "constraint", "contextblock", "contextlist",
  "section_def", "rtlfirstsection", "rtlcontinue", "rtl", "rtlmid",
  "statement", "expr", "sizedstar", "jumpdest", "varnode",
  "integervarnode", "lhsvarnode", "label", "exportvarnode", "familysymbol",
  "specificsymbol", "charstring", "intblist", "intbpart", "stringlist",
  "stringpart", "anystringlist", "anystringpart", "valuelist", "valuepart",
  "varlist", "varpart", "paramlist", "oplist", "anysymbol", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-295)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-273)

#define yytable_value_is_error(Yyn) \
  ((Yyn) == YYTABLE_NINF)

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -40,   -32,     5,  -295,   -72,  -295,    18,  1586,    97,    12,
     -49,    32,    64,  -295,  -295,  -295,  -295,  -295,   377,  -295,
     404,  -295,   103,  -295,  -295,  -295,  -295,  -295,  -295,  -295,
    -295,    36,  -295,    86,  -295,     7,    60,   140,  -295,  -295,
    2557,     1,  2574,   -60,    87,   175,   185,   -50,   -50,   -50,
     164,  -295,  -295,   183,  -295,  -295,  -295,   173,  -295,  -295,
    -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,
    -295,  -295,  -295,    26,   199,  -295,   207,   230,   245,  -295,
     258,  -295,   268,   270,  1587,  -295,  -295,  -295,  -295,  -295,
    1683,  -295,  -295,  -295,  -295,   295,  -295,  1683,  -295,  -295,
    -295,   295,   384,   396,  -295,  -295,   306,   302,  -295,  -295,
     325,   418,  -295,   314,    10,  -295,   329,  -295,  -295,   152,
     330,    -6,   -39,   351,  1683,   332,  -295,  -295,  -295,   334,
     344,  -295,  -295,  -295,  -295,   347,   226,   371,   374,   354,
    1792,  1557,  -295,  -295,  -295,  -295,  -295,  -295,   358,  -295,
    1683,    14,  -295,  -295,   380,  -295,    45,  -295,    14,  -295,
    -295,   496,   398,  -295,  2509,  -295,   387,  -295,  -295,   -36,
    -295,  -295,   -64,  2591,   500,   402,  -295,    42,   503,  -295,
     -82,   504,  -295,   248,   379,   273,   428,   430,   442,   446,
    -295,  -295,  -295,  -295,  -295,   262,   -74,   155,  -295,   443,
    1755,     2,  1661,   -19,   395,   312,   166,   437,   415,    29,
     427,  -295,   432,  -295,  -295,  -295,   435,    38,  -295,  1661,
     -10,  -295,   141,  -295,   153,  -295,   424,     3,  1683,  1683,
    1683,  -295,   -63,  -295,   424,   424,   424,   424,   424,   424,
     -63,  -295,   433,  -295,  -295,  -295,   448,  -295,   488,  -295,
    -295,  -295,  -295,  -295,  2533,  -295,  -295,  -295,   472,  -295,
    -295,   -16,  -295,  -295,  -295,   -87,  -295,  -295,   507,   482,
     487,   489,   524,   525,  -295,  -295,   552,  -295,  -295,   644,
     675,   582,   587,  -295,   566,  -295,  -295,  -295,  1661,   695,
    -295,  1661,   732,  -295,  1661,  1661,  1661,  1661,  1661,   612,
     645,   646,   654,   656,   687,   692,   697,   737,   772,   773,
     812,   813,   815,   852,   853,   855,   892,   893,   895,   932,
    -295,  1661,  1918,  1661,  -295,   -48,     0,   571,   633,   691,
     269,   726,   898,  -295,   291,  1058,  -295,  1095,   756,  1661,
     956,  1661,  1661,  1661,  1616,   996,   998,  1661,  1035,   424,
     424,  -295,   424,  2471,  -295,  -295,  -295,   316,  1133,  -295,
      71,  -295,  -295,  -295,  2471,  2471,  2471,  2471,  2471,  2471,
    -295,  1067,  1075,  1054,  -295,  -295,  -295,  -295,  1078,  -295,
    -295,  -295,  -295,  -295,  -295,  -295,  -295,  1115,  1116,  1118,
    1155,   312,  -295,  -295,  1129,  -295,  1154,   327,  -295,   570,
    -295,   610,  -295,  -295,  -295,  -295,  1661,  1661,  1661,  1661,
    1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,
    1661,  1661,  1661,  1661,  1661,  1661,  1661,   816,  1661,  1661,
    1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,
    1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,
    1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,  1661,
    1661,  1661,  1661,  1661,   317,  -295,    21,  1195,  1196,  -295,
    1661,  1198,  -295,  1211,   261,  1236,  -295,  1238,  1375,  -295,
    1378,  -295,  -295,  -295,  -295,  1973,  1254,  2293,   275,  2013,
     277,  1661,  1291,  1294,  2053,  1293,  -295,  -295,   289,   424,
     424,   424,   424,   424,   424,   424,   424,   424,  1332,  -295,
    1334,  1373,  -295,  -295,  -295,    -5,  1374,  1333,  1398,  -295,
    1411,  1412,  1414,  1451,  -295,  1447,  1488,  1578,  1618,  1651,
     856,   693,   896,   733,   775,   936,   976,  1016,  1056,  1096,
    1136,  1176,  1216,  1256,   285,   650,  1296,  1336,  1376,  1416,
     298,  -295,  2332,  2369,  2369,  2403,  2435,  2496,  2550,  2550,
    2550,  2550,  2576,  2576,  2576,  2576,  2576,  2576,  2576,  2576,
    2576,  2576,  2576,  2576,  1834,  1834,  1834,  1846,  1846,  1846,
    1846,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  1654,  1492,
    1530,  -295,  2093,     4,  1656,  1657,  1658,   312,  -295,  -295,
    -295,  1661,  1663,  1661,  -295,  1669,  2133,  -295,  -295,  -295,
    1570,  -295,  2529,   444,   167,   434,   434,   359,   359,  -295,
    -295,  1845,   424,   424,  1727,   263,  -295,  -295,   335,  1579,
     -60,  -295,  -295,  -295,  -295,  1583,  -295,  -295,  -295,  -295,
    -295,  1661,  -295,  1661,  1661,  -295,  -295,  -295,  -295,  -295,
    -295,  -295,  -295,  -295,  -295,  -295,  1661,  -295,  -295,  -295,
    -295,  -295,  -295,  -295,  1592,  -295,  -295,  1661,  -295,  -295,
    -295,  -295,  2173,  -295,  2293,  -295,  -295,  1549,  1553,  1562,
     527,  1721,  -295,  -295,  1671,  1672,  -295,  -295,  1568,  1722,
    -295,  1456,  1496,  1536,  1576,  1597,  2213,  -295,  1604,  1617,
    1619,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,
    -295,  -295,  -295,  1661,  1607,  1608,  2253,  1728,  1733,  -295,
    -295,  -295
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int16 yydefact[] =
{
       0,     0,     0,     2,     0,     1,     0,     0,     0,     0,
      67,     0,     0,    89,     4,     5,     3,     6,     0,     7,
       0,     8,     0,     9,    10,    11,    12,    13,    14,    17,
      63,     0,    18,     0,    16,     0,     0,     0,    15,    19,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    69,    68,     0,    88,    87,    23,     0,   324,   325,
     326,   327,   330,   331,   332,   333,   334,   338,   335,   336,
     337,   328,   329,    27,     0,    29,     0,    31,     0,    43,
       0,    50,     0,     0,     0,    66,    64,    65,   145,    82,
       0,   283,    83,    86,    85,    84,    81,     0,    78,    80,
      90,    79,     0,     0,    44,    45,     0,     0,    28,   295,
       0,     0,    30,     0,     0,    54,     0,   305,   306,     0,
       0,     0,     0,   321,    70,     0,    34,    35,    36,     0,
       0,    39,    40,    41,    42,     0,     0,     0,     0,     0,
     140,     0,   274,   275,   276,   277,   124,   278,   123,   126,
       0,   127,   106,   111,   113,   114,   125,   284,   127,    20,
      21,     0,     0,   296,     0,    57,     0,    53,    55,     0,
     307,   308,     0,     0,     0,     0,   286,     0,     0,   313,
       0,     0,   322,     0,   127,    71,     0,     0,     0,     0,
      46,    47,    48,    49,    61,     0,     0,   246,   259,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   258,   256,
       0,   279,     0,   280,   281,   282,     0,   257,   146,     0,
       0,   255,     0,   173,   254,   110,     0,     0,     0,     0,
       0,   129,     0,   112,     0,     0,     0,     0,     0,     0,
       0,    22,     0,   297,   294,   298,     0,    52,     0,   311,
     309,   310,   304,   300,     0,   301,    59,   287,     0,   288,
     290,     0,    58,   315,   314,     0,    60,    72,     0,     0,
       0,     0,     0,     0,   256,   257,     0,   261,   254,     0,
       0,     0,     0,   249,   248,   253,   250,   247,     0,     0,
     252,     0,     0,   170,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     240,     0,     0,     0,   174,   254,     0,     0,     0,     0,
       0,     0,   143,   273,     0,     0,   268,     0,     0,     0,
       0,   318,     0,   318,     0,     0,     0,     0,     0,     0,
       0,    91,     0,   122,    92,    93,   115,   108,   109,   107,
       0,    75,   145,    76,   117,   118,   120,   121,   119,   116,
      77,    24,     0,     0,   302,   299,   303,   289,     0,   291,
     293,   285,   317,   316,   312,   323,    62,     0,     0,     0,
       0,     0,   267,   266,     0,   245,     0,     0,   165,     0,
     168,     0,   189,   216,   202,   190,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     318,     0,     0,     0,     0,     0,   318,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   175,     0,     0,     0,   147,
       0,     0,   154,     0,     0,     0,   269,     0,   144,   265,
       0,   263,   141,   161,   260,     0,     0,   319,     0,     0,
       0,     0,     0,     0,     0,     0,   104,   105,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   134,
       0,     0,   128,   138,   145,     0,     0,     0,     0,   292,
       0,     0,     0,     0,   262,   244,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   176,   205,   204,   203,   193,   191,   192,   179,   180,
     206,   207,   181,   184,   182,   183,   185,   186,   187,   188,
     208,   209,   210,   211,   194,   195,   196,   177,   178,   212,
     213,   197,   198,   200,   199,   201,   214,   215,     0,     0,
       0,   238,     0,     0,     0,     0,     0,     0,   271,   142,
     151,     0,     0,     0,   158,     0,     0,   160,   159,   149,
       0,    94,   101,   102,   100,    98,    99,    95,    96,    97,
     103,     0,     0,     0,     0,     0,    73,   137,     0,     0,
       0,    32,    33,    37,    38,     0,   251,   167,   169,   171,
     220,     0,   219,     0,     0,   226,   217,   218,   228,   229,
     230,   225,   224,   227,   242,   231,     0,   233,   234,   235,
     236,   241,   166,   237,     0,   150,   148,     0,   164,   163,
     162,   270,     0,   156,   320,   172,   155,     0,     0,     0,
       0,     0,    74,   139,     0,     0,    26,    25,     0,     0,
     243,     0,     0,     0,     0,     0,     0,   153,     0,     0,
       0,   130,   133,   135,   136,    56,    51,   221,   222,   223,
     232,   239,   152,     0,     0,     0,     0,     0,     0,   157,
     131,   132
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -295,  -295,  1711,  1712,  -295,  -295,  -295,  -295,  -295,  -295,
    -295,  -295,  -295,  -295,  -295,  -295,  -295,  1631,  -295,  -295,
    -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  -295,  1507,
    -295,  -295,  -295,  -194,   -68,  -295,  1611,  -295,  -295,  -145,
    -295,  1124,  -295,  -295,  1387,  1241,  -295,  -198,  -139,  -197,
    -125,  1295,  1425,  -138,  -295,   -90,   -52,  1724,  -295,  -295,
    1132,  -295,  -295,  -295,   390,  -295,  -295,  -295,  -294,  -295,
      15
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,     2,    14,    15,     3,    16,    17,    18,    19,    20,
      73,    77,    21,    22,    23,    24,   114,   115,    25,    26,
      27,    28,    29,    30,    31,    32,    53,   184,    33,   363,
      34,    35,    36,   353,   151,   152,   153,   154,   155,   232,
     360,   627,   513,   514,   139,   140,   218,   487,   323,   289,
     324,   221,   222,   290,   335,   354,   325,    95,   178,   261,
     111,   164,   174,   254,   120,   172,   181,   265,   488,   183,
      74
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     156,   219,   223,   292,   322,     5,     6,   156,   469,   228,
     293,   229,   666,   240,   230,   220,    89,   378,   167,   361,
     228,   344,   229,   382,   625,   230,    38,   175,   263,   158,
     247,     1,   195,   383,   156,    78,   279,     6,   264,   269,
     364,   365,   366,   367,   368,   369,   249,     4,   384,   490,
     109,   156,   250,   280,   251,   105,   185,   108,    37,   234,
     156,    51,   235,   236,   237,   238,   117,   334,   118,    96,
     277,   252,   248,   362,   110,   258,     7,     8,     9,    52,
     329,   179,   227,   466,   119,    10,   467,   198,   224,   468,
     397,   326,   379,   399,   380,   180,   401,   402,   403,   404,
     405,   211,   176,   213,    90,   214,   215,    84,     8,     9,
     126,    79,   127,   128,    91,    11,    10,    92,    93,   381,
     113,   345,    50,   427,   626,   465,   544,   346,   177,   208,
     470,   106,   550,    12,   667,   356,   294,   471,   156,   156,
     156,   485,    13,   278,   489,    94,    11,    39,   231,   494,
     259,   327,   260,   278,   336,   496,   497,    97,   498,   339,
     357,   358,   359,  -264,    12,    85,   340,    91,  -265,    54,
      98,    99,  -265,    13,   355,   239,   508,   330,    80,   245,
      81,   509,   355,   355,   355,   355,   355,   355,   255,   510,
      47,    48,    49,    82,    83,   511,   502,   503,   100,   504,
     505,    55,   197,   506,   507,   476,   512,   112,   530,   531,
     532,   533,   534,   535,   536,   537,   538,   539,   540,   541,
     542,   543,    88,   545,   546,   547,   548,   549,   102,   103,
     552,   553,   554,   555,   556,   557,   558,   559,   560,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,   571,
     572,   573,   574,   575,   576,   577,   578,   579,   580,   581,
     582,   583,   584,   585,   586,   587,   524,   588,   170,   376,
     171,   347,   592,   195,   331,   348,   332,   116,   278,   228,
     195,   229,   481,  -263,   230,   113,   211,  -263,   213,   281,
     214,   215,   282,   606,   333,   123,   499,   355,   355,   500,
     355,   501,   190,   125,   191,   612,   613,   614,   615,   616,
     617,   618,   619,   620,   131,   132,   133,   134,   502,   503,
     124,   504,   505,   195,   229,   506,   507,   230,   198,   129,
     428,   429,   430,   431,   196,   198,   432,   130,   433,   278,
     434,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     208,   595,   274,   684,   596,   135,   685,   208,   198,   274,
     267,   268,   211,   283,   213,    56,   214,   215,   136,   211,
     275,   213,   159,   214,   215,   506,   507,   275,   137,   276,
     138,   478,   157,   672,   160,   674,   475,   602,   603,   605,
     603,   211,    75,   213,   161,   214,   215,   654,   603,   479,
     208,   611,   274,   686,   687,   284,   165,   285,   680,   681,
     661,   603,   211,   162,   213,   163,   214,   215,   121,   122,
     275,   286,   287,   691,   166,   692,   693,   355,   355,   355,
     355,   355,   355,   355,   355,   355,   501,   349,   694,   169,
     196,   182,   527,   186,   173,   187,   504,   505,   350,   696,
     506,   507,   671,   502,   503,   188,   504,   505,   189,   192,
     506,   507,   193,   194,   233,   219,   223,    57,   226,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,   220,
      68,    69,    70,    71,   241,    72,   242,   246,   256,   283,
     257,   262,   266,   231,    76,   716,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,   328,    68,    69,    70,
      71,   678,    72,   351,   499,   701,   270,   500,   271,   501,
     142,   143,   144,   145,   211,   278,   213,   147,   214,   215,
     272,   284,   338,   285,   273,   352,   502,   503,   341,   504,
     505,   337,   342,   506,   507,   371,   343,   286,   287,   679,
     355,   355,   224,   428,   429,   430,   431,   288,   373,   432,
     377,   433,   372,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   428,   429,   430,   431,   385,   386,   432,
     387,   433,   388,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   428,   429,   430,   431,   389,   390,   432,
     391,   433,   392,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   393,   394,   395,   428,   429,   430,   431,
     396,   472,   432,   398,   433,   528,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
     400,   473,   432,   406,   433,   529,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   407,   408,   428,   429,
     430,   431,   655,   656,   432,   409,   433,   410,   434,   435,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   411,   428,
     429,   430,   431,   412,   474,   432,   641,   433,   413,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   477,   484,   432,   643,   433,   414,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   415,   416,   432,  -272,   433,   644,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   417,   418,   432,   419,   433,   551,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   420,   421,   432,   422,   433,   640,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   423,   424,   432,   425,   433,   642,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   426,   486,   432,   482,   433,   645,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   483,   492,   432,   493,   433,   646,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   495,   230,   432,   516,   433,   647,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   517,   518,   432,   519,   433,   648,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   520,   521,   432,   522,   433,   649,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   523,   525,   432,   526,   433,   650,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   590,   591,   432,   593,   433,   651,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   594,   597,   432,   598,   433,   652,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,  -264,   601,   432,   599,   433,   653,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   607,   608,   432,   610,   433,   657,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   621,   622,   432,   629,   433,   658,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   623,   628,   432,   630,   433,   659,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   631,   632,   432,   633,   433,   660,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   634,   635,   432,   637,   433,   707,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   428,
     429,   430,   431,   636,   663,   432,   638,   433,   708,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   639,
      40,    40,   662,   664,   668,   669,   670,    41,   709,    42,
      42,   673,   195,   142,   143,   144,   145,   675,   677,   146,
     147,   148,    43,    43,   698,   149,   699,   688,   150,    44,
      44,   690,    45,    45,   295,   700,   296,   197,    46,    46,
     695,   703,   704,   705,   297,   298,   299,   300,   710,   301,
     302,   303,   304,   305,   306,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,   317,   318,   198,   499,   702,
     706,   500,   711,   501,   713,   714,   720,   715,   195,   717,
     718,   721,    86,    87,   196,   168,   491,   370,   683,   515,
     502,   503,   225,   504,   505,   624,   625,   506,   507,   480,
     101,   589,   689,   197,     0,     0,     0,     0,     0,   208,
       0,   274,   196,     0,     0,     0,   319,     0,     0,     0,
       0,   211,   320,   213,     0,   214,   215,   141,     0,   275,
       0,     0,   321,   198,   199,   200,   201,   202,     0,   142,
     143,   144,   145,   195,     0,   146,   147,   148,     0,   196,
       0,   149,     0,     0,   150,     0,     0,     0,     0,     0,
       0,   283,     0,     0,     0,   203,   204,   205,   197,   207,
       0,     0,     0,     0,     0,   208,     0,   209,     0,     0,
       0,     0,   210,     0,     0,     0,     0,   211,   212,   213,
       0,   214,   215,   216,     0,   217,   682,     0,   198,   199,
     200,   201,   202,   284,     0,   285,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,     0,     0,   286,
     287,     0,   457,   458,   459,   460,   461,   462,   463,   291,
     203,   204,   205,   206,   207,     0,     0,     0,     0,     0,
     208,     0,   209,     0,     0,     0,     0,   210,     0,     0,
       0,     0,   211,   212,   213,     0,   214,   215,   216,     0,
     217,   428,   429,   430,   431,     0,     0,   432,     0,   433,
       0,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   142,   143,   144,   145,   211,     0,   213,   147,   214,
     215,     0,     0,     0,     0,     0,   428,   429,   430,   431,
       0,   600,   432,     0,   433,   464,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   604,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   609,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   665,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   676,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   697,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   712,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,   719,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
       0,     0,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   429,   430,   431,     0,
       0,   432,     0,   433,     0,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   431,     0,     0,   432,     0,
     433,     0,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   433,     0,   434,   435,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   499,     0,
       0,   500,     0,   501,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     502,   503,     0,   504,   505,     0,     0,   506,   507,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   500,
       0,   501,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   502,   503,
       0,   504,   505,     0,     0,   506,   507,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,  -273,  -273,  -273,  -273,  -273,  -273,  -273,
    -273,  -273,  -273,  -273,  -273,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   243,
       0,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,     0,    68,    69,    70,    71,     0,    72,     0,     0,
       0,     0,     0,   374,   244,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,     0,    68,    69,    70,    71,
       0,    72,     0,     0,     0,     0,     0,   104,   375,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,     0,
      68,    69,    70,    71,   107,    72,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,     0,    68,    69,    70,
      71,   253,    72,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,     0,    68,    69,    70,    71,     0,    72
};

static const yytype_int16 yycheck[] =
{
      90,   140,   140,   200,   202,     0,     1,    97,     8,     6,
       8,     8,     8,   158,    11,   140,     9,    33,     8,    82,
       6,   219,     8,   110,    29,    11,     8,    33,   110,    97,
      66,    71,    11,   120,   124,    20,   110,     1,   120,   184,
     234,   235,   236,   237,   238,   239,   110,    79,   135,   343,
     110,   141,   116,   127,   118,    40,   124,    42,   130,    14,
     150,   110,    17,    18,    19,    20,   116,   206,   118,     9,
     195,   135,   108,   136,   134,    33,    71,    72,    73,   128,
     205,   120,   150,   131,   134,    80,   134,    66,   140,   137,
     288,   110,   108,   291,   110,   134,   294,   295,   296,   297,
     298,   120,   108,   122,    97,   124,   125,    71,    72,    73,
      84,     8,    86,    87,   107,   110,    80,   110,   111,   135,
     110,   131,   110,   321,   129,   323,   420,   137,   134,   108,
     130,   130,   426,   128,   130,   132,   134,   137,   228,   229,
     230,   339,   137,   195,   342,   138,   110,   129,   134,   347,
     108,   203,   110,   205,   206,   349,   350,    97,   352,   130,
     228,   229,   230,   134,   128,   129,   137,   107,   130,   137,
     110,   111,   134,   137,   226,   130,   105,    11,    75,   164,
      77,   110,   234,   235,   236,   237,   238,   239,   173,   118,
      93,    94,    95,    90,    91,   124,    29,    30,   138,    32,
      33,   137,    36,    36,    37,   330,   135,   120,   406,   407,
     408,   409,   410,   411,   412,   413,   414,   415,   416,   417,
     418,   419,   136,   421,   422,   423,   424,   425,    88,    89,
     428,   429,   430,   431,   432,   433,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   391,   464,   116,   254,
     118,   130,   470,    11,   108,   134,   110,    92,   330,     6,
      11,     8,   334,   130,    11,   110,   120,   134,   122,   134,
     124,   125,   137,   491,   128,   131,     7,   349,   350,    10,
     352,    12,    76,   130,    78,   499,   500,   501,   502,   503,
     504,   505,   506,   507,    84,    85,    86,    87,    29,    30,
     137,    32,    33,    11,     8,    36,    37,    11,    66,   130,
       3,     4,     5,     6,    17,    66,     9,   130,    11,   391,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
     108,   110,   110,   110,   113,   130,   113,   108,    66,   110,
     132,   133,   120,    66,   122,     8,   124,   125,   130,   120,
     128,   122,     8,   124,   125,    36,    37,   128,   130,   137,
     130,   110,   107,   601,     8,   603,   137,   132,   133,   132,
     133,   120,     8,   122,   108,   124,   125,   132,   133,   128,
     108,   132,   110,    88,    89,   108,     8,   110,   622,   623,
     132,   133,   120,   131,   122,   110,   124,   125,    48,    49,
     128,   124,   125,   641,   130,   643,   644,   499,   500,   501,
     502,   503,   504,   505,   506,   507,    12,    33,   656,   130,
      17,   110,   135,   131,   134,   131,    32,    33,    44,   667,
      36,    37,   597,    29,    30,   131,    32,    33,   131,   108,
      36,    37,   108,   129,   104,   624,   624,   110,   130,   112,
     113,   114,   115,   116,   117,   118,   119,   120,   121,   624,
     123,   124,   125,   126,     8,   128,   108,   120,     8,    66,
     108,     8,     8,   134,   110,   713,   112,   113,   114,   115,
     116,   117,   118,   119,   120,   121,   131,   123,   124,   125,
     126,   621,   128,   109,     7,     8,   108,    10,   108,    12,
     116,   117,   118,   119,   120,   597,   122,   123,   124,   125,
     108,   108,   137,   110,   108,   131,    29,    30,   131,    32,
      33,   124,   130,    36,    37,   132,   131,   124,   125,   621,
     622,   623,   624,     3,     4,     5,     6,   134,    90,     9,
     108,    11,   134,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     3,     4,     5,     6,   110,   136,     9,
     133,    11,   133,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     3,     4,     5,     6,   133,   133,     9,
     108,    11,    18,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,    18,   112,   108,     3,     4,     5,     6,
     134,   130,     9,     8,    11,   135,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
       8,   108,     9,   131,    11,   135,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,   131,   131,     3,     4,
       5,     6,   132,   133,     9,   131,    11,   131,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,   131,     3,
       4,     5,     6,   131,   133,     9,   133,    11,   131,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   137,   108,     9,   133,    11,   131,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   131,   131,     9,     8,    11,   133,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   131,   131,     9,   131,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   131,   131,     9,   131,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   131,   131,     9,   131,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   131,   108,     9,     8,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,     8,   108,     9,   108,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   108,    11,     9,    79,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   108,   130,     9,   108,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   108,   108,     9,   108,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   108,   135,     9,   112,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   108,   108,     9,   108,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   132,   108,     9,   108,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,     8,   130,     9,     8,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   132,   130,     9,   133,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   131,   130,     9,   133,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   130,   130,     9,   108,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   132,   132,     9,   132,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   132,   137,     9,     8,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     3,
       4,     5,     6,   135,   132,     9,     8,    11,   132,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,     8,
      74,    74,     8,   133,     8,     8,     8,    81,   132,    83,
      83,     8,    11,   116,   117,   118,   119,     8,   108,   122,
     123,   124,    96,    96,   135,   128,   133,   108,   131,   103,
     103,   108,   106,   106,    33,   133,    35,    36,   112,   112,
     108,    30,    30,   135,    43,    44,    45,    46,   132,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,     7,     8,
       8,    10,   135,    12,   130,   118,     8,   118,    11,   132,
     132,     8,    31,    31,    17,   114,   130,   240,   624,   362,
      29,    30,   141,    32,    33,   514,    29,    36,    37,   334,
      36,   466,   630,    36,    -1,    -1,    -1,    -1,    -1,   108,
      -1,   110,    17,    -1,    -1,    -1,   115,    -1,    -1,    -1,
      -1,   120,   121,   122,    -1,   124,   125,   104,    -1,   128,
      -1,    -1,   131,    66,    67,    68,    69,    70,    -1,   116,
     117,   118,   119,    11,    -1,   122,   123,   124,    -1,    17,
      -1,   128,    -1,    -1,   131,    -1,    -1,    -1,    -1,    -1,
      -1,    66,    -1,    -1,    -1,    98,    99,   100,    36,   102,
      -1,    -1,    -1,    -1,    -1,   108,    -1,   110,    -1,    -1,
      -1,    -1,   115,    -1,    -1,    -1,    -1,   120,   121,   122,
      -1,   124,   125,   126,    -1,   128,   129,    -1,    66,    67,
      68,    69,    70,   108,    -1,   110,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    -1,    -1,   124,
     125,    -1,    36,    37,    38,    39,    40,    41,    42,   134,
      98,    99,   100,   101,   102,    -1,    -1,    -1,    -1,    -1,
     108,    -1,   110,    -1,    -1,    -1,    -1,   115,    -1,    -1,
      -1,    -1,   120,   121,   122,    -1,   124,   125,   126,    -1,
     128,     3,     4,     5,     6,    -1,    -1,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,   116,   117,   118,   119,   120,    -1,   122,   123,   124,
     125,    -1,    -1,    -1,    -1,    -1,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    67,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,     8,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      -1,    -1,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     4,     5,     6,    -1,
      -1,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     6,    -1,    -1,     9,    -1,
      11,    -1,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    11,    -1,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     7,    -1,
      -1,    10,    -1,    12,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      29,    30,    -1,    32,    33,    -1,    -1,    36,    37,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    10,
      -1,    12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    29,    30,
      -1,    32,    33,    -1,    -1,    36,    37,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,   110,
      -1,   112,   113,   114,   115,   116,   117,   118,   119,   120,
     121,    -1,   123,   124,   125,   126,    -1,   128,    -1,    -1,
      -1,    -1,    -1,   110,   135,   112,   113,   114,   115,   116,
     117,   118,   119,   120,   121,    -1,   123,   124,   125,   126,
      -1,   128,    -1,    -1,    -1,    -1,    -1,   110,   135,   112,
     113,   114,   115,   116,   117,   118,   119,   120,   121,    -1,
     123,   124,   125,   126,   110,   128,   112,   113,   114,   115,
     116,   117,   118,   119,   120,   121,    -1,   123,   124,   125,
     126,   110,   128,   112,   113,   114,   115,   116,   117,   118,
     119,   120,   121,    -1,   123,   124,   125,   126,    -1,   128
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    71,   140,   143,    79,     0,     1,    71,    72,    73,
      80,   110,   128,   137,   141,   142,   144,   145,   146,   147,
     148,   151,   152,   153,   154,   157,   158,   159,   160,   161,
     162,   163,   164,   167,   169,   170,   171,   130,     8,   129,
      74,    81,    83,    96,   103,   106,   112,    93,    94,    95,
     110,   110,   128,   165,   137,   137,     8,   110,   112,   113,
     114,   115,   116,   117,   118,   119,   120,   121,   123,   124,
     125,   126,   128,   149,   209,     8,   110,   150,   209,     8,
      75,    77,    90,    91,    71,   129,   141,   142,   136,     9,
      97,   107,   110,   111,   138,   196,     9,    97,   110,   111,
     138,   196,    88,    89,   110,   209,   130,   110,   209,   110,
     134,   199,   120,   110,   155,   156,    92,   116,   118,   134,
     203,   203,   203,   131,   137,   130,    84,    86,    87,   130,
     130,    84,    85,    86,    87,   130,   130,   130,   130,   183,
     184,   104,   116,   117,   118,   119,   122,   123,   124,   128,
     131,   173,   174,   175,   176,   177,   194,   107,   173,     8,
       8,   108,   131,   110,   200,     8,   130,     8,   156,   130,
     116,   118,   204,   134,   201,    33,   108,   134,   197,   120,
     134,   205,   110,   208,   166,   173,   131,   131,   131,   131,
      76,    78,   108,   108,   129,    11,    17,    36,    66,    67,
      68,    69,    70,    98,    99,   100,   101,   102,   108,   110,
     115,   120,   121,   122,   124,   125,   126,   128,   185,   187,
     189,   190,   191,   192,   195,   175,   130,   173,     6,     8,
      11,   134,   178,   104,    14,    17,    18,    19,    20,   130,
     178,     8,   108,   110,   135,   209,   120,    66,   108,   110,
     116,   118,   135,   110,   202,   209,     8,   108,    33,   108,
     110,   198,     8,   110,   120,   206,     8,   132,   133,   178,
     108,   108,   108,   108,   110,   128,   137,   189,   195,   110,
     127,   134,   137,    66,   108,   110,   124,   125,   134,   188,
     192,   134,   188,     8,   134,    33,    35,    43,    44,    45,
      46,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,   115,
     121,   131,   186,   187,   189,   195,   110,   195,   131,   189,
      11,   108,   110,   128,   187,   193,   195,   124,   137,   130,
     137,   131,   130,   131,   186,   131,   137,   130,   134,    33,
      44,   109,   131,   172,   194,   195,   132,   173,   173,   173,
     179,    82,   136,   168,   172,   172,   172,   172,   172,   172,
     168,   132,   134,    90,   110,   135,   209,   108,    33,   108,
     110,   135,   110,   120,   135,   110,   136,   133,   133,   133,
     133,   108,    18,    18,   112,   108,   134,   186,     8,   186,
       8,   186,   186,   186,   186,   186,   131,   131,   131,   131,
     131,   131,   131,   131,   131,   131,   131,   131,   131,   131,
     131,   131,   131,   131,   131,   131,   131,   186,     3,     4,
       5,     6,     9,    11,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,    67,   186,   131,   134,   137,     8,
     130,   137,   130,   108,   133,   137,   189,   137,   110,   128,
     191,   195,     8,     8,   108,   186,   108,   186,   207,   186,
     207,   130,   108,   108,   186,   108,   172,   172,   172,     7,
      10,    12,    29,    30,    32,    33,    36,    37,   105,   110,
     118,   124,   135,   181,   182,   183,    79,   108,   130,   108,
     108,   108,   108,   108,   189,   135,   112,   135,   135,   135,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   207,   186,   186,   186,   186,   186,
     207,   132,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   188,   190,
     108,   108,   186,   108,   132,   110,   113,   108,   108,     8,
       8,   130,   132,   133,     8,   132,   186,   132,   130,     8,
     133,   132,   172,   172,   172,   172,   172,   172,   172,   172,
     172,   131,   130,   130,   184,    29,   129,   180,   130,   133,
     108,   132,   132,   132,   132,   137,   135,     8,     8,     8,
     132,   133,   132,   133,   133,   132,   132,   132,   132,   132,
     132,   132,   132,   132,   132,   132,   133,   132,   132,   132,
     132,   132,     8,   132,   133,     8,     8,   130,     8,     8,
       8,   189,   186,     8,   186,     8,     8,   108,   194,   195,
     172,   172,   129,   180,   110,   113,    88,    89,   108,   199,
     108,   186,   186,   186,   186,   108,   186,     8,   135,   133,
     133,     8,     8,    30,    30,   135,     8,   132,   132,   132,
     132,   135,     8,   130,   118,   118,   186,   132,   132,     8,
       8,     8
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_uint8 yyr1[] =
{
       0,   139,   140,   140,   140,   140,   141,   141,   141,   141,
     141,   141,   141,   141,   141,   141,   142,   142,   142,   142,
     143,   143,   144,   145,   146,   146,   146,   146,   146,   147,
     148,   148,   149,   149,   149,   149,   149,   150,   150,   150,
     150,   150,   150,   151,   152,   152,   152,   152,   152,   152,
     152,   153,   153,   154,   155,   155,   156,   157,   158,   159,
     160,   161,   162,   163,   163,   163,   164,   165,   165,   165,
     166,   166,   167,   168,   168,   168,   169,   169,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   171,   171,   171,
     171,   172,   172,   172,   172,   172,   172,   172,   172,   172,
     172,   172,   172,   172,   172,   172,   173,   173,   173,   173,
     174,   174,   175,   175,   176,   176,   177,   177,   177,   177,
     177,   177,   177,   177,   177,   177,   177,   178,   178,   179,
     179,   179,   179,   179,   179,   180,   180,   181,   182,   182,
     183,   183,   183,   183,   183,   184,   184,   184,   184,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   187,   187,   187,   187,   188,   188,   188,
     188,   188,   188,   188,   189,   189,   189,   189,   190,   190,
     190,   190,   190,   191,   191,   191,   192,   192,   193,   193,
     193,   193,   193,   193,   194,   194,   194,   194,   194,   195,
     195,   195,   195,   196,   196,   197,   197,   197,   198,   198,
     198,   198,   198,   198,   199,   199,   200,   200,   200,   201,
     202,   202,   202,   202,   203,   203,   203,   204,   204,   204,
     204,   204,   205,   205,   206,   206,   206,   206,   207,   207,
     207,   208,   208,   208,   209,   209,   209,   209,   209,   209,
     209,   209,   209,   209,   209,   209,   209,   209,   209
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     2,     2,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     1,     1,     1,     2,
       5,     5,     5,     2,     6,     9,     9,     2,     3,     2,
       3,     2,     7,     7,     2,     2,     2,     7,     7,     2,
       2,     2,     2,     2,     3,     3,     4,     4,     4,     4,
       2,    10,     5,     4,     1,     2,     8,     4,     5,     5,
       5,     4,     6,     1,     2,     2,     2,     0,     1,     1,
       0,     1,     5,     3,     4,     1,     5,     5,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     1,
       2,     1,     1,     1,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     2,     2,     1,     3,     3,     3,
       2,     1,     2,     1,     1,     3,     3,     3,     3,     3,
       3,     3,     3,     1,     1,     1,     1,     0,     3,     0,
       5,     8,     8,     5,     2,     3,     3,     2,     1,     3,
       1,     4,     5,     3,     4,     0,     2,     4,     6,     4,
       5,     4,     7,     6,     3,     5,     5,     9,     4,     4,
       4,     3,     5,     5,     5,     3,     5,     5,     3,     5,
       2,     5,     5,     1,     1,     2,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     2,
       2,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     2,     4,     4,     4,
       4,     6,     6,     6,     4,     4,     4,     4,     4,     4,
       4,     4,     6,     4,     4,     4,     4,     4,     3,     6,
       1,     4,     4,     6,     4,     3,     1,     1,     1,     1,
       1,     4,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     2,     4,     1,     1,     1,     3,     3,     1,     2,
       4,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     3,     1,     2,     1,     2,
       1,     2,     3,     2,     3,     1,     1,     2,     2,     3,
       1,     1,     2,     2,     3,     1,     1,     1,     1,     2,
       2,     2,     3,     1,     1,     1,     2,     2,     0,     1,
       3,     0,     1,     3,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = SLEIGHEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == SLEIGHEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use SLEIGHerror or SLEIGHUNDEF. */
#define YYERRCODE SLEIGHUNDEF


/* Enable debugging if requested.  */
#if SLEIGHDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !SLEIGHDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !SLEIGHDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = SLEIGHEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == SLEIGHEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= SLEIGHEOF)
    {
      yychar = SLEIGHEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == SLEIGHerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = SLEIGHUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = SLEIGHEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 19: /* constructorlike: error '}'  */
                                       { slgh->resetConstructors(); }
    break;

  case 20: /* endiandef: DEFINE_KEY ENDIAN_KEY '=' BIG_KEY ';'  */
                                                 { slgh->setEndian(1); }
    break;

  case 21: /* endiandef: DEFINE_KEY ENDIAN_KEY '=' LITTLE_KEY ';'  */
                                             { slgh->setEndian(0); }
    break;

  case 22: /* aligndef: DEFINE_KEY ALIGN_KEY '=' INTEGER ';'  */
                                               { slgh->setAlignment(*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 23: /* tokendef: tokenprop ';'  */
                                       {}
    break;

  case 24: /* tokenprop: DEFINE_KEY TOKEN_KEY STRING '(' INTEGER ')'  */
                                                       { (yyval.tokensym) = slgh->defineToken((yyvsp[-3].str),(yyvsp[-1].i),0); }
    break;

  case 25: /* tokenprop: DEFINE_KEY TOKEN_KEY STRING '(' INTEGER ')' ENDIAN_KEY '=' LITTLE_KEY  */
                                                                          { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),-1); }
    break;

  case 26: /* tokenprop: DEFINE_KEY TOKEN_KEY STRING '(' INTEGER ')' ENDIAN_KEY '=' BIG_KEY  */
                                                                       { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),1); }
    break;

  case 27: /* tokenprop: tokenprop fielddef  */
                                       { (yyval.tokensym) = (yyvsp[-1].tokensym); slgh->addTokenField((yyvsp[-1].tokensym),(yyvsp[0].fieldqual)); }
    break;

  case 28: /* tokenprop: DEFINE_KEY TOKEN_KEY anysymbol  */
                                       { string errmsg=(yyvsp[0].anysym)->getName()+": redefined as a token"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 29: /* contextdef: contextprop ';'  */
                                       {}
    break;

  case 30: /* contextprop: DEFINE_KEY CONTEXT_KEY VARSYM  */
                                           { (yyval.varsym) = (yyvsp[0].varsym); }
    break;

  case 31: /* contextprop: contextprop contextfielddef  */
                                         { (yyval.varsym) = (yyvsp[-1].varsym); if (!slgh->addContextField( (yyvsp[-1].varsym), (yyvsp[0].fieldqual) ))
                                            { slgh->reportError("All context definitions must come before constructors"); YYERROR; } }
    break;

  case 32: /* fielddef: STRING '=' '(' INTEGER ',' INTEGER ')'  */
                                                 { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
    break;

  case 33: /* fielddef: anysymbol '=' '(' INTEGER ',' INTEGER ')'  */
                                              { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 34: /* fielddef: fielddef SIGNED_KEY  */
                                        { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
    break;

  case 35: /* fielddef: fielddef HEX_KEY  */
                                        { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
    break;

  case 36: /* fielddef: fielddef DEC_KEY  */
                                        { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
    break;

  case 37: /* contextfielddef: STRING '=' '(' INTEGER ',' INTEGER ')'  */
                                                        { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
    break;

  case 38: /* contextfielddef: anysymbol '=' '(' INTEGER ',' INTEGER ')'  */
                                              { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 39: /* contextfielddef: contextfielddef SIGNED_KEY  */
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
    break;

  case 40: /* contextfielddef: contextfielddef NOFLOW_KEY  */
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->flow = false; }
    break;

  case 41: /* contextfielddef: contextfielddef HEX_KEY  */
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
    break;

  case 42: /* contextfielddef: contextfielddef DEC_KEY  */
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
    break;

  case 43: /* spacedef: spaceprop ';'  */
                                        { slgh->newSpace((yyvsp[-1].spacequal)); }
    break;

  case 44: /* spaceprop: DEFINE_KEY SPACE_KEY STRING  */
                                        { (yyval.spacequal) = new SpaceQuality(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 45: /* spaceprop: DEFINE_KEY SPACE_KEY anysymbol  */
                                        { string errmsg = (yyvsp[0].anysym)->getName()+": redefined as space"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 46: /* spaceprop: spaceprop TYPE_KEY '=' RAM_KEY  */
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::ramtype; }
    break;

  case 47: /* spaceprop: spaceprop TYPE_KEY '=' REGISTER_KEY  */
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::registertype; }
    break;

  case 48: /* spaceprop: spaceprop SIZE_KEY '=' INTEGER  */
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->size = *(yyvsp[0].i); delete (yyvsp[0].i); }
    break;

  case 49: /* spaceprop: spaceprop WORDSIZE_KEY '=' INTEGER  */
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->wordsize = *(yyvsp[0].i); delete (yyvsp[0].i); }
    break;

  case 50: /* spaceprop: spaceprop DEFAULT_KEY  */
                                        { (yyval.spacequal) = (yyvsp[-1].spacequal); (yyval.spacequal)->isdefault = true; }
    break;

  case 51: /* varnodedef: DEFINE_KEY SPACESYM OFFSET_KEY '=' INTEGER SIZE_KEY '=' INTEGER stringlist ';'  */
                                                                                           {
               slgh->defineVarnodes((yyvsp[-8].spacesym),(yyvsp[-5].i),(yyvsp[-2].i),(yyvsp[-1].strlist)); }
    break;

  case 52: /* varnodedef: DEFINE_KEY SPACESYM OFFSET_KEY '=' BADINTEGER  */
                                                  { slgh->reportError("Parsed integer is too big (overflow)"); YYERROR; }
    break;

  case 56: /* bitrangesingle: STRING '=' VARSYM '[' INTEGER ',' INTEGER ']'  */
                                                              {
               slgh->defineBitrange((yyvsp[-7].str),(yyvsp[-5].varsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i); delete (yyvsp[-1].i); }
    break;

  case 57: /* pcodeopdef: DEFINE_KEY PCODEOP_KEY stringlist ';'  */
                                                  { slgh->addUserOp((yyvsp[-1].strlist)); }
    break;

  case 58: /* valueattach: ATTACH_KEY VALUES_KEY valuelist intblist ';'  */
                                                          { slgh->attachValues((yyvsp[-2].symlist),(yyvsp[-1].biglist)); }
    break;

  case 59: /* nameattach: ATTACH_KEY NAMES_KEY valuelist anystringlist ';'  */
                                                             { slgh->attachNames((yyvsp[-2].symlist),(yyvsp[-1].strlist)); }
    break;

  case 60: /* varattach: ATTACH_KEY VARIABLES_KEY valuelist varlist ';'  */
                                                          { slgh->attachVarnodes((yyvsp[-2].symlist),(yyvsp[-1].symlist)); }
    break;

  case 61: /* macrodef: macrostart '{' rtl '}'  */
                                        { slgh->buildMacro((yyvsp[-3].macrosym),(yyvsp[-1].sem)); }
    break;

  case 62: /* withblockstart: WITH_KEY id_or_nil ':' bitpat_or_nil contextblock '{'  */
                                                                       {  slgh->pushWith((yyvsp[-4].subtablesym),(yyvsp[-2].pateq),(yyvsp[-1].contop)); }
    break;

  case 66: /* withblock: withblockmid '}'  */
                             { slgh->popWith(); }
    break;

  case 67: /* id_or_nil: %empty  */
                        { (yyval.subtablesym) = (SubtableSymbol *)0; }
    break;

  case 68: /* id_or_nil: SUBTABLESYM  */
                        { (yyval.subtablesym) = (yyvsp[0].subtablesym); }
    break;

  case 69: /* id_or_nil: STRING  */
                        { (yyval.subtablesym) = slgh->newTable((yyvsp[0].str)); }
    break;

  case 70: /* bitpat_or_nil: %empty  */
                           { (yyval.pateq) = (PatternEquation *)0; }
    break;

  case 71: /* bitpat_or_nil: pequation  */
                           { (yyval.pateq) = (yyvsp[0].pateq); }
    break;

  case 72: /* macrostart: MACRO_KEY STRING '(' oplist ')'  */
                                            { (yyval.macrosym) = slgh->createMacro((yyvsp[-3].str),(yyvsp[-1].strlist)); }
    break;

  case 73: /* rtlbody: '{' rtl '}'  */
                     { (yyval.sectionstart) = slgh->standaloneSection((yyvsp[-1].sem)); }
    break;

  case 74: /* rtlbody: '{' rtlcontinue rtlmid '}'  */
                               { (yyval.sectionstart) = slgh->finalNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem)); }
    break;

  case 75: /* rtlbody: OP_UNIMPL  */
                     { (yyval.sectionstart) = (SectionVector *)0; }
    break;

  case 76: /* constructor: constructprint IS_KEY pequation contextblock rtlbody  */
                                                                  { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
    break;

  case 77: /* constructor: subtablestart IS_KEY pequation contextblock rtlbody  */
                                                                  { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
    break;

  case 78: /* constructprint: subtablestart STRING  */
                                        { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 79: /* constructprint: subtablestart charstring  */
                                        { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 80: /* constructprint: subtablestart SYMBOLSTRING  */
                                        { (yyval.construct) = (yyvsp[-1].construct); if (slgh->isInRoot((yyvsp[-1].construct))) { (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); } else slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
    break;

  case 81: /* constructprint: subtablestart '^'  */
                                                { (yyval.construct) = (yyvsp[-1].construct); if (!slgh->isInRoot((yyvsp[-1].construct))) { slgh->reportError("Unexpected '^' at start of print pieces");  YYERROR; } }
    break;

  case 82: /* constructprint: constructprint '^'  */
                                                { (yyval.construct) = (yyvsp[-1].construct); }
    break;

  case 83: /* constructprint: constructprint STRING  */
                                                { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 84: /* constructprint: constructprint charstring  */
                                        { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 85: /* constructprint: constructprint ' '  */
                                                { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(string(" ")); }
    break;

  case 86: /* constructprint: constructprint SYMBOLSTRING  */
                                        { (yyval.construct) = (yyvsp[-1].construct); slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
    break;

  case 87: /* subtablestart: SUBTABLESYM ':'  */
                                { (yyval.construct) = slgh->createConstructor((yyvsp[-1].subtablesym)); }
    break;

  case 88: /* subtablestart: STRING ':'  */
                                                { SubtableSymbol *sym=slgh->newTable((yyvsp[-1].str)); (yyval.construct) = slgh->createConstructor(sym); }
    break;

  case 89: /* subtablestart: ':'  */
                                                        { (yyval.construct) = slgh->createConstructor((SubtableSymbol *)0); }
    break;

  case 90: /* subtablestart: subtablestart ' '  */
                                        { (yyval.construct) = (yyvsp[-1].construct); }
    break;

  case 91: /* pexpression: INTB  */
                                        { (yyval.patexp) = new ConstantValue(*(yyvsp[0].big)); delete (yyvsp[0].big); }
    break;

  case 92: /* pexpression: familysymbol  */
                                        { if ((actionon==1)&&((yyvsp[0].famsym)->getType() != SleighSymbol::context_symbol))
                                             { string errmsg="Global symbol "+(yyvsp[0].famsym)->getName(); errmsg += " is not allowed in action expression"; slgh->reportError(errmsg); } (yyval.patexp) = (yyvsp[0].famsym)->getPatternValue(); }
    break;

  case 93: /* pexpression: specificsymbol  */
                                        { (yyval.patexp) = (yyvsp[0].specsym)->getPatternExpression(); }
    break;

  case 94: /* pexpression: '(' pexpression ')'  */
                                        { (yyval.patexp) = (yyvsp[-1].patexp); }
    break;

  case 95: /* pexpression: pexpression '+' pexpression  */
                                        { (yyval.patexp) = new PlusExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 96: /* pexpression: pexpression '-' pexpression  */
                                        { (yyval.patexp) = new SubExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 97: /* pexpression: pexpression '*' pexpression  */
                                        { (yyval.patexp) = new MultExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 98: /* pexpression: pexpression OP_LEFT pexpression  */
                                        { (yyval.patexp) = new LeftShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 99: /* pexpression: pexpression OP_RIGHT pexpression  */
                                        { (yyval.patexp) = new RightShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 100: /* pexpression: pexpression OP_AND pexpression  */
                                        { (yyval.patexp) = new AndExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 101: /* pexpression: pexpression OP_OR pexpression  */
                                        { (yyval.patexp) = new OrExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 102: /* pexpression: pexpression OP_XOR pexpression  */
                                        { (yyval.patexp) = new XorExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 103: /* pexpression: pexpression '/' pexpression  */
                                        { (yyval.patexp) = new DivExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 104: /* pexpression: '-' pexpression  */
                                        { (yyval.patexp) = new MinusExpression((yyvsp[0].patexp)); }
    break;

  case 105: /* pexpression: '~' pexpression  */
                                        { (yyval.patexp) = new NotExpression((yyvsp[0].patexp)); }
    break;

  case 107: /* pequation: pequation '&' pequation  */
                                        { (yyval.pateq) = new EquationAnd((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
    break;

  case 108: /* pequation: pequation '|' pequation  */
                                        { (yyval.pateq) = new EquationOr((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
    break;

  case 109: /* pequation: pequation ';' pequation  */
                                        { (yyval.pateq) = new EquationCat((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
    break;

  case 110: /* elleq: ELLIPSIS_KEY ellrt  */
                                        { (yyval.pateq) = new EquationLeftEllipsis((yyvsp[0].pateq)); }
    break;

  case 112: /* ellrt: atomic ELLIPSIS_KEY  */
                                        { (yyval.pateq) = new EquationRightEllipsis((yyvsp[-1].pateq)); }
    break;

  case 115: /* atomic: '(' pequation ')'  */
                                        { (yyval.pateq) = (yyvsp[-1].pateq); }
    break;

  case 116: /* constraint: familysymbol '=' pexpression  */
                                         { (yyval.pateq) = new EqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 117: /* constraint: familysymbol OP_NOTEQUAL pexpression  */
                                         { (yyval.pateq) = new NotEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 118: /* constraint: familysymbol '<' pexpression  */
                                        { (yyval.pateq) = new LessEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 119: /* constraint: familysymbol OP_LESSEQUAL pexpression  */
                                          { (yyval.pateq) = new LessEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 120: /* constraint: familysymbol '>' pexpression  */
                                        { (yyval.pateq) = new GreaterEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 121: /* constraint: familysymbol OP_GREATEQUAL pexpression  */
                                           { (yyval.pateq) = new GreaterEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 122: /* constraint: OPERANDSYM '=' pexpression  */
                                        { (yyval.pateq) = slgh->constrainOperand((yyvsp[-2].operandsym),(yyvsp[0].patexp)); 
                                          if ((yyval.pateq) == (PatternEquation *)0) 
                                            { string errmsg="Constraining currently undefined operand "+(yyvsp[-2].operandsym)->getName(); slgh->reportError(errmsg); } }
    break;

  case 123: /* constraint: OPERANDSYM  */
                                        { (yyval.pateq) = new OperandEquation((yyvsp[0].operandsym)->getIndex()); slgh->selfDefine((yyvsp[0].operandsym)); }
    break;

  case 124: /* constraint: SPECSYM  */
                                        { (yyval.pateq) = new UnconstrainedEquation((yyvsp[0].specsym)->getPatternExpression()); }
    break;

  case 125: /* constraint: familysymbol  */
                                        { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].famsym)); }
    break;

  case 126: /* constraint: SUBTABLESYM  */
                                        { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].subtablesym)); }
    break;

  case 127: /* contextblock: %empty  */
                                        { (yyval.contop) = (vector<ContextChange *> *)0; }
    break;

  case 128: /* contextblock: '[' contextlist ']'  */
                                        { (yyval.contop) = (yyvsp[-1].contop); }
    break;

  case 129: /* contextlist: %empty  */
                                        { (yyval.contop) = new vector<ContextChange *>; }
    break;

  case 130: /* contextlist: contextlist CONTEXTSYM '=' pexpression ';'  */
                                                { (yyval.contop) = (yyvsp[-4].contop); if (!slgh->contextMod((yyvsp[-4].contop),(yyvsp[-3].contextsym),(yyvsp[-1].patexp))) { string errmsg="Cannot use 'inst_next' or 'inst_next2' to set context variable: "+(yyvsp[-3].contextsym)->getName(); slgh->reportError(errmsg); YYERROR; } }
    break;

  case 131: /* contextlist: contextlist GLOBALSET_KEY '(' familysymbol ',' CONTEXTSYM ')' ';'  */
                                                                      { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].famsym),(yyvsp[-2].contextsym)); }
    break;

  case 132: /* contextlist: contextlist GLOBALSET_KEY '(' specificsymbol ',' CONTEXTSYM ')' ';'  */
                                                                        { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].specsym),(yyvsp[-2].contextsym)); }
    break;

  case 133: /* contextlist: contextlist OPERANDSYM '=' pexpression ';'  */
                                               { (yyval.contop) = (yyvsp[-4].contop); slgh->defineOperand((yyvsp[-3].operandsym),(yyvsp[-1].patexp)); }
    break;

  case 134: /* contextlist: contextlist STRING  */
                                        { string errmsg="Expecting context symbol, not "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 135: /* section_def: OP_LEFT STRING OP_RIGHT  */
                                        { (yyval.sectionsym) = slgh->newSectionSymbol( *(yyvsp[-1].str) ); delete (yyvsp[-1].str); }
    break;

  case 136: /* section_def: OP_LEFT SECTIONSYM OP_RIGHT  */
                                        { (yyval.sectionsym) = (yyvsp[-1].sectionsym); }
    break;

  case 137: /* rtlfirstsection: rtl section_def  */
                                        { (yyval.sectionstart) = slgh->firstNamedSection((yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
    break;

  case 138: /* rtlcontinue: rtlfirstsection  */
                             { (yyval.sectionstart) = (yyvsp[0].sectionstart); }
    break;

  case 139: /* rtlcontinue: rtlcontinue rtlmid section_def  */
                                        { (yyval.sectionstart) = slgh->nextNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
    break;

  case 140: /* rtl: rtlmid  */
            { (yyval.sem) = (yyvsp[0].sem); if ((yyval.sem)->getOpvec().empty() && ((yyval.sem)->getResult() == (HandleTpl *)0)) slgh->recordNop(); }
    break;

  case 141: /* rtl: rtlmid EXPORT_KEY exportvarnode ';'  */
                                        { (yyval.sem) = slgh->setResultVarnode((yyvsp[-3].sem),(yyvsp[-1].varnode)); }
    break;

  case 142: /* rtl: rtlmid EXPORT_KEY sizedstar lhsvarnode ';'  */
                                               { (yyval.sem) = slgh->setResultStarVarnode((yyvsp[-4].sem),(yyvsp[-2].starqual),(yyvsp[-1].varnode)); }
    break;

  case 143: /* rtl: rtlmid EXPORT_KEY STRING  */
                                        { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 144: /* rtl: rtlmid EXPORT_KEY sizedstar STRING  */
                                        { string errmsg="Unknown pointer varnode: "+*(yyvsp[0].str); delete (yyvsp[-1].starqual); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 145: /* rtlmid: %empty  */
                                        { (yyval.sem) = slgh->enterSection(); }
    break;

  case 146: /* rtlmid: rtlmid statement  */
                                        { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[0].stmt); slgh->reportError("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }
    break;

  case 147: /* rtlmid: rtlmid LOCAL_KEY STRING ';'  */
                                { (yyval.sem) = (yyvsp[-3].sem); slgh->pcode.newLocalDefinition((yyvsp[-1].str)); }
    break;

  case 148: /* rtlmid: rtlmid LOCAL_KEY STRING ':' INTEGER ';'  */
                                            { (yyval.sem) = (yyvsp[-5].sem); slgh->pcode.newLocalDefinition((yyvsp[-3].str),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 149: /* statement: lhsvarnode '=' expr ';'  */
                                        { (yyvsp[-1].tree)->setOutput((yyvsp[-3].varnode)); (yyval.stmt) = ExprTree::toVector((yyvsp[-1].tree)); }
    break;

  case 150: /* statement: LOCAL_KEY STRING '=' expr ';'  */
                                        { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-3].str)); }
    break;

  case 151: /* statement: STRING '=' expr ';'  */
                                        { (yyval.stmt) = slgh->pcode.newOutput(false,(yyvsp[-1].tree),(yyvsp[-3].str)); }
    break;

  case 152: /* statement: LOCAL_KEY STRING ':' INTEGER '=' expr ';'  */
                                                { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
    break;

  case 153: /* statement: STRING ':' INTEGER '=' expr ';'  */
                                        { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
    break;

  case 154: /* statement: LOCAL_KEY specificsymbol '='  */
                                 { (yyval.stmt) = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+(yyvsp[-1].specsym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 155: /* statement: sizedstar expr '=' expr ';'  */
                                        { (yyval.stmt) = slgh->pcode.createStore((yyvsp[-4].starqual),(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 156: /* statement: USEROPSYM '(' paramlist ')' ';'  */
                                        { (yyval.stmt) = slgh->pcode.createUserOpNoOut((yyvsp[-4].useropsym),(yyvsp[-2].param)); }
    break;

  case 157: /* statement: lhsvarnode '[' INTEGER ',' INTEGER ']' '=' expr ';'  */
                                                        { (yyval.stmt) = slgh->pcode.assignBitRange((yyvsp[-8].varnode),(uint4)*(yyvsp[-6].i),(uint4)*(yyvsp[-4].i),(yyvsp[-1].tree)); delete (yyvsp[-6].i), delete (yyvsp[-4].i); }
    break;

  case 158: /* statement: BITSYM '=' expr ';'  */
                                        { (yyval.stmt)=slgh->pcode.assignBitRange((yyvsp[-3].bitsym)->getParentSymbol()->getVarnode(),(yyvsp[-3].bitsym)->getBitOffset(),(yyvsp[-3].bitsym)->numBits(),(yyvsp[-1].tree)); }
    break;

  case 159: /* statement: varnode ':' INTEGER '='  */
                                        { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); slgh->reportError("Illegal truncation on left-hand side of assignment"); YYERROR; }
    break;

  case 160: /* statement: varnode '(' INTEGER ')'  */
                                        { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); slgh->reportError("Illegal subpiece on left-hand side of assignment"); YYERROR; }
    break;

  case 161: /* statement: BUILD_KEY OPERANDSYM ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpConst(BUILD,(yyvsp[-1].operandsym)->getIndex()); }
    break;

  case 162: /* statement: CROSSBUILD_KEY varnode ',' SECTIONSYM ';'  */
                                              { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),(yyvsp[-1].sectionsym)); }
    break;

  case 163: /* statement: CROSSBUILD_KEY varnode ',' STRING ';'  */
                                            { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),slgh->newSectionSymbol(*(yyvsp[-1].str))); delete (yyvsp[-1].str); }
    break;

  case 164: /* statement: DELAYSLOT_KEY '(' INTEGER ')' ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpConst(DELAY_SLOT,*(yyvsp[-2].i)); delete (yyvsp[-2].i); }
    break;

  case 165: /* statement: GOTO_KEY jumpdest ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCH,new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 166: /* statement: IF_KEY expr GOTO_KEY jumpdest ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CBRANCH,new ExprTree((yyvsp[-1].varnode)),(yyvsp[-3].tree)); }
    break;

  case 167: /* statement: GOTO_KEY '[' expr ']' ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCHIND,(yyvsp[-2].tree)); }
    break;

  case 168: /* statement: CALL_KEY jumpdest ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALL,new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 169: /* statement: CALL_KEY '[' expr ']' ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALLIND,(yyvsp[-2].tree)); }
    break;

  case 170: /* statement: RETURN_KEY ';'  */
                                        { slgh->reportError("Must specify an indirect parameter for return"); YYERROR; }
    break;

  case 171: /* statement: RETURN_KEY '[' expr ']' ';'  */
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_RETURN,(yyvsp[-2].tree)); }
    break;

  case 172: /* statement: MACROSYM '(' paramlist ')' ';'  */
                                        { (yyval.stmt) = slgh->createMacroUse((yyvsp[-4].macrosym),(yyvsp[-2].param)); }
    break;

  case 173: /* statement: label  */
                                        { (yyval.stmt) = slgh->pcode.placeLabel( (yyvsp[0].labelsym) ); }
    break;

  case 174: /* expr: varnode  */
              { (yyval.tree) = new ExprTree((yyvsp[0].varnode)); }
    break;

  case 175: /* expr: sizedstar expr  */
                                { (yyval.tree) = slgh->pcode.createLoad((yyvsp[-1].starqual),(yyvsp[0].tree)); }
    break;

  case 176: /* expr: '(' expr ')'  */
                                { (yyval.tree) = (yyvsp[-1].tree); }
    break;

  case 177: /* expr: expr '+' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 178: /* expr: expr '-' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 179: /* expr: expr OP_EQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 180: /* expr: expr OP_NOTEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 181: /* expr: expr '<' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 182: /* expr: expr OP_GREATEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 183: /* expr: expr OP_LESSEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 184: /* expr: expr '>' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 185: /* expr: expr OP_SLESS expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 186: /* expr: expr OP_SGREATEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 187: /* expr: expr OP_SLESSEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 188: /* expr: expr OP_SGREAT expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 189: /* expr: '-' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_2COMP,(yyvsp[0].tree)); }
    break;

  case 190: /* expr: '~' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NEGATE,(yyvsp[0].tree)); }
    break;

  case 191: /* expr: expr '^' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 192: /* expr: expr '&' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 193: /* expr: expr '|' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 194: /* expr: expr OP_LEFT expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LEFT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 195: /* expr: expr OP_RIGHT expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_RIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 196: /* expr: expr OP_SRIGHT expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SRIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 197: /* expr: expr '*' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 198: /* expr: expr '/' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 199: /* expr: expr OP_SDIV expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SDIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 200: /* expr: expr '%' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_REM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 201: /* expr: expr OP_SREM expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SREM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 202: /* expr: '!' expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_NEGATE,(yyvsp[0].tree)); }
    break;

  case 203: /* expr: expr OP_BOOL_XOR expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 204: /* expr: expr OP_BOOL_AND expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 205: /* expr: expr OP_BOOL_OR expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 206: /* expr: expr OP_FEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 207: /* expr: expr OP_FNOTEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 208: /* expr: expr OP_FLESS expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 209: /* expr: expr OP_FGREAT expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 210: /* expr: expr OP_FLESSEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 211: /* expr: expr OP_FGREATEQUAL expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 212: /* expr: expr OP_FADD expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 213: /* expr: expr OP_FSUB expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 214: /* expr: expr OP_FMULT expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 215: /* expr: expr OP_FDIV expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 216: /* expr: OP_FSUB expr  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NEG,(yyvsp[0].tree)); }
    break;

  case 217: /* expr: OP_ABS '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ABS,(yyvsp[-1].tree)); }
    break;

  case 218: /* expr: OP_SQRT '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SQRT,(yyvsp[-1].tree)); }
    break;

  case 219: /* expr: OP_SEXT '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SEXT,(yyvsp[-1].tree)); }
    break;

  case 220: /* expr: OP_ZEXT '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ZEXT,(yyvsp[-1].tree)); }
    break;

  case 221: /* expr: OP_CARRY '(' expr ',' expr ')'  */
                                   { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_CARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 222: /* expr: OP_SCARRY '(' expr ',' expr ')'  */
                                    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SCARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 223: /* expr: OP_SBORROW '(' expr ',' expr ')'  */
                                     { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SBORROW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 224: /* expr: OP_FLOAT2FLOAT '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOAT2FLOAT,(yyvsp[-1].tree)); }
    break;

  case 225: /* expr: OP_INT2FLOAT '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_INT2FLOAT,(yyvsp[-1].tree)); }
    break;

  case 226: /* expr: OP_NAN '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NAN,(yyvsp[-1].tree)); }
    break;

  case 227: /* expr: OP_TRUNC '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_TRUNC,(yyvsp[-1].tree)); }
    break;

  case 228: /* expr: OP_CEIL '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_CEIL,(yyvsp[-1].tree)); }
    break;

  case 229: /* expr: OP_FLOOR '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOOR,(yyvsp[-1].tree)); }
    break;

  case 230: /* expr: OP_ROUND '(' expr ')'  */
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ROUND,(yyvsp[-1].tree)); }
    break;

  case 231: /* expr: OP_NEW '(' expr ')'  */
                            { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-1].tree)); }
    break;

  case 232: /* expr: OP_NEW '(' expr ',' expr ')'  */
                                 { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 233: /* expr: OP_POPCOUNT '(' expr ')'  */
                             { (yyval.tree) = slgh->pcode.createOp(CPUI_POPCOUNT,(yyvsp[-1].tree)); }
    break;

  case 234: /* expr: OP_LZCOUNT '(' expr ')'  */
                            { (yyval.tree) = slgh->pcode.createOp(CPUI_LZCOUNT,(yyvsp[-1].tree)); }
    break;

  case 235: /* expr: OP_BITREV '(' expr ')'  */
                           { (yyval.tree) = slgh->pcode.createOp(CPUI_BITREV,(yyvsp[-1].tree)); }
    break;

  case 236: /* expr: OP_TZCOUNT '(' expr ')'  */
                            { (yyval.tree) = slgh->pcode.createOp(CPUI_TZCOUNT,(yyvsp[-1].tree)); }
    break;

  case 237: /* expr: specificsymbol '(' integervarnode ')'  */
                                          { (yyval.tree) = slgh->pcode.createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 238: /* expr: specificsymbol ':' INTEGER  */
                                { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }
    break;

  case 239: /* expr: specificsymbol '[' INTEGER ',' INTEGER ']'  */
                                               { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }
    break;

  case 240: /* expr: BITSYM  */
                                { (yyval.tree)=slgh->pcode.createBitRange((yyvsp[0].bitsym)->getParentSymbol(),(yyvsp[0].bitsym)->getBitOffset(),(yyvsp[0].bitsym)->numBits()); }
    break;

  case 241: /* expr: USEROPSYM '(' paramlist ')'  */
                                { (yyval.tree) = slgh->pcode.createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }
    break;

  case 242: /* expr: OP_CPOOLREF '(' paramlist ')'  */
                                   { if ((*(yyvsp[-1].param)).size() < 2) { string errmsg = "Must at least two inputs to cpool"; slgh->reportError(errmsg); YYERROR; } (yyval.tree) = slgh->pcode.createVariadic(CPUI_CPOOLREF,(yyvsp[-1].param)); }
    break;

  case 243: /* sizedstar: '*' '[' SPACESYM ']' ':' INTEGER  */
                                            { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }
    break;

  case 244: /* sizedstar: '*' '[' SPACESYM ']'  */
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }
    break;

  case 245: /* sizedstar: '*' ':' INTEGER  */
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
    break;

  case 246: /* sizedstar: '*'  */
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
    break;

  case 247: /* jumpdest: JUMPSYM  */
                                { VarnodeTpl *sym = (yyvsp[0].specsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
    break;

  case 248: /* jumpdest: INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }
    break;

  case 249: /* jumpdest: BADINTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); slgh->reportError("Parsed integer is too big (overflow)"); }
    break;

  case 250: /* jumpdest: OPERANDSYM  */
                                { (yyval.varnode) = (yyvsp[0].operandsym)->getVarnode(); (yyvsp[0].operandsym)->setCodeAddress(); }
    break;

  case 251: /* jumpdest: INTEGER '[' SPACESYM ']'  */
                                { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }
    break;

  case 252: /* jumpdest: label  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }
    break;

  case 253: /* jumpdest: STRING  */
                                { string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 254: /* varnode: specificsymbol  */
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 255: /* varnode: integervarnode  */
                                { (yyval.varnode) = (yyvsp[0].varnode); }
    break;

  case 256: /* varnode: STRING  */
                                { string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 257: /* varnode: SUBTABLESYM  */
                                { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 258: /* integervarnode: INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }
    break;

  case 259: /* integervarnode: BADINTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); slgh->reportError("Parsed integer is too big (overflow)"); }
    break;

  case 260: /* integervarnode: INTEGER ':' INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
    break;

  case 261: /* integervarnode: '&' varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
    break;

  case 262: /* integervarnode: '&' ':' INTEGER varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 263: /* lhsvarnode: specificsymbol  */
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 264: /* lhsvarnode: STRING  */
                                { string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 265: /* lhsvarnode: SUBTABLESYM  */
                                { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 266: /* label: '<' LABELSYM '>'  */
                                { (yyval.labelsym) = (yyvsp[-1].labelsym); }
    break;

  case 267: /* label: '<' STRING '>'  */
                                { (yyval.labelsym) = slgh->pcode.defineLabel( (yyvsp[-1].str) ); }
    break;

  case 268: /* exportvarnode: specificsymbol  */
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 269: /* exportvarnode: '&' varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
    break;

  case 270: /* exportvarnode: '&' ':' INTEGER varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 271: /* exportvarnode: INTEGER ':' INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
    break;

  case 272: /* exportvarnode: STRING  */
                                { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 273: /* exportvarnode: SUBTABLESYM  */
                                { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 274: /* familysymbol: VALUESYM  */
                                { (yyval.famsym) = (yyvsp[0].valuesym); }
    break;

  case 275: /* familysymbol: VALUEMAPSYM  */
                                { (yyval.famsym) = (yyvsp[0].valuemapsym); }
    break;

  case 276: /* familysymbol: CONTEXTSYM  */
                                { (yyval.famsym) = (yyvsp[0].contextsym); }
    break;

  case 277: /* familysymbol: NAMESYM  */
                                { (yyval.famsym) = (yyvsp[0].namesym); }
    break;

  case 278: /* familysymbol: VARLISTSYM  */
                                { (yyval.famsym) = (yyvsp[0].varlistsym); }
    break;

  case 279: /* specificsymbol: VARSYM  */
                                { (yyval.specsym) = (yyvsp[0].varsym); }
    break;

  case 280: /* specificsymbol: SPECSYM  */
                                { (yyval.specsym) = (yyvsp[0].specsym); }
    break;

  case 281: /* specificsymbol: OPERANDSYM  */
                                { (yyval.specsym) = (yyvsp[0].operandsym); }
    break;

  case 282: /* specificsymbol: JUMPSYM  */
                                { (yyval.specsym) = (yyvsp[0].specsym); }
    break;

  case 283: /* charstring: CHAR  */
                                { (yyval.str) = new string; (*(yyval.str)) += (yyvsp[0].ch); }
    break;

  case 284: /* charstring: charstring CHAR  */
                                { (yyval.str) = (yyvsp[-1].str); (*(yyval.str)) += (yyvsp[0].ch); }
    break;

  case 285: /* intblist: '[' intbpart ']'  */
                                { (yyval.biglist) = (yyvsp[-1].biglist); }
    break;

  case 286: /* intblist: INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 287: /* intblist: '-' INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 288: /* intbpart: INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 289: /* intbpart: '-' INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 290: /* intbpart: STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
    break;

  case 291: /* intbpart: intbpart INTEGER  */
                                { (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 292: /* intbpart: intbpart '-' INTEGER  */
                                { (yyval.biglist) = (yyvsp[-2].biglist); (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 293: /* intbpart: intbpart STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
    break;

  case 294: /* stringlist: '[' stringpart ']'  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); }
    break;

  case 295: /* stringlist: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 296: /* stringpart: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
    break;

  case 297: /* stringpart: stringpart STRING  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 298: /* stringpart: stringpart anysymbol  */
                                { string errmsg = (yyvsp[0].anysym)->getName()+": redefined"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 299: /* anystringlist: '[' anystringpart ']'  */
                                     { (yyval.strlist) = (yyvsp[-1].strlist); }
    break;

  case 300: /* anystringpart: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
    break;

  case 301: /* anystringpart: anysymbol  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( (yyvsp[0].anysym)->getName() ); }
    break;

  case 302: /* anystringpart: anystringpart STRING  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 303: /* anystringpart: anystringpart anysymbol  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back((yyvsp[0].anysym)->getName()); }
    break;

  case 304: /* valuelist: '[' valuepart ']'  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); }
    break;

  case 305: /* valuelist: VALUESYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
    break;

  case 306: /* valuelist: CONTEXTSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 307: /* valuepart: VALUESYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back( (yyvsp[0].valuesym) ); }
    break;

  case 308: /* valuepart: CONTEXTSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 309: /* valuepart: valuepart VALUESYM  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
    break;

  case 310: /* valuepart: valuepart CONTEXTSYM  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 311: /* valuepart: valuepart STRING  */
                                { string errmsg = *(yyvsp[0].str)+": is not a value pattern"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 312: /* varlist: '[' varpart ']'  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); }
    break;

  case 313: /* varlist: VARSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 314: /* varpart: VARSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 315: /* varpart: STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
				  (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
    break;

  case 316: /* varpart: varpart VARSYM  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 317: /* varpart: varpart STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
    break;

  case 318: /* paramlist: %empty  */
                                { (yyval.param) = new vector<ExprTree *>; }
    break;

  case 319: /* paramlist: expr  */
                                { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }
    break;

  case 320: /* paramlist: paramlist ',' expr  */
                                { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }
    break;

  case 321: /* oplist: %empty  */
                                { (yyval.strlist) = new vector<string>; }
    break;

  case 322: /* oplist: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 323: /* oplist: oplist ',' STRING  */
                                { (yyval.strlist) = (yyvsp[-2].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 324: /* anysymbol: SPACESYM  */
                                { (yyval.anysym) = (yyvsp[0].spacesym); }
    break;

  case 325: /* anysymbol: SECTIONSYM  */
                                { (yyval.anysym) = (yyvsp[0].sectionsym); }
    break;

  case 326: /* anysymbol: TOKENSYM  */
                                { (yyval.anysym) = (yyvsp[0].tokensym); }
    break;

  case 327: /* anysymbol: USEROPSYM  */
                                { (yyval.anysym) = (yyvsp[0].useropsym); }
    break;

  case 328: /* anysymbol: MACROSYM  */
                                { (yyval.anysym) = (yyvsp[0].macrosym); }
    break;

  case 329: /* anysymbol: SUBTABLESYM  */
                                { (yyval.anysym) = (yyvsp[0].subtablesym); }
    break;

  case 330: /* anysymbol: VALUESYM  */
                                { (yyval.anysym) = (yyvsp[0].valuesym); }
    break;

  case 331: /* anysymbol: VALUEMAPSYM  */
                                { (yyval.anysym) = (yyvsp[0].valuemapsym); }
    break;

  case 332: /* anysymbol: CONTEXTSYM  */
                                { (yyval.anysym) = (yyvsp[0].contextsym); }
    break;

  case 333: /* anysymbol: NAMESYM  */
                                { (yyval.anysym) = (yyvsp[0].namesym); }
    break;

  case 334: /* anysymbol: VARSYM  */
                                { (yyval.anysym) = (yyvsp[0].varsym); }
    break;

  case 335: /* anysymbol: VARLISTSYM  */
                                { (yyval.anysym) = (yyvsp[0].varlistsym); }
    break;

  case 336: /* anysymbol: OPERANDSYM  */
                                { (yyval.anysym) = (yyvsp[0].operandsym); }
    break;

  case 337: /* anysymbol: JUMPSYM  */
                                { (yyval.anysym) = (yyvsp[0].specsym); }
    break;

  case 338: /* anysymbol: BITSYM  */
                                { (yyval.anysym) = (yyvsp[0].bitsym); }
    break;



      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == SLEIGHEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= SLEIGHEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == SLEIGHEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = SLEIGHEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != SLEIGHEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}



int sleigherror(const char *s)

{
  slgh->reportError(s);
  return 0;
}

} // End namespace ghidra

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
/* A Bison parser, made by GNU Bison 3.7.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
#define YYBISON 30704

/* Bison version string.  */
#define YYBISON_VERSION "3.7.4"

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
  YYSYMBOL_BADINTEGER = 64,                /* BADINTEGER  */
  YYSYMBOL_GOTO_KEY = 65,                  /* GOTO_KEY  */
  YYSYMBOL_CALL_KEY = 66,                  /* CALL_KEY  */
  YYSYMBOL_RETURN_KEY = 67,                /* RETURN_KEY  */
  YYSYMBOL_IF_KEY = 68,                    /* IF_KEY  */
  YYSYMBOL_DEFINE_KEY = 69,                /* DEFINE_KEY  */
  YYSYMBOL_ATTACH_KEY = 70,                /* ATTACH_KEY  */
  YYSYMBOL_MACRO_KEY = 71,                 /* MACRO_KEY  */
  YYSYMBOL_SPACE_KEY = 72,                 /* SPACE_KEY  */
  YYSYMBOL_TYPE_KEY = 73,                  /* TYPE_KEY  */
  YYSYMBOL_RAM_KEY = 74,                   /* RAM_KEY  */
  YYSYMBOL_DEFAULT_KEY = 75,               /* DEFAULT_KEY  */
  YYSYMBOL_REGISTER_KEY = 76,              /* REGISTER_KEY  */
  YYSYMBOL_ENDIAN_KEY = 77,                /* ENDIAN_KEY  */
  YYSYMBOL_WITH_KEY = 78,                  /* WITH_KEY  */
  YYSYMBOL_ALIGN_KEY = 79,                 /* ALIGN_KEY  */
  YYSYMBOL_OP_UNIMPL = 80,                 /* OP_UNIMPL  */
  YYSYMBOL_TOKEN_KEY = 81,                 /* TOKEN_KEY  */
  YYSYMBOL_SIGNED_KEY = 82,                /* SIGNED_KEY  */
  YYSYMBOL_NOFLOW_KEY = 83,                /* NOFLOW_KEY  */
  YYSYMBOL_HEX_KEY = 84,                   /* HEX_KEY  */
  YYSYMBOL_DEC_KEY = 85,                   /* DEC_KEY  */
  YYSYMBOL_BIG_KEY = 86,                   /* BIG_KEY  */
  YYSYMBOL_LITTLE_KEY = 87,                /* LITTLE_KEY  */
  YYSYMBOL_SIZE_KEY = 88,                  /* SIZE_KEY  */
  YYSYMBOL_WORDSIZE_KEY = 89,              /* WORDSIZE_KEY  */
  YYSYMBOL_OFFSET_KEY = 90,                /* OFFSET_KEY  */
  YYSYMBOL_NAMES_KEY = 91,                 /* NAMES_KEY  */
  YYSYMBOL_VALUES_KEY = 92,                /* VALUES_KEY  */
  YYSYMBOL_VARIABLES_KEY = 93,             /* VARIABLES_KEY  */
  YYSYMBOL_PCODEOP_KEY = 94,               /* PCODEOP_KEY  */
  YYSYMBOL_IS_KEY = 95,                    /* IS_KEY  */
  YYSYMBOL_LOCAL_KEY = 96,                 /* LOCAL_KEY  */
  YYSYMBOL_DELAYSLOT_KEY = 97,             /* DELAYSLOT_KEY  */
  YYSYMBOL_CROSSBUILD_KEY = 98,            /* CROSSBUILD_KEY  */
  YYSYMBOL_EXPORT_KEY = 99,                /* EXPORT_KEY  */
  YYSYMBOL_BUILD_KEY = 100,                /* BUILD_KEY  */
  YYSYMBOL_CONTEXT_KEY = 101,              /* CONTEXT_KEY  */
  YYSYMBOL_ELLIPSIS_KEY = 102,             /* ELLIPSIS_KEY  */
  YYSYMBOL_GLOBALSET_KEY = 103,            /* GLOBALSET_KEY  */
  YYSYMBOL_BITRANGE_KEY = 104,             /* BITRANGE_KEY  */
  YYSYMBOL_CHAR = 105,                     /* CHAR  */
  YYSYMBOL_INTEGER = 106,                  /* INTEGER  */
  YYSYMBOL_INTB = 107,                     /* INTB  */
  YYSYMBOL_STRING = 108,                   /* STRING  */
  YYSYMBOL_SYMBOLSTRING = 109,             /* SYMBOLSTRING  */
  YYSYMBOL_SPACESYM = 110,                 /* SPACESYM  */
  YYSYMBOL_SECTIONSYM = 111,               /* SECTIONSYM  */
  YYSYMBOL_TOKENSYM = 112,                 /* TOKENSYM  */
  YYSYMBOL_USEROPSYM = 113,                /* USEROPSYM  */
  YYSYMBOL_VALUESYM = 114,                 /* VALUESYM  */
  YYSYMBOL_VALUEMAPSYM = 115,              /* VALUEMAPSYM  */
  YYSYMBOL_CONTEXTSYM = 116,               /* CONTEXTSYM  */
  YYSYMBOL_NAMESYM = 117,                  /* NAMESYM  */
  YYSYMBOL_VARSYM = 118,                   /* VARSYM  */
  YYSYMBOL_BITSYM = 119,                   /* BITSYM  */
  YYSYMBOL_SPECSYM = 120,                  /* SPECSYM  */
  YYSYMBOL_VARLISTSYM = 121,               /* VARLISTSYM  */
  YYSYMBOL_OPERANDSYM = 122,               /* OPERANDSYM  */
  YYSYMBOL_JUMPSYM = 123,                  /* JUMPSYM  */
  YYSYMBOL_MACROSYM = 124,                 /* MACROSYM  */
  YYSYMBOL_LABELSYM = 125,                 /* LABELSYM  */
  YYSYMBOL_SUBTABLESYM = 126,              /* SUBTABLESYM  */
  YYSYMBOL_127_ = 127,                     /* '}'  */
  YYSYMBOL_128_ = 128,                     /* '='  */
  YYSYMBOL_129_ = 129,                     /* '('  */
  YYSYMBOL_130_ = 130,                     /* ')'  */
  YYSYMBOL_131_ = 131,                     /* ','  */
  YYSYMBOL_132_ = 132,                     /* '['  */
  YYSYMBOL_133_ = 133,                     /* ']'  */
  YYSYMBOL_134_ = 134,                     /* '{'  */
  YYSYMBOL_135_ = 135,                     /* ':'  */
  YYSYMBOL_136_ = 136,                     /* ' '  */
  YYSYMBOL_YYACCEPT = 137,                 /* $accept  */
  YYSYMBOL_spec = 138,                     /* spec  */
  YYSYMBOL_definition = 139,               /* definition  */
  YYSYMBOL_constructorlike = 140,          /* constructorlike  */
  YYSYMBOL_endiandef = 141,                /* endiandef  */
  YYSYMBOL_aligndef = 142,                 /* aligndef  */
  YYSYMBOL_tokendef = 143,                 /* tokendef  */
  YYSYMBOL_tokenprop = 144,                /* tokenprop  */
  YYSYMBOL_contextdef = 145,               /* contextdef  */
  YYSYMBOL_contextprop = 146,              /* contextprop  */
  YYSYMBOL_fielddef = 147,                 /* fielddef  */
  YYSYMBOL_contextfielddef = 148,          /* contextfielddef  */
  YYSYMBOL_spacedef = 149,                 /* spacedef  */
  YYSYMBOL_spaceprop = 150,                /* spaceprop  */
  YYSYMBOL_varnodedef = 151,               /* varnodedef  */
  YYSYMBOL_bitrangedef = 152,              /* bitrangedef  */
  YYSYMBOL_bitrangelist = 153,             /* bitrangelist  */
  YYSYMBOL_bitrangesingle = 154,           /* bitrangesingle  */
  YYSYMBOL_pcodeopdef = 155,               /* pcodeopdef  */
  YYSYMBOL_valueattach = 156,              /* valueattach  */
  YYSYMBOL_nameattach = 157,               /* nameattach  */
  YYSYMBOL_varattach = 158,                /* varattach  */
  YYSYMBOL_macrodef = 159,                 /* macrodef  */
  YYSYMBOL_withblockstart = 160,           /* withblockstart  */
  YYSYMBOL_withblockmid = 161,             /* withblockmid  */
  YYSYMBOL_withblock = 162,                /* withblock  */
  YYSYMBOL_id_or_nil = 163,                /* id_or_nil  */
  YYSYMBOL_bitpat_or_nil = 164,            /* bitpat_or_nil  */
  YYSYMBOL_macrostart = 165,               /* macrostart  */
  YYSYMBOL_rtlbody = 166,                  /* rtlbody  */
  YYSYMBOL_constructor = 167,              /* constructor  */
  YYSYMBOL_constructprint = 168,           /* constructprint  */
  YYSYMBOL_subtablestart = 169,            /* subtablestart  */
  YYSYMBOL_pexpression = 170,              /* pexpression  */
  YYSYMBOL_pequation = 171,                /* pequation  */
  YYSYMBOL_elleq = 172,                    /* elleq  */
  YYSYMBOL_ellrt = 173,                    /* ellrt  */
  YYSYMBOL_atomic = 174,                   /* atomic  */
  YYSYMBOL_constraint = 175,               /* constraint  */
  YYSYMBOL_contextblock = 176,             /* contextblock  */
  YYSYMBOL_contextlist = 177,              /* contextlist  */
  YYSYMBOL_section_def = 178,              /* section_def  */
  YYSYMBOL_rtlfirstsection = 179,          /* rtlfirstsection  */
  YYSYMBOL_rtlcontinue = 180,              /* rtlcontinue  */
  YYSYMBOL_rtl = 181,                      /* rtl  */
  YYSYMBOL_rtlmid = 182,                   /* rtlmid  */
  YYSYMBOL_statement = 183,                /* statement  */
  YYSYMBOL_expr = 184,                     /* expr  */
  YYSYMBOL_sizedstar = 185,                /* sizedstar  */
  YYSYMBOL_jumpdest = 186,                 /* jumpdest  */
  YYSYMBOL_varnode = 187,                  /* varnode  */
  YYSYMBOL_integervarnode = 188,           /* integervarnode  */
  YYSYMBOL_lhsvarnode = 189,               /* lhsvarnode  */
  YYSYMBOL_label = 190,                    /* label  */
  YYSYMBOL_exportvarnode = 191,            /* exportvarnode  */
  YYSYMBOL_familysymbol = 192,             /* familysymbol  */
  YYSYMBOL_specificsymbol = 193,           /* specificsymbol  */
  YYSYMBOL_charstring = 194,               /* charstring  */
  YYSYMBOL_intblist = 195,                 /* intblist  */
  YYSYMBOL_intbpart = 196,                 /* intbpart  */
  YYSYMBOL_stringlist = 197,               /* stringlist  */
  YYSYMBOL_stringpart = 198,               /* stringpart  */
  YYSYMBOL_anystringlist = 199,            /* anystringlist  */
  YYSYMBOL_anystringpart = 200,            /* anystringpart  */
  YYSYMBOL_valuelist = 201,                /* valuelist  */
  YYSYMBOL_valuepart = 202,                /* valuepart  */
  YYSYMBOL_varlist = 203,                  /* varlist  */
  YYSYMBOL_varpart = 204,                  /* varpart  */
  YYSYMBOL_paramlist = 205,                /* paramlist  */
  YYSYMBOL_oplist = 206,                   /* oplist  */
  YYSYMBOL_anysymbol = 207                 /* anysymbol  */
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
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
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
#define YYLAST   2629

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  137
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  71
/* YYNRULES -- Number of rules.  */
#define YYNRULES  336
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  714

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   368


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
       2,     2,   136,    43,     2,     2,     2,    38,    11,     2,
     129,   130,    36,    32,   131,    33,     2,    37,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   135,     8,
      17,   128,    18,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   132,     2,   133,     9,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   134,     6,   127,    44,     2,     2,     2,
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
     118,   119,   120,   121,   122,   123,   124,   125,   126
};

#if SLEIGHDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   163,   163,   164,   165,   166,   168,   169,   170,   171,
     172,   173,   174,   175,   176,   177,   179,   180,   181,   182,
     184,   185,   187,   189,   191,   192,   193,   194,   195,   197,
     199,   200,   203,   204,   205,   206,   207,   209,   210,   211,
     212,   213,   214,   216,   218,   219,   220,   221,   222,   223,
     224,   226,   228,   230,   232,   233,   235,   238,   240,   242,
     244,   246,   249,   251,   252,   253,   255,   257,   258,   259,
     262,   263,   266,   268,   269,   270,   272,   273,   275,   276,
     277,   278,   279,   280,   281,   282,   283,   285,   286,   287,
     288,   290,   292,   295,   296,   297,   298,   299,   300,   301,
     302,   303,   304,   305,   306,   307,   309,   310,   311,   312,
     314,   315,   317,   318,   320,   321,   323,   324,   325,   326,
     327,   328,   329,   332,   333,   334,   335,   337,   338,   340,
     341,   342,   343,   344,   345,   347,   348,   350,   352,   353,
     355,   356,   357,   358,   359,   361,   362,   363,   364,   366,
     367,   368,   369,   370,   371,   372,   373,   374,   375,   376,
     377,   378,   379,   380,   381,   382,   383,   384,   385,   386,
     387,   388,   389,   390,   392,   393,   394,   395,   396,   397,
     398,   399,   400,   401,   402,   403,   404,   405,   406,   407,
     408,   409,   410,   411,   412,   413,   414,   415,   416,   417,
     418,   419,   420,   421,   422,   423,   424,   425,   426,   427,
     428,   429,   430,   431,   432,   433,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   460,   461,   462,   463,   465,   466,   467,   468,   469,
     470,   471,   473,   474,   475,   476,   478,   479,   480,   481,
     482,   484,   485,   486,   488,   489,   491,   492,   493,   494,
     495,   496,   498,   499,   500,   501,   502,   504,   505,   506,
     507,   509,   510,   512,   513,   514,   516,   517,   518,   520,
     521,   522,   525,   526,   528,   529,   530,   532,   534,   535,
     536,   537,   539,   540,   541,   543,   544,   545,   546,   547,
     549,   550,   552,   553,   555,   556,   559,   560,   561,   563,
     564,   565,   567,   568,   569,   570,   571,   572,   573,   574,
     575,   576,   577,   578,   579,   580,   581
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
  "OP_LZCOUNT", "BADINTEGER", "GOTO_KEY", "CALL_KEY", "RETURN_KEY",
  "IF_KEY", "DEFINE_KEY", "ATTACH_KEY", "MACRO_KEY", "SPACE_KEY",
  "TYPE_KEY", "RAM_KEY", "DEFAULT_KEY", "REGISTER_KEY", "ENDIAN_KEY",
  "WITH_KEY", "ALIGN_KEY", "OP_UNIMPL", "TOKEN_KEY", "SIGNED_KEY",
  "NOFLOW_KEY", "HEX_KEY", "DEC_KEY", "BIG_KEY", "LITTLE_KEY", "SIZE_KEY",
  "WORDSIZE_KEY", "OFFSET_KEY", "NAMES_KEY", "VALUES_KEY", "VARIABLES_KEY",
  "PCODEOP_KEY", "IS_KEY", "LOCAL_KEY", "DELAYSLOT_KEY", "CROSSBUILD_KEY",
  "EXPORT_KEY", "BUILD_KEY", "CONTEXT_KEY", "ELLIPSIS_KEY",
  "GLOBALSET_KEY", "BITRANGE_KEY", "CHAR", "INTEGER", "INTB", "STRING",
  "SYMBOLSTRING", "SPACESYM", "SECTIONSYM", "TOKENSYM", "USEROPSYM",
  "VALUESYM", "VALUEMAPSYM", "CONTEXTSYM", "NAMESYM", "VARSYM", "BITSYM",
  "SPECSYM", "VARLISTSYM", "OPERANDSYM", "JUMPSYM", "MACROSYM", "LABELSYM",
  "SUBTABLESYM", "'}'", "'='", "'('", "')'", "','", "'['", "']'", "'{'",
  "':'", "' '", "$accept", "spec", "definition", "constructorlike",
  "endiandef", "aligndef", "tokendef", "tokenprop", "contextdef",
  "contextprop", "fielddef", "contextfielddef", "spacedef", "spaceprop",
  "varnodedef", "bitrangedef", "bitrangelist", "bitrangesingle",
  "pcodeopdef", "valueattach", "nameattach", "varattach", "macrodef",
  "withblockstart", "withblockmid", "withblock", "id_or_nil",
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

#ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   124,   261,    59,    94,
     262,    38,   263,   264,   265,   266,   267,    60,    62,   268,
     269,   270,   271,   272,   273,   274,   275,   276,   277,   278,
     279,   280,    43,    45,   281,   282,    42,    47,    37,   283,
     284,   285,   286,    33,   126,   287,   288,   289,   290,   291,
     292,   293,   294,   295,   296,   297,   298,   299,   300,   301,
     302,   303,   304,   305,   306,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,   317,   318,   319,   320,   321,
     322,   323,   324,   325,   326,   327,   328,   329,   330,   331,
     332,   333,   334,   335,   336,   337,   338,   339,   340,   341,
     342,   343,   344,   345,   346,   347,   348,   349,   350,   351,
     352,   353,   354,   355,   356,   357,   358,   359,   360,   361,
     362,   363,   364,   365,   366,   367,   368,   125,    61,    40,
      41,    44,    91,    93,   123,    58,    32
};
#endif

#define YYPACT_NINF (-293)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-271)

#define yytable_value_is_error(Yyn) \
  ((Yyn) == YYTABLE_NINF)

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
      35,    12,    37,  -293,   -15,  -293,    20,  1667,   303,    61,
     -72,   -13,    41,  -293,  -293,  -293,  -293,  -293,   430,  -293,
    1591,  -293,    89,  -293,  -293,  -293,  -293,  -293,  -293,  -293,
    -293,    40,  -293,    47,  -293,    24,   180,    84,  -293,  -293,
    2467,    99,  2486,   -27,   160,   191,   211,   -41,   -41,   -41,
     206,  -293,  -293,   234,  -293,  -293,  -293,   244,  -293,  -293,
    -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,
    -293,  -293,  -293,   346,   247,  -293,   249,   320,   251,  -293,
     253,  -293,   255,   261,   -33,  -293,  -293,  -293,  -293,  -293,
      78,  -293,  -293,  -293,  -293,   286,  -293,    78,  -293,  -293,
    -293,   286,   390,   392,  -293,  -293,   305,   290,  -293,  -293,
     313,   415,  -293,   301,     6,  -293,   307,  -293,  -293,    36,
     323,   -16,   -92,   344,    78,   327,  -293,  -293,  -293,   328,
     330,  -293,  -293,  -293,  -293,   331,    83,   355,   356,   337,
    1721,  1522,  -293,  -293,  -293,  -293,  -293,  -293,   339,  -293,
      78,     5,  -293,  -293,   368,  -293,    45,  -293,     5,  -293,
    -293,   457,   362,  -293,  2419,  -293,   354,  -293,  -293,   -54,
    -293,  -293,   186,  2503,   466,   370,  -293,   -24,   470,  -293,
     -87,   474,  -293,    60,   352,   365,   381,   388,   393,   397,
    -293,  -293,  -293,  -293,  -293,   262,   -22,  -103,  -293,   369,
     389,    10,  1571,   406,   367,   314,   382,   384,   372,    33,
     387,  -293,   385,  -293,  -293,  -293,   391,    94,  -293,  1571,
      -8,  -293,   149,  -293,   151,  -293,  1543,    16,    78,    78,
      78,  -293,   -60,  -293,  1543,  1543,  1543,  1543,  1543,  1543,
     -60,  -293,   400,  -293,  -293,  -293,   386,  -293,   431,  -293,
    -293,  -293,  -293,  -293,  2443,  -293,  -293,  -293,   416,  -293,
    -293,   -21,  -293,  -293,  -293,   -39,  -293,  -293,   419,   399,
     403,   404,   405,   424,  -293,  -293,   417,  -293,  -293,   519,
     532,   447,   452,  -293,   427,  -293,  -293,  -293,  1571,   552,
    -293,  1571,   553,  -293,  1571,  1571,  1571,  1571,  1571,   433,
     442,   443,   445,   482,   483,   485,   487,   522,   523,   525,
     527,   558,   563,   566,   603,   606,   639,   640,  -293,  1571,
    1845,  1571,  -293,   139,    -4,   448,   587,   602,   363,   642,
     771,  -293,   164,   802,  -293,   807,   712,  1571,   714,  1571,
    1571,  1571,  1528,   749,   752,  1571,   754,  1543,  1543,  -293,
    1543,  2405,  -293,  -293,  -293,    85,   884,  -293,   -50,  -293,
    -293,  -293,  2405,  2405,  2405,  2405,  2405,  2405,  -293,   819,
     794,   812,  -293,  -293,  -293,  -293,   829,  -293,  -293,  -293,
    -293,  -293,  -293,  -293,  -293,   830,   869,   870,   874,   314,
    -293,  -293,   882,  -293,   906,   325,  -293,   564,  -293,   604,
    -293,  -293,  -293,  -293,  1571,  1571,  1571,  1571,  1571,  1571,
    1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,
    1571,  1571,  1571,   808,  1571,  1571,  1571,  1571,  1571,  1571,
    1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,
    1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,
    1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571,
     409,  -293,    14,   914,   949,  -293,  1571,   950,  -293,   930,
     212,   989,  -293,   990,  1092,  -293,  1127,  -293,  -293,  -293,
    -293,  1898,  1012,  2218,    66,  1938,   136,  1571,  1006,  1047,
    1978,  1045,  -293,  -293,   380,  1543,  1543,  1543,  1543,  1543,
    1543,  1543,  1543,  1543,  1051,  -293,  1087,  1132,  -293,  -293,
    -293,   -10,  1167,  1085,  1114,  -293,  1125,  1126,  1166,  1170,
    -293,  1200,  1203,  1332,  1367,  1372,   848,   685,   888,   725,
     767,   928,   968,  1008,  1048,  1088,  1128,  1168,  1208,  1248,
     162,   644,  1288,  1328,   182,  -293,  2257,  2294,  2294,  2328,
    2360,  2430,  1773,  1773,  1773,  1773,  2484,  2484,  2484,  2484,
    2484,  2484,  2484,  2484,  2484,  2484,  2484,  2484,  1856,  1856,
    1856,  2382,  2382,  2382,  2382,  -293,  -293,  -293,  -293,  -293,
    -293,  -293,  1407,  1246,  1285,  -293,  2018,     0,  1412,  1447,
    1452,   314,  -293,  -293,  -293,  1571,  1487,  1571,  -293,  1492,
    2058,  -293,  -293,  -293,  1350,  -293,  2463,   285,  1556,   169,
     169,   296,   296,  -293,  -293,  1613,  1543,  1543,  1656,   216,
    -293,  -293,   321,  1390,   -27,  -293,  -293,  -293,  -293,  1429,
    -293,  -293,  -293,  -293,  -293,  1571,  -293,  1571,  1571,  -293,
    -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,
    1571,  -293,  -293,  -293,  -293,  -293,  1430,  -293,  -293,  1571,
    -293,  -293,  -293,  -293,  2098,  -293,  2218,  -293,  -293,  1438,
    1409,  1443,  1565,  2396,  -293,  -293,  1549,  1550,  -293,  -293,
    1450,  1573,  -293,  1368,  1408,  1448,  1488,  1451,  2138,  -293,
    1462,  1475,  1480,  -293,  -293,  -293,  -293,  -293,  -293,  -293,
    -293,  -293,  -293,  -293,  -293,  1571,  1470,  1473,  2178,  1597,
    1600,  -293,  -293,  -293
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
       0,    69,    68,     0,    88,    87,    23,     0,   322,   323,
     324,   325,   328,   329,   330,   331,   332,   336,   333,   334,
     335,   326,   327,    27,     0,    29,     0,    31,     0,    43,
       0,    50,     0,     0,     0,    66,    64,    65,   145,    82,
       0,   281,    83,    86,    85,    84,    81,     0,    78,    80,
      90,    79,     0,     0,    44,    45,     0,     0,    28,   293,
       0,     0,    30,     0,     0,    54,     0,   303,   304,     0,
       0,     0,     0,   319,    70,     0,    34,    35,    36,     0,
       0,    39,    40,    41,    42,     0,     0,     0,     0,     0,
     140,     0,   272,   273,   274,   275,   124,   276,   123,   126,
       0,   127,   106,   111,   113,   114,   125,   282,   127,    20,
      21,     0,     0,   294,     0,    57,     0,    53,    55,     0,
     305,   306,     0,     0,     0,     0,   284,     0,     0,   311,
       0,     0,   320,     0,   127,    71,     0,     0,     0,     0,
      46,    47,    48,    49,    61,     0,     0,   244,   257,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   256,   254,
       0,   277,     0,   278,   279,   280,     0,   255,   146,     0,
       0,   253,     0,   173,   252,   110,     0,     0,     0,     0,
       0,   129,     0,   112,     0,     0,     0,     0,     0,     0,
       0,    22,     0,   295,   292,   296,     0,    52,     0,   309,
     307,   308,   302,   298,     0,   299,    59,   285,     0,   286,
     288,     0,    58,   313,   312,     0,    60,    72,     0,     0,
       0,     0,     0,     0,   254,   255,     0,   259,   252,     0,
       0,     0,     0,   247,   246,   251,   248,   245,     0,     0,
     250,     0,     0,   170,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   238,     0,
       0,     0,   174,   252,     0,     0,     0,     0,     0,     0,
     143,   271,     0,     0,   266,     0,     0,     0,     0,   316,
       0,   316,     0,     0,     0,     0,     0,     0,     0,    91,
       0,   122,    92,    93,   115,   108,   109,   107,     0,    75,
     145,    76,   117,   118,   120,   121,   119,   116,    77,    24,
       0,     0,   300,   297,   301,   287,     0,   289,   291,   283,
     315,   314,   310,   321,    62,     0,     0,     0,     0,     0,
     265,   264,     0,   243,     0,     0,   165,     0,   168,     0,
     189,   216,   202,   190,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   316,     0,
       0,     0,   316,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   175,     0,     0,     0,   147,     0,     0,   154,     0,
       0,     0,   267,     0,   144,   263,     0,   261,   141,   161,
     258,     0,     0,   317,     0,     0,     0,     0,     0,     0,
       0,     0,   104,   105,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   134,     0,     0,   128,   138,
     145,     0,     0,     0,     0,   290,     0,     0,     0,     0,
     260,   242,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   176,   205,   204,   203,   193,
     191,   192,   179,   180,   206,   207,   181,   184,   182,   183,
     185,   186,   187,   188,   208,   209,   210,   211,   194,   195,
     196,   177,   178,   212,   213,   197,   198,   200,   199,   201,
     214,   215,     0,     0,     0,   236,     0,     0,     0,     0,
       0,     0,   269,   142,   151,     0,     0,     0,   158,     0,
       0,   160,   159,   149,     0,    94,   101,   102,   100,    98,
      99,    95,    96,    97,   103,     0,     0,     0,     0,     0,
      73,   137,     0,     0,     0,    32,    33,    37,    38,     0,
     249,   167,   169,   171,   220,     0,   219,     0,     0,   226,
     217,   218,   228,   229,   230,   225,   224,   227,   240,   231,
       0,   233,   234,   239,   166,   235,     0,   150,   148,     0,
     164,   163,   162,   268,     0,   156,   318,   172,   155,     0,
       0,     0,     0,     0,    74,   139,     0,     0,    26,    25,
       0,     0,   241,     0,     0,     0,     0,     0,     0,   153,
       0,     0,     0,   130,   133,   135,   136,    56,    51,   221,
     222,   223,   232,   237,   152,     0,     0,     0,     0,     0,
       0,   157,   131,   132
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -293,  -293,  1578,  1579,  -293,  -293,  -293,  -293,  -293,  -293,
    -293,  -293,  -293,  -293,  -293,  -293,  -293,  1497,  -293,  -293,
    -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,  -293,  1373,
    -293,  -293,  -293,  -192,   -94,  -293,  1471,  -293,  -293,  -108,
    -293,  1022,  -293,  -293,  1281,  1135,  -293,  -196,  -139,  -195,
    -125,  1184,  1315,  -138,  -293,   -90,   -52,  1616,  -293,  -293,
    1025,  -293,  -293,  -293,   366,  -293,  -293,  -293,  -292,  -293,
      15
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,    14,    15,     3,    16,    17,    18,    19,    20,
      73,    77,    21,    22,    23,    24,   114,   115,    25,    26,
      27,    28,    29,    30,    31,    32,    53,   184,    33,   361,
      34,    35,    36,   351,   151,   152,   153,   154,   155,   232,
     358,   621,   509,   510,   139,   140,   218,   483,   321,   289,
     322,   221,   222,   290,   333,   352,   323,    95,   178,   261,
     111,   164,   174,   254,   120,   172,   181,   265,   484,   183,
      74
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     156,   219,   223,   158,   465,   292,   320,   156,   658,   258,
     247,   228,   376,   229,   167,   220,   230,   175,   293,   619,
     359,   263,   228,   342,   229,   195,   179,   230,    38,   281,
     185,   264,   282,    89,   156,    78,    51,     5,     6,    40,
     180,     6,   362,   363,   364,   365,   366,   367,    42,   486,
     240,   156,   248,   504,    52,   105,   227,   108,   505,   234,
     156,    43,   235,   236,   237,   238,   506,   332,    44,   380,
     277,    45,   507,   117,   360,   118,   269,    46,   198,   381,
     327,   109,   259,   508,   260,   377,   279,   378,   224,     4,
     176,   119,   395,   229,   382,   397,   230,    79,   399,   400,
     401,   402,   403,   280,     1,   110,     7,     8,     9,    84,
       8,     9,   379,    37,   113,    10,   177,   620,    10,    90,
     208,   343,    54,   423,   466,   461,   540,   344,   659,    91,
     544,   467,    92,    93,   355,   356,   357,   231,   156,   156,
     156,   481,   294,   278,   485,    11,   354,    39,    11,   490,
     170,   325,   171,   278,   334,   492,   493,   190,   494,   191,
      94,   337,    80,    12,    81,  -262,    12,    85,   338,    50,
     102,   103,    13,   239,   353,    13,    55,    82,    83,   245,
     141,    88,   353,   353,   353,   353,   353,   353,   255,    96,
     267,   268,   142,   143,   144,   145,   596,   597,   146,   147,
     148,   500,   501,   472,   149,   502,   503,   150,   526,   527,
     528,   529,   530,   531,   532,   533,   534,   535,   536,   537,
     538,   539,  -263,   541,   542,   543,  -263,   106,   546,   547,
     548,   549,   550,   551,   552,   553,   554,   555,   556,   557,
     558,   559,   560,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,   571,   572,   573,   574,   575,   576,   577,
     578,   579,   580,   581,   520,   582,   599,   597,   462,   374,
     586,   463,   474,   195,   464,    97,   278,   345,   112,  -261,
     477,   346,   211,  -261,   213,    91,   214,   215,    98,    99,
     475,   600,   648,   597,   249,   353,   353,   497,   353,   113,
     250,   116,   251,   606,   607,   608,   609,   610,   611,   612,
     613,   614,   653,   597,   498,   499,   100,   500,   501,   252,
     589,   502,   503,   590,   676,   195,   198,   677,   424,   425,
     426,   427,   502,   503,   428,   123,   429,   278,   430,   431,
     432,   433,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   208,   124,
     274,   228,   125,   229,   195,   129,   230,   130,   198,   135,
     211,   136,   213,   137,   214,   215,   196,   495,   275,   138,
     496,   157,   497,   328,    47,    48,    49,   276,   159,   664,
     160,   666,   131,   132,   133,   134,   196,   678,   679,   498,
     499,   161,   500,   501,   121,   122,   502,   503,   197,   162,
     208,   163,   274,   165,   672,   673,   196,   198,   126,   166,
     127,   128,   211,   283,   213,   169,   214,   215,    56,   683,
     275,   684,   685,   353,   353,   353,   353,   353,   353,   353,
     353,   353,   182,   283,   686,   173,   186,   187,   523,   188,
     189,   192,   193,   688,   194,   241,   663,   226,   242,   208,
     233,   274,   246,   283,   256,   284,   257,   285,   262,   219,
     223,   211,   266,   213,   231,   214,   215,   270,   329,   275,
     330,   286,   287,   220,   271,   284,   326,   285,   471,   272,
     211,   288,   213,   273,   214,   215,   335,   336,   331,   708,
     605,   286,   287,   340,   324,   284,   339,   285,   370,   371,
     341,   291,   375,   389,   211,   670,   213,   383,   214,   215,
     369,   286,   287,   384,   385,   386,   387,   390,    57,   278,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
     391,    68,    69,    70,    71,   388,    72,   392,   393,   394,
     396,   398,   404,   671,   353,   353,   224,   424,   425,   426,
     427,   405,   406,   428,   407,   429,   468,   430,   431,   432,
     433,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   424,   425,   426,
     427,   408,   409,   428,   410,   429,   411,   430,   431,   432,
     433,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   424,   425,   426,
     427,   412,   413,   428,   414,   429,   415,   430,   431,   432,
     433,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   416,   424,   425,
     426,   427,   417,   469,   428,   418,   429,   524,   430,   431,
     432,   433,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   424,   425,
     426,   427,   419,   470,   428,   420,   429,   525,   430,   431,
     432,   433,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   421,   422,
     424,   425,   426,   427,   649,   650,   428,   473,   429,  -270,
     430,   431,   432,   433,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     478,   424,   425,   426,   427,   479,   635,   428,   480,   429,
     482,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   488,   637,   428,   489,   429,
     491,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   230,   512,   428,   638,   429,
     513,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   515,   516,   428,   545,   429,
     514,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   517,   518,   428,   634,   429,
     519,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   521,   522,   428,   636,   429,
     584,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   585,   587,   428,   639,   429,
     588,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   591,   592,   428,   640,   429,
    -262,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   593,   601,   428,   641,   429,
     595,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   602,   604,   428,   642,   429,
     615,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   616,   623,   428,   643,   429,
     624,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   625,   626,   428,   644,   429,
     617,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   622,   627,   428,   645,   429,
     628,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   629,   630,   428,   646,   429,
     631,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   632,   655,   428,   647,   429,
     633,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   654,   656,   428,   651,   429,
     660,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   661,   669,   428,   652,   429,
     662,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   665,   680,   428,   699,   429,
     667,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,   682,   687,   428,   700,   429,
     691,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   690,   495,   693,   692,   496,   347,   497,   701,   695,
     696,   698,   195,   697,   703,   498,   499,   348,   500,   501,
     705,   706,   502,   503,   498,   499,   707,   500,   501,    75,
     709,   502,   503,   710,   295,   712,   296,   197,   713,    86,
      87,   168,   225,   368,   297,   298,   299,   300,   702,   301,
     302,   303,   304,   305,   306,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,   198,   142,   143,   144,   145,
     675,   511,   146,   147,   148,   618,   583,   476,   149,   681,
     349,   150,   101,     0,     0,     0,   487,   142,   143,   144,
     145,   211,     0,   213,   147,   214,   215,   195,     0,     0,
       0,     0,   350,   196,     0,     0,     0,   208,     0,   274,
       0,     0,     0,     0,   317,   619,     0,     0,     0,   211,
     318,   213,   197,   214,   215,     0,     0,   275,     0,    76,
     319,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,     0,    68,    69,    70,    71,     0,    72,     0,     0,
     198,   199,   200,   201,   202,     0,     0,   142,   143,   144,
     145,   211,   195,   213,   147,   214,   215,     0,   196,    40,
       0,     0,     0,     0,     0,     0,    41,     0,    42,     0,
       0,     0,   203,   204,   205,     0,   207,   197,     0,     0,
       0,    43,   208,     0,   209,     0,     0,     0,    44,   210,
       0,    45,     0,     0,   211,   212,   213,    46,   214,   215,
     216,     0,   217,   674,     0,   198,   199,   200,   201,   202,
     434,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,     0,   203,   204,   205,
     206,   207,     0,     0,     0,     0,     0,   208,     0,   209,
       0,     0,     0,     0,   210,     0,     0,     0,     0,   211,
     212,   213,     0,   214,   215,   216,     0,   217,   424,   425,
     426,   427,     0,     0,   428,     0,   429,     0,   430,   431,
     432,   433,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,     0,
       0,   424,   425,   426,   427,     0,   594,   428,     0,   429,
     460,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   598,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   603,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   657,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   668,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   689,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   704,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,   711,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   424,   425,   426,   427,     0,     0,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   425,   426,   427,     0,     0,   428,     0,   429,     0,
     430,   431,   432,   433,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     427,     0,     0,   428,     0,   429,     0,   430,   431,   432,
     433,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   428,     0,   429,
       0,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   429,     0,   430,   431,   432,   433,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   495,   694,     0,   496,     0,   497,     0,
       0,     0,   495,     0,     0,   496,     0,   497,   453,   454,
     455,   456,   457,   458,   459,   498,   499,     0,   500,   501,
       0,     0,   502,   503,   498,   499,     0,   500,   501,     0,
       0,   502,   503,   430,   431,   432,   433,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   496,     0,   497,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   498,   499,     0,   500,   501,     0,     0,   502,
     503,  -271,  -271,  -271,  -271,  -271,  -271,  -271,  -271,  -271,
    -271,  -271,  -271,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   243,     0,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,     0,
      68,    69,    70,    71,     0,    72,     0,     0,     0,     0,
       0,   372,   244,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,     0,    68,    69,    70,    71,     0,    72,
       0,     0,     0,     0,     0,   104,   373,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,     0,    68,    69,
      70,    71,     0,    72,   107,     0,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,     0,    68,    69,    70,
      71,   253,    72,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,     0,    68,    69,    70,    71,     0,    72
};

static const yytype_int16 yycheck[] =
{
      90,   140,   140,    97,     8,   200,   202,    97,     8,    33,
      64,     6,    33,     8,     8,   140,    11,    33,     8,    29,
      80,   108,     6,   219,     8,    11,   118,    11,     8,   132,
     124,   118,   135,     9,   124,    20,   108,     0,     1,    72,
     132,     1,   234,   235,   236,   237,   238,   239,    81,   341,
     158,   141,   106,   103,   126,    40,   150,    42,   108,    14,
     150,    94,    17,    18,    19,    20,   116,   206,   101,   108,
     195,   104,   122,   114,   134,   116,   184,   110,    64,   118,
     205,   108,   106,   133,   108,   106,   108,   108,   140,    77,
     106,   132,   288,     8,   133,   291,    11,     8,   294,   295,
     296,   297,   298,   125,    69,   132,    69,    70,    71,    69,
      70,    71,   133,   128,   108,    78,   132,   127,    78,    95,
     106,   129,   135,   319,   128,   321,   418,   135,   128,   105,
     422,   135,   108,   109,   228,   229,   230,   132,   228,   229,
     230,   337,   132,   195,   340,   108,   130,   127,   108,   345,
     114,   203,   116,   205,   206,   347,   348,    74,   350,    76,
     136,   128,    73,   126,    75,   132,   126,   127,   135,   108,
      86,    87,   135,   128,   226,   135,   135,    88,    89,   164,
     102,   134,   234,   235,   236,   237,   238,   239,   173,     9,
     130,   131,   114,   115,   116,   117,   130,   131,   120,   121,
     122,    32,    33,   328,   126,    36,    37,   129,   404,   405,
     406,   407,   408,   409,   410,   411,   412,   413,   414,   415,
     416,   417,   128,   419,   420,   421,   132,   128,   424,   425,
     426,   427,   428,   429,   430,   431,   432,   433,   434,   435,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   389,   460,   130,   131,   129,   254,
     466,   132,   108,    11,   135,    95,   328,   128,   118,   128,
     332,   132,   118,   132,   120,   105,   122,   123,   108,   109,
     126,   487,   130,   131,   108,   347,   348,    12,   350,   108,
     114,    90,   116,   495,   496,   497,   498,   499,   500,   501,
     502,   503,   130,   131,    29,    30,   136,    32,    33,   133,
     108,    36,    37,   111,   108,    11,    64,   111,     3,     4,
       5,     6,    36,    37,     9,   129,    11,   389,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,   106,   135,
     108,     6,   128,     8,    11,   128,    11,   128,    64,   128,
     118,   128,   120,   128,   122,   123,    17,     7,   126,   128,
      10,   105,    12,    11,    91,    92,    93,   135,     8,   595,
       8,   597,    82,    83,    84,    85,    17,    86,    87,    29,
      30,   106,    32,    33,    48,    49,    36,    37,    36,   129,
     106,   108,   108,     8,   616,   617,    17,    64,    82,   128,
      84,    85,   118,    64,   120,   128,   122,   123,     8,   635,
     126,   637,   638,   495,   496,   497,   498,   499,   500,   501,
     502,   503,   108,    64,   650,   132,   129,   129,   133,   129,
     129,   106,   106,   659,   127,     8,   591,   128,   106,   106,
     102,   108,   118,    64,     8,   106,   106,   108,     8,   618,
     618,   118,     8,   120,   132,   122,   123,   106,   106,   126,
     108,   122,   123,   618,   106,   106,   129,   108,   135,   106,
     118,   132,   120,   106,   122,   123,   122,   135,   126,   705,
     130,   122,   123,   128,   108,   106,   129,   108,   132,    88,
     129,   132,   106,   106,   118,   615,   120,   108,   122,   123,
     130,   122,   123,   134,   131,   131,   131,    18,   108,   591,
     110,   111,   112,   113,   114,   115,   116,   117,   118,   119,
      18,   121,   122,   123,   124,   131,   126,   110,   106,   132,
       8,     8,   129,   615,   616,   617,   618,     3,     4,     5,
       6,   129,   129,     9,   129,    11,   128,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,   129,   129,     9,   129,    11,   129,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,   129,   129,     9,   129,    11,   129,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,   129,     3,     4,
       5,     6,   129,   106,     9,   129,    11,   133,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   129,   131,     9,   129,    11,   133,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,   129,   129,
       3,     4,     5,     6,   130,   131,     9,   135,    11,     8,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       8,     3,     4,     5,     6,     8,   131,     9,   106,    11,
     106,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   106,   131,     9,   106,    11,
     106,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    11,    77,     9,   131,    11,
     106,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   106,   106,     9,   130,    11,
     128,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   106,   106,     9,   130,    11,
     106,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   133,   110,     9,   130,    11,
     106,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   106,   106,     9,   130,    11,
     130,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   106,   106,     9,   130,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,     8,   130,     9,   130,    11,
     128,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   128,   131,     9,   130,    11,
     129,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   128,   131,     9,   130,    11,
     106,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   130,   130,     9,   130,    11,
     128,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   128,   130,     9,   130,    11,
     130,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   135,   133,     9,   130,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,     8,   130,     9,   130,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,     8,   131,     9,   130,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,     8,   106,     9,   130,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,     8,   106,     9,   130,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   106,   106,     9,   130,    11,
     131,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,   133,     7,     8,   131,    10,    33,    12,   130,    30,
      30,     8,    11,   133,   133,    29,    30,    44,    32,    33,
     128,   116,    36,    37,    29,    30,   116,    32,    33,     8,
     130,    36,    37,   130,    33,     8,    35,    36,     8,    31,
      31,   114,   141,   240,    43,    44,    45,    46,   130,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,   114,   115,   116,   117,
     618,   360,   120,   121,   122,   510,   462,   332,   126,   624,
     107,   129,    36,    -1,    -1,    -1,   128,   114,   115,   116,
     117,   118,    -1,   120,   121,   122,   123,    11,    -1,    -1,
      -1,    -1,   129,    17,    -1,    -1,    -1,   106,    -1,   108,
      -1,    -1,    -1,    -1,   113,    29,    -1,    -1,    -1,   118,
     119,   120,    36,   122,   123,    -1,    -1,   126,    -1,   108,
     129,   110,   111,   112,   113,   114,   115,   116,   117,   118,
     119,    -1,   121,   122,   123,   124,    -1,   126,    -1,    -1,
      64,    65,    66,    67,    68,    -1,    -1,   114,   115,   116,
     117,   118,    11,   120,   121,   122,   123,    -1,    17,    72,
      -1,    -1,    -1,    -1,    -1,    -1,    79,    -1,    81,    -1,
      -1,    -1,    96,    97,    98,    -1,   100,    36,    -1,    -1,
      -1,    94,   106,    -1,   108,    -1,    -1,    -1,   101,   113,
      -1,   104,    -1,    -1,   118,   119,   120,   110,   122,   123,
     124,    -1,   126,   127,    -1,    64,    65,    66,    67,    68,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    -1,    96,    97,    98,
      99,   100,    -1,    -1,    -1,    -1,    -1,   106,    -1,   108,
      -1,    -1,    -1,    -1,   113,    -1,    -1,    -1,    -1,   118,
     119,   120,    -1,   122,   123,   124,    -1,   126,     3,     4,
       5,     6,    -1,    -1,     9,    -1,    11,    -1,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    -1,
      -1,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      65,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,     8,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,    -1,    -1,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     4,     5,     6,    -1,    -1,     9,    -1,    11,    -1,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       6,    -1,    -1,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,    11,    -1,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     7,     8,    -1,    10,    -1,    12,    -1,
      -1,    -1,     7,    -1,    -1,    10,    -1,    12,    36,    37,
      38,    39,    40,    41,    42,    29,    30,    -1,    32,    33,
      -1,    -1,    36,    37,    29,    30,    -1,    32,    33,    -1,
      -1,    36,    37,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,    10,    -1,    12,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    29,    30,    -1,    32,    33,    -1,    -1,    36,
      37,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,   108,    -1,   110,
     111,   112,   113,   114,   115,   116,   117,   118,   119,    -1,
     121,   122,   123,   124,    -1,   126,    -1,    -1,    -1,    -1,
      -1,   108,   133,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,    -1,   121,   122,   123,   124,    -1,   126,
      -1,    -1,    -1,    -1,    -1,   108,   133,   110,   111,   112,
     113,   114,   115,   116,   117,   118,   119,    -1,   121,   122,
     123,   124,    -1,   126,   108,    -1,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   119,    -1,   121,   122,   123,
     124,   108,   126,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,    -1,   121,   122,   123,   124,    -1,   126
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    69,   138,   141,    77,     0,     1,    69,    70,    71,
      78,   108,   126,   135,   139,   140,   142,   143,   144,   145,
     146,   149,   150,   151,   152,   155,   156,   157,   158,   159,
     160,   161,   162,   165,   167,   168,   169,   128,     8,   127,
      72,    79,    81,    94,   101,   104,   110,    91,    92,    93,
     108,   108,   126,   163,   135,   135,     8,   108,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,   121,   122,
     123,   124,   126,   147,   207,     8,   108,   148,   207,     8,
      73,    75,    88,    89,    69,   127,   139,   140,   134,     9,
      95,   105,   108,   109,   136,   194,     9,    95,   108,   109,
     136,   194,    86,    87,   108,   207,   128,   108,   207,   108,
     132,   197,   118,   108,   153,   154,    90,   114,   116,   132,
     201,   201,   201,   129,   135,   128,    82,    84,    85,   128,
     128,    82,    83,    84,    85,   128,   128,   128,   128,   181,
     182,   102,   114,   115,   116,   117,   120,   121,   122,   126,
     129,   171,   172,   173,   174,   175,   192,   105,   171,     8,
       8,   106,   129,   108,   198,     8,   128,     8,   154,   128,
     114,   116,   202,   132,   199,    33,   106,   132,   195,   118,
     132,   203,   108,   206,   164,   171,   129,   129,   129,   129,
      74,    76,   106,   106,   127,    11,    17,    36,    64,    65,
      66,    67,    68,    96,    97,    98,    99,   100,   106,   108,
     113,   118,   119,   120,   122,   123,   124,   126,   183,   185,
     187,   188,   189,   190,   193,   173,   128,   171,     6,     8,
      11,   132,   176,   102,    14,    17,    18,    19,    20,   128,
     176,     8,   106,   108,   133,   207,   118,    64,   106,   108,
     114,   116,   133,   108,   200,   207,     8,   106,    33,   106,
     108,   196,     8,   108,   118,   204,     8,   130,   131,   176,
     106,   106,   106,   106,   108,   126,   135,   187,   193,   108,
     125,   132,   135,    64,   106,   108,   122,   123,   132,   186,
     190,   132,   186,     8,   132,    33,    35,    43,    44,    45,
      46,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,   113,   119,   129,
     184,   185,   187,   193,   108,   193,   129,   187,    11,   106,
     108,   126,   185,   191,   193,   122,   135,   128,   135,   129,
     128,   129,   184,   129,   135,   128,   132,    33,    44,   107,
     129,   170,   192,   193,   130,   171,   171,   171,   177,    80,
     134,   166,   170,   170,   170,   170,   170,   170,   166,   130,
     132,    88,   108,   133,   207,   106,    33,   106,   108,   133,
     108,   118,   133,   108,   134,   131,   131,   131,   131,   106,
      18,    18,   110,   106,   132,   184,     8,   184,     8,   184,
     184,   184,   184,   184,   129,   129,   129,   129,   129,   129,
     129,   129,   129,   129,   129,   129,   129,   129,   129,   129,
     129,   129,   129,   184,     3,     4,     5,     6,     9,    11,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
      65,   184,   129,   132,   135,     8,   128,   135,   128,   106,
     131,   135,   187,   135,   108,   126,   189,   193,     8,     8,
     106,   184,   106,   184,   205,   184,   205,   128,   106,   106,
     184,   106,   170,   170,   170,     7,    10,    12,    29,    30,
      32,    33,    36,    37,   103,   108,   116,   122,   133,   179,
     180,   181,    77,   106,   128,   106,   106,   106,   106,   106,
     187,   133,   110,   133,   133,   133,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     205,   184,   184,   184,   205,   130,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   186,   188,   106,   106,   184,   106,   130,   108,
     111,   106,   106,     8,     8,   128,   130,   131,     8,   130,
     184,   130,   128,     8,   131,   130,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   129,   128,   128,   182,    29,
     127,   178,   128,   131,   106,   130,   130,   130,   130,   135,
     133,     8,     8,     8,   130,   131,   130,   131,   131,   130,
     130,   130,   130,   130,   130,   130,   130,   130,   130,   130,
     131,   130,   130,   130,     8,   130,   131,     8,     8,   128,
       8,     8,     8,   187,   184,     8,   184,     8,     8,   106,
     192,   193,   170,   170,   127,   178,   108,   111,    86,    87,
     106,   197,   106,   184,   184,   184,   184,   106,   184,     8,
     133,   131,   131,     8,     8,    30,    30,   133,     8,   130,
     130,   130,   130,   133,     8,   128,   116,   116,   184,   130,
     130,     8,     8,     8
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,   137,   138,   138,   138,   138,   139,   139,   139,   139,
     139,   139,   139,   139,   139,   139,   140,   140,   140,   140,
     141,   141,   142,   143,   144,   144,   144,   144,   144,   145,
     146,   146,   147,   147,   147,   147,   147,   148,   148,   148,
     148,   148,   148,   149,   150,   150,   150,   150,   150,   150,
     150,   151,   151,   152,   153,   153,   154,   155,   156,   157,
     158,   159,   160,   161,   161,   161,   162,   163,   163,   163,
     164,   164,   165,   166,   166,   166,   167,   167,   168,   168,
     168,   168,   168,   168,   168,   168,   168,   169,   169,   169,
     169,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   171,   171,   171,   171,
     172,   172,   173,   173,   174,   174,   175,   175,   175,   175,
     175,   175,   175,   175,   175,   175,   175,   176,   176,   177,
     177,   177,   177,   177,   177,   178,   178,   179,   180,   180,
     181,   181,   181,   181,   181,   182,   182,   182,   182,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   185,   185,   185,   185,   186,   186,   186,   186,   186,
     186,   186,   187,   187,   187,   187,   188,   188,   188,   188,
     188,   189,   189,   189,   190,   190,   191,   191,   191,   191,
     191,   191,   192,   192,   192,   192,   192,   193,   193,   193,
     193,   194,   194,   195,   195,   195,   196,   196,   196,   196,
     196,   196,   197,   197,   198,   198,   198,   199,   200,   200,
     200,   200,   201,   201,   201,   202,   202,   202,   202,   202,
     203,   203,   204,   204,   204,   204,   205,   205,   205,   206,
     206,   206,   207,   207,   207,   207,   207,   207,   207,   207,
     207,   207,   207,   207,   207,   207,   207
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
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
       4,     4,     6,     4,     4,     4,     3,     6,     1,     4,
       4,     6,     4,     3,     1,     1,     1,     1,     1,     4,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     2,
       4,     1,     1,     1,     3,     3,     1,     2,     4,     3,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     3,     1,     2,     1,     2,     1,     2,
       3,     2,     3,     1,     1,     2,     2,     3,     1,     1,
       2,     2,     3,     1,     1,     1,     1,     2,     2,     2,
       3,     1,     1,     1,     2,     2,     0,     1,     3,     0,
       1,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = SLEIGHEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


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

/* This macro is provided for backward compatibility. */
# ifndef YY_LOCATION_PRINT
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif


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
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yykind);
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
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL_INTEGER: /* INTEGER  */
            { delete ((*yyvaluep).i); }
        break;

    case YYSYMBOL_INTB: /* INTB  */
            { delete ((*yyvaluep).big); }
        break;

    case YYSYMBOL_STRING: /* STRING  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_SYMBOLSTRING: /* SYMBOLSTRING  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_fielddef: /* fielddef  */
            { delete ((*yyvaluep).fieldqual); }
        break;

    case YYSYMBOL_contextfielddef: /* contextfielddef  */
            { delete ((*yyvaluep).fieldqual); }
        break;

    case YYSYMBOL_spaceprop: /* spaceprop  */
            { delete ((*yyvaluep).spacequal); }
        break;

    case YYSYMBOL_bitpat_or_nil: /* bitpat_or_nil  */
            { if (((*yyvaluep).pateq)) PatternEquation::release(((*yyvaluep).pateq)); }
        break;

    case YYSYMBOL_rtlbody: /* rtlbody  */
            { delete ((*yyvaluep).sectionstart); }
        break;

    case YYSYMBOL_pexpression: /* pexpression  */
            { PatternExpression::release(((*yyvaluep).patexp)); }
        break;

    case YYSYMBOL_pequation: /* pequation  */
            { if (((*yyvaluep).pateq)) PatternEquation::release(((*yyvaluep).pateq)); }
        break;

    case YYSYMBOL_elleq: /* elleq  */
            { if (((*yyvaluep).pateq)) PatternEquation::release(((*yyvaluep).pateq)); }
        break;

    case YYSYMBOL_ellrt: /* ellrt  */
            { if (((*yyvaluep).pateq)) PatternEquation::release(((*yyvaluep).pateq)); }
        break;

    case YYSYMBOL_atomic: /* atomic  */
            { if (((*yyvaluep).pateq)) PatternEquation::release(((*yyvaluep).pateq)); }
        break;

    case YYSYMBOL_constraint: /* constraint  */
            { if (((*yyvaluep).pateq)) PatternEquation::release(((*yyvaluep).pateq)); }
        break;

    case YYSYMBOL_contextblock: /* contextblock  */
            { delete ((*yyvaluep).contop); }
        break;

    case YYSYMBOL_contextlist: /* contextlist  */
            { delete ((*yyvaluep).contop); }
        break;

    case YYSYMBOL_rtlfirstsection: /* rtlfirstsection  */
            { delete ((*yyvaluep).sectionstart); }
        break;

    case YYSYMBOL_rtlcontinue: /* rtlcontinue  */
            { delete ((*yyvaluep).sectionstart); }
        break;

    case YYSYMBOL_rtl: /* rtl  */
            { delete ((*yyvaluep).sem); }
        break;

    case YYSYMBOL_rtlmid: /* rtlmid  */
            { delete ((*yyvaluep).sem); }
        break;

    case YYSYMBOL_statement: /* statement  */
            { delete ((*yyvaluep).stmt); }
        break;

    case YYSYMBOL_expr: /* expr  */
            { delete ((*yyvaluep).tree); }
        break;

    case YYSYMBOL_sizedstar: /* sizedstar  */
            { delete ((*yyvaluep).starqual); }
        break;

    case YYSYMBOL_jumpdest: /* jumpdest  */
            { delete ((*yyvaluep).varnode); }
        break;

    case YYSYMBOL_varnode: /* varnode  */
            { delete ((*yyvaluep).varnode); }
        break;

    case YYSYMBOL_integervarnode: /* integervarnode  */
            { delete ((*yyvaluep).varnode); }
        break;

    case YYSYMBOL_lhsvarnode: /* lhsvarnode  */
            { delete ((*yyvaluep).varnode); }
        break;

    case YYSYMBOL_exportvarnode: /* exportvarnode  */
            { delete ((*yyvaluep).varnode); }
        break;

    case YYSYMBOL_charstring: /* charstring  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_intblist: /* intblist  */
            { delete ((*yyvaluep).biglist); }
        break;

    case YYSYMBOL_intbpart: /* intbpart  */
            { delete ((*yyvaluep).biglist); }
        break;

    case YYSYMBOL_stringlist: /* stringlist  */
            { delete ((*yyvaluep).strlist); }
        break;

    case YYSYMBOL_stringpart: /* stringpart  */
            { delete ((*yyvaluep).strlist); }
        break;

    case YYSYMBOL_anystringlist: /* anystringlist  */
            { delete ((*yyvaluep).strlist); }
        break;

    case YYSYMBOL_anystringpart: /* anystringpart  */
            { delete ((*yyvaluep).strlist); }
        break;

    case YYSYMBOL_valuelist: /* valuelist  */
            { delete ((*yyvaluep).symlist); }
        break;

    case YYSYMBOL_valuepart: /* valuepart  */
            { delete ((*yyvaluep).symlist); }
        break;

    case YYSYMBOL_varlist: /* varlist  */
            { delete ((*yyvaluep).symlist); }
        break;

    case YYSYMBOL_varpart: /* varpart  */
            { delete ((*yyvaluep).symlist); }
        break;

    case YYSYMBOL_paramlist: /* paramlist  */
            { delete ((*yyvaluep).param); }
        break;

    case YYSYMBOL_oplist: /* oplist  */
            { delete ((*yyvaluep).strlist); }
        break;

      default:
        break;
    }
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
    goto yyexhaustedlab;
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
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
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
                                              { (yyval.fieldqual) = (FieldQuality *)0; delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; slgh->reportError(errmsg); YYERROR; }
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
                                              { (yyval.fieldqual) = (FieldQuality *)0; delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; slgh->reportError(errmsg); YYERROR; }
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
                                        { (yyval.spacequal) = (SpaceQuality *)0; string errmsg = (yyvsp[0].anysym)->getName()+": redefined as space"; slgh->reportError(errmsg); YYERROR; }
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
                                                { (yyval.contop) = (yyvsp[-4].contop); if (!slgh->contextMod((yyvsp[-4].contop),(yyvsp[-3].contextsym),(yyvsp[-1].patexp))) { string errmsg="Cannot use 'inst_next' or 'inst_next2' to set context variable: "+(yyvsp[-3].contextsym)->getName(); slgh->reportError(errmsg); delete (yyvsp[-4].contop); (yyvsp[-1].patexp)->layClaim(); PatternExpression::release((yyvsp[-1].patexp)); YYERROR; } }
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
                                        { (yyval.contop) = (vector<ContextChange *> *)0; delete (yyvsp[-1].contop); string errmsg="Expecting context symbol, not "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
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
                                        { (yyval.sem) = (ConstructTpl *)0; delete (yyvsp[-2].sem); string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 144: /* rtl: rtlmid EXPORT_KEY sizedstar STRING  */
                                        { (yyval.sem) = (ConstructTpl *)0; delete (yyvsp[-3].sem); string errmsg="Unknown pointer varnode: "+*(yyvsp[0].str); delete (yyvsp[-1].starqual); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 145: /* rtlmid: %empty  */
                                        { (yyval.sem) = slgh->enterSection(); }
    break;

  case 146: /* rtlmid: rtlmid statement  */
                                        { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[-1].sem); delete (yyvsp[0].stmt); slgh->reportError("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }
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
                                        { (yyval.stmt) = (vector<OpTpl *> *)0; delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); slgh->reportError("Illegal truncation on left-hand side of assignment"); YYERROR; }
    break;

  case 160: /* statement: varnode '(' INTEGER ')'  */
                                        { (yyval.stmt) = (vector<OpTpl *> *)0; delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); slgh->reportError("Illegal subpiece on left-hand side of assignment"); YYERROR; }
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
                                        { (yyval.stmt) = (vector<OpTpl *> *)0; slgh->reportError("Must specify an indirect parameter for return"); YYERROR; }
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

  case 235: /* expr: specificsymbol '(' integervarnode ')'  */
                                          { (yyval.tree) = slgh->pcode.createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 236: /* expr: specificsymbol ':' INTEGER  */
                                { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }
    break;

  case 237: /* expr: specificsymbol '[' INTEGER ',' INTEGER ']'  */
                                               { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }
    break;

  case 238: /* expr: BITSYM  */
                                { (yyval.tree)=slgh->pcode.createBitRange((yyvsp[0].bitsym)->getParentSymbol(),(yyvsp[0].bitsym)->getBitOffset(),(yyvsp[0].bitsym)->numBits()); }
    break;

  case 239: /* expr: USEROPSYM '(' paramlist ')'  */
                                { (yyval.tree) = slgh->pcode.createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }
    break;

  case 240: /* expr: OP_CPOOLREF '(' paramlist ')'  */
                                   { if ((*(yyvsp[-1].param)).size() < 2) { string errmsg = "Must be at least two inputs to cpool"; slgh->reportError(errmsg); delete (yyvsp[-1].param); YYERROR; } (yyval.tree) = slgh->pcode.createVariadic(CPUI_CPOOLREF,(yyvsp[-1].param)); }
    break;

  case 241: /* sizedstar: '*' '[' SPACESYM ']' ':' INTEGER  */
                                            { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }
    break;

  case 242: /* sizedstar: '*' '[' SPACESYM ']'  */
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }
    break;

  case 243: /* sizedstar: '*' ':' INTEGER  */
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
    break;

  case 244: /* sizedstar: '*'  */
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
    break;

  case 245: /* jumpdest: JUMPSYM  */
                                { VarnodeTpl *sym = (yyvsp[0].specsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
    break;

  case 246: /* jumpdest: INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }
    break;

  case 247: /* jumpdest: BADINTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); slgh->reportError("Parsed integer is too big (overflow)"); }
    break;

  case 248: /* jumpdest: OPERANDSYM  */
                                { (yyval.varnode) = (yyvsp[0].operandsym)->getVarnode(); (yyvsp[0].operandsym)->setCodeAddress(); }
    break;

  case 249: /* jumpdest: INTEGER '[' SPACESYM ']'  */
                                { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }
    break;

  case 250: /* jumpdest: label  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }
    break;

  case 251: /* jumpdest: STRING  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 252: /* varnode: specificsymbol  */
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 253: /* varnode: integervarnode  */
                                { (yyval.varnode) = (yyvsp[0].varnode); }
    break;

  case 254: /* varnode: STRING  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 255: /* varnode: SUBTABLESYM  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 256: /* integervarnode: INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }
    break;

  case 257: /* integervarnode: BADINTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); slgh->reportError("Parsed integer is too big (overflow)"); }
    break;

  case 258: /* integervarnode: INTEGER ':' INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
    break;

  case 259: /* integervarnode: '&' varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
    break;

  case 260: /* integervarnode: '&' ':' INTEGER varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 261: /* lhsvarnode: specificsymbol  */
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 262: /* lhsvarnode: STRING  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 263: /* lhsvarnode: SUBTABLESYM  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 264: /* label: '<' LABELSYM '>'  */
                                { (yyval.labelsym) = (yyvsp[-1].labelsym); }
    break;

  case 265: /* label: '<' STRING '>'  */
                                { (yyval.labelsym) = slgh->pcode.defineLabel( (yyvsp[-1].str) ); }
    break;

  case 266: /* exportvarnode: specificsymbol  */
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 267: /* exportvarnode: '&' varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
    break;

  case 268: /* exportvarnode: '&' ':' INTEGER varnode  */
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 269: /* exportvarnode: INTEGER ':' INTEGER  */
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
    break;

  case 270: /* exportvarnode: STRING  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 271: /* exportvarnode: SUBTABLESYM  */
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 272: /* familysymbol: VALUESYM  */
                                { (yyval.famsym) = (yyvsp[0].valuesym); }
    break;

  case 273: /* familysymbol: VALUEMAPSYM  */
                                { (yyval.famsym) = (yyvsp[0].valuemapsym); }
    break;

  case 274: /* familysymbol: CONTEXTSYM  */
                                { (yyval.famsym) = (yyvsp[0].contextsym); }
    break;

  case 275: /* familysymbol: NAMESYM  */
                                { (yyval.famsym) = (yyvsp[0].namesym); }
    break;

  case 276: /* familysymbol: VARLISTSYM  */
                                { (yyval.famsym) = (yyvsp[0].varlistsym); }
    break;

  case 277: /* specificsymbol: VARSYM  */
                                { (yyval.specsym) = (yyvsp[0].varsym); }
    break;

  case 278: /* specificsymbol: SPECSYM  */
                                { (yyval.specsym) = (yyvsp[0].specsym); }
    break;

  case 279: /* specificsymbol: OPERANDSYM  */
                                { (yyval.specsym) = (yyvsp[0].operandsym); }
    break;

  case 280: /* specificsymbol: JUMPSYM  */
                                { (yyval.specsym) = (yyvsp[0].specsym); }
    break;

  case 281: /* charstring: CHAR  */
                                { (yyval.str) = new string; (*(yyval.str)) += (yyvsp[0].ch); }
    break;

  case 282: /* charstring: charstring CHAR  */
                                { (yyval.str) = (yyvsp[-1].str); (*(yyval.str)) += (yyvsp[0].ch); }
    break;

  case 283: /* intblist: '[' intbpart ']'  */
                                { (yyval.biglist) = (yyvsp[-1].biglist); }
    break;

  case 284: /* intblist: INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 285: /* intblist: '-' INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 286: /* intbpart: INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 287: /* intbpart: '-' INTEGER  */
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 288: /* intbpart: STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
    break;

  case 289: /* intbpart: intbpart INTEGER  */
                                { (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 290: /* intbpart: intbpart '-' INTEGER  */
                                { (yyval.biglist) = (yyvsp[-2].biglist); (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 291: /* intbpart: intbpart STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[-1].biglist); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
    break;

  case 292: /* stringlist: '[' stringpart ']'  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); }
    break;

  case 293: /* stringlist: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 294: /* stringpart: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
    break;

  case 295: /* stringpart: stringpart STRING  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 296: /* stringpart: stringpart anysymbol  */
                                { (yyval.strlist) = (vector<string> *)0; delete (yyvsp[-1].strlist); string errmsg = (yyvsp[0].anysym)->getName()+": redefined"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 297: /* anystringlist: '[' anystringpart ']'  */
                                     { (yyval.strlist) = (yyvsp[-1].strlist); }
    break;

  case 298: /* anystringpart: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
    break;

  case 299: /* anystringpart: anysymbol  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( (yyvsp[0].anysym)->getName() ); }
    break;

  case 300: /* anystringpart: anystringpart STRING  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 301: /* anystringpart: anystringpart anysymbol  */
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back((yyvsp[0].anysym)->getName()); }
    break;

  case 302: /* valuelist: '[' valuepart ']'  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); }
    break;

  case 303: /* valuelist: VALUESYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
    break;

  case 304: /* valuelist: CONTEXTSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 305: /* valuepart: VALUESYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back( (yyvsp[0].valuesym) ); }
    break;

  case 306: /* valuepart: CONTEXTSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 307: /* valuepart: valuepart VALUESYM  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
    break;

  case 308: /* valuepart: valuepart CONTEXTSYM  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 309: /* valuepart: valuepart STRING  */
                                { (yyval.symlist) = (vector<SleighSymbol *> *)0; delete (yyvsp[-1].symlist); string errmsg = *(yyvsp[0].str)+": is not a value pattern"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 310: /* varlist: '[' varpart ']'  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); }
    break;

  case 311: /* varlist: VARSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 312: /* varpart: VARSYM  */
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 313: /* varpart: STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
				  (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
    break;

  case 314: /* varpart: varpart VARSYM  */
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 315: /* varpart: varpart STRING  */
                                { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[-1].symlist); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
    break;

  case 316: /* paramlist: %empty  */
                                { (yyval.param) = new vector<ExprTree *>; }
    break;

  case 317: /* paramlist: expr  */
                                { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }
    break;

  case 318: /* paramlist: paramlist ',' expr  */
                                { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }
    break;

  case 319: /* oplist: %empty  */
                                { (yyval.strlist) = new vector<string>; }
    break;

  case 320: /* oplist: STRING  */
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 321: /* oplist: oplist ',' STRING  */
                                { (yyval.strlist) = (yyvsp[-2].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 322: /* anysymbol: SPACESYM  */
                                { (yyval.anysym) = (yyvsp[0].spacesym); }
    break;

  case 323: /* anysymbol: SECTIONSYM  */
                                { (yyval.anysym) = (yyvsp[0].sectionsym); }
    break;

  case 324: /* anysymbol: TOKENSYM  */
                                { (yyval.anysym) = (yyvsp[0].tokensym); }
    break;

  case 325: /* anysymbol: USEROPSYM  */
                                { (yyval.anysym) = (yyvsp[0].useropsym); }
    break;

  case 326: /* anysymbol: MACROSYM  */
                                { (yyval.anysym) = (yyvsp[0].macrosym); }
    break;

  case 327: /* anysymbol: SUBTABLESYM  */
                                { (yyval.anysym) = (yyvsp[0].subtablesym); }
    break;

  case 328: /* anysymbol: VALUESYM  */
                                { (yyval.anysym) = (yyvsp[0].valuesym); }
    break;

  case 329: /* anysymbol: VALUEMAPSYM  */
                                { (yyval.anysym) = (yyvsp[0].valuemapsym); }
    break;

  case 330: /* anysymbol: CONTEXTSYM  */
                                { (yyval.anysym) = (yyvsp[0].contextsym); }
    break;

  case 331: /* anysymbol: NAMESYM  */
                                { (yyval.anysym) = (yyvsp[0].namesym); }
    break;

  case 332: /* anysymbol: VARSYM  */
                                { (yyval.anysym) = (yyvsp[0].varsym); }
    break;

  case 333: /* anysymbol: VARLISTSYM  */
                                { (yyval.anysym) = (yyvsp[0].varlistsym); }
    break;

  case 334: /* anysymbol: OPERANDSYM  */
                                { (yyval.anysym) = (yyvsp[0].operandsym); }
    break;

  case 335: /* anysymbol: JUMPSYM  */
                                { (yyval.anysym) = (yyvsp[0].specsym); }
    break;

  case 336: /* anysymbol: BITSYM  */
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
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturn;
#endif


/*-------------------------------------------------------.
| yyreturn -- parsing is finished, clean up and return.  |
`-------------------------------------------------------*/
yyreturn:
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

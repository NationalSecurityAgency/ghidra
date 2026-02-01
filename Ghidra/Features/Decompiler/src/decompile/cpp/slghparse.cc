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
/* A Bison parser, made by GNU Bison 3.5.1.  */

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

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.5.1"

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

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_SLEIGH_SLGHPARSE_HH_INCLUDED
# define YY_SLEIGH_SLGHPARSE_HH_INCLUDED
/* Debug traces.  */
#ifndef SLEIGHDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define SLEIGHDEBUG 1
#  else
#   define SLEIGHDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define SLEIGHDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined SLEIGHDEBUG */
#if SLEIGHDEBUG
extern int sleighdebug;
#endif

/* Token type.  */
#ifndef SLEIGHTOKENTYPE
# define SLEIGHTOKENTYPE
  enum sleightokentype
  {
    OP_BOOL_OR = 258,
    OP_BOOL_AND = 259,
    OP_BOOL_XOR = 260,
    OP_OR = 261,
    OP_XOR = 262,
    OP_AND = 263,
    OP_EQUAL = 264,
    OP_NOTEQUAL = 265,
    OP_FEQUAL = 266,
    OP_FNOTEQUAL = 267,
    OP_GREATEQUAL = 268,
    OP_LESSEQUAL = 269,
    OP_SLESS = 270,
    OP_SGREATEQUAL = 271,
    OP_SLESSEQUAL = 272,
    OP_SGREAT = 273,
    OP_FLESS = 274,
    OP_FGREAT = 275,
    OP_FLESSEQUAL = 276,
    OP_FGREATEQUAL = 277,
    OP_LEFT = 278,
    OP_RIGHT = 279,
    OP_SRIGHT = 280,
    OP_FADD = 281,
    OP_FSUB = 282,
    OP_SDIV = 283,
    OP_SREM = 284,
    OP_FMULT = 285,
    OP_FDIV = 286,
    OP_ZEXT = 287,
    OP_CARRY = 288,
    OP_BORROW = 289,
    OP_SEXT = 290,
    OP_SCARRY = 291,
    OP_SBORROW = 292,
    OP_NAN = 293,
    OP_ABS = 294,
    OP_SQRT = 295,
    OP_CEIL = 296,
    OP_FLOOR = 297,
    OP_ROUND = 298,
    OP_INT2FLOAT = 299,
    OP_FLOAT2FLOAT = 300,
    OP_TRUNC = 301,
    OP_CPOOLREF = 302,
    OP_NEW = 303,
    OP_POPCOUNT = 304,
    OP_LZCOUNT = 305,
    BADINTEGER = 306,
    GOTO_KEY = 307,
    CALL_KEY = 308,
    RETURN_KEY = 309,
    IF_KEY = 310,
    DEFINE_KEY = 311,
    ATTACH_KEY = 312,
    MACRO_KEY = 313,
    SPACE_KEY = 314,
    TYPE_KEY = 315,
    RAM_KEY = 316,
    DEFAULT_KEY = 317,
    REGISTER_KEY = 318,
    ENDIAN_KEY = 319,
    WITH_KEY = 320,
    ALIGN_KEY = 321,
    OP_UNIMPL = 322,
    TOKEN_KEY = 323,
    SIGNED_KEY = 324,
    NOFLOW_KEY = 325,
    HEX_KEY = 326,
    DEC_KEY = 327,
    BIG_KEY = 328,
    LITTLE_KEY = 329,
    SIZE_KEY = 330,
    WORDSIZE_KEY = 331,
    OFFSET_KEY = 332,
    NAMES_KEY = 333,
    VALUES_KEY = 334,
    VARIABLES_KEY = 335,
    PCODEOP_KEY = 336,
    IS_KEY = 337,
    LOCAL_KEY = 338,
    DELAYSLOT_KEY = 339,
    CROSSBUILD_KEY = 340,
    EXPORT_KEY = 341,
    BUILD_KEY = 342,
    CONTEXT_KEY = 343,
    ELLIPSIS_KEY = 344,
    GLOBALSET_KEY = 345,
    BITRANGE_KEY = 346,
    CHAR = 347,
    INTEGER = 348,
    INTB = 349,
    STRING = 350,
    SYMBOLSTRING = 351,
    SPACESYM = 352,
    SECTIONSYM = 353,
    TOKENSYM = 354,
    USEROPSYM = 355,
    VALUESYM = 356,
    VALUEMAPSYM = 357,
    CONTEXTSYM = 358,
    NAMESYM = 359,
    VARSYM = 360,
    BITSYM = 361,
    SPECSYM = 362,
    VARLISTSYM = 363,
    OPERANDSYM = 364,
    JUMPSYM = 365,
    MACROSYM = 366,
    LABELSYM = 367,
    SUBTABLESYM = 368
  };
#endif

/* Value type.  */
#if ! defined SLEIGHSTYPE && ! defined SLEIGHSTYPE_IS_DECLARED
union SLEIGHSTYPE
{

  char ch;
  uintb *i;
  intb *big;
  string *str;
  vector<string> *strlist;
  vector<intb> *biglist;
  vector<ExprTree *> *param;
  SpaceQuality *spacequal;
  FieldQuality *fieldqual;
  StarQuality *starqual;
  VarnodeTpl *varnode;
  ExprTree *tree;
  vector<OpTpl *> *stmt;
  ConstructTpl *sem;
  SectionVector *sectionstart;
  Constructor *construct;
  PatternEquation *pateq;
  PatternExpression *patexp;

  vector<SleighSymbol *> *symlist;
  vector<ContextChange *> *contop;
  SleighSymbol *anysym;
  SpaceSymbol *spacesym;
  SectionSymbol *sectionsym;
  TokenSymbol *tokensym;
  UserOpSymbol *useropsym;
  MacroSymbol *macrosym;
  LabelSymbol *labelsym;
  SubtableSymbol *subtablesym;
  OperandSymbol *operandsym;
  VarnodeListSymbol *varlistsym;
  VarnodeSymbol *varsym;
  BitrangeSymbol *bitsym;
  NameSymbol *namesym;
  ValueSymbol *valuesym;
  ValueMapSymbol *valuemapsym;
  ContextSymbol *contextsym;
  FamilySymbol *famsym;
  SpecificSymbol *specsym;


};
typedef union SLEIGHSTYPE SLEIGHSTYPE;
# define SLEIGHSTYPE_IS_TRIVIAL 1
# define SLEIGHSTYPE_IS_DECLARED 1
#endif


extern SLEIGHSTYPE sleighlval;

int sleighparse (void);

#endif /* !YY_SLEIGH_SLGHPARSE_HH_INCLUDED  */



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

#if ! defined yyoverflow || YYERROR_VERBOSE

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
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


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

#define YYUNDEFTOK  2
#define YYMAXUTOK   368


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

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
     450,   452,   453,   454,   455,   457,   458,   459,   460,   461,
     462,   463,   465,   466,   467,   468,   470,   471,   472,   473,
     474,   476,   477,   478,   480,   481,   483,   484,   485,   486,
     487,   488,   490,   491,   492,   493,   494,   496,   497,   498,
     499,   501,   502,   504,   505,   506,   508,   509,   510,   512,
     513,   514,   517,   518,   520,   521,   522,   524,   526,   527,
     528,   529,   531,   532,   533,   535,   536,   537,   538,   539,
     541,   542,   544,   545,   547,   548,   551,   552,   553,   555,
     556,   557,   559,   560,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,   571,   572,   573
};
#endif

#if SLEIGHDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "OP_BOOL_OR", "OP_BOOL_AND",
  "OP_BOOL_XOR", "'|'", "OP_OR", "';'", "'^'", "OP_XOR", "'&'", "OP_AND",
  "OP_EQUAL", "OP_NOTEQUAL", "OP_FEQUAL", "OP_FNOTEQUAL", "'<'", "'>'",
  "OP_GREATEQUAL", "OP_LESSEQUAL", "OP_SLESS", "OP_SGREATEQUAL",
  "OP_SLESSEQUAL", "OP_SGREAT", "OP_FLESS", "OP_FGREAT", "OP_FLESSEQUAL",
  "OP_FGREATEQUAL", "OP_LEFT", "OP_RIGHT", "OP_SRIGHT", "'+'", "'-'",
  "OP_FADD", "OP_FSUB", "'*'", "'/'", "'%'", "OP_SDIV", "OP_SREM",
  "OP_FMULT", "OP_FDIV", "'!'", "'~'", "OP_ZEXT", "OP_CARRY", "OP_BORROW",
  "OP_SEXT", "OP_SCARRY", "OP_SBORROW", "OP_NAN", "OP_ABS", "OP_SQRT",
  "OP_CEIL", "OP_FLOOR", "OP_ROUND", "OP_INT2FLOAT", "OP_FLOAT2FLOAT",
  "OP_TRUNC", "OP_CPOOLREF", "OP_NEW", "OP_POPCOUNT", "OP_LZCOUNT",
  "BADINTEGER", "GOTO_KEY", "CALL_KEY", "RETURN_KEY", "IF_KEY",
  "DEFINE_KEY", "ATTACH_KEY", "MACRO_KEY", "SPACE_KEY", "TYPE_KEY",
  "RAM_KEY", "DEFAULT_KEY", "REGISTER_KEY", "ENDIAN_KEY", "WITH_KEY",
  "ALIGN_KEY", "OP_UNIMPL", "TOKEN_KEY", "SIGNED_KEY", "NOFLOW_KEY",
  "HEX_KEY", "DEC_KEY", "BIG_KEY", "LITTLE_KEY", "SIZE_KEY",
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
#endif

# ifdef YYPRINT
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
# endif

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


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
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

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



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
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep);
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
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, int yyrule)
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
                       yystos[+yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              );
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
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
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


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
#  else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                yy_state_t *yyssp, int yytoken)
{
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Actual size of YYARG. */
  int yycount = 0;
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[+*yyssp];
      YYPTRDIFF_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
      yysize = yysize0;
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYPTRDIFF_T yysize1
                    = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    /* Don't count the "%s"s in the final size, but reserve room for
       the terminator.  */
    YYPTRDIFF_T yysize1 = yysize + (yystrlen (yyformat) - 2 * yycount) + 1;
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
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
    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYPTRDIFF_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
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
# undef YYSTACK_RELOCATE
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

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
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
  yychar = YYEMPTY;
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
  case 19:
                                       { slgh->resetConstructors(); }
    break;

  case 20:
                                                 { slgh->setEndian(1); }
    break;

  case 21:
                                             { slgh->setEndian(0); }
    break;

  case 22:
                                               { slgh->setAlignment(*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 23:
                                       {}
    break;

  case 24:
                                                       { (yyval.tokensym) = slgh->defineToken((yyvsp[-3].str),(yyvsp[-1].i),0); }
    break;

  case 25:
                                                                          { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),-1); }
    break;

  case 26:
                                                                       { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),1); }
    break;

  case 27:
                                       { (yyval.tokensym) = (yyvsp[-1].tokensym); slgh->addTokenField((yyvsp[-1].tokensym),(yyvsp[0].fieldqual)); }
    break;

  case 28:
                                       { string errmsg=(yyvsp[0].anysym)->getName()+": redefined as a token"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 29:
                                       {}
    break;

  case 30:
                                           { (yyval.varsym) = (yyvsp[0].varsym); }
    break;

  case 31:
                                         { (yyval.varsym) = (yyvsp[-1].varsym); if (!slgh->addContextField( (yyvsp[-1].varsym), (yyvsp[0].fieldqual) ))
                                            { slgh->reportError("All context definitions must come before constructors"); YYERROR; } }
    break;

  case 32:
                                                 { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
    break;

  case 33:
                                              { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 34:
                                        { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
    break;

  case 35:
                                        { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
    break;

  case 36:
                                        { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
    break;

  case 37:
                                                        { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
    break;

  case 38:
                                              { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 39:
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
    break;

  case 40:
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->flow = false; }
    break;

  case 41:
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
    break;

  case 42:
                                                { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
    break;

  case 43:
                                        { slgh->newSpace((yyvsp[-1].spacequal)); }
    break;

  case 44:
                                        { (yyval.spacequal) = new SpaceQuality(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 45:
                                        { string errmsg = (yyvsp[0].anysym)->getName()+": redefined as space"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 46:
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::ramtype; }
    break;

  case 47:
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::registertype; }
    break;

  case 48:
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->size = *(yyvsp[0].i); delete (yyvsp[0].i); }
    break;

  case 49:
                                        { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->wordsize = *(yyvsp[0].i); delete (yyvsp[0].i); }
    break;

  case 50:
                                        { (yyval.spacequal) = (yyvsp[-1].spacequal); (yyval.spacequal)->isdefault = true; }
    break;

  case 51:
                                                                                           {
               slgh->defineVarnodes((yyvsp[-8].spacesym),(yyvsp[-5].i),(yyvsp[-2].i),(yyvsp[-1].strlist)); }
    break;

  case 52:
                                                  { slgh->reportError("Parsed integer is too big (overflow)"); YYERROR; }
    break;

  case 56:
                                                              {
               slgh->defineBitrange((yyvsp[-7].str),(yyvsp[-5].varsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i); delete (yyvsp[-1].i); }
    break;

  case 57:
                                                  { slgh->addUserOp((yyvsp[-1].strlist)); }
    break;

  case 58:
                                                          { slgh->attachValues((yyvsp[-2].symlist),(yyvsp[-1].biglist)); }
    break;

  case 59:
                                                             { slgh->attachNames((yyvsp[-2].symlist),(yyvsp[-1].strlist)); }
    break;

  case 60:
                                                          { slgh->attachVarnodes((yyvsp[-2].symlist),(yyvsp[-1].symlist)); }
    break;

  case 61:
                                        { slgh->buildMacro((yyvsp[-3].macrosym),(yyvsp[-1].sem)); }
    break;

  case 62:
                                                                       {  slgh->pushWith((yyvsp[-4].subtablesym),(yyvsp[-2].pateq),(yyvsp[-1].contop)); }
    break;

  case 66:
                             { slgh->popWith(); }
    break;

  case 67:
                        { (yyval.subtablesym) = (SubtableSymbol *)0; }
    break;

  case 68:
                        { (yyval.subtablesym) = (yyvsp[0].subtablesym); }
    break;

  case 69:
                        { (yyval.subtablesym) = slgh->newTable((yyvsp[0].str)); }
    break;

  case 70:
                           { (yyval.pateq) = (PatternEquation *)0; }
    break;

  case 71:
                           { (yyval.pateq) = (yyvsp[0].pateq); }
    break;

  case 72:
                                            { (yyval.macrosym) = slgh->createMacro((yyvsp[-3].str),(yyvsp[-1].strlist)); }
    break;

  case 73:
                     { (yyval.sectionstart) = slgh->standaloneSection((yyvsp[-1].sem)); }
    break;

  case 74:
                               { (yyval.sectionstart) = slgh->finalNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem)); }
    break;

  case 75:
                     { (yyval.sectionstart) = (SectionVector *)0; }
    break;

  case 76:
                                                                  { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
    break;

  case 77:
                                                                  { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
    break;

  case 78:
                                        { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 79:
                                        { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 80:
                                        { (yyval.construct) = (yyvsp[-1].construct); if (slgh->isInRoot((yyvsp[-1].construct))) { (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); } else slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
    break;

  case 81:
                                                { (yyval.construct) = (yyvsp[-1].construct); if (!slgh->isInRoot((yyvsp[-1].construct))) { slgh->reportError("Unexpected '^' at start of print pieces");  YYERROR; } }
    break;

  case 82:
                                                { (yyval.construct) = (yyvsp[-1].construct); }
    break;

  case 83:
                                                { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 84:
                                        { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 85:
                                                { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(string(" ")); }
    break;

  case 86:
                                        { (yyval.construct) = (yyvsp[-1].construct); slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
    break;

  case 87:
                                { (yyval.construct) = slgh->createConstructor((yyvsp[-1].subtablesym)); }
    break;

  case 88:
                                                { SubtableSymbol *sym=slgh->newTable((yyvsp[-1].str)); (yyval.construct) = slgh->createConstructor(sym); }
    break;

  case 89:
                                                        { (yyval.construct) = slgh->createConstructor((SubtableSymbol *)0); }
    break;

  case 90:
                                        { (yyval.construct) = (yyvsp[-1].construct); }
    break;

  case 91:
                                        { (yyval.patexp) = new ConstantValue(*(yyvsp[0].big)); delete (yyvsp[0].big); }
    break;

  case 92:
                                        { if ((actionon==1)&&((yyvsp[0].famsym)->getType() != SleighSymbol::context_symbol))
                                             { string errmsg="Global symbol "+(yyvsp[0].famsym)->getName(); errmsg += " is not allowed in action expression"; slgh->reportError(errmsg); } (yyval.patexp) = (yyvsp[0].famsym)->getPatternValue(); }
    break;

  case 93:
                                        { (yyval.patexp) = (yyvsp[0].specsym)->getPatternExpression(); }
    break;

  case 94:
                                        { (yyval.patexp) = (yyvsp[-1].patexp); }
    break;

  case 95:
                                        { (yyval.patexp) = new PlusExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 96:
                                        { (yyval.patexp) = new SubExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 97:
                                        { (yyval.patexp) = new MultExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 98:
                                        { (yyval.patexp) = new LeftShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 99:
                                        { (yyval.patexp) = new RightShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 100:
                                        { (yyval.patexp) = new AndExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 101:
                                        { (yyval.patexp) = new OrExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 102:
                                        { (yyval.patexp) = new XorExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 103:
                                        { (yyval.patexp) = new DivExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
    break;

  case 104:
                                        { (yyval.patexp) = new MinusExpression((yyvsp[0].patexp)); }
    break;

  case 105:
                                        { (yyval.patexp) = new NotExpression((yyvsp[0].patexp)); }
    break;

  case 107:
                                        { (yyval.pateq) = new EquationAnd((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
    break;

  case 108:
                                        { (yyval.pateq) = new EquationOr((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
    break;

  case 109:
                                        { (yyval.pateq) = new EquationCat((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
    break;

  case 110:
                                        { (yyval.pateq) = new EquationLeftEllipsis((yyvsp[0].pateq)); }
    break;

  case 112:
                                        { (yyval.pateq) = new EquationRightEllipsis((yyvsp[-1].pateq)); }
    break;

  case 115:
                                        { (yyval.pateq) = (yyvsp[-1].pateq); }
    break;

  case 116:
                                         { (yyval.pateq) = new EqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 117:
                                         { (yyval.pateq) = new NotEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 118:
                                        { (yyval.pateq) = new LessEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 119:
                                          { (yyval.pateq) = new LessEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 120:
                                        { (yyval.pateq) = new GreaterEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 121:
                                           { (yyval.pateq) = new GreaterEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
    break;

  case 122:
                                        { (yyval.pateq) = slgh->constrainOperand((yyvsp[-2].operandsym),(yyvsp[0].patexp)); 
                                          if ((yyval.pateq) == (PatternEquation *)0) 
                                            { string errmsg="Constraining currently undefined operand "+(yyvsp[-2].operandsym)->getName(); slgh->reportError(errmsg); } }
    break;

  case 123:
                                        { (yyval.pateq) = new OperandEquation((yyvsp[0].operandsym)->getIndex()); slgh->selfDefine((yyvsp[0].operandsym)); }
    break;

  case 124:
                                        { (yyval.pateq) = new UnconstrainedEquation((yyvsp[0].specsym)->getPatternExpression()); }
    break;

  case 125:
                                        { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].famsym)); }
    break;

  case 126:
                                        { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].subtablesym)); }
    break;

  case 127:
                                        { (yyval.contop) = (vector<ContextChange *> *)0; }
    break;

  case 128:
                                        { (yyval.contop) = (yyvsp[-1].contop); }
    break;

  case 129:
                                        { (yyval.contop) = new vector<ContextChange *>; }
    break;

  case 130:
                                                { (yyval.contop) = (yyvsp[-4].contop); if (!slgh->contextMod((yyvsp[-4].contop),(yyvsp[-3].contextsym),(yyvsp[-1].patexp))) { string errmsg="Cannot use 'inst_next' or 'inst_next2' to set context variable: "+(yyvsp[-3].contextsym)->getName(); slgh->reportError(errmsg); YYERROR; } }
    break;

  case 131:
                                                                      { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].famsym),(yyvsp[-2].contextsym)); }
    break;

  case 132:
                                                                        { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].specsym),(yyvsp[-2].contextsym)); }
    break;

  case 133:
                                               { (yyval.contop) = (yyvsp[-4].contop); slgh->defineOperand((yyvsp[-3].operandsym),(yyvsp[-1].patexp)); }
    break;

  case 134:
                                        { string errmsg="Expecting context symbol, not "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 135:
                                        { (yyval.sectionsym) = slgh->newSectionSymbol( *(yyvsp[-1].str) ); delete (yyvsp[-1].str); }
    break;

  case 136:
                                        { (yyval.sectionsym) = (yyvsp[-1].sectionsym); }
    break;

  case 137:
                                        { (yyval.sectionstart) = slgh->firstNamedSection((yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
    break;

  case 138:
                             { (yyval.sectionstart) = (yyvsp[0].sectionstart); }
    break;

  case 139:
                                        { (yyval.sectionstart) = slgh->nextNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
    break;

  case 140:
            { (yyval.sem) = (yyvsp[0].sem); if ((yyval.sem)->getOpvec().empty() && ((yyval.sem)->getResult() == (HandleTpl *)0)) slgh->recordNop(); }
    break;

  case 141:
                                        { (yyval.sem) = slgh->setResultVarnode((yyvsp[-3].sem),(yyvsp[-1].varnode)); }
    break;

  case 142:
                                               { (yyval.sem) = slgh->setResultStarVarnode((yyvsp[-4].sem),(yyvsp[-2].starqual),(yyvsp[-1].varnode)); }
    break;

  case 143:
                                        { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 144:
                                        { string errmsg="Unknown pointer varnode: "+*(yyvsp[0].str); delete (yyvsp[-1].starqual); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 145:
                                        { (yyval.sem) = slgh->enterSection(); }
    break;

  case 146:
                                        { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[0].stmt); slgh->reportError("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }
    break;

  case 147:
                                { (yyval.sem) = (yyvsp[-3].sem); slgh->pcode.newLocalDefinition((yyvsp[-1].str)); }
    break;

  case 148:
                                            { (yyval.sem) = (yyvsp[-5].sem); slgh->pcode.newLocalDefinition((yyvsp[-3].str),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 149:
                                        { (yyvsp[-1].tree)->setOutput((yyvsp[-3].varnode)); (yyval.stmt) = ExprTree::toVector((yyvsp[-1].tree)); }
    break;

  case 150:
                                        { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-3].str)); }
    break;

  case 151:
                                        { (yyval.stmt) = slgh->pcode.newOutput(false,(yyvsp[-1].tree),(yyvsp[-3].str)); }
    break;

  case 152:
                                                { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
    break;

  case 153:
                                        { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
    break;

  case 154:
                                 { (yyval.stmt) = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+(yyvsp[-1].specsym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 155:
                                        { (yyval.stmt) = slgh->pcode.createStore((yyvsp[-4].starqual),(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 156:
                                        { (yyval.stmt) = slgh->pcode.createUserOpNoOut((yyvsp[-4].useropsym),(yyvsp[-2].param)); }
    break;

  case 157:
                                                        { (yyval.stmt) = slgh->pcode.assignBitRange((yyvsp[-8].varnode),(uint4)*(yyvsp[-6].i),(uint4)*(yyvsp[-4].i),(yyvsp[-1].tree)); delete (yyvsp[-6].i), delete (yyvsp[-4].i); }
    break;

  case 158:
                                        { (yyval.stmt)=slgh->pcode.assignBitRange((yyvsp[-3].bitsym)->getParentSymbol()->getVarnode(),(yyvsp[-3].bitsym)->getBitOffset(),(yyvsp[-3].bitsym)->numBits(),(yyvsp[-1].tree)); }
    break;

  case 159:
                                        { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); slgh->reportError("Illegal truncation on left-hand side of assignment"); YYERROR; }
    break;

  case 160:
                                        { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); slgh->reportError("Illegal subpiece on left-hand side of assignment"); YYERROR; }
    break;

  case 161:
                                        { (yyval.stmt) = slgh->pcode.createOpConst(BUILD,(yyvsp[-1].operandsym)->getIndex()); }
    break;

  case 162:
                                              { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),(yyvsp[-1].sectionsym)); }
    break;

  case 163:
                                            { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),slgh->newSectionSymbol(*(yyvsp[-1].str))); delete (yyvsp[-1].str); }
    break;

  case 164:
                                        { (yyval.stmt) = slgh->pcode.createOpConst(DELAY_SLOT,*(yyvsp[-2].i)); delete (yyvsp[-2].i); }
    break;

  case 165:
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCH,new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 166:
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CBRANCH,new ExprTree((yyvsp[-1].varnode)),(yyvsp[-3].tree)); }
    break;

  case 167:
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCHIND,(yyvsp[-2].tree)); }
    break;

  case 168:
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALL,new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 169:
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALLIND,(yyvsp[-2].tree)); }
    break;

  case 170:
                                        { slgh->reportError("Must specify an indirect parameter for return"); YYERROR; }
    break;

  case 171:
                                        { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_RETURN,(yyvsp[-2].tree)); }
    break;

  case 172:
                                        { (yyval.stmt) = slgh->createMacroUse((yyvsp[-4].macrosym),(yyvsp[-2].param)); }
    break;

  case 173:
                                        { (yyval.stmt) = slgh->pcode.placeLabel( (yyvsp[0].labelsym) ); }
    break;

  case 174:
              { (yyval.tree) = new ExprTree((yyvsp[0].varnode)); }
    break;

  case 175:
                                { (yyval.tree) = slgh->pcode.createLoad((yyvsp[-1].starqual),(yyvsp[0].tree)); }
    break;

  case 176:
                                { (yyval.tree) = (yyvsp[-1].tree); }
    break;

  case 177:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 178:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 179:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 180:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 181:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 182:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 183:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 184:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 185:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 186:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 187:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 188:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 189:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_2COMP,(yyvsp[0].tree)); }
    break;

  case 190:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NEGATE,(yyvsp[0].tree)); }
    break;

  case 191:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 192:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 193:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 194:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LEFT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 195:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_RIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 196:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SRIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 197:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 198:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 199:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SDIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 200:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_REM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 201:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SREM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 202:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_NEGATE,(yyvsp[0].tree)); }
    break;

  case 203:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 204:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 205:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 206:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 207:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 208:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 209:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 210:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 211:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
    break;

  case 212:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 213:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 214:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 215:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
    break;

  case 216:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NEG,(yyvsp[0].tree)); }
    break;

  case 217:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ABS,(yyvsp[-1].tree)); }
    break;

  case 218:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SQRT,(yyvsp[-1].tree)); }
    break;

  case 219:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SEXT,(yyvsp[-1].tree)); }
    break;

  case 220:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ZEXT,(yyvsp[-1].tree)); }
    break;

  case 221:
                                   { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_CARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 222:
                                    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SCARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 223:
                                     { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SBORROW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 224:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOAT2FLOAT,(yyvsp[-1].tree)); }
    break;

  case 225:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_INT2FLOAT,(yyvsp[-1].tree)); }
    break;

  case 226:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NAN,(yyvsp[-1].tree)); }
    break;

  case 227:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_TRUNC,(yyvsp[-1].tree)); }
    break;

  case 228:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_CEIL,(yyvsp[-1].tree)); }
    break;

  case 229:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOOR,(yyvsp[-1].tree)); }
    break;

  case 230:
                                { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ROUND,(yyvsp[-1].tree)); }
    break;

  case 231:
                            { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-1].tree)); }
    break;

  case 232:
                                 { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
    break;

  case 233:
                             { (yyval.tree) = slgh->pcode.createOp(CPUI_POPCOUNT,(yyvsp[-1].tree)); }
    break;

  case 234:
                            { (yyval.tree) = slgh->pcode.createOp(CPUI_LZCOUNT,(yyvsp[-1].tree)); }
    break;

  case 235:
                                          { (yyval.tree) = slgh->pcode.createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }
    break;

  case 236:
                                { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }
    break;

  case 237:
                                               { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }
    break;

  case 238:
                                { (yyval.tree)=slgh->pcode.createBitRange((yyvsp[0].bitsym)->getParentSymbol(),(yyvsp[0].bitsym)->getBitOffset(),(yyvsp[0].bitsym)->numBits()); }
    break;

  case 239:
                                { (yyval.tree) = slgh->pcode.createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }
    break;

  case 240:
                                   { if ((*(yyvsp[-1].param)).size() < 2) { string errmsg = "Must at least two inputs to cpool"; slgh->reportError(errmsg); YYERROR; } (yyval.tree) = slgh->pcode.createVariadic(CPUI_CPOOLREF,(yyvsp[-1].param)); }
    break;

  case 241:
                                            { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }
    break;

  case 242:
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }
    break;

  case 243:
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
    break;

  case 244:
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
    break;

  case 245:
                                { VarnodeTpl *sym = (yyvsp[0].specsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
    break;

  case 246:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }
    break;

  case 247:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); slgh->reportError("Parsed integer is too big (overflow)"); }
    break;

  case 248:
                                { (yyval.varnode) = (yyvsp[0].operandsym)->getVarnode(); (yyvsp[0].operandsym)->setCodeAddress(); }
    break;

  case 249:
                                { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }
    break;

  case 250:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }
    break;

  case 251:
                                { string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 252:
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 253:
                                { (yyval.varnode) = (yyvsp[0].varnode); }
    break;

  case 254:
                                { string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 255:
                                { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 256:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }
    break;

  case 257:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); slgh->reportError("Parsed integer is too big (overflow)"); }
    break;

  case 258:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
    break;

  case 259:
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
    break;

  case 260:
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 261:
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 262:
                                { string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 263:
                                { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 264:
                                { (yyval.labelsym) = (yyvsp[-1].labelsym); }
    break;

  case 265:
                                { (yyval.labelsym) = slgh->pcode.defineLabel( (yyvsp[-1].str) ); }
    break;

  case 266:
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
    break;

  case 267:
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
    break;

  case 268:
                                { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
    break;

  case 269:
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
    break;

  case 270:
                                { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 271:
                                { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }
    break;

  case 272:
                                { (yyval.famsym) = (yyvsp[0].valuesym); }
    break;

  case 273:
                                { (yyval.famsym) = (yyvsp[0].valuemapsym); }
    break;

  case 274:
                                { (yyval.famsym) = (yyvsp[0].contextsym); }
    break;

  case 275:
                                { (yyval.famsym) = (yyvsp[0].namesym); }
    break;

  case 276:
                                { (yyval.famsym) = (yyvsp[0].varlistsym); }
    break;

  case 277:
                                { (yyval.specsym) = (yyvsp[0].varsym); }
    break;

  case 278:
                                { (yyval.specsym) = (yyvsp[0].specsym); }
    break;

  case 279:
                                { (yyval.specsym) = (yyvsp[0].operandsym); }
    break;

  case 280:
                                { (yyval.specsym) = (yyvsp[0].specsym); }
    break;

  case 281:
                                { (yyval.str) = new string; (*(yyval.str)) += (yyvsp[0].ch); }
    break;

  case 282:
                                { (yyval.str) = (yyvsp[-1].str); (*(yyval.str)) += (yyvsp[0].ch); }
    break;

  case 283:
                                { (yyval.biglist) = (yyvsp[-1].biglist); }
    break;

  case 284:
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 285:
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 286:
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 287:
                                { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 288:
                                { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
    break;

  case 289:
                                { (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 290:
                                { (yyval.biglist) = (yyvsp[-2].biglist); (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
    break;

  case 291:
                                { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
    break;

  case 292:
                                { (yyval.strlist) = (yyvsp[-1].strlist); }
    break;

  case 293:
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 294:
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
    break;

  case 295:
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 296:
                                { string errmsg = (yyvsp[0].anysym)->getName()+": redefined"; slgh->reportError(errmsg); YYERROR; }
    break;

  case 297:
                                     { (yyval.strlist) = (yyvsp[-1].strlist); }
    break;

  case 298:
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
    break;

  case 299:
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( (yyvsp[0].anysym)->getName() ); }
    break;

  case 300:
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 301:
                                { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back((yyvsp[0].anysym)->getName()); }
    break;

  case 302:
                                { (yyval.symlist) = (yyvsp[-1].symlist); }
    break;

  case 303:
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
    break;

  case 304:
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 305:
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back( (yyvsp[0].valuesym) ); }
    break;

  case 306:
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 307:
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
    break;

  case 308:
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
    break;

  case 309:
                                { string errmsg = *(yyvsp[0].str)+": is not a value pattern"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
    break;

  case 310:
                                { (yyval.symlist) = (yyvsp[-1].symlist); }
    break;

  case 311:
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 312:
                                { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 313:
                                { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
				  (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
    break;

  case 314:
                                { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].varsym)); }
    break;

  case 315:
                                { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
    break;

  case 316:
                                { (yyval.param) = new vector<ExprTree *>; }
    break;

  case 317:
                                { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }
    break;

  case 318:
                                { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }
    break;

  case 319:
                                { (yyval.strlist) = new vector<string>; }
    break;

  case 320:
                                { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 321:
                                { (yyval.strlist) = (yyvsp[-2].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 322:
                                { (yyval.anysym) = (yyvsp[0].spacesym); }
    break;

  case 323:
                                { (yyval.anysym) = (yyvsp[0].sectionsym); }
    break;

  case 324:
                                { (yyval.anysym) = (yyvsp[0].tokensym); }
    break;

  case 325:
                                { (yyval.anysym) = (yyvsp[0].useropsym); }
    break;

  case 326:
                                { (yyval.anysym) = (yyvsp[0].macrosym); }
    break;

  case 327:
                                { (yyval.anysym) = (yyvsp[0].subtablesym); }
    break;

  case 328:
                                { (yyval.anysym) = (yyvsp[0].valuesym); }
    break;

  case 329:
                                { (yyval.anysym) = (yyvsp[0].valuemapsym); }
    break;

  case 330:
                                { (yyval.anysym) = (yyvsp[0].contextsym); }
    break;

  case 331:
                                { (yyval.anysym) = (yyvsp[0].namesym); }
    break;

  case 332:
                                { (yyval.anysym) = (yyvsp[0].varsym); }
    break;

  case 333:
                                { (yyval.anysym) = (yyvsp[0].varlistsym); }
    break;

  case 334:
                                { (yyval.anysym) = (yyvsp[0].operandsym); }
    break;

  case 335:
                                { (yyval.anysym) = (yyvsp[0].specsym); }
    break;

  case 336:
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
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

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
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *, YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
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

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
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
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

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


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
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
                  yystos[+*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}


int sleigherror(const char *s)

{
  slgh->reportError(s);
  return 0;
}

} // End namespace ghidra

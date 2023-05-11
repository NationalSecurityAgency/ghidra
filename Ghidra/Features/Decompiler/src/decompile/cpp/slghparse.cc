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
/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

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

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

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

/* Copy the first part of user declarations.  */


#include "slgh_compile.hh"

extern FILE *sleighin;
extern int sleighlex(void);

namespace ghidra {

extern SleighCompile *slgh;
extern int4 actionon;
extern int sleighdebug;
extern int sleigherror(const char *str );



# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "slghparse.hh".  */
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
    STARTSYM = 365,
    ENDSYM = 366,
    NEXT2SYM = 367,
    MACROSYM = 368,
    LABELSYM = 369,
    SUBTABLESYM = 370
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
  StartSymbol *startsym;
  EndSymbol *endsym;
  Next2Symbol *next2sym;
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

/* Copy the second part of user declarations.  */



#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

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

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
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
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
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
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
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
#define YYLAST   2665

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  139
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  71
/* YYNRULES -- Number of rules.  */
#define YYNRULES  342
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  720

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   370

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
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
static const yytype_uint16 yyrline[] =
{
       0,   160,   160,   161,   162,   163,   165,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   176,   177,   178,   179,
     181,   182,   184,   186,   188,   189,   190,   191,   192,   194,
     196,   197,   200,   201,   202,   203,   204,   206,   207,   208,
     209,   210,   211,   213,   215,   216,   217,   218,   219,   220,
     221,   223,   225,   227,   229,   230,   232,   235,   237,   239,
     241,   243,   246,   248,   249,   250,   252,   254,   255,   256,
     259,   260,   263,   265,   266,   267,   269,   270,   272,   273,
     274,   275,   276,   277,   278,   279,   280,   282,   283,   284,
     285,   287,   289,   292,   293,   294,   295,   296,   297,   298,
     299,   300,   301,   302,   303,   304,   306,   307,   308,   309,
     311,   312,   314,   315,   317,   318,   320,   321,   322,   323,
     324,   325,   326,   329,   330,   331,   332,   334,   335,   337,
     338,   339,   340,   341,   342,   344,   345,   347,   349,   350,
     352,   353,   354,   355,   356,   358,   359,   360,   361,   363,
     364,   365,   366,   367,   368,   369,   370,   371,   372,   373,
     374,   375,   376,   377,   378,   379,   380,   381,   382,   383,
     384,   385,   386,   387,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   457,   458,   459,   460,   462,   463,   464,   465,   466,
     467,   468,   469,   470,   472,   473,   474,   475,   477,   478,
     479,   480,   481,   483,   484,   485,   487,   488,   490,   491,
     492,   493,   494,   495,   497,   498,   499,   500,   501,   503,
     504,   505,   506,   507,   508,   510,   511,   513,   514,   515,
     517,   518,   519,   521,   522,   523,   526,   527,   529,   530,
     531,   533,   535,   536,   537,   538,   540,   541,   542,   544,
     545,   546,   547,   548,   550,   551,   553,   554,   556,   557,
     560,   561,   562,   564,   565,   566,   568,   569,   570,   571,
     572,   573,   574,   575,   576,   577,   578,   579,   580,   581,
     582,   583,   584
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
  "SPECSYM", "VARLISTSYM", "OPERANDSYM", "STARTSYM", "ENDSYM", "NEXT2SYM",
  "MACROSYM", "LABELSYM", "SUBTABLESYM", "'}'", "'='", "'('", "')'", "','",
  "'['", "']'", "'{'", "':'", "' '", "$accept", "spec", "definition",
  "constructorlike", "endiandef", "aligndef", "tokendef", "tokenprop",
  "contextdef", "contextprop", "fielddef", "contextfielddef", "spacedef",
  "spaceprop", "varnodedef", "bitrangedef", "bitrangelist",
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
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
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
     362,   363,   364,   365,   366,   367,   368,   369,   370,   125,
      61,    40,    41,    44,    91,    93,   123,    58,    32
};
# endif

#define YYPACT_NINF -339

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-339)))

#define YYTABLE_NINF -273

#define yytable_value_is_error(Yytable_value) \
  (!!((Yytable_value) == (-273)))

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -20,    14,    11,  -339,   -32,  -339,    -3,   213,   336,     6,
     -75,    -4,    12,  -339,  -339,  -339,  -339,  -339,   425,  -339,
    1512,  -339,   216,  -339,  -339,  -339,  -339,  -339,  -339,  -339,
    -339,    39,  -339,   -31,  -339,    27,    50,    98,  -339,  -339,
    2499,    47,  2518,   -82,    61,   101,   185,   -21,   -21,   -21,
     137,  -339,  -339,   151,  -339,  -339,  -339,   165,  -339,  -339,
    -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,
    -339,  -339,  -339,  -339,  -339,   244,   167,  -339,   171,   253,
     186,  -339,   200,  -339,   220,   266,   230,  -339,  -339,  -339,
    -339,  -339,  2345,  -339,  -339,  -339,  -339,   297,  -339,  2345,
    -339,  -339,  -339,   297,   314,   400,  -339,  -339,   311,   288,
    -339,  -339,   317,   424,  -339,   307,    -2,  -339,   331,  -339,
    -339,     7,   300,   -23,   -93,   334,  2345,   329,  -339,  -339,
    -339,   332,   344,  -339,  -339,  -339,  -339,   345,    95,   356,
     371,   349,  1667,   399,  -339,  -339,  -339,  -339,  -339,  -339,
     357,  -339,  2345,    16,  -339,  -339,   378,  -339,    56,  -339,
      16,  -339,  -339,   478,   382,  -339,  2367,  -339,   375,  -339,
    -339,   -19,  -339,  -339,   192,  2537,   504,   411,  -339,    10,
     510,  -339,   -61,   514,  -339,    68,   389,   304,   418,   419,
     420,   422,  -339,  -339,  -339,  -339,  -339,   287,   -71,   -22,
    -339,   330,  1546,    23,   446,  1538,   401,    74,  1596,   423,
     426,   -38,   429,  -339,   427,  -339,  -339,  -339,  -339,  -339,
     436,   -76,  -339,   446,   -53,  -339,    57,  -339,    59,  -339,
    1696,    24,  2345,  2345,  2345,  -339,   -59,  -339,  1696,  1696,
    1696,  1696,  1696,  1696,   -59,  -339,   440,  -339,  -339,  -339,
     397,  -339,   467,  -339,  -339,  -339,  -339,  -339,  2393,  -339,
    -339,  -339,   474,  -339,  -339,    55,  -339,  -339,  -339,   178,
    -339,  -339,   465,   445,   451,   452,   461,   462,  -339,  -339,
     491,  -339,  -339,   581,   616,   525,   531,  -339,   505,  -339,
    -339,  -339,  -339,  -339,   446,   666,  -339,   446,   669,  -339,
     446,   446,   446,   446,   446,   544,   548,   579,   580,   586,
     589,   626,   629,   662,   663,   671,   673,   704,   709,   714,
     749,   754,   789,   790,  -339,   446,  1819,   446,  -339,    44,
       0,   582,   612,   625,   298,   744,   915,  -339,  1491,   952,
    -339,   955,   735,   446,   855,   446,   446,   446,  1553,   894,
     895,   446,   897,  1696,  1696,  -339,  1696,  2379,  -339,  -339,
    -339,   279,  1029,  -339,   217,  -339,  -339,  -339,  2379,  2379,
    2379,  2379,  2379,  2379,  -339,   964,   937,   950,  -339,  -339,
    -339,  -339,   975,  -339,  -339,  -339,  -339,  -339,  -339,  -339,
    -339,   977,  1014,  1015,  1017,    74,  -339,  -339,  1025,  -339,
    1051,   350,  -339,   587,  -339,   627,  -339,  -339,  -339,  -339,
     446,   446,   446,   446,   446,   446,   446,   446,   446,   446,
     446,   446,   446,   446,   446,   446,   446,   446,   446,   833,
     446,   446,   446,   446,   446,   446,   446,   446,   446,   446,
     446,   446,   446,   446,   446,   446,   446,   446,   446,   446,
     446,   446,   446,   446,   446,   446,   446,   446,   446,   446,
     446,   446,   446,   446,   446,   446,  1584,  -339,    60,  1057,
    1094,  -339,   446,  1095,  -339,  1071,   -45,  1134,  -339,  1135,
    1235,  -339,  1272,  -339,  -339,  -339,  -339,  1872,  1151,  2192,
      96,  1912,   225,   446,  1188,  1191,  1952,  1150,  -339,  -339,
      32,  1696,  1696,  1696,  1696,  1696,  1696,  1696,  1696,  1696,
    1192,  -339,  1230,  1231,  -339,  -339,  -339,    -9,  1270,  1268,
    1257,  -339,  1271,  1308,  1309,  1311,  -339,  1343,  1346,  1475,
    1515,  1552,   873,   710,   913,   750,   792,   953,   993,  1033,
    1073,  1113,  1153,  1193,  1233,  1273,   267,   667,  1313,  1353,
     281,  -339,  2231,  2268,  2268,  2302,  2334,  2404,  2512,  2512,
    2512,  2512,  2538,  2538,  2538,  2538,  2538,  2538,  2538,  2538,
    2538,  2538,  2538,  2538,  2416,  2416,  2416,   409,   409,   409,
     409,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  1588,  1389,
    1428,  -339,  1992,    30,  1589,  1590,  1592,    74,  -339,  -339,
    -339,   446,  1594,   446,  -339,  1595,  2032,  -339,  -339,  -339,
    1498,  -339,   546,  2569,   312,   237,   237,   394,   394,  -339,
    -339,  1748,  1696,  1696,  1630,   235,  -339,  -339,   353,  1500,
     -82,  -339,  -339,  -339,  -339,  1502,  -339,  -339,  -339,  -339,
    -339,   446,  -339,   446,   446,  -339,  -339,  -339,  -339,  -339,
    -339,  -339,  -339,  -339,  -339,  -339,   446,  -339,  -339,  -339,
    -339,  -339,  1506,  -339,  -339,   446,  -339,  -339,  -339,  -339,
    2072,  -339,  2192,  -339,  -339,  1482,  1485,  1488,  1769,  2370,
    -339,  -339,  1609,  1612,  -339,  -339,  1508,  1636,  -339,  1393,
    1433,  1473,  1513,  1514,  2112,  -339,  1520,  1535,  1537,  -339,
    -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,
    -339,   446,  1523,  1525,  2152,  1656,  1657,  -339,  -339,  -339
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       0,     0,     0,     2,     0,     1,     0,     0,     0,     0,
      67,     0,     0,    89,     4,     5,     3,     6,     0,     7,
       0,     8,     0,     9,    10,    11,    12,    13,    14,    17,
      63,     0,    18,     0,    16,     0,     0,     0,    15,    19,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    69,    68,     0,    88,    87,    23,     0,   326,   327,
     328,   329,   332,   333,   334,   335,   336,   342,   337,   338,
     339,   340,   341,   330,   331,    27,     0,    29,     0,    31,
       0,    43,     0,    50,     0,     0,     0,    66,    64,    65,
     145,    82,     0,   285,    83,    86,    85,    84,    81,     0,
      78,    80,    90,    79,     0,     0,    44,    45,     0,     0,
      28,   297,     0,     0,    30,     0,     0,    54,     0,   307,
     308,     0,     0,     0,     0,   323,    70,     0,    34,    35,
      36,     0,     0,    39,    40,    41,    42,     0,     0,     0,
       0,     0,   140,     0,   274,   275,   276,   277,   124,   278,
     123,   126,     0,   127,   106,   111,   113,   114,   125,   286,
     127,    20,    21,     0,     0,   298,     0,    57,     0,    53,
      55,     0,   309,   310,     0,     0,     0,     0,   288,     0,
       0,   315,     0,     0,   324,     0,   127,    71,     0,     0,
       0,     0,    46,    47,    48,    49,    61,     0,     0,   244,
     259,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     258,   256,     0,   279,     0,   280,   281,   282,   283,   284,
       0,   257,   146,     0,     0,   255,     0,   173,   254,   110,
       0,     0,     0,     0,     0,   129,     0,   112,     0,     0,
       0,     0,     0,     0,     0,    22,     0,   299,   296,   300,
       0,    52,     0,   313,   311,   312,   306,   302,     0,   303,
      59,   289,     0,   290,   292,     0,    58,   317,   316,     0,
      60,    72,     0,     0,     0,     0,     0,     0,   256,   257,
       0,   261,   254,     0,     0,     0,     0,   249,   248,   253,
     250,   245,   246,   247,     0,     0,   252,     0,     0,   170,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   238,     0,     0,     0,   174,   254,
       0,     0,     0,     0,     0,     0,   143,   273,     0,     0,
     268,     0,     0,     0,     0,   320,     0,   320,     0,     0,
       0,     0,     0,     0,     0,    91,     0,   122,    92,    93,
     115,   108,   109,   107,     0,    75,   145,    76,   117,   118,
     120,   121,   119,   116,    77,    24,     0,     0,   304,   301,
     305,   291,     0,   293,   295,   287,   319,   318,   314,   325,
      62,     0,     0,     0,     0,     0,   267,   266,     0,   243,
       0,     0,   165,     0,   168,     0,   189,   216,   202,   190,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   320,     0,     0,     0,   320,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   175,     0,     0,
       0,   147,     0,     0,   154,     0,     0,     0,   269,     0,
     144,   265,     0,   263,   141,   161,   260,     0,     0,   321,
       0,     0,     0,     0,     0,     0,     0,     0,   104,   105,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   134,     0,     0,   128,   138,   145,     0,     0,     0,
       0,   294,     0,     0,     0,     0,   262,   242,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   176,   205,   204,   203,   193,   191,   192,   179,   180,
     206,   207,   181,   184,   182,   183,   185,   186,   187,   188,
     208,   209,   210,   211,   194,   195,   196,   177,   178,   212,
     213,   197,   198,   200,   199,   201,   214,   215,     0,     0,
       0,   236,     0,     0,     0,     0,     0,     0,   271,   142,
     151,     0,     0,     0,   158,     0,     0,   160,   159,   149,
       0,    94,   101,   102,   100,    98,    99,    95,    96,    97,
     103,     0,     0,     0,     0,     0,    73,   137,     0,     0,
       0,    32,    33,    37,    38,     0,   251,   167,   169,   171,
     220,     0,   219,     0,     0,   226,   217,   218,   228,   229,
     230,   225,   224,   227,   240,   231,     0,   233,   234,   239,
     166,   235,     0,   150,   148,     0,   164,   163,   162,   270,
       0,   156,   322,   172,   155,     0,     0,     0,     0,     0,
      74,   139,     0,     0,    26,    25,     0,     0,   241,     0,
       0,     0,     0,     0,     0,   153,     0,     0,     0,   130,
     133,   135,   136,    56,    51,   221,   222,   223,   232,   237,
     152,     0,     0,     0,     0,     0,     0,   157,   131,   132
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -339,  -339,  1641,  1642,  -339,  -339,  -339,  -339,  -339,  -339,
    -339,  -339,  -339,  -339,  -339,  -339,  -339,  1551,  -339,  -339,
    -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  -339,  1430,
    -339,  -339,  -339,  -225,   -80,  -339,  1532,  -339,  -339,  -131,
    -339,  1052,  -339,  -339,  1315,  1161,  -339,  -200,  -141,  -199,
     -63,  1211,  1344,  -140,  -339,   -92,   -35,  1649,  -339,  -339,
    1056,  -339,  -339,  -339,   410,  -339,  -339,  -339,  -338,  -339,
       8
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,    14,    15,     3,    16,    17,    18,    19,    20,
      75,    79,    21,    22,    23,    24,   116,   117,    25,    26,
      27,    28,    29,    30,    31,    32,    53,   186,    33,   367,
      34,    35,    36,   357,   153,   154,   155,   156,   157,   236,
     364,   627,   515,   516,   141,   142,   222,   489,   327,   295,
     328,   225,   226,   296,   339,   358,   329,    97,   180,   265,
     113,   166,   176,   258,   122,   174,   183,   269,   490,   185,
      76
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     158,   223,   227,   298,   326,    38,   169,   158,   471,   492,
     177,     5,     6,   368,   369,   370,   371,   372,   373,   160,
     625,   365,   232,   348,   233,   181,   111,   234,    80,   244,
     232,   299,   233,    51,   158,   234,    91,   283,   664,   501,
       6,   182,   502,   262,   503,   251,   187,   267,   107,     1,
     110,   158,   112,    52,  -265,   273,   284,   268,  -265,    98,
     158,   504,   505,   595,   506,   507,   596,   338,   508,   509,
     238,   197,   231,   239,   240,   241,   242,   366,   349,   224,
       7,     8,     9,   178,   350,   197,   546,   252,   382,    10,
     550,     4,   343,   119,   401,   120,  -264,   403,    37,   344,
     405,   406,   407,   408,   409,    90,   115,   228,    86,     8,
       9,   179,   285,   121,    50,   286,   263,    10,   264,    11,
     626,   172,    92,   173,   200,   429,    39,   467,   498,   499,
     472,   500,    93,    54,   281,    94,    95,   473,   200,    12,
     158,   158,   158,   487,   333,    99,   491,    11,    13,    55,
     235,   496,   361,   362,   363,    93,   360,   300,   100,   101,
     665,   383,   282,   384,   611,    96,   210,    12,    87,   192,
     331,   193,   282,   340,   249,   468,    13,   108,   469,   114,
     210,   470,   278,   259,   104,   105,   243,   351,   102,  -263,
     385,   352,   213,  -263,   215,   359,   216,   217,   218,   219,
     271,   272,   279,   359,   359,   359,   359,   359,   359,   115,
     532,   533,   534,   535,   536,   537,   538,   539,   540,   541,
     542,   543,   544,   545,    81,   547,   548,   549,   602,   603,
     552,   553,   554,   555,   556,   557,   558,   559,   560,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,   571,
     572,   573,   574,   575,   576,   577,   578,   579,   580,   581,
     582,   583,   584,   585,   586,   587,   380,   588,   125,   506,
     507,   478,   592,   508,   509,   118,   612,   613,   614,   615,
     616,   617,   618,   619,   620,    40,   386,   233,   126,    82,
     234,    83,    41,   606,    42,   127,   387,   131,   197,   282,
     253,   132,    40,   483,    84,    85,   254,    43,   255,   197,
     232,    42,   233,   388,    44,   234,   137,    45,   359,   359,
     510,   359,   161,    46,    43,   511,   128,   256,   129,   130,
     138,    44,   526,   512,    45,   133,   134,   135,   136,   513,
      46,   504,   505,   682,   506,   507,   683,   198,   508,   509,
     139,   200,   514,   430,   431,   432,   433,   605,   603,   434,
     282,   435,   200,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   465,   210,   287,   278,   140,   678,   679,   654,
     603,   670,   159,   672,   210,   213,   278,   215,   162,   216,
     217,   218,   219,   659,   603,   279,   213,   163,   215,   164,
     216,   217,   218,   219,   280,   165,   279,    47,    48,    49,
     508,   509,   167,    56,   175,   477,   288,   168,   289,   684,
     685,   689,   184,   690,   691,   459,   460,   461,   462,   463,
     464,   465,   290,   291,   292,   293,   692,   197,   123,   124,
     188,   171,   194,   189,   294,   694,   359,   359,   359,   359,
     359,   359,   359,   359,   359,   190,   191,   195,   196,   301,
     237,   302,   199,   223,   227,   529,   245,   230,   246,   303,
     304,   305,   306,   250,   307,   308,   309,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,   320,   321,   322,
     200,   714,   260,   144,   145,   146,   147,   261,   266,   148,
     149,   150,   270,   235,   274,   275,   276,   151,   277,   676,
     152,   376,   332,    57,   669,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,   341,    68,    69,    70,    71,
      72,    73,   210,    74,   278,   377,   502,   346,   503,   323,
     345,   224,   282,   342,   213,   324,   215,   347,   216,   217,
     218,   219,   375,   389,   279,   504,   505,   325,   506,   507,
     381,   390,   508,   509,   391,   392,   677,   359,   359,   228,
     430,   431,   432,   433,   393,   394,   434,   395,   435,   396,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   464,   465,
     430,   431,   432,   433,   397,   398,   434,   399,   435,   400,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   464,   465,
     430,   431,   432,   433,   402,   410,   434,   404,   435,   411,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   464,   465,
     412,   413,   474,   430,   431,   432,   433,   414,   475,   434,
     415,   435,   530,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   465,   430,   431,   432,   433,   416,   476,   434,
     417,   435,   531,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   465,   418,   419,   430,   431,   432,   433,   655,
     656,   434,   420,   435,   421,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   422,   430,   431,   432,   433,
     423,   486,   434,   641,   435,   424,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     425,   479,   434,   643,   435,   426,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     427,   428,   434,  -272,   435,   644,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     484,   488,   434,   485,   435,   551,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     494,   495,   434,   497,   435,   640,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     234,   518,   434,   519,   435,   642,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     520,   521,   434,   522,   435,   645,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     523,   524,   434,   525,   435,   646,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     527,   528,   434,   590,   435,   647,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     591,   593,   434,   594,   435,   648,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     597,   598,   434,  -264,   435,   649,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     599,   601,   434,   610,   435,   650,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     607,   608,   434,   621,   435,   651,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     622,   623,   434,   630,   435,   652,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     628,   629,   434,   631,   435,   653,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     632,   633,   434,   634,   435,   657,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     635,   636,   434,   637,   435,   658,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
      77,   661,   434,   638,   435,   705,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   430,   431,   432,   433,
     639,   662,   434,   198,   435,   706,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   660,   666,   667,   480,
     668,   198,   671,   673,   675,   707,   686,   334,   688,   213,
     287,   215,   693,   216,   217,   218,   219,   696,   697,   481,
      78,   698,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,   199,    68,    69,    70,    71,    72,    73,   701,
      74,   197,   702,   703,   704,   708,   330,   198,   287,   709,
     711,   712,   288,   713,   289,   715,   213,   716,   215,   625,
     216,   217,   218,   219,   718,   719,   199,   170,   290,   291,
     292,   293,    88,    89,   374,   229,   681,   624,   197,   589,
     297,   517,   482,   493,   198,   103,   687,     0,     0,     0,
     288,     0,   289,     0,   200,   201,   202,   203,   204,     0,
       0,     0,   335,   199,   336,     0,   290,   291,   292,   293,
       0,     0,     0,     0,   213,     0,   215,     0,   216,   217,
     218,   219,     0,     0,   337,     0,   205,   206,   207,   353,
     209,   200,   201,   202,   203,   204,   210,     0,   211,     0,
     354,     0,     0,   212,     0,     0,     0,     0,   213,   214,
     215,     0,   216,   217,   218,   219,   220,     0,   221,   680,
       0,     0,     0,   205,   206,   207,   208,   209,     0,     0,
       0,     0,     0,   210,     0,   211,   501,   699,     0,   502,
     212,   503,     0,     0,     0,   213,   214,   215,     0,   216,
     217,   218,   219,   220,     0,   221,     0,     0,   504,   505,
       0,   506,   507,   355,     0,   508,   509,     0,     0,     0,
     144,   145,   146,   147,   213,     0,   215,   149,   216,   217,
     218,   219,   430,   431,   432,   433,     0,   356,   434,     0,
     435,     0,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     464,   465,   144,   145,   146,   147,   213,     0,   215,   149,
     216,   217,   218,   219,     0,   430,   431,   432,   433,     0,
     600,   434,     0,   435,   466,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     604,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     609,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     663,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     674,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     695,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     710,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
     717,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   430,   431,   432,   433,     0,
       0,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   431,   432,   433,     0,     0,
     434,     0,   435,     0,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   464,   465,   433,     0,     0,   434,     0,   435,
       0,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   434,     0,   435,     0,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,   435,     0,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   465,   501,   700,     0,
     502,     0,   503,     0,     0,     0,   501,     0,     0,   502,
       0,   503,     0,     0,     0,     0,     0,     0,     0,   504,
     505,     0,   506,   507,     0,     0,   508,   509,   504,   505,
       0,   506,   507,     0,     0,   508,   509,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   465,   143,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   465,   144,
     145,   146,   147,     0,     0,   148,   149,   150,     0,     0,
       0,     0,     0,   151,     0,   247,   152,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,     0,    68,    69,
      70,    71,    72,    73,     0,    74,     0,     0,     0,     0,
       0,   378,   248,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,     0,    68,    69,    70,    71,    72,    73,
       0,    74,     0,     0,     0,     0,     0,     0,   379,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,   465,  -273,  -273,  -273,  -273,  -273,
    -273,  -273,  -273,  -273,  -273,  -273,  -273,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   503,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   504,   505,
       0,   506,   507,     0,     0,   508,   509,   106,     0,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,     0,
      68,    69,    70,    71,    72,    73,   109,    74,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,     0,    68,
      69,    70,    71,    72,    73,   257,    74,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,     0,    68,    69,
      70,    71,    72,    73,     0,    74
};

static const yytype_int16 yycheck[] =
{
      92,   142,   142,   202,   204,     8,     8,    99,     8,   347,
      33,     0,     1,   238,   239,   240,   241,   242,   243,    99,
      29,    80,     6,   223,     8,   118,   108,    11,    20,   160,
       6,     8,     8,   108,   126,    11,     9,   108,     8,     7,
       1,   134,    10,    33,    12,    64,   126,   108,    40,    69,
      42,   143,   134,   128,   130,   186,   127,   118,   134,     9,
     152,    29,    30,   108,    32,    33,   111,   208,    36,    37,
      14,    11,   152,    17,    18,    19,    20,   136,   131,   142,
      69,    70,    71,   106,   137,    11,   424,   106,    33,    78,
     428,    77,   130,   114,   294,   116,   134,   297,   130,   137,
     300,   301,   302,   303,   304,   136,   108,   142,    69,    70,
      71,   134,   134,   134,   108,   137,   106,    78,   108,   108,
     129,   114,    95,   116,    64,   325,   129,   327,   353,   354,
     130,   356,   105,   137,   197,   108,   109,   137,    64,   128,
     232,   233,   234,   343,   207,    95,   346,   108,   137,   137,
     134,   351,   232,   233,   234,   105,   132,   134,   108,   109,
     130,   106,   197,   108,   132,   138,   106,   128,   129,    74,
     205,    76,   207,   208,   166,   131,   137,   130,   134,   118,
     106,   137,   108,   175,    86,    87,   130,   130,   138,   130,
     135,   134,   118,   134,   120,   230,   122,   123,   124,   125,
     132,   133,   128,   238,   239,   240,   241,   242,   243,   108,
     410,   411,   412,   413,   414,   415,   416,   417,   418,   419,
     420,   421,   422,   423,     8,   425,   426,   427,   132,   133,
     430,   431,   432,   433,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   258,   466,   131,    32,
      33,   334,   472,    36,    37,    90,   501,   502,   503,   504,
     505,   506,   507,   508,   509,    72,   108,     8,   137,    73,
      11,    75,    79,   493,    81,   130,   118,   130,    11,   334,
     108,   130,    72,   338,    88,    89,   114,    94,   116,    11,
       6,    81,     8,   135,   101,    11,   130,   104,   353,   354,
     103,   356,     8,   110,    94,   108,    82,   135,    84,    85,
     130,   101,   395,   116,   104,    82,    83,    84,    85,   122,
     110,    29,    30,   108,    32,    33,   111,    17,    36,    37,
     130,    64,   135,     3,     4,     5,     6,   132,   133,     9,
     395,    11,    64,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,   106,    64,   108,   130,   622,   623,   132,
     133,   601,   105,   603,   106,   118,   108,   120,     8,   122,
     123,   124,   125,   132,   133,   128,   118,   106,   120,   131,
     122,   123,   124,   125,   137,   108,   128,    91,    92,    93,
      36,    37,     8,     8,   134,   137,   106,   130,   108,    86,
      87,   641,   108,   643,   644,    36,    37,    38,    39,    40,
      41,    42,   122,   123,   124,   125,   656,    11,    48,    49,
     131,   130,   106,   131,   134,   665,   501,   502,   503,   504,
     505,   506,   507,   508,   509,   131,   131,   106,   129,    33,
     102,    35,    36,   624,   624,   135,     8,   130,   106,    43,
      44,    45,    46,   118,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,   711,     8,   114,   115,   116,   117,   106,     8,   120,
     121,   122,     8,   134,   106,   106,   106,   128,   106,   621,
     131,   134,   131,   108,   597,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   122,   121,   122,   123,   124,
     125,   126,   106,   128,   108,    88,    10,   130,    12,   113,
     131,   624,   597,   137,   118,   119,   120,   131,   122,   123,
     124,   125,   132,   108,   128,    29,    30,   131,    32,    33,
     106,   136,    36,    37,   133,   133,   621,   622,   623,   624,
       3,     4,     5,     6,   133,   133,     9,   106,    11,    18,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       3,     4,     5,     6,    18,   110,     9,   106,    11,   134,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       3,     4,     5,     6,     8,   131,     9,     8,    11,   131,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
     131,   131,   130,     3,     4,     5,     6,   131,   106,     9,
     131,    11,   135,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     3,     4,     5,     6,   131,   133,     9,
     131,    11,   135,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,   131,   131,     3,     4,     5,     6,   132,
     133,     9,   131,    11,   131,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,   131,     3,     4,     5,     6,
     131,   106,     9,   133,    11,   131,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     131,   137,     9,   133,    11,   131,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     131,   131,     9,     8,    11,   133,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
       8,   106,     9,     8,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     106,   106,     9,   106,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
      11,    77,     9,   106,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     130,   106,     9,   106,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     106,   106,     9,   106,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     135,   110,     9,   106,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     106,   106,     9,   132,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     106,   106,     9,     8,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
       8,   130,     9,   133,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     132,   130,     9,   131,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     130,   130,     9,   106,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     130,   133,     9,   132,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     132,   132,     9,   132,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     137,   135,     9,     8,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
       8,   132,     9,     8,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
       8,   133,     9,    17,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     8,     8,     8,   108,
       8,    17,     8,     8,   106,   132,   106,    11,   106,   118,
      64,   120,   106,   122,   123,   124,   125,   135,   133,   128,
     108,   133,   110,   111,   112,   113,   114,   115,   116,   117,
     118,   119,    36,   121,   122,   123,   124,   125,   126,    30,
     128,    11,    30,   135,     8,   132,   108,    17,    64,   135,
     130,   116,   106,   116,   108,   132,   118,   132,   120,    29,
     122,   123,   124,   125,     8,     8,    36,   116,   122,   123,
     124,   125,    31,    31,   244,   143,   624,   516,    11,   468,
     134,   366,   338,   130,    17,    36,   630,    -1,    -1,    -1,
     106,    -1,   108,    -1,    64,    65,    66,    67,    68,    -1,
      -1,    -1,   106,    36,   108,    -1,   122,   123,   124,   125,
      -1,    -1,    -1,    -1,   118,    -1,   120,    -1,   122,   123,
     124,   125,    -1,    -1,   128,    -1,    96,    97,    98,    33,
     100,    64,    65,    66,    67,    68,   106,    -1,   108,    -1,
      44,    -1,    -1,   113,    -1,    -1,    -1,    -1,   118,   119,
     120,    -1,   122,   123,   124,   125,   126,    -1,   128,   129,
      -1,    -1,    -1,    96,    97,    98,    99,   100,    -1,    -1,
      -1,    -1,    -1,   106,    -1,   108,     7,     8,    -1,    10,
     113,    12,    -1,    -1,    -1,   118,   119,   120,    -1,   122,
     123,   124,   125,   126,    -1,   128,    -1,    -1,    29,    30,
      -1,    32,    33,   107,    -1,    36,    37,    -1,    -1,    -1,
     114,   115,   116,   117,   118,    -1,   120,   121,   122,   123,
     124,   125,     3,     4,     5,     6,    -1,   131,     9,    -1,
      11,    -1,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,   114,   115,   116,   117,   118,    -1,   120,   121,
     122,   123,   124,   125,    -1,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    65,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
       8,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,    -1,
      -1,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     4,     5,     6,    -1,    -1,
       9,    -1,    11,    -1,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,     6,    -1,    -1,     9,    -1,    11,
      -1,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     7,     8,    -1,
      10,    -1,    12,    -1,    -1,    -1,     7,    -1,    -1,    10,
      -1,    12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    29,
      30,    -1,    32,    33,    -1,    -1,    36,    37,    29,    30,
      -1,    32,    33,    -1,    -1,    36,    37,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,   102,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,   114,
     115,   116,   117,    -1,    -1,   120,   121,   122,    -1,    -1,
      -1,    -1,    -1,   128,    -1,   108,   131,   110,   111,   112,
     113,   114,   115,   116,   117,   118,   119,    -1,   121,   122,
     123,   124,   125,   126,    -1,   128,    -1,    -1,    -1,    -1,
      -1,   108,   135,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,    -1,   121,   122,   123,   124,   125,   126,
      -1,   128,    -1,    -1,    -1,    -1,    -1,    -1,   135,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,    12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    29,    30,
      -1,    32,    33,    -1,    -1,    36,    37,   108,    -1,   110,
     111,   112,   113,   114,   115,   116,   117,   118,   119,    -1,
     121,   122,   123,   124,   125,   126,   108,   128,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,    -1,   121,
     122,   123,   124,   125,   126,   108,   128,   110,   111,   112,
     113,   114,   115,   116,   117,   118,   119,    -1,   121,   122,
     123,   124,   125,   126,    -1,   128
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    69,   140,   143,    77,     0,     1,    69,    70,    71,
      78,   108,   128,   137,   141,   142,   144,   145,   146,   147,
     148,   151,   152,   153,   154,   157,   158,   159,   160,   161,
     162,   163,   164,   167,   169,   170,   171,   130,     8,   129,
      72,    79,    81,    94,   101,   104,   110,    91,    92,    93,
     108,   108,   128,   165,   137,   137,     8,   108,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,   121,   122,
     123,   124,   125,   126,   128,   149,   209,     8,   108,   150,
     209,     8,    73,    75,    88,    89,    69,   129,   141,   142,
     136,     9,    95,   105,   108,   109,   138,   196,     9,    95,
     108,   109,   138,   196,    86,    87,   108,   209,   130,   108,
     209,   108,   134,   199,   118,   108,   155,   156,    90,   114,
     116,   134,   203,   203,   203,   131,   137,   130,    82,    84,
      85,   130,   130,    82,    83,    84,    85,   130,   130,   130,
     130,   183,   184,   102,   114,   115,   116,   117,   120,   121,
     122,   128,   131,   173,   174,   175,   176,   177,   194,   105,
     173,     8,     8,   106,   131,   108,   200,     8,   130,     8,
     156,   130,   114,   116,   204,   134,   201,    33,   106,   134,
     197,   118,   134,   205,   108,   208,   166,   173,   131,   131,
     131,   131,    74,    76,   106,   106,   129,    11,    17,    36,
      64,    65,    66,    67,    68,    96,    97,    98,    99,   100,
     106,   108,   113,   118,   119,   120,   122,   123,   124,   125,
     126,   128,   185,   187,   189,   190,   191,   192,   195,   175,
     130,   173,     6,     8,    11,   134,   178,   102,    14,    17,
      18,    19,    20,   130,   178,     8,   106,   108,   135,   209,
     118,    64,   106,   108,   114,   116,   135,   108,   202,   209,
       8,   106,    33,   106,   108,   198,     8,   108,   118,   206,
       8,   132,   133,   178,   106,   106,   106,   106,   108,   128,
     137,   189,   195,   108,   127,   134,   137,    64,   106,   108,
     122,   123,   124,   125,   134,   188,   192,   134,   188,     8,
     134,    33,    35,    43,    44,    45,    46,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,   113,   119,   131,   186,   187,   189,   195,
     108,   195,   131,   189,    11,   106,   108,   128,   187,   193,
     195,   122,   137,   130,   137,   131,   130,   131,   186,   131,
     137,   130,   134,    33,    44,   107,   131,   172,   194,   195,
     132,   173,   173,   173,   179,    80,   136,   168,   172,   172,
     172,   172,   172,   172,   168,   132,   134,    88,   108,   135,
     209,   106,    33,   106,   108,   135,   108,   118,   135,   108,
     136,   133,   133,   133,   133,   106,    18,    18,   110,   106,
     134,   186,     8,   186,     8,   186,   186,   186,   186,   186,
     131,   131,   131,   131,   131,   131,   131,   131,   131,   131,
     131,   131,   131,   131,   131,   131,   131,   131,   131,   186,
       3,     4,     5,     6,     9,    11,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    65,   186,   131,   134,
     137,     8,   130,   137,   130,   106,   133,   137,   189,   137,
     108,   128,   191,   195,     8,     8,   106,   186,   106,   186,
     207,   186,   207,   130,   106,   106,   186,   106,   172,   172,
     172,     7,    10,    12,    29,    30,    32,    33,    36,    37,
     103,   108,   116,   122,   135,   181,   182,   183,    77,   106,
     130,   106,   106,   106,   106,   106,   189,   135,   110,   135,
     135,   135,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   207,   186,   186,   186,
     207,   132,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   188,   190,
     106,   106,   186,   106,   132,   108,   111,   106,   106,     8,
       8,   130,   132,   133,     8,   132,   186,   132,   130,     8,
     133,   132,   172,   172,   172,   172,   172,   172,   172,   172,
     172,   131,   130,   130,   184,    29,   129,   180,   130,   133,
     106,   132,   132,   132,   132,   137,   135,     8,     8,     8,
     132,   133,   132,   133,   133,   132,   132,   132,   132,   132,
     132,   132,   132,   132,   132,   132,   133,   132,   132,   132,
       8,   132,   133,     8,     8,   130,     8,     8,     8,   189,
     186,     8,   186,     8,     8,   106,   194,   195,   172,   172,
     129,   180,   108,   111,    86,    87,   106,   199,   106,   186,
     186,   186,   186,   106,   186,     8,   135,   133,   133,     8,
       8,    30,    30,   135,     8,   132,   132,   132,   132,   135,
       8,   130,   116,   116,   186,   132,   132,     8,     8,     8
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
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
     186,   187,   187,   187,   187,   188,   188,   188,   188,   188,
     188,   188,   188,   188,   189,   189,   189,   189,   190,   190,
     190,   190,   190,   191,   191,   191,   192,   192,   193,   193,
     193,   193,   193,   193,   194,   194,   194,   194,   194,   195,
     195,   195,   195,   195,   195,   196,   196,   197,   197,   197,
     198,   198,   198,   198,   198,   198,   199,   199,   200,   200,
     200,   201,   202,   202,   202,   202,   203,   203,   203,   204,
     204,   204,   204,   204,   205,   205,   206,   206,   206,   206,
     207,   207,   207,   208,   208,   208,   209,   209,   209,   209,
     209,   209,   209,   209,   209,   209,   209,   209,   209,   209,
     209,   209,   209
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
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
       4,     6,     4,     3,     1,     1,     1,     1,     1,     1,
       1,     4,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     2,     4,     1,     1,     1,     3,     3,     1,     2,
       4,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     3,     1,     2,
       1,     2,     1,     2,     3,     2,     3,     1,     1,     2,
       2,     3,     1,     1,     2,     2,     3,     1,     1,     1,
       1,     2,     2,     2,     3,     1,     1,     1,     2,     2,
       0,     1,     3,     0,     1,     3,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
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


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
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
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
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
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
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
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
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
            /* Fall through.  */
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

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
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
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

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
      int yyn = yypact[*yyssp];
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
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
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
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
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
          yyp++;
          yyformat++;
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
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

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
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
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
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

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

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

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
| yyreduce -- Do a reduction.  |
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

    { (yyval.sem) = new ConstructTpl(); }

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

    { VarnodeTpl *sym = (yyvsp[0].startsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }

    break;

  case 246:

    { VarnodeTpl *sym = (yyvsp[0].endsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }

    break;

  case 247:

    { VarnodeTpl *sym = (yyvsp[0].next2sym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }

    break;

  case 248:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }

    break;

  case 249:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); slgh->reportError("Parsed integer is too big (overflow)"); }

    break;

  case 250:

    { (yyval.varnode) = (yyvsp[0].operandsym)->getVarnode(); (yyvsp[0].operandsym)->setCodeAddress(); }

    break;

  case 251:

    { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }

    break;

  case 252:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }

    break;

  case 253:

    { string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }

    break;

  case 254:

    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }

    break;

  case 255:

    { (yyval.varnode) = (yyvsp[0].varnode); }

    break;

  case 256:

    { string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }

    break;

  case 257:

    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }

    break;

  case 258:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }

    break;

  case 259:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); slgh->reportError("Parsed integer is too big (overflow)"); }

    break;

  case 260:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }

    break;

  case 261:

    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }

    break;

  case 262:

    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }

    break;

  case 263:

    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }

    break;

  case 264:

    { string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }

    break;

  case 265:

    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }

    break;

  case 266:

    { (yyval.labelsym) = (yyvsp[-1].labelsym); }

    break;

  case 267:

    { (yyval.labelsym) = slgh->pcode.defineLabel( (yyvsp[-1].str) ); }

    break;

  case 268:

    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }

    break;

  case 269:

    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }

    break;

  case 270:

    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }

    break;

  case 271:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }

    break;

  case 272:

    { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }

    break;

  case 273:

    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); slgh->reportError(errmsg); YYERROR; }

    break;

  case 274:

    { (yyval.famsym) = (yyvsp[0].valuesym); }

    break;

  case 275:

    { (yyval.famsym) = (yyvsp[0].valuemapsym); }

    break;

  case 276:

    { (yyval.famsym) = (yyvsp[0].contextsym); }

    break;

  case 277:

    { (yyval.famsym) = (yyvsp[0].namesym); }

    break;

  case 278:

    { (yyval.famsym) = (yyvsp[0].varlistsym); }

    break;

  case 279:

    { (yyval.specsym) = (yyvsp[0].varsym); }

    break;

  case 280:

    { (yyval.specsym) = (yyvsp[0].specsym); }

    break;

  case 281:

    { (yyval.specsym) = (yyvsp[0].operandsym); }

    break;

  case 282:

    { (yyval.specsym) = (yyvsp[0].startsym); }

    break;

  case 283:

    { (yyval.specsym) = (yyvsp[0].endsym); }

    break;

  case 284:

    { (yyval.specsym) = (yyvsp[0].next2sym); }

    break;

  case 285:

    { (yyval.str) = new string; (*(yyval.str)) += (yyvsp[0].ch); }

    break;

  case 286:

    { (yyval.str) = (yyvsp[-1].str); (*(yyval.str)) += (yyvsp[0].ch); }

    break;

  case 287:

    { (yyval.biglist) = (yyvsp[-1].biglist); }

    break;

  case 288:

    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }

    break;

  case 289:

    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }

    break;

  case 290:

    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }

    break;

  case 291:

    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }

    break;

  case 292:

    { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }

    break;

  case 293:

    { (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }

    break;

  case 294:

    { (yyval.biglist) = (yyvsp[-2].biglist); (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }

    break;

  case 295:

    { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }

    break;

  case 296:

    { (yyval.strlist) = (yyvsp[-1].strlist); }

    break;

  case 297:

    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }

    break;

  case 298:

    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }

    break;

  case 299:

    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }

    break;

  case 300:

    { string errmsg = (yyvsp[0].anysym)->getName()+": redefined"; slgh->reportError(errmsg); YYERROR; }

    break;

  case 301:

    { (yyval.strlist) = (yyvsp[-1].strlist); }

    break;

  case 302:

    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }

    break;

  case 303:

    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( (yyvsp[0].anysym)->getName() ); }

    break;

  case 304:

    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }

    break;

  case 305:

    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back((yyvsp[0].anysym)->getName()); }

    break;

  case 306:

    { (yyval.symlist) = (yyvsp[-1].symlist); }

    break;

  case 307:

    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].valuesym)); }

    break;

  case 308:

    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }

    break;

  case 309:

    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back( (yyvsp[0].valuesym) ); }

    break;

  case 310:

    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }

    break;

  case 311:

    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].valuesym)); }

    break;

  case 312:

    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].contextsym)); }

    break;

  case 313:

    { string errmsg = *(yyvsp[0].str)+": is not a value pattern"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }

    break;

  case 314:

    { (yyval.symlist) = (yyvsp[-1].symlist); }

    break;

  case 315:

    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }

    break;

  case 316:

    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }

    break;

  case 317:

    { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
				  (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }

    break;

  case 318:

    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].varsym)); }

    break;

  case 319:

    { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); slgh->reportError(errmsg); YYERROR; }
                                  (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }

    break;

  case 320:

    { (yyval.param) = new vector<ExprTree *>; }

    break;

  case 321:

    { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }

    break;

  case 322:

    { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }

    break;

  case 323:

    { (yyval.strlist) = new vector<string>; }

    break;

  case 324:

    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }

    break;

  case 325:

    { (yyval.strlist) = (yyvsp[-2].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }

    break;

  case 326:

    { (yyval.anysym) = (yyvsp[0].spacesym); }

    break;

  case 327:

    { (yyval.anysym) = (yyvsp[0].sectionsym); }

    break;

  case 328:

    { (yyval.anysym) = (yyvsp[0].tokensym); }

    break;

  case 329:

    { (yyval.anysym) = (yyvsp[0].useropsym); }

    break;

  case 330:

    { (yyval.anysym) = (yyvsp[0].macrosym); }

    break;

  case 331:

    { (yyval.anysym) = (yyvsp[0].subtablesym); }

    break;

  case 332:

    { (yyval.anysym) = (yyvsp[0].valuesym); }

    break;

  case 333:

    { (yyval.anysym) = (yyvsp[0].valuemapsym); }

    break;

  case 334:

    { (yyval.anysym) = (yyvsp[0].contextsym); }

    break;

  case 335:

    { (yyval.anysym) = (yyvsp[0].namesym); }

    break;

  case 336:

    { (yyval.anysym) = (yyvsp[0].varsym); }

    break;

  case 337:

    { (yyval.anysym) = (yyvsp[0].varlistsym); }

    break;

  case 338:

    { (yyval.anysym) = (yyvsp[0].operandsym); }

    break;

  case 339:

    { (yyval.anysym) = (yyvsp[0].startsym); }

    break;

  case 340:

    { (yyval.anysym) = (yyvsp[0].endsym); }

    break;

  case 341:

    { (yyval.anysym) = (yyvsp[0].next2sym); }

    break;

  case 342:

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

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

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
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
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

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

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
                  yystos[*yyssp], yyvsp);
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

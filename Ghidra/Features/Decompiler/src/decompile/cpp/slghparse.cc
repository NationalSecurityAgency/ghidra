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




/* Copy the first part of user declarations.  */
#line 16 "src/decompile/cpp/slghparse.y" /* yacc.c:339  */

#include "slgh_compile.hh"

#define YYERROR_VERBOSE

  extern SleighCompile *slgh;
  extern int4 actionon;
  extern FILE *yyin;
  extern int yydebug;
  extern int yylex(void);
  extern int yyerror(const char *str );

#line 79 "src/decompile/cpp/slghparse.cc" /* yacc.c:339  */

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
#ifndef YY_YY_SRC_DECOMPILE_CPP_SLGHPARSE_HH_INCLUDED
# define YY_YY_SRC_DECOMPILE_CPP_SLGHPARSE_HH_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
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
    OP_COUNTLEADINGZEROS = 305,
    OP_COUNTLEADINGONES = 306,
    BADINTEGER = 307,
    GOTO_KEY = 308,
    CALL_KEY = 309,
    RETURN_KEY = 310,
    IF_KEY = 311,
    DEFINE_KEY = 312,
    ATTACH_KEY = 313,
    MACRO_KEY = 314,
    SPACE_KEY = 315,
    TYPE_KEY = 316,
    RAM_KEY = 317,
    DEFAULT_KEY = 318,
    REGISTER_KEY = 319,
    ENDIAN_KEY = 320,
    WITH_KEY = 321,
    ALIGN_KEY = 322,
    OP_UNIMPL = 323,
    TOKEN_KEY = 324,
    SIGNED_KEY = 325,
    NOFLOW_KEY = 326,
    HEX_KEY = 327,
    DEC_KEY = 328,
    BIG_KEY = 329,
    LITTLE_KEY = 330,
    SIZE_KEY = 331,
    WORDSIZE_KEY = 332,
    OFFSET_KEY = 333,
    NAMES_KEY = 334,
    VALUES_KEY = 335,
    VARIABLES_KEY = 336,
    PCODEOP_KEY = 337,
    IS_KEY = 338,
    LOCAL_KEY = 339,
    DELAYSLOT_KEY = 340,
    CROSSBUILD_KEY = 341,
    EXPORT_KEY = 342,
    BUILD_KEY = 343,
    CONTEXT_KEY = 344,
    ELLIPSIS_KEY = 345,
    GLOBALSET_KEY = 346,
    BITRANGE_KEY = 347,
    CHAR = 348,
    INTEGER = 349,
    INTB = 350,
    STRING = 351,
    SYMBOLSTRING = 352,
    SPACESYM = 353,
    SECTIONSYM = 354,
    TOKENSYM = 355,
    USEROPSYM = 356,
    VALUESYM = 357,
    VALUEMAPSYM = 358,
    CONTEXTSYM = 359,
    NAMESYM = 360,
    VARSYM = 361,
    BITSYM = 362,
    SPECSYM = 363,
    VARLISTSYM = 364,
    OPERANDSYM = 365,
    STARTSYM = 366,
    ENDSYM = 367,
    MACROSYM = 368,
    LABELSYM = 369,
    SUBTABLESYM = 370
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 29 "src/decompile/cpp/slghparse.y" /* yacc.c:355  */

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

#line 279 "src/decompile/cpp/slghparse.cc" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_SRC_DECOMPILE_CPP_SLGHPARSE_HH_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 296 "src/decompile/cpp/slghparse.cc" /* yacc.c:358  */

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
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

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
#define YYLAST   2721

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  139
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  71
/* YYNRULES -- Number of rules.  */
#define YYNRULES  340
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  721

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

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   156,   156,   157,   158,   159,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   172,   173,   174,   175,
     177,   178,   180,   182,   184,   185,   186,   187,   188,   190,
     192,   193,   196,   197,   198,   199,   200,   202,   203,   204,
     205,   206,   207,   209,   211,   212,   213,   214,   215,   216,
     217,   219,   221,   223,   225,   226,   228,   231,   233,   235,
     237,   239,   242,   244,   245,   246,   248,   250,   251,   252,
     255,   256,   259,   261,   262,   263,   265,   266,   268,   269,
     270,   271,   272,   273,   274,   275,   276,   278,   279,   280,
     281,   283,   285,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   302,   303,   304,   305,
     307,   308,   310,   311,   313,   314,   316,   317,   318,   319,
     320,   321,   322,   325,   326,   327,   328,   330,   331,   333,
     334,   335,   336,   337,   338,   340,   341,   343,   345,   346,
     348,   349,   350,   351,   352,   354,   355,   356,   357,   359,
     360,   361,   362,   363,   364,   365,   366,   367,   368,   369,
     370,   371,   372,   373,   374,   375,   376,   377,   378,   379,
     380,   381,   382,   383,   385,   386,   387,   388,   389,   390,
     391,   392,   393,   394,   395,   396,   397,   398,   399,   400,
     401,   402,   403,   404,   405,   406,   407,   408,   409,   410,
     411,   412,   413,   414,   415,   416,   417,   418,   419,   420,
     421,   422,   423,   424,   425,   426,   427,   428,   429,   430,
     431,   432,   433,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   454,   455,   456,   457,   459,   460,   461,   462,
     463,   464,   465,   466,   468,   469,   470,   471,   473,   474,
     475,   476,   477,   479,   480,   481,   483,   484,   486,   487,
     488,   489,   490,   491,   493,   494,   495,   496,   497,   499,
     500,   501,   502,   503,   505,   506,   508,   509,   510,   512,
     513,   514,   516,   517,   518,   521,   522,   524,   525,   526,
     528,   530,   531,   532,   533,   535,   536,   537,   539,   540,
     541,   542,   543,   545,   546,   548,   549,   551,   552,   555,
     556,   557,   559,   560,   561,   563,   564,   565,   566,   567,
     568,   569,   570,   571,   572,   573,   574,   575,   576,   577,
     578
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
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
  "OP_TRUNC", "OP_CPOOLREF", "OP_NEW", "OP_POPCOUNT",
  "OP_COUNTLEADINGZEROS", "OP_COUNTLEADINGONES", "BADINTEGER", "GOTO_KEY",
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
  "STARTSYM", "ENDSYM", "MACROSYM", "LABELSYM", "SUBTABLESYM", "'}'",
  "'='", "'('", "')'", "','", "'['", "']'", "'{'", "':'", "' '", "$accept",
  "spec", "definition", "constructorlike", "endiandef", "aligndef",
  "tokendef", "tokenprop", "contextdef", "contextprop", "fielddef",
  "contextfielddef", "spacedef", "spaceprop", "varnodedef", "bitrangedef",
  "bitrangelist", "bitrangesingle", "pcodeopdef", "valueattach",
  "nameattach", "varattach", "macrodef", "withblockstart", "withblockmid",
  "withblock", "id_or_nil", "bitpat_or_nil", "macrostart", "rtlbody",
  "constructor", "constructprint", "subtablestart", "pexpression",
  "pequation", "elleq", "ellrt", "atomic", "constraint", "contextblock",
  "contextlist", "section_def", "rtlfirstsection", "rtlcontinue", "rtl",
  "rtlmid", "statement", "expr", "sizedstar", "jumpdest", "varnode",
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

#define YYPACT_NINF -320

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-320)))

#define YYTABLE_NINF -273

#define yytable_value_is_error(Yytable_value) \
  (!!((Yytable_value) == (-273)))

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -45,    -4,    10,  -320,   -98,  -320,     7,  1546,   320,   -12,
     -24,    40,    53,  -320,  -320,  -320,  -320,  -320,   392,  -320,
     423,  -320,    -3,  -320,  -320,  -320,  -320,  -320,  -320,  -320,
    -320,    35,  -320,   -15,  -320,    19,    21,   141,  -320,  -320,
    2557,    22,  2575,   -80,   104,   160,   187,   -40,   -40,   -40,
     151,  -320,  -320,   149,  -320,  -320,  -320,   166,  -320,  -320,
    -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,
    -320,  -320,  -320,  -320,   217,   189,  -320,   196,    27,   200,
    -320,   206,  -320,   251,   254,  1547,  -320,  -320,  -320,  -320,
    -320,  1659,  -320,  -320,  -320,  -320,   280,  -320,  1659,  -320,
    -320,  -320,   280,   398,   407,  -320,  -320,   322,   268,  -320,
    -320,   334,   448,  -320,   330,     0,  -320,   331,  -320,  -320,
     -52,   332,   -16,   -86,   356,  1659,   337,  -320,  -320,  -320,
     338,   340,  -320,  -320,  -320,  -320,   341,   344,   366,   368,
     348,  1753,  1812,  -320,  -320,  -320,  -320,  -320,  -320,   351,
    -320,  1659,    12,  -320,  -320,   379,  -320,   391,  -320,    12,
    -320,  -320,   475,   380,  -320,  2427,  -320,   374,  -320,  -320,
     -46,  -320,  -320,   -39,  2593,   488,   387,  -320,   161,   490,
    -320,   -88,   491,  -320,   243,   385,   317,   393,   395,   422,
     424,  -320,  -320,  -320,  -320,  -320,   264,  -100,    64,  -320,
     273,   355,    -2,  1620,    83,   419,    72,   367,   440,   396,
      31,   433,  -320,   435,  -320,  -320,  -320,  -320,   436,    32,
    -320,  1620,    45,  -320,    44,  -320,    69,  -320,  1716,    41,
    1659,  1659,  1659,  -320,   -68,  -320,  1716,  1716,  1716,  1716,
    1716,  1716,   -68,  -320,   434,  -320,  -320,  -320,   442,  -320,
     492,  -320,  -320,  -320,  -320,  -320,  2452,  -320,  -320,  -320,
     470,  -320,  -320,    13,  -320,  -320,  -320,    14,  -320,  -320,
     507,   443,   484,   523,   524,   526,  -320,  -320,   512,  -320,
    -320,   603,   643,   581,   586,  -320,   560,  -320,  -320,  -320,
    -320,  1620,   691,  -320,  1620,   694,  -320,  1620,  1620,  1620,
    1620,  1620,   608,   611,   644,   645,   653,   655,   686,   696,
     731,   736,   771,   772,   811,   812,   814,   851,   852,   854,
     891,   892,  -320,  1620,  1879,  1620,  -320,   -75,    30,   570,
     633,   689,   309,   726,   897,  -320,  1515,  1017,  -320,  1054,
     716,  1620,   956,  1620,  1620,  1620,  1575,   958,   995,  1620,
     996,  1716,  1716,  -320,  1716,  2440,  -320,  -320,  -320,   283,
    1094,  -320,   -51,  -320,  -320,  -320,  2440,  2440,  2440,  2440,
    2440,  2440,  -320,  1064,  1036,  1052,  -320,  -320,  -320,  -320,
    1038,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  1076,
    1078,  1115,  1116,    72,  -320,  -320,  1090,  -320,  1151,   328,
    -320,   569,  -320,   609,  -320,  -320,  -320,  -320,  1620,  1620,
    1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,
    1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,   815,  1620,
    1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,
    1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,
    1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,  1620,
    1620,  1620,  1620,  1620,  1620,   270,  -320,    28,  1156,  1158,
    -320,  1620,  1195,  -320,  1171,   204,  1198,  -320,  1235,  1337,
    -320,  1374,  -320,  -320,  -320,  -320,  1933,  1213,  2253,   258,
    1973,   290,  1620,  1251,  1292,  2013,  1252,  -320,  -320,   285,
    1716,  1716,  1716,  1716,  1716,  1716,  1716,  1716,  1716,  1294,
    -320,  1293,  1332,  -320,  -320,  -320,   -13,  1333,  1369,  1358,
    -320,  1371,  1373,  1410,  1411,  -320,  1408,  1447,  1577,  1610,
    1613,   855,   692,   895,   732,   774,   935,   975,  1015,  1055,
    1095,  1135,  1175,  1215,  1255,   292,   649,  1295,  1335,  1375,
     303,  -320,  2292,  2329,  2329,  2363,  2395,  2465,  2571,  2571,
    2571,  2571,  2597,  2597,  2597,  2597,  2597,  2597,  2597,  2597,
    2597,  2597,  2597,  2597,   520,   520,   520,   486,   486,   486,
     486,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  1614,  1451,
    1490,  -320,  2053,     4,  1617,  1622,  1624,    72,  -320,  -320,
    -320,  1620,  1625,  1620,  -320,  1627,  2093,  -320,  -320,  -320,
    1530,  -320,  2498,  2628,   244,   252,   252,   402,   402,  -320,
    -320,  2396,  1716,  1716,  1687,   215,  -320,  -320,   353,  1537,
     -80,  -320,  -320,  -320,  -320,  1538,  -320,  -320,  -320,  -320,
    -320,  1620,  -320,  1620,  1620,  -320,  -320,  -320,  -320,  -320,
    -320,  -320,  -320,  -320,  -320,  -320,  1620,  -320,  -320,  -320,
    -320,  -320,  -320,  1539,  -320,  -320,  1620,  -320,  -320,  -320,
    -320,  2133,  -320,  2253,  -320,  -320,  1512,  1517,  1521,  1681,
    2431,  -320,  -320,  1629,  1630,  -320,  -320,  1526,  1654,  -320,
    1415,  1455,  1495,  1535,  1551,  2173,  -320,  1557,  1573,  1578,
    -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,
    -320,  -320,  1620,  1560,  1562,  2213,  1688,  1689,  -320,  -320,
    -320
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
       0,    69,    68,     0,    88,    87,    23,     0,   325,   326,
     327,   328,   331,   332,   333,   334,   335,   340,   336,   337,
     338,   339,   329,   330,    27,     0,    29,     0,    31,     0,
      43,     0,    50,     0,     0,     0,    66,    64,    65,   145,
      82,     0,   284,    83,    86,    85,    84,    81,     0,    78,
      80,    90,    79,     0,     0,    44,    45,     0,     0,    28,
     296,     0,     0,    30,     0,     0,    54,     0,   306,   307,
       0,     0,     0,     0,   322,    70,     0,    34,    35,    36,
       0,     0,    39,    40,    41,    42,     0,     0,     0,     0,
       0,   140,     0,   274,   275,   276,   277,   124,   278,   123,
     126,     0,   127,   106,   111,   113,   114,   125,   285,   127,
      20,    21,     0,     0,   297,     0,    57,     0,    53,    55,
       0,   308,   309,     0,     0,     0,     0,   287,     0,     0,
     314,     0,     0,   323,     0,   127,    71,     0,     0,     0,
       0,    46,    47,    48,    49,    61,     0,     0,   245,   259,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   258,
     256,     0,   279,     0,   280,   281,   282,   283,     0,   257,
     146,     0,     0,   255,     0,   173,   254,   110,     0,     0,
       0,     0,     0,   129,     0,   112,     0,     0,     0,     0,
       0,     0,     0,    22,     0,   298,   295,   299,     0,    52,
       0,   312,   310,   311,   305,   301,     0,   302,    59,   288,
       0,   289,   291,     0,    58,   316,   315,     0,    60,    72,
       0,     0,     0,     0,     0,     0,   256,   257,     0,   261,
     254,     0,     0,     0,     0,   249,   248,   253,   250,   246,
     247,     0,     0,   252,     0,     0,   170,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   239,     0,     0,     0,   174,   254,     0,     0,
       0,     0,     0,     0,   143,   273,     0,     0,   268,     0,
       0,     0,     0,   319,     0,   319,     0,     0,     0,     0,
       0,     0,     0,    91,     0,   122,    92,    93,   115,   108,
     109,   107,     0,    75,   145,    76,   117,   118,   120,   121,
     119,   116,    77,    24,     0,     0,   303,   300,   304,   290,
       0,   292,   294,   286,   318,   317,   313,   324,    62,     0,
       0,     0,     0,     0,   267,   266,     0,   244,     0,     0,
     165,     0,   168,     0,   189,   216,   202,   190,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   319,     0,     0,     0,     0,   319,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   175,     0,     0,     0,
     147,     0,     0,   154,     0,     0,     0,   269,     0,   144,
     265,     0,   263,   141,   161,   260,     0,     0,   320,     0,
       0,     0,     0,     0,     0,     0,     0,   104,   105,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     134,     0,     0,   128,   138,   145,     0,     0,     0,     0,
     293,     0,     0,     0,     0,   262,   243,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   176,   205,   204,   203,   193,   191,   192,   179,   180,
     206,   207,   181,   184,   182,   183,   185,   186,   187,   188,
     208,   209,   210,   211,   194,   195,   196,   177,   178,   212,
     213,   197,   198,   200,   199,   201,   214,   215,     0,     0,
       0,   237,     0,     0,     0,     0,     0,     0,   271,   142,
     151,     0,     0,     0,   158,     0,     0,   160,   159,   149,
       0,    94,   101,   102,   100,    98,    99,    95,    96,    97,
     103,     0,     0,     0,     0,     0,    73,   137,     0,     0,
       0,    32,    33,    37,    38,     0,   251,   167,   169,   171,
     220,     0,   219,     0,     0,   226,   217,   218,   228,   229,
     230,   225,   224,   227,   241,   231,     0,   233,   234,   235,
     240,   166,   236,     0,   150,   148,     0,   164,   163,   162,
     270,     0,   156,   321,   172,   155,     0,     0,     0,     0,
       0,    74,   139,     0,     0,    26,    25,     0,     0,   242,
       0,     0,     0,     0,     0,     0,   153,     0,     0,     0,
     130,   133,   135,   136,    56,    51,   221,   222,   223,   232,
     238,   152,     0,     0,     0,     0,     0,     0,   157,   131,
     132
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -320,  -320,  1668,  1669,  -320,  -320,  -320,  -320,  -320,  -320,
    -320,  -320,  -320,  -320,  -320,  -320,  -320,  1586,  -320,  -320,
    -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  -320,  1460,
    -320,  -320,  -320,  -196,   -61,  -320,  1561,  -320,  -320,  -135,
    -320,  1082,  -320,  -320,  1343,  1193,  -320,  -199,  -140,  -198,
    -127,  1242,  1376,  -139,  -320,   -91,   -53,  1679,  -320,  -320,
    1089,  -320,  -320,  -320,   410,  -320,  -320,  -320,  -319,  -320,
      15
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,    14,    15,     3,    16,    17,    18,    19,    20,
      74,    78,    21,    22,    23,    24,   115,   116,    25,    26,
      27,    28,    29,    30,    31,    32,    53,   185,    33,   365,
      34,    35,    36,   355,   152,   153,   154,   155,   156,   234,
     362,   627,   514,   515,   140,   141,   220,   488,   325,   292,
     326,   223,   224,   293,   337,   356,   327,    96,   179,   263,
     112,   165,   175,   256,   121,   173,   182,   267,   489,   184,
      75
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     157,   221,   225,   295,   324,    80,   296,   157,   168,   281,
       5,     6,   665,   363,   222,    38,   625,   176,   230,   249,
     231,   265,   346,   232,   242,     1,   491,   282,    90,   110,
      97,   266,    37,   180,   157,    79,     6,   159,   470,   196,
     366,   367,   368,   369,   370,   371,   380,   230,   181,   231,
     271,   157,   232,   509,   111,   106,   467,   109,   510,   468,
     157,   250,   469,   171,   186,   172,   511,   336,   364,   279,
     251,    81,   512,    82,     4,   118,   252,   119,   253,   331,
       7,     8,     9,   196,   513,    51,    83,    84,   226,    10,
     229,   177,   399,   199,   120,   401,   254,    50,   403,   404,
     405,   406,   407,   545,    52,    85,     8,     9,   550,   114,
     132,   133,   134,   135,    10,    91,   626,    98,   178,    11,
     381,    89,   382,   384,   428,    92,   466,    92,    93,    94,
      99,   100,   297,   385,   666,   209,    39,   199,    12,   157,
     157,   157,   486,   280,    11,   490,   233,    13,   383,   386,
     495,   329,   107,   280,   338,   497,   498,    95,   499,   101,
     471,   341,  -265,    12,    86,  -264,  -265,   472,   342,   359,
     360,   361,    13,   358,   349,   357,   347,    54,   350,   209,
     247,   276,   348,   357,   357,   357,   357,   357,   357,   257,
      55,   212,   328,   214,   260,   215,   216,   217,   283,  -263,
     277,   284,   212,  -263,   214,   477,   215,   216,   217,   531,
     532,   533,   534,   535,   536,   537,   538,   539,   540,   541,
     542,   543,   544,   113,   546,   547,   548,   549,   103,   104,
     552,   553,   554,   555,   556,   557,   558,   559,   560,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,   571,
     572,   573,   574,   575,   576,   577,   578,   579,   580,   581,
     582,   583,   584,   585,   586,   587,   525,   588,   261,   114,
     262,   378,   592,   503,   504,   196,   505,   506,   117,   280,
     507,   508,   124,   482,   505,   506,   125,   197,   507,   508,
     197,   231,   500,   606,   232,   501,   126,   502,   357,   357,
     127,   357,   128,   129,   612,   613,   614,   615,   616,   617,
     618,   619,   620,   595,   503,   504,   596,   505,   506,   130,
     196,   507,   508,   230,   683,   231,   131,   684,   232,   199,
     136,   429,   430,   431,   432,   285,   137,   433,   285,   434,
     280,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     464,   209,   197,   276,   199,   269,   270,   286,   332,   287,
     286,   138,   287,   212,   139,   214,   158,   215,   216,   217,
     602,   603,   277,   288,   289,   290,   288,   289,   290,   163,
      56,   278,   671,   198,   673,   236,   160,   291,   237,   238,
     239,   240,    47,    48,    49,   161,   209,   611,   276,   191,
     285,   192,   605,   603,   654,   603,   679,   680,   212,   162,
     214,    76,   215,   216,   217,   660,   603,   277,   507,   508,
     685,   686,   690,   164,   691,   692,   476,   357,   357,   357,
     357,   357,   357,   357,   357,   357,   166,   693,   122,   123,
     167,   170,   286,   528,   287,   183,   174,   695,   187,   188,
     670,   189,   190,   193,   333,   194,   334,   195,   288,   289,
     290,   228,   235,   243,   221,   225,   212,   244,   214,   294,
     215,   216,   217,   248,   259,   335,   258,   222,   264,   268,
     272,    57,   273,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,   715,    68,    69,    70,    71,    72,   233,
      73,   241,   458,   459,   460,   461,   462,   463,   464,   274,
     677,   275,    77,   340,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,   280,    68,    69,    70,    71,    72,
     330,    73,   454,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   464,   339,   343,   344,   373,   345,   678,   357,
     357,   226,   429,   430,   431,   432,   374,   379,   433,   388,
     434,   375,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   429,   430,   431,   432,   387,   389,   433,   393,
     434,   394,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   429,   430,   431,   432,   390,   391,   433,   392,
     434,   395,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   396,   397,   398,   429,   430,   431,   432,   400,
     473,   433,   402,   434,   529,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   429,   430,   431,   432,   408,
     474,   433,   409,   434,   530,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   410,   411,   429,   430,   431,
     432,   655,   656,   433,   412,   434,   413,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   464,   414,   429,   430,
     431,   432,   475,   485,   433,   641,   434,   415,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   416,   478,   433,   643,   434,   417,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   418,   419,   433,  -272,   434,   644,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   420,   421,   433,   422,   434,   551,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   423,   424,   433,   425,   434,   640,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   426,   427,   433,   483,   434,   642,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   484,   487,   433,   493,   434,   645,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   494,   496,   433,   232,   434,   646,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   517,   518,   433,   520,   434,   647,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   519,   521,   433,   522,   434,   648,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   523,   524,   433,   526,   434,   649,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   527,   590,   433,   591,   434,   650,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   593,   594,   433,   597,   434,   651,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   598,   601,   433,  -264,   434,   652,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   599,   607,   433,   610,   434,   653,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   608,   622,   433,   621,   434,   657,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   623,   628,   433,   630,   434,   658,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   629,   631,   433,   632,   434,   659,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   633,   634,   433,   635,   434,   706,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   429,   430,
     431,   432,   636,   662,   433,   637,   434,   707,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   638,    40,
      40,   639,   661,   663,   479,   667,    41,   708,    42,    42,
     668,   196,   669,   672,   212,   674,   214,   676,   215,   216,
     217,    43,    43,   480,   687,   689,   694,   697,    44,    44,
     698,    45,    45,   298,   699,   299,   198,    46,    46,   702,
     703,   704,   705,   300,   301,   302,   303,   709,   304,   305,
     306,   307,   308,   309,   310,   311,   312,   313,   314,   315,
     316,   317,   318,   319,   320,   199,   710,   712,   500,   700,
     713,   501,   716,   502,   717,   714,   719,   720,   196,    87,
      88,   169,   372,   227,   197,   492,   682,   516,   624,   589,
     503,   504,   481,   505,   506,   102,   625,   507,   508,   688,
       0,     0,     0,   198,     0,     0,     0,   209,     0,   276,
       0,     0,     0,     0,   321,     0,     0,     0,     0,   212,
     322,   214,     0,   215,   216,   217,     0,     0,   277,   351,
       0,   323,   199,   200,   201,   202,   203,     0,     0,     0,
     352,     0,   142,     0,   196,     0,     0,     0,     0,     0,
     197,     0,     0,     0,   143,   144,   145,   146,     0,     0,
     147,   148,   149,     0,   204,   205,   206,   150,   208,   198,
     151,     0,     0,     0,   209,     0,   210,     0,     0,     0,
       0,   211,     0,     0,     0,     0,   212,   213,   214,     0,
     215,   216,   217,   218,     0,   219,   681,     0,   199,   200,
     201,   202,   203,     0,   353,     0,     0,     0,     0,     0,
       0,   143,   144,   145,   146,   212,     0,   214,   148,   215,
     216,   217,     0,     0,     0,     0,     0,   354,     0,     0,
     204,   205,   206,   207,   208,     0,     0,     0,     0,     0,
     209,     0,   210,     0,     0,     0,     0,   211,     0,     0,
       0,     0,   212,   213,   214,     0,   215,   216,   217,   218,
       0,   219,   429,   430,   431,   432,     0,     0,   433,     0,
     434,     0,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,     0,     0,     0,     0,     0,   143,   144,   145,
     146,     0,     0,   147,   148,   149,   429,   430,   431,   432,
     150,   600,   433,   151,   434,   465,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   604,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   609,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   664,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   675,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   696,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   711,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,   718,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   429,   430,   431,   432,
       0,     0,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   430,   431,   432,     0,
       0,   433,     0,   434,     0,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   432,     0,     0,   433,     0,
     434,     0,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   464,   433,     0,   434,     0,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   434,     0,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   500,   701,
       0,   501,     0,   502,     0,     0,     0,   500,     0,     0,
     501,     0,   502,     0,     0,     0,     0,     0,     0,     0,
     503,   504,     0,   505,   506,     0,     0,   507,   508,   503,
     504,     0,   505,   506,     0,     0,   507,   508,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   501,     0,
     502,   143,   144,   145,   146,   212,     0,   214,   148,   215,
     216,   217,     0,     0,     0,     0,     0,   503,   504,     0,
     505,   506,     0,     0,   507,   508,   245,     0,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,     0,    68,
      69,    70,    71,    72,     0,    73,     0,     0,     0,     0,
       0,   376,   246,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,     0,    68,    69,    70,    71,    72,     0,
      73,     0,     0,     0,     0,     0,     0,   377,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   464,  -273,  -273,  -273,  -273,  -273,  -273,
    -273,  -273,  -273,  -273,  -273,  -273,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     502,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   503,   504,     0,
     505,   506,     0,     0,   507,   508,   105,     0,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,     0,    68,
      69,    70,    71,    72,   108,    73,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,     0,    68,    69,    70,
      71,    72,   255,    73,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,     0,    68,    69,    70,    71,    72,
       0,    73
};

static const yytype_int16 yycheck[] =
{
      91,   141,   141,   201,   203,     8,     8,    98,     8,   109,
       0,     1,     8,    81,   141,     8,    29,    33,     6,    65,
       8,   109,   221,    11,   159,    70,   345,   127,     9,   109,
       9,   119,   130,   119,   125,    20,     1,    98,     8,    11,
     236,   237,   238,   239,   240,   241,    33,     6,   134,     8,
     185,   142,    11,   104,   134,    40,   131,    42,   109,   134,
     151,   107,   137,   115,   125,   117,   117,   207,   136,   196,
     109,    74,   123,    76,    78,   115,   115,   117,   117,   206,
      70,    71,    72,    11,   135,   109,    89,    90,   141,    79,
     151,   107,   291,    65,   134,   294,   135,   109,   297,   298,
     299,   300,   301,   422,   128,    70,    71,    72,   427,   109,
      83,    84,    85,    86,    79,    96,   129,    96,   134,   109,
     107,   136,   109,   109,   323,   106,   325,   106,   109,   110,
     109,   110,   134,   119,   130,   107,   129,    65,   128,   230,
     231,   232,   341,   196,   109,   344,   134,   137,   135,   135,
     349,   204,   130,   206,   207,   351,   352,   138,   354,   138,
     130,   130,   130,   128,   129,   134,   134,   137,   137,   230,
     231,   232,   137,   132,   130,   228,   131,   137,   134,   107,
     165,   109,   137,   236,   237,   238,   239,   240,   241,   174,
     137,   119,   109,   121,    33,   123,   124,   125,   134,   130,
     128,   137,   119,   134,   121,   332,   123,   124,   125,   408,
     409,   410,   411,   412,   413,   414,   415,   416,   417,   418,
     419,   420,   421,   119,   423,   424,   425,   426,    87,    88,
     429,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   464,   393,   465,   107,   109,
     109,   256,   471,    29,    30,    11,    32,    33,    91,   332,
      36,    37,   131,   336,    32,    33,   137,    17,    36,    37,
      17,     8,     7,   492,    11,    10,   130,    12,   351,   352,
      83,   354,    85,    86,   500,   501,   502,   503,   504,   505,
     506,   507,   508,   109,    29,    30,   112,    32,    33,   130,
      11,    36,    37,     6,   109,     8,   130,   112,    11,    65,
     130,     3,     4,     5,     6,    65,   130,     9,    65,    11,
     393,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,   107,    17,   109,    65,   132,   133,   107,    11,   109,
     107,   130,   109,   119,   130,   121,   106,   123,   124,   125,
     132,   133,   128,   123,   124,   125,   123,   124,   125,   131,
       8,   137,   601,    36,   603,    14,     8,   134,    17,    18,
      19,    20,    92,    93,    94,     8,   107,   132,   109,    75,
      65,    77,   132,   133,   132,   133,   622,   623,   119,   107,
     121,     8,   123,   124,   125,   132,   133,   128,    36,    37,
      87,    88,   641,   109,   643,   644,   137,   500,   501,   502,
     503,   504,   505,   506,   507,   508,     8,   656,    48,    49,
     130,   130,   107,   135,   109,   109,   134,   666,   131,   131,
     597,   131,   131,   107,   107,   107,   109,   129,   123,   124,
     125,   130,   103,     8,   624,   624,   119,   107,   121,   134,
     123,   124,   125,   119,   107,   128,     8,   624,     8,     8,
     107,   109,   107,   111,   112,   113,   114,   115,   116,   117,
     118,   119,   120,   712,   122,   123,   124,   125,   126,   134,
     128,   130,    36,    37,    38,    39,    40,    41,    42,   107,
     621,   107,   109,   137,   111,   112,   113,   114,   115,   116,
     117,   118,   119,   120,   597,   122,   123,   124,   125,   126,
     131,   128,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,   123,   131,   130,   132,   131,   621,   622,
     623,   624,     3,     4,     5,     6,   134,   107,     9,   136,
      11,    89,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,     3,     4,     5,     6,   109,   133,     9,   107,
      11,    18,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,     3,     4,     5,     6,   133,   133,     9,   133,
      11,    18,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,   111,   107,   134,     3,     4,     5,     6,     8,
     130,     9,     8,    11,   135,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,   131,
     107,     9,   131,    11,   135,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,   131,   131,     3,     4,     5,
       6,   132,   133,     9,   131,    11,   131,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,   131,     3,     4,
       5,     6,   133,   107,     9,   133,    11,   131,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   131,   137,     9,   133,    11,   131,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   131,   131,     9,     8,    11,   133,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   131,   131,     9,   131,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   131,   131,     9,   131,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   131,   131,     9,     8,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,     8,   107,     9,   107,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   107,   107,     9,    11,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,    78,   107,     9,   107,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   130,   107,     9,   107,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   107,   107,     9,   135,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   111,   107,     9,   107,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   107,   132,     9,   107,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   107,   130,     9,     8,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,     8,   132,     9,   133,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   130,   130,     9,   131,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   130,   130,     9,   107,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   133,   132,     9,   132,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   132,   132,     9,   137,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   135,   132,     9,     8,    11,   132,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     8,    73,
      73,     8,     8,   133,   109,     8,    80,   132,    82,    82,
       8,    11,     8,     8,   119,     8,   121,   107,   123,   124,
     125,    95,    95,   128,   107,   107,   107,   135,   102,   102,
     133,   105,   105,    33,   133,    35,    36,   111,   111,    30,
      30,   135,     8,    43,    44,    45,    46,   132,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,   135,   130,     7,     8,
     117,    10,   132,    12,   132,   117,     8,     8,    11,    31,
      31,   115,   242,   142,    17,   130,   624,   364,   515,   467,
      29,    30,   336,    32,    33,    36,    29,    36,    37,   630,
      -1,    -1,    -1,    36,    -1,    -1,    -1,   107,    -1,   109,
      -1,    -1,    -1,    -1,   114,    -1,    -1,    -1,    -1,   119,
     120,   121,    -1,   123,   124,   125,    -1,    -1,   128,    33,
      -1,   131,    65,    66,    67,    68,    69,    -1,    -1,    -1,
      44,    -1,   103,    -1,    11,    -1,    -1,    -1,    -1,    -1,
      17,    -1,    -1,    -1,   115,   116,   117,   118,    -1,    -1,
     121,   122,   123,    -1,    97,    98,    99,   128,   101,    36,
     131,    -1,    -1,    -1,   107,    -1,   109,    -1,    -1,    -1,
      -1,   114,    -1,    -1,    -1,    -1,   119,   120,   121,    -1,
     123,   124,   125,   126,    -1,   128,   129,    -1,    65,    66,
      67,    68,    69,    -1,   108,    -1,    -1,    -1,    -1,    -1,
      -1,   115,   116,   117,   118,   119,    -1,   121,   122,   123,
     124,   125,    -1,    -1,    -1,    -1,    -1,   131,    -1,    -1,
      97,    98,    99,   100,   101,    -1,    -1,    -1,    -1,    -1,
     107,    -1,   109,    -1,    -1,    -1,    -1,   114,    -1,    -1,
      -1,    -1,   119,   120,   121,    -1,   123,   124,   125,   126,
      -1,   128,     3,     4,     5,     6,    -1,    -1,     9,    -1,
      11,    -1,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,    -1,    -1,    -1,    -1,    -1,   115,   116,   117,
     118,    -1,    -1,   121,   122,   123,     3,     4,     5,     6,
     128,     8,     9,   131,    11,    66,    13,    14,    15,    16,
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
      35,    36,    37,    38,    39,    40,    41,    42,     7,     8,
      -1,    10,    -1,    12,    -1,    -1,    -1,     7,    -1,    -1,
      10,    -1,    12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      29,    30,    -1,    32,    33,    -1,    -1,    36,    37,    29,
      30,    -1,    32,    33,    -1,    -1,    36,    37,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    10,    -1,
      12,   115,   116,   117,   118,   119,    -1,   121,   122,   123,
     124,   125,    -1,    -1,    -1,    -1,    -1,    29,    30,    -1,
      32,    33,    -1,    -1,    36,    37,   109,    -1,   111,   112,
     113,   114,   115,   116,   117,   118,   119,   120,    -1,   122,
     123,   124,   125,   126,    -1,   128,    -1,    -1,    -1,    -1,
      -1,   109,   135,   111,   112,   113,   114,   115,   116,   117,
     118,   119,   120,    -1,   122,   123,   124,   125,   126,    -1,
     128,    -1,    -1,    -1,    -1,    -1,    -1,   135,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
      12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    29,    30,    -1,
      32,    33,    -1,    -1,    36,    37,   109,    -1,   111,   112,
     113,   114,   115,   116,   117,   118,   119,   120,    -1,   122,
     123,   124,   125,   126,   109,   128,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,    -1,   122,   123,   124,
     125,   126,   109,   128,   111,   112,   113,   114,   115,   116,
     117,   118,   119,   120,    -1,   122,   123,   124,   125,   126,
      -1,   128
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    70,   140,   143,    78,     0,     1,    70,    71,    72,
      79,   109,   128,   137,   141,   142,   144,   145,   146,   147,
     148,   151,   152,   153,   154,   157,   158,   159,   160,   161,
     162,   163,   164,   167,   169,   170,   171,   130,     8,   129,
      73,    80,    82,    95,   102,   105,   111,    92,    93,    94,
     109,   109,   128,   165,   137,   137,     8,   109,   111,   112,
     113,   114,   115,   116,   117,   118,   119,   120,   122,   123,
     124,   125,   126,   128,   149,   209,     8,   109,   150,   209,
       8,    74,    76,    89,    90,    70,   129,   141,   142,   136,
       9,    96,   106,   109,   110,   138,   196,     9,    96,   109,
     110,   138,   196,    87,    88,   109,   209,   130,   109,   209,
     109,   134,   199,   119,   109,   155,   156,    91,   115,   117,
     134,   203,   203,   203,   131,   137,   130,    83,    85,    86,
     130,   130,    83,    84,    85,    86,   130,   130,   130,   130,
     183,   184,   103,   115,   116,   117,   118,   121,   122,   123,
     128,   131,   173,   174,   175,   176,   177,   194,   106,   173,
       8,     8,   107,   131,   109,   200,     8,   130,     8,   156,
     130,   115,   117,   204,   134,   201,    33,   107,   134,   197,
     119,   134,   205,   109,   208,   166,   173,   131,   131,   131,
     131,    75,    77,   107,   107,   129,    11,    17,    36,    65,
      66,    67,    68,    69,    97,    98,    99,   100,   101,   107,
     109,   114,   119,   120,   121,   123,   124,   125,   126,   128,
     185,   187,   189,   190,   191,   192,   195,   175,   130,   173,
       6,     8,    11,   134,   178,   103,    14,    17,    18,    19,
      20,   130,   178,     8,   107,   109,   135,   209,   119,    65,
     107,   109,   115,   117,   135,   109,   202,   209,     8,   107,
      33,   107,   109,   198,     8,   109,   119,   206,     8,   132,
     133,   178,   107,   107,   107,   107,   109,   128,   137,   189,
     195,   109,   127,   134,   137,    65,   107,   109,   123,   124,
     125,   134,   188,   192,   134,   188,     8,   134,    33,    35,
      43,    44,    45,    46,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,   114,   120,   131,   186,   187,   189,   195,   109,   195,
     131,   189,    11,   107,   109,   128,   187,   193,   195,   123,
     137,   130,   137,   131,   130,   131,   186,   131,   137,   130,
     134,    33,    44,   108,   131,   172,   194,   195,   132,   173,
     173,   173,   179,    81,   136,   168,   172,   172,   172,   172,
     172,   172,   168,   132,   134,    89,   109,   135,   209,   107,
      33,   107,   109,   135,   109,   119,   135,   109,   136,   133,
     133,   133,   133,   107,    18,    18,   111,   107,   134,   186,
       8,   186,     8,   186,   186,   186,   186,   186,   131,   131,
     131,   131,   131,   131,   131,   131,   131,   131,   131,   131,
     131,   131,   131,   131,   131,   131,   131,   131,   186,     3,
       4,     5,     6,     9,    11,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    66,   186,   131,   134,   137,
       8,   130,   137,   130,   107,   133,   137,   189,   137,   109,
     128,   191,   195,     8,     8,   107,   186,   107,   186,   207,
     186,   207,   130,   107,   107,   186,   107,   172,   172,   172,
       7,    10,    12,    29,    30,    32,    33,    36,    37,   104,
     109,   117,   123,   135,   181,   182,   183,    78,   107,   130,
     107,   107,   107,   107,   107,   189,   135,   111,   135,   135,
     135,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   207,   186,   186,   186,   186,
     207,   132,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   186,   186,
     186,   186,   186,   186,   186,   186,   186,   186,   188,   190,
     107,   107,   186,   107,   132,   109,   112,   107,   107,     8,
       8,   130,   132,   133,     8,   132,   186,   132,   130,     8,
     133,   132,   172,   172,   172,   172,   172,   172,   172,   172,
     172,   131,   130,   130,   184,    29,   129,   180,   130,   133,
     107,   132,   132,   132,   132,   137,   135,     8,     8,     8,
     132,   133,   132,   133,   133,   132,   132,   132,   132,   132,
     132,   132,   132,   132,   132,   132,   133,   132,   132,   132,
     132,     8,   132,   133,     8,     8,   130,     8,     8,     8,
     189,   186,     8,   186,     8,     8,   107,   194,   195,   172,
     172,   129,   180,   109,   112,    87,    88,   107,   199,   107,
     186,   186,   186,   186,   107,   186,     8,   135,   133,   133,
       8,     8,    30,    30,   135,     8,   132,   132,   132,   132,
     135,     8,   130,   117,   117,   186,   132,   132,     8,     8,
       8
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
     186,   186,   187,   187,   187,   187,   188,   188,   188,   188,
     188,   188,   188,   188,   189,   189,   189,   189,   190,   190,
     190,   190,   190,   191,   191,   191,   192,   192,   193,   193,
     193,   193,   193,   193,   194,   194,   194,   194,   194,   195,
     195,   195,   195,   195,   196,   196,   197,   197,   197,   198,
     198,   198,   198,   198,   198,   199,   199,   200,   200,   200,
     201,   202,   202,   202,   202,   203,   203,   203,   204,   204,
     204,   204,   204,   205,   205,   206,   206,   206,   206,   207,
     207,   207,   208,   208,   208,   209,   209,   209,   209,   209,
     209,   209,   209,   209,   209,   209,   209,   209,   209,   209,
     209
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
       4,     4,     6,     4,     4,     4,     4,     3,     6,     1,
       4,     4,     6,     4,     3,     1,     1,     1,     1,     1,
       1,     4,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     2,     4,     1,     1,     1,     3,     3,     1,     2,
       4,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     3,     1,     2,     1,
       2,     1,     2,     3,     2,     3,     1,     1,     2,     2,
       3,     1,     1,     2,     2,     3,     1,     1,     1,     1,
       2,     2,     2,     3,     1,     1,     1,     2,     2,     0,
       1,     3,     0,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1
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
#if YYDEBUG

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
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


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
#line 175 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->resetConstructors(); }
#line 2299 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 20:
#line 177 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->setEndian(1); }
#line 2305 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 21:
#line 178 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->setEndian(0); }
#line 2311 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 22:
#line 180 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->setAlignment(*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 2317 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 23:
#line 182 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    {}
#line 2323 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 24:
#line 184 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = slgh->defineToken((yyvsp[-3].str),(yyvsp[-1].i),0); }
#line 2329 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 25:
#line 185 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),-1); }
#line 2335 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 26:
#line 186 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),1); }
#line 2341 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 27:
#line 187 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = (yyvsp[-1].tokensym); slgh->addTokenField((yyvsp[-1].tokensym),(yyvsp[0].fieldqual)); }
#line 2347 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 28:
#line 188 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg=(yyvsp[0].anysym)->getName()+": redefined as a token"; yyerror(errmsg.c_str()); YYERROR; }
#line 2353 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 29:
#line 190 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    {}
#line 2359 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 30:
#line 192 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varsym) = (yyvsp[0].varsym); }
#line 2365 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 31:
#line 193 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varsym) = (yyvsp[-1].varsym); if (!slgh->addContextField( (yyvsp[-1].varsym), (yyvsp[0].fieldqual) ))
                                            { yyerror("All context definitions must come before constructors"); YYERROR; } }
#line 2372 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 32:
#line 196 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
#line 2378 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 33:
#line 197 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; yyerror(errmsg.c_str()); YYERROR; }
#line 2384 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 34:
#line 198 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
#line 2390 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 35:
#line 199 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
#line 2396 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 36:
#line 200 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
#line 2402 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 37:
#line 202 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
#line 2408 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 38:
#line 203 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; yyerror(errmsg.c_str()); YYERROR; }
#line 2414 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 39:
#line 204 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
#line 2420 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 40:
#line 205 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->flow = false; }
#line 2426 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 41:
#line 206 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
#line 2432 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 42:
#line 207 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
#line 2438 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 43:
#line 209 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->newSpace((yyvsp[-1].spacequal)); }
#line 2444 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 44:
#line 211 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = new SpaceQuality(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2450 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 45:
#line 212 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = (yyvsp[0].anysym)->getName()+": redefined as space"; yyerror(errmsg.c_str()); YYERROR; }
#line 2456 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 46:
#line 213 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::ramtype; }
#line 2462 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 47:
#line 214 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::registertype; }
#line 2468 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 48:
#line 215 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->size = *(yyvsp[0].i); delete (yyvsp[0].i); }
#line 2474 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 49:
#line 216 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->wordsize = *(yyvsp[0].i); delete (yyvsp[0].i); }
#line 2480 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 50:
#line 217 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-1].spacequal); (yyval.spacequal)->isdefault = true; }
#line 2486 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 51:
#line 219 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    {
               slgh->defineVarnodes((yyvsp[-8].spacesym),(yyvsp[-5].i),(yyvsp[-2].i),(yyvsp[-1].strlist)); }
#line 2493 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 52:
#line 221 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { yyerror("Parsed integer is too big (overflow)"); YYERROR; }
#line 2499 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 56:
#line 228 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    {
               slgh->defineBitrange((yyvsp[-7].str),(yyvsp[-5].varsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i); delete (yyvsp[-1].i); }
#line 2506 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 57:
#line 231 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->addUserOp((yyvsp[-1].strlist)); }
#line 2512 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 58:
#line 233 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->attachValues((yyvsp[-2].symlist),(yyvsp[-1].biglist)); }
#line 2518 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 59:
#line 235 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->attachNames((yyvsp[-2].symlist),(yyvsp[-1].strlist)); }
#line 2524 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 60:
#line 237 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->attachVarnodes((yyvsp[-2].symlist),(yyvsp[-1].symlist)); }
#line 2530 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 61:
#line 239 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->buildMacro((yyvsp[-3].macrosym),(yyvsp[-1].sem)); }
#line 2536 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 62:
#line 242 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    {  slgh->pushWith((yyvsp[-4].subtablesym),(yyvsp[-2].pateq),(yyvsp[-1].contop)); }
#line 2542 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 66:
#line 248 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->popWith(); }
#line 2548 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 67:
#line 250 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.subtablesym) = (SubtableSymbol *)0; }
#line 2554 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 68:
#line 251 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.subtablesym) = (yyvsp[0].subtablesym); }
#line 2560 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 69:
#line 252 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.subtablesym) = slgh->newTable((yyvsp[0].str)); }
#line 2566 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 70:
#line 255 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = (PatternEquation *)0; }
#line 2572 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 71:
#line 256 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = (yyvsp[0].pateq); }
#line 2578 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 72:
#line 259 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.macrosym) = slgh->createMacro((yyvsp[-3].str),(yyvsp[-1].strlist)); }
#line 2584 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 73:
#line 261 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->standaloneSection((yyvsp[-1].sem)); }
#line 2590 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 74:
#line 262 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->finalNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem)); }
#line 2596 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 75:
#line 263 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = (SectionVector *)0; }
#line 2602 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 76:
#line 265 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
#line 2608 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 77:
#line 266 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
#line 2614 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 78:
#line 268 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2620 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 79:
#line 269 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2626 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 80:
#line 270 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); if (slgh->isInRoot((yyvsp[-1].construct))) { (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); } else slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
#line 2632 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 81:
#line 271 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); if (!slgh->isInRoot((yyvsp[-1].construct))) { yyerror("Unexpected '^' at start of print pieces");  YYERROR; } }
#line 2638 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 82:
#line 272 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); }
#line 2644 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 83:
#line 273 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2650 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 84:
#line 274 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2656 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 85:
#line 275 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(string(" ")); }
#line 2662 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 86:
#line 276 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
#line 2668 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 87:
#line 278 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = slgh->createConstructor((yyvsp[-1].subtablesym)); }
#line 2674 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 88:
#line 279 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { SubtableSymbol *sym=slgh->newTable((yyvsp[-1].str)); (yyval.construct) = slgh->createConstructor(sym); }
#line 2680 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 89:
#line 280 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = slgh->createConstructor((SubtableSymbol *)0); }
#line 2686 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 90:
#line 281 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); }
#line 2692 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 91:
#line 283 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new ConstantValue(*(yyvsp[0].big)); delete (yyvsp[0].big); }
#line 2698 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 92:
#line 285 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { if ((actionon==1)&&((yyvsp[0].famsym)->getType() != SleighSymbol::context_symbol))
                                             { string errmsg="Global symbol "+(yyvsp[0].famsym)->getName(); errmsg += " is not allowed in action expression"; yyerror(errmsg.c_str()); } (yyval.patexp) = (yyvsp[0].famsym)->getPatternValue(); }
#line 2705 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 93:
#line 288 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = (yyvsp[0].specsym)->getPatternExpression(); }
#line 2711 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 94:
#line 289 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = (yyvsp[-1].patexp); }
#line 2717 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 95:
#line 290 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new PlusExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2723 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 96:
#line 291 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new SubExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2729 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 97:
#line 292 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new MultExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2735 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 98:
#line 293 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new LeftShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2741 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 99:
#line 294 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new RightShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2747 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 100:
#line 295 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new AndExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2753 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 101:
#line 296 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new OrExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2759 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 102:
#line 297 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new XorExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2765 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 103:
#line 298 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new DivExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2771 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 104:
#line 299 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new MinusExpression((yyvsp[0].patexp)); }
#line 2777 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 105:
#line 300 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new NotExpression((yyvsp[0].patexp)); }
#line 2783 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 107:
#line 303 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationAnd((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
#line 2789 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 108:
#line 304 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationOr((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
#line 2795 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 109:
#line 305 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationCat((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
#line 2801 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 110:
#line 307 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationLeftEllipsis((yyvsp[0].pateq)); }
#line 2807 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 112:
#line 310 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationRightEllipsis((yyvsp[-1].pateq)); }
#line 2813 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 115:
#line 314 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = (yyvsp[-1].pateq); }
#line 2819 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 116:
#line 316 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2825 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 117:
#line 317 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new NotEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2831 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 118:
#line 318 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new LessEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2837 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 119:
#line 319 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new LessEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2843 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 120:
#line 320 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new GreaterEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2849 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 121:
#line 321 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new GreaterEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2855 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 122:
#line 322 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = slgh->constrainOperand((yyvsp[-2].operandsym),(yyvsp[0].patexp)); 
                                          if ((yyval.pateq) == (PatternEquation *)0) 
                                            { string errmsg="Constraining currently undefined operand "+(yyvsp[-2].operandsym)->getName(); yyerror(errmsg.c_str()); } }
#line 2863 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 123:
#line 325 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new OperandEquation((yyvsp[0].operandsym)->getIndex()); slgh->selfDefine((yyvsp[0].operandsym)); }
#line 2869 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 124:
#line 326 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new UnconstrainedEquation((yyvsp[0].specsym)->getPatternExpression()); }
#line 2875 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 125:
#line 327 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].famsym)); }
#line 2881 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 126:
#line 328 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].subtablesym)); }
#line 2887 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 127:
#line 330 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (vector<ContextChange *> *)0; }
#line 2893 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 128:
#line 331 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-1].contop); }
#line 2899 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 129:
#line 333 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = new vector<ContextChange *>; }
#line 2905 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 130:
#line 334 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-4].contop); if (!slgh->contextMod((yyvsp[-4].contop),(yyvsp[-3].contextsym),(yyvsp[-1].patexp))) { string errmsg="Cannot use 'inst_next' to set context variable: "+(yyvsp[-3].contextsym)->getName(); yyerror(errmsg.c_str()); YYERROR; } }
#line 2911 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 131:
#line 335 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].famsym),(yyvsp[-2].contextsym)); }
#line 2917 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 132:
#line 336 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].specsym),(yyvsp[-2].contextsym)); }
#line 2923 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 133:
#line 337 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-4].contop); slgh->defineOperand((yyvsp[-3].operandsym),(yyvsp[-1].patexp)); }
#line 2929 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 134:
#line 338 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg="Expecting context symbol, not "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2935 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 135:
#line 340 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionsym) = slgh->newSectionSymbol( *(yyvsp[-1].str) ); delete (yyvsp[-1].str); }
#line 2941 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 136:
#line 341 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionsym) = (yyvsp[-1].sectionsym); }
#line 2947 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 137:
#line 343 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->firstNamedSection((yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
#line 2953 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 138:
#line 345 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = (yyvsp[0].sectionstart); }
#line 2959 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 139:
#line 346 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->nextNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
#line 2965 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 140:
#line 348 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[0].sem); if ((yyval.sem)->getOpvec().empty() && ((yyval.sem)->getResult() == (HandleTpl *)0)) slgh->recordNop(); }
#line 2971 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 141:
#line 349 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = slgh->setResultVarnode((yyvsp[-3].sem),(yyvsp[-1].varnode)); }
#line 2977 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 142:
#line 350 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = slgh->setResultStarVarnode((yyvsp[-4].sem),(yyvsp[-2].starqual),(yyvsp[-1].varnode)); }
#line 2983 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 143:
#line 351 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2989 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 144:
#line 352 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg="Unknown pointer varnode: "+*(yyvsp[0].str); delete (yyvsp[-1].starqual); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2995 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 145:
#line 354 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = new ConstructTpl(); }
#line 3001 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 146:
#line 355 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[0].stmt); yyerror("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }
#line 3007 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 147:
#line 356 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[-3].sem); slgh->pcode.newLocalDefinition((yyvsp[-1].str)); }
#line 3013 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 148:
#line 357 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[-5].sem); slgh->pcode.newLocalDefinition((yyvsp[-3].str),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 3019 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 149:
#line 359 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyvsp[-1].tree)->setOutput((yyvsp[-3].varnode)); (yyval.stmt) = ExprTree::toVector((yyvsp[-1].tree)); }
#line 3025 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 150:
#line 360 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-3].str)); }
#line 3031 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 151:
#line 361 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(false,(yyvsp[-1].tree),(yyvsp[-3].str)); }
#line 3037 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 152:
#line 362 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
#line 3043 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 153:
#line 363 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
#line 3049 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 154:
#line 364 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+(yyvsp[-1].specsym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3055 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 155:
#line 365 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createStore((yyvsp[-4].starqual),(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3061 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 156:
#line 366 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createUserOpNoOut((yyvsp[-4].useropsym),(yyvsp[-2].param)); }
#line 3067 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 157:
#line 367 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.assignBitRange((yyvsp[-8].varnode),(uint4)*(yyvsp[-6].i),(uint4)*(yyvsp[-4].i),(yyvsp[-1].tree)); delete (yyvsp[-6].i), delete (yyvsp[-4].i); }
#line 3073 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 158:
#line 368 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt)=slgh->pcode.assignBitRange((yyvsp[-3].bitsym)->getParentSymbol()->getVarnode(),(yyvsp[-3].bitsym)->getBitOffset(),(yyvsp[-3].bitsym)->numBits(),(yyvsp[-1].tree)); }
#line 3079 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 159:
#line 369 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal truncation on left-hand side of assignment"); YYERROR; }
#line 3085 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 160:
#line 370 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal subpiece on left-hand side of assignment"); YYERROR; }
#line 3091 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 161:
#line 371 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpConst(BUILD,(yyvsp[-1].operandsym)->getIndex()); }
#line 3097 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 162:
#line 372 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),(yyvsp[-1].sectionsym)); }
#line 3103 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 163:
#line 373 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),slgh->newSectionSymbol(*(yyvsp[-1].str))); delete (yyvsp[-1].str); }
#line 3109 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 164:
#line 374 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpConst(DELAY_SLOT,*(yyvsp[-2].i)); delete (yyvsp[-2].i); }
#line 3115 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 165:
#line 375 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCH,new ExprTree((yyvsp[-1].varnode))); }
#line 3121 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 166:
#line 376 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CBRANCH,new ExprTree((yyvsp[-1].varnode)),(yyvsp[-3].tree)); }
#line 3127 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 167:
#line 377 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCHIND,(yyvsp[-2].tree)); }
#line 3133 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 168:
#line 378 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALL,new ExprTree((yyvsp[-1].varnode))); }
#line 3139 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 169:
#line 379 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALLIND,(yyvsp[-2].tree)); }
#line 3145 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 170:
#line 380 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { yyerror("Must specify an indirect parameter for return"); YYERROR; }
#line 3151 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 171:
#line 381 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_RETURN,(yyvsp[-2].tree)); }
#line 3157 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 172:
#line 382 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->createMacroUse((yyvsp[-4].macrosym),(yyvsp[-2].param)); }
#line 3163 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 173:
#line 383 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.placeLabel( (yyvsp[0].labelsym) ); }
#line 3169 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 174:
#line 385 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = new ExprTree((yyvsp[0].varnode)); }
#line 3175 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 175:
#line 386 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createLoad((yyvsp[-1].starqual),(yyvsp[0].tree)); }
#line 3181 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 176:
#line 387 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = (yyvsp[-1].tree); }
#line 3187 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 177:
#line 388 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3193 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 178:
#line 389 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3199 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 179:
#line 390 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3205 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 180:
#line 391 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3211 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 181:
#line 392 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3217 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 182:
#line 393 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3223 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 183:
#line 394 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3229 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 184:
#line 395 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3235 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 185:
#line 396 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3241 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 186:
#line 397 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3247 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 187:
#line 398 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3253 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 188:
#line 399 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3259 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 189:
#line 400 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_2COMP,(yyvsp[0].tree)); }
#line 3265 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 190:
#line 401 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NEGATE,(yyvsp[0].tree)); }
#line 3271 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 191:
#line 402 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3277 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 192:
#line 403 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3283 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 193:
#line 404 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3289 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 194:
#line 405 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LEFT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3295 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 195:
#line 406 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_RIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3301 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 196:
#line 407 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SRIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3307 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 197:
#line 408 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3313 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 198:
#line 409 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3319 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 199:
#line 410 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SDIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3325 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 200:
#line 411 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_REM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3331 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 201:
#line 412 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SREM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3337 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 202:
#line 413 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_NEGATE,(yyvsp[0].tree)); }
#line 3343 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 203:
#line 414 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3349 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 204:
#line 415 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3355 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 205:
#line 416 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3361 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 206:
#line 417 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3367 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 207:
#line 418 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3373 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 208:
#line 419 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3379 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 209:
#line 420 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3385 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 210:
#line 421 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3391 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 211:
#line 422 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3397 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 212:
#line 423 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3403 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 213:
#line 424 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3409 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 214:
#line 425 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3415 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 215:
#line 426 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3421 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 216:
#line 427 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NEG,(yyvsp[0].tree)); }
#line 3427 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 217:
#line 428 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ABS,(yyvsp[-1].tree)); }
#line 3433 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 218:
#line 429 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SQRT,(yyvsp[-1].tree)); }
#line 3439 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 219:
#line 430 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SEXT,(yyvsp[-1].tree)); }
#line 3445 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 220:
#line 431 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ZEXT,(yyvsp[-1].tree)); }
#line 3451 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 221:
#line 432 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_CARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3457 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 222:
#line 433 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SCARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3463 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 223:
#line 434 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SBORROW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3469 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 224:
#line 435 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOAT2FLOAT,(yyvsp[-1].tree)); }
#line 3475 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 225:
#line 436 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_INT2FLOAT,(yyvsp[-1].tree)); }
#line 3481 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 226:
#line 437 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NAN,(yyvsp[-1].tree)); }
#line 3487 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 227:
#line 438 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_TRUNC,(yyvsp[-1].tree)); }
#line 3493 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 228:
#line 439 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_CEIL,(yyvsp[-1].tree)); }
#line 3499 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 229:
#line 440 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOOR,(yyvsp[-1].tree)); }
#line 3505 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 230:
#line 441 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ROUND,(yyvsp[-1].tree)); }
#line 3511 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 231:
#line 442 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-1].tree)); }
#line 3517 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 232:
#line 443 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3523 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 233:
#line 444 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_POPCOUNT,(yyvsp[-1].tree)); }
#line 3529 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 234:
#line 445 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_COUNTLEADINGZEROS,(yyvsp[-1].tree)); }
#line 3535 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 235:
#line 446 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_COUNTLEADINGONES,(yyvsp[-1].tree)); }
#line 3541 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 236:
#line 447 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }
#line 3547 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 237:
#line 448 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }
#line 3553 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 238:
#line 449 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }
#line 3559 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 239:
#line 450 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree)=slgh->pcode.createBitRange((yyvsp[0].bitsym)->getParentSymbol(),(yyvsp[0].bitsym)->getBitOffset(),(yyvsp[0].bitsym)->numBits()); }
#line 3565 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 240:
#line 451 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }
#line 3571 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 241:
#line 452 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { if ((*(yyvsp[-1].param)).size() < 2) { string errmsg = "Must at least two inputs to cpool"; yyerror(errmsg.c_str()); YYERROR; } (yyval.tree) = slgh->pcode.createVariadic(CPUI_CPOOLREF,(yyvsp[-1].param)); }
#line 3577 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 242:
#line 454 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }
#line 3583 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 243:
#line 455 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }
#line 3589 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 244:
#line 456 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
#line 3595 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 245:
#line 457 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
#line 3601 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 246:
#line 459 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { VarnodeTpl *sym = (yyvsp[0].startsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 3607 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 247:
#line 460 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { VarnodeTpl *sym = (yyvsp[0].endsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 3613 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 248:
#line 461 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }
#line 3619 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 249:
#line 462 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); yyerror("Parsed integer is too big (overflow)"); }
#line 3625 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 250:
#line 463 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].operandsym)->getVarnode(); (yyvsp[0].operandsym)->setCodeAddress(); }
#line 3631 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 251:
#line 464 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }
#line 3637 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 252:
#line 465 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }
#line 3643 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 253:
#line 466 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3649 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 254:
#line 468 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 3655 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 255:
#line 469 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].varnode); }
#line 3661 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 256:
#line 470 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3667 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 257:
#line 471 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3673 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 258:
#line 473 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }
#line 3679 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 259:
#line 474 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); yyerror("Parsed integer is too big (overflow)"); }
#line 3685 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 260:
#line 475 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
#line 3691 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 261:
#line 476 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
#line 3697 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 262:
#line 477 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 3703 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 263:
#line 479 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 3709 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 264:
#line 480 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3715 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 265:
#line 481 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3721 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 266:
#line 483 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.labelsym) = (yyvsp[-1].labelsym); }
#line 3727 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 267:
#line 484 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.labelsym) = slgh->pcode.defineLabel( (yyvsp[-1].str) ); }
#line 3733 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 268:
#line 486 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 3739 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 269:
#line 487 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
#line 3745 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 270:
#line 488 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 3751 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 271:
#line 489 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
#line 3757 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 272:
#line 490 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3763 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 273:
#line 491 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3769 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 274:
#line 493 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].valuesym); }
#line 3775 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 275:
#line 494 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].valuemapsym); }
#line 3781 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 276:
#line 495 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].contextsym); }
#line 3787 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 277:
#line 496 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].namesym); }
#line 3793 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 278:
#line 497 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].varlistsym); }
#line 3799 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 279:
#line 499 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].varsym); }
#line 3805 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 280:
#line 500 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].specsym); }
#line 3811 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 281:
#line 501 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].operandsym); }
#line 3817 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 282:
#line 502 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].startsym); }
#line 3823 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 283:
#line 503 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].endsym); }
#line 3829 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 284:
#line 505 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.str) = new string; (*(yyval.str)) += (yyvsp[0].ch); }
#line 3835 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 285:
#line 506 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[-1].str); (*(yyval.str)) += (yyvsp[0].ch); }
#line 3841 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 286:
#line 508 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = (yyvsp[-1].biglist); }
#line 3847 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 287:
#line 509 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3853 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 288:
#line 510 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3859 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 289:
#line 512 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3865 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 290:
#line 513 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3871 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 291:
#line 514 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
                                  (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
#line 3878 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 292:
#line 516 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3884 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 293:
#line 517 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = (yyvsp[-2].biglist); (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3890 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 294:
#line 518 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
                                  (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
#line 3897 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 295:
#line 521 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); }
#line 3903 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 296:
#line 522 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 3909 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 297:
#line 524 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
#line 3915 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 298:
#line 525 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 3921 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 299:
#line 526 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = (yyvsp[0].anysym)->getName()+": redefined"; yyerror(errmsg.c_str()); YYERROR; }
#line 3927 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 300:
#line 528 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); }
#line 3933 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 301:
#line 530 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
#line 3939 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 302:
#line 531 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( (yyvsp[0].anysym)->getName() ); }
#line 3945 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 303:
#line 532 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 3951 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 304:
#line 533 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back((yyvsp[0].anysym)->getName()); }
#line 3957 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 305:
#line 535 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); }
#line 3963 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 306:
#line 536 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
#line 3969 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 307:
#line 537 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
#line 3975 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 308:
#line 539 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back( (yyvsp[0].valuesym) ); }
#line 3981 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 309:
#line 540 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
#line 3987 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 310:
#line 541 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
#line 3993 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 311:
#line 542 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
#line 3999 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 312:
#line 543 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { string errmsg = *(yyvsp[0].str)+": is not a value pattern"; delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 4005 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 313:
#line 545 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); }
#line 4011 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 314:
#line 546 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
#line 4017 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 315:
#line 548 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
#line 4023 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 316:
#line 549 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
				  (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
#line 4030 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 317:
#line 551 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].varsym)); }
#line 4036 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 318:
#line 552 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
                                  (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
#line 4043 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 319:
#line 555 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.param) = new vector<ExprTree *>; }
#line 4049 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 320:
#line 556 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }
#line 4055 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 321:
#line 557 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }
#line 4061 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 322:
#line 559 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; }
#line 4067 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 323:
#line 560 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 4073 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 324:
#line 561 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-2].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 4079 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 325:
#line 563 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].spacesym); }
#line 4085 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 326:
#line 564 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].sectionsym); }
#line 4091 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 327:
#line 565 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].tokensym); }
#line 4097 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 328:
#line 566 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].useropsym); }
#line 4103 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 329:
#line 567 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].macrosym); }
#line 4109 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 330:
#line 568 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].subtablesym); }
#line 4115 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 331:
#line 569 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].valuesym); }
#line 4121 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 332:
#line 570 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].valuemapsym); }
#line 4127 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 333:
#line 571 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].contextsym); }
#line 4133 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 334:
#line 572 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].namesym); }
#line 4139 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 335:
#line 573 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].varsym); }
#line 4145 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 336:
#line 574 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].varlistsym); }
#line 4151 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 337:
#line 575 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].operandsym); }
#line 4157 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 338:
#line 576 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].startsym); }
#line 4163 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 339:
#line 577 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].endsym); }
#line 4169 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;

  case 340:
#line 578 "src/decompile/cpp/slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].bitsym); }
#line 4175 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
    break;


#line 4179 "src/decompile/cpp/slghparse.cc" /* yacc.c:1646  */
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
#line 580 "src/decompile/cpp/slghparse.y" /* yacc.c:1906  */


int yyerror(const char *s)

{
  slgh->reportError(s);
  return 0;
}

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
#line 16 "slghparse.y" /* yacc.c:339  */

#include "slgh_compile.hh"

#define YYERROR_VERBOSE

  extern SleighCompile *slgh;
  extern int4 actionon;
  extern FILE *yyin;
  extern int yydebug;
  extern int yylex(void);
  extern int yyerror(const char *str );

#line 79 "slghparse.cc" /* yacc.c:339  */

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
#ifndef YY_YY_SLGHPARSE_HH_INCLUDED
# define YY_YY_SLGHPARSE_HH_INCLUDED
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
    BADINTEGER = 305,
    GOTO_KEY = 306,
    CALL_KEY = 307,
    RETURN_KEY = 308,
    IF_KEY = 309,
    DEFINE_KEY = 310,
    ATTACH_KEY = 311,
    MACRO_KEY = 312,
    SPACE_KEY = 313,
    TYPE_KEY = 314,
    RAM_KEY = 315,
    DEFAULT_KEY = 316,
    REGISTER_KEY = 317,
    ENDIAN_KEY = 318,
    WITH_KEY = 319,
    ALIGN_KEY = 320,
    OP_UNIMPL = 321,
    TOKEN_KEY = 322,
    SIGNED_KEY = 323,
    NOFLOW_KEY = 324,
    HEX_KEY = 325,
    DEC_KEY = 326,
    BIG_KEY = 327,
    LITTLE_KEY = 328,
    SIZE_KEY = 329,
    WORDSIZE_KEY = 330,
    OFFSET_KEY = 331,
    NAMES_KEY = 332,
    VALUES_KEY = 333,
    VARIABLES_KEY = 334,
    PCODEOP_KEY = 335,
    IS_KEY = 336,
    LOCAL_KEY = 337,
    DELAYSLOT_KEY = 338,
    CROSSBUILD_KEY = 339,
    EXPORT_KEY = 340,
    BUILD_KEY = 341,
    CONTEXT_KEY = 342,
    ELLIPSIS_KEY = 343,
    GLOBALSET_KEY = 344,
    BITRANGE_KEY = 345,
    CHAR = 346,
    INTEGER = 347,
    INTB = 348,
    STRING = 349,
    SYMBOLSTRING = 350,
    SPACESYM = 351,
    SECTIONSYM = 352,
    TOKENSYM = 353,
    USEROPSYM = 354,
    VALUESYM = 355,
    VALUEMAPSYM = 356,
    CONTEXTSYM = 357,
    NAMESYM = 358,
    VARSYM = 359,
    BITSYM = 360,
    SPECSYM = 361,
    VARLISTSYM = 362,
    OPERANDSYM = 363,
    STARTSYM = 364,
    ENDSYM = 365,
    NEXT2SYM = 366,
    MACROSYM = 367,
    LABELSYM = 368,
    SUBTABLESYM = 369
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 29 "slghparse.y" /* yacc.c:355  */

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

#line 279 "slghparse.cc" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_SLGHPARSE_HH_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 296 "slghparse.cc" /* yacc.c:358  */

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
#define YYLAST   2617

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  138
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  71
/* YYNRULES -- Number of rules.  */
#define YYNRULES  341
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  716

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   369

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,   137,    43,     2,     2,     2,    38,    11,     2,
     130,   131,    36,    32,   132,    33,     2,    37,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   136,     8,
      17,   129,    18,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   133,     2,   134,     9,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   135,     6,   128,    44,     2,     2,     2,
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
     118,   119,   120,   121,   122,   123,   124,   125,   126,   127
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   158,   158,   159,   160,   161,   163,   164,   165,   166,
     167,   168,   169,   170,   171,   172,   174,   175,   176,   177,
     179,   180,   182,   184,   186,   187,   188,   189,   190,   192,
     194,   195,   198,   199,   200,   201,   202,   204,   205,   206,
     207,   208,   209,   211,   213,   214,   215,   216,   217,   218,
     219,   221,   223,   225,   227,   228,   230,   233,   235,   237,
     239,   241,   244,   246,   247,   248,   250,   252,   253,   254,
     257,   258,   261,   263,   264,   265,   267,   268,   270,   271,
     272,   273,   274,   275,   276,   277,   278,   280,   281,   282,
     283,   285,   287,   290,   291,   292,   293,   294,   295,   296,
     297,   298,   299,   300,   301,   302,   304,   305,   306,   307,
     309,   310,   312,   313,   315,   316,   318,   319,   320,   321,
     322,   323,   324,   327,   328,   329,   330,   332,   333,   335,
     336,   337,   338,   339,   340,   342,   343,   345,   347,   348,
     350,   351,   352,   353,   354,   356,   357,   358,   359,   361,
     362,   363,   364,   365,   366,   367,   368,   369,   370,   371,
     372,   373,   374,   375,   376,   377,   378,   379,   380,   381,
     382,   383,   384,   385,   387,   388,   389,   390,   391,   392,
     393,   394,   395,   396,   397,   398,   399,   400,   401,   402,
     403,   404,   405,   406,   407,   408,   409,   410,   411,   412,
     413,   414,   415,   416,   417,   418,   419,   420,   421,   422,
     423,   424,   425,   426,   427,   428,   429,   430,   431,   432,
     433,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     454,   455,   456,   457,   459,   460,   461,   462,   463,   464,
     465,   466,   467,   469,   470,   471,   472,   474,   475,   476,
     477,   478,   480,   481,   482,   484,   485,   487,   488,   489,
     490,   491,   492,   494,   495,   496,   497,   498,   500,   501,
     502,   503,   504,   505,   507,   508,   510,   511,   512,   514,
     515,   516,   518,   519,   520,   523,   524,   526,   527,   528,
     530,   532,   533,   534,   535,   537,   538,   539,   541,   542,
     543,   544,   545,   547,   548,   550,   551,   553,   554,   557,
     558,   559,   561,   562,   563,   565,   566,   567,   568,   569,
     570,   571,   572,   573,   574,   575,   576,   577,   578,   579,
     580,   581
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
  "OP_TRUNC", "OP_CPOOLREF", "OP_NEW", "OP_POPCOUNT", "BADINTEGER",
  "GOTO_KEY", "CALL_KEY", "RETURN_KEY", "IF_KEY", "DEFINE_KEY",
  "ATTACH_KEY", "MACRO_KEY", "SPACE_KEY", "TYPE_KEY", "RAM_KEY",
  "DEFAULT_KEY", "REGISTER_KEY", "ENDIAN_KEY", "WITH_KEY", "ALIGN_KEY",
  "OP_UNIMPL", "TOKEN_KEY", "SIGNED_KEY", "NOFLOW_KEY", "HEX_KEY",
  "DEC_KEY", "BIG_KEY", "LITTLE_KEY", "SIZE_KEY", "WORDSIZE_KEY",
  "OFFSET_KEY", "NAMES_KEY", "VALUES_KEY", "VARIABLES_KEY", "PCODEOP_KEY",
  "IS_KEY", "LOCAL_KEY", "DELAYSLOT_KEY", "CROSSBUILD_KEY", "EXPORT_KEY",
  "BUILD_KEY", "CONTEXT_KEY", "ELLIPSIS_KEY", "GLOBALSET_KEY",
  "BITRANGE_KEY", "CHAR", "INTEGER", "INTB", "STRING", "SYMBOLSTRING",
  "SPACESYM", "SECTIONSYM", "TOKENSYM", "USEROPSYM", "VALUESYM",
  "VALUEMAPSYM", "CONTEXTSYM", "NAMESYM", "VARSYM", "BITSYM", "SPECSYM",
  "VARLISTSYM", "OPERANDSYM", "STARTSYM", "ENDSYM", "NEXT2SYM", "MACROSYM",
  "LABELSYM", "SUBTABLESYM", "'}'", "'='", "'('", "')'", "','", "'['",
  "']'", "'{'", "':'", "' '", "$accept", "spec", "definition",
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
     362,   363,   364,   365,   366,   367,   368,   369,   125,    61,
      40,    41,    44,    91,    93,   123,    58,    32
};
# endif

#define YYPACT_NINF -316

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-316)))

#define YYTABLE_NINF -272

#define yytable_value_is_error(Yytable_value) \
  (!!((Yytable_value) == (-272)))

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -39,   -23,     8,  -316,   -41,  -316,     2,    88,   245,     0,
     -38,   -37,   -14,  -316,  -316,  -316,  -316,  -316,   426,  -316,
     453,  -316,    62,  -316,  -316,  -316,  -316,  -316,  -316,  -316,
    -316,    49,  -316,    10,  -316,    16,   191,   123,  -316,  -316,
    2427,    70,  2446,   -21,   111,   189,   204,   -61,   -61,   -61,
     173,  -316,  -316,   171,  -316,  -316,  -316,   182,  -316,  -316,
    -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,
    -316,  -316,  -316,  -316,  -316,   203,   185,  -316,   193,   186,
     210,  -316,   213,  -316,   217,   231,   220,  -316,  -316,  -316,
    -316,  -316,   211,  -316,  -316,  -316,  -316,   214,  -316,   211,
    -316,  -316,  -316,   214,   336,   347,  -316,  -316,   289,   267,
    -316,  -316,   297,   400,  -316,   284,    55,  -316,   295,  -316,
    -316,   159,   299,    47,   -24,   315,   211,   308,  -316,  -316,
    -316,   310,   349,  -316,  -316,  -316,  -316,   353,   215,   372,
     373,   364,  1692,  1754,  -316,  -316,  -316,  -316,  -316,  -316,
     369,  -316,   211,    15,  -316,  -316,   395,  -316,    26,  -316,
      15,  -316,  -316,   492,   401,  -316,  2302,  -316,   396,  -316,
    -316,   -57,  -316,  -316,   -34,  2467,   497,   409,  -316,     9,
     507,  -316,   -85,   509,  -316,   261,   385,   190,   414,   415,
     417,   418,  -316,  -316,  -316,  -316,  -316,   293,   -70,    21,
    -316,   388,  1613,     5,  1556,   226,   399,  1577,   304,   424,
     394,    50,   422,  -316,   425,  -316,  -316,  -316,  -316,  -316,
     429,   -58,  -316,  1556,   -40,  -316,    41,  -316,    60,  -316,
    1662,    27,   211,   211,   211,  -316,   -51,  -316,  1662,  1662,
    1662,  1662,  1662,  1662,   -51,  -316,   441,  -316,  -316,  -316,
     446,  -316,   468,  -316,  -316,  -316,  -316,  -316,  2328,  -316,
    -316,  -316,   451,  -316,  -316,   -13,  -316,  -316,  -316,   -43,
    -316,  -316,   450,   455,   449,   459,   461,   463,  -316,  -316,
     525,  -316,  -316,   613,   615,   526,   565,  -316,   538,  -316,
    -316,  -316,  -316,  -316,  1556,   665,  -316,  1556,   667,  -316,
    1556,  1556,  1556,  1556,  1556,   576,   577,   582,   585,   622,
     625,   658,   659,   669,   704,   709,   744,   749,   784,   785,
     820,   825,   826,  -316,  1556,  1822,  1556,  -316,    54,     3,
     584,   648,   703,   380,   661,   909,  -316,   367,   952,  -316,
     987,   770,  1556,   891,  1556,  1556,  1556,  1512,   895,   930,
    1556,   931,  1662,  1662,  -316,  1662,   423,  -316,  -316,  -316,
     167,  1029,  -316,   187,  -316,  -316,  -316,   423,   423,   423,
     423,   423,   423,  -316,   995,   971,   992,  -316,  -316,  -316,
    -316,   972,  -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,
     976,  1011,  1012,  1051,  1577,  -316,  -316,  1023,  -316,  1052,
     348,  -316,   583,  -316,   623,  -316,  -316,  -316,  -316,  1556,
    1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,
    1556,  1556,  1556,  1556,  1556,  1556,  1556,   827,  1556,  1556,
    1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,
    1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,
    1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,  1556,
    1556,  1556,  1556,  1556,  1700,  -316,    -8,  1087,  1092,  -316,
    1556,  1093,  -316,  1071,    85,  1132,  -316,  1133,  1234,  -316,
    1269,  -316,  -316,  -316,  -316,  1874,  1153,  2194,   271,  1914,
     275,  1556,  1147,  1184,  1954,  1186,  -316,  -316,    29,  1662,
    1662,  1662,  1662,  1662,  1662,  1662,  1662,  1662,  1189,  -316,
    1194,  1229,  -316,  -316,  -316,    39,  1274,  1227,  1258,  -316,
    1267,  1268,  1303,  1308,  -316,  1304,  1310,  1471,  1476,  1511,
     867,   705,   907,   745,   787,   948,   988,  1028,  1069,  1109,
    1149,  1190,  1230,  1270,   287,   663,  1311,   305,  -316,  2233,
    2270,  2270,  2304,  2336,  2366,  2465,  2465,  2465,  2465,  2491,
    2491,  2491,  2491,  2491,  2491,  2491,  2491,  2491,  2491,  2491,
    2491,  2575,  2575,  2575,   408,   408,   408,   408,  -316,  -316,
    -316,  -316,  -316,  -316,  -316,  1516,  1349,  1388,  -316,  1994,
       4,  1549,  1551,  1553,  1577,  -316,  -316,  -316,  1556,  1554,
    1556,  -316,  1557,  2034,  -316,  -316,  -316,  1459,  -316,  2444,
    2435,   495,   273,   273,   421,   421,  -316,  -316,  2482,  1662,
    1662,  1626,   117,  -316,  -316,   387,  1461,   -21,  -316,  -316,
    -316,  -316,  1463,  -316,  -316,  -316,  -316,  -316,  1556,  -316,
    1556,  1556,  -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,
    -316,  -316,  -316,  1556,  -316,  -316,  -316,  -316,  1464,  -316,
    -316,  1556,  -316,  -316,  -316,  -316,  2074,  -316,  2194,  -316,
    -316,  1436,  1439,  1440,  1548,  1615,  -316,  -316,  1543,  1544,
    -316,  -316,  1441,  1568,  -316,  1351,  1391,  1432,  1472,  1445,
    2114,  -316,  1453,  1468,  1475,  -316,  -316,  -316,  -316,  -316,
    -316,  -316,  -316,  -316,  -316,  -316,  -316,  1556,  1455,  1456,
    2154,  1585,  1586,  -316,  -316,  -316
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
     327,   328,   331,   332,   333,   334,   335,   341,   336,   337,
     338,   339,   340,   329,   330,    27,     0,    29,     0,    31,
       0,    43,     0,    50,     0,     0,     0,    66,    64,    65,
     145,    82,     0,   284,    83,    86,    85,    84,    81,     0,
      78,    80,    90,    79,     0,     0,    44,    45,     0,     0,
      28,   296,     0,     0,    30,     0,     0,    54,     0,   306,
     307,     0,     0,     0,     0,   322,    70,     0,    34,    35,
      36,     0,     0,    39,    40,    41,    42,     0,     0,     0,
       0,     0,   140,     0,   273,   274,   275,   276,   124,   277,
     123,   126,     0,   127,   106,   111,   113,   114,   125,   285,
     127,    20,    21,     0,     0,   297,     0,    57,     0,    53,
      55,     0,   308,   309,     0,     0,     0,     0,   287,     0,
       0,   314,     0,     0,   323,     0,   127,    71,     0,     0,
       0,     0,    46,    47,    48,    49,    61,     0,     0,   243,
     258,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     257,   255,     0,   278,     0,   279,   280,   281,   282,   283,
       0,   256,   146,     0,     0,   254,     0,   173,   253,   110,
       0,     0,     0,     0,     0,   129,     0,   112,     0,     0,
       0,     0,     0,     0,     0,    22,     0,   298,   295,   299,
       0,    52,     0,   312,   310,   311,   305,   301,     0,   302,
      59,   288,     0,   289,   291,     0,    58,   316,   315,     0,
      60,    72,     0,     0,     0,     0,     0,     0,   255,   256,
       0,   260,   253,     0,     0,     0,     0,   248,   247,   252,
     249,   244,   245,   246,     0,     0,   251,     0,     0,   170,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   237,     0,     0,     0,   174,   253,     0,
       0,     0,     0,     0,     0,   143,   272,     0,     0,   267,
       0,     0,     0,     0,   319,     0,   319,     0,     0,     0,
       0,     0,     0,     0,    91,     0,   122,    92,    93,   115,
     108,   109,   107,     0,    75,   145,    76,   117,   118,   120,
     121,   119,   116,    77,    24,     0,     0,   303,   300,   304,
     290,     0,   292,   294,   286,   318,   317,   313,   324,    62,
       0,     0,     0,     0,     0,   266,   265,     0,   242,     0,
       0,   165,     0,   168,     0,   189,   216,   202,   190,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   319,     0,     0,   319,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   175,     0,     0,     0,   147,
       0,     0,   154,     0,     0,     0,   268,     0,   144,   264,
       0,   262,   141,   161,   259,     0,     0,   320,     0,     0,
       0,     0,     0,     0,     0,     0,   104,   105,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   134,
       0,     0,   128,   138,   145,     0,     0,     0,     0,   293,
       0,     0,     0,     0,   261,   241,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   176,   205,
     204,   203,   193,   191,   192,   179,   180,   206,   207,   181,
     184,   182,   183,   185,   186,   187,   188,   208,   209,   210,
     211,   194,   195,   196,   177,   178,   212,   213,   197,   198,
     200,   199,   201,   214,   215,     0,     0,     0,   235,     0,
       0,     0,     0,     0,     0,   270,   142,   151,     0,     0,
       0,   158,     0,     0,   160,   159,   149,     0,    94,   101,
     102,   100,    98,    99,    95,    96,    97,   103,     0,     0,
       0,     0,     0,    73,   137,     0,     0,     0,    32,    33,
      37,    38,     0,   250,   167,   169,   171,   220,     0,   219,
       0,     0,   226,   217,   218,   228,   229,   230,   225,   224,
     227,   239,   231,     0,   233,   238,   166,   234,     0,   150,
     148,     0,   164,   163,   162,   269,     0,   156,   321,   172,
     155,     0,     0,     0,     0,     0,    74,   139,     0,     0,
      26,    25,     0,     0,   240,     0,     0,     0,     0,     0,
       0,   153,     0,     0,     0,   130,   133,   135,   136,    56,
      51,   221,   222,   223,   232,   236,   152,     0,     0,     0,
       0,     0,     0,   157,   131,   132
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -316,  -316,  1564,  1565,  -316,  -316,  -316,  -316,  -316,  -316,
    -316,  -316,  -316,  -316,  -316,  -316,  -316,  1481,  -316,  -316,
    -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,  -316,  1354,
    -316,  -316,  -316,  -224,   -69,  -316,  1477,  -316,  -316,   -73,
    -316,  1000,  -316,  -316,  1259,  1112,  -316,  -199,  -141,  -198,
     -60,  1162,  1292,  -140,  -316,   -92,   -36,  1595,  -316,  -316,
    1005,  -316,  -316,  -316,   427,  -316,  -316,  -316,  -315,  -316,
       7
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,    14,    15,     3,    16,    17,    18,    19,    20,
      75,    79,    21,    22,    23,    24,   116,   117,    25,    26,
      27,    28,    29,    30,    31,    32,    53,   186,    33,   366,
      34,    35,    36,   356,   153,   154,   155,   156,   157,   236,
     363,   624,   513,   514,   141,   142,   222,   487,   326,   295,
     327,   225,   226,   296,   338,   357,   328,    97,   180,   265,
     113,   166,   176,   258,   122,   174,   183,   269,   488,   185,
      76
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     158,   223,   227,   197,   298,   325,   251,   158,     5,     6,
      38,   469,   660,   299,   367,   368,   369,   370,   371,   372,
     381,   232,   267,   233,   347,    91,   234,    80,   364,     1,
     160,   490,   268,   232,   158,   233,   499,   283,   234,   500,
     238,   501,   262,   239,   240,   241,   242,   107,   252,   110,
       6,   158,   119,     4,   120,   200,   284,   187,   502,   503,
     158,   504,   505,   169,   385,   506,   507,   337,   622,    51,
      81,  -264,   121,   253,   386,  -264,     7,     8,     9,   254,
     177,   255,   224,   231,   365,    10,   111,   244,    37,    52,
     348,   387,   382,   181,   383,   400,   349,   210,   402,    54,
     256,   404,   405,   406,   407,   408,   228,    50,   544,   182,
      92,   547,   112,   273,   263,    11,   264,    86,     8,     9,
      93,   384,    55,    94,    95,   427,    10,   465,   496,   497,
      39,   498,   470,   661,    82,    12,    83,   281,   300,   471,
     158,   158,   158,   485,    13,    90,   489,   332,   235,    84,
      85,   494,   178,    96,   285,   243,    11,   286,   359,    40,
     608,   282,   115,   360,   361,   362,    41,   623,    42,   330,
     350,   282,   339,   249,   351,   233,    12,    87,   234,   342,
     179,    43,   259,  -263,   466,    13,   343,   467,    44,  -262,
     468,    45,   592,  -262,   358,   593,   232,    46,   233,   108,
      98,   234,   358,   358,   358,   358,   358,   358,   104,   105,
     530,   531,   532,   533,   534,   535,   536,   537,   538,   539,
     540,   541,   542,   543,   678,   545,   546,   679,   114,   549,
     550,   551,   552,   553,   554,   555,   556,   557,   558,   559,
     560,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,   571,   572,   573,   574,   575,   576,   577,   578,   579,
     580,   581,   582,   583,   584,   379,   585,   133,   134,   135,
     136,   589,   172,   476,   173,   609,   610,   611,   612,   613,
     614,   615,   616,   617,   128,    99,   129,   130,   192,   508,
     193,    40,   603,   118,   509,    93,   115,   282,   100,   101,
      42,   481,   510,   125,   197,   504,   505,   126,   511,   506,
     507,   127,   143,    43,   131,   333,   358,   358,   159,   358,
      44,   512,   132,    45,   144,   145,   146,   147,   102,    46,
     148,   149,   150,   329,   524,    47,    48,    49,   151,   137,
     199,   152,   138,   213,   161,   215,   139,   216,   217,   218,
     219,   428,   429,   430,   431,   162,   200,   432,   282,   433,
     140,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   197,   271,   272,   163,   674,   675,   164,   210,   666,
     278,   668,   599,   600,   165,   198,   602,   600,   167,   334,
     213,   335,   215,   168,   216,   217,   218,   219,   651,   600,
     279,   213,   184,   215,   171,   216,   217,   218,   219,   280,
     499,   336,   175,   500,    56,   501,   655,   600,   188,   685,
     189,   686,   687,   200,   457,   458,   459,   460,   461,   462,
     463,   287,   502,   503,   688,   504,   505,   506,   507,   506,
     507,    77,   690,   358,   358,   358,   358,   358,   358,   358,
     358,   358,   680,   681,   478,   123,   124,   194,   195,   190,
     223,   227,   527,   191,   213,   210,   215,   278,   216,   217,
     218,   219,   196,   288,   479,   289,   237,   213,   230,   215,
     245,   216,   217,   218,   219,   260,   246,   279,   710,   290,
     291,   292,   293,   250,   261,   266,   475,   270,   235,   274,
     275,   294,   276,   277,   502,   503,   672,   504,   505,   331,
     341,   506,   507,    57,   665,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,   340,    68,    69,    70,    71,
      72,    73,   344,    74,   345,   376,   380,   388,   282,   346,
      78,   224,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,   374,    68,    69,    70,    71,    72,    73,   375,
      74,   390,   673,   358,   358,   228,   428,   429,   430,   431,
     389,   391,   432,   392,   433,   393,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
     394,   395,   432,   396,   433,   397,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   428,   429,   430,   431,
     398,   399,   432,   401,   433,   403,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   409,   410,   428,   429,
     430,   431,   411,   472,   432,   412,   433,   528,   434,   435,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   428,   429,
     430,   431,   413,   473,   432,   414,   433,   529,   434,   435,
     436,   437,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,   415,   416,
     428,   429,   430,   431,   652,   653,   432,   477,   433,   417,
     434,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     428,   429,   430,   431,   418,   474,   432,   638,   433,   419,
     434,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     428,   429,   430,   431,   420,   484,   432,   640,   433,   421,
     434,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     428,   429,   430,   431,   422,   423,   432,  -271,   433,   641,
     434,   435,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   448,   449,   450,   451,   452,   453,
     454,   455,   456,   457,   458,   459,   460,   461,   462,   463,
     424,   428,   429,   430,   431,   425,   426,   432,   548,   433,
     482,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   428,   429,   430,   431,   483,   486,   432,   637,   433,
     492,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   428,   429,   430,   431,   493,   495,   432,   639,   433,
     234,   434,   435,   436,   437,   438,   439,   440,   441,   442,
     443,   444,   445,   446,   447,   448,   449,   450,   451,   452,
     453,   454,   455,   456,   457,   458,   459,   460,   461,   462,
     463,   516,   428,   429,   430,   431,   517,   519,   432,   642,
     433,   520,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   428,   429,   430,   431,   521,   522,   432,   643,
     433,   518,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   428,   429,   430,   431,   523,   525,   432,   644,
     433,   526,   434,   435,   436,   437,   438,   439,   440,   441,
     442,   443,   444,   445,   446,   447,   448,   449,   450,   451,
     452,   453,   454,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   587,   428,   429,   430,   431,   588,   590,   432,
     645,   433,   591,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   428,   429,   430,   431,   594,   595,   432,
     646,   433,  -263,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   428,   429,   430,   431,   596,   604,   432,
     647,   433,   598,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   605,   428,   429,   430,   431,   607,   618,
     432,   648,   433,   619,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   428,   429,   430,   431,   620,   626,
     432,   649,   433,   627,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   428,   429,   430,   431,   628,   629,
     432,   650,   433,   625,   434,   435,   436,   437,   438,   439,
     440,   441,   442,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   630,   428,   429,   430,   431,   631,
     632,   432,   654,   433,   633,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   428,   429,   430,   431,   634,
     657,   432,   701,   433,   635,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   428,   429,   430,   431,   636,
     658,   432,   702,   433,   656,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   499,   695,   662,   500,   663,
     501,   664,   667,   703,   671,   669,   682,   197,   684,   689,
     692,   693,   694,   697,   698,   699,   700,   502,   503,   705,
     504,   505,   707,   708,   506,   507,   711,   712,   197,   301,
     709,   302,   199,   714,   715,    88,    89,   170,   373,   303,
     304,   305,   306,   704,   307,   308,   309,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,   320,   321,   200,
     229,   677,   499,   696,   515,   500,   621,   501,   586,   480,
     198,   103,   683,     0,     0,     0,     0,   197,     0,     0,
     200,   491,     0,   198,   502,   503,     0,   504,   505,     0,
       0,   506,   507,     0,     0,   622,     0,     0,     0,     0,
       0,   210,   199,   278,     0,     0,     0,     0,   322,     0,
       0,     0,     0,   213,   323,   215,   287,   216,   217,   218,
     219,     0,   210,   279,   278,     0,   324,     0,     0,   200,
     201,   202,   203,   204,   213,   352,   215,     0,   216,   217,
     218,   219,     0,   197,   279,     0,   353,     0,     0,   198,
       0,     0,     0,     0,     0,     0,     0,   198,   288,     0,
     289,   205,   206,   207,     0,   209,     0,     0,   199,     0,
       0,   210,     0,   211,   290,   291,   292,   293,   212,     0,
       0,     0,     0,   213,   214,   215,   297,   216,   217,   218,
     219,   220,     0,   221,   676,   200,   201,   202,   203,   204,
       0,     0,     0,   287,     0,     0,     0,     0,   354,     0,
       0,     0,     0,     0,     0,   144,   145,   146,   147,   213,
       0,   215,   149,   216,   217,   218,   219,   205,   206,   207,
     208,   209,   355,     0,     0,     0,     0,   210,     0,   211,
       0,     0,     0,     0,   212,   288,     0,   289,     0,   213,
     214,   215,     0,   216,   217,   218,   219,   220,     0,   221,
       0,   290,   291,   292,   293,   428,   429,   430,   431,     0,
       0,   432,     0,   433,     0,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,     0,     0,   144,   145,   146,
     147,     0,     0,   148,   149,   150,     0,   428,   429,   430,
     431,   151,   597,   432,   152,   433,   464,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   601,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   606,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   659,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   670,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   691,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   706,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,   713,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   428,   429,   430,
     431,     0,     0,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   429,   430,   431,
       0,     0,   432,     0,   433,     0,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   444,   445,   446,   447,
     448,   449,   450,   451,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   431,     0,     0,   432,
       0,   433,     0,   434,   435,   436,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,   448,   449,   450,
     451,   452,   453,   454,   455,   456,   457,   458,   459,   460,
     461,   462,   463,   432,     0,   433,     0,   434,   435,   436,
     437,   438,   439,   440,   441,   442,   443,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   433,     0,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   247,
       0,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,     0,    68,    69,    70,    71,    72,    73,     0,    74,
       0,     0,     0,     0,     0,   377,   248,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,   501,    68,    69,
      70,    71,    72,    73,   500,    74,   501,     0,     0,     0,
       0,     0,   378,     0,   502,   503,     0,   504,   505,     0,
       0,   506,   507,   502,   503,     0,   504,   505,     0,     0,
     506,   507,   438,   439,   440,   441,   442,   443,   444,   445,
     446,   447,   448,   449,   450,   451,   452,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463,  -272,  -272,
    -272,  -272,  -272,  -272,  -272,  -272,  -272,  -272,  -272,  -272,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   106,     0,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,     0,    68,    69,    70,
      71,    72,    73,   109,    74,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,     0,    68,    69,    70,    71,
      72,    73,     0,    74,   257,     0,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,     0,    68,    69,    70,
      71,    72,    73,     0,    74,   144,   145,   146,   147,   213,
       0,   215,   149,   216,   217,   218,   219,   453,   454,   455,
     456,   457,   458,   459,   460,   461,   462,   463
};

static const yytype_int16 yycheck[] =
{
      92,   142,   142,    11,   202,   204,    63,    99,     0,     1,
       8,     8,     8,     8,   238,   239,   240,   241,   242,   243,
      33,     6,   107,     8,   223,     9,    11,    20,    79,    68,
      99,   346,   117,     6,   126,     8,     7,   107,    11,    10,
      14,    12,    33,    17,    18,    19,    20,    40,   105,    42,
       1,   143,   113,    76,   115,    63,   126,   126,    29,    30,
     152,    32,    33,     8,   107,    36,    37,   208,    29,   107,
       8,   129,   133,   107,   117,   133,    68,    69,    70,   113,
      33,   115,   142,   152,   135,    77,   107,   160,   129,   127,
     130,   134,   105,   117,   107,   294,   136,   105,   297,   136,
     134,   300,   301,   302,   303,   304,   142,   107,   423,   133,
      94,   426,   133,   186,   105,   107,   107,    68,    69,    70,
     104,   134,   136,   107,   108,   324,    77,   326,   352,   353,
     128,   355,   129,   129,    72,   127,    74,   197,   133,   136,
     232,   233,   234,   342,   136,   135,   345,   207,   133,    87,
      88,   350,   105,   137,   133,   129,   107,   136,   131,    71,
     131,   197,   107,   232,   233,   234,    78,   128,    80,   205,
     129,   207,   208,   166,   133,     8,   127,   128,    11,   129,
     133,    93,   175,   133,   130,   136,   136,   133,   100,   129,
     136,   103,   107,   133,   230,   110,     6,   109,     8,   129,
       9,    11,   238,   239,   240,   241,   242,   243,    85,    86,
     409,   410,   411,   412,   413,   414,   415,   416,   417,   418,
     419,   420,   421,   422,   107,   424,   425,   110,   117,   428,
     429,   430,   431,   432,   433,   434,   435,   436,   437,   438,
     439,   440,   441,   442,   443,   444,   445,   446,   447,   448,
     449,   450,   451,   452,   453,   454,   455,   456,   457,   458,
     459,   460,   461,   462,   463,   258,   464,    81,    82,    83,
      84,   470,   113,   333,   115,   499,   500,   501,   502,   503,
     504,   505,   506,   507,    81,    94,    83,    84,    73,   102,
      75,    71,   491,    89,   107,   104,   107,   333,   107,   108,
      80,   337,   115,   130,    11,    32,    33,   136,   121,    36,
      37,   129,   101,    93,   129,    11,   352,   353,   104,   355,
     100,   134,   129,   103,   113,   114,   115,   116,   137,   109,
     119,   120,   121,   107,   394,    90,    91,    92,   127,   129,
      36,   130,   129,   117,     8,   119,   129,   121,   122,   123,
     124,     3,     4,     5,     6,     8,    63,     9,   394,    11,
     129,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,    11,   131,   132,   105,   619,   620,   130,   105,   598,
     107,   600,   131,   132,   107,    17,   131,   132,     8,   105,
     117,   107,   119,   129,   121,   122,   123,   124,   131,   132,
     127,   117,   107,   119,   129,   121,   122,   123,   124,   136,
       7,   127,   133,    10,     8,    12,   131,   132,   130,   638,
     130,   640,   641,    63,    36,    37,    38,    39,    40,    41,
      42,    63,    29,    30,   653,    32,    33,    36,    37,    36,
      37,     8,   661,   499,   500,   501,   502,   503,   504,   505,
     506,   507,    85,    86,   107,    48,    49,   105,   105,   130,
     621,   621,   134,   130,   117,   105,   119,   107,   121,   122,
     123,   124,   128,   105,   127,   107,   101,   117,   129,   119,
       8,   121,   122,   123,   124,     8,   105,   127,   707,   121,
     122,   123,   124,   117,   105,     8,   136,     8,   133,   105,
     105,   133,   105,   105,    29,    30,   618,    32,    33,   130,
     136,    36,    37,   107,   594,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   121,   120,   121,   122,   123,
     124,   125,   130,   127,   129,    87,   105,   107,   594,   130,
     107,   621,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   131,   120,   121,   122,   123,   124,   125,   133,
     127,   132,   618,   619,   620,   621,     3,     4,     5,     6,
     135,   132,     9,   132,    11,   132,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     105,    18,     9,    18,    11,   109,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     3,     4,     5,     6,
     105,   133,     9,     8,    11,     8,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,   130,   130,     3,     4,
       5,     6,   130,   129,     9,   130,    11,   134,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,     3,     4,
       5,     6,   130,   105,     9,   130,    11,   134,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,   130,   130,
       3,     4,     5,     6,   131,   132,     9,   136,    11,   130,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       3,     4,     5,     6,   130,   132,     9,   132,    11,   130,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       3,     4,     5,     6,   130,   105,     9,   132,    11,   130,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
       3,     4,     5,     6,   130,   130,     9,     8,    11,   132,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
     130,     3,     4,     5,     6,   130,   130,     9,   131,    11,
       8,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,     8,   105,     9,   131,    11,
     105,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,     3,     4,     5,     6,   105,   105,     9,   131,    11,
      11,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,    76,     3,     4,     5,     6,   105,   105,     9,   131,
      11,   105,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,     3,     4,     5,     6,   105,   105,     9,   131,
      11,   129,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,     3,     4,     5,     6,   105,   134,     9,   131,
      11,   109,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,   105,     3,     4,     5,     6,   105,   105,     9,
     131,    11,   131,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     3,     4,     5,     6,   105,   105,     9,
     131,    11,     8,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     3,     4,     5,     6,     8,   131,     9,
     131,    11,   129,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,   129,     3,     4,     5,     6,   132,   130,
       9,   131,    11,   129,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,     3,     4,     5,     6,   129,   132,
       9,   131,    11,   105,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,     3,     4,     5,     6,   131,   131,
       9,   131,    11,   129,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,   131,     3,     4,     5,     6,   131,
     136,     9,   131,    11,   134,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,     8,
     131,     9,   131,    11,     8,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     3,     4,     5,     6,     8,
     132,     9,   131,    11,     8,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,     7,     8,     8,    10,     8,
      12,     8,     8,   131,   105,     8,   105,    11,   105,   105,
     134,   132,   132,    30,    30,   134,     8,    29,    30,   134,
      32,    33,   129,   115,    36,    37,   131,   131,    11,    33,
     115,    35,    36,     8,     8,    31,    31,   116,   244,    43,
      44,    45,    46,   131,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
     143,   621,     7,     8,   365,    10,   514,    12,   466,   337,
      17,    36,   627,    -1,    -1,    -1,    -1,    11,    -1,    -1,
      63,   129,    -1,    17,    29,    30,    -1,    32,    33,    -1,
      -1,    36,    37,    -1,    -1,    29,    -1,    -1,    -1,    -1,
      -1,   105,    36,   107,    -1,    -1,    -1,    -1,   112,    -1,
      -1,    -1,    -1,   117,   118,   119,    63,   121,   122,   123,
     124,    -1,   105,   127,   107,    -1,   130,    -1,    -1,    63,
      64,    65,    66,    67,   117,    33,   119,    -1,   121,   122,
     123,   124,    -1,    11,   127,    -1,    44,    -1,    -1,    17,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    17,   105,    -1,
     107,    95,    96,    97,    -1,    99,    -1,    -1,    36,    -1,
      -1,   105,    -1,   107,   121,   122,   123,   124,   112,    -1,
      -1,    -1,    -1,   117,   118,   119,   133,   121,   122,   123,
     124,   125,    -1,   127,   128,    63,    64,    65,    66,    67,
      -1,    -1,    -1,    63,    -1,    -1,    -1,    -1,   106,    -1,
      -1,    -1,    -1,    -1,    -1,   113,   114,   115,   116,   117,
      -1,   119,   120,   121,   122,   123,   124,    95,    96,    97,
      98,    99,   130,    -1,    -1,    -1,    -1,   105,    -1,   107,
      -1,    -1,    -1,    -1,   112,   105,    -1,   107,    -1,   117,
     118,   119,    -1,   121,   122,   123,   124,   125,    -1,   127,
      -1,   121,   122,   123,   124,     3,     4,     5,     6,    -1,
      -1,     9,    -1,    11,    -1,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    -1,    -1,   113,   114,   115,
     116,    -1,    -1,   119,   120,   121,    -1,     3,     4,     5,
       6,   127,     8,     9,   130,    11,    64,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,     8,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     3,     4,     5,
       6,    -1,    -1,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,     4,     5,     6,
      -1,    -1,     9,    -1,    11,    -1,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,     6,    -1,    -1,     9,
      -1,    11,    -1,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,     9,    -1,    11,    -1,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    11,    -1,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,   107,
      -1,   109,   110,   111,   112,   113,   114,   115,   116,   117,
     118,    -1,   120,   121,   122,   123,   124,   125,    -1,   127,
      -1,    -1,    -1,    -1,    -1,   107,   134,   109,   110,   111,
     112,   113,   114,   115,   116,   117,   118,    12,   120,   121,
     122,   123,   124,   125,    10,   127,    12,    -1,    -1,    -1,
      -1,    -1,   134,    -1,    29,    30,    -1,    32,    33,    -1,
      -1,    36,    37,    29,    30,    -1,    32,    33,    -1,    -1,
      36,    37,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,   107,    -1,   109,   110,   111,   112,
     113,   114,   115,   116,   117,   118,    -1,   120,   121,   122,
     123,   124,   125,   107,   127,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,    -1,   120,   121,   122,   123,
     124,   125,    -1,   127,   107,    -1,   109,   110,   111,   112,
     113,   114,   115,   116,   117,   118,    -1,   120,   121,   122,
     123,   124,   125,    -1,   127,   113,   114,   115,   116,   117,
      -1,   119,   120,   121,   122,   123,   124,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    68,   139,   142,    76,     0,     1,    68,    69,    70,
      77,   107,   127,   136,   140,   141,   143,   144,   145,   146,
     147,   150,   151,   152,   153,   156,   157,   158,   159,   160,
     161,   162,   163,   166,   168,   169,   170,   129,     8,   128,
      71,    78,    80,    93,   100,   103,   109,    90,    91,    92,
     107,   107,   127,   164,   136,   136,     8,   107,   109,   110,
     111,   112,   113,   114,   115,   116,   117,   118,   120,   121,
     122,   123,   124,   125,   127,   148,   208,     8,   107,   149,
     208,     8,    72,    74,    87,    88,    68,   128,   140,   141,
     135,     9,    94,   104,   107,   108,   137,   195,     9,    94,
     107,   108,   137,   195,    85,    86,   107,   208,   129,   107,
     208,   107,   133,   198,   117,   107,   154,   155,    89,   113,
     115,   133,   202,   202,   202,   130,   136,   129,    81,    83,
      84,   129,   129,    81,    82,    83,    84,   129,   129,   129,
     129,   182,   183,   101,   113,   114,   115,   116,   119,   120,
     121,   127,   130,   172,   173,   174,   175,   176,   193,   104,
     172,     8,     8,   105,   130,   107,   199,     8,   129,     8,
     155,   129,   113,   115,   203,   133,   200,    33,   105,   133,
     196,   117,   133,   204,   107,   207,   165,   172,   130,   130,
     130,   130,    73,    75,   105,   105,   128,    11,    17,    36,
      63,    64,    65,    66,    67,    95,    96,    97,    98,    99,
     105,   107,   112,   117,   118,   119,   121,   122,   123,   124,
     125,   127,   184,   186,   188,   189,   190,   191,   194,   174,
     129,   172,     6,     8,    11,   133,   177,   101,    14,    17,
      18,    19,    20,   129,   177,     8,   105,   107,   134,   208,
     117,    63,   105,   107,   113,   115,   134,   107,   201,   208,
       8,   105,    33,   105,   107,   197,     8,   107,   117,   205,
       8,   131,   132,   177,   105,   105,   105,   105,   107,   127,
     136,   188,   194,   107,   126,   133,   136,    63,   105,   107,
     121,   122,   123,   124,   133,   187,   191,   133,   187,     8,
     133,    33,    35,    43,    44,    45,    46,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,   112,   118,   130,   185,   186,   188,   194,   107,
     194,   130,   188,    11,   105,   107,   127,   186,   192,   194,
     121,   136,   129,   136,   130,   129,   130,   185,   130,   136,
     129,   133,    33,    44,   106,   130,   171,   193,   194,   131,
     172,   172,   172,   178,    79,   135,   167,   171,   171,   171,
     171,   171,   171,   167,   131,   133,    87,   107,   134,   208,
     105,    33,   105,   107,   134,   107,   117,   134,   107,   135,
     132,   132,   132,   132,   105,    18,    18,   109,   105,   133,
     185,     8,   185,     8,   185,   185,   185,   185,   185,   130,
     130,   130,   130,   130,   130,   130,   130,   130,   130,   130,
     130,   130,   130,   130,   130,   130,   130,   185,     3,     4,
       5,     6,     9,    11,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,    64,   185,   130,   133,   136,     8,
     129,   136,   129,   105,   132,   136,   188,   136,   107,   127,
     190,   194,     8,     8,   105,   185,   105,   185,   206,   185,
     206,   129,   105,   105,   185,   105,   171,   171,   171,     7,
      10,    12,    29,    30,    32,    33,    36,    37,   102,   107,
     115,   121,   134,   180,   181,   182,    76,   105,   129,   105,
     105,   105,   105,   105,   188,   134,   109,   134,   134,   134,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   206,   185,   185,   206,   131,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   187,   189,   105,   105,   185,
     105,   131,   107,   110,   105,   105,     8,     8,   129,   131,
     132,     8,   131,   185,   131,   129,     8,   132,   131,   171,
     171,   171,   171,   171,   171,   171,   171,   171,   130,   129,
     129,   183,    29,   128,   179,   129,   132,   105,   131,   131,
     131,   131,   136,   134,     8,     8,     8,   131,   132,   131,
     132,   132,   131,   131,   131,   131,   131,   131,   131,   131,
     131,   131,   131,   132,   131,   131,     8,   131,   132,     8,
       8,   129,     8,     8,     8,   188,   185,     8,   185,     8,
       8,   105,   193,   194,   171,   171,   128,   179,   107,   110,
      85,    86,   105,   198,   105,   185,   185,   185,   185,   105,
     185,     8,   134,   132,   132,     8,     8,    30,    30,   134,
       8,   131,   131,   131,   131,   134,     8,   129,   115,   115,
     185,   131,   131,     8,     8,     8
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,   138,   139,   139,   139,   139,   140,   140,   140,   140,
     140,   140,   140,   140,   140,   140,   141,   141,   141,   141,
     142,   142,   143,   144,   145,   145,   145,   145,   145,   146,
     147,   147,   148,   148,   148,   148,   148,   149,   149,   149,
     149,   149,   149,   150,   151,   151,   151,   151,   151,   151,
     151,   152,   152,   153,   154,   154,   155,   156,   157,   158,
     159,   160,   161,   162,   162,   162,   163,   164,   164,   164,
     165,   165,   166,   167,   167,   167,   168,   168,   169,   169,
     169,   169,   169,   169,   169,   169,   169,   170,   170,   170,
     170,   171,   171,   171,   171,   171,   171,   171,   171,   171,
     171,   171,   171,   171,   171,   171,   172,   172,   172,   172,
     173,   173,   174,   174,   175,   175,   176,   176,   176,   176,
     176,   176,   176,   176,   176,   176,   176,   177,   177,   178,
     178,   178,   178,   178,   178,   179,   179,   180,   181,   181,
     182,   182,   182,   182,   182,   183,   183,   183,   183,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     185,   185,   185,   185,   185,   185,   185,   185,   185,   185,
     186,   186,   186,   186,   187,   187,   187,   187,   187,   187,
     187,   187,   187,   188,   188,   188,   188,   189,   189,   189,
     189,   189,   190,   190,   190,   191,   191,   192,   192,   192,
     192,   192,   192,   193,   193,   193,   193,   193,   194,   194,
     194,   194,   194,   194,   195,   195,   196,   196,   196,   197,
     197,   197,   197,   197,   197,   198,   198,   199,   199,   199,
     200,   201,   201,   201,   201,   202,   202,   202,   203,   203,
     203,   203,   203,   204,   204,   205,   205,   205,   205,   206,
     206,   206,   207,   207,   207,   208,   208,   208,   208,   208,
     208,   208,   208,   208,   208,   208,   208,   208,   208,   208,
     208,   208
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
       4,     4,     6,     4,     4,     3,     6,     1,     4,     4,
       6,     4,     3,     1,     1,     1,     1,     1,     1,     1,
       4,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       2,     4,     1,     1,     1,     3,     3,     1,     2,     4,
       3,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     3,     1,     2,     1,
       2,     1,     2,     3,     2,     3,     1,     1,     2,     2,
       3,     1,     1,     2,     2,     3,     1,     1,     1,     1,
       2,     2,     2,     3,     1,     1,     1,     2,     2,     0,
       1,     3,     0,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1
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
#line 177 "slghparse.y" /* yacc.c:1646  */
    { slgh->resetConstructors(); }
#line 2273 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 20:
#line 179 "slghparse.y" /* yacc.c:1646  */
    { slgh->setEndian(1); }
#line 2279 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 21:
#line 180 "slghparse.y" /* yacc.c:1646  */
    { slgh->setEndian(0); }
#line 2285 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 22:
#line 182 "slghparse.y" /* yacc.c:1646  */
    { slgh->setAlignment(*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 2291 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 23:
#line 184 "slghparse.y" /* yacc.c:1646  */
    {}
#line 2297 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 24:
#line 186 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = slgh->defineToken((yyvsp[-3].str),(yyvsp[-1].i),0); }
#line 2303 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 25:
#line 187 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),-1); }
#line 2309 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 26:
#line 188 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = slgh->defineToken((yyvsp[-6].str),(yyvsp[-4].i),1); }
#line 2315 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 27:
#line 189 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tokensym) = (yyvsp[-1].tokensym); slgh->addTokenField((yyvsp[-1].tokensym),(yyvsp[0].fieldqual)); }
#line 2321 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 28:
#line 190 "slghparse.y" /* yacc.c:1646  */
    { string errmsg=(yyvsp[0].anysym)->getName()+": redefined as a token"; yyerror(errmsg.c_str()); YYERROR; }
#line 2327 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 29:
#line 192 "slghparse.y" /* yacc.c:1646  */
    {}
#line 2333 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 30:
#line 194 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varsym) = (yyvsp[0].varsym); }
#line 2339 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 31:
#line 195 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varsym) = (yyvsp[-1].varsym); if (!slgh->addContextField( (yyvsp[-1].varsym), (yyvsp[0].fieldqual) ))
                                            { yyerror("All context definitions must come before constructors"); YYERROR; } }
#line 2346 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 32:
#line 198 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
#line 2352 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 33:
#line 199 "slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; yyerror(errmsg.c_str()); YYERROR; }
#line 2358 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 34:
#line 200 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
#line 2364 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 35:
#line 201 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
#line 2370 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 36:
#line 202 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
#line 2376 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 37:
#line 204 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = new FieldQuality((yyvsp[-6].str),(yyvsp[-3].i),(yyvsp[-1].i)); }
#line 2382 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 38:
#line 205 "slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].i); delete (yyvsp[-1].i); string errmsg = (yyvsp[-6].anysym)->getName()+": redefined as field"; yyerror(errmsg.c_str()); YYERROR; }
#line 2388 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 39:
#line 206 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->signext = true; }
#line 2394 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 40:
#line 207 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->flow = false; }
#line 2400 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 41:
#line 208 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = true; }
#line 2406 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 42:
#line 209 "slghparse.y" /* yacc.c:1646  */
    { (yyval.fieldqual) = (yyvsp[-1].fieldqual); (yyval.fieldqual)->hex = false; }
#line 2412 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 43:
#line 211 "slghparse.y" /* yacc.c:1646  */
    { slgh->newSpace((yyvsp[-1].spacequal)); }
#line 2418 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 44:
#line 213 "slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = new SpaceQuality(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2424 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 45:
#line 214 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = (yyvsp[0].anysym)->getName()+": redefined as space"; yyerror(errmsg.c_str()); YYERROR; }
#line 2430 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 46:
#line 215 "slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::ramtype; }
#line 2436 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 47:
#line 216 "slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->type = SpaceQuality::registertype; }
#line 2442 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 48:
#line 217 "slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->size = *(yyvsp[0].i); delete (yyvsp[0].i); }
#line 2448 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 49:
#line 218 "slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-3].spacequal); (yyval.spacequal)->wordsize = *(yyvsp[0].i); delete (yyvsp[0].i); }
#line 2454 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 50:
#line 219 "slghparse.y" /* yacc.c:1646  */
    { (yyval.spacequal) = (yyvsp[-1].spacequal); (yyval.spacequal)->isdefault = true; }
#line 2460 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 51:
#line 221 "slghparse.y" /* yacc.c:1646  */
    {
               slgh->defineVarnodes((yyvsp[-8].spacesym),(yyvsp[-5].i),(yyvsp[-2].i),(yyvsp[-1].strlist)); }
#line 2467 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 52:
#line 223 "slghparse.y" /* yacc.c:1646  */
    { yyerror("Parsed integer is too big (overflow)"); YYERROR; }
#line 2473 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 56:
#line 230 "slghparse.y" /* yacc.c:1646  */
    {
               slgh->defineBitrange((yyvsp[-7].str),(yyvsp[-5].varsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i); delete (yyvsp[-1].i); }
#line 2480 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 57:
#line 233 "slghparse.y" /* yacc.c:1646  */
    { slgh->addUserOp((yyvsp[-1].strlist)); }
#line 2486 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 58:
#line 235 "slghparse.y" /* yacc.c:1646  */
    { slgh->attachValues((yyvsp[-2].symlist),(yyvsp[-1].biglist)); }
#line 2492 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 59:
#line 237 "slghparse.y" /* yacc.c:1646  */
    { slgh->attachNames((yyvsp[-2].symlist),(yyvsp[-1].strlist)); }
#line 2498 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 60:
#line 239 "slghparse.y" /* yacc.c:1646  */
    { slgh->attachVarnodes((yyvsp[-2].symlist),(yyvsp[-1].symlist)); }
#line 2504 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 61:
#line 241 "slghparse.y" /* yacc.c:1646  */
    { slgh->buildMacro((yyvsp[-3].macrosym),(yyvsp[-1].sem)); }
#line 2510 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 62:
#line 244 "slghparse.y" /* yacc.c:1646  */
    {  slgh->pushWith((yyvsp[-4].subtablesym),(yyvsp[-2].pateq),(yyvsp[-1].contop)); }
#line 2516 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 66:
#line 250 "slghparse.y" /* yacc.c:1646  */
    { slgh->popWith(); }
#line 2522 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 67:
#line 252 "slghparse.y" /* yacc.c:1646  */
    { (yyval.subtablesym) = (SubtableSymbol *)0; }
#line 2528 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 68:
#line 253 "slghparse.y" /* yacc.c:1646  */
    { (yyval.subtablesym) = (yyvsp[0].subtablesym); }
#line 2534 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 69:
#line 254 "slghparse.y" /* yacc.c:1646  */
    { (yyval.subtablesym) = slgh->newTable((yyvsp[0].str)); }
#line 2540 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 70:
#line 257 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = (PatternEquation *)0; }
#line 2546 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 71:
#line 258 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = (yyvsp[0].pateq); }
#line 2552 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 72:
#line 261 "slghparse.y" /* yacc.c:1646  */
    { (yyval.macrosym) = slgh->createMacro((yyvsp[-3].str),(yyvsp[-1].strlist)); }
#line 2558 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 73:
#line 263 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->standaloneSection((yyvsp[-1].sem)); }
#line 2564 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 74:
#line 264 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->finalNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem)); }
#line 2570 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 75:
#line 265 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = (SectionVector *)0; }
#line 2576 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 76:
#line 267 "slghparse.y" /* yacc.c:1646  */
    { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
#line 2582 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 77:
#line 268 "slghparse.y" /* yacc.c:1646  */
    { slgh->buildConstructor((yyvsp[-4].construct),(yyvsp[-2].pateq),(yyvsp[-1].contop),(yyvsp[0].sectionstart)); }
#line 2588 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 78:
#line 270 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2594 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 79:
#line 271 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2600 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 80:
#line 272 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); if (slgh->isInRoot((yyvsp[-1].construct))) { (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); } else slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
#line 2606 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 81:
#line 273 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); if (!slgh->isInRoot((yyvsp[-1].construct))) { yyerror("Unexpected '^' at start of print pieces");  YYERROR; } }
#line 2612 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 82:
#line 274 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); }
#line 2618 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 83:
#line 275 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2624 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 84:
#line 276 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 2630 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 85:
#line 277 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); (yyval.construct)->addSyntax(string(" ")); }
#line 2636 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 86:
#line 278 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); slgh->newOperand((yyvsp[-1].construct),(yyvsp[0].str)); }
#line 2642 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 87:
#line 280 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = slgh->createConstructor((yyvsp[-1].subtablesym)); }
#line 2648 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 88:
#line 281 "slghparse.y" /* yacc.c:1646  */
    { SubtableSymbol *sym=slgh->newTable((yyvsp[-1].str)); (yyval.construct) = slgh->createConstructor(sym); }
#line 2654 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 89:
#line 282 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = slgh->createConstructor((SubtableSymbol *)0); }
#line 2660 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 90:
#line 283 "slghparse.y" /* yacc.c:1646  */
    { (yyval.construct) = (yyvsp[-1].construct); }
#line 2666 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 91:
#line 285 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new ConstantValue(*(yyvsp[0].big)); delete (yyvsp[0].big); }
#line 2672 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 92:
#line 287 "slghparse.y" /* yacc.c:1646  */
    { if ((actionon==1)&&((yyvsp[0].famsym)->getType() != SleighSymbol::context_symbol))
                                             { string errmsg="Global symbol "+(yyvsp[0].famsym)->getName(); errmsg += " is not allowed in action expression"; yyerror(errmsg.c_str()); } (yyval.patexp) = (yyvsp[0].famsym)->getPatternValue(); }
#line 2679 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 93:
#line 290 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = (yyvsp[0].specsym)->getPatternExpression(); }
#line 2685 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 94:
#line 291 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = (yyvsp[-1].patexp); }
#line 2691 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 95:
#line 292 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new PlusExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2697 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 96:
#line 293 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new SubExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2703 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 97:
#line 294 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new MultExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2709 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 98:
#line 295 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new LeftShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2715 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 99:
#line 296 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new RightShiftExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2721 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 100:
#line 297 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new AndExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2727 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 101:
#line 298 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new OrExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2733 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 102:
#line 299 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new XorExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2739 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 103:
#line 300 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new DivExpression((yyvsp[-2].patexp),(yyvsp[0].patexp)); }
#line 2745 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 104:
#line 301 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new MinusExpression((yyvsp[0].patexp)); }
#line 2751 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 105:
#line 302 "slghparse.y" /* yacc.c:1646  */
    { (yyval.patexp) = new NotExpression((yyvsp[0].patexp)); }
#line 2757 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 107:
#line 305 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationAnd((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
#line 2763 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 108:
#line 306 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationOr((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
#line 2769 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 109:
#line 307 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationCat((yyvsp[-2].pateq),(yyvsp[0].pateq)); }
#line 2775 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 110:
#line 309 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationLeftEllipsis((yyvsp[0].pateq)); }
#line 2781 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 112:
#line 312 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EquationRightEllipsis((yyvsp[-1].pateq)); }
#line 2787 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 115:
#line 316 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = (yyvsp[-1].pateq); }
#line 2793 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 116:
#line 318 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new EqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2799 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 117:
#line 319 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new NotEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2805 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 118:
#line 320 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new LessEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2811 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 119:
#line 321 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new LessEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2817 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 120:
#line 322 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new GreaterEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2823 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 121:
#line 323 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new GreaterEqualEquation((yyvsp[-2].famsym)->getPatternValue(),(yyvsp[0].patexp)); }
#line 2829 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 122:
#line 324 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = slgh->constrainOperand((yyvsp[-2].operandsym),(yyvsp[0].patexp)); 
                                          if ((yyval.pateq) == (PatternEquation *)0) 
                                            { string errmsg="Constraining currently undefined operand "+(yyvsp[-2].operandsym)->getName(); yyerror(errmsg.c_str()); } }
#line 2837 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 123:
#line 327 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new OperandEquation((yyvsp[0].operandsym)->getIndex()); slgh->selfDefine((yyvsp[0].operandsym)); }
#line 2843 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 124:
#line 328 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = new UnconstrainedEquation((yyvsp[0].specsym)->getPatternExpression()); }
#line 2849 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 125:
#line 329 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].famsym)); }
#line 2855 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 126:
#line 330 "slghparse.y" /* yacc.c:1646  */
    { (yyval.pateq) = slgh->defineInvisibleOperand((yyvsp[0].subtablesym)); }
#line 2861 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 127:
#line 332 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (vector<ContextChange *> *)0; }
#line 2867 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 128:
#line 333 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-1].contop); }
#line 2873 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 129:
#line 335 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = new vector<ContextChange *>; }
#line 2879 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 130:
#line 336 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-4].contop); if (!slgh->contextMod((yyvsp[-4].contop),(yyvsp[-3].contextsym),(yyvsp[-1].patexp))) { string errmsg="Cannot use 'inst_next' or 'inst_next2' to set context variable: "+(yyvsp[-3].contextsym)->getName(); yyerror(errmsg.c_str()); YYERROR; } }
#line 2885 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 131:
#line 337 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].famsym),(yyvsp[-2].contextsym)); }
#line 2891 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 132:
#line 338 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-7].contop); slgh->contextSet((yyvsp[-7].contop),(yyvsp[-4].specsym),(yyvsp[-2].contextsym)); }
#line 2897 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 133:
#line 339 "slghparse.y" /* yacc.c:1646  */
    { (yyval.contop) = (yyvsp[-4].contop); slgh->defineOperand((yyvsp[-3].operandsym),(yyvsp[-1].patexp)); }
#line 2903 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 134:
#line 340 "slghparse.y" /* yacc.c:1646  */
    { string errmsg="Expecting context symbol, not "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2909 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 135:
#line 342 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionsym) = slgh->newSectionSymbol( *(yyvsp[-1].str) ); delete (yyvsp[-1].str); }
#line 2915 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 136:
#line 343 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionsym) = (yyvsp[-1].sectionsym); }
#line 2921 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 137:
#line 345 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->firstNamedSection((yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
#line 2927 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 138:
#line 347 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = (yyvsp[0].sectionstart); }
#line 2933 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 139:
#line 348 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sectionstart) = slgh->nextNamedSection((yyvsp[-2].sectionstart),(yyvsp[-1].sem),(yyvsp[0].sectionsym)); }
#line 2939 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 140:
#line 350 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[0].sem); if ((yyval.sem)->getOpvec().empty() && ((yyval.sem)->getResult() == (HandleTpl *)0)) slgh->recordNop(); }
#line 2945 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 141:
#line 351 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = slgh->setResultVarnode((yyvsp[-3].sem),(yyvsp[-1].varnode)); }
#line 2951 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 142:
#line 352 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = slgh->setResultStarVarnode((yyvsp[-4].sem),(yyvsp[-2].starqual),(yyvsp[-1].varnode)); }
#line 2957 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 143:
#line 353 "slghparse.y" /* yacc.c:1646  */
    { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2963 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 144:
#line 354 "slghparse.y" /* yacc.c:1646  */
    { string errmsg="Unknown pointer varnode: "+*(yyvsp[0].str); delete (yyvsp[-1].starqual); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2969 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 145:
#line 356 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = new ConstructTpl(); }
#line 2975 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 146:
#line 357 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[0].stmt); yyerror("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }
#line 2981 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 147:
#line 358 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[-3].sem); slgh->pcode.newLocalDefinition((yyvsp[-1].str)); }
#line 2987 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 148:
#line 359 "slghparse.y" /* yacc.c:1646  */
    { (yyval.sem) = (yyvsp[-5].sem); slgh->pcode.newLocalDefinition((yyvsp[-3].str),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 2993 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 149:
#line 361 "slghparse.y" /* yacc.c:1646  */
    { (yyvsp[-1].tree)->setOutput((yyvsp[-3].varnode)); (yyval.stmt) = ExprTree::toVector((yyvsp[-1].tree)); }
#line 2999 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 150:
#line 362 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-3].str)); }
#line 3005 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 151:
#line 363 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(false,(yyvsp[-1].tree),(yyvsp[-3].str)); }
#line 3011 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 152:
#line 364 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
#line 3017 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 153:
#line 365 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
#line 3023 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 154:
#line 366 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+(yyvsp[-1].specsym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3029 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 155:
#line 367 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createStore((yyvsp[-4].starqual),(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3035 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 156:
#line 368 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createUserOpNoOut((yyvsp[-4].useropsym),(yyvsp[-2].param)); }
#line 3041 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 157:
#line 369 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.assignBitRange((yyvsp[-8].varnode),(uint4)*(yyvsp[-6].i),(uint4)*(yyvsp[-4].i),(yyvsp[-1].tree)); delete (yyvsp[-6].i), delete (yyvsp[-4].i); }
#line 3047 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 158:
#line 370 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt)=slgh->pcode.assignBitRange((yyvsp[-3].bitsym)->getParentSymbol()->getVarnode(),(yyvsp[-3].bitsym)->getBitOffset(),(yyvsp[-3].bitsym)->numBits(),(yyvsp[-1].tree)); }
#line 3053 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 159:
#line 371 "slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal truncation on left-hand side of assignment"); YYERROR; }
#line 3059 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 160:
#line 372 "slghparse.y" /* yacc.c:1646  */
    { delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal subpiece on left-hand side of assignment"); YYERROR; }
#line 3065 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 161:
#line 373 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpConst(BUILD,(yyvsp[-1].operandsym)->getIndex()); }
#line 3071 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 162:
#line 374 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),(yyvsp[-1].sectionsym)); }
#line 3077 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 163:
#line 375 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->createCrossBuild((yyvsp[-3].varnode),slgh->newSectionSymbol(*(yyvsp[-1].str))); delete (yyvsp[-1].str); }
#line 3083 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 164:
#line 376 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpConst(DELAY_SLOT,*(yyvsp[-2].i)); delete (yyvsp[-2].i); }
#line 3089 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 165:
#line 377 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCH,new ExprTree((yyvsp[-1].varnode))); }
#line 3095 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 166:
#line 378 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CBRANCH,new ExprTree((yyvsp[-1].varnode)),(yyvsp[-3].tree)); }
#line 3101 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 167:
#line 379 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_BRANCHIND,(yyvsp[-2].tree)); }
#line 3107 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 168:
#line 380 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALL,new ExprTree((yyvsp[-1].varnode))); }
#line 3113 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 169:
#line 381 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_CALLIND,(yyvsp[-2].tree)); }
#line 3119 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 170:
#line 382 "slghparse.y" /* yacc.c:1646  */
    { yyerror("Must specify an indirect parameter for return"); YYERROR; }
#line 3125 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 171:
#line 383 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.createOpNoOut(CPUI_RETURN,(yyvsp[-2].tree)); }
#line 3131 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 172:
#line 384 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->createMacroUse((yyvsp[-4].macrosym),(yyvsp[-2].param)); }
#line 3137 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 173:
#line 385 "slghparse.y" /* yacc.c:1646  */
    { (yyval.stmt) = slgh->pcode.placeLabel( (yyvsp[0].labelsym) ); }
#line 3143 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 174:
#line 387 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = new ExprTree((yyvsp[0].varnode)); }
#line 3149 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 175:
#line 388 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createLoad((yyvsp[-1].starqual),(yyvsp[0].tree)); }
#line 3155 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 176:
#line 389 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = (yyvsp[-1].tree); }
#line 3161 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 177:
#line 390 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3167 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 178:
#line 391 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3173 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 179:
#line 392 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3179 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 180:
#line 393 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3185 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 181:
#line 394 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3191 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 182:
#line 395 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3197 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 183:
#line 396 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3203 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 184:
#line 397 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3209 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 185:
#line 398 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3215 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 186:
#line 399 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3221 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 187:
#line 400 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3227 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 188:
#line 401 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SLESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3233 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 189:
#line 402 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_2COMP,(yyvsp[0].tree)); }
#line 3239 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 190:
#line 403 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_NEGATE,(yyvsp[0].tree)); }
#line 3245 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 191:
#line 404 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3251 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 192:
#line 405 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3257 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 193:
#line 406 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3263 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 194:
#line 407 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_LEFT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3269 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 195:
#line 408 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_RIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3275 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 196:
#line 409 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SRIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3281 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 197:
#line 410 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3287 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 198:
#line 411 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3293 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 199:
#line 412 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SDIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3299 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 200:
#line 413 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_REM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3305 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 201:
#line 414 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SREM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3311 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 202:
#line 415 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_NEGATE,(yyvsp[0].tree)); }
#line 3317 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 203:
#line 416 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3323 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 204:
#line 417 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3329 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 205:
#line 418 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_BOOL_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3335 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 206:
#line 419 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3341 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 207:
#line 420 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3347 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 208:
#line 421 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3353 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 209:
#line 422 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3359 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 210:
#line 423 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3365 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 211:
#line 424 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 3371 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 212:
#line 425 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3377 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 213:
#line 426 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3383 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 214:
#line 427 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3389 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 215:
#line 428 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 3395 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 216:
#line 429 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NEG,(yyvsp[0].tree)); }
#line 3401 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 217:
#line 430 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ABS,(yyvsp[-1].tree)); }
#line 3407 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 218:
#line 431 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_SQRT,(yyvsp[-1].tree)); }
#line 3413 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 219:
#line 432 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SEXT,(yyvsp[-1].tree)); }
#line 3419 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 220:
#line 433 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_ZEXT,(yyvsp[-1].tree)); }
#line 3425 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 221:
#line 434 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_CARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3431 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 222:
#line 435 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SCARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3437 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 223:
#line 436 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_INT_SBORROW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3443 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 224:
#line 437 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOAT2FLOAT,(yyvsp[-1].tree)); }
#line 3449 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 225:
#line 438 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_INT2FLOAT,(yyvsp[-1].tree)); }
#line 3455 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 226:
#line 439 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_NAN,(yyvsp[-1].tree)); }
#line 3461 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 227:
#line 440 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_TRUNC,(yyvsp[-1].tree)); }
#line 3467 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 228:
#line 441 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_CEIL,(yyvsp[-1].tree)); }
#line 3473 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 229:
#line 442 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_FLOOR,(yyvsp[-1].tree)); }
#line 3479 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 230:
#line 443 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_FLOAT_ROUND,(yyvsp[-1].tree)); }
#line 3485 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 231:
#line 444 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-1].tree)); }
#line 3491 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 232:
#line 445 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_NEW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 3497 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 233:
#line 446 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_POPCOUNT,(yyvsp[-1].tree)); }
#line 3503 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 234:
#line 447 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }
#line 3509 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 235:
#line 448 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }
#line 3515 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 236:
#line 449 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }
#line 3521 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 237:
#line 450 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree)=slgh->pcode.createBitRange((yyvsp[0].bitsym)->getParentSymbol(),(yyvsp[0].bitsym)->getBitOffset(),(yyvsp[0].bitsym)->numBits()); }
#line 3527 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 238:
#line 451 "slghparse.y" /* yacc.c:1646  */
    { (yyval.tree) = slgh->pcode.createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }
#line 3533 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 239:
#line 452 "slghparse.y" /* yacc.c:1646  */
    { if ((*(yyvsp[-1].param)).size() < 2) { string errmsg = "Must at least two inputs to cpool"; yyerror(errmsg.c_str()); YYERROR; } (yyval.tree) = slgh->pcode.createVariadic(CPUI_CPOOLREF,(yyvsp[-1].param)); }
#line 3539 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 240:
#line 454 "slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }
#line 3545 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 241:
#line 455 "slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }
#line 3551 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 242:
#line 456 "slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
#line 3557 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 243:
#line 457 "slghparse.y" /* yacc.c:1646  */
    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(slgh->getDefaultCodeSpace()); }
#line 3563 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 244:
#line 459 "slghparse.y" /* yacc.c:1646  */
    { VarnodeTpl *sym = (yyvsp[0].startsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 3569 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 245:
#line 460 "slghparse.y" /* yacc.c:1646  */
    { VarnodeTpl *sym = (yyvsp[0].endsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 3575 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 246:
#line 461 "slghparse.y" /* yacc.c:1646  */
    { VarnodeTpl *sym = (yyvsp[0].next2sym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 3581 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 247:
#line 462 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }
#line 3587 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 248:
#line 463 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); yyerror("Parsed integer is too big (overflow)"); }
#line 3593 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 249:
#line 464 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].operandsym)->getVarnode(); (yyvsp[0].operandsym)->setCodeAddress(); }
#line 3599 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 250:
#line 465 "slghparse.y" /* yacc.c:1646  */
    { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }
#line 3605 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 251:
#line 466 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }
#line 3611 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 252:
#line 467 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3617 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 253:
#line 469 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 3623 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 254:
#line 470 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].varnode); }
#line 3629 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 255:
#line 471 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3635 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 256:
#line 472 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3641 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 257:
#line 474 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }
#line 3647 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 258:
#line 475 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); yyerror("Parsed integer is too big (overflow)"); }
#line 3653 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 259:
#line 476 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
#line 3659 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 260:
#line 477 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
#line 3665 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 261:
#line 478 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 3671 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 262:
#line 480 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 3677 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 263:
#line 481 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3683 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 264:
#line 482 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3689 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 265:
#line 484 "slghparse.y" /* yacc.c:1646  */
    { (yyval.labelsym) = (yyvsp[-1].labelsym); }
#line 3695 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 266:
#line 485 "slghparse.y" /* yacc.c:1646  */
    { (yyval.labelsym) = slgh->pcode.defineLabel( (yyvsp[-1].str) ); }
#line 3701 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 267:
#line 487 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 3707 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 268:
#line 488 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),0); }
#line 3713 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 269:
#line 489 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = slgh->pcode.addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 3719 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 270:
#line 490 "slghparse.y" /* yacc.c:1646  */
    { (yyval.varnode) = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
#line 3725 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 271:
#line 491 "slghparse.y" /* yacc.c:1646  */
    { string errmsg="Unknown export varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3731 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 272:
#line 492 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = "Subtable not attached to operand: "+(yyvsp[0].subtablesym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 3737 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 273:
#line 494 "slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].valuesym); }
#line 3743 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 274:
#line 495 "slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].valuemapsym); }
#line 3749 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 275:
#line 496 "slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].contextsym); }
#line 3755 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 276:
#line 497 "slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].namesym); }
#line 3761 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 277:
#line 498 "slghparse.y" /* yacc.c:1646  */
    { (yyval.famsym) = (yyvsp[0].varlistsym); }
#line 3767 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 278:
#line 500 "slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].varsym); }
#line 3773 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 279:
#line 501 "slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].specsym); }
#line 3779 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 280:
#line 502 "slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].operandsym); }
#line 3785 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 281:
#line 503 "slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].startsym); }
#line 3791 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 282:
#line 504 "slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].endsym); }
#line 3797 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 283:
#line 505 "slghparse.y" /* yacc.c:1646  */
    { (yyval.specsym) = (yyvsp[0].next2sym); }
#line 3803 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 284:
#line 507 "slghparse.y" /* yacc.c:1646  */
    { (yyval.str) = new string; (*(yyval.str)) += (yyvsp[0].ch); }
#line 3809 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 285:
#line 508 "slghparse.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[-1].str); (*(yyval.str)) += (yyvsp[0].ch); }
#line 3815 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 286:
#line 510 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = (yyvsp[-1].biglist); }
#line 3821 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 287:
#line 511 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3827 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 288:
#line 512 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3833 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 289:
#line 514 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3839 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 290:
#line 515 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3845 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 291:
#line 516 "slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
                                  (yyval.biglist) = new vector<intb>; (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
#line 3852 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 292:
#line 518 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back(intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3858 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 293:
#line 519 "slghparse.y" /* yacc.c:1646  */
    { (yyval.biglist) = (yyvsp[-2].biglist); (yyval.biglist)->push_back(-intb(*(yyvsp[0].i))); delete (yyvsp[0].i); }
#line 3864 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 294:
#line 520 "slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = "Expecting integer but saw: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
                                  (yyval.biglist) = (yyvsp[-1].biglist); (yyval.biglist)->push_back((intb)0xBADBEEF); delete (yyvsp[0].str); }
#line 3871 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 295:
#line 523 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); }
#line 3877 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 296:
#line 524 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 3883 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 297:
#line 526 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
#line 3889 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 298:
#line 527 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 3895 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 299:
#line 528 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = (yyvsp[0].anysym)->getName()+": redefined"; yyerror(errmsg.c_str()); YYERROR; }
#line 3901 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 300:
#line 530 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); }
#line 3907 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 301:
#line 532 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( *(yyvsp[0].str) ); delete (yyvsp[0].str); }
#line 3913 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 302:
#line 533 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back( (yyvsp[0].anysym)->getName() ); }
#line 3919 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 303:
#line 534 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 3925 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 304:
#line 535 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-1].strlist); (yyval.strlist)->push_back((yyvsp[0].anysym)->getName()); }
#line 3931 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 305:
#line 537 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); }
#line 3937 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 306:
#line 538 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
#line 3943 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 307:
#line 539 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
#line 3949 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 308:
#line 541 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back( (yyvsp[0].valuesym) ); }
#line 3955 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 309:
#line 542 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
#line 3961 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 310:
#line 543 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].valuesym)); }
#line 3967 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 311:
#line 544 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].contextsym)); }
#line 3973 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 312:
#line 545 "slghparse.y" /* yacc.c:1646  */
    { string errmsg = *(yyvsp[0].str)+": is not a value pattern"; delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 3979 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 313:
#line 547 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); }
#line 3985 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 314:
#line 548 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
#line 3991 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 315:
#line 550 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((yyvsp[0].varsym)); }
#line 3997 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 316:
#line 551 "slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
				  (yyval.symlist) = new vector<SleighSymbol *>; (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
#line 4004 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 317:
#line 553 "slghparse.y" /* yacc.c:1646  */
    { (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((yyvsp[0].varsym)); }
#line 4010 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 318:
#line 554 "slghparse.y" /* yacc.c:1646  */
    { if (*(yyvsp[0].str)!="_") { string errmsg = *(yyvsp[0].str)+": is not a varnode symbol"; delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
                                  (yyval.symlist) = (yyvsp[-1].symlist); (yyval.symlist)->push_back((SleighSymbol *)0); delete (yyvsp[0].str); }
#line 4017 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 319:
#line 557 "slghparse.y" /* yacc.c:1646  */
    { (yyval.param) = new vector<ExprTree *>; }
#line 4023 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 320:
#line 558 "slghparse.y" /* yacc.c:1646  */
    { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }
#line 4029 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 321:
#line 559 "slghparse.y" /* yacc.c:1646  */
    { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }
#line 4035 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 322:
#line 561 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; }
#line 4041 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 323:
#line 562 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = new vector<string>; (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 4047 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 324:
#line 563 "slghparse.y" /* yacc.c:1646  */
    { (yyval.strlist) = (yyvsp[-2].strlist); (yyval.strlist)->push_back(*(yyvsp[0].str)); delete (yyvsp[0].str); }
#line 4053 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 325:
#line 565 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].spacesym); }
#line 4059 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 326:
#line 566 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].sectionsym); }
#line 4065 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 327:
#line 567 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].tokensym); }
#line 4071 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 328:
#line 568 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].useropsym); }
#line 4077 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 329:
#line 569 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].macrosym); }
#line 4083 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 330:
#line 570 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].subtablesym); }
#line 4089 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 331:
#line 571 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].valuesym); }
#line 4095 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 332:
#line 572 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].valuemapsym); }
#line 4101 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 333:
#line 573 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].contextsym); }
#line 4107 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 334:
#line 574 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].namesym); }
#line 4113 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 335:
#line 575 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].varsym); }
#line 4119 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 336:
#line 576 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].varlistsym); }
#line 4125 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 337:
#line 577 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].operandsym); }
#line 4131 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 338:
#line 578 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].startsym); }
#line 4137 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 339:
#line 579 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].endsym); }
#line 4143 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 340:
#line 580 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].next2sym); }
#line 4149 "slghparse.cc" /* yacc.c:1646  */
    break;

  case 341:
#line 581 "slghparse.y" /* yacc.c:1646  */
    { (yyval.anysym) = (yyvsp[0].bitsym); }
#line 4155 "slghparse.cc" /* yacc.c:1646  */
    break;


#line 4159 "slghparse.cc" /* yacc.c:1646  */
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
#line 583 "slghparse.y" /* yacc.c:1906  */


int yyerror(const char *s)

{
  slgh->reportError(s);
  return 0;
}

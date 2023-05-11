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
#define YYSTYPE         PCODESTYPE
/* Substitute the variable and function names.  */
#define yyparse         pcodeparse
#define yylex           pcodelex
#define yyerror         pcodeerror
#define yydebug         pcodedebug
#define yynerrs         pcodenerrs

#define yylval          pcodelval
#define yychar          pcodechar

/* Copy the first part of user declarations.  */


#include "pcodeparse.hh"

//#define YYERROR_VERBOSE
namespace ghidra {

extern int pcodelex(void);
static PcodeSnippet *pcode;
extern int pcodeerror(const char *str );



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


/* Debug traces.  */
#ifndef PCODEDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define PCODEDEBUG 1
#  else
#   define PCODEDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define PCODEDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined PCODEDEBUG */
#if PCODEDEBUG
extern int pcodedebug;
#endif

/* Token type.  */
#ifndef PCODETOKENTYPE
# define PCODETOKENTYPE
  enum pcodetokentype
  {
    OP_BOOL_OR = 258,
    OP_BOOL_AND = 259,
    OP_BOOL_XOR = 260,
    OP_EQUAL = 261,
    OP_NOTEQUAL = 262,
    OP_FEQUAL = 263,
    OP_FNOTEQUAL = 264,
    OP_GREATEQUAL = 265,
    OP_LESSEQUAL = 266,
    OP_SLESS = 267,
    OP_SGREATEQUAL = 268,
    OP_SLESSEQUAL = 269,
    OP_SGREAT = 270,
    OP_FLESS = 271,
    OP_FGREAT = 272,
    OP_FLESSEQUAL = 273,
    OP_FGREATEQUAL = 274,
    OP_LEFT = 275,
    OP_RIGHT = 276,
    OP_SRIGHT = 277,
    OP_FADD = 278,
    OP_FSUB = 279,
    OP_SDIV = 280,
    OP_SREM = 281,
    OP_FMULT = 282,
    OP_FDIV = 283,
    OP_ZEXT = 284,
    OP_CARRY = 285,
    OP_BORROW = 286,
    OP_SEXT = 287,
    OP_SCARRY = 288,
    OP_SBORROW = 289,
    OP_NAN = 290,
    OP_ABS = 291,
    OP_SQRT = 292,
    OP_CEIL = 293,
    OP_FLOOR = 294,
    OP_ROUND = 295,
    OP_INT2FLOAT = 296,
    OP_FLOAT2FLOAT = 297,
    OP_TRUNC = 298,
    OP_NEW = 299,
    BADINTEGER = 300,
    GOTO_KEY = 301,
    CALL_KEY = 302,
    RETURN_KEY = 303,
    IF_KEY = 304,
    ENDOFSTREAM = 305,
    LOCAL_KEY = 306,
    INTEGER = 307,
    STRING = 308,
    SPACESYM = 309,
    USEROPSYM = 310,
    VARSYM = 311,
    OPERANDSYM = 312,
    STARTSYM = 313,
    ENDSYM = 314,
    NEXT2SYM = 315,
    LABELSYM = 316
  };
#endif

/* Value type.  */
#if ! defined PCODESTYPE && ! defined PCODESTYPE_IS_DECLARED

union PCODESTYPE
{


  uintb *i;
  string *str;
  vector<ExprTree *> *param;
  StarQuality *starqual;
  VarnodeTpl *varnode;
  ExprTree *tree;
  vector<OpTpl *> *stmt;
  ConstructTpl *sem;

  SpaceSymbol *spacesym;
  UserOpSymbol *useropsym;
  LabelSymbol *labelsym;
  StartSymbol *startsym;
  EndSymbol *endsym;
  Next2Symbol *next2sym;
  OperandSymbol *operandsym;
  VarnodeSymbol *varsym;
  SpecificSymbol *specsym;


};

typedef union PCODESTYPE PCODESTYPE;
# define PCODESTYPE_IS_TRIVIAL 1
# define PCODESTYPE_IS_DECLARED 1
#endif


extern PCODESTYPE pcodelval;

int pcodeparse (void);



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
         || (defined PCODESTYPE_IS_TRIVIAL && PCODESTYPE_IS_TRIVIAL)))

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
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   1968

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  82
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  13
/* YYNRULES -- Number of rules.  */
#define YYNRULES  120
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  298

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   316

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    40,     2,     2,     2,    35,     9,     2,
      77,    78,    33,    29,    80,    30,     2,    34,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    75,     7,
      14,    76,    15,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    79,     2,    81,     8,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     6,     2,    41,     2,     2,     2,
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
       5,    10,    11,    12,    13,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    31,    32,
      36,    37,    38,    39,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    73,    74
};

#if PCODEDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint8 yyrline[] =
{
       0,   104,   104,   106,   107,   108,   109,   111,   112,   113,
     114,   115,   116,   117,   118,   119,   120,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   195,
     196,   197,   198,   200,   201,   202,   203,   204,   205,   206,
     207,   209,   210,   211,   213,   214,   215,   216,   217,   219,
     220,   222,   223,   225,   226,   227,   228,   229,   231,   232,
     233
};
#endif

#if PCODEDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "OP_BOOL_OR", "OP_BOOL_AND",
  "OP_BOOL_XOR", "'|'", "';'", "'^'", "'&'", "OP_EQUAL", "OP_NOTEQUAL",
  "OP_FEQUAL", "OP_FNOTEQUAL", "'<'", "'>'", "OP_GREATEQUAL",
  "OP_LESSEQUAL", "OP_SLESS", "OP_SGREATEQUAL", "OP_SLESSEQUAL",
  "OP_SGREAT", "OP_FLESS", "OP_FGREAT", "OP_FLESSEQUAL", "OP_FGREATEQUAL",
  "OP_LEFT", "OP_RIGHT", "OP_SRIGHT", "'+'", "'-'", "OP_FADD", "OP_FSUB",
  "'*'", "'/'", "'%'", "OP_SDIV", "OP_SREM", "OP_FMULT", "OP_FDIV", "'!'",
  "'~'", "OP_ZEXT", "OP_CARRY", "OP_BORROW", "OP_SEXT", "OP_SCARRY",
  "OP_SBORROW", "OP_NAN", "OP_ABS", "OP_SQRT", "OP_CEIL", "OP_FLOOR",
  "OP_ROUND", "OP_INT2FLOAT", "OP_FLOAT2FLOAT", "OP_TRUNC", "OP_NEW",
  "BADINTEGER", "GOTO_KEY", "CALL_KEY", "RETURN_KEY", "IF_KEY",
  "ENDOFSTREAM", "LOCAL_KEY", "INTEGER", "STRING", "SPACESYM", "USEROPSYM",
  "VARSYM", "OPERANDSYM", "STARTSYM", "ENDSYM", "NEXT2SYM", "LABELSYM",
  "':'", "'='", "'('", "')'", "'['", "','", "']'", "$accept", "rtl",
  "rtlmid", "statement", "expr", "sizedstar", "jumpdest", "varnode",
  "integervarnode", "lhsvarnode", "label", "specificsymbol", "paramlist", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   124,    59,    94,    38,
     261,   262,   263,   264,    60,    62,   265,   266,   267,   268,
     269,   270,   271,   272,   273,   274,   275,   276,   277,    43,
      45,   278,   279,    42,    47,    37,   280,   281,   282,   283,
      33,   126,   284,   285,   286,   287,   288,   289,   290,   291,
     292,   293,   294,   295,   296,   297,   298,   299,   300,   301,
     302,   303,   304,   305,   306,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,    58,    61,    40,    41,    91,
      44,    93
};
# endif

#define YYPACT_NINF -68

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-68)))

#define YYTABLE_NINF -111

#define yytable_value_is_error(Yytable_value) \
  (!!((Yytable_value) == (-111)))

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -68,     9,  1480,   -68,   459,   -40,   -46,   -68,   564,   672,
      -1,  1430,   -68,   -23,   -45,   -48,   -41,   -68,   -68,   -68,
     -68,   -68,   -68,  1430,   -67,   -68,   -22,   -68,   -12,   -68,
     -28,   -68,   -68,    29,    30,   -13,    -5,   -68,    -7,   -68,
     -68,   -68,   -68,  1430,    58,   -68,  1430,    59,   -68,  1430,
    1430,  1430,  1430,  1430,    -3,     5,     8,    11,    12,    28,
      66,    67,    68,    70,    71,    72,    74,    75,   117,   151,
    1430,  1551,  1430,   -68,   -24,     4,    -6,    10,    16,  1430,
    1430,  1398,    19,    41,  1430,   164,   785,   -68,   -68,   -68,
      -4,   172,   150,   -68,   187,   -68,   277,   -68,   -68,   -68,
     -68,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,   534,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,   888,   -68,   175,    -2,   176,   -68,
     178,  1430,   -68,   -68,   170,  1608,  1867,   -20,  1430,   171,
     173,  1645,   168,   -68,   174,   169,    69,   245,   246,   571,
     351,   642,   424,   461,   679,   750,   787,   858,   895,   966,
    1003,  1074,  1111,   314,    -9,   -68,  1903,   387,   387,  1037,
    1144,  1251,  1355,  1355,  1355,  1355,  1929,  1929,  1929,  1929,
    1929,  1929,  1929,  1929,  1929,  1929,  1929,  1929,   -14,   -14,
     -14,   199,   199,   199,   199,   -68,   -68,   -68,   -68,   -68,
     -68,   -68,   247,   -68,   177,   179,     7,  1682,  1430,   -68,
     250,  1430,  1719,   -68,   -68,   -68,   193,   195,   -68,   -68,
     -68,   -68,   -68,  1430,   -68,  1430,  1430,   -68,   -68,   -68,
     -68,   -68,   -68,   -68,   -68,   -68,   -68,  1430,   -68,   -68,
     -68,   196,   -68,  1430,   -68,  1756,   -68,  1867,   -68,   182,
     -68,  1182,  1219,  1290,  1327,   183,  1793,   -68,   189,   -68,
     -68,   -68,   -68,   -68,   -68,  1430,  1830,   -68
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       3,     0,     0,     1,     0,     0,    92,   105,     0,     0,
       0,     0,     2,     0,   104,   103,     0,   113,   114,   115,
     116,   117,     4,     0,     0,   102,     0,    25,   101,   103,
       0,   107,   101,     0,     0,     0,     0,    97,    96,   100,
      93,    94,    95,     0,     0,    99,     0,     0,    23,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    26,   101,     0,     0,     0,     0,     0,
     118,     0,     0,     0,     0,     0,     0,   112,   111,    91,
       0,     0,     0,    18,     0,    21,     0,    41,    68,    54,
      42,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   118,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    27,     0,     0,     0,     5,
       0,     0,    12,   106,     0,     0,   119,     0,     0,     0,
       0,     0,     0,   108,    90,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    28,    57,    56,    55,    45,
      43,    44,    31,    32,    58,    59,    33,    36,    34,    35,
      37,    38,    39,    40,    60,    61,    62,    63,    46,    47,
      48,    29,    30,    64,    65,    49,    50,    52,    51,    53,
      66,    67,     0,    86,     0,     0,     0,     0,     0,     9,
       0,     0,     0,    16,    17,     7,     0,     0,    98,    20,
      22,    24,    72,     0,    71,     0,     0,    78,    69,    70,
      80,    81,    82,    77,    76,    79,    83,     0,    88,    19,
      85,     0,     6,     0,     8,     0,    14,   120,    13,     0,
      89,     0,     0,     0,     0,     0,     0,    11,     0,    73,
      74,    75,    84,    87,    10,     0,     0,    15
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -68,   -68,   -68,   -68,   -11,   264,    -8,     1,   110,   -68,
     267,     0,   154
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,    22,   166,    72,    44,    73,    25,    26,
      45,    74,   167
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      71,    47,    28,    24,    32,    31,    48,     4,    82,     3,
      83,   159,    81,    76,   272,   143,   144,   145,   146,   147,
     148,   149,   150,   151,   152,   153,    33,    78,    79,    35,
      77,  -110,    92,    36,    34,    94,    80,    86,    96,    97,
      98,    99,   100,    75,    87,    88,    17,    18,    19,    20,
      21,   156,    89,   157,    84,   158,     7,    85,   240,   117,
     241,   155,    90,    14,  -109,    93,    95,  -109,   165,   268,
     162,   241,    91,   171,   101,   163,   249,   174,    49,   160,
     161,   164,   102,   273,   169,   103,    32,   173,   104,   105,
     179,   180,   181,   182,   183,   184,   185,   186,   187,   188,
     189,   190,   191,   192,   193,   106,   170,   196,   197,   198,
     199,   200,   201,   202,   203,   204,   205,   206,   207,   208,
     209,   210,   211,   212,   213,   214,   215,   216,   217,   218,
     219,   220,   221,   222,   223,   224,   225,   226,   227,   228,
     229,   230,   231,   107,   108,   109,   232,   110,   111,   112,
     237,   113,   114,   118,   119,   120,   121,   242,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,   115,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   275,   116,   172,
     277,   176,   147,   148,   149,   150,   151,   152,   153,   175,
     233,   235,   281,   236,   282,   283,   238,   243,   246,   247,
     248,   244,   250,   251,   269,   270,   284,   276,   279,   271,
     280,   285,   286,   288,   293,   295,    23,   234,   177,    27,
     194,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     118,   119,   120,   121,   296,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   118,   119,   120,
     121,     0,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,   178,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,   266,   121,   267,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   118,   119,   120,
     121,   253,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,     4,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,     0,     0,   255,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     7,     0,     0,
       0,     0,     0,     0,    14,    29,     0,     0,    17,    18,
      19,    20,    21,     0,    30,     0,     0,   118,   119,   120,
     121,   256,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,     5,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,   195,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    37,     0,     0,     0,     0,     0,     0,    38,
      39,     0,     0,     0,     0,    40,    41,    42,     0,     0,
       0,     0,     0,    43,     0,   118,   119,   120,   121,   252,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   118,   119,   120,   121,     5,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,     0,
     254,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      37,     0,     0,     0,     0,     0,     0,    38,    39,     0,
       0,     0,     0,    40,    41,    42,     0,     0,     0,     0,
       0,    46,     0,   118,   119,   120,   121,   257,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,     4,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,     0,   258,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     7,     0,     0,     0,     0,     0,     0,
      14,    29,     0,     0,    17,    18,    19,    20,    21,     0,
       0,   118,   119,   120,   121,   259,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,   152,   153,   118,   119,
     120,   121,     5,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,     0,   260,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    37,     0,     0,     0,
       0,     0,     0,    38,    39,     0,     0,     0,     0,    40,
      41,    42,     0,     0,     0,     0,     0,     0,     0,   118,
     119,   120,   121,   261,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,   133,   134,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,   151,   152,   153,   118,   119,   120,   121,
       0,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,     0,   262,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   118,   119,   120,
     121,   263,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,     0,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,   264,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,     0,   118,   119,   120,   121,   265,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   118,   119,   120,   121,     0,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,     0,
     289,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,     0,   118,   119,   120,   121,   290,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,     0,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,     0,   291,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,     0,     0,     0,     0,     0,
       0,   118,   119,   120,   121,   292,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,   152,   153,     0,     4,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      50,     0,    51,     6,     0,     0,     0,     0,     0,     0,
      52,    53,    54,    55,   168,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,     7,     4,
       0,     0,     0,     0,     5,    14,    29,     0,    69,    17,
      18,    19,    20,    21,     0,     0,     0,    70,     0,     0,
       0,     0,     0,     6,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     7,     8,
       9,    10,    11,    12,    13,    14,    15,     0,    16,    17,
      18,    19,    20,    21,   118,   119,   120,   121,     0,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     154,   118,   119,   120,   121,   239,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,   152,   153,   118,   119,
     120,   121,   245,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,   118,   119,   120,   121,   274,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   118,   119,   120,   121,   278,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   118,
     119,   120,   121,   287,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,   133,   134,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,   151,   152,   153,   118,   119,   120,   121,
     294,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,   118,   119,   120,   121,   297,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,     0,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   119,   120,   121,
       0,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,  -111,  -111,  -111,  -111,  -111,  -111,  -111,
    -111,  -111,  -111,  -111,  -111,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153
};

static const yytype_int16 yycheck[] =
{
      11,     9,     2,     2,     4,     4,     7,     9,    75,     0,
      77,     7,    23,    13,     7,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    66,    75,    76,    75,
      75,    79,    43,    79,    74,    46,    77,    65,    49,    50,
      51,    52,    53,    66,    15,    15,    69,    70,    71,    72,
      73,    75,    65,    77,    76,    79,    58,    79,    78,    70,
      80,    72,    67,    65,    76,     7,     7,    79,    79,    78,
      76,    80,    79,    84,    77,    65,     7,    81,    79,    75,
      76,    65,    77,    76,    65,    77,    86,    86,    77,    77,
     101,   102,   103,   104,   105,   106,   107,   108,   109,   110,
     111,   112,   113,   114,   115,    77,    65,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,    77,    77,    77,   154,    77,    77,    77,
     161,    77,    77,     3,     4,     5,     6,   168,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,    77,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,   238,    77,    65,
     241,    81,    33,    34,    35,    36,    37,    38,    39,    67,
      65,    65,   253,    65,   255,   256,    76,    76,    80,    75,
      81,    78,     7,     7,     7,    78,   267,     7,    65,    80,
      65,    65,   273,    81,    81,    76,     2,   157,    81,     2,
     116,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
       3,     4,     5,     6,   295,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     3,     4,     5,
       6,    -1,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,    81,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    78,     6,    80,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     3,     4,     5,
       6,    80,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,     9,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,    -1,    80,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,
      -1,    -1,    -1,    -1,    65,    66,    -1,    -1,    69,    70,
      71,    72,    73,    -1,    75,    -1,    -1,     3,     4,     5,
       6,    80,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,    14,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    78,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,    65,
      66,    -1,    -1,    -1,    -1,    71,    72,    73,    -1,    -1,
      -1,    -1,    -1,    79,    -1,     3,     4,     5,     6,    78,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,     3,     4,     5,     6,    14,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    -1,
      78,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      58,    -1,    -1,    -1,    -1,    -1,    -1,    65,    66,    -1,
      -1,    -1,    -1,    71,    72,    73,    -1,    -1,    -1,    -1,
      -1,    79,    -1,     3,     4,     5,     6,    78,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,     9,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    -1,    78,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,
      65,    66,    -1,    -1,    69,    70,    71,    72,    73,    -1,
      -1,     3,     4,     5,     6,    78,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,     3,     4,
       5,     6,    14,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    -1,    78,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,    -1,
      -1,    -1,    -1,    65,    66,    -1,    -1,    -1,    -1,    71,
      72,    73,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     3,
       4,     5,     6,    78,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,     3,     4,     5,     6,
      -1,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    -1,    78,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     3,     4,     5,
       6,    78,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,    -1,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    78,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    -1,     3,     4,     5,     6,    78,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,     3,     4,     5,     6,    -1,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    -1,
      78,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,     3,     4,     5,     6,    78,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,    -1,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    -1,    78,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    -1,    -1,    -1,    -1,    -1,
      -1,     3,     4,     5,     6,    78,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    -1,     9,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      30,    -1,    32,    33,    -1,    -1,    -1,    -1,    -1,    -1,
      40,    41,    42,    43,    76,    45,    46,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,     9,
      -1,    -1,    -1,    -1,    14,    65,    66,    -1,    68,    69,
      70,    71,    72,    73,    -1,    -1,    -1,    77,    -1,    -1,
      -1,    -1,    -1,    33,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    -1,    68,    69,
      70,    71,    72,    73,     3,     4,     5,     6,    -1,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      59,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,     3,     4,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,    -1,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     4,     5,     6,
      -1,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    83,    84,     0,     9,    14,    33,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    68,    69,    70,    71,
      72,    73,    85,    87,    89,    90,    91,    92,    93,    66,
      75,    89,    93,    66,    74,    75,    79,    58,    65,    66,
      71,    72,    73,    79,    88,    92,    79,    88,     7,    79,
      30,    32,    40,    41,    42,    43,    45,    46,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    68,
      77,    86,    87,    89,    93,    66,    93,    75,    75,    76,
      77,    86,    75,    77,    76,    79,    65,    15,    15,    65,
      67,    79,    86,     7,    86,     7,    86,    86,    86,    86,
      86,    77,    77,    77,    77,    77,    77,    77,    77,    77,
      77,    77,    77,    77,    77,    77,    77,    86,     3,     4,
       5,     6,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    59,    86,    75,    77,    79,     7,
      75,    76,    76,    65,    65,    86,    86,    94,    76,    65,
      65,    86,    65,    89,    81,    67,    81,    81,    81,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    94,    78,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    88,    65,    90,    65,    65,    86,    76,     7,
      78,    80,    86,    76,    78,     7,    80,    75,    81,     7,
       7,     7,    78,    80,    78,    80,    80,    78,    78,    78,
      78,    78,    78,    78,    78,    78,    78,    80,    78,     7,
      78,    80,     7,    76,     7,    86,     7,    86,     7,    65,
      65,    86,    86,    86,    86,    65,    86,     7,    81,    78,
      78,    78,    78,    81,     7,    76,    86,     7
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    82,    83,    84,    84,    84,    84,    85,    85,    85,
      85,    85,    85,    85,    85,    85,    85,    85,    85,    85,
      85,    85,    85,    85,    85,    85,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    87,
      87,    87,    87,    88,    88,    88,    88,    88,    88,    88,
      88,    89,    89,    89,    90,    90,    90,    90,    90,    91,
      91,    92,    92,    93,    93,    93,    93,    93,    94,    94,
      94
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     2,     0,     2,     4,     6,     4,     5,     4,
       7,     6,     3,     5,     5,     9,     4,     4,     3,     5,
       5,     3,     5,     2,     5,     1,     1,     2,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     2,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     2,     4,
       4,     4,     4,     6,     6,     6,     4,     4,     4,     4,
       4,     4,     4,     4,     6,     4,     3,     6,     4,     6,
       4,     3,     1,     1,     1,     1,     1,     1,     4,     1,
       1,     1,     1,     1,     1,     1,     3,     2,     4,     1,
       1,     3,     3,     1,     1,     1,     1,     1,     0,     1,
       3
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
#if PCODEDEBUG

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
#else /* !PCODEDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !PCODEDEBUG */


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
  switch (yytype)
    {
          case 65: /* INTEGER  */

      { delete ((*yyvaluep).i); }

        break;

    case 66: /* STRING  */

      { delete ((*yyvaluep).str); }

        break;

    case 84: /* rtlmid  */

      { delete ((*yyvaluep).sem); }

        break;

    case 85: /* statement  */

      { if (((*yyvaluep).stmt) != (vector<OpTpl *> *)0) { for(int4 i=0;i<((*yyvaluep).stmt)->size();++i) delete (*((*yyvaluep).stmt))[i]; delete ((*yyvaluep).stmt);} }

        break;

    case 86: /* expr  */

      { delete ((*yyvaluep).tree); }

        break;

    case 87: /* sizedstar  */

      { delete ((*yyvaluep).starqual); }

        break;

    case 88: /* jumpdest  */

      { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }

        break;

    case 89: /* varnode  */

      { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }

        break;

    case 90: /* integervarnode  */

      { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }

        break;

    case 91: /* lhsvarnode  */

      { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }

        break;

    case 94: /* paramlist  */

      { for(int4 i=0;i<((*yyvaluep).param)->size();++i) delete (*((*yyvaluep).param))[i]; delete ((*yyvaluep).param); }

        break;


      default:
        break;
    }
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
        case 2:

    { pcode->setResult((yyvsp[-1].sem)); }

    break;

  case 3:

    { (yyval.sem) = new ConstructTpl(); }

    break;

  case 4:

    { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[0].stmt); yyerror("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }

    break;

  case 5:

    { (yyval.sem) = (yyvsp[-3].sem); pcode->newLocalDefinition((yyvsp[-1].str)); }

    break;

  case 6:

    { (yyval.sem) = (yyvsp[-5].sem); pcode->newLocalDefinition((yyvsp[-3].str),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }

    break;

  case 7:

    { (yyvsp[-1].tree)->setOutput((yyvsp[-3].varnode)); (yyval.stmt) = ExprTree::toVector((yyvsp[-1].tree)); }

    break;

  case 8:

    { (yyval.stmt) = pcode->newOutput(true,(yyvsp[-1].tree),(yyvsp[-3].str)); }

    break;

  case 9:

    { (yyval.stmt) = pcode->newOutput(false,(yyvsp[-1].tree),(yyvsp[-3].str)); }

    break;

  case 10:

    { (yyval.stmt) = pcode->newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }

    break;

  case 11:

    { (yyval.stmt) = pcode->newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }

    break;

  case 12:

    { (yyval.stmt) = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+(yyvsp[-1].specsym)->getName(); yyerror(errmsg.c_str()); YYERROR; }

    break;

  case 13:

    { (yyval.stmt) = pcode->createStore((yyvsp[-4].starqual),(yyvsp[-3].tree),(yyvsp[-1].tree)); }

    break;

  case 14:

    { (yyval.stmt) = pcode->createUserOpNoOut((yyvsp[-4].useropsym),(yyvsp[-2].param)); }

    break;

  case 15:

    { (yyval.stmt) = pcode->assignBitRange((yyvsp[-8].varnode),(uint4)*(yyvsp[-6].i),(uint4)*(yyvsp[-4].i),(yyvsp[-1].tree)); delete (yyvsp[-6].i), delete (yyvsp[-4].i); }

    break;

  case 16:

    { (yyval.stmt) = (vector<OpTpl *> *)0; delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal truncation on left-hand side of assignment"); YYERROR; }

    break;

  case 17:

    { (yyval.stmt) = (vector<OpTpl *> *)0; delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal subpiece on left-hand side of assignment"); YYERROR; }

    break;

  case 18:

    { (yyval.stmt) = pcode->createOpNoOut(CPUI_BRANCH,new ExprTree((yyvsp[-1].varnode))); }

    break;

  case 19:

    { (yyval.stmt) = pcode->createOpNoOut(CPUI_CBRANCH,new ExprTree((yyvsp[-1].varnode)),(yyvsp[-3].tree)); }

    break;

  case 20:

    { (yyval.stmt) = pcode->createOpNoOut(CPUI_BRANCHIND,(yyvsp[-2].tree)); }

    break;

  case 21:

    { (yyval.stmt) = pcode->createOpNoOut(CPUI_CALL,new ExprTree((yyvsp[-1].varnode))); }

    break;

  case 22:

    { (yyval.stmt) = pcode->createOpNoOut(CPUI_CALLIND,(yyvsp[-2].tree)); }

    break;

  case 23:

    { (yyval.stmt) = (vector<OpTpl *> *)0; yyerror("Must specify an indirect parameter for return"); YYERROR; }

    break;

  case 24:

    { (yyval.stmt) = pcode->createOpNoOut(CPUI_RETURN,(yyvsp[-2].tree)); }

    break;

  case 25:

    { (yyval.stmt) = pcode->placeLabel( (yyvsp[0].labelsym) ); }

    break;

  case 26:

    { (yyval.tree) = new ExprTree((yyvsp[0].varnode)); }

    break;

  case 27:

    { (yyval.tree) = pcode->createLoad((yyvsp[-1].starqual),(yyvsp[0].tree)); }

    break;

  case 28:

    { (yyval.tree) = (yyvsp[-1].tree); }

    break;

  case 29:

    { (yyval.tree) = pcode->createOp(CPUI_INT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 30:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 31:

    { (yyval.tree) = pcode->createOp(CPUI_INT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 32:

    { (yyval.tree) = pcode->createOp(CPUI_INT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 33:

    { (yyval.tree) = pcode->createOp(CPUI_INT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 34:

    { (yyval.tree) = pcode->createOp(CPUI_INT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }

    break;

  case 35:

    { (yyval.tree) = pcode->createOp(CPUI_INT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 36:

    { (yyval.tree) = pcode->createOp(CPUI_INT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }

    break;

  case 37:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SLESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 38:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SLESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }

    break;

  case 39:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SLESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 40:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SLESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }

    break;

  case 41:

    { (yyval.tree) = pcode->createOp(CPUI_INT_2COMP,(yyvsp[0].tree)); }

    break;

  case 42:

    { (yyval.tree) = pcode->createOp(CPUI_INT_NEGATE,(yyvsp[0].tree)); }

    break;

  case 43:

    { (yyval.tree) = pcode->createOp(CPUI_INT_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 44:

    { (yyval.tree) = pcode->createOp(CPUI_INT_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 45:

    { (yyval.tree) = pcode->createOp(CPUI_INT_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 46:

    { (yyval.tree) = pcode->createOp(CPUI_INT_LEFT,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 47:

    { (yyval.tree) = pcode->createOp(CPUI_INT_RIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 48:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SRIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 49:

    { (yyval.tree) = pcode->createOp(CPUI_INT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 50:

    { (yyval.tree) = pcode->createOp(CPUI_INT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 51:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SDIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 52:

    { (yyval.tree) = pcode->createOp(CPUI_INT_REM,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 53:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SREM,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 54:

    { (yyval.tree) = pcode->createOp(CPUI_BOOL_NEGATE,(yyvsp[0].tree)); }

    break;

  case 55:

    { (yyval.tree) = pcode->createOp(CPUI_BOOL_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 56:

    { (yyval.tree) = pcode->createOp(CPUI_BOOL_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 57:

    { (yyval.tree) = pcode->createOp(CPUI_BOOL_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 58:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 59:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 60:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 61:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }

    break;

  case 62:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 63:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }

    break;

  case 64:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 65:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 66:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 67:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }

    break;

  case 68:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_NEG,(yyvsp[0].tree)); }

    break;

  case 69:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_ABS,(yyvsp[-1].tree)); }

    break;

  case 70:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_SQRT,(yyvsp[-1].tree)); }

    break;

  case 71:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SEXT,(yyvsp[-1].tree)); }

    break;

  case 72:

    { (yyval.tree) = pcode->createOp(CPUI_INT_ZEXT,(yyvsp[-1].tree)); }

    break;

  case 73:

    { (yyval.tree) = pcode->createOp(CPUI_INT_CARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }

    break;

  case 74:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SCARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }

    break;

  case 75:

    { (yyval.tree) = pcode->createOp(CPUI_INT_SBORROW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }

    break;

  case 76:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_FLOAT2FLOAT,(yyvsp[-1].tree)); }

    break;

  case 77:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_INT2FLOAT,(yyvsp[-1].tree)); }

    break;

  case 78:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_NAN,(yyvsp[-1].tree)); }

    break;

  case 79:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_TRUNC,(yyvsp[-1].tree)); }

    break;

  case 80:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_CEIL,(yyvsp[-1].tree)); }

    break;

  case 81:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_FLOOR,(yyvsp[-1].tree)); }

    break;

  case 82:

    { (yyval.tree) = pcode->createOp(CPUI_FLOAT_ROUND,(yyvsp[-1].tree)); }

    break;

  case 83:

    { (yyval.tree) = pcode->createOp(CPUI_NEW,(yyvsp[-1].tree)); }

    break;

  case 84:

    { (yyval.tree) = pcode->createOp(CPUI_NEW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }

    break;

  case 85:

    { (yyval.tree) = pcode->createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }

    break;

  case 86:

    { (yyval.tree) = pcode->createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }

    break;

  case 87:

    { (yyval.tree) = pcode->createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }

    break;

  case 88:

    { (yyval.tree) = pcode->createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }

    break;

  case 89:

    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }

    break;

  case 90:

    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }

    break;

  case 91:

    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(pcode->getDefaultSpace()); }

    break;

  case 92:

    { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(pcode->getDefaultSpace()); }

    break;

  case 93:

    { VarnodeTpl *sym = (yyvsp[0].startsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }

    break;

  case 94:

    { VarnodeTpl *sym = (yyvsp[0].endsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }

    break;

  case 95:

    { VarnodeTpl *sym = (yyvsp[0].next2sym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }

    break;

  case 96:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }

    break;

  case 97:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); yyerror("Parsed integer is too big (overflow)"); }

    break;

  case 98:

    { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }

    break;

  case 99:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }

    break;

  case 100:

    { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }

    break;

  case 101:

    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }

    break;

  case 102:

    { (yyval.varnode) = (yyvsp[0].varnode); }

    break;

  case 103:

    { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }

    break;

  case 104:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }

    break;

  case 105:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); yyerror("Parsed integer is too big (overflow)"); }

    break;

  case 106:

    { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }

    break;

  case 107:

    { (yyval.varnode) = pcode->addressOf((yyvsp[0].varnode),0); }

    break;

  case 108:

    { (yyval.varnode) = pcode->addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }

    break;

  case 109:

    { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }

    break;

  case 110:

    { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }

    break;

  case 111:

    { (yyval.labelsym) = (yyvsp[-1].labelsym); }

    break;

  case 112:

    { (yyval.labelsym) = pcode->defineLabel( (yyvsp[-1].str) ); }

    break;

  case 113:

    { (yyval.specsym) = (yyvsp[0].varsym); }

    break;

  case 114:

    { (yyval.specsym) = (yyvsp[0].operandsym); }

    break;

  case 115:

    { (yyval.specsym) = (yyvsp[0].startsym); }

    break;

  case 116:

    { (yyval.specsym) = (yyvsp[0].endsym); }

    break;

  case 117:

    { (yyval.specsym) = (yyvsp[0].next2sym); }

    break;

  case 118:

    { (yyval.param) = new vector<ExprTree *>; }

    break;

  case 119:

    { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }

    break;

  case 120:

    { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }

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



#define IDENTREC_SIZE 46
const IdentRec PcodeLexer::idents[]= { // Sorted list of identifiers
  { "!=", OP_NOTEQUAL },
  { "&&", OP_BOOL_AND },
  { "<<", OP_LEFT },
  { "<=", OP_LESSEQUAL },
  { "==", OP_EQUAL },
  { ">=", OP_GREATEQUAL },
  { ">>", OP_RIGHT },
  { "^^", OP_BOOL_XOR },
  { "||", OP_BOOL_OR },
  { "abs", OP_ABS },
  { "borrow", OP_BORROW },
  { "call", CALL_KEY },
  { "carry", OP_CARRY },
  { "ceil", OP_CEIL },
  { "f!=", OP_FNOTEQUAL },
  { "f*", OP_FMULT },
  { "f+", OP_FADD },
  { "f-", OP_FSUB },
  { "f/", OP_FDIV },
  { "f<", OP_FLESS },
  { "f<=", OP_FLESSEQUAL },
  { "f==", OP_FEQUAL },
  { "f>", OP_FGREAT },
  { "f>=", OP_FGREATEQUAL },
  { "float2float", OP_FLOAT2FLOAT },
  { "floor", OP_FLOOR },
  { "goto", GOTO_KEY },
  { "if", IF_KEY },
  { "int2float", OP_INT2FLOAT },
  { "local", LOCAL_KEY },
  { "nan", OP_NAN },
  { "return", RETURN_KEY },
  { "round", OP_ROUND },
  { "s%", OP_SREM },
  { "s/", OP_SDIV },
  { "s<", OP_SLESS },
  { "s<=", OP_SLESSEQUAL },
  { "s>", OP_SGREAT },
  { "s>=", OP_SGREATEQUAL },
  { "s>>",OP_SRIGHT },
  { "sborrow", OP_SBORROW },
  { "scarry", OP_SCARRY },
  { "sext", OP_SEXT },
  { "sqrt", OP_SQRT },
  { "trunc", OP_TRUNC },
  { "zext", OP_ZEXT }
};

int4 PcodeLexer::findIdentifier(const string &str) const

{
  int4 low = 0;
  int4 high = IDENTREC_SIZE-1;
  int4 comp;
  do {
    int4 targ = (low+high)/2;
    comp = str.compare(idents[targ].nm);
    if (comp < 0) 		// str comes before targ
      high = targ-1;
    else if (comp > 0)		// str comes after targ
      low = targ + 1;
    else
      return targ;
  } while(low <= high);
  return -1;
}

int4 PcodeLexer::moveState(void)

{
  switch(curstate) {
  case start:
    switch(curchar) {
    case '#':
      curstate = comment;
      return start;
    case '|':
      if (lookahead1 == '|') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '&':
      if (lookahead1 == '&') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '^':
      if (lookahead1 == '^') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '>':
      if ((lookahead1 == '>')||(lookahead1=='=')) {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '<':
      if ((lookahead1 == '<')||(lookahead1=='=')) {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '=':
      if (lookahead1 == '=') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '!':
      if (lookahead1 == '=') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '(':
    case ')':
    case ',':
    case ':':
    case '[':
    case ']':
    case ';':
    case '+':
    case '-':
    case '*':
    case '/':
    case '%':
    case '~':
      return punctuation;
    case 's':
    case 'f':
      if (curchar == 's') {
	if ((lookahead1 == '/')||(lookahead1=='%')) {
	  starttoken();
	  curstate = special2;
	  return start;
	}
	else if (lookahead1 == '<') {
	  starttoken();
	  if (lookahead2 == '=')
	    curstate = special3;
	  else
	    curstate = special2;
	  return start;
	}
	else if (lookahead1 == '>') {
	  starttoken();
	  if ((lookahead2=='>')||(lookahead2=='='))
	    curstate = special3;
	  else
	    curstate = special2;
	  return start;
	}
      }
      else {			// curchar == 'f'
	if ((lookahead1=='+')||(lookahead1=='-')||(lookahead1=='*')||(lookahead1=='/')) {
	  starttoken();
	  curstate = special2;
	  return start;
	}
	else if (((lookahead1=='=')||(lookahead1=='!'))&&(lookahead2=='=')) {
	  starttoken();
	  curstate = special3;
	  return start;
	}
	else if ((lookahead1=='<')||(lookahead1=='>')) {
	  starttoken();
	  if (lookahead2 == '=')
	    curstate = special3;
	  else
	    curstate = special2;
	  return start;
	}
      }
      // fall through here, treat 's' and 'f' as ordinary characters
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'g':
    case 'h':
    case 'i':
    case 'j':
    case 'k':
    case 'l':
    case 'm':
    case 'n':
    case 'o':
    case 'p':
    case 'q':
    case 'r':
    case 't':
    case 'u':
    case 'v':
    case 'w':
    case 'x':
    case 'y':
    case 'z':
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'G':
    case 'H':
    case 'I':
    case 'J':
    case 'K':
    case 'L':
    case 'M':
    case 'N':
    case 'O':
    case 'P':
    case 'Q':
    case 'R':
    case 'S':
    case 'T':
    case 'U':
    case 'V':
    case 'W':
    case 'X':
    case 'Y':
    case 'Z':
    case '_':
    case '.':
      starttoken();
      if (isIdent(lookahead1)) {
	curstate = identifier;
	return start;
      }
      curstate = start;
      return identifier;
    case '0':
      starttoken();
      if (lookahead1 == 'x') {
	curstate = hexstring;
	return start;
      }
      if (isDec(lookahead1)) {
	curstate = decstring;
	return start;
      }
      curstate = start;
      return decstring;
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      starttoken();
      if (isDec(lookahead1)) {
	curstate = decstring;
	return start;
      }
      curstate = start;
      return decstring;
    case '\n':
    case ' ':
    case '\t':
    case '\v':
    case '\r':
      return start;		// Ignore whitespace
    case '\0':
      curstate = endstream;
      return endstream;
    default:
      curstate = illegal;
      return illegal;
    }
    break;
  case special2:
    advancetoken();
    curstate = start;
    return identifier;
  case special3:
    advancetoken();
    curstate = special32;
    return start;
  case special32:
    advancetoken();
    curstate = start;
    return identifier;
  case comment:
    if (curchar == '\n')
      curstate = start;
    else if (curchar == '\0') {
      curstate = endstream;
      return endstream;
    }
    return start;
  case identifier:
    advancetoken();
    if (isIdent(lookahead1))
      return start;
    curstate = start;
    return identifier;
  case hexstring:
    advancetoken();
    if (isHex(lookahead1))
      return start;
    curstate = start;
    return hexstring;
  case decstring:
    advancetoken();
    if (isDec(lookahead1))
      return start;
    curstate = start;
    return decstring;
  default:
    curstate = endstream;
  }
  return endstream;
}

int4 PcodeLexer::getNextToken(void)

{ // Will return either: identifier, punctuation, hexstring, decstring, endstream, or illegal
  // If identifier, hexstring, or decstring,  curtoken will be filled with the characters
  int4 tok;
  do {
    curchar = lookahead1;
    lookahead1 = lookahead2;
    if (endofstream)
      lookahead2 = '\0';
    else {
      s->get(lookahead2);
      if (!(*s)) {
	endofstream = true;
	lookahead2 = '\0';
      }
    }
    tok = moveState();
  } while(tok == start);
  if (tok == identifier) {
    curtoken[tokpos] = '\0';	// Append null terminator
    curidentifier = curtoken;
    int4 num = findIdentifier(curidentifier);
    if (num < 0)			// Not a keyword
      return STRING;
    return idents[num].id;
  }
  else if ((tok == hexstring)||(tok == decstring)) {
    curtoken[tokpos] = '\0';
    istringstream s1(curtoken);
    s1.unsetf(ios::dec | ios::hex | ios::oct);
    s1 >> curnum;
    if (!s1)
      return BADINTEGER;
    return INTEGER;
  }
  else if (tok == endstream) {
    if (!endofstreamsent) {
      endofstreamsent = true;
      return ENDOFSTREAM;	// Send 'official' end of stream token
    }
    return 0;			// 0 means end of file to parser
  }
  else if (tok == illegal)
    return 0;
  return (int4)curchar;
}

void PcodeLexer::initialize(istream *t)

{ // Set up for new lex
  s = t;
  curstate = start;
  tokpos = 0;
  endofstream = false;
  endofstreamsent = false;
  lookahead1 = 0;
  lookahead2 = 0;
  s->get(lookahead1);		// Buffer the first two characters
  if (!(*s)) {
    endofstream = true;
    lookahead1 = 0;
    return;
  }
  s->get(lookahead2);
  if (!(*s)) {
    endofstream = true;
    lookahead2 = 0;
    return;
  }
}

uint4 PcodeSnippet::allocateTemp(void)

{ // Allocate a variable in the unique space and return the offset
  uint4 res = tempbase;
  tempbase += 16;
  return res;
}

void PcodeSnippet::addSymbol(SleighSymbol *sym)

{
  pair<SymbolTree::iterator,bool> res;

  res = tree.insert( sym );
  if (!res.second) {
    reportError((const Location *)0,"Duplicate symbol name: "+sym->getName());
    delete sym;		// Symbol is unattached to anything else
  }
}

void PcodeSnippet::clear(void)

{ // Clear everything, prepare for a new parse against the same language
  SymbolTree::iterator iter,tmpiter;
  iter = tree.begin();
  while(iter != tree.end()) {
    SleighSymbol *sym = *iter;
    tmpiter = iter;
    ++iter;			// Increment now, as node may be deleted
    if (sym->getType() != SleighSymbol::space_symbol) {
      delete sym;		// Free any old local symbols
      tree.erase(tmpiter);
    }
  }
  if (result != (ConstructTpl *)0) {
    delete result;
    result = (ConstructTpl *)0;
  }
  // tempbase = 0;
  errorcount = 0;
  firsterror.clear();
  resetLabelCount();
}

PcodeSnippet::PcodeSnippet(const SleighBase *slgh)
  : PcodeCompile()
{
  sleigh = slgh;
  tempbase = 0;
  errorcount = 0;
  result = (ConstructTpl *)0;
  setDefaultSpace(slgh->getDefaultCodeSpace());
  setConstantSpace(slgh->getConstantSpace());
  setUniqueSpace(slgh->getUniqueSpace());
  int4 num = slgh->numSpaces();
  for(int4 i=0;i<num;++i) {
    AddrSpace *spc = slgh->getSpace(i);
    spacetype type = spc->getType();
    if ((type==IPTR_CONSTANT)||(type==IPTR_PROCESSOR)||(type==IPTR_SPACEBASE)||(type==IPTR_INTERNAL))
      tree.insert(new SpaceSymbol(spc));
  }
  addSymbol(new FlowDestSymbol("inst_dest",slgh->getConstantSpace()));
  addSymbol(new FlowRefSymbol("inst_ref",slgh->getConstantSpace()));
}

PcodeSnippet::~PcodeSnippet(void)

{
  SymbolTree::iterator iter;
  for(iter=tree.begin();iter!=tree.end();++iter)
    delete *iter;		// Free ALL temporary symbols
  if (result != (ConstructTpl *)0) {
    delete result;
    result = (ConstructTpl *)0;
  }
}

void PcodeSnippet::reportError(const Location *loc, const string &msg)

{
  if (errorcount == 0)
    firsterror = msg;
  errorcount += 1;
}

int4 PcodeSnippet::lex(void)

{
  int4 tok = lexer.getNextToken();
  if (tok == STRING) {
    SleighSymbol *sym;
    SleighSymbol tmpsym(lexer.getIdentifier());
    SymbolTree::const_iterator iter = tree.find(&tmpsym);
    if (iter != tree.end())
      sym = *iter;		// Found a local symbol
    else
      sym = sleigh->findSymbol(lexer.getIdentifier());
    if (sym != (SleighSymbol *)0) {
      switch(sym->getType()) {
      case SleighSymbol::space_symbol:
	yylval.spacesym = (SpaceSymbol *)sym;
	return SPACESYM;
      case SleighSymbol::userop_symbol:
	yylval.useropsym = (UserOpSymbol *)sym;
	return USEROPSYM;
      case SleighSymbol::varnode_symbol:
	yylval.varsym = (VarnodeSymbol *)sym;
	return VARSYM;
      case SleighSymbol::operand_symbol:
	yylval.operandsym = (OperandSymbol *)sym;
	return OPERANDSYM;
      case SleighSymbol::start_symbol:
	yylval.startsym = (StartSymbol *)sym;
	return STARTSYM;
      case SleighSymbol::end_symbol:
	yylval.endsym = (EndSymbol *)sym;
	return ENDSYM;
	case SleighSymbol::next2_symbol:
	yylval.next2sym = (Next2Symbol *)sym;
	return NEXT2SYM;
      case SleighSymbol::label_symbol:
	yylval.labelsym = (LabelSymbol *)sym;
	return LABELSYM;
      case SleighSymbol::dummy_symbol:
	break;
      default:
	// The translator may have other symbols in it that we don't want visible in the snippet compiler
	break;
      }
    }
    yylval.str = new string(lexer.getIdentifier());
    return STRING;
  }
  if (tok == INTEGER) {
    yylval.i = new uintb(lexer.getNumber());
    return INTEGER;
  }
  return tok;
}

 bool PcodeSnippet::parseStream(istream &s)

{
  lexer.initialize(&s);
  pcode = this;			// Setup global object for yyparse
  int4 res = yyparse();
  if (res != 0) {
    reportError((const Location *)0,"Syntax error");
    return false;
  }
  if (!PcodeCompile::propagateSize(result)) {
    reportError((const Location *)0,"Could not resolve at least 1 variable size");
    return false;
  }
  return true;
}

void PcodeSnippet::addOperand(const string &name,int4 index)

{ // Add an operand symbol for this snippet
  OperandSymbol *sym = new OperandSymbol(name,index,(Constructor *)0);
  addSymbol(sym);
}

int pcodelex(void) {
  return pcode->lex();
}

int pcodeerror(const char *s)

{
  pcode->reportError((const Location *)0,s);
  return 0;
}

} // End namespace ghidra

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
#define YYSTYPE         XMLSTYPE
/* Substitute the variable and function names.  */
#define yyparse         xmlparse
#define yylex           xmllex
#define yyerror         xmlerror
#define yydebug         xmldebug
#define yynerrs         xmlnerrs
#define yylval          xmllval
#define yychar          xmlchar

/* First part of user prologue.  */

#include "xml.hh"
// CharData mode   look for '<' '&' or "]]>"
// Name mode       look for non-name char
// CData mode      looking for "]]>"
// Entity mode     looking for ending ';'
// AttValue mode   looking for endquote  or '&'
// Comment mode    looking for "--"

#include <iostream>
#include <string>

namespace ghidra {

string Attributes::bogus_uri("http://unused.uri");

/// \brief The XML character scanner
///
/// Tokenize a byte stream suitably for the main XML parser.  The scanner expects an ASCII or UTF-8
/// encoding.  Characters is XML tag and attribute names are restricted to ASCII "letters", but
/// extended UTF-8 characters can be used in any other character data: attribute values, content, comments. 
class XmlScan {
public:
  /// \brief Modes of the scanner
  enum mode { CharDataMode, CDataMode, AttValueSingleMode,
	      AttValueDoubleMode, CommentMode, CharRefMode,
	      NameMode, SNameMode, SingleMode };
  /// \brief Additional tokens returned by the scanner, in addition to byte values 00-ff
  enum token { CharDataToken = 258,
	       CDataToken = 259,
	       AttValueToken = 260,
	       CommentToken =261,
	       CharRefToken = 262,
	       NameToken = 263,
	       SNameToken = 264,
	       ElementBraceToken = 265,
	       CommandBraceToken = 266 };
private:
  mode curmode;			///< The current scanning mode
  istream &s;			///< The stream being scanned
  string *lvalue;		///< Current string being built
  int4 lookahead[4];	///< Lookahead into the byte stream
  int4 pos;				///< Current position in the lookahead buffer
  bool endofstream;		///< Has end of stream been reached
  void clearlvalue(void);	///< Clear the current token string

  /// \brief Get the next byte in the stream
  ///
  /// Maintain a lookahead of 4 bytes at all times so that we can check for special
  /// XML character sequences without consuming.
  /// \return the next byte value as an integer
  int4 getxmlchar(void) {
    char c;	    
    int4 ret=lookahead[pos];
    if (!endofstream) {
      s.get(c); 
      if (s.eof()||(c=='\0')) {
	endofstream = true;
	lookahead[pos] = '\n';
      }
      else
	lookahead[pos] = c;
    }
    else
      lookahead[pos] = -1;
    pos = (pos+1)&3;
    return ret;
  }
  int4 next(int4 i) { return lookahead[(pos+i)&3]; }	///< Peek at the next (i-th) byte without consuming
  bool isLetter(int4 val) { return (((val>=0x41)&&(val<=0x5a))||((val>=0x61)&&(val<=0x7a))); }	///< Is the given byte a \e letter
  bool isInitialNameChar(int4 val);		///< Is the given byte/character the valid start of an XML name
  bool isNameChar(int4 val);			///< Is the given byte/character valid for an XML name	
  bool isChar(int4 val);				///< Is the given byte/character valid as an XML character
  int4 scanSingle(void);				///< Scan for the next token in Single Character mode
  int4 scanCharData(void);				///< Scan for the next token is Character Data mode
  int4 scanCData(void);					///< Scan for the next token in CDATA mode
  int4 scanAttValue(int4 quote);		///< Scan for the next token in Attribute Value mode
  int4 scanCharRef(void);				///< Scan for the next token in Character Reference mode
  int4 scanComment(void);				///< Scan for the next token in Comment mode
  int4 scanName(void);					///< Scan a Name or return single non-name character
  int4 scanSName(void);					///< Scan Name, allow white space before
public:
  XmlScan(istream &t);					///< Construct scanner given a stream
  ~XmlScan(void);						///< Destructor
  void setmode(mode m) { curmode = m; }	///< Set the scanning mode
  int4 nexttoken(void);					///< Get the next token
  string *lval(void) { string *ret = lvalue; lvalue = (string *)0; return ret; }	///< Return the last \e lvalue string
};

/// \brief A parsed name/value pair
struct NameValue {
  string *name;		///< The name
  string *value;	///< The value
};

extern int xmllex(void);				///< Interface to the scanner
extern int xmlerror(const char *str);			///< Interface for registering an error in parsing
extern void print_content(const string &str);	///< Send character data to the ContentHandler
extern int4 convertEntityRef(const string &ref);	///< Convert an XML entity to its equivalent character
extern int4 convertCharRef(const string &ref);	///< Convert an XML character reference to its equivalent character
static XmlScan *global_scan;					///< Global reference to the scanner
static ContentHandler *handler;					///< Global reference to the content handler



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


/* Debug traces.  */
#ifndef XMLDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define XMLDEBUG 1
#  else
#   define XMLDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define XMLDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined XMLDEBUG */
#if XMLDEBUG
extern int xmldebug;
#endif

/* Token kinds.  */
#ifndef XMLTOKENTYPE
# define XMLTOKENTYPE
  enum xmltokentype
  {
    XMLEMPTY = -2,
    XMLEOF = 0,                    /* "end of file"  */
    XMLerror = 256,                /* error  */
    XMLUNDEF = 257,                /* "invalid token"  */
    CHARDATA = 258,                /* CHARDATA  */
    CDATA = 259,                   /* CDATA  */
    ATTVALUE = 260,                /* ATTVALUE  */
    COMMENT = 261,                 /* COMMENT  */
    CHARREF = 262,                 /* CHARREF  */
    NAME = 263,                    /* NAME  */
    SNAME = 264,                   /* SNAME  */
    ELEMBRACE = 265,               /* ELEMBRACE  */
    COMMBRACE = 266                /* COMMBRACE  */
  };
  typedef enum xmltokentype xmltoken_kind_t;
#endif

/* Value type.  */
#if ! defined XMLSTYPE && ! defined XMLSTYPE_IS_DECLARED
union XMLSTYPE
{

  int4 i;
  string *str;
  Attributes *attr;
  NameValue *pair;


};
typedef union XMLSTYPE XMLSTYPE;
# define XMLSTYPE_IS_TRIVIAL 1
# define XMLSTYPE_IS_DECLARED 1
#endif


extern XMLSTYPE xmllval;


int xmlparse (void);



/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_CHARDATA = 3,                   /* CHARDATA  */
  YYSYMBOL_CDATA = 4,                      /* CDATA  */
  YYSYMBOL_ATTVALUE = 5,                   /* ATTVALUE  */
  YYSYMBOL_COMMENT = 6,                    /* COMMENT  */
  YYSYMBOL_CHARREF = 7,                    /* CHARREF  */
  YYSYMBOL_NAME = 8,                       /* NAME  */
  YYSYMBOL_SNAME = 9,                      /* SNAME  */
  YYSYMBOL_ELEMBRACE = 10,                 /* ELEMBRACE  */
  YYSYMBOL_COMMBRACE = 11,                 /* COMMBRACE  */
  YYSYMBOL_12_ = 12,                       /* ' '  */
  YYSYMBOL_13_n_ = 13,                     /* '\n'  */
  YYSYMBOL_14_r_ = 14,                     /* '\r'  */
  YYSYMBOL_15_t_ = 15,                     /* '\t'  */
  YYSYMBOL_16_ = 16,                       /* '\''  */
  YYSYMBOL_17_ = 17,                       /* '"'  */
  YYSYMBOL_18_ = 18,                       /* '!'  */
  YYSYMBOL_19_ = 19,                       /* '-'  */
  YYSYMBOL_20_ = 20,                       /* '>'  */
  YYSYMBOL_21_ = 21,                       /* '?'  */
  YYSYMBOL_22_ = 22,                       /* '['  */
  YYSYMBOL_23_C_ = 23,                     /* 'C'  */
  YYSYMBOL_24_D_ = 24,                     /* 'D'  */
  YYSYMBOL_25_A_ = 25,                     /* 'A'  */
  YYSYMBOL_26_T_ = 26,                     /* 'T'  */
  YYSYMBOL_27_ = 27,                       /* ']'  */
  YYSYMBOL_28_O_ = 28,                     /* 'O'  */
  YYSYMBOL_29_Y_ = 29,                     /* 'Y'  */
  YYSYMBOL_30_P_ = 30,                     /* 'P'  */
  YYSYMBOL_31_E_ = 31,                     /* 'E'  */
  YYSYMBOL_32_ = 32,                       /* '='  */
  YYSYMBOL_33_v_ = 33,                     /* 'v'  */
  YYSYMBOL_34_e_ = 34,                     /* 'e'  */
  YYSYMBOL_35_r_ = 35,                     /* 'r'  */
  YYSYMBOL_36_s_ = 36,                     /* 's'  */
  YYSYMBOL_37_i_ = 37,                     /* 'i'  */
  YYSYMBOL_38_o_ = 38,                     /* 'o'  */
  YYSYMBOL_39_n_ = 39,                     /* 'n'  */
  YYSYMBOL_40_c_ = 40,                     /* 'c'  */
  YYSYMBOL_41_d_ = 41,                     /* 'd'  */
  YYSYMBOL_42_g_ = 42,                     /* 'g'  */
  YYSYMBOL_43_x_ = 43,                     /* 'x'  */
  YYSYMBOL_44_m_ = 44,                     /* 'm'  */
  YYSYMBOL_45_l_ = 45,                     /* 'l'  */
  YYSYMBOL_46_ = 46,                       /* '/'  */
  YYSYMBOL_47_ = 47,                       /* '&'  */
  YYSYMBOL_48_ = 48,                       /* '#'  */
  YYSYMBOL_49_ = 49,                       /* ';'  */
  YYSYMBOL_YYACCEPT = 50,                  /* $accept  */
  YYSYMBOL_document = 51,                  /* document  */
  YYSYMBOL_whitespace = 52,                /* whitespace  */
  YYSYMBOL_S = 53,                         /* S  */
  YYSYMBOL_attsinglemid = 54,              /* attsinglemid  */
  YYSYMBOL_attdoublemid = 55,              /* attdoublemid  */
  YYSYMBOL_AttValue = 56,                  /* AttValue  */
  YYSYMBOL_elemstart = 57,                 /* elemstart  */
  YYSYMBOL_commentstart = 58,              /* commentstart  */
  YYSYMBOL_Comment = 59,                   /* Comment  */
  YYSYMBOL_PI = 60,                        /* PI  */
  YYSYMBOL_CDSect = 61,                    /* CDSect  */
  YYSYMBOL_CDStart = 62,                   /* CDStart  */
  YYSYMBOL_CDEnd = 63,                     /* CDEnd  */
  YYSYMBOL_doctypepro = 64,                /* doctypepro  */
  YYSYMBOL_prologpre = 65,                 /* prologpre  */
  YYSYMBOL_prolog = 66,                    /* prolog  */
  YYSYMBOL_doctypedecl = 67,               /* doctypedecl  */
  YYSYMBOL_Eq = 68,                        /* Eq  */
  YYSYMBOL_Misc = 69,                      /* Misc  */
  YYSYMBOL_VersionInfo = 70,               /* VersionInfo  */
  YYSYMBOL_EncodingDecl = 71,              /* EncodingDecl  */
  YYSYMBOL_xmldeclstart = 72,              /* xmldeclstart  */
  YYSYMBOL_XMLDecl = 73,                   /* XMLDecl  */
  YYSYMBOL_element = 74,                   /* element  */
  YYSYMBOL_STag = 75,                      /* STag  */
  YYSYMBOL_EmptyElemTag = 76,              /* EmptyElemTag  */
  YYSYMBOL_stagstart = 77,                 /* stagstart  */
  YYSYMBOL_SAttribute = 78,                /* SAttribute  */
  YYSYMBOL_etagbrace = 79,                 /* etagbrace  */
  YYSYMBOL_ETag = 80,                      /* ETag  */
  YYSYMBOL_content = 81,                   /* content  */
  YYSYMBOL_Reference = 82,                 /* Reference  */
  YYSYMBOL_refstart = 83,                  /* refstart  */
  YYSYMBOL_charrefstart = 84,              /* charrefstart  */
  YYSYMBOL_CharRef = 85,                   /* CharRef  */
  YYSYMBOL_EntityRef = 86                  /* EntityRef  */
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
typedef yytype_uint8 yy_state_t;

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
         || (defined XMLSTYPE_IS_TRIVIAL && XMLSTYPE_IS_TRIVIAL)))

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
#define YYFINAL  25
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   205

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  50
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  37
/* YYNRULES -- Number of rules.  */
#define YYNRULES  70
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  151

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   266


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,    15,
      13,     2,     2,    14,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,    12,    18,    17,    48,     2,     2,    47,    16,
       2,     2,     2,     2,     2,    19,     2,    46,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    49,
       2,    32,    20,    21,     2,    25,     2,    23,    24,    31,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    28,
      30,     2,     2,     2,    26,     2,     2,     2,     2,    29,
       2,    22,     2,    27,     2,     2,     2,     2,     2,    40,
      41,    34,     2,    42,     2,    37,     2,     2,    45,    44,
      39,    38,     2,     2,    35,    36,     2,     2,    33,     2,
      43,     2,     2,     2,     2,     2,     2,     2,     2,     2,
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
       5,     6,     7,     8,     9,    10,    11
};

#if XMLDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint8 yyrline[] =
{
       0,   141,   141,   142,   143,   144,   145,   146,   147,   148,
     150,   151,   152,   153,   154,   155,   156,   157,   158,   159,
     160,   161,   162,   163,   164,   166,   167,   168,   169,   170,
     171,   172,   174,   175,   176,   177,   178,   179,   180,   182,
     183,   184,   185,   186,   187,   188,   190,   191,   193,   194,
     195,   196,   198,   199,   200,   201,   202,   203,   205,   206,
     207,   208,   209,   210,   211,   213,   214,   216,   217,   218,
     219
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if XMLDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "CHARDATA", "CDATA",
  "ATTVALUE", "COMMENT", "CHARREF", "NAME", "SNAME", "ELEMBRACE",
  "COMMBRACE", "' '", "'\\n'", "'\\r'", "'\\t'", "'\\''", "'\"'", "'!'",
  "'-'", "'>'", "'?'", "'['", "'C'", "'D'", "'A'", "'T'", "']'", "'O'",
  "'Y'", "'P'", "'E'", "'='", "'v'", "'e'", "'r'", "'s'", "'i'", "'o'",
  "'n'", "'c'", "'d'", "'g'", "'x'", "'m'", "'l'", "'/'", "'&'", "'#'",
  "';'", "$accept", "document", "whitespace", "S", "attsinglemid",
  "attdoublemid", "AttValue", "elemstart", "commentstart", "Comment", "PI",
  "CDSect", "CDStart", "CDEnd", "doctypepro", "prologpre", "prolog",
  "doctypedecl", "Eq", "Misc", "VersionInfo", "EncodingDecl",
  "xmldeclstart", "XMLDecl", "element", "STag", "EmptyElemTag",
  "stagstart", "SAttribute", "etagbrace", "ETag", "content", "Reference",
  "refstart", "charrefstart", "CharRef", "EntityRef", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-136)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     132,  -136,    42,  -136,  -136,  -136,  -136,    22,  -136,   125,
       9,    20,  -136,  -136,   143,    28,  -136,    79,  -136,   148,
    -136,  -136,    16,    18,     6,  -136,  -136,  -136,    32,    65,
     148,  -136,  -136,   148,    38,    40,    93,    91,  -136,    -1,
      63,  -136,    39,    27,  -136,    45,    26,    52,   -12,  -136,
    -136,  -136,  -136,    69,    57,    77,   104,  -136,    -3,  -136,
    -136,  -136,  -136,    94,  -136,    95,  -136,  -136,    -4,   103,
    -136,  -136,  -136,    67,   136,  -136,  -136,   106,  -136,    68,
     109,    87,  -136,    90,  -136,   144,     2,  -136,   138,   108,
     117,  -136,   118,  -136,  -136,  -136,   125,    -2,     3,  -136,
    -136,   125,  -136,   145,   131,  -136,   147,   146,  -136,  -136,
     121,  -136,  -136,  -136,  -136,  -136,  -136,  -136,  -136,    54,
    -136,   149,   130,   150,   152,  -136,   142,   151,   140,   153,
    -136,   154,   155,   156,   157,   158,   159,   137,   161,   160,
    -136,    63,   162,   163,   136,  -136,   164,  -136,    63,   136,
    -136
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,    18,     0,     4,     5,     6,     7,     0,     8,    38,
       0,     0,    36,    37,    31,     0,    28,     0,    27,     0,
      58,    46,     0,     0,    21,     1,     9,    52,     0,     0,
      30,    25,    29,     0,     0,     0,     0,     0,     2,     0,
       0,    48,     0,     0,    53,     0,     0,     0,     0,    21,
      26,     3,    42,     0,     0,     0,     0,    59,     0,    67,
      64,    63,    62,     0,    60,     0,    47,    61,     0,     0,
      66,    65,    33,     0,     0,    50,    49,     0,    19,     0,
       0,     0,    43,     0,    44,     0,     0,    55,     0,     0,
       0,    68,     0,    34,    10,    13,    35,     0,     0,    54,
      51,     0,    20,     0,     0,    45,     0,     0,    22,    56,
       0,    70,    69,    11,    16,    12,    14,    17,    15,     0,
      41,     0,     0,     0,     0,    57,     0,     0,     0,     0,
      24,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      32,     0,     0,     0,     0,    23,     0,    40,     0,     0,
      39
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -136,  -136,    -8,   -17,  -136,  -136,  -133,  -136,  -136,   165,
     166,  -136,  -136,  -136,  -136,  -136,  -136,  -136,  -135,    71,
    -136,  -136,  -136,  -136,    17,  -136,  -136,  -136,  -136,  -136,
    -136,  -136,   -64,  -136,  -136,  -136,  -136
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     7,     8,     9,    97,    98,    99,    10,    11,    12,
      13,    62,    63,   108,    30,    14,    15,    31,    74,    16,
     120,    36,    17,    18,    19,    20,    21,    22,    44,    65,
      66,    39,    67,    68,    69,    70,    71
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      35,    26,    57,   113,    90,    43,   144,    45,   116,     1,
      58,   147,    81,   149,   114,    86,   150,    27,    49,    56,
     117,    45,    25,    73,   106,    40,    28,    26,     3,     4,
       5,     6,    33,   115,   118,    26,    41,    45,     1,     3,
       4,     5,     6,    87,    91,    59,    59,    76,    26,    46,
      59,    47,     3,     4,     5,     6,    64,    96,    52,    75,
      23,    53,    42,    24,    78,    26,     3,     4,     5,     6,
      79,    80,   110,    77,    54,     3,     4,     5,     6,     3,
       4,     5,     6,    48,   119,    32,    49,   126,    26,    82,
      38,     3,     4,     5,     6,    72,    83,    84,    88,    93,
      34,    50,    26,    89,    51,     3,     4,     5,     6,    23,
      92,    26,    49,   101,    55,   103,     3,     4,     5,     6,
       3,     4,     5,     6,    73,    85,   100,    96,   109,   102,
     104,    73,    96,     3,     4,     5,     6,     3,     4,     5,
       6,   125,     1,     2,     3,     4,     5,     6,     3,     4,
       5,     6,    94,    95,    29,     3,     4,     5,     6,    37,
       3,     4,     5,     6,   105,   107,   111,   112,   121,   122,
     123,   128,   130,   124,   129,   127,   131,   133,   134,   141,
     132,     0,     0,   138,   145,   136,   142,     0,     0,   135,
     140,     0,     0,     0,   139,   137,     0,   143,     0,     0,
       0,   146,     0,   148,    60,    61
};

static const yytype_int16 yycheck[] =
{
      17,     9,     3,     5,     8,    22,   141,    19,     5,    10,
      11,   144,    24,   148,    16,    18,   149,     8,    21,    36,
      17,    19,     0,    40,    22,     9,     6,    35,    12,    13,
      14,    15,    15,    97,    98,    43,    20,    19,    10,    12,
      13,    14,    15,    46,    48,    47,    47,    20,    56,    43,
      47,    19,    12,    13,    14,    15,    39,    74,    20,    20,
      18,    21,    46,    21,    19,    73,    12,    13,    14,    15,
      44,    19,    89,    46,    34,    12,    13,    14,    15,    12,
      13,    14,    15,    18,   101,    14,    21,    33,    96,    20,
      19,    12,    13,    14,    15,    32,    39,    20,     4,    32,
      21,    30,   110,     8,    33,    12,    13,    14,    15,    18,
       7,   119,    21,    45,    21,    28,    12,    13,    14,    15,
      12,    13,    14,    15,   141,    21,    20,   144,    20,    20,
      40,   148,   149,    12,    13,    14,    15,    12,    13,    14,
      15,    20,    10,    11,    12,    13,    14,    15,    12,    13,
      14,    15,    16,    17,    11,    12,    13,    14,    15,    11,
      12,    13,    14,    15,    20,    27,    49,    49,    23,    38,
      23,    41,    20,    27,    24,    26,    34,    37,    25,    42,
      29,    -1,    -1,    26,    22,    30,    25,    -1,    -1,    35,
      31,    -1,    -1,    -1,    36,    39,    -1,    37,    -1,    -1,
      -1,    38,    -1,    39,    39,    39
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    10,    11,    12,    13,    14,    15,    51,    52,    53,
      57,    58,    59,    60,    65,    66,    69,    72,    73,    74,
      75,    76,    77,    18,    21,     0,    52,     8,     6,    11,
      64,    67,    69,    74,    21,    53,    71,    11,    69,    81,
       9,    20,    46,    53,    78,    19,    43,    19,    18,    21,
      69,    69,    20,    21,    34,    21,    53,     3,    11,    47,
      59,    60,    61,    62,    74,    79,    80,    82,    83,    84,
      85,    86,    32,    53,    68,    20,    20,    46,    19,    44,
      19,    24,    20,    39,    20,    21,    18,    46,     4,     8,
       8,    48,     7,    32,    16,    17,    53,    54,    55,    56,
      20,    45,    20,    28,    40,    20,    22,    27,    63,    20,
      53,    49,    49,     5,    16,    82,     5,    17,    82,    53,
      70,    23,    38,    23,    27,    20,    33,    26,    41,    24,
      20,    34,    29,    37,    25,    35,    30,    39,    26,    36,
      31,    42,    25,    37,    68,    22,    38,    56,    39,    68,
      56
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    50,    51,    51,    52,    52,    52,    52,    53,    53,
      54,    54,    54,    55,    55,    55,    56,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    64,    65,    65,    65,
      66,    66,    67,    68,    68,    68,    69,    69,    69,    70,
      71,    72,    73,    73,    73,    73,    74,    74,    75,    75,
      76,    76,    77,    77,    78,    79,    80,    80,    81,    81,
      81,    81,    81,    81,    81,    82,    82,    83,    84,    85,
      86
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     3,     1,     1,     1,     1,     1,     2,
       1,     2,     2,     1,     2,     2,     2,     2,     1,     4,
       5,     2,     3,     9,     3,     1,     2,     1,     1,     2,
       2,     1,     9,     1,     2,     2,     1,     1,     1,    10,
      11,     6,     3,     4,     4,     5,     1,     3,     2,     3,
       3,     4,     2,     2,     3,     2,     3,     4,     0,     2,
       2,     2,     2,     2,     2,     1,     1,     1,     2,     3,
       3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = XMLEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == XMLEMPTY)                                        \
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
   Use XMLerror or XMLUNDEF. */
#define YYERRCODE XMLUNDEF


/* Enable debugging if requested.  */
#if XMLDEBUG

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
#else /* !XMLDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !XMLDEBUG */


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
  switch (yykind)
    {
    case YYSYMBOL_CHARDATA: /* CHARDATA  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_CDATA: /* CDATA  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_ATTVALUE: /* ATTVALUE  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_COMMENT: /* COMMENT  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_CHARREF: /* CHARREF  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_NAME: /* NAME  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_SNAME: /* SNAME  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_ELEMBRACE: /* ELEMBRACE  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_COMMBRACE: /* COMMBRACE  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_attsinglemid: /* attsinglemid  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_attdoublemid: /* attdoublemid  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_AttValue: /* AttValue  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_CDSect: /* CDSect  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_STag: /* STag  */
            { delete ((*yyvaluep).attr); }
        break;

    case YYSYMBOL_EmptyElemTag: /* EmptyElemTag  */
            { delete ((*yyvaluep).attr); }
        break;

    case YYSYMBOL_stagstart: /* stagstart  */
            { delete ((*yyvaluep).attr); }
        break;

    case YYSYMBOL_SAttribute: /* SAttribute  */
            { delete ((*yyvaluep).pair); }
        break;

    case YYSYMBOL_ETag: /* ETag  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_Reference: /* Reference  */
            { }
        break;

    case YYSYMBOL_CharRef: /* CharRef  */
            { delete ((*yyvaluep).str); }
        break;

    case YYSYMBOL_EntityRef: /* EntityRef  */
            { delete ((*yyvaluep).str); }
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

  yychar = XMLEMPTY; /* Cause a token to be read.  */

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
  if (yychar == XMLEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= XMLEOF)
    {
      yychar = XMLEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == XMLerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = XMLUNDEF;
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
  yychar = XMLEMPTY;
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
  case 10: /* attsinglemid: '\''  */
                   { (yyval.str) = new string; global_scan->setmode(XmlScan::AttValueSingleMode); }
    break;

  case 11: /* attsinglemid: attsinglemid ATTVALUE  */
                                      { (yyval.str) = (yyvsp[-1].str); *(yyval.str) += *(yyvsp[0].str); delete (yyvsp[0].str); global_scan->setmode(XmlScan::AttValueSingleMode); }
    break;

  case 12: /* attsinglemid: attsinglemid Reference  */
                                       { (yyval.str) = (yyvsp[-1].str); *(yyval.str) += (yyvsp[0].i); global_scan->setmode(XmlScan::AttValueSingleMode); }
    break;

  case 13: /* attdoublemid: '"'  */
                  { (yyval.str) = new string; global_scan->setmode(XmlScan::AttValueDoubleMode); }
    break;

  case 14: /* attdoublemid: attdoublemid ATTVALUE  */
                                      { (yyval.str) = (yyvsp[-1].str); *(yyval.str) += *(yyvsp[0].str); delete (yyvsp[0].str); global_scan->setmode(XmlScan::AttValueDoubleMode); }
    break;

  case 15: /* attdoublemid: attdoublemid Reference  */
                                       { (yyval.str) = (yyvsp[-1].str); *(yyval.str) += (yyvsp[0].i); global_scan->setmode(XmlScan::AttValueDoubleMode); }
    break;

  case 16: /* AttValue: attsinglemid '\''  */
                            { (yyval.str) = (yyvsp[-1].str); }
    break;

  case 17: /* AttValue: attdoublemid '"'  */
                             { (yyval.str) = (yyvsp[-1].str); }
    break;

  case 18: /* elemstart: ELEMBRACE  */
                     { global_scan->setmode(XmlScan::NameMode); delete (yyvsp[0].str); }
    break;

  case 19: /* commentstart: COMMBRACE '!' '-' '-'  */
                                    { global_scan->setmode(XmlScan::CommentMode); delete (yyvsp[-3].str); }
    break;

  case 20: /* Comment: commentstart COMMENT '-' '-' '>'  */
                                          { delete (yyvsp[-3].str); }
    break;

  case 21: /* PI: COMMBRACE '?'  */
                  { delete (yyvsp[-1].str); yyerror("Processing instructions are not supported"); YYERROR; }
    break;

  case 22: /* CDSect: CDStart CDATA CDEnd  */
                            { (yyval.str) = (yyvsp[-1].str); }
    break;

  case 23: /* CDStart: COMMBRACE '!' '[' 'C' 'D' 'A' 'T' 'A' '['  */
                                                   { global_scan->setmode(XmlScan::CDataMode); delete (yyvsp[-8].str); }
    break;

  case 32: /* doctypedecl: COMMBRACE '!' 'D' 'O' 'C' 'T' 'Y' 'P' 'E'  */
                                                       { delete (yyvsp[-8].str); yyerror("DTD's not supported"); YYERROR; }
    break;

  case 39: /* VersionInfo: S 'v' 'e' 'r' 's' 'i' 'o' 'n' Eq AttValue  */
                                                       { handler->setVersion(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 40: /* EncodingDecl: S 'e' 'n' 'c' 'o' 'd' 'i' 'n' 'g' Eq AttValue  */
                                                            { handler->setEncoding(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 46: /* element: EmptyElemTag  */
                      { handler->endElement((yyvsp[0].attr)->getelemURI(),(yyvsp[0].attr)->getelemName(),(yyvsp[0].attr)->getelemName()); delete (yyvsp[0].attr); }
    break;

  case 47: /* element: STag content ETag  */
                             { handler->endElement((yyvsp[-2].attr)->getelemURI(),(yyvsp[-2].attr)->getelemName(),(yyvsp[-2].attr)->getelemName()); delete (yyvsp[-2].attr); delete (yyvsp[0].str); }
    break;

  case 48: /* STag: stagstart '>'  */
                    { handler->startElement((yyvsp[-1].attr)->getelemURI(),(yyvsp[-1].attr)->getelemName(),(yyvsp[-1].attr)->getelemName(),*(yyvsp[-1].attr)); (yyval.attr) = (yyvsp[-1].attr); }
    break;

  case 49: /* STag: stagstart S '>'  */
                        { handler->startElement((yyvsp[-2].attr)->getelemURI(),(yyvsp[-2].attr)->getelemName(),(yyvsp[-2].attr)->getelemName(),*(yyvsp[-2].attr)); (yyval.attr) = (yyvsp[-2].attr); }
    break;

  case 50: /* EmptyElemTag: stagstart '/' '>'  */
                                { handler->startElement((yyvsp[-2].attr)->getelemURI(),(yyvsp[-2].attr)->getelemName(),(yyvsp[-2].attr)->getelemName(),*(yyvsp[-2].attr)); (yyval.attr) = (yyvsp[-2].attr); }
    break;

  case 51: /* EmptyElemTag: stagstart S '/' '>'  */
                                    { handler->startElement((yyvsp[-3].attr)->getelemURI(),(yyvsp[-3].attr)->getelemName(),(yyvsp[-3].attr)->getelemName(),*(yyvsp[-3].attr)); (yyval.attr) = (yyvsp[-3].attr); }
    break;

  case 52: /* stagstart: elemstart NAME  */
                          { (yyval.attr) = new Attributes((yyvsp[0].str)); global_scan->setmode(XmlScan::SNameMode); }
    break;

  case 53: /* stagstart: stagstart SAttribute  */
                                  { (yyval.attr) = (yyvsp[-1].attr); (yyval.attr)->add_attribute( (yyvsp[0].pair)->name, (yyvsp[0].pair)->value); delete (yyvsp[0].pair); global_scan->setmode(XmlScan::SNameMode); }
    break;

  case 54: /* SAttribute: SNAME Eq AttValue  */
                              { (yyval.pair) = new NameValue; (yyval.pair)->name = (yyvsp[-2].str); (yyval.pair)->value = (yyvsp[0].str); }
    break;

  case 55: /* etagbrace: COMMBRACE '/'  */
                         { global_scan->setmode(XmlScan::NameMode); delete (yyvsp[-1].str); }
    break;

  case 56: /* ETag: etagbrace NAME '>'  */
                         { (yyval.str) = (yyvsp[-1].str); }
    break;

  case 57: /* ETag: etagbrace NAME S '>'  */
                             { (yyval.str) = (yyvsp[-2].str); }
    break;

  case 58: /* content: %empty  */
         { global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 59: /* content: content CHARDATA  */
                            { print_content( *(yyvsp[0].str) ); delete (yyvsp[0].str); global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 60: /* content: content element  */
                           { global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 61: /* content: content Reference  */
                             { string *tmp=new string(); *tmp += (yyvsp[0].i); print_content(*tmp); delete tmp; global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 62: /* content: content CDSect  */
                          { print_content( *(yyvsp[0].str) ); delete (yyvsp[0].str); global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 63: /* content: content PI  */
                      { global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 64: /* content: content Comment  */
                           { global_scan->setmode(XmlScan::CharDataMode); }
    break;

  case 65: /* Reference: EntityRef  */
                     { (yyval.i) = convertEntityRef(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 66: /* Reference: CharRef  */
                     { (yyval.i) = convertCharRef(*(yyvsp[0].str)); delete (yyvsp[0].str); }
    break;

  case 67: /* refstart: '&'  */
              { global_scan->setmode(XmlScan::NameMode); }
    break;

  case 68: /* charrefstart: refstart '#'  */
                           { global_scan->setmode(XmlScan::CharRefMode); }
    break;

  case 69: /* CharRef: charrefstart CHARREF ';'  */
                                  { (yyval.str) = (yyvsp[-1].str); }
    break;

  case 70: /* EntityRef: refstart NAME ';'  */
                             { (yyval.str) = (yyvsp[-1].str); }
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
  yytoken = yychar == XMLEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
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

      if (yychar <= XMLEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == XMLEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = XMLEMPTY;
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
  if (yychar != XMLEMPTY)
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



XmlScan::XmlScan(istream &t) : s(t)

{
  curmode = SingleMode;
  lvalue = (string *)0;
  pos = 0;
  endofstream = false;
  getxmlchar(); getxmlchar(); getxmlchar(); getxmlchar(); // Fill lookahead buffer
}

XmlScan::~XmlScan(void)

{
  clearlvalue();
}

void XmlScan::clearlvalue(void)

{
  if (lvalue != (string *)0)
    delete lvalue;
}

int4 XmlScan::scanSingle(void)

{
  int4 res = getxmlchar();
  if (res == '<') {
    if (isInitialNameChar(next(0))) return ElementBraceToken;
    return CommandBraceToken;
  }
  return res;
}

int4 XmlScan::scanCharData(void)

{
  clearlvalue();
  lvalue = new string();
  
  while(next(0) != -1) {		// look for '<' '&' or ']]>'
    if (next(0) == '<') break;
    if (next(0) == '&') break;
    if (next(0) == ']')
      if (next(1)== ']')
	if (next(2)=='>')
	  break;
    *lvalue += getxmlchar();
  }
  if (lvalue->size()==0)
    return scanSingle();
  return CharDataToken;
}

int4 XmlScan::scanCData(void)

{
  clearlvalue();
  lvalue = new string();

  while(next(0) != -1) {	// Look for "]]>" and non-Char
    if (next(0)==']')
      if (next(1)==']')
	if (next(2)=='>')
	  break;
    if (!isChar(next(0))) break;
    *lvalue += getxmlchar();
  }
  return CDataToken;		// CData can be empty
}

int4 XmlScan::scanCharRef(void)

{
  int4 v;
  clearlvalue();
  lvalue = new string();
  if (next(0) == 'x') {
    *lvalue += getxmlchar();
    while(next(0) != -1) {
      v = next(0);
      if (v < '0') break;
      if ((v>'9')&&(v<'A')) break;
      if ((v>'F')&&(v<'a')) break;
      if (v>'f') break;
      *lvalue += getxmlchar();
    }
    if (lvalue->size()==1)
      return 'x';		// Must be at least 1 hex digit
  }
  else {
    while(next(0) != -1) {
      v = next(0);
      if (v<'0') break;
      if (v>'9') break;
      *lvalue += getxmlchar();
    }
    if (lvalue->size()==0)
      return scanSingle();
  }
  return CharRefToken;
}

int4 XmlScan::scanAttValue(int4 quote)

{
  clearlvalue();
  lvalue = new string();
  while(next(0) != -1) {
    if (next(0) == quote) break;
    if (next(0) == '<') break;
    if (next(0) == '&') break;
    *lvalue += getxmlchar();
  }
  if (lvalue->size() == 0)
    return scanSingle();
  return AttValueToken;
}

int4 XmlScan::scanComment(void)

{
  clearlvalue();
  lvalue = new string();

  while(next(0) != -1) {
    if (next(0)=='-')
      if (next(1)=='-')
	break;
    if (!isChar(next(0))) break;
    *lvalue += getxmlchar();
  }
  return CommentToken;
}

int4 XmlScan::scanName(void)

{
  clearlvalue();
  lvalue = new string();

  if (!isInitialNameChar(next(0)))
    return scanSingle();
  *lvalue += getxmlchar();
  while(next(0) != -1) {
    if (!isNameChar(next(0))) break;
    *lvalue += getxmlchar();
  }
  return NameToken;
}

int4 XmlScan::scanSName(void)

{
  int4 whitecount = 0;
  while((next(0)==' ')||(next(0)=='\n')||(next(0)=='\r')||(next(0)=='\t')) {
    whitecount += 1;
    getxmlchar();
  }
  clearlvalue();
  lvalue = new string();
  if (!isInitialNameChar(next(0))) {	// First non-whitespace is not Name char
    if (whitecount > 0)
      return ' ';
    return scanSingle();
  }
  *lvalue += getxmlchar();
  while(next(0) != -1) {
    if (!isNameChar(next(0))) break;
    *lvalue += getxmlchar();
  }
  if (whitecount>0)
    return SNameToken;
  return NameToken;
}

bool XmlScan::isInitialNameChar(int4 val)

{
  if (isLetter(val)) return true;
  if ((val=='_')||(val==':')) return true;
  return false;
}

bool XmlScan::isNameChar(int4 val)

{
  if (isLetter(val)) return true;
  if ((val>='0')&&(val<='9')) return true;
  if ((val=='.')||(val=='-')||(val=='_')||(val==':')) return true;
  return false;
}

bool XmlScan::isChar(int4 val)

{
  if (val>=0x20) return true;
  if ((val == 0xd)||(val==0xa)||(val==0x9)) return true;
  return false;
}

int4 XmlScan::nexttoken(void)

{
  mode mymode = curmode;
  curmode = SingleMode;
  switch(mymode) {
  case CharDataMode:
    return scanCharData();
  case CDataMode:
    return scanCData();
  case AttValueSingleMode:
    return scanAttValue('\'');
  case AttValueDoubleMode:
    return scanAttValue('"');
  case CommentMode:
    return scanComment();
  case CharRefMode:
    return scanCharRef();
  case NameMode:
    return scanName();
  case SNameMode:
    return scanSName();
  case SingleMode:
    return scanSingle();
  }
  return -1;
}

void print_content(const string &str)

{
  uint4 i;
  for(i=0;i<str.size();++i) {
    if (str[i]==' ') continue;
    if (str[i]=='\n') continue;
    if (str[i]=='\r') continue;
    if (str[i]=='\t') continue;
    break;
  }
  if (i==str.size())
    handler->ignorableWhitespace(str.c_str(),0,str.size());
  else
    handler->characters(str.c_str(),0,str.size());  
}

int4 convertEntityRef(const string &ref)

{
  if (ref == "lt") return '<';
  if (ref == "amp") return '&';
  if (ref == "gt") return '>';
  if (ref == "quot") return '"';
  if (ref == "apos") return '\'';
  return -1;
}

int4 convertCharRef(const string &ref)

{
  uint4 i;
  int4 mult,val,cur;

  if (ref[0]=='x') {
    i = 1;
    mult = 16;
  }
  else {
    i = 0;
    mult = 10;
  }
  val = 0;
  for(;i<ref.size();++i) {
    if (ref[i]<='9') cur = ref[i]-'0';
    else if (ref[i]<='F') cur = 10+ref[i]-'A';
    else cur=10+ref[i]-'a';
    val *= mult;
    val += cur;
  }
  return val;
}

int xmllex(void)

{
  int res = global_scan->nexttoken();
  if (res>255)
    yylval.str = global_scan->lval();
  return res;
}

int xmlerror(const char *str)

{
  handler->setError(str);
  return 0;
}

int4 xml_parse(istream &i,ContentHandler *hand,int4 dbg)

{
#if YYDEBUG
  yydebug = dbg;
#endif
  global_scan = new XmlScan(i);
  handler = hand;
  handler->startDocument();
  int4 res = yyparse();
  if (res == 0)
    handler->endDocument();
  delete global_scan;
  return res;
}

void TreeHandler::startElement(const string &namespaceURI,const string &localName,
			       const string &qualifiedName,const Attributes &atts)
{
  Element *newel = new Element(cur);
  cur->addChild(newel);
  cur = newel;
  newel->setName(localName);
  for(int4 i=0;i<atts.getLength();++i)
    newel->addAttribute(atts.getLocalName(i),atts.getValue(i));
}

void TreeHandler::endElement(const string &namespaceURI,const string &localName,
			     const string &qualifiedName)
{
  cur = cur->getParent();
}

void TreeHandler::characters(const char *text,int4 start,int4 length)

{
  cur->addContent(text,start,length);
}

Element::~Element(void)

{
  List::iterator iter;
  
  for(iter=children.begin();iter!=children.end();++iter)
    delete *iter;
}

const string &Element::getAttributeValue(const string &nm) const

{
  for(uint4 i=0;i<attr.size();++i)
    if (attr[i] == nm)
      return value[i];
  throw DecoderError("Unknown attribute: "+nm);
}

DocumentStorage::~DocumentStorage(void)

{
  for(int4 i=0;i<doclist.size();++i) {
    if (doclist[i] != (Document *)0)
      delete doclist[i];
  }
}

Document *DocumentStorage::parseDocument(istream &s)

{
  doclist.push_back((Document *)0);
  doclist.back() = xml_tree(s);
  return doclist.back();
}

Document *DocumentStorage::openDocument(const string &filename)

{
  ifstream s(filename.c_str());
  if (!s)
    throw DecoderError("Unable to open xml document "+filename);
  Document *res = parseDocument(s);
  s.close();
  return res;
}

void DocumentStorage::registerTag(const Element *el)

{
  tagmap[el->getName()] = el;
}

const Element *DocumentStorage::getTag(const string &nm) const

{
  map<string,const Element *>::const_iterator iter;

  iter = tagmap.find(nm);
  if (iter != tagmap.end())
    return (*iter).second;
  return (const Element *)0;
}

Document *xml_tree(istream &i)

{
  Document *doc = new Document();
  TreeHandler handle(doc);
  if (0!=xml_parse(i,&handle)) {
    delete doc;
    throw DecoderError(handle.getError());
  }
  return doc;
}

void xml_escape(ostream &s,const char *str)

{
  while(*str!='\0') {
    if (*str < '?') {
      if (*str=='<') s << "&lt;";
      else if (*str=='>') s << "&gt;";
      else if (*str=='&') s << "&amp;";
      else if (*str=='"') s << "&quot;";
      else if (*str=='\'') s << "&apos;";
      else s << *str;
    }
    else
      s << *str;
    str++;
  }
}

} // End namespace ghidra

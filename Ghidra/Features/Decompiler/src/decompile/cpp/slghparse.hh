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

/* Bison interface for Yacc-like parsers in C

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

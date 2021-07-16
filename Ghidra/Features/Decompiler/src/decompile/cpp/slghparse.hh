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
#line 29 "src/decompile/cpp/slghparse.y" /* yacc.c:1909  */

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

#line 214 "src/decompile/cpp/slghparse.hh" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_SRC_DECOMPILE_CPP_SLGHPARSE_HH_INCLUDED  */

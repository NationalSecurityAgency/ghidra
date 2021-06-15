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
    MACROSYM = 366,
    LABELSYM = 367,
    SUBTABLESYM = 368
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

#line 212 "src/decompile/cpp/slghparse.hh" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_SRC_DECOMPILE_CPP_SLGHPARSE_HH_INCLUDED  */

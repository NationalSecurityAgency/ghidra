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
%{
#ifdef CPUI_RULECOMPILE
#include "rulecompile.hh"

#define YYERROR_VERBOSE

extern RuleCompile *rulecompile;
extern int ruleparselex(void);
extern int ruleparseerror(const char *str);

%}

%union {
  char ch;
  string *str;
  int8 *big;
  int4 id;
  OpCode opcode;
  vector<OpCode> *opcodelist;
  ConstraintGroup *group;
  RHSConstant *rhsconst;
}

%token RIGHT_ARROW LEFT_ARROW DOUBLE_RIGHT_ARROW DOUBLE_LEFT_ARROW
%left OP_BOOL_OR
%left OP_BOOL_AND OP_BOOL_XOR
%left OP_INT_OR
%left OP_INT_XOR
%left OP_INT_AND
%left OP_INT_EQUAL OP_INT_NOTEQUAL OP_FLOAT_EQUAL OP_FLOAT_NOTEQUAL
%nonassoc OP_INT_LESS OP_INT_LESSEQUAL OP_INT_SLESS OP_INT_SLESSEQUAL OP_FLOAT_LESS OP_FLOAT_LESSEQUAL 
%left OP_INT_LEFT OP_INT_RIGHT OP_INT_SRIGHT
%left OP_INT_ADD OP_INT_SUB OP_FLOAT_ADD OP_FLOAT_SUB
%left OP_INT_SDIV OP_INT_SREM OP_FLOAT_MULT OP_FLOAT_DIV OP_INT_MULT OP_INT_DIV OP_INT_REM 
%right OP_BOOL_NEGATE OP_INT_NEGATE
%token OP_INT_ZEXT OP_INT_CARRY
%token OP_INT_BORROW OP_INT_SEXT OP_INT_SCARRY OP_INT_SBORROW OP_FLOAT_NAN
%token OP_FLOAT_ABS OP_FLOAT_SQRT OP_FLOAT_CEIL OP_FLOAT_FLOOR OP_FLOAT_ROUND
%token OP_FLOAT_INT2FLOAT OP_FLOAT_FLOAT2FLOAT
%token OP_FLOAT_TRUNC OP_BRANCH OP_BRANCHIND OP_CALL OP_CALLIND OP_RETURN
%token OP_CBRANCH OP_CALLOTHER OP_LOAD OP_STORE OP_PIECE OP_SUBPIECE OP_COPY
%token BADINTEGER BEFORE_KEYWORD AFTER_KEYWORD REMOVE_KEYWORD SET_KEYWORD ACTION_TICK
%token ISTRUE_KEYWORD ISFALSE_KEYWORD


%token <ch> CHAR
%token <big> INTB
%token <str> OP_IDENTIFIER VAR_IDENTIFIER CONST_IDENTIFIER OP_NEW_IDENTIFIER VAR_NEW_IDENTIFIER
%token <str> DOT_IDENTIFIER

%type <id> op_ident var_ident const_ident op_new_ident var_new_ident
%type <big> number
%type <opcode> op_any
%type <opcodelist> op_list
%type <rhsconst> rhs_const var_size
%type <group> opnode varnode deadnode statement statementlist orgroupmid actionlist action
%type <group> opnewnode varnewnode deadnewnode megaormid

%%

fullrule: 
'{' statementlist actionlist '}' { rulecompile->setFullRule( rulecompile->mergeGroups($2,$3) ); }
| '{' statementlist '[' megaormid ']' '}' { $2->addConstraint( $4 ); rulecompile->setFullRule( $2 ); }
;

megaormid: statementlist actionlist { $$ = rulecompile->emptyOrGroup(); rulecompile->addOr($$,rulecompile->mergeGroups($1,$2)); }
| megaormid OP_INT_OR statementlist actionlist { $$ = rulecompile->addOr($1,rulecompile->mergeGroups($3,$4)); }
;

actionlist: ACTION_TICK { $$ = rulecompile->emptyGroup(); }
| actionlist action { $$ = rulecompile->mergeGroups($1,$2); }
;

statementlist: { $$ = rulecompile->emptyGroup(); }
| statementlist statement { $$ = rulecompile->mergeGroups($1,$2); }
;

action: opnewnode ';' { $$ = $1; }
| varnewnode ';' { $$ = $1; }
| deadnewnode ';' { $$ = $1; }
;

orgroupmid: statementlist { ConstraintGroup *newbase = rulecompile->emptyOrGroup(); $$ = rulecompile->addOr(newbase,$1); }
| orgroupmid OP_INT_OR statementlist { $$ = rulecompile->addOr($1,$3); }
;

statement: opnode ';' { $$ = $1; }
| varnode ';' { $$ = $1; }
| deadnode ';' { $$ = $1; }
| '[' orgroupmid ']' { $$ = rulecompile->emptyGroup(); $$->addConstraint($2); }
| '(' statementlist ')' { $$ = $2; }
;

opnode: op_ident { $$ = rulecompile->newOp($1); }
| opnode '(' op_list ')' { $$ = rulecompile->opCodeConstraint($1,$3); }
| varnode LEFT_ARROW op_ident { $$ = rulecompile->varDef($1,$3); }
| varnode RIGHT_ARROW op_ident { $$ = rulecompile->varDescend($1,$3); }
| varnode RIGHT_ARROW OP_BOOL_NEGATE op_ident { $$ = rulecompile->varUniqueDescend($1,$4); }
| opnode '(' OP_INT_EQUAL op_ident ')' { $$ = rulecompile->opCompareConstraint($1,$4,CPUI_INT_EQUAL); }
| opnode '(' OP_INT_NOTEQUAL op_ident ')' { $$ = rulecompile->opCompareConstraint($1,$4,CPUI_INT_NOTEQUAL); }
;

varnode: var_ident { $$ = rulecompile->newVarnode($1); }
| opnode LEFT_ARROW '(' INTB ')' var_ident { $$ = rulecompile->opInput($1,$4,$6); }
| opnode LEFT_ARROW var_ident { $$ = rulecompile->opInputAny($1,$3); }
| opnode RIGHT_ARROW var_ident { $$ = rulecompile->opOutput($1,$3); }
| varnode '(' OP_INT_EQUAL var_ident ')' { $$ = rulecompile->varCompareConstraint($1,$4,CPUI_INT_EQUAL); }
| varnode '(' OP_INT_NOTEQUAL var_ident ')' { $$ = rulecompile->varCompareConstraint($1,$4,CPUI_INT_NOTEQUAL); }
;

deadnode: opnode LEFT_ARROW '(' INTB ')' rhs_const { $$ = rulecompile->opInputConstVal($1,$4,$6); }
| opnode  '=' op_ident  { $$ = rulecompile->opCopy($1,$3); }
| varnode '=' var_ident { $$ = rulecompile->varCopy($1,$3); }
| varnode '=' rhs_const var_size { $$ = rulecompile->varConst($1,$3,$4); }
| const_ident '=' rhs_const { $$ = rulecompile->constNamedExpression($1,$3); }
| ISTRUE_KEYWORD '(' rhs_const ')' { $$ = rulecompile->booleanConstraint(true,$3); }
| ISFALSE_KEYWORD '(' rhs_const ')' { $$ = rulecompile->booleanConstraint(false,$3); }
;

opnewnode: op_new_ident '(' op_any BEFORE_KEYWORD op_ident ')' { $$ = rulecompile->opCreation($1,$3,false,$5); }
| op_new_ident '(' op_any AFTER_KEYWORD op_ident ')' { $$ = rulecompile->opCreation($1,$3,true,$5); }
| op_new_ident '(' op_any BEFORE_KEYWORD op_new_ident ')' { $$ = rulecompile->opCreation($1,$3,false,$5); }
| op_new_ident '(' op_any AFTER_KEYWORD op_new_ident ')' { $$ = rulecompile->opCreation($1,$3,true,$5); }
| op_ident { $$ = rulecompile->newOp($1); }
| opnewnode '(' SET_KEYWORD op_any ')' { $$ = rulecompile->newSetOpcode($1,$4); }
;

varnewnode: opnewnode DOUBLE_RIGHT_ARROW var_new_ident '(' INTB ')' { $$ = rulecompile->newUniqueOut($1,$3,-((int4)*$5)); delete $5; }
| opnewnode DOUBLE_RIGHT_ARROW var_new_ident '(' var_ident ')' { $$ = rulecompile->newUniqueOut($1,$3,$5); }
| opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' var_ident { $$ = rulecompile->newSetInput($1,$4,$6); }
| opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' var_new_ident { $$ = rulecompile->newSetInput($1,$4,$6); }
;

deadnewnode: opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' rhs_const var_size { $$ = rulecompile->newSetInputConstVal($1,$4,$6,$7); }
| opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' REMOVE_KEYWORD { $$ = rulecompile->removeInput($$,$4); }
;

rhs_const: number { $$ = rulecompile->constAbsolute($1); }
| '(' rhs_const ')' { $$ = $2; }
| const_ident { $$ = rulecompile->constNamed($1); }
| var_ident DOT_IDENTIFIER { $$ = rulecompile->dotIdentifier($1,$2); }
| rhs_const OP_INT_ADD rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_ADD,$3); }
| rhs_const OP_INT_SUB rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_SUB,$3); }
| rhs_const OP_INT_AND rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_AND,$3); }
| rhs_const OP_INT_OR rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_OR,$3); }
| rhs_const OP_INT_XOR rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_XOR,$3); }
| rhs_const OP_INT_MULT rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_MULT,$3); }
| rhs_const OP_INT_DIV rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_DIV,$3); }
| rhs_const OP_INT_EQUAL rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_EQUAL,$3); }
| rhs_const OP_INT_NOTEQUAL rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_NOTEQUAL,$3); }
| rhs_const OP_INT_LESS rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_LESS,$3); }
| rhs_const OP_INT_LESSEQUAL rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_LESSEQUAL,$3); }
| rhs_const OP_INT_SLESS rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_SLESS,$3); }
| rhs_const OP_INT_SLESSEQUAL rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_SLESSEQUAL,$3); }
| rhs_const OP_INT_LEFT rhs_const { $$ = rulecompile->constBinaryExpression($1,CPUI_INT_LEFT,$3); }
| rhs_const OP_INT_RIGHT rhs_const{ $$ = rulecompile->constBinaryExpression($1,CPUI_INT_RIGHT,$3); }
| rhs_const OP_INT_SRIGHT rhs_const{ $$ = rulecompile->constBinaryExpression($1,CPUI_INT_SRIGHT,$3); }
;

var_size: /* empty */ { $$ = (RHSConstant *)0; }
| ':' rhs_const { $$ = $2; }
;

number: INTB { $$ = $1; }
| OP_INT_SUB INTB { *$2 = -*$2; $$ = $2; }
;

op_any: OP_BOOL_OR             { $$ = CPUI_BOOL_OR; }
  | OP_BOOL_AND            { $$ = CPUI_BOOL_AND; }
  | OP_BOOL_XOR            { $$ = CPUI_BOOL_XOR; }
  | OP_BOOL_NEGATE         { $$ = CPUI_BOOL_NEGATE; }
  | OP_INT_NEGATE          { $$ = CPUI_INT_NEGATE; }
  | OP_INT_ADD             { $$ = CPUI_INT_ADD; }
  | OP_INT_SUB             { $$ = CPUI_INT_SUB; }
  | OP_INT_AND             { $$ = CPUI_INT_AND; }
  | OP_INT_OR              { $$ = CPUI_INT_OR; }
  | OP_INT_XOR             { $$ = CPUI_INT_XOR; }
  | OP_INT_MULT            { $$ = CPUI_INT_MULT; }
  | OP_INT_DIV             { $$ = CPUI_INT_DIV; }
  | OP_INT_REM             { $$ = CPUI_INT_REM; }
  | OP_INT_RIGHT           { $$ = CPUI_INT_RIGHT; }
  | OP_INT_LEFT            { $$ = CPUI_INT_LEFT; }
  | OP_INT_EQUAL           { $$ = CPUI_INT_EQUAL; }
  | OP_INT_NOTEQUAL        { $$ = CPUI_INT_NOTEQUAL; }
  | OP_INT_LESS            { $$ = CPUI_INT_LESS; }
  | OP_INT_LESSEQUAL       { $$ = CPUI_INT_LESSEQUAL; }
  | OP_INT_SDIV            { $$ = CPUI_INT_SDIV; }
  | OP_INT_SREM            { $$ = CPUI_INT_SREM; }
  | OP_INT_SRIGHT          { $$ = CPUI_INT_SRIGHT; }
  | OP_INT_SLESS           { $$ = CPUI_INT_SLESS; }
  | OP_INT_SLESSEQUAL      { $$ = CPUI_INT_SLESSEQUAL; }
  | OP_INT_ZEXT            { $$ = CPUI_INT_ZEXT; }
  | OP_INT_CARRY           { $$ = CPUI_INT_CARRY; }
  | OP_INT_SEXT            { $$ = CPUI_INT_SEXT; }
  | OP_INT_SCARRY          { $$ = CPUI_INT_SCARRY; }
  | OP_INT_SBORROW         { $$ = CPUI_INT_SBORROW; }
  | OP_FLOAT_ADD           { $$ = CPUI_FLOAT_ADD; }
  | OP_FLOAT_SUB           { $$ = CPUI_FLOAT_SUB; }
  | OP_FLOAT_MULT          { $$ = CPUI_FLOAT_MULT; }
  | OP_FLOAT_DIV           { $$ = CPUI_FLOAT_DIV; }
  | OP_FLOAT_EQUAL         { $$ = CPUI_FLOAT_EQUAL; }
  | OP_FLOAT_NOTEQUAL      { $$ = CPUI_FLOAT_NOTEQUAL; }
  | OP_FLOAT_LESS          { $$ = CPUI_FLOAT_LESS; }
  | OP_FLOAT_LESSEQUAL     { $$ = CPUI_FLOAT_LESSEQUAL; }
  | OP_FLOAT_NAN           { $$ = CPUI_FLOAT_NAN; }
  | OP_FLOAT_ABS           { $$ = CPUI_FLOAT_ABS; }
  | OP_FLOAT_SQRT          { $$ = CPUI_FLOAT_SQRT; }
  | OP_FLOAT_CEIL          { $$ = CPUI_FLOAT_CEIL; }
  | OP_FLOAT_FLOOR         { $$ = CPUI_FLOAT_FLOOR; }
  | OP_FLOAT_ROUND         { $$ = CPUI_FLOAT_ROUND; }
  | OP_FLOAT_INT2FLOAT     { $$ = CPUI_FLOAT_INT2FLOAT; }
  | OP_FLOAT_FLOAT2FLOAT   { $$ = CPUI_FLOAT_FLOAT2FLOAT; }
  | OP_FLOAT_TRUNC         { $$ = CPUI_FLOAT_TRUNC; }
  | OP_BRANCH              { $$ = CPUI_BRANCH; }
  | OP_BRANCHIND           { $$ = CPUI_BRANCHIND; }
  | OP_CALL                { $$ = CPUI_CALL; }
  | OP_CALLIND             { $$ = CPUI_CALLIND; }
  | OP_RETURN              { $$ = CPUI_RETURN; }
  | OP_CBRANCH             { $$ = CPUI_CBRANCH; }
  | OP_CALLOTHER           { $$ = CPUI_CALLOTHER; }
  | OP_LOAD                { $$ = CPUI_LOAD; }
  | OP_STORE               { $$ = CPUI_STORE; }
  | OP_PIECE               { $$ = CPUI_PIECE; }
  | OP_SUBPIECE            { $$ = CPUI_SUBPIECE; }
  | OP_COPY                { $$ = CPUI_COPY; }
;

op_list: op_any { $$ = new vector<OpCode>; $$->push_back($1); }
| op_list op_any { $$ = $1; $$->push_back($2); }
;

op_ident: OP_IDENTIFIER { $$ = rulecompile->findIdentifier($1); }
;

var_ident: VAR_IDENTIFIER { $$ = rulecompile->findIdentifier($1); }
;

const_ident: CONST_IDENTIFIER { $$ = rulecompile->findIdentifier($1); }
;

op_new_ident: OP_NEW_IDENTIFIER { $$ = rulecompile->findIdentifier($1); }
;

var_new_ident: VAR_NEW_IDENTIFIER { $$ = rulecompile->findIdentifier($1); }
;

%%

inline int ruleparselex(void)

{
  return rulecompile->nextToken();
}

int ruleparseerror(const char *s)

{
  rulecompile->ruleError(s);
  return 0;
}

#endif

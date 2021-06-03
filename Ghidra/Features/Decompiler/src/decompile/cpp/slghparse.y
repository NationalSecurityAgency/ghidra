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
#include "slgh_compile.hh"

#define YYERROR_VERBOSE

  extern SleighCompile *slgh;
  extern int4 actionon;
  extern FILE *yyin;
  extern int yydebug;
  extern int yylex(void);
  extern int yyerror(const char *str );
%}

%union {
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
}

%expect 5
// Conflicts
// 2 charstring conflicts          (do we lump CHARs together before appending to constructprint)
//     resolved by shifting which lumps before appending (best solution)
// 1 integervarnode ':' conflict   (does ':' apply to INTEGER or varnode)
//     resolved by shifting which applies ':' to INTEGER (best solution)
// 2 statement -> STRING . conflicts (STRING might be mislabelled varnode, or temporary declaration)
//     resolved by shifting which means assume this is a temporary declaration

%left OP_BOOL_OR
%left OP_BOOL_AND OP_BOOL_XOR
%left '|' OP_OR
%left ';'
%left '^' OP_XOR
%left '&' OP_AND
%left OP_EQUAL OP_NOTEQUAL OP_FEQUAL OP_FNOTEQUAL
%nonassoc '<' '>' OP_GREATEQUAL OP_LESSEQUAL OP_SLESS OP_SGREATEQUAL OP_SLESSEQUAL OP_SGREAT OP_FLESS OP_FGREAT OP_FLESSEQUAL OP_FGREATEQUAL
%left OP_LEFT OP_RIGHT OP_SRIGHT
%left '+' '-' OP_FADD OP_FSUB
%left '*' '/' '%' OP_SDIV OP_SREM OP_FMULT OP_FDIV
%right '!' '~'
%token OP_ZEXT OP_CARRY OP_BORROW OP_SEXT OP_SCARRY OP_SBORROW OP_NAN OP_ABS
%token OP_SQRT OP_CEIL OP_FLOOR OP_ROUND OP_INT2FLOAT OP_FLOAT2FLOAT
%token OP_TRUNC OP_CPOOLREF OP_NEW OP_POPCOUNT

%token BADINTEGER GOTO_KEY CALL_KEY RETURN_KEY IF_KEY
%token DEFINE_KEY ATTACH_KEY MACRO_KEY SPACE_KEY TYPE_KEY RAM_KEY DEFAULT_KEY
%token REGISTER_KEY ENDIAN_KEY WITH_KEY ALIGN_KEY OP_UNIMPL
%token TOKEN_KEY SIGNED_KEY NOFLOW_KEY HEX_KEY DEC_KEY BIG_KEY LITTLE_KEY
%token SIZE_KEY WORDSIZE_KEY OFFSET_KEY NAMES_KEY VALUES_KEY VARIABLES_KEY PCODEOP_KEY IS_KEY LOCAL_KEY
%token DELAYSLOT_KEY CROSSBUILD_KEY EXPORT_KEY BUILD_KEY CONTEXT_KEY ELLIPSIS_KEY GLOBALSET_KEY BITRANGE_KEY

%token <ch> CHAR
%token <i> INTEGER
%token <big> INTB
%token <str> STRING SYMBOLSTRING
%token <spacesym> SPACESYM
%token <sectionsym> SECTIONSYM
%token <tokensym> TOKENSYM
%token <useropsym> USEROPSYM
%token <valuesym> VALUESYM
%token <valuemapsym> VALUEMAPSYM
%token <contextsym> CONTEXTSYM
%token <namesym> NAMESYM
%token <varsym> VARSYM
%token <bitsym> BITSYM
%token <specsym> SPECSYM
%token <varlistsym> VARLISTSYM
%token <operandsym> OPERANDSYM
%token <startsym> STARTSYM
%token <endsym> ENDSYM
%token <macrosym> MACROSYM
%token <labelsym> LABELSYM
%token <subtablesym> SUBTABLESYM

%type <macrosym> macrostart
%type <param> paramlist
%type <sem> rtl rtlmid
%type <sectionstart> rtlbody rtlfirstsection rtlcontinue
%type <stmt> statement
%type <tree> expr
%type <varnode> varnode integervarnode exportvarnode lhsvarnode jumpdest
%type <labelsym> label
%type <pateq> pequation bitpat_or_nil elleq ellrt atomic constraint
%type <patexp> pexpression
%type <str> charstring
%type <construct> constructprint subtablestart
%type <sectionsym> section_def
%type <varsym> contextprop
%type <tokensym> tokenprop
%type <spacequal> spaceprop
%type <fieldqual> fielddef contextfielddef
%type <starqual> sizedstar
%type <strlist> stringlist stringpart anystringlist anystringpart oplist
%type <biglist> intblist intbpart
%type <symlist> valuelist valuepart varlist varpart
%type <contop> contextlist contextblock
%type <anysym> anysymbol
%type <famsym> familysymbol
%type <specsym> specificsymbol
%type <subtablesym> id_or_nil

%%
spec: endiandef
  | spec aligndef
  | spec definition
  | spec constructorlike
  ;
definition: tokendef
  | contextdef
  | spacedef
  | varnodedef
  | bitrangedef
  | pcodeopdef
  | valueattach
  | nameattach
  | varattach
  | error ';'
  ;
constructorlike: constructor
  | macrodef
  | withblock
  | error '}'                          { slgh->resetConstructors(); }
  ;
endiandef: DEFINE_KEY ENDIAN_KEY '=' BIG_KEY ';' { slgh->setEndian(1); }
  | DEFINE_KEY ENDIAN_KEY '=' LITTLE_KEY ';' { slgh->setEndian(0); }
  ;
aligndef: DEFINE_KEY ALIGN_KEY '=' INTEGER ';' { slgh->setAlignment(*$4); delete $4; }
  ;
tokendef: tokenprop ';'                {}
  ;
tokenprop: DEFINE_KEY TOKEN_KEY STRING '(' INTEGER ')' { $$ = slgh->defineToken($3,$5,0); }
  | DEFINE_KEY TOKEN_KEY STRING '(' INTEGER ')' ENDIAN_KEY '=' LITTLE_KEY { $$ = slgh->defineToken($3,$5,-1); }
  | DEFINE_KEY TOKEN_KEY STRING '(' INTEGER ')' ENDIAN_KEY '=' BIG_KEY { $$ = slgh->defineToken($3,$5,1); }
  | tokenprop fielddef		       { $$ = $1; slgh->addTokenField($1,$2); }
  | DEFINE_KEY TOKEN_KEY anysymbol     { string errmsg=$3->getName()+": redefined as a token"; yyerror(errmsg.c_str()); YYERROR; }
  ;
contextdef: contextprop ';'            {}
  ;
contextprop: DEFINE_KEY CONTEXT_KEY VARSYM { $$ = $3; }
  | contextprop contextfielddef		 { $$ = $1; if (!slgh->addContextField( $1, $2 ))
                                            { yyerror("All context definitions must come before constructors"); YYERROR; } }
  ;
fielddef: STRING '=' '(' INTEGER ',' INTEGER ')' { $$ = new FieldQuality($1,$4,$6); }
  | anysymbol '=' '(' INTEGER ',' INTEGER ')' { delete $4; delete $6; string errmsg = $1->getName()+": redefined as field"; yyerror(errmsg.c_str()); YYERROR; }
  | fielddef SIGNED_KEY			{ $$ = $1; $$->signext = true; }
  | fielddef HEX_KEY			{ $$ = $1; $$->hex = true; }
  | fielddef DEC_KEY			{ $$ = $1; $$->hex = false; }
  ;
contextfielddef: STRING '=' '(' INTEGER ',' INTEGER ')' { $$ = new FieldQuality($1,$4,$6); }
  | anysymbol '=' '(' INTEGER ',' INTEGER ')' { delete $4; delete $6; string errmsg = $1->getName()+": redefined as field"; yyerror(errmsg.c_str()); YYERROR; }
  | contextfielddef SIGNED_KEY			{ $$ = $1; $$->signext = true; }
  | contextfielddef NOFLOW_KEY			{ $$ = $1; $$->flow = false; }
  | contextfielddef HEX_KEY			{ $$ = $1; $$->hex = true; }
  | contextfielddef DEC_KEY			{ $$ = $1; $$->hex = false; }
  ;
spacedef: spaceprop ';'			{ slgh->newSpace($1); }
  ;
spaceprop: DEFINE_KEY SPACE_KEY STRING	{ $$ = new SpaceQuality(*$3); delete $3; }
  | DEFINE_KEY SPACE_KEY anysymbol	{ string errmsg = $3->getName()+": redefined as space"; yyerror(errmsg.c_str()); YYERROR; }
  | spaceprop TYPE_KEY '=' RAM_KEY	{ $$ = $1; $$->type = SpaceQuality::ramtype; }
  | spaceprop TYPE_KEY '=' REGISTER_KEY { $$ = $1; $$->type = SpaceQuality::registertype; }
  | spaceprop SIZE_KEY '=' INTEGER	{ $$ = $1; $$->size = *$4; delete $4; }
  | spaceprop WORDSIZE_KEY '=' INTEGER	{ $$ = $1; $$->wordsize = *$4; delete $4; }
  | spaceprop DEFAULT_KEY               { $$ = $1; $$->isdefault = true; }
  ;
varnodedef: DEFINE_KEY SPACESYM OFFSET_KEY '=' INTEGER SIZE_KEY '=' INTEGER stringlist ';' {
               slgh->defineVarnodes($2,$5,$8,$9); }
  | DEFINE_KEY SPACESYM OFFSET_KEY '=' BADINTEGER { yyerror("Parsed integer is too big (overflow)"); YYERROR; }
  ;
bitrangedef: DEFINE_KEY BITRANGE_KEY bitrangelist ';'
  ;
bitrangelist: bitrangesingle
  | bitrangelist bitrangesingle
  ;
bitrangesingle: STRING '=' VARSYM '[' INTEGER ',' INTEGER ']' {
               slgh->defineBitrange($1,$3,(uint4)*$5,(uint4)*$7); delete $5; delete $7; }
  ;
pcodeopdef: DEFINE_KEY PCODEOP_KEY stringlist ';' { slgh->addUserOp($3); }
  ;
valueattach: ATTACH_KEY VALUES_KEY valuelist intblist ';' { slgh->attachValues($3,$4); }
  ;
nameattach: ATTACH_KEY NAMES_KEY valuelist anystringlist ';' { slgh->attachNames($3,$4); }
  ;
varattach: ATTACH_KEY VARIABLES_KEY valuelist varlist ';' { slgh->attachVarnodes($3,$4); }
  ;
macrodef: macrostart '{' rtl '}'	{ slgh->buildMacro($1,$3); }
  ;

withblockstart: WITH_KEY id_or_nil ':' bitpat_or_nil contextblock '{'  {  slgh->pushWith($2,$4,$5); }
  ;
withblockmid: withblockstart
  | withblockmid definition
  | withblockmid constructorlike
  ;
withblock: withblockmid '}'  { slgh->popWith(); }
  
id_or_nil: /* empty */  { $$ = (SubtableSymbol *)0; }
  | SUBTABLESYM         { $$ = $1; }
  | STRING              { $$ = slgh->newTable($1); }
  ;

bitpat_or_nil: /* empty */ { $$ = (PatternEquation *)0; }
  | pequation              { $$ = $1; }
  ;

macrostart: MACRO_KEY STRING '(' oplist ')' { $$ = slgh->createMacro($2,$4); }
  ;
rtlbody: '{' rtl '}' { $$ = slgh->standaloneSection($2); }
  | '{' rtlcontinue rtlmid '}' { $$ = slgh->finalNamedSection($2,$3); }
  | OP_UNIMPL        { $$ = (SectionVector *)0; }
  ;
constructor: constructprint IS_KEY pequation contextblock rtlbody { slgh->buildConstructor($1,$3,$4,$5); }
  | subtablestart IS_KEY pequation contextblock rtlbody           { slgh->buildConstructor($1,$3,$4,$5); }
  ;
constructprint: subtablestart STRING	{ $$ = $1; $$->addSyntax(*$2); delete $2; }
  | subtablestart charstring		{ $$ = $1; $$->addSyntax(*$2); delete $2; }
  | subtablestart SYMBOLSTRING		{ $$ = $1; if (slgh->isInRoot($1)) { $$->addSyntax(*$2); delete $2; } else slgh->newOperand($1,$2); }
  | subtablestart '^'				{ $$ = $1; if (!slgh->isInRoot($1)) { yyerror("Unexpected '^' at start of print pieces");  YYERROR; } }
  | constructprint '^'				{ $$ = $1; }
  | constructprint STRING			{ $$ = $1; $$->addSyntax(*$2); delete $2; }
  | constructprint charstring		{ $$ = $1; $$->addSyntax(*$2); delete $2; }
  | constructprint ' '				{ $$ = $1; $$->addSyntax(string(" ")); }
  | constructprint SYMBOLSTRING		{ $$ = $1; slgh->newOperand($1,$2); }
  ;
subtablestart: SUBTABLESYM ':'	{ $$ = slgh->createConstructor($1); }
  | STRING ':'					{ SubtableSymbol *sym=slgh->newTable($1); $$ = slgh->createConstructor(sym); }
  | ':'							{ $$ = slgh->createConstructor((SubtableSymbol *)0); }
  | subtablestart ' '			{ $$ = $1; }
  ;
pexpression: INTB			{ $$ = new ConstantValue(*$1); delete $1; }
// familysymbol is not acceptable in an action expression because it isn't attached to an offset
  | familysymbol			{ if ((actionon==1)&&($1->getType() != SleighSymbol::context_symbol))
                                             { string errmsg="Global symbol "+$1->getName(); errmsg += " is not allowed in action expression"; yyerror(errmsg.c_str()); } $$ = $1->getPatternValue(); }
//  | CONTEXTSYM                          { $$ = $1->getPatternValue(); }
  | specificsymbol			{ $$ = $1->getPatternExpression(); }
  | '(' pexpression ')'			{ $$ = $2; }
  | pexpression '+' pexpression		{ $$ = new PlusExpression($1,$3); }
  | pexpression '-' pexpression		{ $$ = new SubExpression($1,$3); }
  | pexpression '*' pexpression		{ $$ = new MultExpression($1,$3); }
  | pexpression OP_LEFT pexpression	{ $$ = new LeftShiftExpression($1,$3); }
  | pexpression OP_RIGHT pexpression	{ $$ = new RightShiftExpression($1,$3); }
  | pexpression OP_AND pexpression	{ $$ = new AndExpression($1,$3); }
  | pexpression OP_OR pexpression	{ $$ = new OrExpression($1,$3); }
  | pexpression OP_XOR pexpression	{ $$ = new XorExpression($1,$3); }
  | pexpression '/' pexpression		{ $$ = new DivExpression($1,$3); }
  | '-' pexpression %prec '!'		{ $$ = new MinusExpression($2); }
  | '~' pexpression			{ $$ = new NotExpression($2); }
  ;
pequation: elleq
  | pequation '&' pequation		{ $$ = new EquationAnd($1,$3); }
  | pequation '|' pequation		{ $$ = new EquationOr($1,$3); }
  | pequation ';' pequation		{ $$ = new EquationCat($1,$3); }
  ;
elleq: ELLIPSIS_KEY ellrt		{ $$ = new EquationLeftEllipsis($2); }
  | ellrt
  ;
ellrt: atomic ELLIPSIS_KEY		{ $$ = new EquationRightEllipsis($1); }
  | atomic
  ;
atomic: constraint
  | '(' pequation ')'			{ $$ = $2; }
  ;
constraint: familysymbol '=' pexpression { $$ = new EqualEquation($1->getPatternValue(),$3); }
  | familysymbol OP_NOTEQUAL pexpression { $$ = new NotEqualEquation($1->getPatternValue(),$3); }
  | familysymbol '<' pexpression	{ $$ = new LessEquation($1->getPatternValue(),$3); }
  | familysymbol OP_LESSEQUAL pexpression { $$ = new LessEqualEquation($1->getPatternValue(),$3); }
  | familysymbol '>' pexpression	{ $$ = new GreaterEquation($1->getPatternValue(),$3); }
  | familysymbol OP_GREATEQUAL pexpression { $$ = new GreaterEqualEquation($1->getPatternValue(),$3); }
  | OPERANDSYM '=' pexpression		{ $$ = slgh->constrainOperand($1,$3); 
                                          if ($$ == (PatternEquation *)0) 
                                            { string errmsg="Constraining currently undefined operand "+$1->getName(); yyerror(errmsg.c_str()); } }
  | OPERANDSYM				{ $$ = new OperandEquation($1->getIndex()); slgh->selfDefine($1); }
  | SPECSYM                             { $$ = new UnconstrainedEquation($1->getPatternExpression()); }
  | familysymbol                        { $$ = slgh->defineInvisibleOperand($1); }
  | SUBTABLESYM                         { $$ = slgh->defineInvisibleOperand($1); }
  ;
contextblock:				{ $$ = (vector<ContextChange *> *)0; }
  | '[' contextlist ']'			{ $$ = $2; }
  ;
contextlist: 				{ $$ = new vector<ContextChange *>; }
  | contextlist CONTEXTSYM '=' pexpression ';'  { $$ = $1; if (!slgh->contextMod($1,$2,$4)) { string errmsg="Cannot use 'inst_next' to set context variable: "+$2->getName(); yyerror(errmsg.c_str()); YYERROR; } }
  | contextlist GLOBALSET_KEY '(' familysymbol ',' CONTEXTSYM ')' ';' { $$ = $1; slgh->contextSet($1,$4,$6); }
  | contextlist GLOBALSET_KEY '(' specificsymbol ',' CONTEXTSYM ')' ';' { $$ = $1; slgh->contextSet($1,$4,$6); }
  | contextlist OPERANDSYM '=' pexpression ';' { $$ = $1; slgh->defineOperand($2,$4); }
  | contextlist STRING                  { string errmsg="Expecting context symbol, not "+*$2; delete $2; yyerror(errmsg.c_str()); YYERROR; }
  ;
section_def: OP_LEFT STRING OP_RIGHT    { $$ = slgh->newSectionSymbol( *$2 ); delete $2; }
  | OP_LEFT SECTIONSYM OP_RIGHT         { $$ = $2; }
  ;
rtlfirstsection: rtl section_def        { $$ = slgh->firstNamedSection($1,$2); }
  ;
rtlcontinue: rtlfirstsection { $$ = $1; }
  | rtlcontinue rtlmid section_def      { $$ = slgh->nextNamedSection($1,$2,$3); }
  ;
rtl: rtlmid { $$ = $1; if ($$->getOpvec().empty() && ($$->getResult() == (HandleTpl *)0)) slgh->recordNop(); }
  | rtlmid EXPORT_KEY exportvarnode ';' { $$ = slgh->setResultVarnode($1,$3); }
  | rtlmid EXPORT_KEY sizedstar lhsvarnode ';' { $$ = slgh->setResultStarVarnode($1,$3,$4); }
  | rtlmid EXPORT_KEY STRING		{ string errmsg="Unknown export varnode: "+*$3; delete $3; yyerror(errmsg.c_str()); YYERROR; }
  | rtlmid EXPORT_KEY sizedstar STRING	{ string errmsg="Unknown pointer varnode: "+*$4; delete $3; delete $4; yyerror(errmsg.c_str()); YYERROR; }
  ;
rtlmid: /* EMPTY */			{ $$ = new ConstructTpl(); }
  | rtlmid statement			{ $$ = $1; if (!$$->addOpList(*$2)) { delete $2; yyerror("Multiple delayslot declarations"); YYERROR; } delete $2; }
  | rtlmid LOCAL_KEY STRING ';' { $$ = $1; slgh->pcode.newLocalDefinition($3); }
  | rtlmid LOCAL_KEY STRING ':' INTEGER ';' { $$ = $1; slgh->pcode.newLocalDefinition($3,*$5); delete $5; }
  ;
statement: lhsvarnode '=' expr ';'	{ $3->setOutput($1); $$ = ExprTree::toVector($3); }
  | LOCAL_KEY STRING '=' expr ';'	{ $$ = slgh->pcode.newOutput(true,$4,$2); }
  | STRING '=' expr ';'			{ $$ = slgh->pcode.newOutput(false,$3,$1); }
  | LOCAL_KEY STRING ':' INTEGER '=' expr ';'	{ $$ = slgh->pcode.newOutput(true,$6,$2,*$4); delete $4; }
  | STRING ':' INTEGER '=' expr ';'	{ $$ = slgh->pcode.newOutput(true,$5,$1,*$3); delete $3; }
  | LOCAL_KEY specificsymbol '=' { $$ = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+$2->getName(); yyerror(errmsg.c_str()); YYERROR; }
  | sizedstar expr '=' expr ';'		{ $$ = slgh->pcode.createStore($1,$2,$4); }
  | USEROPSYM '(' paramlist ')' ';'	{ $$ = slgh->pcode.createUserOpNoOut($1,$3); }
  | lhsvarnode '[' INTEGER ',' INTEGER ']' '=' expr ';' { $$ = slgh->pcode.assignBitRange($1,(uint4)*$3,(uint4)*$5,$8); delete $3, delete $5; }
  | BITSYM '=' expr ';'                 { $$=slgh->pcode.assignBitRange($1->getParentSymbol()->getVarnode(),$1->getBitOffset(),$1->numBits(),$3); }
  | varnode ':' INTEGER '='		{ delete $1; delete $3; yyerror("Illegal truncation on left-hand side of assignment"); YYERROR; }
  | varnode '(' INTEGER ')'		{ delete $1; delete $3; yyerror("Illegal subpiece on left-hand side of assignment"); YYERROR; }
  | BUILD_KEY OPERANDSYM ';'		{ $$ = slgh->pcode.createOpConst(BUILD,$2->getIndex()); }
  | CROSSBUILD_KEY varnode ',' SECTIONSYM ';' { $$ = slgh->createCrossBuild($2,$4); }
  | CROSSBUILD_KEY varnode ',' STRING ';'   { $$ = slgh->createCrossBuild($2,slgh->newSectionSymbol(*$4)); delete $4; }
  | DELAYSLOT_KEY '(' INTEGER ')' ';'	{ $$ = slgh->pcode.createOpConst(DELAY_SLOT,*$3); delete $3; }
  | GOTO_KEY jumpdest ';'		{ $$ = slgh->pcode.createOpNoOut(CPUI_BRANCH,new ExprTree($2)); }
  | IF_KEY expr GOTO_KEY jumpdest ';'	{ $$ = slgh->pcode.createOpNoOut(CPUI_CBRANCH,new ExprTree($4),$2); }
  | GOTO_KEY '[' expr ']' ';'		{ $$ = slgh->pcode.createOpNoOut(CPUI_BRANCHIND,$3); }
  | CALL_KEY jumpdest ';'		{ $$ = slgh->pcode.createOpNoOut(CPUI_CALL,new ExprTree($2)); }
  | CALL_KEY '[' expr ']' ';'		{ $$ = slgh->pcode.createOpNoOut(CPUI_CALLIND,$3); }
  | RETURN_KEY ';'			{ yyerror("Must specify an indirect parameter for return"); YYERROR; }
  | RETURN_KEY '[' expr ']' ';'		{ $$ = slgh->pcode.createOpNoOut(CPUI_RETURN,$3); }
  | MACROSYM '(' paramlist ')' ';'      { $$ = slgh->createMacroUse($1,$3); }
  | label                               { $$ = slgh->pcode.placeLabel( $1 ); }
  ;
expr: varnode { $$ = new ExprTree($1); }
  | sizedstar expr %prec '!'	{ $$ = slgh->pcode.createLoad($1,$2); }
  | '(' expr ')'		{ $$ = $2; }
  | expr '+' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_ADD,$1,$3); }
  | expr '-' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_SUB,$1,$3); }
  | expr OP_EQUAL expr		{ $$ = slgh->pcode.createOp(CPUI_INT_EQUAL,$1,$3); }
  | expr OP_NOTEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_INT_NOTEQUAL,$1,$3); }
  | expr '<' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_LESS,$1,$3); }
  | expr OP_GREATEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,$3,$1); }
  | expr OP_LESSEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_INT_LESSEQUAL,$1,$3); }
  | expr '>' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_LESS,$3,$1); }
  | expr OP_SLESS expr		{ $$ = slgh->pcode.createOp(CPUI_INT_SLESS,$1,$3); }
  | expr OP_SGREATEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,$3,$1); }
  | expr OP_SLESSEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_INT_SLESSEQUAL,$1,$3); }
  | expr OP_SGREAT expr		{ $$ = slgh->pcode.createOp(CPUI_INT_SLESS,$3,$1); }
  | '-' expr	%prec '!'      	{ $$ = slgh->pcode.createOp(CPUI_INT_2COMP,$2); }
  | '~' expr			{ $$ = slgh->pcode.createOp(CPUI_INT_NEGATE,$2); }
  | expr '^' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_XOR,$1,$3); }
  | expr '&' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_AND,$1,$3); }
  | expr '|' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_OR,$1,$3); }
  | expr OP_LEFT expr		{ $$ = slgh->pcode.createOp(CPUI_INT_LEFT,$1,$3); }
  | expr OP_RIGHT expr		{ $$ = slgh->pcode.createOp(CPUI_INT_RIGHT,$1,$3); }
  | expr OP_SRIGHT expr		{ $$ = slgh->pcode.createOp(CPUI_INT_SRIGHT,$1,$3); }
  | expr '*' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_MULT,$1,$3); }
  | expr '/' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_DIV,$1,$3); }
  | expr OP_SDIV expr		{ $$ = slgh->pcode.createOp(CPUI_INT_SDIV,$1,$3); }
  | expr '%' expr		{ $$ = slgh->pcode.createOp(CPUI_INT_REM,$1,$3); }
  | expr OP_SREM expr		{ $$ = slgh->pcode.createOp(CPUI_INT_SREM,$1,$3); }
  | '!' expr			{ $$ = slgh->pcode.createOp(CPUI_BOOL_NEGATE,$2); }
  | expr OP_BOOL_XOR expr	{ $$ = slgh->pcode.createOp(CPUI_BOOL_XOR,$1,$3); }
  | expr OP_BOOL_AND expr	{ $$ = slgh->pcode.createOp(CPUI_BOOL_AND,$1,$3); }
  | expr OP_BOOL_OR expr	{ $$ = slgh->pcode.createOp(CPUI_BOOL_OR,$1,$3); }
  | expr OP_FEQUAL expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_EQUAL,$1,$3); }
  | expr OP_FNOTEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_NOTEQUAL,$1,$3); }
  | expr OP_FLESS expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_LESS,$1,$3); }
  | expr OP_FGREAT expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_LESS,$3,$1); }
  | expr OP_FLESSEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,$1,$3); }
  | expr OP_FGREATEQUAL expr	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_LESSEQUAL,$3,$1); }
  | expr OP_FADD expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_ADD,$1,$3); }
  | expr OP_FSUB expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_SUB,$1,$3); }
  | expr OP_FMULT expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_MULT,$1,$3); }
  | expr OP_FDIV expr		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_DIV,$1,$3); }
  | OP_FSUB expr %prec '!'      { $$ = slgh->pcode.createOp(CPUI_FLOAT_NEG,$2); }
  | OP_ABS '(' expr ')'		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_ABS,$3); }
  | OP_SQRT '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_SQRT,$3); }
  | OP_SEXT '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_INT_SEXT,$3); }
  | OP_ZEXT '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_INT_ZEXT,$3); }
  | OP_CARRY '(' expr ',' expr ')' { $$ = slgh->pcode.createOp(CPUI_INT_CARRY,$3,$5); }
  | OP_SCARRY '(' expr ',' expr ')' { $$ = slgh->pcode.createOp(CPUI_INT_SCARRY,$3,$5); }
  | OP_SBORROW '(' expr ',' expr ')' { $$ = slgh->pcode.createOp(CPUI_INT_SBORROW,$3,$5); }
  | OP_FLOAT2FLOAT '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_FLOAT2FLOAT,$3); }
  | OP_INT2FLOAT '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_INT2FLOAT,$3); }
  | OP_NAN '(' expr ')'		{ $$ = slgh->pcode.createOp(CPUI_FLOAT_NAN,$3); }
  | OP_TRUNC '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_TRUNC,$3); }
  | OP_CEIL '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_CEIL,$3); }
  | OP_FLOOR '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_FLOOR,$3); }
  | OP_ROUND '(' expr ')'	{ $$ = slgh->pcode.createOp(CPUI_FLOAT_ROUND,$3); }
  | OP_NEW '(' expr ')'     { $$ = slgh->pcode.createOp(CPUI_NEW,$3); }
  | OP_NEW '(' expr ',' expr ')' { $$ = slgh->pcode.createOp(CPUI_NEW,$3,$5); }
  | OP_POPCOUNT '(' expr ')' { $$ = slgh->pcode.createOp(CPUI_POPCOUNT,$3); }
  | specificsymbol '(' integervarnode ')' { $$ = slgh->pcode.createOp(CPUI_SUBPIECE,new ExprTree($1->getVarnode()),new ExprTree($3)); }
  | specificsymbol ':' INTEGER	{ $$ = slgh->pcode.createBitRange($1,0,(uint4)(*$3 * 8)); delete $3; }
  | specificsymbol '[' INTEGER ',' INTEGER ']' { $$ = slgh->pcode.createBitRange($1,(uint4)*$3,(uint4)*$5); delete $3, delete $5; }
  | BITSYM                      { $$=slgh->pcode.createBitRange($1->getParentSymbol(),$1->getBitOffset(),$1->numBits()); }
  | USEROPSYM '(' paramlist ')' { $$ = slgh->pcode.createUserOp($1,$3); }
  | OP_CPOOLREF '(' paramlist ')'  { if ((*$3).size() < 2) { string errmsg = "Must at least two inputs to cpool"; yyerror(errmsg.c_str()); YYERROR; } $$ = slgh->pcode.createVariadic(CPUI_CPOOLREF,$3); }
  ;  
sizedstar: '*' '[' SPACESYM ']' ':' INTEGER { $$ = new StarQuality; $$->size = *$6; delete $6; $$->id=ConstTpl($3->getSpace()); }
  | '*' '[' SPACESYM ']'	{ $$ = new StarQuality; $$->size = 0; $$->id=ConstTpl($3->getSpace()); }
  | '*' ':' INTEGER		{ $$ = new StarQuality; $$->size = *$3; delete $3; $$->id=ConstTpl(slgh->getDefaultCodeSpace()); }
  | '*'				{ $$ = new StarQuality; $$->size = 0; $$->id=ConstTpl(slgh->getDefaultCodeSpace()); }
  ;
jumpdest: STARTSYM		{ VarnodeTpl *sym = $1->getVarnode(); $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
  | ENDSYM			{ VarnodeTpl *sym = $1->getVarnode(); $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
  | INTEGER			{ $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::j_curspace_size)); delete $1; }
  | BADINTEGER                  { $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); yyerror("Parsed integer is too big (overflow)"); }
  | OPERANDSYM			{ $$ = $1->getVarnode(); $1->setCodeAddress(); }
  | INTEGER '[' SPACESYM ']'	{ AddrSpace *spc = $3->getSpace(); $$ = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete $1; }
  | label                       { $$ = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::j_relative,$1->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); $1->incrementRefCount(); }
  | STRING			{ string errmsg = "Unknown jump destination: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  ;
varnode: specificsymbol		{ $$ = $1->getVarnode(); }
  | integervarnode		{ $$ = $1; }
  | STRING			{ string errmsg = "Unknown varnode parameter: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  | SUBTABLESYM                 { string errmsg = "Subtable not attached to operand: "+$1->getName(); yyerror(errmsg.c_str()); YYERROR; }
  ;
integervarnode: INTEGER		{ $$ = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,0)); delete $1; }
  | BADINTEGER                  { $$ = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); yyerror("Parsed integer is too big (overflow)"); }
  | INTEGER ':' INTEGER		{ $$ = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,*$3)); delete $1; delete $3; }
  | '&' varnode                 { $$ = slgh->pcode.addressOf($2,0); }
  | '&' ':' INTEGER varnode     { $$ = slgh->pcode.addressOf($4,*$3); delete $3; }
  ;
lhsvarnode: specificsymbol	{ $$ = $1->getVarnode(); }
  | STRING			{ string errmsg = "Unknown assignment varnode: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  | SUBTABLESYM                 { string errmsg = "Subtable not attached to operand: "+$1->getName(); yyerror(errmsg.c_str()); YYERROR; }
  ;
label: '<' LABELSYM '>'         { $$ = $2; }
  | '<' STRING '>'              { $$ = slgh->pcode.defineLabel( $2 ); }
  ;
exportvarnode: specificsymbol	{ $$ = $1->getVarnode(); }
  | '&' varnode                 { $$ = slgh->pcode.addressOf($2,0); }
  | '&' ':' INTEGER varnode     { $$ = slgh->pcode.addressOf($4,*$3); delete $3; }
  | INTEGER ':' INTEGER		{ $$ = new VarnodeTpl(ConstTpl(slgh->getConstantSpace()),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,*$3)); delete $1; delete $3; }
  | STRING			{ string errmsg="Unknown export varnode: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  | SUBTABLESYM                 { string errmsg = "Subtable not attached to operand: "+$1->getName(); yyerror(errmsg.c_str()); YYERROR; }
  ;
familysymbol: VALUESYM		{ $$ = $1; }
  | VALUEMAPSYM                 { $$ = $1; }
  | CONTEXTSYM                  { $$ = $1; }
  | NAMESYM			{ $$ = $1; }
  | VARLISTSYM			{ $$ = $1; }
  ;
specificsymbol: VARSYM		{ $$ = $1; }
  | SPECSYM                     { $$ = $1; }
  | OPERANDSYM			{ $$ = $1; }
  | STARTSYM			{ $$ = $1; }
  | ENDSYM			{ $$ = $1; }
  ;
charstring: CHAR		{ $$ = new string; (*$$) += $1; }
  | charstring CHAR		{ $$ = $1; (*$$) += $2; }
  ;
intblist: '[' intbpart ']'	{ $$ = $2; }
  | INTEGER                     { $$ = new vector<intb>; $$->push_back(intb(*$1)); delete $1; }
  | '-' INTEGER                 { $$ = new vector<intb>; $$->push_back(-intb(*$2)); delete $2; }
  ;
intbpart: INTEGER		{ $$ = new vector<intb>; $$->push_back(intb(*$1)); delete $1; }
  | '-' INTEGER                 { $$ = new vector<intb>; $$->push_back(-intb(*$2)); delete $2; }
  | STRING                      { if (*$1!="_") { string errmsg = "Expecting integer but saw: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
                                  $$ = new vector<intb>; $$->push_back((intb)0xBADBEEF); delete $1; }
  | intbpart INTEGER            { $$ = $1; $$->push_back(intb(*$2)); delete $2; }
  | intbpart '-' INTEGER        { $$ = $1; $$->push_back(-intb(*$3)); delete $3; }
  | intbpart STRING             { if (*$2!="_") { string errmsg = "Expecting integer but saw: "+*$2; delete $2; yyerror(errmsg.c_str()); YYERROR; }
                                  $$ = $1; $$->push_back((intb)0xBADBEEF); delete $2; }
  ;
stringlist: '[' stringpart ']'	{ $$ = $2; }
  | STRING			{ $$ = new vector<string>; $$->push_back(*$1); delete $1; }
  ;
stringpart: STRING		{ $$ = new vector<string>; $$->push_back( *$1 ); delete $1; }
  | stringpart STRING		{ $$ = $1; $$->push_back(*$2); delete $2; }
  | stringpart anysymbol	{ string errmsg = $2->getName()+": redefined"; yyerror(errmsg.c_str()); YYERROR; }
  ;
anystringlist: '[' anystringpart ']' { $$ = $2; }
  ;
anystringpart: STRING           { $$ = new vector<string>; $$->push_back( *$1 ); delete $1; }
  | anysymbol                   { $$ = new vector<string>; $$->push_back( $1->getName() ); }
  | anystringpart STRING        { $$ = $1; $$->push_back(*$2); delete $2; }
  | anystringpart anysymbol     { $$ = $1; $$->push_back($2->getName()); }
  ;
valuelist: '[' valuepart ']'	{ $$ = $2; }
  | VALUESYM			{ $$ = new vector<SleighSymbol *>; $$->push_back($1); }
  | CONTEXTSYM                  { $$ = new vector<SleighSymbol *>; $$->push_back($1); }
  ;
valuepart: VALUESYM		{ $$ = new vector<SleighSymbol *>; $$->push_back( $1 ); }
  | CONTEXTSYM                  { $$ = new vector<SleighSymbol *>; $$->push_back($1); }
  | valuepart VALUESYM		{ $$ = $1; $$->push_back($2); }
  | valuepart CONTEXTSYM        { $$ = $1; $$->push_back($2); }
  | valuepart STRING		{ string errmsg = *$2+": is not a value pattern"; delete $2; yyerror(errmsg.c_str()); YYERROR; }
  ;
varlist: '[' varpart ']'	{ $$ = $2; }
  | VARSYM			{ $$ = new vector<SleighSymbol *>; $$->push_back($1); }
  ;
varpart: VARSYM			{ $$ = new vector<SleighSymbol *>; $$->push_back($1); }
  | STRING                      { if (*$1!="_") { string errmsg = *$1+": is not a varnode symbol"; delete $1; yyerror(errmsg.c_str()); YYERROR; }
				  $$ = new vector<SleighSymbol *>; $$->push_back((SleighSymbol *)0); delete $1; }
  | varpart VARSYM		{ $$ = $1; $$->push_back($2); }
  | varpart STRING		{ if (*$2!="_") { string errmsg = *$2+": is not a varnode symbol"; delete $2; yyerror(errmsg.c_str()); YYERROR; }
                                  $$ = $1; $$->push_back((SleighSymbol *)0); delete $2; }
  ;
paramlist: /* EMPTY */		{ $$ = new vector<ExprTree *>; }
  | expr			{ $$ = new vector<ExprTree *>; $$->push_back($1); }
  | paramlist ',' expr		{ $$ = $1; $$->push_back($3); }
  ;
oplist: /* EMPTY */		{ $$ = new vector<string>; }
  | STRING			{ $$ = new vector<string>; $$->push_back(*$1); delete $1; }
  | oplist ',' STRING		{ $$ = $1; $$->push_back(*$3); delete $3; }
  ;
anysymbol: SPACESYM		{ $$ = $1; }
  | SECTIONSYM                  { $$ = $1; }
  | TOKENSYM			{ $$ = $1; }
  | USEROPSYM			{ $$ = $1; }
  | MACROSYM			{ $$ = $1; }
  | SUBTABLESYM			{ $$ = $1; }
  | VALUESYM			{ $$ = $1; }
  | VALUEMAPSYM                 { $$ = $1; }
  | CONTEXTSYM                  { $$ = $1; }
  | NAMESYM			{ $$ = $1; }
  | VARSYM			{ $$ = $1; }
  | VARLISTSYM			{ $$ = $1; }
  | OPERANDSYM			{ $$ = $1; }
  | STARTSYM			{ $$ = $1; }
  | ENDSYM			{ $$ = $1; }
  | BITSYM                      { $$ = $1; }
  ;
%%

int yyerror(const char *s)

{
  slgh->reportError(s);
  return 0;
}

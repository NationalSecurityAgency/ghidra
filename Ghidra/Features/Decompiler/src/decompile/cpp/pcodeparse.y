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
#include "pcodeparse.hh"

  //#define YYERROR_VERBOSE
  extern int yylex(void);
  static PcodeSnippet *pcode;
  extern int yydebug;
  extern int yyerror(const char *str );
%}

%union {
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
  OperandSymbol *operandsym;
  VarnodeSymbol *varsym;
  SpecificSymbol *specsym;
}

%expect 3
// Conflicts
// 1 integervarnode ':' conflict   (does ':' apply to INTEGER or varnode)
//     resolved by shifting which applies ':' to INTEGER (best solution)
// 2 statement -> STRING . conflicts (STRING might be mislabelled varnode, or temporary declaration)
//     resolved by shifting which means assume this is a temporary declaration

%left OP_BOOL_OR
%left OP_BOOL_AND OP_BOOL_XOR
%left '|'
%left ';'
%left '^'
%left '&'
%left OP_EQUAL OP_NOTEQUAL OP_FEQUAL OP_FNOTEQUAL
%nonassoc '<' '>' OP_GREATEQUAL OP_LESSEQUAL OP_SLESS OP_SGREATEQUAL OP_SLESSEQUAL OP_SGREAT OP_FLESS OP_FGREAT OP_FLESSEQUAL OP_FGREATEQUAL
%left OP_LEFT OP_RIGHT OP_SRIGHT
%left '+' '-' OP_FADD OP_FSUB
%left '*' '/' '%' OP_SDIV OP_SREM OP_FMULT OP_FDIV
%right '!' '~'
%token OP_ZEXT OP_CARRY OP_BORROW OP_SEXT OP_SCARRY OP_SBORROW OP_NAN OP_ABS
%token OP_SQRT OP_CEIL OP_FLOOR OP_ROUND OP_INT2FLOAT OP_FLOAT2FLOAT
%token OP_TRUNC OP_NEW

%token BADINTEGER GOTO_KEY CALL_KEY RETURN_KEY IF_KEY ENDOFSTREAM LOCAL_KEY

%token <i> INTEGER
%token <str> STRING
%token <spacesym> SPACESYM
%token <useropsym> USEROPSYM
%token <varsym> VARSYM
%token <operandsym> OPERANDSYM
%token <startsym> STARTSYM
%token <endsym> ENDSYM
%token <labelsym> LABELSYM

%type <param> paramlist
%type <sem> rtlmid
%type <stmt> statement
%type <tree> expr
%type <varnode> varnode integervarnode lhsvarnode jumpdest
%type <labelsym> label
%type <starqual> sizedstar
%type <specsym> specificsymbol

%destructor { delete $$; } INTEGER
%destructor { delete $$; } STRING
%destructor { for(int4 i=0;i<$$->size();++i) delete (*$$)[i]; delete $$; } paramlist
%destructor { delete $$; } rtlmid
%destructor { if ($$ != (vector<OpTpl *> *)0) { for(int4 i=0;i<$$->size();++i) delete (*$$)[i]; delete $$;} } statement
%destructor { delete $$; } expr
%destructor { if ($$ != (VarnodeTpl *)0) delete $$; } varnode integervarnode lhsvarnode jumpdest
%destructor { delete $$; } sizedstar

%%
rtl: rtlmid ENDOFSTREAM                 { pcode->setResult($1); }
  ;
rtlmid: /* EMPTY */			{ $$ = new ConstructTpl(); }
  | rtlmid statement			{ $$ = $1; if (!$$->addOpList(*$2)) { delete $2; yyerror("Multiple delayslot declarations"); YYERROR; } delete $2; }
  | rtlmid LOCAL_KEY STRING ';' { $$ = $1; pcode->newLocalDefinition($3); }
  | rtlmid LOCAL_KEY STRING ':' INTEGER ';' { $$ = $1; pcode->newLocalDefinition($3,*$5); delete $5; }
  ;
statement: lhsvarnode '=' expr ';'	{ $3->setOutput($1); $$ = ExprTree::toVector($3); }
  | LOCAL_KEY STRING '=' expr ';'	{ $$ = pcode->newOutput(true,$4,$2); }
  | STRING '=' expr ';'			{ $$ = pcode->newOutput(false,$3,$1); }
  | LOCAL_KEY STRING ':' INTEGER '=' expr ';'	{ $$ = pcode->newOutput(true,$6,$2,*$4); delete $4; }
  | STRING ':' INTEGER '=' expr ';'	{ $$ = pcode->newOutput(true,$5,$1,*$3); delete $3; }
  | LOCAL_KEY specificsymbol '=' { $$ = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+$2->getName(); yyerror(errmsg.c_str()); YYERROR; }
  | sizedstar expr '=' expr ';'		{ $$ = pcode->createStore($1,$2,$4); }
  | USEROPSYM '(' paramlist ')' ';'	{ $$ = pcode->createUserOpNoOut($1,$3); }
  | lhsvarnode '[' INTEGER ',' INTEGER ']' '=' expr ';' { $$ = pcode->assignBitRange($1,(uint4)*$3,(uint4)*$5,$8); delete $3, delete $5; }
  | varnode ':' INTEGER '='		{ $$ = (vector<OpTpl *> *)0; delete $1; delete $3; yyerror("Illegal truncation on left-hand side of assignment"); YYERROR; }
  | varnode '(' INTEGER ')'		{ $$ = (vector<OpTpl *> *)0; delete $1; delete $3; yyerror("Illegal subpiece on left-hand side of assignment"); YYERROR; }
  | GOTO_KEY jumpdest ';'		{ $$ = pcode->createOpNoOut(CPUI_BRANCH,new ExprTree($2)); }
  | IF_KEY expr GOTO_KEY jumpdest ';'	{ $$ = pcode->createOpNoOut(CPUI_CBRANCH,new ExprTree($4),$2); }
  | GOTO_KEY '[' expr ']' ';'		{ $$ = pcode->createOpNoOut(CPUI_BRANCHIND,$3); }
  | CALL_KEY jumpdest ';'		{ $$ = pcode->createOpNoOut(CPUI_CALL,new ExprTree($2)); }
  | CALL_KEY '[' expr ']' ';'		{ $$ = pcode->createOpNoOut(CPUI_CALLIND,$3); }
  | RETURN_KEY ';'			{ $$ = (vector<OpTpl *> *)0; yyerror("Must specify an indirect parameter for return"); YYERROR; }
  | RETURN_KEY '[' expr ']' ';'		{ $$ = pcode->createOpNoOut(CPUI_RETURN,$3); }
  | label                               { $$ = pcode->placeLabel( $1 ); }
  ;
expr: varnode { $$ = new ExprTree($1); }
  | sizedstar expr %prec '!'	{ $$ = pcode->createLoad($1,$2); }
  | '(' expr ')'		{ $$ = $2; }
  | expr '+' expr		{ $$ = pcode->createOp(CPUI_INT_ADD,$1,$3); }
  | expr '-' expr		{ $$ = pcode->createOp(CPUI_INT_SUB,$1,$3); }
  | expr OP_EQUAL expr		{ $$ = pcode->createOp(CPUI_INT_EQUAL,$1,$3); }
  | expr OP_NOTEQUAL expr	{ $$ = pcode->createOp(CPUI_INT_NOTEQUAL,$1,$3); }
  | expr '<' expr		{ $$ = pcode->createOp(CPUI_INT_LESS,$1,$3); }
  | expr OP_GREATEQUAL expr	{ $$ = pcode->createOp(CPUI_INT_LESSEQUAL,$3,$1); }
  | expr OP_LESSEQUAL expr	{ $$ = pcode->createOp(CPUI_INT_LESSEQUAL,$1,$3); }
  | expr '>' expr		{ $$ = pcode->createOp(CPUI_INT_LESS,$3,$1); }
  | expr OP_SLESS expr		{ $$ = pcode->createOp(CPUI_INT_SLESS,$1,$3); }
  | expr OP_SGREATEQUAL expr	{ $$ = pcode->createOp(CPUI_INT_SLESSEQUAL,$3,$1); }
  | expr OP_SLESSEQUAL expr	{ $$ = pcode->createOp(CPUI_INT_SLESSEQUAL,$1,$3); }
  | expr OP_SGREAT expr		{ $$ = pcode->createOp(CPUI_INT_SLESS,$3,$1); }
  | '-' expr	%prec '!'      	{ $$ = pcode->createOp(CPUI_INT_2COMP,$2); }
  | '~' expr			{ $$ = pcode->createOp(CPUI_INT_NEGATE,$2); }
  | expr '^' expr		{ $$ = pcode->createOp(CPUI_INT_XOR,$1,$3); }
  | expr '&' expr		{ $$ = pcode->createOp(CPUI_INT_AND,$1,$3); }
  | expr '|' expr		{ $$ = pcode->createOp(CPUI_INT_OR,$1,$3); }
  | expr OP_LEFT expr		{ $$ = pcode->createOp(CPUI_INT_LEFT,$1,$3); }
  | expr OP_RIGHT expr		{ $$ = pcode->createOp(CPUI_INT_RIGHT,$1,$3); }
  | expr OP_SRIGHT expr		{ $$ = pcode->createOp(CPUI_INT_SRIGHT,$1,$3); }
  | expr '*' expr		{ $$ = pcode->createOp(CPUI_INT_MULT,$1,$3); }
  | expr '/' expr		{ $$ = pcode->createOp(CPUI_INT_DIV,$1,$3); }
  | expr OP_SDIV expr		{ $$ = pcode->createOp(CPUI_INT_SDIV,$1,$3); }
  | expr '%' expr		{ $$ = pcode->createOp(CPUI_INT_REM,$1,$3); }
  | expr OP_SREM expr		{ $$ = pcode->createOp(CPUI_INT_SREM,$1,$3); }
  | '!' expr			{ $$ = pcode->createOp(CPUI_BOOL_NEGATE,$2); }
  | expr OP_BOOL_XOR expr	{ $$ = pcode->createOp(CPUI_BOOL_XOR,$1,$3); }
  | expr OP_BOOL_AND expr	{ $$ = pcode->createOp(CPUI_BOOL_AND,$1,$3); }
  | expr OP_BOOL_OR expr	{ $$ = pcode->createOp(CPUI_BOOL_OR,$1,$3); }
  | expr OP_FEQUAL expr		{ $$ = pcode->createOp(CPUI_FLOAT_EQUAL,$1,$3); }
  | expr OP_FNOTEQUAL expr	{ $$ = pcode->createOp(CPUI_FLOAT_NOTEQUAL,$1,$3); }
  | expr OP_FLESS expr		{ $$ = pcode->createOp(CPUI_FLOAT_LESS,$1,$3); }
  | expr OP_FGREAT expr		{ $$ = pcode->createOp(CPUI_FLOAT_LESS,$3,$1); }
  | expr OP_FLESSEQUAL expr	{ $$ = pcode->createOp(CPUI_FLOAT_LESSEQUAL,$1,$3); }
  | expr OP_FGREATEQUAL expr	{ $$ = pcode->createOp(CPUI_FLOAT_LESSEQUAL,$3,$1); }
  | expr OP_FADD expr		{ $$ = pcode->createOp(CPUI_FLOAT_ADD,$1,$3); }
  | expr OP_FSUB expr		{ $$ = pcode->createOp(CPUI_FLOAT_SUB,$1,$3); }
  | expr OP_FMULT expr		{ $$ = pcode->createOp(CPUI_FLOAT_MULT,$1,$3); }
  | expr OP_FDIV expr		{ $$ = pcode->createOp(CPUI_FLOAT_DIV,$1,$3); }
  | OP_FSUB expr %prec '!'      { $$ = pcode->createOp(CPUI_FLOAT_NEG,$2); }
  | OP_ABS '(' expr ')'		{ $$ = pcode->createOp(CPUI_FLOAT_ABS,$3); }
  | OP_SQRT '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_SQRT,$3); }
  | OP_SEXT '(' expr ')'	{ $$ = pcode->createOp(CPUI_INT_SEXT,$3); }
  | OP_ZEXT '(' expr ')'	{ $$ = pcode->createOp(CPUI_INT_ZEXT,$3); }
  | OP_CARRY '(' expr ',' expr ')' { $$ = pcode->createOp(CPUI_INT_CARRY,$3,$5); }
  | OP_SCARRY '(' expr ',' expr ')' { $$ = pcode->createOp(CPUI_INT_SCARRY,$3,$5); }
  | OP_SBORROW '(' expr ',' expr ')' { $$ = pcode->createOp(CPUI_INT_SBORROW,$3,$5); }
  | OP_FLOAT2FLOAT '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_FLOAT2FLOAT,$3); }
  | OP_INT2FLOAT '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_INT2FLOAT,$3); }
  | OP_NAN '(' expr ')'		{ $$ = pcode->createOp(CPUI_FLOAT_NAN,$3); }
  | OP_TRUNC '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_TRUNC,$3); }
  | OP_CEIL '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_CEIL,$3); }
  | OP_FLOOR '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_FLOOR,$3); }
  | OP_ROUND '(' expr ')'	{ $$ = pcode->createOp(CPUI_FLOAT_ROUND,$3); };
  | OP_NEW '(' expr ')'     { $$ = pcode->createOp(CPUI_NEW,$3); };
  | OP_NEW '(' expr ',' expr ')' { $$ = pcode->createOp(CPUI_NEW,$3,$5); }
  | specificsymbol '(' integervarnode ')' { $$ = pcode->createOp(CPUI_SUBPIECE,new ExprTree($1->getVarnode()),new ExprTree($3)); }
  | specificsymbol ':' INTEGER	{ $$ = pcode->createBitRange($1,0,(uint4)(*$3 * 8)); delete $3; }
  | specificsymbol '[' INTEGER ',' INTEGER ']' { $$ = pcode->createBitRange($1,(uint4)*$3,(uint4)*$5); delete $3, delete $5; }
  | USEROPSYM '(' paramlist ')' { $$ = pcode->createUserOp($1,$3); }
  ;  
sizedstar: '*' '[' SPACESYM ']' ':' INTEGER { $$ = new StarQuality; $$->size = *$6; delete $6; $$->id=ConstTpl($3->getSpace()); }
  | '*' '[' SPACESYM ']'	{ $$ = new StarQuality; $$->size = 0; $$->id=ConstTpl($3->getSpace()); }
  | '*' ':' INTEGER		{ $$ = new StarQuality; $$->size = *$3; delete $3; $$->id=ConstTpl(pcode->getDefaultSpace()); }
  | '*'				{ $$ = new StarQuality; $$->size = 0; $$->id=ConstTpl(pcode->getDefaultSpace()); }
  ;
jumpdest: STARTSYM		{ VarnodeTpl *sym = $1->getVarnode(); $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
  | ENDSYM			{ VarnodeTpl *sym = $1->getVarnode(); $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
  | INTEGER			{ $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::j_curspace_size)); delete $1; }
  | BADINTEGER                  { $$ = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); yyerror("Parsed integer is too big (overflow)"); }
  | INTEGER '[' SPACESYM ']'	{ AddrSpace *spc = $3->getSpace(); $$ = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete $1; }
  | label                       { $$ = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::j_relative,$1->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); $1->incrementRefCount(); }
  | STRING			{ $$ = (VarnodeTpl *)0; string errmsg = "Unknown jump destination: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  ;
varnode: specificsymbol		{ $$ = $1->getVarnode(); }
  | integervarnode		{ $$ = $1; }
  | STRING			{ $$ = (VarnodeTpl *)0; string errmsg = "Unknown varnode parameter: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  ;
integervarnode: INTEGER		{ $$ = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,0)); delete $1; }
  | BADINTEGER                  { $$ = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); yyerror("Parsed integer is too big (overflow)"); }
  | INTEGER ':' INTEGER		{ $$ = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,*$1),ConstTpl(ConstTpl::real,*$3)); delete $1; delete $3; }
  | '&' varnode                 { $$ = pcode->addressOf($2,0); }
  | '&' ':' INTEGER varnode     { $$ = pcode->addressOf($4,*$3); delete $3; }
  ;
lhsvarnode: specificsymbol	{ $$ = $1->getVarnode(); }
  | STRING			{ $$ = (VarnodeTpl *)0; string errmsg = "Unknown assignment varnode: "+*$1; delete $1; yyerror(errmsg.c_str()); YYERROR; }
  ;
label: '<' LABELSYM '>'         { $$ = $2; }
  | '<' STRING '>'              { $$ = pcode->defineLabel( $2 ); }
  ;
specificsymbol: VARSYM		{ $$ = $1; }
  | OPERANDSYM			{ $$ = $1; }
  | STARTSYM			{ $$ = $1; }
  | ENDSYM			{ $$ = $1; }
  ;
paramlist: /* EMPTY */		{ $$ = new vector<ExprTree *>; }
  | expr			{ $$ = new vector<ExprTree *>; $$->push_back($1); }
  | paramlist ',' expr		{ $$ = $1; $$->push_back($3); }
  ;
%%

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
    break;
  case special3:
    advancetoken();
    curstate = special32;
    return start;
    break;
  case special32:
    advancetoken();
    curstate = start;
    return identifier;
    break;
  case comment:
    if (curchar == '\n')
      curstate = start;
    else if (curchar == '\0') {
      curstate = endstream;
      return endstream;
    }
    break;
  case identifier:
    advancetoken();
    if (isIdent(lookahead1))
      return start;
    curstate = start;
    return identifier;
    break;
  case hexstring:
    advancetoken();
    if (isHex(lookahead1))
      return start;
    curstate = start;
    return hexstring;
    break;
  case decstring:
    advancetoken();
    if (isDec(lookahead1))
      return start;
    curstate = start;
    return decstring;
    break;
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

uintb PcodeSnippet::allocateTemp(void)

{ // Allocate a variable in the unique space and return the offset
  uintb res = tempbase;
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

int yylex(void) {
  return pcode->lex();
}

int yyerror(const char *s)

{
  pcode->reportError((const Location *)0,s);
  return 0;
}

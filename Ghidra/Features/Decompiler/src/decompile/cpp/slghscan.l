/* ###
 * IP: GHIDRA
 * NOTE: flex skeletons are NOT bound by flex's BSD license
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
%option prefix="sleigh"
%{
#define sleighwrap() 1
#define YY_SKIP_YYWRAP

/* If we are building don't include unistd.h */
/* flex provides us with this macro for turning it off */
#ifdef _WIN32
#define YY_NO_UNISTD_H
static int isatty (int fildes) { return 0; }
#endif

#include "slgh_compile.hh"

namespace ghidra {

#include "slghparse.hh"

struct FileStreamState {
  YY_BUFFER_STATE lastbuffer;	// Last lex buffer corresponding to the stream
  FILE *file;                   // The NEW file stream
};

extern SleighCompile *slgh;
int4 last_preproc;   // lex state before last preprocessing erasure
int4 actionon;       // whether '&' '|' and '^' are treated as actionon in pattern section
int4 withsection = 0; // whether we are between the 'with' keyword and its open brace '{'
vector<FileStreamState> filebuffers;
vector<int4> ifstack;
int4 negative_if = -1;

void preproc_error(const string &err)

{
  slgh->reportError((const Location *)0, err);
  cerr << "Terminating due to error in preprocessing" << endl;
  exit(1);
}

void check_to_endofline(istream &s)

{ // Make sure there is nothing to the end of the line
  s >> ws;
  if (!s.eof())
    if (s.peek() != '#')
      preproc_error("Extra characters in preprocessor directive"); 
}

string read_identifier(istream &s)

{  // Read a proper identifier from the stream
  s >> ws;   // Skip any whitespace
  string res;
  while(!s.eof()) {
    char tok = s.peek();
    if (isalnum(tok) || (tok == '_')) {
      s >> tok;
      res += tok;
    }
    else
      break;
  }
  return res;
}

void preprocess_string(istream &s,string &res)

{  // Grab string surrounded by double quotes from stream or call preprocess_error
  int4 val;
  
  s >> ws;   // Skip any whitespace
  val = s.get();
  if (val != '\"')
    preproc_error("Expecting double quoted string");
  val = s.get();
  while((val != '\"')&&(val>=0)) {
    res += (char)val;
    val = s.get();
  }
  if (val != '\"')
    preproc_error("Missing terminating double quote");
}

extern int4 preprocess_if(istream &s); // Forward declaration for recursion

int4 read_defined_operator(istream &s)

{  // We have seen a -defined- keyword in an if or elif
   // Read macro name used as input, return 1 if it is defined
  char tok = ' ';
  string macroname;
  
  s >> ws >> tok;
  if (tok != '(')
    preproc_error("Badly formed \"defined\" operator");
  macroname = read_identifier(s);
  int4 res = slgh->getPreprocValue(macroname,macroname) ? 1 : 0;
  s >> ws >> tok;
  if (tok != ')')
    preproc_error("Badly formed \"defined\" operator");
  return res;
}

int4 read_boolean_clause(istream &s)

{				// We have seen an if or elif
				// return 1 if condition is true or else 0
  s >> ws;
  if (s.peek()=='(') {		// Parenthetical expression spawns recursion
    int4 val = s.get();
    int4 res = preprocess_if(s);
    s >> ws;
    val = s.get();
    if (val != ')')
      preproc_error("Unbalanced parentheses");
    return res;
  }
				// Otherwise we must have a normal comparison operator
  string lhs,rhs,comp;

  if (s.peek()=='\"')		// Read left-hand side string
    preprocess_string(s,lhs);
  else {
    lhs = read_identifier(s);
    if (lhs == "defined")
      return read_defined_operator(s);
    if (!slgh->getPreprocValue(lhs,lhs))
      preproc_error("Could not find preprocessor macro "+lhs);
  }

  char tok;
  s >> tok;       // Read comparison symbol
  comp += tok;
  s >> tok;
  comp += tok;
    
  s >> ws;
  if (s.peek()=='\"')            // Read right-hand side string
    preprocess_string(s,rhs);
  else {
    rhs = read_identifier(s);
    if (!slgh->getPreprocValue(rhs,rhs))
      preproc_error("Could not find preprocessor macro "+rhs);
  }

  if (comp == "==")
    return (lhs == rhs) ? 1 : 0;
  else if (comp=="!=")
    return (lhs != rhs) ? 1 : 0;
  else
    preproc_error("Syntax error in condition");
  return 0;
}

int4 preprocess_if(istream &s)

{
  int4 res = read_boolean_clause(s);
  s >> ws;
  while((!s.eof())&&(s.peek()!=')')) {
    string boolop;
    char tok;
    s >> tok;
    boolop += tok;
    s >> tok;
    boolop += tok;
    int4 res2 = read_boolean_clause(s);
    if (boolop == "&&")
      res = res & res2;
    else if (boolop == "||")
      res = res | res2;
    else if (boolop == "^^")
      res = res ^ res2;
    else
      preproc_error("Syntax error in expression");
    s >> ws;
  }
  return res;
}

void expand_preprocmacros(string &str)

{
  string::size_type pos;
  string::size_type lastpos = 0;
  pos = str.find("$(",lastpos);
  if (pos == string::npos)
    return;
  string res;
  for(;;) {
    if (pos == string::npos) {
      res += str.substr(lastpos);
      str = res;
      return;
    }
    else {
      res += str.substr(lastpos,(pos-lastpos));
      string::size_type endpos = str.find(')',pos+2);
      if (endpos == string::npos) {
	preproc_error("Unterminated macro in string");
	break;
      }
      string macro = str.substr(pos+2, endpos - (pos+2));
      string value;
      if (!slgh->getPreprocValue(macro,value)) {
	preproc_error("Unknown preprocessing macro "+macro);
	break;
      }
      res += value;
      lastpos = endpos + 1;
    }
    pos = str.find("$(",lastpos);
  }
}

int4 preprocess(int4 cur_state,int4 blank_state)

{
  string str(sleightext);
  string::size_type pos = str.find('#');
  if (pos != string::npos)
    str.erase(pos);
  istringstream s(str);
  string type;

  if (cur_state != blank_state)
    last_preproc = cur_state;

  s.get();   // Skip the preprocessor marker
  s >> type;
  if (type == "include") {
    if (negative_if == -1) {  // Not in the middle of a false if clause
      filebuffers.push_back(FileStreamState());   // Save state of current file
      filebuffers.back().lastbuffer = YY_CURRENT_BUFFER;
      filebuffers.back().file = (FILE *)0;
      s >> ws;
      string fname;
      preprocess_string(s,fname);
      expand_preprocmacros(fname);
      slgh->parseFromNewFile(fname);
      fname = slgh->grabCurrentFilePath();
      sleighin = fopen(fname.c_str(),"r");
      if (sleighin == (FILE *)0)
        preproc_error("Could not open included file "+fname);
      filebuffers.back().file = sleighin;
      sleigh_switch_to_buffer( sleigh_create_buffer(sleighin, YY_BUF_SIZE) );
      check_to_endofline(s);
    }
  }
  else if (type == "define") {
    if (negative_if == -1) {
      string varname;
      string value;
      varname = read_identifier(s);   // Get name of variable being defined
      s >> ws;
      if (s.peek() == '\"')
        preprocess_string(s,value);
      else
        value = read_identifier(s);
      if (varname.size()==0)
        preproc_error("Error in preprocessor definition");
      slgh->setPreprocValue(varname,value);
      check_to_endofline(s);
    }
  }
  else if (type == "undef") {
    if (negative_if == -1) {
      string varname;
      varname = read_identifier(s);		// Name of variable to undefine
      if (varname.size()==0)
        preproc_error("Error in preprocessor undef");
      slgh->undefinePreprocValue(varname);
      check_to_endofline(s);
    }
  }
  else if (type=="ifdef") {
    string varname;
    varname = read_identifier(s);
    if (varname.size()==0)
      preproc_error("Error in preprocessor ifdef");
    string value;
    int4 truth = (slgh->getPreprocValue(varname,value)) ? 1 : 0;
    ifstack.push_back(truth);
    check_to_endofline(s);
  }
  else if (type=="ifndef") {
    string varname;
    varname = read_identifier(s);
    if (varname.size()==0)
      preproc_error("Error in preprocessor ifndef");
    string value;
    int4 truth = (slgh->getPreprocValue(varname,value)) ? 0 : 1;	// flipped from ifdef
    ifstack.push_back(truth);
    check_to_endofline(s);
  }
  else if (type=="if") {
    int4 truth = preprocess_if(s);
    if (!s.eof())
      preproc_error("Unbalanced parentheses");
    ifstack.push_back(truth);
  }
  else if (type=="elif") {
    if (ifstack.empty())
      preproc_error("elif without preceding if");
    if ((ifstack.back()&2)!=0)		// We have already seen an else clause
      preproc_error("elif follows else");
    if ((ifstack.back()&4)!=0)          // We have already seen a true elif clause
      ifstack.back() = 4;               // don't include any other elif clause
    else if ((ifstack.back()&1)!=0)     // Last clause was a true if
      ifstack.back() = 4;               // don't include this elif
    else {
      int4 truth = preprocess_if(s);
      if (!s.eof())
        preproc_error("Unbalanced parentheses");
      if (truth==0)
        ifstack.back() = 0;
      else
        ifstack.back() = 5;
    }
  }
  else if (type=="endif") {
    if (ifstack.empty())
      preproc_error("preprocessing endif without matching if");
    ifstack.pop_back();
    check_to_endofline(s);
  }
  else if (type=="else") {
    if (ifstack.empty())
      preproc_error("preprocessing else without matching if");
    if ((ifstack.back()&2)!=0)
      preproc_error("second else for one if");
    if ((ifstack.back()&4)!=0)       // Seen a true elif clause before
      ifstack.back() = 6;
    else if (ifstack.back()==0)
      ifstack.back() = 3;
    else
      ifstack.back() = 2;
    check_to_endofline(s);
  }
  else
    preproc_error("Unknown preprocessing directive: "+type);

  if (negative_if >= 0) {  // We were in a false state
    if (negative_if+1 < ifstack.size())
      return blank_state;  // false state is still deep in stack
    else                   // false state is popped off or is current and changed
      negative_if = -1;
  }
  if (ifstack.empty()) return last_preproc;
  if ((ifstack.back()&1)==0) {
    negative_if = ifstack.size()-1;
    return blank_state;
  }
  return last_preproc;
}

void preproc_macroexpand(void)

{
  filebuffers.push_back(FileStreamState());
  filebuffers.back().lastbuffer = YY_CURRENT_BUFFER;
  filebuffers.back().file = (FILE *)0;
  string macro(sleightext);
  macro.erase(0,2);
  macro.erase(macro.size()-1,1);
  string value;
  if (!slgh->getPreprocValue(macro,value))
    preproc_error("Unknown preprocessing macro "+macro);
  sleigh_switch_to_buffer( sleigh_scan_string( value.c_str() ) );
  slgh->parsePreprocMacro();
}

int4 find_symbol(void) {
  string * newstring = new string(sleightext);
  SleighSymbol *sym = slgh->findSymbol(*newstring);
  if (sym == (SleighSymbol *)0) {
    sleighlval.str = newstring;
    return STRING;
  }
  delete newstring;
  switch(sym->getType()) {
  case SleighSymbol::section_symbol:
    sleighlval.sectionsym = (SectionSymbol *)sym;
    return SECTIONSYM;
  case SleighSymbol::space_symbol:
    sleighlval.spacesym = (SpaceSymbol *)sym;
    return SPACESYM;
  case SleighSymbol::token_symbol:
    sleighlval.tokensym = (TokenSymbol *)sym;
    return TOKENSYM;
  case SleighSymbol::userop_symbol:
    sleighlval.useropsym = (UserOpSymbol *)sym;
    return USEROPSYM;
  case SleighSymbol::value_symbol:
    sleighlval.valuesym = (ValueSymbol *)sym;
    return VALUESYM;
  case SleighSymbol::valuemap_symbol:
    sleighlval.valuemapsym = (ValueMapSymbol *)sym;
    return VALUEMAPSYM;
  case SleighSymbol::name_symbol:
    sleighlval.namesym = (NameSymbol *)sym;
    return NAMESYM;
  case SleighSymbol::varnode_symbol:
    sleighlval.varsym = (VarnodeSymbol *)sym;
    return VARSYM;
  case SleighSymbol::bitrange_symbol:
    sleighlval.bitsym = (BitrangeSymbol *)sym;
    return BITSYM;
  case SleighSymbol::varnodelist_symbol:
    sleighlval.varlistsym = (VarnodeListSymbol *)sym;
    return VARLISTSYM;
  case SleighSymbol::operand_symbol:
    sleighlval.operandsym = (OperandSymbol *)sym;
    return OPERANDSYM;
  case SleighSymbol::start_symbol:
    sleighlval.startsym = (StartSymbol *)sym;
    return STARTSYM;
  case SleighSymbol::end_symbol:
    sleighlval.endsym = (EndSymbol *)sym;
    return ENDSYM;
  case SleighSymbol::next2_symbol:
    sleighlval.next2sym = (Next2Symbol *)sym;
    return NEXT2SYM;
  case SleighSymbol::subtable_symbol:
    sleighlval.subtablesym = (SubtableSymbol *)sym;
    return SUBTABLESYM;
  case SleighSymbol::macro_symbol:
    sleighlval.macrosym = (MacroSymbol *)sym;
    return MACROSYM;
  case SleighSymbol::label_symbol:
    sleighlval.labelsym = (LabelSymbol *)sym;
    return LABELSYM;
  case SleighSymbol::epsilon_symbol:
    sleighlval.specsym = (SpecificSymbol *)sym;
    return SPECSYM;
  case SleighSymbol::context_symbol:
    sleighlval.contextsym = (ContextSymbol *)sym;
    return CONTEXTSYM;
  case SleighSymbol::dummy_symbol:
    break;
  }
  return -1;   // Should never reach here
}

int4 scan_number(char *numtext,SLEIGHSTYPE *lval,bool signednum)

{
  uintb val;
  if (numtext[0] == '0' && numtext[1] == 'b') {
    val = 0;
    numtext += 2;
    while ((*numtext) != 0) {
      val <<= 1;
      if (*numtext == '1') {
        val |= 1;
      }
      ++numtext;
    }
  } else {
    istringstream s(numtext);
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> val;
    if (!s)
      return BADINTEGER;
  }
  if (signednum) {
    lval->big = new intb(val);
    return INTB;
  }
  lval->i = new uintb(val);
  return INTEGER;
}

} // End namespace ghidra

using namespace ghidra;

%}

%x defblock
%x macroblock
%x print
%x pattern
%x sem
%x preproc
%%

^@[^\n]*\n?  { slgh->nextLine(); BEGIN( preprocess(INITIAL,preproc) ); }
\$\([a-zA-Z0-9_.][a-zA-Z0-9_.]*\)  { preproc_macroexpand(); }
[(),\-] { sleighlval.ch = sleightext[0]; return sleightext[0]; }
\:    { BEGIN(print); slgh->calcContextLayout(); sleighlval.ch = sleightext[0]; return sleightext[0]; }
\{    { BEGIN(sem); sleighlval.ch = sleightext[0]; return sleightext[0]; }
#.*
[\r\ \t\v]+
\n             { slgh->nextLine(); }
macro  { BEGIN(macroblock); return MACRO_KEY; }
define { BEGIN(defblock); return DEFINE_KEY; }
attach { BEGIN(defblock); slgh->calcContextLayout(); return ATTACH_KEY; }
with   { BEGIN(pattern); withsection = 1; slgh->calcContextLayout(); return WITH_KEY; }
[a-zA-Z_.][a-zA-Z0-9_.]* {  return find_symbol();  }
.      { return sleightext[0]; }

<macroblock>^@[^\n]*\n?  { slgh->nextLine(); BEGIN( preprocess(macroblock,preproc) ); }
<macroblock>\$\([a-zA-Z0-9_.][a-zA-Z0-9_.]*\)  { preproc_macroexpand(); }
<macroblock>[(),]  { sleighlval.ch = sleightext[0]; return sleightext[0]; }
<macroblock>\{     { BEGIN(sem); return sleightext[0]; }
<macroblock>[a-zA-Z_.][a-zA-Z0-9_.]*   {  sleighlval.str = new string(sleightext); return STRING;  }
<macroblock>[\r\ \t\v]+
<macroblock>\n     { slgh->nextLine(); }
<macroblock>.      { return sleightext[0]; }

<defblock>^@[^\n]*\n?  { slgh->nextLine(); BEGIN( preprocess(defblock,preproc) ); }
<defblock>\$\([a-zA-Z0-9_.][a-zA-Z0-9_.]*\)  { preproc_macroexpand(); }
<defblock>[(),=:\[\]]  { sleighlval.ch = sleightext[0]; return sleightext[0]; }
<defblock>\;   { BEGIN(INITIAL); sleighlval.ch = sleightext[0]; return sleightext[0]; }
<defblock>space     { return SPACE_KEY; }
<defblock>type      { return TYPE_KEY; }
<defblock>ram_space { return RAM_KEY; }
<defblock>default   { return DEFAULT_KEY; }
<defblock>register_space  { return REGISTER_KEY; }
<defblock>token     { return TOKEN_KEY; }
<defblock>context   { return CONTEXT_KEY; }
<defblock>bitrange  { return BITRANGE_KEY; }
<defblock>signed    { return SIGNED_KEY; }
<defblock>noflow    { return NOFLOW_KEY; }
<defblock>hex       { return HEX_KEY; }
<defblock>dec       { return DEC_KEY; }
<defblock>endian    { return ENDIAN_KEY; }
<defblock>alignment { return ALIGN_KEY; }
<defblock>big       { return BIG_KEY; }
<defblock>little    { return LITTLE_KEY; }
<defblock>size      { return SIZE_KEY; }
<defblock>wordsize  { return WORDSIZE_KEY; }
<defblock>offset    { return OFFSET_KEY; }
<defblock>names     { return NAMES_KEY; }
<defblock>values    { return VALUES_KEY; }
<defblock>variables { return VARIABLES_KEY; }
<defblock>pcodeop   { return PCODEOP_KEY; }
<defblock>#.*
<defblock>[a-zA-Z_.][a-zA-Z0-9_.]* {  return find_symbol();  }
<defblock>[0-9]|[1-9][0-9]+	{ return scan_number(sleightext,&sleighlval,false); }
<defblock>0x[0-9a-fA-F]+	{ return scan_number(sleightext,&sleighlval,false); }
<defblock>0b[01]+		{ return scan_number(sleightext,&sleighlval,false); }
<defblock>\"([^\"[:cntrl:]]|\"\")*\"	{ sleighlval.str = new string(sleightext+1,strlen(sleightext)-2); return STRING; }
<defblock>[\r\ \t\v]+
<defblock>\n        { slgh->nextLine(); }
<defblock>.         { return sleightext[0]; }


<print>^@[^\n]*\n?  { slgh->nextLine(); BEGIN( preprocess(print,preproc) ); }
<print>\$\([a-zA-Z0-9_.][a-zA-Z0-9_.]*\)  { preproc_macroexpand(); }
<print>[~!@#$%&*()\-=+\[\]{}|;:<>?,/0-9] { sleighlval.ch = sleightext[0]; return CHAR; }
<print>\^           { sleighlval.ch = '^'; return '^'; }
<print>is           { BEGIN(pattern); actionon=0; return IS_KEY; }
<print>[a-zA-Z_.][a-zA-Z0-9_.]*   {  sleighlval.str = new string(sleightext); return SYMBOLSTRING;  }
<print>\"([^\"[:cntrl:]]|\"\")*\"       { sleighlval.str = new string(sleightext+1,strlen(sleightext)-2); return STRING; }
<print>[\r\ \t\v]+  { sleighlval.ch = ' '; return ' '; }
<print>\n           { slgh->nextLine(); return ' '; }
<print>.            { return sleightext[0]; }

<pattern>^@[^\n]*\n?  { slgh->nextLine(); BEGIN( preprocess(pattern,preproc) ); }
<pattern>\$\([a-zA-Z0-9_.][a-zA-Z0-9_.]*\)  { preproc_macroexpand(); }
<pattern>\{         { BEGIN((withsection==1) ? INITIAL:sem); withsection=0; sleighlval.ch = sleightext[0]; return sleightext[0]; }
<pattern>unimpl     { BEGIN(INITIAL); return OP_UNIMPL; }
<pattern>globalset  { return GLOBALSET_KEY; }
<pattern>\>\>       { return OP_RIGHT; }
<pattern>\<\<       { return OP_LEFT; }
<pattern>\!\=       { return OP_NOTEQUAL; }
<pattern>\<\=       { return OP_LESSEQUAL; }
<pattern>\>\=       { return OP_GREATEQUAL; }
<pattern>\$and      { return OP_AND; }
<pattern>\$or       { return OP_OR; }
<pattern>\$xor      { return OP_XOR; }
<pattern>\.\.\.     { return ELLIPSIS_KEY; }
<pattern>\[         { actionon = 1; sleighlval.ch = sleightext[0]; return sleightext[0]; }
<pattern>\]         { actionon = 0; sleighlval.ch = sleightext[0]; return sleightext[0]; }
<pattern>\&         { sleighlval.ch = sleightext[0];  return (actionon==0) ? sleightext[0] : OP_AND; }
<pattern>\|         { sleighlval.ch = sleightext[0];  return (actionon==0) ? sleightext[0] : OP_OR; }
<pattern>\^         { return OP_XOR; }
<pattern>[=(),:;+\-*/~<>]   { sleighlval.ch = sleightext[0]; return sleightext[0]; }
<pattern>#.*
<pattern>[a-zA-Z_.][a-zA-Z0-9_.]*   { return find_symbol();   }
<pattern>[0-9]|[1-9][0-9]+ { return scan_number(sleightext,&sleighlval,true); }
<pattern>0x[0-9a-fA-F]+  { return scan_number(sleightext,&sleighlval,true); }
<pattern>0b[01]+         { return scan_number(sleightext,&sleighlval,true); }
<pattern>[\r\ \t\v]+
<pattern>\n        { slgh->nextLine(); }
<pattern>.         { return sleightext[0]; }

<sem>^@[^\n]*\n?   { slgh->nextLine(); BEGIN( preprocess(sem,preproc) ); }
<sem>\$\([a-zA-Z0-9_.][a-zA-Z0-9_.]*\)  { preproc_macroexpand(); }
<sem>\}            { BEGIN(INITIAL); sleighlval.ch = sleightext[0]; return sleightext[0]; }
<sem>\|\|          { return OP_BOOL_OR; }
<sem>\&\&          { return OP_BOOL_AND; }
<sem>\^\^          { return OP_BOOL_XOR; }
<sem>\>\>          { return OP_RIGHT; }
<sem>\<\<          { return OP_LEFT; }
<sem>\=\=          { return OP_EQUAL; }
<sem>\!\=          { return OP_NOTEQUAL; }
<sem>\<\=          { return OP_LESSEQUAL; }
<sem>\>\=          { return OP_GREATEQUAL; }
<sem>s\/           { return OP_SDIV; }
<sem>s\%           { return OP_SREM; }
<sem>s\>\>         { return OP_SRIGHT; }
<sem>s\<           { return OP_SLESS; }
<sem>s\>           { return OP_SGREAT; }
<sem>s\<\=         { return OP_SLESSEQUAL; }
<sem>s\>\=         { return OP_SGREATEQUAL; }
<sem>f\+           { return OP_FADD; }
<sem>f\-           { return OP_FSUB; }
<sem>f\*           { return OP_FMULT; }
<sem>f\/           { return OP_FDIV; }
<sem>f\=\=         { return OP_FEQUAL; }
<sem>f\!\=         { return OP_FNOTEQUAL; }
<sem>f\<           { return OP_FLESS; }
<sem>f\>           { return OP_FGREAT; }
<sem>f\<\=         { return OP_FLESSEQUAL; }
<sem>f\>\=         { return OP_FGREATEQUAL; }
<sem>zext          { return OP_ZEXT; }
<sem>carry         { return OP_CARRY; }
<sem>borrow        { return OP_BORROW; }
<sem>sext          { return OP_SEXT; }
<sem>scarry        { return OP_SCARRY; }
<sem>sborrow       { return OP_SBORROW; }
<sem>nan           { return OP_NAN; }
<sem>abs           { return OP_ABS; }
<sem>sqrt          { return OP_SQRT; }
<sem>ceil          { return OP_CEIL; }
<sem>floor         { return OP_FLOOR; }
<sem>round         { return OP_ROUND; }
<sem>int2float     { return OP_INT2FLOAT; }
<sem>float2float   { return OP_FLOAT2FLOAT; }
<sem>trunc         { return OP_TRUNC; }
<sem>cpool         { return OP_CPOOLREF; }
<sem>newobject     { return OP_NEW; }
<sem>popcount      { return OP_POPCOUNT; }
<sem>lzcount       { return OP_LZCOUNT; }
<sem>if            { return IF_KEY; }
<sem>goto          { return GOTO_KEY; }
<sem>call          { return CALL_KEY; }
<sem>return        { return RETURN_KEY; }
<sem>delayslot     { return DELAYSLOT_KEY; }
<sem>crossbuild    { return CROSSBUILD_KEY; }
<sem>export        { return EXPORT_KEY; }
<sem>build         { return BUILD_KEY; }
<sem>local         { return LOCAL_KEY; }
<sem>[=(),:\[\];!&|^+\-*/%~<>]   { sleighlval.ch = sleightext[0]; return sleightext[0]; }
<sem>#.*
<sem>[a-zA-Z_.][a-zA-Z0-9_.]*   { return find_symbol();   }
<sem>[0-9]|[1-9][0-9]+ { return scan_number(sleightext,&sleighlval,false); }
<sem>0x[0-9a-fA-F]+  { return scan_number(sleightext,&sleighlval,false); }
<sem>0b[01]+         { return scan_number(sleightext,&sleighlval,false); }
<sem>[\r\ \t\v]+
<sem>\n         { slgh->nextLine(); }
<sem>.          { return sleightext[0]; }

<preproc>^@.*\n?  { slgh->nextLine(); BEGIN( preprocess(preproc,preproc) ); }
<preproc>^.*\n    { slgh->nextLine(); }

<<EOF>> { sleigh_delete_buffer( YY_CURRENT_BUFFER );
          if (filebuffers.empty())
            yyterminate(); 
          sleigh_switch_to_buffer( filebuffers.back().lastbuffer );
	  FILE *curfile = filebuffers.back().file;
	  if (curfile != (FILE *)0)
	    fclose(curfile);
          filebuffers.pop_back();
          slgh->parseFileFinished();
        }

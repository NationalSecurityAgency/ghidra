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
#include "xml.hh"
// CharData mode   look for '<' '&' or "]]>"
// Name mode       look for non-name char
// CData mode      looking for "]]>"
// Entity mode     looking for ending ';'
// AttValue mode   looking for endquote  or '&'
// Comment mode    looking for "--"

#include <iostream>
#include <string>

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

extern int yylex(void);							///< Interface to the scanner
extern int yyerror(const char *str);			///< Interface for registering an error in parsing
extern void print_content(const string &str);	///< Send character data to the ContentHandler
extern int4 convertEntityRef(const string &ref);	///< Convert an XML entity to its equivalent character
extern int4 convertCharRef(const string &ref);	///< Convert an XML character reference to its equivalent character
static XmlScan *global_scan;					///< Global reference to the scanner
static ContentHandler *handler;					///< Global reference to the content handler
extern int yydebug;								///< Debug mode
%}

%union {
  int4 i;
  string *str;
  Attributes *attr;
  NameValue *pair;
}

%expect 8

%token <str> CHARDATA CDATA ATTVALUE COMMENT CHARREF NAME SNAME ELEMBRACE COMMBRACE
%type <str> AttValue attsinglemid attdoublemid ETag CDSect CharRef EntityRef
%type <i> Reference
%type <attr> EmptyElemTag STag stagstart
%type <pair> SAttribute
%%

document:  element Misc;
	   | prolog element Misc;
whitespace: ' '
	    | '\n'
	    | '\r'
	    | '\t';
S: whitespace
   | S whitespace ;

attsinglemid: '\'' { $$ = new string; global_scan->setmode(XmlScan::AttValueSingleMode); }
	      | attsinglemid ATTVALUE { $$ = $1; *$$ += *$2; delete $2; global_scan->setmode(XmlScan::AttValueSingleMode); }
	      | attsinglemid Reference { $$ = $1; *$$ += $2; global_scan->setmode(XmlScan::AttValueSingleMode); };
attdoublemid: '"' { $$ = new string; global_scan->setmode(XmlScan::AttValueDoubleMode); }
	      | attdoublemid ATTVALUE { $$ = $1; *$$ += *$2; delete $2; global_scan->setmode(XmlScan::AttValueDoubleMode); }
	      | attdoublemid Reference { $$ = $1; *$$ += $2; global_scan->setmode(XmlScan::AttValueDoubleMode); };
AttValue: attsinglemid '\'' { $$ = $1; }
	  | attdoublemid '"' { $$ = $1; };
elemstart: ELEMBRACE { global_scan->setmode(XmlScan::NameMode); delete $1; };
commentstart: COMMBRACE '!' '-' '-' { global_scan->setmode(XmlScan::CommentMode); delete $1; } ;
Comment: commentstart COMMENT '-' '-' '>' { delete $2; } ;
PI: COMMBRACE '?' { delete $1; yyerror("Processing instructions are not supported"); YYERROR; };
CDSect: CDStart CDATA CDEnd { $$ = $2; } ;
CDStart: COMMBRACE '!' '[' 'C' 'D' 'A' 'T' 'A' '[' { global_scan->setmode(XmlScan::CDataMode); delete $1; } ;
CDEnd: ']' ']' '>' ;

doctypepro: doctypedecl
	    | doctypepro Misc;
prologpre: XMLDecl
	   | Misc
	   | prologpre Misc;
prolog: prologpre doctypepro
	| prologpre ;

doctypedecl: COMMBRACE '!' 'D' 'O' 'C' 'T' 'Y' 'P' 'E' { delete $1; yyerror("DTD's not supported"); YYERROR; };
Eq: '='
    | S '='
    | Eq S ;
Misc: Comment
      | PI
      | S ;
      
VersionInfo: S 'v' 'e' 'r' 's' 'i' 'o' 'n' Eq AttValue { handler->setVersion(*$10); delete $10; };
EncodingDecl: S 'e' 'n' 'c' 'o' 'd' 'i' 'n' 'g' Eq AttValue { handler->setEncoding(*$11); delete $11; };
xmldeclstart: COMMBRACE '?' 'x' 'm' 'l' VersionInfo
XMLDecl: xmldeclstart '?' '>'
       | xmldeclstart S '?' '>'
       | xmldeclstart EncodingDecl '?' '>'
       | xmldeclstart EncodingDecl S '?' '>' ;

element: EmptyElemTag { handler->endElement($1->getelemURI(),$1->getelemName(),$1->getelemName()); delete $1; }
	 | STag content ETag { handler->endElement($1->getelemURI(),$1->getelemName(),$1->getelemName()); delete $1; delete $3; } ;

STag: stagstart '>' { handler->startElement($1->getelemURI(),$1->getelemName(),$1->getelemName(),*$1); $$ = $1; }
      | stagstart S '>' { handler->startElement($1->getelemURI(),$1->getelemName(),$1->getelemName(),*$1); $$ = $1; };
EmptyElemTag: stagstart '/' '>' { handler->startElement($1->getelemURI(),$1->getelemName(),$1->getelemName(),*$1); $$ = $1; }
	      | stagstart S '/' '>' { handler->startElement($1->getelemURI(),$1->getelemName(),$1->getelemName(),*$1); $$ = $1; };

stagstart: elemstart NAME { $$ = new Attributes($2); global_scan->setmode(XmlScan::SNameMode); }
	   | stagstart SAttribute { $$ = $1; $$->add_attribute( $2->name, $2->value); delete $2; global_scan->setmode(XmlScan::SNameMode); };
SAttribute: SNAME Eq AttValue { $$ = new NameValue; $$->name = $1; $$->value = $3; };
etagbrace: COMMBRACE '/' { global_scan->setmode(XmlScan::NameMode); delete $1; };
ETag: etagbrace NAME '>' { $$ = $2; }
      | etagbrace NAME S '>' { $$ = $2; };

content: { global_scan->setmode(XmlScan::CharDataMode); }
	 | content CHARDATA { print_content( *$2 ); delete $2; global_scan->setmode(XmlScan::CharDataMode); }
	 | content element { global_scan->setmode(XmlScan::CharDataMode); }
	 | content Reference { string *tmp=new string(); *tmp += $2; print_content(*tmp); delete tmp; global_scan->setmode(XmlScan::CharDataMode); }
	 | content CDSect { print_content( *$2 ); delete $2; global_scan->setmode(XmlScan::CharDataMode); }
	 | content PI { global_scan->setmode(XmlScan::CharDataMode); }
	 | content Comment { global_scan->setmode(XmlScan::CharDataMode); };

Reference: EntityRef { $$ = convertEntityRef(*$1); delete $1; }
	   | CharRef { $$ = convertCharRef(*$1); delete $1; };

refstart: '&' { global_scan->setmode(XmlScan::NameMode); } ;
charrefstart: refstart '#' { global_scan->setmode(XmlScan::CharRefMode); };
CharRef: charrefstart CHARREF ';' { $$ = $2; };
EntityRef: refstart NAME ';' { $$ = $2; };
%%

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

int yylex(void)

{
  int res = global_scan->nexttoken();
  if (res>255)
    yylval.str = global_scan->lval();
  return res;
}

int yyerror(const char *str)

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
  throw XmlError("Unknown attribute: "+nm);
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
    throw XmlError("Unable to open xml document "+filename);
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
    throw XmlError(handle.getError());
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

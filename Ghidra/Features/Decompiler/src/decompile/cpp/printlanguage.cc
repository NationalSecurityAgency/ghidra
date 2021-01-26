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
#include <ctype.h>
#include "printlanguage.hh"
#include "funcdata.hh"

vector<PrintLanguageCapability *> PrintLanguageCapability::thelist;

/// This retrieves the capability with its \b isdefault field set or
/// the first capability registered.
/// \return the default language capability
PrintLanguageCapability *PrintLanguageCapability::getDefault(void)

{
  if (thelist.size() == 0)
    throw LowlevelError("No print languages registered");
  return thelist[0];
}

void PrintLanguageCapability::initialize(void)

{
  if (isdefault)
    thelist.insert(thelist.begin(),this);	// Default goes at beginning
  else
    thelist.push_back(this);
}

/// \param name is the language name to search for
/// \return the matching language capability or NULL
PrintLanguageCapability *PrintLanguageCapability::findCapability(const string &name)

{
  for(uint4 i=0;i<thelist.size();++i) {
    PrintLanguageCapability *plc = thelist[i];
    if (plc->getName() == name)
      return plc;
  }
  return (PrintLanguageCapability *)0;
}

/// \param g is the Architecture that owns and will use this PrintLanguage
/// \param nm is the formal name of the language
PrintLanguage::PrintLanguage(Architecture *g,const string &nm)

{
  glb = g;
  castStrategy = (CastStrategy *)0;
  name = nm;
  curscope = (Scope *)0;
  emit = new EmitPrettyPrint();

  pending = 0;
  resetDefaultsInternal();
}

PrintLanguage::~PrintLanguage(void)

{
  delete emit;
  if (castStrategy != (CastStrategy *)0)
    delete castStrategy;
}

/// \param val is the number of characters
void PrintLanguage::setLineCommentIndent(int4 val)

{
  if ((val<0)||(val >= emit->getMaxLineSize()))
    throw LowlevelError("Bad comment indent value");
  line_commentindent = val;
}

/// By default, comments are indicated in the high-level language by preceding
/// them with a specific sequence of delimiter characters, and optionally
/// by ending the comment with another set of delimiter characters.
/// \param start is the initial sequence of characters delimiting a comment
/// \param stop if not empty is the sequence delimiting the end of the comment
/// \param usecommentfill is \b true if the delimiter needs to be emitted after every line break
void PrintLanguage::setCommentDelimeter(const string &start,const string &stop,bool usecommentfill)

{
  commentstart = start;
  commentend = stop;
  if (usecommentfill)
    emit->setCommentFill(start);
  else {
    string spaces;
    for(int4 i=0;i<start.size();++i)
      spaces += ' ';
    emit->setCommentFill(spaces);
  }
}

void PrintLanguage::popScope(void)

{
  scopestack.pop_back();
  if (scopestack.empty())
    curscope = (Scope *)0;
  else
    curscope = scopestack.back();
}

/// This generally will recursively push an entire expression onto the RPN stack,
/// up to Varnode objects marked as \e explicit, and will decide token order
/// and parenthesis placement. As the ordering gets resolved,
/// some amount of the expression may get emitted.
/// \param tok is the operator token to push
/// \param op is the PcodeOp associated with the token
void PrintLanguage::pushOp(const OpToken *tok,const PcodeOp *op)

{
  if (pending < nodepend.size()) // Pending varnode pushes before op
    recurse();			// So we must recurse

  bool paren;
  int4 id;

  if (revpol.empty()) {
    paren = false;
    id = emit->openGroup();
  }
  else {
    emitOp(revpol.back());
    paren = parentheses(tok);
    if (paren)
      id = emit->openParen('(');
    else
      id = emit->openGroup();
  }
  revpol.emplace_back();
  revpol.back().tok = tok;
  revpol.back().visited = 0;
  revpol.back().paren = paren;
  revpol.back().op = op;
  revpol.back().id = id;
}

/// Push a single token (an Atom) onto the RPN stack. This may trigger some amount
/// of the RPN stack to get emitted, depending on what was pushed previously.
/// The 'emit' routines are called, popping off as much as possible.
/// \param atom is the token to be pushed
void PrintLanguage::pushAtom(const Atom &atom)

{
  if (pending < nodepend.size()) // pending varnodes before atom
    recurse();			// So we must recurse

  if (revpol.empty())
    emitAtom(atom);
  else {
    emitOp(revpol.back());
    emitAtom(atom);
    do {
      revpol.back().visited += 1;
      if (revpol.back().visited == revpol.back().tok->stage) {
	emitOp(revpol.back());
	if (revpol.back().paren)
	  emit->closeParen(')',revpol.back().id);
	else
	  emit->closeGroup(revpol.back().id);
	revpol.pop_back();
      }
      else
	break;
    } while(!revpol.empty());
  }
}

/// For a given implied Varnode, the entire expression producing it is
/// recursively pushed onto the RPN stack.
///
/// When calling this method multiple times to push Varnode inputs for a
/// single p-code op, the inputs must be pushed in reverse order.
/// \param vn is the given implied Varnode
/// \param op is PcodeOp taking the Varnode as input
/// \param m is the set of printing modifications to apply for this sub-expression
void PrintLanguage::pushVnImplied(const Varnode *vn,const PcodeOp *op,uint4 m)

{
//   if (pending == nodepend.size())
//     nodepend.push_back(NodePending(vn,op,m));
//   else {
//     nodepend.push_back(NodePending());
//     for(i=vnvec.size()-1;i>pending;--i)
//       nodepend[i] = nodepend[i-1];
//     nodepend[pending] = NodePending(vn,op,m);
//   }

  // But it is more efficient to just call them in reverse order
  nodepend.push_back(NodePending(vn,op,m));
}

/// This method pushes a given Varnode as a \b leaf of the current expression.
/// It decides how the Varnode should get emitted, as a symbol, constant, etc.,
/// and then pushes the resulting leaf Atom onto the stack.
/// \param vn is the given explicit Varnode
/// \param op is the PcodeOp incorporating the Varnode into the current expression
void PrintLanguage::pushVnExplicit(const Varnode *vn,const PcodeOp *op)

{
  if (vn->isAnnotation()) {
    pushAnnotation(vn,op);
    return;
  }
  HighVariable *high = vn->getHigh();
  if (vn->isConstant()) {
    pushConstant(vn->getOffset(),high->getType(),vn,op);
    return;
  }
  Symbol *sym = high->getSymbol();
  if (sym == (Symbol *)0) {
    pushUnnamedLocation(high->getNameRepresentative()->getAddr(),vn,op);
  }
  else {
    int4 symboloff = high->getSymbolOffset();
    if (symboloff == -1)
      pushSymbol(sym,vn,op);
    else {
      if (symboloff + vn->getSize() <= sym->getType()->getSize())
	pushPartialSymbol(sym,symboloff,vn->getSize(),vn,op,vn->getHigh()->getType());
      else
	pushMismatchSymbol(sym,symboloff,vn->getSize(),vn,op);
    }
  }
}

/// The given Varnode will ultimately be emitted as an explicit variable on
/// the left-hand side of an \e assignment statement. As with pushVnExplicit(),
/// this method decides how the Varnode will be emitted and pushes the resulting
/// Atom onto the RPN stack.
/// \param vn is the given LSH Varnode
/// \param op is the PcodeOp which produces the Varnode as an output
void PrintLanguage::pushVnLHS(const Varnode *vn,const PcodeOp *op)

{
  HighVariable *high = vn->getHigh();
  Symbol *sym = high->getSymbol();
  if (sym == (Symbol *)0) {
    pushUnnamedLocation(high->getNameRepresentative()->getAddr(),vn,op);
  }
  else {
    int4 symboloff = high->getSymbolOffset();
    if (symboloff == -1)
      pushSymbol(sym,vn,op);
    else {
      if (symboloff + vn->getSize() <= sym->getType()->getSize())
	pushPartialSymbol(sym,symboloff,vn->getSize(),vn,op,(Datatype *)0);
      else
	pushMismatchSymbol(sym,symboloff,vn->getSize(),vn,op);
    }
  }
}

/// The token at the top of the stack is being emitted. Check if its input expression,
/// ending with the given operator token, needs to be surrounded by parentheses to convey
/// the proper meaning.
/// \param op2 is the input token to \b this operator
/// \return \b true if \b op2 (as input to \b this) should be parenthesized
bool PrintLanguage::parentheses(const OpToken *op2)

{
  ReversePolish &top( revpol.back() );
  const OpToken *topToken = top.tok;
  int4 stage = top.visited;
  switch(topToken->type) {
  case OpToken::space:
  case OpToken::binary:
    if (topToken->precedence > op2->precedence) return true;
    if (topToken->precedence < op2->precedence) return false;
    if (topToken->associative && (topToken == op2)) return false;
    // If operators are adjacent to each other, the
    // operator printed first must be evaluated first
    // In this case op2 must be evaluated first, so we
    // check if it is printed first (in first stage of binary)
    if ((op2->type==OpToken::postsurround)&&(stage==0)) return false;
    return true;
  case OpToken::unary_prefix:
    if (topToken->precedence > op2->precedence) return true;
    if (topToken->precedence < op2->precedence) return false;
    //    if (associative && (this == &op2)) return false;
    if ((op2->type==OpToken::unary_prefix)||(op2->type==OpToken::presurround)) return false;
    return true;
  case OpToken::postsurround:
    if (stage==1) return false;	// Inside the surround
    if (topToken->precedence > op2->precedence) return true;
    if (topToken->precedence < op2->precedence) return false;
    // If the precedences are equal, we know this postsurround
    // comes after, so op2 being first doesn't need parens
    if ((op2->type==OpToken::postsurround)||(op2->type==OpToken::binary)) return false;
    //    if (associative && (this == &op2)) return false;
    return true;
  case OpToken::presurround:
    if (stage==0) return false;	// Inside the surround
    if (topToken->precedence > op2->precedence) return true;
    if (topToken->precedence < op2->precedence) return false;
    //    if (associative && (this == &op2)) return false;
    if ((op2->type==OpToken::unary_prefix)||(op2->type==OpToken::presurround)) return false;
    return true;
  case OpToken::hiddenfunction:
    if ((stage==0)&&(revpol.size() > 1)) {	// If there is an unresolved previous token
      // New token is printed next to the previous token.
      const OpToken *prevToken = revpol[revpol.size()-2].tok;
      if (prevToken->type != OpToken::binary && prevToken->type != OpToken::unary_prefix)
	return false;
      if (prevToken->precedence < op2->precedence) return false;
      // If precedence is equal, make sure we don't treat two tokens as associative,
      // i.e. we should have parentheses
    }
    return true;
  }

  return true;
}

/// An OpToken directly from the RPN is sent to the low-level emitter,
/// resolving any final spacing or parentheses.
/// \param entry is the RPN entry to be emitted
void PrintLanguage::emitOp(const ReversePolish &entry)

{
  switch(entry.tok->type) {
  case OpToken::binary:
    if (entry.visited!=1) return;
    emit->spaces(entry.tok->spacing,entry.tok->bump); // Spacing around operator
    emit->tagOp(entry.tok->print,EmitXml::no_color,entry.op);
    emit->spaces(entry.tok->spacing,entry.tok->bump);
    break;
  case OpToken::unary_prefix:
    if (entry.visited!=0) return;
    emit->tagOp(entry.tok->print,EmitXml::no_color,entry.op);
    emit->spaces(entry.tok->spacing,entry.tok->bump);
    break;
  case OpToken::postsurround:
    if (entry.visited==0) return;
    if (entry.visited==1) {	// Front surround token 
      emit->spaces(entry.tok->spacing,entry.tok->bump);
      entry.id2 = emit->openParen(entry.tok->print[0]);
      emit->spaces(0,entry.tok->bump);
    }
    else {			// Back surround token
      emit->closeParen(entry.tok->print[1],entry.id2);
    }
    break;
  case OpToken::presurround:
    if (entry.visited==2) return;
    if (entry.visited==0) {	// Front surround token 
      entry.id2 = emit->openParen(entry.tok->print[0]);
    }
    else {			// Back surround token
      emit->closeParen(entry.tok->print[1],entry.id2);
      emit->spaces(entry.tok->spacing,entry.tok->bump);
    }
    break;
  case OpToken::space:	       // Like binary but just a space between
    if (entry.visited != 1) return;
    emit->spaces(entry.tok->spacing,entry.tok->bump);
    break;
  case OpToken::hiddenfunction:
    return;			// Never directly prints anything
  }
}

/// Send the given Atom to the low-level emitter, marking it up according to its type
/// \param atom is the given Atom to emit
void PrintLanguage::emitAtom(const Atom &atom)

{
  switch(atom.type) {
  case syntax:
    emit->print(atom.name.c_str(),atom.highlight);
    break;
  case vartoken:
    emit->tagVariable(atom.name.c_str(),atom.highlight,
		      atom.ptr_second.vn,atom.op);
    break;
  case functoken:
    emit->tagFuncName(atom.name.c_str(),atom.highlight,
		      atom.ptr_second.fd,atom.op);
    break;
  case optoken:
    emit->tagOp(atom.name.c_str(),atom.highlight,atom.op);
    break;
  case typetoken:
    emit->tagType(atom.name.c_str(),atom.highlight,atom.ptr_second.ct);
    break;
  case fieldtoken:
    emit->tagField(atom.name.c_str(),atom.highlight,atom.ptr_second.ct,atom.offset);
    break;
  case blanktoken:
    break;			// Print nothing
  }
}

/// Separate unicode characters that can be clearly emitted in a source code string
/// (letters, numbers, punctuation, symbols) from characters that are better represented
/// in source code with an escape sequence (control characters, unusual spaces, separators,
/// private use characters etc.
/// \param codepoint is the given unicode codepoint to categorize.
/// \return \b true if the codepoint needs to be escaped
bool PrintLanguage::unicodeNeedsEscape(int4 codepoint)

{
  if (codepoint < 0x20) {	// C0 Control characters
    return true;
  }
  if (codepoint < 0x7F) {	// Printable ASCII
    switch(codepoint) {
    case 92:			// back-slash
    case '"':
    case '\'':
      return true;
    }
    return false;
  }
  if (codepoint < 0x100) {
    if (codepoint > 0xa0) {	// Printable codepoints  A1-FF
      return false;
    }
    return true;
  }
  if (codepoint >= 0x2fa20) {	// Up to last currently defined language
    return true;
  }
  if (codepoint < 0x2000) {
    if (codepoint >= 0x180b && codepoint <= 0x180e) {
      return true;			// Mongolian separators
    }
    if (codepoint == 0x61c) {
      return true;			// arabic letter mark
    }
    if (codepoint == 0x1680) {
      return true;			// ogham space mark
    }
    return false;
  }
  if (codepoint < 0x3000) {
    if (codepoint < 0x2010) {
      return true;			// white space and separators
    }
    if (codepoint >= 0x2028 && codepoint <= 0x202f) {
      return true;			// white space and separators
    }
    if (codepoint == 0x205f || codepoint == 0x2060) {
      return true;			// white space and word joiner
    }
    if (codepoint >= 0x2066 && codepoint <= 0x206f) {
      return true;			// bidirectional markers
    }
    return false;
  }
  if (codepoint < 0xe000) {
    if (codepoint == 0x3000) {
      return true;			// ideographic space
    }
    if (codepoint >= 0xd7fc) {		// D7FC - D7FF are currently unassigned.
					// D800 - DFFF are high and low surrogates, technically illegal.
      return true;			// Treat as needing to be escaped
    }
    return false;
  }
  if (codepoint < 0xf900) {
    return true;			// private use
  }
  if (codepoint >= 0xfe00 && codepoint <= 0xfe0f) {
    return true;			// variation selectors
  }
  if (codepoint == 0xfeff) {
    return true;			// zero width non-breaking space
  }
  if (codepoint >= 0xfff0 && codepoint <= 0xffff) {
    return true;			// interlinear specials
  }
  return false;
}

/// \brief Emit a byte buffer to the stream as unicode characters.
///
/// Characters are emitted until we reach a terminator character or \b count bytes is consumed.
/// \param s is the output stream
/// \param buf is the byte buffer
/// \param count is the maximum number of bytes to consume
/// \param charsize is 1 for UTF8, 2 for UTF16, or 4 for UTF32
/// \param bigend is \b true for a big endian encoding of UTF elements
/// \return \b true if we reach a terminator character
bool PrintLanguage::escapeCharacterData(ostream &s,const uint1 *buf,int4 count,int4 charsize,bool bigend) const

{
  int4 i=0;
  int4 skip = charsize;
  int4 codepoint = 0;
  while(i<count) {
    codepoint = StringManager::getCodepoint(buf+i,charsize,bigend,skip);
    if (codepoint == 0 || codepoint == -1) break;
    printUnicode(s,codepoint);
    i += skip;
  }
  return (codepoint == 0);
}

/// Any complete sub-expressions that are still on the RPN will get emitted.
void PrintLanguage::recurse(void)

{
  uint4 modsave = mods;
  int4 final = pending;		// Already claimed
  pending = nodepend.size();	// Lay claim to the rest
  while(final < pending) {
    const Varnode *vn = nodepend.back().vn;
    const PcodeOp *op = nodepend.back().op;
    mods = nodepend.back().vnmod;
    nodepend.pop_back();
    pending -= 1;
    if (vn->isImplied()) {
      const PcodeOp *defOp = vn->getDef();
      defOp->getOpcode()->push(this,defOp,op);
    }
    else
      pushVnExplicit(vn,op);
    pending = nodepend.size();
  }
  mods = modsave;
}

/// Push an operator onto the stack that has a normal binary format.
/// Both of its input expressions are also pushed.
/// \param tok is the operator token to push
/// \param op is the associated PcodeOp
void PrintLanguage::opBinary(const OpToken *tok,const PcodeOp *op)

{
  if (isSet(negatetoken)) {
    tok = tok->negate;
    unsetMod(negatetoken);
    if (tok == (const OpToken *)0)
      throw LowlevelError("Could not find fliptoken");
  }
  pushOp(tok,op);		// Push on reverse polish notation
  // implied vn's pushed on in reverse order for efficiency
  // see PrintLanguage::pushVnImplied
  pushVnImplied(op->getIn(1),op,mods);
  pushVnImplied(op->getIn(0),op,mods);
}

/// Push an operator onto the stack that has a normal unary format.
/// Its input expression is also pushed.
/// \param tok is the operator token to push
/// \param op is the associated PcodeOp
void PrintLanguage::opUnary(const OpToken *tok,const PcodeOp *op)

{
  pushOp(tok,op);
  // implied vn's pushed on in reverse order for efficiency
  // see PrintLanguage::pushVnImplied
  pushVnImplied(op->getIn(0),op,mods);
}

void PrintLanguage::resetDefaultsInternal(void)

{
  mods = 0;
  head_comment_type = Comment::header | Comment::warningheader;
  line_commentindent = 20;
  namespc_strategy = MINIMAL_NAMESPACES;
  instr_comment_type = Comment::user2 | Comment::warning;
}

/// The comment will get emitted as a single line using the high-level language's
/// delimiters with the given indent level
/// \param indent is the number of characters to indent
/// \param comm is the Comment object containing the character data and associated markup info
void PrintLanguage::emitLineComment(int4 indent,const Comment *comm)

{
  const string &text( comm->getText() );
  const AddrSpace *spc = comm->getAddr().getSpace();
  uintb off = comm->getAddr().getOffset();
  if (indent <0)
    indent = line_commentindent; // User specified default indent
  emit->tagLine(indent);
  int4 id = emit->startComment();
  // The comment delimeters should not be printed as
  // comment tags, so that they won't get filled
  emit->tagComment(commentstart.c_str(),EmitXml::comment_color,
		    spc,off);
  int4 pos = 0;
  while(pos < text.size()) {
    char tok = text[pos++];
    if ((tok==' ')||(tok=='\t')) {
      int4 count = 1;
      while(pos<text.size()) {
	tok = text[pos];
	if ((tok!=' ')&&(tok!='\t')) break;
	count += 1;
	pos += 1;
      }
      emit->spaces(count);
    }
    else if (tok=='\n')
      emit->tagLine();
    else if (tok=='\r') {
    }
    else {
      int4 count = 1;
      while(pos < text.size()) {
	tok = text[pos];
	if (isspace(tok)) break;
	count += 1;
	pos += 1;
      }
      string sub = text.substr(pos-count,count);
      emit->tagComment(sub.c_str(),EmitXml::comment_color,
			spc,off);
    }
  }
  if (commentend.size() != 0)
    emit->tagComment(commentend.c_str(),EmitXml::comment_color,
		      spc,off);
  emit->stopComment(id);
  comm->setEmitted(true);
}

/// Tell the emitter whether to emit just the raw tokens or if
/// output is in XML format with additional mark-up on the raw tokens.
/// \param val is \b true for XML mark-up
void PrintLanguage::setXML(bool val)

{
  ((EmitPrettyPrint *)emit)->setXML(val);
}

/// Emitting formal code structuring can be turned off, causing all control-flow
/// to be represented as \e goto statements and \e labels.
/// \param val is \b true if no code structuring should be emitted
void PrintLanguage::setFlat(bool val)

{
  if (val)
    mods |= flat;
  else
    mods &= ~flat;
}

void PrintLanguage::resetDefaults(void)

{
  emit->resetDefaults();
  resetDefaultsInternal();
}

void PrintLanguage::clear(void)

{
  emit->clear();
  if (!modstack.empty()) {
    mods = modstack.front();
    modstack.clear();
  }
  scopestack.clear();
  curscope = (const Scope *)0;
  revpol.clear();
  pending = 0;

  nodepend.clear();
}

/// This determines how integers are displayed by default. Possible
/// values are "hex" and "dec" to force a given format, or "best" can
/// be used to let the decompiler select what it thinks best for each individual integer.
/// \param nm is "hex", "dec", or "best"
void PrintLanguage::setIntegerFormat(const string &nm)

{
  uint4 mod;
  if (nm.compare(0,3,"hex")==0)
    mod = force_hex;
  else if (nm.compare(0,3,"dec")==0)
    mod = force_dec;
  else if (nm.compare(0,4,"best")==0)
    mod = 0;
  else
    throw LowlevelError("Unknown integer format option: "+nm);
  mods &= ~((uint4)(force_hex|force_dec)); // Turn off any pre-existing force
  mods |= mod;			// Set any new force
}

/// Count '0' and '9' digits base 10. Count '0' and 'f' digits base 16.
/// The highest count is the preferred base.
/// \param val is the given integer
/// \return 10 for decimal or 16 for hexidecimal
int4 PrintLanguage::mostNaturalBase(uintb val)

{
  int4 countdec = 0;		// Count 0's and 9's

  uintb tmp = val;
  int4 dig,setdig;
  if (tmp==0) return 10;
  setdig = tmp%10;
  if ((setdig==0)||(setdig==9)) {
    countdec += 1;
    tmp /= 10;
    while(tmp != 0) {
      dig = tmp%10;
      if (dig == setdig)
	countdec += 1;
      else
	break;
      tmp /= 10;
    }
  }
  switch(countdec) {
  case 0:
    return 16;
  case 1:
    if ((tmp>1)||(setdig==9)) return 16;
    break;
  case 2:
    if (tmp>10) return 16;
    break;
  case 3:
  case 4:
    if (tmp>100) return 16;
    break;
  default:
    if (tmp>1000) return 16;
    break;
  }

  int4 counthex = 0;		// Count 0's and f's

  tmp = val;
  setdig = tmp & 0xf;
  if ((setdig==0)||(setdig==0xf)) {
    counthex += 1;
    tmp >>= 4;
    while(tmp != 0) {
      dig = tmp & 0xf;
      if (dig == setdig)
	counthex += 1;
      else
	break;
      tmp >>= 4;
    }
  }
  
  return (countdec > counthex) ? 10 : 16;
}

/// Print a string a '0' and '1' characters representing the given value
/// \param s is the output stream
/// \param val is the given value
void PrintLanguage::formatBinary(ostream &s,uintb val)

{
  int4 pos = mostsigbit_set(val);
  if (pos < 0) {
    s << '0';
    return;
  }
  else if (pos < 7)
    pos = 7;
  else if (pos < 15)
    pos = 15;
  else if (pos < 31)
    pos = 31;
  else
    pos = 63;
  uintb mask = 1;
  mask <<= pos;
  while (mask != 0) {
    if ((mask & val) != 0)
      s << '1';
    else
      s << '0';
    mask >>= 1;
  }
}

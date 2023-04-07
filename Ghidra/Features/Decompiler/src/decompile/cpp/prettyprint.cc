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
#include "prettyprint.hh"
#include "funcdata.hh"

namespace ghidra {

AttributeId ATTRIB_BLOCKREF = AttributeId("blockref",35);
AttributeId ATTRIB_CLOSE = AttributeId("close",36);
AttributeId ATTRIB_COLOR = AttributeId("color",37);
AttributeId ATTRIB_INDENT = AttributeId("indent",38);
AttributeId ATTRIB_OFF = AttributeId("off",39);
AttributeId ATTRIB_OPEN = AttributeId("open",40);
AttributeId ATTRIB_OPREF = AttributeId("opref",41);
AttributeId ATTRIB_VARREF = AttributeId("varref",42);
ElementId ELEM_BREAK = ElementId("break",17);
ElementId ELEM_CLANG_DOCUMENT = ElementId("clang_document",18);
ElementId ELEM_FUNCNAME = ElementId("funcname",19);
ElementId ELEM_FUNCPROTO = ElementId("funcproto",20);
ElementId ELEM_LABEL = ElementId("label",21);
ElementId ELEM_RETURN_TYPE = ElementId("return_type",22);
ElementId ELEM_STATEMENT = ElementId("statement",23);
ElementId ELEM_SYNTAX = ElementId("syntax",24);
ElementId ELEM_VARDECL = ElementId("vardecl",25);
ElementId ELEM_VARIABLE = ElementId("variable",26);

const string Emit::EMPTY_STRING = "";

/// \brief Emit a sequence of space characters as part of source code
///
/// \param num is the number of space characters to emit
/// \param bump is the number of characters to indent if the spaces force a line break
void Emit::spaces(int4 num,int4 bump)

{
  static const string spacearray[] = { "", " ", "  ", "   ", "    ", "     ", "      ", "       ",
      "        ", "         ", "          " };
  if (num <= 10)
    print(spacearray[num]);
  else {
    string spc;
    for(int4 i=0;i<num;++i)
      spc += ' ';
    print(spc);
  }
}

EmitMarkup::~EmitMarkup(void)

{
  if (encoder != (Encoder *)0)
    delete encoder;
}

int4 EmitMarkup::beginDocument(void) {
  encoder->openElement(ELEM_CLANG_DOCUMENT);
  return 0;
}

void EmitMarkup::endDocument(int4 id) {
  encoder->closeElement(ELEM_CLANG_DOCUMENT);
}

int4 EmitMarkup::beginFunction(const Funcdata *fd) {
  encoder->openElement(ELEM_FUNCTION);
  return 0;
}

void EmitMarkup::endFunction(int4 id) {
  encoder->closeElement(ELEM_FUNCTION);
}

int4 EmitMarkup::beginBlock(const FlowBlock *bl) {
  encoder->openElement(ELEM_BLOCK);
  encoder->writeSignedInteger(ATTRIB_BLOCKREF, bl->getIndex());
  return 0;
}

void EmitMarkup::endBlock(int4 id) {
  encoder->closeElement(ELEM_BLOCK);
}

void EmitMarkup::tagLine(void) {
  emitPending();
  encoder->openElement(ELEM_BREAK);
  encoder->writeSignedInteger(ATTRIB_INDENT, indentlevel);
  encoder->closeElement(ELEM_BREAK);
}

void EmitMarkup::tagLine(int4 indent) {
  emitPending();
  encoder->openElement(ELEM_BREAK);
  encoder->writeSignedInteger(ATTRIB_INDENT, indent);
  encoder->closeElement(ELEM_BREAK);
}

int4 EmitMarkup::beginReturnType(const Varnode *vn) {
  encoder->openElement(ELEM_RETURN_TYPE);
  if (vn != (const Varnode *)0)
    encoder->writeUnsignedInteger(ATTRIB_VARREF, vn->getCreateIndex());
  return 0;
}

void EmitMarkup::endReturnType(int4 id) {
  encoder->closeElement(ELEM_RETURN_TYPE);
}

int4 EmitMarkup::beginVarDecl(const Symbol *sym) {
  encoder->openElement(ELEM_VARDECL);
  encoder->writeUnsignedInteger(ATTRIB_SYMREF, sym->getId());
  return 0;
}

void EmitMarkup::endVarDecl(int4 id) {
  encoder->closeElement(ELEM_VARDECL);
}

int4 EmitMarkup::beginStatement(const PcodeOp *op) {
  encoder->openElement(ELEM_STATEMENT);
  if (op != (const PcodeOp *)0)
    encoder->writeUnsignedInteger(ATTRIB_OPREF, op->getTime());
  return 0;
}

void EmitMarkup::endStatement(int4 id) {
  encoder->closeElement(ELEM_STATEMENT);
}

int4 EmitMarkup::beginFuncProto(void) {
  encoder->openElement(ELEM_FUNCPROTO);
  return 0;
}

void EmitMarkup::endFuncProto(int4 id) {
  encoder->closeElement(ELEM_FUNCPROTO);
}

void EmitMarkup::tagVariable(const string &name,syntax_highlight hl,const Varnode *vn,const PcodeOp *op)

{
  encoder->openElement(ELEM_VARIABLE);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR, hl);
  if (vn != (const Varnode *)0)
    encoder->writeUnsignedInteger(ATTRIB_VARREF, vn->getCreateIndex());
  if (op != (const PcodeOp *)0)
    encoder->writeUnsignedInteger(ATTRIB_OPREF, op->getTime());
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_VARIABLE);
}

void EmitMarkup::tagOp(const string &name,syntax_highlight hl,const PcodeOp *op)

{
  encoder->openElement(ELEM_OP);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  if (op != (const PcodeOp *)0)
    encoder->writeUnsignedInteger(ATTRIB_OPREF, op->getTime());
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_OP);
}

void EmitMarkup::tagFuncName(const string &name,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op)

{
  encoder->openElement(ELEM_FUNCNAME);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  if (op != (const PcodeOp *)0)
    encoder->writeUnsignedInteger(ATTRIB_OPREF, op->getTime());
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_FUNCNAME);
}

void EmitMarkup::tagType(const string &name,syntax_highlight hl,const Datatype *ct)

{
  encoder->openElement(ELEM_TYPE);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  if (ct->getId() != 0) {
    encoder->writeUnsignedInteger(ATTRIB_ID, ct->getId());
  }
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_TYPE);
}

void EmitMarkup::tagField(const string &name,syntax_highlight hl,const Datatype *ct,int4 o,const PcodeOp *op)

{
  encoder->openElement(ELEM_FIELD);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  if (ct != (const Datatype *)0) {
    encoder->writeString(ATTRIB_NAME,ct->getName());
    if (ct->getId() != 0) {
      encoder->writeUnsignedInteger(ATTRIB_ID, ct->getId());
    }
    encoder->writeSignedInteger(ATTRIB_OFF, o);
    if (op != (const PcodeOp *)0)
      encoder->writeUnsignedInteger(ATTRIB_OPREF, op->getTime());
  }
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_FIELD);
}

void EmitMarkup::tagComment(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off)

{
  encoder->openElement(ELEM_COMMENT);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  encoder->writeSpace(ATTRIB_SPACE, spc);
  encoder->writeUnsignedInteger(ATTRIB_OFF, off);
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_COMMENT);
}

void EmitMarkup::tagLabel(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off)

{
  encoder->openElement(ELEM_LABEL);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  encoder->writeSpace(ATTRIB_SPACE,spc);
  encoder->writeUnsignedInteger(ATTRIB_OFF, off);
  encoder->writeString(ATTRIB_CONTENT,name);
  encoder->closeElement(ELEM_LABEL);
}

void EmitMarkup::print(const string &data,syntax_highlight hl)

{
  encoder->openElement(ELEM_SYNTAX);
  if (hl != no_color)
    encoder->writeUnsignedInteger(ATTRIB_COLOR,hl);
  encoder->writeString(ATTRIB_CONTENT,data);
  encoder->closeElement(ELEM_SYNTAX);
}

int4 EmitMarkup::openParen(const string &paren,int4 id)

{
  encoder->openElement(ELEM_SYNTAX);
  encoder->writeSignedInteger(ATTRIB_OPEN, id);
  encoder->writeString(ATTRIB_CONTENT,paren);
  encoder->closeElement(ELEM_SYNTAX);
  parenlevel += 1;
  return 0;
}

void EmitMarkup::closeParen(const string &paren,int4 id)

{
  encoder->openElement(ELEM_SYNTAX);
  encoder->writeSignedInteger(ATTRIB_CLOSE, id);
  encoder->writeString(ATTRIB_CONTENT,paren);
  encoder->closeElement(ELEM_SYNTAX);
  parenlevel -= 1;
}

void EmitMarkup::setOutputStream(ostream *t)

{
  if (encoder != (Encoder *)0)
    delete encoder;
  s = t;
  encoder = new PackedEncode(*s);
}

int4 TokenSplit::countbase = 0;

/// Emit markup or content corresponding to \b this token on a low-level emitter.
/// The API method matching the token type is called, feeding it content contained in
/// the object.
/// \param emit is the low-level emitter to output to
void TokenSplit::print(Emit *emit) const

{
  switch(tagtype) {
  case docu_b:	// beginDocument
    emit->beginDocument();
    break;
  case docu_e:	// endDocument
    emit->endDocument(count);
    break;
  case func_b:	// beginFunction
    emit->beginFunction(ptr_second.fd);
    break;
  case func_e:	// endFunction
    emit->endFunction(count);
    break;
  case bloc_b:	// beginBlock
    emit->beginBlock(ptr_second.bl);
    break;
  case bloc_e:	// endBlock
    emit->endBlock(count);
    break;
  case rtyp_b:	// beginReturnType
    emit->beginReturnType(ptr_second.vn);
    break;
  case rtyp_e:	// endReturnType
    emit->endReturnType(count);
    break;
  case vard_b:	// beginVarDecl
    emit->beginVarDecl(ptr_second.symbol);
    break;
  case vard_e:	// endVarDecl
    emit->endVarDecl(count);
    break;
  case stat_b:	// beginStatement
    emit->beginStatement(op);
    break;
  case stat_e:	// endStatement
    emit->endStatement(count);
    break;
  case prot_b:	// beginFuncProto
    emit->beginFuncProto();
    break;
  case prot_e:	// endFuncProto
    emit->endFuncProto(count);
    break;
  case vari_t:	// tagVariable
    emit->tagVariable(tok,hl,ptr_second.vn,op);
    break;
  case op_t:		// tagOp
    emit->tagOp(tok,hl,op);
    break;
  case fnam_t:	// tagFuncName
    emit->tagFuncName(tok,hl,ptr_second.fd,op);
    break;
  case type_t:	// tagType
    emit->tagType(tok,hl,ptr_second.ct);
    break;
  case field_t: // tagField
    emit->tagField(tok,hl,ptr_second.ct,(int4)off,op);
    break;
  case comm_t:	// tagComment
    emit->tagComment(tok,hl,ptr_second.spc,off);
    break;
  case label_t:	// tagLabel
    emit->tagLabel(tok,hl,ptr_second.spc,off);
    break;
  case synt_t:	// print
    emit->print(tok,hl);
    break;
  case opar_t:	// openParen
    emit->openParen(tok,count);
    break;
  case cpar_t:	// closeParen
    emit->closeParen(tok,count);
    break;
  case oinv_t:	// Invisible open
    break;
  case cinv_t:	// Invisible close
    break;
  case spac_t:	// Spaces
    emit->spaces(numspaces);
    break;
  case line_t:	// tagLine
  case bump_t:
    throw LowlevelError("Should never get called");
    break;
  }
}

#ifdef PRETTY_DEBUG
void TokenSplit::printDebug(ostream &s) const

{
  switch(tagtype) {
  case docu_b:	// beginDocument
    s << "docu_b";
    break;
  case docu_e:	// endDocument
    s << "docu_e";
    break;
  case func_b:	// beginFunction
    s << "func_b";
    break;
  case func_e:	// endFunction
    s << "func_e";
    break;
  case bloc_b:	// beginBlock
    s << "bloc_b";
    break;
  case bloc_e:	// endBlock
    s << "bloc_e";
    break;
  case rtyp_b:	// beginReturnType
    s << "rtyp_b";
    break;
  case rtyp_e:	// endReturnType
    s << "rtyp_e";
    break;
  case vard_b:	// beginVarDecl
    s << "vard_b";
    break;
  case vard_e:	// endVarDecl
    s << "vard_e";
    break;
  case stat_b:	// beginStatement
    s << "stat_b";
    break;
  case stat_e:	// endStatement
    s << "stat_e";
    break;
  case prot_b:	// beginFuncProto
    s << "prot_b";
    break;
  case prot_e:	// endFuncProto
    s << "prot_e";
    break;
  case vari_t:	// tagVariable
    s << "vari_t";
    break;
  case op_t:		// tagOp
    s << "op_t";
    break;
  case fnam_t:	// tagFuncName
    s << "fnam_t";
    break;
  case type_t:	// tagType
    s << "type_t";
    break;
  case field_t: // tagField
    s << "field_t";
    break;
  case comm_t:	// tagComment
    s << "comm_t";
    break;
  case label_t:	// tagLabel
    s << "label_t";
    break;
  case synt_t:	// print
    s << "synt_t";
    break;
  case opar_t:	// openParen
    s << "opar_t";
    break;
  case cpar_t:	// closeParen
    s << "cpar_t";
    break;
  case oinv_t:	// Invisible open
    s << "oinv_t";
    break;
  case cinv_t:	// Invisible close
    s << "cinv_t";
    break;
  case spac_t:	// Spaces
    s << "spac_t";
    break;
  case line_t:	// tagLine
    s << "line_t";
    break;
  case bump_t:
    s << "bump_t";
    break;
  }
}
#endif

EmitPrettyPrint::EmitPrettyPrint(void)
  : Emit(), scanqueue( 3*100 ), tokqueue( 3*100 )

{
  lowlevel = new EmitNoMarkup();	// Do not emit xml by default
  spaceremain = maxlinesize;
  needbreak = false;
  commentmode = false;
  resetDefaultsPrettyPrint();
}

EmitPrettyPrint::~EmitPrettyPrint(void)

{
  delete lowlevel;
}

/// Increase the number of tokens that can be in the queue simultaneously.
/// This is automatically called when the buffers are full.
/// Given a fixed maximum line size for the pretty printer, the buffer should
/// quickly reach a size that supports the biggest possible number of cached tokens.
/// The current token queue is preserved and references into the queue are
/// recalculated.
void EmitPrettyPrint::expand(void)

{
  int4 max = tokqueue.getMax();
  int4 left = tokqueue.bottomref();
  tokqueue.expand(200);
  // Expanding puts the leftmost element at reference 0
  // So we need to adjust references
  for(int4 i=0;i<max;++i)
    scanqueue.ref(i) = (scanqueue.ref(i) + max - left) % max;
  // The number of elements in scanqueue is always less than
  // or equal to the number of elements in tokqueue, so
  // if we keep scanqueue and tokqueue with the same max
  // we don't need to check for scanqueue overflow
  scanqueue.expand(200);
}

/// (Permanently) adjust the current set of indent levels to guarantee a minimum
/// amount of space and issue a line break.  This disrupts currently established indenting
/// but makes sure that at least half the line is available for the next token.
void EmitPrettyPrint::overflow(void)

{
  int4 half = maxlinesize / 2;
  for(int4 i=indentstack.size()-1;i>=0;--i) {
    if (indentstack[i] < half)
      indentstack[i] = half;
    else
      break;
  }
  int4 newspaceremain;
  if (!indentstack.empty())
    newspaceremain = indentstack.back();
  else
    newspaceremain = maxlinesize;
  if (newspaceremain == spaceremain)
    return;		// Line breaking doesn't give us any additional space
  if (commentmode && (newspaceremain == spaceremain + commentfill.size()))
    return;		// Line breaking doesn't give us any additional space
  spaceremain = newspaceremain;
  lowlevel->tagLine(maxlinesize-spaceremain);
  if (commentmode &&(commentfill.size() != 0)) {
    lowlevel->print(commentfill,EmitMarkup::comment_color);
    spaceremain -= commentfill.size();
  }
}

/// Content and markup is sent to the low-level emitter if appropriate. The
/// \e indentlevel stack is adjusted as necessary depending on the token.
/// \param tok is the given token to emit.
void EmitPrettyPrint::print(const TokenSplit &tok)

{
  int4 val = 0;

  switch(tok.getClass()) {
  case TokenSplit::ignore:
    tok.print(lowlevel);	// Markup or other that doesn't use space
    break;
  case TokenSplit::begin_indent:
    val = indentstack.back() - tok.getIndentBump();
    indentstack.push_back(val);
#ifdef PRETTY_DEBUG
    checkid.push_back(tok.getCount());
#endif
    break;
  case TokenSplit::begin_comment:
    commentmode = true;
    // fallthru, treat as a group begin
  case TokenSplit::begin:
    tok.print(lowlevel);
    indentstack.push_back(spaceremain);
#ifdef PRETTY_DEBUG
    checkid.push_back(tok.getCount());
#endif
    break;
  case TokenSplit::end_indent:
    if (indentstack.empty())
      throw LowlevelError("indent error");
#ifdef PRETTY_DEBUG
    if (checkid.empty() || (checkid.back() != tok.getCount()))
      throw LowlevelError("mismatch1");
    checkid.pop_back();
    if (indentstack.empty())
      throw LowlevelError("Empty indent stack");
#endif
    indentstack.pop_back();
    break;
  case TokenSplit::end_comment:
    commentmode = false;
    // fallthru, treat as a group end
  case TokenSplit::end:
    tok.print(lowlevel);
#ifdef PRETTY_DEBUG
    if (checkid.empty() || (checkid.back() != tok.getCount()))
      throw LowlevelError("mismatch2");
    checkid.pop_back();
    if (indentstack.empty())
      throw LowlevelError("indent error");
#endif
    indentstack.pop_back();
    break;
  case TokenSplit::tokenstring:
    if (tok.getSize() > spaceremain)
      overflow();
    tok.print(lowlevel);
    spaceremain -= tok.getSize();
    break;
  case TokenSplit::tokenbreak:
    if (tok.getSize() > spaceremain) {
      if (tok.getTag() == TokenSplit::line_t) // Absolute indent
	spaceremain = maxlinesize - tok.getIndentBump();
      else {			// relative indent
	val = indentstack.back() - tok.getIndentBump();
	// If creating a line break doesn't save that much
	// don't do the line break
	if ((tok.getNumSpaces() <= spaceremain)&&
	    (val-spaceremain < 10)) {
	  lowlevel->spaces(tok.getNumSpaces());
	  spaceremain -= tok.getNumSpaces();
	  return;
	}
	indentstack.back() = val;
	spaceremain = val;
      }
      lowlevel->tagLine(maxlinesize-spaceremain);
      if (commentmode &&(commentfill.size() != 0)) {
	lowlevel->print(commentfill,EmitMarkup::comment_color);
	spaceremain -= commentfill.size();
      }
    }
    else {
      lowlevel->spaces(tok.getNumSpaces());
      spaceremain -= tok.getNumSpaces();
    }
    break;
  }
}

/// Groups of tokens that have been fully committed are sent to the
/// low-level emitter and purged from the queue. Delimiter tokens that open a new
/// printing group initially have a negative size, indicating the group is uncommitted
/// and may need additional line breaks inserted.  As the ending delimiters are scanned
/// and/or line breaks are forced.  The negative sizes are converted to positive and the
/// corresponding group becomes \e committed, and the constituent content is emitted
/// by this method.
void EmitPrettyPrint::advanceleft(void)

{
  int4 l = tokqueue.bottom().getSize();
  while(l >= 0) {
    const TokenSplit &tok( tokqueue.bottom() );
    print(tok);
    switch(tok.getClass()) {
    case TokenSplit::tokenbreak:
      leftotal += tok.getNumSpaces();
      break;
    case TokenSplit::tokenstring:
      leftotal += l;
      break;
    default:
      break;
    }
    tokqueue.popbottom();
    if (tokqueue.empty()) break;
    l = tokqueue.bottom().getSize();
  }
}

/// The token is assumed to be just added and at the top of the queue.
/// This is the heart of the pretty printing algorithm.  The new token is assigned
/// a size, the queue of open references and line breaks is updated. The amount
/// of space currently available and the size of printing groups are updated.
/// If the current line is going to overflow, a decision is made where in the uncommented
/// tokens a line break needs to be inserted and what its indent level will be. If the
/// leftmost print group closes without needing a line break, all the content it contains
/// is \e committed and is sent to the low-level emitter.
void EmitPrettyPrint::scan(void)

{
  if (tokqueue.empty())		// If we managed to overflow queue
    expand();			// Expand it
  // Delay creating reference until after the possible expansion
  TokenSplit &tok( tokqueue.top() );
  switch(tok.getClass()) {
  case TokenSplit::begin_comment:
  case TokenSplit::begin:
    if (scanqueue.empty()) {
      leftotal = rightotal = 1;
    }
    tok.setSize( -rightotal );
    scanqueue.push() = tokqueue.topref();
    break;
  case TokenSplit::end_comment:
  case TokenSplit::end:
    tok.setSize(0);
    if (!scanqueue.empty()) {
      TokenSplit &ref( tokqueue.ref( scanqueue.pop() ) );
      ref.setSize( ref.getSize() + rightotal );
      if ((ref.getClass() == TokenSplit::tokenbreak)&&(!scanqueue.empty())) {
	TokenSplit &ref2( tokqueue.ref( scanqueue.pop() ) );
	ref2.setSize( ref2.getSize() + rightotal );
      }
      if (scanqueue.empty())
	advanceleft();
    }
    break;
  case TokenSplit::tokenbreak:
    if (scanqueue.empty()) {
      leftotal = rightotal = 1;
    }
    else {
      TokenSplit &ref( tokqueue.ref( scanqueue.top() ) );
      if (ref.getClass() == TokenSplit::tokenbreak) {
	scanqueue.pop();
	ref.setSize( ref.getSize() + rightotal );
      }
    }
    tok.setSize( -rightotal );
    scanqueue.push() = tokqueue.topref();
    rightotal += tok.getNumSpaces();
    break;
  case TokenSplit::begin_indent:
  case TokenSplit::end_indent:
  case TokenSplit::ignore:
    tok.setSize(0);
    break;
  case TokenSplit::tokenstring:
    if (!scanqueue.empty()) {
      rightotal += tok.getSize();
      while(rightotal-leftotal > spaceremain) {
	TokenSplit &ref( tokqueue.ref( scanqueue.popbottom() ) );
	ref.setSize(999999);
	advanceleft();
	if (scanqueue.empty()) break;
      }
    }
  }
}

/// Make sure there is whitespace after the last content token, inserting a zero-sized
/// whitespace token if necessary, before emitting a \e start token.
void EmitPrettyPrint::checkstart(void)

{
  if (needbreak) {
    TokenSplit &tok( tokqueue.push() );
    tok.spaces(0,0);
    scan();
  }
  needbreak = false;
}

/// Make sure there is whitespace after the last content token, inserting a zero-sized
/// whitespace token if necessary, before emitting a \e content token.
void EmitPrettyPrint::checkstring(void)

{
  if (needbreak) {
    TokenSplit &tok( tokqueue.push() );
    tok.spaces(0,0);
    scan();
  }
  needbreak = true;
}

/// Make sure there is some content either in the current print group or following the
/// last line break, inserting an empty string token if necessary, before emitting
/// an \e end token.
void EmitPrettyPrint::checkend(void)

{
  if (!needbreak) {
    TokenSplit &tok( tokqueue.push() );
    tok.print(EMPTY_STRING,EmitMarkup::no_color); // Add a blank string
    scan();
  }
  needbreak = true;
}

/// Make sure there is some content either in the current print group or following the
/// last line break, inserting an empty string token if necessary, before emitting
/// a \e line \e break token.
void EmitPrettyPrint::checkbreak(void)

{
  if (!needbreak) {
    TokenSplit &tok( tokqueue.push() );
    tok.print(EMPTY_STRING,EmitMarkup::no_color); // Add a blank string
    scan();
  }
  needbreak = false;
}

int4 EmitPrettyPrint::beginDocument(void)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginDocument();
  scan();
  return id;
}

void EmitPrettyPrint::endDocument(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.endDocument(id);
  scan();
}

int4 EmitPrettyPrint::beginFunction(const Funcdata *fd)

{
#ifdef PRETTY_DEBUG
  if (!tokqueue.empty())
    throw LowlevelError("Starting with non-empty token queue");
#endif
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginFunction(fd);
  scan();
  return id;
}

void EmitPrettyPrint::endFunction(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.endFunction(id);
  scan();
}

int4 EmitPrettyPrint::beginBlock(const FlowBlock *bl)

{
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginBlock(bl);
  scan();
  return id;
}

void EmitPrettyPrint::endBlock(int4 id)

{
  TokenSplit &tok( tokqueue.push() );
  tok.endBlock(id);
  scan();
}

void EmitPrettyPrint::tagLine(void)

{
  emitPending();
  checkbreak();
  TokenSplit &tok( tokqueue.push() );
  tok.tagLine();
  scan();
}

void EmitPrettyPrint::tagLine(int4 indent)

{
  emitPending();
  checkbreak();
  TokenSplit &tok( tokqueue.push() );
  tok.tagLine(indent);
  scan();
}

int4 EmitPrettyPrint::beginReturnType(const Varnode *vn)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginReturnType(vn);
  scan();
  return id;
}

void EmitPrettyPrint::endReturnType(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.endReturnType(id);
  scan();
}

int4 EmitPrettyPrint::beginVarDecl(const Symbol *sym)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginVarDecl(sym);
  scan();
  return id;
}

void EmitPrettyPrint::endVarDecl(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.endVarDecl(id);
  scan();
}

int4 EmitPrettyPrint::beginStatement(const PcodeOp *op)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginStatement(op);
  scan();
  return id;
}

void EmitPrettyPrint::endStatement(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.endStatement(id);
  scan();
}

int4 EmitPrettyPrint::beginFuncProto(void)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.beginFuncProto();
  scan();
  return id;
}

void EmitPrettyPrint::endFuncProto(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.endFuncProto(id);
  scan();
}

void EmitPrettyPrint::tagVariable(const string &name,syntax_highlight hl,const Varnode *vn,const PcodeOp *op)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagVariable(name,hl,vn,op);
  scan();
}

void EmitPrettyPrint::tagOp(const string &name,syntax_highlight hl,const PcodeOp *op)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagOp(name,hl,op);
  scan();
}

void EmitPrettyPrint::tagFuncName(const string &name,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagFuncName(name,hl,fd,op);
  scan();
}

void EmitPrettyPrint::tagType(const string &name,syntax_highlight hl,const Datatype *ct)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagType(name,hl,ct);
  scan();
}

void EmitPrettyPrint::tagField(const string &name,syntax_highlight hl,const Datatype *ct,int4 o,const PcodeOp *op)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagField(name,hl,ct,o,op);
  scan();
}

void EmitPrettyPrint::tagComment(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagComment(name,hl,spc,off);
  scan();
}

void EmitPrettyPrint::tagLabel(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagLabel(name,hl,spc,off);
  scan();
}

void EmitPrettyPrint::print(const string &data,syntax_highlight hl)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.print(data,hl);
  scan();
}

int4 EmitPrettyPrint::openParen(const string &paren,int4 id)

{
  id = openGroup();	       // Open paren automatically opens group
  TokenSplit &tok( tokqueue.push() );
  tok.openParen(paren,id);
  scan();
  needbreak = true;
  return id;
}

void EmitPrettyPrint::closeParen(const string &paren,int4 id)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.closeParen(paren,id);
  scan();
  closeGroup(id);
}

int4 EmitPrettyPrint::openGroup(void)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.openGroup();
  scan();
  return id;
}

void EmitPrettyPrint::closeGroup(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.closeGroup(id);
  scan();
}

int4 EmitPrettyPrint::startComment(void)

{
  checkstart();
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.startComment();
  scan();
  return id;
}

void EmitPrettyPrint::stopComment(int4 id)

{
  checkend();
  TokenSplit &tok( tokqueue.push() );
  tok.stopComment(id);
  scan();
}

void EmitPrettyPrint::clear(void)

{
  Emit::clear();
  lowlevel->clear();
  indentstack.clear();
  scanqueue.clear();
  tokqueue.clear();
  leftotal = 1;
  rightotal = 1;
  needbreak = false;
  commentmode = false;
  spaceremain = maxlinesize;
}

void EmitPrettyPrint::spaces(int4 num,int4 bump)

{
  checkbreak();
  TokenSplit &tok( tokqueue.push() );
  tok.spaces(num,bump);
  scan();
}

int4 EmitPrettyPrint::startIndent(void)

{
  TokenSplit &tok( tokqueue.push() );
  int4 id = tok.startIndent(indentincrement);
  scan();
  return id;
}

void EmitPrettyPrint::stopIndent(int4 id)

{
  TokenSplit &tok( tokqueue.push() );
  tok.stopIndent(id);
  scan();
}

void EmitPrettyPrint::flush(void)

{
  while(!tokqueue.empty()) {
    TokenSplit &tok( tokqueue.popbottom() );
    if (tok.getSize() < 0)
      throw LowlevelError("Cannot flush pretty printer. Missing group end");
    print(tok);
  }
  needbreak = false;
#ifdef PRETTY_DEBUG
  if (!scanqueue.empty())
    throw LowlevelError("prettyprint scanqueue did not flush");
  if (!indentstack.empty())
    throw LowlevelError("prettyprint indentstack did not flush");
#endif
  lowlevel->flush();
}

/// This method toggles the low-level emitter between EmitMarkup and EmitNoMarkup depending
/// on whether markup is desired.
/// \param val is \b true if markup is desired
void EmitPrettyPrint::setMarkup(bool val)

{
  ostream *t = lowlevel->getOutputStream();
  delete lowlevel;
  if (val)
    lowlevel = new EmitMarkup;
  else
    lowlevel = new EmitNoMarkup;
  lowlevel->setOutputStream(t);
}

void EmitPrettyPrint::setMaxLineSize(int4 val)

{
  if ((val<20)||(val>10000))
    throw LowlevelError("Bad maximum line size");
  maxlinesize = val;
  scanqueue.setMax(3*val);
  tokqueue.setMax(3*val);
  spaceremain = maxlinesize;
  clear();
}

void EmitPrettyPrint::resetDefaults(void)

{
  lowlevel->resetDefaults();
  resetDefaultsInternal();
  resetDefaultsPrettyPrint();
}

} // End namespace ghidra

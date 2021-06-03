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

const char *EmitXml::highlight[] = { "color=\"keyword\"",
					      "color=\"comment\"",
					      "color=\"type\"",
					      "color=\"funcname\"",
					      "color=\"var\"",
					      "color=\"const\"",
					      "color=\"param\"",
					      "color=\"global\"",
					      "" };

/// Inform the emitter that generation of the source code document has begun
/// \return an id associated with the document
int4 EmitXml::beginDocument(void) {
  *s << "<clang_document " << highlight[(int4)no_color] << '>';
  return 0;
}

/// Inform the emitter that generation of the source code document is finished
/// \param id is the id associated with the document (as returned by beginDocument)
void EmitXml::endDocument(int4 id) {
  *s << "</clang_document>";
}

/// Inform the emitter that generation of a function body has begun
/// \return an id associated with the function body
int4 EmitXml::beginFunction(const Funcdata *fd) {
  *s << "<function " << highlight[(int4)no_color];
  *s << '>';
  return 0;
}

/// Inform the emitter that generation of a function body has ended
/// \param id is the id associated with the function body (as returned by beginFunction)
void EmitXml::endFunction(int4 id) {
  *s << "</function>";
}

/// Inform the emitter that a new control-flow section is starting. This is a source code unit
/// usually surrounded with curly braces '{' and '}'.
/// \param bl is the block structure object associated with the section
/// \return an id associated with the section
int4 EmitXml::beginBlock(const FlowBlock *bl) {
  *s << "<block " << highlight[(int4)no_color] << " blockref=\"0x" << hex <<
    bl->getIndex() << "\">";
  return 0;
}

/// Inform the emitter that a control-flow section is ending.
/// \param id is the id associated with the section (as returned by beginBlock)
void EmitXml::endBlock(int4 id) {
  *s << "</block>";
}

/// Tell the emitter that a new line is desired at the current indent level
void EmitXml::tagLine(void) {
  *s << "<break " << highlight[(int4)no_color] << " indent=\"0x" << hex <<
    indentlevel << "\"/>";
}

/// Tell the emitter that a new line is desired at a specific indent level. The indent level
/// is overridden only for the line, then it returns to its previous value.
/// \param indent is the desired indent level for the new line
void EmitXml::tagLine(int4 indent) {
  *s << "<break " << highlight[(int4)no_color] << " indent=\"0x" << hex <<
    indent << "\"/>";
}

/// Inform the emitter that generation of a function's return type is starting.
/// \param vn (if non-null) is the storage location for the return value
/// \return an id associated with the return type
int4 EmitXml::beginReturnType(const Varnode *vn) {
  *s << "<return_type " << highlight[(int4)no_color];
  if (vn != (const Varnode *)0)
    *s << " varref=\"0x" << hex << vn->getCreateIndex() << "\">";
  else
    *s << '>';
  return 0;
}

/// Inform the emitter that generation of a function's return type is ending.
/// \param id is the id associated with the return type (as returned by beginReturnType)
void EmitXml::endReturnType(int4 id) {
  *s << "</return_type>";
}

/// Inform the emitter that a variable declaration has started.
/// \param sym is the symbol being declared
/// \return an id associated with the declaration
int4 EmitXml::beginVarDecl(const Symbol *sym) {
  *s << "<vardecl " << highlight[(int4)no_color];
  *s << " symref=\"0x" << hex << sym->getId() << "\">";
  return 0;
}

/// Inform the emitter that a variable declaration has ended.
/// \param id is the id associated with the declaration (as returned by beginVarDecl)
void EmitXml::endVarDecl(int4 id) {
  *s << "</vardecl>";
}

/// Inform the emitter that a source code statement is beginning.
/// \param op is the root p-code operation of the statement
/// \return an id associated with the statement
int4 EmitXml::beginStatement(const PcodeOp *op) {
  *s << "<statement " << highlight[(int4)no_color];
  if (op != (const PcodeOp *)0)
    *s << " opref=\"0x" << hex << op->getTime() << "\">";
  else
    *s << '>';
  return 0;
}

/// Inform the emitter that a source code statement is ending.
/// \param id is the id associated with the statement (as returned by beginStatement)
void EmitXml::endStatement(int4 id) {
  *s << "</statement>";
}

/// Inform the emitter that a function prototype is starting.
/// \return an id associated with the prototype
int4 EmitXml::beginFuncProto(void) {
  *s << "<funcproto " << highlight[(int4)no_color] << '>';
  return 0;
}

/// Inform the emitter that a function prototype is ending.
/// \param id is the id associated with the prototype (as returned by beginFuncProto)
void EmitXml::endFuncProto(int4 id) {
  *s << "</funcproto>";
}

/// \brief Emit a variable token
///
/// An identifier string representing the variable is output, possibly with additional markup.
/// \param ptr is the character data for the identifier
/// \param hl indicates how the identifier should be highlighted
/// \param vn is the Varnode representing the variable within the syntax tree
/// \param op is a p-code operation related to the use of the variable (may be null)
void EmitXml::tagVariable(const char *ptr,syntax_highlight hl,
			    const Varnode *vn,const PcodeOp *op)
{
  *s << "<variable " << highlight[(int4)hl];
  if (vn != (const Varnode *)0)
    *s << " varref=\"0x" << hex << vn->getCreateIndex() << '\"';
  if (op != (const PcodeOp *)0)
    *s << " opref=\"0x" << hex << op->getTime() << '\"';
  *s << '>';
  xml_escape(*s,ptr);
  *s << "</variable>";
}

/// \brief Emit an operation token
///
/// The string representing the operation as appropriate for the source language is emitted,
/// possibly with additional markup.
/// \param ptr is the character data for the emitted representation
/// \param hl indicates how the token should be highlighted
/// \param op is the PcodeOp object associated with the operation with the syntax tree
void EmitXml::tagOp(const char *ptr,syntax_highlight hl,
		      const PcodeOp *op)
{
  *s << "<op " << highlight[(int4)hl];
  if (op != (const PcodeOp *)0)
    *s << " opref=\"0x" << hex << op->getTime() << "\">";
  else
    *s << '>';
  xml_escape(*s,ptr);
  *s << "</op>";
}

/// \brief Emit a function identifier
///
/// An identifier string representing the symbol name of the function is emitted, possible
/// with additional markup.
/// \param ptr is the character data for the identifier
/// \param hl indicates how the identifier should be highlighted
/// \param fd is the function
/// \param op is the CALL operation associated within the syntax tree or null for a declaration
void EmitXml::tagFuncName(const char *ptr,syntax_highlight hl,
			    const Funcdata *fd,const PcodeOp *op)
{
  *s << "<funcname " << highlight[(int4)hl];
  if (op != (const PcodeOp *)0)
    *s << " opref=\"0x" << hex << op->getTime() << "\">";
  else
    *s << '>';
  xml_escape(*s,ptr);
  *s << "</funcname>";
}

/// \brief Emit a data-type identifier
///
/// A string representing the name of a data-type, as appropriate for the source language
/// is emitted, possibly with additional markup.
/// \param ptr is the character data for the identifier
/// \param hl indicates how the identifier should be highlighted
/// \param ct is the data-type description object
void EmitXml::tagType(const char *ptr,syntax_highlight hl,const Datatype *ct) {
  *s << "<type " << highlight[(int4)hl];
  if (ct->getId() != 0) {
    *s << " id=\"0x" << hex << ct->getId() << '\"';
  }
  *s << '>';
  xml_escape(*s,ptr);
  *s << "</type>";
}

/// \brief Emit an identifier for a field within a structured data-type
///
/// A string representing an individual component of a structured data-type is emitted,
/// possibly with additional markup.
/// \param ptr is the character data for the identifier
/// \param hl indicates how the identifier should be highlighted
/// \param ct is the data-type associated with the field
/// \param o is the (byte) offset of the field within its structured data-type
void EmitXml::tagField(const char *ptr,syntax_highlight hl,const Datatype *ct,int4 o) {
  *s << "<field " << highlight[(int4)hl];
  if (ct != (const Datatype *)0) {
    *s << " name=\"";
    xml_escape(*s,ct->getName().c_str());
    if (ct->getId() != 0) {
      *s << "\" id=\"0x" << hex << ct->getId();
    }
    
    *s << "\" off=\"" << dec << o << '\"';
  }
  *s << '>';
  xml_escape(*s,ptr);
  *s << "</field>";
}

/// \brief Emit a comment string as part of the generated source code
///
/// Individual comments can be broken up and emitted using multiple calls to this method,
/// but ultimately the comment delimiters and the body of the comment are both emitted with
/// this method, which may provide addition markup.
/// \param ptr is the character data for the comment
/// \param hl indicates how the comment should be highlighted
/// \param spc is the address space of the address where the comment is attached
/// \param off is the offset of the address where the comment is attached
void EmitXml::tagComment(const char *ptr,syntax_highlight hl,
			   const AddrSpace *spc,uintb off) {
  *s << "<comment " << highlight[(int4)hl];
  *s << " space=\"" << spc->getName();
  *s << "\" off=\"0x" << hex << off << "\">";
  xml_escape(*s,ptr);
  *s << "</comment>";
}

/// \brief Emit a code label identifier
///
/// A string describing a control-flow destination, as appropriate for the source language
/// is output, possibly with additional markup.
/// \param ptr is the character data of the label
/// \param hl indicates how the label should be highlighted
/// \param spc is the address space of the code address being labeled
/// \param off is the offset of the code address being labeled
void EmitXml::tagLabel(const char *ptr,syntax_highlight hl,
			 const AddrSpace *spc,uintb off) {
  *s << "<label " << highlight[(int4)hl];
  *s << " space=\"" << spc->getName();
  *s << "\" off=\"0x" << hex << off << "\">";
  xml_escape(*s,ptr);
  *s << "</label>";
}

/// \brief Emit other (more unusual) syntax as part of source code generation
///
/// This method is used to emit syntax not covered by the other methods, such as
/// spaces, semi-colons, braces, and other punctuation.
/// \param str is the character data of the syntax being emitted
/// \param hl indicates how the syntax should be highlighted
void EmitXml::print(const char *str,syntax_highlight hl)

{
  *s << "<syntax " << highlight[(int4)hl] << '>';
  xml_escape(*s,str);
  *s << "</syntax>";
}

/// This method emits the parenthesis character itself and also starts a printing unit
/// of the source code being surrounded by the parentheses.
/// \param o is the open parenthesis character to emit
/// \param id is an id to associate with the parenthesis
/// \return an id associated with the parenthesis
int4 EmitXml::openParen(char o,int4 id)

{
  *s << "<syntax " << highlight[(int4)no_color];
  *s << " open=\"" << dec << id << "\">";
  *s << o;
  *s << "</syntax>";
  parenlevel += 1;
  return 0;
}

/// This method emits the parenthesis character itself and ends the printing unit that
/// was started by the matching open parenthesis.
/// \param c is the close parenthesis character to emit
/// \param id is the id associated with the matching open parenthesis (as returned by openParen)
void EmitXml::closeParen(char c,int4 id)

{
  *s << "<syntax " << highlight[(int4)no_color];
  *s << " close=\"" << dec << id << "\">";
  *s << c;
  *s << "</syntax>";
  parenlevel -= 1;
}

/// \brief Emit a sequence of space characters as part of source code
///
/// \param num is the number of space characters to emit
/// \param bump is the number of characters to indent if the spaces force a line break
void EmitXml::spaces(int4 num,int4 bump)

{
  const char *tenspaces = "          ";
  if (num <= 10)
    print(tenspaces+(10-num));
  else {
    string spc;
    for(int4 i=0;i<num;++i)
      spc += ' ';
    print(spc.c_str());
  }
}

void EmitXml::resetDefaults(void)

{
  resetDefaultsInternal();
}

int4 TokenSplit::countbase = 0;

/// Emit markup or content corresponding to \b this token on a low-level emitter.
/// The API method matching the token type is called, feeding it content contained in
/// the object.
/// \param emit is the low-level emitter to output to
void TokenSplit::print(EmitXml *emit) const

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
    emit->tagVariable(tok.c_str(),hl,ptr_second.vn,op);
    break;
  case op_t:		// tagOp
    emit->tagOp(tok.c_str(),hl,op);
    break;
  case fnam_t:	// tagFuncName
    emit->tagFuncName(tok.c_str(),hl,ptr_second.fd,op);
    break;
  case type_t:	// tagType
    emit->tagType(tok.c_str(),hl,ptr_second.ct);
    break;
  case field_t: // tagField
    emit->tagField(tok.c_str(),hl,ptr_second.ct,(int4)off);
    break;
  case comm_t:	// tagComment
    emit->tagComment(tok.c_str(),hl,ptr_second.spc,off);
    break;
  case label_t:	// tagLabel
    emit->tagLabel(tok.c_str(),hl,ptr_second.spc,off);
    break;
  case synt_t:	// print
    emit->print(tok.c_str(),hl);
    break;
  case opar_t:	// openParen
    emit->openParen(tok[0],count);
    break;
  case cpar_t:	// closeParen
    emit->closeParen(tok[0],count);
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
  : EmitXml(), scanqueue( 3*100 ), tokqueue( 3*100 )

{
  lowlevel = new EmitNoXml();	// Do not emit xml by default
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
    lowlevel->print(commentfill.c_str(),EmitXml::comment_color);
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
	lowlevel->print(commentfill.c_str(),EmitXml::comment_color);
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
/// If the current line is going to overflow, a decision is mode where in the uncommented
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
    tok.print("",EmitXml::no_color); // Add a blank string
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
    tok.print("",EmitXml::no_color); // Add a blank string
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
  checkbreak();
  TokenSplit &tok( tokqueue.push() );
  tok.tagLine();
  scan();
}

void EmitPrettyPrint::tagLine(int4 indent)

{
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

void EmitPrettyPrint::tagVariable(const char *ptr,syntax_highlight hl,
				    const Varnode *vn,const PcodeOp *op)
{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagVariable(ptr,hl,vn,op);
  scan();
}

void EmitPrettyPrint::tagOp(const char *ptr,syntax_highlight hl,const PcodeOp *op)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagOp(ptr,hl,op);
  scan();
}

void EmitPrettyPrint::tagFuncName(const char *ptr,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagFuncName(ptr,hl,fd,op);
  scan();
}

void EmitPrettyPrint::tagType(const char *ptr,syntax_highlight hl,const Datatype *ct)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagType(ptr,hl,ct);
  scan();
}

void EmitPrettyPrint::tagField(const char *ptr,syntax_highlight hl,const Datatype *ct,int4 o)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagField(ptr,hl,ct,o);
  scan();
}

void EmitPrettyPrint::tagComment(const char *ptr,syntax_highlight hl,
				   const AddrSpace *spc,uintb off)
{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagComment(ptr,hl,spc,off);
  scan();
}

void EmitPrettyPrint::tagLabel(const char *ptr,syntax_highlight hl,
				 const AddrSpace *spc,uintb off)
{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.tagLabel(ptr,hl,spc,off);
  scan();
}

void EmitPrettyPrint::print(const char *str,syntax_highlight hl)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.print(str,hl);
  scan();
}

int4 EmitPrettyPrint::openParen(char o,int4 id)

{
  id = openGroup();	       // Open paren automatically opens group
  TokenSplit &tok( tokqueue.push() );
  tok.openParen(o,id);
  scan();
  needbreak = true;
  return id;
}

void EmitPrettyPrint::closeParen(char c,int4 id)

{
  checkstring();
  TokenSplit &tok( tokqueue.push() );
  tok.closeParen(c,id);
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
  EmitXml::clear();
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

/// This method toggles the low-level emitter between EmitXml and EmitNoXml depending
/// on whether XML markup is desired.
/// \param val is \b true if XML markup is desired
void EmitPrettyPrint::setXML(bool val)

{
  ostream *t = lowlevel->getOutputStream();
  delete lowlevel;
  if (val)
    lowlevel = new EmitXml;
  else
    lowlevel = new EmitNoXml;
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

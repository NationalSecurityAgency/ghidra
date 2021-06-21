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
/// \file prettyprint.hh
/// \brief Routines for emitting high-level (C) language syntax in a well formatted way.

#ifndef __PRETTYPRINT__
#define __PRETTYPRINT__

#include "type.hh"

class Varnode;
class PcodeOp;
class FlowBlock;
class Funcdata;
class Symbol;

/// \brief Base class (and interface) for pretty printing and XML markup of tokens
///
/// There are two basic functions being implemented through this interface:
///
/// \b XML \b markup: allows recording of the natural grouping of the high-level tokens
/// and directly links the nodes of the abstract syntax tree to the emitted tokens.
///
/// \b Pretty \b printing: Line breaks and additional white space characters are
/// inserted within the emitted source code to enforce a maximum number of characters
/// per line while minimizing breaks in important groups of syntax.
/// Where extra line breaks are necessary, additional indenting is provided to
/// reduce the impact on readability.
///
/// All printing must be surrounded by at least one \e begin and \e end tag pair:
///   - beginDocument endDocument surrounds a whole document of code output
///   - beginFunction endFunction surrounds a whole declaration and body of a function
///   - beginBlock endBlock surrounds control-flow elements
///   - beginReturnType endReturnType
///   - beginVarDecl endVarDecl surrounds variable declarations
///   - beginStatement endStatement  surrounds a single statement
///   - beginFuncProto endFuncProto  surrounds a function prototype declaration
///
/// Additional printing groups can be specified with tag pairs:
///   - openParen closeParen creates a unit surrounded by parentheses and treats
///   - openGroup closeGroup create an arbitrary printing unit
///   - startIndent stopIndent prints a unit at a given indent level
///   - startComment stopComment delimit comments for special indenting and filling
///
/// The tag* functions, emit the actual language tokens, supplying appropriate markup.
///   - tagVariable to print variables
///   - tagOp to print operators
///   - tagFuncName to print a function identifiers
///   - tagType to print data-type identifiers
///   - tagField to print field identifiers for structured data-types
///   - tagComment to print words in a comment
///   - tagLabel to print control-flow labels
///
///   - print is used for any other syntax
///   - spaces is used to print whitespace
///   - tagLine forces a line break
///   - tagLine(indent) forces a line break with an indent override
///
/// This base class does not actually do any pretty printing it only does the XML
/// markup.  For an implementation that actually does pretty printing, see EmitPrettyPrint.
/// This class can be used as the low-level back-end to EmitPrettyPrint to provide a solution
/// that does both pretty printing and XML markup.
class EmitXml {
  static const char *highlight[];	///< Map from syntax_highlight enumeration to color attribute string
protected:
  ostream *s;				///< Stream being emitted to
  int4 indentlevel;			///< Current indent level (in fixed width characters)
  int4 parenlevel;			///< Current depth of parentheses
  int4 indentincrement;			///< Change in indentlevel per level of nesting
  void resetDefaultsInternal(void) { indentincrement = 2; }	///< Set options to default values for EmitXml
public:
  EmitXml(void) { s = (ostream *)0; indentlevel=0; parenlevel=0; resetDefaultsInternal(); }	///< Constructor

  /// \brief Possible types of syntax highlighting
  enum syntax_highlight {
    keyword_color = 0,		///< Keyword in the high-level language
    comment_color = 1,		///< Comments
    type_color = 2,		///< Data-type identifiers
    funcname_color = 3,		///< Function identifiers
    var_color = 4,		///< Local variable identifiers
    const_color = 5,		///< Constant values
    param_color = 6,		///< Function parameters
    global_color = 7,		///< Global variable identifiers
    no_color = 8		///< Un-highlighted
  };
  virtual ~EmitXml(void) {}				///< Destructor
  virtual int4 beginDocument(void);			///< Begin a whole document of output
  virtual void endDocument(int4 id);			///< End a whole document of output
  virtual int4 beginFunction(const Funcdata *fd);	///< Begin a whole declaration and body of a function
  virtual void endFunction(int4 id);			///< End a whole declaration and body of a function
  virtual int4 beginBlock(const FlowBlock *bl);		///< Begin a control-flow element
  virtual void endBlock(int4 id);			///< End a control-flow element
  virtual void tagLine(void);				///< Force a line break
  virtual void tagLine(int4 indent);			///< Force a line break and indent level
  virtual int4 beginReturnType(const Varnode *vn);	///< Begin a return type declaration
  virtual void endReturnType(int4 id);			///< End a return type declaration
  virtual int4 beginVarDecl(const Symbol *sym);		///< Begin a variable declaration
  virtual void endVarDecl(int4 id);			///< End a variable declaration
  virtual int4 beginStatement(const PcodeOp *op);	///< Begin a source code statement
  virtual void endStatement(int4 id);			///< End a source code statement
  virtual int4 beginFuncProto(void);			///< Begin a function prototype declaration
  virtual void endFuncProto(int4 id);			///< End a function prototype declaration
  virtual void tagVariable(const char *ptr,syntax_highlight hl,
			    const Varnode *vn,const PcodeOp *op);
  virtual void tagOp(const char *ptr,syntax_highlight hl,const PcodeOp *op);
  virtual void tagFuncName(const char *ptr,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op);
  virtual void tagType(const char *ptr,syntax_highlight hl,const Datatype *ct);
  virtual void tagField(const char *ptr,syntax_highlight hl,const Datatype *ct,int4 off);
  virtual void tagComment(const char *ptr,syntax_highlight hl,const AddrSpace *spc,uintb off);
  virtual void tagLabel(const char *ptr,syntax_highlight hl,const AddrSpace *spc,uintb off);
  virtual void print(const char *str,syntax_highlight hl=no_color);
  virtual int4 openParen(char o,int4 id=0);		///< Emit an open parenthesis
  virtual void closeParen(char c,int4 id);		///< Emit a close parenthesis

  /// \brief Start a group of things that are printed together
  ///
  /// Inform the emitter that a new printing group is starting.
  /// \return an id associated with the group
  virtual int4 openGroup(void) { return 0; }

  /// \brief End a group of things that are printed together
  ///
  /// Inform the emitter that a printing group is ending.
  /// \param id is the id associated with the group (as returned by openGroup)
  virtual void closeGroup(int4 id) {}
  virtual void clear(void) { parenlevel = 0; indentlevel=0; }	///< Reset the emitter to its initial state
  virtual void setOutputStream(ostream *t) { s = t; }		///< Set the output stream for the emitter
  virtual ostream *getOutputStream(void) const { return s; }	///< Get the current output stream
  virtual void spaces(int4 num,int4 bump=0);

  /// \brief Start a new indent level
  ///
  /// Inform the emitter that one level of nesting is being added.
  /// \return an id associated with the nesting
  virtual int4 startIndent(void) { indentlevel+=indentincrement; return 0; }

  /// \brief End an indent level
  ///
  /// Inform the emitter that the current nesting has ended, and we are returning to the
  /// previous level.
  /// \param id is the id associated with the nesting (as returned by startIndent)
  virtual void stopIndent(int4 id) { indentlevel-=indentincrement; }

  /// \brief Start a comment block within the emitted source code
  ///
  /// Inform the emitter that a set of comment tokens/lines is starting.
  /// \return an id associated with the comment block
  virtual int4 startComment(void) { return 0; }

  /// \brief End a comment block
  ///
  /// Inform the emitter that a set of comment tokens/lines is ending.
  /// \param id is the id associated with the block (as returned by startComment)
  virtual void stopComment(int4 id) {}

  /// \brief Flush any remaining character data
  ///
  /// Depending on the particular emitter, tokens and syntax that have been submitted
  /// to the emitter may be held internally for a time before getting output to the
  /// final stream.  This routine makes sure submitted syntax is fully output.
  virtual void flush(void) {}

  /// \brief Provide a maximum line size to the pretty printer
  ///
  /// The emitter may insert line breaks to enforce this maximum.
  /// \param mls is the number of characters to set for the maximum line size
  virtual void setMaxLineSize(int4 mls) {}

  /// \brief Get the current maximum line size
  ///
  /// If the emitter respects a maximum line size, return that size.
  /// \return the maximum line size or -1 if the emitter does not have a maximum
  virtual int4 getMaxLineSize(void) const { return -1; }

  /// \brief Set the comment fill characters for when line breaks are forced
  ///
  /// If the pretty printer forces a line break in the middle of a comment, this
  /// string is emitted to provide proper syntax and indenting to continue the comment.
  /// \param fill is the set of fill characters
  virtual void setCommentFill(const string &fill) {}

  /// \brief Determine if \b this is an XML markup emitter
  ///
  /// \return \b true if \b this produces an XML markup of its emitted source code
  virtual bool emitsXml(void) const { return true; }

  /// \brief (Re)set the default emitting options
  virtual void resetDefaults(void);

  /// \brief Get the current parentheses depth
  ///
  /// \return the current number of open parenthetical groups
  int4 getParenLevel(void) const { return parenlevel; }

  /// \brief Get the number of characters indented per level of nesting
  ///
  /// \return the number of characters
  int4 getIndentIncrement(void) const { return indentincrement; }

  /// \brief Set the number of characters indented per level of nesting
  ///
  /// \param val is the desired number of characters to indent
  void setIndentIncrement(int4 val) { indentincrement = val; }
};

/// \brief A trivial emitter that outputs syntax straight to the stream
///
/// This emitter does neither pretty printing nor XML markup.  It dumps any tokens
/// straight to the final output stream.  It can be used as the low-level back-end
/// for EmitPrettyPrint.
class EmitNoXml : public EmitXml {
public:
  EmitNoXml(void) : EmitXml() {}	///< Constructor
  virtual int4 beginDocument(void) { return 0; }
  virtual void endDocument(int4 id) {}
  virtual int4 beginFunction(const Funcdata *fd) { return 0; }
  virtual void endFunction(int4 id) {}
  virtual int4 beginBlock(const FlowBlock *bl) { return 0; }
  virtual void endBlock(int4 id) {}
  virtual void tagLine(int4 indent) {
    *s << endl; for(int4 i=indent;i>0;--i) *s << ' '; }
  virtual int4 beginReturnType(const Varnode *vn) { return 0; }
  virtual void endReturnType(int4 id) {}
  virtual int4 beginVarDecl(const Symbol *sym) { return 0; }
  virtual void endVarDecl(int4 id) {}
  virtual int4 beginStatement(const PcodeOp *op) { return 0; }
  virtual void endStatement(int4 id) {}
  virtual int4 beginFuncProto(void) { return 0; }
  virtual void endFuncProto(int4 id) {}
  virtual void tagVariable(const char *ptr,syntax_highlight hl,
			    const Varnode *vn,const PcodeOp *op) {
    *s << ptr; }
  virtual void tagOp(const char *ptr,syntax_highlight hl,const PcodeOp *op) {
    *s << ptr; }
  virtual void tagFuncName(const char *ptr,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op) {
    *s << ptr; }
  virtual void tagType(const char *ptr,syntax_highlight hl,const Datatype *ct) {
    *s << ptr; }
  virtual void tagField(const char *ptr,syntax_highlight hl,const Datatype *ct,int4 off) {
    *s << ptr; }
  virtual void tagComment(const char *ptr,syntax_highlight hl,
			   const AddrSpace *spc,uintb off) {
    *s << ptr; }
  virtual void tagLabel(const char *ptr,syntax_highlight hl,
			 const AddrSpace *spc,uintb off) {
    *s << ptr; }
  virtual void print(const char *str,syntax_highlight hl=no_color) {
    *s << str; }
  virtual int4 openParen(char o,int4 id=0) {
    *s << o; parenlevel += 1; return id; }
  virtual void closeParen(char c,int4 id) {
    *s << c; parenlevel -= 1; }
  virtual bool emitsXml(void) const { return false; }
};

/// \brief A token/command object in the pretty printing stream
///
/// The pretty printing algorithm (see EmitPrettyPrint) works on the stream of
/// tokens, constituting the content actually being output, plus additional
/// embedded commands made up begin/end or open/close pairs that delimit the
/// (hierarchy of) groups of tokens that should be printed as a unit. Instances
/// of this class represent all the possible elements of this stream.
///
/// All instances exhibit a broad \e printclass that generally reflects whether
/// the token is one of the begin/end delimiters or is actual content.
/// Instances also have a \e tag_type that indicate the specific function of the
/// token within the stream, which mirror the begin/end/open/close/tag methods
/// on the emitter classes (EmitXml).
class TokenSplit {
public:
  /// \brief An enumeration denoting the general class of a token
  enum printclass {
    begin,		///< A token that starts a printing group
    end,		///< A token that ends a printing group
    tokenstring,	///< A token representing actual content
    tokenbreak,		///< White space (where line breaks can be inserted)
    begin_indent,	///< Start of a new nesting level
    end_indent,		///< End of a nesting level
    begin_comment,	///< Start of a comment block
    end_comment,	///< End of a comment block
    ignore		///< Mark-up that doesn't affect pretty printing
  };

  /// \brief The exhaustive list of possible token types
  enum tag_type {
    docu_b,		///< Start of a document
    docu_e,		///< End of a document
    func_b,		///< Start of a function body
    func_e,		///< End of a function body
    bloc_b,		///< Start of a control-flow section
    bloc_e,		///< End of a control-flow section
    rtyp_b,		///< Start of a return type declaration
    rtyp_e,		///< End of a return type declaration
    vard_b,		///< Start of a variable declaration
    vard_e,		///< End of a variable declaration
    stat_b,		///< Start of a statement
    stat_e,		///< End of a statement
    prot_b,		///< Start of a function prototype
    prot_e,		///< End of a function prototype
    vari_t,		///< A variable identifier
    op_t,		///< An operator
    fnam_t,		///< A function identifier
    type_t,		///< A data-type identifier
    field_t,		///< A field name for a structured data-type
    comm_t,		///< Part of a comment block
    label_t,		///< A code label
    synt_t,		///< Other unspecified syntax
    opar_t,		///< Open parenthesis
    cpar_t,		///< Close parenthesis
    oinv_t,		///< Start of an arbitrary (invisible) grouping
    cinv_t,		///< End of an arbitrary (invisible) grouping
    spac_t,		///< White space
    bump_t,		///< Required line break
    line_t		///< Required line break with one-time indent level
  };
private:
  tag_type tagtype;		///< Type of token
  printclass delimtype;		///< The general class of the token
  string tok;			///< Characters of token (if any)
  EmitXml::syntax_highlight hl;	///< Highlighting for token
  // Additional markup elements for token
  const PcodeOp *op;		///< Pcode-op associated with \b this token
  union {
    const Varnode *vn;		///< Associated Varnode
    const FlowBlock *bl;	///< Associated Control-flow
    const Funcdata *fd;		///< Associated Function
    const Datatype *ct;		///< Associated Data-type
    const AddrSpace *spc;	///< Associated Address
    const Symbol *symbol;	///< Associated Symbol being displayed
  } ptr_second;			///< Additional markup associated with the token
  uintb off;			///< Offset associated either with address or field markup
  int4 indentbump;		///< Amount to indent if a line breaks
  int4 numspaces;		///< Number of spaces in a whitespace token (\e tokenbreak)
  int4 size;			///< Number of content characters or other size information
  int4 count;			///< Associated id (for matching begin/end pairs)
  static int4 countbase;	///< Static counter for uniquely assigning begin/end pair ids.
public:
  TokenSplit(void) { }		///< Constructor

  /// \brief Create a "begin document" command
  ///
  /// \return an id associated with the document
  int4 beginDocument(void) {
    tagtype=docu_b; delimtype=begin; size=0; count=countbase++; return count; }

  /// \brief Create an "end document" command
  ///
  /// \param id is the id associated with the document (as returned by beginDocument)
  void endDocument(int4 id) {
    tagtype=docu_e; delimtype=end; size=0; count=id; }

  /// \brief Create a "begin function body" command
  ///
  /// \return an id associated with the function body
  int4 beginFunction(const Funcdata *f) {
    tagtype=func_b; delimtype=begin; size=0; ptr_second.fd=f; count=countbase++; return count; }

  /// \brief Create an "end function body" command
  ///
  /// \param id is the id associated with the function body (as returned by beginFunction)
  void endFunction(int4 id) {
    tagtype=func_e; delimtype=end; size=0; count=id; }

  /// \brief Create a "begin control-flow element" command
  ///
  /// \param b is the block structure object associated with the section
  /// \return an id associated with the section
  int4 beginBlock(const FlowBlock *b) {
    tagtype=bloc_b; delimtype=ignore; ptr_second.bl=b; count=countbase++; return count; }

  /// \brief Create an "end control-flow element" command
  ///
  /// \param id is the id associated with the section (as returned by beginBlock)
  void endBlock(int4 id) {
    tagtype=bloc_e; delimtype=ignore; count=id; }

  /// \brief Create a "begin return type declaration" command
  ///
  /// \param v (if non-null) is the storage location for the return value
  /// \return an id associated with the return type
  int4 beginReturnType(const Varnode *v) { 
    tagtype=rtyp_b; delimtype=begin; ptr_second.vn=v; count=countbase++; return count; }

  /// \brief Create an "end return type declaration" command
  ///
  /// \param id is the id associated with the return type (as returned by beginReturnType)
  void endReturnType(int4 id) {
    tagtype=rtyp_e; delimtype=end; count=id; }

  /// \brief Create a "begin variable declaration" command
  ///
  /// \param sym is the symbol being declared
  /// \return an id associated with the declaration
  int4 beginVarDecl(const Symbol *sym) {
    tagtype=vard_b; delimtype=begin; ptr_second.symbol=sym; count = countbase++; return count; }

  /// \brief Create an "end variable declaration" command
  ///
  /// \param id is the id associated with the declaration (as returned by beginVarDecl)
  void endVarDecl(int4 id) {
    tagtype=vard_e; delimtype=end; count=id; }

  /// \brief Create a "begin source code statement" command
  ///
  /// \param o is the root p-code operation of the statement
  /// \return an id associated with the statement
  int4 beginStatement(const PcodeOp *o) {
    tagtype=stat_b; delimtype=begin; op=o; count=countbase++; return count; }

  /// \brief Create an "end source code statement" command
  ///
  /// \param id is the id associated with the statement (as returned by beginStatement)
  void endStatement(int4 id) {
    tagtype=stat_e; delimtype=end; count=id; }

  /// \brief Create a "begin function prototype declaration" command
  ///
  /// \return an id associated with the prototype
  int4 beginFuncProto(void) {
    tagtype=prot_b; delimtype=begin; count=countbase++; return count; }

  /// \brief Create an "end function prototype declaration" command
  ///
  /// \param id is the id associated with the prototype (as returned by beginFuncProto)
  void endFuncProto(int4 id) {
    tagtype=prot_e; delimtype=end; count=id; }

  /// \brief Create a variable identifier token
  ///
  /// \param ptr is the character data for the identifier
  /// \param h indicates how the identifier should be highlighted
  /// \param v is the Varnode representing the variable within the syntax tree
  /// \param o is a p-code operation related to the use of the variable (may be null)
  void tagVariable(const char *ptr,EmitXml::syntax_highlight h,
		    const Varnode *v,const PcodeOp *o) {
    tok = ptr; size = tok.size();
    tagtype=vari_t; delimtype=tokenstring; hl=h; ptr_second.vn=v; op=o; }

  /// \brief Create an operator token
  ///
  /// \param ptr is the character data for the emitted representation
  /// \param h indicates how the token should be highlighted
  /// \param o is the PcodeOp object associated with the operation with the syntax tree
  void tagOp(const char *ptr,EmitXml::syntax_highlight h,const PcodeOp *o) {
    tok = ptr; size = tok.size();
    tagtype=op_t; delimtype=tokenstring; hl=h; op=o; }

  /// \brief Create a function identifier token
  ///
  /// \param ptr is the character data for the identifier
  /// \param h indicates how the identifier should be highlighted
  /// \param f is the function
  /// \param o is the CALL operation associated within the syntax tree or null for a declaration
  void tagFuncName(const char *ptr,EmitXml::syntax_highlight h,const Funcdata *f,const PcodeOp *o) {
    tok = ptr; size = tok.size();
    tagtype=fnam_t; delimtype=tokenstring; hl=h; ptr_second.fd=f; op=o; }

  /// \brief Create a data-type identifier token
  ///
  /// \param ptr is the character data for the identifier
  /// \param h indicates how the identifier should be highlighted
  /// \param ct is the data-type description object
  void tagType(const char *ptr,EmitXml::syntax_highlight h,const Datatype *ct) {
    tok = ptr; size = tok.size();
    tagtype=type_t; delimtype=tokenstring; hl=h; ptr_second.ct=ct; }

  /// \brief Create an identifier for a field within a structured data-type
  ///
  /// \param ptr is the character data for the identifier
  /// \param h indicates how the identifier should be highlighted
  /// \param ct is the data-type associated with the field
  /// \param o is the (byte) offset of the field within its structured data-type
  void tagField(const char *ptr,EmitXml::syntax_highlight h,const Datatype *ct,int4 o) {
    tok = ptr; size = tok.size();
    tagtype=field_t; delimtype=tokenstring; hl=h; ptr_second.ct=ct; off=(uintb)o; }

  /// \brief Create a comment string in the generated source code
  ///
  /// \param ptr is the character data for the comment
  /// \param h indicates how the comment should be highlighted
  /// \param s is the address space of the address where the comment is attached
  /// \param o is the offset of the address where the comment is attached
  void tagComment(const char *ptr,EmitXml::syntax_highlight h,
		   const AddrSpace *s,uintb o) {
    tok = ptr; size = tok.size(); ptr_second.spc=s; off=o;
    tagtype=comm_t; delimtype=tokenstring; hl=h; }

  /// \brief Create a code label identifier token
  ///
  /// \param ptr is the character data of the label
  /// \param h indicates how the label should be highlighted
  /// \param s is the address space of the code address being labeled
  /// \param o is the offset of the code address being labeled
  void tagLabel(const char *ptr,EmitXml::syntax_highlight h,
		 const AddrSpace *s,uintb o) {
    tok = ptr; size = tok.size(); ptr_second.spc=s; off=o;
    tagtype=label_t; delimtype=tokenstring; hl=h; }

  /// \brief Create a token for other (more unusual) syntax in source code
  ///
  /// \param str is the character data of the syntax being emitted
  /// \param h indicates how the syntax should be highlighted
  void print(const char *str,EmitXml::syntax_highlight h) {
    tok = str; size=tok.size();
    tagtype=synt_t; delimtype=tokenstring; hl=h; }

  /// \brief Create an open parenthesis
  ///
  /// \param o is the open parenthesis character to emit
  /// \param id is an id to associate with the parenthesis
  void openParen(char o,int4 id) {
    tok = o; size = 1;
    tagtype=opar_t; delimtype=tokenstring; count=id; }

  /// \brief Create a close parenthesis
  ///
  /// \param c is the close parenthesis character to emit
  /// \param id is the id associated with the matching open parenthesis (as returned by openParen)
  void closeParen(char c,int4 id) {
    tok = c; size = 1;
    tagtype=cpar_t; delimtype=tokenstring; count=id; }

  /// \brief Create a "start a printing group" command
  ///
  /// \return an id associated with the group
  int4 openGroup(void) {
    tagtype=oinv_t; delimtype=begin; count=countbase++; return count; }

  /// \brief Create an "end a printing group" command
  ///
  /// \param id is the id associated with the group (as returned by openGroup)
  void closeGroup(int4 id) {
    tagtype=cinv_t; delimtype=end; count=id; }

  /// \brief Create a "start a new indent level" command
  ///
  /// \param bump the number of additional characters to indent
  /// \return an id associated with the nesting
  int4 startIndent(int4 bump) {
    tagtype=bump_t; delimtype=begin_indent; indentbump=bump; size=0;
    count=countbase++; return count; }

  /// \brief Create an "end an indent level" command
  ///
  /// \param id is the id associated with the nesting (as returned by startIndent)
  void stopIndent(int4 id) {
    tagtype=bump_t; delimtype=end_indent; size=0; count=id; }

  /// \brief Create a "start a comment block" command
  ///
  /// \return an id associated with the comment block
  int4 startComment(void) {
    tagtype=oinv_t; delimtype=begin_comment; count=countbase++; return count; }

  /// \brief Create an "end a comment block" command
  ///
  /// \param id is the id associated with the block (as returned by startComment)
  void stopComment(int4 id) {
    tagtype=cinv_t; delimtype=end_comment; count=id; }

  /// \brief Create a whitespace token
  ///
  /// \param num is the number of space characters to emit
  /// \param bump is the number of characters to indent if the spaces force a line break
  void spaces(int4 num,int4 bump) {
    tagtype=spac_t; delimtype=tokenbreak; numspaces=num; indentbump=bump; }

  /// \brief Create a line break token
  void tagLine(void) {
    tagtype=bump_t; delimtype=tokenbreak; numspaces=999999; indentbump=0; }

  /// \brief Create a line break token with special indentation
  void tagLine(int4 indent) {
    tagtype=line_t; delimtype=tokenbreak; numspaces=999999; indentbump=indent; }

  void print(EmitXml *emit) const;			///< Send \b this token to emitter
  int4 getIndentBump(void) const { return indentbump; }	///< Get the extra indent after a line break
  int4 getNumSpaces(void) const { return numspaces; }	///< Get the number of characters of whitespace
  int4 getSize(void) const { return size; }		///< Get the number of content characters
  void setSize(int4 sz) { size = sz; }			///< Set the number of content characters
  printclass getClass(void) const { return delimtype; }	///< Get the print class of \b this
  tag_type getTag(void) const { return tagtype; }	///< Get \b this tag type
#ifdef PRETTY_DEBUG
  int4 getCount(void) const { return count; }		///< Get the delimiter id
  void printDebug(ostream &s) const;			///< Print \b this token to stream for debugging
#endif
};

/// \brief A circular buffer template
///
/// A circular buffer implementation that can act as a stack: push(), pop().
/// Or it can act as a queue: push(), popbottom().  The size of the buffer can be expanded
/// on the fly using expand(). The object being buffered must support a void constructor and
/// the assignment operator.  Objects can also be looked up via an integer reference.
template<typename _type>
class circularqueue {
  _type *cache;		///< An array of the template object
  int4 left;		///< Index within the array of the leftmost object in the queue
  int4 right;		///< Index within the array of the rightmost object in the queue
  int4 max;		///< Size of the array
public:
  circularqueue(int4 sz);		///< Construct queue of a given size
  ~circularqueue(void);			///< Destructor
  void setMax(int4 sz);			///< Establish a new maximum queue size
  int4 getMax(void) const { return max; }	///< Get the maximum queue size
  void expand(int4 amount);		///< Expand the (maximum) size of the queue
  void clear(void) { left=1; right=0; }	///< Clear the queue
  bool empty(void) const { return (left == (right+1)%max); }	///< Is the queue empty
  int4 topref(void) const { return right; }	///< Get a reference to the last object on the queue/stack
  int4 bottomref(void) const { return left; }	///< Get a reference to the first object on the queue/stack
  _type &ref(int4 r) { return cache[r]; }	///< Retrieve an object by its reference
  _type &top(void) { return cache[right]; }	///< Get the last object on the queue/stack
  _type &bottom(void) { return cache[left]; }	///< Get the first object on the queue/stack
  _type &push(void) { right=(right+1)%max; return cache[right]; }	///< Push a new object onto the queue/stack
  _type &pop(void) { int4 tmp=right; right=(right+max-1)%max; return cache[tmp]; }	///< Pop the (last) object on the stack
  _type &popbottom(void) { int4 tmp=left; left=(left+1)%max; return cache[tmp]; }	///< Get the (next) object in the queue
};

/// \param sz is the maximum number of objects the queue will hold
template<typename _type>
circularqueue<_type>::circularqueue(int4 sz)

{
  max = sz;
  left = 1;			// Set queue to be empty
  right = 0;
  cache = new _type [ sz ];
}

template<typename _type>
circularqueue<_type>::~circularqueue(void)

{
  delete [] cache;
}

/// This destroys the old queue and reallocates a new queue with the given maximum size
/// \param sz the maximum size of the new queue
template<typename _type>
void circularqueue<_type>::setMax(int4 sz)

{
  if (max != sz) {
    delete [] cache;
    max = sz;
    cache = new _type [ sz ];
  }
  left = 1;			// This operation empties queue
  right = 0;
}

/// Expand the maximum size of \b this queue.  Objects currently in the queue
/// are preserved, which involves copying the objects. This routine invalidates
/// references referring to objects currently in the queue, although the references
/// can be systematically adjusted to be valid again.
/// \param amount is the number of additional objects the resized queue will support
template<typename _type>
void circularqueue<_type>::expand(int4 amount)

{
  _type *newcache = new _type [ max + amount ];
  
  int4 i=left;
  int4 j=0;

  // Assume there is at least one element in queue
  while(i != right) {
    newcache[j++] = cache[i];
    i = (i+1)%max;
  }
  newcache[j] = cache[i];	// Copy rightmost
  left=0;
  right = j;
  
  delete [] cache;
  cache = newcache;
  max += amount; 
}

/// \brief A generic source code pretty printer
///
/// This pretty printer is based on the standard Derek C. Oppen pretty printing
/// algorithm. It allows configurable indenting, spacing, and line breaks that enhances
/// the readability of the high-level language output. It makes use of the extra
/// information inherent in the AST to make decisions about how to best print language
/// statements. It attempts to abstract the main formatting elements of imperative
/// languages:  statements, code blocks, declarations, etc., and so should be largely
/// language independent. In this way, the main language emitter doesn't have to worry
/// about formatting issues.
///
/// This emitter encapsulates a lower-level emitter that does the final emitting to
/// stream and may add XML markup.
class EmitPrettyPrint : public EmitXml {
#ifdef PRETTY_DEBUG
  vector<int4> checkid;
#endif
  EmitXml *lowlevel;		///< The low-level emitter
  vector<int4> indentstack;	///< Space available for currently active nesting levels
  int4 spaceremain;		///< Space remaining in current line
  int4 maxlinesize;		///< Maximum number of characters allowed in a line
  int4 leftotal;		///< # of characters committed from the current line
  int4 rightotal;		///< # of characters yet to be committed from the current line
  bool needbreak;   		///< \b true if break needed before next token
  bool commentmode;		///< \b true if in the middle of a comment
  string commentfill;		///< Used to fill comments if line breaks are forced
  circularqueue<int4> scanqueue; ///< References to current \e open and \e whitespace tokens
  circularqueue<TokenSplit> tokqueue;	///< The full stream of tokens
  void expand(void);		///< Expand the stream buffer
  void checkstart(void);	///< Enforce whitespace for a \e start token
  void checkend(void);		///< Enforce whitespace for an \e end token
  void checkstring(void);	///< Enforce whitespace for a \e content token
  void checkbreak(void);	///< Enforce whitespace for a line break
  void overflow(void);		///< Reset indenting levels to accommodate a token that won't fit
  void print(const TokenSplit &tok);	///< Output the given token to the low-level emitter
  void advanceleft(void);	///< Emit tokens that have been fully committed
  void scan(void);		///< Process a new token
  void resetDefaultsPrettyPrint(void) { setMaxLineSize(100); } ///< Reset the defaults
public:
  EmitPrettyPrint(void);	///< Construct with an initial maximum line size
  virtual ~EmitPrettyPrint(void);
  virtual int4 beginDocument(void);
  virtual void endDocument(int4 id);
  virtual int4 beginFunction(const Funcdata *fd);
  virtual void endFunction(int4 id);
  virtual int4 beginBlock(const FlowBlock *bl);
  virtual void endBlock(int4 id);
  virtual void tagLine(void);
  virtual void tagLine(int4 indent);
  virtual int4 beginReturnType(const Varnode *vn);
  virtual void endReturnType(int4 id);
  virtual int4 beginVarDecl(const Symbol *sym);
  virtual void endVarDecl(int4 id);
  virtual int4 beginStatement(const PcodeOp *op);
  virtual void endStatement(int4 id);
  virtual int4 beginFuncProto(void);
  virtual void endFuncProto(int4 id);
  virtual void tagVariable(const char *ptr,syntax_highlight hl,
			   const Varnode *vn,const PcodeOp *op);
  virtual void tagOp(const char *ptr,syntax_highlight hl,const PcodeOp *op);
  virtual void tagFuncName(const char *ptr,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op);
  virtual void tagType(const char *ptr,syntax_highlight hl,const Datatype *ct);
  virtual void tagField(const char *ptr,syntax_highlight hl,const Datatype *ct,int4 off);
  virtual void tagComment(const char *ptr,syntax_highlight hl,
			  const AddrSpace *spc,uintb off);
  virtual void tagLabel(const char *ptr,syntax_highlight hl,
			const AddrSpace *spc,uintb off);
  virtual void print(const char *str,syntax_highlight hl=no_color);
  virtual int4 openParen(char o,int4 id=0);
  virtual void closeParen(char c,int4 id);
  virtual int4 openGroup(void);
  virtual void closeGroup(int4 id);
  virtual void clear(void);
  virtual void setOutputStream(ostream *t) { lowlevel->setOutputStream(t); }
  virtual ostream *getOutputStream(void) const { return lowlevel->getOutputStream(); }
  virtual void spaces(int4 num,int4 bump=0);
  virtual int4 startIndent(void);
  virtual void stopIndent(int4 id);
  virtual int4 startComment(void);
  virtual void stopComment(int4 id);
  virtual void flush(void);
  virtual void setMaxLineSize(int4 val);
  virtual int4 getMaxLineSize(void) const { return maxlinesize; }
  virtual void setCommentFill(const string &fill) { commentfill = fill; }
  virtual bool emitsXml(void) const { return lowlevel->emitsXml(); }
  virtual void resetDefaults(void);
  void setXML(bool val);	///< Toggle whether the low-level emitter emits XML markup or not
};

#endif

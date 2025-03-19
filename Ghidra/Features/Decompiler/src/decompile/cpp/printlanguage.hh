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
/// \file printlanguage.hh
/// \brief Classes for printing tokens in a high-level language

#ifndef __PRINTLANGUAGE_HH__
#define __PRINTLANGUAGE_HH__

#include "capability.hh"
#include "cast.hh"
#include "prettyprint.hh"

namespace ghidra {

class PrintLanguage;
class ResolvedUnion;

/// \brief Base class for high-level language capabilities
///
/// This class is overridden to introduce a new high-level language back-end
/// to the system. A static singleton is instantiated to automatically
/// register the new capability with the system. A static array keeps track of
/// all the registered capabilities.
///
/// The singleton is registered with a name, which the user can use to select the language, and
/// it acts as a factory for the main language printing class for the capability,
/// which must be derived from PrintLanguage.  The factory method for the capability to override
/// is buildLanguage().
class PrintLanguageCapability : public CapabilityPoint {
  static vector<PrintLanguageCapability *> thelist;	///< The static array of registered high-level languages
protected:
  string name;			///< Unique identifier for language capability
  bool isdefault;		///< Set to \b true to treat \b this as the default language
public:
  const string &getName(void) const { return name; }	///< Get the high-level language name
  virtual void initialize(void);

  /// \brief Build the main PrintLanguage object corresponding to \b this capability
  ///
  /// An Architecture will call this once. All decompiling from this Architecture will use this same emitter.
  /// \param glb is the Architecture that will own the new emitter
  /// \return the instantiated PrintLanguage emittter
  virtual PrintLanguage *buildLanguage(Architecture *glb)=0;

  static PrintLanguageCapability *getDefault(void);	///< Retrieve the default language capability
  static PrintLanguageCapability *findCapability(const string &name);	///< Find a language capability by name
};

class BlockGraph;
class BlockBasic;
class BlockList;
class BlockCopy;
class BlockGoto;
class BlockIf;
class BlockCondition;
class BlockWhileDo;
class BlockDoWhile;
class BlockInfLoop;
class BlockSwitch;
class Scope;
class Symbol;
class EquateSymbol;
class Comment;

/// \brief A token representing an operator in the high-level language
///
/// The token knows how to print itself and other syntax information like
/// precedence level and associativity within the language, desired spacing,
/// and how operator groups its input expressions. Note that an operator has
/// a broader meaning than just p-code operators in this context.
class OpToken {
public:
  /// \brief The possible types of operator token
  enum tokentype {
    binary,			///< Binary operator form (printed between its inputs)
    unary_prefix,		///< Unary operator form (printed before its input)
    postsurround,		///< Function or array operator form
    presurround,		///< Modifier form (like a cast operation)
    space,			///< No explicitly printed token
    hiddenfunction		///< Operation that isn't explicitly printed
  };
  string print1;		///< Printing characters for the token
  string print2;		///< (terminating) characters for the token
  int4 stage;			///< Additional elements consumed from the RPN stack when emitting this token
  int4 precedence;		///< Precedence level of this token (higher binds more tightly)
  bool associative;		///< True if the operator is associative
  tokentype type;		///< The basic token type
  int4 spacing;			///< Spaces to print around operator
  int4 bump;			///< Spaces to indent if we break here
  OpToken *negate;		///< The token representing the negation of this token
};

/// \brief The base class API for emitting a high-level language
///
/// Instances of this object are responsible for converting a function's
/// (transformed) data-flow graph into the final stream of tokens of a high-level
/// source code language.  There a few main entry points including:
///   - docFunction()
///   - docAllGlobals()
///   - docTypeDefinitions()
///
/// The system is responsible for printing:
///   - Control-flow structures
///   - Expressions
///   - Type declarations
///   - Function prototypes
///   - Comments
///
/// As part of all this printing, the system is also responsible for
///   - Emitting integers, floats, and character constants
///   - Placing parentheses within expressions to properly represent data-flow
///   - Deciding whether \e cast operations need an explicit cast token
///   - Indenting and line wrapping
///
/// To accomplish this, the API is broken up into three sections. The first section
/// are the main entry point 'doc' methods. The second section are 'emit' methods, which
/// are responsible for printing a representation of a particular high-level code construct.
/// The third section are 'push' and 'op' methods, which are responsible for walking expression trees.
/// The order in which tokens are emitted for an expression is determined by a
/// Reverse Polish Notation (RPN) stack, that the 'push' methods manipulate. Operators and variables
/// are \e pushed onto this stack and are ultimately \e emitted in the correct order.
///
/// The base class provides a generic \e printing \e modifications stack and a \e symbol \e scope
/// stack to provide a printing context mechanism for derived classes.
class PrintLanguage {
public:
  static const string OPEN_PAREN;	///< "(" token
  static const string CLOSE_PAREN;	///< ")" token

  /// \brief Possible context sensitive modifiers to how tokens get emitted
  enum modifiers {
    force_hex = 1,		///< Force printing of hex
    force_dec = 2,     		///< Force printing of dec
    bestfit = 4,       		///< Decide on most aesthetic form
    force_scinote = 8,		///< Force scientific notation for floats
    force_pointer = 0x10,	///< Force '*' notation for pointers
    print_load_value = 0x20,	///< Hide pointer deref for load with other ops
    print_store_value = 0x40,	///< Hide pointer deref for store with other ops
    no_branch = 0x80,		///< Do not print branch instruction
    only_branch = 0x100,	///< Print only the branch instruction
    comma_separate = 0x200,	///< Statements within condition
    flat = 0x400,		///< Do not print block structure
    falsebranch = 0x800,	///< Print the false branch (for flat)
    nofallthru = 0x1000,       	///< Fall-thru no longer exists
    negatetoken = 0x2000,	///< Print the token representing the negation of current token
    hide_thisparam = 0x4000,	///< Do not print the 'this' parameter in argument lists
    pending_brace = 0x8000	///< The current block may need to surround itself with additional braces
  };
  /// \brief Possible types of Atom
  enum tagtype {
    syntax,			///< Emit atom as syntax
    vartoken,			///< Emit atom as variable
    functoken,			///< Emit atom as function name
    optoken,			///< Emit atom as operator
    typetoken,			///< Emit atom as operator
    fieldtoken,			///< Emit atom as structure field
    casetoken,			///< Emit atom as a \e case label
    blanktoken			///< For anonymous types
  };

  /// \brief Strategies for displaying namespace tokens
  enum namespace_strategy {
    MINIMAL_NAMESPACES = 0,	///< (default) Print just enough namespace info to fully resolve symbol
    NO_NAMESPACES = 1,		///< Never print namespace information
    ALL_NAMESPACES = 2		///< Always print all namespace information
  };

  /// \brief An entry on the reverse polish notation (RPN) stack
  struct ReversePolish {
    const OpToken *tok;		///< The operator token
    int4 visited;		///< The current stage of printing for the operator
    bool paren;			///< True if parentheses are required
    const PcodeOp *op;		///< The PcodeOp associated with the operator token
    int4 id;			///< The id of the token group which \b this belongs to
    mutable int4 id2;		///< The id of the token group \b this surrounds (for surround operator tokens)
  };

  /// \brief A pending data-flow node; waiting to be placed on the reverse polish notation stack
  ///
  /// This holds an \e implied Varnode in the data-flow graph, which prints as the expression producing
  /// the value in the Varnode.
  struct NodePending {
    const Varnode *vn;		///< The implied Varnode
    const PcodeOp *op;		///< The single operator consuming value from the implied Varnode
    uint4 vnmod;		///< Printing modifications to enforce on the expression

    /// \brief Construct a pending data-flow node
    NodePending(const Varnode *v,const PcodeOp *o,uint4 m) {
      vn = v; op = o; vnmod = m; }
  };

  /// \brief A single non-operator token emitted by the decompiler
  ///
  /// These play the role of variable tokens on the RPN stack with the operator tokens.
  /// The term \e variable has a broader meaning than just a Varnode. An Atom can also be a data-type
  /// name, a function name, or a structure field etc.
  struct Atom {
    const string &name;		///< The actual printed characters of the token
    tagtype type;		///< The type of Atom
    EmitMarkup::syntax_highlight highlight;	///< The type of highlighting to use when emitting the token
    const PcodeOp *op;		///< A p-code operation associated with the token
    union {
      const Varnode *vn;	///< A Varnode associated with the token
      const Funcdata *fd;	///< A function associated with the token
      const Datatype *ct;	///< A type associated with the token
      uintb intValue;		///< An integer value associated with the token
    } ptr_second;		///< Other meta-data associated with the token
    int4 offset;        	///< The offset (within the parent structure) for a \e field token

    /// \brief Construct a token with no associated data-flow annotations
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl)
      : name(nm) { type = t; highlight = hl; }

    /// \brief Construct a token for a data-type name
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl,const Datatype *c)
      : name(nm) { type = t; highlight = hl; ptr_second.ct = c; }

    /// \brief Construct a token for a field name
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl,const Datatype *c,int4 off,const PcodeOp *o)
      : name(nm) { type = t; highlight = hl; ptr_second.ct = c; offset = off; op = o; }

    /// \brief Construct a token with an associated PcodeOp
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl,const PcodeOp *o)
      : name(nm) { type = t; highlight = hl; op = o; }

    /// \brief Construct a token with an associated PcodeOp and Varnode
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl,const PcodeOp *o,const Varnode *v)
      : name(nm) { type=t; highlight = hl; ptr_second.vn = v; op = o; }

    /// \brief Construct a token for a function name
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl,const PcodeOp *o,const Funcdata *f)
      : name(nm) { type=t; highlight = hl; op = o; ptr_second.fd = f; }

    /// \brief Construct a token with an associated PcodeOp, Varnode, and constant value
    Atom(const string &nm,tagtype t,EmitMarkup::syntax_highlight hl,const PcodeOp *o,const Varnode *v,uintb intValue)
      : name(nm) {
      type=t;
      highlight = hl;
      if (t==casetoken)
	ptr_second.intValue = intValue;
      else
	ptr_second.vn = v;
      op = o;
    }

  };
private:
  string name;				///< The name of the high-level language
  vector<uint4> modstack;		///< Printing modification stack
  vector<const Scope *> scopestack;	///< The symbol scope stack
  vector<ReversePolish> revpol;		///< The Reverse Polish Notation (RPN) token stack
  vector<NodePending> nodepend;		///< Data-flow nodes waiting to be pushed onto the RPN stack
  int4 pending;				///< Number of data-flow nodes waiting to be pushed
  int4 line_commentindent;		///< Number of characters a comment line should be indented
  string commentstart;			///< Delimiter characters for the start of a comment
  string commentend;			///< Delimiter characters (if any) for the end of a comment
protected:
  Architecture *glb;			///< The Architecture owning the language emitter
  const Scope *curscope;		///< The current symbol scope
  CastStrategy *castStrategy;		///< The strategy for emitting explicit \e case operations
  Emit *emit;				///< The low-level token emitter
  uint4 mods;				///< Currently active printing modifications
  uint4 instr_comment_type;		///< Type of instruction comments to display
  uint4 head_comment_type;		///< Type of header comments to display
  namespace_strategy namespc_strategy;	///< How should namespace tokens be displayed
#ifdef CPUI_DEBUG
  bool isStackEmpty(void) const { return (nodepend.empty()&&revpol.empty()); }	///< Return \b true if the RPN stack is empty
  bool isModStackEmpty(void) const { return modstack.empty(); }			///< Return \b true if the printing modification stack is empty
#endif
  // Routines that are probably consistent across languages
  bool isSet(uint4 m) const { return ((mods & m)!=0); }				///< Is the given printing modification active
  void pushScope(const Scope *sc) { scopestack.push_back(sc); curscope = sc; }	///< Push a new symbol scope
  void popScope(void);								///< Pop to the previous symbol scope
  void pushMod(void) { modstack.push_back(mods); }				///< Push current printing modifications to the stack
  void popMod(void) { mods = modstack.back(); modstack.pop_back(); }		///< Pop to the previous printing modifications
  void setMod(uint4 m) { mods |= m; }						///< Activate the given printing modification
  void unsetMod(uint4 m) { mods &= ~m; }					///< Deactivate the given printing modification
  void pushOp(const OpToken *tok,const PcodeOp *op);			///< Push an operator token onto the RPN stack
  void pushAtom(const Atom &atom);					///< Push a variable token onto the RPN stack
  void pushVn(const Varnode *vn,const PcodeOp *op,uint4 m);	///< Push an expression rooted at a Varnode onto the RPN stack
  void pushVnExplicit(const Varnode *vn,const PcodeOp *op);		///< Push an explicit variable onto the RPN stack
  void pushSymbolDetail(const Varnode *vn,const PcodeOp *op,bool isRead);	///< Push symbol name with adornments matching given Varnode

  bool parentheses(const OpToken *op2);	///< Determine if the given token should be emitted in its own parenthetic expression
  void emitOp(const ReversePolish &entry);				///< Send an operator token from the RPN to the emitter
  void emitAtom(const Atom &atom);					///< Send an variable token from the RPN to the emitter
  static bool unicodeNeedsEscape(int4 codepoint);			///< Determine if the given codepoint needs to be escaped
  bool escapeCharacterData(ostream &s,const uint1 *buf,int4 count,int4 charsize,bool bigend) const;
  void recurse(void);							///< Emit from the RPN stack as much as possible
  void opBinary(const OpToken *tok,const PcodeOp *op);			///< Push a binary operator onto the RPN stack
  void opUnary(const OpToken *tok,const PcodeOp *op);			///< Push a unary operator onto the RPN stack
  int4 getPending(void) const { return pending; }			///< Get the number of pending nodes yet to be put on the RPN stack
  void resetDefaultsInternal(void);					///< Reset options to default for PrintLanguage

  /// \brief Print a single unicode character as a \e character \e constant for the high-level language
  ///
  /// For most languages, this prints the character surrounded by single quotes.
  /// \param s is the output stream
  /// \param onechar is the unicode code point of the character to print
  virtual void printUnicode(ostream &s,int4 onechar) const=0;

  /// \brief Push a data-type name onto the RPN expression stack.
  ///
  /// The data-type is generally emitted as if for a cast.
  /// \param ct is the data-type to push
  virtual void pushType(const Datatype *ct)=0;

  /// \brief Push a constant onto the RPN stack.
  ///
  /// The value is ultimately emitted based on its data-type and other associated mark-up
  /// \param val is the value of the constant
  /// \param ct is the data-type of the constant
  /// \param tag is the type of token associated with the constant
  /// \param vn is the Varnode holding the constant (optional)
  /// \param op is the PcodeOp using the constant (optional)
  virtual void pushConstant(uintb val,const Datatype *ct,tagtype tag,
			    const Varnode *vn,const PcodeOp *op)=0;

  /// \brief Push a constant marked up by and EquateSymbol onto the RPN stack
  ///
  /// The equate may substitute a name or force a conversion for the constant
  /// \param val is the value of the constant
  /// \param sz is the number of bytes to use for the encoding
  /// \param sym is the EquateSymbol that marks up the constant
  /// \param vn is the Varnode holding the constant (optional)
  /// \param op is the PcodeOp using the constant (optional)
  virtual bool pushEquate(uintb val,int4 sz,const EquateSymbol *sym,const Varnode *vn,const PcodeOp *op)=0;

  /// \brief Push an address which is not in the normal data-flow.
  ///
  /// The given Varnode is treated as an address, which may or may not have a symbol name.
  /// \param vn is the annotation Varnode
  /// \param op is the PcodeOp which takes the annotation as input
  virtual void pushAnnotation(const Varnode *vn,const PcodeOp *op)=0;

  /// \brief Push a specific Symbol onto the RPN stack
  ///
  /// \param sym is the given Symbol
  /// \param vn is the Varnode holding the Symbol value
  /// \param op is a PcodeOp associated with the Varnode
  virtual void pushSymbol(const Symbol *sym,const Varnode *vn,const PcodeOp *op)=0;

  /// \brief Push an address as a substitute for a Symbol onto the RPN stack
  ///
  /// If there is no Symbol or other name source for an explicit variable,
  /// this method is used to print something to represent the variable based on its storage address.
  /// \param addr is the storage address
  /// \param vn is the Varnode representing the variable (if present)
  /// \param op is a PcodeOp associated with the variable
  virtual void pushUnnamedLocation(const Address &addr,const Varnode *vn,const PcodeOp *op)=0;

  /// \brief Push a variable that represents only part of a symbol onto the RPN stack
  ///
  /// Generally \e member syntax specifying a field within a structure gets emitted.
  /// Nested structures may result in multiple fields being emitted to get to the final size.
  /// If the final size requires truncating a data-type that is not a structure, this method
  /// can optionally emit a final cast to represent the truncation, otherwise an artificial
  /// field representing the truncation is emitted. Any \e union encountered is resolved using
  /// the given PcodeOp and slot.
  /// \param sym is the root Symbol
  /// \param off is the byte offset, within the Symbol, of the partial variable
  /// \param sz is the number of bytes in the partial variable
  /// \param vn is the Varnode holding the partial value
  /// \param op is a PcodeOp associate with the Varnode
  /// \param slot is the slot to use (relative to \b op) for any data-type requiring resolution
  /// \param allowCast is \b true if a final truncation should be printed as a cast
  virtual void pushPartialSymbol(const Symbol *sym,int4 off,int4 sz,
				 const Varnode *vn,const PcodeOp *op,int4 slot,bool allowCast)=0;

  /// \brief Push an identifier for a variable that mismatches with its Symbol
  ///
  /// This happens when a Varnode overlaps, but is not contained by a Symbol.
  /// This most commonly happens when the size of a Symbol is unknown
  /// \param sym is the overlapped symbol
  /// \param off is the byte offset of the variable relative to the symbol
  /// \param sz is the size of the variable in bytes
  /// \param vn is the Varnode representing the variable
  /// \param op is a PcodeOp associated with the Varnode
  virtual void pushMismatchSymbol(const Symbol *sym,int4 off,int4 sz,
				  const Varnode *vn,const PcodeOp *op)=0;

  /// \brief Push the implied field of a given Varnode as an object member extraction operation
  ///
  /// If a Varnode is \e implied and has a \e union data-type, the particular read of the varnode
  /// may correspond to a particular field that needs to get printed as a token, even though the
  /// Varnode itself is printed directly.  This method pushes the field name token.
  /// \param vn is the given Varnode
  /// \param op is the particular PcodeOp reading the Varnode
  virtual void pushImpliedField(const Varnode *vn,const PcodeOp *op)=0;

  virtual void emitLineComment(int4 indent,const Comment *comm);	///< Emit a comment line

  /// \brief Emit a variable declaration
  ///
  /// This can be part of a full a statement, or just the declaration of a function parameter
  /// \param sym is the Symbol to be declared
  virtual void emitVarDecl(const Symbol *sym)=0;

  /// \brief Emit a variable declaration statement
  ///
  /// \param sym is the Symbol to be declared
  virtual void emitVarDeclStatement(const Symbol *sym)=0;

  /// \brief Emit all the variable declarations for a given scope
  ///
  /// A subset of all variables can be declared by specifying a category,
  /// 0 for parameters, -1 for everything.
  /// \param symScope is the given Scope
  /// \param cat is the category of variable to declare
  virtual bool emitScopeVarDecls(const Scope *symScope,int4 cat)=0;

  /// \brief Emit a full expression
  ///
  /// This can be an assignment statement, if the given PcodeOp has an output Varnode,
  /// or it can be a statement with no left-hand side.
  /// \param op is the given PcodeOp performing the final operation of the expression
  virtual void emitExpression(const PcodeOp *op)=0;

  /// \brief Emit a function declaration
  ///
  /// This prints the formal defining prototype for a function.
  /// \param fd is the Funcdata object representing the function to be emitted
  virtual void emitFunctionDeclaration(const Funcdata *fd)=0;

  /// \brief Check whether a given boolean Varnode can be printed in negated form.
  ///
  /// In many situations a boolean value can be inverted by flipping the operator
  /// token producing it to a complementary token.
  /// \param vn is the given boolean Varnode
  /// \return \b true if the value can be easily inverted
  virtual bool checkPrintNegation(const Varnode *vn)=0;
public:
  PrintLanguage(Architecture *g,const string &nm);			///< Constructor
  virtual ~PrintLanguage(void);						///< Destructor
  const string &getName(void) const { return name; }			///< Get the language name
  CastStrategy *getCastStrategy(void) const { return castStrategy; }	///< Get the casting strategy for the language
  ostream *getOutputStream(void) const { return emit->getOutputStream(); }	///< Get the output stream being emitted to
  void setOutputStream(ostream *t) { emit->setOutputStream(t); }	///< Set the output stream to emit to
  void setMaxLineSize(int4 mls) { emit->setMaxLineSize(mls); }		///< Set the maximum number of characters per line
  void setIndentIncrement(int4 inc) { emit->setIndentIncrement(inc); }	///< Set the number of characters to indent per level of code nesting
  void setLineCommentIndent(int4 val);					///< Set the number of characters to indent comment lines
  void setCommentDelimeter(const string &start,const string &stop,
			   bool usecommentfill);			///< Establish comment delimiters for the language
  uint4 getInstructionComment(void) const { return instr_comment_type; }	///< Get the type of comments suitable within the body of a function
  void setInstructionComment(uint4 val) { instr_comment_type = val; }	///< Set the type of comments suitable within the body of a function
  void setNamespaceStrategy(namespace_strategy strat) { namespc_strategy = strat; }	///< Set how namespace tokens are displayed
  uint4 getHeaderComment(void) const { return head_comment_type; }	///< Get the type of comments suitable for a function header
  void setHeaderComment(uint4 val) { head_comment_type = val; }		///< Set the type of comments suitable for a function header
  bool emitsMarkup(void) const { return emit->emitsMarkup(); }		///< Does the low-level emitter, emit markup
  void setMarkup(bool val) { emit->setMarkup(val); }			///< Turn on/off mark-up in emitted output
  void setPackedOutput(bool val);					///< Turn on/off packed output
  void setFlat(bool val);						///< Set whether nesting code structure should be emitted

  virtual void initializeFromArchitecture(void)=0;		///< Initialize architecture specific aspects of printer
  virtual void adjustTypeOperators(void)=0;			///< Set basic data-type information for p-code operators
  virtual void resetDefaults(void);				///< Set printing options to their default value
  virtual void clear(void);					///< Clear the RPN stack and the low-level emitter
  virtual void setIntegerFormat(const string &nm);		///< Set the default integer format

  /// \brief Set the way comments are displayed in decompiler output
  ///
  /// This method can either be provided a formal name or a \e sample of the initial delimiter,
  /// then it will choose from among the schemes it knows
  /// \param nm is the configuration description
  virtual void setCommentStyle(const string &nm)=0;

  /// \brief Emit definitions of data-types
  ///
  /// \param typegrp is the container for the data-types that should be defined
  virtual void docTypeDefinitions(const TypeFactory *typegrp)=0;

  /// \brief Emit declarations of global variables
  virtual void docAllGlobals(void)=0;

  /// \brief Emit the declaration for a single (global) Symbol
  ///
  /// \param sym is the Symbol to declare
  virtual void docSingleGlobal(const Symbol *sym)=0;

  /// \brief Emit the declaration (and body) of a function
  ///
  /// \param fd is the function to emit
  virtual void docFunction(const Funcdata *fd)=0;

  virtual void emitBlockBasic(const BlockBasic *bb)=0;			///< Emit statements in a basic block
  virtual void emitBlockGraph(const BlockGraph *bl)=0;			///< Emit (an unspecified) list of blocks
  virtual void emitBlockCopy(const BlockCopy *bl)=0;			///< Emit a basic block (with any labels)
  virtual void emitBlockGoto(const BlockGoto *bl)=0;			///< Emit a block ending with a goto statement
  virtual void emitBlockLs(const BlockList *bl)=0;			///< Emit a sequence of blocks
  virtual void emitBlockCondition(const BlockCondition *bl)=0;		///< Emit a conditional statement
  virtual void emitBlockIf(const BlockIf *bl)=0;			///< Emit an if/else style construct
  virtual void emitBlockWhileDo(const BlockWhileDo *bl)=0;		///< Emit a loop structure, check at top
  virtual void emitBlockDoWhile(const BlockDoWhile *bl)=0;		///< Emit a loop structure, check at bottom
  virtual void emitBlockInfLoop(const BlockInfLoop *bl)=0;		///< Emit an infinite loop structure
  virtual void emitBlockSwitch(const BlockSwitch *bl)=0;		///< Emit a switch structure

  virtual void opCopy(const PcodeOp *op)=0;				///< Emit a COPY operator
  virtual void opLoad(const PcodeOp *op)=0;				///< Emit a LOAD operator
  virtual void opStore(const PcodeOp *op)=0;				///< Emit a STORE operator
  virtual void opBranch(const PcodeOp *op)=0;				///< Emit a BRANCH operator
  virtual void opCbranch(const PcodeOp *op)=0;				///< Emit a CBRANCH operator
  virtual void opBranchind(const PcodeOp *op)=0;			///< Emit a BRANCHIND operator
  virtual void opCall(const PcodeOp *op)=0;				///< Emit a CALL operator
  virtual void opCallind(const PcodeOp *op)=0;				///< Emit a CALLIND operator
  virtual void opCallother(const PcodeOp *op)=0;			///< Emit a CALLOTHER operator
  virtual void opConstructor(const PcodeOp *op,bool withNew)=0;		///< Emit an operator constructing an object
  virtual void opReturn(const PcodeOp *op)=0;				///< Emit a RETURN operator
  virtual void opIntEqual(const PcodeOp *op)=0;				///< Emit a INT_EQUAL operator
  virtual void opIntNotEqual(const PcodeOp *op)=0;			///< Emit a INT_NOTEQUAL operator
  virtual void opIntSless(const PcodeOp *op)=0;				///< Emit a INT_SLESS operator
  virtual void opIntSlessEqual(const PcodeOp *op)=0;			///< Emit a INT_SLESSEQUAL operator
  virtual void opIntLess(const PcodeOp *op)=0;				///< Emit a INT_LESS operator
  virtual void opIntLessEqual(const PcodeOp *op)=0;			///< Emit a INT_LESSEQUAL operator
  virtual void opIntZext(const PcodeOp *op,const PcodeOp *readOp)=0;	///< Emit a INT_ZEXT operator
  virtual void opIntSext(const PcodeOp *op,const PcodeOp *readOp)=0;	///< Emit a INT_SEXT operator
  virtual void opIntAdd(const PcodeOp *op)=0;				///< Emit a INT_ADD operator
  virtual void opIntSub(const PcodeOp *op)=0;				///< Emit a INT_SUB operator
  virtual void opIntCarry(const PcodeOp *op)=0;				///< Emit a INT_CARRY operator
  virtual void opIntScarry(const PcodeOp *op)=0;			///< Emit a INT_SCARRY operator
  virtual void opIntSborrow(const PcodeOp *op)=0;			///< Emit a INT_SBORROW operator
  virtual void opInt2Comp(const PcodeOp *op)=0;				///< Emit a INT_2COMP operator
  virtual void opIntNegate(const PcodeOp *op)=0;			///< Emit a INT_NEGATE operator
  virtual void opIntXor(const PcodeOp *op)=0;				///< Emit a INT_XOR operator
  virtual void opIntAnd(const PcodeOp *op)=0;				///< Emit a INT_AND operator
  virtual void opIntOr(const PcodeOp *op)=0;				///< Emit a INT_OR operator
  virtual void opIntLeft(const PcodeOp *op)=0;				///< Emit a INT_LEFT operator
  virtual void opIntRight(const PcodeOp *op)=0;				///< Emit a INT_RIGHT operator
  virtual void opIntSright(const PcodeOp *op)=0;			///< Emit a INT_SRIGHT operator
  virtual void opIntMult(const PcodeOp *op)=0;				///< Emit a INT_MULT operator
  virtual void opIntDiv(const PcodeOp *op)=0;				///< Emit a INT_DIV operator
  virtual void opIntSdiv(const PcodeOp *op)=0;				///< Emit a INT_SDIV operator
  virtual void opIntRem(const PcodeOp *op)=0;				///< Emit a INT_REM operator
  virtual void opIntSrem(const PcodeOp *op)=0;				///< Emit a INT_SREM operator
  virtual void opBoolNegate(const PcodeOp *op)=0;			///< Emit a BOOL_NEGATE operator
  virtual void opBoolXor(const PcodeOp *op)=0;				///< Emit a BOOL_XOR operator
  virtual void opBoolAnd(const PcodeOp *op)=0;				///< Emit a BOOL_AND operator
  virtual void opBoolOr(const PcodeOp *op)=0;				///< Emit a BOOL_OR operator
  virtual void opFloatEqual(const PcodeOp *op)=0;			///< Emit a FLOAT_EQUAL operator
  virtual void opFloatNotEqual(const PcodeOp *op)=0;			///< Emit a FLOAT_NOTEQUAL operator
  virtual void opFloatLess(const PcodeOp *op)=0;			///< Emit a FLOAT_LESS operator
  virtual void opFloatLessEqual(const PcodeOp *op)=0;			///< Emit a FLOAT_LESSEQUAL operator
  virtual void opFloatNan(const PcodeOp *op)=0;				///< Emit a FLOAT_NAN operator
  virtual void opFloatAdd(const PcodeOp *op)=0;				///< Emit a FLOAT_ADD operator
  virtual void opFloatDiv(const PcodeOp *op)=0;				///< Emit a FLOAT_DIV operator
  virtual void opFloatMult(const PcodeOp *op)=0;			///< Emit a FLOAT_MULT operator
  virtual void opFloatSub(const PcodeOp *op)=0;				///< Emit a FLOAT_SUB operator
  virtual void opFloatNeg(const PcodeOp *op)=0;				///< Emit a FLOAT_NEG operator
  virtual void opFloatAbs(const PcodeOp *op)=0;				///< Emit a FLOAT_ABS operator
  virtual void opFloatSqrt(const PcodeOp *op)=0;			///< Emit a FLOAT_SQRT operator
  virtual void opFloatInt2Float(const PcodeOp *op)=0;			///< Emit a FLOAT_INT2FLOAT operator
  virtual void opFloatFloat2Float(const PcodeOp *op)=0;			///< Emit a FLOAT_FLOAT2FLOAT operator
  virtual void opFloatTrunc(const PcodeOp *op)=0;			///< Emit a FLOAT_TRUNC operator
  virtual void opFloatCeil(const PcodeOp *op)=0;			///< Emit a FLOAT_CEIL operator
  virtual void opFloatFloor(const PcodeOp *op)=0;			///< Emit a FLOAT_FLOOR operator
  virtual void opFloatRound(const PcodeOp *op)=0;			///< Emit a FLOAT_ROUND operator
  virtual void opMultiequal(const PcodeOp *op)=0;			///< Emit a MULTIEQUAL operator
  virtual void opIndirect(const PcodeOp *op)=0;				///< Emit a INDIRECT operator
  virtual void opPiece(const PcodeOp *op)=0;				///< Emit a PIECE operator
  virtual void opSubpiece(const PcodeOp *op)=0;				///< Emit a SUBPIECE operator
  virtual void opCast(const PcodeOp *op)=0;				///< Emit a CAST operator
  virtual void opPtradd(const PcodeOp *op)=0;				///< Emit a PTRADD operator
  virtual void opPtrsub(const PcodeOp *op)=0;				///< Emit a PTRSUB operator
  virtual void opSegmentOp(const PcodeOp *op)=0;			///< Emit a SEGMENTOP operator
  virtual void opCpoolRefOp(const PcodeOp *op)=0;			///< Emit a CPOOLREF operator
  virtual void opNewOp(const PcodeOp *op)=0;				///< Emit a NEW operator
  virtual void opInsertOp(const PcodeOp *op)=0;				///< Emit an INSERT operator
  virtual void opExtractOp(const PcodeOp *op)=0;			///< Emit an EXTRACT operator
  virtual void opPopcountOp(const PcodeOp *op)=0;			///< Emit a POPCOUNT operator
  virtual void opLzcountOp(const PcodeOp *op)=0;			///< Emit a LZCOUNT operator
  virtual string unnamedField(int4 off,int4 size);			///< Generate an artificial field name

  static int4 mostNaturalBase(uintb val); 			///< Determine the most natural base for an integer
  static void formatBinary(ostream &s,uintb val);		///< Print a number in binary form
};

} // End namespace ghidra
#endif

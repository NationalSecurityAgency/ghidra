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
#include "printc.hh"
#include "funcdata.hh"

namespace ghidra {

// Operator tokens for expressions
//                        token #in prec assoc   optype       space bump
OpToken PrintC::hidden = { "", "", 1, 70, false, OpToken::hiddenfunction, 0, 0, (OpToken *)0 };
OpToken PrintC::scope = { "::", "", 2, 70, true, OpToken::binary, 0, 0, (OpToken *)0 };
OpToken PrintC::object_member = { ".", "", 2, 66, true, OpToken::binary, 0, 0, (OpToken *)0  };
OpToken PrintC::pointer_member = { "->", "", 2, 66, true, OpToken::binary, 0, 0, (OpToken *)0 };
OpToken PrintC::subscript = { "[", "]", 2, 66, false, OpToken::postsurround, 0, 0, (OpToken *)0 };
OpToken PrintC::function_call = { "(", ")", 2, 66, false, OpToken::postsurround, 0, 10, (OpToken *)0 };
OpToken PrintC::bitwise_not = { "~", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::boolean_not = { "!", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::unary_minus = { "-", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::unary_plus = { "+", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::addressof = { "&", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::dereference = { "*", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::typecast = { "(", ")", 2, 62, false, OpToken::presurround, 0, 0, (OpToken *)0 };
OpToken PrintC::multiply = { "*", "", 2, 54, true, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::divide = { "/", "", 2, 54, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::modulo = { "%", "", 2, 54, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::binary_plus = { "+", "", 2, 50, true, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::binary_minus = { "-", "", 2, 50, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::shift_left = { "<<", "", 2, 46, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::shift_right = { ">>", "", 2, 46, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::shift_sright = { ">>", "", 2, 46, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::less_than = { "<", "", 2, 42, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::less_equal = { "<=", "", 2, 42, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::greater_than = { ">", "", 2, 42, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::greater_equal = { ">=", "", 2, 42, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::equal = { "==", "", 2, 38, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::not_equal = { "!=", "", 2, 38, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::bitwise_and = { "&", "", 2, 34, true, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::bitwise_xor = { "^", "", 2, 30, true, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::bitwise_or = { "|", "", 2, 26, true, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::boolean_and = { "&&", "", 2, 22, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::boolean_xor = { "^^", "", 2, 20, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::boolean_or = { "||", "", 2, 18, false, OpToken::binary, 1, 0, (OpToken *)0 };
OpToken PrintC::assignment = { "=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::comma = { ",", "", 2, 2, true, OpToken::binary, 0, 0, (OpToken *)0 };
OpToken PrintC::new_op = { "", "", 2, 62, false, OpToken::space, 1, 0, (OpToken *)0 };

// Inplace assignment operators
OpToken PrintC::multequal = { "*=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::divequal = { "/=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::remequal = { "%=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::plusequal = { "+=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::minusequal = { "-=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::leftequal = { "<<=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::rightequal = { ">>=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::andequal = { "&=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::orequal = { "|=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };
OpToken PrintC::xorequal = { "^=", "", 2, 14, false, OpToken::binary, 1, 5, (OpToken *)0 };

// Operator tokens for type expressions
OpToken PrintC::type_expr_space = { "", "", 2, 10, false, OpToken::space, 1, 0, (OpToken *)0 };
OpToken PrintC::type_expr_nospace = { "", "", 2, 10, false, OpToken::space, 0, 0, (OpToken *)0 };
OpToken PrintC::ptr_expr = { "*", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0 };
OpToken PrintC::array_expr = { "[", "]", 2, 66, false, OpToken::postsurround, 1, 0, (OpToken *)0 };
OpToken PrintC::enum_cat = { "|", "", 2, 26, true, OpToken::binary, 0, 0, (OpToken *)0 };

const string PrintC::EMPTY_STRING = "";
const string PrintC::OPEN_CURLY = "{";
const string PrintC::CLOSE_CURLY = "}";
const string PrintC::SEMICOLON = ";";
const string PrintC::COLON = ":";
const string PrintC::EQUALSIGN = "=";
const string PrintC::COMMA = ",";
const string PrintC::DOTDOTDOT = "...";
const string PrintC::KEYWORD_VOID = "void";
const string PrintC::KEYWORD_TRUE = "true";
const string PrintC::KEYWORD_FALSE = "false";
const string PrintC::KEYWORD_IF = "if";
const string PrintC::KEYWORD_ELSE = "else";
const string PrintC::KEYWORD_DO = "do";
const string PrintC::KEYWORD_WHILE = "while";
const string PrintC::KEYWORD_FOR = "for";
const string PrintC::KEYWORD_GOTO = "goto";
const string PrintC::KEYWORD_BREAK = "break";
const string PrintC::KEYWORD_CONTINUE = "continue";
const string PrintC::KEYWORD_CASE = "case";
const string PrintC::KEYWORD_SWITCH = "switch";
const string PrintC::KEYWORD_DEFAULT = "default";
const string PrintC::KEYWORD_RETURN = "return";
const string PrintC::KEYWORD_NEW = "new";
const string PrintC::typePointerRelToken = "ADJ";

// Constructing this registers the capability
PrintCCapability PrintCCapability::printCCapability;

PrintCCapability::PrintCCapability(void)

{
  name = "c-language";
  isdefault = true;
}

PrintLanguage *PrintCCapability::buildLanguage(Architecture *glb)

{
  return new PrintC(glb,name);
}

/// \param g is the Architecture owning this c-language emitter
/// \param nm is the name assigned to this emitter
PrintC::PrintC(Architecture *g,const string &nm) : PrintLanguage(g,nm)

{
  nullToken = "NULL";
  
  // Set the flip tokens
  less_than.negate = &greater_equal;
  less_equal.negate = &greater_than;
  greater_than.negate = &less_equal;
  greater_equal.negate = &less_than;
  equal.negate = &not_equal;
  not_equal.negate = &equal;

  castStrategy = new CastStrategyC();
  resetDefaultsPrintC();
}

/// Push nested components of a data-type declaration onto a stack, so we can access it bottom up
/// \param ct is the data-type being emitted
/// \param typestack will hold the sub-types involved in the displaying the declaration
void PrintC::buildTypeStack(const Datatype *ct,vector<const Datatype *> &typestack)

{
  for(;;) {
    typestack.push_back(ct);
    if (ct->getName().size() != 0)	// This can be a base type
      break;
    if (ct->getMetatype()==TYPE_PTR)
      ct = ((TypePointer *)ct)->getPtrTo();
    else if (ct->getMetatype()==TYPE_ARRAY)
      ct = ((TypeArray *)ct)->getBase();
    else if (ct->getMetatype()==TYPE_CODE) {
      const FuncProto *proto = ((TypeCode *)ct)->getPrototype();
      if (proto != (const FuncProto *)0)
	ct = proto->getOutputType();
      else
	ct = glb->types->getTypeVoid();
    }
    else
      break;			// Some other anonymous type
  }
}

/// Push the comma separated list of data-type declarations onto the RPN stack as
/// part of emitting a given function prototype
/// \param proto is the given function prototype
void PrintC::pushPrototypeInputs(const FuncProto *proto)

{
  int4 sz = proto->numParams();

  if ((sz == 0)&&(!proto->isDotdotdot()))
    pushAtom(Atom(KEYWORD_VOID,syntax,EmitMarkup::keyword_color));
  else {
    for(int4 i=0;i<sz-1;++i)
      pushOp(&comma,(const PcodeOp *)0); // Print a comma for each parameter (above 1)
    if (proto->isDotdotdot()&&(sz!=0)) // Print comma for dotdotdot (if it is not by itself)
      pushOp(&comma,(const PcodeOp *)0);
    for(int4 i=0;i<sz;++i) {
      ProtoParameter *param = proto->getParam(i);
      pushTypeStart(param->getType(),true);
      pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
      pushTypeEnd(param->getType());
    }
    if (proto->isDotdotdot()) {
      if (sz != 0)
	pushAtom(Atom(DOTDOTDOT,syntax,EmitMarkup::no_color));
      else {
	// In ANSI C, a prototype with empty parens means the parameters are unspecified (not void)
	// In C++, empty parens mean void, we use the ANSI C convention
	pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color)); // An empty list of parameters
      }
    }
  }
}

/// Calculate what elements of a given symbol's namespace path are necessary to distinguish
/// it within the current scope. Then print these elements.
/// \param symbol is the given symbol
void PrintC::pushSymbolScope(const Symbol *symbol)

{
  int4 scopedepth;
  if (namespc_strategy == MINIMAL_NAMESPACES)
    scopedepth = symbol->getResolutionDepth(curscope);
  else if (namespc_strategy == ALL_NAMESPACES) {
    if (symbol->getScope() == curscope)
      scopedepth = 0;
    else
      scopedepth = symbol->getResolutionDepth((const Scope *)0);
  }
  else
    scopedepth = 0;
  if (scopedepth != 0) {
    vector<const Scope *> scopeList;
    const Scope *point = symbol->getScope();
    for(int4 i=0;i<scopedepth;++i) {
      scopeList.push_back(point);
      point = point->getParent();
      pushOp(&scope, (PcodeOp *)0);
    }
    for(int4 i=scopedepth-1;i>=0;--i) {
      pushAtom(Atom(scopeList[i]->getName(),syntax,EmitMarkup::global_color,(PcodeOp *)0,(Varnode *)0));
    }
  }
}

/// Emit the elements of the given symbol's namespace path that distinguish it within
/// the current scope.
/// \param symbol is the given Symbol
void PrintC::emitSymbolScope(const Symbol *symbol)

{
  int4 scopedepth;
  if (namespc_strategy == MINIMAL_NAMESPACES)
    scopedepth = symbol->getResolutionDepth(curscope);
  else if (namespc_strategy == ALL_NAMESPACES) {
    if (symbol->getScope() == curscope)
      scopedepth = 0;
    else
      scopedepth = symbol->getResolutionDepth((const Scope *)0);
  }
  else
    scopedepth = 0;
  if (scopedepth != 0) {
    vector<const Scope *> scopeList;
    const Scope *point = symbol->getScope();
    for(int4 i=0;i<scopedepth;++i) {
      scopeList.push_back(point);
      point = point->getParent();
    }
    for(int4 i=scopedepth-1;i>=0;--i) {
      emit->print(scopeList[i]->getName(), EmitMarkup::global_color);
      emit->print(scope.print1, EmitMarkup::no_color);
    }
  }
}

/// Store off array sizes for printing after the identifier
/// \param ct is the data-type to push
/// \param noident is \b true if an identifier will not be pushed as part of the declaration
void PrintC::pushTypeStart(const Datatype *ct,bool noident)

{
  // Find the root type (the one with an identifier) and layout
  // the stack of types, so we can access in reverse order
  vector<const Datatype *> typestack;
  buildTypeStack(ct,typestack);

  ct = typestack.back();	// The base type
  OpToken *tok;
  
  if (noident && (typestack.size()==1))
    tok = &type_expr_nospace;
  else
    tok = &type_expr_space;

  if (ct->getName().size()==0) {	// Check for anonymous type
    // We could support a struct or enum declaration here
    string nm = genericTypeName(ct);
    pushOp(tok,(const PcodeOp *)0);
    pushAtom(Atom(nm,typetoken,EmitMarkup::type_color,ct));
  }
  else {
    pushOp(tok,(const PcodeOp *)0);
    pushAtom(Atom(ct->getName(),typetoken,EmitMarkup::type_color,ct));
  }
  for(int4 i=typestack.size()-2;i>=0;--i) {
    ct = typestack[i];
    if (ct->getMetatype() == TYPE_PTR)
      pushOp(&ptr_expr,(const PcodeOp *)0);
    else if (ct->getMetatype() == TYPE_ARRAY)
      pushOp(&array_expr,(const PcodeOp *)0);
    else if (ct->getMetatype() == TYPE_CODE)
      pushOp(&function_call,(const PcodeOp *)0);
    else {
      clear();
      throw LowlevelError("Bad type expression");
    }
  }
}

/// Because the front-ends were pushed on
/// base-type -> final-modifier, the tail-ends are pushed on
/// final-modifier -> base-type.
/// The tail-ends amount to
///   - array subscripts      . [ # ] and
///   - function parameters   . ( paramlist )
///
/// \param ct is the data-type being pushed
void PrintC::pushTypeEnd(const Datatype *ct)

{
  pushMod();
  setMod(force_dec);
  
  for(;;) {
    if (ct->getName().size() != 0)	// This is the base type
      break;
    if (ct->getMetatype()==TYPE_PTR)
      ct = ((const TypePointer *)ct)->getPtrTo();
    else if (ct->getMetatype()==TYPE_ARRAY) {
      const TypeArray *ctarray = (const TypeArray *)ct;
      ct = ctarray->getBase();
      push_integer(ctarray->numElements(),4,false,
		   (const Varnode *)0,(const PcodeOp *)0);
    }
    else if (ct->getMetatype()==TYPE_CODE) {
      const TypeCode *ctcode = (const TypeCode *)ct;
      const FuncProto *proto = ctcode->getPrototype();
      if (proto != (const FuncProto *)0) {
	pushPrototypeInputs(proto);
	ct = proto->getOutputType();
      }
      else
	// An empty list of parameters
	pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
    }
    else
      break;			// Some other anonymous type
  }

  popMod();
}

/// An expression involving a LOAD or STORE can sometimes be emitted using
/// \e array syntax (or \e field \e member syntax). This method determines
/// if this kind of syntax is appropriate or if a '*' operator is required.
/// \param vn is the root of the pointer expression (feeding into LOAD or STORE)
/// \return \b false if '*' syntax is required, \b true if some other syntax is used
bool PrintC::checkArrayDeref(const Varnode *vn) const

{
  const PcodeOp *op;

  if (!vn->isImplied()) return false;
  if (!vn->isWritten()) return false;
  op = vn->getDef();
  if (op->code()==CPUI_SEGMENTOP) {
    vn = op->getIn(2);
    if (!vn->isImplied()) return false;
    if (!vn->isWritten()) return false;
    op = vn->getDef();
  }
  if ((op->code()!=CPUI_PTRSUB)&&(op->code()!=CPUI_PTRADD)) return false;
  return true;
}

/// This is used for expression that require functional syntax, where the name of the
/// function is the name of the operator. The inputs to the p-code op form the roots
/// of the comma separated list of \e parameters within the syntax.
/// \param op is the given PcodeOp
void PrintC::opFunc(const PcodeOp *op)

{
  pushOp(&function_call,op);
  // Using function syntax but don't markup the name as
  // a normal function call
  string nm = op->getOpcode()->getOperatorName(op);
  pushAtom(Atom(nm,optoken,EmitMarkup::no_color,op));
  if (op->numInput() > 0) {
    for(int4 i=0;i<op->numInput()-1;++i)
      pushOp(&comma,op);
  // implied vn's pushed on in reverse order for efficiency
  // see PrintLanguage::pushVnImplied
    for(int4 i=op->numInput()-1;i>=0;--i)
      pushVn(op->getIn(i),op,mods);
  }
  else				// Push empty token for void
    pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
}

/// The syntax represents the given op using a standard c-language cast.  The data-type
/// being cast to is obtained from the output variable of the op. The input expression is
/// also recursively pushed.
/// \param op is the given PcodeOp
void PrintC::opTypeCast(const PcodeOp *op)

{
  if (!option_nocasts) {
    pushOp(&typecast,op);
    pushType(op->getOut()->getHighTypeDefFacing());
  }
  pushVn(op->getIn(0),op,mods);
}

/// The syntax represents the given op using a function with one input,
/// where the function name is not printed. The input expression is simply printed
/// without adornment inside the larger expression, with one minor difference.
/// The hidden operator protects against confusing evaluation order between
/// the operators inside and outside the hidden function.  If both the inside
/// and outside operators are the same associative token, the hidden token
/// makes sure the inner expression is surrounded with parentheses.
/// \param op is the given PcodeOp
void PrintC::opHiddenFunc(const PcodeOp *op)

{
  pushOp(&hidden,op);
  pushVn(op->getIn(0),op,mods);
}

void PrintC::opCopy(const PcodeOp *op)

{
  pushVn(op->getIn(0),op,mods);
}

void PrintC::opLoad(const PcodeOp *op)

{
  bool usearray = checkArrayDeref(op->getIn(1));
  uint4 m = mods;
  if (usearray&&(!isSet(force_pointer)))
    m |= print_load_value;
  else {
    pushOp(&dereference,op);
  }
  pushVn(op->getIn(1),op,m);
}

void PrintC::opStore(const PcodeOp *op)

{
  bool usearray;

  // We assume the STORE is a statement
  uint4 m = mods;
  pushOp(&assignment,op);	// This is an assignment
  usearray = checkArrayDeref(op->getIn(1));
  if (usearray && (!isSet(force_pointer)))
    m |= print_store_value;
  else {
    pushOp(&dereference,op);
  }
  // implied vn's pushed on in reverse order for efficiency
  // see PrintLanguage::pushVnImplied
  pushVn(op->getIn(2),op,mods);
  pushVn(op->getIn(1),op,m);
}

void PrintC::opBranch(const PcodeOp *op)

{
  if (isSet(flat)) {
    // Assume the BRANCH is a statement
    emit->tagOp(KEYWORD_GOTO,EmitMarkup::keyword_color,op);
    emit->spaces(1);
    pushVn(op->getIn(0),op,mods);
  }
}

/// Print the branching condition:
///   - If it is the first condition, print \b if
///   - If there is no block structure, print \b goto
///
/// \param op is the CBRANCH PcodeOp
void PrintC::opCbranch(const PcodeOp *op)

{
  // FIXME:  This routine shouldn't emit directly
  bool yesif = isSet(flat);
  bool yesparen = !isSet(comma_separate);
  bool booleanflip = op->isBooleanFlip();
  uint4 m = mods;

  if (yesif) {			// If not printing block structure
    emit->tagOp(KEYWORD_IF,EmitMarkup::keyword_color,op);
    emit->spaces(1);
    if (op->isFallthruTrue()) {	// and the fallthru is the true branch
      booleanflip = !booleanflip; // print negation of condition
      m |= falsebranch;	  // and print the false (non-fallthru) branch
    }
  }
  int4 id;
  if (yesparen)
    id = emit->openParen(OPEN_PAREN);
  else
    id = emit->openGroup();
  if (booleanflip) {
    if (checkPrintNegation(op->getIn(1))) {
      m |= PrintLanguage::negatetoken;
      booleanflip = false;
    }
  }
  if (booleanflip)
    pushOp(&boolean_not,op);
  pushVn(op->getIn(1),op,m);
  // Make sure stack is clear before emitting more
  recurse();
  if (yesparen)
    emit->closeParen(CLOSE_PAREN,id);
  else
    emit->closeGroup(id);

  if (yesif) {
    emit->spaces(1);
    emit->print(KEYWORD_GOTO,EmitMarkup::keyword_color);
    emit->spaces(1);
    pushVn(op->getIn(0),op,mods);
  }
}

void PrintC::opBranchind(const PcodeOp *op)

{
  // FIXME:  This routine shouldn't emit directly
  emit->tagOp(KEYWORD_SWITCH,EmitMarkup::keyword_color,op);	// Print header for switch
  int4 id = emit->openParen(OPEN_PAREN);
  pushVn(op->getIn(0),op,mods);
  recurse();
  emit->closeParen(CLOSE_PAREN,id);
}

void PrintC::opCall(const PcodeOp *op)

{
  pushOp(&function_call,op);
  const Varnode *callpoint = op->getIn(0);
  FuncCallSpecs *fc;
  if (callpoint->getSpace()->getType()==IPTR_FSPEC) {
    fc = FuncCallSpecs::getFspecFromConst(callpoint->getAddr());
    if (fc->getName().size()==0) {
      string nm = genericFunctionName(fc->getEntryAddress());
      pushAtom(Atom(nm,functoken,EmitMarkup::funcname_color,op,(const Funcdata *)0));
    }
    else {
      Funcdata *fd = fc->getFuncdata();
      if (fd != (Funcdata *)0)
	pushSymbolScope(fd->getSymbol());
      pushAtom(Atom(fc->getName(),functoken,EmitMarkup::funcname_color,op,(const Funcdata *)0));
    }
  }
  else {
    clear();
    throw LowlevelError("Missing function callspec");
  }
  // TODO: Cannot hide "this" on a direct call until we print the whole
  // thing with the proper C++ method invocation format. Otherwise the output
  // gives no indication of what object has a method being called.
  // int4 skip = getHiddenThisSlot(op, fc);
  int4 skip = -1;
  int4 count = op->numInput() - 1;	// Number of parameter expressions printed
  count -= (skip < 0) ? 0 : 1;		// Subtract one if "this" is hidden
  if (count > 0) {
    for(int4 i=0;i<count-1;++i)
      pushOp(&comma,op);
    // implied vn's pushed on in reverse order for efficiency
    // see PrintLanguage::pushVnImplied
    for(int4 i=op->numInput()-1;i>=1;--i) {
      if (i == skip) continue;
      pushVn(op->getIn(i),op,mods);
    }
  }
  else				// Push empty token for void
    pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
}

void PrintC::opCallind(const PcodeOp *op)

{
  pushOp(&function_call,op);
  pushOp(&dereference,op);
  const Funcdata *fd = op->getParent()->getFuncdata();
  FuncCallSpecs *fc = fd->getCallSpecs(op);
  if (fc == (FuncCallSpecs *)0)
    throw LowlevelError("Missing indirect function callspec");
  int4 skip = getHiddenThisSlot(op, fc);
  int4 count = op->numInput() - 1;
  count -= (skip < 0) ? 0 : 1;
  if (count > 1) {	// Multiple parameters
    pushVn(op->getIn(0),op,mods);
    for(int4 i=0;i<count-1;++i)
      pushOp(&comma,op);
    // implied vn's pushed on in reverse order for efficiency
    // see PrintLanguage::pushVnImplied
    for(int4 i=op->numInput()-1;i>=1;--i) {
      if (i == skip) continue;
      pushVn(op->getIn(i),op,mods);
    }
  }
  else if (count == 1) {	// One parameter
    if (skip == 1)
      pushVn(op->getIn(2),op,mods);
    else
      pushVn(op->getIn(1),op,mods);
    pushVn(op->getIn(0),op,mods);
  }
  else {			// A void function
    pushVn(op->getIn(0),op,mods);
    pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
  }
}

void PrintC::opCallother(const PcodeOp *op)

{
  UserPcodeOp *userop = glb->userops.getOp(op->getIn(0)->getOffset());
  uint4 display = userop->getDisplay();
  if (display == UserPcodeOp::annotation_assignment) {
    pushOp(&assignment,op);
    pushVn(op->getIn(2),op,mods);
    pushVn(op->getIn(1),op,mods);
  }
  else if (display == UserPcodeOp::no_operator) {
    pushVn(op->getIn(1),op,mods);
  }
  else {	// Emit using functional syntax
    string nm = op->getOpcode()->getOperatorName(op);
    pushOp(&function_call,op);
    pushAtom(Atom(nm,optoken,EmitMarkup::funcname_color,op));
    if (op->numInput() > 1) {
      for(int4 i = 1;i < op->numInput() - 1;++i)
	pushOp(&comma,op);
      // implied vn's pushed on in reverse order for efficiency
      // see PrintLanguage::pushVnImplied
      for(int4 i = op->numInput() - 1;i >= 1;--i)
	pushVn(op->getIn(i),op,mods);
    }
    else
      pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));	// Push empty token for void
  }
}

void PrintC::opConstructor(const PcodeOp *op,bool withNew)

{
  Datatype *dt;
  if (withNew) {
    const PcodeOp *newop = op->getIn(1)->getDef();
    const Varnode *outvn = newop->getOut();
    pushOp(&new_op,newop);
    pushAtom(Atom(KEYWORD_NEW,optoken,EmitMarkup::keyword_color,newop,outvn));
    dt = outvn->getTypeDefFacing();
  }
  else {
    const Varnode *thisvn = op->getIn(1);
    dt = thisvn->getType();
  }
  if (dt->getMetatype() == TYPE_PTR) {
    dt = ((TypePointer *)dt)->getPtrTo();
  }
  string nm = dt->getName();
  pushOp(&function_call,op);
  pushAtom(Atom(nm,optoken,EmitMarkup::funcname_color,op));
  // implied vn's pushed on in reverse order for efficiency
  // see PrintLanguage::pushVnImplied
  if (op->numInput()>3) {	// Multiple (non-this) parameters
    for(int4 i=2;i<op->numInput()-1;++i)
      pushOp(&comma,op);
    for(int4 i=op->numInput()-1;i>=2;--i)
      pushVn(op->getIn(i),op,mods);
  }
  else if (op->numInput()==3) {	// One parameter
    pushVn(op->getIn(2),op,mods);
  }
  else {			// A void function
    pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
  }
}

void PrintC::opReturn(const PcodeOp *op)

{
  string nm;
  switch(op->getHaltType()) {
  default:			// The most common case, plain return
  // FIXME:  This routine shouldn't emit directly
    emit->tagOp(KEYWORD_RETURN,EmitMarkup::keyword_color,op);
    if (op->numInput()>1) {
      emit->spaces(1);
      pushVn(op->getIn(1),op,mods);
    }
    return;
  case PcodeOp::noreturn:	// Previous instruction does not exit
  case PcodeOp::halt:		// Process halts
    nm = "halt";
    break;
  case PcodeOp::badinstruction:
    nm = "halt_baddata";	// CPU executes bad instruction
    break;
  case PcodeOp::unimplemented:	// instruction is unimplemented
    nm = "halt_unimplemented";
    break;
  case PcodeOp::missing:	// Did not analyze this instruction
    nm = "halt_missing";
    break;
  }
  pushOp(&function_call,op);
  pushAtom(Atom(nm,optoken,EmitMarkup::funcname_color,op));
  pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
}

void PrintC::opIntZext(const PcodeOp *op,const PcodeOp *readOp)

{
  if (castStrategy->isZextCast(op->getOut()->getHighTypeDefFacing(),op->getIn(0)->getHighTypeReadFacing(op))) {
    if (option_hide_exts && castStrategy->isExtensionCastImplied(op,readOp))
      opHiddenFunc(op);
    else
      opTypeCast(op);
  }
  else
    opFunc(op);
}

void PrintC::opIntSext(const PcodeOp *op,const PcodeOp *readOp)

{
  if (castStrategy->isSextCast(op->getOut()->getHighTypeDefFacing(),op->getIn(0)->getHighTypeReadFacing(op))) {
    if (option_hide_exts && castStrategy->isExtensionCastImplied(op,readOp))
      opHiddenFunc(op);
    else
      opTypeCast(op);
  }
  else
    opFunc(op);
}

/// Print the BOOL_NEGATE but check for opportunities to flip the next operator instead
/// \param op is the BOOL_NEGATE PcodeOp
void PrintC::opBoolNegate(const PcodeOp *op)

{
  if (isSet(negatetoken)) {	// Check if we are negated by a previous BOOL_NEGATE
    unsetMod(negatetoken);	// If so, mark that negatetoken is consumed
    pushVn(op->getIn(0),op,mods); // Don't print ourselves, but print our input unmodified
  }
  else if (checkPrintNegation(op->getIn(0))) { // If the next operator can be flipped
    pushVn(op->getIn(0),op,mods|negatetoken); // Don't print ourselves, but print a modified input
  }
  else {
    pushOp(&boolean_not,op);	// Otherwise print ourselves
    pushVn(op->getIn(0),op,mods); // And print our input
  }
}

void PrintC::opSubpiece(const PcodeOp *op)

{
  if (op->doesSpecialPrinting()) {		// Special printing means it is a field extraction
    const Varnode *vn = op->getIn(0);
    Datatype *ct = vn->getHighTypeReadFacing(op);
    if (ct->isPieceStructured()) {
      int4 offset;
      int4 byteOff = TypeOpSubpiece::computeByteOffsetForComposite(op);
      const TypeField *field = ct->findTruncation(byteOff,op->getOut()->getSize(),op,1,offset);	// Use artificial slot
      if (field != (const TypeField*)0 && offset == 0) {		// A formal structure field
	pushOp(&object_member,op);
	pushVn(vn,op,mods);
	pushAtom(Atom(field->name,fieldtoken,EmitMarkup::no_color,ct,field->ident,op));
	return;
      }
      else if (vn->isExplicit() && vn->getHigh()->getSymbolOffset() == -1) {	// An explicit, entire, structured object
	Symbol *sym = vn->getHigh()->getSymbol();
	if (sym != (Symbol *)0) {
	  int4 sz = op->getOut()->getSize();
	  int4 off = (int4)op->getIn(1)->getOffset();
	  off = vn->getSpace()->isBigEndian() ? vn->getSize() - (sz + off) : off;
	  pushPartialSymbol(sym, off, sz, vn, op, -1);
	  return;
	}
      }
      // Fall thru to functional printing
    }
  }
  if (castStrategy->isSubpieceCast(op->getOut()->getHighTypeDefFacing(),
				   op->getIn(0)->getHighTypeReadFacing(op),
				   (uint4)op->getIn(1)->getOffset()))
    opTypeCast(op);
  else
    opFunc(op);
}

void PrintC::opPtradd(const PcodeOp *op)

{
  bool printval = isSet(print_load_value|print_store_value);
  uint4 m = mods & ~(print_load_value|print_store_value);
  if (!printval) {
    TypePointer *tp = (TypePointer *)op->getIn(0)->getHighTypeReadFacing(op);
    if (tp->getMetatype() == TYPE_PTR) {
      if (tp->getPtrTo()->getMetatype() == TYPE_ARRAY)
	printval = true;
    }
  }
  if (printval)			// Use array notation if we need value
    pushOp(&subscript,op);
  else				// just a '+'
    pushOp(&binary_plus,op);
  // implied vn's pushed on in reverse order for efficiency
  // see PrintLanguage::pushVnImplied
  pushVn(op->getIn(1),op,m);
  pushVn(op->getIn(0),op,m);
}

static bool isValueFlexible(const Varnode *vn)

{
  if ((vn->isImplied())&&(vn->isWritten())) {
    const PcodeOp *def = vn->getDef();
    if (def->code() == CPUI_PTRSUB) return true;
    if (def->code() == CPUI_PTRADD) return true;
  }
  return false;
}

/// We need to distinguish between the following cases:
///  - ptr->        struct spacebase or array
///  - valueoption  on/off   (from below)
///  - valueflex    yes/no   (can we turn valueoption above?)
///
/// Then the printing breaks up into the following table:
/// \code
///         val flex   |   val flex   |   val flex   |   val flex
///         off  yes       off   no        on  yes        on   no
///
/// struct  &( ).name      &( )->name     ( ).name       ( )->name
/// spcbase n/a            &name          n/a            name
/// array   ( )            *( )           ( )[0]         *( )[0]
/// \endcode
/// The '&' is dropped if the output type is an array
/// \param op is the PTRSUB PcodeOp
void PrintC::opPtrsub(const PcodeOp *op)

{
  TypePointer *ptype;
  TypePointerRel *ptrel;
  Datatype *ct;
  const Varnode *in0;
  uintb in1const;
  bool valueon,flex,arrayvalue;
  uint4 m;

  in0 = op->getIn(0);
  in1const = op->getIn(1)->getOffset();
  ptype = (TypePointer *)in0->getHighTypeReadFacing(op);
  if (ptype->getMetatype() != TYPE_PTR) {
    clear();
    throw LowlevelError("PTRSUB off of non-pointer type");
  }
  if (ptype->isFormalPointerRel() && ((TypePointerRel *)ptype)->evaluateThruParent(in1const)) {
    ptrel = (TypePointerRel *)ptype;
    ct = ptrel->getParent();
  }
  else {
    ptrel = (TypePointerRel *)0;
    ct = ptype->getPtrTo();
  }
  m = mods & ~(print_load_value|print_store_value); // Current state of mods
  valueon = (mods & (print_load_value|print_store_value)) != 0;
  flex = isValueFlexible(in0);

  if (ct->getMetatype() == TYPE_STRUCT || ct->getMetatype() == TYPE_UNION) {
    uintb suboff = in1const;	// How far into container
    if (ptrel != (TypePointerRel *)0) {
      suboff += ptrel->getPointerOffset();
      suboff &= calc_mask(ptype->getSize());
      if (suboff == 0) {
	// Special case where we do not print a field
	pushTypePointerRel(op);
	if (flex)
	  pushVn(in0,op,m | print_load_value);
	else
	  pushVn(in0,op,m);
	return;
      }
    }
    suboff = AddrSpace::addressToByte(suboff,ptype->getWordSize());
    string fieldname;
    Datatype *fieldtype;
    int4 fieldid;
    int4 newoff;
    if (ct->getMetatype() == TYPE_UNION) {
      if (suboff != 0)
	throw LowlevelError("PTRSUB accesses union with non-zero offset");
      const Funcdata *fd = op->getParent()->getFuncdata();
      const ResolvedUnion *resUnion = fd->getUnionField(ptype, op, -1);
      if (resUnion == (const ResolvedUnion *)0 || resUnion->getFieldNum() < 0)
	throw LowlevelError("PTRSUB for union that does not resolve to a field");
      const TypeField *fld = ((TypeUnion *)ct)->getField(resUnion->getFieldNum());
      fieldid = fld->ident;
      fieldname = fld->name;
      fieldtype = fld->type;
    }
    else {	// TYPE_STRUCT
      const TypeField *fld = ct->findTruncation((int4)suboff,0,op,0,newoff);
      if (fld == (const TypeField*)0) {
	if (ct->getSize() <= suboff) {
	  clear();
	  throw LowlevelError("PTRSUB out of bounds into struct");
	}
	// Try to match the Ghidra's default field name from DataTypeComponent.getDefaultFieldName
	ostringstream s;
	s << "field_0x" << hex << suboff;
	fieldname = s.str();
	fieldtype = (Datatype*)0;
	fieldid = suboff;
      }
      else {
	fieldname = fld->name;
	fieldtype = fld->type;
	fieldid = fld->ident;
      }
    }
    arrayvalue = false;
    // The '&' is dropped if the output type is an array
    if ((fieldtype != (Datatype *)0)&&(fieldtype->getMetatype()==TYPE_ARRAY)) {
      arrayvalue = valueon;	// If printing value, use [0]
      valueon = true;		// Don't print &
    }
    
    if (!valueon) {		// Printing an ampersand
      if (flex) {		// EMIT  &( ).name
	pushOp(&addressof,op);
	pushOp(&object_member,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m | print_load_value);
	pushAtom(Atom(fieldname,fieldtoken,EmitMarkup::no_color,ct,fieldid,op));
      }
      else {			// EMIT  &( )->name
	pushOp(&addressof,op);
	pushOp(&pointer_member,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m);
	pushAtom(Atom(fieldname,fieldtoken,EmitMarkup::no_color,ct,fieldid,op));
      }
    }
    else {			// Not printing an ampersand
      if (arrayvalue)
	pushOp(&subscript,op);
      if (flex) {		// EMIT  ( ).name
	pushOp(&object_member,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m | print_load_value);
	pushAtom(Atom(fieldname,fieldtoken,EmitMarkup::no_color,ct,fieldid,op));
      }
      else {			// EMIT  ( )->name
	pushOp(&pointer_member,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m);
	pushAtom(Atom(fieldname,fieldtoken,EmitMarkup::no_color,ct,fieldid,op));
      }
      if (arrayvalue)
	push_integer(0,4,false,(Varnode *)0,op);
    }
  }
  else if (ct->getMetatype() == TYPE_SPACEBASE) {
    HighVariable *high = op->getIn(1)->getHigh();
    Symbol *symbol = high->getSymbol();
    arrayvalue = false;
    if (symbol != (Symbol *)0) {
      ct = symbol->getType();
	   // The '&' is dropped if the output type is an array
      if (ct->getMetatype()==TYPE_ARRAY) {
	arrayvalue = valueon;	// If printing value, use [0]
	valueon = true;		// If printing ptr, don't use &
      }
      else if (ct->getMetatype()==TYPE_CODE)
	valueon = true;		// If printing ptr, don't use &
    }
    if (!valueon) {		// EMIT  &name
      pushOp(&addressof,op);
    }
    else {			// EMIT  name
      if (arrayvalue)
	pushOp(&subscript,op);
    }
    if (symbol == (Symbol *)0) {
      TypeSpacebase *sb = (TypeSpacebase *)ct;
      Address addr = sb->getAddress(in1const,in0->getSize(),op->getAddr());
      pushUnnamedLocation(addr,(Varnode *)0,op);
    }
    else {
      int4 off = high->getSymbolOffset();
      if (off == 0)
	pushSymbol(symbol,(Varnode *)0,op);
      else {
	// If this "value" is getting used as a storage location
	// we can't use a cast in its description, so turn off
	// casting when printing the partial symbol
	//	Datatype *exttype = ((mods & print_store_value)!=0) ? (Datatype *)0 : ct;
	pushPartialSymbol(symbol,off,0,(Varnode *)0,op,-1);
      }
    }
    if (arrayvalue)
      push_integer(0,4,false,(Varnode *)0,op);
  }
  else if (ct->getMetatype() == TYPE_ARRAY) {
    if (in1const != 0) {
      clear();
      throw LowlevelError("PTRSUB with non-zero offset into array type");
    }
  // We are treating array as a structure
  // and this PTRSUB(*,0) represents changing
  // to treating it as a pointer to its element type
    if (!valueon) {
      if (flex) {		// EMIT  ( )
				// (*&struct->arrayfield)[i]
				// becomes struct->arrayfield[i]
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m);
      }
      else {			// EMIT  *( )
	pushOp(&dereference,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m);
      }
    }
    else {
      if (flex) {		// EMIT  ( )[0]
	pushOp(&subscript,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m);
	push_integer(0,4,false,(Varnode *)0,op);
      }
      else {			// EMIT  (* )[0]
	pushOp(&subscript,op);
	pushOp(&dereference,op);
	if (ptrel != (TypePointerRel *)0)
	  pushTypePointerRel(op);
	pushVn(in0,op,m);
	push_integer(0,4,false,(Varnode *)0,op);
      }
    }
  }
  else {
    clear();
    throw LowlevelError("PTRSUB off of non structured pointer type");
  }
}

/// - slot 0 is the spaceid constant
/// - slot 1 is the segment, we could conceivably try to annotate the segment here
/// - slot 2 is the pointer we are really interested in printing
///
/// \param op is the SEGMENTOP PcodeOp
void PrintC::opSegmentOp(const PcodeOp *op)

{
  pushVn(op->getIn(2),op,mods);
}

void PrintC::opCpoolRefOp(const PcodeOp *op)

{
  const Varnode *outvn = op->getOut();
  const Varnode *vn0 = op->getIn(0);
  vector<uintb> refs;
  for(int4 i=1;i<op->numInput();++i)
    refs.push_back(op->getIn(i)->getOffset());
  const CPoolRecord *rec = glb->cpool->getRecord(refs);
  if (rec == (const CPoolRecord *)0) {
    pushAtom(Atom("UNKNOWNREF",syntax,EmitMarkup::const_color,op,outvn));
  }
  else {
    switch(rec->getTag()) {
    case CPoolRecord::string_literal:
      {
	ostringstream str;
	int4 len = rec->getByteDataLength();
	if (len > 2048)
	  len = 2048;
	str << '\"';
	escapeCharacterData(str,rec->getByteData(),len,1,false);
	if (len == rec->getByteDataLength())
	  str << '\"';
	else {
	  str << "...\"";
	}
	pushAtom(Atom(str.str(),vartoken,EmitMarkup::const_color,op,outvn));
	break;
      }
    case CPoolRecord::class_reference:
      pushAtom(Atom(rec->getToken(),vartoken,EmitMarkup::type_color,op,outvn));
      break;
    case CPoolRecord::instance_of:
      {
	Datatype *dt = rec->getType();
	while(dt->getMetatype() == TYPE_PTR) {
	  dt = ((TypePointer *)dt)->getPtrTo();
	}
	pushOp(&function_call,op);
	pushAtom(Atom(rec->getToken(),functoken,EmitMarkup::funcname_color,op,outvn));
	pushOp(&comma,(const PcodeOp *)0);
	pushVn(vn0,op,mods);
	pushAtom(Atom(dt->getName(),syntax,EmitMarkup::type_color,op,outvn));
	break;
      }
    case CPoolRecord::primitive:		// Should be eliminated
    case CPoolRecord::pointer_method:
    case CPoolRecord::pointer_field:
    case CPoolRecord::array_length:
    case CPoolRecord::check_cast:
    default:
      {
	Datatype *ct = rec->getType();
	EmitMarkup::syntax_highlight color = EmitMarkup::var_color;
	if (ct->getMetatype() == TYPE_PTR) {
	  ct = ((TypePointer *) ct)->getPtrTo();
	  if (ct->getMetatype() == TYPE_CODE)
	    color = EmitMarkup::funcname_color;
	}
	if (vn0->isConstant()) {// If this is NOT relative to an object reference
	  pushAtom(Atom(rec->getToken(), vartoken, color, op, outvn));
	}
	else {
	  pushOp(&pointer_member, op);
	  pushVn(vn0, op, mods);
	  pushAtom(Atom(rec->getToken(), syntax, color, op, outvn));
	}
	break;
      }
    }
  }
}

void PrintC::opNewOp(const PcodeOp *op)

{
  const Varnode *outvn = op->getOut();
  const Varnode *vn0 = op->getIn(0);
  if (op->numInput() == 2) {
    const Varnode *vn1 = op->getIn(1);
    if (!vn0->isConstant()) {
      // Array allocation form
      pushOp(&new_op,op);
      pushAtom(Atom(KEYWORD_NEW,optoken,EmitMarkup::keyword_color,op,outvn));
      string nm;
      if (outvn == (const Varnode *)0) {	// Its technically possible, for new result to be unused
	nm = "<unused>";
      }
      else {
	Datatype *dt = outvn->getTypeDefFacing();
	while (dt->getMetatype() == TYPE_PTR) {
	  dt = ((TypePointer *)dt)->getPtrTo();
	}
	nm = dt->getName();
      }
      pushOp(&subscript,op);
      pushAtom(Atom(nm,optoken,EmitMarkup::type_color,op));
      pushVn(vn1,op,mods);
      return;
    }
  }
  // This printing is used only if the 'new' operator doesn't feed directly into a constructor
  pushOp(&function_call,op);
  pushAtom(Atom(KEYWORD_NEW,optoken,EmitMarkup::keyword_color,op,outvn));
  pushVn(vn0,op,mods);
}

void PrintC::opInsertOp(const PcodeOp *op)

{
  opFunc(op);	// If no other way to print it, print as functional operator
}

void PrintC::opExtractOp(const PcodeOp *op)

{
  opFunc(op);	// If no other way to print it, print as functional operator
}

/// \brief Push a constant with an integer data-type to the RPN stack
///
/// Various checks are made to see if the integer should be printed as an \e equate
/// symbol or if there is other overriding information about what format it should be printed in.
/// In any case, a final determination of the format is made and the integer is pushed as
/// a single token.
/// \param val is the given integer value
/// \param sz is the size (in bytes) to associate with the integer
/// \param sign is set to \b true if the integer should be treated as a signed value
/// \param vn is the Varnode holding the value
/// \param op is the PcodeOp using the value
void PrintC::push_integer(uintb val,int4 sz,bool sign,
			  const Varnode *vn,const PcodeOp *op)
{
  bool print_negsign;
  bool force_unsigned_token;
  bool force_sized_token;
  uint4 displayFormat = 0;

  force_unsigned_token = false;
  force_sized_token = false;
  if ((vn != (const Varnode *)0)&&(!vn->isAnnotation())) {
    HighVariable *high = vn->getHigh();
    Symbol *sym = high->getSymbol();
    if (sym != (Symbol *)0) {
      if (sym->isNameLocked() && (sym->getCategory() == Symbol::equate)) {
	if (pushEquate(val,sz,(EquateSymbol *)sym,vn,op))
	  return;
      }
      displayFormat = sym->getDisplayFormat();
    }
    force_unsigned_token = vn->isUnsignedPrint();
    force_sized_token = vn->isLongPrint();
    if (displayFormat == 0)	// The symbol's formatting overrides any formatting on the data-type
      displayFormat = high->getType()->getDisplayFormat();
  }
  if (sign && displayFormat != Symbol::force_char) { // Print the constant as signed
    uintb mask = calc_mask(sz);
    uintb flip = val^mask;
    print_negsign = (flip < val);
    if (print_negsign)
      val = flip+1;
    force_unsigned_token = false;
  }
  else {
    print_negsign = false;
  }

				// Figure whether to print as hex or decimal
  if (displayFormat != 0) {
    // Format is forced by the Symbol
  }
  else if ((mods & force_hex)!=0) {
    displayFormat = Symbol::force_hex;
  }
  else if ((val<=10)||((mods & force_dec))) {
    displayFormat = Symbol::force_dec;
  }
  else {			// Otherwise decide if dec or hex is more natural
    displayFormat = (PrintLanguage::mostNaturalBase(val)==16) ? Symbol::force_hex : Symbol::force_dec;
  }

  ostringstream t;
  if (print_negsign)
    t << '-';
  if (displayFormat == Symbol::force_hex)
    t << hex << "0x" << val;
  else if (displayFormat == Symbol::force_dec)
    t << dec << val;
  else if (displayFormat == Symbol::force_oct)
    t << oct << '0' << val;
  else if (displayFormat == Symbol::force_char) {
    if (doEmitWideCharPrefix() && sz > 1)
      t << 'L';			// Print symbol indicating wide character
    t << '\'';			// char is surrounded with single quotes
    if (sz == 1 && val >= 0x80)
      printCharHexEscape(t,(int4)val);
    else
      printUnicode(t,(int4)val);
    t << '\'';
  }
  else {	// Must be Symbol::force_bin
    t << "0b";
    formatBinary(t, val);
  }
  if (force_unsigned_token)
    t << 'U';			// Force unsignedness explicitly
  if (force_sized_token)
    t << sizeSuffix;

  if (vn==(const Varnode *)0)
    pushAtom(Atom(t.str(),syntax,EmitMarkup::const_color,op));
  else
    pushAtom(Atom(t.str(),vartoken,EmitMarkup::const_color,op,vn));
}

/// \brief Push a constant with a floating-point data-type to the RPN stack
///
/// The encoding is drawn from the underlying Translate object, and the print
/// properties are checked for formatting overrides.  In any case, a format
/// is decided upon, and the constant is pushed as a single token.
/// \param val is the given encoded floating-point value
/// \param sz is the size (in bytes) of the encoded value
/// \param vn is the Varnode holding the value
/// \param op is the PcodeOp using the value
void PrintC::push_float(uintb val,int4 sz,const Varnode *vn,const PcodeOp *op)
{
  string token;

  const FloatFormat *format = glb->translate->getFloatFormat(sz);
  if (format == (const FloatFormat *)0) {
    token = "FLOAT_UNKNOWN";
  }
  else {
    FloatFormat::floatclass type;
    double floatval = format->getHostFloat(val,&type);
    if (type == FloatFormat::infinity) {
      if (format->extractSign(val))
	token = "-INFINITY";
      else
	token = "INFINITY";
    }
    else if (type == FloatFormat::nan) {
      if (format->extractSign(val))
	token = "-NAN";
      else
	token = "NAN";
    }
    else {
      ostringstream t;
      if ((mods & force_scinote)!=0) {
	t.setf( ios::scientific ); // Set to scientific notation
	t.precision(format->getDecimalPrecision()-1);
	t << floatval;
	token = t.str();
      }
      else {
	// Try to print "minimal" accurate representation of the float
	t.unsetf( ios::floatfield );	// Use "default" notation
	t.precision(format->getDecimalPrecision());
	t << floatval;
	token = t.str();
	bool looksLikeFloat = false;
	for(int4 i=0;i<token.size();++i) {
	  char c = token[i];
	  if (c == '.' || c == 'e') {
	    looksLikeFloat = true;
	    break;
	  }
	}
	if (!looksLikeFloat) {
	  token += ".0";	// Force token to look like a floating-point value
	}
      }
    }
  }
  if (vn==(const Varnode *)0)
    pushAtom(Atom(token,syntax,EmitMarkup::const_color,op));
  else
    pushAtom(Atom(token,vartoken,EmitMarkup::const_color,op,vn));
}

void PrintC::printUnicode(ostream &s,int4 onechar) const

{
  if (unicodeNeedsEscape(onechar)) {
    switch(onechar) {		// Special escape characters
    case 0:
      s << "\\0";
      return;
    case 7:
      s << "\\a";
      return;
    case 8:
      s << "\\b";
      return;
    case 9:
      s << "\\t";
      return;
    case 10:
      s << "\\n";
      return;
    case 11:
      s << "\\v";
      return;
    case 12:
      s << "\\f";
      return;
    case 13:
      s << "\\r";
      return;
    case 92:
      s << "\\\\";
      return;
    case '"':
      s << "\\\"";
      return;
    case '\'':
      s << "\\\'";
      return;
    }
    // Generic escape code
    printCharHexEscape(s, onechar);
    return;
  }
  StringManager::writeUtf8(s, onechar);		// emit normally
}

void PrintC::pushType(const Datatype *ct)

{
  pushTypeStart(ct,true);				// Print type (as if for a cast)
  pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
  pushTypeEnd(ct);
}

/// \brief Push a \b true or \b false token to the RPN stack
///
/// A single Atom representing the boolean value is emitted
/// \param val is the boolean value (non-zero for \b true)
/// \param ct is the data-type associated with the value
/// \param vn is the Varnode holding the value
/// \param op is the PcodeOp using the value
void PrintC::pushBoolConstant(uintb val,const TypeBase *ct,
				 const Varnode *vn,
				 const PcodeOp *op)
{
  if (val != 0)
    pushAtom(Atom(KEYWORD_TRUE,vartoken,EmitMarkup::const_color,op,vn));
  else
    pushAtom(Atom(KEYWORD_FALSE,vartoken,EmitMarkup::const_color,op,vn));
}

/// \brief Return \b true if this language requires a prefix when expressing \e wide characters
///
/// The c-language standard requires that strings (and character constants) made up of \e wide
/// character elements have an 'L' prefix added before the quote characters.  Other related languages
/// may not do this.  Having this as a virtual method lets derived languages to tailor their strings
/// while still using the basic PrintC functionality
/// \return \b true if a prefix should be printed
bool PrintC::doEmitWideCharPrefix(void) const
{
  return true;
}

/// Print the given value using the standard character hexadecimal escape sequence.
/// \param s is the stream to write to
/// \param val is the given value
void PrintC::printCharHexEscape(ostream &s,int4 val)

{
  if (val < 256) {
    s << "\\x" << setfill('0') << setw(2) << hex << val;
  }
  else if (val < 65536) {
    s << "\\x" << setfill('0') << setw(4) << hex << val;
  }
  else
    s << "\\x" << setfill('0') << setw(8) << hex << val;
}

/// \brief Print a quoted (unicode) string at the given address.
///
/// Data for the string is obtained directly from the LoadImage.  The bytes are checked
/// for appropriate unicode encoding and the presence of a terminator. If all these checks
/// pass, the string is emitted.
/// \param s is the output stream to print to
/// \param addr is the address of the string data within the LoadImage
/// \param charType is the underlying character data-type
/// \return \b true if a proper string was found and printed to the stream
bool PrintC::printCharacterConstant(ostream &s,const Address &addr,Datatype *charType) const

{
  StringManager *manager = glb->stringManager;

  // Retrieve UTF8 version of string
  bool isTrunc = false;
  const vector<uint1> &buffer(manager->getStringData(addr, charType, isTrunc));
  if (buffer.empty())
    return false;
  if (doEmitWideCharPrefix() && charType->getSize() > 1 && !charType->isOpaqueString())
    s << 'L';			// Print symbol indicating wide character
  s << '"';
  escapeCharacterData(s,buffer.data(),buffer.size(),1,glb->translate->isBigEndian());
  if (isTrunc)
    s << "...\" /* TRUNCATED STRING LITERAL */";
  else
    s << '"';

  return true;
}

/// For the given CALL op, if a "this" pointer exists and needs to be hidden because
/// of the print configuration, return the Varnode slot corresponding to the "this".
/// Otherwise return -1.
/// \param op is the given CALL PcodeOp
/// \param fc is the function prototype corresponding to the CALL
/// \return the "this" Varnode slot or -1
int4 PrintC::getHiddenThisSlot(const PcodeOp *op,FuncProto *fc)

{
  int4 numInput = op->numInput();
  if (isSet(hide_thisparam) && fc->hasThisPointer()) {
    for(int4 i=1;i<numInput-1;++i) {
      ProtoParameter *param = fc->getParam(i-1);
      if (param != (ProtoParameter *)0 && param->isThisPointer())
	return i;
    }
    if (numInput >= 2) {
      ProtoParameter *param = fc->getParam(numInput-2);
      if (param != (ProtoParameter *)0 && param->isThisPointer())
	return numInput - 1;
    }
  }
  return -1;
}

void PrintC::resetDefaultsPrintC(void)

{
  option_convention = true;
  option_hide_exts = true;
  option_inplace_ops = false;
  option_nocasts = false;
  option_NULL = false;
  option_unplaced = false;
  setCStyleComments();
}

/// \brief Push a single character constant to the RPN stack
///
/// For C, a character constant is usually emitted as the character in single quotes.
/// Handle unicode, wide characters, etc. Characters come in with the compiler's raw encoding.
/// \param val is the constant value
/// \param ct is data-type attached to the value
/// \param vn is the Varnode holding the value
/// \param op is the PcodeOp using the value
void PrintC::pushCharConstant(uintb val,const Datatype *ct,const Varnode *vn,const PcodeOp *op)

{
  uint4 displayFormat = 0;
  bool isSigned = (ct->getMetatype() == TYPE_INT);
  if ((vn != (const Varnode *)0)&&(!vn->isAnnotation())) {
    HighVariable *high = vn->getHigh();
    Symbol *sym = high->getSymbol();
    if (sym != (Symbol *)0) {
      if (sym->isNameLocked() && (sym->getCategory() == Symbol::equate)) {
	if (pushEquate(val,vn->getSize(),(EquateSymbol *)sym,vn,op))
	  return;
      }
      displayFormat = sym->getDisplayFormat();
    }
    if (displayFormat == 0)
      displayFormat = high->getType()->getDisplayFormat();
  }
  if (displayFormat != 0 && displayFormat != Symbol::force_char) {
    if (!castStrategy->caresAboutCharRepresentation(vn, op)) {
      push_integer(val, ct->getSize(), isSigned, vn, op);
      return;
    }
  }
  if ((ct->getSize()==1)&&(val >= 0x80)) {
    // For byte characters, the encoding is assumed to be ASCII, UTF-8, or some other
    // code-page that extends ASCII. At 0x80 and above, we cannot treat the value as a
    // unicode code-point. Its either part of a multi-byte UTF-8 encoding or an unknown
    // code-page value. In either case, we print as an integer or an escape sequence.
    if (displayFormat != Symbol::force_hex && displayFormat != Symbol::force_char) {
      push_integer(val, 1, isSigned, vn, op);
      return;
    }
    displayFormat = Symbol::force_hex;	// Fallthru but force a hex representation
  }
  ostringstream t;
  // From here we assume, the constant value is a direct unicode code-point.
  // The value could be an illegal code-point (surrogates or beyond the max code-point),
  // but this will just be emitted as an escape sequence.
  if (doEmitWideCharPrefix() && ct->getSize() > 1)
    t << 'L';		// Print symbol indicating wide character
  t << '\'';			// char is surrounded with single quotes
  if (displayFormat == Symbol::force_hex) {
    printCharHexEscape(t,(int4)val);
  }
  else
    printUnicode(t,(int4)val);
  t << '\'';
  pushAtom(Atom(t.str(),vartoken,EmitMarkup::const_color,op,vn));
}

/// \brief Push an enumerated value to the RPN stack
///
/// Handle cases where the value is built out of multiple named elements of the
/// enumeration or where the value cannot be expressed using named elements
/// \param val is the enumerated value being pushed
/// \param ct is the enumerated data-type attached to the value
/// \param vn is the Varnode holding the value
/// \param op is the PcodeOp using the value
void PrintC::pushEnumConstant(uintb val,const TypeEnum *ct,
				 const Varnode *vn,
				 const PcodeOp *op)
{
  vector<string> valnames;

  bool complement = ct->getMatches(val,valnames);
  if (valnames.size() > 0) {
    if (complement)
      pushOp(&bitwise_not,op);
    for(int4 i=valnames.size()-1;i>0;--i)
      pushOp(&enum_cat,op);
    for(int4 i=0;i<valnames.size();++i)
      pushAtom(Atom(valnames[i],vartoken,EmitMarkup::const_color,op,vn));
  }
  else {
    push_integer(val,ct->getSize(),false,vn,op);
    //    ostringstream s;
    //    s << "BAD_ENUM(0x" << hex << val << ")";
    //    pushAtom(Atom(s.str(),vartoken,EmitMarkup::const_color,op,vn));
  }
}

/// \brief Attempt to push a quoted string representing a given constant pointer onto the RPN stack
///
/// Check if the constant pointer refers to character data that can be emitted as a quoted string.
/// If so push the string, if not return \b false to indicate a token was not pushed
/// \param val is the value of the given constant pointer
/// \param ct is the pointer data-type attached to the value
/// \param vn is the Varnode holding the value (may be null)
/// \param op is the PcodeOp using the value (may be null)
/// \return \b true if a quoted string was pushed to the RPN stack
bool PrintC::pushPtrCharConstant(uintb val,const TypePointer *ct,const Varnode *vn,const PcodeOp *op)

{
  if (val==0) return false;
  AddrSpace *spc = glb->getDefaultDataSpace();
  uintb fullEncoding;
  Address point;
  if (op != (const PcodeOp *)0)
    point = op->getAddr();
  Address stringaddr = glb->resolveConstant(spc,val,ct->getSize(),point,fullEncoding);
  if (stringaddr.isInvalid()) return false;
  if (!glb->symboltab->getGlobalScope()->isReadOnly(stringaddr,1,Address()))
    return false;	     // Check that string location is readonly

  ostringstream str;
  Datatype *subct = ct->getPtrTo();
  if (!printCharacterConstant(str,stringaddr,subct))
    return false;		// Can we get a nice ASCII string

  pushAtom(Atom(str.str(),vartoken,EmitMarkup::const_color,op,vn));
  return true;
}

/// \brief Attempt to push a function name representing a constant pointer onto the RPN stack
///
/// Given the pointer value, try to look up the function at that address and push
/// the function's name as a single Atom.
/// \param val is the given constant pointer value
/// \param ct is the pointer data-type attached to the value
/// \param vn is the Varnode holding the value
/// \param op is the PcodeOp using the value
/// \return \b true if a name was pushed to the RPN stack, return \b false otherwise
bool PrintC::pushPtrCodeConstant(uintb val,const TypePointer *ct,
				    const Varnode *vn,
				    const PcodeOp *op)
{
  AddrSpace *spc = glb->getDefaultCodeSpace();
  Funcdata *fd = (Funcdata *)0;
  val = AddrSpace::addressToByte(val,spc->getWordSize());
  fd = glb->symboltab->getGlobalScope()->queryFunction( Address(spc,val));
  if (fd != (Funcdata *)0) {
    pushAtom(Atom(fd->getName(),functoken,EmitMarkup::funcname_color,op,fd));
    return true;
  }
  return false;
}

void PrintC::pushConstant(uintb val,const Datatype *ct,
			    const Varnode *vn,
			    const PcodeOp *op)
{
  Datatype *subtype;
  switch(ct->getMetatype()) {
  case TYPE_UINT:
    if (ct->isCharPrint())
      pushCharConstant(val,(TypeChar *)ct,vn,op);
    else if (ct->isEnumType())
      pushEnumConstant(val,(TypeEnum *)ct,vn,op);
    else
      push_integer(val,ct->getSize(),false,vn,op);
    return;
  case TYPE_INT:
    if (ct->isCharPrint())
      pushCharConstant(val,(TypeChar *)ct,vn,op);
    else if (ct->isEnumType())
      pushEnumConstant(val,(TypeEnum *)ct,vn,op);
    else
      push_integer(val,ct->getSize(),true,vn,op);
    return;
  case TYPE_UNKNOWN:
    push_integer(val,ct->getSize(),false,vn,op);
    return;
  case TYPE_BOOL:
    pushBoolConstant(val,(const TypeBase *)ct,vn,op);
    return;
  case TYPE_VOID:
    clear();
    throw LowlevelError("Cannot have a constant of type void");
  case TYPE_PTR:
  case TYPE_PTRREL:
    if (option_NULL&&(val==0)) { // A null pointer
      pushAtom(Atom(nullToken,vartoken,EmitMarkup::var_color,op,vn));
      return;
    }
    subtype = ((TypePointer *)ct)->getPtrTo();
    if (subtype->isCharPrint()) {
      if (pushPtrCharConstant(val,(const TypePointer *)ct,vn,op))
	return;
    }
    else if (subtype->getMetatype()==TYPE_CODE) {
      if (pushPtrCodeConstant(val,(const TypePointer *)ct,vn,op))
	return;
    }
    break;
  case TYPE_FLOAT:
    push_float(val,ct->getSize(),vn,op);
    return;
  case TYPE_SPACEBASE:
  case TYPE_CODE:
  case TYPE_ARRAY:
  case TYPE_STRUCT:
  case TYPE_UNION:
  case TYPE_PARTIALSTRUCT:
  case TYPE_PARTIALUNION:
    break;
  }
  // Default printing
  if (!option_nocasts) {
    pushOp(&typecast,op);
    pushType(ct);
  }
  pushMod();
  if (!isSet(force_dec))
    setMod(force_hex);
  push_integer(val,ct->getSize(),false,vn,op);
  popMod();
}

bool PrintC::pushEquate(uintb val,int4 sz,const EquateSymbol *sym,const Varnode *vn,const PcodeOp *op)

{
  uintb mask = calc_mask(sz);
  uintb baseval = sym->getValue();
  uintb modval = baseval & mask;
  if (modval != baseval) {					// If 1-bits are getting masked
    if (sign_extend(modval,sz,sizeof(uintb)) != baseval)	// make sure we only mask sign extension bits
      return false;
  }
  if (modval == val) {
    pushSymbol(sym,vn,op);
    return true;
  }
  modval = (~baseval) & mask;
  if (modval == val) {		// Negation
    pushOp(&bitwise_not,(const PcodeOp *)0);
    pushSymbol(sym,vn,op);
    return true;
  }
  modval = (-baseval) & mask;
  if (modval == val) {		// twos complement
    pushOp(&unary_minus,(const PcodeOp *)0);
    pushSymbol(sym,vn,op);
    return true;
  }
  modval = (baseval + 1) & mask;
  if (modval == val) {
    pushOp(&binary_plus,(const PcodeOp *)0);
    pushSymbol(sym,vn,op);
    push_integer(1, sz, false, (const Varnode *)0, (const PcodeOp *)0);
    return true;
  }
  modval = (baseval - 1) & mask;
  if (modval == val) {
    pushOp(&binary_minus,(const PcodeOp *)0);
    pushSymbol(sym,vn,op);
    push_integer(1, sz, false, (const Varnode *)0, (const PcodeOp *)0);
    return true;
  }
  return false;
}

void PrintC::pushAnnotation(const Varnode *vn,const PcodeOp *op)

{
  const Scope *symScope = op->getParent()->getFuncdata()->getScopeLocal();
  int4 size = 0;
  if (op->code() == CPUI_CALLOTHER) {
    int4 userind = (int4)op->getIn(0)->getOffset();
    size = glb->userops.getOp(userind)->extractAnnotationSize(vn, op);
  }
  SymbolEntry *entry;
  if (size != 0)
    entry = symScope->queryContainer(vn->getAddr(),size,op->getAddr());
  else {
    entry = symScope->queryContainer(vn->getAddr(),1,op->getAddr());
    if (entry != (SymbolEntry *)0)
      size = entry->getSize();
    else
      size = vn->getSize();
  }
  
  if (entry != (SymbolEntry *)0) {
    if (entry->getSize() == size)
      pushSymbol(entry->getSymbol(),vn,op);
    else {
      int4 symboloff = vn->getOffset() - entry->getFirst();
      pushPartialSymbol(entry->getSymbol(),symboloff,size,vn,op,-1);
    }
  }
  else {
    string regname = glb->translate->getRegisterName(vn->getSpace(),vn->getOffset(),size);
    if (regname.empty()) {
      AddrSpace *spc = vn->getSpace();
      string spacename = spc->getName();
      spacename[0] = toupper( spacename[0] ); // Capitalize space
      ostringstream s;
      s << spacename;
      s << hex << setfill('0') << setw(2*spc->getAddrSize());
      s << AddrSpace::byteToAddress( vn->getOffset(), spc->getWordSize() );
      regname = s.str();
    }
    pushAtom(Atom(regname,vartoken,EmitMarkup::special_color,op,vn));
  }
}

void PrintC::pushSymbol(const Symbol *sym,const Varnode *vn,const PcodeOp *op)

{
  EmitMarkup::syntax_highlight tokenColor;
  if (sym->isVolatile())
    tokenColor = EmitMarkup::special_color;
  else if (sym->getScope()->isGlobal())
    tokenColor = EmitMarkup::global_color;
  else if (sym->getCategory() == Symbol::function_parameter)
    tokenColor = EmitMarkup::param_color;
  else
    tokenColor = EmitMarkup::var_color;
  pushSymbolScope(sym);
  if (sym->hasMergeProblems() && vn != (Varnode *)0) {
    HighVariable *high = vn->getHigh();
    if (high->isUnmerged()) {
      ostringstream s;
      s << sym->getName();
      SymbolEntry *entry = high->getSymbolEntry();
      if (entry != (SymbolEntry *)0) {
	s << '$' << dec << entry->getSymbol()->getMapEntryPosition(entry);
      }
      else
	s << "$$";
      pushAtom(Atom(s.str(),vartoken,tokenColor,op,vn));
      return;
    }
  }
  pushAtom(Atom(sym->getName(),vartoken,tokenColor,op,vn));
}

void PrintC::pushUnnamedLocation(const Address &addr,
				   const Varnode *vn,const PcodeOp *op)
{
  ostringstream s;
  s << addr.getSpace()->getName();
  addr.printRaw(s);
  pushAtom(Atom(s.str(),vartoken,EmitMarkup::var_color,op,vn));
}

void PrintC::pushPartialSymbol(const Symbol *sym,int4 off,int4 sz,
			       const Varnode *vn,const PcodeOp *op,
			       int4 inslot)
{
  // We need to print "bottom up" in order to get parentheses right
  // I.e. we want to print globalstruct.arrayfield[0], rather than
  //                       globalstruct.(arrayfield[0])
  vector<PartialSymbolEntry> stack;
  Datatype *finalcast = (Datatype *)0;
  
  Datatype *ct = sym->getType();

  while(ct != (Datatype *)0) {
    if (off == 0) {
      if (sz == 0 || (sz == ct->getSize() && (!ct->needsResolution() || ct->getMetatype()==TYPE_PTR)))
	break;
    }
    bool succeeded = false;
    if (ct->getMetatype()==TYPE_STRUCT) {
      if (ct->needsResolution() && ct->getSize() == sz) {
	Datatype *outtype = ct->findResolve(op, inslot);
	if (outtype == ct)
	  break;	// Turns out we don't resolve to the field
      }
      const TypeField *field;
      field = ct->findTruncation(off,sz,op,inslot,off);
      if (field != (const TypeField *)0) {
	stack.emplace_back();
	PartialSymbolEntry &entry( stack.back() );
	entry.token = &object_member;
	entry.field = field;
	entry.parent = ct;
	entry.fieldname = field->name;
	entry.hilite = EmitMarkup::no_color;
	ct = field->type;
	succeeded = true;
      }
    }
    else if (ct->getMetatype() == TYPE_ARRAY) {
      int4 el;
      Datatype *arrayof = ((TypeArray *)ct)->getSubEntry(off,sz,&off,&el);
      if (arrayof != (Datatype *)0) {
	stack.emplace_back();
	PartialSymbolEntry &entry( stack.back() );
	entry.token = &subscript;
	ostringstream s;
	s << dec << el;
	entry.fieldname = s.str();
	entry.field = (const TypeField *)0;
	entry.hilite = EmitMarkup::const_color;
	ct = arrayof;
	succeeded = true;
      }
    }
    else if (ct->getMetatype() == TYPE_UNION) {
      const TypeField *field;
      field = ct->findTruncation(off,sz,op,inslot,off);
      if (field != (const TypeField*)0) {
	stack.emplace_back();
	PartialSymbolEntry &entry(stack.back());
	entry.token = &object_member;
	entry.field = field;
	entry.parent = ct;
	entry.fieldname = entry.field->name;
	entry.hilite = EmitMarkup::no_color;
	ct = field->type;
	succeeded = true;
      }
      else if (ct->getSize() == sz)
	break;		// Turns out we don't need to resolve the field
    }
    else if (inslot >= 0) {
      Datatype *outtype = vn->getHigh()->getType();
      if (castStrategy->isSubpieceCastEndian(outtype,ct,off,
					     sym->getFirstWholeMap()->getAddr().getSpace()->isBigEndian())) {
	// Treat truncation as SUBPIECE style cast
	finalcast = outtype;
	ct = (Datatype*)0;
	succeeded = true;
      }
    }
    if (!succeeded) {		// Subtype was not good
      stack.emplace_back();
      PartialSymbolEntry &entry(stack.back());
      entry.token = &object_member;
      if (sz == 0)
	sz = ct->getSize() - off;
      entry.fieldname = unnamedField(off, sz);	// If nothing else works, generate artificial field name
      entry.field = (const TypeField *)0;
      entry.hilite = EmitMarkup::no_color;
      ct = (Datatype *)0;
    }
  }

  if ((finalcast != (Datatype *)0)&&(!option_nocasts)) {
    pushOp(&typecast,op);
    pushType(finalcast);
  }
  // Push these on the RPN stack in reverse order
  for(int4 i=stack.size()-1;i>=0;--i)
    pushOp(stack[i].token,op);
  pushSymbol(sym,vn,op);	// Push base symbol name
  for(int4 i=0;i<stack.size();++i) {
    const TypeField *field = stack[i].field;
    if (field == (const TypeField *)0)
      pushAtom(Atom(stack[i].fieldname,syntax,stack[i].hilite,op));
    else
      pushAtom(Atom(stack[i].fieldname,fieldtoken,stack[i].hilite,stack[i].parent,field->ident,op));
  }
}

void PrintC::pushMismatchSymbol(const Symbol *sym,int4 off,int4 sz,
				const Varnode *vn,const PcodeOp *op)
{
  if (off==0) {
  // The most common situation is when a user sees a reference
  // to a variable and forces a symbol to be there but guesses
  // the type (or size) incorrectly
  // The address of the symbol is correct, but the size is too small

  // We prepend an underscore to indicate a close
  // but not quite match
    string nm = '_'+sym->getName();
    pushAtom(Atom(nm,vartoken,EmitMarkup::var_color,op,vn));
  }
  else
    pushUnnamedLocation(vn->getAddr(),vn,op);
}

void PrintC::pushImpliedField(const Varnode *vn,const PcodeOp *op)

{
  bool proceed = false;
  Datatype *parent = vn->getHigh()->getType();
  const TypeField *field;
  if (parent->needsResolution() && parent->getMetatype() != TYPE_PTR) {
    const Funcdata *fd = op->getParent()->getFuncdata();
    int4 slot = op->getSlot(vn);
    const ResolvedUnion *res = fd->getUnionField(parent, op, slot);
    if (res != (const ResolvedUnion *)0 && res->getFieldNum() >= 0) {
      if (parent->getMetatype() == TYPE_STRUCT && res->getFieldNum() == 0) {
        field = &(*((TypeStruct *)parent)->beginField());
        proceed = true;
      }
      else if (parent->getMetatype() == TYPE_UNION) {
        field = ((TypeUnion *)parent)->getField(res->getFieldNum());
        proceed = true;
      }
    }
  }

  const PcodeOp *defOp = vn->getDef();
  if (!proceed) {
    // Just push original op
    defOp->getOpcode()->push(this,defOp,op);
    return;
  }
  pushOp(&object_member,op);
  defOp->getOpcode()->push(this,defOp,op);
  pushAtom(Atom(field->name,fieldtoken,EmitMarkup::no_color,parent,field->ident,op));
}

/// Print all the components making up the data-type, using the \b struct keyword
/// \param ct is the structure data-type
void PrintC::emitStructDefinition(const TypeStruct *ct)

{
  vector<TypeField>::const_iterator iter;

  if (ct->getName().size()==0) {
    clear();
    throw LowlevelError("Trying to save unnamed structure");
  }

  emit->tagLine();
  emit->print("typedef struct",EmitMarkup::keyword_color);
  emit->spaces(1);
  int4 id = emit->startIndent();
  emit->print(OPEN_CURLY);
  emit->tagLine();
  iter = ct->beginField();
  while(iter!=ct->endField()) {
    pushTypeStart((*iter).type,false);
    pushAtom(Atom((*iter).name,syntax,EmitMarkup::var_color));
    pushTypeEnd((*iter).type);
    iter++;
    if (iter != ct->endField()) {
      emit->print(COMMA); // Print comma separator
      emit->tagLine();
    }
  }
  emit->stopIndent(id);
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  emit->spaces(1);
  emit->print(ct->getName());
  emit->print(SEMICOLON);
}

/// Print all the named values making up the data-type, using the \b enum keyword
/// \param ct is the enumerated data-type
void PrintC::emitEnumDefinition(const TypeEnum *ct)

{
  map<uintb,string>::const_iterator iter;

  if (ct->getName().size()==0) {
    clear();
    throw LowlevelError("Trying to save unnamed enumeration");
  }

  pushMod();
  bool sign = (ct->getMetatype() == TYPE_INT);
  emit->tagLine();
  emit->print("typedef enum",EmitMarkup::keyword_color);
  emit->spaces(1);
  int4 id = emit->startIndent();
  emit->print(OPEN_CURLY);
  emit->tagLine();
  iter = ct->beginEnum();
  while(iter!=ct->endEnum()) {
    emit->print((*iter).second,EmitMarkup::const_color);
    emit->spaces(1);
    emit->print(EQUALSIGN,EmitMarkup::no_color);
    emit->spaces(1);
    push_integer((*iter).first,ct->getSize(),sign,(Varnode *)0,
		 (PcodeOp *)0);
    recurse();
    emit->print(SEMICOLON);
    ++iter;
    if (iter != ct->endEnum())
      emit->tagLine();
  }
  popMod();
  emit->stopIndent(id);
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  emit->spaces(1);
  emit->print(ct->getName());
  emit->print(SEMICOLON);
}

/// In C, when printing a function prototype, the function's output data-type is displayed first
/// as a type declaration, where the function name acts as the declaration's identifier.
/// This method emits the declaration in preparation for this.
/// \param proto is the function prototype object
/// \param fd is the (optional) Funcdata object providing additional meta-data about the function
void PrintC::emitPrototypeOutput(const FuncProto *proto,
				 const Funcdata *fd)
{
  PcodeOp *op;
  Varnode *vn;

  if (fd != (const Funcdata *)0) {
    op = fd->getFirstReturnOp();
    if (op != (PcodeOp *)0 && op->numInput() < 2)
      op = (PcodeOp *)0;
  }
  else
    op = (PcodeOp *)0;

  Datatype *outtype = proto->getOutputType();
  if ((outtype->getMetatype()!=TYPE_VOID)&&(op != (PcodeOp *)0))
    vn = op->getIn(1);
  else
    vn = (Varnode *)0;
  int4 id = emit->beginReturnType(vn);
  pushType(outtype);
  recurse();
  emit->endReturnType(id);
}

/// This emits the individual type declarations of the input parameters to the function as a
/// comma separated list.
/// \param proto is the given prototype of the function
void PrintC::emitPrototypeInputs(const FuncProto *proto)

{
  int4 sz = proto->numParams();
  
  if (sz == 0)
    emit->print(KEYWORD_VOID,EmitMarkup::keyword_color);
  else {
    bool printComma = false;
    for(int4 i=0;i<sz;++i) {
      if (printComma)
	emit->print(COMMA);
      ProtoParameter *param = proto->getParam(i);
      if (isSet(hide_thisparam) && param->isThisPointer())
	continue;
      Symbol *sym = param->getSymbol();
      printComma = true;
      if (sym != (Symbol *)0)
	emitVarDecl(sym);
      else {
	// Emit type without name, if there is no backing symbol
	pushTypeStart(param->getType(),true);
	pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));
	pushTypeEnd(param->getType());
	recurse();
      }
    }
  }
  if (proto->isDotdotdot()) {
    if (sz != 0)
      emit->print(COMMA);
    emit->print(DOTDOTDOT);
  }
}

/// A formal variable declaration is emitted for every symbol in the given
/// function scope. I.e. all local variables are declared.
/// \param fd is the function being emitted
void PrintC::emitLocalVarDecls(const Funcdata *fd)

{
  bool notempty = false;

  if (emitScopeVarDecls(fd->getScopeLocal(),Symbol::no_category))
    notempty = true;
  ScopeMap::const_iterator iter,enditer;
  iter = fd->getScopeLocal()->childrenBegin();
  enditer = fd->getScopeLocal()->childrenEnd();
  while(iter!=enditer) {
    Scope *l1 = (*iter).second;
    if (emitScopeVarDecls(l1,Symbol::no_category))
      notempty = true;
    ++iter;
  }

  if (notempty)
    emit->tagLine();
}

/// This emits an entire statement rooted at a given operation. All associated expressions
/// on the right-hand and left-hand sides are recursively emitted. Depending on the current
/// printing properties, the statement is usually terminated with ';' character.
/// \param inst is the given root PcodeOp of the statement
void PrintC::emitStatement(const PcodeOp *inst)

{
  int4 id = emit->beginStatement(inst);
  emitExpression(inst);
  emit->endStatement(id);
  if (!isSet(comma_separate))
    emit->print(SEMICOLON);
}

/// \brief Emit a statement representing an unstructured branch
///
/// Given the type of unstructured branch, with source and destination blocks,
/// construct a statement with the appropriate c-language keyword (\b goto, \b break, \b continue)
/// representing a control-flow branch between the blocks.
/// \param bl is the source block
/// \param exp_bl is the destination block (which may provide a label)
/// \param type is the given type of the branch
void PrintC::emitGotoStatement(const FlowBlock *bl,const FlowBlock *exp_bl,
			       uint4 type)

{
  int4 id = emit->beginStatement(bl->lastOp());
  switch(type) {
  case FlowBlock::f_break_goto:
    emit->print(KEYWORD_BREAK,EmitMarkup::keyword_color);
    break;
  case FlowBlock::f_continue_goto:
    emit->print(KEYWORD_CONTINUE,EmitMarkup::keyword_color);
    break;
  case FlowBlock::f_goto_goto:
    emit->print(KEYWORD_GOTO,EmitMarkup::keyword_color);
    emit->spaces(1);
    emitLabel(exp_bl);
    break;
  }
  emit->print(SEMICOLON);
  emit->endStatement(id);
}

void PrintC::resetDefaults(void)

{
  PrintLanguage::resetDefaults();
  resetDefaultsPrintC();
}

void PrintC::initializeFromArchitecture(void)

{
  castStrategy->setTypeFactory(glb->types);
  if (glb->types->getSizeOfLong() == glb->types->getSizeOfInt())	// If long and int sizes are the same
    sizeSuffix = "LL";		// Use "long long" suffix to indicate large integer
  else
    sizeSuffix = "L";		// Otherwise just use long suffix
}

void PrintC::adjustTypeOperators(void)

{
  scope.print1 = "::";
  shift_right.print1 = ">>";
  TypeOp::selectJavaOperators(glb->inst,false);
}

void PrintC::setCommentStyle(const string &nm)

{
  if ((nm=="c")||
      ( (nm.size()>=2)&&(nm[0]=='/')&&(nm[1]=='*')))
    setCStyleComments();
  else if ((nm=="cplusplus")||
	   ( (nm.size()>=2)&&(nm[0]=='/')&&(nm[1]=='/')))
    setCPlusPlusStyleComments();
  else
    throw LowlevelError("Unknown comment style. Use \"c\" or \"cplusplus\"");
}

/// \brief Emit the definition of the given data-type
///
/// This is currently limited to a 'struct' or 'enum' definitions. The
/// definition is emitted so that name associated with data-type object
/// will be associated with the definition (in anything that parses it)
/// \param ct is the given data-type
void PrintC::emitTypeDefinition(const Datatype *ct)

{
#ifdef CPUI_DEBUG
  if (!isStackEmpty()) {
    clear();
    throw LowlevelError("Expression stack not empty at beginning of emit");
  }
#endif
  if (ct->getMetatype() == TYPE_STRUCT)
    emitStructDefinition((const TypeStruct *)ct);
  else if (ct->isEnumType())
    emitEnumDefinition((const TypeEnum *)ct);
  else {
    clear();
    throw LowlevelError("Unsupported typedef");
  }
}

bool PrintC::checkPrintNegation(const Varnode *vn)

{
  if (!vn->isImplied()) return false;
  if (!vn->isWritten()) return false;
  const PcodeOp *op = vn->getDef();
  bool reorder = false;
  OpCode opc = get_booleanflip(op->code(),reorder); // This is the set of ops that can be negated as a token
  if (opc == CPUI_MAX)
    return false;
  return true;
}

void PrintC::docTypeDefinitions(const TypeFactory *typegrp)

{
  vector<Datatype *> deporder;
  vector<Datatype *>::iterator iter;

  typegrp->dependentOrder(deporder); // Put things in resolvable order
  for(iter=deporder.begin();iter!=deporder.end();++iter) {
    if ((*iter)->isCoreType()) continue;
    emitTypeDefinition(*iter);
  }
}

/// Check that the given p-code op has an \e in-place token form and if the first input and the output
/// are references to  the same variable. If so, emit the expression using the \e in-place token.
/// \param op is the given PcodeOp
/// \return \b true if the expression was emitted (as in-place), or \b false if not emitted at all
bool PrintC::emitInplaceOp(const PcodeOp *op)

{
  OpToken *tok;
  switch(op->code()) {
  case CPUI_INT_MULT:
    tok = &multequal;
    break;
  case CPUI_INT_DIV:
  case CPUI_INT_SDIV:
    tok = &divequal;
    break;
  case CPUI_INT_REM:
  case CPUI_INT_SREM:
    tok = &remequal;
    break;
  case CPUI_INT_ADD:
    tok = &plusequal;
    break;
  case CPUI_INT_SUB:
    tok = &minusequal;
    break;
  case CPUI_INT_LEFT:
    tok = &leftequal;
    break;
  case CPUI_INT_RIGHT:
  case CPUI_INT_SRIGHT:
    tok = &rightequal;
    break;
  case CPUI_INT_AND:
    tok = &andequal;
    break;
  case CPUI_INT_OR:
    tok = &orequal;
    break;
  case CPUI_INT_XOR:
    tok = &xorequal;
    break;
  default:
    return false;
  }
  const Varnode *vn = op->getIn(0);
  if (op->getOut()->getHigh() != vn->getHigh()) return false;
  pushOp(tok,op);
  pushVnExplicit(vn,op);
  pushVn(op->getIn(1),op,mods);
  recurse();
  return true;
}

void PrintC::emitExpression(const PcodeOp *op)
   
{
  const Varnode *outvn = op->getOut();
  if (outvn != (Varnode *)0) {
    if (option_inplace_ops && emitInplaceOp(op)) return;
    pushOp(&assignment,op);
    pushSymbolDetail(outvn,op,false);
  }
  else if (op->doesSpecialPrinting()) {
    // Printing of constructor syntax
    const PcodeOp *newop = op->getIn(1)->getDef();
    outvn = newop->getOut();
    pushOp(&assignment,newop);
    pushSymbolDetail(outvn,newop,false);
    opConstructor(op,true);
    recurse();
    return;
  }
    // If STORE, print  *( ) = ( )
    // If BRANCH, print nothing
    // If CBRANCH, print condition  ( )
    // If BRANCHIND, print switch( )
    // If CALL, CALLIND, CALLOTHER  print  call
    // If RETURN,   print return ( )
  op->getOpcode()->push(this,op,(PcodeOp *)0);
  recurse();
}

void PrintC::emitVarDecl(const Symbol *sym)

{
  int4 id = emit->beginVarDecl(sym);

  pushTypeStart(sym->getType(),false);
  pushSymbol(sym,(Varnode *)0,(PcodeOp *)0);
  pushTypeEnd(sym->getType());
  recurse();
  
  emit->endVarDecl(id);
}

void PrintC::emitVarDeclStatement(const Symbol *sym)

{
  emit->tagLine();
  emitVarDecl(sym);
  emit->print(SEMICOLON);
}

bool PrintC::emitScopeVarDecls(const Scope *symScope,int4 cat)

{
  bool notempty = false;
  
  if (cat >= 0) {		// If a category is specified
    int4 sz = symScope->getCategorySize(cat);
    for(int4 i=0;i<sz;++i) {
      Symbol *sym = symScope->getCategorySymbol(cat,i);
      // Slightly different handling for categorized symbols (cat=1 is dynamic symbols)
      if (sym->getName().size() == 0) continue;
      if (sym->isNameUndefined()) continue;
      notempty = true;
      emitVarDeclStatement(sym);
    }
    return notempty;
  }
  MapIterator iter = symScope->begin();
  MapIterator enditer = symScope->end();
  for(;iter!=enditer;++iter) {
    const SymbolEntry *entry = *iter;
    if (entry->isPiece()) continue; // Don't do a partial entry
    Symbol *sym = entry->getSymbol();
    if (sym->getCategory() != cat) continue;
    if (sym->getName().size() == 0) continue;
    if (dynamic_cast<FunctionSymbol *>(sym) != (FunctionSymbol *)0)
      continue;
    if (dynamic_cast<LabSymbol *>(sym) != (LabSymbol *)0)
      continue;
    if (sym->isMultiEntry()) {
      if (sym->getFirstWholeMap() != entry)
	continue;		// Only emit the first SymbolEntry for declaration of multi-entry Symbol
    }
    notempty = true;
    emitVarDeclStatement(sym);
  }
  list<SymbolEntry>::const_iterator iter_d = symScope->beginDynamic();
  list<SymbolEntry>::const_iterator enditer_d = symScope->endDynamic();
  for(;iter_d!=enditer_d;++iter_d) {
    const SymbolEntry *entry = &(*iter_d);
    if (entry->isPiece()) continue; // Don't do a partial entry
    Symbol *sym = (*iter_d).getSymbol();
    if (sym->getCategory() != cat) continue;
    if (sym->getName().size() == 0) continue;
    if (dynamic_cast<FunctionSymbol *>(sym) != (FunctionSymbol *)0)
      continue;
    if (dynamic_cast<LabSymbol *>(sym) != (LabSymbol *)0)
      continue;
    if (sym->isMultiEntry()) {
      if (sym->getFirstWholeMap() != entry)
	continue;
    }
    notempty = true;
    emitVarDeclStatement(sym);
  }

  return notempty;
}

void PrintC::emitFunctionDeclaration(const Funcdata *fd)
{
  const FuncProto *proto = &fd->getFuncProto();
  int4 id = emit->beginFuncProto();
  emitPrototypeOutput(proto,fd);
  emit->spaces(1);
  if (option_convention) {
    if (fd->getFuncProto().printModelInDecl()) {
      Emit::syntax_highlight highlight = fd->getFuncProto().isModelUnknown() ? Emit::error_color : Emit::keyword_color;
      emit->print(fd->getFuncProto().getModelName(),highlight);
      emit->spaces(1);
    }
  }
  int4 id1 = emit->openGroup();
  emitSymbolScope(fd->getSymbol());
  emit->tagFuncName(fd->getName(),EmitMarkup::funcname_color,fd,(PcodeOp *)0);

  emit->spaces(function_call.spacing,function_call.bump);
  int4 id2 = emit->openParen(OPEN_PAREN);
  emit->spaces(0,function_call.bump);
  pushScope(fd->getScopeLocal());		// Enter the function's scope for parameters
  emitPrototypeInputs(proto);
  emit->closeParen(CLOSE_PAREN,id2);
  emit->closeGroup(id1);

  emit->endFuncProto(id);
}

/// For the given scope and all of its children that are not \e function scopes,
/// emit a variable declaration for each symbol.
/// \param symScope is the given scope
void PrintC::emitGlobalVarDeclsRecursive(Scope *symScope)

{
  if (!symScope->isGlobal()) return;
  emitScopeVarDecls(symScope,Symbol::no_category);
  ScopeMap::const_iterator iter,enditer;
  iter = symScope->childrenBegin();
  enditer = symScope->childrenEnd();
  for(;iter!=enditer;++iter) {
    emitGlobalVarDeclsRecursive((*iter).second);
  }
}

void PrintC::docAllGlobals(void)

{
  int4 id = emit->beginDocument();
  emitGlobalVarDeclsRecursive(glb->symboltab->getGlobalScope());
  emit->tagLine();
  emit->endDocument(id);
  emit->flush();
}

void PrintC::docSingleGlobal(const Symbol *sym)

{
  int4 id = emit->beginDocument();
  emitVarDeclStatement(sym);
  emit->tagLine();		// Extra line
  emit->endDocument(id);
  emit->flush();
}

void PrintC::docFunction(const Funcdata *fd)

{
  uint4 modsave = mods;
  if (!fd->isProcStarted())
    throw RecovError("Function not decompiled");
  if ((!isSet(flat))&&(fd->hasNoStructBlocks()))
    throw RecovError("Function not fully decompiled. No structure present.");
  try {
    commsorter.setupFunctionList(instr_comment_type|head_comment_type,fd,*fd->getArch()->commentdb,option_unplaced);
    int4 id1 = emit->beginFunction(fd);
    emitCommentFuncHeader(fd);
    emit->tagLine();
    emitFunctionDeclaration(fd);	// Causes us to enter function's scope
    emit->tagLine();
    emit->tagLine();
    int4 id = emit->startIndent();
    emit->print(OPEN_CURLY);
    emitLocalVarDecls(fd);
    if (isSet(flat))
      emitBlockGraph(&fd->getBasicBlocks());
    else
      emitBlockGraph(&fd->getStructure());
    popScope();				// Exit function's scope
    emit->stopIndent(id);
    emit->tagLine();
    emit->print(CLOSE_CURLY);
    emit->tagLine();
    emit->endFunction(id1);
    emit->flush();
#ifdef CPUI_DEBUG
    if ((mods != modsave)||(!isModStackEmpty()))
      throw RecovError("Printing modification stack has not been purged");
#endif
    mods = modsave;
  }
  catch(LowlevelError &err) {
    clear();		       // Don't leave printer in partial state
    throw err;
  }
}

void PrintC::emitBlockBasic(const BlockBasic *bb)

{
  const PcodeOp *inst;
  bool separator;

  commsorter.setupBlockList(bb);
  emitLabelStatement(bb);	// Print label (for flat prints)
  if (isSet(only_branch)) {
    inst = bb->lastOp();
    if (inst->isBranch())
      emitExpression(inst);	// Only print branch instruction
  }
  else {
    separator = false;
    list<PcodeOp *>::const_iterator iter;
    for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
      inst = *iter;
      if (inst->notPrinted()) continue;
      if (inst->isBranch()) {
	if (isSet(no_branch)) continue;
	// A straight branch is always printed by
	// the block classes
	if (inst->code() == CPUI_BRANCH) continue;
      }
      const Varnode *vn = inst->getOut();
      if ((vn!=(const Varnode *)0)&&(vn->isImplied()))
	continue;
      if (separator) {
	if (isSet(comma_separate)) {
	  emit->print(COMMA);
	  emit->spaces(1);
	}
	else {
	  emitCommentGroup(inst);
	  emit->tagLine();
	}
      }
      else if (!isSet(comma_separate)) {
	emitCommentGroup(inst);
	emit->tagLine();
      }
      emitStatement(inst);
      separator = true;
    }
				// If we are printing flat structure and there
				// is no longer a normal fallthru, print a goto
    if (isSet(flat)&&isSet(nofallthru)) {
      inst = bb->lastOp();
      emit->tagLine();
      int4 id = emit->beginStatement(inst);
      emit->print(KEYWORD_GOTO,EmitMarkup::keyword_color);
      emit->spaces(1);
      if (bb->sizeOut()==2) {
	if (inst->isFallthruTrue())
	  emitLabel(bb->getOut(1));
	else
	  emitLabel(bb->getOut(0));
      }
      else
	emitLabel(bb->getOut(0));
      emit->print(SEMICOLON);
      emit->endStatement(id);
    }
    emitCommentGroup((const PcodeOp *)0); // Any remaining comments
  }
}

void PrintC::emitBlockGraph(const BlockGraph *bl)

{
  const vector<FlowBlock *> &list(bl->getList());
  vector<FlowBlock *>::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    int4 id = emit->beginBlock(*iter);
    (*iter)->emit(this);
    emit->endBlock(id);
  }
}

void PrintC::emitBlockCopy(const BlockCopy *bl)

{
  emitAnyLabelStatement(bl);
  bl->subBlock(0)->emit(this);
}

void PrintC::emitBlockGoto(const BlockGoto *bl)

{
  pushMod();
  setMod(no_branch);
  bl->getBlock(0)->emit(this);
  popMod();
				// Make sure we don't print goto, if it is the
				// next block to be printed
  if (bl->gotoPrints()) {
    emit->tagLine();
    emitGotoStatement(bl->getBlock(0),bl->getGotoTarget(),bl->getGotoType());
  }
}

void PrintC::emitBlockLs(const BlockList *bl)

{
  int4 i;
  FlowBlock *subbl;

  if (isSet(only_branch)) {
    subbl = bl->getBlock(bl->getSize()-1);
    subbl->emit(this);
    return;
  }

  if (bl->getSize()==0) return;
  i = 0;
  subbl = bl->getBlock(i++);
  int4 id1 = emit->beginBlock(subbl);
  if (i==bl->getSize()) {
    subbl->emit(this);
    emit->endBlock(id1);
    return;
  }
  pushMod();
  if (!isSet(flat))
    setMod(no_branch);
  if (bl->getBlock(i) != subbl->nextInFlow()) {
    pushMod();
    setMod(nofallthru);
    subbl->emit(this);
    popMod();
  }
  else {
    subbl->emit(this);
  }
  emit->endBlock(id1);

  while(i<bl->getSize()-1) {
    subbl = bl->getBlock(i++);
    int4 id2 = emit->beginBlock(subbl);
    if (bl->getBlock(i) != subbl->nextInFlow()) {
      pushMod();
      setMod(nofallthru);
      subbl->emit(this);
      popMod();
    }
    else
      subbl->emit(this);
    emit->endBlock(id2);
  }
  popMod();
  subbl = bl->getBlock(i);		// The final block
  int4 id3 = emit->beginBlock(subbl);
  subbl->emit(this);		// Pass original no_branch state
  emit->endBlock(id3);
}

void PrintC::emitBlockCondition(const BlockCondition *bl)

{
  // FIXME: get rid of parens and properly emit && and ||
  if (isSet(no_branch)) {
    int4 id = emit->beginBlock(bl->getBlock(0));
    bl->getBlock(0)->emit(this);
    emit->endBlock(id);
    return;
  }
  if (isSet(only_branch) || isSet(comma_separate)) {
    int4 id = emit->openParen(OPEN_PAREN);
    bl->getBlock(0)->emit(this);
    pushMod();
    unsetMod(only_branch);
				// Notice comma_separate placed only on second block
    setMod(comma_separate);

    // Set up OpToken so it is emitted as if on the stack
    ReversePolish pol;
    pol.op = (PcodeOp *)0;
    pol.visited = 1;
    if (bl->getOpcode() == CPUI_BOOL_AND)
      pol.tok = &boolean_and;
    else
      pol.tok = &boolean_or;
    emitOp(pol);

    int4 id2 = emit->openParen(OPEN_PAREN);
    bl->getBlock(1)->emit(this);
    emit->closeParen(CLOSE_PAREN,id2);
    popMod();
    emit->closeParen(CLOSE_PAREN,id);
  }
}

void PendingBrace::callback(Emit *emit)

{
  emit->print(PrintC::OPEN_CURLY);
  indentId = emit->startIndent();
}

void PrintC::emitBlockIf(const BlockIf *bl)

{
  const PcodeOp *op;
  PendingBrace pendingBrace;

  if (isSet(pending_brace))
    emit->setPendingPrint(&pendingBrace);

				// if block never prints final branch
				// so no_branch and only_branch don't matter
				// and shouldn't be passed automatically to
				// the subblocks
  pushMod();
  unsetMod(no_branch|only_branch|pending_brace);

  pushMod();
  setMod(no_branch);
  FlowBlock *condBlock = bl->getBlock(0);
  condBlock->emit(this);
  popMod();
  emitCommentBlockTree(condBlock);
  if (emit->hasPendingPrint(&pendingBrace))	// If we issued a brace but it did not emit
    emit->cancelPendingPrint();			// Cancel the brace in order to have "else if" syntax
  else
    emit->tagLine();				// Otherwise start the "if" on a new line

  op = condBlock->lastOp();
  emit->tagOp(KEYWORD_IF,EmitMarkup::keyword_color,op);
  emit->spaces(1);
  pushMod();
  setMod(only_branch);
  condBlock->emit(this);
  popMod();
  if (bl->getGotoTarget() != (FlowBlock *)0) {
    emit->spaces(1);
    emitGotoStatement(condBlock,bl->getGotoTarget(),bl->getGotoType());
  }
  else {
    setMod(no_branch);
    emit->spaces(1);
    int4 id = emit->startIndent();
    emit->print(OPEN_CURLY);
    int4 id1 = emit->beginBlock(bl->getBlock(1));
    bl->getBlock(1)->emit(this);
    emit->endBlock(id1);
    emit->stopIndent(id);
    emit->tagLine();
    emit->print(CLOSE_CURLY);
    if (bl->getSize() == 3) {
      emit->tagLine();
      emit->print(KEYWORD_ELSE,EmitMarkup::keyword_color);
      emit->spaces(1);
      FlowBlock *elseBlock = bl->getBlock(2);
      if (elseBlock->getType() == FlowBlock::t_if) {
	// Attempt to merge the "else" and "if" syntax
	setMod(pending_brace);
	int4 id2 = emit->beginBlock(elseBlock);
	elseBlock->emit(this);
	emit->endBlock(id2);
      }
      else {
	int4 id2 = emit->startIndent();
	emit->print(OPEN_CURLY);
	int4 id3 = emit->beginBlock(elseBlock);
	elseBlock->emit(this);
	emit->endBlock(id3);
	emit->stopIndent(id2);
	emit->tagLine();
	emit->print(CLOSE_CURLY);
      }
    }
  }
  popMod();
  if (pendingBrace.getIndentId() >= 0) {
    emit->stopIndent(pendingBrace.getIndentId());
    emit->tagLine();
    emit->print(CLOSE_CURLY);
  }
}

/// Print the loop using the keyword \e for, followed by a semicolon separated
///   - Initializer statement
///   - Condition statment
///   - Iterate statement
///
/// Then print the body of the loop
void PrintC::emitForLoop(const BlockWhileDo *bl)

{
  const PcodeOp *op;
  int4 indent;

  pushMod();
  unsetMod(no_branch|only_branch);
  emitAnyLabelStatement(bl);
  FlowBlock *condBlock = bl->getBlock(0);
  emitCommentBlockTree(condBlock);
  emit->tagLine();
  op = condBlock->lastOp();
  emit->tagOp(KEYWORD_FOR,EmitMarkup::keyword_color,op);
  emit->spaces(1);
  int4 id1 = emit->openParen(OPEN_PAREN);
  pushMod();
  setMod(comma_separate);
  op = bl->getInitializeOp();		// Emit the (optional) initializer statement
  if (op != (PcodeOp *)0) {
    int4 id3 = emit->beginStatement(op);
    emitExpression(op);
    emit->endStatement(id3);
  }
  emit->print(SEMICOLON);
  emit->spaces(1);
  condBlock->emit(this);		// Emit the conditional statement
  emit->print(SEMICOLON);
  emit->spaces(1);
  op = bl->getIterateOp();		// Emit the iterator statement
  int4 id4 = emit->beginStatement(op);
  emitExpression(op);
  emit->endStatement(id4);
  popMod();
  emit->closeParen(CLOSE_PAREN,id1);
  emit->spaces(1);
  indent = emit->startIndent();
  emit->print(OPEN_CURLY);
  setMod(no_branch); // Dont print goto at bottom of clause
  int4 id2 = emit->beginBlock(bl->getBlock(1));
  bl->getBlock(1)->emit(this);
  emit->endBlock(id2);
  emit->stopIndent(indent);
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  popMod();
}

void PrintC::emitBlockWhileDo(const BlockWhileDo *bl)

{
  const PcodeOp *op;
  int4 indent;

  if (bl->getIterateOp() != (PcodeOp *)0) {
    emitForLoop(bl);
    return;
  }
				// whiledo block NEVER prints final branch
  pushMod();
  unsetMod(no_branch|only_branch);
  emitAnyLabelStatement(bl);
  FlowBlock *condBlock = bl->getBlock(0);
  op = condBlock->lastOp();
  if (bl->hasOverflowSyntax()) {
    // Print conditional block as
    //     while( true ) {
    //       conditionbody ...
    //       if (conditionalbranch) break;
    emit->tagLine();
    emit->tagOp(KEYWORD_WHILE,EmitMarkup::keyword_color,op);
    int4 id1 = emit->openParen(OPEN_PAREN);
    emit->spaces(1);
    emit->print(KEYWORD_TRUE,EmitMarkup::const_color);
    emit->spaces(1);
    emit->closeParen(CLOSE_PAREN,id1);
    emit->spaces(1);
    indent = emit->startIndent();
    emit->print(OPEN_CURLY);
    pushMod();
    setMod(no_branch);
    condBlock->emit(this);
    popMod();
    emitCommentBlockTree(condBlock);
    emit->tagLine();
    emit->tagOp(KEYWORD_IF,EmitMarkup::keyword_color,op);
    emit->spaces(1);
    pushMod();
    setMod(only_branch);
    condBlock->emit(this);
    popMod();
    emit->spaces(1);
    emitGotoStatement(condBlock,(const FlowBlock *)0,FlowBlock::f_break_goto);
  }
  else {
    // Print conditional block "normally" as
    //     while(condition) {
    emitCommentBlockTree(condBlock);
    emit->tagLine();
    emit->tagOp(KEYWORD_WHILE,EmitMarkup::keyword_color,op);
    emit->spaces(1);
    int4 id1 = emit->openParen(OPEN_PAREN);
    pushMod();
    setMod(comma_separate);
    condBlock->emit(this);
    popMod();
    emit->closeParen(CLOSE_PAREN,id1);
    emit->spaces(1);
    indent = emit->startIndent();
    emit->print(OPEN_CURLY);
  }
  setMod(no_branch); // Dont print goto at bottom of clause
  int4 id2 = emit->beginBlock(bl->getBlock(1));
  bl->getBlock(1)->emit(this);
  emit->endBlock(id2);
  emit->stopIndent(indent);
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  popMod();
}

void PrintC::emitBlockDoWhile(const BlockDoWhile *bl)

{
  const PcodeOp *op;

				// dowhile block NEVER prints final branch
  pushMod();
  unsetMod(no_branch|only_branch);
  emitAnyLabelStatement(bl);
  emit->tagLine();
  emit->print(KEYWORD_DO,EmitMarkup::keyword_color);
  emit->spaces(1);
  int4 id = emit->startIndent();
  emit->print(OPEN_CURLY);
  pushMod();
  int4 id2 = emit->beginBlock(bl->getBlock(0));
  setMod(no_branch);
  bl->getBlock(0)->emit(this);
  emit->endBlock(id2);
  popMod();
  emit->stopIndent(id);
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  emit->spaces(1);
  op = bl->getBlock(0)->lastOp();
  emit->tagOp(KEYWORD_WHILE,EmitMarkup::keyword_color,op);
  emit->spaces(1);
  setMod(only_branch);
  bl->getBlock(0)->emit(this);
  emit->print(SEMICOLON);
  popMod();
}

void PrintC::emitBlockInfLoop(const BlockInfLoop *bl)

{
  const PcodeOp *op;

  pushMod();
  unsetMod(no_branch|only_branch);
  emitAnyLabelStatement(bl);
  emit->tagLine();
  emit->print(KEYWORD_DO,EmitMarkup::keyword_color);
  emit->spaces(1);
  int4 id = emit->startIndent();
  emit->print(OPEN_CURLY);
  int4 id1 = emit->beginBlock(bl->getBlock(0));
  bl->getBlock(0)->emit(this);
  emit->endBlock(id1);
  emit->stopIndent(id);
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  emit->spaces(1);
  op = bl->getBlock(0)->lastOp();
  emit->tagOp(KEYWORD_WHILE,EmitMarkup::keyword_color,op);
  int4 id2 = emit->openParen(OPEN_PAREN);
  emit->spaces(1);
  emit->print(KEYWORD_TRUE,EmitMarkup::const_color);
  emit->spaces(1);
  emit->closeParen(CLOSE_PAREN,id2);
  emit->print(SEMICOLON);
  popMod();
}

/// Given a \e switch block and an index indicating a particular \e case block,
/// look up all the labels associated with that \e case and emit them
/// using formal labels with the \b case keyword and a ':' terminator.
/// \param casenum is the given index of the \e case block
/// \param switchbl is the root block of the switch
void PrintC::emitSwitchCase(int4 casenum,const BlockSwitch *switchbl)

{
  int4 i,num;
  uintb val;
  const Datatype *ct;
    
  ct = switchbl->getSwitchType();

  if (switchbl->isDefaultCase(casenum)) {
    emit->tagLine();
    emit->print(KEYWORD_DEFAULT,EmitMarkup::keyword_color);
    emit->print(COLON);
  }
  else {
    num = switchbl->getNumLabels(casenum);
    for(i=0;i<num;++i) {
      val = switchbl->getLabel(casenum,i);
      emit->tagLine();
      emit->print(KEYWORD_CASE,EmitMarkup::keyword_color);
      emit->spaces(1);
      pushConstant(val,ct,(Varnode *)0,(PcodeOp *)0);
      recurse();
      emit->print(COLON);
    }
  }
}

/// Check for an explicit label that has been registered with the basic block.
/// Otherwise, construct a generic label based on the entry address
/// of the block.  Emit the label as a single token.
/// \param bl is the given block
void PrintC::emitLabel(const FlowBlock *bl)

{
  bl = bl->getFrontLeaf();
  if (bl == (FlowBlock *)0) return;
  BlockBasic *bb = (BlockBasic *)bl->subBlock(0);
  Address addr = bb->getEntryAddr();
  const AddrSpace *spc = addr.getSpace();
  uintb off = addr.getOffset();
  if (!bb->hasSpecialLabel()) {
    if (bb->getType() == FlowBlock::t_basic) {
      const Scope *symScope = ((const BlockBasic *)bb)->getFuncdata()->getScopeLocal();
      Symbol *sym = symScope->queryCodeLabel(addr);
      if (sym != (Symbol *)0) {
	emit->tagLabel(sym->getName(),EmitMarkup::no_color,spc,off);
	return;
      }
    }
  }
  ostringstream lb;
  if (bb->isJoined())
    lb << "joined_";
  else if (bb->isDuplicated())
    lb << "dup_";
  else
    lb << "code_";
  lb << addr.getShortcut();
  addr.printRaw(lb);
  emit->tagLabel(lb.str(),EmitMarkup::no_color,spc,off);
}

/// If the basic block is the destination of a \b goto statement, emit a
/// label for the block followed by the ':' terminator.
/// \param bl is the given control-flow block
void PrintC::emitLabelStatement(const FlowBlock *bl)

{
  if (isSet(only_branch)) return;

  if (isSet(flat)) { // Printing flat version
    if (!bl->isJumpTarget()) return; // Print all jump targets
  }
  else {			// Printing structured version
    if (!bl->isUnstructuredTarget()) return;
    if (bl->getType() != FlowBlock::t_copy) return;
				// Only print labels that have unstructured jump to them
  }
  emit->tagLine(0);
  emitLabel(bl);
  emit->print(COLON);
}

/// The block does not have to be a basic block.  This routine finds the entry basic
/// block and prints any necessary labels for that.
/// \param bl is the given control-flow block
void PrintC::emitAnyLabelStatement(const FlowBlock *bl)

{
  if (bl->isLabelBumpUp()) return; // Label printed by someone else
  bl = bl->getFrontLeaf();
  if (bl == (FlowBlock *)0) return;
  emitLabelStatement(bl);
}
  
/// Collect any comment lines the sorter has associated with a statement
/// rooted at a given PcodeOp and emit them using appropriate delimiters
/// \param inst is the given PcodeOp
void PrintC::emitCommentGroup(const PcodeOp *inst)

{
  commsorter.setupOpList(inst);
  while(commsorter.hasNext()) {
    Comment *comm = commsorter.getNext();
    if (comm->isEmitted()) continue;
    if ((instr_comment_type & comm->getType())==0) continue;
    emitLineComment(-1,comm);
  }
}

/// With the control-flow hierarchy, print any comments associated with basic blocks in
/// the specified subtree.  Used where statements from multiple basic blocks are printed on
/// one line and a normal comment would get printed in the middle of this line.
/// \param bl is the root of the control-flow subtree
void PrintC::emitCommentBlockTree(const FlowBlock *bl)

{
  if (bl == (const FlowBlock *)0) return;
  FlowBlock::block_type btype = bl->getType();
  if (btype == FlowBlock::t_copy) {
    bl = bl->subBlock(0);
    btype = bl->getType();
  }
  if (btype == FlowBlock::t_plain) return;
  if (bl->getType() != FlowBlock::t_basic) {
    const BlockGraph *rootbl = (const BlockGraph *)bl;
    int4 size = rootbl->getSize();
    for(int4 i=0;i<size;++i) {
      emitCommentBlockTree(rootbl->subBlock(i));
    }
    return;
  }
  commsorter.setupBlockList(bl);
  emitCommentGroup((const PcodeOp *)0);	// Emit any comments for the block
}

/// Collect all comment lines marked as \e header for the function and
/// emit them with the appropriate delimiters.
/// \param fd is the given function
void PrintC::emitCommentFuncHeader(const Funcdata *fd)

{
  bool extralinebreak = false;
  commsorter.setupHeader(CommentSorter::header_basic);
  while(commsorter.hasNext()) {
    Comment *comm = commsorter.getNext();
    if (comm->isEmitted()) continue;
    if ((head_comment_type & comm->getType())==0) continue;
    emitLineComment(0,comm);
    extralinebreak = true;
  }
  if (option_unplaced) {
    if (extralinebreak)
      emit->tagLine();
    extralinebreak = false;
    commsorter.setupHeader(CommentSorter::header_unplaced);
    while(commsorter.hasNext()) {
      Comment *comm = commsorter.getNext();
      if (comm->isEmitted()) continue;
      if (!extralinebreak) {
	Comment label(Comment::warningheader,fd->getAddress(),fd->getAddress(),0,
		      "Comments that could not be placed in the function body:");
	emitLineComment(0,&label);
	extralinebreak = true;
      }
      emitLineComment(1,comm);
    }
  }
  if (option_nocasts) {
    if (extralinebreak)
      emit->tagLine();
    Comment comm(Comment::warningheader,fd->getAddress(),fd->getAddress(),0,
		 "DISPLAY WARNING: Type casts are NOT being printed");
    emitLineComment(0,&comm);
    extralinebreak = true;
  }
  if (extralinebreak)
    emit->tagLine();		// Extra linebreak if comment exists
}

void PrintC::emitBlockSwitch(const BlockSwitch *bl)

{
  FlowBlock *bl2;

  pushMod();
  unsetMod(no_branch|only_branch);
  pushMod();
  setMod(no_branch);
  bl->getSwitchBlock()->emit(this);
  popMod();
  emit->tagLine();
  pushMod();
  setMod(only_branch|comma_separate);
  bl->getSwitchBlock()->emit(this);
  popMod();
  emit->spaces(1);
  emit->print(OPEN_CURLY);

  for(int4 i=0;i<bl->getNumCaseBlocks();++i) {
    emitSwitchCase(i,bl);
    int4 id = emit->startIndent();
    if (bl->getGotoType(i)!=0) {
      emit->tagLine();
      emitGotoStatement(bl->getBlock(0),bl->getCaseBlock(i),bl->getGotoType(i));
    }
    else {
      bl2 = bl->getCaseBlock(i);
      int4 id2 = emit->beginBlock(bl2);
      bl2->emit(this);
      if (bl->isExit(i)&&(i!=bl->getNumCaseBlocks()-1)) {	// Blocks that formally exit the switch
	emit->tagLine();
	emitGotoStatement(bl2,(const FlowBlock *)0,FlowBlock::f_break_goto); // need an explicit break statement
      }
      emit->endBlock(id2);
    }
    emit->stopIndent(id);
  }
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  popMod();
}

/// \brief Create a generic function name base on the entry point address
///
/// \param addr is the entry point address of the function
/// \return the generated name
string PrintC::genericFunctionName(const Address &addr)

{
  ostringstream s;

  s << "func_";
  addr.printRaw(s);
  return s.str();
}

/// \brief Generate a generic name for an unnamed data-type
///
/// \param ct is the given data-type
/// \return the generated name
string PrintC::genericTypeName(const Datatype *ct)

{
  ostringstream s;
  switch(ct->getMetatype()) {
  case TYPE_INT:
    s << "unkint";
    break;
  case TYPE_UINT:
    s << "unkuint";
    break;
  case TYPE_UNKNOWN:
    s << "unkbyte";
    break;
  case TYPE_SPACEBASE:
    s << "BADSPACEBASE";
    return s.str();
  case TYPE_FLOAT:
    s << "unkfloat";
    break;
  default:
    s << "BADTYPE";
    return s.str();
  }
  s << dec << ct->getSize();
  return s.str();
}

} // End namespace ghidra

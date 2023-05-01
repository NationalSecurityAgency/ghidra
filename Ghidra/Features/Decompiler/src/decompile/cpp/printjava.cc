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
#include "printjava.hh"
#include "funcdata.hh"

namespace ghidra {

OpToken PrintJava::instanceof = { "instanceof", "", 2, 60, true, OpToken::binary, 1, 0, (OpToken *)0 };

// Constructing this registers the capability
PrintJavaCapability PrintJavaCapability::printJavaCapability;

PrintJavaCapability::PrintJavaCapability(void)

{
  name = "java-language";
  isdefault = false;
}

PrintLanguage *PrintJavaCapability::buildLanguage(Architecture *glb)

{
  return new PrintJava(glb,name);
}

PrintJava::PrintJava(Architecture *glb,const string &nm) : PrintC(glb,nm)

{
  resetDefaultsPrintJava();
  nullToken = "null";			// Java standard lower-case 'null'
  if (castStrategy != (CastStrategy *)0)
    delete castStrategy;

  castStrategy = new CastStrategyJava();
}

void PrintJava::resetDefaults(void)

{
  PrintC::resetDefaults();
  resetDefaultsPrintJava();
}

void PrintJava::docFunction(const Funcdata *fd)

{
  bool singletonFunction = false;
  if (curscope == (const Scope *)0) {
    singletonFunction = true;
    // Always assume we are in the scope of the parent class
    pushScope(fd->getScopeLocal()->getParent());
  }
  PrintC::docFunction(fd);
  if (singletonFunction)
    popScope();
}

/// Print a data-type up to the identifier, store off array sizes
/// for printing after the identifier. Find the root type (the one with an identifier)
/// and the count number of wrapping arrays.
/// \param ct is the given data-type
/// \param noident is \b true if no identifier will be pushed with this declaration
void PrintJava::pushTypeStart(const Datatype *ct,bool noident)

{
  int4 arrayCount = 0;
  for(;;) {
    if (ct->getMetatype() == TYPE_PTR) {
      if (isArrayType(ct))
	arrayCount += 1;
      ct = ((TypePointer *)ct)->getPtrTo();
    }
    else if (ct->getName().size() != 0)
      break;
    else {
      ct = glb->types->getTypeVoid();
      break;
    }
  }
  OpToken *tok;

  if (noident)
    tok = &type_expr_nospace;
  else
    tok = &type_expr_space;

  pushOp(tok,(const PcodeOp *)0);
  for(int4 i=0;i<arrayCount;++i)
    pushOp(&subscript,(const PcodeOp *)0);

  if (ct->getName().size()==0) {	// Check for anonymous type
    // We could support a struct or enum declaration here
    string nm = genericTypeName(ct);
    pushAtom(Atom(nm,typetoken,EmitMarkup::type_color,ct));
  }
  else {
    pushAtom(Atom(ct->getName(),typetoken,EmitMarkup::type_color,ct));
  }
  for(int4 i=0;i<arrayCount;++i)
    pushAtom(Atom(EMPTY_STRING,blanktoken,EmitMarkup::no_color));		// Fill in the blank array index
}

void PrintJava::pushTypeEnd(const Datatype *ct)

{ // This routine doesn't have to do anything
}

void PrintJava::adjustTypeOperators(void)

{
  scope.print1 = ".";
  shift_right.print1 = ">>>";
  TypeOp::selectJavaOperators(glb->inst,true);
}

/// References to java array objects where the underlying element is a java primitive look like:
///   - Pointer to int
///   - Pointer to bool
///   - Pointer to float
///
/// An array of java class objects is represented as a pointer to pointer data-type.
/// \param ct is the given data-type
/// \return \b true if the data-type references a java array object
bool PrintJava::isArrayType(const Datatype *ct)

{
  if (ct->getMetatype() != TYPE_PTR)	// Java arrays are always Ghidra pointer types
    return false;
  ct = ((TypePointer *)ct)->getPtrTo();
  switch(ct->getMetatype()) {
  case TYPE_UINT:     // Pointer to unsigned is placeholder for class reference, not an array
    if (ct->isCharPrint())
      return true;
    break;
  case TYPE_INT:
  case TYPE_BOOL:
  case TYPE_FLOAT:	// Pointer to primitive type is an array
  case TYPE_PTR:	// Pointer to class reference is an array
    return true;
  default:
    break;
  }
  return false;
}

void PrintJava::resetDefaultsPrintJava(void)

{
  option_NULL = true;			// Automatically use 'null' token
  option_convention = false;		// Automatically hide convention name
  mods |= hide_thisparam;		// turn on hiding of 'this' parameter
}

/// Assuming the given Varnode is a dereferenced pointer, determine whether
/// it needs to be represented using '[0]' syntax.
/// \param vn is the given Varnode
/// \return \b true if '[0]' syntax is required
bool PrintJava::needZeroArray(const Varnode *vn)

{
  if (!isArrayType(vn->getType()))
    return false;
  if (vn->isExplicit()) return true;
  if (!vn->isWritten()) return true;
  OpCode opc = vn->getDef()->code();
  if ((opc == CPUI_PTRADD)||(opc == CPUI_PTRSUB)||(opc == CPUI_CPOOLREF))
    return false;
  return true;
}

void PrintJava::printUnicode(ostream &s,int4 onechar) const

{
  if (unicodeNeedsEscape(onechar)) {
    switch(onechar) {		// Special escape characters
    case 0:
      s << "\\0";
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
    // Generic unicode escape
    if (onechar < 65536) {
      s << "\\ux" << setfill('0') << setw(4) << hex << onechar;
    }
    else
      s << "\\ux" << setfill('0') << setw(8) << hex << onechar;
    return;
  }
  StringManager::writeUtf8(s, onechar);		// Emit normally
}

void PrintJava::opLoad(const PcodeOp *op)

{
  uint4 m = mods | print_load_value;
  bool printArrayRef = needZeroArray(op->getIn(1));
  if (printArrayRef)
    pushOp(&subscript,op);
  pushVn(op->getIn(1),op,m);
  if (printArrayRef)
    push_integer(0,4,false,(Varnode *)0,op);
}

void PrintJava::opStore(const PcodeOp *op)

{
  uint4 m = mods | print_store_value;	// Inform sub-tree that we are storing
  pushOp(&assignment,op);	// This is an assignment
  if (needZeroArray(op->getIn(1))) {
    pushOp(&subscript,op);
    pushVn(op->getIn(1),op,m);
    push_integer(0,4,false,(Varnode *)0,op);
    pushVn(op->getIn(2),op,mods);
  }
  else {
    // implied vn's pushed on in reverse order for efficiency
    // see PrintLanguage::pushVnImplied
    pushVn(op->getIn(2),op,mods);
    pushVn(op->getIn(1),op,m);
  }
}

void PrintJava::opCallind(const PcodeOp *op)

{
  pushOp(&function_call,op);
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

void PrintJava::opCpoolRefOp(const PcodeOp *op)

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
	pushOp(&instanceof,op);
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
	  ct = ((TypePointer *)ct)->getPtrTo();
	  if (ct->getMetatype() == TYPE_CODE)
	  color = EmitMarkup::funcname_color;
	}
	if (vn0->isConstant()) {	// If this is NOT relative to an object reference
	  pushAtom(Atom(rec->getToken(),vartoken,color,op,outvn));
	}
	else {
	  pushOp(&object_member,op);
	  pushVn(vn0,op,mods);
	  pushAtom(Atom(rec->getToken(),syntax,color,op,outvn));
	}
      }
    }
  }
}

} // End namespace ghidra

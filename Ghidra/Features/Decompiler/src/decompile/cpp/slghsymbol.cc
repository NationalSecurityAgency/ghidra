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
#include "slghsymbol.hh"
#include "sleighbase.hh"
#include <cmath>

SleighSymbol *SymbolScope::addSymbol(SleighSymbol *a)

{
  pair<SymbolTree::iterator,bool> res;
  
  res = tree.insert( a );
  if (!res.second)
    return *res.first;		// Symbol already exists in this table
  return a;
}

SleighSymbol *SymbolScope::findSymbol(const string &nm) const

{
  SleighSymbol dummy(nm);
  SymbolTree::const_iterator iter;

  iter = tree.find( &dummy );
  if (iter != tree.end())
    return *iter;
  return (SleighSymbol *)0;
}

SymbolTable::~SymbolTable(void)

{
  vector<SymbolScope *>::iterator iter;
  for(iter=table.begin();iter!=table.end();++iter)
    delete *iter;
  vector<SleighSymbol *>::iterator siter;
  for(siter=symbollist.begin();siter!=symbollist.end();++siter)
    delete *siter;
}

void SymbolTable::addScope(void)

{
  curscope = new SymbolScope(curscope,table.size());
  table.push_back(curscope);
}

void SymbolTable::popScope(void)

{
  if (curscope != (SymbolScope *)0)
    curscope = curscope->getParent();
}

SymbolScope *SymbolTable::skipScope(int4 i) const

{
  SymbolScope *res = curscope;
  while(i>0) {
    if (res->parent == (SymbolScope *)0) return res;
    res = res->parent;
    --i;
  }
  return res;
}

void SymbolTable::addGlobalSymbol(SleighSymbol *a)

{
  a->id = symbollist.size();
  symbollist.push_back(a);
  SymbolScope *scope = getGlobalScope();
  a->scopeid = scope->getId();
  SleighSymbol *res = scope->addSymbol(a);
  if (res != a)
    throw SleighError("Duplicate symbol name '" + a->getName() + "'");
}

void SymbolTable::addSymbol(SleighSymbol *a)

{
  a->id = symbollist.size();
  symbollist.push_back(a);
  a->scopeid = curscope->getId();
  SleighSymbol *res = curscope->addSymbol(a);
  if (res != a)
    throw SleighError("Duplicate symbol name: "+a->getName());
}

SleighSymbol *SymbolTable::findSymbolInternal(SymbolScope *scope,const string &nm) const

{
  SleighSymbol *res;
  
  while(scope != (SymbolScope *)0) {
    res = scope->findSymbol(nm);
    if (res != (SleighSymbol *)0)
      return res;
    scope = scope->getParent();	// Try higher scope
  }
  return (SleighSymbol *)0;
}

void SymbolTable::replaceSymbol(SleighSymbol *a,SleighSymbol *b)

{				// Replace symbol a with symbol b
				// assuming a and b have the same name
  SleighSymbol *sym;
  int4 i = table.size()-1;
  
  while(i>=0) {			// Find the particular symbol
    sym = table[i]->findSymbol( a->getName() );
    if (sym == a) {
      table[i]->removeSymbol(a);
      b->id = a->id;
      b->scopeid = a->scopeid;
      symbollist[b->id] = b;
      table[i]->addSymbol(b);
      delete a;
      return;
    }
    --i;
  }
}

void SymbolTable::saveXml(ostream &s) const

{
  s << "<symbol_table";
  s << " scopesize=\"" << dec << table.size() << "\"";
  s << " symbolsize=\"" << symbollist.size() << "\">\n";
  for(int4 i=0;i<table.size();++i) {
    s << "<scope id=\"0x" << hex << table[i]->getId() << "\"";
    s << " parent=\"0x";
    if (table[i]->getParent() == (SymbolScope *)0)
      s << "0";
    else
      s << hex << table[i]->getParent()->getId();
    s << "\"/>\n";
  }

				// First save the headers
  for(int4 i=0;i<symbollist.size();++i)
    symbollist[i]->saveXmlHeader(s);

				// Now save the content of each symbol
  for(int4 i=0;i<symbollist.size();++i) // Must save IN ORDER
    symbollist[i]->saveXml(s);
  s << "</symbol_table>\n";
}

void SymbolTable::restoreXml(const Element *el,SleighBase *trans)

{
  {
    uint4 size;
    istringstream s(el->getAttributeValue("scopesize"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> size;
    table.resize(size,(SymbolScope *)0);
  }
  {
    uint4 size;
    istringstream s(el->getAttributeValue("symbolsize"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> size;
    symbollist.resize(size,(SleighSymbol *)0);
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  for(int4 i=0;i<table.size();++i) { // Restore the scopes
    Element *subel = *iter;
    if (subel->getName() != "scope")
      throw SleighError("Misnumbered symbol scopes");
    uintm id;
    uintm parent;
    {
      istringstream s(subel->getAttributeValue("id"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> id;
    }
    {
      istringstream s(subel->getAttributeValue("parent"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> parent;
    }
    SymbolScope *parscope = (parent==id) ? (SymbolScope *)0 : table[parent];
    table[id] = new SymbolScope( parscope, id );
    ++iter;
  }
  curscope = table[0];		// Current scope is global

				// Now restore the symbol shells
  for(int4 i=0;i<symbollist.size();++i) {
    restoreSymbolHeader(*iter);
    ++iter;
  }
				// Now restore the symbol content
  while(iter != list.end()) {
    Element *subel = *iter;
    uintm id;
    SleighSymbol *sym;
    {
      istringstream s(subel->getAttributeValue("id"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> id;
    }
    sym = findSymbol(id);
    sym->restoreXml(subel,trans);
    ++iter;
  }
}

void SymbolTable::restoreSymbolHeader(const Element *el)

{				// Put the shell of a symbol in the symbol table
				// in order to allow recursion
  SleighSymbol *sym;
  if (el->getName() == "userop_head")
    sym = new UserOpSymbol();
  else if (el->getName() == "epsilon_sym_head")
    sym = new EpsilonSymbol();
  else if (el->getName() == "value_sym_head")
    sym = new ValueSymbol();
  else if (el->getName() == "valuemap_sym_head")
    sym = new ValueMapSymbol();
  else if (el->getName() == "name_sym_head")
    sym = new NameSymbol();
  else if (el->getName() == "varnode_sym_head")
    sym = new VarnodeSymbol();
  else if (el->getName() == "context_sym_head")
    sym = new ContextSymbol();
  else if (el->getName() == "varlist_sym_head")
    sym = new VarnodeListSymbol();
  else if (el->getName() == "operand_sym_head")
    sym = new OperandSymbol();
  else if (el->getName() == "start_sym_head")
    sym = new StartSymbol();
  else if (el->getName() == "end_sym_head")
    sym = new EndSymbol();
  else if (el->getName() == "subtable_sym_head")
    sym = new SubtableSymbol();
  else if (el->getName() == "flowdest_sym_head")
    sym = new FlowDestSymbol();
  else if (el->getName() == "flowref_sym_head")
    sym = new FlowRefSymbol();
  else
    throw SleighError("Bad symbol xml");
  sym->restoreXmlHeader(el);	// Restore basic elements of symbol
  symbollist[sym->id] = sym;	// Put the basic symbol in the table
  table[sym->scopeid]->addSymbol(sym); // to allow recursion
}

void SymbolTable::purge(void)

{				// Get rid of unsavable symbols and scopes
  SleighSymbol *sym;
  for(int4 i=0;i<symbollist.size();++i) {
    sym = symbollist[i];
    if (sym == (SleighSymbol *)0) continue;
    if (sym->scopeid != 0) { // Not in global scope
      if (sym->getType() == SleighSymbol::operand_symbol) continue;
    }
    else {
      switch(sym->getType()) {
      case SleighSymbol::space_symbol:
      case SleighSymbol::token_symbol:
      case SleighSymbol::epsilon_symbol:
      case SleighSymbol::section_symbol:
	break;
      case SleighSymbol::macro_symbol:
	{			// Delete macro's local symbols
	  MacroSymbol *macro = (MacroSymbol *)sym;
	  for(int4 i=0;i<macro->getNumOperands();++i) {
	    SleighSymbol *opersym = macro->getOperand(i);
	    table[opersym->scopeid]->removeSymbol(opersym);
	    symbollist[opersym->id] = (SleighSymbol *)0;
	    delete opersym;
	  }
	  break;
	}
      case SleighSymbol::subtable_symbol:
	{			// Delete unused subtables
	  SubtableSymbol *subsym = (SubtableSymbol *)sym;
	  if (subsym->getPattern() != (TokenPattern *)0) continue;
	  for(int4 i=0;i<subsym->getNumConstructors();++i) { // Go thru each constructor
	    Constructor *con = subsym->getConstructor(i);
	    for(int4 j=0;j<con->getNumOperands();++j) { // Go thru each operand
	      OperandSymbol *oper = con->getOperand(j);
	      table[oper->scopeid]->removeSymbol(oper);
	      symbollist[oper->id] = (SleighSymbol *)0;
	      delete oper;
	    }
	  }
	  break;		// Remove the subtable symbol itself
	}
      default:
	continue;
      }
    }
    table[sym->scopeid]->removeSymbol(sym); // Remove the symbol
    symbollist[i] = (SleighSymbol *)0;
    delete sym;
  }
  for(int4 i=1;i<table.size();++i) { // Remove any empty scopes
    if (table[i]->tree.empty()) {
      delete table[i];
      table[i] = (SymbolScope *)0;
    }
  }
  renumber();
}

void SymbolTable::renumber(void)

{				// Renumber all the scopes and symbols
				// so that there are no gaps
  vector<SymbolScope *> newtable;
  vector<SleighSymbol *> newsymbol;
				// First renumber the scopes
  SymbolScope *scope;
  for(int4 i=0;i<table.size();++i) {
    scope = table[i];
    if (scope != (SymbolScope *)0) {
      scope->id = newtable.size();
      newtable.push_back(scope);
    }
  }
				// Now renumber the symbols
  SleighSymbol *sym;
  for(int4 i=0;i<symbollist.size();++i) {
    sym = symbollist[i];
    if (sym != (SleighSymbol *)0) {
      sym->scopeid = table[sym->scopeid]->id;
      sym->id = newsymbol.size();
      newsymbol.push_back(sym);
    }
  }
  table = newtable;
  symbollist = newsymbol;
}

void SleighSymbol::saveXmlHeader(ostream &s) const

{				// Save the basic attributes of a symbol
  s << " name=\"" << name << "\"";
  s << " id=\"0x" << hex << id << "\"";
  s << " scope=\"0x" << scopeid << "\"";
}

void SleighSymbol::restoreXmlHeader(const Element *el)

{
  name = el->getAttributeValue("name");
  {
    istringstream s(el->getAttributeValue("id"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> id;
  }
  {
    istringstream s(el->getAttributeValue("scope"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> scopeid;
  }
}

void UserOpSymbol::saveXml(ostream &s) const

{
  s << "<userop";
  SleighSymbol::saveXmlHeader(s);
  s << " index=\"" << dec << index << "\"";
  s << "/>\n";
}

void UserOpSymbol::saveXmlHeader(ostream &s) const

{
  s << "<userop_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void UserOpSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  istringstream s(el->getAttributeValue("index"));
  s.unsetf(ios::dec | ios::hex | ios::oct);
  s >> index;
}

PatternlessSymbol::PatternlessSymbol(void)

{				// The void constructor must explicitly build
				// the ConstantValue because it is not stored
				// or restored via xml
  patexp = new ConstantValue((intb)0);
  patexp->layClaim();
}

PatternlessSymbol::PatternlessSymbol(const string &nm)
  : SpecificSymbol(nm)
{
  patexp = new ConstantValue((intb)0);
  patexp->layClaim();
}

PatternlessSymbol::~PatternlessSymbol(void)

{
  PatternExpression::release(patexp);
}

void EpsilonSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  hand.space = const_space;
  hand.offset_space = (AddrSpace *)0; // Not a dynamic value
  hand.offset_offset = 0;
  hand.size = 0;		// Cannot provide size
}

void EpsilonSymbol::print(ostream &s,ParserWalker &walker) const

{
  s << '0';
}

VarnodeTpl *EpsilonSymbol::getVarnode(void) const

{
  VarnodeTpl *res = new VarnodeTpl(ConstTpl(const_space),
				     ConstTpl(ConstTpl::real,0),
				     ConstTpl(ConstTpl::real,0));
  return res;
}

void EpsilonSymbol::saveXml(ostream &s) const

{
  s << "<epsilon_sym";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void EpsilonSymbol::saveXmlHeader(ostream &s) const

{
  s << "<epsilon_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void EpsilonSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const_space = trans->getConstantSpace();
}

ValueSymbol::ValueSymbol(const string &nm,PatternValue *pv)
  : FamilySymbol(nm)
{
  (patval=pv)->layClaim();
}

ValueSymbol::~ValueSymbol(void)

{
  if (patval != (PatternValue *)0)
    PatternExpression::release(patval);
}

void ValueSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  hand.space = walker.getConstSpace();
  hand.offset_space = (AddrSpace *)0;
  hand.offset_offset = (uintb) patval->getValue(walker);
  hand.size = 0;		// Cannot provide size
}

void ValueSymbol::print(ostream &s,ParserWalker &walker) const

{
  intb val = patval->getValue(walker);
  if (val >= 0)
    s << "0x" << hex << val;
  else
    s << "-0x" << hex << -val;
}

void ValueSymbol::saveXml(ostream &s) const

{
  s << "<value_sym";
  SleighSymbol::saveXmlHeader(s);
  s << ">\n";
  patval->saveXml(s);
  s << "</value_sym>\n";
}

void ValueSymbol::saveXmlHeader(ostream &s) const

{
  s << "<value_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void ValueSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  patval = (PatternValue *) PatternExpression::restoreExpression(*iter,trans);
  patval->layClaim();
}

void ValueMapSymbol::checkTableFill(void)

{ // Check if all possible entries in the table have been filled
  intb min = patval->minValue();
  intb max = patval->maxValue();
  tableisfilled = (min>=0)&&(max<valuetable.size());
  for(uint4 i=0;i<valuetable.size();++i) {
    if (valuetable[i] == 0xBADBEEF)
      tableisfilled = false;
  }
}

Constructor *ValueMapSymbol::resolve(ParserWalker &walker)

{
  if (!tableisfilled) {
    intb ind = patval->getValue(walker);
    if ((ind >= valuetable.size())||(ind<0)||(valuetable[ind] == 0xBADBEEF)) {
      ostringstream s;
      s << walker.getAddr().getShortcut();
      walker.getAddr().printRaw(s);
      s << ": No corresponding entry in valuetable";
      throw BadDataError(s.str());
    }
  }
  return (Constructor *)0;
}

void ValueMapSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  uint4 ind = (uint4) patval->getValue(walker);
  // The resolve routine has checked that -ind- must be a valid index
  hand.space = walker.getConstSpace();
  hand.offset_space = (AddrSpace *)0; // Not a dynamic value
  hand.offset_offset = (uintb)valuetable[ind];
  hand.size = 0;		// Cannot provide size
}

void ValueMapSymbol::print(ostream &s,ParserWalker &walker) const

{
  uint4 ind = (uint4)patval->getValue(walker);
  // ind is already checked to be in range by the resolve routine
  intb val = valuetable[ind];
  if (val >= 0)
    s << "0x" << hex << val;
  else
    s << "-0x" << hex << -val;
}

void ValueMapSymbol::saveXml(ostream &s) const

{
  s << "<valuemap_sym";
  SleighSymbol::saveXmlHeader(s);
  s << ">\n";
  patval->saveXml(s);
  for(uint4 i=0;i<valuetable.size();++i)
    s << "<valuetab val=\"" << dec << valuetable[i] << "\"/>\n";
  s << "</valuemap_sym>\n";
}

void ValueMapSymbol::saveXmlHeader(ostream &s) const

{
  s << "<valuemap_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void ValueMapSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  patval = (PatternValue *) PatternExpression::restoreExpression(*iter,trans);
  patval->layClaim();
  ++iter;
  while(iter != list.end()) {
    istringstream s((*iter)->getAttributeValue("val"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    intb val;
    s >> val;
    valuetable.push_back(val);
    ++iter;
  }
  checkTableFill();
}

void NameSymbol::checkTableFill(void)

{ // Check if all possible entries in the table have been filled
  intb min = patval->minValue();
  intb max = patval->maxValue();
  tableisfilled = (min>=0)&&(max<nametable.size());
  for(uint4 i=0;i<nametable.size();++i) {
    if ((nametable[i] == "_")||(nametable[i] == "\t")) {
      nametable[i] = "\t";		// TAB indicates illegal index
      tableisfilled = false;
    }
  }
}

Constructor *NameSymbol::resolve(ParserWalker &walker)

{
  if (!tableisfilled) {
    intb ind = patval->getValue(walker);
    if ((ind >= nametable.size())||(ind<0)||((nametable[ind].size()==1)&&(nametable[ind][0]=='\t'))) {
      ostringstream s;
      s << walker.getAddr().getShortcut();
      walker.getAddr().printRaw(s);
      s << ": No corresponding entry in nametable";
      throw BadDataError(s.str());
    }
  }
  return (Constructor *)0;
}

void NameSymbol::print(ostream &s,ParserWalker &walker) const

{
  uint4 ind = (uint4)patval->getValue(walker);
  // ind is already checked to be in range by the resolve routine
  s << nametable[ind];
}

void NameSymbol::saveXml(ostream &s) const

{
  s << "<name_sym";
  SleighSymbol::saveXmlHeader(s);
  s << ">\n";
  patval->saveXml(s);
  for(int4 i=0;i<nametable.size();++i) {
    if (nametable[i] == "\t")		// TAB indicates an illegal index
      s << "<nametab/>\n";		// Emit tag with no name attribute
    else
      s << "<nametab name=\"" << nametable[i] << "\"/>\n";
  }
  s << "</name_sym>\n";
}

void NameSymbol::saveXmlHeader(ostream &s) const

{
  s << "<name_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void NameSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  patval = (PatternValue *) PatternExpression::restoreExpression(*iter,trans);
  patval->layClaim();
  ++iter;
  while(iter != list.end()) {
    const Element *subel = *iter;
    if (subel->getNumAttributes() >= 1)
      nametable.push_back(subel->getAttributeValue("name"));
    else
      nametable.push_back("\t");		// TAB indicates an illegal index
    ++iter;
  }
  checkTableFill();
}

VarnodeSymbol::VarnodeSymbol(const string &nm,AddrSpace *base,uintb offset,int4 size)
  : PatternlessSymbol(nm)
{
  fix.space = base;
  fix.offset = offset;
  fix.size = size;
  context_bits = false;
}

VarnodeTpl *VarnodeSymbol::getVarnode(void) const

{
  return new VarnodeTpl(ConstTpl(fix.space),ConstTpl(ConstTpl::real,fix.offset),ConstTpl(ConstTpl::real,fix.size));
}

void VarnodeSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  hand.space = fix.space;
  hand.offset_space = (AddrSpace *)0; // Not a dynamic symbol
  hand.offset_offset = fix.offset;
  hand.size = fix.size;
}

void VarnodeSymbol::collectLocalValues(vector<uintb> &results) const

{
  if (fix.space->getType() == IPTR_INTERNAL)
    results.push_back(fix.offset);
}

void VarnodeSymbol::saveXml(ostream &s) const

{
  s << "<varnode_sym";
  SleighSymbol::saveXmlHeader(s);
  s << " space=\"" << fix.space->getName() << "\"";
  s << " offset=\"0x" << hex << fix.offset << "\"";
  s << " size=\"" << dec << fix.size << "\"";
  s << ">\n";
  PatternlessSymbol::saveXml(s);
  s << "</varnode_sym>\n";
}

void VarnodeSymbol::saveXmlHeader(ostream &s) const

{
  s << "<varnode_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void VarnodeSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  fix.space = trans->getSpaceByName(el->getAttributeValue("space"));
  {
    istringstream s(el->getAttributeValue("offset"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> fix.offset;
  }
  {
    istringstream s(el->getAttributeValue("size"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> fix.size;
  }
				// PatternlessSymbol does not need restoring
}

ContextSymbol::ContextSymbol(const string &nm,ContextField *pate,VarnodeSymbol *v,
			     uint4 l,uint4 h,bool fl)
  : ValueSymbol(nm,pate)
{
  vn = v;
  low = l;
  high = h;
  flow = fl;
}

void ContextSymbol::saveXml(ostream &s) const

{
  s << "<context_sym";
  SleighSymbol::saveXmlHeader(s);
  s << " varnode=\"0x" << hex << vn->getId() << "\"";
  s << " low=\"" << dec << low << "\"";
  s << " high=\"" << high << "\"";
  a_v_b(s,"flow",flow);
  s << ">\n";
  patval->saveXml(s);
  s << "</context_sym>\n";
}

void ContextSymbol::saveXmlHeader(ostream &s) const

{
  s << "<context_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void ContextSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  ValueSymbol::restoreXml(el,trans);
  {
    uintm id;
    istringstream s(el->getAttributeValue("varnode"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> id;
    vn = (VarnodeSymbol *)trans->findSymbol(id);
  }
  {  
    istringstream s(el->getAttributeValue("low"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> low;
  }
  {  
    istringstream s(el->getAttributeValue("high"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> high;
  }
  flow = true;
  for(int4 i=el->getNumAttributes()-1;i>=0;--i) {
    if (el->getAttributeName(i)=="flow") {
      flow = xml_readbool(el->getAttributeValue(i));
      break;
    }
  }
}

VarnodeListSymbol::VarnodeListSymbol(const string &nm,PatternValue *pv,const vector<SleighSymbol *> &vt)
  : ValueSymbol(nm,pv)
{
  for(int4 i=0;i<vt.size();++i)
    varnode_table.push_back((VarnodeSymbol *)vt[i]);
  checkTableFill();
}

void VarnodeListSymbol::checkTableFill(void)

{
  intb min = patval->minValue();
  intb max = patval->maxValue();
  tableisfilled = (min>=0)&&(max<varnode_table.size());
  for(uint4 i=0;i<varnode_table.size();++i) {
    if (varnode_table[i] == (VarnodeSymbol *)0)
      tableisfilled = false;
  }
}

Constructor *VarnodeListSymbol::resolve(ParserWalker &walker)

{
  if (!tableisfilled) {
    intb ind = patval->getValue(walker);
    if ((ind<0)||(ind>=varnode_table.size())||(varnode_table[ind]==(VarnodeSymbol *)0)) {
      ostringstream s;
      s << walker.getAddr().getShortcut();
      walker.getAddr().printRaw(s);
      s << ": No corresponding entry in varnode list";
      throw BadDataError(s.str());
    }
  }
  return (Constructor *)0;
}

void VarnodeListSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  uint4 ind = (uint4) patval->getValue(walker);
  // The resolve routine has checked that -ind- must be a valid index
  const VarnodeData &fix( varnode_table[ind]->getFixedVarnode() );
  hand.space = fix.space;
  hand.offset_space = (AddrSpace *)0; // Not a dynamic value
  hand.offset_offset = fix.offset;
  hand.size = fix.size;
}

int4 VarnodeListSymbol::getSize(void) const

{
  for(int4 i=0;i<varnode_table.size();++i) {
    VarnodeSymbol *vnsym = varnode_table[i]; // Assume all are same size
    if (vnsym != (VarnodeSymbol *)0)
      return vnsym->getSize();
  }
  throw SleighError("No register attached to: "+getName());
}

void VarnodeListSymbol::print(ostream &s,ParserWalker &walker) const

{
  uint4 ind = (uint4)patval->getValue(walker);
  if (ind >= varnode_table.size())
    throw SleighError("Value out of range for varnode table");
  s << varnode_table[ind]->getName();
}

void VarnodeListSymbol::saveXml(ostream &s) const

{
  s << "<varlist_sym";
  SleighSymbol::saveXmlHeader(s);
  s << ">\n";
  patval->saveXml(s);
  for(int4 i=0;i<varnode_table.size();++i) {
    if (varnode_table[i] == (VarnodeSymbol *)0)
      s << "<null/>\n";
    else
      s << "<var id=\"0x" << hex << varnode_table[i]->getId() << "\"/>\n";
  }
  s << "</varlist_sym>\n";
}

void VarnodeListSymbol::saveXmlHeader(ostream &s) const

{
  s << "<varlist_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void VarnodeListSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  patval = (PatternValue *) PatternExpression::restoreExpression(*iter,trans);
  patval->layClaim();
  ++iter;
  while(iter!=list.end()) {
    const Element *subel = *iter;
    if (subel->getName() == "var") {
      uintm id;
      istringstream s(subel->getAttributeValue("id"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> id;
      varnode_table.push_back( (VarnodeSymbol *)trans->findSymbol(id) );
    }
    else
      varnode_table.push_back( (VarnodeSymbol *)0 );
    ++iter;
  }
  checkTableFill();
}

OperandSymbol::OperandSymbol(const string &nm,int4 index,Constructor *ct)
  : SpecificSymbol(nm)
{
  flags = 0;
  hand = index;
  localexp = new OperandValue(index,ct);
  localexp->layClaim();
  defexp = (PatternExpression *)0;
  triple = (TripleSymbol *)0;
}

void OperandSymbol::defineOperand(PatternExpression *pe)

{
  if ((defexp != (PatternExpression *)0)||(triple!=(TripleSymbol *)0))
    throw SleighError("Redefining operand");
  defexp = pe;
  defexp->layClaim();
}

void OperandSymbol::defineOperand(TripleSymbol *tri)

{
  if ((defexp != (PatternExpression *)0)||(triple!=(TripleSymbol *)0))
    throw SleighError("Redefining operand");
  triple = tri;
}

OperandSymbol::~OperandSymbol(void)

{
  PatternExpression::release(localexp);
  if (defexp != (PatternExpression *)0)
    PatternExpression::release(defexp);
}

VarnodeTpl *OperandSymbol::getVarnode(void) const

{
  VarnodeTpl *res;
  if (defexp != (PatternExpression *)0)
    res = new VarnodeTpl(hand,true); // Definite constant handle
  else {
    SpecificSymbol *specsym = dynamic_cast<SpecificSymbol *>(triple);
    if (specsym != (SpecificSymbol *)0)
      res = specsym->getVarnode();
    else if ((triple != (TripleSymbol *)0)&&
	     ((triple->getType() == valuemap_symbol)||(triple->getType() == name_symbol)))
      res = new VarnodeTpl(hand,true); // Zero-size symbols
    else
      res = new VarnodeTpl(hand,false); // Possible dynamic handle
  }
  return res;
}

void OperandSymbol::getFixedHandle(FixedHandle &hnd,ParserWalker &walker) const

{
  hnd = walker.getFixedHandle(hand);
}

int4 OperandSymbol::getSize(void) const

{
  if (triple != (TripleSymbol *)0)
    return triple->getSize();
  return 0;
}

void OperandSymbol::print(ostream &s,ParserWalker &walker) const

{
  walker.pushOperand(getIndex());
  if (triple != (TripleSymbol *)0) {
    if (triple->getType() == SleighSymbol::subtable_symbol)
      walker.getConstructor()->print(s,walker);
    else
      triple->print(s,walker);
  }
  else {
    intb val = defexp->getValue(walker);
    if (val >= 0)
      s << "0x" << hex << val;
    else
      s << "-0x" << hex << -val;
  }
  walker.popOperand();
}

void OperandSymbol::collectLocalValues(vector<uintb> &results) const

{
  if (triple != (TripleSymbol *)0)
    triple->collectLocalValues(results);
}

void OperandSymbol::saveXml(ostream &s) const

{
  s << "<operand_sym";
  SleighSymbol::saveXmlHeader(s);
  if (triple != (TripleSymbol *)0)
    s << " subsym=\"0x" << hex << triple->getId() << "\"";
  s << " off=\"" << dec << reloffset << "\"";
  s << " base=\"" << offsetbase << "\"";
  s << " minlen=\"" << minimumlength << "\"";
  if (isCodeAddress())
    s << " code=\"true\"";
  s << " index=\"" << dec << hand << "\">\n";
  localexp->saveXml(s);
  if (defexp != (PatternExpression *)0)
    defexp->saveXml(s);
  s << "</operand_sym>\n";
}

void OperandSymbol::saveXmlHeader(ostream &s) const

{
  s << "<operand_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void OperandSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  defexp = (PatternExpression *)0;
  triple = (TripleSymbol *)0;
  flags = 0;
  {
    istringstream s(el->getAttributeValue("index"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> hand;
  }
  {
    istringstream s(el->getAttributeValue("off"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> reloffset;
  }
  {
    istringstream s(el->getAttributeValue("base"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> offsetbase;
  }
  {
    istringstream s(el->getAttributeValue("minlen"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> minimumlength;
  }
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i) == "subsym") {
      uintm id;
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> id;
      triple = (TripleSymbol *)trans->findSymbol(id);
    }
    else if (el->getAttributeName(i) == "code") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= code_address;
    }
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  localexp = (OperandValue *)PatternExpression::restoreExpression(*iter,trans);
  localexp->layClaim();
  ++iter;
  if (iter != list.end()) {
    defexp = PatternExpression::restoreExpression(*iter,trans);
    defexp->layClaim();
  }
}

StartSymbol::StartSymbol(const string &nm,AddrSpace *cspc) : SpecificSymbol(nm)

{
  const_space = cspc;
  patexp = new StartInstructionValue();
  patexp->layClaim();
}

StartSymbol::~StartSymbol(void)

{
  if (patexp != (PatternExpression *)0)
    PatternExpression::release(patexp);
}

VarnodeTpl *StartSymbol::getVarnode(void) const

{ // Returns current instruction offset as a constant
  ConstTpl spc(const_space);
  ConstTpl off(ConstTpl::j_start);
  ConstTpl sz_zero;
  return new VarnodeTpl(spc,off,sz_zero);
}

void StartSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  hand.space = walker.getCurSpace();
  hand.offset_space = (AddrSpace *)0;
  hand.offset_offset = walker.getAddr().getOffset(); // Get starting address of instruction
  hand.size = hand.space->getAddrSize();
}

void StartSymbol::print(ostream &s,ParserWalker &walker) const

{
  intb val = (intb) walker.getAddr().getOffset();
  s << "0x" << hex << val;
}

void StartSymbol::saveXml(ostream &s) const

{
  s << "<start_sym";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void StartSymbol::saveXmlHeader(ostream &s) const

{
  s << "<start_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void StartSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const_space = trans->getConstantSpace();
  patexp = new StartInstructionValue();
  patexp->layClaim();
}

EndSymbol::EndSymbol(const string &nm,AddrSpace *cspc) : SpecificSymbol(nm)

{
  const_space = cspc;
  patexp = new EndInstructionValue();
  patexp->layClaim();
}

EndSymbol::~EndSymbol(void)

{
  if (patexp != (PatternExpression *)0)
    PatternExpression::release(patexp);
}

VarnodeTpl *EndSymbol::getVarnode(void) const

{ // Return next instruction offset as a constant
  ConstTpl spc(const_space);
  ConstTpl off(ConstTpl::j_next);
  ConstTpl sz_zero;
  return new VarnodeTpl(spc,off,sz_zero);
}

void EndSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  hand.space = walker.getCurSpace();
  hand.offset_space = (AddrSpace *)0;
  hand.offset_offset = walker.getNaddr().getOffset(); // Get starting address of next instruction
  hand.size = hand.space->getAddrSize();
}

void EndSymbol::print(ostream &s,ParserWalker &walker) const

{
  intb val = (intb) walker.getNaddr().getOffset();
  s << "0x" << hex << val;
}

void EndSymbol::saveXml(ostream &s) const

{
  s << "<end_sym";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void EndSymbol::saveXmlHeader(ostream &s) const

{
  s << "<end_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void EndSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const_space = trans->getConstantSpace();
  patexp = new EndInstructionValue();
  patexp->layClaim();
}

FlowDestSymbol::FlowDestSymbol(const string &nm,AddrSpace *cspc) : SpecificSymbol(nm)

{
  const_space = cspc;
}

VarnodeTpl *FlowDestSymbol::getVarnode(void) const

{
  ConstTpl spc(const_space);
  ConstTpl off(ConstTpl::j_flowdest);
  ConstTpl sz_zero;
  return new VarnodeTpl(spc,off,sz_zero);
}

void FlowDestSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  Address refAddr = walker.getDestAddr();
  hand.space = const_space;
  hand.offset_space = (AddrSpace *)0;
  hand.offset_offset = refAddr.getOffset();
  hand.size = refAddr.getAddrSize();
}

void FlowDestSymbol::print(ostream &s,ParserWalker &walker) const

{
  intb val = (intb) walker.getDestAddr().getOffset();
  s << "0x" << hex << val;
}

void FlowDestSymbol::saveXml(ostream &s) const

{
  s << "<flowdest_sym";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void FlowDestSymbol::saveXmlHeader(ostream &s) const

{
  s << "<flowdest_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void FlowDestSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const_space = trans->getConstantSpace();
}

FlowRefSymbol::FlowRefSymbol(const string &nm,AddrSpace *cspc) : SpecificSymbol(nm)

{
  const_space = cspc;
}

VarnodeTpl *FlowRefSymbol::getVarnode(void) const

{
  ConstTpl spc(const_space);
  ConstTpl off(ConstTpl::j_flowref);
  ConstTpl sz_zero;
  return new VarnodeTpl(spc,off,sz_zero);
}

void FlowRefSymbol::getFixedHandle(FixedHandle &hand,ParserWalker &walker) const

{
  Address refAddr = walker.getRefAddr();
  hand.space = const_space;
  hand.offset_space = (AddrSpace *)0;
  hand.offset_offset = refAddr.getOffset();
  hand.size = refAddr.getAddrSize();
}

void FlowRefSymbol::print(ostream &s,ParserWalker &walker) const

{
  intb val = (intb) walker.getRefAddr().getOffset();
  s << "0x" << hex << val;
}

void FlowRefSymbol::saveXml(ostream &s) const

{
  s << "<flowref_sym";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void FlowRefSymbol::saveXmlHeader(ostream &s) const

{
  s << "<flowref_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void FlowRefSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  const_space = trans->getConstantSpace();
}

Constructor::Constructor(void)

{
  pattern = (TokenPattern *)0;
  parent = (SubtableSymbol *)0;
  pateq = (PatternEquation *)0;
  templ = (ConstructTpl *)0;
  firstwhitespace = -1;
  flowthruindex = -1;
  inerror = false;
}

Constructor::Constructor(SubtableSymbol *p)

{
  pattern = (TokenPattern *)0;
  parent = p;
  pateq = (PatternEquation *)0;
  templ = (ConstructTpl *)0;
  firstwhitespace = -1;
  inerror = false;
}

Constructor::~Constructor(void)

{
  if (pattern != (TokenPattern *)0)
    delete pattern;
  if (pateq != (PatternEquation *)0)
    PatternEquation::release(pateq);
  if (templ != (ConstructTpl *)0)
    delete templ;
  for(int4 i=0;i<namedtempl.size();++i) {
    ConstructTpl *ntpl = namedtempl[i];
    if (ntpl != (ConstructTpl *)0)
      delete ntpl;
  }
  vector<ContextChange *>::iterator iter;
  for(iter=context.begin();iter!=context.end();++iter)
    delete *iter;
}

void Constructor::addInvisibleOperand(OperandSymbol *sym)

{
  operands.push_back(sym);
}

void Constructor::addOperand(OperandSymbol *sym)

{
  string operstring = "\n ";	// Indicater character for operand
  operstring[1] = ('A'+operands.size()); // Encode index of operand
  operands.push_back(sym);
  printpiece.push_back(operstring); // Placeholder for operand's string
}

void Constructor::addSyntax(const string &syn)

{
  string syntrim;

  if (syn.size() == 0) return;
  bool hasNonSpace = false;
  for(int4 i=0;i<syn.size();++i) {
    if (syn[i] != ' ') {
      hasNonSpace = true;
      break;
    }
  }
  if (hasNonSpace)
    syntrim = syn;
  else
    syntrim = " ";
  if ((firstwhitespace==-1)&&(syntrim == " "))
    firstwhitespace = printpiece.size();
  if (printpiece.empty())
    printpiece.push_back(syntrim);
  else if (printpiece.back() == " " && syntrim == " ") {
    // Don't add more whitespace
  }
  else if (printpiece.back()[0] == '\n' || printpiece.back() == " " || syntrim == " ")
    printpiece.push_back(syntrim);
  else {
    printpiece.back() += syntrim;
  }
}

void Constructor::addEquation(PatternEquation *pe)

{
  (pateq=pe)->layClaim();
}

void Constructor::setNamedSection(ConstructTpl *tpl,int4 id)

{				// Add a named section to the constructor
  while(namedtempl.size() <= id)
    namedtempl.push_back((ConstructTpl *)0);
  namedtempl[id] = tpl;
}

ConstructTpl *Constructor::getNamedTempl(int4 secnum) const

{
  if (secnum < namedtempl.size())
    return namedtempl[secnum];
  return (ConstructTpl *)0;
}

void Constructor::print(ostream &s,ParserWalker &walker) const

{
  vector<string>::const_iterator piter;

  for(piter=printpiece.begin();piter!=printpiece.end();++piter) {
    if ((*piter)[0] == '\n') {
      int4 index = (*piter)[1]-'A';
      operands[index]->print(s,walker);
    }
    else
      s << *piter;
  }
}

void Constructor::printMnemonic(ostream &s,ParserWalker &walker) const

{
  if (flowthruindex != -1) {
    SubtableSymbol *sym = dynamic_cast<SubtableSymbol *>(operands[flowthruindex]->getDefiningSymbol());
    if (sym != (SubtableSymbol *)0) {
      walker.pushOperand(flowthruindex);
      walker.getConstructor()->printMnemonic(s,walker);
      walker.popOperand();
      return;
    }
  }
  int4 endind = (firstwhitespace==-1) ? printpiece.size() : firstwhitespace;
  for(int4 i=0;i<endind;++i) {
    if (printpiece[i][0] == '\n') {
      int4 index = printpiece[i][1]-'A';
      operands[index]->print(s,walker);
    }
    else
      s << printpiece[i];
  }
}

void Constructor::printBody(ostream &s,ParserWalker &walker) const

{
  if (flowthruindex != -1) {
    SubtableSymbol *sym = dynamic_cast<SubtableSymbol *>(operands[flowthruindex]->getDefiningSymbol());
    if (sym != (SubtableSymbol *)0) {
      walker.pushOperand(flowthruindex);
      walker.getConstructor()->printBody(s,walker);
      walker.popOperand();
      return;
    }
  }
  if (firstwhitespace == -1) return; // Nothing to print after firstwhitespace
  for(int4 i=firstwhitespace+1;i<printpiece.size();++i) {
    if (printpiece[i][0]=='\n') {
      int4 index = printpiece[i][1]-'A';
      operands[index]->print(s,walker);
    }
    else
      s << printpiece[i];
  }
}

void Constructor::removeTrailingSpace(void)

{
  // Allow for user to force extra space at end of printing
  if ((!printpiece.empty())&&(printpiece.back()==" "))
    printpiece.pop_back();
  //  while((!printpiece.empty())&&(printpiece.back()==" "))
  //    printpiece.pop_back();
}

void Constructor::markSubtableOperands(vector<int4> &check) const

{ // Adjust -check- so it has one entry for every operand, a 0 if it is a subtable, a 2 if it is not
  check.resize(operands.size());
  for(int4 i=0;i<operands.size();++i) {
    TripleSymbol *sym = operands[i]->getDefiningSymbol();
    if ((sym != (TripleSymbol *)0)&&(sym->getType() == SleighSymbol::subtable_symbol))
      check[i] = 0;
    else
      check[i] = 2;
  }
}

void Constructor::collectLocalExports(vector<uintb> &results) const

{
  if (templ == (ConstructTpl *)0) return;
  HandleTpl *handle = templ->getResult();
  if (handle == (HandleTpl *)0) return;
  if (handle->getSpace().isConstSpace()) return;	// Even if the value is dynamic, the pointed to value won't get used
  if (handle->getPtrSpace().getType() != ConstTpl::real) {
    if (handle->getTempSpace().isUniqueSpace())
      results.push_back(handle->getTempOffset().getReal());
    return;
  }
  if (handle->getSpace().isUniqueSpace()) {
    results.push_back(handle->getPtrOffset().getReal());
    return;
  }
  if (handle->getSpace().getType() == ConstTpl::handle) {
    int4 handleIndex = handle->getSpace().getHandleIndex();
    OperandSymbol *opSym = getOperand(handleIndex);
    opSym->collectLocalValues(results);
  }
}

bool Constructor::isRecursive(void) const

{ // Does this constructor cause recursion with its table
  for(int4 i=0;i<operands.size();++i) {
    TripleSymbol *sym = operands[i]->getDefiningSymbol();
    if (sym == parent) return true;
  }
  return false;
}

void Constructor::saveXml(ostream &s) const

{
  s << "<constructor";
  s << " parent=\"0x" << hex << parent->getId() << "\"";
  s << " first=\"" << dec << firstwhitespace << "\"";
  s << " length=\"" << minimumlength << "\"";
  s << " line=\"" << src_index << ":" << lineno << "\">\n";
  for(int4 i=0;i<operands.size();++i)
    s << "<oper id=\"0x" << hex << operands[i]->getId() << "\"/>\n";
  for(int4 i=0;i<printpiece.size();++i) {
    if (printpiece[i][0]=='\n') {
      int4 index = printpiece[i][1]-'A';
      s << "<opprint id=\"" << dec << index << "\"/>\n";
    }
    else {
      s << "<print piece=\"";
      xml_escape(s, printpiece[i].c_str()); 
      s << "\"/>\n";
    }
  }
  for(int4 i=0;i<context.size();++i)
    context[i]->saveXml(s);
  if (templ != (ConstructTpl *)0)
    templ->saveXml(s,-1);
  for(int4 i=0;i<namedtempl.size();++i) {
    if (namedtempl[i] == (ConstructTpl *)0) // Some sections may be NULL
      continue;
    namedtempl[i]->saveXml(s,i);
  }
  s << "</constructor>\n";
}

void Constructor::restoreXml(const Element *el,SleighBase *trans)

{
  uintm id;
  {
    istringstream s(el->getAttributeValue("parent"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> id;
    parent = (SubtableSymbol *)trans->findSymbol(id);
  }
  {
    istringstream s(el->getAttributeValue("first"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> firstwhitespace;
  }
  {
    istringstream s(el->getAttributeValue("length"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> minimumlength;
  }
  {
   	string src_and_line = el->getAttributeValue("line");
    size_t pos = src_and_line.find(":");
    src_index = stoi(src_and_line.substr(0, pos),NULL,10);
    lineno = stoi(src_and_line.substr(pos+1,src_and_line.length()),NULL,10);
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  while(iter != list.end()) {
    if ((*iter)->getName() == "oper") {
      uintm id;
      {
	istringstream s((*iter)->getAttributeValue("id"));
	s.unsetf(ios::dec | ios::hex | ios::oct);
	s >> id;
      }
      OperandSymbol *sym = (OperandSymbol *)trans->findSymbol(id);
      operands.push_back(sym);
    }
    else if ((*iter)->getName() == "print")
      printpiece.push_back( (*iter)->getAttributeValue("piece"));
    else if ((*iter)->getName() == "opprint") {
      int4 index;
      istringstream s((*iter)->getAttributeValue("id"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> index;
      string operstring = "\n ";
      operstring[1] = ('A' + index);
      printpiece.push_back(operstring);
    }
    else if ((*iter)->getName() == "context_op") {
      ContextOp *c_op = new ContextOp();
      c_op->restoreXml(*iter,trans);
      context.push_back(c_op);
    }
    else if ((*iter)->getName() == "commit") {
      ContextCommit *c_op = new ContextCommit();
      c_op->restoreXml(*iter,trans);
      context.push_back(c_op);
    }
    else {
      ConstructTpl *cur = new ConstructTpl();
      int4 sectionid = cur->restoreXml(*iter,trans);
      if (sectionid < 0) {
	if (templ != (ConstructTpl *)0)
	  throw LowlevelError("Duplicate main section");
	templ = cur;
      }
      else {
	while(namedtempl.size() <= sectionid)
	  namedtempl.push_back((ConstructTpl *)0);
	if (namedtempl[sectionid] != (ConstructTpl *)0)
	  throw LowlevelError("Duplicate named section");
	namedtempl[sectionid] = cur;
      }
    }
    ++iter;
  }
  pattern = (TokenPattern *)0;
  if ((printpiece.size()==1)&&(printpiece[0][0]=='\n'))
    flowthruindex = printpiece[0][1] - 'A';
  else
    flowthruindex = -1;
}

void Constructor::orderOperands(void)

{
  OperandSymbol *sym;
  vector<OperandSymbol *> patternorder;
  vector<OperandSymbol *> newops; // New order of the operands
  int4 lastsize;

  pateq->operandOrder(this,patternorder);
  for(int4 i=0;i<operands.size();++i) { // Make sure patternorder contains all operands
    sym = operands[i];
    if (!sym->isMarked()) {
      patternorder.push_back(sym);
      sym->setMark();		// Make sure all operands are marked
    }
  }
  do {
    lastsize = newops.size();
    for(int4 i=0;i<patternorder.size();++i) {
      sym = patternorder[i];
      if (!sym->isMarked()) continue; // "unmarked" means it is already in newops
      if (sym->isOffsetIrrelevant()) continue; // expression Operands come last
      if ((sym->offsetbase == -1)||(!operands[sym->offsetbase]->isMarked())) {
	newops.push_back(sym);
	sym->clearMark();
      }
    }
  } while(newops.size() != lastsize);
  for(int4 i=0;i<patternorder.size();++i) { // Tack on expression Operands
    sym = patternorder[i];
    if (sym->isOffsetIrrelevant()) {
      newops.push_back(sym);
      sym->clearMark();
    }
  }

  if (newops.size() != operands.size())
    throw SleighError("Circular offset dependency between operands");


  for(int4 i=0;i<newops.size();++i) { // Fix up operand indices
    newops[i]->hand = i;
    newops[i]->localexp->changeIndex(i);
  }
  vector<int4> handmap;		// Create index translation map
  for(int4 i=0;i<operands.size();++i)
    handmap.push_back(operands[i]->hand);

				// Fix up offsetbase
  for(int4 i=0;i<newops.size();++i) {
    sym = newops[i];
    if (sym->offsetbase == -1) continue;
    sym->offsetbase = handmap[sym->offsetbase];
  }

  if (templ != (ConstructTpl *)0) // Fix up templates
    templ->changeHandleIndex(handmap);
  for(int4 i=0;i<namedtempl.size();++i) {
    ConstructTpl *ntempl = namedtempl[i];
    if (ntempl != (ConstructTpl *)0)
      ntempl->changeHandleIndex(handmap);
  }

				// Fix up printpiece operand refs
  for(int4 i=0;i<printpiece.size();++i) {
    if (printpiece[i][0] == '\n') {
      int4 index = printpiece[i][1]-'A';
      index = handmap[index];
      printpiece[i][1] = 'A'+index;
    }
  }
  operands = newops;
}

TokenPattern *Constructor::buildPattern(ostream &s)

{
  if (pattern != (TokenPattern *)0) return pattern; // Already built

  pattern = new TokenPattern();
  vector<TokenPattern> oppattern;
  bool recursion = false;
				// Generate pattern for each operand, store in oppattern
  for(int4 i=0;i<operands.size();++i) {
    OperandSymbol *sym = operands[i];
    TripleSymbol *triple = sym->getDefiningSymbol();
    PatternExpression *defexp = sym->getDefiningExpression();
    if (triple != (TripleSymbol *)0) {
      SubtableSymbol *subsym = dynamic_cast<SubtableSymbol *>(triple);
      if (subsym != (SubtableSymbol *)0) {
	if (subsym->isBeingBuilt()) { // Detected recursion
	  if (recursion) {
	    throw SleighError("Illegal recursion");
	  }
				// We should also check that recursion is rightmost extreme
	  recursion = true;
	  oppattern.emplace_back();
	}
	else
	  oppattern.push_back(*subsym->buildPattern(s));
      }
      else
	oppattern.push_back(triple->getPatternExpression()->genMinPattern(oppattern));
    }
    else if (defexp != (PatternExpression *)0)
      oppattern.push_back(defexp->genMinPattern(oppattern));
    else {
      throw SleighError(sym->getName()+": operand is undefined");
    }
    TokenPattern &sympat( oppattern.back() );
    sym->minimumlength = sympat.getMinimumLength();
    if (sympat.getLeftEllipsis() || sympat.getRightEllipsis())
      sym->setVariableLength();
  }

  if (pateq == (PatternEquation *)0)
    throw SleighError("Missing equation");

				// Build the entire pattern
  pateq->genPattern(oppattern);
  *pattern = pateq->getTokenPattern();
  if (pattern->alwaysFalse())
    throw SleighError("Impossible pattern");
  if (recursion)
    pattern->setRightEllipsis(true);
  minimumlength = pattern->getMinimumLength(); // Get length of the pattern in bytes

				// Resolve offsets of the operands
  OperandResolve resolve(operands);
  if (!pateq->resolveOperandLeft(resolve))
    throw SleighError("Unable to resolve operand offsets");

  for(int4 i=0;i<operands.size();++i) { // Unravel relative offsets to absolute (if possible)
    int4 base,offset;
    OperandSymbol *sym = operands[i];
    if (sym->isOffsetIrrelevant()) {
      sym->offsetbase = -1;
      sym->reloffset = 0;
      continue;
    }
    base = sym->offsetbase;
    offset = sym->reloffset;
    while(base >= 0) {
      sym = operands[base];
      if (sym->isVariableLength()) break; // Cannot resolve to absolute
      base = sym->offsetbase;
      offset += sym->getMinimumLength();
      offset += sym->reloffset;
      if (base < 0) {
	operands[i]->offsetbase = base;
	operands[i]->reloffset = offset;
      }
    }
  }

  // Make sure context expressions are valid
  for(int4 i=0;i<context.size();++i)
    context[i]->validate();

  orderOperands();		// Order the operands based on offset dependency
  return pattern;
}

void Constructor::printInfo(ostream &s) const

{				// Print identifying information about constructor
				// for use in error messages
  s << "table \"" << parent->getName();
  s << "\" constructor starting at line " << dec << lineno;
}

SubtableSymbol::SubtableSymbol(const string &nm) : TripleSymbol(nm)

{
  beingbuilt = false;
  pattern = (TokenPattern *)0;
  decisiontree = (DecisionNode *)0;
  errors = 0;
}

SubtableSymbol::~SubtableSymbol(void)

{
  if (pattern != (TokenPattern *)0)
    delete pattern;
  if (decisiontree != (DecisionNode *)0)
    delete decisiontree;
  vector<Constructor *>::iterator iter;
  for(iter=construct.begin();iter!=construct.end();++iter)
    delete *iter;
}

void SubtableSymbol::collectLocalValues(vector<uintb> &results) const

{
  for(int4 i=0;i<construct.size();++i)
    construct[i]->collectLocalExports(results);
}

void SubtableSymbol::saveXml(ostream &s) const

{
  if (decisiontree == (DecisionNode *)0) return; // Not fully formed
  s << "<subtable_sym";
  SleighSymbol::saveXmlHeader(s);
  s << " numct=\"" << dec << construct.size() << "\">\n";
  for(int4 i=0;i<construct.size();++i)
    construct[i]->saveXml(s);
  decisiontree->saveXml(s);
  s << "</subtable_sym>\n";
}

void SubtableSymbol::saveXmlHeader(ostream &s) const

{
  s << "<subtable_sym_head";
  SleighSymbol::saveXmlHeader(s);
  s << "/>\n";
}

void SubtableSymbol::restoreXml(const Element *el,SleighBase *trans)

{
  {
    int4 numct;
    istringstream s(el->getAttributeValue("numct"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> numct;
    construct.reserve(numct);
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  while(iter != list.end()) {
    if ((*iter)->getName() == "constructor") {
      Constructor *ct = new Constructor();
      addConstructor(ct);
      ct->restoreXml(*iter,trans);
    }
    else if ((*iter)->getName() == "decision") {
      decisiontree = new DecisionNode();
      decisiontree->restoreXml(*iter,(DecisionNode *)0,this);
    }
    ++iter;
  }
  pattern = (TokenPattern *)0;
  beingbuilt = false;
  errors = 0;
}

void SubtableSymbol::buildDecisionTree(DecisionProperties &props)

{				// Associate pattern disjoints to constructors
  if (pattern == (TokenPattern *)0) return; // Pattern not fully formed
  Pattern *pat;
  decisiontree = new DecisionNode((DecisionNode *)0);
  for(int4 i=0;i<construct.size();++i) {
    pat = construct[i]->getPattern()->getPattern();
    if (pat->numDisjoint() == 0)
      decisiontree->addConstructorPair((const DisjointPattern *)pat,construct[i]);
    else
      for(int4 j=0;j<pat->numDisjoint();++j)
	decisiontree->addConstructorPair(pat->getDisjoint(j),construct[i]);
  }
  decisiontree->split(props);	// Create the decision strategy
}

TokenPattern *SubtableSymbol::buildPattern(ostream &s)

{
  if (pattern != (TokenPattern *)0) return pattern; // Already built

  errors = false;
  beingbuilt = true;
  pattern = new TokenPattern();
  if (construct.empty()) {
    s << "Error: There are no constructors in table: "+getName() << endl;
    errors = true;
    return pattern;
  }
  try {
    construct.front()->buildPattern(s);
  } catch(SleighError &err) {
    s << "Error: " << err.explain << ": for ";
    construct.front()->printInfo(s);
    s << endl;
    errors = true;
  }
  *pattern = *construct.front()->getPattern();
  for(int4 i=1;i<construct.size();++i) {
    try {
      construct[i]->buildPattern(s);
    } catch(SleighError &err) {
      s << "Error: " << err.explain << ": for ";
      construct[i]->printInfo(s);
      s << endl;
      errors = true;
    }
    *pattern = construct[i]->getPattern()->commonSubPattern(*pattern);
  }
  beingbuilt = false;
  return pattern;
}

void DecisionProperties::identicalPattern(Constructor *a,Constructor *b)

{ // Note that -a- and -b- have identical patterns
  if ((!a->isError())&&(!b->isError())) {
    a->setError(true);
    b->setError(true);

    identerrors.push_back(make_pair(a, b));
  }
}

void DecisionProperties::conflictingPattern(Constructor *a,Constructor *b)

{ // Note that -a- and -b- have (potentially) conflicting patterns
  if ((!a->isError())&&(!b->isError())) {
    a->setError(true);
    b->setError(true);

    conflicterrors.push_back(make_pair(a, b));
  }
}

DecisionNode::DecisionNode(DecisionNode *p)

{
  parent = p;
  num = 0;
  startbit = 0;
  bitsize = 0;
  contextdecision = false;
}

DecisionNode::~DecisionNode(void)

{				// We own sub nodes
  vector<DecisionNode *>::iterator iter;
  for(iter=children.begin();iter!=children.end();++iter)
    delete *iter;
  vector<pair<DisjointPattern *,Constructor *> >::iterator piter;
  for(piter=list.begin();piter!=list.end();++piter)
    delete (*piter).first;	// Delete the patterns
}

void DecisionNode::addConstructorPair(const DisjointPattern *pat,Constructor *ct)

{
  DisjointPattern *clone = (DisjointPattern *)pat->simplifyClone(); // We need to own pattern
  list.push_back(pair<DisjointPattern *,Constructor *>(clone,ct));
  num += 1;
}

int4 DecisionNode::getMaximumLength(bool context)

{				// Get maximum length of instruction pattern in bytes
  int4 max = 0;
  int4 val,i;

  for(i=0;i<list.size();++i) {
    val = list[i].first->getLength(context);
    if (val > max)
      max = val;
  }
  return max;
}

int4 DecisionNode::getNumFixed(int4 low,int4 size,bool context)

{				// Get number of patterns that specify this field
  int4 count = 0;
  uintm mask;
				// Bits which must be specified in the mask
  uintm m = (size==8*sizeof(uintm)) ? 0 : (((uintm)1)<<size);
  m = m-1;

  for(int4 i=0;i<list.size();++i) {
    mask = list[i].first->getMask(low,size,context);
    if ((mask&m)==m)
      count += 1;
  }
  return count;
}

double DecisionNode::getScore(int4 low,int4 size,bool context)

{
  int4 numBins = 1 << size;		// size is between 1 and 8
  int4 i;
  uintm val,mask;
  uintm m = ((uintm)1)<<size;
  m = m-1;

  int4 total = 0;
  vector<int4> count(numBins,0);

  for(i=0;i<list.size();++i) {
    mask = list[i].first->getMask(low,size,context);
    if ((mask&m)!=m) continue;	// Skip if field not fully specified
    val = list[i].first->getValue(low,size,context);
    total += 1;
    count[val] += 1;
  }
  if (total <= 0) return -1.0;
  double sc = 0.0;
  for(i=0;i<numBins;++i) {
    if (count[i] <= 0) continue;
    if (count[i] >= list.size()) return -1.0;
    double p = ((double)count[i])/total;
    sc -= p * log(p);
  }
  return ( sc / log(2.0) );
}

void DecisionNode::chooseOptimalField(void)

{
  double score = 0.0;
  
  int4 sbit,size;		// The current field
  bool context;
  double sc;

  int4 maxlength,numfixed,maxfixed;

  maxfixed = 1;
  context = true;
  do {
    maxlength = 8*getMaximumLength(context);
    for(sbit=0;sbit<maxlength;++sbit) {
      numfixed = getNumFixed(sbit,1,context); // How may patterns specify this bit
      if (numfixed < maxfixed) continue; // Skip this bit, if we don't have maximum specification
      sc = getScore(sbit,1,context);

 // if we got more patterns this time than previously, and a positive score, reset
 // the high score (we prefer this bit, because it has a higher numfixed, regardless
 // of the difference in score, as long as the new score is positive).
      if ((numfixed > maxfixed)&&(sc > 0.0)) {
	score = sc;
	maxfixed = numfixed;
	startbit = sbit;
	bitsize = 1;
	contextdecision = context;
	continue;
      }
				// We have maximum patterns
      if (sc > score) {
	score = sc;
	startbit = sbit;
	bitsize = 1;
	contextdecision = context;
      }
    }
    context = !context;
  } while(!context);

  context = true;
  do {
    maxlength = 8*getMaximumLength(context);
    for(size=2;size <= 8;++size) {
      for(sbit=0;sbit<maxlength-size+1;++sbit) {
	if (getNumFixed(sbit,size,context) < maxfixed) continue; // Consider only maximal fields
	sc = getScore(sbit,size,context);
	if (sc > score) {
	  score = sc;
	  startbit = sbit;
	  bitsize = size;
	  contextdecision = context;
	}
      }
    }
    context = !context;
  } while(!context);
  if (score <= 0.0)		// If we failed to get a positive score
    bitsize = 0;		// treat the node as terminal
}

void DecisionNode::consistentValues(vector<uint4> &bins,DisjointPattern *pat)

{				// Produce all possible values of -pat- by
				// iterating through all possible values of the
				// "don't care" bits within the value of -pat-
				// that intersects with this node (startbit,bitsize,context)
  uintm m = (bitsize==8*sizeof(uintm)) ? 0 : (((uintm)1)<<bitsize);
  m = m-1;
  uintm commonMask = m & pat->getMask(startbit,bitsize,contextdecision);
  uintm commonValue = commonMask & pat->getValue(startbit,bitsize,contextdecision);
  uintm dontCareMask = m^commonMask;

  for(uintm i=0;i<=dontCareMask;++i) { // Iterate over values that contain all don't care bits
    if ((i&dontCareMask)!=i) continue; // If all 1 bits in the value are don't cares
    bins.push_back( commonValue | i ); // add 1 bits into full value and store
  }
}

void DecisionNode::split(DecisionProperties &props)

{
  if (list.size() <= 1) {
    bitsize = 0;		// Only one pattern, terminal node by default
    return;
  }

  chooseOptimalField();
  if (bitsize == 0) {
    orderPatterns(props);
    return;
  }
  if ((parent != (DecisionNode *)0) && (list.size() >= parent->num))
    throw LowlevelError("Child has as many Patterns as parent");

  int4 numChildren = 1 << bitsize;

  for(int4 i=0;i<numChildren;++i) {
    DecisionNode *nd = new DecisionNode( this );
    children.push_back( nd );
  }
  for(int4 i=0;i<list.size();++i) {
    vector<uint4> vals;		// Bins this pattern belongs in
				// If the pattern does not care about some
				// bits in the field we are splitting on, that
				// pattern will get put into multiple bins
    consistentValues(vals,list[i].first);
    for(int4 j=0;j<vals.size();++j)
      children[vals[j]]->addConstructorPair(list[i].first,list[i].second);
    delete list[i].first;	// We no longer need original pattern
  }
  list.clear();

  for(int4 i=0;i<numChildren;++i)
    children[i]->split(props);
}

void DecisionNode::orderPatterns(DecisionProperties &props)

{
  // This is a tricky routine.  When this routine is called, the patterns remaining in the
  // the decision node can no longer be distinguished by examining additional bits. The basic
  // idea here is that the patterns should be ordered so that the most specialized should come
  // first in the list. Pattern 1 is a specialization of pattern 2, if the set of instructions
  // matching 1 is contained in the set matching 2.  So in the simplest case, the pattern order
  // should represent a strict nesting.  Unfortunately, there are many potential situations where
  // patterns don't necessarily nest.
  //   1) An "or" of two patterns.  This can be an explicit '|' operator in the Constructor, in
  //      which case this can be detected because the two patterns point to the same constructor
  //      But the "or" can be implied across two constructors that do the same thing.  This should
  //      probably be flagged as an error except in the following case.
  //   2) Two patterns aren't properly nested, but they are "resolved" by a third pattern which
  //      covers the intersection of the first two patterns.  Sometimes its easier to specify
  //      three cases that need to be distinguished in this way.
  //   3) Recursive constructors that use a "guard" context bit.  The guard bit is used to prevent
  //      the recursive constructor from matching repeatedly, but it's too much work to put a
  //      constraint an the bit for every other pattern.
  //   4) Other situations where the ability to distinguish between constructors is hidden in
  //      the subconstructors.
  // This routine can determine if an intersection results from case 1) or case 2)
  int4 i,j,k;
  vector<pair<DisjointPattern *,Constructor *> > newlist;
  vector<pair<DisjointPattern *,Constructor *> > conflictlist;

  // Check for identical patterns
  for(i=0;i<list.size();++i) {
    for(j=0;j<i;++j) {
      DisjointPattern *ipat = list[i].first;
      DisjointPattern *jpat = list[j].first;
      if (ipat->identical(jpat))
	props.identicalPattern(list[i].second,list[j].second);
    }
  }

  newlist = list;
  for(i=0;i<list.size();++i) {
    for(j=0;j<i;++j) {
      DisjointPattern *ipat = newlist[i].first;
      DisjointPattern *jpat = list[j].first;
      if (ipat->specializes(jpat))
	break;
      if (!jpat->specializes(ipat)) { // We have a potential conflict
	Constructor *iconst = newlist[i].second;
	Constructor *jconst = list[j].second;
	if (iconst == jconst) { // This is an OR in the pattern for ONE constructor
	  // So there is no conflict
	}
	else {			// A true conflict that needs to be resolved
	  conflictlist.push_back(pair<DisjointPattern *,Constructor *>(ipat,iconst));
	  conflictlist.push_back(pair<DisjointPattern *,Constructor *>(jpat,jconst));
	}
      }
    }
    for(k=i-1;k>=j;--k)
      list[k+1] = list[k];
    list[j] = newlist[i];
  }
  
  // Check if intersection patterns are present, which resolve conflicts
  for(i=0;i<conflictlist.size();i+=2) {
    DisjointPattern *pat1,*pat2;
    Constructor *const1,*const2;
    pat1 = conflictlist[i].first;
    const1 = conflictlist[i].second;
    pat2 = conflictlist[i+1].first;
    const2 = conflictlist[i+1].second;
    bool resolved = false;
    for(j=0;j<list.size();++j) {
      DisjointPattern *tpat = list[j].first;
      Constructor *tconst = list[j].second;
      if ((tpat == pat1)&&(tconst==const1)) break; // Ran out of possible specializations
      if ((tpat == pat2)&&(tconst==const2)) break;
      if (tpat->resolvesIntersect(pat1,pat2)) {
	resolved = true;
	break;
      }
    }
    if (!resolved)
      props.conflictingPattern(const1,const2);
  }
}

Constructor *DecisionNode::resolve(ParserWalker &walker) const

{
  if (bitsize == 0) {		// The node is terminal
    vector<pair<DisjointPattern *,Constructor *> >::const_iterator iter;
    for(iter=list.begin();iter!=list.end();++iter)
      if ((*iter).first->isMatch(walker))
	return (*iter).second;
    ostringstream s;
    s << walker.getAddr().getShortcut();
    walker.getAddr().printRaw(s);
    s << ": Unable to resolve constructor";
    throw BadDataError(s.str());
  }
  uintm val;
  if (contextdecision)
    val = walker.getContextBits(startbit,bitsize);
  else
    val = walker.getInstructionBits(startbit,bitsize);
  return children[val]->resolve(walker);
}

void DecisionNode::saveXml(ostream &s) const

{
  s << "<decision";
  s << " number=\"" << dec << num << "\"";
  s << " context=\"";
  if (contextdecision)
    s << "true\"";
  else
    s << "false\"";
  s << " start=\"" << startbit << "\"";
  s << " size=\"" << bitsize << "\"";
  s << ">\n";
  for(int4 i=0;i<list.size();++i) {
    s << "<pair id=\"" << dec << list[i].second->getId() << "\">\n";
    list[i].first->saveXml(s);
    s << "</pair>\n";
  }
  for(int4 i=0;i<children.size();++i)
    children[i]->saveXml(s);
  s << "</decision>\n";
}

void DecisionNode::restoreXml(const Element *el,DecisionNode *par,SubtableSymbol *sub)

{
  parent = par;
  {
    istringstream s(el->getAttributeValue("number"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> num;
  }
  contextdecision = xml_readbool(el->getAttributeValue("context"));
  {
    istringstream s(el->getAttributeValue("start"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> startbit;
  }
  {
    istringstream s(el->getAttributeValue("size"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> bitsize;
  }
  const List &childlist(el->getChildren());
  List::const_iterator iter;
  iter = childlist.begin();
  while(iter != childlist.end()) {
    if ((*iter)->getName() == "pair") {
      Constructor *ct;
      DisjointPattern *pat;
      uintm id;
      istringstream s((*iter)->getAttributeValue("id"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> id;
      ct = sub->getConstructor(id);
      pat = DisjointPattern::restoreDisjoint((*iter)->getChildren().front());
      //This increments num      addConstructorPair(pat,ct);
      list.push_back(pair<DisjointPattern *,Constructor *>(pat,ct));
      //delete pat;		// addConstructorPair makes its own copy
    }
    else if ((*iter)->getName() == "decision") {
      DecisionNode *subnode = new DecisionNode();
      subnode->restoreXml(*iter,this,sub);
      children.push_back(subnode);
    }
    ++iter;
  }
}

static void calc_maskword(int4 sbit,int4 ebit,int4 &num,int4 &shift,uintm &mask)

{
  num = sbit/(8*sizeof(uintm));
  if ( num != ebit/(8*sizeof(uintm)))
    throw SleighError("Context field not contained within one machine int");
  sbit -= num*8*sizeof(uintm);
  ebit -= num*8*sizeof(uintm);

  shift = 8*sizeof(uintm)-ebit-1;
  mask = (~((uintm)0))>>(sbit+shift);
  mask <<= shift;
}

ContextOp::ContextOp(int4 startbit,int4 endbit,PatternExpression *pe)

{
  calc_maskword(startbit,endbit,num,shift,mask);
  patexp = pe;
  patexp->layClaim();
}

void ContextOp::apply(ParserWalkerChange &walker) const

{
  uintm val = patexp->getValue(walker); // Get our value based on context
  val <<= shift;
  walker.getParserContext()->setContextWord(num,val,mask);
}

void ContextOp::validate(void) const

{ // Throw an exception if the PatternExpression is not valid
  vector<const PatternValue *> values;

  patexp->listValues(values);	// Get all the expression tokens
  for(int4 i=0;i<values.size();++i) {
    const OperandValue *val = dynamic_cast<const OperandValue *>(values[i]);
    if (val == (const OperandValue *)0) continue;
    // Certain operands cannot be used in context expressions
    // because these are evaluated BEFORE the operand offset
    // has been recovered. If the offset is not relative to
    // the base constructor, then we throw an error
    if (!val->isConstructorRelative())
      throw SleighError(val->getName()+": cannot be used in context expression");
  }
}

void ContextOp::saveXml(ostream &s) const

{
  s << "<context_op";
  s << " i=\"" << dec << num << "\"";
  s << " shift=\"" << shift << "\"";
  s << " mask=\"0x" << hex << mask << "\" >\n";
  patexp->saveXml(s);
  s << "</context_op>\n";
}

void ContextOp::restoreXml(const Element *el,SleighBase *trans)

{
  {
    istringstream s(el->getAttributeValue("i"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> num;
  }
  {
    istringstream s(el->getAttributeValue("shift"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> shift;
  }
  {
    istringstream s(el->getAttributeValue("mask"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> mask;
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  patexp = (PatternValue *)PatternExpression::restoreExpression(*iter,trans);
  patexp->layClaim();
}

ContextChange *ContextOp::clone(void) const

{
  ContextOp *res = new ContextOp();
  (res->patexp = patexp)->layClaim();
  res->mask = mask;
  res->num = num;
  res->shift = shift;
  return res;
}

ContextCommit::ContextCommit(TripleSymbol *s,int4 sbit,int4 ebit,bool fl)

{
  sym = s;
  flow = fl;

  int4 shift;
  calc_maskword(sbit,ebit,num,shift,mask);
}

void ContextCommit::apply(ParserWalkerChange &walker) const

{
  walker.getParserContext()->addCommit(sym,num,mask,flow,walker.getPoint());
}

void ContextCommit::saveXml(ostream &s) const

{
  s << "<commit";
  a_v_u(s,"id",sym->getId());
  a_v_i(s,"num",num);
  a_v_u(s,"mask",mask);
  a_v_b(s,"flow",flow);
  s << "/>\n";
}

void ContextCommit::restoreXml(const Element *el,SleighBase *trans)

{
  uintm id;
  {
    istringstream s(el->getAttributeValue("id"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> id;
    sym = (TripleSymbol *)trans->findSymbol(id);
  }
  {
    istringstream s(el->getAttributeValue("num"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> num;
  }
  {
    istringstream s(el->getAttributeValue("mask"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> mask;
  }
  if (el->getNumAttributes()==4)
    flow = xml_readbool(el->getAttributeValue("flow"));
  else
    flow = true;		// Default is to flow.  flow=true
}

ContextChange *ContextCommit::clone(void) const

{
  ContextCommit *res = new ContextCommit();
  res->sym = sym;
  res->flow = flow;
  res->mask = mask;
  res->num = num;
  return res;
}

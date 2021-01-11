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
#include "variable.hh"
#include "op.hh"
#include "database.hh"

/// The new instance starts off with no associate Symbol and all properties marked as \e dirty.
/// \param vn is the single Varnode member
HighVariable::HighVariable(Varnode *vn)

{
  numMergeClasses = 1;
  highflags = flagsdirty | namerepdirty | typedirty | coverdirty;
  flags = 0;
  type = (Datatype *)0;
  symbol = (Symbol *)0;
  nameRepresentative = (Varnode *)0;
  symboloffset = -1;
  inst.push_back(vn);
  vn->setHigh( this, numMergeClasses-1 );
  if (vn->getSymbolEntry() != (SymbolEntry *)0)
    setSymbol(vn);
}

/// The given Varnode \b must be a member and \b must have a non-null SymbolEntry
void HighVariable::setSymbol(Varnode *vn) const

{
  SymbolEntry *entry = vn->getSymbolEntry();
  if (symbol != (Symbol *)0 && symbol != entry->getSymbol()) {
    if ((highflags & symboldirty)==0) {
      ostringstream s;
      s << "Symbols \"" << symbol->getName() << "\" and \"" << entry->getSymbol()->getName();
      s << "\" assigned to the same variable";
      throw LowlevelError(s.str());
    }
  }
  symbol = entry->getSymbol();
  if (entry->isDynamic())	// Dynamic symbols match whole variable
    symboloffset = -1;
  else if (symbol->getCategory() == 1)
    symboloffset = -1;			// For equates, we don't care about size
  else if (symbol->getType()->getSize() == vn->getSize() &&
      entry->getAddr() == vn->getAddr() && !entry->isPiece())
    symboloffset = -1;			// A matching entry
  else
    symboloffset = vn->getAddr().overlap(0,entry->getAddr(),symbol->getType()->getSize()) + entry->getOffset();

  highflags &= ~((uint4)symboldirty);		// We are no longer dirty
}

/// Link information to \b this from a Symbol that is not attached to a member Varnode.
/// This only works for a HighVariable with a constant member Varnode.  This used when there
/// is a constant address reference to the Symbol and the Varnode holds the reference, not
/// the actual value of the Symbol.
/// \param sym is the given Symbol to attach
/// \param off is the byte offset into the Symbol of the reference
void HighVariable::setSymbolReference(Symbol *sym,int4 off)

{
  symbol = sym;
  symboloffset = off;
  highflags &= ~((uint4)symboldirty);
}

/// Only update if the cover is marked as \e dirty.
/// Merge the covers of all Varnode instances.
/// This is \b only called by the Merge class which knows when to call it properly.
void HighVariable::updateCover(void) const

{
  if ((highflags & coverdirty)==0) return; // Cover info is upto date
  highflags &= ~coverdirty;

  wholecover.clear();
  if (!inst[0]->hasCover()) return;
  for(int4 i=0;i<inst.size();++i)
    wholecover.merge(*inst[i]->getCover());
}

/// Only update if flags are marked as \e dirty.
/// Generally if any member Varnode possesses the property, \b this HighVariable should
/// inherit it.  The Varnode::typelock field is not set here, but in updateType().
void HighVariable::updateFlags(void) const

{
  if ((highflags & flagsdirty)==0) return; // flags are up to date

  vector<Varnode *>::const_iterator iter;
  uint4 fl = 0;

  for(iter=inst.begin();iter!=inst.end();++iter)
    fl |= (*iter)->getFlags();

				// Keep these flags
  flags &= (Varnode::mark | Varnode::typelock);
				// Update all but these
  flags |= fl & ~(Varnode::mark | Varnode::directwrite | Varnode::typelock );
  highflags &= ~flagsdirty; // Clear the dirty flag
}

/// Find the member Varnode with the most \e specialized data-type, handling \e bool specially.
/// Boolean data-types are \e specialized in the data-type lattice, but not all byte values are boolean values.
/// Within the Varnode/PcodeOp tree, the \e bool data-type can only propagate to a Varnode if it is verified to
/// only take the boolean values 0 and 1. Since the data-type representative represents the type of all
/// instances, if any instance is not boolean, then the HighVariable cannot be boolean, even though \e bool
/// is more specialized. This method uses Datatype::typeOrderBool() to implement the special handling.
/// \return the representative member
Varnode *HighVariable::getTypeRepresentative(void) const

{
  vector<Varnode *>::const_iterator iter;
  Varnode *vn,*rep;
  
  iter = inst.begin();
  rep = *iter;
  ++iter;
  for(;iter!=inst.end();++iter) {
    vn = *iter;
    if (rep->isTypeLock() != vn->isTypeLock()) {
      if (vn->isTypeLock())
	rep = vn;
    }
    else if (0>vn->getType()->typeOrderBool(*rep->getType()))
      rep = vn;
  }
  return rep;
}

/// Only update if the data-type is marked as \e dirty.
/// Get the most locked, most specific data-type from member Varnode objects.
void HighVariable::updateType(void) const

{
  Varnode *vn;

  if ((highflags&typedirty)==0) return; // Type is up to date
  highflags &= ~typedirty; // Mark type as clean
  if ((highflags & type_finalized)!=0) return;	// Type has been finalized
  vn = getTypeRepresentative();

  type = vn->getType();
				// Update lock flags
  flags &= ~Varnode::typelock;
  if (vn->isTypeLock())
    flags |= Varnode::typelock;
}

void HighVariable::updateSymbol(void) const

{
  if ((highflags & symboldirty)==0) return; // flags are up to date
  highflags &= ~((uint4)symboldirty);
  vector<Varnode *>::const_iterator iter;
  symbol = (Symbol *)0;
  Varnode *vn = (Varnode *)0;

  for(iter=inst.begin();iter!=inst.end();++iter) {
    Varnode *tmpvn = *iter;
    if (tmpvn->getSymbolEntry() != (SymbolEntry *)0)
      vn = tmpvn;
  }
  if (vn != (Varnode *)0)
    setSymbol(vn);
}

/// Compare two Varnode objects based just on their storage address
/// \param a is the first Varnode to compare
/// \param b is the second Varnode
/// \return \b true if the first Varnode should be ordered before the second
bool HighVariable::compareJustLoc(const Varnode *a,const Varnode *b)

{
  return (a->getAddr() < b->getAddr());
}

/// Given two Varnode (members), sort them based on naming properties:
///  - A Varnode with an assigned name is preferred
///  - An \e unaffected Varnode is preferred
///  - A global Varnode is preferred
///  - An \e input Varnode is preferred
///  - An \e address \e tied Varnode is preferred
///  - A non-temporary Varnode is preferred
///  - A written Varnode is preferred
///  - An earlier Varnode is preferred
///
/// \return \b true if the second Varnode's name would override the first's
bool HighVariable::compareName(Varnode *vn1,Varnode *vn2)

{
  if (vn1->isNameLock()) return false; // Check for namelocks
  if (vn2->isNameLock()) return true;

  if (vn1->isUnaffected() != vn2->isUnaffected()) // Prefer unaffected
    return vn2->isUnaffected();
  if (vn1->isPersist() != vn2->isPersist()) // Prefer persistent
    return vn2->isPersist();
  if (vn1->isInput() != vn2->isInput())	// Prefer an input
    return vn2->isInput();
  if (vn1->isAddrTied() != vn2->isAddrTied()) // Prefer address tied
    return vn2->isAddrTied();

  // Prefer NOT internal
  if ((vn1->getSpace()->getType() != IPTR_INTERNAL)&&
      (vn2->getSpace()->getType() == IPTR_INTERNAL))
    return false;
  if ((vn1->getSpace()->getType() == IPTR_INTERNAL)&&
      (vn2->getSpace()->getType() != IPTR_INTERNAL))
    return true;
  if (vn1->isWritten() != vn2->isWritten()) // Prefer written
    return vn2->isWritten();
  if (!vn1->isWritten())
    return false;
  // Prefer earlier
  if (vn1->getDef()->getTime() != vn2->getDef()->getTime())
    return (vn2->getDef()->getTime() < vn1->getDef()->getTime());
  return false;
}

/// Members are scored based the properties that are most dominating in choosing a name.
/// \return the highest scoring Varnode member
Varnode *HighVariable::getNameRepresentative(void) const

{
  if ((highflags & namerepdirty)==0)
    return nameRepresentative;		// Name representative is up to date
  highflags &= ~namerepdirty;

  vector<Varnode *>::const_iterator iter;
  Varnode *vn;

  iter = inst.begin();
  nameRepresentative = *iter;
  ++iter;
  for(;iter!=inst.end();++iter) {
    vn = *iter;
    if (compareName(nameRepresentative,vn))
      nameRepresentative = vn;
  }
  return nameRepresentative;
}

/// Search for the given Varnode and cut it out of the list, marking all properties as \e dirty.
/// \param vn is the given Varnode member to remove
void HighVariable::remove(Varnode *vn)

{
  vector<Varnode *>::iterator iter;

  iter = lower_bound(inst.begin(),inst.end(),vn,compareJustLoc);
  for(;iter!=inst.end();++iter) {
    if (*iter == vn) {
      inst.erase(iter);
      highflags |= (flagsdirty|namerepdirty|coverdirty|typedirty);
      if (vn->getSymbolEntry() != (SymbolEntry *)0)
	highflags |= symboldirty;
      return;
    }
  }
}

/// Assuming there is a Symbol attached to \b this, run through the Varnode members
/// until we find one with a SymbolEntry corresponding to the Symbol and return it.
/// \return the SymbolEntry that mapped the Symbol to \b this or null if no Symbol is attached
SymbolEntry *HighVariable::getSymbolEntry(void) const

{
  for(int4 i=0;i<inst.size();++i) {
    SymbolEntry *entry = inst[i]->getSymbolEntry();
    if (entry != (SymbolEntry *)0 && entry->getSymbol() == symbol)
      return entry;
  }
  return (SymbolEntry *)0;
}

/// The data-type its dirtying mechanism is disabled.  The data-type will not change, unless
/// this method is called again.
/// \param tp is the data-type to set
void HighVariable::finalizeDatatype(Datatype *tp)

{
  type = tp;
  highflags |= type_finalized;
}

/// The lists of members are merged and the other HighVariable is deleted.
/// \param tv2 is the other HighVariable to merge into \b this
/// \param isspeculative is \b true to keep the new members in separate \e merge classes
void HighVariable::merge(HighVariable *tv2,bool isspeculative)

{
  int4 i;

  if (tv2 == this) return;

  highflags |= (flagsdirty|namerepdirty|typedirty);
  if (tv2->symbol != (Symbol *)0) {		// Check if we inherit a Symbol
    if ((tv2->highflags & symboldirty)==0) {
      symbol = tv2->symbol;			// Overwrite our Symbol (assume it is the same)
      symboloffset = tv2->symboloffset;
      highflags &= ~((uint4)symboldirty);	// Mark that we are not symbol dirty
    }
  }

  if (isspeculative) {
    for(i=0;i<tv2->inst.size();++i) {
      Varnode *vn = tv2->inst[i];
      vn->setHigh(this,vn->getMergeGroup() + numMergeClasses);
    }
    numMergeClasses += tv2->numMergeClasses;
  }
  else {
    if ((numMergeClasses!=1)||(tv2->numMergeClasses!=1))
      throw LowlevelError("Making a non-speculative merge after speculative merges have occurred");
    for(i=0;i<tv2->inst.size();++i) {
      Varnode *vn = tv2->inst[i];
      vn->setHigh(this,vn->getMergeGroup());
    }
  }
  vector<Varnode *> instcopy(inst);
  inst.resize(inst.size()+tv2->inst.size(),(Varnode *)0);
  std::merge(instcopy.begin(),instcopy.end(),tv2->inst.begin(),tv2->inst.end(),inst.begin(),compareJustLoc);
  tv2->inst.clear();

  if (((highflags&coverdirty)==0)&&((tv2->highflags&coverdirty)==0))
    wholecover.merge(tv2->wholecover);
  else
    highflags |= coverdirty;

  delete tv2;
}

/// All Varnode objects are assigned a HighVariable, including those that don't get names like
/// indirect variables, constants, and annotations.  Determine if \b this, as inherited from its
/// member Varnodes, can have a name.
/// \return \b true if \b this can have a name
bool HighVariable::hasName(void) const

{
  bool indirectonly = true;
  for(int4 i=0;i<inst.size();++i) {
    Varnode *vn = inst[i];
    if (!vn->hasCover()) {
      if (inst.size() > 1)
	throw LowlevelError("Non-coverable varnode has been merged");
      return false;
    }
    if (vn->isImplied()) {
      if (inst.size() > 1)
	throw LowlevelError("Implied varnode has been merged");
      return false;
    }
    if (!vn->isIndirectOnly())
      indirectonly = false;
  }
  if (isUnaffected()) {
    if (!isInput()) return false;
    if (indirectonly) return false;
    Varnode *vn = getInputVarnode();
    if (!vn->isIllegalInput()) { // A leftover unaff illegal input gets named
      if (vn->isSpacebase())	// A legal input, unaff, gets named
	return false;		// Unless it is the stackpointer
    }
  }
  return true;
}

/// This should only be called if isAddrTied() returns \b true. If there is no address tied
/// member, this will throw an exception.
/// \return the first address tied member
Varnode *HighVariable::getTiedVarnode(void) const

{
  int4 i;

  for(i=0;i<inst.size();++i)
    if (inst[i]->isAddrTied())
      return inst[i];

  throw LowlevelError("Could not find address-tied varnode");
}

/// This should only be called if isInput() returns \b true. If there is no input
/// member, this will throw an exception.
/// \return the input Varnode member
Varnode *HighVariable::getInputVarnode(void) const

{
  for(int4 i=0;i<inst.size();++i)
    if (inst[i]->isInput())
      return inst[i];
  throw LowlevelError("Could not find input varnode");
}

/// This is generally used for debug purposes.
/// \param s is the output stream
void HighVariable::printInfo(ostream &s) const

{
  vector<Varnode *>::const_iterator viter;
  Varnode *vn;

  updateType();
  if (symbol == (Symbol *)0) {
    s << "Variable: UNNAMED" << endl;
  }
  else {
    s << "Variable: " << symbol->getName();
    if (symboloffset!=-1)
      s << "(partial)";
    s << endl;
  }
  s << "Type: ";
  type->printRaw(s);
  s << "\n\n";
				
  for(viter=inst.begin();viter!=inst.end();++viter) {
    vn = *viter;
    s << dec << vn->getMergeGroup() << ": ";
    vn->printInfo(s);
  }
}

/// Find the index, for use with getInstance(), that will retrieve the given Varnode member
/// \param vn is the given Varnode member
/// \return the index of the member or -1 if it is not a member
int4 HighVariable::instanceIndex(const Varnode *vn) const

{
  int4 i;

  for(i=0;i<inst.size();++i)
    if (inst[i] == vn) return i;

  return -1;
}

/// \param s is the output stream to write XML to
void HighVariable::saveXml(ostream &s) const

{
  Varnode *vn = getNameRepresentative(); // Get representative varnode
  s << "<high ";
  //    a_v(s,"name",high->getName());
  a_v_u(s,"repref",vn->getCreateIndex());
  if (isSpacebase()||isImplied()) // This is a special variable
    a_v(s,"class",string("other"));
  else if (isPersist()&&isAddrTied()) // Global variable
    a_v(s,"class",string("global"));
  else if (isConstant())
    a_v(s,"class",string("constant"));
  else if (!isPersist() && (symbol != (Symbol *)0)) {
    if (symbol->getCategory() == 0)
      a_v(s,"class",string("param"));
    else
      a_v(s,"class",string("local"));
  }
  else {
    a_v(s,"class",string("other"));
  }
  if (isTypeLock())
    a_v_b(s,"typelock",true);
  if (symbol != (Symbol *)0) {
    a_v_u(s,"symref",symbol->getId());
    if (symboloffset >= 0)
      a_v_i(s, "offset", symboloffset);
  }
  s << '>';
  getType()->saveXml(s);
  for(int4 j=0;j<inst.size();++j) {
    s << "<addr ";
    a_v_u(s,"ref",inst[j]->getCreateIndex());
    s << "/>";
  }
  s << "</high>";
}

/// Given a Varnode at the root of an expression, we collect all the \e explicit HighVariables
/// involved in the expression.  This should only be run after \e explicit and \e implicit
/// properties have been computed on Varnodes.  The expression is traced back from the root
/// until explicit Varnodes are encountered; then their HighVariable is marked and added to the list.
/// The routine returns a value based on PcodeOps encountered in the expression:
///   - 1 for call instructions
///   - 2 for LOAD instructions
///   - 3 for both call and LOAD
///   - 0 for no calls or LOADS
///
/// \param vn is the given root Varnode of the expression
/// \param highList will hold the collected HighVariables
/// \return a value based on call and LOAD instructions in the expression
int4 HighVariable::markExpression(Varnode *vn,vector<HighVariable *> &highList)

{
  HighVariable *high = vn->getHigh();
  high->setMark();
  highList.push_back(high);
  int4 retVal = 0;
  if (!vn->isWritten()) return retVal;

  vector<PcodeOpNode> path;
  PcodeOp *op = vn->getDef();
  if (op->isCall())
    retVal |= 1;
  if (op->code() == CPUI_LOAD)
    retVal |= 2;
  path.push_back(PcodeOpNode(op,0));
  while(!path.empty()) {
    PcodeOpNode &node(path.back());
    if (node.op->numInput() <= node.slot) {
      path.pop_back();
      continue;
    }
    Varnode *vn = node.op->getIn(node.slot);
    node.slot += 1;
    if (vn->isAnnotation()) continue;
    if (vn->isExplicit()) {
      high = vn->getHigh();
      if (high->isMark()) continue;	// Already in the list
      high->setMark();
      highList.push_back(high);
      continue;				// Truncate at explicit
    }
    if (!vn->isWritten()) continue;
    op = vn->getDef();
    if (op->isCall())
      retVal |= 1;
    if (op->code() == CPUI_LOAD)
      retVal |= 2;
    path.push_back(PcodeOpNode(vn->getDef(),0));
  }
  return retVal;
}

#ifdef MERGEMULTI_DEBUG
/// \brief Check that there are no internal Cover intersections within \b this
///
/// Look for any pair of Varnodes whose covers intersect, but they are not
/// COPY shadows.  Throw an exception in this case.
void HighVariable::verifyCover(void) const

{
  Cover accumCover;

  for(int4 i=0;i<inst.size();++i) {
    Varnode *vn = inst[i];
    if (accumCover.intersect(*vn->getCover()) == 2) {
      for(int4 j=0;j<i;++j) {
	Varnode *otherVn = inst[j];
	if (otherVn->getCover()->intersect(*vn->getCover())==2) {
	  if (!otherVn->copyShadow(vn))
	    throw LowlevelError("HighVariable has internal intersection");
	}
      }
    }
    accumCover.merge(*vn->getCover());
  }
}
#endif

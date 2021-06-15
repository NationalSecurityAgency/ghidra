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
#include "varmap.hh"
#include "funcdata.hh"

/// \brief Can the given intersecting RangeHint coexist with \b this at their given offsets
///
/// Determine if the data-type information in the two ranges \e line \e up
/// properly, in which case the union of the two ranges can exist without
/// destroying data-type information.
/// \param b is the range to reconcile with \b this
/// \return \b true if the data-type information can be reconciled
bool RangeHint::reconcile(const RangeHint *b) const

{
  const RangeHint *a = this;
  if (a->type->getSize() < b->type->getSize()) {
    const RangeHint *tmp = b;
    b = a;			// Make sure b is smallest
    a = tmp;
  }
  intb mod = (b->sstart - a->sstart) % a->type->getSize();
  if (mod < 0)
    mod += a->type->getSize();

  Datatype *sub = a->type;
  uintb umod = mod;
  while((sub!=(Datatype *)0)&&(sub->getSize() > b->type->getSize()))
    sub = sub->getSubType(umod,&umod);

  if (sub == (Datatype *)0) return false;
  if (umod != 0) return false;
  if (sub->getSize() < b->type->getSize()) return false;
  return true;
}

/// \brief Return \b true if \b this or the given range contains the other.
///
/// We assume \b this range starts at least as early as the given range
/// and that the two ranges intersect.
/// \param b is the given range to check for containment with \b this
/// \return \b true if one contains the other
bool RangeHint::contain(const RangeHint *b) const

{
  if (sstart == b->sstart) return true;
  //  if (sstart==send) return true;
  //  if (b->sstart==b->send) return true;
  if (b->sstart+b->size-1 <= sstart+size-1) return true;
  return false;
}

/// \brief Return \b true if the \b this range's data-type is preferred over the other given range
///
/// A locked data-type is preferred over unlocked. A \e fixed size over \e open size.
/// Otherwise data-type ordering is used.
/// \param b is the other given range
/// \param reconcile is \b true is the two ranges have \e reconciled data-types
/// \return \b true if the \b this ranges's data-type is preferred
bool RangeHint::preferred(const RangeHint *b,bool reconcile) const

{
  if (start != b->start)
    return true;		// Something must occupy a->start to b->start
				// Prefer the locked type
  if ((b->flags & Varnode::typelock)!=0) {
    if ((flags & Varnode::typelock)==0)
      return false;
  }
  else if ((flags & Varnode::typelock)!=0)
    return true;

  if (!reconcile) {		// If the ranges don't reconcile
    if ((rangeType == RangeHint::open)&&(b->rangeType != RangeHint::open)) // Throw out the open range
      return false;
    if ((b->rangeType == RangeHint::open)&&(rangeType != RangeHint::open))
      return true;
  }

  return (0>type->typeOrder(*b->type)); // Prefer the more specific
}

/// If \b this RangeHint is an array and the following details line up, adjust \b this
/// so that it \e absorbs the other given RangeHint and return \b true.
/// The second RangeHint:
///   - must have the same element size
///   - must have close to the same data-type
///   - must line up with the step of the first array
///   - must not be a locked data-type
///   - must not extend the size of the first array beyond what is known of its limits
///
/// \param b is the other RangeHint to absorb
/// \return \b true if the other RangeHint was successfully absorbed
bool RangeHint::absorb(RangeHint *b)

{
  if (rangeType != RangeHint::open) return false;
  if (highind < 0) return false;
  if (b->rangeType == RangeHint::endpoint) return false;	// Don't merge with bounding range
  Datatype *settype = type;					// Assume we will keep this data-type
  if (settype->getSize() != b->type->getSize()) return false;
  if (settype != b->type) {
    Datatype *aTestType = type;
    Datatype *bTestType = b->type;
    while(aTestType->getMetatype() == TYPE_PTR) {
      if (bTestType->getMetatype() != TYPE_PTR)
	break;
      aTestType = ((TypePointer *)aTestType)->getPtrTo();
      bTestType = ((TypePointer *)bTestType)->getPtrTo();
    }
    if (aTestType->getMetatype() == TYPE_UNKNOWN)
      settype = b->type;
    else if (bTestType->getMetatype() == TYPE_UNKNOWN) {
    }
    else if (aTestType->getMetatype() == TYPE_INT && bTestType->getMetatype() == TYPE_UINT) {
    }
    else if (aTestType->getMetatype() == TYPE_UINT && bTestType->getMetatype() == TYPE_INT) {
    }
    else if (aTestType != bTestType)	// If they are both not unknown, they must be the same
      return false;
  }
  if ((flags & Varnode::typelock)!=0) return false;
  if ((b->flags & Varnode::typelock)!=0) return false;
  if (flags != b->flags) return false;
  intb diffsz = b->sstart - sstart;
  if ((diffsz % settype->getSize()) != 0) return false;
  diffsz /= settype->getSize();
  if (diffsz > highind) return false;
  type = settype;
  if (b->rangeType == RangeHint::open && (0 <= b->highind)) { // If b has array indexing
    int4 trialhi = b->highind + diffsz;
    if (highind < trialhi)
      highind = trialhi;
  }
  return true;
}

/// Given that \b this and the other RangeHint intersect, redefine \b this so that it
/// becomes the union of the two original ranges.  The union must succeed in some form.
/// An attempt is made to preserve the data-type information of both the original ranges,
/// but changes will be made if necessary.  An exception is thrown if the data-types
/// are locked and cannot be reconciled.
/// \param b is the other RangeHint to merge with \b this
/// \param space is the address space holding the ranges
/// \param typeFactory is a factory for producing data-types
/// \return \b true if there was an overlap that could be reconciled
bool RangeHint::merge(RangeHint *b,AddrSpace *space,TypeFactory *typeFactory)

{
  uintb aend,bend;
  uintb end;
  Datatype *resType;
  uint4 resFlags;
  bool didReconcile;
  int4 resHighIndex;
  bool overlapProblems = false;

  aend = space->wrapOffset(start+size);
  bend = space->wrapOffset(b->start+b->size);
  RangeHint::RangeType resRangeType = RangeHint::fixed;
  resHighIndex = -1;
  if ((aend==0)||(bend==0))
    end = 0;
  else
    end = (aend > bend) ? aend : bend;

  if (contain(b)) {			// Does one range contain the other
    didReconcile = reconcile(b);	// Can the data-type layout be reconciled
    if (preferred(b,didReconcile)) { 	// If a's data-type is preferred over b
      resType = type;
      resFlags = flags;
      resRangeType = rangeType;
      resHighIndex = highind;
    }
    else {
      resType = b->type;
      resFlags = b->flags;
      resRangeType = b->rangeType;
      resHighIndex = b->highind;
    }
    if ((start==b->start)&&(size==b->size)) {
      resRangeType = (rangeType==RangeHint::open || b->rangeType==RangeHint::open) ? RangeHint::open : RangeHint::fixed;
      if (resRangeType == RangeHint::open)
	resHighIndex = (highind < b->highind) ? b->highind : highind;
    }
    if (!didReconcile) { // See if two types match up
      if ((b->rangeType != RangeHint::open)&&(rangeType != RangeHint::open))
	overlapProblems = true;
    }
  }
  else {
    didReconcile = false;
    resType = (Datatype *)0;	// Unable to resolve the type
    resFlags = 0;
  }
				// Check for really problematic cases
  if (!didReconcile) {
    if ((b->flags & Varnode::typelock)!=0) {
      if ((flags & Varnode::typelock)!=0)
	throw LowlevelError("Overlapping forced variable types : " + type->getName() + "   " + b->type->getName());
    }
  }
  if (resType == (Datatype *)0) // If all else fails
    resType = typeFactory->getBase(1,TYPE_UNKNOWN); // Do unknown array (size 1)

  type = resType;
  flags = resFlags;
  rangeType = resRangeType;
  highind = resHighIndex;
  if ((!didReconcile)&&(start != b->start)) { // Truncation is forced
    if ((flags & Varnode::typelock)!=0) { // If a is locked
      return overlapProblems;		// Discard b entirely in favor of a
    }
    // Concede confusion about types, set unknown type rather than a or b's type
    rangeType = RangeHint::fixed;
    size = space->wrapOffset(end-start);
    if (size != 1 && size != 2 && size != 4 && size != 8) {
      size = 1;
      rangeType = RangeHint::open;
    }
    type = typeFactory->getBase(size,TYPE_UNKNOWN);
    flags = 0;
    highind = -1;
    return overlapProblems;
  }
  size = resType->getSize();
  return overlapProblems;
}

/// Compare (signed) offset, size, RangeType, type lock, and high index, in that order.
/// Datatype is \e not compared.
/// \param op2 is the other RangeHint to compare with \b this
/// \return -1, 0, or 1 depending on if \b this comes before, is equal to, or comes after
int4 RangeHint::compare(const RangeHint &op2) const

{
  if (sstart != op2.sstart)
    return (sstart < op2.sstart) ? -1 : 1;
  if (size != op2.size)
    return (size < op2.size) ? -1 : 1;		// Small sizes come first
  if (rangeType != op2.rangeType)
    return (rangeType < op2.rangeType) ? -1 : 1;
  uint4 thisLock = flags & Varnode::typelock;
  uint4 op2Lock = op2.flags & Varnode::typelock;
  if (thisLock != op2Lock)
    return (thisLock < op2Lock) ? -1 : 1;
  if (highind != op2.highind)
    return (highind < op2.highind) ? -1 : 1;
  return 0;
}

/// \param id is the globally unique id associated with the function scope
/// \param spc is the (stack) address space associated with this function's local variables
/// \param fd is the function associated with these local variables
/// \param g is the Architecture
ScopeLocal::ScopeLocal(uint8 id,AddrSpace *spc,Funcdata *fd,Architecture *g) : ScopeInternal(id,fd->getName(),g)

{
  space = spc;
  rangeLocked = false;
  stackGrowsNegative = true;
  restrictScope(fd);
} 

/// Turn any symbols that are \e name \e locked but not \e type \e locked into name recommendations
/// removing the symbol in the process.  This allows the decompiler to decide on how the stack is layed
/// out without forcing specific variables to mapped. But, if the decompiler does create a variable at
/// the specific location, it will use the original name.
void ScopeLocal::collectNameRecs(void)

{
  nameRecommend.clear();	// Clear out any old name recommendations
  dynRecommend.clear();

  SymbolNameTree::iterator iter = nametree.begin();
  while(iter!=nametree.end()) {
    Symbol *sym = *iter++;
    if (sym->isNameLocked()&&(!sym->isTypeLocked())) {
      if (sym->isThisPointer()) {		// If there is a "this" pointer
	Datatype *dt = sym->getType();
	if (dt->getMetatype() == TYPE_PTR) {
	  if (((TypePointer *)dt)->getPtrTo()->getMetatype() == TYPE_STRUCT) {
	    // If the "this" pointer points to a class, try to preserve the data-type
	    // even though the symbol is not preserved.
	    SymbolEntry *entry = sym->getFirstWholeMap();
	    typeRecommend.push_back(TypeRecommend(entry->getAddr(),dt));
	  }
	}
      }
      addRecommendName(sym);	// This deletes the symbol
    }
  }
}

/// This resets the discovery process for new local variables mapped to the scope's address space.
/// Any analysis removing specific ranges from the mapped set (via markNotMapped()) is cleared.
void ScopeLocal::resetLocalWindow(void)

{
  if (rangeLocked) return;

  localRange = fd->getFuncProto().getLocalRange();
  const RangeList &paramrange( fd->getFuncProto().getParamRange() );

  stackGrowsNegative = fd->getFuncProto().isStackGrowsNegative();
  RangeList newrange;

  set<Range>::const_iterator iter;
  for(iter=localRange.begin();iter!=localRange.end();++iter) {
    AddrSpace *spc = (*iter).getSpace();
    uintb first = (*iter).getFirst();
    uintb last = (*iter).getLast();
    newrange.insertRange(spc,first,last);
  }
  for(iter=paramrange.begin();iter!=paramrange.end();++iter) {
    AddrSpace *spc = (*iter).getSpace();
    uintb first = (*iter).getFirst();
    uintb last = (*iter).getLast();
    newrange.insertRange(spc,first,last);
  }
  glb->symboltab->setRange(this,newrange);
}

void ScopeLocal::saveXml(ostream &s) const

{
  s << "<localdb";
  a_v(s,"main",space->getName());
  a_v_b(s,"lock",rangeLocked);
  s << ">\n";
  ScopeInternal::saveXml(s);
  s << "</localdb>\n";
}

void ScopeLocal::restoreXml(const Element *el)

{
  rangeLocked = false;
  if (xml_readbool(el->getAttributeValue("lock")))
    rangeLocked = true;
  space = glb->getSpaceByName(el->getAttributeValue("main"));
  
  ScopeInternal::restoreXml( *(el->getChildren().begin()) );
  collectNameRecs();
}

/// The given range can no longer hold a \e mapped local variable. This indicates the range
/// is being used for temporary storage.
/// \param spc is the address space holding the given range
/// \param first is the starting offset of the given range
/// \param sz is the number of bytes in the range
/// \param parameter is \b true if the range is being used to store a sub-function parameter
void ScopeLocal::markNotMapped(AddrSpace *spc,uintb first,int4 sz,bool parameter)

{
  if (space != spc) return;
  uintb last = first + sz - 1;
  // Do not allow the range to cover the split point between "negative" and "positive" stack offsets
  if (last < first)		// Check for possible wrap around
    last = spc->getHighest();
  else if (last > spc->getHighest())
    last = spc->getHighest();
  if (parameter) {		// Everything above parameter
    if (stackGrowsNegative) {
      const Range *rng = localRange.getRange(spc,first);
      if (rng != (const Range *)0)
	first = rng->getFirst(); // Everything less is not mapped
    }
    else {
      const Range *rng = localRange.getRange(spc,last);
      if (rng != (const Range *)0)
	last = rng->getLast();	// Everything greater is not mapped
    }
    sz = (last-first)+1;
  }
  Address addr(space,first);
				// Remove any symbols under range
  SymbolEntry *overlap = findOverlap(addr,sz);
  while(overlap != (SymbolEntry *)0) { // For every overlapping entry
    Symbol *sym = overlap->getSymbol();
    if ((sym->getFlags()&Varnode::typelock)!=0) {
      // If the symbol and the use are both as parameters
      // this is likely the special case of a shared return call sharing the parameter location
      // of the original function in which case we don't print a warning
      if ((!parameter) || (sym->getCategory() != 0))
	fd->warningHeader("Variable defined which should be unmapped: "+sym->getName());
      return;
    }
    removeSymbol(sym);
    overlap = findOverlap(addr,sz);
  }
  glb->symboltab->removeRange(this,space,first,last);
}

string ScopeLocal::buildVariableName(const Address &addr,
				     const Address &pc,
				     Datatype *ct,
				     int4 &index,uint4 flags) const
{
  if (((flags & (Varnode::addrtied|Varnode::persist))==Varnode::addrtied) &&
      addr.getSpace() == space) {
    if (fd->getFuncProto().getLocalRange().inRange(addr,1)) {
      intb start = (intb) AddrSpace::byteToAddress(addr.getOffset(),space->getWordSize());
      sign_extend(start,addr.getAddrSize()*8-1);
      if (stackGrowsNegative)
	start = -start;
      ostringstream s;
      if (ct != (Datatype *)0)
	ct->printNameBase(s);
      string spacename = addr.getSpace()->getName();
      spacename[0] = toupper(spacename[0]);
      s << spacename;
      if (start <= 0) {
	s << 'X';		// Indicate local stack space allocated by caller
	start = -start;
      }
      s << dec << start;
      return makeNameUnique(s.str());
    }
  }
  return ScopeInternal::buildVariableName(addr,pc,ct,index,flags);
}

/// Shrink the RangeHint as necessary so that it fits in the mapped region of the Scope
/// and doesn't overlap any other Symbols.  If this is not possible, return \b false.
/// \param a is the given RangeHint to fit
/// \return \b true if a valid adjustment was made
bool ScopeLocal::adjustFit(RangeHint &a) const

{
  if (a.size==0) return false;	// Nothing to fit
  if ((a.flags & Varnode::typelock)!=0) return false; // Already entered
  Address addr(space,a.start);
  uintb maxsize = getRangeTree().longestFit(addr,a.size);
  if (maxsize==0) return false;
  if (maxsize < a.size) {	// Suggested range doesn't fit
    if (maxsize < a.type->getSize()) return false; // Can't shrink that match
    a.size = (int4)maxsize;
  }
  // We want ANY symbol that might be within this range
  SymbolEntry *entry = findOverlap(addr,a.size);
  if (entry == (SymbolEntry *)0)
    return true;
  if (entry->getAddr() <= addr) {
    // < generally shouldn't be possible
    // == we might want to check for anything in -a- after -entry-
    return false;
  }
  maxsize = entry->getAddr().getOffset() - a.start;
  if (maxsize < a.type->getSize()) return false;	// Can't shrink for this type
  a.size = maxsize;
  return true;
}

/// A name and final data-type is constructed for the RangeHint, and they are entered as
/// a new Symbol into \b this scope.
/// \param a is the given RangeHint to create a Symbol for
void ScopeLocal::createEntry(const RangeHint &a)

{
  Address addr(space,a.start);
  Address usepoint;
  Datatype *ct = glb->types->concretize(a.type);
  int4 num = a.size/ct->getSize();
  if (num>1)
    ct = glb->types->getTypeArray(num,ct);

  addSymbol("",ct,addr,usepoint);
}

/// Set up basic offset boundaries for what constitutes a local variable
/// or a parameter on the stack. This can be informed by the ProtoModel if available.
/// \param proto is the function prototype to use as a prototype model
void AliasChecker::deriveBoundaries(const FuncProto &proto)

{
  localExtreme = ~((uintb)0);			// Default settings
  localBoundary = 0x1000000;
  if (direction == -1)
    localExtreme = localBoundary;

  if (proto.hasModel()) {
    const RangeList &localrange( proto.getLocalRange() );
    const RangeList &paramrange( proto.getParamRange() );

    const Range *local = localrange.getFirstRange();
    const Range *param = paramrange.getLastRange();
    if ((local != (const Range *)0)&&(param != (const Range *)0)) {
      localBoundary = param->getLast();
      if (direction == -1) {
	localBoundary = paramrange.getFirstRange()->getFirst();
	localExtreme = localBoundary;
      }
    }
  }
}

/// If there is an AddrSpace (stack) pointer, find its input Varnode, and look for additive uses
/// of it. Once all these Varnodes are accumulated, calculate specific offsets that start a region
/// being aliased.
void AliasChecker::gatherInternal(void) const

{
  calculated = true;
  aliasBoundary = localExtreme;
  Varnode *spacebase = fd->findSpacebaseInput(space);
  if (spacebase == (Varnode *)0) return; // No possible alias

  gatherAdditiveBase(spacebase,addBase);
  for(vector<AddBase>::iterator iter=addBase.begin();iter!=addBase.end();++iter) {
    uintb offset = gatherOffset((*iter).base);
    offset = AddrSpace::addressToByte(offset,space->getWordSize()); // Convert to byte offset
    alias.push_back(offset);
    if (direction == 1) {
      if (offset < localBoundary) continue; // Parameter ref
    }
    else {
      if (offset > localBoundary) continue; // Parameter ref
    }
    // Always consider anything AFTER a pointer reference as
    // aliased, regardless of the stack direction
    if (offset < aliasBoundary)
      aliasBoundary = offset;
  }
}

/// For the given function and address space, gather all Varnodes that are pointers into the
/// address space.  The actual calculation can be deferred until the first time
/// hasLocalAlias() is called.
/// \param f is the given function
/// \param spc is the given address space
/// \param defer is \b true is gathering is deferred
void AliasChecker::gather(const Funcdata *f,AddrSpace *spc,bool defer)

{
  fd = f;
  space = spc;
  calculated = false;		// Defer calculation
  addBase.clear();
  alias.clear();
  direction = space->stackGrowsNegative() ? 1 : -1;		// direction == 1 for normal negative stack growth
  deriveBoundaries(fd->getFuncProto());
  if (!defer)
    gatherInternal();
}

/// This is gives a rough analysis of whether the given Varnode might be aliased by another pointer in
/// the function. If \b false is returned, the Varnode is not likely to have an alias. If \b true is returned,
/// the Varnode might have an alias.
/// \param vn is the given Varnode
/// \return \b true if the Varnode might have a pointer alias
bool AliasChecker::hasLocalAlias(Varnode *vn) const

{
  if (vn == (Varnode *)0) return false;
  if (!calculated)
    gatherInternal();
  if (vn->getSpace() != space) return false;
  // For positive stack growth, this is not a good test because values being queued on the
  // stack to be passed to a subfunction always have offsets a little bit bigger than ALL
  // local variables on the stack
  if (direction == -1)
    return false;
  return (vn->getOffset() >= aliasBoundary);
}

void AliasChecker::sortAlias(void) const

{
  sort(alias.begin(),alias.end());
}

/// \brief Gather result Varnodes for all \e sums that the given starting Varnode is involved in
///
/// For every sum that involves \b startvn, collect the final result Varnode of the sum.
/// A sum is any expression involving only the additive operators
/// INT_ADD, INT_SUB, PTRADD, PTRSUB, and SEGMENTOP.  The routine traverses forward recursively
/// through all descendants of \b vn that are additive operations and collects all the roots
/// of the traversed trees.
/// \param startvn is the Varnode to trace
/// \param addbase will contain all the collected roots
void AliasChecker::gatherAdditiveBase(Varnode *startvn,vector<AddBase> &addbase)

{
  vector<AddBase> vnqueue;		// varnodes involved in addition with original vn
  Varnode *vn,*subvn,*indexvn,*othervn;
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  bool nonadduse;
  int4 i=0;

  vn = startvn;
  vn->setMark();
  vnqueue.push_back(AddBase(vn,(Varnode *)0));
  while(i<vnqueue.size()) {
    vn = vnqueue[i].base;
    indexvn = vnqueue[i++].index;
    nonadduse = false;
    for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      op = *iter;
      switch(op->code()) {
      case CPUI_COPY:
	nonadduse = true;	// Treat COPY as both non-add use and part of ADD expression
	subvn = op->getOut();
	if (!subvn->isMark()) {
	  subvn->setMark();
	  vnqueue.push_back(AddBase(subvn,indexvn));
	}
	break;
      case CPUI_INT_SUB:
	if (vn == op->getIn(1)) {	// Subtracting the pointer
	  nonadduse = true;
	  break;
	}
	othervn = op->getIn(1);
	if (!othervn->isConstant())
	  indexvn = othervn;
	subvn = op->getOut();
	if (!subvn->isMark()) {
	  subvn->setMark();
	  vnqueue.push_back(AddBase(subvn,indexvn));
	}
	break;
      case CPUI_INT_ADD:
      case CPUI_PTRADD:
	othervn = op->getIn(1);	// Check if something else is being added in besides a constant
	if (othervn == vn)
	  othervn = op->getIn(0);
	if (!othervn->isConstant())
	  indexvn = othervn;
	// fallthru
      case CPUI_PTRSUB:
      case CPUI_SEGMENTOP:
	subvn = op->getOut();
	if (!subvn->isMark()) {
	  subvn->setMark();
	  vnqueue.push_back(AddBase(subvn,indexvn));
	}
	break;
      default:
	nonadduse = true;	// Used in non-additive expression
      }
    }
    if (nonadduse)
      addbase.push_back(AddBase(vn,indexvn));
  }
  for(i=0;i<vnqueue.size();++i)
    vnqueue[i].base->clearMark();
}

/// \brief If the given Varnode is a sum result, return the constant portion of this sum.
///
/// Treat \b vn as the result of a series of ADD operations.
/// Examine all the constant terms of this sum and add them together by traversing
/// the syntax tree rooted at \b vn, backwards, only through additive operations.
/// \param vn is the given Varnode to gather off of
/// \return the resulting sub-sum
uintb AliasChecker::gatherOffset(Varnode *vn)

{
  uintb retval;
  Varnode *othervn;

  if (vn->isConstant()) return vn->getOffset();
  PcodeOp *def = vn->getDef();
  if (def == (PcodeOp *)0) return 0;
  switch(def->code()) {
  case CPUI_COPY:
    retval = gatherOffset(def->getIn(0));
    break;
  case CPUI_PTRSUB:
  case CPUI_INT_ADD:
    retval = gatherOffset(def->getIn(0));
    retval += gatherOffset(def->getIn(1));
    break;
  case CPUI_INT_SUB:
    retval = gatherOffset(def->getIn(0));
    retval -= gatherOffset(def->getIn(1));
    break;
  case CPUI_PTRADD:
    othervn = def->getIn(2);
    retval = gatherOffset(def->getIn(0));
    // We need to treat PTRADD exactly as if it were encoded as an ADD and MULT
    // Because a plain MULT truncates the ADD tree
    // We only follow getIn(1) if the PTRADD multiply is by 1
    if (othervn->isConstant() && (othervn->getOffset()==1))
      retval = retval + gatherOffset(def->getIn(1));
    break;
  case CPUI_SEGMENTOP:
    retval = gatherOffset(def->getIn(2));
    break;
  default:
    retval = 0;
  }
  return retval & calc_mask(vn->getSize());
}

/// \param spc is the address space being analyzed
/// \param rn is the subset of addresses within the address space to analyze
/// \param pm is subset of ranges within the address space considered to be parameters
/// \param dt is the default data-type
MapState::MapState(AddrSpace *spc,const RangeList &rn,
		     const RangeList &pm,Datatype *dt) : range(rn)
{
  spaceid = spc;
  defaultType = dt;
  set<Range>::const_iterator iter;
  for(iter=pm.begin();iter!=pm.end();++iter) {
    AddrSpace *spc = (*iter).getSpace();
    uintb first = (*iter).getFirst();
    uintb last = (*iter).getLast();
    range.removeRange(spc,first,last); // Clear possible input symbols
  }
#ifdef OPACTION_DEBUG
  debugon = false;
#endif
}

MapState::~MapState(void)

{
  vector<RangeHint *>::iterator iter;
  for(iter=maplist.begin();iter!=maplist.end();++iter)
    delete *iter;
}

/// A specific range of bytes is described for the hint, given a starting offset and other information.
/// The size of range can be fixed or open-ended. A putative data-type can be provided.
/// \param st is the starting offset of the range
/// \param ct is the (optional) data-type information, which may be NULL
/// \param fl is additional boolean properties
/// \param rt is the type of the hint
/// \param hi is the biggest guaranteed index for \e open range hints
void MapState::addRange(uintb st,Datatype *ct,uint4 fl,RangeHint::RangeType rt,int4 hi)

{
  if ((ct == (Datatype *)0)||(ct->getSize()==0)) // Must have a real type
    ct = defaultType;
  int4 sz = ct->getSize();
  if (!range.inRange(Address(spaceid,st),sz))
    return;
  intb sst = (intb)AddrSpace::byteToAddress(st,spaceid->getWordSize());
  sign_extend(sst,spaceid->getAddrSize()*8-1);
  sst = (intb)AddrSpace::addressToByte(sst,spaceid->getWordSize());
  RangeHint *range = new RangeHint(st,sz,sst,ct,fl,rt,hi);
  maplist.push_back(range);
#ifdef OPACTION_DEBUG
  if (debugon) {
    ostringstream s;
    s << "Add Range: " << hex << st << ":" << dec << sz;
    s << " ";
    ct->printRaw(s);
    s << endl;
    glb->printDebug(s.str());
  }
#endif
}

/// Assuming a sorted list, from among a sequence of RangeHints with the same start and size, select
/// the most specific data-type.  Set all elements to use this data-type, and eliminate duplicates.
void MapState::reconcileDatatypes(void)

{
  vector<RangeHint *> newList;
  newList.reserve(maplist.size());
  int4 startPos = 0;
  RangeHint *startHint = maplist[0];
  Datatype *startDatatype = startHint->type;
  newList.push_back(startHint);
  int4 curPos = 1;
  while(curPos < maplist.size()) {
    RangeHint *curHint = maplist[curPos++];
    if (curHint->start == startHint->start && curHint->size == startHint->size) {
      Datatype *curDatatype = curHint->type;
      if (curDatatype->typeOrder(*startDatatype) < 0)	// Take the most specific variant of data-type
	startDatatype = curDatatype;
      if (curHint->compare(*newList.back()) != 0)
	newList.push_back(curHint);		// Keep the current hint if it is otherwise different
      else
	delete curHint;		// RangeHint is on the heap, so delete if we are not keeping it
    }
    else {
      while(startPos < newList.size()) {
	newList[startPos]->type = startDatatype;
	startPos += 1;
      }
      startHint = curHint;
      startDatatype = startHint->type;
      newList.push_back(startHint);
    }
  }
  while(startPos < newList.size()) {
    newList[startPos]->type = startDatatype;
    startPos += 1;
  }
  maplist.swap(newList);
}

/// The given LoadGuard, which may be a LOAD or STORE is converted into an appropriate
/// RangeHint, attempting to make use of any data-type or index information.
/// \param guard is the given LoadGuard
/// \param opc is the expected op-code (CPUI_LOAD or CPUI_STORE)
/// \param typeFactory is used to manufacture a data-type for the hint if necessary
void MapState::addGuard(const LoadGuard &guard,OpCode opc,TypeFactory *typeFactory)

{
  if (!guard.isValid(opc)) return;
  int4 step = guard.getStep();
  if (step == 0) return;		// No definitive sign of array access
  Datatype *ct = guard.getOp()->getIn(1)->getType();
  if (ct->getMetatype() == TYPE_PTR) {
    ct = ((TypePointer *) ct)->getPtrTo();
    while (ct->getMetatype() == TYPE_ARRAY)
      ct = ((TypeArray *) ct)->getBase();
  }
  int4 outSize;
  if (opc == CPUI_STORE)
    outSize = guard.getOp()->getIn(2)->getSize();	// The Varnode being stored
  else
    outSize = guard.getOp()->getOut()->getSize();	// The Varnode being loaded
  if (outSize != step) {
    // LOAD size doesn't match step:  field in array of structures or something more unusual
    if (outSize > step || (step % outSize) != 0)
      return;
    // Since the LOAD size divides the step and we want to preserve the arrayness
    // we pretend we have an array of LOAD's size
    step = outSize;
  }
  if (ct->getSize() != step) {	// Make sure data-type matches our step size
    if (step > 8)
      return;		// Don't manufacture primitives bigger than 8-bytes
    ct = typeFactory->getBase(step, TYPE_UNKNOWN);
  }
  if (guard.isRangeLocked()) {
    int4 minItems = ((guard.getMaximum() - guard.getMinimum()) + 1) / step;
    addRange(guard.getMinimum(),ct,0,RangeHint::open,minItems-1);
  }
  else
    addRange(guard.getMinimum(),ct,0,RangeHint::open,3);
}

/// Run through all Symbols in the given map and create a corresponding RangeHint
/// to \b this collection for each Symbol.
/// \param rangemap is the given map of Symbols
void MapState::gatherSymbols(const EntryMap *rangemap)

{
  list<SymbolEntry>::const_iterator iter;
  Symbol *sym;
  if (rangemap == (EntryMap *)0) return;
  for(iter=rangemap->begin_list();iter!=rangemap->end_list();++iter) {
    sym = (*iter).getSymbol();
    if (sym == (Symbol *)0) continue;
    //    if ((*iter).isPiece()) continue;     // This should probably never happen
    uintb start = (*iter).getAddr().getOffset();
    Datatype *ct = sym->getType();
    addRange(start,ct,sym->getFlags(),RangeHint::fixed,-1);
  }
}

/// Sort the collection and add a special terminating RangeHint
/// \return \b true if the collection isn't empty (and iteration can begin)
bool MapState::initialize(void)

{
				// Enforce boundaries of local variables
  const Range *lastrange = range.getLastSignedRange(spaceid);
  if (lastrange == (Range *)0) return false;
  if (maplist.empty()) return false;
  uintb high = spaceid->wrapOffset(lastrange->getLast()+1);
  intb sst = (intb)AddrSpace::byteToAddress(high,spaceid->getWordSize());
  sign_extend(sst,spaceid->getAddrSize()*8-1);
  sst = (intb)AddrSpace::addressToByte(sst,spaceid->getWordSize());
  // Add extra range to bound any final open entry
  RangeHint *range = new RangeHint(high,1,sst,defaultType,0,RangeHint::endpoint,-2);
  maplist.push_back(range);

  stable_sort(maplist.begin(),maplist.end(),RangeHint::compareRanges);
  reconcileDatatypes();
  iter = maplist.begin();
  return true;
}

/// Add a RangeHint corresponding to each Varnode stored in the address space
/// for the given function.  The current knowledge of the Varnode's data-type
/// is included as part of the hint.
/// \param fd is the given function
void MapState::gatherVarnodes(const Funcdata &fd)

{
  VarnodeLocSet::const_iterator iter,iterend;
  Varnode *vn;
  iter = fd.beginLoc(spaceid);
  iterend = fd.endLoc(spaceid);
  while(iter != iterend) {
    vn = *iter++;
    if (vn->isFree()) continue;
    uintb start = vn->getOffset();
    Datatype *ct = vn->getType();
				// Do not force Varnode flags on the entry
				// as the flags were inherited from the previous
				// (now obsolete) entry
    addRange(start,ct,0,RangeHint::fixed,-1);
  }
}

/// Add a RangeHint corresponding to each HighVariable that is mapped to our
/// address space for the given function.
/// \param fd is the given function
void MapState::gatherHighs(const Funcdata &fd)

{
  vector<HighVariable *> varvec;
  VarnodeLocSet::const_iterator iter,iterend;
  Varnode *vn;
  HighVariable *high;
  iter = fd.beginLoc(spaceid);
  iterend = fd.endLoc(spaceid);
  while(iter != iterend) {
    vn = *iter++;
    high = vn->getHigh();
    if (high == (HighVariable *)0) continue;
    if (high->isMark()) continue;
    if (!high->isAddrTied()) continue;
    vn = high->getTiedVarnode();	// Original vn may not be good representative
    high->setMark();
    varvec.push_back(high);
    uintb start = vn->getOffset();
    Datatype *ct = high->getType(); // Get type from high
    addRange(start,ct,0,RangeHint::fixed,-1);
  }
  for(int4 i=0;i<varvec.size();++i)
    varvec[i]->clearMark();
}

/// For any Varnode that looks like a pointer into our address space, create an
/// \e open RangeHint. The size of the object may not be known.
/// \param fd is the given function
void MapState::gatherOpen(const Funcdata &fd)

{
  checker.gather(&fd,spaceid,false);

  const vector<AliasChecker::AddBase> &addbase( checker.getAddBase() );
  const vector<uintb> &alias( checker.getAlias() );
  uintb offset;
  Datatype *ct;

  for(int4 i=0;i<addbase.size();++i) {
    offset = alias[i];
    ct = addbase[i].base->getType();
    if (ct->getMetatype() == TYPE_PTR) {
      ct = ((TypePointer *)ct)->getPtrTo();
      while(ct->getMetatype() == TYPE_ARRAY)
	ct = ((TypeArray *)ct)->getBase();
    }
    else
      ct = (Datatype *)0;	// Do unknown array
    int4 minItems;
    if ( addbase[i].index != (Varnode *)0) {
      minItems = 3;			// If there is an index, assume it takes on at least the 4 values [0,3]
    }
    else {
      minItems = -1;
    }
    addRange(offset,ct,0,RangeHint::open,minItems);
  }

  TypeFactory *typeFactory = fd.getArch()->types;
  const list<LoadGuard> &loadGuard( fd.getLoadGuards() );
  for(list<LoadGuard>::const_iterator iter=loadGuard.begin();iter!=loadGuard.end();++iter)
    addGuard(*iter,CPUI_LOAD,typeFactory);

  const list<LoadGuard> &storeGuard( fd.getStoreGuards() );
  for(list<LoadGuard>::const_iterator iter=storeGuard.begin();iter!=storeGuard.end();++iter)
    addGuard(*iter,CPUI_STORE,typeFactory);
}

/// Define stack Symbols based on Varnodes.
/// This method can be called repeatedly during decompilation. It helps propagate data-types.
/// Unaliased symbols can optionally be marked to facilitate removal of INDIRECT ops, but
/// this is generally done later in the process.
/// \param aliasyes is \b true if unaliased Symbols should be marked
void ScopeLocal::restructureVarnode(bool aliasyes)

{
  clearUnlockedCategory(-1);	// Clear out any unlocked entries
  MapState state(space,getRangeTree(),fd->getFuncProto().getParamRange(),
		  glb->types->getBase(1,TYPE_UNKNOWN)); // Organize list of ranges to insert
    
#ifdef OPACTION_DEBUG
  if (debugon)
    state.turnOnDebug(glb);
#endif
  state.gatherVarnodes(*fd); // Gather stack type information from varnodes
  state.gatherOpen(*fd);
  state.gatherSymbols(maptable[space->getIndex()]);
  restructure(state);

  // At some point, processing mapped input symbols may be folded
  // into the above gather/restructure process, but for now
  // we just define fake symbols so that mark_unaliased will work
  clearUnlockedCategory(0);
  fakeInputSymbols();

  state.sortAlias();
  if (aliasyes)
    markUnaliased(state.getAlias());
}

/// Define stack Symbols based on HighVariables.
/// This method is called once at the end of decompilation to create the final set of stack Symbols after
/// all data-type propagation has settled. It creates a consistent data-type for all Varnode instances of
/// a HighVariable.
void ScopeLocal::restructureHigh(void)

{				// Define stack mapping based on highs
  clearUnlockedCategory(-1);	// Clear out any unlocked entries
  MapState state(space,getRangeTree(),fd->getFuncProto().getParamRange(),
		  glb->types->getBase(1,TYPE_UNKNOWN)); // Organize list of ranges to insert
    
#ifdef OPACTION_DEBUG
  if (debugon)
    state.turnOnDebug(glb);
#endif
  state.gatherHighs(*fd); // Gather stack type information from highs
  state.gatherOpen(*fd);
  state.gatherSymbols(maptable[space->getIndex()]);
  bool overlapProblems = restructure(state);

  if (overlapProblems)
    fd->warningHeader("Could not reconcile some variable overlaps");
}

/// RangeHints from the given collection are merged into a definitive set of Symbols
/// for \b this scope. Overlapping or open RangeHints are adjusted to form a disjoint
/// cover of the mapped portion of the address space.  Names for the disjoint cover elements
/// are chosen, and these form the final Symbols.
/// \param state is the given collection of RangeHints
/// \return \b true if there were overlaps that could not be reconciled
bool ScopeLocal::restructure(MapState &state)

{
  RangeHint cur;
  RangeHint *next;
 				// This implementation does not allow a range
				// to contain both ~0 and 0
  bool overlapProblems = false;
  if (!state.initialize())
    return overlapProblems; // No references to stack at all

  cur = *state.next();
  while(state.getNext()) {
    next = state.next();
    if (next->sstart < cur.sstart+cur.size) {	// Do the ranges intersect
      if (cur.merge(next,space,glb->types))	// Union them
	overlapProblems = true;
    }
    else {
      if (!cur.absorb(next)) {
	if (cur.rangeType == RangeHint::open)
	  cur.size = next->sstart-cur.sstart;
	if (adjustFit(cur))
	  createEntry(cur);
	cur = *next;
      }
    }
  }
				// The last range is artificial so we don't
				// build an entry for it
  return overlapProblems;
}

/// Given a set of alias starting offsets, calculate whether each Symbol within this scope might be
/// aliased by a pointer.  The method uses locked Symbol information when available to determine
/// how far an alias start might extend.  Otherwise a heuristic is used to determine if the Symbol
/// is far enough away from the start of the alias to be considered unaliased.
/// \param alias is the given set of alias starting offsets
void ScopeLocal::markUnaliased(const vector<uintb> &alias)

{
  EntryMap *rangemap = maptable[space->getIndex()];
  if (rangemap == (EntryMap *)0) return;
  list<SymbolEntry>::iterator iter,enditer;

  int4 alias_block_level = glb->alias_block_level;
  bool aliason = false;
  uintb curalias=0;
  int4 i=0;
  
  iter = rangemap->begin_list();
  enditer = rangemap->end_list();

  while(iter!=enditer) {
    if ((i<alias.size()) && (alias[i] <= (*iter).getAddr().getOffset() + (*iter).getSize() - 1)) {
      aliason = true;
      curalias = alias[i++];
    }
    else {
      SymbolEntry &entry(*iter++);
      Symbol *symbol = entry.getSymbol();
      // Test if there is enough distance between symbol
      // and last alias to warrant ignoring the alias
      // NOTE: this is primarily to reset aliasing between
      // stack parameters and stack locals
      if (aliason && (entry.getAddr().getOffset()+entry.getSize() -1 - curalias > 0xffff))
	aliason = false;
      if (!aliason)
	symbol->getScope()->setAttribute(symbol,Varnode::nolocalalias);
      if (symbol->isTypeLocked() && alias_block_level != 0) {
	if (alias_block_level == 3)
	  aliason = false;		// For this level, all locked data-types block aliases
	else {
	  type_metatype meta = symbol->getType()->getMetatype();
	  if (meta == TYPE_STRUCT)
	    aliason = false;		// Only structures block aliases
	  else if (meta == TYPE_ARRAY && alias_block_level > 1)
	    aliason = false;		// Only arrays (and structures) block aliases
	}
      }
    }
  }
}

/// This assigns a Symbol to any input Varnode stored in our address space, which could be
/// a parameter but isn't in the formal prototype of the function (these should already be in
/// the scope marked as category '0').
void ScopeLocal::fakeInputSymbols(void)

{
  int4 lockedinputs = getCategorySize(0);
  VarnodeDefSet::const_iterator iter,enditer;

  iter = fd->beginDef(Varnode::input);
  enditer = fd->endDef(Varnode::input);

  while(iter != enditer) {
    Varnode *vn = *iter++;
    bool locked = vn->isTypeLock();
    Address addr = vn->getAddr();
    if (addr.getSpace() != space) continue;
    // Only allow offsets which can be parameters
    if (!fd->getFuncProto().getParamRange().inRange(addr,1)) continue;
    uintb endpoint = addr.getOffset() + vn->getSize() - 1;
    while(iter != enditer) {
      vn = *iter;
      if (vn->getSpace() != space) break;
      if (endpoint < vn->getOffset()) break;
      uintb newendpoint = vn->getOffset() + vn->getSize() -1;
      if (endpoint < newendpoint)
	endpoint = newendpoint;
      if (vn->isTypeLock())
	locked = true;
      ++iter;
    }
    if (!locked) {
      Address usepoint;
      //      if (!vn->addrtied())
      // 	usepoint = vn->getUsePoint(*fd);
      // Double check to make sure vn doesn't already have a
      // representative symbol.  If the input prototype is locked
      // but one of the types is TYPE_UNKNOWN, then the 
      // corresponding varnodes won't get typelocked
      if (lockedinputs != 0) {
	uint4 vflags = 0;
	SymbolEntry *entry = queryProperties(vn->getAddr(),vn->getSize(),usepoint,vflags);
	if (entry != (SymbolEntry *)0) {
	  if (entry->getSymbol()->getCategory()==0)
	    continue;		// Found a matching symbol
	}
      }
      
      int4 size = (endpoint - addr.getOffset()) + 1;
      Datatype *ct = fd->getArch()->types->getBase(size,TYPE_UNKNOWN);
      try {
	addSymbol("",ct,addr,usepoint)->getSymbol();
      }
      catch(LowlevelError &err) {
	fd->warningHeader(err.explain);
      }
      //      setCategory(sym,0,index);
    }
  }
}

/// \brief Change the primary mapping for the given Symbol to be a specific storage address and use point
///
/// Remove any other mapping and create a mapping based on the given storage.
/// \param sym is the given Symbol to remap
/// \param addr is the starting address of the storage
/// \param usepoint is the use point for the mapping
/// \return the new mapping
SymbolEntry *ScopeLocal::remapSymbol(Symbol *sym,const Address &addr,const Address &usepoint)

{
  SymbolEntry *entry = sym->getFirstWholeMap();
  int4 size = entry->getSize();
  if (!entry->isDynamic()) {
    if (entry->getAddr() == addr) {
      if (usepoint.isInvalid() && entry->getFirstUseAddress().isInvalid())
	return entry;
      if (entry->getFirstUseAddress() == usepoint)
	return entry;
    }
  }
  removeSymbolMappings(sym);
  RangeList rnglist;
  if (!usepoint.isInvalid())
    rnglist.insertRange(usepoint.getSpace(),usepoint.getOffset(),usepoint.getOffset());
  return addMapInternal(sym,Varnode::mapped,addr,0,size,rnglist);
}

/// \brief Make the primary mapping for the given Symbol, dynamic
///
/// Remove any other mapping and create a new dynamic mapping based on a given
/// size and hash
/// \param sym is the given Symbol to remap
/// \param hash is the dynamic hash
/// \param usepoint is the use point for the mapping
/// \return the new dynamic mapping
SymbolEntry *ScopeLocal::remapSymbolDynamic(Symbol *sym,uint8 hash,const Address &usepoint)

{
  SymbolEntry *entry = sym->getFirstWholeMap();
  int4 size = entry->getSize();
  if (entry->isDynamic()) {
    if (entry->getHash() == hash && entry->getFirstUseAddress() == usepoint)
      return entry;
  }
  removeSymbolMappings(sym);
  RangeList rnglist;
  if (!usepoint.isInvalid())
    rnglist.insertRange(usepoint.getSpace(),usepoint.getOffset(),usepoint.getOffset());
  return addDynamicMapInternal(sym,Varnode::mapped,hash,0,size,rnglist);
}

/// \brief Run through name recommendations, checking if any match unnamed symbols
///
/// Unlocked symbols that are presented to the decompiler are stored off as \e recommended names. These
/// can be reattached after the decompiler makes a determination of what the final Symbols are.
/// This method runs through the recommended names and checks if they can be applied to an existing
/// unnamed Symbol.
void ScopeLocal::recoverNameRecommendationsForSymbols(void)

{
  Address param_usepoint = fd->getAddress() - 1;
  list<NameRecommend>::const_iterator iter;
  for(iter=nameRecommend.begin();iter!=nameRecommend.end();++iter) {
    const Address &addr((*iter).getAddr());
    const Address &usepoint((*iter).getUseAddr());
    int4 size = (*iter).getSize();
    Symbol *sym;
    Varnode *vn = (Varnode *)0;
    if (usepoint.isInvalid()) {
      SymbolEntry *entry = findOverlap(addr, size);	// Recover any Symbol regardless of usepoint
      if (entry == (SymbolEntry *)0) continue;
      if (entry->getAddr() != addr)		// Make sure Symbol has matching address
	continue;
      sym = entry->getSymbol();
      if ((sym->getFlags() & Varnode::addrtied)==0)
	continue;				// Symbol must be address tied to match this name recommendation
      vn = fd->findLinkedVarnode(entry);
    }
    else {
      if (usepoint == param_usepoint)
	vn = fd->findVarnodeInput(size, addr);
      else
	vn = fd->findVarnodeWritten(size,addr,usepoint);
      if (vn == (Varnode *)0) continue;
      sym = vn->getHigh()->getSymbol();
      if (sym == (Symbol *)0) continue;
      if ((sym->getFlags() & Varnode::addrtied)!=0)
	continue;				// Cannot use untied varnode as primary map for address tied symbol
      SymbolEntry *entry = sym->getFirstWholeMap();
      // entry->getAddr() does not need to match address of the recommendation
      if (entry->getSize() != size) continue;
    }
    if (!sym->isNameUndefined()) continue;
    renameSymbol(sym,makeNameUnique((*iter).getName()));
    setSymbolId(sym, (*iter).getSymbolId());
    setAttribute(sym, Varnode::namelock);
    if (vn != (Varnode *)0) {
      fd->remapVarnode(vn, sym, usepoint);
    }
  }

  if (dynRecommend.empty()) return;

  list<DynamicRecommend>::const_iterator dyniter;
  DynamicHash dhash;
  for(dyniter=dynRecommend.begin();dyniter!=dynRecommend.end();++dyniter) {
    dhash.clear();
    const DynamicRecommend &dynEntry(*dyniter);
    Varnode *vn = dhash.findVarnode(fd, dynEntry.getAddress(), dynEntry.getHash());
    if (vn == (Varnode *)0) continue;
    if (vn->isAnnotation()) continue;
    Symbol *sym = vn->getHigh()->getSymbol();
    if (sym == (Symbol *)0) continue;
    if (sym->getScope() != this) continue;
    if (!sym->isNameUndefined()) continue;
    renameSymbol(sym,makeNameUnique( dynEntry.getName() ));
    setAttribute(sym, Varnode::namelock);
    setSymbolId(sym, dynEntry.getSymbolId());
    fd->remapDynamicVarnode(vn, sym, dynEntry.getAddress(), dynEntry.getHash());
  }
}

/// Run through the recommended list, search for an input Varnode matching the storage address
/// and try to apply the data-type to it.  Do not override existing type lock.
void ScopeLocal::applyTypeRecommendations(void)

{
  list<TypeRecommend>::const_iterator iter;
  for(iter=typeRecommend.begin();iter!=typeRecommend.end();++iter) {
    Datatype *dt = (*iter).getType();
    Varnode *vn = fd->findVarnodeInput(dt->getSize(), (*iter).getAddress());
    if (vn != (Varnode *)0)
      vn->updateType(dt, true, false);
  }
}

/// The symbol is stored as a name recommendation and then removed from the scope.
/// Name recommendations are associated either with a storage address and usepoint, or a dynamic hash.
/// The name may be reattached to a Symbol after decompilation.
/// \param sym is the given Symbol to treat as a name recommendation
void ScopeLocal::addRecommendName(Symbol *sym)

{
  SymbolEntry *entry = sym->getFirstWholeMap();
  if (entry == (SymbolEntry *) 0) return;
  if (entry->isDynamic()) {
    dynRecommend.emplace_back(entry->getFirstUseAddress(), entry->getHash(), sym->getName(), sym->getId());
  }
  else {
    Address usepoint((AddrSpace *)0,0);
    if (!entry->getUseLimit().empty()) {
      const Range *range = entry->getUseLimit().getFirstRange();
      usepoint = Address(range->getSpace(), range->getFirst());
    }
    nameRecommend.emplace_back(entry->getAddr(),usepoint, entry->getSize(), sym->getName(), sym->getId());
  }
  if (sym->getCategory() < 0)
    removeSymbol(sym);
}

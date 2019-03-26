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

AddressSorter::AddressSorter(const Address &ad,const Address &use,int4 sz) : addr(ad), useaddr(use)

{
  size = sz;
  if (useaddr.isInvalid())	// If invalid
    useaddr = Address((AddrSpace *)0,0); // Make sure to set offset to zero, so invalids compare equal
}

bool AddressSorter::operator<(const AddressSorter &op2) const

{				// Compare address and use, but NOT size
  if (addr != op2.addr)
    return (addr < op2.addr);
  return (useaddr < op2.useaddr);
}

bool AddressSorter::operator==(const AddressSorter &op2) const

{
  if (addr != op2.addr) return false;
  return (useaddr == op2.useaddr);
}

bool AddressSorter::operator!=(const AddressSorter &op2) const

{
  if (addr != op2.addr) return true;
  return (useaddr != op2.useaddr);
}

ScopeLocal::ScopeLocal(AddrSpace *spc,Funcdata *fd,Architecture *g) : ScopeInternal(fd->getName(),g)

{
  spaceid = spc;
  qflags = 0;
  restrictScope(fd);
  dedupId = fd->getAddress().getOffset();		// Allow multiple scopes with same name
} 

void ScopeLocal::collectNameRecs(void)

{ // Turn any symbols that are namelocked but not typelocked into name recommendations (removing symbol)
  SymbolNameTree::iterator iter;

  name_recommend.clear();	// Clear out any old name recommendations

  iter = nametree.begin();
  while(iter!=nametree.end()) {
    Symbol *sym = *iter++;
    if (sym->isNameLocked()&&(!sym->isTypeLocked())) {
      SymbolEntry *entry = sym->getFirstWholeMap();
      if (entry != (SymbolEntry *)0) {
	if (entry->isDynamic()) continue; // Don't collect names for dynamic mappings
	Address usepoint;
	if (!entry->getUseLimit().empty()) {
	  const Range *range = entry->getUseLimit().getFirstRange();
	  usepoint = Address(range->getSpace(),range->getFirst());
	}
	addRecommendName( entry->getAddr(), usepoint, sym->getName(), entry->getSize() );
	if (sym->getCategory()<0)
	  removeSymbol(sym);
      }
    }
  }
}

void ScopeLocal::resetLocalWindow(void)

{				// Reset local discovery
  if ((qflags&range_locked)!=0) return;
  qflags = 0;

  localrange = fd->getFuncProto().getLocalRange();
  const RangeList &paramrange( fd->getFuncProto().getParamRange() );

  stackgrowsnegative = fd->getFuncProto().isStackGrowsNegative();
  RangeList newrange;

  set<Range>::const_iterator iter;
  for(iter=localrange.begin();iter!=localrange.end();++iter) {
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
  a_v(s,"main",spaceid->getName());
  a_v_b(s,"lock",((qflags & range_locked)!=0));
  s << ">\n";
  ScopeInternal::saveXml(s);
  s << "</localdb>\n";
}

void ScopeLocal::restoreXml(const Element *el)

{
  qflags = 0;
  if (xml_readbool(el->getAttributeValue("lock")))
    qflags |= range_locked;
  spaceid = glb->getSpaceByName(el->getAttributeValue("main"));
  
  ScopeInternal::restoreXml( *(el->getChildren().begin()) );
  collectNameRecs();
}

void ScopeLocal::markNotMapped(AddrSpace *spc,uintb first,int4 sz,bool parameter)

{
  if (spaceid != spc) return;
  uintb last = first + sz - 1;
  // Do not allow the range to cover the split point between "negative" and "positive" stack offsets
  if (last < first)		// Check for possible wrap around
    last = spc->getHighest();
  else if (last > spc->getHighest())
    last = spc->getHighest();
  if (parameter) {		// Everything above parameter
    if (stackgrowsnegative) {
      const Range *rng = localrange.getRange(spc,first);
      if (rng != (const Range *)0)
	first = rng->getFirst(); // Everything less is not mapped
    }
    else {
      const Range *rng = localrange.getRange(spc,last);
      if (rng != (const Range *)0)
	last = rng->getLast();	// Everything greater is not mapped
    }
    sz = (last-first)+1;
  }
  Address addr(spaceid,first);
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
  glb->symboltab->removeRange(this,spaceid,first,last);
}

string ScopeLocal::buildVariableName(const Address &addr,
				     const Address &pc,
				     Datatype *ct,
				     int4 &index,uint4 flags) const
{
  map<AddressSorter,string>::const_iterator iter;
  iter = name_recommend.find( AddressSorter(addr,pc,0));
  if (iter != name_recommend.end()) {
    // We are not checking if the recommended size matches
    return makeNameUnique((*iter).second);
  }
  if (((flags & (Varnode::addrtied|Varnode::persist))==Varnode::addrtied) &&
      addr.getSpace() == spaceid) {
    if (fd->getFuncProto().getLocalRange().inRange(addr,1)) {
      intb start = (intb) AddrSpace::byteToAddress(addr.getOffset(),spaceid->getWordSize());
      sign_extend(start,addr.getAddrSize()*8-1);
      if (stackgrowsnegative)
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
		
bool ScopeLocal::adjustFit(MapRange &a) const

{
  if (a.size==0) return false;	// Nothing to fit
  if ((a.flags & Varnode::typelock)!=0) return false; // Already entered
  Address addr(spaceid,a.start);
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
		     
void ScopeLocal::createEntry(const MapRange &a)

{
  Address addr(spaceid,a.start);
  Address usepoint;
  Datatype *ct = a.type;
  int4 num = a.size/ct->getSize();
  if (num>1)
    ct = glb->types->getTypeArray(num,ct);

  int4 index=0;
  string nm = buildVariableName(addr,usepoint,ct,index,Varnode::addrtied);

  addSymbol(nm,ct,addr,usepoint);
}

static bool compare_ranges(const MapRange *a,const MapRange *b)

{
  if (a->sstart != b->sstart)
    return (a->sstart < b->sstart);
  if (a->size != b->size)
    return (a->size < b->size);		// Small sizes come first
  type_metatype ameta = a->type->getMetatype();
  type_metatype bmeta = b->type->getMetatype();
  if (ameta != bmeta)
    return (ameta < bmeta);		// Order more specific types first
  return true;
}

void AliasChecker::deriveBoundaries(const FuncProto &proto)

{
  localextreme = ~((uintb)0);			// Default settings
  localboundary = 0x1000000;
  if (direction == -1)
    localextreme = localboundary;

  if (proto.hasModel()) {
    const RangeList &localrange( proto.getLocalRange() );
    const RangeList &paramrange( proto.getParamRange() );

    const Range *local = localrange.getFirstRange();
    const Range *param = paramrange.getLastRange();
    if ((local != (const Range *)0)&&(param != (const Range *)0)) {
      localboundary = param->getLast();
      if (direction == -1) {
	localboundary = paramrange.getFirstRange()->getFirst();
	localextreme = localboundary;
      }
    }
  }
}

void AliasChecker::gatherInternal(void) const

{
  calculated = true;
  aliasboundary = localextreme;
  Varnode *spacebase = fd->findSpacebaseInput(spaceid);
  if (spacebase == (Varnode *)0) return; // No possible alias

  gatherAdditiveBase(spacebase,addbase);
  for(vector<AddBase>::iterator iter=addbase.begin();iter!=addbase.end();++iter) {
    uintb offset = gatherOffset((*iter).base);
    offset = AddrSpace::addressToByte(offset,spaceid->getWordSize()); // Convert to byte offset
    alias.push_back(offset);
    if (direction == 1) {
      if (offset < localboundary) continue; // Parameter ref
    }
    else {
      if (offset > localboundary) continue; // Parameter ref
    }
    // Always consider anything AFTER a pointer reference as
    // aliased, regardless of the stack direction
    if (offset < aliasboundary)
      aliasboundary = offset;
  }
}

void AliasChecker::gather(const Funcdata *f,AddrSpace *spc,bool defer)

{
  fd = f;
  spaceid = spc;
  calculated = false;		// Defer calculation
  addbase.clear();
  alias.clear();
  direction = spaceid->stackGrowsNegative() ? 1 : -1;		// direction == 1 for normal negative stack growth
  deriveBoundaries(fd->getFuncProto());
  if (!defer)
    gatherInternal();
}

bool AliasChecker::hasLocalAlias(Varnode *vn) const

{
  if (vn == (Varnode *)0) return false;
  if (!calculated)
    gatherInternal();
  if (vn->getSpace() != spaceid) return false;
  // For positive stack growth, this is not a good test because values being queued on the
  // stack to be passed to a subfunction always have offsets a little bit bigger than ALL
  // local variables on the stack
  if (direction == -1)
    return false;
  return (vn->getOffset() >= aliasboundary);
}

void AliasChecker::sortAlias(void) const

{
  sort(alias.begin(),alias.end());
}

// For every sum that involves \b startvn, collect the final result Varnode of the sum.
// A sum is any expression involving only the additive operators
// INT_ADD, INT_SUB, PTRADD, PTRSUB, and SEGMENTOP.  The routine traverses forward recursively
// through all descendants of \b vn that are additive operations and collects all the roots
// of the traversed trees.
// \param startvn is the Varnode to trace
// \param addbase will contain all the collected roots
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
      case CPUI_INT_ADD:
      case CPUI_INT_SUB:
      case CPUI_PTRADD:
	othervn = op->getIn(1);	// Check if something else is being added in besides a constant
	if (othervn == vn)
	  othervn = op->getIn(0);
	if (!othervn->isConstant())
	  indexvn = othervn;
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

// Treat \b vn as the result of a series of ADD operations.
// Examine all the constant terms of this sum and add them together by traversing
// the syntax tree rooted at \b vn, backwards, only through additive operations.
// \param vn is the Varnode to gather off of
// \return the resulting sub-sum
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

MapState::MapState(AddrSpace *spc,const RangeList &rn,
		     const RangeList &pm,Datatype *dt) : range(rn)
{
  spaceid = spc;
  default_type = dt;
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
  vector<MapRange *>::iterator iter;
  for(iter=maplist.begin();iter!=maplist.end();++iter)
    delete *iter;
}

void MapState::addRange(uintb st,Datatype *ct,uint4 fl,bool ay,int4 lo,int4 hi)

{
  if ((ct == (Datatype *)0)||(ct->getSize()==0)) // Must have a real type
    ct = default_type;
  int4 sz = ct->getSize();
  if (!range.inRange(Address(spaceid,st),sz))
    return;
  intb sst = (intb)AddrSpace::byteToAddress(st,spaceid->getWordSize());
  sign_extend(sst,spaceid->getAddrSize()*8-1);
  sst = (intb)AddrSpace::addressToByte(sst,spaceid->getWordSize());
  MapRange *range = new MapRange(st,sz,sst,ct,fl,ay,lo,hi);
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

void MapState::addRange(const EntryMap *rangemap)

{				// Add rangemap entries to MapState
  list<SymbolEntry>::const_iterator iter;
  Symbol *sym;
  if (rangemap == (EntryMap *)0) return;
  for(iter=rangemap->begin_list();iter!=rangemap->end_list();++iter) {
    sym = (*iter).getSymbol();
    if (sym == (Symbol *)0) continue;
    //    if ((*iter).isPiece()) continue;     // This should probably never happen
    uintb start = (*iter).getAddr().getOffset();
    Datatype *ct = sym->getType();
    addRange(start,ct,sym->getFlags(),false,0,-1);
  }
}

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
  MapRange *range = new MapRange(high,1,sst,default_type,0,false,0,-2);
  maplist.push_back(range);

  stable_sort(maplist.begin(),maplist.end(),compare_ranges);
  iter = maplist.begin();
  return true;
}

void MapState::gatherVarnodes(const Funcdata &fd)

{				// Add MapState entry for each varnode in -spaceid-
  VarnodeLocSet::const_iterator iter,iterend;
  Varnode *vn;
  iter = fd.beginLoc(spaceid);
  iterend = fd.endLoc(spaceid);
  while(iter != iterend) {
    vn = *iter++;
    if (vn->isFree()) continue;
    uintb start = vn->getOffset();
    Datatype *ct = vn->getType();
				// Do not force varnodes flags on the entry
				// as the flags were inherited from the previous
				// (now obsolete) entry
    
    addRange(start,ct,0,false,0,-1);
  }
}

void MapState::gatherHighs(const Funcdata &fd)

{				// Same as gather_varnodes, but get types from highs
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
    addRange(start,ct,0,false,0,-1);
  }
  for(int4 i=0;i<varvec.size();++i)
    varvec[i]->clearMark();
}

void MapState::gatherOpen(const Funcdata &fd)

{				// Gather open-ended ranges. These correspond
				// to the use of ptrs to local variables
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
    int4 lo,hi;
    if ( addbase[i].index != (Varnode *)0) {
      lo = 0;
      hi = 3;			// If there is an index, assume it takes on at least the 4 values [0,3]
    }
    else {
      lo = 0;
      hi = -1;
    }
    addRange(offset,ct,0,true,lo,hi);
  }
}

void ScopeLocal::restructureVarnode(bool aliasyes)

{ // Define stack mapping based on varnodes. Don't mark unaliased symbols unless -aliasyes- is true
  clearUnlockedCategory(-1);	// Clear out any unlocked entries
  MapState state(spaceid,getRangeTree(),fd->getFuncProto().getParamRange(),
		  glb->types->getBase(1,TYPE_UNKNOWN)); // Organize list of ranges to insert
    
#ifdef OPACTION_DEBUG
  if (debugon)
    state.turnOnDebug(glb);
#endif
  state.gatherVarnodes(*fd); // Gather stack type information from varnodes
  state.gatherOpen(*fd);
  state.addRange(maptable[spaceid->getIndex()]);
  restructure(state,false);

  // At some point, processing mapped input symbols may be folded
  // into the above gather/restructure process, but for now
  // we just define fake symbols so that mark_unaliased will work
  clearUnlockedCategory(0);
  fakeInputSymbols();

  state.sortAlias();
  if (aliasyes)
    markUnaliased(state.getAlias());
}

void ScopeLocal::restructureHigh(void)

{				// Define stack mapping based on highs
  clearUnlockedCategory(-1);	// Clear out any unlocked entries
  MapState state(spaceid,getRangeTree(),fd->getFuncProto().getParamRange(),
		  glb->types->getBase(1,TYPE_UNKNOWN)); // Organize list of ranges to insert
    
#ifdef OPACTION_DEBUG
  if (debugon)
    state.turnOnDebug(glb);
#endif
  state.gatherHighs(*fd); // Gather stack type information from highs
  state.gatherOpen(*fd);
  state.addRange(maptable[spaceid->getIndex()]);
  restructure(state,true);

  if (overlapproblems)
    fd->warningHeader("Could not reconcile some variable overlaps");
}

static bool range_reconcile(const MapRange *a,const MapRange *b)

{				// Can the types coexist at the given offsets
  if (a->type->getSize() < b->type->getSize()) {
    const MapRange *tmp = b;
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

static bool range_contain(const MapRange *a,const MapRange *b)

{				// Return true if one contains the other
				// We assume a starts at least as early as b
				// and that a and b intersect
  if (a->sstart == b->sstart) return true;
  //  if (a->sstart==a->send) return true;
  //  if (b->sstart==b->send) return true;
  if (b->sstart+b->size-1 <= a->sstart+a->size-1) return true;
  return false;
}

static bool range_preferred(const MapRange *a,const MapRange *b,bool reconcile)

{				// Return true if a's type is preferred over b's
  if (a->start != b->start)
    return true;		// Something must occupy a->start to b->start
				// Prefer the locked type
  if ((b->flags & Varnode::typelock)!=0) {
    if ((a->flags & Varnode::typelock)==0)
      return false;
  }
  else if ((a->flags & Varnode::typelock)!=0)
    return true;
  
  if (!reconcile) {		// If the ranges don't reconcile
    if ((a->arrayyes)&&(!b->arrayyes)) // Throw out the open range
      return false;
    if ((b->arrayyes)&&(!a->arrayyes))
      return true;
  }

  return (0>a->type->typeOrder(*b->type)); // Prefer the more specific
}

bool ScopeLocal::rangeAbsorb(MapRange *a,MapRange *b)

{ // check if -a- is an array and could absorb -b-
  if (!a->arrayyes) return false; 
  if (a->highind < a->lowind) return false;
  if ((b->lowind == 0)&&(b->highind==-2)) return false;	// Don't merge with bounding range
  Datatype *settype = a->type;
  if (settype->getSize() != b->type->getSize()) return false;
  if (settype->getMetatype() == TYPE_UNKNOWN)
    settype = b->type;
  else if (b->type->getMetatype() == TYPE_UNKNOWN) {
  }
  else if (settype != b->type)	// If they are both not unknown, they must be the same
    return false;
  if ((a->flags & Varnode::typelock)!=0) return false;
  if ((b->flags & Varnode::typelock)!=0) return false;
  if (a->flags != b->flags) return false;
  intb diffsz = b->sstart - a->sstart;
  if ((diffsz % settype->getSize()) != 0) return false;
  diffsz /= settype->getSize();
  if (diffsz > a->highind) return false;
  a->type = settype;
  if (b->arrayyes && (b->lowind <= b->highind)) { // If b has array indexing
    int4 triallo = b->lowind + diffsz; // Adjust its indexing to the new base
    int4 trialhi = b->highind + diffsz;
    if (triallo < a->lowind)	// Check if we can expand the base indexing
      a->lowind = triallo;
    if (a->highind < trialhi)
      a->highind = trialhi;
  }
  return true;
}

void ScopeLocal::rangeUnion(MapRange *a,MapRange *b,bool warning)

{				// Two ranges intersect, produce the reconciled union (in a)
  uintb aend,bend;
  uintb end;
  Datatype *restype;
  uint4 flags;
  bool arrayyes,reconcile;
  int4 lo,hi;

  aend = spaceid->wrapOffset(a->start+a->size);
  bend = spaceid->wrapOffset(b->start+b->size);
  arrayyes = false;
  lo = 0;
  hi = -1;
  if ((aend==0)||(bend==0))
    end = 0;
  else
    end = (aend > bend) ? aend : bend;

  if (range_contain(a,b)) {	// Check for containment
    reconcile = range_reconcile(a,b);
    if (range_preferred(a,b,reconcile)) { // Find bigger type
      restype = a->type;
      flags = a->flags;
      arrayyes = a->arrayyes;
      lo = a->lowind;
      hi = a->highind;
    }
    else {
      restype = b->type;
      flags = b->flags;
      arrayyes = b->arrayyes;
      lo = b->lowind;
      hi = b->highind;
    }
    if ((a->start==b->start)&&(a->size==b->size)) {
      arrayyes = a->arrayyes || b->arrayyes;
      if (arrayyes) {
	lo = (a->lowind < b->lowind) ? a->lowind : b->lowind;
	hi = (a->highind < b->highind) ? b->highind : a->highind;
      }
    }
    if (warning && (!reconcile)) { // See if two types match up
      if ((!b->arrayyes)&&(!a->arrayyes))
	overlapproblems = true;
    }
  }
  else {
    reconcile = false;
    restype = (Datatype *)0;	// Unable to resolve the type
    flags = 0;
  }
				// Check for really problematic cases
  if (!reconcile) {
    if ((b->flags & Varnode::typelock)!=0) {
      if ((a->flags & Varnode::typelock)!=0)
	throw LowlevelError("Overlapping forced variable types : " + a->type->getName() + "   " + b->type->getName());
    }
  }
  if (restype == (Datatype *)0) // If all else fails
    restype = glb->types->getBase(1,TYPE_UNKNOWN); // Do unknown array (size 1)

  a->type = restype;
  a->flags = flags;
  a->arrayyes = arrayyes;
  a->lowind = lo;
  a->highind = hi;
  if ((!reconcile)&&(a->start != b->start)) { // Truncation is forced
    if ((a->flags & Varnode::typelock)!=0) { // If a is locked
      return;			// Discard b entirely in favor of a
    }
    // Concede confusion about types, set unknown type rather than a or b's type
    a->size = spaceid->wrapOffset(end-a->start);
    a->type = glb->types->getBase(a->size,TYPE_UNKNOWN);
    a->flags = 0;
    a->arrayyes = false;
    a->lowind = 0;
    a->highind = -1;
    return;
  }
  a->size = restype->getSize();
}

void ScopeLocal::restructure(MapState &state,bool warning)

{
  MapRange cur;
  MapRange *next;
 				// This implementation does not allow a range
				// to contain both ~0 and 0
  overlapproblems = false;
  if (!state.initialize()) return; // No references to stack at all

  cur = *state.next();
  while(state.getNext()) {
    next = state.next();
    if (next->sstart < cur.sstart+cur.size) // Do the ranges intersect
      rangeUnion(&cur,next,warning); // Union them
    else {
      if (!rangeAbsorb(&cur,next)) {
	if (cur.arrayyes)
	  cur.size = next->sstart-cur.sstart;
	if (adjustFit(cur))
	  createEntry(cur);
	cur = *next;
      }
    }
  }
				// The last range is artificial so we don't
				// build an entry for it
}

void ScopeLocal::markUnaliased(const vector<uintb> &alias)

{ // Mark all local symbols for which there are no aliases
  EntryMap *rangemap = maptable[spaceid->getIndex()];
  if (rangemap == (EntryMap *)0) return;
  list<SymbolEntry>::iterator iter,enditer;

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
      if (symbol->isTypeLocked())
	aliason = false;
    }
  }
}

void ScopeLocal::fakeInputSymbols(void)

{ // We create fake input symbols on the stack
  int4 lockedinputs = getCategorySize(0);
  VarnodeDefSet::const_iterator iter,enditer;

  iter = fd->beginDef(Varnode::input);
  enditer = fd->endDef(Varnode::input);

  while(iter != enditer) {
    Varnode *vn = *iter++;
    bool locked = vn->isTypeLock();
    Address addr = vn->getAddr();
    if (addr.getSpace() != spaceid) continue;
    // Only allow offsets which can be parameters
    if (!fd->getFuncProto().getParamRange().inRange(addr,1)) continue;
    uintb endpoint = addr.getOffset() + vn->getSize() - 1;
    while(iter != enditer) {
      vn = *iter;
      if (vn->getSpace() != spaceid) break;
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
      int4 index = -1;		// NOT a parameter
      string nm = buildVariableName(addr,usepoint,ct,index,Varnode::input);
      try {
	addSymbol(nm,ct,addr,usepoint)->getSymbol();
      }
      catch(LowlevelError &err) {
	fd->warningHeader(err.explain);
      }
      //      setCategory(sym,0,index);
    }
  }
}

bool ScopeLocal::makeNameRecommendation(string &res,const Address &addr,const Address &usepoint) const

{
  map<AddressSorter,string>::const_iterator iter;
  iter = name_recommend.find( AddressSorter(addr,usepoint,0) );
  if (iter != name_recommend.end()) {
    res = (*iter).second;
    return true;
  }
  return false;
}

void ScopeLocal::makeNameRecommendationsForSymbols(vector<string> &resname,vector<Symbol *> &ressym) const

{ 				// Find nameable symbols with a varnode rep matching a name recommendation
  map<AddressSorter,string>::const_iterator iter;
  for(iter=name_recommend.begin();iter!=name_recommend.end();++iter) {
    VarnodeLocSet::const_iterator biter,eiter;
    bool isaddrtied;
    const Address &addr((*iter).first.getAddr());
    const Address &useaddr((*iter).first.getUseAddr());
    int4 size = (*iter).first.getSize();
    if (useaddr.isInvalid()) {
      isaddrtied = true;
      biter = fd->beginLoc(size,addr);
      eiter = fd->endLoc(size,addr);
    }
    else {
      isaddrtied = false;
      biter = fd->beginLoc(size,addr,useaddr);
      eiter = fd->endLoc(size,addr,useaddr);
    }
    while(biter != eiter) {
      Varnode *vn = *biter;
      if (!vn->isAnnotation()) {
	Symbol *sym = vn->getHigh()->getSymbol();
	if (sym != (Symbol *)0) {
	  if (sym->isNameUndefined()) {
	    resname.push_back( (*iter).second);
	    ressym.push_back(sym);
	    break;
	  }
	}
      }
      if (isaddrtied) break;
      ++biter;
    }
  }
}

void ScopeLocal::addRecommendName(const Address &addr,const Address &usepoint,const string &nm,int4 sz)

{ // Add a recommended name for a local symbol
  name_recommend[ AddressSorter(addr,usepoint,sz) ] = nm;
}

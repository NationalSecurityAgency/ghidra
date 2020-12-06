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
#include "database_ghidra.hh"
#include "funcdata.hh"

Scope *ScopeGhidra::buildSubScope(uint8 id,const string &nm)

{
  return new ScopeGhidraNamespace(id,nm,ghidra);
}

/// \param g is the Architecture and connection to the Ghidra client
///
ScopeGhidra::ScopeGhidra(ArchitectureGhidra *g)
  : Scope(0,"",g,this)
{
  ghidra = g;
  cache = new ScopeInternal(0,"",g,this);
  cacheDirty = false;
}

ScopeGhidra::~ScopeGhidra(void)

{
  delete cache;
}

/// The Ghidra client reports a \e namespace id associated with
/// Symbol. Determine if a matching \e namespace Scope already exists in the cache and build
/// it if it isn't. This may mean creating a new \e namespace Scope.
/// \param id is the ID associated with the Ghidra namespace
/// \return the Scope matching the id.
Scope *ScopeGhidra::reresolveScope(uint8 id) const

{
  if (id == 0) return cache;
  Database *symboltab = ghidra->symboltab;
  Scope *cacheScope = symboltab->resolveScope(id);
  if (cacheScope != (Scope *)0)
    return cacheScope;		// Scope was previously cached

  Document *doc = ghidra->getNamespacePath(id);
  if (doc == (Document *)0)
    throw LowlevelError("Could not get namespace info");

  Scope *curscope = symboltab->getGlobalScope();	// Get pointer to ourselves (which is not const)
  try {
    const List &list(doc->getRoot()->getChildren());
    List::const_iterator iter = list.begin();
    ++iter;		// Skip element describing the root scope
    while(iter != list.end()) {
      const Element *el = *iter;
      ++iter;
      uint8 scopeId;
      istringstream s(el->getAttributeValue("id"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> scopeId;
      curscope = symboltab->findCreateScope(scopeId, el->getContent(), curscope);
    }
    delete doc;
  }
  catch(LowlevelError &err) {
    delete doc;
    throw err;
  }
  return curscope;
}

/// The Ghidra client can respond to a query negatively by sending a
/// \<hole> tag, which describes the (largest) range of addresses containing
/// the query address that do not have any Symbol mapped to them. This object
/// stores this information in the \b holes map, which it consults to avoid
/// sending queries for the same unmapped address repeatedly. The tag may
/// also contain boolean property information about the memory range, which
/// also gets stored.
/// \param el is the \<hole> element
void ScopeGhidra::processHole(const Element *el) const

{
  Range range;
  range.restoreXml(el,ghidra);
  holes.insertRange(range.getSpace(),range.getFirst(),range.getLast());
  uint4 flags = 0;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if ((el->getAttributeName(i)=="readonly")&&
	xml_readbool(el->getAttributeValue(i)))
      flags |= Varnode::readonly;
    else if ((el->getAttributeName(i)=="volatile")&&
	     xml_readbool(el->getAttributeValue(i)))
      flags |= Varnode::volatil;
  }
  if (flags != 0) {
    ghidra->symboltab->setPropertyRange(flags,range);
    cacheDirty = true;
  }
}

/// Build the global object described by the XML document
/// and put it in the cache. The XML can either be a
/// \<hole> tag, describing the absence of symbols at the queried
/// address, or one of the symbol tags
/// \param doc is the XML document
/// \return the newly constructed Symbol or NULL if there was a hole
Symbol *ScopeGhidra::dump2Cache(Document *doc) const

{
  const Element *el = doc->getRoot();
  Symbol *sym = (Symbol *)0;

  if (el->getName() == "hole") {
    processHole(el);
    return sym;
  }

  List::const_iterator iter = el->getChildren().begin();
  uint8 scopeId;
  {
    istringstream s(el->getAttributeValue("id"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> scopeId;
  }

  Scope *scope = reresolveScope(scopeId);
  el = *iter;
  try {
    sym = scope->addMapSym(el);
  }
  catch(RecovError &err) {
    // Duplicate name error (when trying to create the new function's scope)
    // Check for function object where the full size is not stored in the cache
    // Entries for functions always start at the entry address
    // of the function in order to deal with non-contiguous functions
    // But ghidra will still return the function for queries at addresses in the
    // interior of the function
    const Element *symel = *el->getChildren().begin();
    if (symel->getName() == "function") {	// Make sure new record is for a function
      const Element *baseAddrEl = *symel->getChildren().begin();
      Address baseaddr = Address::restoreXml( baseAddrEl, glb );	// Decode address from record
      vector<Symbol *> symList;
      scope->queryByName(symel->getAttributeValue("name"),symList);	// Lookup symbols with duplicate name
      for(int4 i=0;i<symList.size();++i) {
	FunctionSymbol *funcSym = dynamic_cast<FunctionSymbol *>(symList[i]);
	if (funcSym != (FunctionSymbol *)0) {				// If duplicate symbol is for function
	  if (funcSym->getFunction()->getAddress() == baseaddr) {	//   and the address matches
	    sym = funcSym;						// use the old symbol
	    break;
	  }
	}
      }
    }
    if (sym == (Symbol *)0) {
      ostringstream s;
      s << err.explain << ": entry didn't cache";
      throw LowlevelError(s.str());
    }
  }
  if (sym != (Symbol *)0) {
    SymbolEntry *entry = sym->getFirstWholeMap();
    if (entry != (SymbolEntry *)0) {
      if (scope != cache) {	// We have a namespace cache
	// With a global namespace, mark the address range as a "hole", so the same query won't
	// go up again.  With this limitation, a function can only refer to a single global symbol at a
	// a given address
 	AddrSpace *spc = entry->getAddr().getSpace();
 	uintb first = entry->getAddr().getOffset();
	uintb last = first+entry->getSize()-1;
	holes.insertRange(spc,first,last);
      }
// 	// Add a range to the namespace, so that -map_scope-
// 	// can pick up references to this symbol
// 	ghidra->symboltab->addRange(scope,spc,first,last);

// The decompiler does not currently maintain properties itself
// So we need to cache any properties returned by the query
      uint4 props = sym->getFlags() & (Varnode::readonly | Varnode::volatil);
      if (props != 0) {
	Range rng(entry->getAddr().getSpace(),entry->getFirst(),entry->getLast());
	ghidra->symboltab->setPropertyRange(props,rng);
	cacheDirty = true;
      }
//       uint4 flags = ghidra->symboltab->getProperty(entry->getAddr());
//       if (flags != 0)
// 	scope->setAttribute(sym,flags);
    }
  }
  return sym;
}

/// Determine if the given address should be sent to the Ghidra client
/// at all, by checking the hole map and other factors.
/// If it passes, send the query to the client, process the result,
/// and update the cache. If a Symbol is ultimately recovered, return it.
/// \param addr is the address to potentially query
/// \return the matching Symbol or NULL if there is hole
Symbol *ScopeGhidra::removeQuery(const Address &addr) const

{
  Document *doc;
  Symbol *sym = (Symbol *)0;

  // Don't send up queries on constants or uniques
  //  if (addr.getSpace()->getType() != IPTR_PROCESSOR) return sym;
  //  if (!cache->inScope(addr,1,Address())) return (Symbol *)0;

  // There is an efficiency/functionality trade-off problem here.
  // We don't want to send every address query up to Ghidra
  // as this is inefficient. Previously we only sent up if the
  // the address was in the discovery scope, but there is the
  // possibility that there is a global symbol that is not in
  // the discovery scope.  Now we send up if there is ANY
  // part of the space the address is in that is part of the
  // discovery scope.
  if (addr.getSpace()->getIndex() >= spacerange.size())
    return (Symbol *)0;
  if (spacerange[addr.getSpace()->getIndex()] == 0)
    return (Symbol *)0;

  // Have we queried this address before
  if (holes.inRange(addr,1)) return (Symbol *)0;
  doc = ghidra->getMappedSymbolsXML(addr); // Query GHIDRA about this address
  if (doc != (Document *)0) {
    sym = dump2Cache(doc);	// Add it to the cache
    delete doc;
  }
  return sym;
}

void ScopeGhidra::addRange(AddrSpace *spc,uintb first,uintb last)

{
  Scope::addRange(spc,first,last);
  int4 ind = spc->getIndex();	// Mark all spaces that have a range
  while(spacerange.size() <= ind)
    spacerange.push_back(0);
  spacerange[ind] = 1;
}

void ScopeGhidra::clear(void)

{
  cache->clear();
  holes.clear();
  if (cacheDirty) {
    ghidra->symboltab->setProperties(flagbaseDefault); // Restore database properties to defaults
    cacheDirty = false;
  }
}

SymbolEntry *ScopeGhidra::findAddr(const Address &addr,
					    const Address &usepoint) const
{
  SymbolEntry *entry;
  entry = cache->findAddr(addr,usepoint);
  if (entry == (SymbolEntry *)0) { // Didn't find symbol
    entry = cache->findContainer(addr,1,Address());
    if (entry != (SymbolEntry *)0)
      return (SymbolEntry *)0;	// Address is already queried, but symbol doesn't start at our address
    Symbol *sym = removeQuery(addr); // Query server
    if (sym != (Symbol *)0)
      entry = sym->getMapEntry(addr);
    // entry may be null for certain queries, ghidra may return symbol of size <8 with
    // address equal to START of function, even though the query was for an address INTERNAL to the function
  }
  if ((entry != (SymbolEntry *)0)&&(entry->getAddr()==addr))
    return entry;
  return (SymbolEntry *)0;
}

SymbolEntry *ScopeGhidra::findContainer(const Address &addr,int4 size,
						 const Address &usepoint) const
{
  SymbolEntry *entry;
  entry = cache->findClosestFit(addr,size,usepoint);
  if (entry == (SymbolEntry *)0) {
    Symbol *sym = removeQuery(addr);
    if (sym != (Symbol *)0)
      entry = sym->getMapEntry(addr);
    // entry may be null for certain queries, ghidra may return symbol of size <8 with
    // address equal to START of function, even though the query was for an address INTERNAL to the function
  }
  if (entry != (SymbolEntry *)0) {
    // Entry contains addr, does it contain addr+size
    uintb last = entry->getAddr().getOffset() + entry->getSize() -1;
    if (last >= addr.getOffset() + size-1)
      return entry;
  }
  return (SymbolEntry *)0;
}

ExternRefSymbol *ScopeGhidra::findExternalRef(const Address &addr) const

{
  ExternRefSymbol *sym;
  sym = cache->findExternalRef(addr);
  if (sym == (ExternRefSymbol *)0) {
    // Check if this address has already been queried,
    // (returning a symbol other than an external ref symbol)
    SymbolEntry *entry;
    entry = cache->findContainer(addr,1,Address());
    if (entry == (SymbolEntry *)0)
      sym = dynamic_cast<ExternRefSymbol *>(removeQuery(addr));
  }
  return sym;
}

Funcdata *ScopeGhidra::findFunction(const Address &addr) const

{
  Funcdata *fd = cache->findFunction(addr);
  if (fd == (Funcdata *)0) {
    // Check if this address has already been queried,
    // (returning a symbol other than a function_symbol)
    SymbolEntry *entry = cache->findContainer(addr,1,Address());
    if (entry == (SymbolEntry *)0) {
      FunctionSymbol *sym;
      sym = dynamic_cast<FunctionSymbol *>(removeQuery(addr));
      if (sym != (FunctionSymbol *)0)
	fd = sym->getFunction();
    }
  }
  return fd;
}

LabSymbol *ScopeGhidra::findCodeLabel(const Address &addr) const

{
  LabSymbol *sym;
  sym = cache->findCodeLabel(addr);
  if (sym == (LabSymbol *)0) {
    // Check if this address has already been queried,
    // (returning a symbol other than a code label)
    SymbolEntry *entry;
    entry = cache->findAddr(addr,Address());
    if (entry == (SymbolEntry *)0) {
      string symname = ghidra->getCodeLabel(addr);	// Do the remote query
      if (!symname.empty())
	sym = cache->addCodeLabel(addr,symname);
    }
  }
  return sym;
}

Funcdata *ScopeGhidra::resolveExternalRefFunction(ExternRefSymbol *sym) const

{
  Funcdata *fd = (Funcdata *)0;
  const Scope *basescope = ghidra->symboltab->mapScope(this,sym->getRefAddr(),Address());
  // Truncate search at this scope, we don't want
  // the usual remote_query if the function isn't in cache
  // this won't recover external functions, but will just
  // return the externalref symbol again
  stackFunction(basescope,this,sym->getRefAddr(),&fd);
  if (fd == (Funcdata *)0)
    fd = cache->findFunction(sym->getRefAddr());
  if (fd == (Funcdata *)0) {
    // If the function isn't in cache, we use the special
    // getExternalRefXML interface to recover the external function
    Document *doc;
    SymbolEntry *entry = sym->getFirstWholeMap();
    doc = ghidra->getExternalRefXML(entry->getAddr());
    if (doc != (Document *)0) {
      FunctionSymbol *sym;
      // Make sure referenced function is cached
      sym = dynamic_cast<FunctionSymbol *>(dump2Cache(doc));
      delete doc;
      if (sym != (FunctionSymbol *)0)
	fd = sym->getFunction();
    }
  }
  return fd;
}

SymbolEntry *ScopeGhidra::addSymbol(const string &name,Datatype *ct,
					      const Address &addr,const Address &usepoint)
{
  // We do not inform Ghidra of the new symbol, we just
  // stick it in the cache.  This allows the mapglobals action
  // to build global variables that Ghidra knows nothing about
  return cache->addSymbol(name,ct,addr,usepoint);
}

SymbolEntry *ScopeGhidraNamespace::addMapInternal(Symbol *sym,uint4 exfl,const Address &addr,int4 off,int4 sz,
						  const RangeList &uselim)
{
  SymbolEntry *res;
  res = ScopeInternal::addMapInternal(sym,exfl,addr,off,sz,uselim);
  glb->symboltab->addRange(this,res->getAddr().getSpace(),res->getFirst(),res->getLast());
  return res;
}

bool ScopeGhidraNamespace::isNameUsed(const string &nm,const Scope *op2) const

{
  if (ArchitectureGhidra::isDynamicSymbolName(nm))
    return false;		// Just assume default FUN_ and DAT_ names don't collide
  const ScopeGhidraNamespace *otherScope = dynamic_cast<const ScopeGhidraNamespace *>(op2);
  uint8 otherId = (otherScope != (const ScopeGhidraNamespace *)0) ? otherScope->getId() : 0;
  return ghidra->isNameUsed(nm, uniqueId, otherId);
}

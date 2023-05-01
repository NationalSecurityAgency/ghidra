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

namespace ghidra {

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

  PackedDecode decoder(ghidra);
  if (!ghidra->getNamespacePath(id,decoder))
    throw LowlevelError("Could not get namespace info");

  Scope *curscope = symboltab->getGlobalScope();	// Get pointer to ourselves (which is not const)
  uint4 elemId = decoder.openElement();
  uint4 subId = decoder.openElement();
  decoder.closeElementSkipping(subId);		// Skip element describing the root scope
  for(;;) {
    subId = decoder.openElement();
    if (subId == 0) break;
    uint8 scopeId = decoder.readUnsignedInteger(ATTRIB_ID);
    curscope = symboltab->findCreateScope(scopeId, decoder.readString(ATTRIB_CONTENT), curscope);
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
  return curscope;
}

/// The Ghidra client can respond to a query negatively by sending a
/// \<hole> element, which describes the (largest) range of addresses containing
/// the query address that do not have any Symbol mapped to them. This object
/// stores this information in the \b holes map, which it consults to avoid
/// sending queries for the same unmapped address repeatedly. The tag may
/// also contain boolean property information about the memory range, which
/// also gets stored.
/// \param decoder is the stream decoder
void ScopeGhidra::decodeHole(Decoder &decoder) const

{
  uint4 elemId = decoder.openElement(ELEM_HOLE);
  uint4 flags = 0;
  Range range;
  range.decodeFromAttributes(decoder);
  decoder.rewindAttributes();
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId==ATTRIB_READONLY &&  decoder.readBool())
      flags |= Varnode::readonly;
    else if (attribId==ATTRIB_VOLATILE && decoder.readBool())
      flags |= Varnode::volatil;
  }
  holes.insertRange(range.getSpace(),range.getFirst(),range.getLast());
  decoder.closeElement(elemId);
  if (flags != 0) {
    ghidra->symboltab->setPropertyRange(flags,range);
    cacheDirty = true;
  }
}

/// Build the global object described by the stream element
/// and put it in the cache. The element can either be a \<hole>, describing the absence
/// of symbols at the queried address, or one of the symbol elements.
/// \param decoder is the stream decoder
/// \return the newly constructed Symbol or NULL if there was a hole
Symbol *ScopeGhidra::dump2Cache(Decoder &decoder) const

{
  Symbol *sym = (Symbol *)0;

  uint4 elemId = decoder.peekElement();
  if (elemId == ELEM_HOLE) {
    decodeHole(decoder);
    return sym;
  }

  decoder.openElement();
  uint8 scopeId = decoder.readUnsignedInteger(ATTRIB_ID);
  Scope *scope = reresolveScope(scopeId);

  try {
    sym = scope->addMapSym(decoder);
    decoder.closeElement(elemId);
  }
  catch(DuplicateFunctionError &err) {
    // Duplicate name error (when trying to create the new function's scope)
    // Check for function object where the full size is not stored in the cache
    // Entries for functions always start at the entry address
    // of the function in order to deal with non-contiguous functions
    // But ghidra will still return the function for queries at addresses in the
    // interior of the function
    if (!err.address.isInvalid()) {	// Make sure the address was parsed
      vector<Symbol *> symList;
      scope->queryByName(err.functionName,symList);	// Lookup symbols with duplicate name
      for(int4 i=0;i<symList.size();++i) {
	FunctionSymbol *funcSym = dynamic_cast<FunctionSymbol *>(symList[i]);
	if (funcSym != (FunctionSymbol *)0) {				// If duplicate symbol is for function
	  if (funcSym->getFunction()->getAddress() == err.address) {	//   and the address matches
	    sym = funcSym;						// use the old symbol
	    break;
	  }
	}
      }
    }
    if (sym == (Symbol *)0)
      throw LowlevelError("DuplicateFunctionError, but could not recover original symbol");
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
  PackedDecode decoder(ghidra);
  if (ghidra->getMappedSymbolsXML(addr,decoder)) {	// Query GHIDRA about this address
    sym = dump2Cache(decoder);	// Add it to the cache
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
  Funcdata *resFd = cache->findFunction(addr);
  if (resFd == (Funcdata *)0) {
    // Check if this address has already been queried,
    // (returning a symbol other than a function_symbol)
    SymbolEntry *entry = cache->findContainer(addr,1,Address());
    if (entry == (SymbolEntry *)0) {
      FunctionSymbol *sym;
      sym = dynamic_cast<FunctionSymbol *>(removeQuery(addr));
      if (sym != (FunctionSymbol *)0)
	resFd = sym->getFunction();
    }
  }
  return resFd;
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
  Funcdata *resFd = (Funcdata *)0;
  const Scope *basescope = ghidra->symboltab->mapScope(this,sym->getRefAddr(),Address());
  // Truncate search at this scope, we don't want
  // the usual remote_query if the function isn't in cache
  // this won't recover external functions, but will just
  // return the externalref symbol again
  stackFunction(basescope,this,sym->getRefAddr(),&resFd);
  if (resFd == (Funcdata *)0)
    resFd = cache->findFunction(sym->getRefAddr());
  if (resFd == (Funcdata *)0) {
    // If the function isn't in cache, we use the special
    // getExternalRefXML interface to recover the external function
    PackedDecode decoder(ghidra);
    SymbolEntry *entry = sym->getFirstWholeMap();
    if (ghidra->getExternalRef(entry->getAddr(),decoder)) {
      FunctionSymbol *funcSym;
      // Make sure referenced function is cached
      funcSym = dynamic_cast<FunctionSymbol *>(dump2Cache(decoder));
      if (funcSym != (FunctionSymbol *)0)
	resFd = funcSym->getFunction();
    }
  }
  return resFd;
}

SymbolEntry *ScopeGhidra::addSymbol(const string &nm,Datatype *ct,
				    const Address &addr,const Address &usepoint)
{
  // We do not inform Ghidra of the new symbol, we just
  // stick it in the cache.  This allows the mapglobals action
  // to build global variables that Ghidra knows nothing about
  return cache->addSymbol(nm,ct,addr,usepoint);
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

} // End namespace ghidra

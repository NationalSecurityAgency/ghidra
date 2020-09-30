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
/// \file database_ghidra.hh
/// \brief Facilities for retrieving symbol information from a Ghidra client

#ifndef __DATABASE_GHIDRA__
#define __DATABASE_GHIDRA__

#include "database.hh"
#include "ghidra_arch.hh"

/// \brief An implementation of the Scope interface by querying a Ghidra client for Symbol information
///
/// This object is generally instantiated once for an executable and
/// acts as the \e global \e scope for the decompiler. Queries for
/// symbol information are forwarded to the Ghidra client and the response is cached.
/// This object fields queries for all scopes above functions.
/// Responses may be for Symbol objects that are not global but belong to sub-scopes,
/// like \e namespace and function Scopes.  This object will build any new Scope or Funcdata,
/// object as necessary and stick the Symbol in, returning as if the new Scope
/// had caught the query in the first place.
class ScopeGhidra : public Scope {
  ArchitectureGhidra *ghidra;		///< Architecture and connection to the Ghidra client
  mutable ScopeInternal *cache;		///< An internal cache of previously fetched Symbol objects
  mutable RangeList holes;		///< List of (queried) memory ranges with no Symbol in them
  vector<int4> spacerange;		///< List of address spaces that are in the global range
  partmap<Address,uint4> flagbaseDefault;	///< Default boolean properties on memory
  mutable bool cacheDirty;		///< Is flagbaseDefault different from cache
  Symbol *dump2Cache(Document *doc) const;			///< Parse a response into the cache
  Symbol *removeQuery(const Address &addr) const;		///< Process a query that missed the cache
  void processHole(const Element *el) const;			///< Process a response describing a hole
  Scope *reresolveScope(uint8 id) const;	///< Find the Scope that will contain a result Symbol
  virtual void addRange(AddrSpace *spc,uintb first,uintb last);
  virtual void removeRange(AddrSpace *spc,uintb first,uintb last) {
    throw LowlevelError("remove_range should not be performed on ghidra scope");
  }
  virtual Scope *buildSubScope(uint8 id,const string &nm);
  virtual void addSymbolInternal(Symbol *sym) { throw LowlevelError("add_symbol_internal unimplemented"); }
  virtual SymbolEntry *addMapInternal(Symbol *sym,uint4 exfl,const Address &addr,int4 off,int4 sz,
				      const RangeList &uselim) { throw LowlevelError("addMap unimplemented"); }
  virtual SymbolEntry *addDynamicMapInternal(Symbol *sym,uint4 exfl,uint8 hash,int4 off,int4 sz,
					     const RangeList &uselim) { throw LowlevelError("addMap unimplemented"); }
public:
  ScopeGhidra(ArchitectureGhidra *g);	///< Constructor

  /// \brief Lock in the default state of the boolean property map
  ///
  /// When \b this Scope gets created, parsing of .pspec and .cspec files may lay down
  /// property information about memory before any the load-image is consulted.
  /// This method locks creates a copy of this state of memory, so the decompiler
  /// can reset to it before decompiling a new function.
  void lockDefaultProperties(void) { flagbaseDefault = ghidra->symboltab->getProperties(); cacheDirty = false; }
  virtual ~ScopeGhidra(void);
  virtual void clear(void);
  virtual SymbolEntry *addSymbol(const string &name,Datatype *ct,
				 const Address &addr,const Address &usepoint);
  virtual string buildVariableName(const Address &addr,
				   const Address &pc,
				   Datatype *ct,int4 &index,uint4 flags) const {
    return cache->buildVariableName(addr,pc,ct,index,flags); }
  virtual string buildUndefinedName(void) const { return cache->buildUndefinedName(); }
  virtual void setAttribute(Symbol *sym,uint4 attr) { cache->setAttribute(sym,attr); }
  virtual void clearAttribute(Symbol *sym,uint4 attr) { cache->clearAttribute(sym,attr); }
  virtual void setDisplayFormat(Symbol *sym,uint4 attr) { cache->setDisplayFormat(sym,attr); }

  virtual void adjustCaches(void) { cache->adjustCaches(); }
  virtual SymbolEntry *findAddr(const Address &addr,const Address &usepoint) const;
  virtual SymbolEntry *findContainer(const Address &addr,int4 size,
					const Address &usepoint) const;
  virtual SymbolEntry *findClosestFit(const Address &addr,int4 size,
					 const Address &usepoint) const {
    throw LowlevelError("findClosestFit unimplemented"); }
  virtual Funcdata *findFunction(const Address &addr) const;
  virtual ExternRefSymbol *findExternalRef(const Address &addr) const;
  virtual LabSymbol *findCodeLabel(const Address &addr) const;
  virtual Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const;

  virtual SymbolEntry *findOverlap(const Address &addr,int4 size) const { throw LowlevelError("findOverlap unimplemented"); }
  virtual void findByName(const string &name,vector<Symbol *> &res) const { throw LowlevelError("findByName unimplemented"); }
  virtual bool isNameUsed(const string &nm,const Scope *op2) const { throw LowlevelError("isNameUsed unimplemented"); }

  virtual MapIterator begin(void) const { throw LowlevelError("begin unimplemented"); }
  virtual MapIterator end(void) const { throw LowlevelError("end unimplemented"); }
  virtual list<SymbolEntry>::const_iterator beginDynamic(void) const { throw LowlevelError("beginDynamic unimplemented"); }
  virtual list<SymbolEntry>::const_iterator endDynamic(void) const { throw LowlevelError("endDynamic unimplemented"); }
  virtual list<SymbolEntry>::iterator beginDynamic(void) { throw LowlevelError("beginDynamic unimplemented"); }
  virtual list<SymbolEntry>::iterator endDynamic(void) { throw LowlevelError("endDynamic unimplemented"); }
  virtual void clearCategory(int4 cat) { throw LowlevelError("clearCategory unimplemented"); }
  virtual void clearUnlockedCategory(int4 cat) { throw LowlevelError("clearUnlockedCategory unimplemented"); }
  virtual void clearUnlocked(void) { throw LowlevelError("clearUnlocked unimplemented"); }
  virtual void restrictScope(Funcdata *f) { throw LowlevelError("restrictScope unimplemented"); }
  virtual void removeSymbolMappings(Symbol *symbol) { throw LowlevelError("removeSymbolMappings unimplemented"); }
  virtual void removeSymbol(Symbol *symbol) { throw LowlevelError("removeSymbol unimplemented"); }
  virtual void renameSymbol(Symbol *sym,const string &newname) { throw LowlevelError("renameSymbol unimplemented"); }
  virtual void retypeSymbol(Symbol *sym,Datatype *ct) { throw LowlevelError("retypeSymbol unimplemented"); }
  virtual string makeNameUnique(const string &nm) const { throw LowlevelError("makeNameUnique unimplemented"); }
  virtual void saveXml(ostream &s) const { throw LowlevelError("saveXml unimplemented"); }
  virtual void restoreXml(const Element *el) { throw LowlevelError("restoreXml unimplemented"); }
  virtual void printEntries(ostream &s) const { throw LowlevelError("printEntries unimplemented"); }
  virtual int4 getCategorySize(int4 cat) const { throw LowlevelError("getCategorySize unimplemented"); }
  virtual Symbol *getCategorySymbol(int4 cat,int4 ind) const { throw LowlevelError("getCategorySymbol unimplemented"); }
  virtual void setCategory(Symbol *sym,int4 cat,int4 ind) { throw LowlevelError("setCategory unimplemented"); }
};

/// \brief A global \e namespace Scope
///
/// The only difference between \b this and a ScopeInternal is that this scope
/// builds up its \e ownership range with the symbols that are placed in it.
/// This allows Database::mapScope() to recover the \e namespace Scope for symbols
/// that have been placed in it. Queries for \e namespace symbols
/// that haven't been cached yet percolate up to the global scope, which must
/// be a ScopeGhidra.  This will query the Ghidra client on behalf of the \e namespace and
/// register any new symbols with \b this Scope.
class ScopeGhidraNamespace : public ScopeInternal {
  friend class ScopeGhidra;
  ArchitectureGhidra *ghidra;		///< Connection to the Ghidra client
protected:
  virtual SymbolEntry *addMapInternal(Symbol *sym,uint4 exfl,const Address &addr,int4 off,int4 sz,
				      const RangeList &uselim);
public:
  ScopeGhidraNamespace(uint8 id,const string &nm,ArchitectureGhidra *g)
    : ScopeInternal(id,nm,g) { ghidra = g; }		///< Constructor

  virtual bool isNameUsed(const string &nm,const Scope *op2) const;
};

#endif

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
/// \file varmap.hh
/// \brief Classes for keeping track of local variables and reconstructing stack layout

#ifndef __CPUI_VARMAP__
#define __CPUI_VARMAP__

#include "database.hh"

/// \brief A symbol name recommendation with its associated storage location
///
/// The name is associated with a static Address and use point in the code. Symbols
/// present at the end of function decompilation without a name can acquire \b this name
/// if their storage matches.
class NameRecommend {
  Address addr;			///< The starting address of the storage location
  Address useaddr;		///< The code address at the point of use
  int4 size;			///< An optional/recommended size for the variable being stored
  string name;			///< The local symbol name recommendation
  uint8 symbolId;		///< Id associated with the original Symbol
public:
  NameRecommend(const Address &ad,const Address &use,int4 sz,const string &nm,uint8 id) :
    addr(ad), useaddr(use), size(sz), name(nm), symbolId(id) {} ///< Constructor
  const Address &getAddr(void) const { return addr; }	///< Get the storage address
  const Address &getUseAddr(void) const { return useaddr; }	///< Get the use point address
  int4 getSize(void) const { return size; }			///< Get the optional size
  string getName(void) const { return name; }			///< Get the recommended name
  uint8 getSymbolId(void) const { return symbolId; }		///< Get the original Symbol id
};

/// \brief A name recommendation for a particular dynamic storage location
///
/// A recommendation for a symbol name whose storage is dynamic. The storage
/// is identified using the DynamicHash mechanism and may or may not exist.
class DynamicRecommend {
  Address usePoint;		///< Use point of the Symbol
  uint8 hash;			///< Hash encoding the Symbols environment
  string name;			///< The local symbol name recommendation
  uint8 symbolId;		///< Id associated with the original Symbol
public:
  DynamicRecommend(const Address &addr,uint8 h,const string &nm,uint8 id) :
    usePoint(addr), hash(h), name(nm), symbolId(id) {}	///< Constructor
  const Address &getAddress(void) const { return usePoint; }	///< Get the use point address
  uint8 getHash(void) const { return hash; }			///< Get the dynamic hash
  string getName(void) const { return name; }			///< Get the recommended name
  uint8 getSymbolId(void) const { return symbolId; }		///< Get the original Symbol id
};

/// \brief Data-type for a storage location when there is no Symbol (yet)
///
/// Allow a data-type to be fed into a specific storage location.  Currently
/// this only applies to input Varnodes.
class TypeRecommend {
  Address addr;		///< Storage address of the Varnode
  Datatype *dataType;	///< Data-type to assign to the Varnode
public:
  TypeRecommend(const Address &ad,Datatype *dt) :
    addr(ad), dataType(dt) {}	///< Constructor
  const Address &getAddress(void) const { return addr; }	///< Get the storage address
  Datatype *getType(void) const { return dataType; }		///< Get the data-type
};

/// \brief Partial data-type information mapped to a specific range of bytes
///
/// This object gives a hint about the data-type for a sequence of bytes
/// starting at a specific address offset (typically on the stack). It describes
/// where the data-type starts, what data-type it might be, and how far it extends
/// from the start point (possibly as an array).
class RangeHint {
  friend class MapState;
  friend class ScopeLocal;
public:
  /// \brief The basic categorization of the range
  enum RangeType {
    fixed = 0,		///< A data-type with a fixed size
    open = 1,		///< An array with a (possibly unknown) number of elements
    endpoint = 2	///< An (artificial) boundary to the range of bytes getting analyzed
  };
private:
  uintb start;		///< Starting offset of \b this range of bytes
  int4 size;		///< Number of bytes in a single element of this range
  intb sstart;		///< A signed version of the starting offset
  Datatype *type;	///< Putative data-type for a single element of this range
  uint4 flags;		///< Additional boolean properties of this range
  RangeType rangeType;	///< The type of range
  int4 highind;		///< Minimum upper bound on the array index (if \b this is \e open)
public:
  RangeHint(void) {}	///< Uninitialized constructor
  RangeHint(uintb st,int4 sz,intb sst,Datatype *ct,uint4 fl,RangeType rt,int4 hi) {
    start=st; size=sz; sstart=sst; type=ct; flags=fl; rangeType = rt; highind=hi; }	///< Initialized constructor
  bool reconcile(const RangeHint *b) const;
  bool contain(const RangeHint *b) const;
  bool preferred(const RangeHint *b,bool reconcile) const;
  bool absorb(RangeHint *b);	///< Try to absorb the other RangeHint into \b this
  bool merge(RangeHint *b,AddrSpace *space,TypeFactory *typeFactory);	///< Try to form the union of \b this with another RangeHint
  int4 compare(const RangeHint &op2) const;		///< Order \b this with another RangeHint
  static bool compareRanges(const RangeHint *a,const RangeHint *b) { return (a->compare(*b) < 0); }	///< Compare two RangeHint pointers
};

class ProtoModel;
class LoadGuard;

/// \brief A light-weight class for analyzing pointers and aliasing on the stack
///
/// The gather() method looks for pointer references into a specific AddressSpace
/// (usually the stack). Then hasLocalAlias() checks if a specific Varnode within
/// the AddressSpace is (possibly) aliased by one of the gathered pointer references.
class AliasChecker {
public:
  /// \brief A helper class holding a Varnode pointer reference and a possible index added to it
  struct AddBase {
    Varnode *base;		///< The Varnode holding the base pointer
    Varnode *index;		///< The index value or NULL
    AddBase(Varnode *b,Varnode *i) { base=b; index=i; }	///< Constructor
  };
private:
  const Funcdata *fd;		///< Function being searched for aliases
  AddrSpace *space;		///< AddressSpace in which to search
  mutable vector<AddBase> addBase; ///< Collection of pointers into the AddressSpace
  mutable vector<uintb> alias;	///< List of aliased addresses (as offsets)
  mutable bool calculated;	///< Have aliases been calculated
  uintb localExtreme;		///< Largest possible offset for a local variable
  uintb localBoundary;		///< Boundary offset separating locals and parameters
  mutable uintb aliasBoundary;	///< Shallowest alias
  int4 direction;		///< 1=stack grows negative, -1=positive
  void deriveBoundaries(const FuncProto &proto);	///< Set up basic boundaries for the stack layout
  void gatherInternal(void) const;	///< Run through Varnodes looking for pointers into the stack
public:
  AliasChecker() { fd = (const Funcdata *)0; space = (AddrSpace *)0; calculated=false; }	///< Constructor
  void gather(const Funcdata *f,AddrSpace *spc,bool defer);		///< Gather Varnodes that point on the stack
  bool hasLocalAlias(Varnode *vn) const;	///< Return \b true if it looks like the given Varnode is aliased by a pointer
  void sortAlias(void) const;			///< Sort the alias starting offsets
  const vector<AddBase> &getAddBase(void) const { return addBase; }	///< Get the collection of pointer Varnodes
  const vector<uintb> &getAlias(void) const { return alias; }		///< Get the list of alias starting offsets
  static void gatherAdditiveBase(Varnode *startvn,vector<AddBase> &addbase);
  static uintb gatherOffset(Varnode *vn);
};

/// \brief A container for hints about the data-type layout of an address space
///
/// A collection of data-type hints for the address space (as RangeHint objects) can
/// be collected from Varnodes, HighVariables or other sources, using the
/// gatherVarnodes(), gatherHighs(), and gatherOpen() methods. This class can then sort
/// and iterate through the RangeHint objects.
class MapState {
  AddrSpace *spaceid;			///< The address space being analyzed
  RangeList range;			///< The subset of ranges, within the whole address space to analyze
  vector<RangeHint *> maplist;		///< The list of collected RangeHints
  vector<RangeHint *>::iterator iter;	///< The current iterator into the RangeHints
  Datatype *defaultType;		///< The default data-type to use for RangeHints
  AliasChecker checker;			///< A collection of pointer Varnodes into our address space
  void addGuard(const LoadGuard &guard,OpCode opc,TypeFactory *typeFactory);	///< Add LoadGuard record as a hint to the collection
  void addRange(uintb st,Datatype *ct,uint4 fl,RangeHint::RangeType rt,int4 hi);	///< Add a hint to the collection
  void reconcileDatatypes(void);	///< Decide on data-type for RangeHints at the same address
public:
#ifdef OPACTION_DEBUG
  mutable bool debugon;
  mutable Architecture *glb;
  void turnOnDebug(Architecture *g) const { debugon = true; glb=g; }
  void turnOffDebug(void) const { debugon = false; }
#endif
  MapState(AddrSpace *spc,const RangeList &rn,const RangeList &pm,Datatype *dt);	///< Constructor
  ~MapState(void);		///< Destructor
  bool initialize(void);	///< Initialize the hint collection for iteration
  void sortAlias(void) { checker.sortAlias(); }		///< Sort the alias starting offsets
  const vector<uintb> &getAlias(void) { return checker.getAlias(); }	///< Get the list of alias starting offsets
  void gatherSymbols(const EntryMap *rangemap);		///< Add Symbol information as hints to the collection
  void gatherVarnodes(const Funcdata &fd);		///< Add stack Varnodes as hints to the collection
  void gatherHighs(const Funcdata &fd);			///< Add HighVariables as hints to the collection
  void gatherOpen(const Funcdata &fd);			///< Add pointer references as hints to the collection
  RangeHint *next(void) { return *iter; }		///< Get the current RangeHint in the collection
  bool getNext(void) { ++iter; if (iter==maplist.end()) return false; return true; }	///< Advance the iterator, return \b true if another hint is available
};

/// \brief A Symbol scope for \e local variables of a particular function.
///
/// This acts like any other variable Scope, but is associated with a specific function
/// and the address space where the function maps its local variables and parameters, typically
/// the \e stack space. This object in addition to managing the local Symbols, builds up information
/// about the \e stack address space: what portions of it are used for mapped local variables, what
/// portions are used for temporary storage (not mapped), and what portion is for parameters.
class ScopeLocal : public ScopeInternal {
  AddrSpace *space;		///< Address space containing the local stack
  RangeList localRange;		///< The set of addresses that might hold mapped locals (not parameters)
  list<NameRecommend> nameRecommend;	///< Symbol name recommendations for specific addresses
  list<DynamicRecommend> dynRecommend;		///< Symbol name recommendations for dynamic locations
  list<TypeRecommend> typeRecommend;	///< Data-types for specific storage locations
  bool stackGrowsNegative;	///< Marked \b true if the stack is considered to \e grow towards smaller offsets
  bool rangeLocked;		///< True if the subset of addresses \e mapped to \b this scope has been locked
  bool adjustFit(RangeHint &a) const;	///< Make the given RangeHint fit in the current Symbol map
  void createEntry(const RangeHint &a);	///< Create a Symbol entry corresponding to the given (fitted) RangeHint
  bool restructure(MapState &state);	///< Merge hints into a formal Symbol layout of the address space
  void markUnaliased(const vector<uintb> &alias);	///< Mark all local symbols for which there are no aliases
  void fakeInputSymbols(void);		///< Make sure all stack inputs have an associated Symbol
  void addRecommendName(Symbol *sym);	///< Convert the given symbol to a name recommendation
  void collectNameRecs(void);		///< Collect names of unlocked Symbols on the stack
public:
  ScopeLocal(uint8 id,AddrSpace *spc,Funcdata *fd,Architecture *g);	///< Constructor
  virtual ~ScopeLocal(void) {}	///< Destructor

  AddrSpace *getSpaceId(void) const { return space; }		///< Get the associated (stack) address space

  /// \brief Is this a storage location for \e unaffected registers
  ///
  /// \param vn is the Varnode storing an \e unaffected register
  /// \return \b true is the Varnode can be used as unaffected storage
  bool isUnaffectedStorage(Varnode *vn) const { return (vn->getSpace() == space); }

  void markNotMapped(AddrSpace *spc,uintb first,int4 sz,bool param);	///< Mark a specific address range is not mapped

				// Routines that are specific to one address space
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
  virtual string buildVariableName(const Address &addr,
				   const Address &pc,
				   Datatype *ct,
				   int4 &index,uint4 flags) const;
  void resetLocalWindow(void);	///< Reset the set of addresses that are considered mapped by the scope to the default
  void restructureVarnode(bool aliasyes);	///< Layout mapped symbols based on Varnode information
  void restructureHigh(void);			///< Layout mapped symbols based on HighVariable information
  SymbolEntry *remapSymbol(Symbol *sym,const Address &addr,const Address &usepoint);
  SymbolEntry *remapSymbolDynamic(Symbol *sym,uint8 hash,const Address &usepoint);
  void recoverNameRecommendationsForSymbols(void);
  void applyTypeRecommendations(void);		///< Try to apply recommended data-type information
};

#endif

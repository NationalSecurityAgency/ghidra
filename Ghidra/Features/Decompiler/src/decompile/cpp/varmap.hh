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
// Structure for dealing with local variables

#ifndef __CPUI_VARMAP__
#define __CPUI_VARMAP__

#include "database.hh"

class AddressSorter {
  Address addr;
  Address useaddr;
  int4 size;			// Recommended size
public:
  AddressSorter(const Address &ad,const Address &use,int4 sz);
  AddressSorter(const AddressSorter &op2) : addr(op2.addr), useaddr(op2.useaddr) { size = op2.size; }
  const Address &getAddr(void) const { return addr; }
  const Address &getUseAddr(void) const { return useaddr; }
  int4 getSize(void) const { return size; }
  bool operator<(const AddressSorter &op2) const;
  bool operator==(const AddressSorter &op2) const;
  bool operator!=(const AddressSorter &op2) const;
};

// All offsets are byte based (as opposed to unit based)

// Structure for internal map layout
struct MapRange {
  uintb start;			// Start of range
  int4 size;
  intb sstart;			// Signed version of start point
  Datatype *type;
  uint4 flags;
  bool arrayyes;
  int4 lowind;			// Lower bound of index
  int4 highind;			// Upper bound of index
  MapRange(void) {}
  MapRange(uintb st,int4 sz,intb sst,Datatype *ct,uint4 fl,bool ay,int4 lo,int4 hi) {
    start=st; size=sz; sstart=sst; type=ct; flags=fl; arrayyes=ay; lowind=lo; highind=hi; }
};

class ProtoModel;

class AliasChecker {
public:
  struct AddBase {
    Varnode *base;
    Varnode *index;
    AddBase(Varnode *b,Varnode *i) { base=b; index=i; }
  };
private:
  const Funcdata *fd;	// getFuncdata to search for aliases
  AddrSpace *spaceid;		// Space in which to search
  mutable vector<AddBase> addbase; // Collection of pointer exprs
  mutable vector<uintb> alias;	// List of aliased addresses
  mutable bool calculated;	// Are aliases cached
  uintb localextreme;		// Local varible which is deepest on stack
  uintb localboundary;		// Boundary between locals and parameters
  mutable uintb aliasboundary;	// Shallowest alias
  int4 direction;		// 1=stack grows negative, -1=positive
  void deriveBoundaries(const FuncProto &proto);
  void gatherInternal(void) const;
public:
  AliasChecker() { fd = (const Funcdata *)0; spaceid = (AddrSpace *)0; calculated=false; }
  void gather(const Funcdata *f,AddrSpace *spc,bool defer);
  bool hasLocalAlias(Varnode *vn) const;
  void sortAlias(void) const;
  const vector<AddBase> &getAddBase(void) const { return addbase; }
  const vector<uintb> &getAlias(void) const { return alias; }
  static void gatherAdditiveBase(Varnode *startvn,vector<AddBase> &addbase); // Gather result varnodes for all \e sums that \b startvn is involved in
  static uintb gatherOffset(Varnode *vn); // If \b vn is a sum result, return the constant portion of this sum
};

class MapState {
  AddrSpace *spaceid;
  RangeList range;
  vector<MapRange *> maplist;
  vector<MapRange *>::iterator iter;
  Datatype *default_type;
  AliasChecker checker;
public:
#ifdef OPACTION_DEBUG
  mutable bool debugon;
  mutable Architecture *glb;
  void turnOnDebug(Architecture *g) const { debugon = true; glb=g; }
  void turnOffDebug(void) const { debugon = false; }
#endif
  MapState(AddrSpace *spc,const RangeList &rn,const RangeList &pm,Datatype *dt);
  ~MapState(void);
  void addRange(uintb st,Datatype *ct,uint4 fl,bool ay,int4 lo,int4 hi);
  void addRange(const EntryMap *rangemap);
  bool initialize(void);
  void sortAlias(void) { checker.sortAlias(); }
  const vector<uintb> &getAlias(void) { return checker.getAlias(); }
  void gatherVarnodes(const Funcdata &fd);
  void gatherHighs(const Funcdata &fd);
  void gatherOpen(const Funcdata &fd);
  MapRange *next(void) { return *iter; }
  bool getNext(void) { ++iter; if (iter==maplist.end()) return false; return true; }
};

class ScopeLocal : public ScopeInternal {
  enum { range_locked=1 };
  AddrSpace *spaceid;		// Space containing main local stack
  bool stackgrowsnegative;
  RangeList localrange;		// Address ranges that might hold mapped locals (not parameters)
  bool overlapproblems;		// Cached problem flag
  uint4 qflags;
  map<AddressSorter,string> name_recommend;
  bool adjustFit(MapRange &a) const;
  void createEntry(const MapRange &a);
  bool rangeAbsorb(MapRange *a,MapRange *b);
  void rangeUnion(MapRange *a,MapRange *b,bool warning);
  void restructure(MapState &state,bool warning);
  void markUnaliased(const vector<uintb> &alias);
  void fakeInputSymbols(void);
  void collectNameRecs(void);
public:
  ScopeLocal(AddrSpace *spc,Funcdata *fd,Architecture *g);
  virtual ~ScopeLocal(void) {}

  AddrSpace *getSpaceId(void) const { return spaceid; }
  bool isUnaffectedStorage(Varnode *vn) const { return (vn->getSpace() == spaceid); }
  void markNotMapped(AddrSpace *spc,uintb first,int4 sz,bool param);

				// Routines that are specific to one address space
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
  virtual string buildVariableName(const Address &addr,
				   const Address &pc,
				   Datatype *ct,
				   int4 &index,uint4 flags) const;
  void resetLocalWindow(void);
  void restructureVarnode(bool aliasyes);
  void restructureHigh(void);
  bool makeNameRecommendation(string &res,const Address &addr,const Address &usepoint) const;
  void makeNameRecommendationsForSymbols(vector<string> &resname,vector<Symbol *> &ressym) const;
  void addRecommendName(const Address &addr,const Address &usepoint,const string &nm,int4 sz);
};

#endif

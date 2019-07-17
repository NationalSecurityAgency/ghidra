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
#ifndef __CPUI_CALLGRAPH__
#define __CPUI_CALLGRAPH__

#include "address.hh"

// Forward declarations
class Architecture;
class Funcdata;
class CallGraphNode;
class CallGraph;

class CallGraphEdge {
public:
  enum {
    cycle = 1,			// Edge that was snipped to eliminate cycles
    dontfollow = 2		// Edge that is not in the spanning tree
  };
private:
  friend class CallGraphNode;
  friend class CallGraph;
  CallGraphNode *from;		// Node of the caller
  CallGraphNode *to;		// Node of the callee
  Address callsiteaddr;		// Address where call was made from
  int4 complement;		// Index of complementary edge
  mutable uint4 flags;
public:
  CallGraphEdge(void) { flags = 0; }
  bool isCycle(void) const { return ((flags&1)!=0); }
  void saveXml(ostream &s) const;
  const Address &getCallSiteAddr(void) const { return callsiteaddr; }
  static void restoreXml(const Element *el,CallGraph *graph);
};

class CallGraphNode {
public:
  enum {
    mark = 1,
    onlycyclein = 2,
    currentcycle = 4,
    entrynode = 8
  };
private:
  friend class CallGraph;
  Address entryaddr;		// Starting address of function
  string name;			// Name of the function if available
  Funcdata *fd;			// Pointer to funcdata if we have it
  vector<CallGraphEdge> inedge;
  vector<CallGraphEdge> outedge;
  int4 parentedge;		// Incoming edge for spanning tree
  mutable uint4 flags;
public:
  CallGraphNode(void) { fd = (Funcdata *)0; flags = 0; parentedge = -1; }
  void clearMark(void) const { flags &= ~((uint4)mark); }
  bool isMark(void) const { return ((flags&mark)!=0); }
  const Address getAddr(void) const { return entryaddr; }
  const string &getName(void) const { return name; }
  Funcdata *getFuncdata(void) const { return fd; }
  int4 numInEdge(void) const { return inedge.size(); }
  const CallGraphEdge &getInEdge(int4 i) const { return inedge[i]; }
  CallGraphNode *getInNode(int4 i) const { return inedge[i].from; }
  int4 numOutEdge(void) const { return outedge.size(); }
  const CallGraphEdge &getOutEdge(int4 i) const { return outedge[i]; }
  CallGraphNode *getOutNode(int4 i) const { return outedge[i].to; }
  void setFuncdata(Funcdata *f);
  void saveXml(ostream &s) const;
  static void restoreXml(const Element *el,CallGraph *graph);
};

struct LeafIterator {
  CallGraphNode *node;
  int4 outslot;
  LeafIterator(CallGraphNode *n) { node=n; outslot = 0; }
};

class Scope;		// forward declaration
class CallGraph {
  Architecture *glb;
  map<Address,CallGraphNode> graph; // Nodes in the graph sorted by address
  vector<CallGraphNode *> seeds;
  bool findNoEntry(vector<CallGraphNode *> &seeds);
  void snipCycles(CallGraphNode *node);
  void snipEdge(CallGraphNode *node,int4 i);
  void clearMarks(void);
  void cycleStructure(void);
  CallGraphNode *popPossible(CallGraphNode *node,int4 &outslot);
  CallGraphNode *pushPossible(CallGraphNode *node,int4 outslot);
  CallGraphEdge &insertBlankEdge(CallGraphNode *node,int4 slot);
  void iterateScopesRecursive(Scope *scope);
  void iterateFunctionsAddrOrder(Scope *scope);
public:
  CallGraph(Architecture *g) { glb = g; }
  Architecture *getArch(void) const { return glb; }
  CallGraphNode *addNode(Funcdata *f);
  CallGraphNode *addNode(const Address &addr,const string &nm);
  CallGraphNode *findNode(const Address &addr);
  void addEdge(CallGraphNode *from,CallGraphNode *to,const Address &addr);
  void deleteInEdge(CallGraphNode *node,int4 i);
  CallGraphNode * initLeafWalk(void);
  CallGraphNode *nextLeaf(CallGraphNode *node);
  map<Address,CallGraphNode>::iterator begin(void) { return graph.begin(); }
  map<Address,CallGraphNode>::iterator end(void) { return graph.end(); }
  void buildAllNodes(void);
  void buildEdges(Funcdata *fd);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el);
};

#endif

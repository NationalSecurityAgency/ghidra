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
#include "callgraph.hh"
#include "funcdata.hh"

void CallGraphEdge::saveXml(ostream &s) const

{
  s << "  <edge>\n";
  s << "    ";
  from->getAddr().saveXml(s);
  s << "\n    ";
  to->getAddr().saveXml(s);
  s << "\n    ";
  callsiteaddr.saveXml(s);
  s << "\n  </edge>\n";
}

void CallGraphEdge::restoreXml(const Element *el,CallGraph *graph)

{
  const AddrSpaceManager *manage = graph->getArch();
  Address fromaddr,toaddr,siteaddr;
  
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  fromaddr = Address::restoreXml(*iter,manage);
  ++iter;
  toaddr = Address::restoreXml(*iter,manage);
  ++iter;
  siteaddr = Address::restoreXml(*iter,manage);

  CallGraphNode *fromnode = graph->findNode(fromaddr);
  if (fromnode == (CallGraphNode *)0)
    throw LowlevelError("Could not find from node");
  CallGraphNode *tonode = graph->findNode(toaddr);
  if (tonode == (CallGraphNode *)0)
    throw LowlevelError("Could not find to node");

  graph->addEdge(fromnode,tonode,siteaddr);
}

void CallGraphNode::setFuncdata(Funcdata *f)

{
  if ((fd != (Funcdata *)0)&&(fd != f))
    throw LowlevelError("Multiple functions at one address in callgraph");

  if (f->getAddress() != entryaddr)
    throw LowlevelError("Setting function data at wrong address in callgraph");
  fd = f;
}

void CallGraphNode::saveXml(ostream &s) const

{
  s << "  <node";
  if (name.size() != 0)
    a_v(s,"name",name);
  s << ">\n    ";
  entryaddr.saveXml(s);
  s << "\n  </node>\n";
}

void CallGraphNode::restoreXml(const Element *el,CallGraph *graph)

{
  int4 num = el->getNumAttributes();
  string name;
  for(int4 i=0;i<num;++i) {
    if (el->getAttributeName(i) == "name")
      name = el->getAttributeValue(i);
  }
  Address addr = Address::restoreXml(*el->getChildren().begin(),graph->getArch());

  graph->addNode(addr,name);
}

bool CallGraph::findNoEntry(vector<CallGraphNode *> &seeds)

{ // Find all functions (that are not already marked) that either have no in edges at all,
  // or have no in edges that haven't been snipped as part of cycles

  map<Address,CallGraphNode>::iterator iter;
  CallGraphNode *lownode = (CallGraphNode *)0;
  bool allcovered = true;
  bool newseeds = false;

  for(iter=graph.begin();iter!=graph.end();++iter) {
    CallGraphNode &node( (*iter).second );
    if (node.isMark()) continue;
    if ((node.inedge.size() == 0)||((node.flags&CallGraphNode::onlycyclein)!=0)) {
      seeds.push_back(&node);
      node.flags |= CallGraphNode::mark | CallGraphNode::entrynode;
      newseeds = true;
    }
    else {
      allcovered = false;
      // We need to worry about the case where everything is in a cycle, so we don't find a natural root
      // We use the node with the lowest number of in edges as a pseudo root
      if (lownode == (CallGraphNode *)0)
	lownode = &node;
      else {
	if (node.numInEdge() < lownode->numInEdge())
	  lownode = &node;
      }
    }
  }
  if ((!newseeds)&&(!allcovered)) {
    seeds.push_back(lownode);
    lownode->flags |= CallGraphNode::mark | CallGraphNode::entrynode;
  }
  return allcovered;
}

void CallGraph::snipCycles(CallGraphNode *node)

{ // Snip any cycles starting from root -node-
  CallGraphNode *next;
  vector<LeafIterator> stack;

  node->flags |= CallGraphNode::currentcycle;
  stack.push_back(LeafIterator(node));

  while(!stack.empty()) {
    CallGraphNode *cur = stack.back().node; // Current node
    int4 st = stack.back().outslot; // which out edge we will follow
    if (st >= cur->outedge.size()) {
      cur->flags &= ~((uint4)CallGraphNode::currentcycle);
      stack.pop_back();
    }
    else {
      stack.back().outslot += 1;
      if ((cur->outedge[st].flags&CallGraphEdge::cycle)!=0) continue;
      next = cur->outedge[st].to;
      if ((next->flags&CallGraphNode::currentcycle)!=0) { // Found a cycle
	snipEdge(cur,st);
	continue;
      }
      else if ((next->flags&CallGraphNode::mark)!=0) {	// Already traced before
	cur->outedge[st].flags |= CallGraphEdge::dontfollow;
	continue;
      }
      next->parentedge = cur->outedge[st].complement;
      next->flags |= (CallGraphNode::currentcycle| CallGraphNode::mark);
      stack.push_back(LeafIterator(next));
    }
  }
}

void CallGraph::snipEdge(CallGraphNode *node,int4 i)

{
  node->outedge[i].flags |= CallGraphEdge::cycle | CallGraphEdge::dontfollow;
  int4 toi = node->outedge[i].complement;
  CallGraphNode *to = node->outedge[i].to;
  to->inedge[toi].flags |= CallGraphEdge::cycle;
  bool onlycycle = true;
  for(uint4 j=0;j<to->inedge.size();++j) {
    if ((to->inedge[j].flags & CallGraphEdge::cycle)==0) {
      onlycycle = false;
      break;
    }
  }
  if (onlycycle)
    to->flags |= CallGraphNode::onlycyclein;
}

void CallGraph::clearMarks(void)

{
  map<Address,CallGraphNode>::iterator iter;

  for(iter=graph.begin();iter!=graph.end();++iter)
    (*iter).second.clearMark();
}

CallGraphEdge &CallGraph::insertBlankEdge(CallGraphNode *node,int4 slot)

{
  node->outedge.emplace_back();
  if (node->outedge.size() > 1) {
    for(int4 i=node->outedge.size()-2;i>=slot;--i) {
      int4 newi = i+1;
      CallGraphEdge &edge( node->outedge[newi] );
      edge = node->outedge[i];
      CallGraphNode *nodeout = edge.to;
      nodeout->inedge[ edge.complement ].complement += 1;
    }
  }
  return node->outedge[slot];
}

CallGraphNode *CallGraph::addNode(Funcdata *f)

{ // Add a node, based on an existing function -f-
  CallGraphNode &node( graph[f->getAddress()] );

  if ((node.getFuncdata() != (Funcdata *)0)&&(node.getFuncdata() != f))
    throw LowlevelError("Functions with duplicate entry points: "+f->getName()+" "+node.getFuncdata()->getName());

  node.entryaddr = f->getAddress();
  node.name = f->getName();
  node.fd = f;
  return &node;
}

CallGraphNode *CallGraph::addNode(const Address &addr,const string &nm)

{
  CallGraphNode &node( graph[addr] );

  node.entryaddr = addr;
  node.name = nm;

  return &node;
}

CallGraphNode *CallGraph::findNode(const Address &addr)

{				// Find function at given address, or return null
  map<Address,CallGraphNode>::iterator iter;

  iter = graph.find(addr);
  if (iter != graph.end())
    return &(*iter).second;
  return (CallGraphNode *)0;
}

void CallGraph::addEdge(CallGraphNode *from,CallGraphNode *to,const Address &addr)

{
  int4 i;
  for(i=0;i<from->outedge.size();++i) {
    CallGraphNode *outnode = from->outedge[i].to;
    if (outnode == to) return;	// Already have an out edge
    if (to->entryaddr < outnode->entryaddr) break;
  }

  CallGraphEdge &fromedge( insertBlankEdge(from,i) );

  int4 toi = to->inedge.size();
  to->inedge.emplace_back();
  CallGraphEdge &toedge( to->inedge.back() );

  fromedge.from = from;
  fromedge.to = to;
  fromedge.callsiteaddr = addr;
  fromedge.complement = toi;

  toedge.from = from;
  toedge.to = to;
  toedge.callsiteaddr = addr;
  toedge.complement = i;
}

void CallGraph::deleteInEdge(CallGraphNode *node,int4 i)

{
  int4 tosize = node->inedge.size();
  int4 fromi = node->inedge[i].complement;
  CallGraphNode *from = node->inedge[i].from;
  int4 fromsize = from->outedge.size();

  for(int4 j=i+1;j<tosize;++j) {
    node->inedge[j-1] = node->inedge[j];
    if (node->inedge[j-1].complement >= fromi)
      node->inedge[j-1].complement -= 1;
  }
  node->inedge.pop_back();
  
  for(int4 j=fromi+1;j<fromsize;++j) {
    from->outedge[j-1] = from->outedge[j];
    if (from->outedge[j-1].complement >= i)
      from->outedge[j-1].complement -= 1;
  }
  from->outedge.pop_back();
}

CallGraphNode *CallGraph::popPossible(CallGraphNode *node,int4 &outslot)

{
  if ((node->flags & CallGraphNode::entrynode)!=0) {
    outslot = node->parentedge;
    return (CallGraphNode *)0;
  }
  outslot = node->inedge[node->parentedge].complement;
  return node->inedge[node->parentedge].from;
}

CallGraphNode *CallGraph::pushPossible(CallGraphNode *node,int4 outslot)

{
  if (node == (CallGraphNode *)0) {
    if (outslot >= seeds.size())
      return (CallGraphNode *)0;
    return seeds[outslot];
  }
  while(outslot < node->outedge.size()) {
    if ((node->outedge[outslot].flags & CallGraphEdge::dontfollow)!=0)
      outslot += 1;
    else
      return node->outedge[outslot].to;
  }
  return (CallGraphNode *)0;
}

CallGraphNode *CallGraph::initLeafWalk(void)

{
  cycleStructure();
  if (seeds.empty()) return (CallGraphNode *)0;
  CallGraphNode *node = seeds[0];
  for(;;) {
    CallGraphNode *pushnode = pushPossible(node,0);
    if (pushnode == (CallGraphNode *)0)
      break;
    node = pushnode;
  }
  return node;
}

CallGraphNode *CallGraph::nextLeaf(CallGraphNode *node)

{
  int4 outslot;
  node = popPossible(node,outslot);
  outslot += 1;
  for(;;) {
    CallGraphNode *pushnode = pushPossible(node,outslot);
    if (pushnode == (CallGraphNode *)0)
      break;
    node = pushnode;
    outslot = 0;
  }
  return node;
}

void CallGraph::cycleStructure(void)

{ // Generate list of seeds nodes (from which we can get to everything)
  if (!seeds.empty())
    return;
  uint4 walked = 0;
  bool allcovered;

  do {
    allcovered = findNoEntry(seeds);
    while(walked < seeds.size()) {
      CallGraphNode *rootnode = seeds[walked];
      rootnode->parentedge = walked;
      snipCycles(rootnode);
      walked += 1;
    }
  } while(!allcovered);
  clearMarks();
}

void CallGraph::iterateScopesRecursive(Scope *scope)

{
  if (!scope->isGlobal()) return;
  iterateFunctionsAddrOrder(scope);
  ScopeMap::const_iterator iter,enditer;
  iter = scope->childrenBegin();
  enditer = scope->childrenEnd();
  for(;iter!=enditer;++iter) {
    iterateScopesRecursive((*iter).second);
  }
}

void CallGraph::iterateFunctionsAddrOrder(Scope *scope)

{
  MapIterator miter,menditer;
  miter = scope->begin();
  menditer = scope->end();
  while(miter != menditer) {
    Symbol *sym = (*miter)->getSymbol();
    FunctionSymbol *fsym = dynamic_cast<FunctionSymbol *>(sym);
    ++miter;
    if (fsym != (FunctionSymbol *)0)
	addNode(fsym->getFunction());
  }
}

void CallGraph::buildAllNodes(void)

{				// Make every function symbol into a node
  iterateScopesRecursive(glb->symboltab->getGlobalScope());
}

void CallGraph::buildEdges(Funcdata *fd)

{				// Build edges from a disassembled (decompiled) function
  CallGraphNode *fdnode = findNode(fd->getAddress());
  CallGraphNode *tonode;
  if (fdnode == (CallGraphNode *)0)
    throw LowlevelError("Function is missing from callgraph");
  if (fd->getFuncProto().getModelExtraPop() == ProtoModel::extrapop_unknown)
    fd->fillinExtrapop();

  int4 numcalls = fd->numCalls();
  for(int4 i=0;i<numcalls;++i) {
    FuncCallSpecs  *fs = fd->getCallSpecs(i);
    Address addr = fs->getEntryAddress();
    if (!addr.isInvalid()) {
      tonode = findNode(addr);
      if (tonode == (CallGraphNode *)0) {
	string name;
	glb->nameFunction(addr,name);
	tonode = addNode(addr,name);
      }
      addEdge(fdnode,tonode,fs->getOp()->getAddr());
    }
  }
}

void CallGraph::saveXml(ostream &s) const

{
  map<Address,CallGraphNode>::const_iterator iter;

  s << "<callgraph>\n";

  for(iter=graph.begin();iter!=graph.end();++iter)
    (*iter).second.saveXml(s);

  // Dump all the "in" edges
  for(iter=graph.begin();iter!=graph.end();++iter) {
    const CallGraphNode &node( (*iter).second );

    for(uint4 i=0;i<node.inedge.size();++i)
      node.inedge[i].saveXml(s);
  }

  s << "</callgraph>\n";
}

void CallGraph::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  while(iter != list.end()) {
    const Element *subel = *iter;
    ++iter;
    if (subel->getName() == "edge")
      CallGraphEdge::restoreXml(subel,this);
    else
      CallGraphNode::restoreXml(subel,this);
  }
}


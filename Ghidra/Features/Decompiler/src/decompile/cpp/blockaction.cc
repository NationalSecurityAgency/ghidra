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
#include "blockaction.hh"
#include "funcdata.hh"

/// Retrieve the current edge (as a \e top FlowBlock and the index of the outgoing edge).
/// If the end-points have been collapsed together, this returns NULL.
/// The top and bottom nodes of the edge are updated to FlowBlocks in the current collapsed graph.
/// \param outedge will hold the index of the edge (outgoing relative to returned FlowBlock)
/// \param graph is the containing BlockGraph
/// \return the current \e top of the edge or NULL
FlowBlock *FloatingEdge::getCurrentEdge(int4 &outedge,FlowBlock *graph)

{
  while(top->getParent() != graph)
    top = top->getParent();	// Move up through collapse hierarchy to current graph
  while(bottom->getParent() != graph)
    bottom = bottom->getParent();
  outedge = top->getOutIndex(bottom);
  if (outedge < 0)
    return (FlowBlock *)0;	// Edge does not exist (any longer)
  return top;
}

/// \brief Find blocks in containing loop that aren't in \b this
///
/// Assuming \b this has all of its nodes marked, find all additional nodes that create the
/// body of the \b container loop. Mark these and put them in \b body list.
/// \param container is a loop that contains \b this
/// \param body will hold blocks in the body of the container that aren't in \b this
void LoopBody::extendToContainer(const LoopBody &container,vector<FlowBlock *> &body) const

{
  int4 i = 0;
  if (!container.head->isMark()) { // container head may already be in subloop, if not
    container.head->setMark();		// add it to new body
    body.push_back(container.head);
    i = 1;		// make sure we don't traverse back from it
  }
  for(int4 j=0;j<container.tails.size();++j) {
    FlowBlock *tail = container.tails[j];
    if (!tail->isMark()) {	// container tail may already be in subloop, if not
      tail->setMark();
      body.push_back(tail);	// add to body, make sure we DO traverse back from it
    }
  }
  // -this- head is already marked, but hasn't been traversed
  if (head != container.head) { // Unless the container has the same head, traverse the contained head
    int4 sizein = head->sizeIn();
    for(int4 k=0;k<sizein;++k) {
      if (head->isGotoIn(k)) continue; // Don't trace back through irreducible edges
      FlowBlock *bl = head->getIn(k);
      if (bl->isMark()) continue; // Already in list
      bl->setMark();
      body.push_back(bl);
    }
  }
  
  while(i < body.size()) {
    FlowBlock *curblock = body[i++];
    int4 sizein = curblock->sizeIn();
    for(int4 k=0;k<sizein;++k) {
      if (curblock->isGotoIn(k)) continue; // Don't trace back through irreducible edges
      FlowBlock *bl = curblock->getIn(k);
      if (bl->isMark()) continue; // Already in list
      bl->setMark();
      body.push_back(bl);
    }
  }
}

/// This updates the \b head and \b tail nodes to FlowBlock in the current collapsed graph.
/// This returns the first \b tail and passes back the head.
/// \param top is where \b head is passed back
/// \param graph is the containing control-flow structure
/// \return the current loop \b head
FlowBlock *LoopBody::getCurrentBounds(FlowBlock **top,FlowBlock *graph)

{
  while(head->getParent() != graph)
    head = head->getParent();	// Move up through collapse hierarchy to current graph
  FlowBlock *bottom;
  for(int4 i=0;i<tails.size();++i) {
    bottom = tails[i];
    while(bottom->getParent() != graph)
      bottom = bottom->getParent();
    tails[i] = bottom;
    if (bottom != head) {	// If the loop hasn't been fully collapsed yet
      *top = head;
      return bottom;
    }
  }
  return (FlowBlock *)0;
}

/// Collect all FlowBlock nodes that reach a \b tail of the loop without going through \b head.
/// Put them in a list and mark them.
/// \param body will contain the body nodes
void LoopBody::findBase(vector<FlowBlock *> &body)

{
  head->setMark();
  body.push_back(head);
  for(int4 j=0;j<tails.size();++j) {
    FlowBlock *tail = tails[j];
    if (!tail->isMark()) {
      tail->setMark();
      body.push_back(tail);
    }
  }
  uniquecount = body.size();	// Number of nodes that either head or tail
  int4 i=1;
  while(i < body.size()) {
    FlowBlock *curblock = body[i++];
    int4 sizein = curblock->sizeIn();
    for(int4 k=0;k<sizein;++k) {
      if (curblock->isGotoIn(k)) continue; // Don't trace back through irreducible edges
      FlowBlock *bl = curblock->getIn(k);
      if (bl->isMark()) continue; // Already in list
      bl->setMark();
      body.push_back(bl);
    }
  }
}

/// Extend the \b body of this loop to every FlowBlock that can be reached
/// \b only from \b head without hitting the \b exitblock.
/// Assume \b body has been filled out by findBase() and that all these blocks have their mark set.
/// \param body contains the current loop body and will be extended
void LoopBody::extend(vector<FlowBlock *> &body) const

{
  vector<FlowBlock *> trial;
  int4 i=0;
  while(i<body.size()) {
    FlowBlock *bl = body[i++];
    int4 sizeout = bl->sizeOut();
    for(int4 j=0;j<sizeout;++j) {
      if (bl->isGotoOut(j)) continue; // Don't extend through goto edge
      FlowBlock *curbl = bl->getOut(j);
      if (curbl->isMark()) continue;
      if (curbl == exitblock) continue;
      int4 count = curbl->getVisitCount();
      if (count == 0)
	trial.push_back(curbl);	// New possible extension
      count += 1;
      curbl->setVisitCount(count);
      if (count == curbl->sizeIn()) {
	curbl->setMark();
	body.push_back(curbl);
      }
    }
  }
  for(i=0;i<trial.size();++i)
    trial[i]->setVisitCount(0); // Make sure to clear the count
}

/// A structured loop is allowed at most one exit block: pick this block.
/// First build a set of trial exits, preferring from a \b tail, then from  \b head,
/// then from the middle. If there is no containing loop, just return the first such exit we find.
/// \param body is the list FlowBlock objects in the loop body, which we assume are marked.
void LoopBody::findExit(const vector<FlowBlock *> &body)

{
  vector<FlowBlock *> trialexit;
  FlowBlock *tail;

  for(int4 j=0;j<tails.size();++j) {
    tail = tails[j];
    int4 sizeout = tail->sizeOut();

    for(int4 i=0;i<sizeout;++i) {
      if (tail->isGotoOut(i)) continue; // Don't use goto as exit edge
      FlowBlock *curbl = tail->getOut(i);
      if (!curbl->isMark()) {
	if (immed_container == (LoopBody *)0) {
	  exitblock = curbl;
	  return;
	}
	trialexit.push_back(curbl);
      }
    }
  }

  for(int4 i=0;i<body.size();++i) {
    FlowBlock *bl = body[i];
    if ((i>0)&&(i<uniquecount)) continue; // Filter out tails (processed previously)
    int4 sizeout = bl->sizeOut();
    for(int4 j=0;j<sizeout;++j) {
      if (bl->isGotoOut(j)) continue; // Don't use goto as exit edge
      FlowBlock *curbl = bl->getOut(j);
      if (!curbl->isMark()) {
	if (immed_container == (LoopBody *)0) {
	  exitblock = curbl;
	  return;
	}
	trialexit.push_back(curbl);
      }
    }
  }
  
  exitblock = (FlowBlock *)0; // Default exit is null, if no block meeting condition can be found
  if (trialexit.empty())
    return;

  // If there is a containing loop, force exitblock to be in the containing loop
  if (immed_container != (LoopBody *)0) {
    vector<FlowBlock *> extension;
    extendToContainer(*immed_container,extension);
    for(int4 i=0;i<trialexit.size();++i) {
      FlowBlock *bl = trialexit[i];
      if (bl->isMark()) {
	exitblock = bl;
	break;
      }
    }
    clearMarks(extension);
  }
}

/// The idea is if there is more than one \b tail for a loop, some tails are more "preferred" than others
/// and should have their exit edges preserved longer and be the target of the DAG path.
/// Currently we look for a single \b tail that has an outgoing edge to the \b exitblock and
/// make sure it is the first tail.
void LoopBody::orderTails(void)

{
  if (tails.size() <= 1) return;
  if (exitblock == (FlowBlock *)0) return;
  int4 prefindex;
  FlowBlock *trial;
  for(prefindex=0;prefindex < tails.size(); ++prefindex) {
    trial = tails[prefindex];
    int4 sizeout = trial->sizeOut();
    int4 j;
    for(j=0;j<sizeout;++j)
      if (trial->getOut(j) == exitblock) break;
    if (j<sizeout) break;
  }
  if (prefindex >= tails.size()) return;
  if (prefindex == 0) return;
  tails[prefindex] = tails[0];	// Swap preferred tail into the first position
  tails[0] = trial;
}

/// Label any edge that leaves the set of nodes in \b body.
/// Put the edges in priority for removal,  middle exit at front, \e head exit, then \e tail exit.
/// We assume all the FlowBlock nodes in \b body have been marked.
/// \param body is list of nodes in \b this loop body
void LoopBody::labelExitEdges(const vector<FlowBlock *> &body)

{
  vector<FlowBlock *> toexitblock;
  for(int4 i=uniquecount;i<body.size();++i) { // For non-head/tail nodes of graph
    FlowBlock *curblock = body[i];
    int4 sizeout = curblock->sizeOut();
    for(int4 k=0;k<sizeout;++k) {
      if (curblock->isGotoOut(k)) continue; // Don't exit through goto edges
      FlowBlock *bl = curblock->getOut(k);
      if (bl == exitblock) {
	toexitblock.push_back(curblock);
	continue; // Postpone exit to exitblock
      }
      if (!bl->isMark())
	exitedges.push_back(FloatingEdge(curblock,bl));
    }
  }
  if (head != (FlowBlock *)0) {
    int4 sizeout = head->sizeOut();
    for(int4 k=0;k<sizeout;++k) {
      if (head->isGotoOut(k)) continue; // Don't exit through goto edges
      FlowBlock *bl = head->getOut(k);
      if (bl == exitblock) {
	toexitblock.push_back(head);
	continue; // Postpone exit to exitblock
      }
      if (!bl->isMark())
	exitedges.push_back(FloatingEdge(head,bl));
    }
  }
  for(int4 i=tails.size()-1;i>=0;--i) {	// Put exits from more preferred tails later
    FlowBlock *curblock = tails[i];
    if (curblock == head) continue;
    int4 sizeout = curblock->sizeOut();
    for(int4 k=0;k<sizeout;++k) {
      if (curblock->isGotoOut(k)) continue; // Don't exit through goto edges
      FlowBlock *bl = curblock->getOut(k);
      if (bl == exitblock) {
	toexitblock.push_back(curblock);
	continue; // Postpone exit to exitblock
      }
      if (!bl->isMark())
	exitedges.push_back(FloatingEdge(curblock,bl));
    }
  }
  for(int4 i=0;i<toexitblock.size();++i) { // Now we do exits to exitblock
    FlowBlock *bl = toexitblock[i];
    exitedges.push_back(FloatingEdge(bl,exitblock));
  }
}

/// \brief Record any loops that \b body contains.
///
/// Search for any loop contained by \b this and update is \b depth and \b immed_container field.
/// \param body is the set of FlowBlock nodes making up this loop
/// \param looporder is the list of known loops
void LoopBody::labelContainments(const vector<FlowBlock *> &body,const vector<LoopBody *> &looporder)

{
  vector<LoopBody *> containlist;

  for(int4 i=0;i<body.size();++i) {
    FlowBlock *curblock = body[i];
    if (curblock != head) {
      LoopBody *subloop = LoopBody::find(curblock,looporder);
      if (subloop != (LoopBody *)0) {
	containlist.push_back(subloop);
	subloop->depth += 1;
      }
    }
  }
  // Note the following code works even though the depth fields may shift during subsequent calls to this routine
  // Once a LoopBody calls this routine
  //    the depth of any contained loop will permanently be bigger than this LoopBody
  //       because any other loop will either
  //         increment the depth of both this LoopBody and any loop that it contains   OR
  //         increment neither the LoopBody  nor a loop it contains  OR
  //         NOT increment the LoopBody but DO increment a contained loop
  // So when the immediate container a of loop b calls this routine
  //         a has a depth greater than any containing LoopBody that has already run
  //         =>  therefore b->immed_container->depth < a->depth    and  a claims the immed_container position
  // Subsequent containers c of a and b, will have c->depth < a->depth because c contains a
  for(int4 i=0;i<containlist.size();++i) { // Keep track of the most immediate container
    LoopBody *lb = containlist[i];
    if ((lb->immed_container == (LoopBody *)0)||(lb->immed_container->depth < depth))
      lb->immed_container = this;
  }
}

/// Add edges that exit from \b this loop body to the list of likely \e gotos,
/// giving them the proper priority.
/// \param likely will hold the exit edges in (reverse) priority order
/// \param graph is the containing control-flow graph
void LoopBody::emitLikelyEdges(list<FloatingEdge> &likely,FlowBlock *graph)

{
  while(head->getParent() != graph)
    head = head->getParent();
  if (exitblock != (FlowBlock *)0) {
    while(exitblock->getParent() != graph)
      exitblock = exitblock->getParent();
  }
  for(int4 i=0;i<tails.size();++i) {
    FlowBlock *tail = tails[i];
    while(tail->getParent() != graph)
      tail = tail->getParent();
    tails[i] = tail;
    if (tail == exitblock)	// If the exitblock was collapsed into the tail, we no longer really have an exit
      exitblock = (FlowBlock *)0;
  }
  list<FloatingEdge>::iterator iter,enditer;
  iter = exitedges.begin();;
  enditer = exitedges.end();
  FlowBlock *holdin = (FlowBlock *)0;
  FlowBlock *holdout = (FlowBlock *)0;
  while(iter != enditer) {
    int4 outedge;
    FlowBlock *inbl = (*iter).getCurrentEdge(outedge,graph);
    ++iter;
    if (inbl == (FlowBlock *)0) continue;
    FlowBlock *outbl = inbl->getOut(outedge);
    if (iter==enditer) {
      if (outbl == exitblock) {	// If this is the official exit edge
	holdin = inbl;		// Hold off putting the edge in list
	holdout = outbl;
	break;
      }
    }
    likely.push_back(FloatingEdge(inbl,outbl));
  }
  for(int4 i=tails.size()-1;i>=0;--i) {	// Go in reverse order, to put out less preferred back-edges first
    if ((holdin!=(FlowBlock *)0)&&(i==0))
      likely.push_back(FloatingEdge(holdin,holdout)); // Put in delayed exit, right before final backedge
    FlowBlock *tail = tails[i];
    int4 sizeout = tail->sizeOut();
    for(int4 j=0;j<sizeout;++j) {
      FlowBlock *bl = tail->getOut(j);
      if (bl == head)		// If out edge to head (back-edge for this loop)
	likely.push_back(FloatingEdge(tail,head)); // emit it
    }
  }
}

/// Exit edges have their f_loop_exit_edge property set.
/// \param graph is the containing control-flow structure
void LoopBody::setExitMarks(FlowBlock *graph)

{
  list<FloatingEdge>::iterator iter;
  for(iter=exitedges.begin();iter!=exitedges.end();++iter) {
    int4 outedge;
    FlowBlock *inloop = (*iter).getCurrentEdge(outedge,graph);
    if (inloop != (FlowBlock *)0)
      inloop->setLoopExit(outedge);
  }
}

/// This clears the f_loop_exit_edge on any edge exiting \b this loop.
/// \param graph is the containing control-flow structure
void LoopBody::clearExitMarks(FlowBlock *graph)

{
  list<FloatingEdge>::iterator iter;
  for(iter=exitedges.begin();iter!=exitedges.end();++iter) {
    int4 outedge;
    FlowBlock *inloop = (*iter).getCurrentEdge(outedge,graph);
    if (inloop != (FlowBlock *)0)
      inloop->clearLoopExit(outedge);
  }
}

/// Look for LoopBody records that share a \b head. Merge each \b tail
/// from one into the other. Set the merged LoopBody \b head to NULL,
/// for later clean up.
/// \param looporder is the list of LoopBody records
void LoopBody::mergeIdenticalHeads(vector<LoopBody *> &looporder)

{
  int4 i=0;
  int4 j=i+1;

  LoopBody *curbody = looporder[i];
  while(j < looporder.size()) {
    LoopBody *nextbody = looporder[j++];
    if (nextbody->head == curbody->head) {
      curbody->addTail( nextbody->tails[0] );
      nextbody->head = (FlowBlock *)0; // Mark this LoopBody as subsumed
    }
    else {
      i += 1;
      looporder[i] = nextbody;
      curbody = nextbody;
    }
  }
  i += 1;			// Total size of merged array
  looporder.resize(i);
}

/// Compare two loops based on the indices of the \b head and then the \e tail.
/// \param a is the first LoopBody to compare
/// \param b is the second LoopBody to compare
/// \return \b true if the first LoopBody comes before the second
bool LoopBody::compare_ends(LoopBody *a,LoopBody *b)

{
  int4 aindex = a->head->getIndex();
  int4 bindex = b->head->getIndex();
  if (aindex != bindex)
    return (aindex < bindex);
  aindex = a->tails[0]->getIndex(); // Only compare the first tail
  bindex = b->tails[0]->getIndex();
  return (aindex < bindex);
}

/// Compare two loops based on the indices of the \b head
/// \param a is the first LoopBody to compare
/// \param looptop is the second
/// \return -1,0, or 1 if the first is ordered before, the same, or after the second
int4 LoopBody::compare_head(LoopBody *a,FlowBlock *looptop)

{
  int4 aindex = a->head->getIndex();
  int4 bindex = looptop->getIndex();
  if (aindex != bindex)
    return (aindex < bindex) ? -1 : 1;
  return 0;
}

void TraceDAG::BranchPoint::createTraces(void)

{
  int4 sizeout = top->sizeOut();
  for(int4 i=0;i<sizeout;++i) {
    if (!top->isLoopDAGOut(i)) continue;
    paths.push_back( new BlockTrace(this,paths.size(),i) );
  }
}

void TraceDAG::BranchPoint::markPath(void)

{
  BranchPoint *cur = this;
  do {
    cur->ismark = !cur->ismark;
    cur = cur->parent;
  } while(cur != (BranchPoint *)0);
}

/// The \e distance is the number of edges from \b this up to the common
/// ancestor plus the number of edges down to the other BranchPoint.
/// We assume that \b this has had its path up to the root marked.
/// \param op2 is the other BranchPoint
/// \return the distance
int4 TraceDAG::BranchPoint::distance(BranchPoint *op2)

{
  // find the common ancestor
  BranchPoint *cur = op2;
  do {
    if (cur->ismark) {	// Found the common ancestor
      return (depth - cur->depth) + (op2->depth - cur->depth);
    }
    cur = cur->parent;
  } while(cur != (BranchPoint *)0);
  return depth + op2->depth + 1;
}

/// Get the first FlowBlock along the i-th BlockTrace path.
/// \param i is the index of the path
/// \return the first FlowBlock along the path
FlowBlock *TraceDAG::BranchPoint::getPathStart(int4 i)

{
  int4 res=0;
  int4 sizeout = top->sizeOut();
  for(int4 j=0;j<sizeout;++j) {
    if (!top->isLoopDAGOut(j)) continue;
    if (res == i)
      return top->getOut(j);
    res += 1;
  }
  return (FlowBlock *)0;
}

TraceDAG::BranchPoint::BranchPoint(void)

{
  parent = (BranchPoint *)0;
  depth = 0;
  pathout = -1;
  ismark = false;
  top = (FlowBlock *)0;
}

TraceDAG::BranchPoint::BranchPoint(BlockTrace *parenttrace)

{
  parent = parenttrace->top;
  depth = parent->depth + 1;
  pathout = parenttrace->pathout;
  ismark = false;
  top = parenttrace->destnode;
  createTraces();
}

TraceDAG::BranchPoint::~BranchPoint(void)

{
  for(int4 i=0;i<paths.size();++i)
    delete paths[i];
}

/// \param t is the parent BranchPoint
/// \param po is the index of the formal \e path out of the BranchPoint to \b this
/// \param eo is the edge index out of the BranchPoints root FlowBlock
TraceDAG::BlockTrace::BlockTrace(BranchPoint *t,int4 po,int4 eo)

{
  flags = 0;
  top = t;
  pathout = po;
  bottom = top->top;
  destnode = bottom->getOut(eo);
  edgelump = 1;
  derivedbp = (BranchPoint *)0;
}

/// Attach BlockTrace to a virtual root BranchPoint, where there
/// isn't an explicit FlowBlock acting as branch point.
/// \param root is the virtual BranchPoint
/// \param po is the \e path out the BranchPoint to \b this
/// \param bl is the first FlowBlock along the path
TraceDAG::BlockTrace::BlockTrace(BranchPoint *root,int4 po,FlowBlock *bl)

{
  flags = 0;
  top = root;
  pathout = po;
  bottom = (FlowBlock *)0;
  destnode = bl;
  edgelump = 1;
  derivedbp = (BranchPoint *)0;
}

/// \param op2 is the other BadEdgeScore to compare with \b this
/// \return true if \b this is LESS likely to be the bad edge than \b op2
bool TraceDAG::BadEdgeScore::compareFinal(const BadEdgeScore &op2) const

{
  if (siblingedge != op2.siblingedge)
    return (op2.siblingedge < siblingedge); // A bigger sibling edge is less likely to be the bad edge
  // A sibling edge is more important than a terminal edge.  Terminal edges have the most effect on
  // node-joined returns, which usually doesn't happen on a switch edge, whereas switch's frequently
  // exit to a terminal node
  if (terminal !=op2.terminal)
    return (terminal < op2.terminal);
  if (distance != op2.distance)
    return (distance < op2.distance); // Less distance between branchpoints means less likely to be bad
  return (trace->top->depth < op2.trace->top->depth); // Less depth means less likely to be bad
}

/// Comparator for grouping BlockTraces with the same exit block and parent BranchPoint
/// \param op2 is the other BadEdgeScore to compare to
/// \return \b true is \b this should be ordered before \b op2
bool TraceDAG::BadEdgeScore::operator<(const BadEdgeScore &op2) const

{
  int4 thisind = exitproto->getIndex();
  int4 op2ind = op2.exitproto->getIndex();
  if (thisind != op2ind)	// Sort on exit block being traced to
    return (thisind < op2ind);
  FlowBlock *tmpbl = trace->top->top;
  thisind = (tmpbl != (FlowBlock *)0) ? tmpbl->getIndex() : -1;
  tmpbl = op2.trace->top->top;
  op2ind = (tmpbl != (FlowBlock *)0) ? tmpbl->getIndex() : -1;
  if (thisind != op2ind)	// Then sort on branch point being traced from
    return (thisind < op2ind);
  thisind = trace->pathout;
  op2ind = op2.trace->pathout;	// Then on the branch being taken
  return (thisind < op2ind);
}

/// This adds the BlockTrace to the list of potential unstructured edges.
/// Then patch up the BranchPoint/BlockTrace/pathout hierarchy.
/// \param trace is the indicated BlockTrace to remove
void TraceDAG::removeTrace(BlockTrace *trace)

{
  // Record that we should now treat this edge like goto
  likelygoto.push_back(FloatingEdge(trace->bottom,trace->destnode)); // Create goto record
  trace->destnode->setVisitCount( trace->destnode->getVisitCount() + trace->edgelump ); // Ignore edge(s)

  BranchPoint *parentbp = trace->top;

  if (trace->bottom != parentbp->top) {	// If trace has moved past the root branch, we can treat trace as terminal
    trace->flags |= BlockTrace::f_terminal;
    trace->bottom = (FlowBlock *)0;
    trace->destnode = (FlowBlock *)0;
    trace->edgelump = 0;
    // Do NOT remove from active list
    return;
  }
  // Otherwise we need to actually remove the path from the BranchPoint as the root branch will be marked as a goto
  removeActive(trace);	// The trace will no longer be active
  int4 size = parentbp->paths.size();
  for(int4 i=trace->pathout+1;i<size;++i) { // Move every trace above -trace-s pathout down one slot
    BlockTrace *movedtrace = parentbp->paths[i];
    movedtrace->pathout -= 1;	// Correct the trace's pathout
    BranchPoint *derivedbp = movedtrace->derivedbp;
    if (derivedbp != (BranchPoint *)0)
      derivedbp->pathout -= 1;	// Correct any derived BranchPoint's pathout
    parentbp->paths[i-1] = movedtrace;
  }
  parentbp->paths.pop_back();	// Remove the vacated slot
  
  delete trace;			// Delete the record
}

/// \brief Process a set of conflicting BlockTrace objects that go to the same exit point.
///
/// For each conflicting BlockTrace, calculate the minimum distance between it and any other BlockTrace.
/// \param start is the beginning of the list of conflicting BlockTraces (annotated as BadEdgeScore)
/// \param end is the end of the list of conflicting BlockTraces
void TraceDAG::processExitConflict(list<BadEdgeScore>::iterator start,list<BadEdgeScore>::iterator end)

{
  list<BadEdgeScore>::iterator iter;
  BranchPoint *startbp;

  while(start != end) {
    iter = start;
    ++iter;
    startbp = (*start).trace->top;
    if (iter != end) {
      startbp->markPath();	// Mark path to root, so we can find common ancestors easily
      do {
	if (startbp == (*iter).trace->top) { // Edge coming from same BranchPoint
	  (*start).siblingedge += 1;
	  (*iter).siblingedge += 1;
	}
	int4 dist = startbp->distance( (*iter).trace->top );
	// Distance is symmetric with respect to the pair of traces,
	// Update minimum for both traces
	if (((*start).distance == -1)||((*start).distance > dist))
	  (*start).distance = dist;
	if (((*iter).distance == -1)||((*iter).distance > dist))
	  (*iter).distance = dist;
	++iter;
      } while(iter != end);
      startbp->markPath();	// Unmark the path
    }
    ++start;
  }
}

/// Run through the list of active BlockTrace objects, annotate them using
/// the BadEdgeScore class, then select the BlockTrace which is the most likely
/// candidate for an unstructured edge.
/// \return the BlockTrace corresponding to the unstructured edge
TraceDAG::BlockTrace *TraceDAG::selectBadEdge(void)

{
  list<BadEdgeScore> badedgelist;
  list<BlockTrace *>::const_iterator aiter;
  for(aiter=activetrace.begin();aiter!=activetrace.end();++aiter) {
    if ((*aiter)->isTerminal()) continue;
    if (((*aiter)->top->top == (FlowBlock *)0)&&((*aiter)->bottom==(FlowBlock *)0))
      continue;	// Never remove virtual edges
    badedgelist.emplace_back();
    BadEdgeScore &score( badedgelist.back() );
    score.trace = *aiter;
    score.exitproto = score.trace->destnode;
    score.distance = -1;
    score.siblingedge = 0;
    score.terminal = (score.trace->destnode->sizeOut()==0) ? 1 : 0;
  }
  badedgelist.sort();
  
  list<BadEdgeScore>::iterator iter=badedgelist.begin();
  list<BadEdgeScore>::iterator startiter = iter;
  FlowBlock *curbl = (*iter).exitproto;
  int4 samenodecount = 1;
  ++iter;
  while(iter != badedgelist.end()) { // Find traces to the same exitblock
    BadEdgeScore &score( *iter );
    if (curbl == score.exitproto) {
      samenodecount += 1;	// Count another trace to the same exit
      ++iter;
    }
    else {			// A new exit node
      if (samenodecount > 1)
	processExitConflict(startiter,iter);
      curbl = score.exitproto;
      startiter = iter;
      samenodecount = 1;
      ++iter;
    }
  }
  if (samenodecount > 1)	// Process possible final group of traces exiting to same block
    processExitConflict(startiter,iter);

  iter = badedgelist.begin();

  list<BadEdgeScore>::iterator maxiter = iter;
  ++iter;
  while(iter != badedgelist.end()) {
    if ((*maxiter).compareFinal( *iter )) {
      maxiter = iter;
    }
    ++iter;
  }
  return (*maxiter).trace;
}

/// \param trace is the BlockTrace to mark as \e active
void TraceDAG::insertActive(BlockTrace *trace)

{
  activetrace.push_back(trace);
  list<BlockTrace *>::iterator iter = activetrace.end();
  --iter;
  trace->activeiter = iter;
  trace->flags |= BlockTrace::f_active;
  activecount += 1;
}

/// \param trace is the BlockTrace to be unmarked
void TraceDAG::removeActive(BlockTrace *trace)

{
  activetrace.erase(trace->activeiter);
  trace->flags &= ~((uint4)BlockTrace::f_active);
  activecount -= 1;
}

/// Verify the given BlockTrace can push into the next FlowBlock (\b destnode).
/// A FlowBlock node can only be \e opened if all the incoming edges have been traced.
/// \param trace is the given BlockTrace to push
/// \return \b true is the new node can be opened
bool TraceDAG::checkOpen(BlockTrace *trace)

{
  if (trace->isTerminal()) return false; // Already been opened
  bool isroot = false;
  if (trace->top->depth == 0) {
    if (trace->bottom == (FlowBlock *)0)
      return true; // Artificial root can always open its first level (edge is not real edge)
    isroot = true;
  }

  FlowBlock *bl = trace->destnode;
  if ((bl == finishblock)&&(!isroot))
    return false; // If there is a designated exit, only the root can open it
  int4 ignore = trace->edgelump + bl->getVisitCount();
  int4 count = 0;
  for(int4 i=0;i<bl->sizeIn();++i) {
    if (bl->isLoopDAGIn(i)) {
      count += 1;
      if (count > ignore) return false;
    }
  }
  return true;
}

/// Given that a BlockTrace can be opened into its next FlowBlock node,
/// create a new BranchPoint at that node, and set up new sub-traces.
/// \param parent is the given BlockTrace to split
/// \return an iterator (within the \e active list) to the new BlockTrace objects
list<TraceDAG::BlockTrace *>::iterator TraceDAG::openBranch(BlockTrace *parent)

{
  BranchPoint *newbranch = new BranchPoint( parent );
  parent->derivedbp = newbranch;
  if (newbranch->paths.size() == 0) { // No new traces, return immediately to parent trace
    delete newbranch;
    parent->derivedbp = (BranchPoint *)0;
    parent->flags |= BlockTrace::f_terminal; // marking it as terminal
    parent->bottom = (FlowBlock *)0;
    parent->destnode = (FlowBlock *)0;
    parent->edgelump = 0;
    return parent->activeiter;
  }
  removeActive(parent);
  branchlist.push_back( newbranch );
  for(int4 i=0;i<newbranch->paths.size();++i)
    insertActive(newbranch->paths[i]);
  return newbranch->paths[0]->activeiter;
}

/// For the given BlockTrace, make sure all other sibling BlockTraces from its
/// BranchPoint parent either terminate or flow to the same FlowBlock node.
/// If so, return \b true and pass back that node as the \b exitblock.
/// \param trace is the given BlockTrace
/// \param exitblock will hold the passed back exit block
/// \return \b true is the BlockTrace can be retired
bool TraceDAG::checkRetirement(BlockTrace *trace,FlowBlock *&exitblock)

{
  if (trace->pathout != 0) return false; // Only check, if this is the first sibling
  BranchPoint *bp = trace->top;
  if (bp->depth == 0) {		// Special conditions for retirement of root branch point
    for(int4 i=0;i<bp->paths.size();++i) {
      BlockTrace *curtrace = bp->paths[i];
      if (!curtrace->isActive()) return false;
      if (!curtrace->isTerminal()) return false; // All root paths must be terminal
    }
    return true;
  }
  FlowBlock *outblock = (FlowBlock *)0;
  for(int4 i=0;i<bp->paths.size();++i) {
    BlockTrace *curtrace = bp->paths[i];
    if (!curtrace->isActive()) return false;
    if (curtrace->isTerminal()) continue;
    if (outblock == curtrace->destnode) continue;
    if (outblock != (FlowBlock *)0) return false;
    outblock = curtrace->destnode;
  }
  exitblock = outblock;
  return true;
}

/// \brief Retire a BranchPoint, updating its parent BlockTrace
///
/// Knowing a given BranchPoint can be retired, remove all its BlockTraces
/// from the \e active list, and update the BranchPoint's parent BlockTrace
/// as having reached the BlockTrace exit point.
/// \param bp is the given BranchPoint
/// \param exitblock is unique exit FlowBlock (calculated by checkRetirement())
/// \return an iterator to the next \e active BlockTrace to examine
list<TraceDAG::BlockTrace *>::iterator TraceDAG::retireBranch(BranchPoint *bp,FlowBlock *exitblock)

{
  FlowBlock *edgeout_bl = (FlowBlock *)0;
  int4 edgelump_sum = 0;

  for(int4 i=0;i<bp->paths.size();++i) {
    BlockTrace *curtrace = bp->paths[i];
    if (!curtrace->isTerminal()) {
      edgelump_sum += curtrace->edgelump;
      if (edgeout_bl == (FlowBlock *)0)
	edgeout_bl = curtrace->bottom;
    }
    removeActive(curtrace); // Child traces are complete and no longer active
  }
  if (bp->depth == 0)		// If this is the root block
    return activetrace.begin();	// This is all there is to do

  if (bp->parent != (BranchPoint *)0) {
    BlockTrace *parenttrace = bp->parent->paths[bp->pathout];
    parenttrace->derivedbp = (BranchPoint *)0; // Derived branchpoint is gone
    if (edgeout_bl == (FlowBlock *)0) {		// If all traces were terminal
      parenttrace->flags |= BlockTrace::f_terminal;
      parenttrace->bottom = (FlowBlock *)0;
      parenttrace->destnode = (FlowBlock *)0;
      parenttrace->edgelump = 0;
    }
    else {
      parenttrace->bottom = edgeout_bl;
      parenttrace->destnode = exitblock;
      parenttrace->edgelump = edgelump_sum;
    }
    insertActive(parenttrace); // Parent trace gets re-activated
    return parenttrace->activeiter;
  }
  return activetrace.begin();
}

/// The \b visitcount field is only modified in removeTrace() whenever we put an edge
/// in the \b likelygoto list.
void TraceDAG::clearVisitCount(void)

{
  list<FloatingEdge>::const_iterator iter;
  for(iter=likelygoto.begin();iter!=likelygoto.end();++iter)
    (*iter).getBottom()->setVisitCount(0);
}

/// Prepare for a new trace using the provided storage for the likely unstructured
/// edges that will be discovered.
/// \param lg is the container for likely unstructured edges
TraceDAG::TraceDAG(list<FloatingEdge> &lg)
  : likelygoto(lg)
{
  activecount = 0;
  finishblock = (FlowBlock *)0;
}

TraceDAG::~TraceDAG(void)

{
  for(int4 i=0;i<branchlist.size();++i)
    delete branchlist[i];
}

/// Given the registered root FlowBlocks, create the initial (virtual) BranchPoint
/// and an associated BlockTrace for each root FlowBlock.
void TraceDAG::initialize(void)

{
  BranchPoint *rootBranch = new BranchPoint(); // Create a virtual BranchPoint for all entry points
  branchlist.push_back(rootBranch);

  for(uint4 i=0;i<rootlist.size();++i) {	// Find the entry points
    BlockTrace *newtrace = new BlockTrace(rootBranch,rootBranch->paths.size(),rootlist[i]);
    rootBranch->paths.push_back(newtrace);
    insertActive(newtrace);
  }
}

/// From the root BranchPoint, recursively push the trace. At any point where pushing
/// is no longer possible, select an appropriate edge to remove and add it to the
/// list of likely unstructured edges.  Then continue pushing the trace.
void TraceDAG::pushBranches(void)

{
  FlowBlock *exitblock;

  current_activeiter = activetrace.begin();
  missedactivecount = 0;
  while(activecount > 0) {
    if (current_activeiter == activetrace.end())
      current_activeiter = activetrace.begin();
    BlockTrace *curtrace = *current_activeiter;
    if (missedactivecount >= activecount) { // Could not push any trace further
      BlockTrace *badtrace = selectBadEdge(); // So we pick an edge to be unstructured
      removeTrace(badtrace);	// destroy the trace
      current_activeiter = activetrace.begin();
      missedactivecount = 0;
    }
    else if (checkRetirement(curtrace,exitblock)) {
      current_activeiter = retireBranch(curtrace->top,exitblock);
      missedactivecount = 0;
    }
    else if (checkOpen(curtrace)) {
      current_activeiter = openBranch(curtrace);
      missedactivecount = 0;
    }
    else {
      missedactivecount += 1;
      current_activeiter++;
    }
  }
  clearVisitCount();
}

/// Given the top FlowBlock of a loop, find corresponding LoopBody record from an ordered list.
/// This assumes mergeIdenticalHeads() has been run so that the head is uniquely identifying.
/// \param looptop is the top of the loop
/// \param looporder is the ordered list of LoopBody records
/// \return the LoopBody or NULL if none found
LoopBody *LoopBody::find(FlowBlock *looptop,const vector<LoopBody *> &looporder)

{
  int4 min=0;
  int4 max=looporder.size()-1;
  while(min<=max) {
    int4 mid = (min + max)/2;
    int4 comp = compare_head(looporder[mid],looptop);
    if (comp == 0) return looporder[mid];
    if (comp < 0)
      min = mid + 1;
    else
      max = mid - 1;
  }
  return (LoopBody *)0;
}

/// \param body is the list of FlowBlock nodes that have been marked
void LoopBody::clearMarks(vector<FlowBlock *> &body)

{
  for(int4 i=0;i<body.size();++i)
    body[i]->clearMark();
}

/// \brief Mark FlowBlocks \b only reachable from a given root
///
/// For a given root FlowBlock, find all the FlowBlocks that can only be reached from it,
/// mark them and put them in a list/
/// \param root is the given FlowBlock root
/// \param body is the container to hold the list of reachable nodes
void CollapseStructure::onlyReachableFromRoot(FlowBlock *root,vector<FlowBlock *> &body)

{
  vector<FlowBlock *> trial;
  int4 i=0;
  root->setMark();
  body.push_back(root);
  while(i<body.size()) {
    FlowBlock *bl = body[i++];
    int4 sizeout = bl->sizeOut();
    for(int4 j=0;j<sizeout;++j) {
      FlowBlock *curbl = bl->getOut(j);
      if (curbl->isMark()) continue;
      int4 count = curbl->getVisitCount();
      if (count == 0)
	trial.push_back(curbl);	// New possible extension
      count += 1;
      curbl->setVisitCount(count);
      if (count == curbl->sizeIn()) {
	curbl->setMark();
	body.push_back(curbl);
      }
    }
  }
  for(i=0;i<trial.size();++i)
    trial[i]->setVisitCount(0); // Make sure to clear the count
}

/// The FlowBlock objects in the \b body must all be marked.
/// \param body is the list of FlowBlock objects in the body
/// \return the number of edges that were marked as \e unstructured
int4 CollapseStructure::markExitsAsGotos(vector<FlowBlock *> &body)

{
  int4 changecount = 0;
  for(int4 i=0;i<body.size();++i) {
    FlowBlock *bl = body[i];
    int4 sizeout = bl->sizeOut();
    for(int4 j=0;j<sizeout;++j) {
      FlowBlock *curbl = bl->getOut(j);
      if (!curbl->isMark()) {
	bl->setGotoBranch(j);	// mark edge as goto
	changecount += 1;
      }
    }
  }
  return changecount;
}

/// Find distinct control-flow FlowBlock roots (having no incoming edges).
/// These delineate disjoint subsets of the control-flow graph, where a subset
/// is defined as the FlowBlock nodes that are only reachable from the root.
/// This method searches for one disjoint subset with \b cross-over edges,
/// edges from that subset into another.  The exiting edges for this subset are marked
/// as \e unstructured \e gotos and \b true is returned.
/// \return true if any cross-over edges were found (and marked)
bool CollapseStructure::clipExtraRoots(void)

{
  for(int4 i=1;i<graph.getSize();++i) {	// Skip the canonical root
    FlowBlock *bl = graph.getBlock(i);
    if (bl->sizeIn() != 0) continue;
    vector<FlowBlock *> body;
    onlyReachableFromRoot(bl,body);
    int4 count = markExitsAsGotos(body);
    LoopBody::clearMarks(body);
    if (count != 0)
      return true;
  }
  return false;
}

/// Identify all the distinct loops in the graph (via their back-edge) and create a LoopBody record.
/// \param looporder is the container that will hold the LoopBody record for each loop
void CollapseStructure::labelLoops(vector<LoopBody *> &looporder)

{
  for(int4 i=0;i<graph.getSize();++i) {
    FlowBlock *bl = graph.getBlock(i);
    int4 sizein = bl->sizeIn();
    for(int4 j=0;j<sizein;++j) {
      if (bl->isBackEdgeIn(j)) { // back-edge coming in must be from the bottom of a loop
	FlowBlock *loopbottom = bl->getIn(j);
	loopbody.emplace_back(bl);
	LoopBody &curbody( loopbody.back() );
	curbody.addTail(loopbottom);
	looporder.push_back( & curbody );
      }
    }
  }
  sort(looporder.begin(),looporder.end(),LoopBody::compare_ends);
}

/// Find the loop bodies, then:
///   - Label all edges which exit their loops.
///   - Generate a partial order on the loop bodies.
void CollapseStructure::orderLoopBodies(void)

{
  vector<LoopBody *> looporder;
  labelLoops(looporder);
  if (!loopbody.empty()) {
    int4 oldsize = looporder.size();
    LoopBody::mergeIdenticalHeads(looporder);
    list<LoopBody>::iterator iter;
    if (oldsize != looporder.size()) { // If there was merging
      iter = loopbody.begin();
      while(iter != loopbody.end()) {
	if ((*iter).getHead() == (FlowBlock *)0) {
	  list<LoopBody>::iterator deliter = iter;
	  ++iter;
	  loopbody.erase(deliter); // Delete the subsumed loopbody
	}
	else
	  ++iter;
      }
    }
    for(iter=loopbody.begin();iter!=loopbody.end();++iter) {
      vector<FlowBlock *> body;
      (*iter).findBase(body);
      (*iter).labelContainments(body,looporder);
      LoopBody::clearMarks(body);
    }
    loopbody.sort(); // Sort based on nesting depth (deepest come first) (sorting is stable)
    for(iter=loopbody.begin();iter!=loopbody.end();++iter) {
      vector<FlowBlock *> body;
      (*iter).findBase(body);
      (*iter).findExit(body);
      (*iter).orderTails();
      (*iter).extend(body);
      (*iter).labelExitEdges(body);
      LoopBody::clearMarks(body);
    }
  }
  likelylistfull = false;
  loopbodyiter = loopbody.begin();
}

/// Find the current innermost loop, make sure its \e likely \e goto edges are calculated.
/// If there are no loops, make sure the \e likely \e goto edges are calculated for the final DAG.
/// \return true if there are likely \e unstructured edges left to provide
bool CollapseStructure::updateLoopBody(void)

{
  FlowBlock *loopbottom = (FlowBlock *)0;
  FlowBlock *looptop = (FlowBlock *)0;
  if (finaltrace) {		// If we've already performed the final trace
    if (likelyiter == likelygoto.end())
      return false;		// We have nothing more to give
    return true;
  }
  while (loopbodyiter != loopbody.end()) {	// Last innermost loop
    loopbottom = (*loopbodyiter).getCurrentBounds(&looptop,&graph);
    if (loopbottom != (FlowBlock *)0) {
      if ((!likelylistfull) ||
	  (likelyiter != likelygoto.end())) // Reaching here means, we removed edges but loop still didn't collapse
	break; // Loop still exists
    }
    ++loopbodyiter;
    likelylistfull = false;	// Need to generate likely list for new loopbody (or no loopbody)
    loopbottom = (FlowBlock *)0;
  }
  if (likelylistfull) return true;
  // If we reach here, need to generate likely gotos for a new inner loop
  likelygoto.clear();		// Clear out any old likely gotos from last inner loop
  TraceDAG tracer(likelygoto);
  if (loopbottom != (FlowBlock *)0) {
    tracer.addRoot( looptop ); // Trace from the top of the loop
    tracer.setFinishBlock(loopbottom);
    (*loopbodyiter).setExitMarks(&graph); // Set the bounds of the TraceDAG
  }
  else {
    finaltrace = true;
    for(uint4 i=0;i<graph.getSize();++i) {
      FlowBlock *bl = graph.getBlock(i);
      if (bl->sizeIn() == 0)
	tracer.addRoot(bl);
    }
  }
  tracer.initialize();
  tracer.pushBranches();
  if (loopbottom != (FlowBlock *)0) {
    (*loopbodyiter).emitLikelyEdges(likelygoto,&graph);
    (*loopbodyiter).clearExitMarks(&graph);
  }
  likelylistfull = true;
  likelyiter = likelygoto.begin();
  return true;
}

/// Pick an edge from among the \e likely \e goto list generated by a
/// trace of the current innermost loop.  Given ongoing collapsing, this
/// may involve updating which loop is currently innermost and throwing
/// out potential edges whose endpoints have already been collapsed.
/// \return the FlowBlock whose outgoing edge was marked \e unstructured or NULL
FlowBlock *CollapseStructure::selectGoto(void)

{
  while(updateLoopBody()) {
    while(likelyiter != likelygoto.end()) {
      int4 outedge;
      FlowBlock *startbl = (*likelyiter).getCurrentEdge(outedge,&graph);
      ++likelyiter;
      if (startbl != (FlowBlock *)0) {
	startbl->setGotoBranch(outedge); // Mark the selected branch as goto
	return startbl;
      }
    }
  }
  if (!clipExtraRoots())
    throw LowlevelError("Could not finish collapsing block structure");
  return (FlowBlock *)0;
}

/// Try to concatenate a straight sequences of blocks starting with the given FlowBlock.
/// All of the internal edges should be DAG  (no \e exit, \e goto,or \e loopback).
/// The final edge can be an exit or loopback
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockCat(FlowBlock *bl)

{
  FlowBlock *outblock,*outbl2;

  if (bl->sizeOut() != 1) return false;
  if (bl->isSwitchOut()) return false;
  if ((bl->sizeIn()==1)&&(bl->getIn(0)->sizeOut()==1)) return false; // Must be start of chain
  outblock = bl->getOut(0);
  if (outblock == bl) return false; // No looping
  if (outblock->sizeIn() != 1) return false; // Nothing else can hit outblock
  if (!bl->isDecisionOut(0)) return false; // Not a goto or a loopbottom
  if (outblock->isSwitchOut()) return false; // Switch must be resolved first

  vector<FlowBlock *> nodes;
  nodes.push_back(bl);		// The first two blocks being concatenated
  nodes.push_back(outblock);

  while(outblock->sizeOut()==1) {
    outbl2 = outblock->getOut(0);
    if (outbl2 == bl) break; // No looping
    if (outbl2->sizeIn() != 1) break;	// Nothing else can hit outblock
    if (!outblock->isDecisionOut(0)) break; // Don't use loop bottom
    if (outbl2->isSwitchOut()) break; // Switch must be resolved first
    outblock = outbl2;
    nodes.push_back(outblock);	// Extend the cat chain
  }

  graph.newBlockList(nodes);	// Concatenate the nodes into a single block
  return true;
}

/// Try to find an OR conditions (finding ANDs by duality) starting with the given FlowBlock.
/// The top of the OR should not perform \e gotos, the edge to the \b orblock should not
/// be \e exit or \e loopback
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockOr(FlowBlock *bl)

{
  FlowBlock *orblock,*clauseblock;
  int4 i,j;

  if (bl->sizeOut() != 2) return false;
  if (bl->isGotoOut(0)) return false;
  if (bl->isGotoOut(1)) return false;
  if (bl->isSwitchOut()) return false;
  // NOTE: complex behavior can happen in the first block because we (may) only
  // print the branch
  //  if (bl->isComplex()) return false; // Control flow too complicated for condition
  for(i=0;i<2;++i) {
    orblock = bl->getOut(i);	// False out is other part of OR
    if (orblock==bl) continue;	// orblock cannot be same block
    if (orblock->sizeIn()!=1) continue;	// Nothing else can hit orblock
    if (orblock->sizeOut()!=2) continue; // orblock must also be binary condition
    if (orblock->isInteriorGotoTarget()) continue; // No unstructured jumps into or
    if (orblock->isSwitchOut()) continue;
    if (bl->isBackEdgeOut(i)) continue; // Don't use loop branch to get to orblock
    if (orblock->isComplex()) continue;
    // This line was always commented out.  I assume minor
    // block order variations were screwing up this rule
    clauseblock = bl->getOut(1-i);
    if (clauseblock == bl) continue; // No looping
    if (clauseblock == orblock) continue;
    for(j=0;j<2;++j) {
      if (clauseblock != orblock->getOut(j)) continue; // Clauses don't match
      break;
    }
    if (j==2) continue;
    if (orblock->getOut(1-j) == bl) continue; // No looping

    // Do we need to check that
    //   bl->isBackEdgeOut(i)  =>  orblock->isBackEdgeOut(j)
    //   bl->isLoopExitOut(i)  =>  orblock->isLoopExitOut(j)
    if (i==1) {			// orblock needs to be false out of bl
      if (bl->negateCondition(true))
	dataflow_changecount += 1;
    }
    if (j==0) {			// clauseblock needs to be true out of orblock
      if (orblock->negateCondition(true))
	dataflow_changecount += 1;
    }

    graph.newBlockCondition(bl,orblock);
    return true;
  }
  return false;
}

/// Try to structure a \e proper if structure (with no \b else clause) starting from the given FlowBlock.
/// The edge to the clause should not be an \e exit or \e loopbottom.
/// The outgoing edges can be \e exit or \e loopbottom.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockProperIf(FlowBlock *bl)

{
  FlowBlock *clauseblock,*outblock;
  int4 i;

  if (bl->sizeOut() != 2) return false; // Must be binary condition
  if (bl->isSwitchOut()) return false;
  if (bl->getOut(0) == bl) return false; // No loops
  if (bl->getOut(1) == bl) return false;
  if (bl->isGotoOut(0)) return false; // Neither branch must be unstructured
  if (bl->isGotoOut(1)) return false;
  for(i=0;i<2;++i) {
    clauseblock = bl->getOut(i);
    if (clauseblock->sizeIn() != 1) continue; // Nothing else can hit clauseblock
    if (clauseblock->sizeOut() != 1) continue; // Only one way out of clause
    if (clauseblock->isSwitchOut()) continue; // Don't use switch (possibly with goto edges)
    if (!bl->isDecisionOut(i)) continue; // Don't use loopbottom or exit
    if (clauseblock->isGotoOut(0)) continue; // No unstructured jumps out of clause
    outblock = clauseblock->getOut(0);
    if (outblock != bl->getOut(1-i)) continue; // Path after clause must be the same

    if (i==0) {			// Clause must be true
      if (bl->negateCondition(true))
	dataflow_changecount += 1;
    }

    graph.newBlockIf(bl,clauseblock);
    return true;
  }
  return false;
}

/// Try to find an if/else structure starting with the given FlowBlock.
/// Edges into the clauses cannot be \e goto, \e exit,or \e loopback.
/// The returning edges can be \e exit or \e loopback.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockIfElse(FlowBlock *bl)

{
  FlowBlock *tc,*fc,*outblock;

  if (bl->sizeOut() != 2) return false; // Must be binary condition
  if (bl->isSwitchOut()) return false;
  if (!bl->isDecisionOut(0)) return false;
  if (!bl->isDecisionOut(1)) return false;

  tc = bl->getTrueOut();
  fc = bl->getFalseOut();
  if (tc->sizeIn() != 1) return false; // Nothing else must hit true clause
  if (fc->sizeIn() != 1) return false; // Nothing else must hit false clause

  if (tc->sizeOut() != 1) return false; // Only one exit from clause
  if (fc->sizeOut() != 1) return false; // Only one exit from clause
  outblock = tc->getOut(0);
  if (outblock == bl) return false; // No loops
  if (outblock != fc->getOut(0)) return false; // Clauses must exit to same place

  if (tc->isSwitchOut()) return false;
  if (fc->isSwitchOut()) return false;
  if (tc->isGotoOut(0)) return false;
  if (fc->isGotoOut(0)) return false;
  
  graph.newBlockIfElse(bl,tc,fc);
  return true;
}

/// For the given FlowBlock, look for an outgoing edge marked as \e unstructured.
/// Create or update the BlockGoto or BlockMultiGoto structure.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockGoto(FlowBlock *bl)

{
  int4 sizeout = bl->sizeOut();
  for(int4 i=0;i<sizeout;++i) {
    if (bl->isGotoOut(i)) {
      if (bl->isSwitchOut()) {
	graph.newBlockMultiGoto(bl,i);
	return true;
      }
      if (sizeout == 2) {
	if (!bl->isGotoOut(1)) { // True branch must be goto
	  if (bl->negateCondition(true))
	    dataflow_changecount += 1;
	}
	graph.newBlockIfGoto(bl);
	return true;
      }
      if (sizeout == 1) {
	graph.newBlockGoto(bl);
	return true;
      }
    }
  }
  return false;
}

/// Try to find an if structure, where the condition clause does not exit,
/// starting with the given FlowBlock.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockIfNoExit(FlowBlock *bl)

{
  FlowBlock *clauseblock;
  int4 i;

  if (bl->sizeOut() != 2) return false; // Must be binary condition
  if (bl->isSwitchOut()) return false;
  if (bl->getOut(0) == bl) return false; // No loops
  if (bl->getOut(1) == bl) return false;
  if (bl->isGotoOut(0)) return false;
  if (bl->isGotoOut(1)) return false;
  for(i=0;i<2;++i) {
    clauseblock = bl->getOut(i);
    if (clauseblock->sizeIn() != 1) continue; // Nothing else must hit clause
    if (clauseblock->sizeOut() != 0) continue; // Must be no way out of clause
    if (clauseblock->isSwitchOut()) continue;
    if (!bl->isDecisionOut(i)) continue;
    //    if (clauseblock->isInteriorGotoTarget()) {
    //      bl->setGotoBranch(i);
    //      return true;
    //    }

    if (i==0) {			// clause must be true out of bl
      if (bl->negateCondition(true))
	dataflow_changecount += 1;
    }
    graph.newBlockIf(bl,clauseblock);
    return true;
  }
  return false;
}

/// Try to find a while/do structure, starting with a given FlowBlock.
/// Any \e break or \e continue must have already been collapsed as some form of \e goto.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockWhileDo(FlowBlock *bl)

{
  FlowBlock *clauseblock;
  int4 i;

  if (bl->sizeOut() != 2) return false; // Must be binary condition
  if (bl->isSwitchOut()) return false;
  if (bl->getOut(0) == bl) return false; // No loops at this point
  if (bl->getOut(1) == bl) return false;
  if (bl->isInteriorGotoTarget()) return false;
  if (bl->isGotoOut(0)) return false;
  if (bl->isGotoOut(1)) return false;
  for(i=0;i<2;++i) {
    clauseblock = bl->getOut(i);
    if (clauseblock->sizeIn() != 1) continue; // Nothing else must hit clause
    if (clauseblock->sizeOut() != 1) continue; // Only one way out of clause
    if (clauseblock->isSwitchOut()) continue;
    if (clauseblock->getOut(0) != bl) continue; // Clause must loop back to bl

    bool overflow = bl->isComplex(); // Check if we need to use overflow syntax
    if ((i==0)!=overflow) {			// clause must be true out of bl unless we use overflow syntax
      if (bl->negateCondition(true))
	dataflow_changecount += 1;
    }
    BlockWhileDo *newbl = graph.newBlockWhileDo(bl,clauseblock);
    if (overflow)
      newbl->setOverflowSyntax();
    return true;
  }
  return false;
}

/// Try to find a do/while structure, starting with the given FlowBlock.
/// Any \e break and \e continue must have already been collapsed as some form of \e goto.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockDoWhile(FlowBlock *bl)

{
  int4 i;

  if (bl->sizeOut() != 2) return false; // Must be binary condition
  if (bl->isSwitchOut()) return false;
  if (bl->isGotoOut(0)) return false;
  if (bl->isGotoOut(1)) return false;
  for(i=0;i<2;++i) {
    if (bl->getOut(i) != bl) continue; // Must loop back on itself
    if (i==0) {			// must loop on true condition
      if (bl->negateCondition(true))
	dataflow_changecount += 1;
    }
    graph.newBlockDoWhile(bl);
    return true;
  }
  return false;
}

/// Try to find a loop structure with no exits, starting at the given FlowBlock.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockInfLoop(FlowBlock *bl)

{
  if (bl->sizeOut() != 1) return false; // Must only be one way out

  // If the single out edge is from a switch (BRANCHIND) and also forms an infinite
  // loop, the ruleBlockSwitch method will not hit because the switch won't have a
  // proper exit block.  So we let this method collapse it by NOT checking for switch.
  //  if (bl->isSwitchOut()) return false;

  if (bl->isGotoOut(0)) return false;
  if (bl->getOut(0) != bl) return false; // Must fall into itself
  graph.newBlockInfLoop(bl);
  return true;
}

/// \brief Check for switch edges that go straight to the exit block
///
/// Some switch forms have edges that effectively skip the body of the switch and go straight to the exit
/// Many jumptables schemes have a \e default (i.e. if nothing else matches) edge.  This edge cannot be a normal
/// \b case because there would be too many labels to explicitly specify.  The edge must either be labeled as
/// \e default or it must go straight to the exit block.  If there is a \e default edge, if it does not go
/// straight to the exit, there can be no other edge that skips straight to the exit.
///
/// If such skip edges exist, they are converted to gotos and \b false is returned.
/// \param switchbl is the entry FlowBlock for the switch
/// \param exitblock is the designated exit FlowBlock for the switch
/// \return true if there are no \e skip edges
bool CollapseStructure::checkSwitchSkips(FlowBlock *switchbl,FlowBlock *exitblock)

{
  if (exitblock == (FlowBlock *)0) return true;
  
  // Is there a "default" edge that goes straight to the exitblock
  int4 sizeout,edgenum;
  sizeout = switchbl->sizeOut();
  bool defaultnottoexit = false;
  bool anyskiptoexit = false;
  for(edgenum=0;edgenum<sizeout;++edgenum) {
    if (switchbl->getOut(edgenum) == exitblock) {
      if (!switchbl->isDefaultBranch(edgenum))
	anyskiptoexit = true;
    }
    else {
      if (switchbl->isDefaultBranch(edgenum))
	defaultnottoexit = true;
    }
  }

  if (!anyskiptoexit) return true;

  if ((!defaultnottoexit)&&(switchbl->getType() == FlowBlock::t_multigoto)) {
    BlockMultiGoto *multibl = (BlockMultiGoto *)switchbl;
    if (multibl->hasDefaultGoto())
      defaultnottoexit = true;
  }
  if (!defaultnottoexit) return true;
  
  for(edgenum=0;edgenum<sizeout;++edgenum) {
    if (switchbl->getOut(edgenum) == exitblock) {
      if (!switchbl->isDefaultBranch(edgenum))
	switchbl->setGotoBranch(edgenum);
    }
  }
  return false;
}

/// Try to find a switch structure, starting with the given FlowBlock.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleBlockSwitch(FlowBlock *bl)

{
  if (!bl->isSwitchOut()) return false;
  FlowBlock *exitblock = (FlowBlock *)0;
  int4 sizeout = bl->sizeOut();

  // Find "obvious" exitblock,  is sizeIn>1 or sizeOut>1
  for(int4 i=0;i<sizeout;++i) {
    FlowBlock *curbl = bl->getOut(i);
    if (curbl == bl) {
      exitblock = curbl;	// Exit back to top of switch (loop)
      break;
    }
    if (curbl->sizeOut() > 1) {
      exitblock = curbl;
      break;
    }
    if (curbl->sizeIn() > 1) {
      exitblock = curbl;
      break;
    }
  }
  if (exitblock == (FlowBlock *)0) { 
    // If we reach here, every immediate block out of switch must have sizeIn==1 and sizeOut<=1
    // Any immediate block that was an "exitblock" would have no cases exiting to it (because sizeIn==1)
    // If that block had an output, that output can also viably be an output.
    // So as soon as we see an immediate block with an output, we make the output the exit
    for(int4 i=0;i<sizeout;++i) {
      FlowBlock *curbl = bl->getOut(i);
      if (curbl->isGotoIn(0)) return false; // In cannot be a goto
      if (curbl->isSwitchOut()) return false; // Must resolve nested switch first
      if (curbl->sizeOut() == 1) {
	if (curbl->isGotoOut(0)) return false; // Out cannot be goto
	if (exitblock != (FlowBlock *)0) {
	  if (exitblock != curbl->getOut(0)) return false;
	}
	else {
	  exitblock = curbl->getOut(0);
	}
      }
    }
  }
  else {			// From here we have a determined exitblock
    for(int4 i=0;i<exitblock->sizeIn();++i) // No in gotos to exitblock
      if (exitblock->isGotoIn(i)) return false;
    for(int4 i=0;i<exitblock->sizeOut();++i) // No out gotos from exitblock
      if (exitblock->isGotoOut(i)) return false;
    for(int4 i=0;i<sizeout;++i) {
      FlowBlock *curbl = bl->getOut(i);
      if (curbl == exitblock) continue;	// The switch can go straight to the exit block
      if (curbl->sizeIn() > 1) return false; // A case can only have the switch fall into it
      if (curbl->isGotoIn(0)) return false; // In cannot be a goto
      if (curbl->sizeOut() > 1) return false; // There can be at most 1 exit from a case
      if (curbl->sizeOut() == 1) {
	if (curbl->isGotoOut(0)) return false; // Out cannot be goto
	if (curbl->getOut(0) != exitblock) return false; // which must be to the exitblock
      }
      if (curbl->isSwitchOut()) return false; // Nested switch must be resolved first
    }
  }

  if (!checkSwitchSkips(bl,exitblock))
    return true;		// We match, but have special condition that adds gotos

  vector<FlowBlock *> cases;
  cases.push_back(bl);
  for(int4 i=0;i<sizeout;++i) {
    FlowBlock *curbl = bl->getOut(i);
    if (curbl == exitblock) continue; // Don't include exit as a case
    cases.push_back(curbl);
  }
  graph.newBlockSwitch(cases,(exitblock != (FlowBlock *)0));
  return true;
}

/// Look for a switch case that falls thru to another switch case, starting
/// with the given switch FlowBlock.
/// \param bl is the given FlowBlock
/// \return \b true if the structure was applied
bool CollapseStructure::ruleCaseFallthru(FlowBlock *bl)

{
  if (!bl->isSwitchOut()) return false;
  int4 sizeout = bl->sizeOut();
  int4 nonfallthru = 0;		// Count of exits that are not fallthru
  vector<FlowBlock *> fallthru;
  
  for(int4 i=0;i<sizeout;++i) {
    FlowBlock *curbl = bl->getOut(i);
    if (curbl == bl) return false; // Cannot exit to itself
    if ((curbl->sizeIn() > 2)||(curbl->sizeOut() > 1))
      nonfallthru += 1;
    else if (curbl->sizeOut()==1) {
      FlowBlock *target = curbl->getOut(0);
      if ((target->sizeIn()==2)&&(target->sizeOut()<=1)) {
	int4 inslot = curbl->getOutRevIndex(0);
	if (target->getIn(1-inslot)==bl)
	  fallthru.push_back(curbl);
      }
    }
    if (nonfallthru > 1) return false; // Can have at most 1 other exit block
  }
  if (fallthru.empty()) return false; // No fall thru candidates
  // Check exit block matches the 1 nonfallthru exit

  // Mark the fallthru edges as gotos
  for(int4 i=0;i<fallthru.size();++i) {
    FlowBlock *curbl = fallthru[i];
    curbl->setGotoBranch(0);
  }

  return true;
}

/// Collapse everything until no additional rules apply.
/// If handed a particular FlowBlock, try simplifying from that block first.
/// \param targetbl is the FlowBlock to start from or NULL
/// \return the count of \e isolated FlowBlocks (with no incoming or outgoing edges)
int4 CollapseStructure::collapseInternal(FlowBlock *targetbl)

{
  int4 index;
  bool change,fullchange;
  int4 isolated_count;
  FlowBlock *bl;

  do {
    do {
      change = false;
      index = 0;
      isolated_count = 0;
      while(index < graph.getSize()) {
	if (targetbl == (FlowBlock *)0) {
	  bl = graph.getBlock(index);
	  index += 1;
	}
	else {
	  bl = targetbl;		// Pick out targeted block
	  change = true;		// but force a change so we still go through all blocks
	  targetbl = (FlowBlock *)0; // Only target the block once
	  index = graph.getSize();
	}
	if ((bl->sizeIn()==0)&&(bl->sizeOut()==0)) { // A completely collapsed block
	  isolated_count += 1;
	  continue;		// This does not constitute a chanage
	}
	// Try each rule on the block
	if (ruleBlockGoto(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockCat(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockProperIf(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockIfElse(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockWhileDo(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockDoWhile(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockInfLoop(bl)) {
	  change = true;
	  continue;
	}
	if (ruleBlockSwitch(bl)) {
	  change = true;
	  continue;
	}
	//      if (ruleBlockOr(bl)) {
	//	change = true;
	//	continue;
	//      }
      }
    } while(change);
    // Applying IfNoExit rule too early can cause other (preferable) rules to miss
    // Only apply the rule if nothing else can apply
    fullchange = false;
    for(index=0;index<graph.getSize();++index) {
      bl = graph.getBlock(index);
      if (ruleBlockIfNoExit(bl)) { // If no other change is possible but still blocks left, try ifnoexit
	fullchange = true;
	break;
      }
      if (ruleCaseFallthru(bl)) { // Check for fallthru cases in a switch
	fullchange = true;
	break;
      }
    }
  } while(fullchange);
  return isolated_count;
}

/// Simplify just the conditional AND/OR constructions.
void CollapseStructure::collapseConditions(void)

{
  bool change;
  do {
    change = false;
    for(int4 i=0;i<graph.getSize();++i) {
      if (ruleBlockOr(graph.getBlock(i)))
	change = true;
    }
  } while(change);
}

/// The initial BlockGraph should be a copy of the permanent control-flow graph.
/// In particular the FlowBlock nodes should be BlockCopy instances.
/// \param g is the (copy of the) control-flow graph
CollapseStructure::CollapseStructure(BlockGraph &g)
  : graph(g)
{
  dataflow_changecount = 0;
}

/// Collapse everything in the control-flow graph to isolated blocks with no inputs and outputs.
void CollapseStructure::collapseAll(void)

{
  int4 isolated_count;

  finaltrace = false;
  graph.clearVisitCount();
  orderLoopBodies();

  collapseConditions();

  isolated_count = collapseInternal((FlowBlock *)0);
  while(isolated_count < graph.getSize()) {
    FlowBlock *targetbl = selectGoto();
    isolated_count = collapseInternal(targetbl);
  }
}

/// Compare based on the creation index of \b side1 first then \b side2
/// \param op2 is the MergePair to compare to \b this
/// \return \b true if \b this comes before \b op2
bool ConditionalJoin::MergePair::operator<(const MergePair &op2) const

{
  uint4 s1 = side1->getCreateIndex();
  uint4 s2 = op2.side1->getCreateIndex();
  if (s1 != s2)
    return (s1 < s2);
  return (side2->getCreateIndex() < op2.side2->getCreateIndex());
}

/// Given two conditional blocks, determine if the corresponding conditional
/// expressions are equivalent, up to Varnodes that need to be merged.
/// Any Varnode pairs that need to be merged are put in the \b mergeneed map.
/// \return \b true if there are matching conditions
bool ConditionalJoin::findDups(void)

{
  cbranch1 = block1->lastOp();
  if (cbranch1->code() != CPUI_CBRANCH) return false;
  cbranch2 = block2->lastOp();
  if (cbranch2->code() != CPUI_CBRANCH) return false;

  if (cbranch1->isBooleanFlip()) return false; // flip hasn't propagated through yet
  if (cbranch2->isBooleanFlip()) return false;

  Varnode *vn1 = cbranch1->getIn(1);
  Varnode *vn2 = cbranch2->getIn(1);

  if (vn1 == vn2)
    return true;

  // Parallel RulePushMulti,  so we know it will apply if we do the join
  if (!vn1->isWritten()) return false;
  if (!vn2->isWritten()) return false;
  if (vn1->isSpacebase()) return false;
  if (vn2->isSpacebase()) return false;
  Varnode *buf1[2];
  Varnode *buf2[2];
  int4 res = functionalEqualityLevel(vn1,vn2,buf1,buf2);
  if (res < 0) return false;
  if (res > 1) return false;
  PcodeOp *op1 = vn1->getDef();
  if (op1->code() == CPUI_SUBPIECE) return false;
  if (op1->code() == CPUI_COPY) return false;

  mergeneed[ MergePair(vn1,vn2) ] = (Varnode *)0;
  return true;
}

/// \brief Look for additional Varnode pairs in an exit block that need to be merged.
///
/// Varnodes that are merged in the exit block flowing from \b block1 and \b block2
/// will need to merged in the new joined block.  Add these pairs to the \b mergeneed map.
/// \param exit is the exit block
/// \param in1 is the index of the edge coming from \b block1
/// \param in2 is the index of the edge coming from \b block2
void ConditionalJoin::checkExitBlock(BlockBasic *exit,int4 in1,int4 in2)

{
  list<PcodeOp *>::const_iterator iter,enditer;

  iter = exit->beginOp();
  enditer = exit->endOp();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->code() == CPUI_MULTIEQUAL) { // Anything merging from our two root blocks -block1- and -block2-
      Varnode *vn1 = op->getIn(in1);
      Varnode *vn2 = op->getIn(in2);
      if (vn1 != vn2)
	mergeneed[ MergePair(vn1,vn2) ] = (Varnode *)0;
    }
    else if (op->code() != CPUI_COPY) break;
  }
}

/// \brief Substitute new joined Varnode in the given exit block
///
/// For any MULTIEQUAL in the \b exit, given two input slots, remove one Varnode,
/// and substitute the other Varnode from the corresponding Varnode in the \b mergeneed map.
/// \param exit is the exit block
/// \param in1 is the index of the incoming edge from \b block1
/// \param in2 is the index of the incoming edge from \b block2
void ConditionalJoin::cutDownMultiequals(BlockBasic *exit,int4 in1,int4 in2)

{
  list<PcodeOp *>::const_iterator iter,enditer;

  int4 lo,hi;
  if (in1 > in2) {
    hi = in1;
    lo = in2;
  }
  else {
    hi = in2;
    lo = in1;
  }
  iter = exit->beginOp();
  enditer = exit->endOp();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;			// Advance iterator before inserts happen
    if (op->code() == CPUI_MULTIEQUAL) {
      Varnode *vn1 = op->getIn(in1);
      Varnode *vn2 = op->getIn(in2);
      if (vn1 == vn2) {
	data.opRemoveInput(op,hi);
      }
      else {
	Varnode *subvn = mergeneed[ MergePair(vn1,vn2) ];
	data.opRemoveInput(op,hi);
	data.opSetInput(op,subvn,lo);
      }
      if (op->numInput() == 1) {
	data.opUninsert(op);
	data.opSetOpcode(op,CPUI_COPY);
	data.opInsertBegin(op,exit);
      }
    }
    else if (op->code() != CPUI_COPY) break;
  }
}

/// Create a new Varnode and its defining MULTIEQUAL operation
/// for each MergePair in the map.
void ConditionalJoin::setupMultiequals(void)

{
  map<MergePair,Varnode *>::iterator iter;

  for(iter=mergeneed.begin();iter!=mergeneed.end();++iter) {
    if ((*iter).second != (Varnode *)0) continue;
    Varnode *vn1 = (*iter).first.side1;
    Varnode *vn2 = (*iter).first.side2;
    PcodeOp *multi = data.newOp(2,cbranch1->getAddr());
    data.opSetOpcode(multi,CPUI_MULTIEQUAL);
    Varnode *outvn = data.newUniqueOut(vn1->getSize(),multi);
    data.opSetInput(multi,vn1,0);
    data.opSetInput(multi,vn2,1);
    (*iter).second = outvn;
    data.opInsertEnd(multi,joinblock);
  }
}

/// Remove the other CBRANCH
void ConditionalJoin::moveCbranch(void)

{
  Varnode *vn1 = cbranch1->getIn(1);
  Varnode *vn2 = cbranch2->getIn(1);
  data.opUninsert(cbranch1);
  data.opInsertEnd(cbranch1,joinblock);
  Varnode *vn;
  if (vn1 != vn2)
    vn = mergeneed[ MergePair(vn1,vn2) ];
  else
    vn = vn1;
  data.opSetInput(cbranch1,vn,1);
  data.opDestroy(cbranch2);
}

/// Given a pair of conditional blocks, make sure that they match the \e split conditions
/// necessary for merging and set up to do the merge.
/// If the conditions are not met, this method cleans up so that additional calls can be made.
/// \param b1 is the BlockBasic exhibiting one side of the split
/// \param b2 is the BlockBasic on the other side of the split
/// \return \b true if the conditions for merging are met
bool ConditionalJoin::match(BlockBasic *b1,BlockBasic *b2)

{
  block1 = b1;
  block2 = b2;
				// Check for the ConditionalJoin block pattern
  if (block2 == block1) return false;
  if (block1->sizeOut() != 2) return false;
  if (block2->sizeOut() != 2) return false;
  exita = (BlockBasic *)block1->getOut(0);
  exitb = (BlockBasic *)block1->getOut(1);
  if (exita == exitb) return false;
  if (block2->getOut(0) == exita) {
    if (block2->getOut(1) != exitb) return false;
    a_in2 = block2->getOutRevIndex(0);
    b_in2 = block2->getOutRevIndex(1);
  }
  else if (block2->getOut(0) == exitb) {
    if (block2->getOut(1) != exita) return false;
    a_in2 = block2->getOutRevIndex(1);
    b_in2 = block2->getOutRevIndex(0);
  }
  else
    return false;
  a_in1 = block1->getOutRevIndex(0);
  b_in1 = block1->getOutRevIndex(1);

  if (!findDups()) {
    clear();
    return false;
  }
  checkExitBlock(exita,a_in1,a_in2);
  checkExitBlock(exitb,b_in1,b_in2);
  return true;
}

/// All the conditions have been met.  Go ahead and do the join.
void ConditionalJoin::execute(void)

{
  joinblock = data.nodeJoinCreateBlock(block1,block2,exita,exitb,(a_in1 > a_in2),(b_in1 > b_in2),cbranch1->getAddr());
  setupMultiequals();
  moveCbranch();
  cutDownMultiequals(exita,a_in1,a_in2);
  cutDownMultiequals(exitb,b_in1,b_in2);
}

void ConditionalJoin::clear(void)

{ // Clear out data from previous join
  mergeneed.clear();
}

int4 ActionStructureTransform::apply(Funcdata &data)

{
  data.getStructure().finalTransform(data);
  return 0;
}

int4 ActionNormalizeBranches::apply(Funcdata &data)

{
  const BlockGraph &graph(data.getBasicBlocks());
  vector<PcodeOp *> fliplist;

  for(int4 i=0;i<graph.getSize();++i) {
    BlockBasic *bb = (BlockBasic *)graph.getBlock(i);
    if (bb->sizeOut() != 2) continue;
    PcodeOp *cbranch = bb->lastOp();
    if (cbranch == (PcodeOp *)0) continue;
    if (cbranch->code() != CPUI_CBRANCH) continue;
    fliplist.clear();
    if (opFlipInPlaceTest(cbranch,fliplist) != 0)
      continue;
    opFlipInPlaceExecute(data,fliplist);
    bb->flipInPlaceExecute();
    count += 1;			// Indicate a change was made
  }
  data.clearDeadOps();		// Clear any ops deleted by opFlipInPlaceExecute
  return 0;
}

int4 ActionPreferComplement::apply(Funcdata &data)

{
  BlockGraph &graph(data.getStructure());
  
  if (graph.getSize() == 0) return 0;
  vector<BlockGraph *> vec;
  vec.push_back(&graph);
  int4 pos = 0;
  
  while(pos < vec.size()) {
    BlockGraph *curbl = vec[pos];
    FlowBlock::block_type bt;
    pos += 1;
    int4 sz = curbl->getSize();
    for(int4 i=0;i<sz;++i) {
      FlowBlock *childbl = curbl->getBlock(i);
      bt = childbl->getType();
      if ((bt == FlowBlock::t_copy)||(bt == FlowBlock::t_basic))
	continue;
      vec.push_back((BlockGraph *)childbl);
    }
    if (curbl->preferComplement(data))
      count += 1;
  }
  data.clearDeadOps();		// Clear any ops deleted during this action
  return 0;
}

int4 ActionBlockStructure::apply(Funcdata &data)

{
  BlockGraph &graph(data.getStructure());

  // Check if already structured
  if (graph.getSize() != 0) return 0;
  data.installSwitchDefaults();
  graph.buildCopy(data.getBasicBlocks());

  CollapseStructure collapse(graph);
  collapse.collapseAll();
  count += collapse.getChangeCount();

  return 0;
}

int4 ActionFinalStructure::apply(Funcdata &data)

{
  BlockGraph &graph(data.getStructure());

  graph.orderBlocks();
  graph.finalizePrinting(data);
  graph.scopeBreak(-1,-1);	// Put in \e break statements
  graph.markUnstructured();	// Put in \e gotos
  graph.markLabelBumpUp(false); // Fix up labeling
  return 0;
}

/// \brief Gather all blocks that have \e goto edge to a RETURN
///
/// Collect all BlockGoto or BlockIf nodes, where there is a \e goto
/// edge to a RETURN block.
/// \param parent is a FlowBlock that ends in a RETURN operation
/// \param vec will hold the \e goto blocks
void ActionReturnSplit::gatherReturnGotos(FlowBlock *parent,vector<FlowBlock *> &vec)

{
  FlowBlock *bl,*ret;

  for(int4 i=0;i<parent->sizeIn();++i) {
    bl = parent->getIn(i)->getCopyMap();
    while(bl != (FlowBlock *)0) {
      if (!bl->isMark()) {
	ret = (FlowBlock *)0;
	if (bl->getType() == FlowBlock::t_goto) {
	  if (((BlockGoto *)bl)->gotoPrints())
	    ret = ((BlockGoto *)bl)->getGotoTarget();
	}
	else if (bl->getType() == FlowBlock::t_if)
	  // if this is an ifgoto block, get target, otherwise null
	  ret = ((BlockIf *)bl)->getGotoTarget();
	if (ret != (FlowBlock *)0) {
	  while(ret->getType() != FlowBlock::t_basic)
	    ret = ret->subBlock(0);
	  if (ret == parent) {
	    bl->setMark();
	    vec.push_back(bl);
	  }
	}
      }
      bl = bl->getParent();
    }
  }
}

/// Given a BasicBlock ending in a RETURN operation, determine
/// if there is any other substantive operation going on in the block. If there
/// is, the block is deemed too complicated to split.
/// \param b is the given BasicBlock
/// \return \b true if the block can be split
bool ActionReturnSplit::isSplittable(BlockBasic *b)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;

  for(iter=b->beginOp();iter!=b->endOp();++iter) {
    op = *iter;
    OpCode opc = op->code();
    if (opc == CPUI_MULTIEQUAL) continue;
    if ((opc == CPUI_COPY)||(opc == CPUI_RETURN)) {
      for(int4 i=0;i<op->numInput();++i) {
	if (op->getIn(i)->isConstant()) continue;
	if (op->getIn(i)->isAnnotation()) continue;
	if (op->getIn(i)->isFree()) return false;
      }
      continue;
    }
    return false;
  }
  return true;
}

int4 ActionReturnSplit::apply(Funcdata &data)

{
  PcodeOp *op;
  BlockBasic *parent;
  FlowBlock *bl;
  list<PcodeOp *>::const_iterator iter,iterend;
  vector<int4> splitedge;
  vector<BlockBasic *> retnode;

  if (data.getStructure().getSize() == 0)
    return 0;			// Some other restructuring happened first
  iterend = data.endOp(CPUI_RETURN);
  for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
    op = *iter;
    if (op->isDead()) continue;
    parent = op->getParent();
    if (parent->sizeIn() <= 1) continue;
    if (!isSplittable(parent)) continue;
    vector<FlowBlock *> gotoblocks;
    gatherReturnGotos(parent,gotoblocks);
    if (gotoblocks.empty()) continue;

    int4 splitcount = 0;
    // splitedge will contain edges to be split, IN THE ORDER
    // they will be split.  So we start from the biggest index
    // So that edge removal won't change the index of remaining edges
    for(int4 i=parent->sizeIn()-1;i>=0;--i) {
      bl = parent->getIn(i)->getCopyMap();
      while(bl != (FlowBlock *)0) {
	if (bl->isMark()) {
	  splitedge.push_back(i);
	  retnode.push_back(parent);
	  bl = (FlowBlock *)0;
	  splitcount += 1;
	}
	else
	  bl = bl->getParent();
      }
    }

    for(int4 i=0;i<gotoblocks.size();++i) // Clear our marks
      gotoblocks[i]->clearMark();

    // Can't split ALL in edges
    if (parent->sizeIn() == splitcount) {
      splitedge.pop_back();
      retnode.pop_back();
    }
  }

  for(int4 i=0;i<splitedge.size();++i) {
    data.nodeSplit(retnode[i],splitedge[i]);
    count += 1;
#ifdef BLOCKCONSISTENT_DEBUG
    if (!data.getBasicBlocks().isConsistent())
      data.getArch()->printMessage("Block structure is not consistent");
#endif
  }
  return 0;
}

int4 ActionNodeJoin::apply(Funcdata &data)

{
  const BlockGraph &graph(data.getBasicBlocks());
  if (graph.getSize()==0) return 0;

  ConditionalJoin condjoin(data);

  for(int4 i=0;i<graph.getSize();++i) {
    BlockBasic *bb = (BlockBasic *) graph.getBlock(i);
    if (bb->sizeOut() != 2) continue;
    BlockBasic *out1 = (BlockBasic *) bb->getOut(0);
    BlockBasic *out2 = (BlockBasic *) bb->getOut(1);
    int4 inslot;
    BlockBasic *leastout;
    if (out1->sizeIn() < out2->sizeIn()) {
      leastout = out1;
      inslot = bb->getOutRevIndex(0);
    }
    else {
      leastout = out2;
      inslot = bb->getOutRevIndex(1);
    }
    if (leastout->sizeIn()==1) continue;

    for(int4 j=0;j<leastout->sizeIn();++j) {
      if (j == inslot) continue;
      BlockBasic *bb2 = (BlockBasic *)leastout->getIn(j);
      if (condjoin.match(bb,bb2)) {
	count += 1;		// Indicate change has been made
	condjoin.execute();
	condjoin.clear();
	break;
      }
    }
    
  }
  return 0;
}

/* ###
 * IP: GHIDRA
 * NOTE: Cooper, Harvey, Kennedy dominance algorithm
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
#include "block.hh"
#include "funcdata.hh"

/// The edge is saved assuming we already know what block we are in
/// \param s is the output stream
void BlockEdge::saveXml(ostream &s) const

{
  s << "<edge";
  // We are not saving label currently
  a_v_i(s,"end",point->getIndex());		// Reference to other end of edge
  a_v_i(s,"rev",reverse_index);			// Position within other blocks edgelist
  s << "/>\n";
}

/// \param el is the \<edge> tag
/// \param resolver is used to cross-reference the edge's FlowBlock endpoints
void BlockEdge::restoreXml(const Element *el,BlockMap &resolver)

{
  label = 0;		// Tag does not currently contain info about label
  int4 endIndex;
  istringstream s(el->getAttributeValue("end"));
  s.unsetf(ios::dec | ios::hex | ios::oct);
  s >> endIndex;
  point = resolver.findLevelBlock(endIndex);
  if (point == (FlowBlock *)0)
    throw LowlevelError("Bad serialized edge in block graph");
  istringstream s2(el->getAttributeValue("rev"));
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  s2 >> reverse_index;
}

FlowBlock::FlowBlock(void)

{
  flags = 0;
  index = 0;
  visitcount = 0;
  parent = (FlowBlock *)0;
  immed_dom = (FlowBlock *)0;
}

/// \param b is the FlowBlock coming in
/// \param lab is a label for the edge
void FlowBlock::addInEdge(FlowBlock *b,uint4 lab)

{
  int4 ourrev = b->outofthis.size();
  int4 brev = intothis.size();
  intothis.push_back(BlockEdge(b,lab,ourrev));
  b->outofthis.push_back(BlockEdge(this,lab,brev));
}

/// \param el is the \<edge> element
/// \param resolver is used to resolve block references
void FlowBlock::restoreNextInEdge(const Element *el,BlockMap &resolver)

{
  intothis.emplace_back();
  BlockEdge &inedge(intothis.back());
  inedge.restoreXml(el,resolver);
  while(inedge.point->outofthis.size() <= inedge.reverse_index)
    inedge.point->outofthis.emplace_back();
  BlockEdge &outedge(inedge.point->outofthis[inedge.reverse_index]);
  outedge.label = 0;
  outedge.point = this;
  outedge.reverse_index = intothis.size()-1;
}

/// \param slot is the index of the incoming edge being altered
void FlowBlock::halfDeleteInEdge(int4 slot)

{
  while(slot < intothis.size()-1) {
    BlockEdge &edge( intothis[slot] );
    edge = intothis[slot+1];	// Slide the edge entry over
    // Correct the index coming the other way
    BlockEdge &edger( edge.point->outofthis[edge.reverse_index] );
    edger.reverse_index -= 1;
    slot += 1;
  }
  intothis.pop_back();
}

/// \param slot is the index of the outgoing edge being altered
void FlowBlock::halfDeleteOutEdge(int4 slot)

{
  while(slot < outofthis.size()-1) {
    BlockEdge &edge( outofthis[slot] );
    edge = outofthis[slot+1];	// Slide the edge
    // Correct the index coming the other way
    BlockEdge &edger( edge.point->intothis[edge.reverse_index] );
    edger.reverse_index -= 1;
    slot += 1;
  }
  outofthis.pop_back();
}

/// \param slot is the index of the incoming edge to remove
void FlowBlock::removeInEdge(int4 slot)

{
  FlowBlock *b = intothis[slot].point;
  int4 rev = intothis[slot].reverse_index;
  halfDeleteInEdge(slot);
  b->halfDeleteOutEdge(rev);
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  b->checkEdges();
#endif
}

/// \param slot is the index of the outgoing edge to remove
void FlowBlock::removeOutEdge(int4 slot)

{
  FlowBlock *b = outofthis[slot].point;
  int4 rev = outofthis[slot].reverse_index;
  halfDeleteOutEdge(slot);
  b->halfDeleteInEdge(rev);
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  b->checkEdges();
#endif
}

/// The original edge, which must exist, is replaced.
/// \param num is the index of the incoming edge
/// \param b is the new incoming block
void FlowBlock::replaceInEdge(int4 num,FlowBlock *b)

{
  FlowBlock *oldb = intothis[num].point;
  oldb->halfDeleteOutEdge(intothis[num].reverse_index);
  intothis[num].point = b;
  intothis[num].reverse_index = b->outofthis.size();
  b->outofthis.push_back(BlockEdge(this,intothis[num].label,num));
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  b->checkEdges();
  oldb->checkEdges();
#endif
}

/// The original edge, which must exist is replaced.
/// \param num is the index of the outgoing edge
/// \param b is the new outgoing block
void FlowBlock::replaceOutEdge(int4 num,FlowBlock *b)

{
  FlowBlock *oldb = outofthis[num].point;
  oldb->halfDeleteInEdge(outofthis[num].reverse_index);
  outofthis[num].point = b;
  outofthis[num].reverse_index = b->intothis.size();
  b->intothis.push_back(BlockEdge(this,outofthis[num].label,num));
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  b->checkEdges();
  oldb->checkEdges();
#endif
}

/// Remove edge \b in and \b out from \b this block, but create
/// a new edge between the in-block and the out-block, preserving
/// position in the in/out edge lists.
/// \param in is the index of the incoming block
/// \param out is the index of the outgoing block
void FlowBlock::replaceEdgesThru(int4 in,int4 out)

{
  FlowBlock *inb = intothis[in].point;
  int4 inblock_outslot = intothis[in].reverse_index;
  FlowBlock *outb = outofthis[out].point;
  int4 outblock_inslot = outofthis[out].reverse_index;
  inb->outofthis[inblock_outslot].point = outb;
  inb->outofthis[inblock_outslot].reverse_index = outblock_inslot;
  outb->intothis[outblock_inslot].point = inb;
  outb->intothis[outblock_inslot].reverse_index = inblock_outslot;
  halfDeleteInEdge(in);
  halfDeleteOutEdge(out);
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  inb->checkEdges();
  outb->checkEdges();
#endif
}

void FlowBlock::swapEdges(void)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if (outofthis.size() != 2)
    throw LowlevelError("Swapping edges for block that doesn't have two edges");
#endif
  BlockEdge tmp = outofthis[0];
  outofthis[0] = outofthis[1];
  outofthis[1] = tmp;
  FlowBlock *bl = outofthis[0].point;
  bl->intothis[ outofthis[0].reverse_index ].reverse_index = 0;
  bl = outofthis[1].point;
  bl->intothis[ outofthis[1].reverse_index ].reverse_index = 1;
  flags ^= f_flip_path;
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
#endif
}

/// \param i is the index of the outgoing edge
/// \param lab is the new edge label
void FlowBlock::setOutEdgeFlag(int4 i,uint4 lab)

{
  FlowBlock *bbout = outofthis[i].point;
  outofthis[i].label |= lab;
  bbout->intothis[ outofthis[i].reverse_index ].label |= lab;
}

/// \param i is the index of the outgoing edge
/// \param lab is the edge label to remove
void FlowBlock::clearOutEdgeFlag(int4 i,uint4 lab)

{
  FlowBlock *bbout = outofthis[i].point;
  outofthis[i].label &= ~lab;
  bbout->intothis[ outofthis[i].reverse_index ].label &= ~lab;
}

/// \param bump if \b true, mark that labels for this block are printed by somebody higher in hierarchy
void FlowBlock::markLabelBumpUp(bool bump)

{
  if (bump)
    flags |= f_label_bumpup;
}

/// Block references are updated using the getCopyMap() reference on the original block
/// \param vec is the list of edges whose block references should be updated
void FlowBlock::replaceEdgeMap(vector<BlockEdge> &vec)

{
  vector<BlockEdge>::iterator iter;

  for(iter=vec.begin();iter!=vec.end();++iter)
    (*iter).point = (*iter).point->getCopyMap();
}

/// Run through incoming and outgoing edges and replace FlowBlock references with
/// the FlowBlock accessed via the getCopyMap() method.
void FlowBlock::replaceUsingMap(void)

{
  replaceEdgeMap(intothis);
  replaceEdgeMap(outofthis);
  if (immed_dom != (FlowBlock *)0)
    immed_dom = immed_dom->getCopyMap();
}

/// Flip the order of outgoing edges (at least).
/// This should also affect the original op causing the condition.
/// Note: we don't have to flip at all levels of the hierarchy
/// only at the top and at the bottom
/// \param toporbottom is \b true if \b this is the top outermost block of the hierarchy getting negated
/// \return \b true if a change was made to data-flow
bool FlowBlock::negateCondition(bool toporbottom)

{
  if (!toporbottom) return false; // No change was made to data-flow
  swapEdges();
  return false;
}

/// This is the main entry point for marking a branch
/// from one block to another as unstructured.
/// \param i is the index of the outgoing edge to mark
void FlowBlock::setGotoBranch(int4 i)

{  if ((i>=0)&&(i < outofthis.size()))
    setOutEdgeFlag(i,f_goto_edge);
  else
    throw LowlevelError("Could not find block edge to mark unstructured");
  flags |= f_interior_gotoout; // Mark that there is a goto out of this block
  
  outofthis[i].point->flags |= f_interior_gotoin;
}

/// \b return \b true if block is the target of a jump
bool FlowBlock::isJumpTarget(void) const

{
  for(int4 i=0;i<intothis.size();++i)
    if (intothis[i].point->index != index-1) return true;
  return false;
}

/// Keep descending tree hierarchy, taking the front block,
/// until we get to the bottom copy block
/// \return the first leaf FlowBlock to execute
const FlowBlock *FlowBlock::getFrontLeaf(void) const

{
  const FlowBlock *bl = this;
  while(bl->getType() != t_copy) {
    bl = bl->subBlock(0);
    if (bl == (const FlowBlock *)0) return bl;
  }
  return bl;
}

/// Keep descending tree hierarchy, taking the front block,
/// until we get to the bottom copy block
/// \return the first leaf FlowBlock to execute
FlowBlock *FlowBlock::getFrontLeaf(void)

{
  FlowBlock *bl = this;
  while(bl->getType() != t_copy) {
    bl = bl->subBlock(0);
    if (bl == (FlowBlock *)0) return bl;
  }
  return bl;
}

/// How many getParent() calls from the leaf to \b this
/// \param leaf is the component FlowBlock
/// \return the depth count
int4 FlowBlock::calcDepth(const FlowBlock *leaf) const

{
  int4 depth = 0;
  while(leaf != this) {
    if (leaf == (const FlowBlock *)0)
      return -1;
    leaf = leaf->getParent();
    depth += 1;
  }
  return depth;
}

/// Return \b true if \b this block \e dominates the given block (or is equal to it).
/// This assumes that block indices have been set with a reverse post order so that having a
/// smaller index is a necessary condition for dominance.
/// \param subBlock is the given block to test against \b this for dominance
/// \return \b true if \b this dominates
bool FlowBlock::dominates(const FlowBlock *subBlock) const

{
  while(subBlock != (const FlowBlock *)0 && index <= subBlock->index) {
    if (subBlock == this) return true;
    subBlock = subBlock->getImmedDom();
  }
  return false;
}

/// \brief Check if the condition from the given block holds for \b this block
///
/// We assume the given block has 2 out-edges and that \b this block is immediately reached by
/// one of these two edges. Some condition holds when traversing the out-edge to \b this, and the complement
/// of the condition holds for traversing the other out-edge. We verify that the condition holds for
/// this entire block.  More specifically, we check that that there is no path to \b this through the
/// sibling edge, where the complement of the condition holds (unless we loop back through the conditional block).
/// \param cond is the conditional block with 2 out-edges
/// \return \b true if the condition holds for this block
bool FlowBlock::restrictedByConditional(const FlowBlock *cond) const

{
  if (sizeIn() == 1) return true;	// Its impossible for any path to come through sibling to this
  if (getImmedDom() != cond) return false;	// This is not dominated by conditional block at all
  for(int4 i=0;i<sizeIn();++i) {
    const FlowBlock *inBlock = getIn(i);
    if (inBlock == cond) continue;	// The unique edge from cond to this
    while(inBlock != this) {
      if (inBlock == cond) return false;	// Must have come through sibling
      inBlock = inBlock->getImmedDom();
    }
  }
  return true;
}

/// \return \b true if \b this is the top of a loop
bool FlowBlock::hasLoopIn(void) const

{
  for(int4 i=0;i<intothis.size();++i)
    if ((intothis[i].label & f_loop_edge)!=0) return true;
  return false;
}

/// \return \b true if \b this is the bottom of a loop
bool FlowBlock::hasLoopOut(void) const

{
  for(int4 i=0;i<outofthis.size();++i)
    if ((outofthis[i].label & f_loop_edge)!=0) return true;
  return false;
}

/// \param bl is the given block
void FlowBlock::eliminateInDups(FlowBlock *bl)

{
  int4 indval = -1;

  int4 i=0;
  while(i < intothis.size()) {
    if (intothis[i].point == bl) {
      if (indval == -1) {	// The first instance of bl
	indval = i;		// We keep it
	i += 1;
      }
      else {
	intothis[indval].label |= intothis[i].label;
	int4 rev = intothis[i].reverse_index;
	halfDeleteInEdge(i);
	bl->halfDeleteOutEdge(rev);
      }
    }
    else
      i += 1;
  }
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  bl->checkEdges();
#endif
}

/// \param bl is the given block
void FlowBlock::eliminateOutDups(FlowBlock *bl)

{
  int4 indval = -1;

  int4 i=0;
  while(i < outofthis.size()) {
    if (outofthis[i].point == bl) {
      if (indval == -1) {	// The first instance of bl
	indval = i;		// We keep it
	i += 1;
      }
      else {
	outofthis[indval].label |= outofthis[i].label;
	int4 rev = outofthis[i].reverse_index;
	halfDeleteOutEdge(i);
	bl->halfDeleteInEdge(rev);
      }
    }
    else
      i += 1;
  }
#ifdef BLOCKCONSISTENT_DEBUG
  checkEdges();
  bl->checkEdges();
#endif
}

/// \brief Find blocks that are at the end of multiple edges
///
/// \param ref is the list of BlockEdges to search
/// \param duplist will contain the list of blocks with duplicate edges
void FlowBlock::findDups(const vector<BlockEdge> &ref,vector<FlowBlock *> &duplist)

{
  vector<BlockEdge>::const_iterator iter;

  for(iter=ref.begin();iter!=ref.end();++iter) {
    if (((*iter).point->flags&f_mark2)!=0) continue; // Already marked as a duplicate
    if (((*iter).point->flags&f_mark)!=0) { // We have a duplicate
      duplist.push_back((*iter).point);
      (*iter).point->flags |= f_mark2;
    }
    else
      (*iter).point->flags |= f_mark;
  }
  for(iter=ref.begin();iter!=ref.end();++iter) // Erase our marks
    (*iter).point->flags &= ~(f_mark | f_mark2);
}

void FlowBlock::dedup(void)

{
  vector<FlowBlock *> duplist;
  vector<FlowBlock *>::iterator iter;

  findDups(intothis,duplist);
  for(iter=duplist.begin();iter!=duplist.end();++iter)
    eliminateInDups(*iter);

  duplist.clear();
  findDups(outofthis,duplist);
  for(iter=duplist.begin();iter!=duplist.end();++iter)
    eliminateOutDups(*iter);
}

#ifdef BLOCKCONSISTENT_DEBUG
/// Make sure block references in the BlockEdge objects owned
/// by \b this block, and any other block at the other end of these edges,
/// are consistent.
void FlowBlock::checkEdges(void)

{
  for(int4 i=0;i<intothis.size();++i) {
    BlockEdge &edge( intothis[i] );
    int4 rev = edge.reverse_index;
    FlowBlock *bl = edge.point;
    if (bl->outofthis.size() <= rev)
      throw LowlevelError("Not enough outofthis blocks");
    BlockEdge &edger( bl->outofthis[rev] );
    if (edger.point != this)
      throw LowlevelError("Intothis edge mismatch");
    if (edger.reverse_index != i)
      throw LowlevelError("Intothis index mismatch");
  }
  for(int4 i=0;i<outofthis.size();++i) {
    BlockEdge &edge( outofthis[i] );
    int4 rev = edge.reverse_index;
    FlowBlock *bl = edge.point;
    if (bl->intothis.size() <= rev)
      throw LowlevelError("Not enough intothis blocks");
    BlockEdge &edger( bl->intothis[rev] );
    if (edger.point != this)
      throw LowlevelError("Outofthis edge mismatch");
    if (edger.reverse_index != i)
      throw LowlevelError("Outofthis index mismatch");
  }
}

#endif

/// Search through incoming blocks in edge order for the given block.
/// \param bl is the given FlowBlock
/// \return the matching edge index or -1 if \b bl doesn't flow into \b this
int4 FlowBlock::getInIndex(const FlowBlock *bl) const

{
  int4 blocknum;

  for(blocknum=0;blocknum<intothis.size();++blocknum)
    if (intothis[blocknum].point==bl) return blocknum;
  return -1;			// That block not found
}

/// Search through outgoing blocks in edge order for the given block.
/// \param bl is the given FlowBlock
/// \return the matching edge index or -1 if \b bl doesn't flow out of \b this
int4 FlowBlock::getOutIndex(const FlowBlock *bl) const

{
  int4 blocknum;

  for(blocknum=0;blocknum<outofthis.size();++blocknum)
    if (outofthis[blocknum].point==bl) return blocknum;
  return -1;
}

/// Only print a header for \b this single block
/// \param s is the output stream
void FlowBlock::printHeader(ostream &s) const

{
  s << dec << index;
  if (!getStart().isInvalid() && !getStop().isInvalid()) {
    s << ' ' << getStart() << '-' << getStop();
  }
}

/// Recursively print out the hierarchical structure of \b this FlowBlock.
/// \param s is the output stream
/// \param level is the current level of indentation
void FlowBlock::printTree(ostream &s,int4 level) const

{
  int4 i;

  for(i=0;i<level;++i)
    s << "  ";
  printHeader(s);
  s << endl;
}

/// If \b this FlowBlock was ends with a computed jump, retrieve
/// the associated JumpTable object
/// \return the JumpTable object or NULL
JumpTable *FlowBlock::getJumptable(void) const

{
  JumpTable *jt = (JumpTable *)0;
  if (!isSwitchOut()) return jt;
  PcodeOp *indop = lastOp();
  if (indop != (PcodeOp *)0)
    jt = indop->getParent()->getFuncdata()->findJumpTable(indop);
  return jt;
}

/// Given a string describing a FlowBlock type, return the block_type.
/// This is currently only used by the restoreXml() process.
/// TODO: Fill in the remaining names and types
/// \param nm is the name string
/// \return the corresponding block_type
FlowBlock::block_type FlowBlock::nameToType(const string &nm)

{
  FlowBlock::block_type bt = FlowBlock::t_plain;
  if (nm == "graph")
    bt = FlowBlock::t_graph;
  else if (nm == "copy")
    bt = FlowBlock::t_copy;
  return bt;
}

/// For use in serializng FlowBlocks to XML.
/// \param bt is the block_type
/// \return the corresponding name string
string FlowBlock::typeToName(FlowBlock::block_type bt)

{
  switch(bt) {
  case t_plain:
    return "plain";
  case t_basic:
    return "basic";
  case t_graph:
    return "graph";
  case t_copy:
    return "copy";
  case t_goto:
    return "goto";
  case t_multigoto:
    return "multigoto";
  case t_ls:
    return "list";
  case t_condition:
    return "condition";
  case t_if:
    return "properif";
  case t_whiledo:
    return "whiledo";
  case t_dowhile:
    return "dowhile";
  case t_switch:
    return "switch";
  case t_infloop:
    return "infloop";
  }
  return "";
}

/// Comparator for ordering the final 0-exit blocks
/// \param bl1 is the first FlowBlock to compare
/// \param bl2 is the second FlowBlock
/// \return true if the first comes before the second
bool FlowBlock::compareFinalOrder(const FlowBlock *bl1,const FlowBlock *bl2)

{
  if (bl1->getIndex() == 0) return true; // Make sure the entry point comes first
  if (bl2->getIndex() == 0) return false;
  PcodeOp *op1 = bl1->lastOp();
  PcodeOp *op2 = bl2->lastOp();

  if (op1 != (PcodeOp *)0) {	// Make sure return blocks come last
    if (op2 != (PcodeOp *)0) {
      if ((op1->code() == CPUI_RETURN)&&(op2->code() != CPUI_RETURN))
	return false;
      else if ((op1->code() != CPUI_RETURN)&&(op2->code() == CPUI_RETURN))
	return true;
    }
    if (op1->code() == CPUI_RETURN) return false;
  }
  else if (op2 != (PcodeOp *)0) {
    if (op2->code() == CPUI_RETURN) return true;
  }
  return (bl1->getIndex() < bl2->getIndex());	// Otherwise use index
}

/// Within the dominator tree, find the earliest common ancestor of two FlowBlocks
/// \param bl1 is the first FlowBlock
/// \param bl2 is the second
/// \return the common ancestor which dominates both
FlowBlock *FlowBlock::findCommonBlock(FlowBlock *bl1,FlowBlock *bl2)

{
  FlowBlock *b1,*b2,*common;

  common = (FlowBlock *)0;
  b1 = bl1;
  b2 = bl2;
  for(;;) {
    if (b2 == (FlowBlock *)0) {
      while(b1 != (FlowBlock *)0) {
	if (b1->isMark()) {
	  common = b1;
	  break;
	}
	b1 = b1->getImmedDom();
      }
      break;
    }
    if (b1 == (FlowBlock *)0) {
      while(b2 != (FlowBlock *)0) {
	if (b2->isMark()) {
	  common = b2;
	  break;
	}
	b2 = b2->getImmedDom();
      }
      break;
    }
    if (b1->isMark()) {
      common = b1;
      break;
    }
    b1->setMark();
    if (b2->isMark()) {
      common = b2;
      break;
    }
    b2->setMark();
    b1 = b1->getImmedDom();
    b2 = b2->getImmedDom();
  }
  // Clear our marks
  while(bl1!=(FlowBlock *)0) {
    if (!bl1->isMark()) break;
    bl1->clearMark();
    bl1 = bl1->getImmedDom();
  }
  while(bl2!=(FlowBlock *)0) {
    if (!bl2->isMark()) break;
    bl2->clearMark();
    bl2 = bl2->getImmedDom();
  }
  return common;
}

/// Find the most immediate dominating FlowBlock of all blocks in the given set.
/// The container must not be empty.
/// \param blockSet is the given set of blocks
/// \return the most immediate dominating FlowBlock
FlowBlock *FlowBlock::findCommonBlock(const vector<FlowBlock *> &blockSet)

{
  vector<FlowBlock *> markedSet;
  FlowBlock *bl;
  FlowBlock *res = blockSet[0];
  int4 bestIndex = res->getIndex();
  bl = res;
  do {
    bl->setMark();
    markedSet.push_back(bl);
    bl = bl->getImmedDom();
  } while (bl != (FlowBlock *)0);
  for(int4 i=1;i<blockSet.size();++i) {
    if (bestIndex == 0)
      break;
    bl = blockSet[i];
    while(!bl->isMark()) {
      bl->setMark();
      markedSet.push_back(bl);
      bl = bl->getImmedDom();
    }
    if (bl->getIndex() < bestIndex) {	// If first meeting with old paths is higher than ever before
      res = bl;				// we have a new best
      bestIndex = res->getIndex();
    }
  }
  for(int4 i=0;i<markedSet.size();++i)
    markedSet[i]->clearMark();
  return res;
}

/// Add the given FlowBlock to the list and make \b this the parent
/// Update \b index so that it has the minimum over all components
/// \param bl is the given FlowBlock
void BlockGraph::addBlock(FlowBlock *bl)

{
  int4 min = bl->index;

  if (list.empty()) {
    index = min;
  }
  else {
    if (min < index) index = min;
  }
  bl->parent = this;
  list.push_back(bl);
}

/// Force \b this FlowBlock to have the indicated number of outputs.
/// Create edges back into itself if necessary.
/// \param i is the number of out edges to force
void BlockGraph::forceOutputNum(int4 i)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if (sizeOut() > i)
    throw LowlevelError("Bad block output force");
#endif
  while(sizeOut() < i)
    addInEdge(this,f_loop_edge|f_back_edge);
}

/// Examine the set of components and their incoming and outgoing edges.  If both
/// ends of the edge are not within the set, then \b this block inherits the edge.
/// A formal BlockEdge is added between \b this and the FlowBlock outside the set.
/// The edges are deduplicated.
void BlockGraph::selfIdentify(void)

{
  vector<FlowBlock *>::iterator iter;
  FlowBlock *mybl,*otherbl;

  if (list.empty()) return;
  for(iter=list.begin();iter!=list.end();++iter) {
    mybl = *iter;
    int4 i = 0;
    while(i<mybl->intothis.size()) {
      otherbl = mybl->intothis[i].point;
      if (otherbl->parent == this)
	i += 1;
      else {
	for(int4 j=0;j<otherbl->outofthis.size();++j)
	  if (otherbl->outofthis[j].point == mybl)
	    otherbl->replaceOutEdge(j,this);
	// Dont increment i
      }
    }
    i = 0;
    while(i<mybl->outofthis.size()) {
      otherbl = mybl->outofthis[i].point;
      if (otherbl->parent == this)
	i += 1;
      else {
	for(int4 j=0;j<otherbl->intothis.size();++j)
	  if (otherbl->intothis[j].point == mybl)
	    otherbl->replaceInEdge(j,this); 
	if (mybl->isSwitchOut())	// Check for indirect branch out
	  setFlag(f_switch_out);
      }
    }
  }
  dedup();
}

/// \brief Move nodes from \b this into a new BlockGraph
///
/// This does most of the work of collapsing a set of components in \b this
/// into a single node. The components are removed from \b this, put in the new FlowBlock
/// and adjusts edges. The new FlowBlock must be added back into \b this.
/// \param ident is the new FlowBlock
/// \param nodes is the list component FlowBlocks to move
void BlockGraph::identifyInternal(BlockGraph *ident,const vector<FlowBlock *> &nodes)

{
  vector<FlowBlock *>::const_iterator iter;
  for(iter=nodes.begin();iter!=nodes.end();++iter) {
#ifdef BLOCKCONSISTENT_DEBUG
    if ((*iter)->parent != this)
      throw LowlevelError("Bad block identify");
#endif
    (*iter)->setMark();
    ident->addBlock(*iter);	// Maintain order of blocks
    ident->flags |= ((*iter)->flags & (f_interior_gotoout | f_interior_gotoin));
  }
  vector<FlowBlock *> newlist;
  for(iter=list.begin();iter!=list.end();++iter) { // Remove -nodes- from our list
    if (!(*iter)->isMark())
      newlist.push_back(*iter);
    else
      (*iter)->clearMark();
  }
  list = newlist;

  ident->selfIdentify();
}

/// \param flags is the set of boolean properties
void BlockGraph::clearEdgeFlags(uint4 flags)

{
  flags = ~flags;
  int4 size = list.size();
  for(int4 i=0;i<size;++i) {
    FlowBlock *bl = list[i];
    for(int4 i=0;i<bl->intothis.size();++i)
      bl->intothis[i].label &= flags;
    for(int4 i=0;i<bl->outofthis.size();++i)
      bl->outofthis[i].label &= flags;
  }
}

/// \brief Create a single root block
///
/// Some algorithms need a graph with a single entry node. Given multiple entry points,
/// this routine creates an artificial root with no \e in edges and an \e out
/// edge to each of the real entry points.  The resulting root FlowBlock isn't
/// owned by any BlockGraph, and the caller is responsible for freeing it.
/// \param rootlist is the given set of entry point FlowBlocks
/// \return the new artificial root FlowBlock
FlowBlock *BlockGraph::createVirtualRoot(const vector<FlowBlock *> &rootlist)

{
  FlowBlock *newroot = new FlowBlock();
  for(int4 i=0;i<rootlist.size();++i)
    rootlist[i]->addInEdge(newroot,0);
  return newroot;
}

/// \brief Find a spanning tree (skipping irreducible edges).
///
///   - Label pre and reverse-post orderings, tree, forward, cross, and back edges.
///   - Calculate number of descendants.
///   - Put the blocks of the graph in reverse post order.
///   - Return an array of all nodes in pre-order.
///   - If the graph does not have a real root, create one and return it, otherwise return null.
///
/// Algorithm originally due to Tarjan.
/// The first block is the entry block, and should remain the first block
/// \param preorder will hold the list of FlowBlock components in pre-order
/// \param rootlist will hold the list of entry points
void BlockGraph::findSpanningTree(vector<FlowBlock *> &preorder,vector<FlowBlock *> &rootlist)

{
  if (list.size()==0) return;
  vector<FlowBlock *> rpostorder;
  vector<FlowBlock *> state;
  vector<int4> istate;
  FlowBlock *tmpbl;
  int4 origrootpos;

  preorder.reserve(list.size());
  rpostorder.resize(list.size());
  state.reserve(list.size());
  istate.reserve(list.size());
  for(int4 i=0;i<list.size();++i) {
    tmpbl = list[i];
    tmpbl->index = -1;	// reverse post-order starts at 0
    tmpbl->visitcount = -1;
    tmpbl->copymap = tmpbl;
    if (tmpbl->sizeIn()==0)	// Keep track of all potential roots of the tree
      rootlist.push_back(tmpbl);
  }
  if (rootlist.size() > 1) {	// Make sure orighead is visited last, (so it is first in the reverse post order)
    tmpbl = rootlist[rootlist.size()-1];
    rootlist[rootlist.size()-1] = rootlist[0];
    rootlist[0] = tmpbl;
  }
  else if (rootlist.size() == 0) {	// If there's no obvious starting block
    rootlist.push_back(list[0]);	// Assume first block is entry point
  }
  origrootpos = rootlist.size()-1; // Position of original head in rootlist

  for(int4 repeat=0;repeat<2;++repeat) {
    bool extraroots = false;
    int4 rpostcount = list.size();
    int4 rootindex = 0;
    clearEdgeFlags(~((uint4)0));	// Clear all edge flags
    while(preorder.size() < list.size()) {
      FlowBlock *startbl = (FlowBlock *)0;
      while(rootindex<rootlist.size()) { // Go thru blocks with no in edges
	startbl = rootlist[rootindex];
	rootindex += 1;
	if (startbl->visitcount == -1) break;
	// If we reach here, startbl isn't really a root (root from previous pass)
	for(int4 i=rootindex;i<rootlist.size();++i)
	  rootlist[i-1] = rootlist[i];
	rootlist.pop_back();	// Remove it
	rootindex -= 1;
	startbl = (FlowBlock *)0;
      }
      if (startbl == (FlowBlock *)0) {	// If we didn't find one, just take next unvisited
	extraroots = true;
	for(int4 i=0;i<list.size();++i) {
	  startbl = list[i];
	  if (startbl->visitcount == -1) break;
	}
	rootlist.push_back(startbl); // We have to treat this block as another root
	rootindex += 1;		// Update root traversal state
      }
      
      state.push_back(startbl);
      istate.push_back(0);
      startbl->visitcount = preorder.size();
      preorder.push_back(startbl);
      startbl->numdesc = 1;
      
      while(!state.empty()) {
	FlowBlock *curbl = state.back();
	if (curbl->sizeOut() <= istate.back()) { // We've visited all children of this node
	  state.pop_back();
	  istate.pop_back();
	  rpostcount -= 1;
	  curbl->index = rpostcount;
	  rpostorder[rpostcount] = curbl;
	  if (!state.empty())
	    state.back()->numdesc += curbl->numdesc;
	}
	else {
	  int4 edgenum = istate.back();
	  istate.back() += 1;	// Next visit to this state should try next child
	  if (curbl->isIrreducibleOut(edgenum)) continue;	// Pretend irreducible edges don't exist
	  FlowBlock *childbl = curbl->getOut(edgenum); // New child to try
	  
	  if (childbl->visitcount == -1) {	// If we haven't visited this node before
	    curbl->setOutEdgeFlag(edgenum,f_tree_edge);
	    state.push_back(childbl);
	    istate.push_back(0);
	    childbl->visitcount = preorder.size();
	    preorder.push_back(childbl);
	    childbl->numdesc = 1;
	  }
	  else if (childbl->index == -1) // childbl is already on stack
	    curbl->setOutEdgeFlag(edgenum,f_back_edge|f_loop_edge);
	  else if (curbl->visitcount < childbl->visitcount) // childbl processing is already done
	    curbl->setOutEdgeFlag(edgenum,f_forward_edge);
	  else
	    curbl->setOutEdgeFlag(edgenum,f_cross_edge);
	}
      }
    }
    if (!extraroots) break;
    if (repeat==1)
      throw LowlevelError("Could not generate spanning tree");

    // We had extra roots we did not know about so we have to regenerate the post order so entry block comes first
    tmpbl = rootlist[rootlist.size()-1];
    rootlist[rootlist.size()-1] = rootlist[origrootpos]; // Move entry block to last position in rootlist
    rootlist[origrootpos] = tmpbl;

    for(int4 i=0;i<list.size();++i) {
      tmpbl = list[i];
      tmpbl->index = -1;	// reverse post-order starts at 0
      tmpbl->visitcount = -1;
      tmpbl->copymap = tmpbl;
    }
    preorder.clear();
    state.clear();
    istate.clear();
  }
    
  if (rootlist.size() > 1) {	// Make sure orighead is at the front of the rootlist as well
    tmpbl = rootlist[rootlist.size()-1];
    rootlist[rootlist.size()-1] = rootlist[0];
    rootlist[0] = tmpbl;
  }
  
  list = rpostorder;
}

/// \brief Identify irreducible edges
///
/// Assuming the spanning tree has been properly labeled using findSpanningTree(),
/// test for and label and irreducible edges (the test ignores any edges already labeled as irreducible).
/// Return \b true if the spanning tree needs to be rebuilt, because one of the tree edges is irreducible.
/// Original algorithm due to Tarjan.
/// \param preorder is the list of FlowBlocks in pre-order
/// \param irreduciblecount will hold the number of irreducible edges
/// \return true if the spanning tree needs to be rebuilt
bool BlockGraph::findIrreducible(const vector<FlowBlock *> &preorder,int4 &irreduciblecount)

{
  vector<FlowBlock *> reachunder; // The current reachunder set being built (also with mark set on each block)
  bool needrebuild = false;
  int4 xi = preorder.size()-1;
  while(xi >= 0) {		// For each vertex in reverse pre-order
    FlowBlock *x = preorder[xi];
    xi -= 1;
    int4 sizein = x->sizeIn();
    for(int4 i=0;i<sizein;++i) {
      if (!x->isBackEdgeIn(i)) continue; // For each back-edge into x
      FlowBlock *y = x->getIn(i);
      if (y==x) continue;	// Reachunder set does not include the loop head
      reachunder.push_back(y->copymap);	// Add FIND(y) to reachunder
      y->copymap->setMark();
    }
    int4 q = 0;
    while(q < reachunder.size()) {
      FlowBlock *t = reachunder[q];
      q += 1;
      int4 sizein_t = t->sizeIn();
      for(int4 i=0;i<sizein_t;++i) {
	if (t->isIrreducibleIn(i)) continue; // Pretend irreducible edges don't exist
	// All back-edges into t have already been collapsed, so this is 
	FlowBlock *y = t->getIn(i); // For each forward, tree, or cross edge
	FlowBlock *yprime = y->copymap;	// y' = FIND(y)
	if ((x->visitcount > yprime->visitcount)||( x->visitcount + x->numdesc <= yprime->visitcount)) {
	  // The original Tarjan algorithm reports reducibility failure at this point
	  irreduciblecount += 1;
	  int4 edgeout = t->getInRevIndex(i);
	  y->setOutEdgeFlag(edgeout,f_irreducible);
	  if (t->isTreeEdgeIn(i))
	    needrebuild = true;	// If a tree edge is irreducible, we need to rebuild the spanning tree
	  else		// Otherwise we can pretend the edge was already marked irreducible
	    y->clearOutEdgeFlag(edgeout,f_cross_edge|f_forward_edge);
	}
	else if ((!yprime->isMark())&&(yprime != x)) { // if yprime is not in reachunder and not equal to x
	  reachunder.push_back(yprime);
	  yprime->setMark();
	}
      }
    }
    // Collapse reachunder into a single node, labeled as x
    for(int4 i=0;i<reachunder.size();++i) {
      FlowBlock *s = reachunder[i];
      s->clearMark();
      s->copymap = x;
    }
    reachunder.clear();
  }
  return needrebuild;
}

/// Make sure \b this has exactly 2 out edges and the first edge flows to the given FlowBlock.
/// Swap the edges if necessary. Throw an exception if this is not possible.
/// \param out0 is the given FlowBlock
void BlockGraph::forceFalseEdge(const FlowBlock *out0)

{
  if (sizeOut() != 2)
    throw LowlevelError("Can only preserve binary condition");
  if (out0->getParent() == this)	// Allow for loops to self
    out0 = this;

  if (outofthis[0].point != out0)
    swapEdges();

  if (outofthis[0].point != out0)
    throw LowlevelError("Unable to preserve condition");
}

/// \param i is the position of the first FlowBlock to swap
/// \param j is the position of the second
void BlockGraph::swapBlocks(int4 i,int4 j)

{
  FlowBlock *bl = list[i];
  list[i] = list[j];
  list[j] = bl;
}

/// For the given BlockGraph find the first component leaf FlowBlock and
/// set its properties
/// \param bl is the given BlockGraph
/// \param fl is the property to set
void BlockGraph::markCopyBlock(FlowBlock *bl,uint4 fl)

{
  bl->getFrontLeaf()->flags |= fl;
}

void BlockGraph::clear(void)

{
  vector<FlowBlock *>::iterator iter;

  for(iter=list.begin();iter!=list.end();++iter)
    delete *iter;
  list.clear();
}

void BlockGraph::markUnstructured(void)

{
  vector<FlowBlock *>::iterator iter;

  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->markUnstructured(); // Recurse
}
  
void BlockGraph::markLabelBumpUp(bool bump)

{
  FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
  if (list.empty()) return;
  vector<FlowBlock *>::iterator iter = list.begin();
  (*iter)->markLabelBumpUp(bump); // Only pass true down to first subblock
  ++iter;
  for(;iter!=list.end();++iter)
    (*iter)->markLabelBumpUp(false);
}

void BlockGraph::scopeBreak(int4 curexit,int4 curloopexit)

{
  vector<FlowBlock *>::iterator iter;
  FlowBlock *curbl;
  int4 ind;

  iter = list.begin();
  while(iter != list.end()) {
    curbl = *iter;
    ++iter;
    if (iter == list.end())
      ind = curexit;
    else
      ind = (*iter)->getIndex();
    // Recurse the scopeBreak call, making sure we pass the appropriate exit index.
    curbl->scopeBreak(ind,curloopexit);
  }
}
  
void BlockGraph::printTree(ostream &s,int4 level) const

{
  vector<FlowBlock *>::const_iterator iter;

  FlowBlock::printTree(s,level);
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->printTree(s,level+1);
}

void BlockGraph::printRaw(ostream &s) const

{
  vector<FlowBlock *>::const_iterator iter;

  printHeader(s);
  s << endl;
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->printRaw(s);
}

FlowBlock *BlockGraph::nextFlowAfter(const FlowBlock *bl) const

{
  FlowBlock *nextbl;
  vector<FlowBlock *>::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter)
    if ((*iter)==bl)
      break;
  ++iter;			// Find the first block after bl
  if (iter == list.end()) {
    if (getParent() == (FlowBlock *)0)
      return (FlowBlock *)0;
    return getParent()->nextFlowAfter(this);
  }
  nextbl = *iter;		// The next block after bl (to be emitted)
  if (nextbl != (FlowBlock *)0)
    nextbl = nextbl->getFrontLeaf();
  return nextbl;
}

void BlockGraph::finalTransform(Funcdata &data)

{
  // Recurse into all the substructures
  vector<FlowBlock *>::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->finalTransform(data);
}

void BlockGraph::finalizePrinting(Funcdata &data) const

{
  // Recurse into all the substructures
  vector<FlowBlock *>::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->finalizePrinting(data);
}

void BlockGraph::saveXmlBody(ostream &s) const

{
  FlowBlock::saveXmlBody(s);
  for(int4 i=0;i<list.size();++i) {
    FlowBlock *bl = list[i];
    s << "<bhead";
    a_v_i(s,"index",bl->getIndex());
    FlowBlock::block_type bt = bl->getType();
    string nm;
    if (bt == FlowBlock::t_if) {
      int4 sz = ((BlockGraph *)bl)->getSize();
      if (sz == 1)
	nm = "ifgoto";
      else if (sz == 2)
	nm = "properif";
      else
	nm = "ifelse";
    }
    else
      nm = FlowBlock::typeToName(bt);
    a_v(s,"type",nm);
    s << "/>\n";
  }
  for(int4 i=0;i<list.size();++i)
    list[i]->saveXml(s);
}

void BlockGraph::restoreXmlBody(List::const_iterator &iter,List::const_iterator enditer,BlockMap &resolver)

{
  BlockMap newresolver(resolver);
  FlowBlock::restoreXmlBody(iter,enditer,newresolver);
  vector<FlowBlock *> tmplist;

  while(iter != enditer) {
    const Element *el = *iter;
    if (el->getName() != "bhead") break;
    ++iter;
    int4 newindex;
    istringstream s(el->getAttributeValue("index"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> newindex;
    const string &nm( el->getAttributeValue("type") );
    FlowBlock *bl = newresolver.createBlock(nm);
    bl->index = newindex;	// Need to set index here for sort
    tmplist.push_back(bl);
  }
  newresolver.sortList();

  for(int4 i=0;i<tmplist.size();++i) {
    if (iter == enditer)
      throw LowlevelError("Bad BlockGraph xml");
    FlowBlock *bl = tmplist[i];
    bl->restoreXml(*iter,newresolver);
    addBlock(bl);
    ++iter;
  }
}

/// This is currently just a wrapper around the FlowBlock::restoreXml()
/// that sets of the BlockMap resolver
/// \param el is the root \<block> tag
/// \param m is the address space manager
void BlockGraph::restoreXml(const Element *el,const AddrSpaceManager *m)

{
  BlockMap resolver(m);
  FlowBlock::restoreXml(el,resolver);
  // Restore goto references here
}

/// \param begin is the start FlowBlock
/// \param end is the stop FlowBlock
void BlockGraph::addEdge(FlowBlock *begin,FlowBlock *end)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if ((begin->parent != this)||(end->parent != this))
    throw LowlevelError("Bad edge create");
#endif
  end->addInEdge(begin,0);
}

/// \param begin is a given component FlowBlock
/// \param outindex is the index of the \e out edge to mark as a loop
void BlockGraph::addLoopEdge(FlowBlock *begin,int4 outindex)

{
#ifdef BLOCKCONSISTENT_DEBUG
  //if ((begin->parent != this)||(end->parent != this))
if ((begin->parent != this))
    throw LowlevelError("Bad loopedge create");
#endif
  //  int4 i;
  //  i = begin->OutIndex(end);
  // using OutIndex did not necessarily get the right edge
  // if there were multiple outedges to the same block
  begin->setOutEdgeFlag(outindex,f_loop_edge);
}

/// The edge must already exist
/// \param begin is the incoming FlowBlock of the edge
/// \param end is the outgoing FlowBlock
void BlockGraph::removeEdge(FlowBlock *begin,FlowBlock *end)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if ((begin->parent != this)||(end->parent != this))
    throw LowlevelError("Bad edge remove");
#endif
  int4 i;
  for(i=0;i<end->intothis.size();++i)
    if (end->intothis[i].point == begin)
      break;
  end->removeInEdge(i);
}

/// The edge from \b in to \b outbefore must already exist.  It will get removed
/// and replaced with an edge from \b in to \b outafter.  The new edge index
/// will be the same as the removed edge, and all other edge ordering will be preserved.
/// \param in is the input FlowBlock
/// \param outbefore is the initial output FlowBlock
/// \param outafter is the new output FlowBlock
void BlockGraph::switchEdge(FlowBlock *in,FlowBlock *outbefore,FlowBlock *outafter)

{
  for(int4 i=0;i<in->outofthis.size();++i)
    if (in->outofthis[i].point == outbefore)
      in->replaceOutEdge(i,outafter);
}

/// Given an edge specified by its input FlowBlock, replace that
/// input with new FlowBlock.
/// \param blold is the original input FlowBlock
/// \param slot is the index of the \e out edge of \b blold
/// \param blnew is the FlowBlock that will become the input to the edge
void BlockGraph::moveOutEdge(FlowBlock *blold,int4 slot,FlowBlock *blnew)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if ((blold->parent != this)||(blnew->parent != this))
    throw LowlevelError("Bad edge move");
#endif
  FlowBlock *outbl = blold->getOut(slot);
  int4 i = blold->getOutRevIndex(slot);
  outbl->replaceInEdge(i,blnew);
}

/// The indicated block is pulled out of the component list and deleted.
/// Any edges between it and the rest of the BlockGraph are simply removed.
/// \param bl is the indicated block
void BlockGraph::removeBlock(FlowBlock *bl)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if (bl->parent != this)
    throw LowlevelError("Bad block remove");
#endif
  vector<FlowBlock *>::iterator iter;
  while(bl->sizeIn()>0)		// Rip the block out of the graph
    removeEdge(bl->getIn(0),bl);
  while(bl->sizeOut()>0)
    removeEdge(bl,bl->getOut(0));

  for(iter=list.begin();iter!=list.end();++iter)
    if (*iter == bl) {
      list.erase(iter);
      break;
    }
  delete bl;			// Free up memory
}

/// This should be applied only if the given FlowBlock has 0 or 1 outputs.
/// If there is an output FlowBlock, all incoming edges to the given FlowBlock
/// are moved so they flow into the output FlowBlock, then all remaining edges
/// into or out of the given FlowBlock are removed.  The given FlowBlock is \b not
/// removed from \b this.
/// This routine doesn't preserve loopedge information
/// \param bl is the given FlowBlock component
void BlockGraph::removeFromFlow(FlowBlock *bl)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if (bl->parent != this)
    throw LowlevelError("Bad remove from flow");
  if ((bl->sizeIn()>0)&&(bl->sizeOut()>1))
    throw LowlevelError("Illegal remove from flow");
#endif
  FlowBlock *bbout,*bbin;
  while(bl->sizeOut()>0) {
    bbout = bl->getOut(bl->sizeOut()-1);
    bl->removeOutEdge(bl->sizeOut()-1);
    while(bl->sizeIn()>0) {
      bbin = bl->getIn(0);
      bbin->replaceOutEdge(bl->intothis[0].reverse_index,bbout);
    }
  }
}

/// Remove the given FlowBlock from the flow of the graph. It must have
/// 2 inputs, and 2 outputs.  The edges will be remapped so that
///   - In(0) -> Out(0) and
///   - In(1) -> Out(1)
///
/// Or if \b flipflow is true:
///   - In(0) -> Out(1)
///   - In(1) -> Out(0)
/// \param bl is the given FlowBlock
/// \param flipflow indicates how the edges are remapped
void BlockGraph::removeFromFlowSplit(FlowBlock *bl,bool flipflow)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if (bl->parent != this)
    throw LowlevelError("Bad remove from flow split");
  if ((bl->sizeIn()!=2)&&(bl->sizeOut()!=2))
    throw LowlevelError("Illegal remove from flow split");
#endif
  if (flipflow)
    bl->replaceEdgesThru(0,1);	// Replace edge slot from 0 -> 1
  else
    bl->replaceEdgesThru(1,1);	// Replace edge slot from 1 -> 1
  // Removing the first edge
  bl->replaceEdgesThru(0,0);	// Replace remaining edge
}

/// The given FlowBlock must have exactly one output.  That output must have
/// exactly one input.  The output FlowBlock is removed and any outgoing edges
/// it has become outgoing edge of the given FlowBlock.  The output FlowBlock
/// is permanently removed. It is viewed as being \e spliced together with the given FlowBlock.
/// \param bl is the given FlowBlock
void BlockGraph::spliceBlock(FlowBlock *bl)

{
  FlowBlock *outbl = (FlowBlock *)0;
  if (bl->sizeOut() == 1) {
    outbl = bl->getOut(0);
    if (outbl->sizeIn() != 1)
      outbl = (FlowBlock *)0;
  }
  if (outbl == (FlowBlock *)0)
    throw LowlevelError("Can only splice a block with 1 output to a block with 1 input");
  // Flags from the input block that we keep
  uint4 fl1 = bl->flags & (f_unstructured_targ|f_entry_point);
  // Flags from the output block that we keep
  uint4 fl2 = outbl->flags & f_switch_out;
  bl->removeOutEdge(0);
  // Move every out edge of -outbl- to -bl-
  int4 szout = outbl->sizeOut();
  for(int4 i=0;i<szout;++i)
    moveOutEdge(outbl,0,bl);

  removeBlock(outbl);
  bl->flags = fl1 | fl2;
}

/// The component list is reordered to make the given FlowBlock first.
/// The \e f_entry_point property is updated.
/// \param bl is the given FlowBlock to make the entry point
void BlockGraph::setStartBlock(FlowBlock *bl)

{
#ifdef BLOCKCONSISTENT_DEBUG
  if (bl->parent != this)
    throw LowlevelError("Bad set start");
#endif
  if ((list[0]->flags&f_entry_point)!=0) {
    if (bl == list[0]) return;	// Already set as start block
    list[0]->flags &= ~f_entry_point; // Remove old entry point
  }

  int4 i;
  for(i=0;i<list.size();++i)
    if (list[i] == bl) break;

  for(int4 j=i;j>0;--j)		// Slide everybody down
    list[j] = list[j-1];
  list[0] = bl;
  bl->flags |= f_entry_point;
}

/// Throw an exception if no entry point is registered
/// \return the entry point FlowBlock
FlowBlock *BlockGraph::getStartBlock(void) const

{
  if (list.empty() || ((list[0]->flags&f_entry_point)==0))
    throw LowlevelError("No start block registered");
  return list[0];
}

/// Add the new FlowBlock to \b this
/// \return the new FlowBlock
FlowBlock *BlockGraph::newBlock(void)

{
  FlowBlock *ret = new FlowBlock();
  addBlock(ret);
  return ret;
}

/// Add the new BlockBasic to \b this
/// \param fd is the function underlying the basic block
/// \return the new BlockBasic
BlockBasic *BlockGraph::newBlockBasic(Funcdata *fd)

{
  BlockBasic *ret = new BlockBasic(fd);
  addBlock(ret);
  return ret;
}

/// Add the new BlockCopy to \b this
/// \param bl is the FlowBlock underlying the copy
/// \return the new BlockCopy
BlockCopy *BlockGraph::newBlockCopy(FlowBlock *bl)

{
  BlockCopy *ret = new BlockCopy(bl);
  ret->intothis = bl->intothis;
  ret->outofthis = bl->outofthis;
  ret->immed_dom = bl->immed_dom;
  ret->index = bl->index;
  // visitcount needs to be initialized to zero via FlowBlock constructure
  //  ret->visitcount = bl->visitcount;
  ret->numdesc = bl->numdesc;
  ret->flags |= bl->flags;
  if (ret->outofthis.size() > 2)
    ret->flags |= f_switch_out;	// Make sure switch is marked (even if not produced by INDIRECT) as it is needed for structuring
  addBlock(ret);
  return ret;
}

/// Add the new BlockGoto to \b this, incorporating the given FlowBlock
/// \param bl is the given FlowBlock whose outgoing edge is to be marked as a \e goto
/// \return the new BlockGoto
BlockGoto *BlockGraph::newBlockGoto(FlowBlock *bl)

{
  BlockGoto *ret = new BlockGoto(bl->getOut(0));
  vector<FlowBlock *> nodes;
  nodes.push_back(bl);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(1);
  removeEdge(ret,ret->getOut(0));	// Treat out edge as if it didn't exist
  return ret;
}

/// The given FlowBlock may already be a BlockMultiGoto, otherwise we
/// add the new BlockMultiGoto to \b this.
/// \param bl is the given FlowBlock with the new \e goto edge
/// \param outedge is the index of the outgoing edge to make into a \e goto
/// \return the (possibly new) BlockMultiGoto
BlockMultiGoto *BlockGraph::newBlockMultiGoto(FlowBlock *bl,int4 outedge)

{
  BlockMultiGoto *ret;
  FlowBlock *targetbl = bl->getOut(outedge);
  bool isdefaultedge = bl->isDefaultBranch(outedge);
  if (bl->getType() == t_multigoto) { // Already one goto edge from this same block, we add to existing structure
    ret = (BlockMultiGoto *)bl;
    ret->addEdge(targetbl);
    removeEdge(ret,targetbl);
    if (isdefaultedge)
      ret->setDefaultGoto();
  }
  else {
    ret = new BlockMultiGoto(bl);
    vector<FlowBlock *> nodes;
    nodes.push_back(bl);
    identifyInternal(ret,nodes);
    addBlock(ret);
    ret->addEdge(targetbl);
    if (targetbl != bl)		// If the target is itself, edge is already removed by identifyInternal
      removeEdge(ret,targetbl);
    if (isdefaultedge)
      ret->setDefaultGoto();
  }
  return ret;
}

/// Add the new BlockList to \b this, collapsing the given FlowBlock components into it.
/// \param nodes is the given set of FlowBlocks components
/// \return the new BlockList
BlockList *BlockGraph::newBlockList(const vector<FlowBlock *> &nodes)

{
  const FlowBlock *out0 = (const FlowBlock *)0;
  int4 outforce = nodes.back()->sizeOut();
  if (outforce==2)
    out0 = nodes.back()->getOut(0);
  BlockList *ret = new BlockList();
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(outforce);
  if (ret->sizeOut()==2)
    ret->forceFalseEdge(out0);	// Preserve the condition
  //  if ((ret->OutSize() == 2)&&(nodes.back()->Out(0) == nodes.front()))
  //    ret->FlowBlock::negateCondition(); // Preserve out ordering of last block
  return ret;
}

/// Add the new BlockCondition to \b this, collapsing its pieces into it.
/// \param b1 is the first FlowBlock piece
/// \param b2 is the second FlowBlock piece
/// \return the new BlockCondition
BlockCondition *BlockGraph::newBlockCondition(FlowBlock *b1,FlowBlock *b2)

{
  const FlowBlock *out0 = b2->getOut(0);
  vector<FlowBlock *> nodes;
  OpCode opc = (b1->getFalseOut() == b2) ? CPUI_INT_OR : CPUI_INT_AND;
  BlockCondition *ret = new BlockCondition(opc);
  nodes.push_back(b1);
  nodes.push_back(b2);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(2);	// All conditions must have two outputs
  ret->forceFalseEdge(out0);	// Preserve the condition
  return ret;
}

/// Add the new BlockIfGoto to \b this, collapsing the given condition FlowBlock into it.
/// \param cond is the given condition FlowBlock
/// \return the new BlockIfGoto
BlockIf *BlockGraph::newBlockIfGoto(FlowBlock *cond)

{
  if (!cond->isGotoOut(1))	// True branch must be a goto branch
    throw LowlevelError("Building ifgoto where true branch is not the goto");

  const FlowBlock *out0 = cond->getOut(0);
  vector<FlowBlock *> nodes;
  BlockIf *ret = new BlockIf();
  ret->setGotoTarget(cond->getOut(1)); // Store the target
  nodes.push_back(cond);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(2);
  ret->forceFalseEdge(out0);		// Preserve the condition
  removeEdge(ret,ret->getTrueOut());	// Treat the true edge as if it didn't exist
  return ret;
}

/// Add the new BlockIf to \b this, collapsing the condition and body FlowBlocks into it.
/// \param cond is the condition FlowBlock
/// \param tc is the body FlowBlock
/// \return the new BlockIf
BlockIf *BlockGraph::newBlockIf(FlowBlock *cond,FlowBlock *tc)

{
  vector<FlowBlock *> nodes;
  BlockIf *ret = new BlockIf();
  nodes.push_back(cond);
  nodes.push_back(tc);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(1);
  return ret;
}

/// Add the new BlockIfElse to \b this, collapsing the condition, true clause, and false clause into it.
/// \param cond is the condition FlowBlock
/// \param tc is the true clause FlowBlock
/// \param fc is the false clause FlowBlock
/// \return the new BlockIf
BlockIf *BlockGraph::newBlockIfElse(FlowBlock *cond,FlowBlock *tc,FlowBlock *fc)

{
  vector<FlowBlock *> nodes;
  BlockIf *ret = new BlockIf();
  nodes.push_back(cond);
  nodes.push_back(tc);
  nodes.push_back(fc);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(1);
  return ret;
}

/// Add the new BlockWhileDo to \b this, collapsing the condition and clause into it.
/// \param cond is the condition FlowBlock
/// \param cl is the clause FlowBlock
/// \return the new BlockWhileDo
BlockWhileDo *BlockGraph::newBlockWhileDo(FlowBlock *cond,FlowBlock *cl)

{
  vector<FlowBlock *> nodes;
  BlockWhileDo *ret = new BlockWhileDo();
  nodes.push_back(cond);
  nodes.push_back(cl);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(1);
  return ret;
}

/// Add the new BlockDoWhile to \b this, collapsing the condition clause FlowBlock into it.
/// \param condcl is the condition clause FlowBlock
/// \return the new BlockDoWhile
BlockDoWhile *BlockGraph::newBlockDoWhile(FlowBlock *condcl)

{
  vector<FlowBlock *> nodes;
  BlockDoWhile *ret = new BlockDoWhile();
  nodes.push_back(condcl);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(1);
  return ret;
}

/// Add the new BlockInfLoop to \b this, collapsing the body FlowBlock into it.
/// \param body is the body FlowBlock
/// \return the new BlockInfLoop
BlockInfLoop *BlockGraph::newBlockInfLoop(FlowBlock *body)

{
  vector<FlowBlock *> nodes;
  BlockInfLoop *ret = new BlockInfLoop();
  nodes.push_back(body);
  identifyInternal(ret,nodes);
  addBlock(ret);
  return ret;
}

/// Add the new BlockSwitch to \b this, collapsing all the case FlowBlocks into it.
/// \param cs is the list of case FlowBlocks
/// \param hasExit is \b true if the switch has a formal exit
/// \return the new BlockSwitch
BlockSwitch *BlockGraph::newBlockSwitch(const vector<FlowBlock *> &cs,bool hasExit)

{
  FlowBlock *rootbl = cs[0];
  BlockSwitch *ret = new BlockSwitch(rootbl);
  const FlowBlock *leafbl = rootbl->getExitLeaf();
  if ((leafbl == (const FlowBlock *)0)||(leafbl->getType() != FlowBlock::t_copy))
    throw LowlevelError("Could not get switch leaf");
  ret->grabCaseBasic(leafbl->subBlock(0),cs); // Must be called before the identifyInternal
  identifyInternal(ret,cs);
  addBlock(ret);
  if (hasExit)
    ret->forceOutputNum(1);	// If there is an exit, there should be exactly 1 out edge
  ret->clearFlag(f_switch_out);	// Don't consider this as being a switch "out"
  return ret;
}

/// Construct a copy of the given BlockGraph in \b this.  The nodes of the copy
/// will be official BlockCopy objects which will contain a reference to their
/// corresponding FlowBlock in the given graph.  All edges will be duplicated.
/// \param graph is the given BlockGraph to copy
void BlockGraph::buildCopy(const BlockGraph &graph)

{
  BlockCopy *copyblock;
  int4 startsize = list.size();
  vector<FlowBlock *>::const_iterator iter;
  
  for(iter=graph.list.begin();iter!=graph.list.end();++iter) {
    copyblock = newBlockCopy(*iter);
    (*iter)->copymap = copyblock; // Store map basic->copy
  }
  for(iter=list.begin()+startsize;iter!=list.end();++iter)
    (*iter)->replaceUsingMap();
}

void BlockGraph::clearVisitCount(void)

{
  for(int4 i=0;i<list.size();++i)
    list[i]->visitcount = 0;
}

/// Calculate the immediate dominator for each FlowBlock node in \b this BlockGraph,
/// for forward control-flow.
/// The algorithm must be provided a list of entry points for the graph.
/// We assume the blocks are in reverse post-order and this is reflected in the index field.
/// Using an algorithm by Cooper, Harvey, and Kennedy.
/// Softw. Pract. Exper. 2001; 4: 1-10
/// \param rootlist is the list of entry point FlowBlocks
void BlockGraph::calcForwardDominator(const vector<FlowBlock *> &rootlist)

{
  vector<FlowBlock *> postorder;
  FlowBlock *virtualroot;
  FlowBlock *b,*new_idom,*rho;
  bool changed;
  int4 i,j,finger1,finger2;

  if (list.empty()) return;
  int4 numnodes = list.size()-1;
  postorder.resize(list.size());
  for(i=0;i<list.size();++i) {
    list[i]->immed_dom = (FlowBlock *)0; // Clear the dominator field
    postorder[ numnodes-i ] = list[i]; // Construct a forward post order list
  }
  if (rootlist.size() > 1) {
    virtualroot = createVirtualRoot(rootlist);
    postorder.push_back(virtualroot);
  }
  else
    virtualroot = (FlowBlock *)0;

  b = postorder.back();		// The official start node
  if (b->sizeIn() != 0) {	// Root node must have no in edges
    if ((rootlist.size() != 1)||(rootlist[0] != b))
      throw LowlevelError("Problems finding root node of graph");
    virtualroot = createVirtualRoot(rootlist); // Create virtual root with no in edges
    postorder.push_back(virtualroot);
    b = virtualroot;
  }
  b->immed_dom = b;
  for(i=0;i<b->sizeOut();++i)	// Fill in dom of nodes which start immediately
    b->getOut(i)->immed_dom = b;	// connects to (to deal with possible artificial edge)
  changed = true;
  new_idom = (FlowBlock *)0;
  while(changed) {
    changed = false;
    for(i=postorder.size()-2;i>=0;--i) { // For all nodes, in reverse post-order, except root
      b = postorder[i];
      if (b->immed_dom != postorder.back()) {
	for(j=0;j<b->sizeIn();++j) { // Find first processed node
	  new_idom = b->getIn(j);
	  if (new_idom->immed_dom != (FlowBlock *)0)
	    break;
	}
	j += 1;
	for(;j<b->sizeIn();++j) {
	  rho = b->getIn(j);
	  if (rho->immed_dom != (FlowBlock *)0) { // Here is the intersection routine
	    finger1 = numnodes - rho->index;
	    finger2 = numnodes - new_idom->index;
	    while(finger1 != finger2) {
	      while(finger1 < finger2)
		finger1 = numnodes - postorder[finger1]->immed_dom->index;
	      while(finger2 < finger1)
		finger2 = numnodes - postorder[finger2]->immed_dom->index;
	    }
	    new_idom = postorder[finger1];
	  }
	}
	if (b->immed_dom != new_idom) {
	  b->immed_dom = new_idom;
	  changed = true;
	}
      }
    }
  }
  if (virtualroot != (FlowBlock *)0) { // If there was a virtual root, excise it from the dominator tree
    for(i=0;i<list.size();++i)
      if (postorder[i]->immed_dom == virtualroot)
	postorder[i]->immed_dom = (FlowBlock *)0; // Remove the dominator link to virtualroot
    while(virtualroot->sizeOut() > 0)
      virtualroot->removeOutEdge(virtualroot->sizeOut()-1); // Remove any edges from virtualroot
    delete virtualroot;
  }
  else
    postorder.back()->immed_dom = (FlowBlock *)0;
}

/// Associate dominator children with each node via a list (of lists) indexed by the FlowBlock index.
/// \param child is the initially empty list of lists
void BlockGraph::buildDomTree(vector<vector<FlowBlock *> > &child) const

{
  FlowBlock *bl;

  child.clear();
  child.resize(list.size()+1);
  for(int4 i=0;i<list.size();++i) {
    bl = list[i];
    if (bl->immed_dom != (FlowBlock *)0)
      child[bl->immed_dom->index].push_back(bl);
    else
      child[list.size()].push_back(bl);
  }
}

/// Associate every FlowBlock node in \b this graph with its depth in the dominator tree.
/// The dominator root has depth 1, the nodes it immediately dominates have depth 2, etc.
/// \param depth is array that will be populated with depths
/// \return the maximum depth across all nodes
int4 BlockGraph::buildDomDepth(vector<int4> &depth) const

{
  FlowBlock *bl;
  int4 max = 0;

  depth.resize(list.size()+1);
  for(int4 i=0;i<list.size();++i) {
    bl = list[i]->immed_dom;
    if (bl != (FlowBlock *)0)
      depth[i] = depth[bl->getIndex()] + 1;
    else
      depth[i] = 1;
    if (max<depth[i])
      max = depth[i];
  }
  depth[list.size()] = 0;
  return max;
}

/// Collect all nodes in the dominator sub-tree starting at a given root FlowBlock.
/// We assume blocks in are reverse post order.
/// \param res will hold the list of nodes in the sub-tree
/// \param root is the given root FlowBlock
void BlockGraph::buildDomSubTree(vector<FlowBlock *> &res,FlowBlock *root) const

{
  FlowBlock *bl,*dombl;
  int4 rootindex = root->getIndex();
  res.push_back(root);
  for(int4 i=rootindex+1;i<list.size();++i) {
    bl = list[i];
    dombl = bl->getImmedDom();
    if (dombl == (FlowBlock *)0) break;
    if (dombl->getIndex() > rootindex) break;
    res.push_back(bl);
  }
}

/// This algorithm identifies a set of edges such that,
/// if the edges are removed, the remaining graph has NO directed cycles
/// The algorithm works as follows:
/// Starting from the start block, do a depth first search through the "out" edges
/// of the block.  If the outblock is already on the current path from root to node,
/// we have found a cycle, we add the last edge to the list and continue pretending
/// that edge didn't exist.  If the outblock is not on the current path but has
/// been visited before, we can truncate the search.
/// This is now only applied as a failsafe if the graph has irreducible edges.
void BlockGraph::calcLoop(void)

{				// Look for directed cycles in graph
				// Mark edges (loopedges) that can be removed
				// to prevent looping
  vector<FlowBlock *>::iterator iter;
  FlowBlock *bl,*nextbl;
  int4 i;

  if (list.empty()) return;	// Nothing to do

  vector<FlowBlock *> path;		// Current depth first path
  vector<int4> state;

  path.push_back(list.front());
  state.push_back(0);		// No children visited yet
  list.front()->setFlag(f_mark|f_mark2); // Mark this node as visited and on path
  while(!path.empty()) {
    bl = path.back();
    i = state.back();
    if (i >= bl->sizeOut()) {	// Visited everything below this node, POP
      bl->clearFlag(f_mark2);	// Mark this node as no longer on the path
      path.pop_back();
      state.pop_back();
    }
    else {
      state.back() += 1;
      if (bl->isLoopOut(i)) continue; // Previously marked loop-edge (act as if it doesn't exist)
      nextbl = bl->getOut(i);
      if ((nextbl->flags&f_mark2) != 0) { // We found a cycle!
	// Technically we should never reach here if the reducibility algorithms work
	addLoopEdge(bl,i);
	//	throw LowlevelError("Found a new loop despite irreducibility");
      }
      else if ((nextbl->flags&f_mark)==0) { // Fresh node
	nextbl->setFlag(f_mark|f_mark2);
	path.push_back(nextbl);
	state.push_back(0);
      }
    }
  }
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->clearFlag(f_mark|f_mark2);	// Clear our marks
}

/// If the boolean \b un is \b true, collect unreachable blocks. Otherwise
/// collect reachable blocks.
/// \param res will hold the reachable or unreachable FlowBlocks
/// \param bl is the starting FlowBlock
/// \param un toggles reachable,unreachable
void BlockGraph::collectReachable(vector<FlowBlock *> &res,FlowBlock *bl,bool un) const

{
  FlowBlock *blk,*blk2;

  bl->setMark();
  res.push_back(bl);
  int4 total = 0;

  // Propagate forward to find all reach blocks from entry point
  while(total < res.size()) {
    blk = res[total++];
    for(int4 j=0;j<blk->sizeOut();++j) {
      blk2 = blk->getOut(j);
      if (blk2->isMark()) continue;
      blk2->setMark();
      res.push_back(blk2);
    }
  }
  if (un) {
    res.clear();		// Anything not marked is unreachable
    for(int4 i=0;i<list.size();++i) {
      blk = list[i];
      if (blk->isMark())
	blk->clearMark();
      else
	res.push_back(blk);
    }
  }
  else {
    for(int4 i=0;i<res.size();++i)
      res[i]->clearMark();
  }
}

/// - Find irreducible edges
/// - Find a spanning tree
/// - Set FlowBlock indices in reverse-post order
/// - Label tree-edges, forward-edges, cross-edges, and back-edges
/// \param rootlist will contain the entry points for the graph
void BlockGraph::structureLoops(vector<FlowBlock *> &rootlist)

{
  vector<FlowBlock *> preorder;
  bool needrebuild;
  int4 irreduciblecount = 0;

  do {
    needrebuild = false;
    findSpanningTree(preorder,rootlist);
    needrebuild = findIrreducible(preorder,irreduciblecount);
    if (needrebuild) {
      clearEdgeFlags(f_tree_edge|f_forward_edge|f_cross_edge|f_back_edge|f_loop_edge); // Clear the spanning tree
      preorder.clear();
      rootlist.clear();
    }
  } while(needrebuild);
  if (irreduciblecount > 0) {
    // We need some kind of check here, like calcLoop, to make absolutely sure removing the loop edges makes a DAG
    calcLoop();
  }
}

#ifdef BLOCKCONSISTENT_DEBUG
bool BlockGraph::isConsistent(void) const

{
  FlowBlock *bl1,*bl2;
  int4 i,j,k;
  int4 count1,count2;

  for(i=0;i<list.size();++i) {
    bl1 = list[i];
    for(j=0;j<bl1->sizeIn();++j) {
      bl2 = bl1->getIn(j);		// For each in edge
      count1 = 0;
      for(k=0;k<bl1->sizeIn();++k)
	if (bl1->getIn(k)==bl2) count1 += 1;
      count2 = 0;
      for(k=0;k<bl2->sizeOut();++k)
	if (bl2->getOut(k)==bl1) count2 += 1;
      if (count1 != count2)
	return false;
    }
    for(j=0;j<bl1->sizeOut();++j) {
      bl2 = bl1->getOut(j);	// Similarly for each out edge
      count1 = 0;
      for(k=0;k<bl1->sizeOut();++k)
	if (bl1->getOut(k)==bl2) count1 += 1;
      count2 = 0;
      for(k=0;k<bl2->sizeIn();++k)
	if (bl2->getIn(k)==bl1) count2 += 1;
      if (count1 != count2)
	return false;
    }
  }
  return true;
}
#endif

/// The operation is inserted \e before the PcodeOp pointed at by the iterator.
/// This method also assigns the ordering index for the PcodeOp, getSeqNum().getOrder()
/// \param iter points at the PcodeOp to insert before
/// \param inst is the PcodeOp to insert
void BlockBasic::insert(list<PcodeOp *>::iterator iter,PcodeOp *inst)

{
  uintm ordbefore,ordafter;
  list<PcodeOp *>::iterator newiter;

  inst->setParent( this );
  newiter = op.insert(iter,inst);
  inst->setBasicIter(newiter);
  if (newiter == op.begin())
    ordbefore = 2;		// This is minimum possible order val
  else {
    --newiter;
    ordbefore = (*newiter)->getSeqNum().getOrder();
  }
  if (iter==op.end()) {
    ordafter = ordbefore+0x1000000;
    if (ordafter <= ordbefore)
      ordafter = ~((uintm)0);
  }
  else
    ordafter = (*iter)->getSeqNum().getOrder();
  if (ordafter-ordbefore<=1)
    setOrder();
  else
    inst->setOrder( ordafter/2 + ordbefore/2 ); // Beware overflow

  if (inst->isBranch()) {
    if (inst->code()==CPUI_BRANCHIND)
      setFlag(f_switch_out);
  }
}

/// \param inst is the PcodeOp to remove, which \e must be in the block
void BlockBasic::removeOp(PcodeOp *inst)

{
  inst->setParent( (BlockBasic *)0 );
  op.erase(inst->basiciter);
}

/// This relies slightly on \e normal semantics: when instructions \e fall-thru during execution,
/// the associated address increases.
/// \return the address of the original entry point instruction for \b this block
Address BlockBasic::getEntryAddr(void) const

{
  const Range *range;
  if (cover.numRanges() == 1)		// If block consists of 1 range
    range = cover.getFirstRange();	// return the start of range
  else {
    if (op.empty())
      return Address();
    const Address &addr(op.front()->getAddr());	// Find range of first op
    range = cover.getRange(addr.getSpace(),addr.getOffset());
    if (range == (const Range *)0)
      return op.front()->getAddr();
  }
  return range->getFirstAddr();
}

Address BlockBasic::getStart(void) const

{
  const Range *range = cover.getFirstRange();
  if (range == (const Range *)0)
    return Address();
  return range->getFirstAddr();
}

Address BlockBasic::getStop(void) const

{
  const Range *range = cover.getLastRange();
  if (range == (const Range *)0)
    return Address();
  return range->getLastAddr();
}

PcodeOp *BlockBasic::lastOp(void) const

{
  if (op.empty()) return (PcodeOp *)0;
  return (PcodeOp *) op.back();
}

bool BlockBasic::negateCondition(bool toporbottom)

{
  PcodeOp *lastop = op.back();
  lastop->flipFlag(PcodeOp::boolean_flip); // Flip the meaning of condition
  lastop->flipFlag(PcodeOp::fallthru_true); // Flip whether fall-thru block is true/false
  FlowBlock::negateCondition(true); // Flip the order of outgoing edges
  return true;			// Return -true- to indicate a change was made to data-flow
}

FlowBlock *BlockBasic::getSplitPoint(void)

{
  if (sizeOut() != 2) return (FlowBlock *)0;
  return this;
}

int4 BlockBasic::flipInPlaceTest(vector<PcodeOp *> &fliplist) const

{
  if (op.empty()) return 2;
  PcodeOp *lastop = op.back();
  if (lastop->code() != CPUI_CBRANCH)
    return 2;
  return opFlipInPlaceTest(lastop,fliplist);
}

void BlockBasic::flipInPlaceExecute(void)

{
  PcodeOp *lastop = op.back();
  // This is similar to negateCondition but we don't need to set the boolean_flip flag on lastop
  // because it is getting explicitly changed
  lastop->flipFlag(PcodeOp::fallthru_true); // Flip whether the fallthru block is true/false
  FlowBlock::negateCondition(true); // Flip the order of outof this
}

bool BlockBasic::isComplex(void) const

{
  list<PcodeOp *>::const_iterator iter,iter2;
  PcodeOp *inst,*d_op;
  Varnode *vn;
  int4 statement,maxref;

  // Is this block too complicated for a condition.
  // We count the number of statements in the block
  statement = 0;
  if (sizeOut()>=2)
    statement = 1;		// Consider the branch as a statement
  maxref = data->getArch()->max_implied_ref; // Max number of uses a varnode can have
				// before it must be considered an explicit variable
  for(iter=op.begin();iter!=op.end();++iter) {
    inst = *iter;
    if (inst->isMarker()) continue;
    vn = inst->getOut();
    if (inst->isCall())
      statement += 1;
    else if (vn==(Varnode *)0) {
      if (inst->isFlowBreak()) continue;
      statement += 1;
    }
    else {			// If the operation is a calculation with output
				// This is a conservative version of 
				// Varnode::calc_explicit
      bool yesstatement = false;
      if (vn->hasNoDescend())
	yesstatement = true;
      else if (vn->isAddrTied())	// Being conservative
	yesstatement = true;
      else {
	int4 totalref = 0;	// Number of references to this variable
	
	for(iter2=vn->beginDescend();iter2!=vn->endDescend();++iter2) {
	  d_op = *iter2;
	  if (d_op->isMarker()||(d_op->getParent() != this)) { // Variable used outside of block
	    yesstatement = true;
	    break;
	  }
	  totalref += 1;
	  if (totalref > maxref) {	// If used too many times
	    yesstatement = true; // consider defining op as a statement
	    break;
	  }
	}
      }
      if (yesstatement)
	statement += 1;
    }

    if (statement >2) return true;
  }
  return false;
}

/// \param s is the output stream
void FlowBlock::saveXmlHeader(ostream &s) const

{
  a_v_i(s,"index",index);
}

/// \param el is the XML element to pull attributes from
void FlowBlock::restoreXmlHeader(const Element *el)

{
  istringstream s(el->getAttributeValue("index"));
  s.unsetf(ios::dec | ios::hex | ios::oct);
  s >> index;
}

/// Write \<edge> tags to stream
/// \param s is the output stream
void FlowBlock::saveXmlEdges(ostream &s) const

{
  for(int4 i=0;i<intothis.size();++i) {
    intothis[i].saveXml(s);
  }
}

/// \brief Restore edges from an XML stream
///
/// \param iter is an iterator to the \<edge> tags
/// \param enditer marks the end of the list of tags
/// \param resolver is used to recover FlowBlock cross-references
void FlowBlock::restoreXmlEdges(List::const_iterator &iter,List::const_iterator enditer,BlockMap &resolver)

{
  while(iter != enditer) {
    const Element *el = *iter;
    if (el->getName() != "edge")
      return;
    ++iter;
    restoreNextInEdge(el,resolver);
  }
}

/// Serialize \b this and all its sub-components as an XML \<block> tag.
/// \param s is the output stream
void FlowBlock::saveXml(ostream &s) const

{
  s << "<block";
  saveXmlHeader(s);
  s << ">\n";
  saveXmlBody(s);
  saveXmlEdges(s);
  s << "</block>\n";
}

/// Recover \b this and all it sub-components from an XML \<block> tag.
///
/// This will construct all the sub-components using \b resolver as a factory.
/// \param el is the root XML element
/// \param resolver acts as a factory and resolves cross-references
void FlowBlock::restoreXml(const Element *el,BlockMap &resolver)

{
  restoreXmlHeader(el);
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  restoreXmlBody(iter,list.end(),resolver);
  restoreXmlEdges(iter,list.end(),resolver);
}

/// If there are two branches, pick the fall-thru branch
/// \return the next block in flow, or NULL otherwise
const FlowBlock *FlowBlock::nextInFlow(void) const

{
  const PcodeOp *op;

  if (sizeOut()==1) return getOut(0);
  if (sizeOut()==2) {
    op = lastOp();
    if (op == (const PcodeOp *)0) return (const FlowBlock *)0;
    if (op->code() != CPUI_CBRANCH) return (const FlowBlock *)0;
    return op->isFallthruTrue() ? getOut(1) : getOut(0);
  }
  return (const FlowBlock *)0;
}

/// Does removing this block leads to redundant MULTIEQUAL entries which are inconsistent.
/// A MULTIEQUAL can hide an implied copy, in which case \b this block is actually doing something
/// and shouldn't be removed.
/// \param outslot is the index of the outblock that \b this is getting collapsed to
/// \return true if there is no implied COPY
bool BlockBasic::unblockedMulti(int4 outslot) const

{
  const BlockBasic *blout = (const BlockBasic *)getOut(outslot);
  const FlowBlock *bl;
  PcodeOp *multiop,*othermulti;
  list<PcodeOp *>::const_iterator iter;
  Varnode *vnremove,*vnredund;
  
				// First we build list of blocks which would have
				// redundant branches into blout
  vector<const FlowBlock *> redundlist;
  for(int4 i=0;i<sizeIn();++i) {
    bl = getIn(i);
    for(int4 j=0;j<bl->sizeOut();++j)
      if (bl->getOut(j)==blout)
	redundlist.push_back(bl);
				// We assume blout appears only once in bl's and this's
				// outlists
  }
  if (redundlist.empty()) return true;
  for(iter=blout->op.begin();iter!=blout->op.end();++iter) {
    multiop = *iter;
    if (multiop->code() != CPUI_MULTIEQUAL) continue;
    for(vector<const FlowBlock *>::iterator biter=redundlist.begin();biter!=redundlist.end();++biter) {
      bl = *biter;
      vnredund = multiop->getIn(blout->getInIndex(bl)); // One of the redundant varnodes
      vnremove = multiop->getIn(blout->getInIndex(this));
      if (vnremove->isWritten()) {
	othermulti = vnremove->getDef();
	if ((othermulti->code()==CPUI_MULTIEQUAL)&&(othermulti->getParent()==this))
	  vnremove = othermulti->getIn(getInIndex(bl));
      }
      if (vnremove != vnredund) return false; // Redundant branches must be identical
    }
  }
  return true;
}

/// This is a crucial test for whether \b this block is doing anything substantial
/// or is a candidate for removal.  Even blocks that "do nothing" have some kind of branch
/// and placeholder operations (MULTIEQUAL and INDIRECT) for data flowing through the block.
/// This tests if there is any other operation going on.
/// \return \b true if there only MULTIEQUAL, INDIRECT, and branch operations in \b this
bool BlockBasic::hasOnlyMarkers(void) const

{
  // (and a branch)
  list<PcodeOp *>::const_iterator iter;
  const PcodeOp *bop;

  for(iter=op.begin();iter!=op.end();++iter) {
    bop = *iter;
    if (bop->isMarker()) continue;
    if (bop->isBranch()) continue;
    return false;
  }
  return true;
}

/// Check if \b this block is doing anything useful.
/// \return \b true if the block does nothing and should be removed
bool BlockBasic::isDoNothing(void) const

{
  if (sizeOut() != 1) return false; // A block that does nothing useful
				// has exactly one out, (no return or cbranch)
  if (sizeIn() == 0) return false; // A block that does nothing but
				// is a starting block, may need to be a
				// placeholder for global(persistent) vars
  if ((sizeIn()==1)&&(getIn(0)->isSwitchOut())) {
    if (getOut(0)->sizeIn() > 1)
      return false;		// Don't remove switch targets
  }
  PcodeOp *lastop = lastOp();
  if ((lastop != (PcodeOp *)0)&&(lastop->code()==CPUI_BRANCHIND))
    return false;		// Don't remove single-out indirect jumps
  return hasOnlyMarkers();
}

/// In terms of machine instructions, a basic block always covers a range of addresses,
/// from its first instruction to its last. This method establishes that range.
/// \param beg is the address of the first instruction in the block
/// \param end is the address of the last instruction in the block
void BlockBasic::setInitialRange(const Address &beg,const Address &end)

{
  cover.clear();
  // TODO: We could check that -beg- and -end- are in the same address space
  cover.insertRange(beg.getSpace(),beg.getOffset(),end.getOffset());
}

/// The SeqNum::order field for each PcodeOp must mirror the ordering of that PcodeOp within
/// \b this block.  Insertions are usually handled by calculating an appropriate SeqNum::order field
/// for the new PcodeOp, but sometime there isn't enough room between existing ops.  This method is
/// then called to recalculate the SeqNum::order field for all PcodeOp objects in \b this block,
/// reestablishing space between the field values.
void BlockBasic::setOrder(void)

{
  list<PcodeOp *>::iterator iter;
  uintm count,step;

  step = ~((uintm)0);
  step = ( step / op.size() ) -1;
  count = 0;
  for(iter=op.begin();iter!=op.end();++iter) {
    count += step;
    (*iter)->setOrder(count);
  }
}

void BlockBasic::saveXmlBody(ostream &s) const

{
  cover.saveXml(s);
}

void BlockBasic::restoreXmlBody(List::const_iterator &iter,List::const_iterator enditer,BlockMap &resolver)

{
  cover.restoreXml(*iter, resolver.getAddressManager());
  ++iter;
}

void BlockBasic::printHeader(ostream &s) const

{
  s << "Basic Block ";
  FlowBlock::printHeader(s);
}

void BlockBasic::printRaw(ostream &s) const
  
{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *inst;

  printHeader(s);
  s << endl;
  for(iter=op.begin();iter!=op.end();++iter) {
    inst = *iter;
    s << inst->getSeqNum() << ":\t";
    inst->printRaw(s);
    s << endl;
  }
}

/// \brief Check if there is meaningful activity between two branch instructions
///
/// The first branch is assumed to be a CBRANCH one edge of which flows into
/// the other branch. The flow can be through 1 or 2 blocks.  If either block
/// performs an operation other than MULTIEQUAL, INDIRECT (or the branch), then
/// return \b false.
/// \param first is the CBRANCH operation
/// \param path is the index of the edge to follow to the other branch
/// \param last is the other branch operation
/// \return \b true if there is no meaningful activity
bool BlockBasic::noInterveningStatement(PcodeOp *first,int4 path,PcodeOp *last)

{
  BlockBasic *curbl = (BlockBasic *)first->getParent()->getOut(path);
  for(int4 i=0;i<2;++i) {
    if (!curbl->hasOnlyMarkers()) return false;
    if (curbl != last->getParent()) {
      if (curbl->sizeOut() != 1) return false; // Intervening conditional branch
    }
    else
      return true;
    curbl = (BlockBasic *)curbl->getOut(0);
  }
  return false;
}

void BlockCopy::printHeader(ostream &s) const

{
  s << "Basic(copy) block ";
  FlowBlock::printHeader(s);
}

void BlockCopy::printTree(ostream &s,int4 level) const

{
  copy->printTree(s,level);
}

void BlockCopy::saveXmlHeader(ostream &s) const

{
  FlowBlock::saveXmlHeader(s);
  int4 altindex = copy->getIndex();
  a_v_i(s,"altindex",altindex);
}

void BlockGoto::markUnstructured(void)

{
  BlockGraph::markUnstructured(); // Recurse
  if (gototype == f_goto_goto) {
    if (gotoPrints())
      markCopyBlock(gototarget,f_unstructured_targ);
  }
}

void BlockGoto::scopeBreak(int4 curexit,int4 curloopexit)

{
  getBlock(0)->scopeBreak(gototarget->getIndex(),curloopexit); // Recurse

  // Check if our goto hits the current loop exit
  if (curloopexit == gototarget->getIndex())
    gototype = f_break_goto;	// If so, our goto is a break
}

/// Under rare circumstances, the emitter can place the target block of the goto immediately
/// after this goto block.  In this case, because the control-flow is essentially a fall-thru,
/// there should not be a formal goto statement emitted.
/// Check if the goto is to the next block in flow in which case the goto should not be printed.
/// \return \b true if the goto should be printed formally
bool BlockGoto::gotoPrints(void) const

{
  if (getParent() != (FlowBlock *)0) {
    FlowBlock *nextbl = getParent()->nextFlowAfter(this);
    FlowBlock *gotobl = getGotoTarget()->getFrontLeaf();
    return (gotobl != nextbl);
  }
  return false;
}

void BlockGoto::printHeader(ostream &s) const

{
  s << "Plain goto block ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockGoto::nextFlowAfter(const FlowBlock *bl) const

{				// Return the block containing the next statement in flow
  return getGotoTarget()->getFrontLeaf();
}

void BlockGoto::saveXmlBody(ostream &s) const

{
  BlockGraph::saveXmlBody(s);
  s << "<target";
  const FlowBlock *leaf = gototarget->getFrontLeaf();
  int4 depth = gototarget->calcDepth(leaf);
  a_v_i(s,"index",leaf->getIndex());
  a_v_i(s,"depth",depth);
  a_v_u(s,"type",gototype);
  s << "/>\n";
}

void BlockMultiGoto::scopeBreak(int4 curexit,int4 curloopexit)

{
  getBlock(0)->scopeBreak(-1,curloopexit); // Recurse
}

void BlockMultiGoto::printHeader(ostream &s) const

{
  s << "Multi goto block ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockMultiGoto::nextFlowAfter(const FlowBlock *bl) const

{
  // The child of this can never be a BlockGoto
  return (FlowBlock *)0;
} 

void BlockMultiGoto::saveXmlBody(ostream &s) const

{
  BlockGraph::saveXmlBody(s);
  for(int4 i=0;i<gotoedges.size();++i) {
    FlowBlock *gototarget = gotoedges[i];
    const FlowBlock *leaf = gototarget->getFrontLeaf();
    int4 depth = gototarget->calcDepth(leaf);
    s << "<target";
    a_v_i(s,"index",leaf->getIndex());
    a_v_i(s,"depth",depth);
    s << "/>\n";
  }
}

const FlowBlock *BlockList::getExitLeaf(void) const

{
  if (getSize()==0) return (FlowBlock *)0;
  return getBlock(getSize()-1)->getExitLeaf();
}

PcodeOp *BlockList::lastOp(void) const

{
  if (getSize()==0) return (PcodeOp *)0;
  return getBlock(getSize()-1)->lastOp();	// Get last instruction of last block
}

bool BlockList::negateCondition(bool toporbottom)

{
  FlowBlock *bl = getBlock(getSize()-1);
  bool res = bl->negateCondition(false);	// Negate condition of last block
  FlowBlock::negateCondition(toporbottom); // Flip order of outgoing edges
  return res;
}

FlowBlock *BlockList::getSplitPoint(void)

{
  if (getSize()==0) return (FlowBlock *)0;
  return getBlock(getSize()-1)->getSplitPoint();
}

void BlockList::printHeader(ostream &s) const

{
  s << "List block ";
  FlowBlock::printHeader(s);
}

int4 BlockCondition::flipInPlaceTest(vector<PcodeOp *> &fliplist) const

{
  FlowBlock *split1 = getBlock(0)->getSplitPoint();
  if (split1 == (FlowBlock *)0)
    return 2;
  FlowBlock *split2 = getBlock(1)->getSplitPoint();
  if (split2 == (FlowBlock *)0)
    return 2;
  int4 subtest1 = split1->flipInPlaceTest(fliplist);
  if (subtest1 == 2)
    return 2;
  int4 subtest2 = split2->flipInPlaceTest(fliplist);
  if (subtest2 == 2)
    return 2;
  return subtest1;
}

void BlockCondition::flipInPlaceExecute(void)

{
  opc = (opc==CPUI_BOOL_AND) ? CPUI_BOOL_OR : CPUI_BOOL_AND;
  getBlock(0)->getSplitPoint()->flipInPlaceExecute();
  getBlock(1)->getSplitPoint()->flipInPlaceExecute();
}

PcodeOp *BlockCondition::lastOp(void) const

{				// Is destination of condition reached
				// by an unstructured goto
  return getBlock(1)->lastOp();
}

bool BlockCondition::negateCondition(bool toporbottom)

{
  bool res1,res2;
  res1 = getBlock(0)->negateCondition(false);	// Distribute the NOT
  res2 = getBlock(1)->negateCondition(false);	// to each side of condition
  opc = (opc==CPUI_BOOL_AND) ? CPUI_BOOL_OR : CPUI_BOOL_AND;
  FlowBlock::negateCondition(toporbottom); // Flip order of outofthis
  return (res1 || res2);
}

void BlockCondition::scopeBreak(int4 curexit,int4 curloopexit)

{
  getBlock(0)->scopeBreak(-1,curloopexit); // No fixed exit
  getBlock(1)->scopeBreak(-1,curloopexit);
}

void BlockCondition::printHeader(ostream &s) const

{
  s << "Condition block(";
  if (opc==CPUI_BOOL_AND)
    s << "&&";
  else
    s << "||";
  s << ") ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockCondition::nextFlowAfter(const FlowBlock *bl) const

{
  return (FlowBlock *)0;	// Do not know where flow goes
}

void BlockCondition::saveXmlHeader(ostream &s) const

{
  BlockGraph::saveXmlHeader(s);
  string nm(get_opname(opc));
  a_v(s,"opcode",nm);
}

void BlockIf::markUnstructured(void)

{
  BlockGraph::markUnstructured(); // Recurse
  if ((gototarget != (FlowBlock *)0)&&(gototype==f_goto_goto))
    markCopyBlock(gototarget,f_unstructured_targ);
}

void BlockIf::scopeBreak(int4 curexit,int4 curloopexit)

{
  getBlock(0)->scopeBreak(-1,curloopexit); // Condition block has multiple exits
  // Blocks don't flow into one another, but share same exit block
  for(int4 i=1;i<getSize();++i)
    getBlock(i)->scopeBreak(curexit,curloopexit);
  if ((gototarget != (FlowBlock *)0)&&(gototarget->getIndex() == curloopexit))
    gototype = f_break_goto;
}

void BlockIf::printHeader(ostream &s) const

{
  s << "If block ";
  FlowBlock::printHeader(s);
}

bool BlockIf::preferComplement(Funcdata &data)

{
  if (getSize()!=3)		// If we are an if/else
    return false;

  FlowBlock *split = getBlock(0)->getSplitPoint();
  if (split == (FlowBlock *)0)
    return false;
  vector<PcodeOp *> fliplist;
  if (0 != split->flipInPlaceTest(fliplist))
    return false;
  split->flipInPlaceExecute();
  opFlipInPlaceExecute(data,fliplist);
  swapBlocks(1,2);
  return true;
}

const FlowBlock *BlockIf::getExitLeaf(void) const

{ // In the special case of an ifgoto block, we do have an exit leaf
  if (getSize() == 1)
    return getBlock(0)->getExitLeaf();
  return (FlowBlock *)0;
}

PcodeOp *BlockIf::lastOp(void) const

{ // In the special case of an ifgoto block, we do have a last op, otherwise we don't
  if (getSize() == 1)
    return getBlock(0)->lastOp();
  return (PcodeOp *)0;
}

FlowBlock *BlockIf::nextFlowAfter(const FlowBlock *bl) const

{
  if (getBlock(0)==bl)
    return (FlowBlock *)0;	// Do not know where flow goes
  if (getParent() == (FlowBlock *)0)
    return (FlowBlock *)0;
  return getParent()->nextFlowAfter(this);
}

void BlockIf::saveXmlBody(ostream &s) const

{
  BlockGraph::saveXmlBody(s);
  if (getSize() == 1) {		// If this is a if GOTO block
    const FlowBlock *leaf = gototarget->getFrontLeaf();
    int4 depth = gototarget->calcDepth(leaf);
    s << "<target";
    a_v_i(s,"index",leaf->getIndex());
    a_v_i(s,"depth",depth);
    a_v_u(s,"type",gototype);
    s << "/>\n";
  }
}

/// Try to find a Varnode that represents the controlling \e loop \e variable for \b this loop.
/// The Varnode must be:
///   - tested by the exit condition
///   - have a MULTIEQUAL in the head block
///   - have a modification coming in from the tail block
///   - the modification must be the last op or moveable to the last op
///
/// If the loop variable is found, this routine sets the \e iterateOp and the \e loopDef.
/// \param cbranch is the CBRANCH implementing the loop exit
/// \param head is the head basic-block of the loop
/// \param tail is the tail basic-block of the loop
/// \param lastOp is the precomputed last PcodeOp of tail that isn't a BRANCH
void BlockWhileDo::findLoopVariable(PcodeOp *cbranch,BlockBasic *head,BlockBasic *tail,PcodeOp *lastOp)

{
  Varnode *vn = cbranch->getIn(1);
  if (!vn->isWritten()) return;		// No loop variable found
  PcodeOp *op = vn->getDef();
  int4 slot = tail->getOutRevIndex(0);

  PcodeOpNode path[4];
  int4 count = 0;
  if (op->isCall() || op->isMarker()) {
      return;
  }
  path[0].op = op;
  path[0].slot = 0;
  while(count>=0) {
    PcodeOp *curOp = path[count].op;
    int4 ind = path[count].slot++;
    if (ind >= curOp->numInput()) {
      count -= 1;
      continue;
    }
    Varnode *nextVn = curOp->getIn(ind);
    if (!nextVn->isWritten()) continue;
    PcodeOp *defOp = nextVn->getDef();
    if (defOp->code() == CPUI_MULTIEQUAL) {
      if (defOp->getParent() != head) continue;
      Varnode *itvn = defOp->getIn(slot);
      if (!itvn->isWritten()) continue;
      PcodeOp *possibleIterate = itvn->getDef();
      if (possibleIterate->getParent() == tail) {	// Found proper head/tail configuration
	if (possibleIterate->isMarker())
	  continue;	// No iteration in tail
	if (!possibleIterate->isMoveable(lastOp))
	  continue;	// Not the final statement
	loopDef = defOp;
	iterateOp = possibleIterate;
	return;		// Found the loop variable
      }
    }
    else {
      if (count == 3) continue;
      if (defOp->isCall() || defOp->isMarker()) continue;
      count += 1;
      path[count].op = defOp;
      path[count].slot = 0;
    }
  }
  return;		// No loop variable found
}

/// Given a control flow loop, try to find a putative initializer PcodeOp for the loop variable.
/// The initializer must be read by read by \e loopDef and by in a block that
/// flows only into the loop.  If an initializer is found, then
/// \e initializeOp is set and the lastOp (not including a branch) in the initializer
/// block is returned. Otherwise null is returned.
/// \param head is the head block of the loop
/// \param slot is the block input coming from the loop tail
/// \return the last PcodeOp in the initializer's block
PcodeOp *BlockWhileDo::findInitializer(BlockBasic *head,int4 slot) const

{
  if (head->sizeIn() != 2) return (PcodeOp *)0;
  slot = 1 - slot;
  Varnode *initVn = loopDef->getIn(slot);
  if (!initVn->isWritten()) return (PcodeOp *)0;
  PcodeOp *res = initVn->getDef();
  if (res->isMarker()) return (PcodeOp *)0;
  FlowBlock *initialBlock = res->getParent();
  if (initialBlock != head->getIn(slot))
    return (PcodeOp *)0;			// Statement must terminate in block flowing to head
  PcodeOp *lastOp = initialBlock->lastOp();
  if (lastOp == (PcodeOp *)0) return (PcodeOp *)0;
  if (initialBlock->sizeOut() != 1) return (PcodeOp *)0;	// Initializer block must flow only to for loop
  if (lastOp->isBranch()) {
    lastOp = lastOp->previousOp();
    if (lastOp == (PcodeOp *)0) return (PcodeOp *)0;
  }
  initializeOp = res;
  return lastOp;
}

/// For-loop initializer or iterator statements must be the final statement in
/// their respective basic block. This method tests that iterateOp/initializeOp (specified
/// by \e slot) is the root of or can be turned into the root of a terminal statement.
/// The root output must be an explicit variable being read by the
/// \e loopDef MULTIEQUAL at the top of the loop. If the root is not the last
/// PcodeOp in the block, an attempt is made to move it.
/// Return the root PcodeOp if all these conditions are met, otherwise return null.
/// \param data is the function containing the while loop
/// \param slot is the slot read by \e loopDef from the output of the statement
/// \return an explicit statement or null
PcodeOp *BlockWhileDo::testTerminal(Funcdata &data,int4 slot) const

{
  Varnode *vn = loopDef->getIn(slot);
  if (!vn->isWritten()) return (PcodeOp *)0;
  PcodeOp *finalOp = vn->getDef();
  BlockBasic *parentBlock = (BlockBasic *)loopDef->getParent()->getIn(slot);
  PcodeOp *resOp = finalOp;
  if (finalOp->code() == CPUI_COPY && finalOp->notPrinted()) {
    vn = finalOp->getIn(0);
    if (!vn->isWritten()) return (PcodeOp *)0;
    resOp = vn->getDef();
    if (resOp->getParent() != parentBlock) return (PcodeOp *)0;
  }

  if (!vn->isExplicit()) return (PcodeOp *)0;
  if (resOp->notPrinted())
    return (PcodeOp *)0;	// Statement MUST be printed

  // finalOp MUST be the last op in the basic block (except for the branch)
  PcodeOp *lastOp = finalOp->getParent()->lastOp();
  if (lastOp->isBranch())
    lastOp = lastOp->previousOp();
  if (!data.moveRespectingCover(finalOp, lastOp))
    return (PcodeOp *)0;

  return resOp;
}

/// Make sure the loop variable is involved as input in the iterator statement.
/// \return \b true if the loop variable is an input to the iterator statement
bool BlockWhileDo::testIterateForm(void) const

{
  Varnode *targetVn = loopDef->getOut();
  HighVariable *high = targetVn->getHigh();

  vector<PcodeOpNode> path;
  PcodeOp *op = iterateOp;
  path.push_back(PcodeOpNode(op,0));
  while(!path.empty()) {
    PcodeOpNode &node(path.back());
    if (node.op->numInput() <= node.slot) {
      path.pop_back();
      continue;
    }
    Varnode *vn = node.op->getIn(node.slot);
    node.slot += 1;
    if (vn->isAnnotation()) continue;
    if (vn->getHigh() == high) {
      return true;
    }
    if (vn->isExplicit()) continue;	// Truncate at explicit
    if (!vn->isWritten()) continue;
    op = vn->getDef();
    path.push_back(PcodeOpNode(vn->getDef(),0));
  }
  return false;
}

void BlockWhileDo::markLabelBumpUp(bool bump)

{
  BlockGraph::markLabelBumpUp(true); // whiledos steal lower blocks labels
  if (!bump)
    clearFlag(f_label_bumpup);
}

void BlockWhileDo::scopeBreak(int4 curexit,int4 curloopexit)

{
  // A new loop scope (current loop exit becomes curexit)
  getBlock(0)->scopeBreak(-1,curexit); // Top block has multiple exits
  getBlock(1)->scopeBreak(getBlock(0)->getIndex(),curexit); // Exits into topblock
}

void BlockWhileDo::printHeader(ostream &s) const

{
  s << "Whiledo block ";
  if (hasOverflowSyntax())
    s << "(overflow) ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockWhileDo::nextFlowAfter(const FlowBlock *bl) const

{
  if (getBlock(0) == bl)
    return (FlowBlock *)0;	// Don't know what will execute next

  FlowBlock *nextbl = getBlock(0); // Will execute first block of while
  if (nextbl != (FlowBlock *)0)
    nextbl = nextbl->getFrontLeaf();
  return nextbl;
}

/// Determine if \b this block can be printed as a \e for loop, with an \e initializer statement
/// extracted from the previous block, and an \e iterator statement extracted from the body.
/// \param data is the function containing \b this loop
void BlockWhileDo::finalTransform(Funcdata &data)

{
  BlockGraph::finalTransform(data);
  if (!data.getArch()->analyze_for_loops) return;
  if (hasOverflowSyntax()) return;
  FlowBlock *copyBl = getFrontLeaf();
  if (copyBl == (FlowBlock *)0) return;
  BlockBasic *head = (BlockBasic *)copyBl->subBlock(0);
  if (head->getType() != t_basic) return;
  PcodeOp *lastOp = getBlock(1)->lastOp();	// There must be a last op in body, for there to be an iterator statement
  if (lastOp == (PcodeOp *)0) return;
  BlockBasic *tail = lastOp->getParent();
  if (tail->sizeOut() != 1) return;
  if (tail->getOut(0) != head) return;
  PcodeOp *cbranch = getBlock(0)->lastOp();
  if (cbranch == (PcodeOp *)0 || cbranch->code() != CPUI_CBRANCH) return;
  if (lastOp->isBranch()) {			// Convert lastOp to -point- iterateOp must appear after
    lastOp = lastOp->previousOp();
    if (lastOp == (PcodeOp *)0) return;
  }

  findLoopVariable(cbranch, head, tail, lastOp);
  if (iterateOp == (PcodeOp *)0) return;

  if (iterateOp != lastOp) {
    data.opUninsert(iterateOp);
    data.opInsertAfter(iterateOp, lastOp);
  }

  // Try to set up initializer statement
  lastOp = findInitializer(head, tail->getOutRevIndex(0));
  if (lastOp == (PcodeOp *)0) return;
  if (!initializeOp->isMoveable(lastOp)) {
    initializeOp = (PcodeOp *)0;		// Turn it off
    return;
  }
  if (initializeOp != lastOp) {
    data.opUninsert(initializeOp);
    data.opInsertAfter(initializeOp, lastOp);
  }
}

/// Assume that finalTransform() has run and that all HighVariable merging has occurred.
/// Do any final tests checking that the initialization and iteration statements are good.
/// Extract initialization and iteration statements from their basic blocks.
/// \param data is the function containing the loop
void BlockWhileDo::finalizePrinting(Funcdata &data) const

{
  BlockGraph::finalizePrinting(data);	// Continue recursing
  if (iterateOp == (PcodeOp *)0) return;	// For-loop printing not enabled
  // TODO: We can check that iterate statement is not too complex
  int4 slot = iterateOp->getParent()->getOutRevIndex(0);
  iterateOp = testTerminal(data,slot);		// Make sure iterator statement is explicit
  if (iterateOp == (PcodeOp *)0) return;
  if (!testIterateForm()) {
    iterateOp = (PcodeOp *)0;
    return;
  }
  if (initializeOp == (PcodeOp *)0)
    findInitializer(loopDef->getParent(), slot);	// Last chance initializer
  if (initializeOp != (PcodeOp *)0)
    initializeOp = testTerminal(data,1-slot);	// Make sure initializer statement is explicit

  data.opMarkNonPrinting(iterateOp);
  if (initializeOp != (PcodeOp *)0)
    data.opMarkNonPrinting(initializeOp);
}

void BlockDoWhile::markLabelBumpUp(bool bump)

{
  BlockGraph::markLabelBumpUp(true); // dowhiles steal lower blocks labels
  if (!bump)
    clearFlag(f_label_bumpup);
}

void BlockDoWhile::scopeBreak(int4 curexit,int4 curloopexit)

{
  // A new loop scope, current loop exit becomes curexit
  getBlock(0)->scopeBreak(-1,curexit); // Multiple exits
}

void BlockDoWhile::printHeader(ostream &s) const

{
  s << "Dowhile block ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockDoWhile::nextFlowAfter(const FlowBlock *bl) const

{
  return (FlowBlock *)0;	// Don't know what will execute next
}

void BlockInfLoop::markLabelBumpUp(bool bump)

{
  BlockGraph::markLabelBumpUp(true); // infloops steal lower blocks labels
  if (!bump)
    clearFlag(f_label_bumpup);
}

void BlockInfLoop::scopeBreak(int4 curexit,int4 curloopexit)

{
  // A new loop scope, current loop exit becomes curexit
  getBlock(0)->scopeBreak(getBlock(0)->getIndex(),curexit); // Exits into itself
}

void BlockInfLoop::printHeader(ostream &s) const

{
  s << "Infinite loop block ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockInfLoop::nextFlowAfter(const FlowBlock *bl) const

{
  FlowBlock *nextbl = getBlock(0); // Will execute first block of infloop
  if (nextbl != (FlowBlock *)0)
    nextbl = nextbl->getFrontLeaf();
  return nextbl;
}

BlockSwitch::BlockSwitch(FlowBlock *ind)

{
  jump = ind->getJumptable();
}

/// Associate a structured block as a full \e case of \b this switch.
/// \param switchbl is the underlying switch statement block
/// \param bl is the new block to make into a case
/// \param gt gives the unstructured branch type if the switch edge to the new case was unstructured (zero otherwise)
void BlockSwitch::addCase(FlowBlock *switchbl,FlowBlock *bl,uint4 gt)

{
  caseblocks.emplace_back();
  CaseOrder &curcase( caseblocks.back() );
  const FlowBlock *basicbl = bl->getFrontLeaf()->subBlock(0);
  curcase.block = bl;
  curcase.basicblock = basicbl;
  curcase.label = 0;
  curcase.depth = 0;
  curcase.chain = -1;
  int4 inindex = basicbl->getInIndex(switchbl);
  if (inindex==-1)
    throw LowlevelError("Case block has become detached from switch");
  curcase.outindex = basicbl->getInRevIndex(inindex);
  curcase.gototype = gt;
  if (gt != 0)
    curcase.isexit = false;
  else
    curcase.isexit = (bl->sizeOut() == 1);
  curcase.isdefault = switchbl->isDefaultBranch( curcase.outindex );
 }

/// Given the list of components for the switch structure, build the annotated descriptions
/// of the cases.  Work out flow between cases and if there are any unstructured cases.
/// The first FlowBlock in the component list is the switch component itself.  All other
/// FlowBlocks in the list are the \e case components.
/// \param switchbl is the underlying basic block, with multiple outgoing edges, for the switch
/// \param cs is the list of switch and case components
void BlockSwitch::grabCaseBasic(FlowBlock *switchbl,const vector<FlowBlock *> &cs)

{
  vector<int4> casemap(switchbl->sizeOut(),-1);	// Map from from switchtarget's outindex to position in caseblocks
  caseblocks.clear();
  for(int4 i=1;i<cs.size();++i) {
    FlowBlock *casebl = cs[i];
    addCase(switchbl,casebl,0);
    casemap[caseblocks[i-1].outindex] = i-1; // Build map from outindex to caseblocks index
    
  }
  // Fillin fallthru chaining
  for(int4 i=0;i<caseblocks.size();++i) {
    CaseOrder &curcase( caseblocks[i] );
    FlowBlock *casebl = curcase.block;
    if (casebl->getType() == t_goto) { // All fall-thru blocks are plain gotos
      FlowBlock *targetbl = ((BlockGoto *)casebl)->getGotoTarget();
      const FlowBlock *basicbl = targetbl->getFrontLeaf()->subBlock(0);
      int4 inindex = basicbl->getInIndex(switchbl);
      if (inindex == -1) continue; // Goto target is not another switch case
      curcase.chain = casemap[ basicbl->getInRevIndex(inindex) ];
    }
  }

  if (cs[0]->getType() == t_multigoto) { // Check if some of the main switch edges were marked as goto
    BlockMultiGoto *gotoedgeblock = (BlockMultiGoto *)cs[0];
    int4 numgoto = gotoedgeblock->numGotos();
    for(int4 i=0;i<numgoto;++i)
      addCase(switchbl,gotoedgeblock->getGoto(i),f_goto_goto);
  }
}

void BlockSwitch::finalizePrinting(Funcdata &data) const

{
  BlockGraph::finalizePrinting(data);	// Make sure to still recurse
  // We need to order the cases based on the label
  // First populate the label and depth fields of the CaseOrder objects
  for(int4 i=0;i<caseblocks.size();++i) { // Construct the depth parameter, to sort fall-thru cases
    CaseOrder &curcase( caseblocks[i] );
    int4 j = curcase.chain;
    while(j != -1) {		// Run through the fall-thru chain
      if (caseblocks[j].depth != 0) break; // Break any possible loops (already visited this node)
      caseblocks[j].depth = -1;	// Mark non-roots of chains
      j = caseblocks[j].chain;
    }
  }
  for(int4 i=0;i<caseblocks.size();++i) {
    CaseOrder &curcase( caseblocks[i] );
    if (jump->numIndicesByBlock(curcase.basicblock) > 0) {
      if (curcase.depth == 0) {	// Only set label on chain roots
	int4 index = jump->getIndexByBlock(curcase.basicblock,0);
	curcase.label = jump->getLabelByIndex(index);
	int4 j = curcase.chain;
	int4 depthcount = 1;
	while(j != -1) {
	  if (caseblocks[j].depth > 0) break; // Has this node had its depth set. Break any possible loops.
	  caseblocks[j].depth = depthcount++;
	  caseblocks[j].label = curcase.label;
	  j = caseblocks[j].chain;
	}
      }
    }
    else
      curcase.label = 0;	// Should never happen
  }
  // Do actual sort of the cases based on label
  stable_sort(caseblocks.begin(),caseblocks.end(),CaseOrder::compare);
}

/// Drill down to the variable associated with the BRANCHIND itself, and return its data-type
/// \return the Datatype associated with the switch variable
const Datatype *BlockSwitch::getSwitchType(void) const

{
  PcodeOp *op = jump->getIndirectOp();
  return op->getIn(0)->getHigh()->getType();
}

void BlockSwitch::markUnstructured(void)

{
  BlockGraph::markUnstructured(); // Recurse
  for(int4 i=0;i<caseblocks.size();++i) {
    if (caseblocks[i].gototype == f_goto_goto)
      markCopyBlock(caseblocks[i].block,f_unstructured_targ);
  }
}

void BlockSwitch::scopeBreak(int4 curexit,int4 curloopexit)

{
  // New scope, current loop exit = curexit
  getBlock(0)->scopeBreak(-1,curexit); // Top block has multiple exits
  for(int4 i=0;i<caseblocks.size();++i) {
    FlowBlock *bl = caseblocks[i].block;
    if (caseblocks[i].gototype != 0) {
      if (bl->getIndex() == curexit) // A goto that goes straight to exit, print is (empty) break
	caseblocks[i].gototype = f_break_goto;
    }
    else {
      // All case blocks are either plaingotos (curexit doesn't matter)
      //                            exitpoints (exit to switches exit   curexit = curexit)
      bl->scopeBreak(curexit,curexit);
    }
  }
}

void BlockSwitch::printHeader(ostream &s) const

{
  s << "Switch block ";
  FlowBlock::printHeader(s);
}

FlowBlock *BlockSwitch::nextFlowAfter(const FlowBlock *bl) const

{
  if (getBlock(0) == bl)
    return (FlowBlock *)0;	// Don't know what will execute
  int4 i;
  // Look for block to find flow after
  for(i=0;i<caseblocks.size();++i)
    if (caseblocks[i].block == bl) break;
  if (i==caseblocks.size()) return (FlowBlock *)0; // Didn't find block
  
  i = i + 1;                  // Blocks are printed in fallthru order, "flow" is to next block in this order
  if (i < caseblocks.size())
    return caseblocks[i].block->getFrontLeaf();
  // Otherwise we are at last block of switch, flow is to exit of switch
  if (getParent() == (const FlowBlock *)0) return (FlowBlock *)0;
  return getParent()->nextFlowAfter(this);
}

BlockMap::BlockMap(const BlockMap &op2)

{
  manage = op2.manage;
}

/// \param bt is the block_type
/// \return a new instance of the specialized FlowBlock
FlowBlock *BlockMap::resolveBlock(FlowBlock::block_type bt)

{
  switch(bt) {
  case FlowBlock::t_plain:
    return new FlowBlock();
  case FlowBlock::t_copy:
    return new BlockCopy((FlowBlock *)0);
  case FlowBlock::t_graph:
    return new BlockGraph();
  default:
    break;
  }
  return (FlowBlock *)0;
}

/// Given a list of FlowBlock objects sorted by index, use binary search to find the FlowBlock with matching index
/// \param list is the sorted list of FlowBlock objects
/// \param ind is the FlowBlock index to match
/// \return the matching FlowBlock or NULL
FlowBlock *BlockMap::findBlock(const vector<FlowBlock *> &list,int4 ind)

{
  int4 min = 0;
  int4 max = list.size();
  max -= 1;
  while(min <= max) {
    int4 mid = (min + max)/2;
    FlowBlock *block = list[mid];
    if (block->getIndex() == ind)
      return block;
    if (block->getIndex() < ind)
      min = mid + 1;
    else
      max = mid -1;
  }
  return (FlowBlock *)0;
}

void BlockMap::sortList(void)

{
  sort(sortlist.begin(),sortlist.end(),FlowBlock::compareBlockIndex);
}


/// Given the name of a block (deserialized from a \<bhead> tag), build the corresponding type of block.
/// \param name is the name of the block type
/// \return a new instance of the named FlowBlock type
FlowBlock *BlockMap::createBlock(const string &name)

{
  FlowBlock::block_type bt = FlowBlock::nameToType(name);
  FlowBlock *bl = resolveBlock(bt);
  sortlist.push_back(bl);
  return bl;
}

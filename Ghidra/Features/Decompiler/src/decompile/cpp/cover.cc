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
#include "cover.hh"
#include "block.hh"

const CoverBlock Cover::emptyBlock;

/// PcodeOp objects and a CoverBlock start/stop boundaries have
/// a natural ordering that can be used to tell if a PcodeOp falls
/// between boundary points and if CoverBlock objects intersect.
/// Ordering is determined by comparing the values returned by this method.
/// \param op is the PcodeOp and/or boundary point
/// \return a value for comparison
uintm CoverBlock::getUIndex(const PcodeOp *op)

{
  uintp switchval = (uintp)op;
  switch(switchval) {
  case 0:			// Special marker for very beginning of block
    return (uintm)0;
  case 1:			// Special marker for very end of block
    return ~((uintm)0);
  case 2:			// Special marker for input
    return (uintm)0;
  }
  if (op->isMarker()) {
    if (op->code() == CPUI_MULTIEQUAL) // MULTIEQUALs are considered very beginning
      return (uintm)0;
    else if (op->code() == CPUI_INDIRECT) // INDIRECTs are considered to be at
				// the location of the op they are indirect for
      return PcodeOp::getOpFromConst(op->getIn(1)->getAddr())->getSeqNum().getOrder();
  }
  return op->getSeqNum().getOrder();
}

/// Characterize the intersection of \b this range with another CoverBlock.
/// Return:
///   - 0 if there is no intersection
///   - 1 if only the intersection is at boundary points
///   - 2 if a whole interval intersects
///
/// \param op2 is the other CoverBlock to compare
/// \return the intersection characterization
int4 CoverBlock::intersect(const CoverBlock &op2) const

{
  uintm ustart,ustop;
  uintm u2start,u2stop;

  if (empty()) return 0;
  if (op2.empty()) return 0;

  ustart = getUIndex(start);
  ustop = getUIndex(stop);
  u2start = getUIndex(op2.start);
  u2stop = getUIndex(op2.stop);
  if (ustart <= ustop) {
    if (u2start <= u2stop) { // We are both one piece
      if ((ustop<=u2start)||(u2stop<=ustart)) {
	if ((ustart==u2stop)||(ustop==u2start))
	  return 1;		// Boundary intersection
	else
	  return 0;		// No intersection
      }
    }
    else {			// They are two-piece, we are one-piece
      if ((ustart>=u2stop)&&(ustop<=u2start)) {
	if ((ustart==u2stop)||(ustop==u2start))
	  return 1;
	else
	  return 0;
      }
    }
  }
  else {
    if (u2start <= u2stop) { // They are one piece, we are two-piece
      if ((u2start>=ustop)&&(u2stop<=ustart)) {
	if ((u2start==ustop)||(u2stop==ustart))
	  return 1;
	else
	  return 0;
      }
    }
    // If both are two-pieces, then the intersection must be an interval
  }
  return 2;			// Interval intersection
}

/// If the given PcodeOp or boundary point is contained in \b this range, return true.
/// \param point is the given PcodeOp
/// \return \b true if the point is contained
bool CoverBlock::contain(const PcodeOp *point) const

{
  uintm ustart,ustop,upoint;

  if (empty()) return false;
  upoint = getUIndex(point);
  ustart = getUIndex(start);
  ustop = getUIndex(stop);

  if (ustart<=ustop)
    return ((upoint>=ustart)&&(upoint<=ustop));
  return ((upoint<=ustop)||(upoint>=ustart));
}

/// Return:
///   - 0 if point not on boundary
///   - 1 if on tail
///   - 2 if on the defining point
///
/// \param point is the given PcodeOp point
/// \return the characterization
int4 CoverBlock::boundary(const PcodeOp *point) const

{
  uintm val;

  if (empty()) return 0;
  val = getUIndex(point);
  if (getUIndex(start)==val) {
    if (start!=(const PcodeOp *)0)
      return 2;
  }
  if (getUIndex(stop)==val) return 1;
  return 0;
}

/// Compute the union of \b this with the other given CoverBlock,
/// replacing \b this in place.
/// \param op2 is the other given CoverBlock
void CoverBlock::merge(const CoverBlock &op2)

{
  bool internal1,internal2,internal3,internal4;
  uintm ustart,u2start;

  if (op2.empty()) return;	// Nothing to merge in
  if (empty()) {
    start = op2.start;
    stop = op2.stop;
    return;
  }
  ustart = getUIndex(start);
  u2start = getUIndex(op2.start);
				// Is start contained in op2
  internal4 = ((ustart==(uintm)0)&&(op2.stop==(const PcodeOp *)1));
  internal1 = internal4 || op2.contain(start);
				// Is op2.start contained in this
  internal3 = ((u2start==0)&&(stop==(const PcodeOp *)1));
  internal2 = internal3 || contain(op2.start);

  if (internal1&&internal2)
    if ((ustart!=u2start)|| internal3 || internal4) { // Covered entire block
      setAll();
      return;
    }
  if (internal1)
    start = op2.start;		// Pick non-internal start
  else if ((!internal1)&&(!internal2)) { // Disjoint intervals
    if (ustart < u2start)	// Pick earliest start
      stop = op2.stop;		// then take other stop
    else
      start = op2.start;
    return;
  }
  if (internal3 || op2.contain(stop)) // Pick non-internal stop
    stop = op2.stop;
}

/// Print a description of the covered range of ops in this block
/// \param s is the output stream
void CoverBlock::print(ostream &s) const

{
  uintm ustart,ustop;

  if (empty()) {
    s << "empty";
    return;
  }

  ustart = getUIndex(start);
  ustop = getUIndex(stop);
  if (ustart==(uintm)0)
    s << "begin";
  else if (ustart==~((uintm)0))
    s << "end";
  else
    s << start->getSeqNum();

  s << '-';

  if (ustop==(uintm)0)
    s << "begin";
  else if (ustop==~((uintm)0))
    s << "end";
  else
    s << stop->getSeqNum();
}

/// Compare \b this with another Cover by comparing just
/// the indices of the first blocks respectively that are partly covered.
/// Return -1, 0, or 1 if \b this Cover's first block has a
/// smaller, equal, or bigger index than the other Cover's first block.
/// \param op2 is the other Cover
/// \return the comparison value
int4 Cover::compareTo(const Cover &op2) const

{
  int4 a,b;

  map<int4,CoverBlock>::const_iterator iter;
  iter = cover.begin();
  if (iter==cover.end())
    a = 1000000;
  else
    a = (*iter).first;
  iter = op2.cover.begin();
  if (iter==op2.cover.end())
    b = 1000000;
  else
    b = (*iter).first;

  if ( a < b ) {
	return -1;
  }
  else if ( a == b ) {
	return 0;
  }
  return 1;
}

/// Return a representative CoverBlock describing how much of the given block
/// is covered by \b this
/// \param i is the index of the given block
/// \return a reference to the corresponding CoverBlock
const CoverBlock &Cover::getCoverBlock(int4 i) const

{
  map<int4,CoverBlock>::const_iterator iter = cover.find(i);
  if (iter == cover.end())
    return emptyBlock;
  return (*iter).second;
}

/// Return
///   - 0 if there is no intersection
///   - 1 if the only intersection is on a boundary point
///   - 2 if the intersection contains a range of p-code ops
///
/// \param op2 is the other Cover
/// \return the intersection characterization
int4 Cover::intersect(const Cover &op2) const

{
  map<int4,CoverBlock>::const_iterator iter,iter2;
  int4 res,newres;

  res = 0;
  iter = cover.begin();
  iter2 = op2.cover.begin();

  for(;;) {
    if (iter == cover.end()) return res;
    if (iter2 == op2.cover.end()) return res;

    if ((*iter).first < (*iter2).first)
      ++iter;
    else if ((*iter).first > (*iter2).first)
      ++iter2;
    else {
      newres = (*iter).second.intersect((*iter2).second);
      if (newres == 2) return 2;
      if (newres == 1)
	res = 1;		// At least a point intersection
      ++iter;
      ++iter2;
    }
  }
  return res;
}

/// \brief Generate a list of blocks that intersect
///
/// For each block for which \b this and another Cover intersect,
/// and the block's index to a result list if the type of intersection
/// exceeds a characterization level.
/// \param listout will hold the list of intersecting block indices
/// \param op2 is the other Cover
/// \param level is the characterization threshold which must be exceeded
void Cover::intersectList(vector<int4> &listout,const Cover &op2,int4 level) const

{
  map<int4,CoverBlock>::const_iterator iter,iter2;
  int4 val;

  listout.clear();

  iter = cover.begin();
  iter2 = op2.cover.begin();

  for(;;) {
    if (iter == cover.end()) return;
    if (iter2 == op2.cover.end()) return;

    if ((*iter).first < (*iter2).first)
      ++iter;
    else if ((*iter).first > (*iter2).first)
      ++iter2;
    else {
      val = (*iter).second.intersect((*iter2).second);
      if (val >= level)
	listout.push_back((*iter).first);
      ++iter;
      ++iter2;
    }
  }
}

/// Looking only at the given block, Return
///   - 0 if there is no intersection
///   - 1 if the only intersection is on a boundary point
///   - 2 if the intersection contains a range of p-code ops
///
/// \param blk is the index of the given block
/// \param op2 is the other Cover
/// \return the characterization
int4 Cover::intersectByBlock(int4 blk,const Cover &op2) const

{
  map<int4,CoverBlock>::const_iterator iter;

  iter = cover.find(blk);
  if (iter == cover.end()) return 0;
  
  map<int4,CoverBlock>::const_iterator iter2;

  iter2 = op2.cover.find(blk);
  if (iter2 == op2.cover.end()) return 0;

  return (*iter).second.intersect((*iter2).second);
}

/// \brief Does \b this contain the given PcodeOp
///
/// \param op is the given PcodeOp
/// \param max is 1 to test for any containment, 2 to force interior containment
/// \return true if there is containment
bool Cover::contain(const PcodeOp *op,int4 max) const

{
  map<int4,CoverBlock>::const_iterator iter;

  iter = cover.find(op->getParent()->getIndex());
  if (iter == cover.end()) return false;
  if ((*iter).second.contain(op)) {
    if (max==1) return true;
    if (0==(*iter).second.boundary(op)) return true;
  }
  return false;
}

/// \brief Check the definition of a Varnode for containment
///
/// If the given Varnode has a defining PcodeOp this is
/// checked for containment.  If the Varnode is an input,
/// check if \b this covers the start of the function.
///
/// Return:
///   - 0 if cover does not contain varnode definition
///   - 1 if there if it is contained in interior
///   - 2 if the defining points intersect
///   - 3 if Cover's tail is the varnode definition
///
/// \param vn is the given Varnode
/// \return the containment characterization
int4 Cover::containVarnodeDef(const Varnode *vn) const

{
  const PcodeOp *op = vn->getDef();
  int4 blk;

  if (op == (const PcodeOp *)0) {
    op = (const PcodeOp *)2;
    blk = 0;
  }
  else
    blk = op->getParent()->getIndex();
  map<int4,CoverBlock>::const_iterator iter = cover.find(blk);
  if (iter == cover.end()) return 0;
  if ((*iter).second.contain(op)) {
    int4 boundtype = (*iter).second.boundary(op);
    if (boundtype == 0) return 1;
    if (boundtype == 2) return 2;
    return 3;
  }
  return 0;
}

/// \param op2 is the other Cover
void Cover::merge(const Cover &op2)

{
  map<int4,CoverBlock>::const_iterator iter;

  for(iter=op2.cover.begin();iter!=op2.cover.end();++iter)
    cover[(*iter).first].merge((*iter).second);
}

/// The cover is set to all p-code ops between the point where
/// the Varnode is defined and all the points where it is read
/// \param vn is the single Varnode
void Cover::rebuild(const Varnode *vn)

{
  list<PcodeOp *>::const_iterator iter;

  addDefPoint(vn);
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter)
    addRefPoint(*iter,vn);
}

/// Any previous cover is removed. Calling this with an
/// input Varnode still produces a valid Cover.
/// \param vn is the Varnode
void Cover::addDefPoint(const Varnode *vn)

{
  const PcodeOp *def;

  cover.clear();

  def = vn->getDef();
  if (def != (const PcodeOp *)0) {
    CoverBlock &block( cover[def->getParent()->getIndex() ] );
    block.setBegin(def);	// Set the point topology
    block.setEnd(def);
  }
  else if (vn->isInput()) {
    CoverBlock &block( cover[0] );
    block.setBegin( (const PcodeOp *)2 ); // Special mark for input
    block.setEnd( (const PcodeOp *)2 );
  }
}

/// Add to \b this Cover recursively, starting at bottom of the given block
/// and filling in backward until we run into existing cover.
/// \param bl is the starting block to add
void Cover::addRefRecurse(const FlowBlock *bl)

{
  int4 j;
  uintm ustart,ustop;

  CoverBlock &block(cover[bl->getIndex()]);
  if (block.empty()) {
    block.setAll();		// No cover encountered, fill in entire block
    //    if (bl->InSize()==0)
    //      throw LowlevelError("Ref point is not in flow of defpoint");
    for(j=0;j<bl->sizeIn();++j)	// Recurse to all blocks that fall into bl
      addRefRecurse(bl->getIn(j));
  }
  else {
    const PcodeOp *op = block.getStop();
    ustart = CoverBlock::getUIndex(block.getStart());
    ustop = CoverBlock::getUIndex(op);
    if ((ustop != ~((uintm)0))&&( ustop >= ustart))
      block.setEnd((const PcodeOp *)1); // Fill in to the bottom


    if ((ustop==(uintm)0)&&(block.getStart() == (const PcodeOp *)0)) {
      if ((op != (const PcodeOp *)0)&&(op->code()==CPUI_MULTIEQUAL)) {
				// This block contains only an infinitesimal tip
				// of cover through one branch of a MULTIEQUAL
				// we still need to traverse through branches
	for(j=0;j<bl->sizeIn();++j)
	  addRefRecurse(bl->getIn(j));
      }
    }


  }
}

/// Given a Varnode being read and the PcodeOp which reads it,
/// add the point of the read to \b this and recursively fill in backwards until
/// we run into existing cover.
/// \param ref is the reading PcodeOp
/// \param vn is the Varnode being read
void Cover::addRefPoint(const PcodeOp *ref,const Varnode *vn)

{
  int4 j;
  const FlowBlock *bl;
  uintm ustop;

  bl = ref->getParent();
  CoverBlock &block(cover[bl->getIndex()]);
  if (block.empty()) {
    block.setEnd(ref);
  }
  else {
    if (block.contain(ref)) {
       if (ref->code() != CPUI_MULTIEQUAL) return;
				// Even if MULTIEQUAL ref is contained
				// we may be adding new cover because we are
				// looking at a different branch. So don't return
    }
    else {
      const PcodeOp *op = block.getStop();
      const PcodeOp *startop = block.getStart();
      block.setEnd(ref);		// Otherwise update endpoint
      ustop = CoverBlock::getUIndex(block.getStop());
      if (ustop >= CoverBlock::getUIndex(startop)) {
	if ((op!=(const PcodeOp *)0)&&(op!=(const PcodeOp *)2)&&
	    (op->code()==CPUI_MULTIEQUAL)&&(startop==(const PcodeOp *)0)) {
				// This block contains only an infinitesimal tip
				// of cover through one branch of a MULTIEQUAL
				// we still need to traverse through branches
	  for(j=0;j<bl->sizeIn();++j)
	    addRefRecurse(bl->getIn(j));
	}
	return;
      }
    }
  }
  //  if (bl->InSize()==0)
  //    throw LowlevelError("Ref point is not in flow of defpoint");
  if (ref->code() == CPUI_MULTIEQUAL) {
    for(j=0;j<ref->numInput();++j)
      if (ref->getIn(j)==vn)
	addRefRecurse(bl->getIn(j));
  }
  else
    for(j=0;j<bl->sizeIn();++j)
      addRefRecurse(bl->getIn(j));
}

/// \param s is the output stream
void Cover::print(ostream &s) const

{
  map<int4,CoverBlock>::const_iterator iter;

  for(iter=cover.begin();iter!=cover.end();++iter) {
    s << dec << (*iter).first << ": ";
    (*iter).second.print(s);
    s << endl;
  }
}

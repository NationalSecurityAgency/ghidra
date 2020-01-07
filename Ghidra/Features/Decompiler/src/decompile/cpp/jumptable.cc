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
#include "jumptable.hh"
#include "emulate.hh"
#include "flow.hh"

void LoadTable::saveXml(ostream &s) const

{
  s << "<loadtable";
  a_v_i(s,"size",size);
  a_v_i(s,"num",num);
  s << ">\n  ";
  addr.saveXml(s);
  s << "</loadtable>\n";
}

void LoadTable::restoreXml(const Element *el,Architecture *glb)

{
  istringstream s1(el->getAttributeValue("size"));	
  s1.unsetf(ios::dec | ios::hex | ios::oct);
  s1 >> size;
  istringstream s2(el->getAttributeValue("num"));	
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  s2 >> num;
  const List &list( el->getChildren() );
  List::const_iterator iter = list.begin();
  addr = Address::restoreXml( *iter, glb);
}

void LoadTable::collapseTable(vector<LoadTable> &table)

{ // Assuming -table- is sorted, collapse sequential LoadTable entries into single LoadTable entries
  if (table.empty()) return;
  vector<LoadTable>::iterator iter,lastiter;
  int4 count = 1;
  iter = table.begin();
  lastiter = iter;
  Address nextaddr = (*iter).addr + (*iter).size * (*iter).num;
  ++iter;
  for(;iter!=table.end();++iter) {
    if (( (*iter).addr == nextaddr ) && ((*iter).size == (*lastiter).size)) {
      (*lastiter).num += (*iter).num;
      nextaddr = (*iter).addr + (*iter).size * (*iter).num;
    }
    else if (( nextaddr < (*iter).addr )|| ((*iter).size != (*lastiter).size)) {
      // Starting a new table
      lastiter++;
      *lastiter = *iter;
      nextaddr = (*iter).addr + (*iter).size * (*iter).num;
      count += 1;
    }
  }
  table.resize(count,LoadTable(nextaddr,0));
}

void EmulateFunction::executeLoad(void)

{
  if (collectloads) {
    uintb off = getVarnodeValue(currentOp->getIn(1));
    AddrSpace *spc = Address::getSpaceFromConst(currentOp->getIn(0)->getAddr());
    off = AddrSpace::addressToByte(off,spc->getWordSize());
    int4 sz = currentOp->getOut()->getSize();
    loadpoints.push_back(LoadTable(Address(spc,off),sz));
  }
  EmulatePcodeOp::executeLoad();
}

void EmulateFunction::executeBranch(void)

{
  throw LowlevelError("Branch encountered emulating jumptable calculation");
}

void EmulateFunction::executeBranchind(void)

{
  throw LowlevelError("Indirect branch encountered emulating jumptable calculation");
}

void EmulateFunction::executeCall(void)

{
  // Ignore calls, as presumably they have nothing to do with final address
  fallthruOp();
}

void EmulateFunction::executeCallind(void)

{
  // Ignore calls, as presumably they have nothing to do with final address
  fallthruOp();
}

void EmulateFunction::executeCallother(void)

{
  // Ignore callothers
  fallthruOp();
}

EmulateFunction::EmulateFunction(Funcdata *f)
  : EmulatePcodeOp(f->getArch())
{
  fd = f;
  collectloads = false;
}

void EmulateFunction::setExecuteAddress(const Address &addr)

{
  if (!addr.getSpace()->hasPhysical())
    throw LowlevelError("Bad execute address");

  currentOp = fd->target(addr);
  if (currentOp == (PcodeOp *)0)
    throw LowlevelError("Could not set execute address");
  currentBehave = currentOp->getOpcode()->getBehavior();
}

uintb EmulateFunction::getVarnodeValue(Varnode *vn) const

{ // Get the value of a Varnode which is in a syntax tree
  // We can't just use the memory location as, within the tree,
  // this is just part of the label
  if (vn->isConstant())
    return vn->getOffset();
  map<Varnode *,uintb>::const_iterator iter;
  iter = varnodeMap.find(vn);
  if (iter != varnodeMap.end())
    return (*iter).second;	// We have seen this varnode before

  return getLoadImageValue(vn->getSpace(),vn->getOffset(),vn->getSize());
}

void EmulateFunction::setVarnodeValue(Varnode *vn,uintb val)

{
  varnodeMap[vn] = val;
}

void EmulateFunction::fallthruOp(void)

{
  lastOp = currentOp;		// Keep track of lastOp for MULTIEQUAL
  // Otherwise do nothing: outer loop is controlling execution flow
}

uintb EmulateFunction::emulatePath(uintb val,const PathMeld &pathMeld,
				   PcodeOp *startop,Varnode *startvn)
{
  uint4 i;
  for(i=0;i<pathMeld.numOps();++i)
    if (pathMeld.getOp(i) == startop) break;
  if (startop->code() == CPUI_MULTIEQUAL) { // If we start on a MULTIEQUAL
    int4 j;
    for(j=0;j<startop->numInput();++j) { // Is our startvn one of the branches
      if (startop->getIn(j) == startvn)
	break;
    }
    if ((j == startop->numInput())||(i==0)) // If not, we can't continue;
      throw LowlevelError("Cannot start jumptable emulation with unresolved MULTIEQUAL");
    // If the startvn was a branch of the MULTIEQUAL, emulate as if we just came from that branch
    startvn = startop->getOut(); // So the output of the MULTIEQUAL is the new startvn (as if a COPY from old startvn)
    i -= 1;			// Move to the next instruction to be executed
    startop = pathMeld.getOp(i);
  }
  if (i==pathMeld.numOps())
    throw LowlevelError("Bad jumptable emulation");
  if (!startvn->isConstant())
    setVarnodeValue(startvn,val);
  while(i>0) {
    PcodeOp *curop = pathMeld.getOp(i);
    --i;
    setCurrentOp( curop );
    try {
      executeCurrentOp();
    }
    catch(DataUnavailError &err) {
      ostringstream msg;
      msg << "Could not emulate address calculation at " << curop->getAddr();
      throw LowlevelError(msg.str());
    }
  }
  Varnode *invn = pathMeld.getOp(0)->getIn(0);
  return getVarnodeValue(invn);
}

void EmulateFunction::collectLoadPoints(vector<LoadTable> &res) const

{
  if (loadpoints.empty()) return;
  bool issorted = true;
  vector<LoadTable>::const_iterator iter;
  vector<LoadTable>::iterator lastiter;

  iter = loadpoints.begin();
  res.push_back( *iter );	// Copy the first entry
  ++iter;
  lastiter = res.begin();

  Address nextaddr = (*lastiter).addr + (*lastiter).size;
  for(;iter!=loadpoints.end();++iter) {
    if (issorted && (( (*iter).addr == nextaddr ) && ((*iter).size == (*lastiter).size))) {
      (*lastiter).num += (*iter).num;
      nextaddr = (*iter).addr + (*iter).size;
    }
    else {
      issorted = false;
      res.push_back( *iter );
    }
  }
  if (!issorted) {
    sort(res.begin(),res.end());
    LoadTable::collapseTable(res);
  }
}

/// The starting value for the range and the step is preserved.  The
/// ending value is set so there are exactly the given number of elements
/// in the range.
/// \param nm is the given number
void JumpValuesRange::truncate(int4 nm)

{
  int4 rangeSize = 8*sizeof(uintb) - count_leading_zeros(range.getMask());
  rangeSize >>= 3;
  uintb left = range.getMin();
  int4 step = range.getStep();
  uintb right = (left + step * nm) & range.getMask();
  range.setRange(left, right, rangeSize, step);
}

uintb JumpValuesRange::getSize(void) const

{
  return range.getSize();
}

bool JumpValuesRange::contains(uintb val) const

{
  return range.contains(val);
}

bool JumpValuesRange::initializeForReading(void) const

{
  if (range.getSize()==0) return false;
  curval = range.getMin();
  return true;
}

bool JumpValuesRange::next(void) const

{
  return range.getNext(curval);
}

uintb JumpValuesRange::getValue(void) const

{
  return curval;
}

Varnode *JumpValuesRange::getStartVarnode(void) const

{
  return normqvn;
}

PcodeOp *JumpValuesRange::getStartOp(void) const

{
  return startop;
}

JumpValues *JumpValuesRange::clone(void) const

{
  JumpValuesRange *res = new JumpValuesRange();
  res->range = range;
  res->normqvn = normqvn;
  res->startop = startop;
  return res;
}

uintb JumpValuesRangeDefault::getSize(void) const

{
  return range.getSize() + 1;
}

bool JumpValuesRangeDefault::contains(uintb val) const

{
  if (extravalue == val)
    return true;
  return range.contains(val);
}

bool JumpValuesRangeDefault::initializeForReading(void) const

{
  if (range.getSize()==0) return false;
  curval = range.getMin();
  lastvalue = false;
  return true;
}

bool JumpValuesRangeDefault::next(void) const

{
  if (lastvalue) return false;
  if (range.getNext(curval))
    return true;
  lastvalue = true;
  curval = extravalue;
  return true;
}

Varnode *JumpValuesRangeDefault::getStartVarnode(void) const

{
  return lastvalue ? extravn : normqvn;
}

PcodeOp *JumpValuesRangeDefault::getStartOp(void) const

{
  return lastvalue ? extraop : startop;
}

JumpValues *JumpValuesRangeDefault::clone(void) const

{
  JumpValuesRangeDefault *res = new JumpValuesRangeDefault();
  res->range = range;
  res->normqvn = normqvn;
  res->startop = startop;
  res->extravalue = extravalue;
  res->extravn = extravn;
  res->extraop = extraop;
  return res;
}

bool JumpModelTrivial::recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)

{
  size = indop->getParent()->sizeOut();
  return ((size != 0)&&(size<=matchsize));
}

void JumpModelTrivial::buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const

{
  addresstable.clear();
  BlockBasic *bl = indop->getParent();
  for(int4 i=0;i<bl->sizeOut();++i) {
    const BlockBasic *outbl = (const BlockBasic *)bl->getOut(i);
    addresstable.push_back( outbl->getStart() );
  }
}

void JumpModelTrivial::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{
  for(uint4 i=0;i<addresstable.size();++i)
    label.push_back(addresstable[i].getOffset()); // Address itself is the label
}

JumpModel *JumpModelTrivial::clone(JumpTable *jt) const

{
  JumpModelTrivial *res = new JumpModelTrivial(jt);
  res->size = size;
  return res;
}

bool JumpBasic::isprune(Varnode *vn)

{
  if (!vn->isWritten()) return true;
  PcodeOp *op = vn->getDef();
  if (op->isCall()||op->isMarker()) return true;
  if (op->numInput()==0) return true;
  return false;
}

bool JumpBasic::ispoint(Varnode *vn)

{				// Is this a possible switch variable
  if (vn->isConstant()) return false;
  if (vn->isAnnotation()) return false;
  if (vn->isReadOnly()) return false;
  return true;
}

/// If the some of the least significant bits of the given Varnode are known to
/// be zero, translate this into a stride for the jumptable range.
/// \param vn is the given Varnode
/// \return the calculated stride = 1,2,4,...
int4 JumpBasic::getStride(Varnode *vn)

{
  uintb mask = vn->getNZMask();
  if ((mask & 0x3f)==0)		// Limit the maximum stride we can return
    return 32;
  int4 stride = 1;
  while((mask&1)==0) {
    mask >>= 1;
    stride <<= 1;
  }
  return stride;
}

uintb JumpBasic::backup2Switch(Funcdata *fd,uintb output,Varnode *outvn,Varnode *invn)

{ // Back up constant normalized value -outvn- to unnormalized
  Varnode *curvn = outvn;
  PcodeOp *op;
  TypeOp *top;
  int4 slot;

  while(curvn != invn) {
    op = curvn->getDef();
    top = op->getOpcode();
    for(slot=0;slot<op->numInput();++slot) // Find first non-constant input
      if (!op->getIn(slot)->isConstant()) break;
    if (op->getEvalType() == PcodeOp::binary) {
      const Address &addr(op->getIn(1-slot)->getAddr());
      uintb otherval;
      if (!addr.isConstant()) {
	MemoryImage mem(addr.getSpace(),4,1024,fd->getArch()->loader);
	otherval = mem.getValue(addr.getOffset(),op->getIn(1-slot)->getSize());
      }
      else
	otherval = addr.getOffset();
      output = top->recoverInputBinary(slot,op->getOut()->getSize(),output,
				       op->getIn(slot)->getSize(),otherval);
      curvn = op->getIn(slot);
    }
    else if (op->getEvalType() == PcodeOp::unary) {
      output = top->recoverInputUnary(op->getOut()->getSize(),output,op->getIn(slot)->getSize());
      curvn = op->getIn(slot);
    }
    else
      throw LowlevelError("Bad switch normalization op");
  }
  return output;
}

void JumpBasic::findDeterminingVarnodes(PcodeOp *op,int4 slot)

{
  vector<PcodeOp *> path;
  vector<int4> slotpath;
  PcodeOp *curop;
  Varnode *curvn;
  bool firstpoint = false;	// Have not seen likely switch variable yet

  path.push_back(op);
  slotpath.push_back(slot);

  do {	// Traverse through tree of inputs to final address
    curop = path.back();
    curvn = curop->getIn(slotpath.back());
    if (isprune(curvn)) {	// Here is a node of the tree
      if (ispoint(curvn)) {	// Is it a possible switch variable
	if (!firstpoint) {	// If it is the first possible
	  pathMeld.set(path,slotpath);	// Take the current path as the result
	  firstpoint = true;
	}
	else			// If we have already seen at least one possible
	  pathMeld.meld(path,slotpath);
      }

      slotpath.back() += 1;
      while(slotpath.back() >= path.back()->numInput()) {
	path.pop_back();
	slotpath.pop_back();
	if (path.empty()) break;
	slotpath.back() += 1;
      }
    }
    else {			// This varnode is not pruned
      path.push_back(curvn->getDef());
      slotpath.push_back(0);
    }
  } while(path.size() > 1);
  if (pathMeld.empty()) {	// Never found a likely point, which means that
				// it looks like the address is uniquely determined
				// but the constants/readonlys haven't been collapsed
    pathMeld.set(op,op->getIn(slot));
  }
}

static bool matching_constants(Varnode *vn1,Varnode *vn2)

{
  if (!vn1->isConstant()) return false;
  if (!vn2->isConstant()) return false;
  if (vn1->getOffset() != vn2->getOffset()) return false;
  return true;
}

GuardRecord::GuardRecord(PcodeOp *op,int4 path,const CircleRange &rng,Varnode *v)

{
  cbranch = op;
  indpath = path;
  range = rng;
  vn = v;
  baseVn = quasiCopy(v,bitsPreserved,false);		// Look for varnode whose bits are copied
}

int4 GuardRecord::valueMatch(Varnode *vn2,Varnode *baseVn2,int4 bitsPreserved2) const

{ // Return 0, if -vn- and -vn2- are not clearly the same value
  // Return 1, if -vn- and -vn2- are clearly the same value
  // Return 2, if -vn- and -vn2- are clearly the same value, pending no writes beteen the def of -vn- and -vn2-
  if (vn == vn2) return 1;		// Same varnode, same value
  PcodeOp *loadOp,*loadOp2;
  if (bitsPreserved == bitsPreserved2) {	// Are the same number of bits being copied
    if (baseVn == baseVn2)			// Are bits being copied from same varnode
      return 1;					// If so, values are the same
    loadOp = baseVn->getDef();			// Otherwise check if different base varnodes hold same value
    loadOp2 = baseVn2->getDef();
  }
  else {
    loadOp = vn->getDef();			// Check if different varnodes hold same value
    loadOp2 = vn2->getDef();
  }
  if (loadOp == (PcodeOp *)0) return 0;
  if (loadOp2 == (PcodeOp *)0) return 0;
  if (oneOffMatch(loadOp,loadOp2) == 1)		// Check for simple duplicate calculations
    return 1;
  if (loadOp->code() != CPUI_LOAD) return 0;
  if (loadOp2->code() != CPUI_LOAD) return 0;
  if (loadOp->getIn(0)->getOffset() != loadOp2->getIn(0)->getOffset()) return 0;
  Varnode *ptr = loadOp->getIn(1);
  Varnode *ptr2 = loadOp2->getIn(1);
  if (ptr == ptr2) return 2;
  if (!ptr->isWritten()) return 0;
  if (!ptr2->isWritten()) return 0;
  PcodeOp *addop = ptr->getDef();
  if (addop->code() != CPUI_INT_ADD) return 0;
  Varnode *constvn = addop->getIn(1);
  if (!constvn->isConstant()) return 0;
  PcodeOp *addop2 = ptr2->getDef();
  if (addop2->code() != CPUI_INT_ADD) return 0;
  Varnode *constvn2 = addop2->getIn(1);
  if (!constvn2->isConstant()) return 0;
  if (addop->getIn(0) != addop2->getIn(0)) return 0;
  if (constvn->getOffset() != constvn2->getOffset()) return 0;
  return 2;
}

int4 GuardRecord::oneOffMatch(PcodeOp *op1,PcodeOp *op2)

{ // Return 1 if -op1- and -op2- produce exactly the same value, 0 if otherwise
  // (one value is allowed to be the zero extension of the other)
  if (op1->code() != op2->code())
    return 0;
  switch(op1->code()) {
  case CPUI_INT_AND:
  case CPUI_INT_ADD:
  case CPUI_INT_XOR:
  case CPUI_INT_OR:
  case CPUI_INT_LEFT:
  case CPUI_INT_RIGHT:
  case CPUI_INT_SRIGHT:
  case CPUI_INT_MULT:
  case CPUI_SUBPIECE:
    if (op2->getIn(0) != op1->getIn(0)) return 0;
    if (matching_constants(op2->getIn(1),op1->getIn(1)))
      return 1;
    break;
  default:
    break;
  }
  return 0;
}

Varnode *GuardRecord::quasiCopy(Varnode *vn,int4 &bitsPreserved,bool noWholeValue)

{
  Varnode *origVn = vn;
  bitsPreserved = mostsigbit_set(vn->getNZMask()) + 1;
  if (bitsPreserved == 0) return vn;
  uintb mask = 1;
  mask <<= bitsPreserved;
  mask -= 1;
  PcodeOp *op = vn->getDef();
  Varnode *constVn;
  while(op != (PcodeOp *)0) {
    if (noWholeValue && (vn != origVn)) {
      uintb inputMask = vn->getNZMask() | mask;
      if (mask == inputMask)
	return origVn;		// vn contains whole value, -noWholeValue- indicates we should abort
    }
    switch(op->code()) {
    case CPUI_COPY:
      vn = op->getIn(0);
      op = vn->getDef();
      break;
    case CPUI_INT_AND:
      constVn = op->getIn(1);
      if (constVn->isConstant() && constVn->getOffset() == mask) {
	vn = op->getIn(0);
	op = vn->getDef();
      }
      else
	op = (PcodeOp *)0;
      break;
    case CPUI_INT_OR:
      constVn = op->getIn(1);
      if (constVn->isConstant() && ((constVn->getOffset() | mask) == (constVn->getOffset() ^ mask))) {
	vn = op->getIn(0);
	op = vn->getDef();
      }
      else
	op = (PcodeOp *)0;
      break;
    case CPUI_INT_SEXT:
    case CPUI_INT_ZEXT:
      if (op->getIn(0)->getSize() * 8 >= bitsPreserved) {
	vn = op->getIn(0);
	op = vn->getDef();
      }
      else
	op = (PcodeOp *)0;
      break;
    case CPUI_PIECE:
      if (op->getIn(1)->getSize() * 8 >= bitsPreserved) {
	vn = op->getIn(1);
	op = vn->getDef();
      }
      else
	op = (PcodeOp *)0;
      break;
    case CPUI_SUBPIECE:
      constVn = op->getIn(1);
      if (constVn->isConstant() && constVn->getOffset() == 0) {
	vn = op->getIn(0);
	op = vn->getDef();
      }
      else
	op = (PcodeOp *)0;
      break;
    default:
      op = (PcodeOp *)0;
      break;
    }
  }
  return vn;
}

void PathMeld::internalIntersect(vector<int4> &parentMap)

{ // Calculate intersection of new path (marked vn's) with old path (commonVn)
  // Put intersection back into commonVn
  // Calculate parentMap : from old commonVn index to new commonVn index
  vector<Varnode *> newVn;
  int4 lastIntersect = -1;
  for(int4 i=0;i<commonVn.size();++i) {
    Varnode *vn = commonVn[i];
    if (vn->isMark()) {		// Look for previously marked varnode, so we know it is in both lists
      lastIntersect = newVn.size();
      parentMap.push_back(lastIntersect);
      newVn.push_back(vn);
      vn->clearMark();
    }
    else
      parentMap.push_back(-1);
  }
  commonVn = newVn;
  lastIntersect = -1;
  for(int4 i=parentMap.size()-1;i>=0;--i) {
    int4 val = parentMap[i];
    if (val == -1)			// Fill in varnodes that are cut out of intersection
      parentMap[i] = lastIntersect;	// with next earliest varnode that is in intersection
    else
      lastIntersect = val;
  }
}

int4 PathMeld::meldOps(const vector<PcodeOp *> &path,int4 cutOff,const vector<int4> &parentMap)

{ // Meld old ops (opMeld) with new ops (path), updating rootVn with new commonVn order
  // Ops should remain in (reverse) execution order
  // Ops that split (use a vn not in intersection) and do not rejoin (have a predecessor vn in intersection)
  //     get cut
  // If splitting ops arent can't be ordered with the existing meld, we get a new cut point

  // First update opMeld.rootVn with new intersection information
  for(int4 i=0;i<opMeld.size();++i) {
    int4 pos = parentMap[opMeld[i].rootVn];
    if (pos == -1) {
      opMeld[i].op = (PcodeOp *)0;		// Op split but did not rejoin
    }
    else
      opMeld[i].rootVn = pos;			// New index
  }

  // Do a merge sort, keeping ops in execution order
  vector<RootedOp> newMeld;
  int4 curRoot = -1;
  int4 meldPos = 0;				// Ops moved from old opMeld into newMeld
  const BlockBasic *lastBlock = (const BlockBasic *)0;
  for(int4 i=0;i<cutOff;++i) {
    PcodeOp *op = path[i];			// Current op in the new path
    PcodeOp *curOp = (PcodeOp *)0;
    while(meldPos < opMeld.size()) {
      PcodeOp *trialOp = opMeld[meldPos].op;	// Current op in the old opMeld
      if (trialOp == (PcodeOp *)0) {
	meldPos += 1;
	continue;
      }
      if (trialOp->getParent() != op->getParent()) {
	if (op->getParent() == lastBlock) {
	  curOp = (PcodeOp *)0;		// op comes AFTER trialOp
	  break;
	}
	else if (trialOp->getParent() != lastBlock) {
	  // Both trialOp and op come from different blocks that are not the lastBlock
	  int4 res = opMeld[meldPos].rootVn;		// Force truncatePath at (and above) this op

	  // Found a new cut point
	  opMeld = newMeld;				// Take what we've melded so far
	  return res;					// return the new cutpoint
	}
      }
      else if (trialOp->getSeqNum().getOrder() <= op->getSeqNum().getOrder()) {
	curOp = trialOp;		// op is equal to or comes later than trialOp
	break;
      }
      lastBlock = trialOp->getParent();
      newMeld.push_back(opMeld[meldPos]);	// Current old op moved into newMeld
      curRoot = opMeld[meldPos].rootVn;
      meldPos += 1;
    }
    if (curOp == op) {
      newMeld.push_back(opMeld[meldPos]);
      curRoot = opMeld[meldPos].rootVn;
      meldPos += 1;
    }
    else {
      newMeld.push_back(RootedOp(op,curRoot));
    }
    lastBlock = op->getParent();
  }
  opMeld = newMeld;
  return -1;
}

void PathMeld::truncatePaths(int4 cutPoint)

{ // Make sure all paths in opMeld terminate at -cutPoint- varnode
  // and cut varnodes beyond the cutPoint out of the intersection (commonVn)
  while(opMeld.size() > 1) {
    if (opMeld.back().rootVn < cutPoint)	// If we see op using varnode earlier than cut point
      break;					// Keep that and all subsequent ops
    opMeld.pop_back();				// Otherwise cut the op
  }
  commonVn.resize(cutPoint);			// Since intersection is ordered, just resize to cutPoint
}

void PathMeld::set(const PathMeld &op2)

{
  commonVn = op2.commonVn;
  opMeld = op2.opMeld;
}

void PathMeld::set(const vector<PcodeOp *> &path,const vector<int4> &slot)

{
  for(int4 i=0;i<path.size();++i) {
    PcodeOp *op = path[i];
    Varnode *vn = op->getIn(slot[i]);
    opMeld.push_back(RootedOp(op,i));
    commonVn.push_back(vn);
  }
}

void PathMeld::set(PcodeOp *op,Varnode *vn)

{ // Set a single varnode and op as the path
  commonVn.push_back(vn);
  opMeld.push_back(RootedOp(op,0));
}

void PathMeld::append(const PathMeld &op2)

{
  commonVn.insert(commonVn.begin(),op2.commonVn.begin(),op2.commonVn.end());
  opMeld.insert(opMeld.begin(),op2.opMeld.begin(),op2.opMeld.end());
  // Renumber all the rootVn refs to varnodes we have moved
  for(int4 i=op2.opMeld.size();i<opMeld.size();++i)
    opMeld[i].rootVn += op2.commonVn.size();
}

void PathMeld::clear(void)

{
  commonVn.clear();
  opMeld.clear();
}

void PathMeld::meld(vector<PcodeOp *> &path,vector<int4> &slot)

{ // Meld the new -path- into our collection of paths
  // making sure all ops that split from the main path intersection eventually rejoin
  vector<int4> parentMap;

  for(int4 i=0;i<path.size();++i) {
    Varnode *vn = path[i]->getIn(slot[i]);
    vn->setMark();		// Mark varnodes in the new path, so its easy to see intersection
  }
  internalIntersect(parentMap);	// Calculate varnode intersection, and map from old intersection -> new
  int4 cutOff = -1;

  // Calculate where the cutoff point is in the new path
  for(int4 i=0;i<path.size();++i) {
    Varnode *vn = path[i]->getIn(slot[i]);
    if (!vn->isMark()) {	// If mark already cleared, we know it is in intersection
      cutOff = i + 1;		// Cut-off must at least be past this -vn-
    }
    else
      vn->clearMark();
  }
  int4 newCutoff = meldOps(path,cutOff,parentMap);	// Given cutoff point, meld in new ops
  if (newCutoff >= 0)					// If not all ops could be ordered
    truncatePaths(newCutoff);				// Cut off at the point where we couldn't order
  path.resize(cutOff);
  slot.resize(cutOff);
}

PcodeOp *PathMeld::getEarliestOp(int4 pos) const

{ // Find "earliest" op that has commonVn[i] as input
  for(int4 i=opMeld.size()-1;i>=0;--i) {
    if (opMeld[i].rootVn == pos)
      return opMeld[i].op;
  }
  return (PcodeOp *)0;
}

void JumpBasic::analyzeGuards(BlockBasic *bl,int4 pathout)

{ // Analyze each CBRANCH leading up to -bl- switch.
  // (if pathout>=0, also analyze the CBRANCH in -bl- that chooses this path)
  // Analyze the range restrictions on the various variables which allow
  // control flow to pass through the CBRANCHs to the switch.
  // Make note of all these restrictions in the guard list
  // For later determination of the correct switch variable.
  int4 i,j,indpath;
  int4 maxbranch = 2;		// Maximum number of CBRANCHs to consider
  int4 maxpullback = 2;
  bool usenzmask = (jumptable->getStage() == 0);

  selectguards.clear();
  BlockBasic *prevbl;
  Varnode *vn;

  for(i=0;i<maxbranch;++i) {
    if ((pathout>=0)&&(bl->sizeOut()==2)) {
      prevbl = bl;
      bl = (BlockBasic *)prevbl->getOut(pathout);
      indpath = pathout;
      pathout = -1;
    }
    else {
      pathout = -1;		// Make sure not to use pathout next time around
      for(;;) {
	if (bl->sizeIn() != 1) return; // Assume only 1 path to switch
	prevbl = (BlockBasic *)bl->getIn(0);
	if (prevbl->sizeOut() != 1) break; // Is it possible to deviate from switch path in this block
	bl = prevbl;		// If not, back up to next block
      }
      indpath = bl->getInRevIndex(0);
    }
    PcodeOp *cbranch = prevbl->lastOp();
    if ((cbranch==(PcodeOp *)0)||(cbranch->code() != CPUI_CBRANCH))
      break;
    bool toswitchval = (indpath == 1);
    if (cbranch->isBooleanFlip())
      toswitchval = !toswitchval;
    bl = prevbl;
    vn = cbranch->getIn(1);
    CircleRange rng(toswitchval);
    
    // The boolean variable could conceivably be the switch variable
    int4 indpathstore = prevbl->getFlipPath() ? 1-indpath : indpath;
    selectguards.push_back(GuardRecord(cbranch,indpathstore,rng,vn));
    for(j=0;j<maxpullback;++j) {
      Varnode *markup;		// Throw away markup information
      if (!vn->isWritten()) break;
      vn = rng.pullBack(vn->getDef(),&markup,usenzmask);
      if (vn == (Varnode *)0) break;
      if (rng.isEmpty()) break;
      selectguards.push_back(GuardRecord(cbranch,indpathstore,rng,vn));
    }
  }
}

void JumpBasic::calcRange(Varnode *vn,CircleRange &rng) const

{ // For a putative switch variable, calculate the range of
  // possible values that variable can have AT the switch
  // by using the precalculated guard ranges.

  // Get an initial range, based on the size/type of -vn-
  int4 stride = 1;
  if (vn->isConstant())
    rng = CircleRange(vn->getOffset(),vn->getSize());
  else if (vn->isWritten() && vn->getDef()->isBoolOutput())
    rng = CircleRange(0,2,1,1);	// Only 0 or 1 possible
  else {			// Should we go ahead and use nzmask in all cases?
    uintb maxValue = 0;		// Every possible value
    if (vn->isWritten()) {
      PcodeOp *andop = vn->getDef();
      if (andop->code() == CPUI_INT_AND) {
	Varnode *constvn = andop->getIn(1);
	if (constvn->isConstant()) {
	  maxValue = coveringmask( constvn->getOffset() );
	  maxValue = (maxValue + 1) & calc_mask(vn->getSize());
	}
      }
    }
    stride = getStride(vn);
    rng = CircleRange(0,maxValue,vn->getSize(),stride);
  }

  // Intersect any guard ranges which apply to -vn-
  int4 bitsPreserved;
  Varnode *baseVn = GuardRecord::quasiCopy(vn, bitsPreserved, true);
  vector<GuardRecord>::const_iterator iter;
  for(iter=selectguards.begin();iter!=selectguards.end();++iter) {
    const GuardRecord &guard( *iter );
    int4 matchval = guard.valueMatch(vn,baseVn,bitsPreserved);
    // if (matchval == 2)   TODO: we need to check for aliases
    if (matchval==0) continue;
    if (rng.intersect(guard.getRange())!=0) continue;
  }

  // It may be an assumption that the switch value is positive
  // in which case the guard might not check for it. If the
  // size is too big, we try only positive values
  if (rng.getSize() > 0x10000) {
    CircleRange positive(0,(rng.getMask()>>1)+1,vn->getSize(),stride);
    positive.intersect(rng);
    if (!positive.isEmpty())
      rng = positive;
  }
}

void JumpBasic::findSmallestNormal(uint4 matchsize)

{ // Find normalized switch variable with smallest range of values
  CircleRange rng;
  uintb sz,maxsize;

  varnodeIndex = 0;
  calcRange(pathMeld.getVarnode(0),rng);
  jrange->setRange(rng);
  jrange->setStartVn(pathMeld.getVarnode(0));
  jrange->setStartOp(pathMeld.getOp(0));
  maxsize = rng.getSize();
  for(uint4 i=1;i<pathMeld.numCommonVarnode();++i) {
    if (maxsize == matchsize)	// Found variable that gives (already recovered) size
      return;
    calcRange(pathMeld.getVarnode(i),rng);
    sz = rng.getSize();
    if (sz < maxsize) {
      // Don't let a 1-byte switch variable get thru without a guard
      if ((sz != 256)||(pathMeld.getVarnode(i)->getSize()!=1)) {
	varnodeIndex = i;
	maxsize = sz;
	jrange->setRange(rng);
	jrange->setStartVn(pathMeld.getVarnode(i));
	jrange->setStartOp(pathMeld.getEarliestOp(i));
      }
    }
  }
}

void JumpBasic::findNormalized(Funcdata *fd,BlockBasic *rootbl,int4 pathout,uint4 matchsize,uint4 maxtablesize)

{				// Find the normalized switch variable
  uintb sz;

  analyzeGuards(rootbl,pathout);
  findSmallestNormal(matchsize);
  sz = jrange->getSize();
  if ((sz > maxtablesize)&&(pathMeld.numCommonVarnode()==1)) {
    // Check for jump through readonly variable
    // Note the normal jumptable algorithms are cavalier about
    // the jumptable being in readonly memory or not because
    // a jumptable construction almost always implies that the
    // entries are readonly even if they aren't labelled properly
    // The exception is if the jumptable has only one branch
    // as it very common to have semi-dynamic vectors that are
    // set up by the system. But the original LoadImage values
    // are likely incorrect. So for 1 branch, we insist on readonly
    Architecture *glb = fd->getArch();
    Varnode *vn = pathMeld.getVarnode(0);
    if (vn->isReadOnly()) {
      MemoryImage mem(vn->getSpace(),4,16,glb->loader);
      uintb val = mem.getValue(vn->getOffset(),vn->getSize());
      varnodeIndex = 0;
      jrange->setRange(CircleRange(val,vn->getSize()));
      jrange->setStartVn(vn);
      jrange->setStartOp(pathMeld.getOp(0));
    }
  }
}

void JumpBasic::markFoldableGuards(void)

{ // Indicate which are the true guards (that need to be folded) by leaving their cbranch non-null
  Varnode *vn = pathMeld.getVarnode(varnodeIndex);
  int4 bitsPreserved;
  Varnode *baseVn = GuardRecord::quasiCopy(vn, bitsPreserved, true);
  for(int4 i=0;i<selectguards.size();++i) {
    if (selectguards[i].valueMatch(vn,baseVn,bitsPreserved)==0) {
      selectguards[i].clear();		// Indicate this is not a true guard
    }
  }
}

bool JumpBasic::foldInOneGuard(Funcdata *fd,GuardRecord &guard,JumpTable *jump)

{
  PcodeOp *cbranch = guard.getBranch();
  int4 indpath = guard.getPath();	// Get stored path to indirect block
  BlockBasic *cbranchblock = cbranch->getParent();
  if (cbranchblock->getFlipPath()) // Based on whether out branches have been flipped
    indpath = 1 - indpath;	// get actual path to indirect block
  BlockBasic *guardtarget = (BlockBasic *)cbranchblock->getOut(1-indpath);
  bool change = false;
  uint4 pos;

  // Its possible the guard branch has been converted between the switch recovery and now
  if (cbranchblock->sizeOut() != 2) return false; // In which case, we can't fold it in
  BlockBasic *switchbl = jump->getIndirectOp()->getParent();
  for(pos=0;pos<switchbl->sizeOut();++pos)
    if (switchbl->getOut(pos) == guardtarget) break;
  if (pos == switchbl->sizeOut()) {
    if (BlockBasic::noInterveningStatement(cbranch,indpath,switchbl->lastOp())) {
      // Adjust tables and control flow graph
      // for new jumptable destination
      jump->addBlockToSwitch(guardtarget,0xBAD1ABE1);
      jump->setMostCommonIndex(jump->numEntries()-1);
      fd->pushBranch(cbranchblock,1-indpath,switchbl);
      guard.clear();
      change = true;
    }
  }
  else {
    // We should probably check that there are no intervening
    // statements between the guard and the switch. But the
    // fact that the guard target is also a switch target
    // is a good indicator that there are none
    uintb val = ((indpath==0)!=(cbranch->isBooleanFlip())) ? 0 : 1;
    fd->opSetInput(cbranch,fd->newConstant(cbranch->getIn(0)->getSize(),val),1);
    jump->setMostCommonBlock(pos);	// A guard branch must be most common
    guard.clear();
    change = true;
  }
  return change;
}

JumpBasic::~JumpBasic(void)

{
  if (jrange != (JumpValuesRange *)0)
    delete jrange;
}

bool JumpBasic::recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)

{ // Try to recover a jumptable using the basic model
  // Basically there needs to be a straight line calculation from a switch variable to the final
  // address used for the BRANCHIND.  The switch variable is restricted to a small range by one
  // or more "guard" instructions that, if the switch variable is not in range, branch to a default
  // location.
  jrange = new JumpValuesRange();
  findDeterminingVarnodes(indop,0);
  findNormalized(fd,indop->getParent(),-1,matchsize,maxtablesize);
  if (jrange->getSize() > maxtablesize)
    return false;
  markFoldableGuards();
  return true;
}

void JumpBasic::buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const

{
  uintb val,addr;
  addresstable.clear();		// Clear out any partial recoveries
				// Build the emulation engine
  EmulateFunction emul(fd);
  if (loadpoints != (vector<LoadTable> *)0)
    emul.setLoadCollect(true);

  AddrSpace *spc = indop->getAddr().getSpace();
  bool notdone = jrange->initializeForReading();
  while(notdone) {
    val = jrange->getValue();
    addr = emul.emulatePath(val,pathMeld,jrange->getStartOp(),jrange->getStartVarnode());
    addr = AddrSpace::addressToByte(addr,spc->getWordSize());
    addresstable.push_back(Address(spc,addr));
    notdone = jrange->next();
  }
  if (loadpoints != (vector<LoadTable> *)0)
    emul.collectLoadPoints(*loadpoints);
}

void JumpBasic::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{				// Assuming normalized is recovered, try to work
				// back to the unnormalized varnode
  int4 i,j;
  Varnode *testvn;
  PcodeOp *normop;

  i = varnodeIndex;
  normalvn = pathMeld.getVarnode(i++);
  switchvn = normalvn;

  int4 countaddsub=0;
  int4 countext=0;
  while(i<pathMeld.numCommonVarnode()) {
				// Between switchvn and normalvn, should be singleuse
    if ((switchvn != normalvn)&&(switchvn->loneDescend() == (PcodeOp *)0)) break;
    testvn = pathMeld.getVarnode(i);
    if (!switchvn->isWritten()) break;
    normop = switchvn->getDef();
    for(j=0;j<normop->numInput();++j)
      if (normop->getIn(j) == testvn) break;
    if (j==normop->numInput()) break;
    switch(normop->code()) {
    case CPUI_INT_ADD:
    case CPUI_INT_SUB:
      countaddsub += 1;
      if (countaddsub > maxaddsub) break;
      if (!normop->getIn(1-j)->isConstant()) break;
      switchvn = testvn;
      break;
    case CPUI_INT_ZEXT:
    case CPUI_INT_SEXT:
      countext += 1;
      if (countext > maxext) break;
      switchvn = testvn;
      break;
    default:
      break;
    }
    if (switchvn != testvn) break;
    i += 1;
  }
}

void JumpBasic::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{ // Trace back each normal value to
  // the unnormalized value, this is the "case" label
  uintb val,switchval;
  const JumpValuesRange *origrange = (( const JumpBasic *)orig)->getValueRange();

  bool notdone = origrange->initializeForReading();
  while(notdone) {
    val = origrange->getValue();
    int4 needswarning = 0;	// 0=nowarning, 1=this code block may not be properly labeled, 2=calculation failed
    if (origrange->isReversible()) {	// If the current value is reversible
      if (!jrange->contains(val))
	needswarning = 1;
      try {
	switchval = backup2Switch(fd,val,normalvn,switchvn);		// Do reverse emulation to get original switch value
      } catch(EvaluationError &err) {
	switchval = 0xBAD1ABE1;
	needswarning = 2;
      }
    }
    else
      switchval = 0xBAD1ABE1;	// If can't reverse, hopefully this is the default or exit, otherwise give "badlabel"
    if (needswarning==1)
      fd->warning("This code block may not be properly labeled as switch case",addresstable[label.size()]);
    else if (needswarning==2)
      fd->warning("Calculation of case label failed",addresstable[label.size()]);
    label.push_back(switchval);
      
  // Take into account the fact that the address table may have
  // been truncated (via the sanity check)
    if (label.size() >= addresstable.size()) break;
    notdone = origrange->next();
  }

  while(label.size() < addresstable.size()) {
    fd->warning("Bad switch case",addresstable[label.size()]);
    label.push_back(0xBAD1ABE1);
  }
}

void JumpBasic::foldInNormalization(Funcdata *fd,PcodeOp *indop)

{				// Assume normalized and unnormalized values are found
				// Fold normalization pcode into indirect branch
				// Treat unnormalized value as input CPUI_BRANCHIND
				// so it becomes literally the C switch statement
  fd->opSetInput(indop,switchvn,0);
}

bool JumpBasic::foldInGuards(Funcdata *fd,JumpTable *jump)

{ // We now think of the BRANCHIND as encompassing
  // the guard function, so we "disarm" the guard
  // instructions by making the guard condition
  // always false.  If the simplification removes
  // the unusable branches, we are left with only
  // one path through the switch
  bool change = false;
  for(int4 i=0;i<selectguards.size();++i) {
    PcodeOp *cbranch = selectguards[i].getBranch();
    if (cbranch == (PcodeOp *)0) continue; // Already normalized
    if (cbranch->isDead()) {
      selectguards[i].clear();
      continue;
    }
    if (foldInOneGuard(fd,selectguards[i],jump))
      change = true;
  }
  return change;
}

bool JumpBasic::sanityCheck(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable)

{				// Test all the addresses in the addresstable checking
				// that they are reasonable. We cut off at first
				// unreasonable
  int4 i;
  uintb diff;
  if (addresstable.empty()) return true;
  Address addr = addresstable[0];
  i = 0;
  if (addr.getOffset() != 0) {
    for(i=1;i<addresstable.size();++i) {
      if (addresstable[i].getOffset() == 0) break;
      diff = (addr.getOffset() < addresstable[i].getOffset()) ? 
	(addresstable[i].getOffset()-addr.getOffset()) :
	(addr.getOffset()-addresstable[i].getOffset());
      if (diff > 0xffff) {
	uint1 buffer[8];
	LoadImage *loadimage = fd->getArch()->loader;
	bool dataavail = true;
	try {
	  loadimage->loadFill(buffer,4,addresstable[i]);
	} catch(DataUnavailError &err) {
	  dataavail = false;
	}
	if (!dataavail) break;
      }
    }
  }
  if (i==0)
    return false;
  if (i!=addresstable.size()) {
    addresstable.resize(i);
    jrange->truncate(i);
  }
  return true;
}

JumpModel *JumpBasic::clone(JumpTable *jt) const

{ // We only need to clone the JumpValues
  JumpBasic *res = new JumpBasic(jt);
  res->jrange = (JumpValuesRange *)jrange->clone();
  return res;
}

void JumpBasic::clear(void)

{
  if (jrange != (JumpValuesRange *)0) {
    delete jrange;
    jrange = (JumpValuesRange *)0;
  }
  pathMeld.clear();
  selectguards.clear();
  normalvn = (Varnode *)0;
  switchvn = (Varnode *)0;
}

bool JumpBasic2::foldInOneGuard(Funcdata *fd,GuardRecord &guard,JumpTable *jump)

{ // The are two main cases here:
  //    If we recovered a switch in a loop,
  //       the guard is also the loop condition, so we don't want to remove it.
  //
  //    If the guard is just deciding whether or not to use a default switch value,
  //       the guard will disappear anyway because the normalization foldin will make all its blocks donothings
  //
  // So we don't make any special mods, in case there are extra statements in these blocks

  // The final block in the table is the single value produced by the model2 guard
  jump->setMostCommonIndex(jump->numEntries()-1);	// It should be the default block
  guard.clear();	// Mark that we are folded
  return true;
}

void JumpBasic2::initializeStart(const PathMeld &pathMeld)

{ // Initialize with the point at which model 1 failed
  if (pathMeld.empty()) {
    extravn = (Varnode *)0;
    return;
  }
  extravn = pathMeld.getVarnode(pathMeld.numCommonVarnode()-1);
  origPathMeld.set(pathMeld);
}

bool JumpBasic2::recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)

{ // Try to recover a jumptable using the second model
  // Basically there is a guard on the main switch variable,
  // Along one path, an intermediate value is set to a default constant.
  // Along the other path, the intermediate value results in a straight line calculation from the switch var
  // The two-pathed intermediate value comes together in a MULTIEQUAL, and there is a straightline
  // calculation to the BRANCHIND
  
  // We piggy back on the partial calculation from the basic model to see if we have the MULTIEQUAL
  Varnode *othervn = (Varnode *)0;
  PcodeOp *copyop = (PcodeOp *)0;
  uintb extravalue = 0;
  Varnode *joinvn = extravn;	// extravn should be set to as far back as model 1 could trace
  if (joinvn == (Varnode *)0) return false;
  if (!joinvn->isWritten()) return false;
  PcodeOp *multiop = joinvn->getDef(); 
  if (multiop->code() != CPUI_MULTIEQUAL) return false;
  if (multiop->numInput() != 2) return false; // Must be exactly 2 paths
  // Search for a constant along one of the paths
  int4 path;
  for(path=0;path<2;++path) {
    Varnode *vn = multiop->getIn(path);
    if (!vn->isWritten()) continue;
    copyop = vn->getDef();
    if (copyop->code() != CPUI_COPY) continue;
    othervn = copyop->getIn(0);
    if (othervn->isConstant()) {
      extravalue = othervn->getOffset();
      break;
    }
  }
  if (path == 2) return false;
  BlockBasic *rootbl = (BlockBasic *)multiop->getParent()->getIn(1-path);
  int4 pathout = multiop->getParent()->getInRevIndex(1-path);
  JumpValuesRangeDefault *jdef = new JumpValuesRangeDefault();
  jrange = jdef;
  jdef->setExtraValue(extravalue);
  jdef->setDefaultVn(joinvn);	// Emulate the default calculation from the join point
  jdef->setDefaultOp(origPathMeld.getOp(origPathMeld.numOps()-1));

  findDeterminingVarnodes(multiop,1-path);
  findNormalized(fd,rootbl,pathout,matchsize,maxtablesize);
  if (jrange->getSize() > maxtablesize)
    return false;		// We didn't find a good range

  // Insert the final sequence of operations, after the MULTIEQUAL, for constructing the address
  pathMeld.append(origPathMeld);
  varnodeIndex += origPathMeld.numCommonVarnode();	// index is pushed up by the append
  return true;
}

bool JumpBasic2::checkNormalDominance(void) const

{ // Check if the block that defines the normalized switch variable dominates the block containing the switch
  if (normalvn->isInput())
    return true;
  FlowBlock *defblock = normalvn->getDef()->getParent();
  FlowBlock *switchblock = pathMeld.getOp(0)->getParent();
  while(switchblock != (FlowBlock *)0) {
    if (switchblock == defblock)
      return true;
    switchblock = switchblock->getImmedDom();
  }
  return false;
}

void JumpBasic2::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  normalvn = pathMeld.getVarnode(varnodeIndex);	// Normalized switch variable
  if (checkNormalDominance()) {	// If the normal switch variable dominates the switch itself
    JumpBasic::findUnnormalized(maxaddsub,maxleftright,maxext);	// We can use the basic form of calculating the unnormalized
    return;
  }

  // We have the unusual situation that we must go BACKWARD from the unnormalized variable
  // to get to the normalized variable
  switchvn = extravn;
  PcodeOp *multiop = extravn->getDef();	// Already tested that this is a MULTIEQUAL with 2 inputs
  if ((multiop->getIn(0)==normalvn)||(multiop->getIn(1)==normalvn)) {
    normalvn = switchvn;	// No value difference between normalized and unnormalized
  }
  else
    throw LowlevelError("Backward normalization not implemented");
}

JumpModel *JumpBasic2::clone(JumpTable *jt) const

{ // We only need to clone the JumpValues
  JumpBasic2 *res = new JumpBasic2(jt);
  res->jrange = (JumpValuesRange *)jrange->clone();
  return res;
}

void JumpBasic2::clear(void)

{
  extravn = (Varnode *)0;
  origPathMeld.clear();
  JumpBasic::clear();
}

JumpBasicOverride::JumpBasicOverride(JumpTable *jt)
  : JumpBasic(jt)
{
  startingvalue = 0;
  hash = 0;
  istrivial = false;
}

void JumpBasicOverride::setAddresses(const vector<Address> &adtable)

{
  for(int4 i=0;i<adtable.size();++i)
    adset.insert(adtable[i]);
}

int4 JumpBasicOverride::findStartOp(Varnode *vn)

{ // Return the op (within determop) that takes -vn- as input, otherwise return null
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = vn->beginDescend();
  enditer = vn->endDescend();
  for(;iter!=enditer;++iter)
    (*iter)->setMark();
  int4 res = -1;
  for(int4 i=0;i<pathMeld.numOps();++i) {
    if (pathMeld.getOp(i)->isMark()) {
      res = i;
      break;
    }
  }
  for(iter=vn->beginDescend();iter!=enditer;++iter)
    (*iter)->clearMark();
  return res;
}

int4 JumpBasicOverride::trialNorm(Funcdata *fd,Varnode *trialvn,uint4 tolerance)

{ // Given a potential normalized switch variable, try to figure out the set of values that
  // produce the addresses in the -adset-.   Basically we start with value -startingvalue-
  // and increment from there, allowing for duplicates and misses.  Once we see all addresses
  // in -adset- we returning the index of the starting op, otherwise return -1
  int4 opi = findStartOp(trialvn);
  if (opi < 0) return -1;
  PcodeOp *startop = pathMeld.getOp(opi);

  if (!values.empty())		// Have we already worked out the values and addresses
    return opi;

  EmulateFunction emul(fd);
  //  if (loadpoints != (vector<LoadTable> *)0)
  //    emul.setLoadCollect(true);

  AddrSpace *spc = startop->getAddr().getSpace();
  uintb val = startingvalue;
  uintb addr;
  uint4 total = 0;
  uint4 miss = 0;
  set<Address> alreadyseen;
  while(total < adset.size()) {
    try {
      addr = emul.emulatePath(val,pathMeld,startop,trialvn);
    } catch(LowlevelError &err) { // Something went wrong with emulation
      addr = 0;
      miss = tolerance;		// Terminate early
    }
    addr = AddrSpace::addressToByte(addr,spc->getWordSize());
    Address newaddr(spc,addr);
    if (adset.find(newaddr) != adset.end()) {
      if (alreadyseen.insert(newaddr).second) // If this is the first time we've seen this address
	total += 1;		// Count it
      values.push_back(val);
      addrtable.push_back(newaddr);
      // We may be seeing the same (valid) address over and over, without seeing others in -adset-
      // Terminate if things get too large
      if (values.size() > adset.size() + 100) break;
      miss = 0;
    }
    else {
      miss += 1;
      if (miss >= tolerance) break;
    }
    val += 1;
  }
  
  //  if ((loadpoint != (vector<LoadTable> *)0)&&(total == adset.size()))
  //    emul.collectLoadPoints(*loadpoints);
  if (total == adset.size())
    return opi;
  values.clear();
  addrtable.clear();
  return -1;
}

void JumpBasicOverride::setupTrivial(void)

{ // Since we have an absolute set of addresses, if all else fails we can use the indirect variable
  // as the normalized switch and the addresses as the values, similar to the trivial model
  set<Address>::const_iterator iter;
  if (addrtable.empty()) {
    for(iter=adset.begin();iter!=adset.end();++iter) {
      const Address &addr( *iter );
      addrtable.push_back(addr);
    }
  }
  values.clear();
  for(int4 i=0;i<addrtable.size();++i)
    values.push_back( addrtable[i].getOffset() );
  varnodeIndex = 0;
  normalvn = pathMeld.getVarnode(0);
  istrivial = true;
}

Varnode *JumpBasicOverride::findLikelyNorm(void)

{ // If the normalized switch variable is explicitly provided, look for the norm varnode in the
  // most common jumptable constructions, otherwise return null
  Varnode *res = (Varnode *)0;
  PcodeOp *op;
  uint4 i;

  for(i=0;i<pathMeld.numOps();++i) { // Look for last LOAD
    op = pathMeld.getOp(i);
    if (op->code() == CPUI_LOAD) {
      res = pathMeld.getOpParent(i);
      break;
    }
  }
  if (res == (Varnode *)0) return res;
  i += 1;
  while(i<pathMeld.numOps()) { // Look for preceding ADD
    op = pathMeld.getOp(i);
    if (op->code() == CPUI_INT_ADD) {
      res = pathMeld.getOpParent(i);
      break;
    }
    ++i;
  }
  i += 1;
  while(i<pathMeld.numOps()) { // Look for preceding MULT
    op = pathMeld.getOp(i);
    if (op->code() == CPUI_INT_MULT) {
      res = pathMeld.getOpParent(i);
      break;
    }
    ++i;
  }
  return res;
}

void JumpBasicOverride::clearCopySpecific(void)

{ // Clear varnodes and ops that are specific to one instance of a Funcdata
  selectguards.clear();
  pathMeld.clear();
  normalvn = (Varnode *)0;
  switchvn = (Varnode *)0;
}

bool JumpBasicOverride::recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)

{
  clearCopySpecific();
  findDeterminingVarnodes(indop,0);
  if (!istrivial) {		// If we haven't previously decided to use trivial model
    Varnode *trialvn = (Varnode *)0;
    if (hash != 0) {
      DynamicHash dyn;
      trialvn = dyn.findVarnode(fd,normaddress,hash);
    }
    // If there was never a specified norm, or the specified norm was never recovered
    if ((trialvn == (Varnode *)0)&&(values.empty()||(hash==0)))
      trialvn = findLikelyNorm();
    
    if (trialvn != (Varnode *)0) {
      int4 opi = trialNorm(fd,trialvn,10);
      if (opi >= 0) {
	varnodeIndex = opi;
	normalvn = trialvn;
	return true;
      }
    }
  }
  setupTrivial();
  return true;
}

void JumpBasicOverride::buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const

{
  addresstable = addrtable;	// Addresses are already calculated, just copy them out
}

void JumpBasicOverride::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{
  uintb addr;

  for(uint4 i=0;i<values.size();++i) {
    try {
      addr = backup2Switch(fd,values[i],normalvn,switchvn);
    } catch(EvaluationError &err) {
      addr = 0xBAD1ABE1;
    }
    label.push_back(addr);
    if (label.size() >= addresstable.size()) break; // This should never happen
  }

  while(label.size() < addresstable.size()) {
    fd->warning("Bad switch case",addresstable[label.size()]); // This should never happen
    label.push_back(0xBAD1ABE1);
  }
}

JumpModel *JumpBasicOverride::clone(JumpTable *jt) const

{ // We only need to clone the values and addresses
  JumpBasicOverride *res = new JumpBasicOverride(jt);
  res->adset = adset;
  res->values = values;
  res->addrtable = addrtable;
  res->startingvalue = startingvalue;
  res->normaddress = normaddress;
  res->hash = hash;
  return res;
}

void JumpBasicOverride::clear(void)

{
  // -adset- is a permanent feature, do no clear
  // -startingvalue- is permanent
  // -normaddress- is permanent
  // -hash- is permanent
  values.clear();
  addrtable.clear();
  istrivial = false;
}

void JumpBasicOverride::saveXml(ostream &s) const

{
  set<Address>::const_iterator iter;

  s << "<basicoverride>\n";
  for(iter=adset.begin();iter!=adset.end();++iter) {
    s << "  <dest";
    AddrSpace *spc = (*iter).getSpace();
    uintb off = (*iter).getOffset();
    spc->saveXmlAttributes(s,off);
    s << "/>\n";
  }
  if (hash != 0) {
    s << "  <normaddr";
    normaddress.getSpace()->saveXmlAttributes(s,normaddress.getOffset());
    s << "/>\n";
    s << "  <normhash>0x" << hex << hash << "</normhash>\n";
  }
  if (startingvalue != 0) {
    s << "  <startval>0x" << hex << startingvalue << "</startval>\n";
  }
  s << "</basicoverride>\n";
}

void JumpBasicOverride::restoreXml(const Element *el,Architecture *glb)

{
  const List &list( el->getChildren() );
  List::const_iterator iter = list.begin();
  while(iter != list.end()) {
    const Element *subel = *iter;
    ++iter;
    if (subel->getName() == "dest") {
      adset.insert( Address::restoreXml(subel,glb) );
    }
    else if (subel->getName() == "normaddr")
      normaddress = Address::restoreXml(subel,glb);
    else if (subel->getName() == "normhash") {
      istringstream s1(subel->getContent());	
      s1.unsetf(ios::dec | ios::hex | ios::oct);
      s1 >> hash;
    }
    else if (subel->getName() == "startval") {
      istringstream s2(subel->getContent());	
      s2.unsetf(ios::dec | ios::hex | ios::oct);
      s2 >> startingvalue;
    }
  }
  if (adset.empty())
    throw LowlevelError("Empty jumptable override");
}

bool JumpAssisted::recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)

{ // Try to recover a jumptable using the assisted model model
  // Look for the special "jumpassist" pseudo-op
  Varnode *addrVn = indop->getIn(0);
  if (!addrVn->isWritten()) return false;
  assistOp = addrVn->getDef();
  if (assistOp == (PcodeOp *)0) return false;
  if (assistOp->code() != CPUI_CALLOTHER) return false;
  if (assistOp->numInput() < 3) return false;
  int4 index = assistOp->getIn(0)->getOffset();
  userop = dynamic_cast<JumpAssistOp *>(fd->getArch()->userops.getOp(index));
  if (userop == (JumpAssistOp *)0) return false;

  switchvn = assistOp->getIn(1);		// The switch variable
  for(int4 i=2;i<assistOp->numInput();++i)
    if (!assistOp->getIn(i)->isConstant())
      return false;				// All remaining params must be constant
  if (userop->getCalcSize() == -1)		// If no size script, first param after switch var is size
    sizeIndices = assistOp->getIn(2)->getOffset();
  else {
    ExecutablePcode *pcodeScript = (ExecutablePcode *)fd->getArch()->pcodeinjectlib->getPayload(userop->getCalcSize());
    vector<uintb> inputs;
    int4 numInputs = assistOp->numInput() - 1;	// How many remaining varnodes after useropid
    if (pcodeScript->sizeInput() != numInputs)
      throw LowlevelError(userop->getName() + ": <size_pcode> has wrong number of parameters");
    for(int4 i=0;i<numInputs;++i)
      inputs.push_back(assistOp->getIn(i+1)->getOffset());
    sizeIndices = pcodeScript->evaluate(inputs);
  }
  if (matchsize !=0 && matchsize-1 != sizeIndices)	// matchsize has 1 added to it for the default case
    return false;			// Not matching the size we saw previously
  if (sizeIndices > maxtablesize)
    return false;

  return true;
}

void JumpAssisted::buildAddresses(Funcdata *fd,PcodeOp *indop,vector<Address> &addresstable,vector<LoadTable> *loadpoints) const

{
  if (userop->getIndex2Addr() == -1)
    throw LowlevelError("Final index2addr calculation outside of jumpassist");
  ExecutablePcode *pcodeScript = (ExecutablePcode *)fd->getArch()->pcodeinjectlib->getPayload(userop->getIndex2Addr());
  addresstable.clear();

  AddrSpace *spc = indop->getAddr().getSpace();
  vector<uintb> inputs;
  int4 numInputs = assistOp->numInput() - 1;	// How many remaining varnodes after useropid
  if (pcodeScript->sizeInput() != numInputs)
    throw LowlevelError(userop->getName() + ": <addr_pcode> has wrong number of parameters");
  for(int4 i=0;i<numInputs;++i)
    inputs.push_back(assistOp->getIn(i+1)->getOffset());

  for(int4 index=0;index<sizeIndices;++index) {
    inputs[0] = index;
    uintb output = pcodeScript->evaluate(inputs);
    addresstable.push_back(Address(spc,output));
  }
  ExecutablePcode *defaultScript = (ExecutablePcode *)fd->getArch()->pcodeinjectlib->getPayload(userop->getDefaultAddr());
  if (defaultScript->sizeInput() != numInputs)
    throw LowlevelError(userop->getName() + ": <default_pcode> has wrong number of parameters");
  inputs[0] = 0;
  uintb defaultAddress = defaultScript->evaluate(inputs);
  addresstable.push_back(Address(spc,defaultAddress));		// Add default location to end of addresstable
}

void JumpAssisted::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{
  if ((( const JumpAssisted *)orig)->sizeIndices != sizeIndices)
    throw LowlevelError("JumpAssisted table size changed during recovery");
  if (userop->getIndex2Case() == -1) {
    for(int4 i=0;i<sizeIndices;++i)
      label.push_back(i);		// The index is the label
  }
  else {
    ExecutablePcode *pcodeScript = (ExecutablePcode *)fd->getArch()->pcodeinjectlib->getPayload(userop->getIndex2Case());
    vector<uintb> inputs;
    int4 numInputs = assistOp->numInput() - 1;	// How many remaining varnodes after useropid
    if (numInputs != pcodeScript->sizeInput())
      throw LowlevelError(userop->getName() + ": <case_pcode> has wrong number of parameters");
    for(int4 i=0;i<numInputs;++i)
      inputs.push_back(assistOp->getIn(i+1)->getOffset());

    for(int4 index=0;index<sizeIndices;++index) {
      inputs[0] = index;
      uintb output = pcodeScript->evaluate(inputs);
      label.push_back(output);
    }
  }
  label.push_back(0xBAD1ABE1);		// Add fake label to match the defaultAddress
}

void JumpAssisted::foldInNormalization(Funcdata *fd,PcodeOp *indop)

{
  // Replace all outputs of jumpassist op with switchvn (including BRANCHIND)
  Varnode *outvn = assistOp->getOut();
  list<PcodeOp *>::const_iterator iter = outvn->beginDescend();
  while(iter != outvn->endDescend()) {
    PcodeOp *op = *iter;
    ++iter;
    fd->opSetInput(op,switchvn,0);
  }
  fd->opDestroy(assistOp);		// Get rid of the assist op (it has served its purpose)
}

bool JumpAssisted::foldInGuards(Funcdata *fd,JumpTable *jump)

{
  int4 origVal = jump->getMostCommon();
  jump->setMostCommonIndex(jump->numEntries()-1);	// Default case is always the last block
  return (origVal != jump->getMostCommon());
}

JumpModel *JumpAssisted::clone(JumpTable *jt) const

{
  JumpAssisted *clone = new JumpAssisted(jt);
  clone->userop = userop;
  clone->sizeIndices = sizeIndices;
  return clone;
}

void JumpTable::recoverModel(Funcdata *fd)

{ // Try to recover each model in turn, until we find one that matches
  if (jmodel != (JumpModel *)0) {
    if (jmodel->isOverride()) {	// If preexisting model is override
      jmodel->recoverModel(fd,indirect,0,maxtablesize);
      return;
    }
    delete jmodel;		// Otherwise this is an old attempt we should remove
  }
  Varnode *vn = indirect->getIn(0);
  if (vn->isWritten()) {
    PcodeOp *op = vn->getDef();
    if (op->code() == CPUI_CALLOTHER) {
      JumpAssisted *jassisted = new JumpAssisted(this);
      jmodel = jassisted;
      if (jmodel->recoverModel(fd,indirect,addresstable.size(),maxtablesize))
	return;
    }
  }
  JumpBasic *jbasic = new JumpBasic(this);
  jmodel = jbasic;
  if (jmodel->recoverModel(fd,indirect,addresstable.size(),maxtablesize))
    return;
  jmodel = new JumpBasic2(this);
  ((JumpBasic2 *)jmodel)->initializeStart(jbasic->getPathMeld());
  delete jbasic;
  if (jmodel->recoverModel(fd,indirect,addresstable.size(),maxtablesize))
    return;
  delete jmodel;
  jmodel = (JumpModel *)0;
}

void JumpTable::sanityCheck(Funcdata *fd)

{
  uint4 sz = addresstable.size();

  if (!isReachable(indirect))
    throw JumptableNotReachableError("No legal flow");
  if (addresstable.size() == 1) { // One entry is likely some kind of thunk
    bool isthunk = false;
    uintb diff;
    Address addr = addresstable[0];
    if (addr.getOffset()==0) 
      isthunk = true;
    else {
      Address addr2 = indirect->getAddr();
      diff = (addr.getOffset() < addr2.getOffset()) ?
	(addr2.getOffset() - addr.getOffset()) :
	(addr.getOffset() - addr2.getOffset());
      if (diff > 0xffff)
	isthunk = true;
    }
    if (isthunk) {
      throw JumptableThunkError("Likely thunk");
    }
  }
  if (!jmodel->sanityCheck(fd,indirect,addresstable)) {
    ostringstream err;
    err << "Jumptable at " << opaddress << " did not pass sanity check.";
    throw LowlevelError(err.str());
  }
  if (sz!=addresstable.size()) // If address table was resized
    fd->warning("Sanity check requires truncation of jumptable",opaddress);
}

uint4 JumpTable::block2Position(const FlowBlock *bl) const

{
  FlowBlock *parent;
  uint4 position;

  if (!isSwitchedOver())
    throw LowlevelError("Jumptable switchover has not happened yet");
  
  parent = indirect->getParent();
  for(position=0;position<parent->sizeOut();++position)
    if (parent->getOut(position) == bl) break;
  if (position==parent->sizeOut())
    throw LowlevelError("Requested block, not in jumptable");
  return position;
}

bool JumpTable::isReachable(PcodeOp *op)

{ // Check if -op- seems reachable in current flow
  // We are not doing a complete check, we are looking for a guard that has collapsed to "if (false)"
  BlockBasic *parent = op->getParent();

  for(int4 i=0;i<2;++i) {	// Only check two levels
    if (parent->sizeIn() != 1) return true;
    BlockBasic *bl = (BlockBasic *)parent->getIn(0);
    if (bl->sizeOut() != 2) continue; // Check if -bl- looks like it contains a guard
    PcodeOp *cbranch = bl->lastOp();
    if ((cbranch==(PcodeOp *)0)||(cbranch->code() != CPUI_CBRANCH))
      continue;
    Varnode *vn = cbranch->getIn(1); // Get the boolean variable
    if (!vn->isConstant()) continue; // Has the guard collapsed
    int4 trueslot = cbranch->isBooleanFlip() ? 0: 1;
    if (vn->getOffset() == 0)
      trueslot = 1 - trueslot;
    if (bl->getOut(trueslot) != parent)	// If the remaining path does not lead to -op-
      return false;		// return that op is not reachable
    parent = bl;
  }
  return true;
}

JumpTable::JumpTable(Architecture *g,Address ad)
  : opaddress(ad)
{
  glb = g;
  jmodel = (JumpModel *)0;
  origmodel = (JumpModel *)0;
  indirect = (PcodeOp *)0;
  mostcommon = ~((uint4)0);
  maxtablesize = 1024;
  maxaddsub = 1;
  maxleftright = 1;
  maxext = 1;
  recoverystage = 0;
  collectloads = false;
}

JumpTable::JumpTable(const JumpTable *op2)

{				// Partial clone of the jumptable
  glb = op2->glb;
  jmodel = (JumpModel *)0;
  origmodel = (JumpModel *)0;
  indirect = (PcodeOp *)0;
  mostcommon = ~((uint4)0);
  maxtablesize = op2->maxtablesize;
  maxaddsub = op2->maxaddsub;
  maxleftright = op2->maxleftright;
  maxext = op2->maxext;
  recoverystage = op2->recoverystage;
  collectloads = op2->collectloads;
				// We just clone the addresses themselves
  addresstable = op2->addresstable;
  loadpoints = op2->loadpoints;
  opaddress = op2->opaddress;
  if (op2->jmodel != (JumpModel *)0)
    jmodel = op2->jmodel->clone(this);
}

JumpTable::~JumpTable(void)

{
  if (jmodel != (JumpModel *)0)
    delete jmodel;
  if (origmodel != (JumpModel *)0)
    delete origmodel;
}

int4 JumpTable::numIndicesByBlock(const FlowBlock *bl) const

{				// Number of jumptable entries for this block
  uint4 position,count;
  int4 i;

  position = block2Position(bl);
  count = 0;
  for(i=0;i<blocktable.size();++i)
    if (blocktable[i] == position)
      count += 1;
  return count;
}

bool JumpTable::isOverride(void) const

{
  if (jmodel == (JumpModel *)0)
    return false;
  return jmodel->isOverride();
}

void JumpTable::setOverride(const vector<Address> &addrtable,const Address &naddr,uintb h,uintb sv)

{ // Force an override on a jumptable
  if (jmodel != (JumpModel *)0)
    delete jmodel;

  JumpBasicOverride *override;
  jmodel = override = new JumpBasicOverride(this);
  override->setAddresses(addrtable);
  override->setNorm(naddr,h);
  override->setStartingValue(sv);
}

int4 JumpTable::getIndexByBlock(const FlowBlock *bl,int4 i) const

{
  uint4 position,count;
  int4 j;

  position = block2Position(bl);
  count = 0;
  for(j=0;j<blocktable.size();++j) {
    if (blocktable[j] == position) {
      if (i==count) return j;
      count += 1;
    }
  }
  throw LowlevelError("Could not get jumptable index for block");
}

void JumpTable::setMostCommonIndex(uint4 tableind)

{  // Set the most common address jump destination by supplying the (an) index for its address
  mostcommon = blocktable[tableind]; // Translate addresstable index to switch block out index
}

void JumpTable::addBlockToSwitch(BlockBasic *bl,uintb lab)

{  // Force a block to be possible switch destination
  addresstable.push_back(bl->getStart());
  uint4 pos = indirect->getParent()->sizeOut();
  blocktable.push_back(pos);
  label.push_back(lab);
}

void JumpTable::switchOver(const FlowInfo &flow)

{				// Convert absolute addresses to block indices
  FlowBlock *parent,*tmpbl;
  uint4 pos;
  int4 i,j,count,maxcount;
  PcodeOp *op;

  blocktable.clear();
  blocktable.resize(addresstable.size(),~((uint4)0));
  mostcommon = ~((uint4)0);	// There is no "mostcommon"
  maxcount = 1;			// If the maxcount is less than 2
  parent = indirect->getParent();

  for(i=0;i<addresstable.size();++i) {
    Address addr = addresstable[i];
    if (blocktable[i] != ~((uint4)0)) continue;
    op = flow.target(addr);
    tmpbl = op->getParent();
    for(pos=0;pos<parent->sizeOut();++pos)
      if (parent->getOut(pos) == tmpbl) break;
    if (pos==parent->sizeOut())
      throw LowlevelError("Jumptable destination not linked");
    count = 0;
    for(j=i;j<addresstable.size();++j) {
      if (addr == addresstable[j]) {
	count += 1;
	blocktable[j] = pos;
      }
    }
    if (count>maxcount) {
      maxcount = count;
      mostcommon = pos;
    }
  }
}

void JumpTable::trivialSwitchOver(void)

{
  FlowBlock *parent;

  blocktable.clear();
  blocktable.resize(addresstable.size(),~((uint4)0));
  parent = indirect->getParent();

  if (parent->sizeOut() != addresstable.size())
    throw LowlevelError("Trivial addresstable and switch block size do not match");
  for(uint4 i=0;i<parent->sizeOut();++i)
    blocktable[i] = i;		// blocktable corresponds exactly to outlist of switch block
  mostcommon = ~((uint4)0);	// There is no "mostcommon"
}

void JumpTable::recoverAddresses(Funcdata *fd)

{				// Assuming we only have a partial function
				// recover just the jumptable addresses
  recoverModel(fd);
  if (jmodel == (JumpModel *)0) {
    ostringstream err;
    err << "Could not recover jumptable at " << opaddress << ". Too many branches";
    throw LowlevelError(err.str());
  }
  if (jmodel->getTableSize() == 0) {
    ostringstream err;
    err << "Impossible to reach jumptable at " << opaddress;
    throw JumptableNotReachableError(err.str());
  }
  //  if (sz < 2)
  //    fd->warning("Jumptable has only one branch",opaddress);
  if (collectloads)
    jmodel->buildAddresses(fd,indirect,addresstable,&loadpoints);
  else
    jmodel->buildAddresses(fd,indirect,addresstable,(vector<LoadTable> *)0);
  sanityCheck(fd);
}

void JumpTable::recoverMultistage(Funcdata *fd)

{ // Do a normal recoverAddresses, but save off old model, and if we fail recovery, put back the old model
  if (origmodel != (JumpModel *)0)
    delete origmodel;
  origmodel = jmodel;
  jmodel = (JumpModel *)0;
  
  vector<Address> oldaddresstable = addresstable;
  addresstable.clear();
  loadpoints.clear();
  try {
    recoverAddresses(fd);
  }
  catch(JumptableThunkError &err) {
    if (jmodel != (JumpModel *)0)
      delete jmodel;
    jmodel = origmodel;
    origmodel = (JumpModel *)0;
    addresstable = oldaddresstable;
    fd->warning("Second-stage recovery error",indirect->getAddr());
  }
  catch(LowlevelError &err) {
    if (jmodel != (JumpModel *)0)
      delete jmodel;
    jmodel = origmodel;
    origmodel = (JumpModel *)0;
    addresstable = oldaddresstable;
    fd->warning("Second-stage recovery error",indirect->getAddr());
  }
  recoverystage = 2;
  if (origmodel != (JumpModel *)0) { // Keep the new model if it was created successfully
    delete origmodel;
    origmodel = (JumpModel *)0;
  }
}

bool JumpTable::recoverLabels(Funcdata *fd)

{ // Assuming we have entire function, recover labels.  Return -true- if it looks like a multistage restart is needed.
  if (!isRecovered())
    throw LowlevelError("Trying to recover jumptable labels without addresses");

  // Unless the model is an override, move model (created on a flow copy) so we can create a current instance
  if (jmodel != (JumpModel *)0) {
    if (origmodel != (JumpModel *)0)
      delete origmodel;
    if (!jmodel->isOverride()) {
      origmodel = jmodel;
      jmodel = (JumpModel *)0;
    }
    else
      fd->warning("Switch is manually overridden",opaddress);
  }

  bool multistagerestart = false;
  recoverModel(fd);		// Create a current instance of the model
  if (jmodel != (JumpModel *)0) {
    if (jmodel->getTableSize() != addresstable.size()) {
      fd->warning("Could not find normalized switch variable to match jumptable",opaddress);
      if ((addresstable.size()==1)&&(jmodel->getTableSize() > 1))
	multistagerestart = true;
    }
    if ((origmodel == (JumpModel *)0)||(origmodel->getTableSize()==0)) {
      jmodel->findUnnormalized(maxaddsub,maxleftright,maxext);
      jmodel->buildLabels(fd,addresstable,label,jmodel);
    }
    else {
      jmodel->findUnnormalized(maxaddsub,maxleftright,maxext);
      jmodel->buildLabels(fd,addresstable,label,origmodel);
    }
  }
  else {
    jmodel = new JumpModelTrivial(this);
    jmodel->recoverModel(fd,indirect,addresstable.size(),maxtablesize);
    jmodel->buildAddresses(fd,indirect,addresstable,(vector<LoadTable> *)0);
    trivialSwitchOver();
    jmodel->buildLabels(fd,addresstable,label,origmodel);
  }
  if (origmodel != (JumpModel *)0) {
    delete origmodel;
    origmodel = (JumpModel *)0;
  }
  return multistagerestart;
}

void JumpTable::clear(void)

{ // Right now this is only getting called, when the jumptable is an override in order to clear out derived data
  if (origmodel != (JumpModel *)0) {
    delete origmodel;
    origmodel = (JumpModel *)0;
  }
  if (jmodel->isOverride())
    jmodel->clear();
  else {
    delete jmodel;
    jmodel = (JumpModel *)0;
  }
  blocktable.clear();
  label.clear();
  loadpoints.clear();
  indirect = (PcodeOp *)0;
  recoverystage = 0;
  // -opaddress- -maxtablesize- -maxaddsub- -maxleftright- -maxext- -collectloads- are permanent
}

void JumpTable::saveXml(ostream &s) const

{				// Save addresses in a jump table in XML format
  if (!isRecovered())
    throw LowlevelError("Trying to save unrecovered jumptable");

  s << "<jumptable>\n";
  opaddress.saveXml(s);
  s << '\n';
  for(int4 i=0;i<addresstable.size();++i) {
    s << "<dest";
    AddrSpace *spc = addresstable[i].getSpace();
    uintb off = addresstable[i].getOffset();
    if (spc != (AddrSpace *)0)
      spc->saveXmlAttributes(s,off);
    if (i<label.size()) {
      if (label[i] != 0xBAD1ABE1)
	a_v_u(s,"label",label[i]);
    }
    s << "/>\n";
  }
  if (!loadpoints.empty()) {
    for(int4 i=0;i<loadpoints.size();++i)
      loadpoints[i].saveXml(s);
  }
  if ((jmodel != (JumpModel *)0)&&(jmodel->isOverride()))
    jmodel->saveXml(s);
  s << "</jumptable>\n";
}

void JumpTable::restoreXml(const Element *el)

{
  const List &list( el->getChildren() );
  List::const_iterator iter = list.begin();
  opaddress = Address::restoreXml( *iter, glb);
  bool missedlabel = false;
  ++iter;
  while(iter != list.end()) {
    const Element *subel = *iter;
    if (subel->getName() == "dest") {
      addresstable.push_back( Address::restoreXml( subel, glb) );
      int4 maxnum = subel->getNumAttributes();
      int4 i;
      for(i=0;i<maxnum;++i) {
	if (subel->getAttributeName(i) == "label") break;
      }
      if (i<maxnum) {		// Found a label attribute
	if (missedlabel)
	  throw LowlevelError("Jumptable entries are missing labels");
	istringstream s1(subel->getAttributeValue(i));	
	s1.unsetf(ios::dec | ios::hex | ios::oct);
	uintb lab;
	s1 >> lab;
	label.push_back(lab);
      }
      else			// No label attribute
	missedlabel = true;	// No following entries are allowed to have a label attribute
    }
    else if (subel->getName() == "loadtable") {
      loadpoints.push_back(LoadTable());
      loadpoints.back().restoreXml(subel,glb);
    }
    else if (subel->getName() == "basicoverride") {
      if (jmodel != (JumpModel *)0)
	throw LowlevelError("Duplicate jumptable override specs");
      jmodel = new JumpBasicOverride(this);
      jmodel->restoreXml(subel,glb);
    }
    ++iter;
  }

  if (label.size()!=0) {
    while(label.size() < addresstable.size())
      label.push_back(0xBAD1ABE1);
  }
}

bool JumpTable::checkForMultistage(Funcdata *fd)

{ // Look for a change in control that indicates we need an additional of jump recovery
  if (addresstable.size()!=1) return false;
  if (recoverystage != 0) return false;
  if (indirect == (PcodeOp *)0) return false;

  if (fd->getOverride().queryMultistageJumptable(indirect->getAddr())) {
    recoverystage = 1;		// Mark that we need additional recovery
    return true;
  }
  return false;
}

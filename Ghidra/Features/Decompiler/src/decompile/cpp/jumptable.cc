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

/// \param s is the XML stream to write to
void LoadTable::saveXml(ostream &s) const

{
  s << "<loadtable";
  a_v_i(s,"size",size);
  a_v_i(s,"num",num);
  s << ">\n  ";
  addr.saveXml(s);
  s << "</loadtable>\n";
}

/// \param el is the root \<loadtable> tag
/// \param glb is the architecture for resolving address space tags
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

/// We assume the list of LoadTable entries is sorted and perform an in-place
/// collapse of any sequences into a single LoadTable entry.
/// \param table is the list of entries to collapse
void LoadTable::collapseTable(vector<LoadTable> &table)

{
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

/// \param f is the function to emulate within
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

/// \brief Execute from a given starting point and value to the common end-point of the path set
///
/// Flow the given value through all paths in the path container to produce the
/// single output value.
/// \param val is the starting value
/// \param pathMeld is the set of paths to execute
/// \param startop is the starting PcodeOp within the path set
/// \param startvn is the Varnode holding the starting value
/// \return the calculated value at the common end-point
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

/// Pass back any LOAD records collected during emulation.  The individual records
/// are sorted and collapsed into concise \e table descriptions.
/// \param res will hold any resulting table descriptions
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

/// \param vn is the Varnode we are testing for pruning
/// \return \b true if the search should be pruned here
bool JumpBasic::isprune(Varnode *vn)

{
  if (!vn->isWritten()) return true;
  PcodeOp *op = vn->getDef();
  if (op->isCall()||op->isMarker()) return true;
  if (op->numInput()==0) return true;
  return false;
}

/// \param vn is the given Varnode to test
/// \return \b false if it is impossible for the Varnode to be the switch variable
bool JumpBasic::ispoint(Varnode *vn)

{
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

/// \brief Back up the constant value in the output Varnode to the value in the input Varnode
///
/// This does the work of going from a normalized switch value to the unnormalized value.
/// PcodeOps between the output and input Varnodes must be reversible or an exception is thrown.
/// \param fd is the function containing the switch
/// \param output is the constant value to back up
/// \param outvn is the output Varnode of the data-flow
/// \param invn is the input Varnode to back up to
/// \return the recovered value associated with the input Varnode
uintb JumpBasic::backup2Switch(Funcdata *fd,uintb output,Varnode *outvn,Varnode *invn)

{
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

/// \brief Calculate the initial set of Varnodes that might be switch variables
///
/// Paths that terminate at the given PcodeOp are calculated and organized
/// in a PathMeld object that determines Varnodes that are common to all the paths.
/// \param op is the given PcodeOp
/// \param slot is input slot to the PcodeOp all paths must terminate at
void JumpBasic::findDeterminingVarnodes(PcodeOp *op,int4 slot)

{
  vector<PcodeOpNode> path;
  bool firstpoint = false;	// Have not seen likely switch variable yet

  path.push_back(PcodeOpNode(op,slot));

  do {	// Traverse through tree of inputs to final address
    PcodeOpNode &node(path.back());
    Varnode *curvn = node.op->getIn(node.slot);
    if (isprune(curvn)) {	// Here is a node of the tree
      if (ispoint(curvn)) {	// Is it a possible switch variable
	if (!firstpoint) {	// If it is the first possible
	  pathMeld.set(path);	// Take the current path as the result
	  firstpoint = true;
	}
	else			// If we have already seen at least one possible
	  pathMeld.meld(path);
      }

      path.back().slot += 1;
      while(path.back().slot >= path.back().op->numInput()) {
	path.pop_back();
	if (path.empty()) break;
	path.back().slot += 1;
      }
    }
    else {			// This varnode is not pruned
      path.push_back(PcodeOpNode(curvn->getDef(),0));
    }
  } while(path.size() > 1);
  if (pathMeld.empty()) {	// Never found a likely point, which means that
				// it looks like the address is uniquely determined
				// but the constants/readonlys haven't been collapsed
    pathMeld.set(op,op->getIn(slot));
  }
}

/// \brief Check if the two given Varnodes are matching constants
///
/// \param vn1 is the first given Varnode
/// \param vn2 is the second given Varnode
/// \return \b true if the Varnodes are both constants with the same value
static bool matching_constants(Varnode *vn1,Varnode *vn2)

{
  if (!vn1->isConstant()) return false;
  if (!vn2->isConstant()) return false;
  if (vn1->getOffset() != vn2->getOffset()) return false;
  return true;
}

/// \param bOp is the CBRANCH \e guarding the switch
/// \param rOp is the PcodeOp immediately reading the Varnode
/// \param path is the specific branch to take from the CBRANCH to reach the switch
/// \param rng is the range of values causing the switch path to be taken
/// \param v is the Varnode holding the value controlling the CBRANCH
GuardRecord::GuardRecord(PcodeOp *bOp,PcodeOp *rOp,int4 path,const CircleRange &rng,Varnode *v)

{
  cbranch = bOp;
  readOp = rOp;
  indpath = path;
  range = rng;
  vn = v;
  baseVn = quasiCopy(v,bitsPreserved);		// Look for varnode whose bits are copied
}

/// \brief Determine if \b this guard applies to the given Varnode
///
/// The guard applies if we know the given Varnode holds the same value as the Varnode
/// attached to the guard. So we return:
///   - 0, if the two Varnodes do not clearly hold the same value.
///   - 1, if the two Varnodes clearly hold the same value.
///   - 2, if the two Varnode clearly hold the same value, pending no writes between their defining op.
///
/// \param vn2 is the given Varnode being tested against \b this guard
/// \param baseVn2 is the earliest Varnode from which the given Varnode is quasi-copied.
/// \param bitsPreserved2 is the number of potentially non-zero bits in the given Varnode
/// \return the matching code 0, 1, or 2
int4 GuardRecord::valueMatch(Varnode *vn2,Varnode *baseVn2,int4 bitsPreserved2) const

{
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

/// \brief Return 1 if the two given PcodeOps produce exactly the same value, 0 if otherwise
///
/// We up through only one level of PcodeOp calculation and only for certain binary ops
/// where the second parameter is a constant.
/// \param op1 is the first given PcodeOp to test
/// \param op2 is the second given PcodeOp
/// \return 1 if the same value is produced, 0 otherwise
int4 GuardRecord::oneOffMatch(PcodeOp *op1,PcodeOp *op2)

{
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

/// \brief Compute the source of a quasi-COPY chain for the given Varnode
///
/// A value is a \b quasi-copy if a sequence of PcodeOps producing it always hold
/// the value as the least significant bits of their output Varnode, but the sequence
/// may put other non-zero values in the upper bits.
/// This method computes the earliest ancestor Varnode for which the given Varnode
/// can be viewed as a quasi-copy.
/// \param vn is the given Varnode
/// \param bitsPreserved will hold the number of least significant bits preserved by the sequence
/// \return the earliest source of the quasi-copy, which may just be the given Varnode
Varnode *GuardRecord::quasiCopy(Varnode *vn,int4 &bitsPreserved)

{
  bitsPreserved = mostsigbit_set(vn->getNZMask()) + 1;
  if (bitsPreserved == 0) return vn;
  uintb mask = 1;
  mask <<= bitsPreserved;
  mask -= 1;
  PcodeOp *op = vn->getDef();
  Varnode *constVn;
  while(op != (PcodeOp *)0) {
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

/// \brief Calculate intersection of a new Varnode path with the old path
///
/// The new path of Varnodes must all be \e marked. The old path, commonVn,
/// is replaced with the intersection.  A map is created from the index of each
/// Varnode in the old path with its index in the new path.  If the Varnode is
/// not in the intersection, its index is mapped to -1.
/// \param parentMap will hold the new index map
void PathMeld::internalIntersect(vector<int4> &parentMap)

{
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

/// \brief Meld in PcodeOps from a new path into \b this container
///
/// Execution order of the PcodeOps in the container is maintained.  Each PcodeOp, old or new,
/// has its split point from the common path recalculated.
/// PcodeOps that split (use a vn not in intersection) and do not rejoin
/// (have a predecessor Varnode in the intersection) get removed.
/// If splitting PcodeOps can't be ordered with the existing meld, we get a new cut point.
/// \param path is the new path of PcodeOps in sequence
/// \param cutOff is the number of PcodeOps with an input in the common path
/// \param parentMap is the map from old common Varnodes to the new common Varnodes
/// \return the index of the last (earliest) Varnode in the common path or -1
int4 PathMeld::meldOps(const vector<PcodeOpNode> &path,int4 cutOff,const vector<int4> &parentMap)

{
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
    PcodeOp *op = path[i].op;			// Current op in the new path
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

/// \brief Truncate all paths at the given new Varnode
///
/// The given Varnode is provided as an index into the current common Varnode list.
/// All Varnodes and PcodeOps involved in execution before this new cut point are removed.
/// \param cutPoint is the given new Varnode
void PathMeld::truncatePaths(int4 cutPoint)

{
  while(opMeld.size() > 1) {
    if (opMeld.back().rootVn < cutPoint)	// If we see op using varnode earlier than cut point
      break;					// Keep that and all subsequent ops
    opMeld.pop_back();				// Otherwise cut the op
  }
  commonVn.resize(cutPoint);			// Since intersection is ordered, just resize to cutPoint
}

/// \param op2 is the path container to copy from
void PathMeld::set(const PathMeld &op2)

{
  commonVn = op2.commonVn;
  opMeld = op2.opMeld;
}

/// This container is initialized to hold a single data-flow path.
/// \param path is the list of PcodeOpNode edges in the path (in reverse execution order)
void PathMeld::set(const vector<PcodeOpNode> &path)

{
  for(int4 i=0;i<path.size();++i) {
    const PcodeOpNode &node(path[i]);
    Varnode *vn = node.op->getIn(node.slot);
    opMeld.push_back(RootedOp(node.op,i));
    commonVn.push_back(vn);
  }
}

/// \param op is the one PcodeOp in the path
/// \param vn is the one Varnode (input to the PcodeOp) in the path
void PathMeld::set(PcodeOp *op,Varnode *vn)

{
  commonVn.push_back(vn);
  opMeld.push_back(RootedOp(op,0));
}

/// The new paths must all start at the common end-point of the paths in
/// \b this container.  The new set of melded paths start at the original common start
/// point for \b this container, flow through this old common end-point, and end at
/// the new common end-point.
/// \param op2 is the set of paths to be appended
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

/// Add the new path, recalculating the set of Varnodes common to all paths.
/// Paths are trimmed to ensure that any path that splits from the common intersection
/// must eventually rejoin.
/// \param path is the new path of PcodeOpNode edges to meld, in reverse execution order
void PathMeld::meld(vector<PcodeOpNode> &path)

{
  vector<int4> parentMap;

  for(int4 i=0;i<path.size();++i) {
    PcodeOpNode &node(path[i]);
    node.op->getIn(node.slot)->setMark();	// Mark varnodes in the new path, so its easy to see intersection
  }
  internalIntersect(parentMap);	// Calculate varnode intersection, and map from old intersection -> new
  int4 cutOff = -1;

  // Calculate where the cutoff point is in the new path
  for(int4 i=0;i<path.size();++i) {
    PcodeOpNode &node(path[i]);
    Varnode *vn = node.op->getIn(node.slot);
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
}

/// The starting Varnode, common to all paths, is provided as an index.
/// All PcodeOps up to the final BRANCHIND are (un)marked.
/// \param val is \b true for marking, \b false for unmarking
/// \param startVarnode is the index of the starting PcodeOp
void PathMeld::markPaths(bool val,int4 startVarnode)

{
  int4 startOp;
  for(startOp=opMeld.size()-1;startOp>=0;--startOp) {
    if (opMeld[startOp].rootVn == startVarnode)
      break;
  }
  if (startOp < 0) return;
  if (val) {
    for(int4 i=0;i<=startOp;++i)
      opMeld[i].op->setMark();
  }
  else {
    for(int4 i=0;i<=startOp;++i)
      opMeld[i].op->clearMark();
  }
}

/// The Varnode is specified by an index into sequence of Varnodes common to all paths in \b this PathMeld.
/// We find the earliest (as in executed first) PcodeOp, within \b this PathMeld that uses the Varnode as input.
/// \param pos is the index of the Varnode
/// \return the earliest PcodeOp using the Varnode
PcodeOp *PathMeld::getEarliestOp(int4 pos) const

{
  for(int4 i=opMeld.size()-1;i>=0;--i) {
    if (opMeld[i].rootVn == pos)
      return opMeld[i].op;
  }
  return (PcodeOp *)0;
}

/// \brief Analyze CBRANCHs leading up to the given basic-block as a potential switch \e guard.
///
/// In general there is only one path to the switch, and the given basic-block will
/// hold the BRANCHIND.  In some models, there is more than one path to the switch block,
/// and a path must be specified.  In this case, the given basic-block will be a block that
/// flows into the switch block, and the \e pathout parameter describes which path leads
/// to the switch block.
///
/// For each CBRANCH, range restrictions on the various variables which allow
/// control flow to pass through the CBRANCH to the switch are analyzed.
/// A GuardRecord is created for each of these restrictions.
/// \param bl is the given basic-block
/// \param pathout is an optional path from the basic-block to the switch or -1
void JumpBasic::analyzeGuards(BlockBasic *bl,int4 pathout)

{
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
    if (i != 0) {
      // Check that this CBRANCH isn't protecting some other switch
      BlockBasic *otherbl = (BlockBasic *)prevbl->getOut(1-indpath);
      PcodeOp *otherop = otherbl->lastOp();
      if (otherop != (PcodeOp *)0 && otherop->code() == CPUI_BRANCHIND) {
	if (otherop != jumptable->getIndirectOp())
	  break;
      }
    }
    bool toswitchval = (indpath == 1);
    if (cbranch->isBooleanFlip())
      toswitchval = !toswitchval;
    bl = prevbl;
    vn = cbranch->getIn(1);
    CircleRange rng(toswitchval);
    
    // The boolean variable could conceivably be the switch variable
    int4 indpathstore = prevbl->getFlipPath() ? 1-indpath : indpath;
    selectguards.push_back(GuardRecord(cbranch,cbranch,indpathstore,rng,vn));
    for(j=0;j<maxpullback;++j) {
      Varnode *markup;		// Throw away markup information
      if (!vn->isWritten()) break;
      PcodeOp *readOp = vn->getDef();
      vn = rng.pullBack(readOp,&markup,usenzmask);
      if (vn == (Varnode *)0) break;
      if (rng.isEmpty()) break;
      selectguards.push_back(GuardRecord(cbranch,readOp,indpathstore,rng,vn));
    }
  }
}

/// \brief Calculate the range of values in the given Varnode that direct control-flow to the switch
///
/// The Varnode is evaluated against each GuardRecord to determine if its range of values
/// can be restricted. Multiple guards may provide different restrictions.
/// \param vn is the given Varnode
/// \param rng will hold resulting range of values the Varnode can hold at the switch
void JumpBasic::calcRange(Varnode *vn,CircleRange &rng) const

{
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
  Varnode *baseVn = GuardRecord::quasiCopy(vn, bitsPreserved);
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

/// \brief Find the putative switch variable with the smallest range of values reaching the switch
///
/// The Varnode with the smallest range and closest to the BRANCHIND is assumed to be the normalized
/// switch variable. If an expected range size is provided, it is used to \e prefer a particular
/// Varnode as the switch variable.  Whatever Varnode is selected,
/// the JumpValue object is set up to iterator over its range.
/// \param matchsize optionally gives an expected size of the range, or it can be 0
void JumpBasic::findSmallestNormal(uint4 matchsize)

{
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

/// \brief Do all the work necessary to recover the normalized switch variable
///
/// The switch can be specified as the basic-block containing the BRANCHIND, or
/// as a block that flows to the BRANCHIND block by following the specified path out.
/// \param fd is the function containing the switch
/// \param rootbl is the basic-block
/// \param pathout is the (optional) path to the BRANCHIND or -1
/// \param matchsize is an (optional) size to expect for the normalized switch variable range
/// \param maxtablesize is the maximum size expected for the normalized switch variable range
void JumpBasic::findNormalized(Funcdata *fd,BlockBasic *rootbl,int4 pathout,uint4 matchsize,uint4 maxtablesize)

{
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

/// \brief Mark the guard CBRANCHs that are truly part of the model.
///
/// These CBRANCHs will be removed from the active control-flow graph, their
/// function \e folded into the action of the model, as represented by BRANCHIND.
void JumpBasic::markFoldableGuards(void)

{
  Varnode *vn = pathMeld.getVarnode(varnodeIndex);
  int4 bitsPreserved;
  Varnode *baseVn = GuardRecord::quasiCopy(vn, bitsPreserved);
  for(int4 i=0;i<selectguards.size();++i) {
    if (selectguards[i].valueMatch(vn,baseVn,bitsPreserved)==0) {
      selectguards[i].clear();		// Indicate this is not a true guard
    }
  }
}

/// \param val is \b true to set marks, \b false to clear marks
void JumpBasic::markModel(bool val)

{
  pathMeld.markPaths(val, varnodeIndex);
  for(int4 i=0;i<selectguards.size();++i) {
    PcodeOp *op = selectguards[i].getBranch();
    if (op == (PcodeOp *)0) continue;
    PcodeOp *readOp = selectguards[i].getReadOp();
    if (val)
      readOp->setMark();
    else
      readOp->clearMark();
  }
}

/// The PcodeOps in \b this model must have been previously marked with markModel().
/// Run through the descendants of the given Varnode and look for this mark.
/// \param vn is the given Varnode
/// \param trailOp is an optional known PcodeOp that leads to the model
/// \return \b true if the only flow is into \b this model
bool JumpBasic::flowsOnlyToModel(Varnode *vn,PcodeOp *trailOp)

{
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op == trailOp) continue;
    if (!op->isMark())
      return false;
  }
  return true;
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
  int4 pos;

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
      jump->setLastAsMostCommon();
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
    jump->setDefaultBlock(pos);	// A guard branch generally targets the default case
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

{
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

  uintb mask = ~((uintb)0);
  int4 bit = fd->getArch()->funcptr_align;
  if (bit != 0) {
    mask = (mask >> bit) << bit;
  }
  AddrSpace *spc = indop->getAddr().getSpace();
  bool notdone = jrange->initializeForReading();
  while(notdone) {
    val = jrange->getValue();
    addr = emul.emulatePath(val,pathMeld,jrange->getStartOp(),jrange->getStartVarnode());
    addr = AddrSpace::addressToByte(addr,spc->getWordSize());
    addr &= mask;
    addresstable.push_back(Address(spc,addr));
    notdone = jrange->next();
  }
  if (loadpoints != (vector<LoadTable> *)0)
    emul.collectLoadPoints(*loadpoints);
}

void JumpBasic::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  int4 i,j;

  i = varnodeIndex;
  normalvn = pathMeld.getVarnode(i++);
  switchvn = normalvn;
  markModel(true);

  int4 countaddsub=0;
  int4 countext=0;
  PcodeOp *normop = (PcodeOp *)0;
  while(i<pathMeld.numCommonVarnode()) {
    if (!flowsOnlyToModel(switchvn, normop)) break;	// Switch variable should only flow into model
    Varnode *testvn = pathMeld.getVarnode(i);
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
  markModel(false);
}

void JumpBasic::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{
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

Varnode *JumpBasic::foldInNormalization(Funcdata *fd,PcodeOp *indop)

{
  // Set the BRANCHIND input to be the unnormalized switch variable, so
  // all the intervening code to calculate the final address is eliminated as dead.
  fd->opSetInput(indop,switchvn,0);
  return switchvn;
}

bool JumpBasic::foldInGuards(Funcdata *fd,JumpTable *jump)

{
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

{
  // Test all the addresses in \b this address table checking
  // that they are reasonable. We cut off at the first unreasonable address.
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

{
  JumpBasic *res = new JumpBasic(jt);
  res->jrange = (JumpValuesRange *)jrange->clone();	// We only need to clone the JumpValues
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
  jump->setLastAsMostCommon();	// It should be the default block
  guard.clear();		// Mark that we are folded
  return true;
}

void JumpBasic2::initializeStart(const PathMeld &pathMeld)

{
  if (pathMeld.empty()) {
    extravn = (Varnode *)0;
    return;
  }
  // Initialize at point where the JumpBasic model failed
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

/// \brief Check if the block that defines the normalized switch variable dominates the block containing the switch
///
/// \return \b true if the switch block is dominated
bool JumpBasic2::checkNormalDominance(void) const

{
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

{
  JumpBasic2 *res = new JumpBasic2(jt);
  res->jrange = (JumpValuesRange *)jrange->clone();	// We only need to clone the JumpValues
  return res;
}

void JumpBasic2::clear(void)

{
  extravn = (Varnode *)0;
  origPathMeld.clear();
  JumpBasic::clear();
}

/// \param jt is the parent JumpTable
JumpBasicOverride::JumpBasicOverride(JumpTable *jt)
  : JumpBasic(jt)
{
  startingvalue = 0;
  hash = 0;
  istrivial = false;
}

/// \param adtable is the list of externally provided addresses, which will be deduped
void JumpBasicOverride::setAddresses(const vector<Address> &adtable)

{
  for(int4 i=0;i<adtable.size();++i)
    adset.insert(adtable[i]);
}

/// \brief Return the PcodeOp (within the PathMeld set) that takes the given Varnode as input
///
/// If there no PcodeOp in the set reading the Varnode, null is returned
/// \param vn is the given Varnode
/// \return the PcodeOp or null
int4 JumpBasicOverride::findStartOp(Varnode *vn)

{
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

/// \brief Test a given Varnode as a potential normalized switch variable
///
/// This method tries to figure out the set of values for the Varnode that
/// produce the manually provided set of addresses.   Starting with \e startingvalue
/// and simply incrementing by one to obtain new values, the path from the potential variable
/// to the BRANCHIND is emulated to produce addresses in the manual set.  Duplicates and
/// misses are allowed. Once we see all addresses in the manual set,
/// the method returns the index of the starting op, otherwise -1 is returned.
/// \param fd is the function containing the switch
/// \param trialvn is the given trial normalized switch variable
/// \param tolerance is the number of misses that will be tolerated
/// \return the index of the starting PcodeOp within the PathMeld or -1
int4 JumpBasicOverride::trialNorm(Funcdata *fd,Varnode *trialvn,uint4 tolerance)

{
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

/// \brief Convert \b this to a trivial model
///
/// Since we have an absolute set of addresses, if all else fails we can use the indirect variable
/// as the normalized switch and the addresses as the values, similar to JumpModelTrivial
void JumpBasicOverride::setupTrivial(void)

{
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

/// \brief Find a potential normalized switch variable
///
/// This method is called if the normalized switch variable is not explicitly provided.
/// It looks for the normalized Varnode in the most common jump-table constructions,
/// otherwise it returns null.
/// \return the potential normalized switch variable or null
Varnode *JumpBasicOverride::findLikelyNorm(void)

{
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

/// \brief Clear varnodes and ops that are specific to one instance of a function
void JumpBasicOverride::clearCopySpecific(void)

{
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

{
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

{
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

  uintb mask = ~((uintb)0);
  int4 bit = fd->getArch()->funcptr_align;
  if (bit != 0) {
    mask = (mask >> bit) << bit;
  }
  for(int4 index=0;index<sizeIndices;++index) {
    inputs[0] = index;
    uintb output = pcodeScript->evaluate(inputs);
    output &= mask;
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

Varnode *JumpAssisted::foldInNormalization(Funcdata *fd,PcodeOp *indop)

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
  return switchvn;
}

bool JumpAssisted::foldInGuards(Funcdata *fd,JumpTable *jump)

{
  int4 origVal = jump->getDefaultBlock();
  jump->setLastAsMostCommon();			// Default case is always the last block
  return (origVal != jump->getDefaultBlock());
}

JumpModel *JumpAssisted::clone(JumpTable *jt) const

{
  JumpAssisted *clone = new JumpAssisted(jt);
  clone->userop = userop;
  clone->sizeIndices = sizeIndices;
  return clone;
}

/// Try to recover each model in turn, until we find one that matches the specific BRANCHIND.
/// \param fd is the function containing the switch
void JumpTable::recoverModel(Funcdata *fd)

{
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

/// Check that the BRANCHIND is still reachable, if not throw JumptableNotReachableError.
/// Check pathological cases when there is only one address in the table, if we find
/// this, throw the JumptableThunkError. Let the model run its sanity check.
/// Print a warning if the sanity check truncates the original address table.
/// \param fd is the function containing the switch
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

/// Given a specific basic-block, figure out which edge out of the switch block
/// hits it.  This \e position is different from the index into the address table,
/// the out edges are deduped and may include additional guard destinations.
/// If no edge hits it, throw an exception.
/// \param bl is the specific basic-block
/// \return the position of the basic-block
int4 JumpTable::block2Position(const FlowBlock *bl) const

{
  FlowBlock *parent;
  int4 position;

  parent = indirect->getParent();
  for(position=0;position<bl->sizeIn();++position)
    if (bl->getIn(position) == parent) break;
  if (position==bl->sizeIn())
    throw LowlevelError("Requested block, not in jumptable");
  return bl->getInRevIndex(position);
}

/// We are not doing a complete check, we are looking for a guard that has collapsed to "if (false)"
/// \param op is the given PcodeOp to check
/// \return \b true is the PcodeOp is reachable
bool JumpTable::isReachable(PcodeOp *op)

{
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

/// \param g is the Architecture the table exists within
/// \param ad is the Address of the BRANCHIND \b this models
JumpTable::JumpTable(Architecture *g,Address ad)
  : opaddress(ad)
{
  glb = g;
  jmodel = (JumpModel *)0;
  origmodel = (JumpModel *)0;
  indirect = (PcodeOp *)0;
  switchVarConsume = ~((uintb)0);
  defaultBlock = -1;
  lastBlock = -1;
  maxtablesize = 1024;
  maxaddsub = 1;
  maxleftright = 1;
  maxext = 1;
  recoverystage = 0;
  collectloads = false;
}

/// This is a partial clone of another jump-table. Objects that are specific
/// to the particular Funcdata instance must be recalculated.
/// \param op2 is the jump-table to clone
JumpTable::JumpTable(const JumpTable *op2)

{
  glb = op2->glb;
  jmodel = (JumpModel *)0;
  origmodel = (JumpModel *)0;
  indirect = (PcodeOp *)0;
  switchVarConsume = ~((uintb)0);
  defaultBlock = -1;
  lastBlock = op2->lastBlock;
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

/// \brief Return the number of address table entries that target the given basic-block
///
/// \param bl is the given basic-block
/// \return the count of entries
int4 JumpTable::numIndicesByBlock(const FlowBlock *bl) const

{
  IndexPair val(block2Position(bl),0);
  pair<vector<IndexPair>::const_iterator,vector<IndexPair>::const_iterator> range;
  range = equal_range(block2addr.begin(),block2addr.end(),val,IndexPair::compareByPosition);
  return range.second - range.first;
}

bool JumpTable::isOverride(void) const

{
  if (jmodel == (JumpModel *)0)
    return false;
  return jmodel->isOverride();
}

/// \brief Force manual override information on \b this jump-table.
///
/// The model is switched over to JumpBasicOverride, which is initialized with an externally
/// provided list of addresses.  The addresses are forced as the output addresses the BRANCHIND
/// for \b this jump-table.  If a non-zero hash and an address is provided, this identifies a
/// specific Varnode to use as the normalized switch variable. A potential starting value for
/// normalized switch variable range is provided.
/// \param addrtable is the manually provided list of addresses to put in the address table
/// \param naddr is the address where the normalized switch variable is defined
/// \param h is a hash identifying the normalized switch variable (or 0)
/// \param sv is the starting value for the range of possible normalized switch variable values (usually 0)
void JumpTable::setOverride(const vector<Address> &addrtable,const Address &naddr,uintb h,uintb sv)

{
  if (jmodel != (JumpModel *)0)
    delete jmodel;

  JumpBasicOverride *override;
  jmodel = override = new JumpBasicOverride(this);
  override->setAddresses(addrtable);
  override->setNorm(naddr,h);
  override->setStartingValue(sv);
}

/// \brief Get the index of the i-th address table entry that corresponds to the given basic-block
///
/// An exception is thrown if no address table entry targets the block.
/// \param bl is the given basic-block
/// \param i requests a specific position within the duplicate entries
/// \return the address table index
int4 JumpTable::getIndexByBlock(const FlowBlock *bl,int4 i) const

{
  IndexPair val(block2Position(bl),0);
  int4 count = 0;
  vector<IndexPair>::const_iterator iter = lower_bound(block2addr.begin(),block2addr.end(),val,IndexPair::compareByPosition);
  while(iter != block2addr.end()) {
    if ((*iter).blockPosition == val.blockPosition) {
      if (count == i)
	return (*iter).addressIndex;
      count += 1;
    }
    ++iter;
  }
  throw LowlevelError("Could not get jumptable index for block");
}

void JumpTable::setLastAsMostCommon(void)

{
  defaultBlock = lastBlock;
}

/// This is used to add address targets from guard branches if they are
/// not already in the address table. A specific case label for the block
/// can also be provided. The new target is appended directly to the end of the table.
/// \param bl is the given basic-block
/// \param lab is the case label for the block
void JumpTable::addBlockToSwitch(BlockBasic *bl,uintb lab)

{
  addresstable.push_back(bl->getStart());
  lastBlock = indirect->getParent()->sizeOut();		// The block WILL be added to the end of the out-edges
  block2addr.push_back(IndexPair(lastBlock,addresstable.size()-1));
  label.push_back(lab);
}

/// Convert addresses in \b this table to actual targeted basic-blocks.
///
/// This constructs a map from each out-edge from the basic-block containing the BRANCHIND
/// to addresses in the table targetting that out-block. The most common
/// address table entry is also calculated here.
/// \param flow is used to resolve address targets
void JumpTable::switchOver(const FlowInfo &flow)

{
  FlowBlock *parent,*tmpbl;
  int4 pos;
  PcodeOp *op;

  block2addr.clear();
  block2addr.reserve(addresstable.size());
  parent = indirect->getParent();

  for(int4 i=0;i<addresstable.size();++i) {
    Address addr = addresstable[i];
    op = flow.target(addr);
    tmpbl = op->getParent();
    for(pos=0;pos<parent->sizeOut();++pos)
      if (parent->getOut(pos) == tmpbl) break;
    if (pos==parent->sizeOut())
      throw LowlevelError("Jumptable destination not linked");
    block2addr.push_back(IndexPair(pos,i));
  }
  lastBlock = block2addr.back().blockPosition;	// Out-edge of last address in table
  sort(block2addr.begin(),block2addr.end());

  defaultBlock = -1;			// There is no default case initially
  int4 maxcount = 1;			// If the maxcount is less than 2
  vector<IndexPair>::const_iterator iter = block2addr.begin();
  while(iter != block2addr.end()) {
    int4 curPos = (*iter).blockPosition;
    vector<IndexPair>::const_iterator nextiter = iter;
    int4 count = 0;
    while(nextiter != block2addr.end() && (*nextiter).blockPosition == curPos) {
      count += 1;
      ++nextiter;
    }
    iter = nextiter;
    if (count > maxcount) {
      maxcount = count;
      defaultBlock = curPos;
    }
  }
}

/// Eliminate any code involved in actually computing the destination address so
/// it looks like the CPUI_BRANCHIND operation does it all internally.
/// \param fd is the function containing \b this switch
void JumpTable::foldInNormalization(Funcdata *fd)

{
  Varnode *switchvn = jmodel->foldInNormalization(fd,indirect);
  if (switchvn != (Varnode *)0) {
    // If possible, mark up the switch variable as not fully consumed so that
    // subvariable flow can truncate it.
    switchVarConsume = minimalmask(switchvn->getNZMask());
    if (switchVarConsume >= calc_mask(switchvn->getSize())) {	// If mask covers everything
      if (switchvn->isWritten()) {
	PcodeOp *op = switchvn->getDef();
	if (op->code() == CPUI_INT_SEXT) {			// Check for a signed extension
	  switchVarConsume = calc_mask(op->getIn(0)->getSize());	// Assume the extension is not consumed
	}
      }
    }
  }
}

/// Make exactly one case for each output edge of the switch block.
void JumpTable::trivialSwitchOver(void)

{
  FlowBlock *parent;

  block2addr.clear();
  block2addr.reserve(addresstable.size());
  parent = indirect->getParent();

  if (parent->sizeOut() != addresstable.size())
    throw LowlevelError("Trivial addresstable and switch block size do not match");
  for(uint4 i=0;i<parent->sizeOut();++i)
    block2addr.push_back(IndexPair(i,i));	// Addresses corresponds exactly to out-edges of switch block
  lastBlock = parent->sizeOut()-1;
  defaultBlock = -1;		// Trivial case does not have default case
}

/// The addresses that the raw BRANCHIND op might branch to itself are recovered,
/// not including other targets of the final model, like guard addresses.  The normalized switch
/// variable and the guards are identified in the process however.
///
/// Generally this method is run during flow analysis when we only have partial information about
/// the function (and possibly the switch itself).  The Funcdata instance is a partial clone of the
/// function and is different from the final instance that will hold the fully recovered jump-table.
/// The final instance inherits the addresses recovered here, but recoverModel() will need to be
/// run on it separately.
///
/// A sanity check is also run, which might truncate the original set of addresses.
/// \param fd is the function containing the switch
void JumpTable::recoverAddresses(Funcdata *fd)

{
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

/// Do a normal recoverAddresses, but save off the old JumpModel, and if we fail recovery, put back the old model.
/// \param fd is the function containing the switch
void JumpTable::recoverMultistage(Funcdata *fd)

{
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

/// This is run assuming the address table has already been recovered, via recoverAddresses() in another
/// Funcdata instance. So recoverModel() needs to be rerun on the instance passed in here.
///
/// The unnormalized switch variable is recovered, and for each possible address table entry, the variable
/// value that produces it is calculated and stored as the formal \e case label for the associated code block.
/// \param fd is the (final instance of the) function containing the switch
/// \return \b true if it looks like a multi-stage restart is needed.
bool JumpTable::recoverLabels(Funcdata *fd)

{
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

/// Clear out any data that is specific to a Funcdata instance.  The address table is not cleared
/// if it was recovered, and override information is left intact.
/// Right now this is only getting called, when the jumptable is an override in order to clear out derived data.
void JumpTable::clear(void)

{
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
  block2addr.clear();
  lastBlock = -1;
  label.clear();
  loadpoints.clear();
  indirect = (PcodeOp *)0;
  switchVarConsume = ~((uintb)0);
  recoverystage = 0;
  // -opaddress- -maxtablesize- -maxaddsub- -maxleftright- -maxext- -collectloads- are permanent
}

/// The recovered addresses and case labels are saved to the XML stream.
/// If override information is present, this is also incorporated into the tag.
/// \param s is the stream to write to
void JumpTable::saveXml(ostream &s) const

{
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

/// Restore the addresses, \e case labels, and any override information from the tag.
/// Other parts of the model and jump-table will still need to be recovered.
/// \param el is the root \<jumptable> tag to restore from
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
      loadpoints.emplace_back();
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

/// Look for the override directive that indicates we need an additional recovery stage for
/// \b this jump-table.
/// \param fd is the function containing the switch
/// \return \b true if an additional recovery stage is required.
bool JumpTable::checkForMultistage(Funcdata *fd)

{
  if (addresstable.size()!=1) return false;
  if (recoverystage != 0) return false;
  if (indirect == (PcodeOp *)0) return false;

  if (fd->getOverride().queryMultistageJumptable(indirect->getAddr())) {
    recoverystage = 1;		// Mark that we need additional recovery
    return true;
  }
  return false;
}

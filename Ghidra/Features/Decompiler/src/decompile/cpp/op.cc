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
#include "op.hh"
#include "funcdata.hh"

/// Constructor for the \b iop space.
/// There is only one such space, and it is considered internal
/// to the model, i.e. the Translate engine should never generate
/// addresses in this space.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param nm is the name of the space (always \b iop)
/// \param ind is the associated index
IopSpace::IopSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind)
  : AddrSpace(m,t,IPTR_IOP,nm,sizeof(void *),1,ind,0,1)
{
  clearFlags(heritaged|does_deadcode|big_endian);
  if (HOST_ENDIAN==1)		// Endianness always set to host
    setFlags(big_endian);
}

void IopSpace::printRaw(ostream &s,uintb offset) const

{				// Print info about op this address refers to
  BlockBasic *bs;
  BlockBasic *bl;
  PcodeOp *op = (PcodeOp *)(uintp)offset; // Treat offset as op

  if (!op->isBranch()) {	// op parameter for CPUI_INDIRECT
    s << op->getSeqNum();
    return;
  }
  bs = op->getParent();
  if (bs->sizeOut()==2)		// We print the non-fallthru condition
    bl = (BlockBasic *)(op->isFallthruTrue() ? bs->getOut(0) : bs->getOut(1));
  else
    bl = (BlockBasic *)bs->getOut(0);
  s << "code_" << bl->getStart().getShortcut();
  bl->getStart().printRaw(s);
}

void IopSpace::saveXml(ostream &s) const

{
  throw LowlevelError("Should never save iop space to XML");
}

void IopSpace::restoreXml(const Element *el)

{
  throw LowlevelError("Should never restore iop space from XML");
}

/// Construct a completely unattached PcodeOp.  Space is reserved for input and output Varnodes
/// but all are set initially to null.
/// \param s indicates the number of input slots reserved
/// \param sq is the sequence number to associate with the new PcodeOp
PcodeOp::PcodeOp(int4 s,const SeqNum &sq) : start(sq),inrefs(s)

{
  flags = 0;			// Start out life as dead
  addlflags = 0;
  parent = (BlockBasic *)0; // No parent yet
  
  output = (Varnode *) 0;
  opcode = (TypeOp *)0;
  for(int4 i=0;i<inrefs.size();++i)
    inrefs[i] = (Varnode *)0;
}

/// \brief Find the slot for a given Varnode, which may be take up multiple input slots
///
/// In the rare case that \b this PcodeOp takes the same Varnode as input multiple times,
/// use the specific descendant iterator producing \b this PcodeOp to work out the corresponding slot.
/// Every slot containing the given Varnode will be produced exactly once over the course of iteration.
/// \param vn is the given Varnode
/// \param firstSlot is the first instance of the Varnode in \b this input list
/// \param iter is the specific descendant iterator producing \b this
/// \return the slot corresponding to the iterator
int4 PcodeOp::getRepeatSlot(const Varnode *vn,int4 firstSlot,list<PcodeOp *>::const_iterator iter) const

{
  int4 count = 1;
  for(list<PcodeOp *>::const_iterator oiter=vn->beginDescend();oiter != iter;++oiter) {
    if ((*oiter) == this)
      count += 1;
  }
  if (count == 1) return firstSlot;
  int4 recount = 1;
  for(int4 i=firstSlot+1;i<inrefs.size();++i) {
    if (inrefs[i] == vn) {
      recount += 1;
      if (recount == count)
	return i;
    }
  }
  return -1;
}

/// Can this be collapsed to a copy op, i.e. are all inputs constants
/// \return \b true if this op can be callapsed
bool PcodeOp::isCollapsible(void) const

{
  if (code() == CPUI_COPY) return false;
  if ((flags & PcodeOp::nocollapse)!=0) return false;
  if (!isAssignment()) return false;
  if (inrefs.size()==0) return false;
  for(int4 i=0;i<inrefs.size();++i)
    if (!getIn(i)->isConstant()) return false;
  if (getOut()->getSize() > sizeof(uintb)) return false;
  return true;
}

/// Produce a hash of the following attributes: output size, the opcode, and the identity
/// of each input varnode.  This is suitable for determining if two PcodeOps calculate identical values
/// \return the calculated hash or 0 if the op is not cse hashable
uintm PcodeOp::getCseHash(void) const

{
  uintm hash;
  if ((getEvalType()&(PcodeOp::unary|PcodeOp::binary))==0) return ((uintm)0);
  if (code()==CPUI_COPY) return ((uintm)0); // Let copy propagation deal with this
  
  hash = (output->getSize()<<8) | (uintm)code();
  for(int4 i=0;i<inrefs.size();++i) {
    const Varnode *vn = getIn(i);
    hash = (hash<<8) | (hash>>(sizeof(uintm)*8-8));
    if (vn->isConstant())
      hash ^= (uintm)vn->getOffset();
    else
      hash ^= (uintm)vn->getCreateIndex(); // Hash in pointer itself as unique id
  }
  return hash;
}

/// Do these two ops represent a common subexpression?
/// This is the full test of matching indicated by getCseHash
/// \param op is the PcodeOp to compare with this
/// \return \b true if the two ops are a common subexpression match
bool PcodeOp::isCseMatch(const PcodeOp *op) const

{
  if ((getEvalType()&(PcodeOp::unary|PcodeOp::binary))==0) return false;
  if ((op->getEvalType()&(PcodeOp::unary|PcodeOp::binary))==0) return false;
  if (output->getSize() != op->output->getSize()) return false;
  if (code() != op->code()) return false;
  if (code() == CPUI_COPY) return false; // Let copy propagation deal with this
  if (inrefs.size() != op->inrefs.size()) return false;
  for(int4 i=0;i<inrefs.size();++i) {
    const Varnode *vn1 = getIn(i);
    const Varnode *vn2 = op->getIn(i);
    if (vn1 == vn2) continue;
    if (vn1->isConstant()&&vn2->isConstant()&&(vn1->getOffset()==vn2->getOffset()))
      continue;
    return false;
  }
  return true;
}

/// Its possible for the order of operations to be rearranged in some instances but still keep
/// equivalent data-flow.  Test if \b this operation can be moved to occur immediately after
/// a specified \e point operation. This currently only tests for movement within a basic block.
/// \param point is the specified point to move \b this after
/// \return \b true if the move is possible
bool PcodeOp::isMoveable(const PcodeOp *point) const

{
  if (this == point) return true;	// No movement necessary
  bool movingLoad = false;
  if (getEvalType() == PcodeOp::special) {
    if (code() == CPUI_LOAD)
      movingLoad = true;	// Allow LOAD to be moved with additional restrictions
    else
      return false;	// Don't move special ops
  }
  if (parent != point->parent) return false;	// Not in the same block
  if (output != (Varnode *)0) {
    // Output cannot be moved past an op that reads it
    list<PcodeOp *>::const_iterator iter = output->beginDescend();
    list<PcodeOp *>::const_iterator enditer = output->endDescend();
    while(iter != enditer) {
      PcodeOp *readOp = *iter;
      ++iter;
      if (readOp->parent != parent) continue;
      if (readOp->start.getOrder() <= point->start.getOrder())
	return false;		// Is in the block and is read before (or at) -point-
    }
  }
  // Only allow this op to be moved across a CALL in very restrictive circumstances
  bool crossCalls = false;
  if (getEvalType() != PcodeOp::special) {
    // Check for a normal op where all inputs and output are not address tied
    if (output != (Varnode *)0 && !output->isAddrTied() && !output->isPersist()) {
      int4 i;
      for(i=0;i<numInput();++i) {
	const Varnode *vn = getIn(i);
	if (vn->isAddrTied() || vn->isPersist())
	  break;
      }
      if (i == numInput())
	crossCalls = true;
    }
  }
  vector<const Varnode *> tiedList;
  for(int4 i=0;i<numInput();++i) {
    const Varnode *vn = getIn(i);
    if (vn->isAddrTied())
      tiedList.push_back(vn);
  }
  list<PcodeOp *>::iterator biter = basiciter;
  do {
    ++biter;
    PcodeOp *op = *biter;
    if (op->getEvalType() == PcodeOp::special) {
      switch (op->code()) {
	case CPUI_LOAD:
	  if (output != (Varnode *)0) {
	    if (output->isAddrTied()) return false;
	  }
	  break;
	case CPUI_STORE:
	  if (movingLoad)
	    return false;
	  else {
	    if (!tiedList.empty()) return false;
	    if (output != (Varnode *)0) {
	      if (output->isAddrTied()) return false;
	    }
	  }
	  break;
	case CPUI_INDIRECT:		// Let thru, deal with what's INDIRECTed around separately
	case CPUI_SEGMENTOP:
	case CPUI_CPOOLREF:
	  break;
	case CPUI_CALL:
	case CPUI_CALLIND:
	case CPUI_NEW:
	  if (!crossCalls) return false;
	  break;
	default:
	  return false;
      }
    }
    if (op->output != (Varnode *)0) {
      if (movingLoad) {
	if (op->output->isAddrTied()) return false;
      }
      for(int4 i=0;i<tiedList.size();++i) {
	const Varnode *vn = tiedList[i];
	if (vn->overlap(*op->output)>=0)
	  return false;
	if (op->output->overlap(*vn)>=0)
	  return false;
      }
    }
  } while(biter != point->basiciter);
  return true;
}

/// Set the behavioral class (opcode) of this operation. For most applications this should only be called
/// by the PcodeOpBank.  This is fairly low-level but does cache various boolean flags associated with the opcode
/// \param t_op is the behavioural class to set
void PcodeOp::setOpcode(TypeOp *t_op)

{
  flags &= ~(PcodeOp::branch | PcodeOp::call | PcodeOp::coderef | PcodeOp::commutative |
	     PcodeOp::returns | PcodeOp::nocollapse | PcodeOp::marker | PcodeOp::booloutput |
	     PcodeOp::unary | PcodeOp::binary | PcodeOp::special);
  opcode = t_op;
  flags |= t_op->getFlags();
}

/// Make sure there are exactly \e num input slots for this op.
/// All slots, regardless of the total being increased or decreased, are set to \e null.
/// \param num is the number of inputs to set
void PcodeOp::setNumInputs(int4 num)

{
  inrefs.resize(num);
  for(int4 i=0;i<num;++i)
    inrefs[i] = (Varnode *)0;
}

/// Remove the input Varnode in a specific slot.  The slot is eliminated and all Varnodes beyond this
/// slot are renumbered.  All the other Varnodes are otherwise undisturbed.
/// \param slot is the index of the Varnode to remove
void PcodeOp::removeInput(int4 slot)

{
  for(int4 i=slot+1;i<inrefs.size();++i)
    inrefs[i-1] = inrefs[i];
  inrefs.pop_back();
}

/// Insert space for a new Varnode before \e slot.  The new space is filled with \e null.
/// \param slot is index of the slot where the new space is inserted
void PcodeOp::insertInput(int4 slot)

{
  inrefs.push_back((Varnode *)0);
  for(int4 i=inrefs.size()-1;i>slot;--i)
    inrefs[i] = inrefs[i-1];
  inrefs[slot] = (Varnode *)0;
}
  
// Find the next op in sequence from this op.  This is usually in the same basic block, but this
// routine will follow flow into successive blocks during its search, so long as there is only one path
// \return the next PcodeOp or \e null
PcodeOp *PcodeOp::nextOp(void) const

{
  list<PcodeOp *>::iterator iter;
  BlockBasic *p;

  p = parent;			// Current parent
  iter = basiciter;		// Current iterator

  iter ++;
  while(iter == p->endOp()) {
    if ((p->sizeOut() != 1)&&(p->sizeOut()!=2)) return (PcodeOp *)0;
    p = (BlockBasic *) p->getOut(0);
    iter = p->beginOp();
  }
  return *iter;
}

/// Find the previous op that flowed uniquely into this op, if it exists.  This routine will not search
/// farther than the basic block containing this.
/// \return the previous PcodeOp or \e null
PcodeOp *PcodeOp::previousOp(void) const

{
  list<PcodeOp *>::iterator iter;

  if (basiciter == parent->beginOp()) return (PcodeOp *) 0;
  iter = basiciter;
  iter--;
  return *iter;
}
  
/// Scan backward within the basic block containing this op and find the first op marked as the
/// start of an instruction.  This also works if basic blocks haven't been calculated yet, and all
/// the ops are still in the dead list.  The starting op may be from a different instruction if
/// this op was from an instruction in a delay slot
/// \return the starting PcodeOp
PcodeOp *PcodeOp::target(void) const

{
  PcodeOp *retop;
  list<PcodeOp *>::iterator iter;
  iter = isDead() ? insertiter : basiciter;
  retop = *iter;
  while((retop->flags&PcodeOp::startmark)==0) {
    --iter;
    retop = *iter;
  }
  return retop;
}

/// Print an address and a raw representation of this op to the stream, suitable for console debugging apps
/// \param s is the stream to print to
void PcodeOp::printDebug(ostream &s) const

{
  s << start << ": ";
  if (isDead()||(parent==(BlockBasic *)0))
    s << "**";
  else
    printRaw(s);
}

/// Write a description including: the opcode name, the sequence number, and separate xml tags
/// providing a reference number for each input and output Varnode
/// \param s is the stream to write to
void PcodeOp::saveXml(ostream &s) const

{
  s << "<op";
  a_v_i(s,"code",(int4)code());
  s << ">\n";
  start.saveXml(s);
  s << '\n';
  if (output==(Varnode *)0)
    s << "<void/>\n";
  else
    s << "<addr ref=\"0x" << hex << output->getCreateIndex() << "\"/>\n";
  for(int4 i=0;i<inrefs.size();++i) {
    const Varnode *vn = getIn(i);
    if (vn == (const Varnode *)0)
      s << "<void/>\n";
    else if (vn->getSpace()->getType()==IPTR_IOP) {
      if ((i==1)&&(code()==CPUI_INDIRECT)) {
	PcodeOp *indop = PcodeOp::getOpFromConst(vn->getAddr());
	s << "<iop";
	a_v_u(s,"value",indop->getSeqNum().getTime());
	s << "/>\n";
      }
      else
	s << "<void/>\n";
    }
    else if (vn->getSpace()->getType()==IPTR_CONSTANT) {
      if ((i==0)&&((code()==CPUI_STORE)||(code()==CPUI_LOAD))) {
	AddrSpace *spc = Address::getSpaceFromConst(vn->getAddr());
	s << "<spaceid name=\"";
	s << spc->getName() << "\"/>\n";
      }
      else
	s << "<addr ref=\"0x" << hex << vn->getCreateIndex() << "\"/>\n";
    }
    else {
      s << "<addr ref=\"0x" << hex << vn->getCreateIndex() << "\"/>\n";
    }
  }
  s << "</op>\n";
}

/// Assuming all the inputs to this op are constants, compute the constant result of evaluating
/// this op on this inputs. If one if the inputs has attached symbol information,
/// pass-back "the fact of" as we may want to propagate the info to the new constant.
/// Throw an exception if a constant result cannot be produced.
/// \param markedInput will pass-back whether or not one of the inputs is a marked constant
/// \return the constant result
uintb PcodeOp::collapse(bool &markedInput) const {
  const Varnode *vn0;
  const Varnode *vn1;

  vn0 = getIn(0);
  if (vn0->getSymbolEntry() != (SymbolEntry *)0) {
    markedInput = true;
  }
  switch(getEvalType()) {
  case PcodeOp::unary:
    return opcode->evaluateUnary(output->getSize(),vn0->getSize(),vn0->getOffset());
  case PcodeOp::binary:
    vn1 = getIn(1);
    if (vn1->getSymbolEntry() != (SymbolEntry *)0) {
      markedInput = true;
    }
    return opcode->evaluateBinary(output->getSize(),vn0->getSize(),
				  vn0->getOffset(),vn1->getOffset());
  default: 
    break;
  }
  throw LowlevelError("Invalid constant collapse");
}

/// Knowing that \b this PcodeOp has collapsed its constant inputs, one of which has
/// symbol content, figure out if the symbol should propagate to the new given output constant.
/// \param newConst is the given output constant
void PcodeOp::collapseConstantSymbol(Varnode *newConst) const

{
 const Varnode *copyVn = (const Varnode *)0;
  switch(code()) {
    case CPUI_SUBPIECE:
      if (getIn(1)->getOffset() != 0)
	return;				// Must be truncating high bytes
      copyVn = getIn(0);
      break;
    case CPUI_COPY:
    case CPUI_INT_ZEXT:
    case CPUI_INT_NEGATE:
    case CPUI_INT_2COMP:
      copyVn = getIn(0);
      break;
    case CPUI_INT_LEFT:
    case CPUI_INT_RIGHT:
    case CPUI_INT_SRIGHT:
      copyVn = getIn(0);	// Marked varnode must be first input
      break;
    case CPUI_INT_ADD:
    case CPUI_INT_MULT:
    case CPUI_INT_AND:
    case CPUI_INT_OR:
    case CPUI_INT_XOR:
      copyVn = getIn(0);
      if (copyVn->getSymbolEntry() == (SymbolEntry *)0) {
	copyVn = getIn(1);
      }
      break;
    default:
      return;
  }
  if (copyVn->getSymbolEntry() == (SymbolEntry *)0)
	return;				// The first input must be marked
  newConst->copySymbolIfValid(copyVn);
}

/// Compute nonzeromask assuming inputs to op have their masks properly defined. Assume the op has an output.
/// For any inputs to this op, that have zero bits where their nzmasks have zero bits, then the output
/// produced by this op is guaranteed to have zero bits at every location in the nzmask calculated by this function.
/// \param cliploop indicates the calculation shouldn't include inputs from known looping edges
/// \return the calculated non-zero mask
uintb PcodeOp::getNZMaskLocal(bool cliploop) const

{
  int4 sa,sz1,sz2,size;
  uintb resmask,val;

  size = output->getSize();
  uintb fullmask = calc_mask( size );

  switch(opcode->getOpcode()) {
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_CARRY:
  case CPUI_INT_SCARRY:
  case CPUI_INT_SBORROW:
  case CPUI_BOOL_NEGATE:
  case CPUI_BOOL_XOR:
  case CPUI_BOOL_AND:
  case CPUI_BOOL_OR:
  case CPUI_FLOAT_EQUAL:
  case CPUI_FLOAT_NOTEQUAL:
  case CPUI_FLOAT_LESS:
  case CPUI_FLOAT_LESSEQUAL:
  case CPUI_FLOAT_NAN:
    resmask=1;			// Only 1 bit not guaranteed to be 0
    break;
  case CPUI_COPY:
  case CPUI_INT_ZEXT:
    resmask = getIn(0)->getNZMask();
    break;
  case CPUI_INT_SEXT:
    resmask = sign_extend( getIn(0)->getNZMask(), getIn(0)->getSize(), size);
    break;
  case CPUI_INT_XOR:
  case CPUI_INT_OR:
    resmask = getIn(0)->getNZMask();
    if (resmask != fullmask)
      resmask |= getIn(1)->getNZMask();
    break;
  case CPUI_INT_AND:
    resmask = getIn(0)->getNZMask();
    if (resmask != 0)
      resmask &= getIn(1)->getNZMask();
    break;
  case CPUI_INT_LEFT:
    if (!getIn(1)->isConstant())
      resmask = fullmask;
    else {
      sa = getIn(1)->getOffset(); // Get shift amount
      resmask = getIn(0)->getNZMask();
      resmask = pcode_left(resmask,sa) & fullmask;
    }
    break;
  case CPUI_INT_RIGHT:
    if (!getIn(1)->isConstant())
      resmask = fullmask;
    else {
      sz1 = getIn(0)->getSize();
      sa = getIn(1)->getOffset(); // Get shift amount
      resmask = getIn(0)->getNZMask();
      resmask = pcode_right(resmask,sa);
      if (sz1 > sizeof(uintb)) {
	// resmask did not hold most sig bits of mask
	if (sa >= 8*sz1)
	  resmask = 0;
	else if (sa >= 8*sizeof(uintb)) {
	  // Full mask shifted over 8*sizeof(uintb)
	  resmask = calc_mask( sz1-sizeof(uintb) );
	  // Shift over remaining portion of sa
	  resmask >>= (sa-8*sizeof(uintb));
	}
	else {
	  // Fill in one bits from part of mask not originally
	  // calculated
	  uintb tmp = 0;
	  tmp -= 1;
	  tmp <<= (8*sizeof(uintb)-sa);
	  resmask |= tmp;
	}
      }
    }
    break;
  case CPUI_INT_SRIGHT:
    if ((!getIn(1)->isConstant())||(size > sizeof(uintb)))
      resmask = fullmask;
    else {
      sa = getIn(1)->getOffset();	// Get shift amount
      resmask = getIn(0)->getNZMask();
      if ((resmask & (fullmask ^ (fullmask>>1))) == 0) {	// If we know sign bit is zero
	resmask = pcode_right(resmask,sa);			// Same as CPUI_INT_RIGHT
      }
      else {
	resmask = pcode_right(resmask,sa);
	resmask |= (fullmask >> sa) ^ fullmask;			// Don't know what the new high bits are
      }
    }
    break;
  case CPUI_INT_DIV:
    val = getIn(0)->getNZMask();
    resmask = coveringmask(val);
    if (getIn(1)->isConstant()) {
    // Dividing by power of 2 is equiv to right shift
    // if the denom is bigger than a power of 2, then
    // the result still has at least that many highsig zerobits
      sa = mostsigbit_set(getIn(1)->getNZMask());
      if (sa != -1)
	resmask >>= sa;		// Add sa additional zerobits
    }
    break;
  case CPUI_INT_REM:
    val = (getIn(1)->getNZMask()-1); // Result is less than modulus
    resmask = coveringmask(val);
    break;
  case CPUI_POPCOUNT:
    sz1 = popcount(getIn(0)->getNZMask());
    resmask = coveringmask((uintb)sz1);
    resmask &= fullmask;
    break;
  case CPUI_SUBPIECE:
    resmask = getIn(0)->getNZMask();
    sz1 = (int4)getIn(1)->getOffset();
    if ((int4)getIn(0)->getSize() <= sizeof(uintb)) {
      if (sz1 < sizeof(uintb))
	resmask >>= 8*sz1;
      else
	resmask = 0;
    }
    else {			// Extended precision
      if (sz1 < sizeof(uintb)) {
	resmask >>= 8*sz1;
	if (sz1 > 0)
	  resmask |= fullmask << (8*(sizeof(uintb)-sz1));
      }
      else
	resmask = fullmask;
    }
    resmask &= fullmask;
    break;
  case CPUI_PIECE:
    resmask = getIn(0)->getNZMask();
    resmask <<= 8*getIn(1)->getSize();
    resmask |= getIn(1)->getNZMask();
    break;
  case CPUI_INT_MULT:
    val = getIn(0)->getNZMask();
    resmask = getIn(1)->getNZMask();
    sz1 = (size > sizeof(uintb)) ? 8*size-1 : mostsigbit_set(val);
    if (sz1 == -1)
      resmask = 0;
    else {
      sz2 = (size > sizeof(uintb)) ? 8*size-1 : mostsigbit_set(resmask);
      if (sz2 == -1)
	resmask = 0;
      else {
	if (sz1 + sz2 < 8*size-2)
	  fullmask >>= (8*size-2-sz1-sz2);
	sz1 = leastsigbit_set(val);
	sz2 = leastsigbit_set(resmask);
	resmask = (~((uintb)0))<<(sz1+sz2);
	resmask &= fullmask;
      }
    }
    break;
  case CPUI_INT_ADD:
    resmask = getIn(0)->getNZMask();
    if (resmask!=fullmask) {
      resmask |= getIn(1)->getNZMask();
      resmask |= (resmask<<1);	// Account for possible carries
      resmask &= fullmask;
    }
    break;
  case CPUI_MULTIEQUAL:
    if (inrefs.size()==0)
      resmask = fullmask;
    else {
      int4 i=0;
      resmask = 0;
      if (cliploop) {
	for(;i<inrefs.size();++i) {
	  if (parent->isLoopIn(i)) continue;
	  resmask |= getIn(i)->getNZMask();
	}
      }
      else {
	for(;i<inrefs.size();++i)
	  resmask |= getIn(i)->getNZMask();
      }
    }
    break;
  case CPUI_CALL:
  case CPUI_CALLIND:
  case CPUI_CPOOLREF:
    if (isCalculatedBool())
      resmask = 1;		// In certain cases we know the output is strictly boolean
    else
      resmask = fullmask;
    break;
  default:
    resmask = fullmask;
    break;
  }
  return resmask;
}

/// Compare the execution order of -this- and -bop-, if -this- executes earlier (dominates) return -1;
/// if -bop- executes earlier return 1, otherwise return 0.  Note that 0 is returned if there is no absolute
/// execution order.
/// \param bop is the PcodeOp to compare this to
/// \return -1, 0, or 1, depending on the comparison
int4 PcodeOp::compareOrder(const PcodeOp *bop) const

{
  if (parent == bop->parent)
    return (start.getOrder() < bop->start.getOrder()) ? -1 : 1;

  FlowBlock *common = FlowBlock::findCommonBlock(parent,bop->parent);
  if (common == parent)
    return -1;
  if (common == bop->parent)
    return 1;
  return 0;
}

/// Add the PcodeOp to the list of ops with the same op-code. Currently only certain
/// op-codes have a dedicated list.
/// \param op is the given PcodeOp
void PcodeOpBank::addToCodeList(PcodeOp *op)

{
  switch(op->code()) {
  case CPUI_STORE:
    op->codeiter = storelist.insert(storelist.end(),op);
    break;
  case CPUI_LOAD:
    op->codeiter = loadlist.insert(loadlist.end(), op);
    break;
  case CPUI_RETURN:
    op->codeiter = returnlist.insert(returnlist.end(),op);
    break;
  case CPUI_CALLOTHER:
    op->codeiter = useroplist.insert(useroplist.end(),op);
    break;
  default:
    break;
  }
}

/// Remove the PcodeOp from its list of ops with the same op-code. Currently only certain
/// op-codes have a dedicated list.
/// \param op is the given PcodeOp
void PcodeOpBank::removeFromCodeList(PcodeOp *op)

{
  switch(op->code()) {
  case CPUI_STORE:
    storelist.erase(op->codeiter);
    break;
  case CPUI_LOAD:
    loadlist.erase(op->codeiter);
    break;
  case CPUI_RETURN:
    returnlist.erase(op->codeiter);
    break;
  case CPUI_CALLOTHER:
    useroplist.erase(op->codeiter);
    break;
  default:
    break;
  }
}

void PcodeOpBank::clearCodeLists(void)

{
  storelist.clear();
  loadlist.clear();
  returnlist.clear();
  useroplist.clear();
}

/// A new PcodeOp is allocated with the indicated number of input slots, which
/// start out empty.  A sequence number is assigned, and the op is added to the
/// end of the \e dead list.
/// \param inputs is the number of input slots
/// \param pc is the Address to associate with the PcodeOp
/// \return the newly allocated PcodeOp
PcodeOp *PcodeOpBank::create(int4 inputs,const Address &pc)

{
  PcodeOp *op = new PcodeOp(inputs,SeqNum(pc,uniqid++));
  optree[op->getSeqNum()] = op;
  op->setFlag(PcodeOp::dead);		// Start out life as dead
  op->insertiter = deadlist.insert(deadlist.end(),op);
  return op;
}

/// A new PcodeOp is allocated with the indicated number of input slots and the
/// specific sequence number, suitable for cloning and restoring from XML.
/// The op is added to the end of the \e dead list.
/// \param inputs is the number of input slots
/// \param sq is the specified sequence number
/// \return the newly allocated PcodeOp
PcodeOp *PcodeOpBank::create(int4 inputs,const SeqNum &sq)

{
  PcodeOp *op;
  op = new PcodeOp(inputs,sq);
  if (sq.getTime() >= uniqid)
    uniqid = sq.getTime() + 1;

  optree[op->getSeqNum()] = op;
  op->setFlag(PcodeOp::dead);		// Start out life as dead
  op->insertiter = deadlist.insert(deadlist.end(),op);
  return op;
}

void PcodeOpBank::destroyDead(void)

{
  list<PcodeOp *>::iterator iter;
  PcodeOp *op;

  iter = deadlist.begin();
  while(iter!=deadlist.end()) {
    op = *iter++;
    destroy(op);
  }
}

/// The given PcodeOp is removed from all internal lists and added to a final
/// \e deadandgone list. The memory is not reclaimed until the whole container is
/// destroyed, in case pointer references still exist.  These will all still
/// be marked as \e dead.
/// \param op is the given PcodeOp to destroy
void PcodeOpBank::destroy(PcodeOp *op)

{
  if (!op->isDead())
    throw LowlevelError("Deleting integrated op");

  optree.erase(op->getSeqNum());
  deadlist.erase(op->insertiter);
  removeFromCodeList(op);
  deadandgone.push_back(op);
}

/// The PcodeOp is assigned the new op-code, which may involve moving it
/// between the internal op-code specific lists.
/// \param op is the given PcodeOp to change
/// \param newopc is the new op-code object
void PcodeOpBank::changeOpcode(PcodeOp *op,TypeOp *newopc)

{
  if (op->opcode != (TypeOp *)0)
    removeFromCodeList(op);
  op->setOpcode( newopc );
  addToCodeList(op);
}

/// The PcodeOp is moved out of the \e dead list into the \e alive list.  The
/// PcodeOp::isDead() method will now return \b false.
/// \param op is the given PcodeOp to mark
void PcodeOpBank::markAlive(PcodeOp *op)

{
  deadlist.erase(op->insertiter);
  op->clearFlag(PcodeOp::dead);
  op->insertiter = alivelist.insert(alivelist.end(),op);
}

/// The PcodeOp is moved out of the \e alive list into the \e dead list. The
/// PcodeOp::isDead() method will now return \b true.
/// \param op is the given PcodeOp to mark
void PcodeOpBank::markDead(PcodeOp *op)

{
  alivelist.erase(op->insertiter);
  op->setFlag(PcodeOp::dead);
  op->insertiter = deadlist.insert(deadlist.end(),op);
}

/// The op is moved to right after a specified op in the \e dead list.
/// \param op is the given PcodeOp to move
/// \param prev is the specified op in the \e dead list
void PcodeOpBank::insertAfterDead(PcodeOp *op,PcodeOp *prev)

{
  if ((!op->isDead())||(!prev->isDead()))
    throw LowlevelError("Dead move called on ops which aren't dead");
  deadlist.erase(op->insertiter);
  list<PcodeOp *>::iterator iter = prev->insertiter;
  ++iter;
  op->insertiter = deadlist.insert(iter,op);
}

/// \brief Move a sequence of PcodeOps to a point in the \e dead list.
///
/// The point is right after a provided op. All ops must be in the \e dead list.
/// \param firstop is the first PcodeOp in the sequence to be moved
/// \param lastop is the last PcodeOp in the sequence to be moved
/// \param prev is the provided point to move to
void PcodeOpBank::moveSequenceDead(PcodeOp *firstop,PcodeOp *lastop,PcodeOp *prev)

{
  list<PcodeOp *>::iterator enditer = lastop->insertiter;
  ++enditer;
  list<PcodeOp *>::iterator previter = prev->insertiter;
  ++previter;
  if (previter != firstop->insertiter) // Check for degenerate move
    deadlist.splice(previter,deadlist,firstop->insertiter,enditer);
}

/// Incidental COPYs are not considered active use of parameter passing Varnodes by
/// parameter analysis algorithms.
/// \param firstop is the start of the range of incidental COPY ops
/// \param lastop is the end of the range of incidental COPY ops
void PcodeOpBank::markIncidentalCopy(PcodeOp *firstop,PcodeOp *lastop)

{
  list<PcodeOp *>::iterator iter = firstop->insertiter;
  list<PcodeOp *>::iterator enditer = lastop->insertiter;
  ++enditer;
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->code() == CPUI_COPY)
      op->setAdditionalFlag(PcodeOp::incidental_copy);
  }
}

/// Find the first PcodeOp at or after the given Address assuming they have not
/// yet been broken up into basic blocks. Take into account delay slots.
/// \param addr is the given Address
/// \return the targeted PcodeOp (or NULL)
PcodeOp *PcodeOpBank::target(const Address &addr) const

{
  PcodeOpTree::const_iterator iter = optree.lower_bound(SeqNum(addr,0));
  if (iter == optree.end()) return (PcodeOp *)0;
  return (*iter).second->target();
}

/// \param num is the given sequence number
/// \return the matching PcodeOp (or NULL)
PcodeOp *PcodeOpBank::findOp(const SeqNum &num) const

{
  PcodeOpTree::const_iterator iter = optree.find(num);
  if (iter == optree.end()) return (PcodeOp *)0;
  return (*iter).second;
}

/// The term \e fallthru in this context refers to p-code \e not assembly instructions.
/// \param op is the given PcodeOp
/// \return the fallthru PcodeOp
PcodeOp *PcodeOpBank::fallthru(const PcodeOp *op) const

{
  PcodeOp *retop;
  if (op->isDead()) {
				// In this case we know an instruction is contiguous
				// in the dead list
    list<PcodeOp *>::const_iterator iter = op->insertiter;
    ++iter;
    if (iter != deadlist.end()) {
      retop = *iter;
      if (!retop->isInstructionStart()) // If the next in dead list is not marked
	return retop;		// It is in the same instruction, and is the fallthru
    }
    --iter;
    SeqNum max = op->getSeqNum();
    while(!(*iter)->isInstructionStart()) // Find start of instruction
      --iter;
				// Find biggest sequence number in this instruction
				// This is probably -op- itself because it is the
				// last op in the instruction, but it might not be
				// because of delay slot reordering
    while((iter!=deadlist.end())&&(*iter != op)) {
      if (max < (*iter)->getSeqNum())
	max = (*iter)->getSeqNum();
      ++iter;
    }
    PcodeOpTree::const_iterator nextiter = optree.upper_bound(max);
    if (nextiter == optree.end()) return (PcodeOp *)0;
    retop = (*nextiter).second;
    return retop;
  }
  else
    return op->nextOp();
}

PcodeOpTree::const_iterator PcodeOpBank::begin(const Address &addr) const

{
  return optree.lower_bound(SeqNum(addr,0));
}

PcodeOpTree::const_iterator PcodeOpBank::end(const Address &addr) const

{
  return optree.upper_bound(SeqNum(addr,~((uintm)0)));
}

list<PcodeOp *>::const_iterator PcodeOpBank::begin(OpCode opc) const

{
  switch(opc) {
  case CPUI_STORE:
    return storelist.begin();
  case CPUI_LOAD:
    return loadlist.begin();
  case CPUI_RETURN:
    return returnlist.begin();
  case CPUI_CALLOTHER:
    return useroplist.begin();
  default:
    break;
  }
  return alivelist.end();
}

list<PcodeOp *>::const_iterator PcodeOpBank::end(OpCode opc) const

{
  switch(opc) {
  case CPUI_STORE:
    return storelist.end();
  case CPUI_LOAD:
    return loadlist.end();
  case CPUI_RETURN:
    return returnlist.end();
  case CPUI_CALLOTHER:
    return useroplist.end();
  default:
    break;
  }
  return alivelist.end();
}

void PcodeOpBank::clear(void)

{
  list<PcodeOp *>::iterator iter;

  for(iter=alivelist.begin();iter!=alivelist.end();++iter)
    delete *iter;
  for(iter=deadlist.begin();iter!=deadlist.end();++iter)
    delete *iter;
  for(iter=deadandgone.begin();iter!=deadandgone.end();++iter)
    delete *iter;
  optree.clear();
  alivelist.clear();
  deadlist.clear();
  clearCodeLists();
  deadandgone.clear();
  uniqid = 0;
}

static int4 functionalEqualityLevel0(Varnode *vn1,Varnode *vn2)

{ // Return 0 if -vn1- and -vn2- must hold same value
  // Return -1 if they definitely don't hold same value
  // Return 1 if the same value depends on ops writing to -vn1- and -vn2-
  if (vn1==vn2) return 0;
  if (vn1->getSize() != vn2->getSize()) return -1;
  if (vn1->isConstant()) {
    if (vn2->isConstant()) {
      return (vn1->getOffset() == vn2->getOffset()) ? 0 : -1;
    }
    return -1;
  }
  if (vn2->isConstant()) return -1;
  if (vn1->isWritten() && vn2->isWritten()) return 1;
  return -1;
}

/// \brief Try to determine if \b vn1 and \b vn2 contain the same value
///
/// Return:
///    -  -1, if they do \b not, or if it can't be immediately verified
///    -   0, if they \b do hold the same value
///    -  >0, if the result is contingent on additional varnode pairs having the same value
/// In the last case, the varnode pairs are returned as (res1[i],res2[i]),
/// where the return value is the number of pairs.
/// \param vn1 is the first Varnode to compare
/// \param vn2 is the second Varnode
/// \param res1 is a reference to the first returned Varnode
/// \param res2 is a reference to the second returned Varnode
/// \return the result of the comparison
int4 functionalEqualityLevel(Varnode *vn1,Varnode *vn2,Varnode **res1,Varnode **res2)

{
  int4 testval = functionalEqualityLevel0(vn1,vn2);
  if (testval != 1) return testval;
  PcodeOp *op1 = vn1->getDef();
  PcodeOp *op2 = vn2->getDef();
  OpCode opc = op1->code();

  if (opc != op2->code()) return -1;

  int4 num = op1->numInput();
  if (num != op2->numInput()) return -1;
  if (op1->isMarker()) return -1;
  if (op2->isCall()) return -1;
  if (opc == CPUI_LOAD) {
				// FIXME: We assume two loads produce the same
				// result if the address is the same and the loads
				// occur in the same instruction
    if (op1->getAddr() != op2->getAddr()) return -1;
  }
  if (num >= 3) {
    if (opc != CPUI_PTRADD) return -1; // If this is a PTRADD
    if (op1->getIn(2)->getOffset() != op2->getIn(2)->getOffset()) return -1; // Make sure the elsize constant is equal
    num = 2;			// Otherwise treat as having 2 inputs
  }
  for(int4 i=0;i<num;++i) {
    res1[i] = op1->getIn(i);
    res2[i] = op2->getIn(i);
  }

  testval = functionalEqualityLevel0(res1[0],res2[0]);
  if (testval == 0) {	      	// A match locks in this comparison ordering
    if (num==1) return 0;
    testval = functionalEqualityLevel0(res1[1],res2[1]);
    if (testval==0) return 0;
    if (testval < 0) return -1;
    res1[0] = res1[1];		// Match is contingent on second pair
    res2[0] = res2[1];
    return 1;
  }
  if (num == 1) return testval;
  int4 testval2 = functionalEqualityLevel0(res1[1],res2[1]);
  if (testval2 == 0) {		// A match locks in this comparison ordering
    return testval;
  }
  int4 unmatchsize;
  if ((testval==1)&&(testval2==1))
    unmatchsize = 2;
  else
    unmatchsize = -1;

  if (!op1->isCommutative()) return unmatchsize;
  // unmatchsize must be 2 or -1 here on a commutative operator,
  // try flipping
  int4 comm1 = functionalEqualityLevel0(res1[0],res2[1]);
  int4 comm2 = functionalEqualityLevel0(res1[1],res2[0]);
  if ((comm1==0) && (comm2==0))
    return 0;
  if ((comm1<0)||(comm2<0))
    return unmatchsize;
  if (comm1==0)	{		// AND (comm2==1)
    res1[0] = res1[1];		// Left over unmatch is res1[1] and res2[0]
    return 1;
  }
  if (comm2==0) {		// AND (comm1==1)
    res2[0] = res2[1];		// Left over unmatch is res1[0] and res2[1]
    return 1;
  }
  // If we reach here (comm1==1) AND (comm2==1)
  if (unmatchsize == 2)		// If the original ordering wasn't impossible
    return 2;			// Prefer the original ordering
  Varnode *tmpvn = res2[0];	// Otherwise swap the ordering
  res2[0] = res2[1];
  res2[1] = tmpvn;
  return 2;
}

/// \brief Determine if two Varnodes hold the same value
///
/// Only return \b true if it can be immediately determined they are equivalent
/// \param vn1 is the first Varnode
/// \param vn2 is the second Varnode
/// \return true if they are provably equal
bool functionalEquality(Varnode *vn1,Varnode *vn2)

{
  Varnode *buf1[2];
  Varnode *buf2[2];
  return (functionalEqualityLevel(vn1,vn2,buf1,buf2)==0);
}

/// \brief Return true if vn1 and vn2 are verifiably different values
///
/// This is actually a rather speculative test
/// \param vn1 is the first Varnode to compare
/// \param vn2 is the second Varnode
/// \param depth is the maximum level to recurse while testing
/// \return \b true if they are different
bool functionalDifference(Varnode *vn1,Varnode *vn2,int4 depth)

{
  PcodeOp *op1,*op2;
  int4 i,num;

  if (vn1 == vn2) return false;
  if ((!vn1->isWritten())||(!vn2->isWritten())) {
    if (vn1->isConstant() && vn2->isConstant())
      return !(vn1->getAddr()==vn2->getAddr());
    if (vn1->isInput()&&vn2->isInput()) return false; // Might be the same
    if (vn1->isFree()||vn2->isFree()) return false; // Might be the same
    return true;
  }
  op1 = vn1->getDef();
  op2 = vn2->getDef();
  if (op1->code() != op2->code()) return true;
  num = op1->numInput();
  if (num != op2->numInput()) return true;
  if (depth==0) return true;	// Different as far as we can tell
  depth -= 1;
  for(i=0;i<num;++i)
    if (functionalDifference(op1->getIn(i),op2->getIn(i),depth))
      return true;
  return false;
}

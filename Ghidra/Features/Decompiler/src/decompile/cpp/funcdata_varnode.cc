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
#include "funcdata.hh"

// Funcdata members pertaining directly to varnodes

/// Properties of a given storage location are gathered from symbol information and
/// applied to the given Varnode.
/// \param vn is the given Varnode
void Funcdata::setVarnodeProperties(Varnode *vn) const

{
  if (!vn->isMapped()) {
  // One more chance to find entry, now that we know usepoint
    uint4 vflags=0;
    SymbolEntry *entry = localmap->queryProperties(vn->getAddr(),vn->getSize(),vn->getUsePoint(*this),vflags);
    if (entry != (SymbolEntry *)0) // Let entry try to force type
      vn->setSymbolProperties(entry);
    else
      vn->setFlags(vflags & ~Varnode::typelock); // typelock set by updateType
  }

  if (vn->cover == (Cover *)0) {
    if (isHighOn())
      vn->calcCover();
  }
}

/// If HighVariables are enabled, make sure the given Varnode has one assigned. Allocate
/// a dedicated HighVariable, that contains only the one Varnode if necessary.
/// \param vn is the given Varnode
/// \return the assigned HighVariable or NULL if one is not assigned
HighVariable *Funcdata::assignHigh(Varnode *vn)

{
  if ((flags & highlevel_on)!=0) {
    if (vn->hasCover())
      vn->calcCover();
    if (!vn->isAnnotation()) {
      return new HighVariable(vn);
    }
  }
  return (HighVariable *)0;
}

/// A Varnode is allocated which represents the indicated constant value.
/// Its storage address is in the \e constant address space.
/// \param s is the size of the Varnode in bytes
/// \param constant_val is the indicated constant value
/// \return the new Varnode object
Varnode *Funcdata::newConstant(int4 s,uintb constant_val)

{
  Datatype *ct = glb->types->getBase(s,TYPE_UNKNOWN);

  Varnode *vn = vbank.create(s,glb->getConstant(constant_val),ct);
  assignHigh(vn);

				// There is no chance of matching localmap
  return vn;
}

/// A new temporary register storage location is allocated from the \e unique
/// address space
/// \param s is the size of the Varnode in bytes
/// \param ct is an optional data-type to associated with the Varnode
/// \return the newly allocated \e temporary Varnode
Varnode *Funcdata::newUnique(int4 s,Datatype *ct)

{
  if (ct == (Datatype *)0)
    ct = glb->types->getBase(s,TYPE_UNKNOWN);
  Varnode *vn = vbank.createUnique(s,ct);
  assignHigh(vn);
  if (s >= minLanedSize)
    checkForLanedRegister(s, vn->getAddr());

				// No chance of matching localmap
  return vn;
}

/// Create a new Varnode which is already defined as output of a given PcodeOp.
/// This if more efficient as it avoids the initial insertion of the free form of the
/// Varnode into the tree, and queryProperties only needs to be called once.
/// \param s is the size of the new Varnode in bytes
/// \param m is the storage Address of the Varnode
/// \param op is the given PcodeOp whose output is created
/// \return the new Varnode object
Varnode *Funcdata::newVarnodeOut(int4 s,const Address &m,PcodeOp *op)

{
  Datatype *ct = glb->types->getBase(s,TYPE_UNKNOWN);
  Varnode *vn = vbank.createDef(s,m,ct,op);
  op->setOutput(vn);
  assignHigh(vn);

  if (s >= minLanedSize)
    checkForLanedRegister(s,m);
  uint4 vflags = 0;
  SymbolEntry *entry = localmap->queryProperties(m,s,op->getAddr(),vflags);
  if (entry != (SymbolEntry *)0)
    vn->setSymbolProperties(entry);
  else
    vn->setFlags(vflags & ~Varnode::typelock); // Typelock set by updateType

  return vn;
}

/// Allocate a new register from the \e unique address space and create a new
/// Varnode object representing it as an output to the given PcodeOp
/// \param s is the size of the new Varnode in bytes
/// \param op is the given PcodeOp whose output is created
/// \return the new temporary register Varnode
Varnode *Funcdata::newUniqueOut(int4 s,PcodeOp *op)

{
  Datatype *ct = glb->types->getBase(s,TYPE_UNKNOWN);
  Varnode *vn = vbank.createDefUnique(s,ct,op);
  op->setOutput(vn);
  assignHigh(vn);
  if (s >= minLanedSize)
    checkForLanedRegister(s, vn->getAddr());
  // No chance of matching localmap
  return vn;
}

/// \brief Create a new unattached Varnode object
///
/// \param s is the size of the new Varnode in bytes
/// \param m is the storage Address of the Varnode
/// \param ct is a data-type to associate with the Varnode
/// \return the newly allocated Varnode object
Varnode *Funcdata::newVarnode(int4 s,const Address &m,Datatype *ct)

{
  Varnode *vn;

  if (ct == (const Datatype *)0)
    ct = glb->types->getBase(s,TYPE_UNKNOWN);

  vn = vbank.create(s,m,ct);
  assignHigh(vn);

  if (s >= minLanedSize)
    checkForLanedRegister(s,m);
  uint4 vflags=0;
  SymbolEntry *entry = localmap->queryProperties(vn->getAddr(),vn->getSize(),Address(),vflags);
  if (entry != (SymbolEntry *)0)	// Let entry try to force type
    vn->setSymbolProperties(entry);
  else
    vn->setFlags(vflags & ~Varnode::typelock); // Typelock set by updateType

  return vn;
}

/// Create a special \e annotation Varnode that holds a pointer reference to a specific
/// PcodeOp.  This is used specifically to let a CPUI_INDIRECT op refer to the PcodeOp
/// it is holding an indirect effect for.
/// \param op is the PcodeOp to encode in the annotation
/// \return the newly allocated \e annotation Varnode
Varnode *Funcdata::newVarnodeIop(PcodeOp *op)

{
  Datatype *ct = glb->types->getBase(sizeof(op),TYPE_UNKNOWN);
  AddrSpace *cspc = glb->getIopSpace();
  Varnode *vn = vbank.create(sizeof(op),Address(cspc,(uintb)(uintp)op),ct);
  assignHigh(vn);
  return vn;
}

/// A reference to a particular address space is encoded as a constant Varnode.
/// These are used for LOAD and STORE p-code ops in particular.
/// \param spc is the address space to encode
/// \return the newly allocated constant Varnode
Varnode *Funcdata::newVarnodeSpace(AddrSpace *spc)

{
  Datatype *ct = glb->types->getBase(sizeof(spc),TYPE_UNKNOWN);

  Varnode *vn = vbank.create(sizeof(spc),glb->createConstFromSpace(spc),ct);
  assignHigh(vn);
  return vn;
}

/// A call specification (FuncCallSpecs) is encoded into an \e annotation Varnode.
/// The Varnode is used specifically as an input to CPUI_CALL ops to speed up access
/// to their associated call specification.
/// \param fc is the call specification to encode
/// \return the newly allocated \e annotation Varnode
Varnode *Funcdata::newVarnodeCallSpecs(FuncCallSpecs *fc)

{
  Datatype *ct = glb->types->getBase(sizeof(fc),TYPE_UNKNOWN);

  AddrSpace *cspc = glb->getFspecSpace();
  Varnode *vn = vbank.create(sizeof(fc),Address(cspc,(uintb)(uintp)fc),ct);
  assignHigh(vn);
  return vn;
}

/// A reference to a specific Address is encoded in a Varnode.  The Varnode is
/// an \e annotation in the sense that it will hold no value in the data-flow, it will
/// will only hold a reference to an address. This is used specifically by the branch
/// p-code operations to hold destination addresses.
/// \param m is the Address to encode
/// \return the newly allocated \e annotation Varnode
Varnode *Funcdata::newCodeRef(const Address &m)

{
  Varnode *vn;
  Datatype *ct;

  ct = glb->types->getTypeCode();
  vn = vbank.create(1,m,ct);
  vn->setFlags(Varnode::annotation);
  assignHigh(vn);
  return vn;
}

/// \param s is the size of the Varnode in bytes
/// \param base is the address space of the Varnode
/// \param off is the offset into the address space of the Varnode
/// \return the newly allocated Varnode
Varnode *Funcdata::newVarnode(int4 s,AddrSpace *base,uintb off)

{
  Varnode *vn;

  vn = newVarnode(s,Address(base,off));

  return vn;
}

/// Internal factory for copying Varnodes from another Funcdata object into \b this.
/// \param vn is the Varnode to clone
/// \return the cloned Varnode (contained by \b this)
Varnode *Funcdata::cloneVarnode(const Varnode *vn)

{
  Varnode *newvn;

  newvn = vbank.create(vn->getSize(),vn->getAddr(),vn->getType());
  uint4 vflags = vn->getFlags();
  // These are the flags we allow to be cloned
  vflags &= (Varnode::annotation | Varnode::externref |
	     Varnode::readonly | Varnode::persist |
	     Varnode::addrtied | Varnode::addrforce |
	     Varnode::indirect_creation | Varnode::incidental_copy |
	     Varnode::volatil | Varnode::mapped);
  newvn->setFlags(vflags);
  return newvn;
}

/// References to the Varnode are replaced with NULL pointers and the object is freed,
/// with no possibility of resuse.
/// \param vn is the Varnode to delete
void Funcdata::destroyVarnode(Varnode *vn)

{
  list<PcodeOp *>::const_iterator iter;

  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
#ifdef OPACTION_DEBUG
    if (opactdbg_active)
      debugModCheck(op);
#endif
    op->clearInput(op->getSlot(vn));
  }
  if (vn->def != (PcodeOp *)0) {
    vn->def->setOutput((Varnode *)0);
    vn->def = (PcodeOp *)0;
  }

  vn->destroyDescend();
  vbank.destroy(vn);
}

/// Check if the given storage range is a potential laned register.
/// If so, record the storage with the matching laned register record.
/// \param size is the size of the storage range in bytes
/// \param addr is the starting address of the storage range
void Funcdata::checkForLanedRegister(int4 size,const Address &addr)

{
  const LanedRegister *lanedRegister  = glb->getLanedRegister(addr,size);
  if (lanedRegister == (const LanedRegister *)0)
    return;
  VarnodeData storage;
  storage.space = addr.getSpace();
  storage.offset = addr.getOffset();
  storage.size = size;
  lanedMap[storage] = lanedRegister;
}

/// Look up the Symbol visible in \b this function's Scope and return the HighVariable
/// associated with it.  If the Symbol doesn't exist or there is no Varnode holding at least
/// part of the value of the Symbol, NULL is returned.
/// \param name is the name to search for
/// \return the matching HighVariable or NULL
HighVariable *Funcdata::findHigh(const string &name) const

{
  vector<Symbol *> symList;
  localmap->queryByName(name,symList);
  if (symList.empty()) return (HighVariable *)0;
  Symbol *sym = symList[0];
  Varnode *vn = findLinkedVarnode(sym->getFirstWholeMap());
  if (vn != (Varnode *)0)
    return vn->getHigh();

  return (HighVariable *)0;
}

/// An \e input Varnode has a special designation within SSA form as not being defined
/// by a p-code operation and is a formal input to the data-flow of the function.  It is
/// not necessarily a formal function parameter.
///
/// The given Varnode to be marked is also returned unless there is an input Varnode that
/// already exists which overlaps the given Varnode.  If the Varnodes have the same size and
/// storage address, the preexisting input Varnode is returned instead. Otherwise an
/// exception is thrown.
/// \param vn is the given Varnode to mark as an input
/// \return the marked Varnode
Varnode *Funcdata::setInputVarnode(Varnode *vn)

{
  Varnode *invn;

  if (vn->isInput()) return vn;	// Already an input
				// First we check if it overlaps any other varnode
  VarnodeDefSet::const_iterator iter;
  iter = vbank.beginDef(Varnode::input,vn->getAddr()+vn->getSize());

  // Iter points at first varnode AFTER vn
  if (iter != vbank.beginDef()) {
    --iter;			// previous varnode
    invn = *iter;	  	// comes before vn or intersects
    if (invn->isInput()) {
      if ((-1 != vn->overlap(*invn))||(-1 != invn->overlap(*vn))) {
	if ((vn->getSize() == invn->getSize())&&(vn->getAddr() == invn->getAddr()))
	  return invn;
	throw LowlevelError("Overlapping input varnodes");
      }
    }
  }

  vn = vbank.setInput(vn);
  setVarnodeProperties(vn);
  uint4 effecttype = funcp.hasEffect(vn->getAddr(),vn->getSize());
  if (effecttype == EffectRecord::unaffected)
    vn->setUnaffected();
  if (effecttype == EffectRecord::return_address) {
    vn->setUnaffected();	// Should be unaffected over the course of the function
    vn->setReturnAddress();
  }
  return vn;
}

/// \brief Adjust input Varnodes contained in the given range
///
/// After this call, a single \e input Varnode will exist that fills the given range.
/// Any previous input Varnodes contained in this range are redefined using a SUBPIECE
/// op off of the new single input.  If an overlapping Varnode isn't fully contained
/// an exception is thrown.
/// \param addr is the starting address of the range
/// \param size is the number of bytes in the range
void Funcdata::adjustInputVarnodes(const Address &addr,int4 size)

{
  Address endaddr = addr + (size-1);
  vector<Varnode *> inlist;
  VarnodeDefSet::const_iterator iter,enditer;
  iter = vbank.beginDef(Varnode::input,addr);
  enditer = vbank.endDef(Varnode::input,endaddr);
  while(iter != enditer) {
    Varnode *vn = *iter;
    ++iter;
    if (vn->getOffset() + (vn->getSize()-1) > endaddr.getOffset())
      throw LowlevelError("Cannot properly adjust input varnodes");
    inlist.push_back(vn);
  }

  for(uint4 i=0;i<inlist.size();++i) {
    Varnode *vn = inlist[i];
    int4 sa = addr.justifiedContain(size,vn->getAddr(),vn->getSize(),false);
    if ((!vn->isInput())||(sa < 0)||(size<=vn->getSize()))
      throw LowlevelError("Bad adjustment to input varnode");
    PcodeOp *subop = newOp(2,getAddress());
    opSetOpcode(subop,CPUI_SUBPIECE);
    opSetInput(subop,newConstant(4,sa),1);
    Varnode *newvn = newVarnodeOut(vn->getSize(),vn->getAddr(),subop);
    // newvn must not be free in order to give all vn's descendants
    opInsertBegin(subop,(BlockBasic *)bblocks.getBlock(0));
    totalReplace(vn,newvn);
    deleteVarnode(vn); // Get rid of old input before creating new input
    inlist[i] = newvn;
  }
  // Now that all the intersecting inputs have been pulled out, we can create the new input
  Varnode *invn = newVarnode(size,addr);
  invn = setInputVarnode(invn);
  // The new input may cause new heritage and "Heritage AFTER dead removal" errors
  // So tell heritage to ignore it
  // FIXME: It would probably be better to insert this directly into heritage's globaldisjoint
  invn->setWriteMask();
  // Now change all old inputs to be created as SUBPIECE from the new input
  for(uint4 i=0;i<inlist.size();++i) {
    PcodeOp *op = inlist[i]->getDef();
    opSetInput(op,invn,0);
  }
}

/// All p-code ops that read the Varnode are transformed so that they read
/// a special constant instead (associate with unreachable block removal).
/// \param vn is the given Varnode
/// \return \b true if a PcodeOp is modified
bool Funcdata::descend2Undef(Varnode *vn)

{
  PcodeOp *op,*copyop;
  BlockBasic *inbl;
  Varnode *badconst;
  list<PcodeOp *>::const_iterator iter;
  int4 i,size;
  bool res;

  res = false;
  size = vn->getSize();
  iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    op = *iter++;		// Move to next in list before deletion
    if (op->getParent()->isDead()) continue;
    if (op->getParent()->sizeIn()!=0) res = true;
    i = op->getSlot(vn);
    badconst = newConstant(size,0xBADDEF);
    if (op->code()==CPUI_MULTIEQUAL) { // Cannot put constant directly into MULTIEQUAL
      inbl = (BlockBasic *) op->getParent()->getIn(i);
      copyop = newOp(1,inbl->getStart());
      Varnode *inputvn = newUniqueOut(size,copyop);
      opSetOpcode(copyop,CPUI_COPY);
      opSetInput(copyop,badconst,0);
      opInsertEnd(copyop,inbl);
      opSetInput(op,inputvn,i);
    }
    else if (op->code()==CPUI_INDIRECT) { // Cannot put constant directly into INDIRECT
      copyop = newOp(1,op->getAddr());
      Varnode *inputvn = newUniqueOut(size,copyop);
      opSetOpcode(copyop,CPUI_COPY);
      opSetInput(copyop,badconst,0);
      opInsertBefore(copyop,op);
      opSetInput(op,inputvn,i);
    }
    else
      opSetInput(op,badconst,i);
  }
  return res;
}

void Funcdata::initActiveOutput(void)

{
  activeoutput = new ParamActive(false);
  int4 maxdelay = funcp.getMaxOutputDelay();
  if (maxdelay > 0)
    maxdelay = 3;
  activeoutput->setMaxPass(maxdelay);
}

void Funcdata::setHighLevel(void)

{
  if ((flags & highlevel_on)!=0) return;
  flags |= highlevel_on;
  high_level_index = vbank.getCreateIndex();
  VarnodeLocSet::const_iterator iter;

  for(iter=vbank.beginLoc();iter!=vbank.endLoc();++iter)
    assignHigh(*iter);
}

/// \brief Copy properties from an existing Varnode to a new Varnode
///
/// The new Varnode is assumed to overlap the storage of the existing Varnode.
/// Properties like boolean flags and \e consume bits are copied as appropriate.
/// \param vn is the existing Varnode
/// \param newVn is the new Varnode that has its properties set
/// \param lsbOffset is the significance offset of the new Varnode within the exising
void Funcdata::transferVarnodeProperties(Varnode *vn,Varnode *newVn,int4 lsbOffset)

{
  uintb newConsume = (vn->getConsume() >> 8*lsbOffset) & calc_mask(newVn->getSize());

  uint4 vnFlags = vn->getFlags() & (Varnode::directwrite|Varnode::addrforce);

  newVn->setFlags(vnFlags);	// Preserve addrforce setting
  newVn->setConsume(newConsume);
}

/// Treat the given Varnode as read-only, look up its value in LoadImage
/// and replace read references with the value as a constant Varnode.
/// \param vn is the given Varnode
/// \return \b true if any change was made
bool Funcdata::fillinReadOnly(Varnode *vn)

{
  if (vn->isWritten()) {	// Can't replace output with constant
    PcodeOp *defop = vn->getDef();
    if (defop->isMarker())
      defop->setAdditionalFlag(PcodeOp::warning);	// Not a true write, ignore it
    else if (!defop->isWarning()) { // No warning generated before
      defop->setAdditionalFlag(PcodeOp::warning);
      ostringstream s;
      if ((!vn->isAddrForce())||(!vn->hasNoDescend())) {
	s << "Read-only address (";
	s << vn->getSpace()->getName();
	s << ',';
	vn->getAddr().printRaw(s);
	s << ") is written";
	warning(s.str(),defop->getAddr());
      }
    }
    return false;		// No change was made
  }

  if (vn->getSize() > sizeof(uintb))
    return false;		// Constant will exceed precision

  uintb res;
  uint1 bytes[32];
  try {
    glb->loader->loadFill(bytes,vn->getSize(),vn->getAddr());
  } catch(DataUnavailError &err) { // Could not get value from LoadImage
    vn->clearFlags(Varnode::readonly); // Treat as writeable
    return true;
  }

  if (vn->getSpace()->isBigEndian()) { // Big endian
    res = 0;
    for(int4 i=0;i<vn->getSize();++i) {
      res <<= 8;
      res |= bytes[i];
    }
  }
  else {
    res = 0;
    for(int4 i=vn->getSize()-1;i>=0;--i) {
      res <<= 8;
      res |= bytes[i];
    }
  }
				// Replace all references to vn
  bool changemade = false;
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  int4 i;
  Datatype *locktype = vn->isTypeLock() ? vn->getType() : (Datatype *)0;

  iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    op = *iter++;
    i = op->getSlot(vn);
    if (op->isMarker()) {		// Must be careful putting constants in here
      if ((op->code()!=CPUI_INDIRECT)||(i!=0)) continue;
      Varnode *outvn = op->getOut();
      if (outvn->getAddr() == vn->getAddr()) continue; // Ignore indirect to itself
      // Change the indirect to a COPY
      opRemoveInput(op,1);
      opSetOpcode(op,CPUI_COPY);
    }
    Varnode *cvn = newConstant(vn->getSize(),res);
    if (locktype != (Datatype *)0)
      cvn->updateType(locktype,true,true); // Try to pass on the locked datatype
    opSetInput(op,cvn,i);
    changemade = true;
  }
  return changemade;
}

/// The Varnode is assumed not fully linked.  The read or write action is
/// modeled by inserting a special \e user op that represents the action. The given Varnode is
/// replaced by a temporary Varnode within the data-flow, and the original address becomes
/// a parameter to the user op.
/// \param vn is the given Varnode to model as volatile
/// \return \b true if a change was made
bool Funcdata::replaceVolatile(Varnode *vn)

{
  PcodeOp *newop;
  if (vn->isWritten()) {	// A written value
    VolatileWriteOp *vw_op = glb->userops.getVolatileWrite();
    if (!vn->hasNoDescend()) throw LowlevelError("Volatile memory was propagated");
    PcodeOp *defop = vn->getDef();
    newop = newOp(3,defop->getAddr());
    opSetOpcode(newop,CPUI_CALLOTHER);
    // Create a userop of type specified by vw_op
    opSetInput(newop,newConstant(4,vw_op->getIndex()),0);
    // The first parameter is the offset of volatile memory location
    opSetInput(newop,newCodeRef(vn->getAddr()),1);
    // Replace the volatile variable with a temp
    Varnode *tmp = newUnique(vn->getSize());
    opSetOutput(defop,tmp);
    // The temp is the second parameter to the userop
    opSetInput(newop,tmp,2);
    opInsertAfter(newop,defop); // Insert after defining op
  }
  else {			// A read value
    VolatileReadOp *vr_op = glb->userops.getVolatileRead();
    if (vn->hasNoDescend()) return false; // Dead
    PcodeOp *readop = vn->loneDescend();
    if (readop == (PcodeOp *)0)
      throw LowlevelError("Volatile memory value used more than once");
    newop = newOp(2,readop->getAddr());
    opSetOpcode(newop,CPUI_CALLOTHER);
    // Create a temp to replace the volatile variable
    Varnode *tmp = newUniqueOut(vn->getSize(),newop);
    // Create a userop of type specified by vr_op
    opSetInput(newop,newConstant(4,vr_op->getIndex()),0);
    // The first parameter is the offset of the volatile memory loc
    opSetInput(newop,newCodeRef(vn->getAddr()),1);
    opSetInput(readop,tmp,readop->getSlot(vn));
    opInsertBefore(newop,readop); // Insert before read
  }
  if (vn->isTypeLock())		// If the original varnode had a type locked on it
    newop->setAdditionalFlag(PcodeOp::special_prop); // Mark this op as doing special propagation
  return true;
}

/// \brief Check if the given Varnode only flows into call-based INDIRECT ops
///
/// Flow is only followed through MULTIEQUAL ops.
/// \param vn is the given Varnode
/// \return \b true if all flows hit an INDIRECT op
bool Funcdata::checkIndirectUse(Varnode *vn)

{
  vector<Varnode *> vlist;
  int4 i = 0;
  vlist.push_back(vn);
  vn->setMark();
  bool result = true;
  while((i<vlist.size())&&result) {
    vn = vlist[i++];
    list<PcodeOp *>::const_iterator iter;
    for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      PcodeOp *op = *iter;
      OpCode opc = op->code();
      if (opc == CPUI_INDIRECT) {
	if (op->isIndirectStore()) {
	  // INDIRECT from a STORE is not a negative result but continue to follow data-flow
	  Varnode *outvn = op->getOut();
	  if (!outvn->isMark()) {
	    vlist.push_back(outvn);
	    outvn->setMark();
	  }
	}
      }
      else if (opc == CPUI_MULTIEQUAL) {
	Varnode *outvn = op->getOut();
	if (!outvn->isMark()) {
	  vlist.push_back(outvn);
	  outvn->setMark();
	}
      }
      else {
	result = false;
	break;
      }
    }
  }
  for(i=0;i<vlist.size();++i)
    vlist[i]->clearMark();
  return result;
}

/// The illegal inputs are additionally marked as \b indirectonly and
/// isIndirectOnly() returns \b true.
void Funcdata::markIndirectOnly(void)

{
  VarnodeDefSet::const_iterator iter,enditer;

  iter = beginDef(Varnode::input);
  enditer = endDef(Varnode::input);
  for(;iter!=enditer;++iter) {	// Loop over all inputs
    Varnode *vn = *iter;
    if (!vn->isIllegalInput()) continue; // Only check illegal inputs
    if (checkIndirectUse(vn))
      vn->setFlags(Varnode::indirectonly);
  }
}

/// Free any Varnodes not attached to anything. This is only performed at fixed times so that
/// editing operations can detach (and then reattach) Varnodes without losing them.
void Funcdata::clearDeadVarnodes(void)

{
  VarnodeLocSet::const_iterator iter;
  Varnode *vn;

  iter = vbank.beginLoc();
  while(iter!=vbank.endLoc()) {
    vn = *iter++;
    if (vn->hasNoDescend()) {
      if (vn->isInput() && !vn->isLockedInput()) {
	vbank.makeFree(vn);
	vn->clearCover();
      }
      if (vn->isFree())
	vbank.destroy(vn);
    }
  }
}

/// All Varnodes are initialized assuming that all its bits are possibly non-zero. This method
/// looks for situations where a p-code produces a value that is known to have some bits that are
/// guaranteed to be zero.  It updates the state of the output Varnode then tries to push the
/// information forward through the data-flow until additional changes are apparent.
void Funcdata::calcNZMask(void)

{
  vector<PcodeOpNode> opstack;
  list<PcodeOp *>::const_iterator oiter;

  for(oiter=beginOpAlive();oiter!=endOpAlive();++oiter) {
    PcodeOp *op = *oiter;
    if (op->isMark()) continue;
    opstack.push_back(PcodeOpNode(op,0));
    op->setMark();

    do {
      // Get next edge
      PcodeOpNode &node( opstack.back() );
      if (node.slot >= node.op->numInput()) { // If no edge left
	Varnode *outvn = node.op->getOut();
	if (outvn != (Varnode *)0) {
	  outvn->nzm = node.op->getNZMaskLocal(true);
	}
	opstack.pop_back();	// Pop a level
	continue;
      }
      int4 oldslot = node.slot;
      node.slot += 1; // Advance to next input
      // Determine if we want to traverse this edge
      if (node.op->code() == CPUI_MULTIEQUAL) {
	if (node.op->getParent()->isLoopIn(oldslot)) // Clip looping edges
	  continue;
      }
      // Traverse edge indicated by slot
      Varnode *vn = node.op->getIn(oldslot);
      if (!vn->isWritten()) {
	if (vn->isConstant())
	  vn->nzm = vn->getOffset();
	else {
	  vn->nzm = calc_mask(vn->getSize());
	  if (vn->isSpacebase())
	    vn->nzm &= ~((uintb)0xff); // Treat spacebase input as aligned
	}
      }
      else if (!vn->getDef()->isMark()) { // If haven't traversed before
	opstack.push_back(PcodeOpNode(vn->getDef(),0));
	vn->getDef()->setMark();
      }
    } while(!opstack.empty());
  }

  vector<PcodeOp *> worklist;
  // Clear marks and push ops with looping edges onto worklist
  for(oiter=beginOpAlive();oiter!=endOpAlive();++oiter) {
    PcodeOp *op = *oiter;
    op->clearMark();
    if (op->code() == CPUI_MULTIEQUAL)
      worklist.push_back(op);
  }

  // Continue to propagate changes along all edges
  while(!worklist.empty()) {
    PcodeOp *op = worklist.back();
    worklist.pop_back();
    Varnode *vn = op->getOut();
    if (vn == (Varnode *)0) continue;
    uintb nzmask = op->getNZMaskLocal(false);
    if (nzmask != vn->nzm) {
      vn->nzm = nzmask;
      for(oiter=vn->beginDescend();oiter!=vn->endDescend();++oiter)
	worklist.push_back(*oiter);
    }
  }
}

/// \brief Update Varnode properties based on (new) Symbol information
///
/// Boolean properties \b addrtied, \b addrforce, and \b nolocalalias
/// for Varnodes are updated based on new Symbol information they map to.
/// The caller can elect to update data-type information as well, where Varnodes
/// and their associated HighVariables have their data-type finalized based symbols.
/// \param lm is the Symbol scope within which to search for mapped Varnodes
/// \param typesyes is \b true if the caller wants to update data-types
/// \return \b true if any Varnode was updated
bool Funcdata::syncVarnodesWithSymbols(const ScopeLocal *lm,bool typesyes)

{
  bool updateoccurred = false;
  VarnodeLocSet::const_iterator iter,enditer;
  Datatype *ct;
  SymbolEntry *entry;
  uint4 flags;

  iter = vbank.beginLoc(lm->getSpaceId());
  enditer = vbank.endLoc(lm->getSpaceId());
  while(iter != enditer) {
    Varnode *vnexemplar = *iter;
    entry = lm->findOverlap(vnexemplar->getAddr(),vnexemplar->getSize());
    ct = (Datatype *)0;
    if (entry != (SymbolEntry *)0) {
      flags = entry->getAllFlags();
      if (entry->getSize() >= vnexemplar->getSize()) {
	if (typesyes) {
	  uintb off = (vnexemplar->getOffset() - entry->getAddr().getOffset()) + entry->getOffset();
	  Datatype *cur = entry->getSymbol()->getType();
	  do {
	    ct = cur;
	    cur = cur->getSubType(off,&off);
	  } while(cur != (Datatype *)0);
	  if ((ct->getSize() != vnexemplar->getSize())||(ct->getMetatype() == TYPE_UNKNOWN))
	    ct = (Datatype *)0;
	}
      }
      else { // Overlapping but not containing
	// This is usual indicative of a small locked symbol
	// getting put in a bigger register
	// Don't try to figure out type
	// Don't keep typelock and namelock
	flags &= ~((uint4)(Varnode::typelock|Varnode::namelock));
	// we do particularly want to keep the nolocalalias
      }
    }
    else { // Could not find any symbol
      if (lm->inScope(vnexemplar->getAddr(),vnexemplar->getSize(),
		      vnexemplar->getUsePoint(*this))) {
	// This is technically an error, there should be some
	// kind of symbol, if we are in scope
	flags = Varnode::mapped | Varnode::addrtied;
      }
      else
	flags = 0;
    }
    if (syncVarnodesWithSymbol(iter,flags,ct))
	updateoccurred = true;
  }
  return updateoccurred;
}

/// A Varnode overlaps the given SymbolEntry.  Make sure the Varnode is part of the variable
/// underlying the Symbol.  If not, remap things so that the Varnode maps to a distinct Symbol.
/// In either case, attach the appropriate Symbol to the Varnode
/// \param entry is the given SymbolEntry
/// \param vn is the overlapping Varnode
/// \return the Symbol attached to the Varnode
Symbol *Funcdata::handleSymbolConflict(SymbolEntry *entry,Varnode *vn)

{
  if (vn->isInput() || vn->isAddrTied() ||
      vn->isPersist() || vn->isConstant() || entry->isDynamic()) {
    vn->setSymbolEntry(entry);
    return entry->getSymbol();
  }
  HighVariable *high = vn->getHigh();
  Varnode *otherVn;
  HighVariable *otherHigh = (HighVariable *)0;
  // Look for a conflicting HighVariable
  VarnodeLocSet::const_iterator iter = beginLoc(entry->getSize(),entry->getAddr());
  while(iter != endLoc()) {
    otherVn = *iter;
    if (otherVn->getSize() != entry->getSize()) break;
    if (otherVn->getAddr() != entry->getAddr()) break;
    HighVariable *tmpHigh = otherVn->getHigh();
    if (tmpHigh != high) {
      otherHigh = tmpHigh;
      break;
    }
    ++iter;
  }
  if (otherHigh == (HighVariable *)0) {
    vn->setSymbolEntry(entry);
    return entry->getSymbol();
  }

  // If we reach here, we have a conflicting variable
  buildDynamicSymbol(vn);
  return vn->getSymbolEntry()->getSymbol();
}

/// \brief Update properties (and the data-type) for a set of Varnodes associated with one Symbol
///
/// The set of Varnodes with the same size and address all have their boolean properties
/// updated to the given values. The set is specified by providing an iterator reference
/// to the first Varnode in the set assuming a 'loc' ordering. This iterator is updated
/// to point to the first Varnode after the affected set.
///
/// The only properties that can be effectively changed with this
/// routine are \b mapped, \b addrtied, \b addrforce, and \b nolocalalias.
/// HighVariable splits must occur if \b addrtied is cleared.
///
/// If the given data-type is non-null, an attempt is made to update all the Varnodes
/// to this data-type. The \b typelock and \b namelock properties cannot be changed here.
/// \param iter points to the first Varnode in the set
/// \param flags holds the new set of boolean properties
/// \param ct is the given data-type to set (or NULL)
/// \return \b true if at least one Varnode was modified
bool Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator &iter,uint4 flags,Datatype *ct)

{
  VarnodeLocSet::const_iterator enditer;
  Varnode *vn;
  uint4 vnflags;
  bool updateoccurred = false;
				// These are the flags we are going to try to update
  uint4 mask = Varnode::mapped;
				// We take special care with the addrtied flag
				// as we cannot set it here if it is clear
				// We can CLEAR but not SET the addrtied flag
				// If addrtied is cleared, so should addrforce
  if ((flags&Varnode::addrtied)==0) // Is the addrtied flags cleared
    mask |= Varnode::addrtied | Varnode::addrforce;
  // We can set the nolocalalias flag, but not clear it
  // If nolocalalias is set, then addrforce should be cleared
  if ((flags&Varnode::nolocalalias)!=0)
    mask |= Varnode::nolocalalias | Varnode::addrforce;
  flags &= mask;

  vn = *iter;
  enditer = vbank.endLoc(vn->getSize(),vn->getAddr());
  do {
    vn = *iter++;
    if (vn->isFree()) continue;
    vnflags = vn->getFlags();
    if (vn->mapentry != (SymbolEntry *)0) {		// If there is already an attached SymbolEntry (dynamic)
      uint4 localMask = mask & ~Varnode::mapped;	// Make sure 'mapped' bit is unchanged
      uint4 localFlags = flags & localMask;
      if ((vnflags & localMask) != localFlags) {
	updateoccurred = true;
	vn->setFlags(localFlags);
	vn->clearFlags((~localFlags)&localMask);
      }
    }
    else if ((vnflags & mask) != flags) { // We have a change
      updateoccurred = true;
      vn->setFlags(flags);
      vn->clearFlags((~flags)&mask);
    }
    if (ct != (Datatype *)0) {
      if (vn->updateType(ct,false,false))
	updateoccurred = true;
      vn->getHigh()->finalizeDatatype(ct);	// Permanently set the data-type on the HighVariable
    }
  } while(iter != enditer);
  return updateoccurred;
}

/// For each instance Varnode, remove any SymbolEntry reference and associated properties.
/// \param high is the given HighVariable to clear
void Funcdata::clearSymbolLinks(HighVariable *high)

{
  for(int4 i=0;i<high->numInstances();++i) {
    Varnode *vn = high->getInstance(i);
    vn->mapentry = (SymbolEntry *)0;
    vn->clearFlags(Varnode::namelock | Varnode::typelock | Varnode::mapped);
  }
}

/// \brief Remap a Symbol to a given Varnode using a static mapping
///
/// Any previous links between the Symbol, the Varnode, and the associate HighVariable are
/// removed.  Then a new link is created.
/// \param vn is the given Varnode
/// \param sym is the Symbol the Varnode maps to
/// \param usepoint is the desired usepoint for the mapping
void Funcdata::remapVarnode(Varnode *vn,Symbol *sym,const Address &usepoint)

{
  clearSymbolLinks(vn->getHigh());
  SymbolEntry *entry = localmap->remapSymbol(sym, vn->getAddr(), usepoint);
  vn->setSymbolEntry(entry);
}

/// \brief Remap a Symbol to a given Varnode using a new dynamic mapping
///
/// Any previous links between the Symbol, the Varnode, and the associate HighVariable are
/// removed.  Then a new dynamic link is created.
/// \param vn is the given Varnode
/// \param sym is the Symbol the Varnode maps to
/// \param usepoint is the code Address where the Varnode is defined
/// \param hash is the hash for the new dynamic mapping
void Funcdata::remapDynamicVarnode(Varnode *vn,Symbol *sym,const Address &usepoint,uint8 hash)

{
  clearSymbolLinks(vn->getHigh());
  SymbolEntry *entry = localmap->remapSymbolDynamic(sym, hash, usepoint);
  vn->setSymbolEntry(entry);
}

/// The Symbol is really attached to the Varnode's HighVariable (which must exist).
/// The only reason a Symbol doesn't get set is if, the HighVariable
/// is global and there is no pre-existing Symbol.  (see mapGlobals())
/// \param vn is the given Varnode
/// \return the associated Symbol or NULL
Symbol *Funcdata::linkSymbol(Varnode *vn)

{
  HighVariable *high = vn->getHigh();
  SymbolEntry *entry;
  uint4 flags = 0;
  Symbol *sym = high->getSymbol();
  if (sym != (Symbol *)0) return sym; // Symbol already assigned

  Address usepoint = vn->getUsePoint(*this);
  // Find any entry overlapping base address
  entry = localmap->queryProperties(vn->getAddr(), 1, usepoint, flags);
  if (entry != (SymbolEntry *) 0) {
    sym = handleSymbolConflict(entry, vn);
  }
  else {			// Must create a symbol entry
    if (!vn->isPersist()) {	// Only create local symbol
      entry = localmap->addSymbol("", high->getType(), vn->getAddr(), usepoint);
      sym = entry->getSymbol();
      vn->setSymbolEntry(entry);
    }
  }

  return sym;
}

/// A reference to a symbol (i.e. &varname) is typically stored as a PTRSUB operation, where the
/// first input Varnode is a \e spacebase Varnode indicating whether the symbol is on the \e stack or at
/// a \e global RAM location.  The second input Varnode is a constant encoding the address of the symbol.
/// This method takes this constant Varnode, recovers the symbol it is referring to, and stores
/// on the HighVariable object attached to the Varnode.
/// \param vn is the constant Varnode (second input) to a PTRSUB operation
/// \return the symbol being referred to or null
Symbol *Funcdata::linkSymbolReference(Varnode *vn)

{
  PcodeOp *op = vn->loneDescend();
  Varnode *in0 = op->getIn(0);
  TypePointer *ptype = (TypePointer *)in0->getHigh()->getType();
  if (ptype->getMetatype() != TYPE_PTR) return (Symbol *)0;
  TypeSpacebase *sb = (TypeSpacebase *)ptype->getPtrTo();
  if (sb->getMetatype() != TYPE_SPACEBASE)
      return (Symbol *)0;
  Scope *scope = sb->getMap();
  Address addr = sb->getAddress(vn->getOffset(),in0->getSize(),op->getAddr());
  if (addr.isInvalid())
    throw LowlevelError("Unable to generate proper address from spacebase");
  SymbolEntry *entry = scope->queryContainer(addr,1,Address());
  if (entry == (SymbolEntry *)0)
    return (Symbol *)0;
  int4 off = (int4)(addr.getOffset() - entry->getAddr().getOffset()) + entry->getOffset();
  vn->setSymbolReference(entry, off);
  return entry->getSymbol();
}

/// Return the (first) Varnode that matches the given SymbolEntry
/// \param entry is the given SymbolEntry
/// \return a matching Varnode or null
Varnode *Funcdata::findLinkedVarnode(SymbolEntry *entry) const

{
  if (entry->isDynamic()) {
    DynamicHash dhash;
    Varnode *vn = dhash.findVarnode(this, entry->getFirstUseAddress(), entry->getHash());
    if (vn == (Varnode *)0 || vn->isAnnotation())
      return (Varnode *)0;
    return vn;
  }

  VarnodeLocSet::const_iterator iter,enditer;
  Address usestart = entry->getFirstUseAddress();
  enditer = vbank.endLoc(entry->getSize(),entry->getAddr());

  if (usestart.isInvalid()) {
    iter = vbank.beginLoc(entry->getSize(),entry->getAddr());
    if (iter == enditer)
      return (Varnode *)0;
    Varnode *vn = *iter;
    if (!vn->isAddrTied())
      return (Varnode *)0;	// Varnode(s) must be address tied in order to match this symbol
    return vn;
  }
  iter = vbank.beginLoc(entry->getSize(),entry->getAddr(),usestart,~((uintm)0));
  // TODO: Use a better end iterator
  for(;iter!=enditer;++iter) {
    Varnode *vn = *iter;
    Address usepoint = vn->getUsePoint(*this);
    if (entry->inUse(usepoint))
      return vn;
  }
  return (Varnode *)0;
}

/// Look for Varnodes that are (should be) mapped to the given SymbolEntry and
/// add them to the end of the result list.
/// \param entry is the given SymbolEntry to match
/// \param res is the container holding the result list of matching Varnodes
void Funcdata::findLinkedVarnodes(SymbolEntry *entry,vector<Varnode *> &res) const

{
  if (entry->isDynamic()) {
    DynamicHash dhash;
    Varnode *vn = dhash.findVarnode(this,entry->getFirstUseAddress(),entry->getHash());
    if (vn != (Varnode *)0)
      res.push_back(vn);
  }
  else {
    VarnodeLocSet::const_iterator iter = beginLoc(entry->getSize(),entry->getAddr());
    VarnodeLocSet::const_iterator enditer = endLoc(entry->getSize(),entry->getAddr());
    for(;iter!=enditer;++iter) {
      Varnode *vn = *iter;
      Address addr = vn->getUsePoint(*this);
      if (entry->inUse(addr)) {
	res.push_back(vn);
      }
    }
  }
}

/// If a Symbol is already attached, no change is made. Otherwise a special \e dynamic Symbol is
/// created that is associated with the Varnode via a hash of its local data-flow (rather
/// than its storage address).
/// \param vn is the given Varnode
void Funcdata::buildDynamicSymbol(Varnode *vn)

{
  if (vn->isTypeLock()||vn->isNameLock())
    throw RecovError("Trying to build dynamic symbol on locked varnode");
  if (!isHighOn())
    throw RecovError("Cannot create dynamic symbols until decompile has completed");
  HighVariable *high = vn->getHigh();
  if (high->getSymbol() != (Symbol *)0)
    return;			// Symbol already exists
  DynamicHash dhash;

  dhash.uniqueHash(vn,this);	// Calculate a unique dynamic hash for this varnode
  if (dhash.getHash() == 0)
    throw RecovError("Unable to find unique hash for varnode");

  Symbol *sym = localmap->addDynamicSymbol("",high->getType(),dhash.getAddress(),dhash.getHash());
  vn->setSymbolEntry(sym->getFirstWholeMap());
}

/// \brief Map properties of a dynamic symbol to a Varnode
///
/// Given a dynamic mapping, try to find the mapped Varnode, then adjust (type and flags)
/// to reflect this mapping.
/// \param entry is the (dynamic) Symbol entry
/// \param dhash is the dynamic mapping information
/// \return \b true if a Varnode was adjusted
bool Funcdata::attemptDynamicMapping(SymbolEntry *entry,DynamicHash &dhash)

{
  Symbol *sym = entry->getSymbol();
  if (sym->getScope() != localmap)
    throw LowlevelError("Cannot currently have a dynamic symbol outside the local scope");
  dhash.clear();
  Varnode *vn = dhash.findVarnode(this,entry->getFirstUseAddress(),entry->getHash());
  if (vn == (Varnode *)0) return false;
  if (entry->getSymbol()->getCategory() == 1) {	// Is this an equate symbol
    if (vn->mapentry != entry) {		// Check we haven't marked this before
      vn->setSymbolEntry(entry);
      return true;
    }
  }
  else if (entry->getSize() == vn->getSize()) {
    if (vn->setSymbolProperties(entry))
      return true;
  }
  return false;
}

/// \brief Map the name of a dynamic symbol to a Varnode
///
/// Given a dynamic mapping, try to find the mapped Varnode, then attach the Symbol to the Varnode.
/// The name of the Symbol is used, but the data-type and possibly other properties are not
/// put on the Varnode.
/// \param entry is the (dynamic) Symbol entry
/// \param dhash is the dynamic mapping information
/// \return \b true if a Varnode was adjusted
bool Funcdata::attemptDynamicMappingLate(SymbolEntry *entry,DynamicHash &dhash)

{
  dhash.clear();
  Varnode *vn = dhash.findVarnode(this,entry->getFirstUseAddress(),entry->getHash());
  if (vn == (Varnode *)0)
    return false;
  if (vn->getSymbolEntry() == entry) return false; // Already applied it
  Symbol *sym = entry->getSymbol();
  if (vn->getSize() != entry->getSize()) {
    ostringstream s;
    s << "Unable to use symbol ";
    if (!sym->isNameUndefined())
	s << sym->getName() << ' ';
    s << ": Size does not match variable it labels";
    warningHeader(s.str());
    return false;
  }

  if (vn->isImplied()) {	// This should be finding an explicit, but a cast may have been inserted
    Varnode *newvn = (Varnode *)0;
    // Look at the "other side" of the cast
    if (vn->isWritten() && (vn->getDef()->code() == CPUI_CAST))
	newvn = vn->getDef()->getIn(0);
    else {
	PcodeOp *castop = vn->loneDescend();
	if ((castop != (PcodeOp *)0)&&(castop->code() == CPUI_CAST))
	  newvn = castop->getOut();
    }
    // See if the varnode on the other side is explicit
    if ((newvn != (Varnode *)0)&&(newvn->isExplicit()))
	vn = newvn;		// in which case we use it
  }

  vn->setSymbolEntry(entry);
  if (!sym->isTypeLocked()) {	// If the dynamic symbol did not lock its type
    localmap->retypeSymbol(sym,vn->getType()); // use the type propagated into the varnode
  }
  else if (sym->getType() != vn->getType()) {
    ostringstream s;
    s << "Unable to use type for symbol " << sym->getName();
    warningHeader(s.str());
    localmap->retypeSymbol(sym,vn->getType()); // use the type propagated into the varnode
  }
  return true;
}

/// \brief Replace all read references to the first Varnode with a second Varnode
///
/// \param vn is the first Varnode (being replaced)
/// \param newvn is the second Varnode (the replacement)
void Funcdata::totalReplace(Varnode *vn,Varnode *newvn)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  int4 i;

  iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    op = *iter++;	       // Increment before removing descendant
    i = op->getSlot(vn);
    opSetInput(op,newvn,i);
  }
}

/// \brief Replace every read reference of the given Varnode with a constant value
///
/// A new constant Varnode is created for each read site. If there are any marker ops
/// (MULTIEQUAL) a single COPY op is inserted and the marker input is set to be the
/// output of the COPY.
/// \param vn is the given Varnode
/// \param val is the constant value to replace it with
void Funcdata::totalReplaceConstant(Varnode *vn,uintb val)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  PcodeOp *copyop = (PcodeOp *)0;
  Varnode *newrep;
  int4 i;

  iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    op = *iter++;		// Increment before removing descendant
    i = op->getSlot(vn);
    if (op->isMarker()) {    // Do not put constant directly in marker
      if (copyop == (PcodeOp *)0) {
	if (vn->isWritten()) {
	  copyop = newOp(1,vn->getDef()->getAddr());
	  opSetOpcode(copyop,CPUI_COPY);
	  newrep = newUniqueOut(vn->getSize(),copyop);
	  opSetInput(copyop,newConstant(vn->getSize(),val),0);
	  opInsertAfter(copyop,vn->getDef());
	}
	else {
	  BlockBasic *bb = (BlockBasic *)getBasicBlocks().getBlock(0);
	  copyop = newOp(1,bb->getStart());
	  opSetOpcode(copyop,CPUI_COPY);
	  newrep = newUniqueOut(vn->getSize(),copyop);
	  opSetInput(copyop,newConstant(vn->getSize(),val),0);
	  opInsertBegin(copyop,bb);
	}
      }
      else
	newrep = copyop->getOut();
    }
    else
      newrep = newConstant(vn->getSize(),val);
    opSetInput(op,newrep,i);
  }
}

/// For the given Varnode, duplicate its defining PcodeOp at each read of the Varnode
/// so that the read becomes a new unique Varnode. This operation should not be performed on any
/// PcodeOp with side effects like CPUI_CALL.
/// \param vn is the given Varnode
void Funcdata::splitUses(Varnode *vn)

{
  PcodeOp *op = vn->getDef();
  Varnode *newvn;
  PcodeOp *newop,*useop;
  list<PcodeOp *>::iterator iter;
  int4 slot;

  iter = vn->descend.begin();
  if (iter == vn->descend.end()) return; // No descendants at all
  useop = *iter++;
  if (iter == vn->descend.end()) return; // Only one descendant
  for(;;) {
    slot = useop->getSlot(vn);		// Get first descendant
    newop = newOp(op->numInput(),op->getAddr());
    newvn = newVarnode(vn->getSize(),vn->getAddr(),vn->getType());
    opSetOutput(newop,newvn);
    opSetOpcode(newop,op->code());
    for(int4 i=0;i<op->numInput();++i)
      opSetInput(newop,op->getIn(i),i);
    opSetInput(useop,newvn,slot);
    opInsertBefore(newop,op);
    if (iter == vn->descend.end()) break;
    useop = *iter++;
  }
				// Dead-code actions should remove original op
}

/// Find the minimal Address range covering the given Varnode that doesn't split other Varnodes
/// \param vn is the given Varnode
/// \param sz is used to pass back the size of the resulting range
/// \return the starting address of the resulting range
Address Funcdata::findDisjointCover(Varnode *vn,int4 &sz)

{
  Address addr = vn->getAddr();
  Address endaddr = addr + vn->getSize();
  VarnodeLocSet::const_iterator iter = vn->lociter;

  while(iter != beginLoc()) {
    --iter;
    Varnode *curvn = *iter;
    Address curEnd = curvn->getAddr() + curvn->getSize();
    if (curEnd <= addr) break;
    addr = curvn->getAddr();
  }
  iter = vn->lociter;
  while(iter != endLoc()) {
    Varnode *curvn = *iter;
    ++iter;
    if (endaddr <= curvn->getAddr()) break;
    endaddr = curvn->getAddr() + curvn->getSize();
  }
  sz = (int4)(endaddr.getOffset() - addr.getOffset());
  return addr;
}

/// \brief Make sure every Varnode in the given list has a Symbol it will link to
///
/// This is used when Varnodes overlap a locked Symbol but extend beyond it.
/// An existing Symbol is passed in with a list of possibly overextending Varnodes.
/// The list is in Address order.  We check that each Varnode has a Symbol that
/// overlaps its first byte (to guarantee a link). If one doesn't exist it is created.
/// \param entry is the existing Symbol entry
/// \param list is the list of Varnodes
void Funcdata::coverVarnodes(SymbolEntry *entry,vector<Varnode *> &list)

{
  Scope *scope = entry->getSymbol()->getScope();
  for(int4 i=0;i<list.size();++i) {
    Varnode *vn = list[i];
    // We only need to check once for all Varnodes at the same Address
    // Of these, pick the biggest Varnode
    if (i+1<list.size() && list[i+1]->getAddr() == vn->getAddr())
      continue;
    Address usepoint = vn->getUsePoint(*this);
    SymbolEntry *overlapEntry = scope->findContainer(vn->getAddr(), vn->getSize(), usepoint);
    if (overlapEntry == (SymbolEntry *)0) {
      int4 diff = (int4)(vn->getOffset() - entry->getAddr().getOffset());
      ostringstream s;
      s << entry->getSymbol()->getName() << '_' << diff;
      scope->addSymbol(s.str(),vn->getHigh()->getType(),vn->getAddr(),usepoint);
    }
  }
}

/// Search for \e addrtied Varnodes whose storage falls in the global Scope, then
/// build a new global Symbol if one didn't exist before.
void Funcdata::mapGlobals(void)

{
  SymbolEntry *entry;
  VarnodeLocSet::const_iterator iter,enditer;
  Varnode *vn,*maxvn;
  Datatype *ct;
  uint4 flags;
  vector<Varnode *> uncoveredVarnodes;
  bool inconsistentuse = false;

  iter = vbank.beginLoc(); // Go through all varnodes for this space
  enditer = vbank.endLoc();
  while(iter != enditer) {
    vn = *iter++;
    if (vn->isFree()) continue;
    if (!vn->isPersist()) continue; // Could be a code ref
    if (vn->getSymbolEntry() != (SymbolEntry *)0) continue;
    maxvn = vn;
    Address addr = vn->getAddr();
    Address endaddr = addr + vn->getSize();
    uncoveredVarnodes.clear();
    while(iter != enditer) {
      vn = *iter;
      if (!vn->isPersist()) break;
      if (vn->getAddr() < endaddr) {
	// Varnodes at the same base address will get linked to the Symbol at that address
	// even if the size doesn't match, but we check for internal Varnodes that
	// do not have an attached Symbol as these won't get linked to anything
	if (vn->getAddr() != addr && vn->getSymbolEntry() == (SymbolEntry *)0)
	  uncoveredVarnodes.push_back(vn);
	endaddr = vn->getAddr() + vn->getSize();
	if (vn->getSize() > maxvn->getSize())
	  maxvn = vn;
	++iter;
      }
      else
	break;
    }
    if ((maxvn->getAddr() == addr)&&(addr+maxvn->getSize() == endaddr))
      ct = maxvn->getHigh()->getType();
    else
      ct = glb->types->getBase(endaddr.getOffset()-addr.getOffset(),TYPE_UNKNOWN);

    flags = 0;
    // Assume existing symbol is addrtied, so use empty usepoint
    Address usepoint;
    // Find any entry overlapping base address
    entry = localmap->queryProperties(addr,1,usepoint,flags);
    if (entry==(SymbolEntry *)0) {
      Scope *discover = localmap->discoverScope(addr,ct->getSize(),usepoint);
      if (discover == (Scope *)0)
	throw LowlevelError("Could not discover scope");
      int4 index = 0;
      string symbolname = discover->buildVariableName(addr,usepoint,ct,index,
						      Varnode::addrtied|Varnode::persist);
      discover->addSymbol(symbolname,ct,addr,usepoint);
    }
    else if ((addr.getOffset()+ct->getSize())-1 > (entry->getAddr().getOffset()+entry->getSize()) -1) {
      inconsistentuse = true;
      if (!uncoveredVarnodes.empty())	// Provide Symbols for any uncovered internal Varnodes
	coverVarnodes(entry, uncoveredVarnodes);
    }
  }
  if (inconsistentuse)
    warningHeader("Globals starting with '_' overlap smaller symbols at the same address");
}

/// \brief Return \b true if the alternate path looks more valid than the main path.
///
/// Two different paths from a common Varnode each terminate at a CALL, CALLIND, or RETURN.
/// Evaluate which path most likely represents actual parameter/return value passing,
/// based on traversal information about each path.
/// \param vn is the Varnode terminating the \e alternate path
/// \param flags indicates traversals for both paths
/// \return \b true if the alternate path is preferred
bool Funcdata::isAlternatePathValid(const Varnode *vn,uint4 flags)

{
  if ((flags & (traverse_indirect | traverse_indirectalt)) == traverse_indirect)
    // If main path traversed an INDIRECT but the alternate did not
    return true;	// Main path traversed INDIRECT, alternate did not
  if ((flags & (traverse_indirect | traverse_indirectalt)) == traverse_indirectalt)
    return false;	// Alternate path traversed INDIRECT, main did not
  if ((flags & traverse_actionalt) != 0)
    return true;	// Alternate path traversed a dedicated COPY
  if (vn->loneDescend() == (PcodeOp*)0) return false;
  const PcodeOp *op = vn->getDef();
  if (op == (PcodeOp*)0) return true;
  return !op->isMarker();	// MULTIEQUAL or INDIRECT indicates multiple values
}

/// \brief Test for legitimate double use of a parameter trial
///
/// The given trial is a \e putative input to first CALL, but can also trace its data-flow
/// into a second CALL. Return \b false if this leads us to conclude that the trial is not
/// a likely parameter.
/// \param opmatch is the first CALL linked to the trial
/// \param op is the second CALL
/// \param vn is the Varnode parameter for the second CALL
/// \param flags indicates what p-code ops were crossed to reach \e vn
/// \param trial is the given parameter trial
/// \return \b true for a legitimate double use
bool Funcdata::checkCallDoubleUse(const PcodeOp *opmatch,const PcodeOp *op,const Varnode *vn,uint4 flags,const ParamTrial &trial) const

{
  int4 j = op->getSlot(vn);
  if (j<=0) return false;	// Flow traces to indirect call variable, definitely not a param
  FuncCallSpecs	*fc = getCallSpecs(op);
  FuncCallSpecs *matchfc = getCallSpecs(opmatch);
  if (op->code() == opmatch->code()) {
    bool isdirect = (opmatch->code() == CPUI_CALL);
    if ((isdirect&&(matchfc->getEntryAddress() == fc->getEntryAddress())) ||
	((!isdirect)&&(op->getIn(0) == opmatch->getIn(0)))) { // If it is a call to the same function
      // Varnode addresses are unreliable for this test because copy propagation may have occurred
      // So we check the actual ParamTrial which holds the original address
//	  if (j == 0) return false;
      const ParamTrial &curtrial( fc->getActiveInput()->getTrialForInputVarnode(j) );
      if (curtrial.getAddress() == trial.getAddress()) { // Check for same memory location
	if (op->getParent() == opmatch->getParent()) {
	  if (opmatch->getSeqNum().getOrder() < op->getSeqNum().getOrder())
	    return true;	// opmatch has dibs, don't reject
	  // If use op occurs earlier than match op, we might still need to reject
	}
	else
	  return true;		// Same function, different basic blocks, assume legit doubleuse
      }
    }
  }

  if (fc->isInputActive()) {
    const ParamTrial &curtrial( fc->getActiveInput()->getTrialForInputVarnode(j) );
    if (curtrial.isChecked()) {
      if (curtrial.isActive())
	return false;
    }
    else if (isAlternatePathValid(vn,flags))
      return false;
    return true;
  }
  return false;
}

/// \brief Test if the given Varnode seems to only be used by a CALL
///
/// Part of testing whether a Varnode makes sense as parameter passing storage is looking for
/// different explicit uses.
/// \param invn is the given Varnode
/// \param opmatch is the putative CALL op using the Varnode for parameter passing
/// \param trial is the parameter trial object associated with the Varnode
/// \param mainFlags are flags describing traversals along the \e main path, from \e invn to \e opmatch
/// \return \b true if the Varnode seems only to be used as parameter to \b opmatch
bool Funcdata::onlyOpUse(const Varnode *invn,const PcodeOp *opmatch,const ParamTrial &trial,uint4 mainFlags) const

{
  vector<TraverseNode> varlist;
  list<PcodeOp *>::const_iterator iter;
  const Varnode *vn,*subvn;
  const PcodeOp *op;
  int4 i;
  bool res = true;

  varlist.reserve(64);
  invn->setMark();		// Marks prevent infinite loops
  varlist.emplace_back(invn,mainFlags);

  for(i=0;i < varlist.size();++i) {
    vn = varlist[i].vn;
    uint4 baseFlags = varlist[i].flags;
    for(iter=vn->descend.begin();iter!=vn->descend.end();++iter) {
      op = *iter;
      if (op == opmatch) {
	if (op->getIn(trial.getSlot())==vn) continue;
      }
      uint4 curFlags = baseFlags;
      switch(op->code()) {
      case CPUI_BRANCH:		// These ops define a USE of a variable
      case CPUI_CBRANCH:
      case CPUI_BRANCHIND:
      case CPUI_LOAD:
      case CPUI_STORE:
	res = false;
	break;
      case CPUI_CALL:
      case CPUI_CALLIND:
	if (checkCallDoubleUse(opmatch,op,vn,curFlags,trial)) continue;
	res = false;
	break;
      case CPUI_INDIRECT:
	curFlags |= Funcdata::traverse_indirectalt;
	break;
      case CPUI_COPY:
	if ((op->getOut()->getSpace()->getType()!=IPTR_INTERNAL)&&!op->isIncidentalCopy()&&!vn->isIncidentalCopy()) {
	  curFlags |= Funcdata::traverse_actionalt;
	}
	break;
      case CPUI_RETURN:
	if (opmatch->code()==CPUI_RETURN) { // Are we in a different return
	  if (op->getIn(trial.getSlot())==vn) // But at the same slot
	    continue;
	}
	else if (activeoutput != (ParamActive *)0) {	// Are we in the middle of analyzing returns
	  if (op->getIn(0) != vn) {		// Unless we hold actual return value
	    if (!isAlternatePathValid(vn,curFlags))
	      continue;				// Don't consider this a "use"
	  }
	}
	res = false;
	break;
      case CPUI_MULTIEQUAL:
      case CPUI_PIECE:
      case CPUI_SUBPIECE:
      case CPUI_INT_SEXT:
      case CPUI_INT_ZEXT:
      case CPUI_CAST:
	break;
      default:
	curFlags |= Funcdata::traverse_actionalt;
	break;
      }
      if (!res) break;
      subvn = op->getOut();
      if (subvn != (const Varnode *)0) {
	if (subvn->isPersist()) {
	  res = false;
	  break;
	}
	if (!subvn->isMark()) {
	  varlist.emplace_back(subvn,curFlags);
	  subvn->setMark();
	}
      }
    }
    if (!res) break;
  }
  for(i=0;i<varlist.size();++i)
    varlist[i].vn->clearMark();
  return res;
}

/// \brief Test if the given trial Varnode is likely only used for parameter passing
///
/// Flow is followed from the Varnode itself and from ancestors the Varnode was copied from
/// to see if it hits anything other than the given CALL or RETURN operation.
/// \param maxlevel is the maximum number of times to recurse through ancestor copies
/// \param invn is the given trial Varnode to test
/// \param op is the given CALL or RETURN
/// \param trial is the associated parameter trial object
/// \param mainFlags describes traversals along the path from \e invn to \e op
/// \return \b true if the Varnode is only used for the CALL/RETURN
bool Funcdata::ancestorOpUse(int4 maxlevel,const Varnode *invn,
			     const PcodeOp *op,ParamTrial &trial,uint4 mainFlags) const

{
  int4 i;

  if (maxlevel==0) return false;

  if (!invn->isWritten()) {
    if (!invn->isInput()) return false;
    if (!invn->isTypeLock()) return false;
				// If the input is typelocked
				// this is as good as being written
    return onlyOpUse(invn,op,trial,mainFlags); // Test if varnode is only used in op
  }

  const PcodeOp *def = invn->getDef();
  switch(def->code()) {
  case CPUI_INDIRECT:
    // An indirectCreation is an indication of an output trial, this should not count as
    // as an "only use"
    if (def->isIndirectCreation())
      return false;
    return ancestorOpUse(maxlevel-1,def->getIn(0),op,trial,mainFlags | Funcdata::traverse_indirect);
  case CPUI_MULTIEQUAL:
				// Check if there is any ancestor whose only
				// use is in this op
    if (def->isMark()) return false;	// Trim the loop
    def->setMark();		// Mark that this MULTIEQUAL is on the path
				// Note: onlyOpUse is using Varnode::setMark
    for(i=0;i<def->numInput();++i) {
      if (ancestorOpUse(maxlevel-1,def->getIn(i),op,trial, mainFlags)) {
	def->clearMark();
	return true;
      }
    }
    def->clearMark();
    return false;
  case CPUI_COPY:
    if ((invn->getSpace()->getType()==IPTR_INTERNAL)||def->isIncidentalCopy()||def->getIn(0)->isIncidentalCopy()) {
      return ancestorOpUse(maxlevel-1,def->getIn(0),op,trial,mainFlags);
    }
    break;
  case CPUI_PIECE:
    // Concatenation tends to be artificial, so recurse through the least significant part
    return ancestorOpUse(maxlevel-1,def->getIn(1),op,trial,mainFlags);
  case CPUI_SUBPIECE:
    // This is a rather kludgy way to get around where a DIV (or other similar) instruction
    // causes a register that looks like the high precision piece of the function return
    // to be set with the remainder as a side effect
    if (def->getIn(1)->getOffset()==0) {
      const Varnode *vn = def->getIn(0);
      if (vn->isWritten()) {
	const PcodeOp *remop = vn->getDef();
	if ((remop->code()==CPUI_INT_REM)||(remop->code()==CPUI_INT_SREM))
	  trial.setRemFormed();
      }
    }
    break;
  case CPUI_CALL:
  case CPUI_CALLIND:
    return false;		// A call is never a good indication of a single op use
  default:
    break;
  }
				// This varnode must be top ancestor at this point
  return onlyOpUse(invn,op,trial,mainFlags); // Test if varnode is only used in op
}

/// \return \b true if there are two input flows, one of which is a normal \e solid flow
bool AncestorRealistic::checkConditionalExe(State &state)

{
  const BlockBasic *bl = state.op->getParent();
  if (bl->sizeIn() != 2)
    return false;
  const FlowBlock *solidBlock = bl->getIn(state.getSolidSlot());
  if (solidBlock->sizeOut() != 1)
    return false;
//  const BlockBasic *callbl = stateStack[0].op->getParent();
//  if (callbl != bl) {
//    bool dominates = false;
//    FlowBlock *dombl = callbl->getImmedDom();
//    for(int4 i=0;i<2;++i) {
//      if (dombl == bl) {
//	dominates = true;
//	break;
//      }
//      if (dombl == (FlowBlock *)0) break;
//      dombl = dombl->getImmedDom();
//    }
//    if (!dominates)
//      return false;
//  }
  return true;
}

/// Analyze a new node that has just entered, during the depth-first traversal
/// \param state is the current node on the path, with associated state information
/// \return the command indicating the next traversal step: push (enter_node), or pop (pop_success, pop_fail, pop_solid...)
int4 AncestorRealistic::enterNode(State &state)

{
  // If the node has already been visited, we truncate the traversal to prevent cycles.
  // We always return success assuming the proper result will get returned along the first path
  if (state.vn->isMark()) return pop_success;
  if (!state.vn->isWritten()) {
    if (state.vn->isInput()) {
      if (state.vn->isUnaffected()) return pop_fail;
      if (state.vn->isPersist()) return pop_success;	// A global input, not active movement, but a valid possibility
      if (!state.vn->isDirectWrite()) return pop_fail;
    }
    return pop_success;		// Probably a normal parameter, not active movement, but valid
  }
  mark(state.vn);		// Mark that the varnode has now been visited
  PcodeOp *op = state.vn->getDef();
  switch(op->code()) {
  case CPUI_INDIRECT:
    if (op->isIndirectCreation()) {	// Backtracking is stopped by a call
      trial->setIndCreateFormed();
      if (op->getIn(0)->isIndirectZero())	// True only if not a possible output
	return pop_failkill;		// Truncate this path, indicating killedbycall
      return pop_success;		// otherwise it could be valid
    }
    if (!op->isIndirectStore()) {	// If flow goes THROUGH a call
      if (op->getOut()->isReturnAddress()) return pop_fail;	// Storage address location is completely invalid
      if (trial->isKilledByCall()) return pop_fail;		// "Likely" killedbycall is invalid
    }
    stateStack.push_back(State(op,0));
    return enter_node;			// Enter the new node
  case CPUI_SUBPIECE:
    // Extracting to a temporary, or to the same storage location, or otherwise incidental
    // are viewed as just another node on the path to traverse
    if (op->getOut()->getSpace()->getType()==IPTR_INTERNAL
	|| op->isIncidentalCopy() || op->getIn(0)->isIncidentalCopy()
	|| (op->getOut()->overlap(*op->getIn(0)) == (int4)op->getIn(1)->getOffset())) {
      stateStack.push_back(State(op,0));
      return enter_node;		// Push into the new node
    }
    // For other SUBPIECES, do a minimal traversal to rule out unaffected or other invalid inputs,
    // but otherwise treat it as valid, active, movement into the parameter
    do {
      Varnode *vn = op->getIn(0);
      if ((!vn->isMark())&&(vn->isInput())) {
	if (vn->isUnaffected()||(!vn->isDirectWrite()))
	  return pop_fail;
      }
      op = vn->getDef();
    } while((op!=(PcodeOp *)0)&&((op->code() == CPUI_COPY)||(op->code()==CPUI_SUBPIECE)));
    return pop_solid;	// treat the COPY as a solid movement
  case CPUI_COPY:
    // Copies to a temporary, or between varnodes with same storage location, or otherwise incidental
    // are viewed as just another node on the path to traverse
    if (op->getOut()->getSpace()->getType()==IPTR_INTERNAL
	|| op->isIncidentalCopy() || op->getIn(0)->isIncidentalCopy()
	|| (op->getOut()->getAddr() == op->getIn(0)->getAddr())) {
      stateStack.push_back(State(op,0));
      return enter_node;		// Push into the new node
    }
    // For other COPIES, do a minimal traversal to rule out unaffected or other invalid inputs,
    // but otherwise treat it as valid, active, movement into the parameter
    do {
      Varnode *vn = op->getIn(0);
      if ((!vn->isMark())&&(vn->isInput())) {
	if (!vn->isDirectWrite())
	  return pop_fail;
      }
      op = vn->getDef();
    } while((op!=(PcodeOp *)0)&&((op->code() == CPUI_COPY)||(op->code()==CPUI_SUBPIECE)));
    return pop_solid;	// treat the COPY as a solid movement
  case CPUI_MULTIEQUAL:
    multiDepth += 1;
    stateStack.push_back(State(op,0));
    return enter_node;				// Nothing to check, start traversing inputs of MULTIEQUAL
  case CPUI_PIECE:
    // If the trial is getting pieced together and then truncated in a register,
    // this is evidence of artificial data-flow.
    if (state.vn->getSize() > trial->getSize() && state.vn->getSpace()->getType() != IPTR_SPACEBASE)
      return pop_fail;
    return pop_solid;
  default:
    return pop_solid;				// Any other LOAD or arithmetic/logical operation is viewed as solid movement
  }
}

/// Backtrack into a previously visited node
/// \param state is the node that needs to be popped from the stack
/// \param pop_command is the type of pop (pop_success, pop_fail, pop_failkill, pop_solid) being performed
/// \return the command to execute (push or pop) after the current pop
int4 AncestorRealistic::uponPop(State &state,int4 pop_command)

{
  if (state.op->code() == CPUI_MULTIEQUAL) {	// All the interesting action happens for MULTIEQUAL branch points
    State &prevstate( stateStack[ stateStack.size()-2 ]);	// State previous the one being popped
    if (pop_command == pop_fail) {		// For a pop_fail, we always pop and pass along the fail
      multiDepth -= 1;
      stateStack.pop_back();
      return pop_command;
    }
    else if ((pop_command == pop_solid)&&(multiDepth == 1)&&(state.op->numInput()==2))
      prevstate.markSolid(state.slot);	// Indicate we have seen a "solid" that could override a "failkill"
    else if (pop_command == pop_failkill)
      prevstate.markKill();		// Indicate we have seen a "failkill" along at least one path of MULTIEQUAL
    state.slot += 1;				// Move to the next sibling
    if (state.slot == state.op->numInput()) {		// If we have traversed all siblings
      if (prevstate.seenSolid()) {			// If we have seen an overriding "solid" along at least one path
	pop_command = pop_success;			// this is always a success
	if (prevstate.seenKill()) {			// UNLESS we have seen a failkill
	  if (allowFailingPath) {
	    if (!checkConditionalExe(state))		// that can NOT be attributed to conditional execution
	      pop_command = pop_fail;			// in which case we fail despite having solid movement
	    else
	      trial->setCondExeEffect();			// Slate this trial for additional testing
	  }
	  else
	    pop_command = pop_fail;
	}
      }
      else if (prevstate.seenKill())	// If we have seen a failkill without solid movement
	pop_command = pop_failkill;			// this is always a failure
      else
	pop_command = pop_success;			// seeing neither solid nor failkill is still a success
      multiDepth -= 1;
      stateStack.pop_back();
      return pop_command;
    }
    state.vn = state.op->getIn(state.slot); // Advance to next sibling
    return enter_node;
  }
  else {
    stateStack.pop_back();
    return pop_command;
  }
}

/// \brief Perform a full ancestor check on a given parameter trial
///
/// \param op is the CALL or RETURN to test parameter passing for
/// \param slot is the index of the particular input varnode to test
/// \param t is the ParamTrial object corresponding to the varnode
/// \param allowFail is \b true if we allow and test for failing paths due to conditional execution
/// \return \b true if the varnode has realistic ancestors for a parameter passing location
bool AncestorRealistic::execute(PcodeOp *op,int4 slot,ParamTrial *t,bool allowFail)

{
  trial = t;
  allowFailingPath = allowFail;
  markedVn.clear();		// Make sure to clear out any old data
  stateStack.clear();
  multiDepth = 0;
  // If the parameter itself is an input, we don't consider this realistic, we expect to see active
  // movement into the parameter. There are some cases where this doesn't happen, but they are rare and
  // failure here doesn't necessarily mean further analysis won't still declare this a parameter
  if (op->getIn(slot)->isInput()) {
    if (!trial->hasCondExeEffect())	// Make sure we are not retesting
      return false;
  }
  // Run the depth first traversal
  int4 command = enter_node;
  stateStack.push_back(State(op,slot));		// Start by entering the initial node
  while(!stateStack.empty()) {			// Continue until all paths have been exhausted
    switch(command) {
    case enter_node:
      command = enterNode(stateStack.back());
      break;
    case pop_success:
    case pop_solid:
    case pop_fail:
    case pop_failkill:
      command = uponPop(stateStack.back(),command);
      break;
    }
  }
  for(int4 i=0;i<markedVn.size();++i)		// Clean up marks we left along the way
    markedVn[i]->clearMark();
  if ((command != pop_success)&&(command != pop_solid))
    return false;
  return true;
}

/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
#include "prefersplit.hh"
#include "funcdata.hh"

bool PreferSplitRecord::operator<(const PreferSplitRecord &op2) const

{
  if (storage.space != op2.storage.space)
    return (storage.space->getIndex() < op2.storage.space->getIndex());
  if (storage.size != op2.storage.size)
    return (storage.size > op2.storage.size); // Bigger sizes come first
  return storage.offset < op2.storage.offset;
}

void PreferSplitManager::fillinInstance(SplitInstance *inst,bool bigendian,bool sethi,bool setlo)

{ // Define the varnode pieces of -inst-
  Varnode *vn = inst->vn;
  int4 losize;
  if (bigendian)
    losize = vn->getSize() - inst->splitoffset;
  else
    losize = inst->splitoffset;
  int4 hisize = vn->getSize() - losize;
  if (vn->isConstant()) {
    uintb origval = vn->getOffset();
    
    uintb loval = origval & calc_mask( losize );// Split the constant into two pieces
    uintb hival = (origval >> 8*losize) & calc_mask( hisize );
    if (setlo && (inst->lo == (Varnode *)0))
      inst->lo = data->newConstant(losize,loval);
    if (sethi && (inst->hi == (Varnode *)0))
      inst->hi = data->newConstant(hisize,hival);
  }
  else {
    if (bigendian) {
      if (setlo && (inst->lo == (Varnode *)0))
	inst->lo = data->newVarnode(losize,vn->getAddr() + inst->splitoffset);
      if (sethi && (inst->hi == (Varnode *)0))
	inst->hi = data->newVarnode(hisize,vn->getAddr());
    }
    else {
      if (setlo && (inst->lo == (Varnode *)0))
	inst->lo = data->newVarnode(losize,vn->getAddr());
      if (sethi && (inst->hi == (Varnode *)0))
	inst->hi = data->newVarnode(hisize,vn->getAddr() + inst->splitoffset);
    }
  }
}

void PreferSplitManager::createCopyOps(SplitInstance *ininst,SplitInstance *outinst,PcodeOp *op,bool istemp)

{ // Create COPY ops based on input -ininst- and output -outinst- to replace -op-
  PcodeOp *hiop = data->newOp(1,op->getAddr()); // Create two new COPYs
  PcodeOp *loop = data->newOp(1,op->getAddr());
  data->opSetOpcode(hiop,CPUI_COPY);
  data->opSetOpcode(loop,CPUI_COPY);

  data->opInsertAfter(loop,op); // Insert new COPYs at same position as original operation
  data->opInsertAfter(hiop,op);
  data->opUnsetInput(op,0);	// Unset input so we can reassign free inputs to new ops

  data->opSetOutput(hiop,outinst->hi); // Outputs
  data->opSetOutput(loop,outinst->lo);
  data->opSetInput(hiop,ininst->hi,0);
  data->opSetInput(loop,ininst->lo,0);
  tempsplits.push_back(hiop);
  tempsplits.push_back(loop);
}

bool PreferSplitManager::testDefiningCopy(SplitInstance *inst,PcodeOp *def,bool &istemp)

{ // Check that -inst- defined by -def- is really splittable
  Varnode *invn = def->getIn(0);
  istemp = false;
  if (!invn->isConstant()) {
    if (invn->getSpace()->getType() != IPTR_INTERNAL) {
      const PreferSplitRecord *inrec = findRecord(invn);
      if (inrec == (const PreferSplitRecord *)0) return false;
      if (inrec->splitoffset != inst->splitoffset) return false;
      if (!invn->isFree()) return false;
    }
    else
      istemp = true;
  }
  return true;
}

void PreferSplitManager::splitDefiningCopy(SplitInstance *inst,PcodeOp *def,bool istemp)

{ // Do split of prefered split varnode that is defined by a COPY
  Varnode *invn = def->getIn(0);
  SplitInstance ininst(invn,inst->splitoffset);
  bool bigendian = inst->vn->getSpace()->isBigEndian();
  fillinInstance(inst,bigendian,true,true);
  fillinInstance(&ininst,bigendian,true,true);
  createCopyOps(&ininst,inst,def,istemp);
}

bool PreferSplitManager::testReadingCopy(SplitInstance *inst,PcodeOp *readop,bool &istemp)

{ // Check that -inst- read by -readop- is really splittable
  Varnode *outvn = readop->getOut();
  istemp = false;
  if (outvn->getSpace()->getType() != IPTR_INTERNAL) {
    const PreferSplitRecord *outrec = findRecord(outvn);
    if (outrec == (const PreferSplitRecord *)0) return false;
    if (outrec->splitoffset != inst->splitoffset) return false;
  }
  else
    istemp = true;
  return true;
}

void PreferSplitManager::splitReadingCopy(SplitInstance *inst,PcodeOp *readop,bool istemp)

{ // Do split of varnode that is read by a COPY
  Varnode *outvn = readop->getOut();
  SplitInstance outinst(outvn,inst->splitoffset);
  bool bigendian = inst->vn->getSpace()->isBigEndian();
  fillinInstance(inst,bigendian,true,true);
  fillinInstance(&outinst,bigendian,true,true);
  createCopyOps(inst,&outinst,readop,istemp);
}

bool PreferSplitManager::testZext(SplitInstance *inst,PcodeOp *op)

{ // Check that -inst- defined by ZEXT is really splittable
  Varnode *invn = op->getIn(0);
  if (invn->isConstant())
    return true;
  bool bigendian = inst->vn->getSpace()->isBigEndian();
  int4 losize;
  if (bigendian)
    losize = inst->vn->getSize() - inst->splitoffset;
  else
    losize = inst->splitoffset;
  if (invn->getSize() != losize) return false;
  return true;
}

void PreferSplitManager::splitZext(SplitInstance *inst,PcodeOp *op)

{
  SplitInstance ininst(op->getIn(0),inst->splitoffset);
  int4 losize,hisize;
  bool bigendian = inst->vn->getSpace()->isBigEndian();
  if (bigendian) {
    hisize = inst->splitoffset;
    losize = inst->vn->getSize() - inst->splitoffset;
  }
  else {
    losize = inst->splitoffset;
    hisize = inst->vn->getSize() - inst->splitoffset;
  }
  if (ininst.vn->isConstant()) {
    uintb origval = ininst.vn->getOffset();
    uintb loval = origval & calc_mask( losize );// Split the constant into two pieces
    uintb hival = (origval >> 8*losize) & calc_mask( hisize );
    ininst.lo = data->newConstant(losize,loval);
    ininst.hi = data->newConstant(hisize,hival);
  }
  else {
    ininst.lo = ininst.vn;
    ininst.hi = data->newConstant(hisize,0);
  }

  fillinInstance(inst,bigendian,true,true);
  createCopyOps(&ininst,inst,op,false);
}

bool PreferSplitManager::testPiece(SplitInstance *inst,PcodeOp *op)

{ // Check that -inst- defined by PIECE is really splittable
  if (inst->vn->getSpace()->isBigEndian()) {
    if (op->getIn(0)->getSize() != inst->splitoffset) return false;
  }
  else {
    if (op->getIn(1)->getSize() != inst->splitoffset) return false;
  }
  return true;
}

void PreferSplitManager::splitPiece(SplitInstance *inst,PcodeOp *op)

{
  Varnode *loin = op->getIn(1);
  Varnode *hiin = op->getIn(0);
  bool bigendian = inst->vn->getSpace()->isBigEndian();
  fillinInstance(inst,bigendian,true,true);
  PcodeOp *hiop = data->newOp(1,op->getAddr());
  PcodeOp *loop = data->newOp(1,op->getAddr());
  data->opSetOpcode(hiop,CPUI_COPY);
  data->opSetOpcode(loop,CPUI_COPY);
  data->opSetOutput(hiop,inst->hi); // Outputs are the pieces of the original
  data->opSetOutput(loop,inst->lo);

  data->opInsertAfter(loop,op);
  data->opInsertAfter(hiop,op);
  data->opUnsetInput(op,0);
  data->opUnsetInput(op,1);

  if (hiin->isConstant())
    hiin = data->newConstant(hiin->getSize(),hiin->getOffset());
  data->opSetInput(hiop,hiin,0);	// Input for the COPY of the most significant part comes from high part of PIECE
  if (loin->isConstant())
    loin = data->newConstant(loin->getSize(),loin->getOffset());
  data->opSetInput(loop,loin,0);	// Input for the COPY of the least significant part comes from low part of PIECE
}

bool PreferSplitManager::testSubpiece(SplitInstance *inst,PcodeOp *op)

{ // Check that -inst- read by SUBPIECE is really splittable
  Varnode *vn = inst->vn;
  Varnode *outvn = op->getOut();
  int4 suboff = (int4)op->getIn(1)->getOffset();
  if (suboff == 0) {
    if (vn->getSize() - inst->splitoffset != outvn->getSize())
      return false;
  }
  else {
    if (vn->getSize() - suboff != inst->splitoffset)
      return false;
    if (outvn->getSize() != inst->splitoffset)
      return false;
  }
  return true;
}

void PreferSplitManager::splitSubpiece(SplitInstance *inst,PcodeOp *op)

{ // Knowing -op- is a CPUI_SUBPIECE that extracts a logical piece from -inst-, rewrite it to a copy
  Varnode *vn = inst->vn;
  int4 suboff = (int4)op->getIn(1)->getOffset();
  bool grabbinglo = (suboff==0);

  bool bigendian = vn->getSpace()->isBigEndian();
  fillinInstance(inst,bigendian,!grabbinglo,grabbinglo);
  data->opSetOpcode(op,CPUI_COPY); // Change SUBPIECE to a copy
  data->opRemoveInput(op,1);

  // Input is most/least significant piece, depending on which the SUBPIECE extracts
  Varnode *invn = grabbinglo ? inst->lo : inst->hi;
  data->opSetInput(op,invn,0);
}

bool PreferSplitManager::testLoad(SplitInstance *inst,PcodeOp *op)

{
  return true;
}

void PreferSplitManager::splitLoad(SplitInstance *inst,PcodeOp *op)

{ // Knowing -op- is a CPUI_LOAD that defines the -inst- varnode, split it into two pieces
  bool bigendian = inst->vn->getSpace()->isBigEndian();
  fillinInstance(inst,bigendian,true,true);
  PcodeOp *hiop = data->newOp(2,op->getAddr());	// Create two new LOAD ops
  PcodeOp *loop = data->newOp(2,op->getAddr());
  PcodeOp *addop = data->newOp(2,op->getAddr());
  Varnode *ptrvn = op->getIn(1);
  
  data->opSetOpcode(hiop,CPUI_LOAD);
  data->opSetOpcode(loop,CPUI_LOAD);

  data->opSetOpcode(addop,CPUI_INT_ADD);	// Create a new ADD op to calculate and hold the second pointer

  data->opInsertAfter(loop,op);
  data->opInsertAfter(hiop,op);
  data->opInsertAfter(addop,op);
  data->opUnsetInput(op,1);	// Free up ptrvn

  Varnode *addvn = data->newUniqueOut(ptrvn->getSize(),addop);
  data->opSetInput(addop,ptrvn,0);
  data->opSetInput(addop,data->newConstant(ptrvn->getSize(),inst->splitoffset),1);

  data->opSetOutput(hiop,inst->hi); // Outputs are the pieces of the original
  data->opSetOutput(loop,inst->lo);
  Varnode *spaceid = op->getIn(0);
  AddrSpace *spc = Address::getSpaceFromConst(spaceid->getAddr());
  spaceid = data->newConstant(spaceid->getSize(),spaceid->getOffset()); // Duplicate original spaceid into new LOADs
  data->opSetInput(hiop,spaceid,0);
  spaceid = data->newConstant(spaceid->getSize(),spaceid->getOffset());
  data->opSetInput(loop,spaceid,0);
  if (ptrvn->isFree())		// Don't read a free varnode twice
    ptrvn = data->newVarnode(ptrvn->getSize(),ptrvn->getSpace(),ptrvn->getOffset());
  
  if (spc->isBigEndian()) {
    data->opSetInput(hiop,ptrvn,1);
    data->opSetInput(loop,addvn,1);
  }
  else {
    data->opSetInput(hiop,addvn,1);
    data->opSetInput(loop,ptrvn,1);
  }
}

bool PreferSplitManager::testStore(SplitInstance *inst,PcodeOp *op)

{
  return true;
}

void PreferSplitManager::splitStore(SplitInstance *inst,PcodeOp *op)

{ // Knowing -op- stores the value -inst-, split it in two
  fillinInstance(inst,inst->vn->getSpace()->isBigEndian(),true,true);
  PcodeOp *hiop = data->newOp(3,op->getAddr());	// Create 2 new STOREs
  PcodeOp *loop = data->newOp(3,op->getAddr());
  PcodeOp *addop = data->newOp(2,op->getAddr());
  Varnode *ptrvn = op->getIn(1);
  
  data->opSetOpcode(hiop,CPUI_STORE);
  data->opSetOpcode(loop,CPUI_STORE);

  data->opSetOpcode(addop,CPUI_INT_ADD);	// Create a new ADD op to calculate and hold the second pointer

  data->opInsertAfter(loop,op);
  data->opInsertAfter(hiop,op);
  data->opInsertAfter(addop,op);
  data->opUnsetInput(op,1);	// Free up ptrvn
  data->opUnsetInput(op,2);	// Free up inst

  Varnode *addvn = data->newUniqueOut(ptrvn->getSize(),addop);
  data->opSetInput(addop,ptrvn,0);
  data->opSetInput(addop,data->newConstant(ptrvn->getSize(),inst->splitoffset),1);

  data->opSetInput(hiop,inst->hi,2); // Varnodes "being stored" are the pieces of the original
  data->opSetInput(loop,inst->lo,2);
  Varnode *spaceid = op->getIn(0);
  AddrSpace *spc = Address::getSpaceFromConst(spaceid->getAddr());
  spaceid = data->newConstant(spaceid->getSize(),spaceid->getOffset()); // Duplicate original spaceid into new STOREs
  data->opSetInput(hiop,spaceid,0);
  spaceid = data->newConstant(spaceid->getSize(),spaceid->getOffset());
  data->opSetInput(loop,spaceid,0);
  
  if (ptrvn->isFree())		// Don't read a free varnode twice
    ptrvn = data->newVarnode(ptrvn->getSize(),ptrvn->getSpace(),ptrvn->getOffset());
  if (spc->isBigEndian()) {
    data->opSetInput(hiop,ptrvn,1);
    data->opSetInput(loop,addvn,1);
  }
  else {
    data->opSetInput(hiop,addvn,1);
    data->opSetInput(loop,ptrvn,1);
  }
}

bool PreferSplitManager::splitVarnode(SplitInstance *inst)

{ // Test if -vn- can be readily split, if so, do the split
  Varnode *vn = inst->vn;
  bool istemp;
  if (vn->isWritten()) {
    if (!vn->hasNoDescend()) return false; // Already linked in
    PcodeOp *op = vn->getDef();
    switch (op->code()) {
    case CPUI_COPY:
      if (!testDefiningCopy(inst,op,istemp))
	return false;
      splitDefiningCopy(inst,op,istemp);
      break;
    case CPUI_PIECE:
      if (!testPiece(inst,op))
	return false;
      splitPiece(inst,op);
      break;
    case CPUI_LOAD:
      if (!testLoad(inst,op))
	return false;
      splitLoad(inst,op);
      break;
    case CPUI_INT_ZEXT:
      if (!testZext(inst,op))
	return false;
      splitZext(inst,op);
      break;
    default:
      return false;
    }
    data->opDestroy(op);
  }
  else {
    if (!vn->isFree()) return false;	// Make sure vn is not already a marked input
    PcodeOp *op = vn->loneDescend();
    if (op == (PcodeOp *)0)	// vn must be read exactly once
      return false;
    switch(op->code()) {
    case CPUI_COPY:
      if (!testReadingCopy(inst,op,istemp))
	return false;
      splitReadingCopy(inst,op,istemp);
      break;
    case CPUI_SUBPIECE:
      if (!testSubpiece(inst,op))
	return false;
      splitSubpiece(inst,op);
      return true;		// Do not destroy op, it has been transformed
    case CPUI_STORE:
      if (!testStore(inst,op))
	return false;
      splitStore(inst,op);
      break;
    default:
      return false;
    }
    data->opDestroy(op);	// Original op is now dead
  }
  return true;
}

void PreferSplitManager::splitRecord(const PreferSplitRecord &rec)

{
  Address addr = rec.storage.getAddr();
  VarnodeLocSet::const_iterator iter,enditer;

  SplitInstance inst((Varnode *)0,rec.splitoffset);
  iter = data->beginLoc(rec.storage.size,addr);
  enditer = data->endLoc(rec.storage.size,addr);
  while(iter != enditer) {
    inst.vn = *iter;
    ++iter;
    inst.lo = (Varnode *)0;
    inst.hi = (Varnode *)0;
    if (splitVarnode(&inst)) {	// If we found something, regenerate iterators, as they may be stale
      iter = data->beginLoc(rec.storage.size,addr);
      enditer = data->endLoc(rec.storage.size,addr);
    }
  }
}

bool PreferSplitManager::testTemporary(SplitInstance *inst)

{
  PcodeOp *op = inst->vn->getDef();
  switch(op->code()) {
  case CPUI_PIECE:
    if (!testPiece(inst,op))
      return false;
    break;
  case CPUI_LOAD:
    if (!testLoad(inst,op))
      return false;
    break;
  case CPUI_INT_ZEXT:
    if (!testZext(inst,op))
      return false;
    break;
  default:
    return false;
  }
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = inst->vn->beginDescend();
  enditer = inst->vn->endDescend();
  while(iter != enditer) {
    PcodeOp *readop = *iter;
    ++iter;
    switch(readop->code()) {
    case CPUI_SUBPIECE:
      if (!testSubpiece(inst,readop))
	return false;
      break;
    case CPUI_STORE:
      if (!testStore(inst,readop))
	return false;
      break;
    default:
      return false;
    }
  }
  return true;
}

void PreferSplitManager::splitTemporary(SplitInstance *inst)

{
  Varnode *vn = inst->vn;
  PcodeOp *op = vn->getDef();
  switch(op->code()) {
  case CPUI_PIECE:
    splitPiece(inst,op);
    break;
  case CPUI_LOAD:
    splitLoad(inst,op);
    break;
  case CPUI_INT_ZEXT:
    splitZext(inst,op);
    break;
  default:
    break;
  }

  while(vn->beginDescend() != vn->endDescend()) {
    PcodeOp *readop = *vn->beginDescend();
    switch(readop->code()) {
    case CPUI_SUBPIECE:
      splitSubpiece(inst,readop);
      break;
    case CPUI_STORE:
      splitStore(inst,readop);
      data->opDestroy(readop);
      break;
    default:
      break;
    }
  }
  data->opDestroy(op);
}

void PreferSplitManager::init(Funcdata *fd,const vector<PreferSplitRecord> *rec)

{
  data = fd;
  records = rec;
}

const PreferSplitRecord *PreferSplitManager::findRecord(Varnode *vn) const

{ // Find the split record that applies to -vn-, otherwise return null
  PreferSplitRecord templ;
  templ.storage.space = vn->getSpace();
  templ.storage.size = vn->getSize();
  templ.storage.offset = vn->getOffset();
  vector<PreferSplitRecord>::const_iterator iter;
  iter = lower_bound(records->begin(),records->end(),templ);
  if (iter == records->end())
    return (PreferSplitRecord *)0;
  if (templ < *iter)
    return (PreferSplitRecord *)0;
  return &(*iter);
}

void PreferSplitManager::initialize(vector<PreferSplitRecord> &records)

{
  sort(records.begin(),records.end());
}

void PreferSplitManager::split(void)

{
  for(int4 i=0;i<records->size();++i)
    splitRecord((*records)[i]);
}

void PreferSplitManager::splitAdditional(void)

{
  vector<PcodeOp *> defops;
  for(int4 i=0;i<tempsplits.size();++i) {
    PcodeOp *op = tempsplits[i]; // Look at everything connected to COPYs in -tempsplits-
    if (op->isDead()) continue;
    Varnode *vn = op->getIn(0);
    if (vn->isWritten()) {
      PcodeOp *defop = vn->getDef();
      if (defop->code() == CPUI_SUBPIECE) { // SUBPIECEs flowing into the COPY
	Varnode *invn = defop->getIn(0);
	if (invn->getSpace()->getType() == IPTR_INTERNAL) // Might be from a temporary that needs further splitting
	  defops.push_back(defop);
      }
    }
    list<PcodeOp *>::const_iterator iter,enditer;
    iter = op->getOut()->beginDescend();
    enditer = op->getOut()->endDescend();
    while(iter != enditer) {
      PcodeOp *defop = *iter;
      ++iter;
      if (defop->code() == CPUI_PIECE) { // COPY flowing into PIECEs
	Varnode *outvn = defop->getOut();
	if (outvn->getSpace()->getType() == IPTR_INTERNAL) // Might be to a temporary that needs further splitting
	  defops.push_back(defop);
      }
    }
  }
  for(int4 i=0;i<defops.size();++i) {
    PcodeOp *op = defops[i];
    if (op->isDead()) continue;
    if (op->code() == CPUI_PIECE) {
      int4 splitoff;
      Varnode *vn = op->getOut();
      if (vn->getSpace()->isBigEndian())
	splitoff = op->getIn(0)->getSize();
      else
	splitoff = op->getIn(1)->getSize();
      SplitInstance inst(vn,splitoff);
      if (testTemporary(&inst))
	splitTemporary(&inst);
    }
    else if (op->code() == CPUI_SUBPIECE) {
      int4 splitoff;
      Varnode *vn = op->getIn(0);
      uintb suboff = op->getIn(1)->getOffset();
      if (vn->getSpace()->isBigEndian()) {
	if (suboff == 0)
	  splitoff = vn->getSize() - op->getOut()->getSize();
	else
	  splitoff = vn->getSize() - (int4)suboff;
      }
      else {
	if (suboff == 0)
	  splitoff = op->getOut()->getSize();
	else
	  splitoff = (int4)suboff;
      }
      SplitInstance inst(vn,splitoff);
      if (testTemporary(&inst))
	splitTemporary(&inst);
    }
  }
}

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
#include "transform.hh"
#include "funcdata.hh"

/// Create the Varnode object (constant, unique, vector piece) described by the
/// given placeholder. If the Varnode is an output, assume the op already exists
/// and create the Varnode as an output. Set the \b replacement field with the
/// new Varnode.
/// \param fd is the function in which to create the replacement
void TransformVar::createReplacement(Funcdata *fd)

{
  switch(type) {
    case TransformVar::preexisting:
      replacement = vn;
      break;
    case TransformVar::constant:
      replacement = fd->newConstant(size,val);
      break;
    case TransformVar::normal_temp:
      if (def == (TransformOp *)0)
	replacement = fd->newUnique(size);
      else
	replacement = fd->newUniqueOut(size,def->replacement);
      break;
    case TransformVar::piece:
    {
      Address addr = vn->getAddr() + (int4)val;
      if (def == (TransformOp *)0)
	replacement = fd->newVarnode(size,addr);
      else
	replacement = fd->newVarnodeOut(size, addr, def->replacement);
      break;
    }
    case TransformVar::constant_iop:
    {
      PcodeOp *indeffect = PcodeOp::getOpFromConst(Address(fd->getArch()->getIopSpace(),val));
      replacement = fd->newVarnodeIop(indeffect);
      break;
    }
    default:
      throw LowlevelError("Bad TransformVar type");
  }
}

/// Create a new PcodeOp or modify an existing one so that it matches this placeholder description.
/// Go ahead an insert the new PcodeOp into the basic block if possible
/// \param fd is the function in which to make the modifications
void TransformOp::createReplacement(Funcdata *fd)

{
  if ((special & TransformOp::op_preexisting)!=0) {
    replacement = op;
    fd->opSetOpcode(op, opc);
    while(input.size() < op->numInput())
      fd->opRemoveInput(op, op->numInput()-1);
    while(op->numInput() < input.size())
      fd->opInsertInput(op, (Varnode *)0, op->numInput()-1);
  }
  else {
    replacement = fd->newOp(input.size(),op->getAddr());
    fd->opSetOpcode(replacement, opc);
    if (output != (TransformVar *)0)
      output->createReplacement(fd);
    if (follow == (TransformOp *)0)		// Can be inserted immediately
      fd->opInsertBefore(replacement, op);
  }
}

/// \param fd is the function into which the PcodeOp will be inserted
/// \return \b true if the op is successfully inserted or already inserted
bool TransformOp::attemptInsertion(Funcdata *fd)

{
  if (follow != (TransformOp *)0) {
    if (follow->follow == (TransformOp *)0) {	// Check if the follow is inserted
      fd->opInsertBefore(replacement,follow->replacement);
      follow = (TransformOp *)0;	// Mark that this has been inserted
      return true;
    }
    return false;
  }
  return true;		// Already inserted
}

/// \param vn is the preexisting Varnode to create a placeholder for
/// \return the new placeholder node
TransformVar *TransformManager::newPreexistingVarnode(Varnode *vn)

{
  newVarnodes.push_back(TransformVar());
  TransformVar *res = &newVarnodes.back();
  res->vn = vn;
  res->replacement = (Varnode *)0;
  res->size = vn->getSize();
  res->def = (TransformOp *)0;
  res->type = TransformVar::preexisting;
  MapKey key(vn->getCreateIndex(),0);
  pieceMap[key] = res;		// Enter preexisting Varnode into map, so we don't make another placeholder
  return res;
}

/// \param size is the size in bytes of the new unique Varnode
/// \return the new placeholder node
TransformVar *TransformManager::newUnique(int4 size)

{
  newVarnodes.push_back(TransformVar());
  TransformVar *res = &newVarnodes.back();
  res->replacement = (Varnode *)0;
  res->size = size;
  res->def = (TransformOp *)0;
  res->type = TransformVar::normal_temp;
  return res;
}

/// \param size is the size in bytes of the new constant
/// \param val is the value of the new constant
/// \return the new placeholder node
TransformVar *TransformManager::newConstant(int4 size,uintb val)

{
  newVarnodes.push_back(TransformVar());
  TransformVar *res = &newVarnodes.back();
  res->replacement = (Varnode *)0;
  res->size = size;
  res->val = val;
  res->def = (TransformOp *)0;
  res->type = TransformVar::constant;
  return res;
}

TransformVar *TransformManager::newIop(Varnode *vn)

{
  newVarnodes.push_back(TransformVar());
  TransformVar *res = &newVarnodes.back();
  res->vn = (Varnode *)0;
  res->replacement = (Varnode *)0;
  res->size = vn->getSize();
  res->val = vn->getOffset();	// The encoded iop
  res->def = (TransformOp *)0;
  res->type = TransformVar::constant_iop;
  return res;
}

/// Given a single logical value within a larger Varnode, create a placeholder for
/// that logical value.
/// \param vn is the large Varnode
/// \param size is the size of the logical value in bytes
/// \param lsbOffset is the number of least significant bytes of the Varnode dropped from the value
/// \return the placeholder variable
TransformVar *TransformManager::newPiece(Varnode *vn,int4 size,int4 lsbOffset)

{
  newVarnodes.push_back(TransformVar());
  TransformVar *res = &newVarnodes.back();
  res->vn = vn;
  res->replacement = (Varnode *)0;
  res->size = size;
  res->def = (TransformOp *)0;
  res->type = TransformVar::piece;
  MapKey key(vn->getCreateIndex(),lsbOffset);
  pieceMap[key] = res;
  return res;
}

/// \brief Create placeholder nodes splitting a Varnode into its lanes
///
/// Given a big Varnode and a lane description, create placeholders for all the explicit pieces
/// that the big Varnode will be split into.
/// \param res will hold references to the new placeholders in significance order
/// \param vn is the big Varnode to split
/// \param description shows how the big Varnode will be split
void TransformManager::newSplit(vector<TransformVar *> &res,Varnode *vn,const LaneDescription &description)

{
  int4 num = description.getNumLanes();
  res.resize(num,(TransformVar *)0);
  for(int4 i=0;i<num;++i) {
    newVarnodes.push_back(TransformVar());
    TransformVar *newVar = &newVarnodes.back();
    newVar->vn = vn;
    newVar->replacement = (Varnode *)0;
    newVar->size = description.getSize(i);
    newVar->def = (TransformOp *)0;
    newVar->type = TransformVar::piece;
    MapKey key(vn->getCreateIndex(),description.getPosition(i));
    pieceMap[key] = newVar;
    res[i] = newVar;
  }
}

/// \brief Create a new placeholder op intended to replace an existing op
///
/// An uninitialized placeholder for the new op is created.
/// \param numParams is the number of Varnode inputs intended for the new op
/// \param opc is the opcode of the new op
/// \param replace is the existing op the new op will replace
/// \return the new placeholder node
TransformOp *TransformManager::newOpReplace(int4 numParams,OpCode opc,PcodeOp *replace)

{
  newOps.push_back(TransformOp());
  TransformOp &rop(newOps.back());
  rop.op = replace;
  rop.replacement = (PcodeOp *)0;
  rop.opc = opc;
  rop.special = TransformOp::op_replacement;
  rop.output = (TransformVar *)0;
  rop.follow = (TransformOp *)0;
  rop.input.resize(numParams,(TransformVar *)0);
  return &rop;
}

/// \brief Create a new placeholder op that will not replace an existing op
///
/// An uninitialized placeholder for the new op is created. When (if) the new op is created
/// it will not replace an existing op.  The op that follows it must be given.
/// \param numParams is the number of Varnode inputs intended for the new op
/// \param opc is the opcode of the new op
/// \param follow is the placeholder for the op that follow the new op when it is created
/// \return the new placeholder node
TransformOp *TransformManager::newOp(int4 numParams,OpCode opc,TransformOp *follow)

{
  newOps.push_back(TransformOp());
  TransformOp &rop(newOps.back());
  rop.op = follow->op;
  rop.replacement = (PcodeOp *)0;
  rop.opc = opc;
  rop.special = 0;
  rop.output = (TransformVar *)0;
  rop.follow = follow;
  rop.input.resize(numParams,(TransformVar *)0);
  return &rop;
}

/// \brief Create a new placeholder op for an existing PcodeOp
///
/// An uninitialized placeholder for the existing op is created. When applied, this causes
/// the op to be transformed as described by the placeholder, changing its opcode and
/// inputs.  The output however is unaffected.
/// \param numParams is the number of Varnode inputs intended for the transformed op
/// \param opc is the opcode of the transformed op
/// \param originalOp is the preexisting PcodeOp
/// \return the new placeholder node
TransformOp *TransformManager::newPreexistingOp(int4 numParams,OpCode opc,PcodeOp *originalOp)

{
  newOps.push_back(TransformOp());
  TransformOp &rop(newOps.back());
  rop.op = originalOp;
  rop.replacement = (PcodeOp *)0;
  rop.opc = opc;
  rop.special = TransformOp::op_preexisting;
  rop.output = (TransformVar *)0;
  rop.follow = (TransformOp *)0;
  rop.input.resize(numParams,(TransformVar *)0);
  return &rop;
}

/// Check if a placeholder node was created for the preexisting Varnode for,
/// otherwise create a new one.
/// \param vn is the preexisting Varnode to find a placeholder for
/// \return the placeholder node
TransformVar *TransformManager::getPreexistingVarnode(Varnode *vn)

{
  map<MapKey,TransformVar *>::const_iterator iter;
  MapKey key(vn->getCreateIndex(),0);
  iter = pieceMap.find(key);
  if (iter != pieceMap.end())
    return (*iter).second;
  return newPreexistingVarnode(vn);
}

/// Given a big Varnode, find the placeholder corresponding to the logical value
/// given by a size and significance offset.  If it doesn't exist, create it.
/// \param vn is the big Varnode containing the logical value
/// \param size is the size of the logical value in bytes
/// \param lsbOffset is the signficance offset of the logical value within the Varnode
/// \return the found/created placeholder
TransformVar *TransformManager::getPiece(Varnode *vn,int4 size,int4 lsbOffset)

{
  map<MapKey,TransformVar *>::const_iterator iter;
  MapKey key(vn->getCreateIndex(),lsbOffset);
  iter = pieceMap.find(key);
  if (iter != pieceMap.end()) {
    return (*iter).second;
  }
  return newPiece(vn,size,lsbOffset);
}

/// \brief Find (or create) placeholder nodes splitting a Varnode into its lanes
///
/// Given a big Varnode and a lane description, look up placeholders for all its
/// explicit pieces. If they don't exist, create them.
/// \param res will hold the array of recovered placeholders in significance order
/// \param vn is the big Varnode to split
/// \param description shows how the big Varnode will be split
void TransformManager::getSplit(vector<TransformVar *> &res,Varnode *vn,const LaneDescription &description)

{
  map<MapKey,TransformVar *>::const_iterator iter;
  MapKey key(vn->getCreateIndex(),0);
  iter = pieceMap.lower_bound(key);
  if (iter != pieceMap.end() && (*iter).first.getCreateIndex() == vn->getCreateIndex()) {
    int4 num = description.getNumLanes();
    res.resize(num,(TransformVar *)0);
    for(int4 i=0;i<num;++i) {
      res[i] = (*iter).second;
      ++iter;
    }
    return;
  }
  newSplit(res,vn,description);
}

void TransformManager::opSetInput(TransformOp *rop,TransformVar *rvn,int4 slot)

{
  rop->input[slot] = rvn;
}

/// \brief Handle some special PcodeOp marking
/// If a PcodeOp is an INDIRECT creation, we need to do special marking of the op and Varnodes
/// \param rop is the placeholder op with the special requirement
void TransformManager::specialHandling(TransformOp &rop)
{
  if ((rop.special & TransformOp::indirect_creation) != 0)
    fd->markIndirectCreation(rop.replacement, false);
  else if ((rop.special & TransformOp::indirect_creation_possible_out) != 0)
    fd->markIndirectCreation(rop.replacement, true);
}

/// Run through the list of TransformOp placeholders and create the actual PcodeOp object.
/// If the op has an output Varnode, create it.  Make sure all the new ops are inserted in
/// control flow.
void TransformManager::createOps(void)

{
  list<TransformOp>::iterator iter;
  for(iter=newOps.begin();iter!=newOps.end();++iter)
    (*iter).createReplacement(fd);

  int4 followCount;
  do {
    followCount = 0;
    for(iter=newOps.begin();iter!=newOps.end();++iter) {
      if (!(*iter).attemptInsertion(fd))
	followCount += 1;
    }
  } while(followCount != 0);
}

void TransformManager::createVarnodes(void)

{
  list<TransformVar>::iterator iter;
  for(iter=newVarnodes.begin();iter!=newVarnodes.end();++iter) {
    (*iter).createReplacement(fd);
  }
}

void TransformManager::removeOld(void)

{
  list<TransformOp>::iterator iter;
  for(iter=newOps.begin();iter!=newOps.end();++iter) {
    TransformOp &rop(*iter);
    if ((rop.special & TransformOp::op_replacement) != 0) {
      if (!rop.op->isDead())
	fd->opDestroy(rop.op);	// Destroy old op (and its output Varnode)
    }
  }
}

/// Collect all the Varnodes that are inputs and are getting replaced.
/// There may be multiple references so we dedup with marks.
/// Remove all the replaced input Varnodes.
/// Mark all the replacement Varnodes as inputs.
void TransformManager::transformInputVarnodes(void)

{
  list<TransformVar>::iterator iter;
  vector<Varnode *> deadList;

  for(iter=newVarnodes.begin();iter!=newVarnodes.end();++iter) {
    TransformVar &rvn(*iter);
    if (rvn.type == TransformVar::piece && rvn.def == (TransformOp *)0) {
      if (!rvn.vn->isMark()) {
	rvn.vn->setMark();
	deadList.push_back(rvn.vn);
      }
    }
  }

  for(int4 i=0;i<deadList.size();++i)
    fd->deleteVarnode(deadList[i]);

  for(iter=newVarnodes.begin();iter!=newVarnodes.end();++iter) {
    TransformVar &rvn(*iter);
    if (rvn.type == TransformVar::piece && rvn.def == (TransformOp *)0) {
      rvn.replacement = fd->setInputVarnode(rvn.replacement);
    }
  }
}

void TransformManager::placeInputs(void)

{
  list<TransformOp>::iterator iter;
  for(iter=newOps.begin();iter!=newOps.end();++iter) {
    TransformOp &rop(*iter);
    PcodeOp *op = rop.replacement;
    for(int4 i=0;i<rop.input.size();++i) {
      TransformVar *rvn = rop.input[i];
      Varnode *vn = rvn->replacement;
      fd->opSetInput(op, vn, i);
    }
    specialHandling(rop);
  }
}

void TransformManager::apply(void)

{
  createOps();
  createVarnodes();
  removeOld();
  transformInputVarnodes();
  placeInputs();
}

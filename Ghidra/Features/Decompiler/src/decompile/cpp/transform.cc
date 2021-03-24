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

/// \param op2 is the lane description to copy from
LaneDescription::LaneDescription(const LaneDescription &op2)

{
  wholeSize = op2.wholeSize;
  laneSize = op2.laneSize;
  lanePosition = op2.lanePosition;
}

/// Create lanes that are all the same size
/// \param origSize is the size of the whole in bytes
/// \param sz is the size of a lane in bytes
LaneDescription::LaneDescription(int4 origSize,int4 sz)

{
  wholeSize = origSize;
  int4 numLanes = origSize / sz;
  laneSize.resize(numLanes);
  lanePosition.resize(numLanes);
  int4 pos = 0;
  for(int4 i=0;i<numLanes;++i) {
    laneSize[i] = sz;
    lanePosition[i] = pos;
    pos += sz;
  }
}

/// \param origSize is the size of the whole in bytes
/// \param lo is the size of the least significant lane in bytes
/// \param hi is the size of the most significant lane in bytes
LaneDescription::LaneDescription(int4 origSize,int4 lo,int4 hi)

{
  wholeSize = origSize;
  laneSize.resize(2);
  lanePosition.resize(2);
  laneSize[0] = lo;
  laneSize[1] = hi;
  lanePosition[0] = 0;
  lanePosition[1] = lo;
}

/// Given a subrange, specified as an offset into the whole and size,
/// throw out any lanes in \b this that aren't in the subrange, so that the
/// size of whole is the size of the subrange.  If the subrange intersects partially
/// with any of the lanes, return \b false.
/// \param lsbOffset is the number of bytes to remove from the front of the description
/// \param size is the number of bytes in the subrange
/// \return \b true if \b this was successfully transformed to the subrange
bool LaneDescription::subset(int4 lsbOffset,int4 size)

{
  if (lsbOffset == 0 && size == wholeSize)
    return true;			// subrange is the whole range
  int4 firstLane = getBoundary(lsbOffset);
  if (firstLane < 0) return false;
  int4 lastLane = getBoundary(lsbOffset + size);
  if (lastLane < 0) return false;
  vector<int4> newLaneSize;
  lanePosition.clear();
  int4 newPosition = 0;
  for(int4 i=firstLane;i<lastLane;++i) {
    int4 sz = laneSize[i];
    lanePosition.push_back(newPosition);
    newLaneSize.push_back(sz);
    newPosition += sz;
  }
  wholeSize = size;
  laneSize = newLaneSize;
  return true;
}

/// Position 0 will map to index 0 and a position equal to whole size will
/// map to the number of lanes.  Positions that are out of bounds or that do
/// not fall on a lane boundary will return -1.
/// \param bytePos is the given byte position to test
/// \return the index of the lane that start at the given position
int4 LaneDescription::getBoundary(int4 bytePos) const

{
  if (bytePos < 0 || bytePos > wholeSize)
    return -1;
  if (bytePos == wholeSize)
    return lanePosition.size();
  int4 min = 0;
  int4 max = lanePosition.size() - 1;
  while(min <= max) {
    int4 index = (min + max) / 2;
    int4 pos = lanePosition[index];
    if (pos == bytePos) return index;
    if (pos < bytePos)
      min = index + 1;
    else
      max = index - 1;
  }
  return -1;
}

/// \brief Decide if a given truncation is natural for \b this description
///
/// A subset of lanes are specified and a truncation (given by a byte position and byte size).
/// If the truncation, relative to the subset, contains at least 1 lane and does not split any
/// lanes, then return \b true and pass back the number of lanes and starting lane of the truncation.
/// \param numLanes is the number of lanes in the original subset
/// \param skipLanes is the starting (least significant) lane index of the original subset
/// \param bytePos is the number of bytes to truncate from the front (least significant portion) of the subset
/// \param size is the number of bytes to include in the truncation
/// \param resNumLanes will hold the number of lanes in the truncation
/// \param resSkipLanes will hold the starting lane in the truncation
/// \return \b true if the truncation is natural
bool LaneDescription::restriction(int4 numLanes,int4 skipLanes,int4 bytePos,int4 size,
				  int4 &resNumLanes,int4 &resSkipLanes) const

{
  resSkipLanes = getBoundary(lanePosition[skipLanes] + bytePos);
  if (resSkipLanes < 0) return false;
  int4 finalIndex = getBoundary(lanePosition[skipLanes] + bytePos + size);
  if (finalIndex < 0) return false;
  resNumLanes = finalIndex - resSkipLanes;
  return (resNumLanes != 0);
}

/// \brief Decide if a given subset of lanes can be extended naturally for \b this description
///
/// A subset of lanes are specified and their position within an extension (given by a byte position).
/// The size in bytes of the extension is also given. If the extension is contained within \b this description,
/// and the boundaries of the extension don't split any lanes, then return \b true and pass back
/// the number of lanes and starting lane of the extension.
/// \param numLanes is the number of lanes in the original subset
/// \param skipLanes is the starting (least significant) lane index of the original subset
/// \param bytePos is the number of bytes to truncate from the front (least significant portion) of the extension
/// \param size is the number of bytes in the extension
/// \param resNumLanes will hold the number of lanes in the extension
/// \param resSkipLanes will hold the starting lane in the extension
/// \return \b true if the extension is natural
bool LaneDescription::extension(int4 numLanes,int4 skipLanes,int4 bytePos,int4 size,
				int4 &resNumLanes,int4 &resSkipLanes) const

{
  resSkipLanes = getBoundary(lanePosition[skipLanes] - bytePos);
  if (resSkipLanes < 0) return false;
  int4 finalIndex = getBoundary(lanePosition[skipLanes] - bytePos + size);
  if (finalIndex < 0) return false;
  resNumLanes = finalIndex - resSkipLanes;
  return (resNumLanes != 0);
}

/// Create the Varnode object (constant, unique, vector piece) described by the
/// given placeholder. If the Varnode is an output, assume the op already exists
/// and create the Varnode as an output. Set the \b replacement field with the
/// new Varnode.
/// \param fd is the function in which to create the replacement
void TransformVar::createReplacement(Funcdata *fd)

{
  if (replacement != (Varnode *)0)
    return;			// Replacement already created
  switch(type) {
    case TransformVar::preexisting:
      replacement = vn;
      break;
    case TransformVar::constant:
      replacement = fd->newConstant(byteSize,val);
      break;
    case TransformVar::normal_temp:
    case TransformVar::piece_temp:
      if (def == (TransformOp *)0)
	replacement = fd->newUnique(byteSize);
      else
	replacement = fd->newUniqueOut(byteSize,def->replacement);
      break;
    case TransformVar::piece:
    {
      int4 bytePos = (int4)val;
      if ((bytePos & 7) != 0)
	throw LowlevelError("Varnode piece is not byte aligned");
      bytePos >>= 3;
      if (vn->getSpace()->isBigEndian())
	bytePos = vn->getSize() - bytePos - byteSize;
      Address addr = vn->getAddr() + bytePos;
      addr.renormalize(byteSize);
      if (def == (TransformOp *)0)
	replacement = fd->newVarnode(byteSize,addr);
      else
	replacement = fd->newVarnodeOut(byteSize, addr, def->replacement);
      fd->transferVarnodeProperties(vn,replacement,bytePos);
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
    for(int4 i=0;i<op->numInput();++i)
      fd->opUnsetInput(op,i);			// Clear any remaining inputs
    while(op->numInput() < input.size())
      fd->opInsertInput(op, (Varnode *)0, op->numInput()-1);
  }
  else {
    replacement = fd->newOp(input.size(),op->getAddr());
    fd->opSetOpcode(replacement, opc);
    if (output != (TransformVar *)0)
      output->createReplacement(fd);
    if (follow == (TransformOp *)0) {		// Can be inserted immediately
      if (opc == CPUI_MULTIEQUAL)
	fd->opInsertBegin(replacement, op->getParent());
      else
	fd->opInsertBefore(replacement, op);
    }
  }
}

/// \param fd is the function into which the PcodeOp will be inserted
/// \return \b true if the op is successfully inserted or already inserted
bool TransformOp::attemptInsertion(Funcdata *fd)

{
  if (follow != (TransformOp *)0) {
    if (follow->follow == (TransformOp *)0) {	// Check if the follow is inserted
      if (opc == CPUI_MULTIEQUAL)
	fd->opInsertBegin(replacement, follow->replacement->getParent());
      else
	fd->opInsertBefore(replacement,follow->replacement);
      follow = (TransformOp *)0;	// Mark that this has been inserted
      return true;
    }
    return false;
  }
  return true;		// Already inserted
}

void LanedRegister::LanedIterator::normalize(void)

{
  uint4 flag = 1;
  flag <<= size;
  while(flag <= mask) {
    if ((flag & mask) != 0) return;	// Found a valid lane size
    size += 1;
    flag <<= 1;
  }
  size = -1;		// Indicate ending iterator
}

/// Read XML of the form \<register name=".." vector_lane_sizes=".."/>
/// \param el is the particular \e register tag
/// \param manage is used to map register names to storage info
/// \return \b true if the XML description provides lane sizes
bool LanedRegister::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  string laneSizes;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i) == "vector_lane_sizes") {
      laneSizes = el->getAttributeValue(i);
      break;
    }
  }
  if (laneSizes.empty()) return false;
  VarnodeData storage;
  storage.space = (AddrSpace *)0;
  storage.restoreXml(el, manage);
  wholeSize = storage.size;
  sizeBitMask = 0;
  string::size_type pos = 0;
  while(pos != string::npos) {
    string::size_type nextPos = laneSizes.find(',',pos);
    string value;
    if (nextPos == string::npos) {
      value = laneSizes.substr(pos);	// To the end of the string
      pos = nextPos;
    }
    else {
      value = laneSizes.substr(pos,(nextPos - pos));
      pos = nextPos + 1;
      if (pos >= laneSizes.size())
	pos = string::npos;
    }
    istringstream s(value);
    s.unsetf(ios::dec | ios::hex | ios::oct);
    int4 sz = -1;
    s >> sz;
    if (sz < 0 || sz > 16)
      throw LowlevelError("Bad lane size: " + value);
    addLaneSize(sz);
  }
  return true;
}

TransformManager::~TransformManager(void)

{
  map<int4,TransformVar *>::iterator iter;
  for(iter=pieceMap.begin();iter!=pieceMap.end();++iter) {
    delete [] (*iter).second;
  }
}

/// \brief Should the address of the given Varnode be preserved when constructing a piece
///
/// A new Varnode will be created that represents a logical piece of the given Varnode.
/// This routine determines whether the new Varnode should be constructed using
/// storage which overlaps the given Varnode. It returns \b true if overlapping storage
/// should be used, \b false if the new Varnode should be constructed as a unique temporary.
/// \param vn is the given Varnode
/// \param bitSize is the logical size of the Varnode piece being constructed
/// \param lsbOffset is the least significant bit position of the logical value within the given Varnode
/// \return \b true if overlapping storage should be used in construction
bool TransformManager::preserveAddress(Varnode *vn,int4 bitSize,int4 lsbOffset) const

{
  if ((lsbOffset & 7) != 0) return false;	// Logical value not aligned
  if (vn->getSpace()->getType() == IPTR_INTERNAL) return false;
  return true;
}

void TransformManager::clearVarnodeMarks(void)

{
  map<int4,TransformVar *>::const_iterator iter;
  for(iter=pieceMap.begin();iter!=pieceMap.end();++iter) {
    Varnode *vn = (*iter).second->vn;
    if (vn == (Varnode *)0)
      continue;
    vn->clearMark();
  }
}

/// \param vn is the preexisting Varnode to create a placeholder for
/// \return the new placeholder node
TransformVar *TransformManager::newPreexistingVarnode(Varnode *vn)

{
  TransformVar *res = new TransformVar[1];
  pieceMap[vn->getCreateIndex()] = res;	// Enter preexisting Varnode into map, so we don't make another placeholder

  // value of 0 treats this as "piece" of itself at offset 0, allows getPiece() to find it
  res->initialize(TransformVar::preexisting,vn,vn->getSize()*8,vn->getSize(),0);
  res->flags = TransformVar::split_terminator;
  return res;
}

/// \param size is the size in bytes of the new unique Varnode
/// \return the new placeholder node
TransformVar *TransformManager::newUnique(int4 size)

{
  newVarnodes.emplace_back();
  TransformVar *res = &newVarnodes.back();
  res->initialize(TransformVar::normal_temp,(Varnode *)0,size*8,size,0);
  return res;
}

/// Create a new constant in the transform view.  A piece of an existing constant
/// can be created  by giving the existing value and the least significant offset.
/// \param size is the size in bytes of the new constant
/// \param lsbOffset is the number of bits to strip off of the existing value
/// \param val is the value of the constant
/// \return the new placeholder node
TransformVar *TransformManager::newConstant(int4 size,int4 lsbOffset,uintb val)

{
  newVarnodes.emplace_back();
  TransformVar *res = &newVarnodes.back();
  res->initialize(TransformVar::constant,(Varnode *)0,size*8,size,(val >> lsbOffset) & calc_mask(size));
  return res;
}

/// Used for creating INDIRECT placeholders.
/// \param vn is the original iop parameter to the INDIRECT
/// \return the new placeholder node
TransformVar *TransformManager::newIop(Varnode *vn)

{
  newVarnodes.emplace_back();
  TransformVar *res = &newVarnodes.back();
  res->initialize(TransformVar::constant_iop,(Varnode *)0,vn->getSize()*8,vn->getSize(),vn->getOffset());
  return res;
}

/// Given a single logical value within a larger Varnode, create a placeholder for
/// that logical value.
/// \param vn is the large Varnode
/// \param bitSize is the size of the logical value in bits
/// \param lsbOffset is the number of least significant bits of the Varnode dropped from the value
/// \return the placeholder variable
TransformVar *TransformManager::newPiece(Varnode *vn,int4 bitSize,int4 lsbOffset)

{
  TransformVar *res = new TransformVar[1];
  pieceMap[vn->getCreateIndex()] = res;
  int4 byteSize = (bitSize + 7) / 8;
  uint4 type = preserveAddress(vn, bitSize, lsbOffset) ? TransformVar::piece : TransformVar::piece_temp;
  res->initialize(type, vn, bitSize, byteSize, lsbOffset);
  res->flags = TransformVar::split_terminator;
  return res;
}

/// \brief Create placeholder nodes splitting a Varnode into its lanes
///
/// Given a big Varnode and a lane description, create placeholders for all the explicit pieces
/// that the big Varnode will be split into.
/// \param vn is the big Varnode to split
/// \param description shows how the big Varnode will be split
/// \return an array of the new TransformVar placeholders from least to most significant
TransformVar *TransformManager::newSplit(Varnode *vn,const LaneDescription &description)

{
  int4 num = description.getNumLanes();
  TransformVar *res = new TransformVar[num];
  pieceMap[vn->getCreateIndex()] = res;
  for(int4 i=0;i<num;++i) {
    int4 bitpos = description.getPosition(i) * 8;
    TransformVar *newVar = &res[i];
    int4 byteSize = description.getSize(i);
    if (vn->isConstant())
      newVar->initialize(TransformVar::constant,vn,byteSize * 8,byteSize, (vn->getOffset() >> bitpos) & calc_mask(byteSize));
    else {
      uint4 type = preserveAddress(vn, byteSize * 8, bitpos) ? TransformVar::piece : TransformVar::piece_temp;
      newVar->initialize(type,vn,byteSize * 8, byteSize, bitpos);
    }
  }
  res[num-1].flags = TransformVar::split_terminator;
  return res;
}

/// \brief Create placeholder nodes splitting a Varnode into a subset of lanes in the given description
///
/// Given a big Varnode and specific subset of a lane description, create placeholders for all
/// the explicit pieces that the big Varnode will be split into.
/// \param vn is the big Varnode to split
/// \param description gives a list of potentional lanes
/// \param numLanes is the number of lanes in the subset
/// \param startLane is the starting (least significant) lane in the subset
/// \return an array of the new TransformVar placeholders from least to most significant
TransformVar *TransformManager::newSplit(Varnode *vn,const LaneDescription &description,int4 numLanes,int4 startLane)

{
  TransformVar *res = new TransformVar[numLanes];
  pieceMap[vn->getCreateIndex()] = res;
  int4 baseBitPos = description.getPosition(startLane) * 8;
  for(int4 i=0;i<numLanes;++i) {
    int4 bitpos = description.getPosition(startLane + i) * 8 - baseBitPos;
    int4 byteSize = description.getSize(startLane + i);
    TransformVar *newVar = &res[i];
    if (vn->isConstant())
      newVar->initialize(TransformVar::constant,vn,byteSize * 8, byteSize, (vn->getOffset() >> bitpos) & calc_mask(byteSize));
    else {
      uint4 type = preserveAddress(vn, byteSize * 8, bitpos) ? TransformVar::piece : TransformVar::piece_temp;
      newVar->initialize(type,vn,byteSize * 8, byteSize, bitpos);
    }
  }
  res[numLanes-1].flags = TransformVar::split_terminator;
  return res;
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
  newOps.emplace_back();
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
  newOps.emplace_back();
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
  newOps.emplace_back();
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
  if (vn->isConstant())
    return newConstant(vn->getSize(), 0, vn->getOffset());
  map<int4,TransformVar *>::const_iterator iter;
  iter = pieceMap.find(vn->getCreateIndex());
  if (iter != pieceMap.end())
    return (*iter).second;
  return newPreexistingVarnode(vn);
}

/// Given a big Varnode, find the placeholder corresponding to the logical value
/// given by a size and significance offset.  If it doesn't exist, create it.
/// \param vn is the big Varnode containing the logical value
/// \param bitSize is the size of the logical value in bytes
/// \param lsbOffset is the signficance offset of the logical value within the Varnode
/// \return the found/created placeholder
TransformVar *TransformManager::getPiece(Varnode *vn,int4 bitSize,int4 lsbOffset)

{
  map<int4,TransformVar *>::const_iterator iter;
  iter = pieceMap.find(vn->getCreateIndex());
  if (iter != pieceMap.end()) {
    TransformVar *res = (*iter).second;
    if (res->bitSize != bitSize || res->val != lsbOffset)
      throw LowlevelError("Cannot create multiple pieces for one Varnode through getPiece");
    return res;
  }
  return newPiece(vn,bitSize,lsbOffset);
}

/// \brief Find (or create) placeholder nodes splitting a Varnode into its lanes
///
/// Given a big Varnode and a lane description, look up placeholders for all its
/// explicit pieces. If they don't exist, create them.
/// \param vn is the big Varnode to split
/// \param description shows how the big Varnode will be split
/// \return an array of the TransformVar placeholders from least to most significant
TransformVar *TransformManager::getSplit(Varnode *vn,const LaneDescription &description)

{
  map<int4,TransformVar *>::const_iterator iter;
  iter = pieceMap.find(vn->getCreateIndex());
  if (iter != pieceMap.end()) {
    return (*iter).second;
  }
  return newSplit(vn,description);
}

/// \brief Find (or create) placeholder nodes splitting a Varnode into a subset of lanes from a description
///
/// Given a big Varnode and a specific subset of a lane description, look up placeholders
/// for all the explicit pieces. If they don't exist, create them.
/// \param vn is the big Varnode to split
/// \param description describes all the possible lanes
/// \param numLanes is the number of lanes in the subset
/// \param startLane is the starting (least significant) lane in the subset
/// \return an array of the TransformVar placeholders from least to most significant
TransformVar *TransformManager::getSplit(Varnode *vn,const LaneDescription &description,int4 numLanes,int4 startLane)

{
  map<int4,TransformVar *>::const_iterator iter;
  iter = pieceMap.find(vn->getCreateIndex());
  if (iter != pieceMap.end()) {
    return (*iter).second;
  }
  return newSplit(vn,description,numLanes,startLane);
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

/// Record any input vars in the given container
/// \param inputList will hold any inputs
void TransformManager::createVarnodes(vector<TransformVar *> &inputList)

{
  map<int4,TransformVar *>::iterator piter;
  for(piter=pieceMap.begin();piter!=pieceMap.end();++piter) {
    TransformVar *vArray = (*piter).second;
    for(int4 i=0;;++i) {
      TransformVar *rvn = vArray + i;
      if (rvn->type == TransformVar::piece) {
	Varnode *vn = rvn->vn;
	if (vn->isInput()) {
	  inputList.push_back(rvn);
	  if (vn->isMark())
	    rvn->flags |= TransformVar::input_duplicate;
	  else
	    vn->setMark();
	}
      }
      rvn->createReplacement(fd);
      if ((rvn->flags & TransformVar::split_terminator)!=0)
	break;
    }
  }
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

/// Remove all input Varnodes from the given container.
/// Mark all the replacement Varnodes as inputs.
/// \param inputList is the given container of input placeholders
void TransformManager::transformInputVarnodes(vector<TransformVar *> &inputList)

{
  for(int4 i=0;i<inputList.size();++i) {
    TransformVar *rvn = inputList[i];
    if ((rvn->flags & TransformVar::input_duplicate)==0)
      fd->deleteVarnode(rvn->vn);
    rvn->replacement = fd->setInputVarnode(rvn->replacement);
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
  vector<TransformVar *> inputList;
  createOps();
  createVarnodes(inputList);
  removeOld();
  transformInputVarnodes(inputList);
  placeInputs();
}

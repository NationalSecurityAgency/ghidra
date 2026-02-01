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
#include "constseq.hh"
#include "funcdata.hh"

namespace ghidra {

const int4 ArraySequence::MINIMUM_SEQUENCE_LENGTH = 4;
const int4 ArraySequence::MAXIMUM_SEQUENCE_LENGTH = 0x20000;

/// Initialize the sequence with the \b root operation which writes the earliest character in the memory region.
/// \param fdata is the function containing the sequence
/// \param ct is the data-type of an element in the array
/// \param root is the PcodeOp to be interpreted as the root, copying the earliest element
ArraySequence::ArraySequence(Funcdata &fdata,Datatype *ct,PcodeOp *root)
  :data(fdata)
{
  rootOp = root;
  charType = ct;
  block = rootOp->getParent();
  numElements = 0;
}

/// The output Varnodes themselves should be verified to only be read outside of the basic block.
/// So effectively only LOADs, STOREs, and CALLs can really interfere.  Check for these between the given ops.
/// \param startOp is the starting op to check
/// \param endOp is the ending op
/// \return \b true if there is no interference, \b false if there is possible interference
bool ArraySequence::interfereBetween(PcodeOp *startOp,PcodeOp *endOp)

{
  startOp = startOp->nextOp();
  while(startOp != endOp) {
    if (startOp->getEvalType() == PcodeOp::special) {
      OpCode opc = startOp->code();
      if (opc != CPUI_INDIRECT && opc != CPUI_CALLOTHER &&
	  opc != CPUI_SEGMENTOP && opc != CPUI_CPOOLREF && opc != CPUI_NEW)
	return false;
    }
    startOp = startOp->nextOp();
  }
  return true;
}

/// Sort the ops based on block order. Starting with the root op, walk backward until an interfering
/// gap is found or until the earliest op is reached.  Similarly, walk forward until an interfering gap is found.
/// Truncate the op array to be this smaller set.  If too many were truncated, return \b false.
/// \return \b true if a maximal set of ops is found containing at the least the minimum number required
bool ArraySequence::checkInterference(void)

{
  sort(moveOps.begin(),moveOps.end());		// Sort ops based on basic block order
  int4 pos;
  for(pos=0;pos<moveOps.size();++pos) {
    if (moveOps[pos].op == rootOp) break;
  }
  if (pos == moveOps.size()) return false;
  PcodeOp *curOp = moveOps[pos].op;
  int4 startingPos,endingPos;
  for(startingPos=pos-1;startingPos>=0;--startingPos) {
    PcodeOp *prevOp = moveOps[startingPos].op;
    if (!interfereBetween(prevOp,curOp))
      break;
    curOp = prevOp;
  }
  startingPos += 1;
  curOp = moveOps[pos].op;
  for(endingPos=pos+1;endingPos < moveOps.size();++endingPos) {
    PcodeOp *nextOp = moveOps[endingPos].op;
    if (!interfereBetween(curOp,nextOp))
      break;
    curOp = nextOp;
  }
  if (endingPos- startingPos < MINIMUM_SEQUENCE_LENGTH)
    return false;
  if (startingPos > 0) {
    for(int4 i=startingPos;i<endingPos;++i) {
      moveOps[i-startingPos] = moveOps[i];
    }
  }
  moveOps.resize(endingPos-startingPos,WriteNode(0,(PcodeOp *)0,-1));
  return true;
}

/// Create an array of bytes being written into the memory region.
/// Run through the ops and place their constant input (at given \b slot) into the array based on their
/// offset, relative to the given root offset.
/// If there are gaps in the byte array, remove any op that doesn't write to the contiguous
/// region in front of the root.  Return 0 if the contiguous region is too small.
/// \param sz is the maximum size of the byte array
/// \param slot is the slot to fetch input constants from
/// \param rootOff is the root offset
/// \param bigEndian is \b true if constant inputs have big endian encoding
/// \return the number of characters in the contiguous region
int4 ArraySequence::formByteArray(int4 sz,int4 slot,uint8 rootOff,bool bigEndian)

{
  byteArray.resize(sz,0);
  vector<uint1> used(sz,0);
  int4 elSize = charType->getSize();
  for(int4 i=0;i<moveOps.size();++i) {
    int4 bytePos = moveOps[i].offset - rootOff;
    if (bytePos < 0 || bytePos + elSize > sz) continue;
    uint8 val = moveOps[i].op->getIn(slot)->getOffset();
    used[bytePos] = (val == 0) ? 2 : 1;		// Mark byte as used, a 2 indicates a null terminator
    if (bigEndian) {
      for(int4 j=0;j<elSize;++j) {
	uint1 b = (val >> (elSize-1-j)*8) & 0xff;
	byteArray[bytePos+j] = b;
      }
    }
    else {
      for(int4 j=0;j<elSize;++j) {
	byteArray[bytePos+j] = (uint1)val;
	val >>= 8;
      }
    }
  }
  int4 bigElSize = charType->getAlignSize();
  int4 maxEl = used.size() / bigElSize;
  int4 count;
  for(count=0;count<maxEl;count += 1) {
    uint1 val = used[ count * bigElSize ];
    if (val != 1) {		// Count number of characters not including null terminator
      if (val == 2)
	count += 1;		// Allow a single null terminator
      break;
    }
  }
  if (count < MINIMUM_SEQUENCE_LENGTH)
    return 0;
  if (count != moveOps.size()) {
    uint8 maxOff = rootOff + count * bigElSize;
    vector<WriteNode> finalOps;
    for(int4 i=0;i<moveOps.size();++i) {
      if (moveOps[i].offset < maxOff)
	finalOps.push_back(moveOps[i]);
    }
    moveOps.swap(finalOps);
  }
  return count;
}

/// Use the \b charType to select the appropriate string copying function.  If a match to the \b charType
/// doesn't exist, use a built-in \b memcpy function.  The id of the selected built-in function is returned.
/// The value indicating either the number of characters or number of bytes being copied is also passed back.
/// \param index will hold the number of elements being copied
uint4 ArraySequence::selectStringCopyFunction(int4 &index)

{
  TypeFactory *types = data.getArch()->types;
  if (charType == types->getTypeChar(types->getSizeOfChar())) {
    index = numElements;
    return UserPcodeOp::BUILTIN_STRNCPY;
  }
  else if (charType == types->getTypeChar(types->getSizeOfWChar())) {
    index = numElements;
    return UserPcodeOp::BUILTIN_WCSNCPY;
  }
  index = numElements * charType->getAlignSize();
  return UserPcodeOp::BUILTIN_MEMCPY;
}

/// \brief Set-up for recovering COPY ops into a memory range, given a Symbol and an Address being COPYed into
///
/// The SymbolEntry and Address are passed in, with an expected data-type.  Check if there is an array
/// of the data-type within the Symbol, and if so, initialize the memory range for the sequence.
/// Follow on with gathering PcodeOps and testing if the sequence is viable.  If not, the size of the memory
/// range will be set to zero.
/// \param fdata is the function containing the root COPY
/// \param ct is the specific data-type for which there should be an array
/// \param ent is the given Symbol
/// \param root is the COPY holding the constant
/// \param addr is the Address being COPYed into
StringSequence::StringSequence(Funcdata &fdata,Datatype *ct,SymbolEntry *ent,PcodeOp *root,const Address &addr)
  : ArraySequence(fdata,ct,root)
{
  rootAddr = addr;
  entry = ent;
  if (entry->getAddr().getSpace() != addr.getSpace())
    return;
  int8 off = rootAddr.getOffset() - entry->getFirst();
  if (off >= entry->getSize())
    return;
  if (rootOp->getIn(0)->getOffset() == 0)
    return;
  Datatype *parentType = entry->getSymbol()->getType();
  Datatype *arrayType = (Datatype *)0;
  int8 lastOff = 0;
  do {
    if (parentType == ct)
      break;
    arrayType = parentType;
    lastOff = off;
    parentType = parentType->getSubType(off, &off);
  } while(parentType != (Datatype *)0);
  if (parentType != ct || arrayType == (Datatype *)0 || arrayType->getMetatype() != TYPE_ARRAY)
    return;
  startAddr = rootAddr - lastOff;
  if (!collectCopyOps(arrayType->getSize()))
    return;
  if (!checkInterference())
    return;
  int4 arrSize = arrayType->getSize() - (int4)(rootAddr.getOffset() - startAddr.getOffset());
  numElements = formByteArray(arrSize,0,rootAddr.getOffset(),rootAddr.isBigEndian());
}

/// The COPYs must be in the same basic block.
/// If any COPY size does not match the \b copyType, return \b false.
/// If there is a COPY to the array entry before rootVn, return \b false.
/// Otherwise earlier COPYs are skipped. No COPYs are collected after the first gap (entry with no COPY to it).
/// \param size is the number of bytes in the memory region
/// \return \b true to indicate legal COPY ops of constants were recovered.
bool StringSequence::collectCopyOps(int4 size)

{
  Address endAddr = startAddr + (size - 1);		// startAddr - endAddr bounds the formal array
  Address beginAddr = startAddr;			// Start search for COPYs at the start of the array
  if (startAddr != rootAddr) {
    beginAddr = rootAddr - charType->getAlignSize();	// or the first address before the root address (whichever is later)
  }
  VarnodeLocSet::const_iterator iter = data.beginLoc(beginAddr);
  VarnodeLocSet::const_iterator enditer = data.endLoc(endAddr);
  int4 diff = rootAddr.getOffset() - startAddr.getOffset();
  while(iter != enditer) {
    Varnode *vn = *iter;
    ++iter;
    if (!vn->isWritten()) continue;
    PcodeOp *op = vn->getDef();
    if (op->code() != CPUI_COPY) continue;
    if (op->getParent() != block) continue;
    if (!op->getIn(0)->isConstant()) continue;
    if (vn->getSize() != charType->getSize())
      return false;		// COPY is the wrong size (has yet to be split)
    int4 tmpDiff = vn->getOffset() - startAddr.getOffset();
    if (tmpDiff < diff) {
      if (tmpDiff + charType->getAlignSize() == diff)
	return false;		// COPY to previous element, rootVn is not the first in sequence
      continue;
    }
    else if (tmpDiff > diff) {
      if (tmpDiff - diff < charType->getAlignSize())
	continue;
      if (tmpDiff - diff > charType->getAlignSize())
	break;			// Gap in COPYs
      diff = tmpDiff;		// Advanced by one character
    }
    moveOps.emplace_back(vn->getOffset(),op,-1);
  }
  return (moveOps.size() >= MINIMUM_SEQUENCE_LENGTH);
}

/// \brief Construct a Varnode, with data-type, that acts as a pointer (in)to the Symbol to the root Address
///
/// First, a PTRSUB is built from the base register to the Symbol.  Then depending on its data-type, additional
/// PTRSUBs and PTRADDs are buit to get from the start of the Symbol to the memory region holding the character data.
/// All the new Varnodes have the appropriate pointer data-type set.  The final Varnode holding the pointer to
/// the memory region is returned.
/// \param insertPoint is the point before which all new PTRSUBs and PTRADDs are inserted
Varnode *StringSequence::constructTypedPointer(PcodeOp *insertPoint)

{
  Varnode *spacePtr;
  AddrSpace *spc = rootAddr.getSpace();
  TypeFactory *types = data.getArch()->types;
  if (spc->getType() == IPTR_SPACEBASE)
    spacePtr = data.constructSpacebaseInput(spc);
  else
    spacePtr = data.constructConstSpacebase(spc);
  Datatype *baseType = entry->getSymbol()->getType();
  PcodeOp *ptrsub = data.newOp(2, insertPoint->getAddr());
  data.opSetOpcode(ptrsub, CPUI_PTRSUB);
  data.opSetInput(ptrsub,spacePtr,0);
  uintb baseOff = AddrSpace::byteToAddress(entry->getFirst(),spc->getWordSize());	// Convert to address units
  data.opSetInput(ptrsub,data.newConstant(spacePtr->getSize(), baseOff),1);
  spacePtr = data.newUniqueOut(spacePtr->getSize(), ptrsub);
  data.opInsertBefore(ptrsub, insertPoint);
  TypePointer *curType = types->getTypePointerStripArray(spacePtr->getSize(), baseType, spc->getWordSize());
  spacePtr->updateType(curType);
  int8 curOff = rootAddr.getOffset() - entry->getFirst();
  while(baseType != charType) {
    int4 elSize = -1;
    if (baseType->getMetatype() == TYPE_ARRAY)
      elSize = ((TypeArray *)baseType)->getBase()->getAlignSize();
    int8 newOff;
    baseType = baseType->getSubType(curOff, &newOff );
    if (baseType == (Datatype *)0) break;
    curOff -= newOff;
    baseOff = AddrSpace::byteToAddress(curOff, spc->getWordSize());
    if (elSize >= 0) {
      if (curOff == 0) {	// Don't create a PTRADD( #0, ...)
	// spacePtr already has data-type with ARRAY stripped
	// baseType is already updated
	continue;
      }
      ptrsub = data.newOp(3, insertPoint->getAddr());
      data.opSetOpcode(ptrsub, CPUI_PTRADD);
      int8 numEl = curOff / elSize;
      data.opSetInput(ptrsub,data.newConstant(4, numEl),1);
      data.opSetInput(ptrsub,data.newConstant(4,elSize),2);
    }
    else {
      ptrsub = data.newOp(2, insertPoint->getAddr());
      data.opSetOpcode(ptrsub, CPUI_PTRSUB);
      data.opSetInput(ptrsub,data.newConstant(spacePtr->getSize(), baseOff), 1);
    }
    data.opSetInput(ptrsub,spacePtr,0);
    spacePtr = data.newUniqueOut(spacePtr->getSize(), ptrsub);
    data.opInsertBefore(ptrsub, insertPoint);
    curType = types->getTypePointerStripArray(spacePtr->getSize(), baseType, spc->getWordSize());
    spacePtr->updateType(curType);
    curOff = newOff;
  }
  if (curOff != 0) {
    PcodeOp *addOp = data.newOp(2, insertPoint->getAddr());
    data.opSetOpcode(addOp, CPUI_INT_ADD);
    data.opSetInput(addOp, spacePtr, 0);
    baseOff = AddrSpace::byteToAddress(curOff, spc->getWordSize());
    data.opSetInput(addOp, data.newConstant(spacePtr->getSize(), baseOff), 1);
    spacePtr = data.newUniqueOut(spacePtr->getSize(), addOp);
    data.opInsertBefore(addOp, insertPoint);
    curType = types->getTypePointer(spacePtr->getSize(), charType, spc->getWordSize());
    spacePtr->updateType(curType);
  }
  return spacePtr;
}

/// A built-in user-op that copies string data is created.  Its first (destination) parameter is constructed
/// as a pointer to the array holding the character data, which may be nested in other arrays or structures.
/// The second (source) parameter is an \e internal \e string constructed from the \b byteArray.  The
/// third parameter is the constant indicating the length of the string.  The \e user-op is inserted just before
/// the last PcodeOp moving a character into the memory region.
/// \return the constructed PcodeOp representing the \b memcpy
PcodeOp *StringSequence::buildStringCopy(void)

{
  PcodeOp *insertPoint = moveOps[0].op;		// Earliest COPY in the block
  int4 numBytes = moveOps.size() * charType->getSize();
  Architecture *glb = data.getArch();
  TypeFactory *types = glb->types;
  Datatype *charPtrType = types->getTypePointer(types->getSizeOfPointer(),charType,rootAddr.getSpace()->getWordSize());
  Varnode *srcPtr = data.getInternalString(byteArray.data(), numBytes, charPtrType, insertPoint);
  if (srcPtr == (Varnode *)0)
    return (PcodeOp *)0;
  int4 index;
  uint4 builtInId = selectStringCopyFunction(index);
  glb->userops.registerBuiltin(builtInId);
  PcodeOp *copyOp = data.newOp(4,insertPoint->getAddr());
  data.opSetOpcode(copyOp, CPUI_CALLOTHER);
  data.opSetInput(copyOp, data.newConstant(4, builtInId), 0);
  Varnode *destPtr = constructTypedPointer(insertPoint);
  data.opSetInput(copyOp, destPtr, 1);
  data.opSetInput(copyOp, srcPtr, 2);
  Varnode *lenVn = data.newConstant(4,index);
  lenVn->updateType(copyOp->inputTypeLocal(3));
  data.opSetInput(copyOp, lenVn, 3);
  data.opInsertBefore(copyOp, insertPoint);
  return copyOp;
}

/// \brief Analyze output descendants of the given PcodeOp being removed
///
/// Record any \b points where the output is being read, for later replacement.
/// Keep track of CPUI_PIECE ops whose input is from a PcodeOp being removed, and if both inputs are
/// visited, remove the input \e points and add the CPUI_PIECE to the list of PcodeOps being removed.
/// \param curNode is the given PcodeOp being removed
/// \param xref are the set of CPUI_PIECE ops with one input visited
/// \param points is the set of input points whose PcodeOp is being removed
/// \param deadOps is the current collection of PcodeOps being removed
void StringSequence::removeForward(const WriteNode &curNode,map<PcodeOp *,list<WriteNode>::iterator> &xref,
				   list<WriteNode> &points,vector<WriteNode> &deadOps)
{
  Varnode *vn = curNode.op->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    map<PcodeOp *,list<WriteNode>::iterator>::iterator miter = xref.find(op);
    if (miter != xref.end()) {
      // We have seen the PIECE twice
      uint8 off = (*(*miter).second).offset;
      if (curNode.offset < off)
	off = curNode.offset;
      points.erase((*miter).second);
      deadOps.emplace_back(off,op,-1);
    }
    else {
      int4 slot = op->getSlot(vn);
      points.emplace_back(curNode.offset,op,slot);
      if (op->code() == CPUI_PIECE) {
	list<WriteNode>::iterator xrefIter = points.end();
	--xrefIter;
	xref[op] = xrefIter;
      }
    }
  }
}

/// The COPY ops are removed.  Any descendants of the COPY output are redefined with an INDIRECT around
/// the a CALLOTHER op.  If the COPYs feed into a PIECE op (as part of a CONCAT stack), the PIECE is removed
/// as well, which may cascade into removal of other PIECE ops in the stack.
/// \param replaceOp is the CALLOTHER op creating the INDIRECT effect
void StringSequence::removeCopyOps(PcodeOp *replaceOp)

{
  map<PcodeOp *,list<WriteNode>::iterator> concatSet;
  list<WriteNode> points;
  vector<WriteNode> deadOps;
  for(int4 i=0;i<moveOps.size();++i) {
    removeForward(moveOps[i],concatSet,points,deadOps);
  }
  int4 pos = 0;
  while(pos < deadOps.size()) {
    removeForward(deadOps[pos],concatSet,points,deadOps);
    pos += 1;
  }
  for(list<WriteNode>::iterator iter=points.begin();iter!=points.end();++iter) {
    PcodeOp *op = (*iter).op;
    Varnode *vn = op->getIn((*iter).slot);
    if (vn->getDef()->code() != CPUI_INDIRECT) {
      Varnode *newIn = data.newConstant(vn->getSize(),0);
      PcodeOp *indOp = data.newOp(2, replaceOp->getAddr());
      data.opSetOpcode(indOp,CPUI_INDIRECT);
      data.opSetInput(indOp,newIn,0);
      data.opSetInput(indOp,data.newVarnodeIop(replaceOp),1);
      data.opSetOutput(indOp, vn);
      data.markIndirectCreation(indOp, false);
      data.opInsertBefore(indOp,replaceOp);
    }
  }
  for(int4 i=0;i<moveOps.size();++i)
    data.opDestroy(moveOps[i].op);
  for(int4 i=0;i<deadOps.size();++i)
    data.opDestroy(deadOps[i].op);
}

/// The transform can only fail if the byte array does not encode a valid string, in which case \b false is returned.
/// Otherwise, a CALLOTHER representing \b memcpy is constructed taking the string constant as its \e source pointer.
/// The original COPY ops are removed.
/// \return \b true if the transform succeeded and the CALLOTHER is created
bool StringSequence::transform(void)

{
  PcodeOp *memCpyOp = buildStringCopy();
  if (memCpyOp == (PcodeOp *)0)
    return false;
  removeCopyOps(memCpyOp);
  return true;
}

/// From a starting pointer, backtrack through PTRADDs and COPYs to a putative root Varnode pointer.
/// \param initPtr is pointer Varnode into the root STORE
void HeapSequence::findBasePointer(Varnode *initPtr)

{
  basePointer = initPtr;
  while(basePointer->isWritten()) {
    PcodeOp *op = basePointer->getDef();
    OpCode opc = op->code();
    if (opc == CPUI_PTRADD) {
      int8 sz = op->getIn(2)->getOffset();
      if (sz != ptrAddMult) break;
    }
    else if (opc != CPUI_COPY)
      break;
    basePointer = op->getIn(0);
  }
}

/// Back-track from \b basePointer through PTRSUBs, PTRADDs, and INT_ADDs to an earlier root, keeping track
/// of any offsets.  If an earlier root exists, trace forward, through ops trying to match the offsets.
/// For trace of ops whose offsets match exactly, the resulting Varnode is added to the list of duplicates.
/// \param duplist will hold the list of duplicate Varnodes (including \b basePointer)
void HeapSequence::findDuplicateBases(vector<Varnode *> &duplist)

{
  if (!basePointer->isWritten()) {
    duplist.push_back(basePointer);
    return;
  }
  PcodeOp *op = basePointer->getDef();
  OpCode opc = op->code();
  if ((opc != CPUI_PTRSUB && opc != CPUI_INT_ADD && opc != CPUI_PTRADD) || !op->getIn(1)->isConstant()) {
    duplist.push_back(basePointer);
    return;
  }
  Varnode *copyRoot = basePointer;
  vector<uintb> offset;
  do {
    uintb off = op->getIn(1)->getOffset();
    if (opc == CPUI_PTRADD)
      off *= op->getIn(2)->getOffset();
    offset.push_back(off);
    copyRoot = op->getIn(0);
    if (!copyRoot->isWritten()) break;
    op = copyRoot->getDef();
    opc = op->code();
    if (opc != CPUI_PTRSUB && opc != CPUI_INT_ADD && opc != CPUI_PTRSUB)
      break;
  } while(op->getIn(1)->isConstant());

  duplist.push_back(copyRoot);
  vector<Varnode *> midlist;
  for(int4 i=offset.size()-1;i>=0;--i) {
    duplist.swap(midlist);
    duplist.clear();
    for(int4 j=0;j<midlist.size();++j) {
      Varnode *vn = midlist[j];
      list<PcodeOp *>::const_iterator iter = vn->beginDescend();
      while(iter != vn->endDescend()) {
	op = *iter;
	++iter;
	opc = op->code();
	if (opc != CPUI_PTRSUB && opc != CPUI_INT_ADD && opc != CPUI_PTRSUB)
	  continue;
	if (op->getIn(0) != vn || !op->getIn(1)->isConstant())
	  continue;
	uintb off = op->getIn(1)->getOffset();
	if (opc == CPUI_PTRADD)
	  off *= op->getIn(2)->getOffset();
	if (off != offset[i])
	  continue;
	duplist.push_back(op->getOut());
      }
    }
  }
}

/// Find STOREs with pointers derived from the \b basePointer and that are in the same
/// basic block as the root STORE.  The root STORE is \e not included in the resulting set.
/// \param stores holds the collected STOREs
void HeapSequence::findInitialStores(vector<PcodeOp *> &stores)

{
  vector<Varnode *> ptradds;
  findDuplicateBases(ptradds);
  int4 pos = 0;
  while(pos < ptradds.size()) {
    Varnode *vn = ptradds[pos];
    pos += 1;
    list<PcodeOp *>::const_iterator iter;
    for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      PcodeOp *op = *iter;
      OpCode opc = op->code();
      if (opc == CPUI_PTRADD) {
	if (op->getIn(0) != vn) continue;
	// We only check array element size here, if we checked the data-type, we would
	// need to take into account different pointer styles to the same element data-type
	if (op->getIn(2)->getOffset() != ptrAddMult) continue;
	ptradds.push_back(op->getOut());
      }
      else if (opc == CPUI_COPY) {
	ptradds.push_back(op->getOut());
      }
      else if (opc == CPUI_STORE && op->getParent() == block && op != rootOp) {
	if (op->getIn(1) != vn) continue;
	stores.push_back(op);
      }
    }
  }
}

/// \brief Recursively walk an ADD tree from a given root, collecting offsets and non-constant elements
///
/// The constant offsets are returned as a final summed offset.  Any non-constant Varnodes encountered are
/// passed back in a list.  Recursion is depth limited.
/// \param vn is the given root of ADD tree
/// \param nonConst will hold the list of non-constant Varnodes in the tree
/// \param maxDepth is the maximum recursion depth
/// \return the sum of all constant offsets
uint8 HeapSequence::calcAddElements(Varnode *vn,vector<Varnode *> &nonConst,int4 maxDepth)

{
  if (vn->isConstant())
    return vn->getOffset();
  if (!vn->isWritten()||vn->getDef()->code() != CPUI_INT_ADD || maxDepth == 0) {
    nonConst.push_back(vn);
    return 0;
  }
  uint8 res = calcAddElements(vn->getDef()->getIn(0),nonConst,maxDepth-1);
  res += calcAddElements(vn->getDef()->getIn(1),nonConst,maxDepth-1);
  return res;
}

/// \brief Calculate the  byte offset and any non-constant additive elements between the given Varnode and the \b basePointer
///
/// Walk backward from the given Varnode thru PTRADDs and COPYs, summing any offsets encountered.
/// Any non-constant Varnodes encountered in the path, that are not themselves a pointer, are passed back in a list.
/// \param vn is the given Varnode to trace back to the \b basePointer
/// \param nonConst will hold the list of non-constant Varnodes being passed back
/// \return the sum off constant offsets on the path in byte units
uint8 HeapSequence::calcPtraddOffset(Varnode *vn,vector<Varnode *> &nonConst)

{
  uint8 res = 0;
  while(vn->isWritten()) {
    PcodeOp *op = vn->getDef();
    OpCode opc = op->code();
    if (opc == CPUI_PTRADD) {
      uint8 mult = op->getIn(2)->getOffset();
      if (mult != ptrAddMult)
	break;
      uint8 off = calcAddElements(op->getIn(1),nonConst,3);
      off *= mult;
      res += off;
      vn = op->getIn(0);
    }
    else if (opc == CPUI_COPY) {
      vn = op->getIn(0);
    }
    else
      break;
  }
  return AddrSpace::addressToByteInt(res, storeSpace->getWordSize());
}

/// \brief Determine if two sets of Varnodes are equal
///
/// The sets are passed in as arrays that are assumed sorted.  If the sets contain the
/// exact same Varnodes, \b true is returned, \b false otherwise.
/// \param op1 is the first set
/// \param op2 is the second set
/// \return \b true if and only if the sets are equal
bool HeapSequence::setsEqual(const vector<Varnode *> &op1,const vector<Varnode *> &op2)

{
  if (op1.size() != op2.size()) return false;
  for(int4 i=0;i<op1.size();++i) {
    if (op1[i] != op2[i]) return false;
  }
  return true;
}

/// \param op is the STORE to test
/// \return \b true if the value being STOREd has the right size and type
bool HeapSequence::testValue(PcodeOp *op)

{
  Varnode *vn = op->getIn(2);
  if (!vn->isConstant())
    return false;
  if (vn->getSize() != charType->getSize())
    return false;
  return true;
}

/// Walk forward from the base pointer to all STORE ops from that pointer, keeping track of the offset.
/// The final set of STOREs will all be in the same basic block as the root STORE and have
/// a greater than or equal offset.  If the minimum sequence size is reached, \b true is returned.
/// \return \b true if the minimum number of STOREs is collected.
bool HeapSequence::collectStoreOps(void)

{
  vector<PcodeOp *> initStores;
  findInitialStores(initStores);
  if (initStores.size() + 1 < MINIMUM_SEQUENCE_LENGTH)
    return false;
  uint8 maxSize = MAXIMUM_SEQUENCE_LENGTH * charType->getAlignSize();	// Maximum bytes
  uint8 wrapMask = calc_mask(storeSpace->getAddrSize());
  baseOffset = calcPtraddOffset(rootOp->getIn(1), nonConstAdds);
  vector<Varnode *> nonConstComp;
  for(int4 i=0;i<initStores.size();++i) {
    PcodeOp *op = initStores[i];
    nonConstComp.clear();
    uint8 curOffset = calcPtraddOffset(op->getIn(1), nonConstComp);
    uint8 diff = (curOffset - baseOffset) & wrapMask;	// Allow wrapping relative to base pointer
    if (setsEqual(nonConstAdds, nonConstComp)) {
      if (diff >= maxSize)
	return false;			// Root is not the earliest STORE, or offsets span range larger then maxSize
      if (!testValue(op))
	return false;
      moveOps.emplace_back(diff,op,-1);
    }
  }
  moveOps.emplace_back(0,rootOp,-1);

  return true;
}

/// A built-in user-op that copies string data is created.  Its first (destination) parameter is
/// the base pointer of the STOREs. with the base offset added to it.
/// The second (source) parameter is an \e internal \e string constructed from the \b byteArray.  The
/// third parameter is the constant indicating the length of the string.  The \e user-op is inserted just before
/// the last PcodeOp moving a character into the memory region.
/// \return the constructed PcodeOp representing the \b memcpy
PcodeOp *HeapSequence::buildStringCopy(void)

{
  PcodeOp *insertPoint = moveOps[0].op;		// Earliest STORE in the block
  Datatype *charPtrType = rootOp->getIn(1)->getTypeReadFacing(rootOp);
  int4 numBytes = numElements * charType->getSize();
  Architecture *glb = data.getArch();
  Varnode *srcPtr = data.getInternalString(byteArray.data(), numBytes, charPtrType, insertPoint);
  if (srcPtr == (Varnode *)0)
    return (PcodeOp *)0;
  Varnode *destPtr = basePointer;
  if (baseOffset != 0 || !nonConstAdds.empty()) {	// Create the index Varnode
    Varnode *indexVn = (Varnode *)0;
    Datatype *intType = glb->types->getBase(basePointer->getSize(), TYPE_INT);
    if (nonConstAdds.size() > 0) {			// Add in any non-constant Varnodes
      indexVn = nonConstAdds[0];
      for(int4 i=1;i<nonConstAdds.size();++i) {
	PcodeOp *addOp = data.newOp(2,insertPoint->getAddr());
	data.opSetOpcode(addOp, CPUI_INT_ADD);
	data.opSetInput(addOp, indexVn, 0);
	data.opSetInput(addOp, nonConstAdds[i],1);
	indexVn = data.newUniqueOut(indexVn->getSize(), addOp);
	indexVn->updateType(intType);
	data.opInsertBefore(addOp, insertPoint);
      }
    }
    if (baseOffset != 0) {				// Add in any non-zero constant
      uint8 numEl = baseOffset / charType->getAlignSize();
      Varnode *cvn = data.newConstant(basePointer->getSize(), numEl);
      cvn->updateType(intType);
      if (indexVn == (Varnode *)0)
	indexVn = cvn;
      else {
	PcodeOp *addOp = data.newOp(2,insertPoint->getAddr());
	data.opSetOpcode(addOp, CPUI_INT_ADD);
	data.opSetInput(addOp, indexVn, 0);
	data.opSetInput(addOp, cvn,1);
	indexVn = data.newUniqueOut(indexVn->getSize(), addOp);
	indexVn->updateType(intType);
	data.opInsertBefore(addOp, insertPoint);
      }
    }
    PcodeOp *ptrAdd = data.newOp(3,insertPoint->getAddr());
    data.opSetOpcode(ptrAdd, CPUI_PTRADD);
    destPtr = data.newUniqueOut(basePointer->getSize(), ptrAdd);
    data.opSetInput(ptrAdd,basePointer,0);
    data.opSetInput(ptrAdd,indexVn,1);
    data.opSetInput(ptrAdd,data.newConstant(basePointer->getSize(), charType->getAlignSize()),2);
    destPtr->updateType(charPtrType);
    data.opInsertBefore(ptrAdd, insertPoint);
  }
  int4 index;
  uint4 builtInId = selectStringCopyFunction(index);
  glb->userops.registerBuiltin(builtInId);
  PcodeOp *copyOp = data.newOp(4,insertPoint->getAddr());
  data.opSetOpcode(copyOp, CPUI_CALLOTHER);
  data.opSetInput(copyOp, data.newConstant(4, builtInId), 0);
  data.opSetInput(copyOp, destPtr, 1);
  data.opSetInput(copyOp, srcPtr, 2);
  Varnode *lenVn = data.newConstant(4,index);
  lenVn->updateType(copyOp->inputTypeLocal(3));
  data.opSetInput(copyOp, lenVn, 3);
  data.opInsertBefore(copyOp, insertPoint);
  return copyOp;
}

/// \brief Gather INDIRECT ops attached to the final sequence STOREs and their input/output Varnode pairs
///
/// There may be chained INDIRECTs for a single storage location as it crosses multiple STORE ops.  Only
/// the initial input and final output are gathered.
/// \param indirects will hold the INDIRECT ops attached to sequence STOREs
/// \param pairs will hold Varnode pairs where the first in the pair is the input and the second is the output
void HeapSequence::gatherIndirectPairs(vector<PcodeOp *> &indirects,vector<Varnode *> &pairs)

{
  for(int4 i=0;i<moveOps.size();++i) {
    PcodeOp *op = moveOps[i].op->previousOp();
    while(op != (PcodeOp *)0) {
      if (op->code() != CPUI_INDIRECT) break;
      op->setMark();
      indirects.push_back(op);
      op = op->previousOp();
    }
  }
  for(int4 i=0;i<indirects.size();++i) {
    PcodeOp *op = indirects[i];
    Varnode *outvn = op->getOut();
    bool hasUse = false;
    list<PcodeOp *>::const_iterator iter;
    for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
      PcodeOp *useOp = *iter;
      if (!useOp->isMark()) {	// Look for read of outvn that is not by another STORE INDIRECT
	hasUse = true;
	break;
      }
    }
    if (hasUse) {		// If it has another use
      Varnode *invn = op->getIn(0);
      while(invn->isWritten()) {
	PcodeOp *defOp = invn->getDef();	// Trace back to input Varnode that is not defined by a STORE INDIRECT
	if (!defOp->isMark()) break;
	invn = defOp->getIn(0);
      }
      pairs.push_back(invn);
      pairs.push_back(outvn);
      data.opUnsetOutput(op);
    }
  }
  for(int4 i=0;i<indirects.size();++i)
    indirects[i]->clearMark();
}

/// If the STORE pointer no longer has any other uses, remove the PTRADD producing it, recursively,
/// up to the base pointer.  INDIRECT ops surrounding any STORE that is removed are replaced with
/// INDIRECTs around the user-op replacing the STOREs.
/// \param replaceOp is the user-op replacement for the STOREs
void HeapSequence::removeStoreOps(PcodeOp *replaceOp)

{
  vector<PcodeOp *> indirects;
  vector<Varnode *> indirectPairs;
  vector<PcodeOp *> scratch;
  gatherIndirectPairs(indirects, indirectPairs);
  for(int4 i=0;i<moveOps.size();++i) {
    PcodeOp *op = moveOps[i].op;
    data.opDestroyRecursive(op, scratch);
  }
  for(int4 i=0;i<indirects.size();++i) {
    data.opDestroy(indirects[i]);
  }
  for(int4 i=0;i<indirectPairs.size();i+=2) {
    Varnode *invn = indirectPairs[i];
    Varnode *outvn = indirectPairs[i+1];
    PcodeOp *newInd = data.newOp(2,replaceOp->getAddr());
    data.opSetOpcode(newInd, CPUI_INDIRECT);
    data.opSetOutput(newInd,outvn);
    data.opSetInput(newInd,invn,0);
    data.opSetInput(newInd,data.newVarnodeIop(replaceOp),1);
    data.opInsertBefore(newInd, replaceOp);
  }
}

/// \brief Constructor for the sequence of STORE ops
///
/// From a given STORE op, construct the sequence of STOREs off of the same root pointer.
/// The STOREs must be in the same basic block.  They can be out of order but must fill out a contiguous
/// region of memory with a minimum number of character elements.  The values being stored are accumulated
/// in a byte array. The initial STORE must have the earliest offset in the sequence.  If a sequence
/// matching these conditions isn't found, the constructed object will be in an invalid state, and
/// isInvalid() will return \b true.
/// \param fdata is the function containing the sequence
/// \param ct is the character data-type being STOREd
/// \param root is the given (putative) initial STORE in the sequence
HeapSequence::HeapSequence(Funcdata &fdata,Datatype *ct,PcodeOp *root)
  : ArraySequence(fdata,ct,root)
{
  baseOffset = 0;
  storeSpace = root->getIn(0)->getSpaceFromConst();
  ptrAddMult = AddrSpace::byteToAddressInt(charType->getAlignSize(), storeSpace->getWordSize());
  findBasePointer(rootOp->getIn(1));
  if (!collectStoreOps())
    return;
  if (!checkInterference())
    return;
  int4 arrSize = moveOps.size() * charType->getAlignSize();
  bool bigEndian = storeSpace->isBigEndian();
  numElements = formByteArray(arrSize, 2, 0, bigEndian);
}

/// The user-op representing the string move is created and all the STORE ops are removed.
/// If successful \b true is returned.  The transform fails (only) if the accumulated bytes do not
/// represent a legal unicode string.
/// \return \b true if STOREs are successfully converted to a user-op with a string representation
bool HeapSequence::transform(void)

{
  PcodeOp *memCpyOp = buildStringCopy();
  if (memCpyOp == (PcodeOp *)0)
    return false;
  removeStoreOps(memCpyOp);
  return true;
}

void RuleStringCopy::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_COPY);
}

/// \class RuleStringCopy
/// \brief Replace a sequence of COPY ops moving single characters with a CALLOTHER copying a whole string
///
/// Given a root COPY of a constant character, search for other COPYs in the same basic block that form a sequence
/// of characters that can be interpreted as a single string.  Replace the sequence of COPYs with a single
/// \b memcpy or \b wcsncpy user-op.
int4 RuleStringCopy::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(0)->isConstant()) return 0;		// Constant
  Varnode *outvn = op->getOut();
  Datatype *ct = outvn->getType();
  if (!ct->isCharPrint()) return 0;			// Copied to a "char" data-type Varnode
  if (ct->isOpaqueString()) return 0;
  if (!outvn->isAddrTied()) return 0;
  SymbolEntry *entry = data.getScopeLocal()->queryContainer(outvn->getAddr(), outvn->getSize(), op->getAddr());
  if (entry == (SymbolEntry *)0)
    return 0;
  StringSequence sequence(data,ct,entry,op,outvn->getAddr());
  if (!sequence.isValid())
    return 0;
  if (!sequence.transform())
    return 0;
  return 1;
}

void RuleStringStore::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_STORE);
}

/// \class RuleStringStore
/// \brief Replace a sequence of STORE ops moving single characters with a CALLOTHER copying a whole string
///
/// Given a root STORE of a constant character, search for other STOREs in the same basic block off of the
/// same base pointer that form a sequence a sequence that can be interpreted as a single string.  Replace
/// the STOREs with a single \b strncpy or \b wcsncpy user-op.
int4 RuleStringStore::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(2)->isConstant()) return 0;		// Constant
  Varnode *ptrvn = op->getIn(1);
  Datatype *ct = ptrvn->getTypeReadFacing(op);
  if (ct->getMetatype() != TYPE_PTR) return 0;
  ct = ((TypePointer *)ct)->getPtrTo();
  if (!ct->isCharPrint()) return 0;			// Copied to a "char" data-type Varnode
  if (ct->isOpaqueString()) return 0;
  HeapSequence sequence(data,ct,op);
  if (!sequence.isValid())
    return 0;
  if (!sequence.transform())
    return 0;
  return 1;
}

} // End namespace ghidra

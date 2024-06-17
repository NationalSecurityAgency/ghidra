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

const int4 StringSequence::MINIMUM_SEQUENCE_LENGTH = 4;

/// \brief Set-up for recovering COPY ops into a memory range, given a Symbol and an Address being COPYed into
///
/// The SymbolEntry and Address are passed in, with an expected data-type.  Check if there is an array
/// of the data-type within the Symbol, and if so, initialize the memory range for the
/// the sequence.  Follow on with gathering PcodeOps and testing if the sequence is viable.  If not, the
/// the size the memory range will be set to zero.
/// \param fdata is the function containing the root COPY
/// \param ct is the specific data-type for which there should be an array
/// \param ent is the given Symbol
/// \param root is the COPY holding the constant
/// \param addr is the Address being COPYed into
StringSequence::StringSequence(Funcdata &fdata,Datatype *ct,SymbolEntry *ent,PcodeOp *root,const Address &addr)
  : data(fdata)
{
  rootOp = root;
  rootAddr = addr;
  charType = ct;
  entry = ent;
  size = 0;
  if (entry->getAddr().getSpace() != addr.getSpace())
    return;
  int8 off = rootAddr.getOffset() - entry->getFirst();
  if (off >= entry->getSize())
    return;
  if (rootOp->getIn(0)->getOffset() == 0)
    return;
  Datatype *parentType = entry->getSymbol()->getType();
  Datatype *lastType = (Datatype *)0;
  int8 lastOff = 0;
  do {
    if (parentType == ct)
      break;
    lastType = parentType;
    lastOff = off;
    parentType = parentType->getSubType(off, &off);
  } while(parentType != (Datatype *)0);
  if (parentType != ct || lastType == (Datatype *)0 || lastType->getMetatype() != TYPE_ARRAY)
    return;
  startAddr = rootAddr - lastOff;
  size = ((TypeArray *)lastType)->numElements() * charType->getAlignSize();
  block = rootOp->getParent();
  if (collectCopyOps()) {
    if (checkCopyInterference()) {
      if (formByteArray()) {
	return;
      }
    }
  }
  clear();
}

void StringSequence::clear(void)

{
  size = 0;
  moveOps.clear();
}

/// The COPYs must be in the same basic block.
/// If any COPY size does not match the \b copyType, return \b false.
/// If there is a COPY to the array entry before rootVn, return \b false.
/// Otherwise earlier COPYs are skipped. No COPYs are collected after the first gap (entry with no COPY to it).
/// \return \b true to indicate legal COPY ops of constants were recovered.
bool StringSequence::collectCopyOps(void)

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

/// The output Varnodes themselves should be verified to only be read outside of the basic block.
/// So effectively only LOADs, STOREs, and CALLs can really interfere.  Check for these between the given ops.
/// \param startOp is the is the starting COPY
/// \param endOp is the ending COPY
/// \return \b true if there is no interference, \b false if there is possible interference
bool StringSequence::checkBetweenCopy(PcodeOp *startOp,PcodeOp *endOp)

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

/// Sort the COPY ops based on block order. Starting with the root COPY, walk backward until an interfering
/// gap is found or until the earliest COPY is reached.  Similarly, walk forward until an interfering gap is found.
/// Truncate the COPY op array to be this smaller set.  If too many were truncated, return \b false.
/// \return \b true if a maximal set of COPYs is found containing at the least the minimum number required
bool StringSequence::checkCopyInterference(void)

{
  sort(moveOps.begin(),moveOps.end());		// Sort COPYs based on basic block order
  int4 pos;
  for(pos=0;pos<moveOps.size();++pos) {
    if (moveOps[pos].op == rootOp) break;
  }
  if (pos == moveOps.size()) return false;
  PcodeOp *curOp = moveOps[pos].op;
  int4 startingPos,endingPos;
  for(startingPos=pos-1;startingPos>=0;--startingPos) {
    PcodeOp *prevOp = moveOps[startingPos].op;
    if (!checkBetweenCopy(prevOp,curOp))
      break;
    curOp = prevOp;
  }
  startingPos += 1;
  curOp = moveOps[pos].op;
  for(endingPos=pos+1;endingPos < moveOps.size();++endingPos) {
    PcodeOp *nextOp = moveOps[endingPos].op;
    if (!checkBetweenCopy(curOp,nextOp))
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
  spacePtr->updateType(curType, false, false);
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
    spacePtr->updateType(curType, false, false);
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
    spacePtr->updateType(curType, false, false);
  }
  return spacePtr;
}

/// Create an array of bytes from the root Varnode to the extent of the memory region.
/// Run through the COPYs and place their constant input into the array.
/// If there are gaps in the byte array, remove any COPY that doesn't write to the contiguous
/// region in front of the root Varnode.  Return \b false if the contiguous region is too small.
/// \return \b true if there exists enough COPYs that write into the region in front of the root Varnode without gaps
bool StringSequence::formByteArray(void)

{
  int4 diff = rootAddr.getOffset() - startAddr.getOffset();
  byteArray.resize(size-diff,0);
  vector<uint1> used(size-diff,0);
  int4 elSize = charType->getSize();
  bool isBigEndian = rootAddr.isBigEndian();
  for(int4 i=0;i<moveOps.size();++i) {
    int4 bytePos = moveOps[i].offset - rootAddr.getOffset();
    if (used[bytePos] != 0)
      return false;		// Multiple COPYs to same place
    uint8 val = moveOps[i].op->getIn(0)->getOffset();
    used[bytePos] = (val == 0) ? 2 : 1;		// Mark byte as used, a 2 indicates a null terminator
    if (isBigEndian) {
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
  int4 count;
  for(count=0;count<moveOps.size();++count) {
    uint1 val = used[ count * bigElSize ];
    if (val != 1) {		// Count number of characters not including null terminator
      if (val == 2)
	count += 1;		// Allow a single null terminator
      break;
    }
  }
  if (count < MINIMUM_SEQUENCE_LENGTH)
    return false;
  if (count != moveOps.size()) {
    uintb maxOff = rootAddr.getOffset() + count * bigElSize;
    vector<WriteNode> finalOps;
    for(int4 i=0;i<moveOps.size();++i) {
      if (moveOps[i].offset < maxOff)
	finalOps.push_back(moveOps[i]);
    }
    moveOps.swap(finalOps);
  }
  return true;
}

/// Use the \b charType to select the appropriate string copying function.  If a match to the \b charType
/// doesn't exist, use a built-in \b memcpy function.  The id of the selected built-in function is returned.
/// The value indicating either the number of characters or number of bytes being copied is also passed back.
/// \param index will hold the number of elements being copied
uint4 StringSequence::selectStringCopyFunction(int4 &index)

{
  TypeFactory *types = data.getArch()->types;
  if (charType == types->getTypeChar(types->getSizeOfChar())) {
    index = moveOps.size();
    return UserPcodeOp::BUILTIN_STRNCPY;
  }
  else if (charType == types->getTypeChar(types->getSizeOfWChar())) {
    index = moveOps.size();
    return UserPcodeOp::BUILTIN_WCSNCPY;
  }
  index = moveOps.size() * charType->getSize();
  return UserPcodeOp::BUILTIN_MEMCPY;
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
  lenVn->updateType(copyOp->inputTypeLocal(3), false, false);
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
      uintb off = (*(*miter).second).offset;
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

void RuleStringSequence::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_COPY);
}

/// \class RuleStringSequence
/// \brief Replace a sequence of COPY ops moving single characters with a \b memcpy CALLOTHER copying a whole string
///
/// Given a root COPY of a constant character, search for other COPYs in the same basic block that form a sequence
/// of characters that can be interpreted as a single string.  Replace the sequence of COPYs with a single
/// \b memcpy CALLOTHER.
int4 RuleStringSequence::applyOp(PcodeOp *op,Funcdata &data)

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

} // End namespace ghidra

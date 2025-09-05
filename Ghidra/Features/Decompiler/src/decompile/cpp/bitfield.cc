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
#include "bitfield.hh"
#include "funcdata.hh"

namespace ghidra {

BitFieldNodeState::BitFieldNodeState(const BitRange &used,Varnode *vn,const TypeBitField *fld)
    : bitsUsed(used), bitsField(fld->bits,used.byteOffset,used.byteSize)
{
  node = vn;
  field = fld;
  origLeastSigBit = bitsField.leastSigBit;
  isSignExtended = (field->type->getMetatype() == TYPE_INT) && bitsField.isMostSignificant();
}

BitFieldNodeState::BitFieldNodeState(const BitRange &used,Varnode *vn,int4 leastSig,int4 numBits)
  : bitsUsed(used), bitsField(used.byteOffset,used.byteSize,leastSig,numBits,used.isBigEndian)
{
  node = vn;
  field = (const TypeBitField *)0;
  origLeastSigBit = bitsField.leastSigBit;
  isSignExtended = false;
}

/// Copy another state, but replace \b bitsField
/// \param copy is the state to copy
/// \param newField is the new range for \b bitsField
/// \param vn is the Varnode holding the new range
/// \param sgnExt is the new state of sign extension
BitFieldNodeState::BitFieldNodeState(const BitFieldNodeState &copy,const BitRange &newField,Varnode *vn,bool sgnExt)
  : bitsUsed(copy.bitsUsed), bitsField(newField)
{
  node = vn;
  field = copy.field;
  origLeastSigBit = copy.origLeastSigBit;
  isSignExtended = sgnExt;
}

/// A BitFieldNodeState is constructed for each bitfield that the Varnode overlaps.
/// Holes between bitfields can also have a BitFieldNodeState.
/// \param vn is the given Varnode
/// \param followHoles is \b true if a record for each hole should be created
void BitFieldTransform::establishFields(Varnode *vn,bool followHoles)

{
  int4 vnBitSize = vn->getSize() * 8;
  BitRange bitrange(initialOffset,vn->getSize(),0,vnBitSize,isBigEndian);
  vector<BitFieldTriple> overlap;
  parentStruct->collectBitFields(0, overlap, initialOffset, vn->getSize());
  sort(overlap.begin(),overlap.end(),BitFieldTriple::compare);
  int4 pos = 0;
  for(int4 i=0;i<overlap.size();++i) {	// Iterate from least significant to most
    BitFieldTriple &triple(overlap[i]);
    int4 fieldPos = bitrange.translateLSB(triple.bitfield->bits);
    int4 fieldEnd = fieldPos + triple.bitfield->bits.numBits;
    if (fieldPos > vnBitSize)
      fieldPos = vnBitSize;
    if (fieldEnd > vnBitSize)
      fieldEnd = vnBitSize;
    if (fieldPos > pos) {		// We have a hole
      if (followHoles)
	workList.emplace_back(bitrange,vn,pos,(fieldPos - pos));
      pos = fieldPos;
    }
    int4 code = bitrange.overlapTest(triple.bitfield->bits);
    if (code == 0 || code == 3)// Note if field is properly contained in vn
      workList.emplace_back(bitrange,vn,triple.bitfield);		// Field is properly contained in vn
    else {
      if (followHoles)
	workList.emplace_back(bitrange,vn,pos,(fieldEnd-pos));
    }
    pos = fieldEnd;
  }
  if (pos < vnBitSize && followHoles) {
    workList.emplace_back(bitrange,vn,pos,vnBitSize-pos);	// Final hole
  }
}

/// \param f is the containing function
/// \param dt is the bitfield data-type
/// \param off is any initial byte offset into the data-type for the root Varnode
BitFieldTransform::BitFieldTransform(Funcdata *f,Datatype *dt,int4 off)

{
  func = f;
  parentStruct = (TypeStruct *)0;
  containerSize = -1;
  initialOffset = -1;
  if (dt->getMetatype() == TYPE_STRUCT) {
    parentStruct = (TypeStruct *)dt;
    initialOffset = off;
  }
  else if (dt->getMetatype() == TYPE_PARTIALSTRUCT) {
    TypePartialStruct *part = (TypePartialStruct *)dt;
    dt = part->getParent();
    if (dt->getMetatype() == TYPE_STRUCT) {
      parentStruct = (TypeStruct *)dt;
      initialOffset = off + part->getOffset();
    }
  }
  isBigEndian = f->getArch()->getDefaultDataSpace()->isBigEndian();
}

/// If the state is for a partial field whose storage location is overwritten
/// later in the same basic block, return \b true
/// \param state is the field
/// \return \b true if a partial field has been overwritten
bool BitFieldInsertTransform::isOverwrittenPartial(const BitFieldNodeState &state)

{
  if (state.field != (const TypeBitField *)0)
    return false;		// Field is not partial
  if (state.bitsField.byteSize > sizeof(uintb))
    return false;
  if (finalWriteOp->code() != CPUI_STORE) {
    // Reconstruct the original bit range
    BitRange curRange(initialOffset,mappedVn->getSize(),state.origLeastSigBit,state.bitsField.numBits,isBigEndian);
    return findOverwrite(mappedVn,finalWriteOp->getParent(),curRange);
  }
  return false;
}

bool BitFieldInsertTransform::checkPulledOriginalValue(BitFieldNodeState &state)

{
  if (!state.node->isWritten()) return false;
  PcodeOp *op = state.node->getDef();
  OpCode opc = op->code();
  if (opc != CPUI_ZPULL && opc != CPUI_SPULL) return false;
  int4 pos = (int4)op->getIn(1)->getOffset();
  int4 numbits = (int4)op->getIn(2)->getOffset();
  if (pos != state.bitsField.leastSigBit) return false;
  if (numbits != state.bitsField.numBits) return false;
  return checkOriginalBase(op->getIn(0));
}

/// If the Varnode is a the initial value of the storage being inserted into, return \b true.
/// This can be either the result of the initial LOAD or the mapped storage location being read directly.
/// \param vn is the given Varnode to check
/// \return \b true if it is the original value
bool BitFieldInsertTransform::checkOriginalBase(Varnode *vn)

{
  if (finalWriteOp->code() == CPUI_STORE) {
    if (!vn->isWritten()) return false;
    PcodeOp *loadOp = vn->getDef();
    if (loadOp->code() != CPUI_LOAD) return false;
    if (!pointerEquality(loadOp->getIn(1), finalWriteOp->getIn(1))) return false;
    if (loadOp->getParent() != finalWriteOp->getParent()) return false;
  }
  else {
    if (mappedVn == vn) return false;
    if (mappedVn->getAddr() != vn->getAddr() || mappedVn->getSize() != vn->getSize())
      return false;
    if (!vn->isAddrTied()) return false;
  }
  originalValue = vn;
  return true;
}

/// \param state is the given Varnode
/// \return \b true if the Varnode contains the \e original \e value for the bitfield(s)
bool BitFieldInsertTransform::isOriginalValue(BitFieldNodeState &state)

{
  if (state.bitsField.leastSigBit != state.origLeastSigBit) return false;
  if (state.node == originalValue) return true;
  if (checkPulledOriginalValue(state))
    return true;
  return checkOriginalBase(state.node);
}

/// If the state is not following a specific field, \b false is returned.
/// \param state gives the constant Varnode and field
/// \return \b true if an InsertRecord was created
bool BitFieldInsertTransform::addConstantWrite(BitFieldNodeState &state)

{
  uintb value = state.node->getOffset();
  state.node = (Varnode *)0;
  if (state.field == (const TypeBitField *)0) {
    return false;
  }
  if (state.bitsField.byteSize > sizeof(uintb)) return false;
  uintb mask = state.bitsField.getMask();
  value = value & mask;
  value >>= state.bitsField.leastSigBit;
  if (state.field->type->getMetatype() == TYPE_INT) {
    value = extend_signbit(value, state.bitsField.numBits, state.bitsField.byteSize);
  }
  insertList.emplace_back(value,state.field->type,state.origLeastSigBit,state.field->bits.numBits);
  return true;
}

/// If the state is not following a specific field, \b false is returned.
/// The state will no longer be followed.
/// \param state describes the field
/// \return \b true if an InsertRecord was created
bool BitFieldInsertTransform::addZeroOut(BitFieldNodeState &state)

{
  state.node = (Varnode *)0;
  if (state.field == (const TypeBitField *)0) {
    return false;
  }
  insertList.emplace_back(0,state.field->type,state.origLeastSigBit,state.field->bits.numBits);
  return true;
}

/// \param state is the specific Varnode and field
void BitFieldInsertTransform::addFieldWrite(BitFieldNodeState &state)

{
  Datatype *dt = state.field->type;
  if (dt->getSize() != state.node->getSize())
    dt = (Datatype *)0;
  insertList.emplace_back(state.node,dt,state.origLeastSigBit,state.field->bits.numBits,state.bitsField.leastSigBit);
  state.node = (Varnode *)0;
}

/// The second input must be a constant mask.
/// If the mask zeroes out the field, create a zero InsertRecord.
/// If the mask fully contains the field, follow the field through the first input.
/// Otherwise return \b false.
/// \param state is the field being followed
/// \param op is the INT_AND
/// \return \b true if the field is followed or zeroed out
bool BitFieldInsertTransform::handleAndBack(BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return false;
  if (state.bitsField.byteSize > sizeof(uintb)) return false;
  uintb val = state.bitsField.getMask();
  uintb res = val & cvn->getOffset();
  if (res == val) {
    state.node = op->getIn(0);
    state.bitsUsed.intersectMask(cvn->getOffset());	// Update bitsUsed to indicate a bit range was masked
    return true;			// This field is contained in mask
  }
  if (res == 0) {			// The field is zeroed out
    return addZeroOut(state);
  }
  return false;		// Partial zeroing
}

/// Follow the field through the input that has not masked off its bitrange.
/// If neither input has mased off the bitrange, or if both have, return \b false;
/// \param state is the field being followed
/// \param op is the INT_OR
/// \return \b true if the field is followed through a single input
bool BitFieldInsertTransform::handleOrBack(BitFieldNodeState &state,PcodeOp *op)

{
  if (state.bitsField.byteSize > sizeof(uintb)) return false;
  uintb mask = state.bitsField.getMask();
  Varnode *vn0 = op->getIn(0);
  Varnode *vn1 = op->getIn(1);
  bool isMasked0 = (vn0->getNZMask() & mask) == 0;
  bool isMasked1 = (vn1->getNZMask() & mask) == 0;
  if (isMasked0 == isMasked1) {
    if (vn1->isConstant()) {
      if ((vn1->getNZMask() & mask) == mask) {	// Or-ing constant that sets all bits of field to 1
	state.node = vn1;			// Follow the constant
	return true;
      }
    }
    return false;			// Both inputs are unmasked (or both masked), can't follow field
  }
  state.node = isMasked0 ? vn1 : vn0;		// Follow the unmasked Varnode

  return true;
}

bool BitFieldInsertTransform::handleAddBack(BitFieldNodeState &state,PcodeOp *op)

{
  if (state.bitsField.byteSize > sizeof(uintb)) return false;
  Varnode *vn0 = op->getIn(0);
  Varnode *vn1 = op->getIn(1);
  uintb mask0 = vn0->getNZMask();
  uintb mask1 = vn1->getNZMask();
  if ((mask0 & mask1) != 0)
    return false;			// Inputs are mixed, can't follow
  uintb mask = state.bitsField.getMask();
  bool isMasked0 = (mask0 & mask) == 0;
  bool isMasked1 = (mask1 & mask) == 0;
  if (isMasked0 == isMasked1)		// If both unmasked (or both masked), can't follow field
    return false;
  state.node = isMasked0 ? vn1 : vn0;
  return true;
}

/// Update the state to reflect the shift.  If the field has been completely filled with
/// zeroes by the shift, create a zero InsertRecord. If the field is only partially filled,
/// return \b false.
/// \param state is the field being followed
/// \param op is the INT_LEFT
/// \return \b true if the field is followed or been zeroed out
bool BitFieldInsertTransform::handleLeftBack(BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return false;
  int4 sa = cvn->getOffset();
  if (sa < 0 || sa >= sizeof(uintb)*8) return false;
  BitRange newRange(state.bitsField);
  newRange.shift(-sa);
  if (state.bitsField.numBits == newRange.numBits) {	// All the bits are still present
    state.bitsField = newRange;
    state.bitsUsed.shift(-sa);
    state.node = op->getIn(0);
    return true;
  }
  else if (newRange.numBits == 0) {		// Zero bits shifted into field
    return addZeroOut(state);
  }

  return false;
}

/// Update the state to reflect the shift.
/// \param state is the field being followed
/// \param op is the INT_RIGHT
/// \return \b true if the field is followed
bool BitFieldInsertTransform::handleRightBack(BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return false;
  int4 sa = cvn->getOffset();
  if (sa < 0 || sa >= sizeof(uintb)*8) return false;
  BitRange newRange(state.bitsField);
  newRange.shift(sa);
  if (state.bitsField.numBits == newRange.numBits) {	// All the bits are still present
    state.bitsField = newRange;
    state.bitsUsed.shift(sa);
    state.node = op->getIn(0);
    return true;
  }
  return false;
}

/// Follow the field to the input, and update the state to reflect the smaller byte container.
/// If the extension puts zero bits in field, return \b false.
/// \param state is the field being followed
/// \param op is the INT_ZEXT
/// \return \b true if field is followed
bool BitFieldInsertTransform::handleZextBack(BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *vn = op->getIn(0);
  int4 truncAmount = op->getOut()->getSize() - vn->getSize();
  BitRange newRange(state.bitsField);
  newRange.truncateMostSigBytes(truncAmount);
  if (state.bitsField.numBits == newRange.numBits) {
    state.bitsField = newRange;
    state.bitsUsed.truncateMostSigBytes(truncAmount);
    state.node = vn;
  }
  else if (state.bitsField.numBits == 0)
    return addZeroOut(state);		// Extended zeroes fill out the bitfield
  else
    return false;
  return true;
}

/// Treat INT_MULT by a power of 2 like INT_LEFT.
/// \param state is the field being followed
/// \param op is the INT_MULT
/// \return \b true if field is followed or zeroed out
bool BitFieldInsertTransform::handleMultBack(BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *vn1 = op->getIn(1);
  if (!vn1->isConstant()) return false;
  uintb val = vn1->getOffset();
  if (popcount(val) != 1) return false;
  int4 sa = leastsigbit_set(val);
  BitRange newRange(state.bitsField);
  newRange.shift(-sa);
  if (state.bitsField.numBits == newRange.numBits) {	// All the bits are still present
    state.bitsField = newRange;
    state.bitsUsed.shift(-sa);
    state.node = op->getIn(0);
    return true;
  }
  else if (state.bitsField.numBits == 0) {		// Zero bits shifted into field
    return addZeroOut(state);
  }
  return false;
}

/// Follow the field into the input of the SUBPIECE, which may have shifted it
/// \param state is the field being followed
/// \param op is the SUBPIECE
/// \return \b true if field is followed
bool BitFieldInsertTransform::handleSubpieceBack(BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *inVn = op->getIn(0);
  int4 extendAmount = inVn->getSize() - state.node->getSize();
  int4 sa = (int4)op->getIn(1)->getOffset() * 8;
  BitRange newRange(state.bitsField);
  newRange.extendBytes(extendAmount);
  newRange.shift(-sa);
  if (state.bitsField.numBits == newRange.numBits) {	// All the bits are still present
    state.bitsField = newRange;
    state.bitsUsed.extendBytes(extendAmount);
    state.bitsUsed.shift(-sa);
    state.node = op->getIn(0);
    return true;
  }
  return false;
}

/// If the call produces the bitfield structure directly, we can treat the return value
/// as the original value, even though the storage is not address tied.
/// \param state is the field being followed
/// \param op is the call
/// \return \b true if the return value can be treated as the \e original \e value
bool BitFieldInsertTransform::testCallOriginal(BitFieldNodeState &state,PcodeOp *op)

{
  if (!op->isCall()) return false;
  if (finalWriteOp->code() == CPUI_STORE) return false;		// If value is being STOREd, original value is not a call
  if (state.bitsField.leastSigBit != state.origLeastSigBit) return false;
  if (mappedVn->isAddrTied()) return false;		// If value is address tied, cannot have different storage
  if (originalValue != (Varnode *)0) return false;	// Already found an original value
  Datatype *dt = op->getOut()->getTypeDefFacing();
  int4 off;
  if (dt->getMetatype() == TYPE_STRUCT) {
    off = 0;
  }
  else if (dt->getMetatype() == TYPE_PARTIALSTRUCT) {
    TypePartialStruct *part = (TypePartialStruct *)dt;
    off = part->getOffset();
    dt = part->getParent();
  }
  else
    return false;
  if (dt != parentStruct) return false;		// Check if data-type matches
  if (off != initialOffset) return false;
  originalValue = op->getOut();
  return true;
}

/// \param state is the field to follow backward
/// \return \b true if there was no conflicting information
bool BitFieldInsertTransform::processBackward(BitFieldNodeState &state)

{
  while(state.node != (Varnode *)0) {
    if (state.node->isConstant()) {
      return addConstantWrite(state);
    }
    if (isOriginalValue(state)) {
      state.node = (Varnode *)0;
      return true;
    }
    if (state.field != (const TypeBitField *)0) {
      if (state.isFieldAligned()) {
	addFieldWrite(state);
	return true;
      }
    }
    if (!state.node->isWritten()) return false;
    PcodeOp *op = state.node->getDef();
    bool liftRes;
    switch(op->code()) {
      case CPUI_COPY:
	state.node = op->getIn(0);
	liftRes = true;
	break;
      case CPUI_INT_ADD:
	liftRes = handleAddBack(state, op);
	break;
      case CPUI_INT_AND:
	liftRes = handleAndBack(state, op);
	break;
      case CPUI_INT_LEFT:
	liftRes = handleLeftBack(state, op);
	break;
      case CPUI_INT_ZEXT:
	liftRes = handleZextBack(state, op);
	break;
      case CPUI_INT_OR:
	liftRes = handleOrBack(state, op);
	break;
      case CPUI_INT_MULT:
	liftRes = handleMultBack(state, op);
	break;
      case CPUI_SUBPIECE:
	liftRes = handleSubpieceBack(state, op);
	break;
      case CPUI_INT_SRIGHT:
	liftRes = handleRightBack(state, op);
	break;
      case CPUI_CALL:
      case CPUI_CALLIND:
      case CPUI_CALLOTHER:
	liftRes = testCallOriginal(state, op);
	if (liftRes) {
	  state.node = (Varnode *)0;	// We can treat this as if it matched the original value
	  return true;
	}
	break;
      default:
	liftRes = false;
	break;
    }
    if (!liftRes) {
      if (state.field == (const TypeBitField *)0)
	return false;
      if (state.bitsField.byteSize > sizeof(uintb))
	return false;
      BitRange nonZeroBits(state.bitsField);
      nonZeroBits.intersectMask(state.node->getNZMask());	// Apply what we know about zero bits
      if (nonZeroBits.numBits == 0)
	return addZeroOut(state);				// All bits in the field are zero
      state.bitsUsed.intersectMask(state.node->getNZMask());
      if (nonZeroBits.numBits == state.bitsUsed.numBits) {	// Only used non-zero bits are in the field
	addFieldWrite(state);
	return true;
      }
      return false;
    }
  }
  return true;
}

/// \return the bitfield data-type
Datatype *BitFieldTransform::buildPartialType(void)

{
  if (containerSize == parentStruct->getSize())
    return parentStruct;
  return func->getArch()->types->getTypePartialStruct(parentStruct, initialOffset, containerSize);
}

/// \brief Return \b true if specified bits in a Varnode are overwritten in the same basic block
///
/// This assumes other unspecified bits within the given Varnode are preserved at the point of overwrite.
/// \param vn is the given Varnode
/// \param bl is the given block
/// \param range specifies the bits within the Varnode
/// \return \b true if the bits are used
bool BitFieldTransform::findOverwrite(Varnode *vn,BlockBasic *bl,const BitRange &range)

{
  Varnode *cvn;
  BitRange minRange = range;
  minRange.minimizeContainer();
  Address addr = vn->getAddr() + (minRange.byteOffset - range.byteOffset);
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    Varnode *curVn = vn;
    PcodeOp *op = *iter;
    BitRange curRange = range;
    do {
      if (op->getParent() != bl) {
	if (curRange.numBits != 0)
	  return false;		// Bits are used outside the block
        break;
      }
      switch(op->code()) {
	case CPUI_PIECE:
	  if (op->getIn(0) == curVn) {
	    int4 sz = op->getIn(1)->getSize();
	    curRange.extendBytes(sz);
	    curRange.shift(sz * 8);
	  }
	  else {
	    curRange.extendBytes(op->getIn(0)->getSize());
	  }
	  break;
	case CPUI_INT_LEFT:
	  cvn = op->getIn(1);
	  if (cvn->isConstant())
	    curRange.shift((int4)cvn->getOffset());
	  else
	    return false;
	  break;
	case CPUI_INT_RIGHT:
	  cvn = op->getIn(1);
	  if (cvn->isConstant())
	    curRange.shift(-(int4)cvn->getOffset());
	  else
	    return false;
	  break;
	case CPUI_COPY:
	case CPUI_INT_OR:
	case CPUI_INT_XOR:
	case CPUI_INT_NEGATE:
	  break;			// Remaining range continues to be used
	case CPUI_INT_AND:
	  cvn = op->getIn(1);
	  if (cvn->isConstant())
	    curRange.intersectMask(cvn->getOffset());
	  break;
	case CPUI_INSERT:
	  curRange.intersectMask(~InsertExpression::getRangeMask(op));
	  break;
	case CPUI_INDIRECT:
	  curVn = op->getOut();
	  if (addr.containedBy(minRange.byteSize, curVn->getAddr(), curVn->getSize()))
	    return (curRange.numBits == 0);
	  return false;
	  break;
	default:
	  if (curRange.numBits != 0)
	    return false;			// Bits are actively used, not overwritten
	  op = (PcodeOp *)0;			// No overlap yet, but don't follow this path further
	  break;
      }
      if (op == (PcodeOp *)0) break;
      curVn = op->getOut();
      if (addr.containedBy(minRange.byteSize, curVn->getAddr(), curVn->getSize())) {
	if (curRange.numBits == 0)
	  return true;
      }
      if (curVn->hasNoDescend()) break;
      op = curVn->loneDescend();
    } while(op != (PcodeOp *)0);
  }
  return false;
}

/// If the given op is null, a new INSERT is created, otherwise, op is redefined to be an INSERT.
/// All the INSERT inputs are set based on the InsertRecord.  The output is not set or modified.
/// \param op is a preexisting p-code op to reconfigure, or null
/// \param rec is the record describing the INSERT
/// \return the configured INSERT op
PcodeOp *BitFieldInsertTransform::setInsertInputs(PcodeOp *op,const InsertRecord &rec)

{
  if (op == (PcodeOp *)0) {
    op = func->newOp(4,finalWriteOp->getAddr());
  }
  else {
    while(op->numInput() < 4)
      func->opInsertInput(op, (Varnode *)0, op->numInput());
  }
  func->opSetOpcode(op, CPUI_INSERT);
  func->opSetInput(op,originalValue,0);
  Varnode *valVn = rec.vn;
  if (valVn == (Varnode *)0) {
    if (rec.dt != (Datatype *)0) {
      valVn = func->newConstant(rec.dt->getSize(), rec.constVal);
      valVn->updateType(rec.dt);
    }
    else {
      valVn = func->newConstant(containerSize, rec.constVal);
    }
  }
  func->opSetInput(op,valVn,1);
  func->opSetInput(op,func->newConstant(4,rec.pos),2);
  func->opSetInput(op,func->newConstant(4,rec.numBits),3);
  func->opMarkSpecialPrint(op);		// Not printed as normal operator with output
  return op;
}

/// If necessary, a INT_RIGHT is performed on the (insertion value) input to INSERT.
/// \param insertOp is the INSERT
/// \param rec is the given InsertRecord
void BitFieldInsertTransform::addFieldShift(PcodeOp *insertOp,const InsertRecord &rec)

{
  if (rec.shiftAmount == 0) return;
  Varnode *valVn = insertOp->getIn(1);
  PcodeOp *shiftOp = func->newOp(2, insertOp->getAddr());
  func->opSetOpcode(shiftOp, CPUI_INT_RIGHT);
  Varnode *newOut = func->newUniqueOut(valVn->getSize(),shiftOp);
  func->opSetInput(insertOp, newOut, 1);
  func->opSetInput(shiftOp, valVn, 0);
  func->opSetInput(shiftOp, func->newConstant(4, rec.shiftAmount),1);
  func->opInsertBefore(shiftOp, insertOp);
}

/// Check that the output of the LOAD has only INSERT, ZPULL, SPULL, or the finalWriteOp as a descendant.
/// If so mark the LOAD as non-printing.
/// \param loadOp is the LOAD
/// \return \b true if the LOAD was marked as non-printing
bool BitFieldInsertTransform::foldLoad(PcodeOp *loadOp) const

{
  Varnode *outvn = loadOp->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op == finalWriteOp) continue;
    OpCode opc = op->code();
    if (opc != CPUI_INSERT && opc != CPUI_ZPULL && opc != CPUI_SPULL)
      return false;
  }
  func->opMarkNonPrinting(loadOp);
  return true;
}

/// Check that the pointer into the given LOAD is defined by a PTRSUB and that all descendants of the pointer
/// are LOADs or STOREs that have been absorbed.  If so mark the PTRSUB as non-printing.
/// \param loadOp is the LOAD
void BitFieldInsertTransform::foldPtrsub(PcodeOp *loadOp) const

{
  Varnode *vn = loadOp->getIn(1);
  if (!vn->isWritten()) return;
  PcodeOp *ptrsub = vn->getDef();
  if (ptrsub->code() != CPUI_PTRSUB) return;
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->code() == CPUI_STORE && op->doesSpecialPrinting()) continue;
    if (op->code() == CPUI_LOAD && op->notPrinted()) continue;
    return;
  }
  func->opMarkNonPrinting(ptrsub);
}

/// Look for (first) two INSERT descendants of \e value being inserted.
/// If these exist and are of the same form and in the same basic block, delete the second one.
/// \param rec is the record referencing the INSERTed \e value
void BitFieldInsertTransform::checkRedundancy(const InsertRecord &rec)

{
  if (rec.vn == (Varnode *)0) return;
  PcodeOp *immedOp = (PcodeOp *)0;
  list<PcodeOp *>::const_iterator iter = rec.vn->beginDescend();
  for(;iter != rec.vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->code() != CPUI_INSERT) {
      if (op->code() != CPUI_INT_RIGHT) continue;
      op = op->getOut()->loneDescend();
      if (op == (PcodeOp *)0 || op->code() != CPUI_INSERT) continue;
    }
    if (immedOp == (PcodeOp *)0) {
      immedOp = op;
      continue;
    }
    if (op->getIn(2)->getOffset() != immedOp->getIn(2)->getOffset()) continue;
    if (op->getIn(3)->getOffset() != immedOp->getIn(3)->getOffset()) continue;
    if (finalWriteOp->code() == CPUI_STORE) {
      PcodeOp *store1 = op->getOut()->loneDescend();
      if (store1 == (PcodeOp *)0) continue;
      if (store1->code() != CPUI_STORE) continue;
      PcodeOp *store2 = immedOp->getOut()->loneDescend();
      if (store2 == (PcodeOp *)0) continue;
      if (store2->code() != CPUI_STORE) continue;
      if (store1->getParent() != store2->getParent()) continue;
      if (!pointerEquality(store1->getIn(1), store2->getIn(1))) continue;
      vector<PcodeOp *> scratch;
      if (store1->getSeqNum().getOrder() < store2->getSeqNum().getOrder())
	func->opDestroyRecursive(store2, scratch);
      else
	func->opDestroyRecursive(store1, scratch);
    }
    else {

    }
    return;
  }
}

/// \param f is the function
/// \param op is the p-code terminating the putative bitfield expression
/// \param dt is the structure containing bitfields
/// \param off is the amount of offset
BitFieldInsertTransform::BitFieldInsertTransform(Funcdata *f,PcodeOp *op,Datatype *dt,int4 off)
  : BitFieldTransform(f,dt,off)
{
  if (initialOffset == -1)
    return;
  finalWriteOp = op;
  Varnode *outvn;
  if (finalWriteOp->code() == CPUI_STORE) {
    outvn = finalWriteOp->getIn(2);
  }
  else if (finalWriteOp->code() == CPUI_INDIRECT) {
    mappedVn = finalWriteOp->getOut();		// Keep the storage location of the INDIRECT output
    outvn = op->getIn(0);
    if (!outvn->isWritten()) return;
    finalWriteOp = outvn->getDef();		// But use the op feeding the INDIRECT as the finalWriteOp
  }
  else {
    outvn = finalWriteOp->getOut();
    mappedVn = outvn;
  }
  containerSize = outvn->getSize();
  originalValue = (Varnode *)0;
  establishFields(outvn,true);
}

/// Verify that any STORE between the original value LOAD and the final STORE
/// does not affect any of the known original value bits.
/// \param mask is the set of bits that must come from the putative \e original \e value
/// \return \b true if there is no interference
bool BitFieldInsertTransform::verifyLoadStoreOriginalValue(uintb mask) const

{
  PcodeOp *loadOp = originalValue->getDef();
  list<PcodeOp *>::const_iterator iter = finalWriteOp->getBasicIter();
  list<PcodeOp *>::const_iterator biter = finalWriteOp->getParent()->beginOp();
  uintb off;
  Varnode *basePtr = rootPointer(finalWriteOp->getIn(1), off);
  while(iter != biter) {
    --iter;
    PcodeOp *op = *iter;
    if (op == loadOp) return true;
    if (op->isCall()) return false;
    if (op->code() != CPUI_STORE) continue;
    if (op->getIn(0)->getOffset() != loadOp->getIn(0)->getOffset())
      continue;					// LOAD and STORE not to same address space
    uintb otherOff;
    if (basePtr != rootPointer(op->getIn(1),otherOff))
      return false;				// Unrelated pointer (potential alias)
    if (otherOff != off)
      continue;
    Varnode *vn = op->getIn(2);
    if (!vn->isWritten()) return false;		// Unknown value
    PcodeOp *insertOp = vn->getDef();
    if (insertOp->code() != CPUI_INSERT) return false;	// Unknown value
    uintb insertMask = InsertExpression::getRangeMask(insertOp);
    if ((insertMask & mask) != 0) return false;		// Writing bits that are supposed to be original value
  }
  return true;
}

/// Verify that any write to the mapped storage location between the original value LOAD and the STORE
/// does not affect any of the known original value bits
/// \param mask is the set of bits that must come from the putative \e original \e value
/// \return \b true if there is no interference
bool BitFieldInsertTransform::verifyMappedOriginalValue(uintb mask) const

{
  list<PcodeOp *>::const_iterator iter = finalWriteOp->getBasicIter();
  list<PcodeOp *>::const_iterator biter = finalWriteOp->getParent()->beginOp();
  while(iter != biter) {
    --iter;
    PcodeOp *op = *iter;
    Varnode *vn = op->getOut();
    if (vn == originalValue) return true;
    if (vn == (Varnode *)0) continue;
    if (op->isCall()) return false;	// Mapped location in unknown state
    if (vn->getAddr() != originalValue->getAddr()) continue;
    if (vn->getSize() != originalValue->getSize()) continue;
    if (!vn->isWritten()) return false;	// Unknown value
    PcodeOp *insertOp = vn->getDef();
    if (insertOp->code() != CPUI_INSERT) return false;	// Unknown value
    uintb insertMask = InsertExpression::getRangeMask(insertOp);
    if ((insertMask & mask) != 0) return false;		// Writing bits that are supposed to be original value
  }
  return true;
}

/// Collect all bits which are \b not being INSERTed to by \b this transform.
/// These must be from the \e original \e value of the storage location.
/// \return a mask representing any bits coming from the original value
uintb BitFieldInsertTransform::constructOriginalValueMask(void) const

{
  uintb mask = 0;
  for(list<InsertRecord>::const_iterator iter=insertList.begin();iter!=insertList.end();++iter) {
    const InsertRecord &rec(*iter);
    uintb val = 0;
    if (rec.numBits < 8*sizeof(uintb)) {
      val = 1;
      val <<= rec.numBits;
    }
    val -= 1;
    val <<= rec.pos;
    mask |= val;
  }
  mask = ~mask & calc_mask(originalValue->getSize());
  return mask;
}

/// \return \b true if putative original value bits are unaffected
bool BitFieldInsertTransform::verifyOriginalValueBits(void) const

{
  if (originalValue == (Varnode *)0) return true;	// Not using original value bits
  uintb mask = constructOriginalValueMask();
  if (mask == 0) return true;
  if (finalWriteOp->code() == CPUI_STORE)
    return verifyLoadStoreOriginalValue(mask);
  return verifyMappedOriginalValue(mask);
}

/// Follow all field in the \b workList back and try to match \e insert expressions.
/// \return \b true if all fields match
bool BitFieldInsertTransform::doTrace(void)

{
  if (workList.empty())
    return false;		// Nothing to follow
  while(!workList.empty()) {
    BitFieldNodeState &node( workList.front() );
    if (!processBackward(node) && !isOverwrittenPartial(node))
      return false;
    workList.pop_front();
  }
  if (insertList.empty()) return false;
  return verifyOriginalValueBits();
}

void BitFieldInsertTransform::apply(void)

{
  list<InsertRecord>::const_iterator iter;
  Datatype *partialType = buildPartialType();
  if (finalWriteOp->code() == CPUI_STORE) {
    Varnode *deadPoint = finalWriteOp->getIn(2);		// Root of expression that may be dead
    PcodeOp *currentStore = finalWriteOp;			// Original STORE is modified for first INSERT
    PcodeOp *loadModel = (PcodeOp *)0;
    Datatype *loadType = (Datatype *)0;
    if (originalValue == (Varnode *)0) {
      originalValue = func->newConstant(containerSize, 0);
    }
    else {
      loadModel = originalValue->getDef();
      loadType = originalValue->getTypeDefFacing();
    }
    for(iter=insertList.begin();iter!=insertList.end();++iter) {
      const InsertRecord &rec(*iter);
      if (currentStore == (PcodeOp *)0) {
	currentStore = func->newOp(3, finalWriteOp->getAddr());		// Create new STORE for each additional INSERT
	func->opSetOpcode(currentStore, CPUI_STORE);
	func->opSetInput(currentStore, finalWriteOp->getIn(0), 0);
	func->opSetInput(currentStore, finalWriteOp->getIn(1), 1);
	func->opInsertAfter(currentStore, finalWriteOp);
	if (loadModel != (PcodeOp *)0) {
	  PcodeOp *loadOp = func->newOp(2, loadModel->getAddr());	// Create new LOAD for each additional INSERT
	  func->opSetOpcode(loadOp, CPUI_LOAD);
	  func->opSetInput(loadOp, loadModel->getIn(0),0);
	  func->opSetInput(loadOp, loadModel->getIn(1),1);
	  originalValue = func->newUniqueOut(containerSize, loadOp);
	  originalValue->updateType(loadType);
	  func->opInsertBefore(loadOp,currentStore);
	  func->opMarkNonPrinting(loadOp);		// Don't print LOAD, prevent CAST ops
	}
      }
      PcodeOp *insertOp = setInsertInputs((PcodeOp *)0,rec);
      Varnode *newOut = func->newUniqueOut(containerSize, insertOp);
      newOut->updateType(partialType);
      func->opSetInput(currentStore,insertOp->getOut(),2);
      func->opInsertBefore(insertOp,currentStore);
      func->opMarkSpecialPrint(currentStore);		// Mark special bitfield printing on STORE
      addFieldShift(insertOp, rec);
      currentStore = (PcodeOp *)0;
    }
    func->destroyVarnodeRecursive(deadPoint);
    if (loadModel != (PcodeOp *)0 && loadModel->code() == CPUI_LOAD) {
      if (foldLoad(loadModel)) {
	foldPtrsub(loadModel);
      }
    }
  }
  else {		// Mapped variable
    vector<Varnode *> deadPoints;
    for(int4 i=0;i<finalWriteOp->numInput();++i)
      deadPoints.push_back(finalWriteOp->getIn(i));	// Roots of expressions that may be dead
    if (originalValue == (Varnode *)0) {
      originalValue = func->newConstant(containerSize, 0);
    }
    iter = insertList.begin();
    PcodeOp *insertOp = setInsertInputs(finalWriteOp, *iter);	// Redefine finalWriteOp as INSERT, preserving original output
    insertOp->getOut()->updateType(partialType);
    addFieldShift(insertOp, *iter);
    ++iter;

    for(;iter!=insertList.end();++iter) {
      PcodeOp *lastOp = insertOp;
      func->opUnsetInput(lastOp,0);		// Unset originalValue as input, so it can go to new INSERT
      insertOp = setInsertInputs((PcodeOp *)0, *iter);	// New INSERT
      Varnode *newOut = func->newVarnodeOut(containerSize, mappedVn->getAddr(), insertOp);
      newOut->updateType(partialType);
      func->opSetInput(lastOp,newOut,0);
      func->opInsertBefore(insertOp, lastOp);
      addFieldShift(insertOp, *iter);
    }
    for(int4 i=0;i<deadPoints.size();++i)
      func->destroyVarnodeRecursive(deadPoints[i]);
  }

  for(iter=insertList.begin();iter!=insertList.end();++iter)
    checkRedundancy(*iter);
}

/// If a PcodeOp is given, the specific read of the state.readVn will be replaced with a new \e unique Varnode
/// holding the effective extraction.  Otherwise the state.readVn will be redefined as an extraction for all reads.
/// \param state holds the extracted Varnode and the position of the bitfield at the point of extraction
/// \param op is the specific PcodeOp reading the extracted field or null
BitFieldPullTransform::PullRecord::PullRecord(const BitFieldNodeState &state,PcodeOp *op)

{
  type = normal;
  readVn = state.node;
  readOp = op;
  dt = state.field->type;
  pos = state.origLeastSigBit;
  numBits = state.field->bits.numBits;
  leftShift = state.bitsField.leastSigBit;
  mask = 0;
}

/// \param state holds the extracted Varnode and the position of the bitfield at the point of extraction
/// \param op is the specific INT_EQUAL or INT_NOTEQUAL PcodeOp reading the extracted field
/// \param val is a mask representing the bitfield within the Varnode
BitFieldPullTransform::PullRecord::PullRecord(const BitFieldNodeState &state,PcodeOp *op,uintb val)

{
  type = equal;
  readVn = state.node;
  readOp = op;
  dt = state.field->type;
  pos = state.origLeastSigBit;
  numBits = state.field->bits.numBits;
  leftShift = state.bitsField.leastSigBit;
  mask = val;
}

/// \param op is the PcodeOp whose input pull is being aborted
BitFieldPullTransform::PullRecord::PullRecord(PcodeOp *op)

{
  type = aborted;
  readVn = (Varnode *)0;
  readOp = op;
  dt = (Datatype *)0;
  pos = 0;
  numBits = 0;
  leftShift = 0;
  mask = 0;
}

/// Sort based on the PcodeOp whose input is being pulled
/// \param op2 is the record to compare with \b this
/// \return \b true if \b this comes before \b op2
bool BitFieldPullTransform::PullRecord::operator<(const PullRecord &op2) const

{
  if (readOp != (PcodeOp *)0 && op2.readOp != (PcodeOp *)0) {
    if (readOp != op2.readOp)
      return (readOp->getSeqNum() < op2.readOp->getSeqNum());
  }
  else if (readOp == (PcodeOp *)0)
    return true;
  else if (op2.readOp == (PcodeOp *)0)
    return false;
  return false;
}

/// \param vn is the Varnode being read
/// \param bitField is the bitfield being followed
/// \return \b true if all consumed bits are in the bitfield
bool BitFieldPullTransform::testConsumed(Varnode *vn,const BitRange &bitField)

{
  if (bitField.byteSize > sizeof(uintb)) return false;
  uintb mask = bitField.getMask();
  uintb intersect = mask & vn->getConsume();
  return (intersect == vn->getConsume());
}

/// If the \e bitfield is moved into the output Varnode without losing bits,
/// add the output as a new \e bitfield state and update usage information for original \b root bits.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INT_LEFT reading the \e bitfield Varnode
void BitFieldPullTransform::handleLeftForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (op->getIn(0) != state.node) return;
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return;
  int4 sa = (int4)cvn->getOffset();
  BitRange newRange(state.bitsField);
  newRange.shift(sa);
  if (newRange.numBits == 0)
    return;
  if (state.bitsField.numBits == newRange.numBits) {
    bool newSignExt = state.isSignExtended || newRange.isMostSignificant();
    workList.emplace_back(state,newRange,op->getOut(),newSignExt);
    workList.back().bitsUsed.shift(sa);
  }
  else if (testConsumed(op->getOut(),newRange)) {
    pullList.emplace_back(state,op);
  }
}

/// If the \e bitfield is moved into the output Varnode without losing bits,
/// add the output as a new \e bitfield state and update usage information for original \b root bits.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INT_RIGHT or INT_SRIGHT reading the \e bitfield Varnode
void BitFieldPullTransform::handleRightForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (op->getIn(0) != state.node) return;
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return;
  int4 sa = (int4)cvn->getOffset();
  BitRange newRange(state.bitsField);
  newRange.shift(-sa);
  if (newRange.numBits == 0)
    return;
  if (state.bitsField.numBits == newRange.numBits) {
    bool newSignExt = (op->code() == CPUI_INT_SRIGHT) ? state.isSignExtended : false;
    workList.emplace_back(state,newRange,op->getOut(),newSignExt);
    workList.back().bitsUsed.shift(-sa);
    if (op->code() == CPUI_INT_SRIGHT && !state.isSignExtended) {
	workList.back().bitsUsed.expandToMost();	// Sign extending bits not in the field
    }
  }
  else if (testConsumed(op->getOut(),newRange)) {
    pullList.emplace_back(state,op);
  }
}

/// If the \e bitfield is masked into the output Varnode without losing bits,
/// add the output as a new \e bitfield state and update usage information for original \b root bits.
/// If every bit outside the \e bitfield is zeroed plus additional bits in the \e bitfield,
/// create a PullRecord for this particular read.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INT_AND reading the \e bitfield Varnode
void BitFieldPullTransform::handleAndForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (op->getIn(0) != state.node) return;
  if (state.bitsField.byteSize > sizeof(uintb)) return;
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return;
  uintb andVal = cvn->getOffset();
  uintb mask = state.bitsField.getMask();
  uintb intersect = andVal & mask;
  if (intersect == 0) return;			// Field is completely masked away
  if (intersect == mask) {			// Nothing is masked away, follow the whole field
    bool newSignExt = state.bitsField.isMostSignificant();
    workList.emplace_back(state,state.bitsField,op->getOut(),newSignExt);
    workList.back().bitsUsed.intersectMask(andVal);
  }
  else if (testConsumed(op->getOut(),state.bitsField)) {
    pullList.emplace_back(state,op);
  }
}

/// Add the output Varnode as a new \e bitfield state and update usage information for original \b root bits.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INT_ZEXT or INT_SEXT reading the \e bitfield Varnode
void BitFieldPullTransform::handleExtForward(const BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *outvn = op->getOut();
  int4 diff = outvn->getSize() - state.node->getSize();
  bool newSignExt = (op->code() == CPUI_INT_SEXT) ? state.isSignExtended : false;
  workList.emplace_back(state,state.bitsField,outvn,newSignExt);
  workList.back().bitsField.extendBytes(diff);
  workList.back().bitsUsed.extendBytes(diff);
  if (op->code() == CPUI_INT_SEXT && !state.isSignExtended) {
    workList.back().bitsUsed.expandToMost();	// Sign extending bits not in the field
  }
}

/// If the INT_MULT can be viewed as a left shift, and If the \e bitfield is moved into the output
/// Varnode without losing bits, add the output as a new \e bitfield state and update usage information
/// for original \b root bits.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INT_MULT reading the \e bitfield Varnode
void BitFieldPullTransform::handleMultForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (op->getIn(0) != state.node) return;
  Varnode *vn1 = op->getIn(1);
  if (!vn1->isConstant()) return;
  uintb val = vn1->getOffset();
  if (popcount(val) != 1) {
    handleLeastSigOp(state, op);
    return;
  }
  int4 sa = leastsigbit_set(val);
  BitRange newRange(state.bitsField);
  newRange.shift(sa);
  if (newRange.numBits == 0)
    return;
  if (state.bitsField.numBits == newRange.numBits) {
    bool newSignExt = state.isSignExtended || newRange.isMostSignificant();
    workList.emplace_back(state,newRange,op->getOut(),newSignExt);
    workList.back().bitsUsed.shift(sa);
  }
}

/// If the \e bitfield is truncated without losing bits, add the output as a new
/// \e bitfield state and update usage information for original \b root bits.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the SUBPIECE reading the \e bitfield Varnode
void BitFieldPullTransform::handleSubpieceForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (op->getIn(0) != state.node) return;
  int4 leastTrunc = (int4)op->getIn(1)->getOffset();
  int4 mostTrunc = (state.bitsField.byteSize - leastTrunc) - op->getOut()->getSize();
  BitRange newRange(state.bitsField);

  newRange.truncateLeastSigBytes(leastTrunc);
  newRange.truncateMostSigBytes(mostTrunc);
  if (newRange.numBits == 0)
    return;
  if (state.bitsField.numBits == newRange.numBits) {
    bool newSignExt = state.isSignExtended;	// Any sign extension is preserved, since we only truncate and whole field is present
    workList.emplace_back(state,newRange,op->getOut(),newSignExt);
    workList.back().bitsUsed.truncateLeastSigBytes(leastTrunc);
    workList.back().bitsUsed.truncateMostSigBytes(mostTrunc);
  }
  else if (testConsumed(op->getOut(),newRange)) {
    pullList.emplace_back(state,op);
  }
}

/// Test if we can treat the value being INSERTed as a PULL of the current bitfield.
/// The INSERT must only be inserting bits from the bitfield, in which case we create a PullRecord directly.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INSERT reading the \e bitfield Varnode
void BitFieldPullTransform::handleInsertForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (op->getIn(1) != state.node) return;	// Handle only if pull is value being inserted
  if (state.bitsField.leastSigBit != 0) return;	// Test if least sig bits of inserted value are in the bitfield
  int4 sz = (int4)op->getIn(3)->getOffset();
  if (sz > state.bitsField.numBits) return;	// Test if more bits are getting INSERTed than are in bitfield

  pullList.emplace_back(state,op);	// Can treat input to INSERT as pull of current bitfield
}

/// If the \b bitfield is the most significant bits being compared, and the
/// constant being compared to has 1 bits in the least significant positions,
/// create a PullRecord indicating the comparison acts on the pulled bits.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the comparison reading the \e bitfield Varnode
void BitFieldPullTransform::handleLessForward(const BitFieldNodeState &state,PcodeOp *op)

{
  if (!state.bitsField.isMostSignificant())
    return;
  int4 slot = op->getSlot(state.node);
  Varnode *cvn = op->getIn(1-slot);
  if (!cvn->isConstant()) return;
  uintb val = cvn->getOffset();
  bool leastSigZeroBits = (val & 1) == 0;
  int4 numExtremalBits;
  if (leastSigZeroBits)
    numExtremalBits = leastsigbit_set(val);	// Check how many least significant 0 bits
  else
    numExtremalBits = leastsigbit_set(~val);	// Check how many least significant 1 bits
  if (numExtremalBits < 0)
    numExtremalBits = sizeof(uintb) * 8;
  bool needMaskCheck = false;
  OpCode opc = op->code();
  if (opc == CPUI_INT_SLESS || opc == CPUI_INT_LESS) {
    if (leastSigZeroBits && slot != 0) return;
    if (!leastSigZeroBits && slot == 0)
      needMaskCheck = true;
  }
  else if (opc == CPUI_INT_SLESSEQUAL || opc == CPUI_INT_LESSEQUAL) {
    if (leastSigZeroBits && slot != 1) return;
    if (!leastSigZeroBits && slot == 1)
      needMaskCheck = true;
  }
  if (needMaskCheck) {
    uintb mask;
    if (numExtremalBits >= 8*sizeof(uintb))
      mask = 0;
    else {
      mask = 1;
      mask <<= numExtremalBits;
    }
    mask -= 1;
    if ((mask & state.node->getNZMask()) == mask) return;	// Must be at least one 0 bit
  }
  if (state.bitsField.leastSigBit <= numExtremalBits) {	// If the field extends into the extremal bits
    // The comparison is only affected by field bits. View field as pulled and then shifted.
    pullList.emplace_back(state,op);
  }
}

/// This handles arithmetic/logical ops where the result on least significant bits doesn't change
/// if the more significant bits are truncated from the inputs.
/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the arithmetic/logical op
void BitFieldPullTransform::handleLeastSigOp(const BitFieldNodeState &state,PcodeOp *op)

{
  if (state.bitsField.leastSigBit != 0) return;		// Field must be in least significant bits
  if (testConsumed(op->getOut(),state.bitsField)) {
    pullList.emplace_back(state,op);
  }
}

/// \param state is the current state of the \e bitfield and the Varnode holding it
/// \param op is the INT_EQUAL or INT_NOTEQUAL comparison reading the \e bitfield Varnode
void BitFieldPullTransform::handleEqualForward(const BitFieldNodeState &state,PcodeOp *op)

{
  Varnode *cvn = op->getIn(1);
  if (state.bitsField.byteSize > sizeof(uintb)) return;
  if (!cvn->isConstant()) return;
  if (state.field != (const TypeBitField *)0 && state.field->bits.numBits == state.bitsField.numBits) {
    uintb val = state.bitsField.getMask();
    pullList.emplace_back(state,op,val);
  }
  else {
    pullList.emplace_back(op);	// Abort any pulls into this op
  }
}

/// \param state is the current state of the \e bitfield and the Varnode holding it
void BitFieldPullTransform::processForward(BitFieldNodeState &state)

{
  list<PcodeOp *>::const_iterator iter;
  if (state.isFieldAligned() && state.doesSignExtensionMatch()) {
    pullList.emplace_back(state,(PcodeOp *)0);
    return;
  }
  for(iter=state.node->beginDescend();iter!=state.node->endDescend();++iter) {
    PcodeOp *op = *iter;
    switch(op->code()) {
      case CPUI_INT_LEFT:
	handleLeftForward(state, op);
	break;
      case CPUI_INT_MULT:
	handleMultForward(state, op);
	break;
      case CPUI_INT_RIGHT:
      case CPUI_INT_SRIGHT:
	handleRightForward(state, op);
	break;
      case CPUI_INT_AND:
	handleAndForward(state, op);
	break;
      case CPUI_INT_ZEXT:
      case CPUI_INT_SEXT:
	handleExtForward(state, op);
	break;
      case CPUI_INT_LESS:
      case CPUI_INT_LESSEQUAL:
      case CPUI_INT_SLESS:
      case CPUI_INT_SLESSEQUAL:
	handleLessForward(state, op);
	break;
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
	handleEqualForward(state, op);
	break;
      case CPUI_INT_ADD:
      case CPUI_INT_OR:
      case CPUI_INT_XOR:
      case CPUI_INT_2COMP:
      case CPUI_INT_NEGATE:
	handleLeastSigOp(state, op);
	break;
      case CPUI_SUBPIECE:
	handleSubpieceForward(state, op);
	break;
      case CPUI_INSERT:
	handleInsertForward(state, op);
	break;
      default:
	break;
    }
  }
}

/// \brief Determine if pulls at a specific INT_EQUAL or INT_NOTEQUAL are consistent as a whole
///
/// Run through PullRecords for a single INT_EQUAL or INT_NOTEQUAL.  These records are deleted if:
///   - An \e aborted record is present, indicating a partial field or hole is being compared
///   - Other unrelated bits are being compared
///
/// \param iter points to the first PullRecord for the op
/// \return an iterator pointing after all PullRecords for the op
list<BitFieldPullTransform::PullRecord>::iterator BitFieldPullTransform::testCompareGroup(list<PullRecord>::iterator iter)

{
  list<PullRecord>::iterator curiter = iter;
  bool isAborted = false;
  uintb collectMask = 0;		// Collect mask of all fields being tested
  Varnode *vn = (*iter).readVn;
  PcodeOp *op = (*iter).readOp;
  uintb val = op->getIn(1)->getOffset();
  do {
    PullRecord &rec( *curiter );
    if (rec.readOp != op) break;
    ++curiter;
    if (rec.type == PullRecord::aborted)
      isAborted = true;
    collectMask |= rec.mask;
  } while(curiter != pullList.end());
  if (isAborted || (~collectMask & val) != 0 || (~collectMask & vn->getNZMask()) != 0) {
    curiter = pullList.erase(iter,curiter);
  }
  return curiter;
}

/// Create the ZPULL or SPULL op.  Duplicate the LOAD if necessary. Add an INT_LEFT if needed.
/// \param rec is the given PullRecord
/// \param state is state maintained across all transforms
void BitFieldPullTransform::applyRecord(PullRecord &rec,TransformState &state)

{
  PcodeOp *modOp;
  if (rec.readOp == (PcodeOp *)0) {	// null here indicates readVn contains a complete pull
    modOp = rec.readVn->getDef();	// readVn always has a defining op
    func->opUnsetOutput(modOp);	// set up to modify the definition of readVn
  }
  else {				// Otherwise modify the single read of readVn, readOp
    if (rec.readVn != root)
	modOp = rec.readVn->getDef();
    else
	modOp = rec.readOp;
    int4 slot = rec.readOp->getSlot(rec.readVn);
    rec.readVn = func->newUnique(rec.readVn->getSize());	// New Varnode to hold the complete pull
    func->opSetInput(rec.readOp,rec.readVn,slot);
  }
  Varnode *inVn = root;
  if (loadOp != (PcodeOp *)0 && state.count > 0) {
    PcodeOp *newLoad = func->newOp(2, loadOp->getAddr());
    func->opSetOpcode(newLoad, CPUI_LOAD);		// Make copy of original LOAD
    func->opSetInput(newLoad,loadOp->getIn(0),0);
    func->opSetInput(newLoad,loadOp->getIn(1),1);
    inVn = func->newUniqueOut(containerSize, newLoad);
    func->opInsertAfter(newLoad,loadOp);
    func->opMarkNonPrinting(newLoad);
  }
  inVn->updateType(state.partialType);
  PcodeOp *pullOp = func->newOp(3, modOp->getAddr());
  func->opSetOpcode(pullOp, (rec.dt->getMetatype() == TYPE_INT) ? CPUI_SPULL : CPUI_ZPULL);
  func->opSetInput(pullOp,inVn,0);
  func->opSetInput(pullOp,func->newConstant(4,rec.pos),1);
  func->opSetInput(pullOp,func->newConstant(4,rec.numBits),2);
  if (modOp != rec.readOp)
    func->opInsertAfter(pullOp, modOp);
  else
    func->opInsertBefore(pullOp, modOp);
  if (rec.leftShift != 0) {
    Varnode *shiftVn = func->newUniqueOut(containerSize, pullOp);
    PcodeOp *shiftOp = func->newOp(2, modOp->getAddr());
    func->opSetOpcode(shiftOp, CPUI_INT_LEFT);
    func->opSetInput(shiftOp,shiftVn,0);
    func->opSetInput(shiftOp,func->newConstant(4,rec.leftShift),1);
    func->opInsertAfter(shiftOp,pullOp);
    func->opSetOutput(shiftOp, rec.readVn);
  }
  else {
    func->opSetOutput(pullOp, rec.readVn);
  }

  Varnode *pullOut = pullOp->getOut();
  if (pullOut->getType()->getMetatype() == TYPE_UNKNOWN) {
    Datatype *dt = func->getArch()->types->resizeInteger(rec.dt,pullOut->getSize());
    pullOut->updateType(dt);
  }
  else if (rec.dt->getMetatype() == TYPE_BOOL && pullOut->getSize() == 1 && rec.numBits == 1) {
    pullOut->updateType(rec.dt);
  }
  if (modOp != rec.readOp) {
    Varnode *outvn = modOp->getOut();
    if (outvn == (Varnode *)0 || outvn->hasNoDescend())
      func->opDestroyRecursive(modOp, state.deadScratch);
  }
  state.count += 1;
}

/// The first PullRecord at least must be for a comparison op.  If there are more than one,
/// the op is converted into a boolean expression with comparison for each record.
/// Then the constant value for each comparison is adjusted to match the PullRecord bitfield.
/// The PullRecords are \e not removed, but are converted to \e normal records so that
/// the applyRecord() method can create the ZPULL or SPULL ops.
/// \param rec must be the first PullRecord in \b pullList
void BitFieldPullTransform::applyCompareRecord(const PullRecord &rec)

{
  uintb origVal = rec.readOp->getIn(1)->getOffset();
  int4 num = 0;
  list<PullRecord>::iterator iter,enditer;
  enditer = pullList.begin();
  while(enditer != pullList.end()) {		// Gather pulls to the same compare
    if ((*enditer).readOp != rec.readOp)
      break;
    ++enditer;
    num += 1;
  }
  if (num > 1) {
    OpCode opc = rec.readOp->code();
    OpCode combineCode = (opc == CPUI_INT_EQUAL) ? CPUI_BOOL_AND : CPUI_BOOL_OR;
    Varnode *vn = rec.readOp->getIn(0);
    PcodeOp *curCombine = rec.readOp;
    func->opSetOpcode(curCombine,combineCode);
    iter = pullList.begin();
    for(int4 i=0;i<num;++i) {
      PcodeOp *op = func->newOp(2,curCombine->getAddr());
      func->opSetOpcode(op, opc);
      Varnode *boolVn = func->newUniqueOut(1, op);
      func->opSetInput(op,vn,0);
      func->opInsertBefore(op,curCombine);
      if (i == 0) {
	func->opSetInput(curCombine, boolVn, 0);
      }
      else if (i < num-1) {
	PcodeOp *combineOp = func->newOp(2,curCombine->getAddr());
	func->opSetOpcode(combineOp,combineCode);
	Varnode *bool2Vn = func->newUniqueOut(1,combineOp);
	func->opSetInput(curCombine,bool2Vn,1);
	func->opSetInput(combineOp,boolVn,0);
	func->opInsertBefore(combineOp,curCombine);
	curCombine = combineOp;
      }
      else {
	func->opSetInput(curCombine,boolVn,1);
      }
      (*iter).readOp = op;
      ++iter;
    }
  }
  iter = pullList.begin();
  while(iter != enditer) {
    PullRecord &subrec(*iter);
    uintb val = origVal & subrec.mask;
    val >>= subrec.leftShift;
    if (subrec.dt->getMetatype() == TYPE_INT)
      val = extend_signbit(val, subrec.numBits, subrec.readVn->getSize());
    Varnode *vn = func->newConstant(subrec.readVn->getSize(),val);
    Datatype *dt = func->getArch()->types->resizeInteger(subrec.dt, subrec.readVn->getSize());
    vn->updateType(dt);
    func->opSetInput(subrec.readOp,vn,1);		// Adjust compare value
    subrec.type = PullRecord::normal;			// Convert to normal pull
    subrec.leftShift = 0;				// left shift has been accounted for
    ++iter;
  }
}

/// Check that the output of the LOAD has only ZPULL, SPULL, or INSERT as a descendant.
/// If so mark the LOAD as non-printing.
/// \param loadOp is the LOAD
/// \return \b true if the LOAD was marked as non-printing
bool BitFieldPullTransform::foldLoad(PcodeOp *loadOp) const

{
  Varnode *outvn = loadOp->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    OpCode opc = (*iter)->code();
    if (opc != CPUI_ZPULL && opc != CPUI_SPULL && opc != CPUI_INSERT)
      return false;
  }
  func->opMarkNonPrinting(loadOp);
  return true;
}

/// Check that the pointer into the given LOAD is defined by a PTRSUB and that all descendants of the pointer
/// are LOADs that have been absorbed.  If so mark the PTRSUB as non-printing.
/// \param loadOp is the LOAD
void BitFieldPullTransform::foldPtrsub(PcodeOp *loadOp) const

{
  Varnode *vn = loadOp->getIn(1);
  if (!vn->isWritten()) return;
  PcodeOp *ptrsub = vn->getDef();
  if (ptrsub->code() != CPUI_PTRSUB) return;
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->code() != CPUI_LOAD) return;
    if (!op->notPrinted()) return;		// Check if LOAD has been absorbed
  }
  func->opMarkNonPrinting(ptrsub);
}

/// \param f is the function
/// \param r is the root Varnode with a \e bitfield data-type
/// \param dt is the data-type containing bitfields (may be partial)
/// \param off is the byte offset into the data-type to associate with \b root
BitFieldPullTransform::BitFieldPullTransform(Funcdata *f,Varnode *r,Datatype *dt,int4 off)
  : BitFieldTransform(f,dt,off)
{
  if (initialOffset == -1)
    return;
  root = r;
  containerSize = root->getSize();
  if (root->isWritten() && root->getDef()->code() == CPUI_LOAD)
    loadOp = root->getDef();
  else
    loadOp = (PcodeOp *)0;
  establishFields(root,false);		// Don't follow holes
}

/// Create a PullRecord at each pull point.
/// \return \b true if any PullRecords were created
bool BitFieldPullTransform::doTrace(void)

{
  while(!workList.empty()) {
    processForward(workList.front());
    workList.pop_front();
  }
  if (pullList.empty())
    return false;
  pullList.sort();
  list<PullRecord>::iterator iter = pullList.begin();
  while(iter != pullList.end()) {
    if ((*iter).type != PullRecord::normal)
      iter = testCompareGroup(iter);
    else
      ++iter;
  }
  return !pullList.empty();
}

/// For each pull record, either:
///   - Redefine \b readVn with a ZPULL or SPULL.  Delete the original op defining \b readVn
///   - Create a Varnode for a specific \b readOp that effectively holds the pulled value
void BitFieldPullTransform::apply(void)

{
  TransformState state;
  state.count = 0;
  state.partialType = buildPartialType();
  while(!pullList.empty()) {
    PullRecord &rec(pullList.front());
    if (rec.type == PullRecord::equal) {
      applyCompareRecord(rec);
    }
    else {
      applyRecord(rec,state);
      pullList.pop_front();
    }
  }
  if (loadOp != (PcodeOp *)0) {
    if (foldLoad(loadOp))
      foldPtrsub(loadOp);
  }
}

void RuleBitFieldStore::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_STORE);
}

int4 RuleBitFieldStore::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *ptr = op->getIn(1)->getTypeReadFacing(op);
  int4 off;
  Datatype *dt = ptr->getPtrInto(off);
  if (dt == (Datatype *)0) return 0;
  if (!dt->hasBitfields()) return 0;
  Varnode *vn = op->getIn(2);
  if (vn->isWritten() && vn->getDef()->code() == CPUI_INSERT) return 0;
  BitFieldInsertTransform transform(&data,op,dt,off);
  if (!transform.doTrace())
    return 0;
  transform.apply();
  return 1;
}

void RuleBitFieldOut::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]={ CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
    CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_ADD, CPUI_INT_CARRY,
    CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_LEFT, CPUI_INT_RIGHT,
    CPUI_INT_SRIGHT, CPUI_INT_MULT, CPUI_BOOL_NEGATE, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
    CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
    CPUI_INDIRECT, CPUI_SUBPIECE };
  oplist.insert(oplist.end(),list,list+30);
}

int4 RuleBitFieldOut::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *outvn = op->getOut();
  Datatype *dt = outvn->getTypeDefFacing();
  if (!dt->hasBitfields()) return 0;
  BitFieldInsertTransform transform(&data,op,dt,0);
  if (!transform.doTrace())
    return 0;
  transform.apply();
  return 1;
}

void RuleBitFieldLoad::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_LOAD);
}

int4 RuleBitFieldLoad::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *ptr = op->getIn(1)->getTypeReadFacing(op);
  int4 off;
  Datatype *dt = ptr->getPtrInto(off);
  if (dt == (Datatype *)0) return 0;
  if (!dt->hasBitfields()) return 0;
  if (op->notPrinted()) return 0;	// LOAD visited before
  BitFieldPullTransform transform(&data,op->getOut(),dt,off);
  if (!transform.doTrace())
    return 0;
  transform.apply();
  return 1;
}

void RuleBitFieldIn::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]={ CPUI_COPY,
      CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
      CPUI_INT_ZEXT, CPUI_INT_SEXT,
      CPUI_INT_ADD, CPUI_INT_NEGATE,
      CPUI_INT_AND, CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT,
      CPUI_SUBPIECE };
  oplist.insert(oplist.end(),list,list+17);
}

int4 RuleBitFieldIn::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *invn = op->getIn(0);
  Datatype *dt = invn->getTypeReadFacing(op);
  if (!dt->hasBitfields()) return 0;
  BitFieldPullTransform transform(&data,invn,dt,0);
  if (!transform.doTrace())
    return 0;
  transform.apply();
  return 1;
}

/// \brief Perform transforms involving the expression:  `field >> #c`
///
/// \param data is the function
/// \param rightOp is the INT_RIGHT or INT_SRIGHT op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if a transform was performed, 0 otherwise
int4 RulePullAbsorb::absorbRight(Funcdata &data,PcodeOp *rightOp,PcodeOp *pullOp)

{
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = rightOp->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    if (readOp->code() == CPUI_INT_AND) {
      int4 res = absorbRightAndCompZero(data,rightOp,readOp,pullOp);
      if (res != 0) return res;
    }
  }
  return 0;
}

/// \brief Perform transform:  `((sfield >> #n) & #1) == #0    =>    #0 <= sfield`
///
/// Perform the variant:  `((sfield >> #n) & #1) != #0    =>    sfield < #0`
/// \param data is the function
/// \param rightOp is the INT_RIGHT or INT_SRIGHT op
/// \param andOp is the INT_AND
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if a transform was performed, 0 otherwise
int4 RulePullAbsorb::absorbRightAndCompZero(Funcdata &data,PcodeOp *rightOp,PcodeOp *andOp,PcodeOp *pullOp)

{
  if (pullOp->code() != CPUI_SPULL) return 0;
  Varnode *cvn = rightOp->getIn(1);
  if (!cvn->isConstant()) return 0;
  int4 sa = cvn->getOffset();
  int4 numbits = pullOp->getIn(2)->getOffset();
  if (numbits -1 != sa) return 0;		// Check that shift puts sign bit into least sig position
  if (!andOp->getIn(1)->constantMatch(1)) return 0;
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = andOp->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    OpCode opc = readOp->code();
    if (opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL) continue;
    if (!readOp->getIn(1)->constantMatch(0)) continue;
    Varnode *vn = pullOp->getOut();
    if (opc == CPUI_INT_EQUAL) {
      data.opSetOpcode(readOp, CPUI_INT_LESSEQUAL);
      Varnode *zvn = readOp->getIn(1);
      data.opSetInput(readOp,vn,1);
      data.opSetInput(readOp,zvn,0);
    }
    else {
      data.opSetOpcode(readOp,CPUI_INT_SLESS);
      data.opSetInput(readOp,vn,0);
    }
    data.destroyVarnodeRecursive(outvn);
    return 1;
  }
  return 0;
}

/// \brief Perform transforms involving the expression:  `field << #c`
///
/// \param data is the function
/// \param leftOp is the INT_LEFT op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if a transform was performed, 0 otherwise
int4 RulePullAbsorb::absorbLeft(Funcdata &data,PcodeOp *leftOp,PcodeOp *pullOp)

{
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = leftOp->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    int4 res = 0;
    OpCode opc = readOp->code();
    if (opc == CPUI_INT_SLESS)
      res = absorbCompare(data,readOp,leftOp,pullOp);
    else if (opc == CPUI_INT_RIGHT)
      res = absorbLeftRight(data,readOp,leftOp,pullOp);
    else if (opc == CPUI_INT_AND)
      res = absorbLeftAnd(data,readOp,leftOp,pullOp);
    if (res != 0) return res;
  }
  return 0;
}

/// \brief Perform the transform: `(field << #c) >> #d   =>  field  >> (#d-#c)`
///
/// \param data is the function
/// \param rightOp is the INT_RIGHT op
/// \param leftOp is the INT_LEFT op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if a transform was performed, 0 otherwise
int4 RulePullAbsorb::absorbLeftRight(Funcdata &data,PcodeOp *rightOp,PcodeOp *leftOp,PcodeOp *pullOp)

{
  Varnode *leftcvn = leftOp->getIn(1);
  if (!leftcvn->isConstant()) return 0;
  Varnode *rightcvn = rightOp->getIn(1);
  if (!rightcvn->isConstant()) return 0;
  int4 bitsize = pullOp->getIn(2)->getOffset();
  Varnode *invn = pullOp->getIn(0);
  int4 containerSize = invn->getSize() * 8;
  int4 leftshift = leftcvn->getOffset();
  int4 rightshift = rightcvn->getOffset();
  if (leftshift + bitsize > containerSize) return 0;	// Check if left shift destroys field data
  int4 sa = rightshift - leftshift;
  if (sa == 0) {
    data.totalReplace(rightOp->getOut(),pullOp->getOut());
    data.destroyVarnodeRecursive(rightOp->getOut());
  }
  else if (sa > 0) {		// Right shift is bigger than left
    data.opSetInput(rightOp, data.newConstant(rightcvn->getSize(),sa), 1);
    data.opSetInput(rightOp, pullOp->getOut(),0);
    data.destroyVarnodeRecursive(leftOp->getOut());
  }
  else {			// Left shift is bigger than right
    data.opSetOpcode(rightOp, CPUI_INT_LEFT);
    data.opSetInput(rightOp, data.newConstant(rightcvn->getSize(),-sa), 1);
    data.opSetInput(rightOp, pullOp->getOut(),0);
    data.destroyVarnodeRecursive(leftOp->getOut());
  }
  return 1;
}

/// \brief Perform the transform: `((field << #c) & #b) == #d   =>  (field & #b>>c) == #d>>c`
///
/// \param data is the function
/// \param andOp is the INT_AND op
/// \param leftOp is the INT_LEFT op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if a transform was performed, 0 otherwise
int4 RulePullAbsorb::absorbLeftAnd(Funcdata &data,PcodeOp *andOp,PcodeOp *leftOp,PcodeOp *pullOp)

{
  Varnode *shiftAmount = leftOp->getIn(1);
  if (!shiftAmount->isConstant()) return 0;
  int4 sa = shiftAmount->getOffset();
  if (sa < 0 || sa >= sizeof(uintb)*8) return 0;
  Varnode *maskVn = andOp->getIn(1);
  if (!maskVn->isConstant()) return 0;
  uintb mask = maskVn->getOffset();
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = andOp->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    OpCode opc = readOp->code();
    if (opc == CPUI_INT_EQUAL || opc == CPUI_INT_NOTEQUAL) {
      Varnode *compVal = readOp->getIn(1);
      if (!compVal->isConstant()) continue;
      uintb val = compVal->getOffset() >> sa;
      if (val << sa != compVal->getOffset()) continue;
      mask >>= sa;
      Varnode *newAnd = data.newConstant(maskVn->getSize(), mask);
      newAnd->updateType(maskVn->getType());
      data.opSetInput(andOp,newAnd,1);
      if (val != compVal->getOffset()) {
	Varnode *newVal = data.newConstant(compVal->getSize(),val);
	newVal->updateType(compVal->getType());
	data.opSetInput(readOp,newVal,1);
      }
      data.opSetInput(andOp,leftOp->getIn(0),0);
      data.destroyVarnodeRecursive(leftOp->getOut());
      return 1;
    }
  }
  return 0;
}

/// \brief Perform transform:  `field & #signbit == #0   =>  field < 0`
///
/// \param data is the function
/// \param andOp is the INT_AND op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if a transform was performed, 0 otherwise
int4 RulePullAbsorb::absorbAnd(Funcdata &data,PcodeOp *andOp,PcodeOp *pullOp)

{
  Varnode *maskVn = andOp->getIn(1);
  if (!maskVn->isConstant()) return 0;
  Varnode *vn = pullOp->getOut();
  if (pullOp->code() != CPUI_SPULL) return 0;	// Not signed
  int4 bitsize = (int4)pullOp->getIn(2)->getOffset();
  uintb matchVal = 1;
  matchVal <<= (bitsize-1);			// Mask for sign-bit
  if (matchVal != maskVn->getOffset()) return 0;
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = andOp->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    OpCode opc = readOp->code();
    if (opc == CPUI_INT_EQUAL || opc == CPUI_INT_NOTEQUAL) {
      if (!readOp->getIn(1)->constantMatch(0)) continue;
      Varnode *newZero = data.newConstant(vn->getSize(),0);
      Datatype *dt = data.getArch()->types->resizeInteger(vn->getType(),vn->getSize());
      newZero->updateType(dt);
      if (opc == CPUI_INT_EQUAL) {
	data.opSetOpcode(readOp, CPUI_INT_SLESSEQUAL);
	data.opSetInput(readOp,newZero,0);
	data.opSetInput(readOp,vn,1);
      }
      else {
	data.opSetOpcode(readOp, CPUI_INT_SLESS);
	data.opSetInput(readOp,vn,0);
	data.opSetInput(readOp,newZero,1);
      }
      data.destroyVarnodeRecursive(andOp->getOut());
      return 1;
    }
  }
  return 0;
}

/// \brief Perform transforms involving comparisons: INT_LESS, INT_SLESS
///
/// Perform transforms:
///   - `(boolfield << #c) s< #0   => boolfield`
///   - `#0 s< (boolfield << #c)   => !boolfield`
///   - `(field << #c) < (#d<<#c)   =>  field < #d`
///   - `(#d<<#c) < (field << #c)   =>  #d < field`
///
/// \param data is the function
/// \param compOp is the INT_LESS or INT_SLESS op
/// \param leftOp is the INT_LEFT op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if transform performed, 0 otherwise
int4 RulePullAbsorb::absorbCompare(Funcdata &data,PcodeOp *compOp,PcodeOp *leftOp,PcodeOp *pullOp)

{
  int4 sa = 0;
  if (leftOp != (PcodeOp *)0) {
    Varnode *cvn = leftOp->getIn(1);
    if (!cvn->isConstant()) return 0;
    sa = cvn->getOffset();
  }
  int4 numbits = pullOp->getIn(2)->getOffset();
  Varnode *invn = pullOp->getIn(0);
  int4 sz = invn->getSize() * 8;
  if (numbits + sa != sz)		// Verify that high bit of field is shifted into sign-bit
    return 0;
  Varnode *inVn = (leftOp == (PcodeOp *)0) ? pullOp->getOut() : leftOp->getOut();
  Varnode *lessVn0 = compOp->getIn(0);
  Varnode *lessVn1 = compOp->getIn(1);
  if (compOp->code() == CPUI_INT_SLESS) {
    if (numbits == 1 && lessVn0 == inVn && lessVn1->isConstant() && lessVn1->getOffset() == 0) {
      Varnode *oldVn = compOp->getOut();
      data.totalReplace(oldVn,pullOp->getOut());
      data.destroyVarnodeRecursive(oldVn);
      return 1;
    }
    if (numbits == 1 && lessVn1 == inVn && lessVn0->isConstant()
	&& lessVn0->getOffset() == calc_mask(inVn->getSize())) {
      data.opRemoveInput(compOp,0);
      data.opSetOpcode(compOp,CPUI_BOOL_NEGATE);
      data.opSetInput(compOp,pullOp->getOut(),0);
      data.destroyVarnodeRecursive(inVn);
      return 1;
    }
  }
  uintb mask = 1;
  mask = (mask << sa) -1;
  if (sa > 0 && sa < 8*sizeof(uintb) && inVn == lessVn0 && lessVn1->isConstant()) {
    uintb origVal = lessVn1->getOffset();
    uintb lowBits = mask & origVal;
    if (lowBits == 0 || lowBits == 1) {
      uintb newVal;
      if (lowBits == 1) {
	newVal = (origVal - 1) >> sa;	// Convert to constant for LESSEQUAL
	newVal = (newVal + 1) & calc_mask(inVn->getSize());	// Convert back to LESS after shift
      }
      else
	newVal = origVal >> sa;
      data.opSetInput(compOp,pullOp->getOut(),0);
      data.opSetInput(compOp,data.newConstant(inVn->getSize(), newVal),1);
      data.destroyVarnodeRecursive(inVn);
      return 1;
    }
  }
  if (sa > 0 && sa < 8*sizeof(uintb) && inVn == lessVn1 && lessVn0->isConstant()) {
    uintb origVal = lessVn0->getOffset();
    uintb lowBits = mask & origVal;
    if (lowBits == 0 || lowBits == mask) {
      uintb newVal;
      if (lowBits == mask) {
	newVal = (origVal + 1) >> sa;		// Convert to constant for LESSEQUAL
	newVal = (newVal - 1) & calc_mask(inVn->getSize());	// Convert back to LESS after shift
      }
      else
	newVal = origVal >> sa;
      data.opSetInput(compOp,pullOp->getOut(),1);
      data.opSetInput(compOp,data.newConstant(inVn->getSize(), newVal),0);
      data.destroyVarnodeRecursive(inVn);
      return 1;
    }
  }
  return 0;
}

/// \brief Perform transform: `y = SEXT( SPULL( x, #p, #n ) )    =>    y = SPULL( x, #p, #n )`
///
/// Also transform:  `y = ZEXT( ZPULL( x, #p, #n ) )    =>   y = ZPULL( x, #p, #n )`
///
/// \param data is the function
/// \param extOp is the INT_SEXT or INT_ZEXT op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if transform performed, 0 otherwise
int4 RulePullAbsorb::absorbExt(Funcdata &data,PcodeOp *extOp,PcodeOp *pullOp)

{
  bool pullSigned = pullOp->code() == CPUI_SPULL;
  bool extSigned = extOp->code() == CPUI_INT_SEXT;
  if (extSigned != pullSigned) return 0;
  Varnode *vn = extOp->getIn(0);
  if (vn->loneDescend() != extOp) return 0;
  data.opSetOpcode(extOp, pullOp->code());
  data.opSetInput(extOp,pullOp->getIn(0),0);
  Varnode *posVn = pullOp->getIn(1);
  Varnode *numVn = pullOp->getIn(2);
  data.opInsertInput(extOp,posVn,1);
  data.opInsertInput(extOp,numVn,2);
  data.destroyVarnodeRecursive(vn);
  return 1;
}

/// \brief Perform transform:  `y = SUB( PULL( x, #p, #n ) )    =>   y = PULL( x, #p, #n )`
///
/// \param data is the function
/// \param subOp is the SUBPIECE op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if transform performed, 0 otherwise
int4 RulePullAbsorb::absorbSubpiece(Funcdata &data,PcodeOp *subOp,PcodeOp *pullOp)

{
  if (subOp->getIn(1)->getOffset() != 0) return 0;
  int4 bitsize = (int4)pullOp->getIn(2)->getOffset();
  Varnode *outvn = subOp->getOut();
  if (bitsize > 8*outvn->getSize()) return 0;
  Varnode *vn = subOp->getIn(0);
  if (vn->loneDescend() != subOp) return 0;
  data.opSetOpcode(subOp, pullOp->code());
  data.opSetInput(subOp, pullOp->getIn(0), 0);
  Varnode *posVn = pullOp->getIn(1);
  Varnode *numVn = pullOp->getIn(2);
  data.opSetInput(subOp,posVn,1);
  data.opInsertInput(subOp,numVn,2);
  data.destroyVarnodeRecursive(vn);
  return 1;
}

/// \brief Perform transform:   `ZPULL( x, #p, #1) != #0    =>   ZPULL(x, #p, #1)`
///
/// Also transform the variant  `ZPULL( x, #p, #1) == #0    =>   !ZPULL(x, #p, #1)`
/// \param data is the function
/// \param compOp is the INT_EQUAL or INT_NOTEQUAL op
/// \param pullOp is the ZPULL or SPULL op
/// \return 1 if transform performed, 0 otherwise
int4 RulePullAbsorb::absorbCompZero(Funcdata &data,PcodeOp *compOp,PcodeOp *pullOp)

{
  Varnode *zvn = compOp->getIn(1);
  if (!zvn->constantMatch(0)) return 0;
  int4 bitsize = (int4)pullOp->getIn(2)->getOffset();
  if (bitsize != 1) return 0;
  Varnode *vn = compOp->getIn(0);
  if (vn->loneDescend() != compOp) return 0;
  if (vn->isAddrTied()) return 0;
  if (pullOp->code() == CPUI_SPULL) return 0;
  const TypeBitField *field = BitFieldExpression::getPullField(pullOp);
  if (field == (const TypeBitField *)0 || field->type->getMetatype() != TYPE_BOOL)
    return 0;
  if (compOp->code() == CPUI_INT_EQUAL) {
    if (vn->getSize() > 1) {
      Address smalladdr = vn->getAddr();
      if (vn->getSpace()->isBigEndian())
        smalladdr = smalladdr + (vn->getSize() -1);
      data.opUnsetOutput(pullOp);
      Varnode *newVn = data.newVarnodeOut(1, smalladdr, pullOp);
      Datatype *dt = data.getArch()->types->getBase(1,TYPE_BOOL);
      newVn->updateType(dt);
      data.opSetInput(compOp,newVn,0);
      data.deleteVarnode(vn);
    }
    data.opSetOpcode(compOp,CPUI_BOOL_NEGATE);
    data.opRemoveInput(compOp, 1);
  }
  else {
    data.opSetOpcode(compOp,pullOp->code());
    data.opSetInput(compOp, pullOp->getIn(0), 0);
    Varnode *posVn = pullOp->getIn(1);
    Varnode *numVn = pullOp->getIn(2);
    data.opSetInput(compOp,posVn,1);
    data.opInsertInput(compOp,numVn,2);
    data.destroyVarnodeRecursive(vn);
  }
  return 1;
}

void RulePullAbsorb::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_ZPULL);
  oplist.push_back(CPUI_SPULL);
}

int4 RulePullAbsorb::applyOp(PcodeOp *op,Funcdata &data)

{
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = op->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    int4 res = 0;
    switch(readOp->code()) {
      case CPUI_INT_RIGHT:
      case CPUI_INT_SRIGHT:
	res = absorbRight(data,readOp,op);
	break;
      case CPUI_INT_LEFT:
	res = absorbLeft(data,readOp,op);
	break;
      case CPUI_INT_AND:
	res = absorbAnd(data,readOp,op);
	break;
      case CPUI_INT_SLESS:
      case CPUI_INT_LESS:
	res = absorbCompare(data,readOp,(PcodeOp *)0,op);
	break;
      case CPUI_INT_ZEXT:
      case CPUI_INT_SEXT:
	res = absorbExt(data, readOp, op);
	break;
      case CPUI_SUBPIECE:
	res = absorbSubpiece(data, readOp, op);
	break;
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
	res = absorbCompZero(data, readOp, op);
	break;
      default:
	break;
    }
    if (res != 0) return res;
  }
  return 0;
}

/// If the Varnode is shifted, return the Varnode stripped of the shift.
/// \param vn is the Varnode to test
/// \param sa is the given shift amount
/// \return the stripped Varnode or null
Varnode *RuleInsertAbsorb::leftShiftVarnode(Varnode *vn,int sa)

{
  if (!vn->isWritten()) return (Varnode *)0;
  PcodeOp *multOp = vn->getDef();
  Varnode *multVal = multOp->getIn(1);
  if (!multVal->isConstant()) return (Varnode *)0;
  uintb matchVal;
  if (multOp->code() == CPUI_INT_MULT) {
    matchVal = 1;
    matchVal <<= sa;
  }
  else if (multOp->code() == CPUI_INT_LEFT) {
    matchVal = sa;
  }
  else
    return (Varnode *)0;
  if (multVal->getOffset() != matchVal) return (Varnode *)0;
  return multOp->getIn(0);
}

/// \brief Perform the transform:  `INSERT( x & #mask, #p, #n )   =>   INSERT( x, #p, #n )`
///
/// \param data is the function
/// \param andOp is the INT_AND op
/// \param insertOp is the INSERT op
/// \return 1 if transform performed, 0 otherwise
int4 RuleInsertAbsorb::absorbAnd(Funcdata &data,PcodeOp *andOp,PcodeOp *insertOp)

{
  Varnode *cvn = andOp->getIn(1);
  if (!cvn->isConstant()) return 0;
  uintb val = cvn->getOffset();
  uintb mask = InsertExpression::getLSBMask(insertOp);
  if ((mask & val) != mask) return 0;		// AND mask must be of least significant bits that get INSERTed
  data.opSetInput(insertOp,andOp->getIn(0),1);
  data.destroyVarnodeRecursive(andOp->getOut());
  return 1;
}

/// \brief Perform the transform:  `INSERT( (x << #c) >> #c, #p, #n )  =>  INSERT(x, #p, #n )`
///
/// Also transform the variant: `INSERT( SUB( x << #c, #0) >> #c, #p, #n )  =>  INSERT(x, #p, #n)`
int4 RuleInsertAbsorb::absorbRightLeft(Funcdata &data,PcodeOp *nextOp,PcodeOp *rightOp,PcodeOp *insertOp)

{
  PcodeOp *leftOp;
  if (nextOp->code() == CPUI_INT_LEFT)
    leftOp = nextOp;
  else if (nextOp->code() == CPUI_SUBPIECE) {
    if (nextOp->getIn(1)->getOffset() != 0)
      return 0;
    Varnode *subin = nextOp->getIn(0);
    if (!subin->isWritten()) return 0;
    leftOp = subin->getDef();
    if (leftOp->code() != CPUI_INT_LEFT) return 0;
  }
  else
    return 0;
  Varnode *lvn = leftOp->getIn(1);
  if (!lvn->isConstant()) return 0;
  Varnode *rvn = rightOp->getIn(1);
  if (!rvn->isConstant()) return 0;
  int4 lsa = (int4)lvn->getOffset();
  int4 rsa = (int4)rvn->getOffset();
  if (lsa != rsa) return 0;
  int4 bitsize = (int4)insertOp->getIn(3)->getOffset();
  if (bitsize > insertOp->getIn(1)->getSize() * 8 - lsa)	// Shifts cancel unless bitsize exceeds number of bits preserved
    return 0;
  data.opSetInput(insertOp,leftOp->getIn(0),1);
  data.destroyVarnodeRecursive(rightOp->getOut());
  return 1;
}

/// \brief Perform the transform:  `field = (a * #c + b * #c) >> #n  =>  field = a + b`
///
/// \param data is the function
/// \param rightOp is the INT_RIGHT or INT_SRIGHT op
/// \param addOp is the INT_ADD op
/// \param insertOp is the INSERT op
/// \return 1 if transform performed, 0 otherwise
int4 RuleInsertAbsorb::absorbShiftAdd(Funcdata &data,PcodeOp *rightOp,PcodeOp *addOp,PcodeOp *insertOp)

{
  int4 sa = (int4)rightOp->getIn(1)->getOffset();
  if (sa <=0 || sa >= 8*sizeof(uintb))
    return 0;
  Varnode *vn0 = leftShiftVarnode(addOp->getIn(0),sa);
  if (vn0 == (Varnode *)0) return 0;
  Varnode *vn1;
  Varnode *addVn1 = addOp->getIn(1);
  if (addVn1->isConstant()) {
    uintb addVal = addVn1->getOffset();
    addVal >>= sa;
    if ((addVal << sa) != addVn1->getOffset()) return 0;
    vn1 = data.newConstant(vn0->getSize(), addVal);
    vn1->updateType(addVn1->getType());
  }
  else {
    vn1 = leftShiftVarnode(addVn1,sa);
    if (vn1 == (Varnode *)0) return 0;
  }
  int4 bitsize = (int4)insertOp->getIn(3)->getOffset();
  if (bitsize > vn0->getSize() * 8 - sa)	// Check that none of the carry bits make it into field
    return 0;
  data.opSetOpcode(rightOp, CPUI_INT_ADD);
  data.opSetInput(rightOp, vn0, 0);
  data.opSetInput(rightOp, vn1, 1);
  data.destroyVarnodeRecursive(addOp->getOut());
  return 1;
}

/// \brief Perform transforms like:  `INSERT( (x & #0xff) + y )   =>  INSERT( x + y )`
///
/// The op feeding the INSERT can be any operation where more significant bits of the input do not affect the less significant bits.
/// \param data is the function
/// \param baseOp is one of INT_ADD, INT_AND, INT_OR, or INT_XOR.
/// \param insertOp is the INSERT op
/// \return 1 if transform performed, 0 otherwise
int4 RuleInsertAbsorb::absorbNestedAnd(Funcdata &data,PcodeOp *baseOp,PcodeOp *insertOp)

{
  if (baseOp->getOut()->loneDescend() != insertOp) return 0;	// Result only used by INSERT
  for(int4 slot=0;slot<2;++slot) {
    Varnode *vn = baseOp->getIn(slot);
    if (!vn->isWritten()) continue;
    PcodeOp *andOp = vn->getDef();
    if (andOp->code() != CPUI_INT_AND) continue;
    Varnode *cvn = andOp->getIn(1);
    if (!cvn->isConstant()) continue;
    uintb mask = coveringmask(cvn->getOffset());
    if (mask != cvn->getOffset()) continue;
    if ((mask & 1)==0) continue;	// Masking off least significant bits
    int4 count = popcount(mask);
    int4 bitsize = (int4)insertOp->getIn(3)->getOffset();
    if (count < bitsize) continue;	// INSERT masks off fewer bits, so AND still has an effect
    data.opSetInput(baseOp,andOp->getIn(0),slot);
    data.destroyVarnodeRecursive(andOp->getOut());
    return 1;
  }
  return 0;
}

void RuleInsertAbsorb::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INSERT);
}

int4 RuleInsertAbsorb::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *inVn = op->getIn(1);
  if (!inVn->isWritten()) return 0;
  PcodeOp *inOp = inVn->getDef();
  Varnode *vn;
  PcodeOp *nextOp;
  OpCode opc;
  switch(inOp->code()) {
    case CPUI_SUBPIECE:
      if (inOp->getIn(1)->getOffset() != 0) return 0;
      data.opSetInput(op,inOp->getIn(0),1);
      data.destroyVarnodeRecursive(inVn);
      return 1;
    case CPUI_INT_RIGHT:
    case CPUI_INT_SRIGHT:
      if (!inOp->getIn(1)->isConstant()) return 0;
      vn = inOp->getIn(0);
      if (!vn->isWritten()) return 0;
      nextOp = vn->getDef();
      opc = nextOp->code();
      if (opc == CPUI_INT_ADD)
	return absorbShiftAdd(data, inOp, nextOp, op);
      else if (opc == CPUI_INT_LEFT || opc == CPUI_SUBPIECE)
	return absorbRightLeft(data, nextOp, inOp, op);
      break;
    case CPUI_INT_AND:
      return absorbAnd(data,inOp,op);
    case CPUI_INT_ADD:
    case CPUI_INT_OR:
    case CPUI_INT_XOR:
    case CPUI_INT_MULT:
      return absorbNestedAnd(data, inOp, op);
    default:
      break;
  }
  return 0;
}

} // End namespace ghidra

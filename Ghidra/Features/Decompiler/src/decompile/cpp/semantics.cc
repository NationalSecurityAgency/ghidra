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
#include "semantics.hh"
#include "translate.hh"

namespace ghidra {

/// \param tp is the specialized constant type: \b j_start, \b j_next, \b j_next2, \b j_flowdest, \b j_curspace, etc.
ConstTpl::ConstTpl(const_type tp)

{
  type = tp;
}

/// \param tp is constant type: either \b real or \b j_relative
/// \param val is the constant value
ConstTpl::ConstTpl(const_type tp,uintb val)

{
  type = tp;
  value_real = val;
  value.handle_index = 0;
  select = v_space;
}

/// \param tp is the constant type:  must be \b handle
/// \param ht is the index of the sub-constructor computing the \b handle value
/// \param vf is the part (space, offset, or size) of the computed value to encode as the constant
ConstTpl::ConstTpl(const_type tp,int4 ht,v_field vf)

{
  type = handle;
  value.handle_index = ht;
  select = vf;
  value_real = 0;
}

/// \param tp is the constant type: must be \b handle
/// \param ht is the index of the sub-constructor computing the \b handle value
/// \param vf is the part of the computed value to encode: must be \b v_offset_plus
/// \param plus is the additional constant value to add to the \b handle offset
ConstTpl::ConstTpl(const_type tp,int4 ht,v_field vf,uintb plus)

{
  type = handle;
  value.handle_index = ht;
  select = vf;
  value_real = plus;
}

/// \param sid is the address space to encode
ConstTpl::ConstTpl(AddrSpace *sid)

{
  type = spaceid;
  value.spaceid = sid;
}

bool ConstTpl::isConstSpace(void) const

{
  if (type==spaceid)
    return (value.spaceid->getType()==IPTR_CONSTANT);
  return false;
}

bool ConstTpl::isUniqueSpace(void) const

{
  if (type==spaceid)
    return (value.spaceid->getType()==IPTR_INTERNAL);
  return false;
}

/// The constants must be equal in both value and type.
/// \param op2 is the constant to compare with \b this
/// \return \b true if \b this is equal to \b op2, \b false otherwise
bool ConstTpl::operator==(const ConstTpl &op2) const

{
  if (type != op2.type) return false;
  switch(type) {
  case real:
    return (value_real == op2.value_real);
  case handle:
    if (value.handle_index != op2.value.handle_index) return false;
    if (select != op2.select) return false;
    break;
  case spaceid:
    return (value.spaceid == op2.value.spaceid);
  default:			// Nothing additional to compare
    break;
  }
  return true;
}

/// \param op2 is the constant to compare with \b this
/// \return \b true if \b this should be ordered before \b op2
bool ConstTpl::operator<(const ConstTpl &op2) const

{
  if (type != op2.type) return (type < op2.type);
  switch(type) {
  case real:
    return (value_real < op2.value_real);
  case handle:
    if (value.handle_index != op2.value.handle_index)
      return (value.handle_index < op2.value.handle_index);
    if (select != op2.select) return (select < op2.select);
    break;
  case spaceid:
    return (value.spaceid < op2.value.spaceid);
  default:			// Nothing additional to compare
    break;
  }
  return false;
}

/// If this is a \b handle associated with a dynamically computed value, this method returns
/// the properties of the temporary storage used to hold the computed value.
/// \param walker is the context for the parse of a single instruction
/// \return the computed constant value
uintb ConstTpl::fix(const ParserWalker &walker) const

{
  switch(type) {
  case j_start:
    return walker.getAddr().getOffset(); // Fill in starting address placeholder with real address
  case j_next:
    return walker.getNaddr().getOffset(); // Fill in next address placeholder with real address
  case j_next2:
    return walker.getN2addr().getOffset(); // Fill in next2 address placeholder with real address
  case j_flowref:
    return walker.getRefAddr().getOffset();
  case j_flowref_size:
    return walker.getRefAddr().getAddrSize();
  case j_flowdest:
    return walker.getDestAddr().getOffset();
  case j_flowdest_size:
    return walker.getDestAddr().getAddrSize();
  case j_curspace_size:
    return walker.getCurSpace()->getAddrSize();
  case j_curspace:
    return (uintb)(uintp)walker.getCurSpace();
  case handle:
    {
      const FixedHandle &hand(walker.getFixedHandle(value.handle_index));
      switch(select) {
      case v_space:
	if (hand.offset_space == (AddrSpace *)0)
	  return (uintb)(uintp)hand.space;
	return (uintb)(uintp)hand.temp_space;
      case v_offset:
	if (hand.offset_space==(AddrSpace *)0)
	  return hand.offset_offset;
	return hand.temp_offset;
      case v_size:
	return hand.size;
      case v_offset_plus:
	if (hand.space != walker.getConstSpace()) { // If we are not a constant
	  if (hand.offset_space==(AddrSpace *)0)
	    return hand.offset_offset + (value_real&0xffff); // Adjust offset by truncation amount
	  return hand.temp_offset + (value_real&0xffff);
	}
	else {			// If we are a constant, we want to return a shifted value
	  uintb val;
	  if (hand.offset_space==(AddrSpace *)0)
	    val = hand.offset_offset;
	  else
	    val = hand.temp_offset;
	  val >>= 8 * (value_real>>16);
	  return val;
	}
      }
      break;
    }
  case j_relative:
  case real:
    return value_real;
  case spaceid:
    return (uintb)(uintp)value.spaceid;
  }
  return 0;			// Should never reach here
}

AddrSpace *ConstTpl::fixSpace(const ParserWalker &walker) const

{				// Get the value of the ConstTpl in context
				// when we know it is a space
  switch(type) {
  case j_curspace:
    return walker.getCurSpace();
  case handle:
    {
      const FixedHandle &hand(walker.getFixedHandle(value.handle_index));
      switch(select) {
      case v_space:
	if (hand.offset_space == (AddrSpace *)0)
	  return hand.space;
	return hand.temp_space;
      default:
	break;
      }
      break;
    }
  case spaceid:
    return value.spaceid;
  case j_flowref:
    return walker.getRefAddr().getSpace();
  default:
    break;
  }
  throw LowlevelError("ConstTpl is not a spaceid as expected");
}

/// If \b this represents an address space, including if \b this is the address space
/// piece of a \b handle, replace the address space portion of the FixedHandle with \b this.
/// \param hand is the FixedHandle to replace
/// \param walker is the current context
void ConstTpl::fillinSpace(FixedHandle &hand,const ParserWalker &walker) const

{
  switch(type) {
  case j_curspace:
    hand.space = walker.getCurSpace();
    return;
  case handle:
    {
      const FixedHandle &otherhand(walker.getFixedHandle(value.handle_index));
      switch(select) {
      case v_space:
	hand.space = otherhand.space;
	return;
      default:
	break;
      }
      break;
    }
  case spaceid:
    hand.space = value.spaceid;
    return;
  default:
    break;
  }
  throw LowlevelError("ConstTpl is not a spaceid as expected");
}

/// First, \b this is \e fixed, based on the current context.  Then the final fixed
/// value is copied into the FixedHandle.  If \b this itself is a \b handle, the
/// entire fixed handle is copied into the FixedHandle.
/// \param hand is the FixedHandle to copy into
/// \param walker is the context to fix against
void ConstTpl::fillinOffset(FixedHandle &hand,const ParserWalker &walker) const

{
  // If the offset value is dynamic, indicate this in the handle
  // we don't just fill in the temporary variable offset
  // we assume hand.space is already filled in
  if (type == handle) {
    const FixedHandle &otherhand(walker.getFixedHandle(value.handle_index));
    hand.offset_space = otherhand.offset_space;
    hand.offset_offset = otherhand.offset_offset;
    hand.offset_size = otherhand.offset_size;
    hand.temp_space = otherhand.temp_space;
    hand.temp_offset = otherhand.temp_offset;
  }
  else {
    hand.offset_space = (AddrSpace *)0;
    hand.offset_offset = hand.space->wrapOffset(fix(walker));
  }
}

/// If \b this is not a \b handle, do nothing. Otherwise, copy the details of the indexed HandleTpl into \b this.
/// Copy the piece of the HandleTpl specified by \b select.
/// \param params is the array of HandleTpl
void ConstTpl::transfer(const vector<HandleTpl *> &params)

{
  if (type != handle) return;
  HandleTpl *newhandle = params[value.handle_index];

  switch(select) {
  case v_space:
    *this = newhandle->getSpace();
    break;
  case v_offset:
    *this = newhandle->getPtrOffset();
    break;
  case v_offset_plus:
    {
      uintb tmp = value_real;
      *this = newhandle->getPtrOffset();
      if (type == real) {
	value_real += (tmp&0xffff);
      }
      else if ((type == handle)&&(select == v_offset)) {
	select = v_offset_plus;
	value_real = tmp;
      }
      else
	throw LowlevelError("Cannot truncate macro input in this way");
      break;
    }
  case v_size:
    *this = newhandle->getSize();
    break;
  }
}

/// This is used to help reorder sub-constructors.
/// If \b this is a \b handle, its index is translated by looking up a new value in the given array of indices.
/// \param handmap is the given array of new \b handle indices
void ConstTpl::changeHandleIndex(const vector<int4> &handmap)

{
  if (type == handle)
    value.handle_index = handmap[value.handle_index];
}

/// \param encoder is the output stream
void ConstTpl::encode(Encoder &encoder) const

{
  switch(type) {
  case real:
    encoder.openElement(sla::ELEM_CONST_REAL);
    encoder.writeUnsignedInteger(sla::ATTRIB_VAL, value_real);
    encoder.closeElement(sla::ELEM_CONST_REAL);
    break;
  case handle:
    encoder.openElement(sla::ELEM_CONST_HANDLE);
    encoder.writeSignedInteger(sla::ATTRIB_VAL, value.handle_index);
    encoder.writeSignedInteger(sla::ATTRIB_S, select);
    if (select == v_offset_plus)
      encoder.writeUnsignedInteger(sla::ATTRIB_PLUS, value_real);
    encoder.closeElement(sla::ELEM_CONST_HANDLE);
    break;
  case j_start:
    encoder.openElement(sla::ELEM_CONST_START);
    encoder.closeElement(sla::ELEM_CONST_START);
    break;
  case j_next:
    encoder.openElement(sla::ELEM_CONST_NEXT);
    encoder.closeElement(sla::ELEM_CONST_NEXT);
    break;
  case j_next2:
    encoder.openElement(sla::ELEM_CONST_NEXT2);
    encoder.closeElement(sla::ELEM_CONST_NEXT2);
    break;
  case j_curspace:
    encoder.openElement(sla::ELEM_CONST_CURSPACE);
    encoder.closeElement(sla::ELEM_CONST_CURSPACE);
    break;
  case j_curspace_size:
    encoder.openElement(sla::ELEM_CONST_CURSPACE_SIZE);
    encoder.closeElement(sla::ELEM_CONST_CURSPACE_SIZE);
    break;
  case spaceid:
    encoder.openElement(sla::ELEM_CONST_SPACEID);
    encoder.writeSpace(sla::ATTRIB_SPACE, value.spaceid);
    encoder.closeElement(sla::ELEM_CONST_SPACEID);
    break;
  case j_relative:
    encoder.openElement(sla::ELEM_CONST_RELATIVE);
    encoder.writeUnsignedInteger(sla::ATTRIB_VAL, value_real);
    encoder.closeElement(sla::ELEM_CONST_RELATIVE);
    break;
  case j_flowref:
    encoder.openElement(sla::ELEM_CONST_FLOWREF);
    encoder.closeElement(sla::ELEM_CONST_FLOWREF);
    break;
  case j_flowref_size:
    encoder.openElement(sla::ELEM_CONST_FLOWREF_SIZE);
    encoder.closeElement(sla::ELEM_CONST_FLOWREF_SIZE);
    break;
  case j_flowdest:
    encoder.openElement(sla::ELEM_CONST_FLOWDEST);
    encoder.closeElement(sla::ELEM_CONST_FLOWDEST);
    break;
  case j_flowdest_size:
    encoder.openElement(sla::ELEM_CONST_FLOWDEST_SIZE);
    encoder.closeElement(sla::ELEM_CONST_FLOWDEST_SIZE);
    break;
  }
}

/// \param decoder is the input stream
void ConstTpl::decode(Decoder &decoder)

{
  uint4 el = decoder.openElement();
  if (el == sla::ELEM_CONST_REAL) {
    type = real;
    value_real = decoder.readUnsignedInteger(sla::ATTRIB_VAL);
  }
  else if (el == sla::ELEM_CONST_HANDLE) {
    type = handle;
    value.handle_index = decoder.readSignedInteger(sla::ATTRIB_VAL);
    uint4 selectInt = decoder.readSignedInteger(sla::ATTRIB_S);
    if (selectInt > v_offset_plus)
      throw DecoderError("Bad handle selector encoding");
    select = (v_field)selectInt;
    if (select == v_offset_plus) {
      value_real = decoder.readUnsignedInteger(sla::ATTRIB_PLUS);
    }
  }
  else if (el == sla::ELEM_CONST_START) {
    type = j_start;
  }
  else if (el == sla::ELEM_CONST_NEXT) {
    type = j_next;
  }
  else if (el == sla::ELEM_CONST_NEXT2) {
    type = j_next2;
  }
  else if (el == sla::ELEM_CONST_CURSPACE) {
    type = j_curspace;
  }
  else if (el == sla::ELEM_CONST_CURSPACE_SIZE) {
    type = j_curspace_size;
  }
  else if (el == sla::ELEM_CONST_SPACEID) {
    type = spaceid;
    value.spaceid = decoder.readSpace(sla::ATTRIB_SPACE);
  }
  else if (el == sla::ELEM_CONST_RELATIVE) {
    type = j_relative;
    value_real = decoder.readUnsignedInteger(sla::ATTRIB_VAL);
  }
  else if (el == sla::ELEM_CONST_FLOWREF) {
    type = j_flowref;
  }
  else if (el == sla::ELEM_CONST_FLOWREF_SIZE) {
    type = j_flowref_size;
  }
  else if (el == sla::ELEM_CONST_FLOWDEST) {
    type = j_flowdest;
  }
  else if (el == sla::ELEM_CONST_FLOWDEST_SIZE) {
    type = j_flowdest_size;
  }
  else
    throw LowlevelError("Bad constant type");
  decoder.closeElement(el);
}

/// \param hand is the index of the sub-constructor computing the \b handle value
/// \param zerosize is \b true if the size of \b this should be disassociated from the computed \b handle and forced to zero
VarnodeTpl::VarnodeTpl(int4 hand,bool zerosize) :
  space(ConstTpl::handle,hand,ConstTpl::v_space), offset(ConstTpl::handle,hand,ConstTpl::v_offset), size(ConstTpl::handle,hand,ConstTpl::v_size)
{
  if (zerosize)
    size = ConstTpl(ConstTpl::real,0);	// if zerosize is true, set the size constant to zero
  unnamed_flag = false;
}

/// \param sp represents the address space
/// \param off represents the offset into the address space
/// \param sz represents the number of bytes
VarnodeTpl::VarnodeTpl(const ConstTpl &sp,const ConstTpl &off,const ConstTpl &sz) :
  space(sp), offset(off), size(sz)

{
  unnamed_flag = false;
}

/// \param vn is the VarnodeTpl to copy
VarnodeTpl::VarnodeTpl(const VarnodeTpl &vn)
  : space(vn.space), offset(vn.offset), size(vn.size)
{
  unnamed_flag = vn.unnamed_flag;
}

bool VarnodeTpl::isLocalTemp(void) const

{
  if (space.getType() != ConstTpl::spaceid) return false;
  if (space.getSpace()->getType()!=IPTR_INTERNAL) return false;
  return true;
}

/// If the offset is computed by a sub-constructor using a p-code LOAD into a temporary register,
/// then return \b true.  If the sub-constructor does not use a LOAD, or \b this is not a \b handle, return \b false.
/// \param walker is the instruction context (used to look-up the specific sub-constructor)
/// \return \b true if \b this is a dynamic value computed by a sub-constructor
bool VarnodeTpl::isDynamic(const ParserWalker &walker) const

{
  if (offset.getType()!=ConstTpl::handle) return false;
				// Technically we should probably check all three
				// ConstTpls for dynamic handles, but in all cases
				// if there is any dynamic piece then the offset is
  const FixedHandle &hand(walker.getFixedHandle(offset.getHandleIndex()));
  return (hand.offset_space != (AddrSpace *)0);
}

/// For any piece of \b this (address space,offset,size) that is a handle, copy the HandleTpl with matching index.
/// If \b this needs an additional constant added to its final offset piece, return that constant.
/// \param params is the given array of HandleTpl to match against
/// \return any additional constant that still needs to be added in, or -1 otherwise
int4 VarnodeTpl::transfer(const vector<HandleTpl *> &params)

{
  bool doesOffsetPlus = false;
  int4 handleIndex;
  int4 plus;
  if ((offset.getType() == ConstTpl::handle)&&(offset.getSelect()==ConstTpl::v_offset_plus)) {
    handleIndex = offset.getHandleIndex();
    plus = (int4)offset.getReal();
    doesOffsetPlus = true;
  }
  space.transfer(params);
  offset.transfer(params);
  size.transfer(params);
  if (doesOffsetPlus) {
    if (isLocalTemp())
      return plus;		// A positive number indicates truncation of a local temp
    if (params[handleIndex]->getSize().isZero())
      return plus;		//    or a zerosize object
  }
  return -1;
}

/// This is used to help reorder sub-constructors.
/// For each piece of \b this, if it is a \b handle, its index is translated by looking up a new value in the
/// given array of indices.
/// \param handmap is the given array of new \b handle indices
void VarnodeTpl::changeHandleIndex(const vector<int4> &handmap)

{
  space.changeHandleIndex(handmap);
  offset.changeHandleIndex(handmap);
  size.changeHandleIndex(handmap);
}

/// The offset piece must be \b v_offset_plus, indicating \b this is truncated.
/// Compute the final form of the truncation given the final size and endianness.
/// Also check that the truncation is in bounds for the given final size.
/// \param sz is the final size of the Varnode in bytes
/// \param isbigendian is \b true if the address space is big endian.
/// \return \b true if the truncation is in bounds
bool VarnodeTpl::adjustTruncation(int4 sz,bool isbigendian)

{
  if (size.getType() != ConstTpl::real)
    return false;
  int4 numbytes = (int4) size.getReal();
  int4 byteoffset = (int4) offset.getReal();
  if (numbytes + byteoffset > sz) return false;

  // Encode the original truncation amount with the plus value
  uintb val = byteoffset;
  val <<= 16;
  if (isbigendian) {
    val |= (uintb)(sz - (numbytes+byteoffset));
  }
  else {
    val |= (uintb) byteoffset;
  }
  

  offset = ConstTpl(ConstTpl::handle,offset.getHandleIndex(),ConstTpl::v_offset_plus,val);
  return true;
}

/// \param encoder is the output stream
void VarnodeTpl::encode(Encoder &encoder) const

{
  encoder.openElement(sla::ELEM_VARNODE_TPL);
  space.encode(encoder);
  offset.encode(encoder);
  size.encode(encoder);
  encoder.closeElement(sla::ELEM_VARNODE_TPL);
}

/// \param decoder is the input stream
void VarnodeTpl::decode(Decoder &decoder)

{
  uint4 el = decoder.openElement(sla::ELEM_VARNODE_TPL);
  space.decode(decoder);
  offset.decode(decoder);
  size.decode(decoder);
  decoder.closeElement(el);
}

/// \param op2 is the VarnodeTpl to compare with \b this
/// \return \b true if address space, offset, and size or all equal
bool VarnodeTpl::operator==(const VarnodeTpl &op2) const

{
  return space==op2.space && offset==op2.offset && size==op2.size;
}

/// \param op2 is the VarnodeTpl to compare with \b this
/// \return \b true if address space, offset, or size is not equal
bool VarnodeTpl::operator!=(const VarnodeTpl &op2) const

{
  return !(*this == op2);
}

/// Order by address space, then offset, then size
/// \param op2 is the VarnodeTpl to order with \b this
/// \return \b true if \b this should come before \b op2
bool VarnodeTpl::operator<(const VarnodeTpl &op2) const

{
  if (!(space==op2.space)) return (space<op2.space);
  if (!(offset==op2.offset)) return (offset<op2.offset);
  if (!(size==op2.size)) return (size<op2.size);
  return false;
}

/// The constructed HandleTpl is not dynamic and matches the given VarnodeTpl
/// \param vn is the given VarnodeTpl
HandleTpl::HandleTpl(const VarnodeTpl *vn)

{
  space = vn->getSpace();
  size = vn->getSize();
  ptrspace = ConstTpl(ConstTpl::real,0);
  ptroffset = vn->getOffset();
}

/// \param spc is the address space
/// \param sz is the size
/// \param vn is the varnode representing the dynamic pointer
/// \param t_space is the address space of the temporary register
/// \param t_offset is the offset of the temporary register
HandleTpl::HandleTpl(const ConstTpl &spc,const ConstTpl &sz,const VarnodeTpl *vn,
		       AddrSpace *t_space,uintb t_offset) :
  space(spc), size(sz), ptrspace(vn->getSpace()), ptroffset(vn->getOffset()), ptrsize(vn->getSize()),
  temp_space(t_space), temp_offset(ConstTpl::real,t_offset)
{
}

/// The final constant values for \b this are computed in context and stored in the given FixedHandle object.
/// \param hand is FixedHandle holding the final \b handle constants
/// \param walker is the context used to fix constants
void HandleTpl::fix(FixedHandle &hand,const ParserWalker &walker) const

{
  if (ptrspace.getType() == ConstTpl::real) {
    // The export is unstarred, but this doesn't mean the varnode
    // being exported isn't dynamic
    space.fillinSpace(hand,walker);
    hand.size = size.fix(walker);
    ptroffset.fillinOffset(hand,walker);
  }
  else {
    hand.space = space.fixSpace(walker);
    hand.size = size.fix(walker);
    hand.offset_offset = ptroffset.fix(walker);
    hand.offset_space = ptrspace.fixSpace(walker);
    if (hand.offset_space->getType()==IPTR_CONSTANT) {
				// Handle could have been dynamic but wasn't
      hand.offset_space = (AddrSpace *)0;
      hand.offset_offset = AddrSpace::addressToByte(hand.offset_offset,hand.space->getWordSize());
      hand.offset_offset = hand.space->wrapOffset(hand.offset_offset);
    }
    else {
      hand.offset_size = ptrsize.fix(walker);
      hand.temp_space = temp_space.fixSpace(walker);
      hand.temp_offset = temp_offset.fix(walker);
    }
  }
}

/// This is used to help reorder sub-constructors.
/// For each piece of \b this, if it is a \b handle, its index is translated by looking up a new value in the
/// given array of indices.
/// \param handmap is the given array of new \b handle indices
void HandleTpl::changeHandleIndex(const vector<int4> &handmap)

{
  space.changeHandleIndex(handmap);
  size.changeHandleIndex(handmap);
  ptrspace.changeHandleIndex(handmap);
  ptroffset.changeHandleIndex(handmap);
  ptrsize.changeHandleIndex(handmap);
  temp_space.changeHandleIndex(handmap);
  temp_offset.changeHandleIndex(handmap);
}

/// \param encoder is the output stream
void HandleTpl::encode(Encoder &encoder) const

{
  encoder.openElement(sla::ELEM_HANDLE_TPL);
  space.encode(encoder);
  size.encode(encoder);
  ptrspace.encode(encoder);
  ptroffset.encode(encoder);
  ptrsize.encode(encoder);
  temp_space.encode(encoder);
  temp_offset.encode(encoder);
  encoder.closeElement(sla::ELEM_HANDLE_TPL);
}

/// \param decoder is the input stream
void HandleTpl::decode(Decoder &decoder)

{
  uint4 el = decoder.openElement(sla::ELEM_HANDLE_TPL);
  space.decode(decoder);
  size.decode(decoder);
  ptrspace.decode(decoder);
  ptroffset.decode(decoder);
  ptrsize.decode(decoder);
  temp_space.decode(decoder);
  temp_offset.decode(decoder);
  decoder.closeElement(el);
}

/// An OpTpl owns its VarnodeTpl
OpTpl::~OpTpl(void)

{
  if (output != (VarnodeTpl *)0)
    delete output;
  vector<VarnodeTpl *>::iterator iter;
  for(iter=input.begin();iter!=input.end();++iter)
    delete *iter;
}

bool OpTpl::isZeroSize(void) const

{
  vector<VarnodeTpl *>::const_iterator iter;

  if (output != (VarnodeTpl *)0)
    if (output->isZeroSize()) return true;
  for(iter=input.begin();iter!=input.end();++iter)
    if ((*iter)->isZeroSize()) return true;
  return false;
}

/// \param index is the index of the input to remove
void OpTpl::removeInput(int4 index)

{
  delete input[index];
  for(int4 i=index;i<input.size()-1;++i)
    input[i] = input[i+1];
  input.pop_back();
}

/// This is used to help reorder sub-constructors.
/// Each input and output VarnodeTpl is remapped using the given array of \b handle indices
/// \param handmap is the given array of new \b handle indices
void OpTpl::changeHandleIndex(const vector<int4> &handmap)

{
  if (output != (VarnodeTpl *)0)
    output->changeHandleIndex(handmap);
  vector<VarnodeTpl *>::const_iterator iter;

  for(iter=input.begin();iter!=input.end();++iter)
    (*iter)->changeHandleIndex(handmap);
}

/// \param encoder is the output stream
void OpTpl::encode(Encoder &encoder) const

{
  encoder.openElement(sla::ELEM_OP_TPL);
  encoder.writeOpcode(sla::ATTRIB_CODE, opc);
  if (output == (VarnodeTpl *)0) {
    encoder.openElement(sla::ELEM_NULL);
    encoder.closeElement(sla::ELEM_NULL);
  }
  else
    output->encode(encoder);
  for(int4 i=0;i<input.size();++i)
    input[i]->encode(encoder);
  encoder.closeElement(sla::ELEM_OP_TPL);
}

/// \param decoder is the input stream
void OpTpl::decode(Decoder &decoder)

{
  uint4 el = decoder.openElement(sla::ELEM_OP_TPL);
  opc = decoder.readOpcode(sla::ATTRIB_CODE);
  uint4 subel = decoder.peekElement();
  if (subel == sla::ELEM_NULL) {
    decoder.openElement();
    decoder.closeElement(subel);
    output = (VarnodeTpl *)0;
  }
  else {
    output = new VarnodeTpl();
    output->decode(decoder);
  }
  while(decoder.peekElement() != 0) {
    VarnodeTpl *vn = new VarnodeTpl();
    input.push_back(vn);
    vn->decode(decoder);
  }
  decoder.closeElement(el);
}

/// ConstructTpl owns any OpTpl and HandleTpl
ConstructTpl::~ConstructTpl(void)

{
  vector<OpTpl *>::iterator oiter;
  for(oiter=vec.begin();oiter!=vec.end();++oiter)
    delete *oiter;
  if (result != (HandleTpl *)0)
    delete result;
}

/// The added OpTpl can be a normal operation, which will be executed directly, or it can be a directive, like a
/// \b build or \b delayslot, which may ultimately decode to multiple operations.  Additionally, an OpTpl can represent
/// a \e label, used to resolve internal p-code branches.
/// \param ot is the OpTpl to add
/// \return \b true if the operation was successfully added and did not violate a compile time rules
bool ConstructTpl::addOp(OpTpl *ot)

{
  if (ot->getOpcode() == DELAY_SLOT) {
    if (delayslot != 0)
      return false;		// Cannot have multiple delay slots
    delayslot = ot->getIn(0)->getOffset().getReal();
  }
  else if (ot->getOpcode() == LABELBUILD)
    numlabels += 1;		// Count labels
  vec.push_back(ot);
  return true;
}

/// \param oplist is the list of operations to add
/// \return \b true if all operations were successfully added
bool ConstructTpl::addOpList(const vector<OpTpl *> &oplist)

{
  for(int4 i=0;i<oplist.size();++i)
    if (!addOp(oplist[i]))
      return false;
  return true;
}

/// For any sub-constructor that does not already one, a new \b build directive is added to the front
/// of the operation sequence.
/// \param check is an array of integers, initialized to 0, used to mark sub-constructors with a directive.
/// \param const_space is the \e constant address space
/// \return 0 upon success, 1 if there is a duplicate \b build, 2 if there is a \b build for a non-subtable
int4 ConstructTpl::fillinBuild(vector<int4> &check,AddrSpace *const_space)

{
  vector<OpTpl *>::iterator iter;
  OpTpl *op;
  VarnodeTpl *indvn;

  for(iter=vec.begin();iter!=vec.end();++iter) {
    op = *iter;
    if (op->getOpcode() == BUILD) {
      int4 index = op->getIn(0)->getOffset().getReal();
      if (check[index] != 0)
	return check[index];	// Duplicate BUILD statement or non-subtable
      check[index] = 1;		// Mark to avoid future duplicate build
    }
  }
  for(int4 i=0;i<check.size();++i) {
    if (check[i] == 0) {	// Didn't see a BUILD statement
      op = new OpTpl(BUILD);
      indvn = new VarnodeTpl(ConstTpl(const_space),
			      ConstTpl(ConstTpl::real,i),
			      ConstTpl(ConstTpl::real,4));
      op->addInput(indvn);
      vec.insert(vec.begin(),op);
    }
  }
  return 0;
}

/// \return \b true if every operation is a \b build directive
bool ConstructTpl::buildOnly(void) const

{
  vector<OpTpl *>::const_iterator iter;
  OpTpl *op;
  for(iter=vec.begin();iter!=vec.end();++iter) {
    op = *iter;
    if (op->getOpcode() != BUILD)
      return false;
  }
  return true;
}

/// Each OpTpl operation is remapped using the given array of \b handle indices
/// \param handmap is the given array of new \b handle indices
void ConstructTpl::changeHandleIndex(const vector<int4> &handmap)

{
  vector<OpTpl *>::const_iterator iter;
  OpTpl *op;

  for(iter=vec.begin();iter!=vec.end();++iter) {
    op = *iter;
    if (op->getOpcode() == BUILD) {
      int4 index = op->getIn(0)->getOffset().getReal();
      index = handmap[index];
      op->getIn(0)->setOffset(index);
    }
    else
      op->changeHandleIndex(handmap);
  }
  if (result != (HandleTpl *)0)
    result->changeHandleIndex(handmap);
}

/// For use with optimization routines.
/// \param vn is the new input
/// \param index is the position of the operation within the sequence
/// \param slot is the input slot to replace with the new input
void ConstructTpl::setInput(VarnodeTpl *vn,int4 index,int4 slot)

{
  OpTpl *op = vec[index];
  VarnodeTpl *oldvn = op->getIn(slot);
  op->setInput(vn,slot);
  if (oldvn != (VarnodeTpl *)0)
    delete oldvn;
}

/// For use with optimization routines.
/// \param vn is the new output
/// \param index is the position of the operation within the sequence
void ConstructTpl::setOutput(VarnodeTpl *vn,int4 index)

{
  OpTpl *op = vec[index];
  VarnodeTpl *oldvn = op->getOut();
  op->setOutput(vn);
  if (oldvn != (VarnodeTpl *)0)
    delete oldvn;
}

/// \param indices is an array of the indices indicating the positions of the OpTpl to be deleted
void ConstructTpl::deleteOps(const vector<int4> &indices)

{
  for(uint4 i=0;i<indices.size();++i) {
    delete vec[indices[i]];
    vec[indices[i]] = (OpTpl *)0;
  }
  uint4 poscur = 0;
  for(uint4 i=0;i<vec.size();++i) {
    OpTpl *op = vec[i];
    if (op != (OpTpl *)0) {
      vec[poscur] = op;
      poscur += 1;
    }
  }
  while(vec.size() > poscur)
    vec.pop_back();
}

/// \param encoder is the output stream
/// \param sectionid is the id of the specific Constructor section to associate with \b this sequence
void ConstructTpl::encode(Encoder &encoder,int4 sectionid) const

{
  encoder.openElement(sla::ELEM_CONSTRUCT_TPL);
  if (sectionid >=0 )
    encoder.writeSignedInteger(sla::ATTRIB_SECTION, sectionid);
  if (delayslot != 0)
    encoder.writeSignedInteger(sla::ATTRIB_DELAY, delayslot);
  if (numlabels != 0)
    encoder.writeSignedInteger(sla::ATTRIB_LABELS, numlabels);
  if (result != (HandleTpl *)0)
    result->encode(encoder);
  else {
    encoder.openElement(sla::ELEM_NULL);
    encoder.closeElement(sla::ELEM_NULL);
  }
  for(int4 i=0;i<vec.size();++i)
    vec[i]->encode(encoder);
  encoder.closeElement(sla::ELEM_CONSTRUCT_TPL);
}

/// \param decoder is the stream to decode from
/// \return the Constructor section id associated with the sequence
int4 ConstructTpl::decode(Decoder &decoder)

{
  uint4 el = decoder.openElement(sla::ELEM_CONSTRUCT_TPL);
  int4 sectionid = -1;
  uint4 attrib = decoder.getNextAttributeId();
  while(attrib != 0) {
    if (attrib == sla::ATTRIB_DELAY) {
      delayslot = decoder.readSignedInteger();
    }
    else if (attrib == sla::ATTRIB_LABELS) {
      numlabels = decoder.readSignedInteger();
    }
    else if (attrib == sla::ATTRIB_SECTION) {
      sectionid = decoder.readSignedInteger();
    }
    attrib = decoder.getNextAttributeId();
  }
  uint4 subel = decoder.peekElement();
  if (subel == sla::ELEM_NULL) {
    decoder.openElement();
    decoder.closeElement(subel);
    result = (HandleTpl *)0;
  }
  else {
    result = new HandleTpl();
    result->decode(decoder);
  }
  while(decoder.peekElement() != 0) {
    OpTpl *op = new OpTpl();
    vec.push_back(op);
    op->decode(decoder);
  }
  decoder.closeElement(el);
  return sectionid;
}

/// Process all the semantic operations in the given ConstructTpl, handling directives and labels.
/// \param construct is the given ConstructTpl sequence
/// \param secnum is the section number associated with the sequence
void PcodeBuilder::build(ConstructTpl *construct,int4 secnum)

{
  if (construct == (ConstructTpl *)0)
    throw UnimplError("",0);	// Pcode is not implemented for this constructor

  uint4 oldbase = labelbase;	// Recursively store old labelbase
  labelbase = labelcount;	// Set the newbase
  labelcount += construct->numLabels();	// Add labels from this template

  vector<OpTpl *>::const_iterator iter;
  OpTpl *op;
  const vector<OpTpl *> &ops(construct->getOpvec());

  for(iter=ops.begin();iter!=ops.end();++iter) {
    op = *iter;
    switch(op->getOpcode()) {
    case BUILD:
      appendBuild( op, secnum );
      break;
    case DELAY_SLOT:
      delaySlot( op );
      break;
    case LABELBUILD:
      setLabel( op );
      break;
    case CROSSBUILD:
      appendCrossBuild(op,secnum);
      break;
    default:
      dump( op );
      break;
    }
  }
  labelbase = oldbase;		// Restore old labelbase
}

} // End namespace ghidra

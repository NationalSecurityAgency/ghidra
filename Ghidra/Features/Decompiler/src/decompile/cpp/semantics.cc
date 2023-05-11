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

ConstTpl::ConstTpl(const_type tp)

{				// Constructor for relative jump constants and uniques
  type = tp;
}

ConstTpl::ConstTpl(const_type tp,uintb val)

{				// Constructor for real constants
  type = tp;
  value_real = val;
  value.handle_index = 0;
  select = v_space;
}

ConstTpl::ConstTpl(const_type tp,int4 ht,v_field vf)

{				// Constructor for handle constant
  type = handle;
  value.handle_index = ht;
  select = vf;
  value_real = 0;
}

ConstTpl::ConstTpl(const_type tp,int4 ht,v_field vf,uintb plus)

{
  type = handle;
  value.handle_index = ht;
  select = vf;
  value_real = plus;
}

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

uintb ConstTpl::fix(const ParserWalker &walker) const

{ // Get the value of the ConstTpl in context
  // NOTE: if the property is dynamic this returns the property
  // of the temporary storage
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

void ConstTpl::fillinSpace(FixedHandle &hand,const ParserWalker &walker) const

{ // Fill in the space portion of a FixedHandle, base on this ConstTpl
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

void ConstTpl::fillinOffset(FixedHandle &hand,const ParserWalker &walker) const

{ // Fillin the offset portion of a FixedHandle, based on this ConstTpl
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

void ConstTpl::transfer(const vector<HandleTpl *> &params)

{				// Replace old handles with new handles
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

void ConstTpl::printHandleSelector(ostream &s,v_field val)

{
  switch(val) {
  case v_space:
    s << "space";
    break;
  case v_offset:
    s << "offset";
    break;
  case v_size:
    s << "size";
    break;
  case v_offset_plus:
    s << "offset_plus";
    break;
  }
}

ConstTpl::v_field ConstTpl::readHandleSelector(const string &name)

{
  if (name == "space")
    return v_space;
  if (name == "offset")
    return v_offset;
  if (name == "size")
    return v_size;
  if (name == "offset_plus")
    return v_offset_plus;
  throw LowlevelError("Bad handle selector");
}

void ConstTpl::changeHandleIndex(const vector<int4> &handmap)

{
  if (type == handle)
    value.handle_index = handmap[value.handle_index];
}

void ConstTpl::saveXml(ostream &s) const

{
  s << "<const_tpl type=\"";
  switch(type) {
  case real:
    s << "real\" val=\"0x" << hex << value_real << "\"/>";
    break;
  case handle:
    s << "handle\" val=\"" << dec << value.handle_index << "\" ";
    s << "s=\"";
    printHandleSelector(s,select);
    s << "\"";
    if (select == v_offset_plus)
      s << " plus=\"0x" << hex << value_real << "\"";
    s << "/>";
    break;
  case j_start:
    s << "start\"/>";
    break;
  case j_next:
    s << "next\"/>";
    break;
  case j_next2:
    s << "next2\"/>";
    break;
  case j_curspace:
    s << "curspace\"/>";
    break;
  case j_curspace_size:
    s << "curspace_size\"/>";
    break;
  case spaceid:
    s << "spaceid\" name=\"" << value.spaceid->getName() << "\"/>";
    break;
  case j_relative:
    s << "relative\" val=\"0x" << hex << value_real << "\"/>";
    break;
  case j_flowref:
    s << "flowref\"/>";
    break;
  case j_flowref_size:
    s << "flowref_size\"/>";
    break;
  case j_flowdest:
    s << "flowdest\"/>";
    break;
  case j_flowdest_size:
    s << "flowdest_size\"/>";
    break;
  }
}

void ConstTpl::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  const string &typestring(el->getAttributeValue("type"));
  if (typestring == "real") {
    type = real;
    istringstream s(el->getAttributeValue("val"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> value_real;
  }
  else if (typestring=="handle") {
    type = handle;
    istringstream s(el->getAttributeValue("val"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> value.handle_index;
    select = readHandleSelector(el->getAttributeValue("s"));
    if (select == v_offset_plus) {
      istringstream s2(el->getAttributeValue("plus"));
      s2.unsetf(ios::dec | ios::hex | ios::oct);
      s2 >> value_real;
    }
  }
  else if (typestring=="start") {
    type = j_start;
  }
  else if (typestring=="next") {
    type = j_next;
  }
  else if (typestring=="next2") {
    type = j_next2;
  }
  else if (typestring=="curspace") {
    type = j_curspace;
  }
  else if (typestring=="curspace_size") {
    type = j_curspace_size;
  }
  else if (typestring=="spaceid") {
    type = spaceid;
    value.spaceid = manage->getSpaceByName(el->getAttributeValue("name"));
  }
  else if (typestring=="relative") {
    type = j_relative;
    istringstream s(el->getAttributeValue("val"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> value_real;
  }
  else if (typestring == "flowref") {
    type = j_flowref;
  }
  else if (typestring == "flowref_size") {
    type = j_flowref_size;
  }
  else if (typestring == "flowdest") {
    type = j_flowdest;
  }
  else if (typestring == "flowdest_size") {
    type = j_flowdest_size;
  }
  else
    throw LowlevelError("Bad constant type");
}

VarnodeTpl::VarnodeTpl(int4 hand,bool zerosize) :
  space(ConstTpl::handle,hand,ConstTpl::v_space), offset(ConstTpl::handle,hand,ConstTpl::v_offset), size(ConstTpl::handle,hand,ConstTpl::v_size)
{				// Varnode built from a handle
				// if zerosize is true, set the size constant to zero
  if (zerosize)
    size = ConstTpl(ConstTpl::real,0);
  unnamed_flag = false;
}

VarnodeTpl::VarnodeTpl(const ConstTpl &sp,const ConstTpl &off,const ConstTpl &sz) :
  space(sp), offset(off), size(sz)

{
  unnamed_flag = false;
}

VarnodeTpl::VarnodeTpl(const VarnodeTpl &vn)
  : space(vn.space), offset(vn.offset), size(vn.size)
{				// A clone of the VarnodeTpl
  unnamed_flag = vn.unnamed_flag;
}

bool VarnodeTpl::isLocalTemp(void) const

{
  if (space.getType() != ConstTpl::spaceid) return false;
  if (space.getSpace()->getType()!=IPTR_INTERNAL) return false;
  return true;
}

bool VarnodeTpl::isDynamic(const ParserWalker &walker) const

{
  if (offset.getType()!=ConstTpl::handle) return false;
				// Technically we should probably check all three
				// ConstTpls for dynamic handles, but in all cases
				// if there is any dynamic piece then the offset is
  const FixedHandle &hand(walker.getFixedHandle(offset.getHandleIndex()));
  return (hand.offset_space != (AddrSpace *)0);
}

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

void VarnodeTpl::changeHandleIndex(const vector<int4> &handmap)

{
  space.changeHandleIndex(handmap);
  offset.changeHandleIndex(handmap);
  size.changeHandleIndex(handmap);
}

bool VarnodeTpl::adjustTruncation(int4 sz,bool isbigendian)

{ // We know this->offset is an offset_plus, check that the truncation is in bounds (given -sz-)
  // adjust plus for endianness if necessary
  // return true if truncation is in bounds
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

void VarnodeTpl::saveXml(ostream &s) const

{
  s << "<varnode_tpl>";
  space.saveXml(s);
  offset.saveXml(s);
  size.saveXml(s);
  s << "</varnode_tpl>\n";
}

void VarnodeTpl::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  space.restoreXml(*iter,manage);
  ++iter;
  offset.restoreXml(*iter,manage);
  ++iter;
  size.restoreXml(*iter,manage);
}

bool VarnodeTpl::operator<(const VarnodeTpl &op2) const

{
  if (!(space==op2.space)) return (space<op2.space);
  if (!(offset==op2.offset)) return (offset<op2.offset);
  if (!(size==op2.size)) return (size<op2.size);
  return false;
}

HandleTpl::HandleTpl(const VarnodeTpl *vn)

{				// Build handle which indicates given varnode
  space = vn->getSpace();
  size = vn->getSize();
  ptrspace = ConstTpl(ConstTpl::real,0);
  ptroffset = vn->getOffset();
}

HandleTpl::HandleTpl(const ConstTpl &spc,const ConstTpl &sz,const VarnodeTpl *vn,
		       AddrSpace *t_space,uintb t_offset) :
  space(spc), size(sz), ptrspace(vn->getSpace()), ptroffset(vn->getOffset()), ptrsize(vn->getSize()),
  temp_space(t_space), temp_offset(ConstTpl::real,t_offset)
{				// Build handle to thing being pointed at by -vn-
}

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

void HandleTpl::saveXml(ostream &s) const

{
  s << "<handle_tpl>";
  space.saveXml(s);
  size.saveXml(s);
  ptrspace.saveXml(s);
  ptroffset.saveXml(s);
  ptrsize.saveXml(s);
  temp_space.saveXml(s);
  temp_offset.saveXml(s);
  s << "</handle_tpl>\n";
}

void HandleTpl::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  space.restoreXml(*iter,manage);
  ++iter;
  size.restoreXml(*iter,manage);
  ++iter;
  ptrspace.restoreXml(*iter,manage);
  ++iter;
  ptroffset.restoreXml(*iter,manage);
  ++iter;
  ptrsize.restoreXml(*iter,manage);
  ++iter;
  temp_space.restoreXml(*iter,manage);
  ++iter;
  temp_offset.restoreXml(*iter,manage);
}

OpTpl::~OpTpl(void)

{				// An OpTpl owns its varnode_tpls
  if (output != (VarnodeTpl *)0)
    delete output;
  vector<VarnodeTpl *>::iterator iter;
  for(iter=input.begin();iter!=input.end();++iter)
    delete *iter;
}

bool OpTpl::isZeroSize(void) const

{				// Return if any input or output has zero size
  vector<VarnodeTpl *>::const_iterator iter;

  if (output != (VarnodeTpl *)0)
    if (output->isZeroSize()) return true;
  for(iter=input.begin();iter!=input.end();++iter)
    if ((*iter)->isZeroSize()) return true;
  return false;
}

void OpTpl::removeInput(int4 index)

{ // Remove the indicated input
  delete input[index];
  for(int4 i=index;i<input.size()-1;++i)
    input[i] = input[i+1];
  input.pop_back();
}

void OpTpl::changeHandleIndex(const vector<int4> &handmap)

{
  if (output != (VarnodeTpl *)0)
    output->changeHandleIndex(handmap);
  vector<VarnodeTpl *>::const_iterator iter;

  for(iter=input.begin();iter!=input.end();++iter)
    (*iter)->changeHandleIndex(handmap);
}

void OpTpl::saveXml(ostream &s) const

{
  s << "<op_tpl code=\"" << get_opname(opc) << "\">";
  if (output == (VarnodeTpl *)0)
    s << "<null/>\n";
  else
    output->saveXml(s);
  for(int4 i=0;i<input.size();++i)
    input[i]->saveXml(s);
  s << "</op_tpl>\n";
}

void OpTpl::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  opc = get_opcode(el->getAttributeValue("code"));
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  if ((*iter)->getName() == "null")
    output = (VarnodeTpl *)0;
  else {
    output = new VarnodeTpl();
    output->restoreXml(*iter,manage);
  }
  ++iter;
  while(iter != list.end()) {
    VarnodeTpl *vn = new VarnodeTpl();
    vn->restoreXml(*iter,manage);
    input.push_back(vn);
    ++iter;
  }
}

ConstructTpl::~ConstructTpl(void)

{				// Constructor owns its ops and handles
  vector<OpTpl *>::iterator oiter;
  for(oiter=vec.begin();oiter!=vec.end();++oiter)
    delete *oiter;
  if (result != (HandleTpl *)0)
    delete result;
}

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

bool ConstructTpl::addOpList(const vector<OpTpl *> &oplist)

{
  for(int4 i=0;i<oplist.size();++i)
    if (!addOp(oplist[i]))
      return false;
  return true;
}

int4 ConstructTpl::fillinBuild(vector<int4> &check,AddrSpace *const_space)

{ // Make sure there is a build statement for all subtable params
  // Return 0 upon success, 1 if there is a duplicate BUILD, 2 if there is a build for a non-subtable
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

void ConstructTpl::setInput(VarnodeTpl *vn,int4 index,int4 slot)

{ // set the VarnodeTpl input for a particular op
  // for use with optimization routines
  OpTpl *op = vec[index];
  VarnodeTpl *oldvn = op->getIn(slot);
  op->setInput(vn,slot);
  if (oldvn != (VarnodeTpl *)0)
    delete oldvn;
}

void ConstructTpl::setOutput(VarnodeTpl *vn,int4 index)

{ // set the VarnodeTpl output for a particular op
  // for use with optimization routines
  OpTpl *op = vec[index];
  VarnodeTpl *oldvn = op->getOut();
  op->setOutput(vn);
  if (oldvn != (VarnodeTpl *)0)
    delete oldvn;
}

void ConstructTpl::deleteOps(const vector<int4> &indices)

{ // delete a particular set of ops
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

void ConstructTpl::saveXml(ostream &s,int4 sectionid) const

{
  s << "<construct_tpl";
  if (sectionid >=0 )
    s << " section=\"" << dec << sectionid << "\"";
  if (delayslot != 0)
    s << " delay=\"" << dec << delayslot << "\"";
  if (numlabels != 0)
    s << " labels=\"" << dec << numlabels << "\"";
  s << ">\n";
  if (result != (HandleTpl *)0)
    result->saveXml(s);
  else
    s << "<null/>";
  for(int4 i=0;i<vec.size();++i)
    vec[i]->saveXml(s);
  s << "</construct_tpl>\n";
}

int4 ConstructTpl::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  int4 sectionid = -1;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i)=="delay") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> delayslot;
    }
    else if (el->getAttributeName(i)=="labels") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> numlabels;
    }
    else if (el->getAttributeName(i)=="section") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> sectionid;
    }
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  if ((*iter)->getName() == "null")
    result = (HandleTpl *)0;
  else {
    result = new HandleTpl();
    result->restoreXml(*iter,manage);
  }
  ++iter;
  while(iter != list.end()) {
    OpTpl *op = new OpTpl();
    op->restoreXml(*iter,manage);
    vec.push_back(op);
    ++iter;
  }
  return sectionid;
}

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

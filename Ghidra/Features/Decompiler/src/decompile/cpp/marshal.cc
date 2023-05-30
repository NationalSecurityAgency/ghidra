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
#include "marshal.hh"
#include "translate.hh"

namespace ghidra {

using namespace PackedFormat;

unordered_map<string,uint4> AttributeId::lookupAttributeId;

const int4 PackedDecode::BUFFER_SIZE = 1024;

/// Access static vector of AttributeId objects that are registered during static initialization
/// The list itself is created once on the first call to this method.
/// \return a reference to the vector
vector<AttributeId *> &AttributeId::getList(void)

{
  static vector<AttributeId *> thelist;
  return thelist;
}

/// This constructor should only be invoked for static objects.  It registers the attribute for inclusion
/// in the global hashtable.
/// \param nm is the name of the attribute
/// \param i is an id to associate with the attribute
AttributeId::AttributeId(const string &nm,uint4 i)
  : name(nm)
{
  id = i;
  getList().push_back(this);
}

/// Fill the hashtable mapping attribute names to their id, from registered attribute objects
void AttributeId::initialize(void)

{
  vector<AttributeId *> &thelist(getList());
  for(int4 i=0;i<thelist.size();++i) {
    AttributeId *attrib = thelist[i];
#ifdef CPUI_DEBUG
  if (lookupAttributeId.find(attrib->name) != lookupAttributeId.end())
    throw DecoderError(attrib->name + " attribute registered more than once");
#endif
    lookupAttributeId[attrib->name] = attrib->id;
  }
  thelist.clear();
  thelist.shrink_to_fit();
}

unordered_map<string,uint4> ElementId::lookupElementId;

/// Access static vector of ElementId objects that are registered during static initialization
/// The list itself is created once on the first call to this method.
/// \return a reference to the vector
vector<ElementId *> &ElementId::getList(void)

{
  static vector<ElementId *> thelist;
  return thelist;
}

/// This constructor should only be invoked for static objects.  It registers the element for inclusion
/// in the global hashtable.
/// \param nm is the name of the element
/// \param i is an id to associate with the element
ElementId::ElementId(const string &nm,uint4 i)
  : name(nm)
{
  id = i;
  getList().push_back(this);
}

/// Fill the hashtable mapping element names to their id, from registered element objects
void ElementId::initialize(void)

{
  vector<ElementId *> &thelist(getList());
  for(int4 i=0;i<thelist.size();++i) {
    ElementId *elem = thelist[i];
#ifdef CPUI_DEBUG
  if (lookupElementId.find(elem->name) != lookupElementId.end())
    throw DecoderError(elem->name + " element registered more than once");
#endif
    lookupElementId[elem->name] = elem->id;
  }
  thelist.clear();
  thelist.shrink_to_fit();
}

XmlDecode::~XmlDecode(void)

{
  if (document != (Document *)0)
    delete document;
}

void XmlDecode::ingestStream(istream &s)

{
  document = xml_tree(s);
  rootElement = document->getRoot();
}

uint4 XmlDecode::peekElement(void)

{
  const Element *el;
  if (elStack.empty()) {
    if (rootElement == (const Element *)0)
      return 0;
    el = rootElement;
  }
  else {
    el = elStack.back();
    List::const_iterator iter = iterStack.back();
    if (iter == el->getChildren().end())
      return 0;
    el = *iter;
  }
  return ElementId::find(el->getName());
}

uint4 XmlDecode::openElement(void)

{
  const Element *el;
  if (elStack.empty()) {
    if (rootElement == (const Element *)0)
      return 0;				// Document already traversed
    el = rootElement;
   rootElement = (const Element *)0;		// Only open once
  }
  else {
    el = elStack.back();
    List::const_iterator iter = iterStack.back();
    if (iter == el->getChildren().end())
      return 0;				// Element already fully traversed
    el = *iter;
    iterStack.back() = ++iter;
  }
  elStack.push_back(el);
  iterStack.push_back(el->getChildren().begin());
  attributeIndex = -1;
  return ElementId::find(el->getName());
}

uint4 XmlDecode::openElement(const ElementId &elemId)

{
  const Element *el;
  if (elStack.empty()) {
    if (rootElement == (const Element *)0)
      throw DecoderError("Expecting <" + elemId.getName() + "> but reached end of document");
    el = rootElement;
    rootElement = (const Element *)0;		// Only open document once
  }
  else {
    el = elStack.back();
    List::const_iterator iter = iterStack.back();
    if (iter != el->getChildren().end()) {
      el = *iter;
      iterStack.back() = ++iter;
    }
    else
      throw DecoderError("Expecting <" + elemId.getName() + "> but no remaining children in current element");
  }
  if (el->getName() != elemId.getName())
    throw DecoderError("Expecting <" + elemId.getName() + "> but got <" + el->getName() + ">");
  elStack.push_back(el);
  iterStack.push_back(el->getChildren().begin());
  attributeIndex = -1;
  return elemId.getId();
}

void XmlDecode::closeElement(uint4 id)

{
#ifdef CPUI_DEBUG
  const Element *el = elStack.back();
  if (iterStack.back() != el->getChildren().end())
    throw DecoderError("Closing element <" + el->getName() + "> with additional children");
  if (ElementId::find(el->getName()) != id)
    throw DecoderError("Trying to close <" + el->getName() + "> with mismatching id");
#endif
  elStack.pop_back();
  iterStack.pop_back();
  attributeIndex = 1000;	// Cannot read any additional attributes
}

void XmlDecode::closeElementSkipping(uint4 id)

{
#ifdef CPUI_DEBUG
  const Element *el = elStack.back();
  if (ElementId::find(el->getName()) != id)
    throw DecoderError("Trying to close <" + el->getName() + "> with mismatching id");
#endif
  elStack.pop_back();
  iterStack.pop_back();
  attributeIndex = 1000;  // We could check that id matches current element
}

void XmlDecode::rewindAttributes(void)

{
  attributeIndex = -1;
}

uint4 XmlDecode::getNextAttributeId(void)

{
  const Element *el = elStack.back();
  int4 nextIndex = attributeIndex + 1;
  if (nextIndex < el->getNumAttributes()) {
    attributeIndex = nextIndex;
    return AttributeId::find(el->getAttributeName(attributeIndex));
  }
  return 0;
}

uint4 XmlDecode::getIndexedAttributeId(const AttributeId &attribId)

{
  const Element *el = elStack.back();
  if (attributeIndex < 0 || attributeIndex >= el->getNumAttributes())
    return ATTRIB_UNKNOWN.getId();
  // For XML, the index is encoded directly in the attribute name
  const string &attribName(el->getAttributeName(attributeIndex));
  // Does the name start with desired attribute base name?
  if (0 != attribName.compare(0,attribId.getName().size(),attribId.getName()))
    return ATTRIB_UNKNOWN.getId();
  uint4 val = 0;
  istringstream s(attribName.substr(attribId.getName().size()));	// Strip off the base name
  s >> dec >> val;		// Decode the remaining decimal integer (starting at 1)
  if (val == 0)
    throw LowlevelError("Bad indexed attribute: " + attribId.getName());
  return attribId.getId() + (val-1);
}

/// \brief Find the attribute index, within the given element, for the given name
///
/// Run through the attributes of the element until we find the one matching the name,
/// or throw an exception otherwise.
/// \param el is the given element to search
/// \param attribName is the attribute name to search for
/// \return the matching attribute index
int4 XmlDecode::findMatchingAttribute(const Element *el,const string &attribName)

{
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i) == attribName)
      return i;
  }
  throw DecoderError("Attribute missing: " + attribName);
}

bool XmlDecode::readBool(void)

{
  const Element *el = elStack.back();
  return xml_readbool(el->getAttributeValue(attributeIndex));
}

bool XmlDecode::readBool(const AttributeId &attribId)

{
  const Element *el = elStack.back();
  if (attribId == ATTRIB_CONTENT)
    return xml_readbool(el->getContent());
  int4 index = findMatchingAttribute(el, attribId.getName());
  return xml_readbool(el->getAttributeValue(index));
}

intb XmlDecode::readSignedInteger(void)

{
  const Element *el = elStack.back();
  intb res = 0;
  istringstream s2(el->getAttributeValue(attributeIndex));
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  s2 >> res;
  return res;
}

intb XmlDecode::readSignedInteger(const AttributeId &attribId)

{
  const Element *el = elStack.back();
  intb res = 0;
  if (attribId == ATTRIB_CONTENT) {
    istringstream s(el->getContent());
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> res;
  }
  else {
    int4 index = findMatchingAttribute(el, attribId.getName());
    istringstream s(el->getAttributeValue(index));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> res;
  }
  return res;
}

intb XmlDecode::readSignedIntegerExpectString(const string &expect,intb expectval)

{
  const Element *el = elStack.back();
  const string &value( el->getAttributeValue(attributeIndex) );
  if (value == expect)
    return expectval;
  istringstream s2(value);
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  intb res = 0;
  s2 >> res;
  return res;
}

intb XmlDecode::readSignedIntegerExpectString(const AttributeId &attribId,const string &expect,intb expectval)

{
  string value = readString(attribId);
  if (value == expect)
    return expectval;
  istringstream s2(value);
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  intb res = 0;
  s2 >> res;
  return res;
}

uintb XmlDecode::readUnsignedInteger(void)

{
  const Element *el = elStack.back();
  uintb res = 0;
  istringstream s2(el->getAttributeValue(attributeIndex));
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  s2 >> res;
  return res;
}

uintb XmlDecode::readUnsignedInteger(const AttributeId &attribId)

{
  const Element *el = elStack.back();
  uintb res = 0;
  if (attribId == ATTRIB_CONTENT) {
    istringstream s(el->getContent());
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> res;
  }
  else {
    int4 index = findMatchingAttribute(el, attribId.getName());
    istringstream s(el->getAttributeValue(index));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> res;
  }
  return res;
}

string XmlDecode::readString(void)

{
  const Element *el = elStack.back();
  return el->getAttributeValue(attributeIndex);
}

string XmlDecode::readString(const AttributeId &attribId)

{
  const Element *el = elStack.back();
  if (attribId == ATTRIB_CONTENT)
    return el->getContent();
  int4 index = findMatchingAttribute(el, attribId.getName());
  return el->getAttributeValue(index);
}

AddrSpace *XmlDecode::readSpace(void)

{
  const Element *el = elStack.back();
  string nm = el->getAttributeValue(attributeIndex);
  AddrSpace *res = spcManager->getSpaceByName(nm);
  if (res == (AddrSpace *)0)
    throw DecoderError("Unknown address space name: "+nm);
  return res;
}

AddrSpace *XmlDecode::readSpace(const AttributeId &attribId)

{
  const Element *el = elStack.back();
  string nm;
  if (attribId == ATTRIB_CONTENT) {
    nm = el->getContent();
  }
  else {
    int4 index = findMatchingAttribute(el, attribId.getName());
    nm = el->getAttributeValue(index);
  }
  AddrSpace *res = spcManager->getSpaceByName(nm);
  if (res == (AddrSpace *)0)
    throw DecoderError("Unknown address space name: "+nm);
  return res;
}

void XmlEncode::openElement(const ElementId &elemId)

{
  if (elementTagIsOpen)
    outStream << '>';
  else
    elementTagIsOpen = true;
  outStream << '<' << elemId.getName();
}

void XmlEncode::closeElement(const ElementId &elemId)

{
  if (elementTagIsOpen) {
    outStream << "/>";
    elementTagIsOpen = false;
  }
  else {
    outStream << "</" << elemId.getName() << '>';
  }
}

void XmlEncode::writeBool(const AttributeId &attribId,bool val)

{
  if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
    if (elementTagIsOpen) {
      outStream << '>';
      elementTagIsOpen = false;
    }
    if (val)
      outStream << "true";
    else
      outStream << "false";
    return;
  }
  a_v_b(outStream, attribId.getName(), val);
}

void XmlEncode::writeSignedInteger(const AttributeId &attribId,intb val)

{
  if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
    if (elementTagIsOpen) {
      outStream << '>';
      elementTagIsOpen = false;
    }
    outStream << dec << val;
    return;
  }
  a_v_i(outStream, attribId.getName(), val);
}

void XmlEncode::writeUnsignedInteger(const AttributeId &attribId,uintb val)

{
  if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
    if (elementTagIsOpen) {
      outStream << '>';
      elementTagIsOpen = false;
    }
    outStream << hex << "0x" << val;
    return;
  }
  a_v_u(outStream, attribId.getName(), val);
}

void XmlEncode::writeString(const AttributeId &attribId,const string &val)

{
  if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
    if (elementTagIsOpen) {
      outStream << '>';
      elementTagIsOpen = false;
    }
    xml_escape(outStream, val.c_str());
    return;
  }
  a_v(outStream,attribId.getName(),val);
}

void XmlEncode::writeStringIndexed(const AttributeId &attribId,uint4 index,const string &val)

{
  outStream << ' ' << attribId.getName() << dec << index + 1;
  outStream << "=\"";
  xml_escape(outStream,val.c_str());
  outStream << "\"";

}

void XmlEncode::writeSpace(const AttributeId &attribId,const AddrSpace *spc)

{
  if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
    if (elementTagIsOpen) {
      outStream << '>';
      elementTagIsOpen = false;
    }
    xml_escape(outStream, spc->getName().c_str());
    return;
  }
  a_v(outStream,attribId.getName(),spc->getName());
}

/// The integer is encoded, 7-bits per byte, starting with the most significant 7-bits.
/// The integer is decode from the \e current position, and the position is advanced.
/// \param len is the number of bytes to extract
uint8 PackedDecode::readInteger(int4 len)

{
  uint8 res = 0;
  while(len > 0) {
    res <<= RAWDATA_BITSPERBYTE;
    res |= (getNextByte(curPos) & RAWDATA_MASK);
    len -= 1;
  }
  return res;
}

/// The \e current position is reset to the start of the current open element. Attributes are scanned
/// and skipped until the attribute matching the given id is found.  The \e current position is set to the
/// start of the matching attribute, in preparation for one of the read*() methods.
/// If the id is not found an exception is thrown.
/// \param attribId is the attribute id to scan for.
void PackedDecode::findMatchingAttribute(const AttributeId &attribId)

{
  curPos = startPos;
  for(;;) {
    uint1 header1 = getByte(curPos);
    if ((header1 & HEADER_MASK) != ATTRIBUTE) break;
    uint4 id = header1 & ELEMENTID_MASK;
    if ((header1 & HEADEREXTEND_MASK) != 0) {
      id <<= RAWDATA_BITSPERBYTE;
      id |= (getBytePlus1(curPos) & RAWDATA_MASK);
    }
    if (attribId.getId() == id)
      return;		// Found it
    skipAttribute();
  }
  throw DecoderError("Attribute " + attribId.getName() + " is not present");
}

/// The attribute at the \e current position is scanned enough to determine its length, and the position
/// is advanced to the following byte.
void PackedDecode::skipAttribute(void)

{
  uint1 header1 = getNextByte(curPos);	// Attribute header
  if ((header1 & HEADEREXTEND_MASK) != 0)
    getNextByte(curPos);		// Extra byte for extended id
  uint1 typeByte = getNextByte(curPos);	// Type (and length) byte
  uint1 attribType = typeByte >> TYPECODE_SHIFT;
  if (attribType == TYPECODE_BOOLEAN || attribType == TYPECODE_SPECIALSPACE)
    return;				// has no additional data
  uint4 length = readLengthCode(typeByte);	// Length of data in bytes
  if (attribType == TYPECODE_STRING) {
    length = readInteger(length);	// Read length field to get final length of string
  }
  advancePosition(curPos, length);	// Skip -length- data
}

/// This assumes the header and \b type \b byte have been read.  Decode type and length info and finish
/// skipping over the attribute so that the next call to getNextAttributeId() is on cut.
/// \param typeByte is the previously scanned type byte
void PackedDecode::skipAttributeRemaining(uint1 typeByte)

{
  uint1 attribType = typeByte >> TYPECODE_SHIFT;
  if (attribType == TYPECODE_BOOLEAN || attribType == TYPECODE_SPECIALSPACE)
    return;				// has no additional data
  uint4 length = readLengthCode(typeByte);	// Length of data in bytes
  if (attribType == TYPECODE_STRING) {
    length = readInteger(length);	// Read length field to get final length of string
  }
  advancePosition(curPos, length);	// Skip -length- data
}

PackedDecode::~PackedDecode(void)

{
  list<ByteChunk>::const_iterator iter;
  for(iter=inStream.begin();iter!=inStream.end();++iter) {
    delete [] (*iter).start;
  }
}

void PackedDecode::ingestStream(istream &s)

{
  int4 gcount = 0;
  while(s.peek() > 0) {
    uint1 *buf = new uint1[BUFFER_SIZE + 1];
    inStream.emplace_back(buf,buf+BUFFER_SIZE);
    s.get((char *)buf,BUFFER_SIZE+1,'\0');
    gcount = s.gcount();
  }
  endPos.seqIter = inStream.begin();
  if (endPos.seqIter != inStream.end()) {
    endPos.current = (*endPos.seqIter).start;
    endPos.end = (*endPos.seqIter).end;
    // Make sure there is at least one character after ingested buffer
    if (gcount == BUFFER_SIZE) {
      // Last buffer was entirely filled
      uint1 *endbuf = new uint1[1];		// Add one more buffer
      inStream.emplace_back(endbuf,endbuf + 1);
      gcount = 0;
    }
    uint1 *buf = inStream.back().start;
    buf[gcount] = ELEMENT_END;
  }
}

uint4 PackedDecode::peekElement(void)

{
  uint1 header1 = getByte(endPos);
  if ((header1 & HEADER_MASK) != ELEMENT_START)
    return 0;
  uint4 id = header1 & ELEMENTID_MASK;
  if ((header1 & HEADEREXTEND_MASK) != 0) {
    id <<= RAWDATA_BITSPERBYTE;
    id |= (getBytePlus1(endPos) & RAWDATA_MASK);
  }
  return id;
}

uint4 PackedDecode::openElement(void)

{
  uint1 header1 = getByte(endPos);
  if ((header1 & HEADER_MASK) != ELEMENT_START)
    return 0;
  getNextByte(endPos);
  uint4 id = header1 & ELEMENTID_MASK;
  if ((header1 & HEADEREXTEND_MASK) != 0) {
    id <<= RAWDATA_BITSPERBYTE;
    id |= (getNextByte(endPos) & RAWDATA_MASK);
  }
  startPos = endPos;
  curPos = endPos;
  header1 = getByte(curPos);
  while((header1 & HEADER_MASK) == ATTRIBUTE) {
    skipAttribute();
    header1 = getByte(curPos);
  }
  endPos = curPos;
  curPos = startPos;
  attributeRead = true;		// "Last attribute was read" is vacuously true
  return id;
}

uint4 PackedDecode::openElement(const ElementId &elemId)

{
  uint4 id = openElement();
  if (id != elemId.getId()) {
    if (id == 0)
      throw DecoderError("Expecting <" + elemId.getName() + "> but did not scan an element");
    throw DecoderError("Expecting <" + elemId.getName() + "> but id did not match");
  }
  return id;
}

void PackedDecode::closeElement(uint4 id)

{
  uint1 header1 = getNextByte(endPos);
  if ((header1 & HEADER_MASK) != ELEMENT_END)
    throw DecoderError("Expecting element close");
  uint4 closeId = header1 & ELEMENTID_MASK;
  if ((header1 & HEADEREXTEND_MASK) != 0) {
    closeId <<= RAWDATA_BITSPERBYTE;
    closeId |= (getNextByte(endPos) & RAWDATA_MASK);
  }
  if (id != closeId)
    throw DecoderError("Did not see expected closing element");
}

void PackedDecode::closeElementSkipping(uint4 id)

{
  vector<uint4> idstack;
  idstack.push_back(id);
  do {
    uint1 header1 = getByte(endPos) & HEADER_MASK;
    if (header1 == ELEMENT_END) {
      closeElement(idstack.back());
      idstack.pop_back();
    }
    else if (header1 == ELEMENT_START) {
      idstack.push_back(openElement());
    }
    else
      throw DecoderError("Corrupt stream");
  } while(!idstack.empty());
}

void PackedDecode::rewindAttributes(void)

{
  curPos = startPos;
  attributeRead = true;
}

uint4 PackedDecode::getNextAttributeId(void)

{
  if (!attributeRead)
    skipAttribute();
  uint1 header1 = getByte(curPos);
  if ((header1 & HEADER_MASK) != ATTRIBUTE)
    return 0;
  uint4 id = header1 & ELEMENTID_MASK;
  if ((header1 & HEADEREXTEND_MASK) != 0) {
    id <<= RAWDATA_BITSPERBYTE;
    id |= (getBytePlus1(curPos) & RAWDATA_MASK);
  }
  attributeRead = false;
  return id;
}

uint4 PackedDecode::getIndexedAttributeId(const AttributeId &attribId)

{
  return ATTRIB_UNKNOWN.getId();	// PackedDecode never needs to reinterpret an attribute
}

bool PackedDecode::readBool(void)

{
  uint1 header1 = getNextByte(curPos);
  if ((header1 & HEADEREXTEND_MASK)!=0)
    getNextByte(curPos);
  uint1 typeByte = getNextByte(curPos);
  attributeRead = true;
  if ((typeByte >> TYPECODE_SHIFT) != TYPECODE_BOOLEAN)
    throw DecoderError("Expecting boolean attribute");
  return ((typeByte & LENGTHCODE_MASK) != 0);
}

bool PackedDecode::readBool(const AttributeId &attribId)

{
  findMatchingAttribute(attribId);
  bool res = readBool();
  curPos = startPos;
  return res;
}

intb PackedDecode::readSignedInteger(void)

{
  uint1 header1 = getNextByte(curPos);
  if ((header1 & HEADEREXTEND_MASK)!=0)
    getNextByte(curPos);
  uint1 typeByte = getNextByte(curPos);
  uint4 typeCode = typeByte >> TYPECODE_SHIFT;
  intb res;
  if (typeCode == TYPECODE_SIGNEDINT_POSITIVE) {
    res = readInteger(readLengthCode(typeByte));
  }
  else if (typeCode == TYPECODE_SIGNEDINT_NEGATIVE) {
    res = readInteger(readLengthCode(typeByte));
    res = -res;
  }
  else {
    skipAttributeRemaining(typeByte);
    attributeRead = true;
    throw DecoderError("Expecting signed integer attribute");
  }
  attributeRead = true;
  return res;
}

intb PackedDecode::readSignedInteger(const AttributeId &attribId)

{
  findMatchingAttribute(attribId);
  intb res = readSignedInteger();
  curPos = startPos;
  return res;
}

intb PackedDecode::readSignedIntegerExpectString(const string &expect,intb expectval)

{
  intb res;
  Position tmpPos = curPos;
  uint1 header1 = getNextByte(tmpPos);
  if ((header1 & HEADEREXTEND_MASK)!=0)
    getNextByte(tmpPos);
  uint1 typeByte = getNextByte(tmpPos);
  uint4 typeCode = typeByte >> TYPECODE_SHIFT;
  if (typeCode == TYPECODE_STRING) {
    string val = readString();
    if (val != expect) {
      ostringstream s;
      s << "Expecting string \"" << expect << "\" but read \"" << val << "\"";
      throw DecoderError(s.str());
    }
    res = expectval;
  }
  else {
    res = readSignedInteger();
  }
  return res;
}

intb PackedDecode::readSignedIntegerExpectString(const AttributeId &attribId,const string &expect,intb expectval)

{
  findMatchingAttribute(attribId);
  intb res = readSignedIntegerExpectString(expect,expectval);
  curPos = startPos;
  return res;
}

uintb PackedDecode::readUnsignedInteger(void)

{
  uint1 header1 = getNextByte(curPos);
  if ((header1 & HEADEREXTEND_MASK)!=0)
    getNextByte(curPos);
  uint1 typeByte = getNextByte(curPos);
  uint4 typeCode = typeByte >> TYPECODE_SHIFT;
  uintb res;
  if (typeCode == TYPECODE_UNSIGNEDINT) {
    res = readInteger(readLengthCode(typeByte));
  }
  else {
    skipAttributeRemaining(typeByte);
    attributeRead = true;
    throw DecoderError("Expecting unsigned integer attribute");
  }
  attributeRead = true;
  return res;
}

uintb PackedDecode::readUnsignedInteger(const AttributeId &attribId)

{
  findMatchingAttribute(attribId);
  uintb res = readUnsignedInteger();
  curPos = startPos;
  return res;
}

string PackedDecode::readString(void)

{
  uint1 header1 = getNextByte(curPos);
  if ((header1 & HEADEREXTEND_MASK)!=0)
    getNextByte(curPos);
  uint1 typeByte = getNextByte(curPos);
  uint4 typeCode = typeByte >> TYPECODE_SHIFT;
  if (typeCode != TYPECODE_STRING) {
    skipAttributeRemaining(typeByte);
    attributeRead = true;
    throw DecoderError("Expecting string attribute");
  }
  int4 length = readLengthCode(typeByte);
  length = readInteger(length);

  attributeRead = true;
  int4 curLen = curPos.end - curPos.current;
  if (curLen >= length) {
    string res((const char *)curPos.current,length);
    advancePosition(curPos, length);
    return res;
  }
  string res((const char *)curPos.current,curLen);
  length -= curLen;
  advancePosition(curPos, curLen);
  while(length > 0) {
    curLen = curPos.end - curPos.current;
    if (curLen > length)
      curLen = length;
    res.append((const char *)curPos.current,curLen);
    length -= curLen;
    advancePosition(curPos, curLen);
  }
  return res;
}

string PackedDecode::readString(const AttributeId &attribId)

{
  findMatchingAttribute(attribId);
  string res = readString();
  curPos = startPos;
  return res;
}

AddrSpace *PackedDecode::readSpace(void)

{
  uint1 header1 = getNextByte(curPos);
  if ((header1 & HEADEREXTEND_MASK)!=0)
    getNextByte(curPos);
  uint1 typeByte = getNextByte(curPos);
  uint4 typeCode = typeByte >> TYPECODE_SHIFT;
  int4 res;
  AddrSpace *spc;
  if (typeCode == TYPECODE_ADDRESSSPACE) {
    res = readInteger(readLengthCode(typeByte));
    spc = spcManager->getSpace(res);
    if (spc == (AddrSpace *)0)
      throw DecoderError("Unknown address space index");
  }
  else if (typeCode == TYPECODE_SPECIALSPACE) {
    uint4 specialCode = readLengthCode(typeByte);
    if (specialCode == SPECIALSPACE_STACK)
      spc = spcManager->getStackSpace();
    else if (specialCode == SPECIALSPACE_JOIN) {
      spc = spcManager->getJoinSpace();
    }
    else {
      throw DecoderError("Cannot marshal special address space");
    }
  }
  else {
    skipAttributeRemaining(typeByte);
    attributeRead = true;
    throw DecoderError("Expecting space attribute");
  }
  attributeRead = true;
  return spc;
}

AddrSpace *PackedDecode::readSpace(const AttributeId &attribId)

{
  findMatchingAttribute(attribId);
  AddrSpace *res = readSpace();
  curPos = startPos;
  return res;
}

/// The value is either an unsigned integer, an address space index, or (the absolute value of) a signed integer.
/// A type header is passed in with the particular type code for the value already filled in.
/// This method then fills in the length code, outputs the full type header and the encoded bytes of the integer.
/// \param typeByte is the type header
/// \param val is the integer value
void PackedEncode::writeInteger(uint1 typeByte,uint8 val)

{
  uint1 lenCode;
  int4 sa;
  if (val == 0) {
    lenCode = 0;
    sa = -1;
  }
  if (val < 0x800000000) {
    if (val < 0x200000) {
      if (val < 0x80) {
	lenCode = 1;		// 7-bits
	sa = 0;
      }
      else if (val < 0x4000) {
	lenCode = 2;		// 14-bits
	sa = RAWDATA_BITSPERBYTE;
      }
      else {
	lenCode = 3;		// 21-bits
	sa = 2*RAWDATA_BITSPERBYTE;
      }
    }
    else if (val < 0x10000000) {
      lenCode = 4;		// 28-bits
      sa = 3*RAWDATA_BITSPERBYTE;
    }
    else {
      lenCode = 5;		// 35-bits
      sa = 4*RAWDATA_BITSPERBYTE;
    }
  }
  else if (val < 0x2000000000000) {
    if (val < 0x40000000000) {
      lenCode = 6;
      sa = 5*RAWDATA_BITSPERBYTE;
    }
    else {
      lenCode = 7;
      sa = 6*RAWDATA_BITSPERBYTE;
    }
  }
  else {
    if (val < 0x100000000000000) {
      lenCode = 8;
      sa = 7*RAWDATA_BITSPERBYTE;
    }
    else if (val < 0x8000000000000000) {
      lenCode = 9;
      sa = 8*RAWDATA_BITSPERBYTE;
    }
    else {
      lenCode = 10;
      sa = 9*RAWDATA_BITSPERBYTE;
    }
  }
  typeByte |= lenCode;
  outStream.put(typeByte);
  for(;sa >= 0;sa -= RAWDATA_BITSPERBYTE) {
    uint1 piece = (val >> sa) & RAWDATA_MASK;
    piece |= RAWDATA_MARKER;
    outStream.put(piece);
  }
}

void PackedEncode::openElement(const ElementId &elemId)

{
  writeHeader(ELEMENT_START, elemId.getId());
}

void PackedEncode::closeElement(const ElementId &elemId)

{
  writeHeader(ELEMENT_END, elemId.getId());
}

void PackedEncode::writeBool(const AttributeId &attribId,bool val)

{
  writeHeader(ATTRIBUTE, attribId.getId());
  uint1 typeByte = val ? ((TYPECODE_BOOLEAN << TYPECODE_SHIFT) | 1) : (TYPECODE_BOOLEAN << TYPECODE_SHIFT);
  outStream.put(typeByte);
}

void PackedEncode::writeSignedInteger(const AttributeId &attribId,intb val)

{
  writeHeader(ATTRIBUTE, attribId.getId());
  uint1 typeByte;
  uint8 num;
  if (val < 0) {
    typeByte = (TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT);
    num = -val;
  }
  else {
    typeByte = (TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT);
    num = val;
  }
  writeInteger(typeByte, num);
}

void PackedEncode::writeUnsignedInteger(const AttributeId &attribId,uintb val)

{
  writeHeader(ATTRIBUTE, attribId.getId());
  writeInteger((TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT),val);
}

void PackedEncode::writeString(const AttributeId &attribId,const string &val)

{
  uint8 length = val.length();
  writeHeader(ATTRIBUTE, attribId.getId());
  writeInteger((TYPECODE_STRING << TYPECODE_SHIFT), length);
  outStream.write(val.c_str(), length);
}

void PackedEncode::writeStringIndexed(const AttributeId &attribId,uint4 index,const string &val)

{
  uint8 length = val.length();
  writeHeader(ATTRIBUTE, attribId.getId() + index);
  writeInteger((TYPECODE_STRING << TYPECODE_SHIFT), length);
  outStream.write(val.c_str(), length);
}

void PackedEncode::writeSpace(const AttributeId &attribId,const AddrSpace *spc)

{
  writeHeader(ATTRIBUTE, attribId.getId());
  switch(spc->getType()) {
    case IPTR_FSPEC:
      outStream.put((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_FSPEC);
      break;
    case IPTR_IOP:
      outStream.put((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_IOP);
      break;
    case IPTR_JOIN:
      outStream.put((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_JOIN);
      break;
   case IPTR_SPACEBASE:
     if (spc->isFormalStackSpace())
       outStream.put((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK);
     else
       outStream.put((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_SPACEBASE);	// A secondary register offset space
     break;
   default:
    uint8 spcId = spc->getIndex();
    writeInteger((TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT), spcId);
    break;
  }
}

// Common attributes.  Attributes with multiple uses
AttributeId ATTRIB_CONTENT = AttributeId("XMLcontent",1);
AttributeId ATTRIB_ALIGN = AttributeId("align",2);
AttributeId ATTRIB_BIGENDIAN = AttributeId("bigendian",3);
AttributeId ATTRIB_CONSTRUCTOR = AttributeId("constructor",4);
AttributeId ATTRIB_DESTRUCTOR = AttributeId("destructor",5);
AttributeId ATTRIB_EXTRAPOP = AttributeId("extrapop",6);
AttributeId ATTRIB_FORMAT = AttributeId("format",7);
AttributeId ATTRIB_HIDDENRETPARM = AttributeId("hiddenretparm",8);
AttributeId ATTRIB_ID = AttributeId("id",9);
AttributeId ATTRIB_INDEX = AttributeId("index",10);
AttributeId ATTRIB_INDIRECTSTORAGE = AttributeId("indirectstorage",11);
AttributeId ATTRIB_METATYPE = AttributeId("metatype",12);
AttributeId ATTRIB_MODEL = AttributeId("model",13);
AttributeId ATTRIB_NAME = AttributeId("name",14);
AttributeId ATTRIB_NAMELOCK = AttributeId("namelock",15);
AttributeId ATTRIB_OFFSET = AttributeId("offset",16);
AttributeId ATTRIB_READONLY = AttributeId("readonly",17);
AttributeId ATTRIB_REF = AttributeId("ref",18);
AttributeId ATTRIB_SIZE = AttributeId("size",19);
AttributeId ATTRIB_SPACE = AttributeId("space",20);
AttributeId ATTRIB_THISPTR = AttributeId("thisptr",21);
AttributeId ATTRIB_TYPE = AttributeId("type",22);
AttributeId ATTRIB_TYPELOCK = AttributeId("typelock",23);
AttributeId ATTRIB_VAL = AttributeId("val",24);
AttributeId ATTRIB_VALUE = AttributeId("value",25);
AttributeId ATTRIB_WORDSIZE = AttributeId("wordsize",26);
AttributeId ATTRIB_STORAGE = AttributeId("storage",149);

AttributeId ATTRIB_UNKNOWN = AttributeId("XMLunknown",150); // Number serves as next open index

ElementId ELEM_DATA = ElementId("data",1);
ElementId ELEM_INPUT = ElementId("input",2);
ElementId ELEM_OFF = ElementId("off",3);
ElementId ELEM_OUTPUT = ElementId("output",4);
ElementId ELEM_RETURNADDRESS = ElementId("returnaddress",5);
ElementId ELEM_SYMBOL = ElementId("symbol",6);
ElementId ELEM_TARGET = ElementId("target",7);
ElementId ELEM_VAL = ElementId("val",8);
ElementId ELEM_VALUE = ElementId("value",9);
ElementId ELEM_VOID = ElementId("void",10);

ElementId ELEM_UNKNOWN = ElementId("XMLunknown",284); // Number serves as next open index

} // End namespace ghidra

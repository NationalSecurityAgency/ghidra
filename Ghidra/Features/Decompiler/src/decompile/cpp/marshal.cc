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

unordered_map<string,uint4> AttributeId::lookupAttributeId;

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
    throw XmlError(attrib->name + " attribute registered more than once");
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
    throw XmlError(elem->name + " element registered more than once");
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

void XmlDecode::clear(void)

{
  if (document != (Document *)0)
    delete document;
  document = (Document *)0;
  rootElement = (const Element *)0;
  attributeIndex = -1;
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
      throw XmlError("Expecting <" + elemId.getName() + "> but reached end of document");
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
      throw XmlError("Expecting <" + elemId.getName() + "> but no remaining children in current element");
  }
  if (el->getName() != elemId.getName())
    throw XmlError("Expecting <" + elemId.getName() + "> but got <" + el->getName() + ">");
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
    throw XmlError("Closing element <" + el->getName() + "> with additional children");
  if (ElementId::find(el->getName()) != id)
    throw XmlError("Trying to close <" + el->getName() + "> with mismatching id");
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
    throw XmlError("Trying to close <" + el->getName() + "> with mismatching id");
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
  throw XmlError("Attribute missing: " + attribName);
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
    throw XmlError("Unknown address space name: "+nm);
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
    throw XmlError("Unknown address space name: "+nm);
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

AttributeId ATTRIB_UNKNOWN = AttributeId("XMLunknown",144); // Number serves as next open index

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

ElementId ELEM_UNKNOWN = ElementId("XMLunknown",218); // Number serves as next open index

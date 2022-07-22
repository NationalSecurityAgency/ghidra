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
#ifndef __CPUI_MARSHAL__
#define __CPUI_MARSHAL__

#include "xml.hh"
#include <unordered_map>

using namespace std;

/// \brief An annotation for a data element to being transferred to/from a stream
///
/// This class parallels the XML concept of an \b attribute on an element. An AttributeId describes
/// a particular piece of data associated with an ElementId.  The defining characteristic of the AttributeId is
/// its name.  Internally this name is associated with an integer id.  The name (and id) uniquely determine
/// the data being labeled, within the context of a specific ElementId.  Within this context, an AttributeId labels either
///   - An unsigned integer
///   - A signed integer
///   - A boolean value
///   - A string
///
/// The same AttributeId can be used to label a different type of data when associated with a different ElementId.
class AttributeId {
  static unordered_map<string,uint4> lookupAttributeId;		///< A map of AttributeId names to their associated id
  static vector<AttributeId *> &getList(void);			///< Retrieve the list of static AttributeId
  string name;			///< The name of the attribute
  uint4 id;			///< The (internal) id of the attribute
public:
  AttributeId(const string &nm,uint4 i);	///< Construct given a name and id
  const string &getName(void) const { return name; }				///< Get the attribute's name
  uint4 getId(void) const { return id; }					///< Get the attribute's id
  bool operator==(const AttributeId &op2) const { return (id == op2.id); }	///< Test equality with another AttributeId
  static uint4 find(const string &nm);			///< Find the id associated with a specific attribute name
  static void initialize(void);				///< Populate a hashtable with all AttributeId objects
  friend bool operator==(uint4 id,const AttributeId &op2) { return (id == op2.id); }	///< Test equality of a raw integer id with an AttributeId
  friend bool operator==(const AttributeId &op1,uint4 id) { return (op1.id == id); }	///< Test equality of an AttributeId with a raw integer id
};

/// \brief An annotation for a specific collection of hierarchical data
///
/// This class parallels the XML concept of an \b element.  An ElementId describes a collection of data, where each
/// piece is annotated by a specific AttributeId.  In addition, each ElementId can contain zero or more \e child
/// ElementId objects, forming a hierarchy of annotated data.  Each ElementId has a name, which is unique at least
/// within the context of its parent ElementId. Internally this name is associated with an integer id. A special
/// AttributeId ATTRIB_CONTENT is used to label the XML element's text content, which is traditionally not labeled
/// as an attribute.
class ElementId {
  static unordered_map<string,uint4> lookupElementId;	///< A map of ElementId names to their associated id
  static vector<ElementId *> &getList(void);		///< Retrieve the list of static ElementId
  string name;			///< The name of the element
  uint4 id;			///< The (internal) id of the attribute
public:
  ElementId(const string &nm,uint4 i);		///< Construct given a name and id
  const string &getName(void) const { return name; }				///< Get the element's name
  uint4 getId(void) const { return id; }					///< Get the element's id
  bool operator==(const ElementId &op2) const { return (id == op2.id); }	///< Test equality with another ElementId
  static uint4 find(const string &nm);			///< Find the id associated with a specific element name
  static void initialize(void);				///< Populate a hashtable with all ElementId objects
  friend bool operator==(uint4 id,const ElementId &op2) { return (id == op2.id); }	///< Test equality of a raw integer id with an ElementId
  friend bool operator==(const ElementId &op1,uint4 id) { return (op1.id == id); }	///< Test equality of an ElementId with a raw integer id
  friend bool operator!=(uint4 id,const ElementId &op2) { return (id != op2.id); }	///< Test inequality of a raw integer id with an ElementId
  friend bool operator!=(const ElementId &op1,uint4 id) { return (op1.id != id); }	///< Test inequality of an ElementId with a raw integer id
};

class AddrSpace;
class AddrSpaceManager;

/// \brief A class for reading structured data from a stream
///
/// All data is loosely structured as with an XML document.  A document contains a nested set
/// of \b elements, with labels corresponding to the ElementId class. A single element can hold
/// zero or more attributes and zero or more child elements.  An attribute holds a primitive
/// data element (bool, integer, string) and is labeled by an AttributeId. The document is traversed
/// using a sequence of openElement() and closeElement() calls, intermixed with read*() calls to extract
/// the data. The elements are traversed in a depth first order.  Attributes within an element can
/// be traversed in order using repeated calls to the getNextAttributeId() method, followed by a calls to
/// one of the read*(void) methods to extract the data.  Alternately a read*(AttributeId) call can be used
/// to extract data for an attribute known to be in the element.  There is a special content attribute
/// whose data can be extracted using a read*(AttributeId) call that is passed the special ATTRIB_CONTENT id.
/// This attribute will not be traversed by getNextAttribute().
class Decoder {
protected:
  const AddrSpaceManager *spcManager;		///< Manager for decoding address space attributes
public:
  Decoder(const AddrSpaceManager *spc) { spcManager = spc; }	///< Base constructor

  const AddrSpaceManager *getAddrSpaceManager(void) const { return spcManager; }	///< Get the manager used for address space decoding
  virtual ~Decoder(void) {}	///< Destructor

  /// \brief Clear any current decoding state
  ///
  /// Allows the same decoder to be reused. Object is ready for new call to ingestStream.
  virtual void clear(void)=0;

  /// \brief Prepare to decode a given stream
  ///
  /// Called once before any decoding.  Currently this is assumed to make an internal copy of the stream data,
  /// i.e. the input stream is cleared before any decoding takes place.
  /// \param s is the given input stream to be decode
  /// \return \b true if the stream was fully ingested
  virtual void ingestStream(istream &s)=0;

  /// \brief Peek at the next child element of the current parent, without traversing in (opening) it.
  ///
  /// The element id is returned, which can be compared to ElementId labels.
  /// If there are no remaining child elements to traverse, 0 is returned.
  /// \return the element id or 0
  virtual uint4 peekElement(void)=0;

  /// \brief Open (traverse into) the next child element of the current parent.
  ///
  /// The child becomes the current parent.  The list of attributes is initialized for use with getNextAttributeId.
  /// \return the id of the child element
  virtual uint4 openElement(void)=0;

  /// \brief Open (traverse into) the next child element, which must be of a specific type
  ///
  /// The child becomes the current parent, and its attributes are initialized for use with getNextAttributeId.
  /// The child must match the given element id or an exception is thrown.
  /// \param elemId is the given element id to match
  /// \return the id of the child element
  virtual uint4 openElement(const ElementId &elemId)=0;

  /// \brief Close the current element
  ///
  /// The data for the current element is considered fully processed.  If the element has additional children,
  /// an exception is thrown.  The stream must indicate the end of the element in some way.
  /// \param id is the id of the element to close (which must be the current element)
  virtual void closeElement(uint4 id)=0;

  /// \brief Close the current element, skipping any child elements that have not yet been parsed
  ///
  /// This closes the given element, which must be current.  If there are child elements that have not been
  /// parsed, this is not considered an error, and they are skipped over in the parse.
  /// \param id is the id of the element to close (which must be the current element)
  virtual void closeElementSkipping(uint4 id)=0;

  /// \brief Get the next attribute id for the current element
  ///
  /// Attributes are automatically set up for traversal using this method, when the element is opened.
  /// If all attributes have been traversed (or there are no attributes), 0 is returned.
  /// \return the id of the next attribute or 0
  virtual uint4 getNextAttributeId(void)=0;

  /// \brief Reset attribute traversal for the current element
  ///
  /// Attributes for a single element can be traversed more than once using the getNextAttributeId method.
  virtual void rewindAttributes(void)=0;

  /// \brief Parse the current attribute as a boolean value
  ///
  /// The last attribute, as returned by getNextAttributeId, is treated as a boolean, and its value is returned.
  /// \return the boolean value associated with the current attribute.
  virtual bool readBool(void)=0;

  /// \brief Find and parse a specific attribute in the current element as a boolean value
  ///
  /// The set of attributes for the current element is searched for a match to the given attribute id.
  /// This attribute is then parsed as a boolean and its value returned.
  /// If there is no attribute matching the id, an exception is thrown.
  /// Parsing via getNextAttributeId is reset.
  /// \param attribId is the specific attribute id to match
  /// \return the boolean value
  virtual bool readBool(const AttributeId &attribId)=0;

  /// \brief Parse the current attribute as a signed integer value
  ///
  /// The last attribute, as returned by getNextAttributeId, is treated as a signed integer, and its value is returned.
  /// \return the signed integer value associated with the current attribute.
  virtual intb readSignedInteger(void)=0;

  /// \brief Find and parse a specific attribute in the current element as a signed integer
  ///
  /// The set of attributes for the current element is searched for a match to the given attribute id.
  /// This attribute is then parsed as a signed integer and its value returned.
  /// If there is no attribute matching the id, an exception is thrown.
  /// Parsing via getNextAttributeId is reset.
  /// \param attribId is the specific attribute id to match
  /// \return the signed integer value
  virtual intb readSignedInteger(const AttributeId &attribId)=0;

  /// \brief Parse the current attribute as an unsigned integer value
  ///
  /// The last attribute, as returned by getNextAttributeId, is treated as an unsigned integer, and its value is returned.
  /// \return the unsigned integer value associated with the current attribute.
  virtual uintb readUnsignedInteger(void)=0;

  /// \brief Find and parse a specific attribute in the current element as an unsigned integer
  ///
  /// The set of attributes for the current element is searched for a match to the given attribute id.
  /// This attribute is then parsed as an unsigned integer and its value returned.
  /// If there is no attribute matching the id, an exception is thrown.
  /// Parsing via getNextAttributeId is reset.
  /// \param attribId is the specific attribute id to match
  /// \return the unsigned integer value
  virtual uintb readUnsignedInteger(const AttributeId &attribId)=0;

  /// \brief Parse the current attribute as a string
  ///
  /// The last attribute, as returned by getNextAttributeId, is returned as a string.
  /// \return the string associated with the current attribute.
  virtual string readString(void)=0;

  /// \brief Find the specific attribute in the current element and return it as a string
  ///
  /// The set of attributes for the current element is searched for a match to the given attribute id.
  /// This attribute is then returned as a string.  If there is no attribute matching the id, and exception is thrown.
  /// Parse via getNextAttributeId is reset.
  /// \param attribId is the specific attribute id to match
  /// \return the string associated with the attribute
  virtual string readString(const AttributeId &attribId)=0;

  /// \brief Parse the current attribute as an address space
  ///
  /// The last attribute, as returned by getNextAttributeId, is returned as an address space.
  /// \return the address space associated with the current attribute.
  virtual AddrSpace *readSpace(void)=0;

  /// \brief Find the specific attribute in the current element and return it as an address space
  ///
  /// Search attributes from the current element for a match to the given attribute id.
  /// Return this attribute as an address space. If there is no attribute matching the id, an exception is thrown.
  /// Parse via getNextAttributeId is reset.
  /// \param attribId is the specific attribute id to match
  /// \return the address space associated with the attribute
  virtual AddrSpace *readSpace(const AttributeId &attribId)=0;

  /// \brief Skip parsing of the next element
  ///
  /// The element skipped is the one that would be opened by the next call to openElement.
  void skipElement(void) {
    uint4 elemId = openElement();
    closeElementSkipping(elemId);
  }
};

/// \brief A class for writing structured data to a stream
///
/// The resulting encoded data is structured similarly to an XML document. The document contains a nested set
/// of \b elements, with labels corresponding to the ElementId class. A single element can hold
/// zero or more attributes and zero or more child elements.  An \b attribute holds a primitive
/// data element (bool, integer, string) and is labeled by an AttributeId. The document is written
/// using a sequence of openElement() and closeElement() calls, intermixed with write*() calls to encode
/// the data primitives.  All primitives written using a write*() call are associated with current open element,
/// and all write*() calls for one element must come before opening any child element.
/// The traditional XML element text content can be written using the special ATTRIB_CONTENT AttributeId, which
/// must be the last write*() call associated with the specific element.
class Encoder {
public:
  virtual ~Encoder(void) {}		///< Destructor

  /// \brief Clear any state associated with the encoder
  ///
  /// The encoder should be ready to write a new document after this call.
  virtual void clear(void)=0;

  /// \brief Begin a new element in the encoding
  ///
  /// The element will have the given ElementId annotation and becomes the \e current element.
  /// \param elemId is the given ElementId annotation
  virtual void openElement(const ElementId &elemId)=0;

  /// \brief End the current element in the encoding
  ///
  /// The current element must match the given annotation or an exception is thrown.
  /// \param elemId is the given (expected) annotation for the current element
  virtual void closeElement(const ElementId &elemId)=0;

  /// \brief Write an annotated boolean value into the encoding
  ///
  /// The boolean data is associated with the given AttributeId annotation and the current open element.
  /// \param attribId is the given AttributeId annotation
  /// \param val is boolean value to encode
  virtual void writeBool(const AttributeId &attribId,bool val)=0;

  /// \brief Write an annotated signed integer value into the encoding
  ///
  /// The integer is associated with the given AttributeId annotation and the current open element.
  /// \param attribId is the given AttributeId annotation
  /// \param val is the signed integer value to encode
  virtual void writeSignedInteger(const AttributeId &attribId,intb val)=0;

  /// \brief Write an annotated unsigned integer value into the encoding
  ///
  /// The integer is associated with the given AttributeId annotation and the current open element.
  /// \param attribId is the given AttributeId annotation
  /// \param val is the unsigned integer value to encode
  virtual void writeUnsignedInteger(const AttributeId &attribId,uintb val)=0;

  /// \brief Write an annotated string into the encoding
  ///
  /// The string is associated with the given AttributeId annotation and the current open element.
  /// \param attribId is the given AttributeId annotation
  /// \param val is the string to encode
  virtual void writeString(const AttributeId &attribId,const string &val)=0;

  /// \brief Write an address space reference into the encoding
  ///
  /// The address space is associated with the given AttributeId annotation and the current open element.
  /// \param attribId is the given AttributeId annotation
  /// \param spc is the address space to encode
  virtual void writeSpace(const AttributeId &attribId,const AddrSpace *spc)=0;
};

/// \brief An XML based decoder
///
/// The underlying transfer encoding is an XML document.  The decoder can either be initialized with an
/// existing Element as the root of the data to transfer, or the ingestStream() method can be invoked
/// to read the XML document from an input stream, in which case the decoder manages the Document object.
class XmlDecode : public Decoder {
  Document *document;				///< An ingested XML document, owned by \b this decoder
  const Element *rootElement;			///< The root XML element to be decoded
  vector<const Element *> elStack;		///< Stack of currently \e open elements
  vector<List::const_iterator> iterStack;	///< Index of next child for each \e open element
  int4 attributeIndex;				///< Position of \e current attribute to parse (in \e current element)
  int4 findMatchingAttribute(const Element *el,const string &attribName);
public:
  XmlDecode(const AddrSpaceManager *spc,const Element *root) : Decoder(spc) {
    document = (Document *)0; rootElement = root; attributeIndex = -1; }	///< Constructor with preparsed root
  XmlDecode(const AddrSpaceManager *spc) : Decoder(spc) {
    document = (Document *)0; rootElement = (const Element *)0; attributeIndex = -1; }	///< Constructor for use with ingestStream
  virtual ~XmlDecode(void);
  virtual void clear(void);
  virtual void ingestStream(istream &s);
  virtual uint4 peekElement(void);
  virtual uint4 openElement(void);
  virtual uint4 openElement(const ElementId &elemId);
  virtual void closeElement(uint4 id);
  virtual void closeElementSkipping(uint4 id);
  virtual void rewindAttributes(void);
  virtual uint4 getNextAttributeId(void);
  virtual bool readBool(void);
  virtual bool readBool(const AttributeId &attribId);
  virtual intb readSignedInteger(void);
  virtual intb readSignedInteger(const AttributeId &attribId);
  virtual uintb readUnsignedInteger(void);
  virtual uintb readUnsignedInteger(const AttributeId &attribId);
  virtual string readString(void);
  virtual string readString(const AttributeId &attribId);
  virtual AddrSpace *readSpace(void);
  virtual AddrSpace *readSpace(const AttributeId &attribId);
};

/// \brief An XML based encoder
///
/// The underlying transfer encoding is an XML document.  The encoder is initialized with a stream which will
/// receive the XML document as calls are made on the encoder.
class XmlEncode : public Encoder {
  friend class XmlDecode;
  ostream &outStream;			///< The stream receiving the encoded data
  bool elementTagIsOpen;		///< If \b true, new attributes can be written to the current element
public:
  XmlEncode(ostream &s) : outStream(s) { elementTagIsOpen = false; } ///< Construct from a stream
  virtual void clear(void) { elementTagIsOpen = false; }
  virtual void openElement(const ElementId &elemId);
  virtual void closeElement(const ElementId &elemId);
  virtual void writeBool(const AttributeId &attribId,bool val);
  virtual void writeSignedInteger(const AttributeId &attribId,intb val);
  virtual void writeUnsignedInteger(const AttributeId &attribId,uintb val);
  virtual void writeString(const AttributeId &attribId,const string &val);
  virtual void writeSpace(const AttributeId &attribId,const AddrSpace *spc);
};

extern ElementId ELEM_UNKNOWN;		///< Special element to represent an element with an unrecognized name
extern AttributeId ATTRIB_UNKNOWN;	///< Special attribute  to represent an attribute with an unrecognized name
extern AttributeId ATTRIB_CONTENT;	///< Special attribute for XML text content of an element

/// The name is looked up in the global list of all attributes.  If the attribute is not in the list, a special
/// placeholder attribute, ATTRIB_UNKNOWN, is returned as a placeholder for attributes with unrecognized names.
/// \param nm is the name of the attribute
/// \return the associated id
inline uint4 AttributeId::find(const string &nm)

{
  unordered_map<string,uint4>::const_iterator iter = lookupAttributeId.find(nm);
  if (iter != lookupAttributeId.end())
    return (*iter).second;
  return ATTRIB_UNKNOWN.id;
}

/// The name is looked up in the global list of all elements.  If the element is not in the list, a special
/// placeholder element, ELEM_UNKNOWN, is returned as a placeholder for elements with unrecognized names.
/// \param nm is the name of the element
/// \return the associated id
inline uint4 ElementId::find(const string &nm)

{
  unordered_map<string,uint4>::const_iterator iter = lookupElementId.find(nm);
  if (iter != lookupElementId.end())
    return (*iter).second;
  return ELEM_UNKNOWN.id;
}

extern AttributeId ATTRIB_ALIGN;	///< Marshaling attribute "align"
extern AttributeId ATTRIB_BIGENDIAN;	///< Marshaling attribute "bigendian"
extern AttributeId ATTRIB_CONSTRUCTOR;	///< Marshaling attribute "constructor"
extern AttributeId ATTRIB_DESTRUCTOR;	///< Marshaling attribute "destructor"
extern AttributeId ATTRIB_EXTRAPOP;	///< Marshaling attribute "extrapop"
extern AttributeId ATTRIB_FORMAT;	///< Marshaling attribute "format"
extern AttributeId ATTRIB_HIDDENRETPARM;	///< Marshaling attribute "hiddenretparm"
extern AttributeId ATTRIB_ID;		///< Marshaling attribute "id"
extern AttributeId ATTRIB_INDEX;	///< Marshaling attribute "index"
extern AttributeId ATTRIB_INDIRECTSTORAGE;	///< Marshaling attribute "indirectstorage"
extern AttributeId ATTRIB_METATYPE;	///< Marshaling attribute "metatype"
extern AttributeId ATTRIB_MODEL;	///< Marshaling attribute "model"
extern AttributeId ATTRIB_NAME;		///< Marshaling attribute "name"
extern AttributeId ATTRIB_NAMELOCK;	///< Marshaling attribute "namelock"
extern AttributeId ATTRIB_OFFSET;	///< Marshaling attribute "offset"
extern AttributeId ATTRIB_READONLY;	///< Marshaling attribute "readonly"
extern AttributeId ATTRIB_REF;		///< Marshaling attribute "ref"
extern AttributeId ATTRIB_SIZE;		///< Marshaling attribute "size"
extern AttributeId ATTRIB_SPACE;	///< Marshaling attribute "space"
extern AttributeId ATTRIB_THISPTR;	///< Marshaling attribute "thisptr"
extern AttributeId ATTRIB_TYPE;		///< Marshaling attribute "type"
extern AttributeId ATTRIB_TYPELOCK;	///< Marshaling attribute "typelock"
extern AttributeId ATTRIB_VAL;		///< Marshaling attribute "val"
extern AttributeId ATTRIB_VALUE;	///< Marshaling attribute "value"
extern AttributeId ATTRIB_WORDSIZE;	///< Marshaling attribute "wordsize"

extern ElementId ELEM_DATA;		///< Marshaling element \<data>
extern ElementId ELEM_INPUT;		///< Marshaling element \<input>
extern ElementId ELEM_OFF;		///< Marshaling element \<off>
extern ElementId ELEM_OUTPUT;		///< Marshaling element \<output>
extern ElementId ELEM_RETURNADDRESS;	///< Marshaling element \<returnaddress>
extern ElementId ELEM_SYMBOL;		///< Marshaling element \<symbol>
extern ElementId ELEM_TARGET;		///< Marshaling element \<target>
extern ElementId ELEM_VAL;		///< Marshaling element \<val>
extern ElementId ELEM_VALUE;		///< Marshaling element \<value>
extern ElementId ELEM_VOID;		///< Marshaling element \<void>

#endif

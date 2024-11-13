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
#ifndef __MARSHAL_HH__
#define __MARSHAL_HH__

#include "xml.hh"
#include "opcodes.hh"
#include <list>
#include <unordered_map>

namespace ghidra {

using std::list;
using std::unordered_map;

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
  AttributeId(const string &nm,uint4 i,int4 scope=0);	///< Construct given a name and id
  const string &getName(void) const { return name; }				///< Get the attribute's name
  uint4 getId(void) const { return id; }					///< Get the attribute's id
  bool operator==(const AttributeId &op2) const { return (id == op2.id); }	///< Test equality with another AttributeId
  static uint4 find(const string &nm,int4 scope);	///< Find the id associated with a specific attribute name
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
  ElementId(const string &nm,uint4 i,int4 scope=0);		///< Construct given a name and id
  const string &getName(void) const { return name; }				///< Get the element's name
  uint4 getId(void) const { return id; }					///< Get the element's id
  bool operator==(const ElementId &op2) const { return (id == op2.id); }	///< Test equality with another ElementId
  static uint4 find(const string &nm,int4 scope);	///< Find the id associated with a specific element name
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

  /// \brief Get the id for the (current) attribute, assuming it is indexed
  ///
  /// Assuming the previous call to getNextAttributeId() returned the id of ATTRIB_UNKNOWN,
  /// reinterpret the attribute as being an indexed form of the given attribute. If the attribute
  /// matches, return this indexed id, otherwise return ATTRIB_UNKNOWN.
  /// \param attribId is the attribute being indexed
  /// \return the indexed id or ATTRIB_UNKNOWN
  virtual uint4 getIndexedAttributeId(const AttributeId &attribId)=0;

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

  /// \brief Parse the current attribute as either a signed integer value or a string.
  ///
  /// If the attribute is an integer, its value is returned. If the attribute is a string, it must match an
  /// expected string passed to the method, and a predetermined integer value associated with the string is returned.
  /// If the attribute neither matches the expected string nor is an integer, the return value is undefined.
  /// \param expect is the string value to expect if the attribute is encoded as a string
  /// \param expectval is the integer value to return if the attribute matches the expected string
  /// \return the encoded integer or the integer value associated with the expected string
  virtual intb readSignedIntegerExpectString(const string &expect,intb expectval)=0;

  /// \brief Find and parse a specific attribute in the current element as either a signed integer or a string.
  ///
  /// If the attribute is an integer, its value is parsed and returned.
  /// If the attribute is encoded as a string, it must match an expected string passed to this method.
  /// In this case, a predetermined integer value is passed back, indicating a matching string was parsed.
  /// If the attribute neither matches the expected string nor is an integer, the return value is undefined.
  /// If there is no attribute matching the id, an exception is thrown.
  /// \param attribId is the specific attribute id to match
  /// \param expect is the string to expect, if the attribute is not encoded as an integer
  /// \param expectval is the integer value to return if the attribute matches the expected string
  /// \return the encoded integer or the integer value associated with the expected string
  virtual intb readSignedIntegerExpectString(const AttributeId &attribId,const string &expect,intb expectval)=0;

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

  /// \brief Parse the current attribute as a p-code OpCode
  ///
  /// The last attribute, as returned by getNextAttributeId, is returned as an OpCode.
  /// \return the OpCode associated with the current attribute
  virtual OpCode readOpcode(void)=0;

  /// \brief Find the specific attribute in the current element and return it as an OpCode
  ///
  /// Search attributes from the current element for a match to the given attribute id.
  /// Return this attribute as an OpCode. If there is no matching attribute id, an exception is thrown.
  /// Parse via getNextAttributeId is reset.
  /// \param attribId is the specific attribute id to match
  /// \return the OpCode associated with the attribute
  virtual OpCode readOpcode(AttributeId &attribId)=0;

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

  /// \brief Write an annotated string, using an indexed attribute, into the encoding
  ///
  /// Multiple attributes with a shared name can be written to the same element by calling this method
  /// multiple times with a different \b index value. The encoding will use attribute ids up to the base id
  /// plus the maximum index passed in.  Implementors must be careful to not use other attributes with ids
  /// bigger than the base id within the element taking the indexed attribute.
  /// \param attribId is the shared AttributeId
  /// \param index is the unique index to associated with the string
  /// \param val is the string to encode
  virtual void writeStringIndexed(const AttributeId &attribId,uint4 index,const string &val)=0;

  /// \brief Write an address space reference into the encoding
  ///
  /// The address space is associated with the given AttributeId annotation and the current open element.
  /// \param attribId is the given AttributeId annotation
  /// \param spc is the address space to encode
  virtual void writeSpace(const AttributeId &attribId,const AddrSpace *spc)=0;

  /// \brief Write a p-code operation opcode into the encoding, associating it with the given annotation
  ///
  /// \param attribId is the given annotation
  /// \param opc is the opcode
  virtual void writeOpcode(const AttributeId &attribId,OpCode opc)=0;

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
  int4 scope;					///< Scope of element/attribute tags to look up
  int4 findMatchingAttribute(const Element *el,const string &attribName);
public:
  XmlDecode(const AddrSpaceManager *spc,const Element *root,int4 sc=0) : Decoder(spc) {
    document = (Document *)0; rootElement = root; attributeIndex = -1; scope = sc; }	///< Constructor with preparsed root
  XmlDecode(const AddrSpaceManager *spc,int4 sc=0) : Decoder(spc) {
    document = (Document *)0; rootElement = (const Element *)0; attributeIndex = -1; scope=sc; }	///< Constructor for use with ingestStream
  const Element *getCurrentXmlElement(void) const { return elStack.back(); }	///< Get pointer to underlying XML element object
  virtual ~XmlDecode(void);
  virtual void ingestStream(istream &s);
  virtual uint4 peekElement(void);
  virtual uint4 openElement(void);
  virtual uint4 openElement(const ElementId &elemId);
  virtual void closeElement(uint4 id);
  virtual void closeElementSkipping(uint4 id);
  virtual void rewindAttributes(void);
  virtual uint4 getNextAttributeId(void);
  virtual uint4 getIndexedAttributeId(const AttributeId &attribId);
  virtual bool readBool(void);
  virtual bool readBool(const AttributeId &attribId);
  virtual intb readSignedInteger(void);
  virtual intb readSignedInteger(const AttributeId &attribId);
  virtual intb readSignedIntegerExpectString(const string &expect,intb expectval);
  virtual intb readSignedIntegerExpectString(const AttributeId &attribId,const string &expect,intb expectval);
  virtual uintb readUnsignedInteger(void);
  virtual uintb readUnsignedInteger(const AttributeId &attribId);
  virtual string readString(void);
  virtual string readString(const AttributeId &attribId);
  virtual AddrSpace *readSpace(void);
  virtual AddrSpace *readSpace(const AttributeId &attribId);
  virtual OpCode readOpcode(void);
  virtual OpCode readOpcode(AttributeId &attribId);
};

/// \brief An XML based encoder
///
/// The underlying transfer encoding is an XML document.  The encoder is initialized with a stream which will
/// receive the XML document as calls are made on the encoder.
class XmlEncode : public Encoder {
  friend class XmlDecode;
  enum {
    tag_start = 0,			///< Tag has been opened, attributes can be written
    tag_content = 1,			///< Opening tag and content have been written
    tag_stop = 2			///< No tag is currently being written
  };
  static const char spaces[];		///< Array of ' ' characters for emitting indents
  static const int4 MAX_SPACES;		///< Maximum number of leading spaces when indenting XML
  ostream &outStream;			///< The stream receiving the encoded data
  int4 tagStatus;			///< Stage of writing an element tag
  int4 depth;				///< Depth of open elements
  bool doFormatting;			///< \b true if encoder should indent and emit newlines
  void newLine(void);			///< Emit a newline and proper indenting for the next tag
public:
  XmlEncode(ostream &s,bool doFormat=true) : outStream(s) { depth=0; tagStatus=tag_stop; doFormatting=doFormat; } ///< Construct from a stream
  virtual void openElement(const ElementId &elemId);
  virtual void closeElement(const ElementId &elemId);
  virtual void writeBool(const AttributeId &attribId,bool val);
  virtual void writeSignedInteger(const AttributeId &attribId,intb val);
  virtual void writeUnsignedInteger(const AttributeId &attribId,uintb val);
  virtual void writeString(const AttributeId &attribId,const string &val);
  virtual void writeStringIndexed(const AttributeId &attribId,uint4 index,const string &val);
  virtual void writeSpace(const AttributeId &attribId,const AddrSpace *spc);
  virtual void writeOpcode(const AttributeId &attribId,OpCode opc);
};

/// \brief Protocol format for PackedEncode and PackedDecode classes
///
/// All bytes in the encoding are expected to be non-zero.  Element encoding looks like
///   - 01xiiiii is an element start
///   - 10xiiiii is an element end
///   - 11xiiiii is an attribute start
///
/// Where iiiii is the (first) 5 bits of the element/attribute id.
/// If x=0, the id is complete.  If x=1, the next byte contains 7 more bits of the id:  1iiiiiii
///
/// After an attribute start, there follows a \e type byte:  ttttllll, where the first 4 bits indicate the
/// type of attribute and final 4 bits are a \b length \b code.  The types are:
///   - 1 = boolean (lengthcode=0 for false, lengthcode=1 for true)
///   - 2 = positive signed integer
///   - 3 = negative signed integer (stored in negated form)
///   - 4 = unsigned integer
///   - 5 = basic address space (encoded as the integer index of the space)
///   - 6 = special address space (lengthcode 0=>stack 1=>join 2=>fspec 3=>iop)
///   - 7 = string
///
/// All attribute types except \e boolean and \e special, have an encoded integer after the \e type byte.
/// The \b length \b code, indicates the number bytes used to encode the integer, 7-bits of info per byte, 1iiiiiii.
/// A \b length \b code of zero is used to encode an integer value of 0, with no following bytes.
///
/// For strings, the integer encoded after the \e type byte, is the actual length of the string.  The
/// string data itself is stored immediately after the length integer using UTF8 format.
namespace PackedFormat {
  static const uint1 HEADER_MASK = 0xc0;		///< Bits encoding the record type
  static const uint1 ELEMENT_START = 0x40;		///< Header for an element start record
  static const uint1 ELEMENT_END = 0x80;		///< Header for an element end record
  static const uint1 ATTRIBUTE = 0xc0;			///< Header for an attribute record
  static const uint1 HEADEREXTEND_MASK = 0x20;		///< Bit indicating the id extends into the next byte
  static const uint1 ELEMENTID_MASK = 0x1f;		///< Bits encoding (part of) the id in the record header
  static const uint1 RAWDATA_MASK = 0x7f;		///< Bits of raw data in follow-on bytes
  static const int4 RAWDATA_BITSPERBYTE = 7;		///< Number of bits used in a follow-on byte
  static const uint1 RAWDATA_MARKER = 0x80;		///< The unused bit in follow-on bytes. (Always set to 1)
  static const int4 TYPECODE_SHIFT = 4;			///< Bit position of the type code in the type byte
  static const uint1 LENGTHCODE_MASK = 0xf;		///< Bits in the type byte forming the length code
  static const uint1 TYPECODE_BOOLEAN = 1;		///< Type code for the \e boolean type
  static const uint1 TYPECODE_SIGNEDINT_POSITIVE = 2;	///< Type code for the \e signed \e positive \e integer type
  static const uint1 TYPECODE_SIGNEDINT_NEGATIVE = 3;	///< Type code for the \e signed \e negative \e integer type
  static const uint1 TYPECODE_UNSIGNEDINT = 4;		///< Type code for the \e unsigned \e integer type
  static const uint1 TYPECODE_ADDRESSSPACE = 5;		///< Type code for the \e address \e space type
  static const uint1 TYPECODE_SPECIALSPACE = 6;		///< Type code for the \e special \e address \e space type
  static const uint1 TYPECODE_STRING = 7;		///< Type code for the \e string type
  static const uint4 SPECIALSPACE_STACK = 0;		///< Special code for the \e stack space
  static const uint4 SPECIALSPACE_JOIN = 1;		///< Special code for the \e join space
  static const uint4 SPECIALSPACE_FSPEC = 2;		///< Special code for the \e fspec space
  static const uint4 SPECIALSPACE_IOP = 3;		///< Special code for the \e iop space
  static const uint4 SPECIALSPACE_SPACEBASE = 4;	///< Special code for a \e spacebase space
}

/// \brief A byte-based decoder designed to marshal info to the decompiler efficiently
///
/// The decoder expects an encoding as described in PackedFormat.  When ingested, the stream bytes are
/// held in a sequence of arrays (ByteChunk). During decoding, \b this object maintains a Position in the
/// stream at the start and end of the current open element, and a Position of the next attribute to read to
/// facilitate getNextAttributeId() and associated read*() methods.
class PackedDecode : public Decoder {
public:
  static const int4 BUFFER_SIZE;	///< The size, in bytes, of a single cached chunk of the input stream
private:
  /// \brief A bounded array of bytes
  class ByteChunk {
    friend class PackedDecode;
    uint1 *start;			///< Start of the byte array
    uint1 *end;				///< End of the byte array
  public:
    ByteChunk(uint1 *s,uint1 *e) { start = s; end = e; }	///< Constructor
  };
  /// \brief An iterator into input stream
  class Position {
    friend class PackedDecode;
    list<ByteChunk>::const_iterator seqIter;	///< Current byte sequence
    uint1 *current;				///< Current position in sequence
    uint1 *end;					///< End of current sequence
  };
  list<ByteChunk> inStream;		///< Incoming raw data as a sequence of byte arrays
  Position startPos;			///< Position at the start of the current open element
  Position curPos;			///< Position of the next attribute as returned by getNextAttributeId
  Position endPos;			///< Ending position after all attributes in current open element
  bool attributeRead;			///< Has the last attribute returned by getNextAttributeId been read
  uint1 getByte(Position &pos) { return *pos.current; }	///< Get the byte at the current position, do not advance
  uint1 getBytePlus1(Position &pos);	///< Get the byte following the current byte, do not advance position
  uint1 getNextByte(Position &pos);	///< Get the byte at the current position and advance to the next byte
  void advancePosition(Position &pos,int4 skip);	///< Advance the position by the given number of bytes
  uint8 readInteger(int4 len);		///< Read an integer from the \e current position given its length in bytes
  uint4 readLengthCode(uint1 typeByte) { return ((uint4)typeByte & PackedFormat::LENGTHCODE_MASK); }	///< Extract length code from type byte
  void findMatchingAttribute(const AttributeId &attribId);	///< Find attribute matching the given id in open element
  void skipAttribute(void);		///< Skip over the attribute at the current position
  void skipAttributeRemaining(uint1 typeByte);	///< Skip over remaining attribute data, after a mismatch
protected:
  uint1 *allocateNextInputBuffer(int4 pad);	///< Allocate the next chunk of space in the input stream
  void endIngest(int4 bufPos);		///< Finish set up for reading input stream
public:
  PackedDecode(const AddrSpaceManager *spcManager) : Decoder(spcManager) {}	///< Constructor
  virtual ~PackedDecode(void);
  virtual void ingestStream(istream &s);
  virtual uint4 peekElement(void);
  virtual uint4 openElement(void);
  virtual uint4 openElement(const ElementId &elemId);
  virtual void closeElement(uint4 id);
  virtual void closeElementSkipping(uint4 id);
  virtual void rewindAttributes(void);
  virtual uint4 getNextAttributeId(void);
  virtual uint4 getIndexedAttributeId(const AttributeId &attribId);
  virtual bool readBool(void);
  virtual bool readBool(const AttributeId &attribId);
  virtual intb readSignedInteger(void);
  virtual intb readSignedInteger(const AttributeId &attribId);
  virtual intb readSignedIntegerExpectString(const string &expect,intb expectval);
  virtual intb readSignedIntegerExpectString(const AttributeId &attribId,const string &expect,intb expectval);
  virtual uintb readUnsignedInteger(void);
  virtual uintb readUnsignedInteger(const AttributeId &attribId);
  virtual string readString(void);
  virtual string readString(const AttributeId &attribId);
  virtual AddrSpace *readSpace(void);
  virtual AddrSpace *readSpace(const AttributeId &attribId);
  virtual OpCode readOpcode(void);
  virtual OpCode readOpcode(AttributeId &attribId);
};

/// \brief A byte-based encoder designed to marshal from the decompiler efficiently
///
/// See PackedDecode for details of the encoding format.
class PackedEncode : public Encoder {
  ostream &outStream;			///< The stream receiving the encoded data
  void writeHeader(uint1 header,uint4 id);	///< Write a header, element or attribute, to stream
  void writeInteger(uint1 typeByte,uint8 val);	///< Write an integer value to the stream
public:
  PackedEncode(ostream &s) : outStream(s) {} ///< Construct from a stream
  virtual void openElement(const ElementId &elemId);
  virtual void closeElement(const ElementId &elemId);
  virtual void writeBool(const AttributeId &attribId,bool val);
  virtual void writeSignedInteger(const AttributeId &attribId,intb val);
  virtual void writeUnsignedInteger(const AttributeId &attribId,uintb val);
  virtual void writeString(const AttributeId &attribId,const string &val);
  virtual void writeStringIndexed(const AttributeId &attribId,uint4 index,const string &val);
  virtual void writeSpace(const AttributeId &attribId,const AddrSpace *spc);
  virtual void writeOpcode(const AttributeId &attribId,OpCode opc);
};

/// An exception is thrown if the position currently points to the last byte in the stream
/// \param pos is the position in the stream to look ahead from
/// \return the next byte
inline uint1 PackedDecode::getBytePlus1(Position &pos)

{
  uint1 *ptr = pos.current + 1;
  if (ptr == pos.end) {
    list<ByteChunk>::const_iterator iter = pos.seqIter;
    ++iter;
    if (iter == inStream.end())
      throw DecoderError("Unexpected end of stream");
    ptr = (*iter).start;
  }
  return *ptr;
}

/// An exception is thrown if there are no additional bytes in the stream
/// \param pos is the position of the byte
/// \return the byte at the current position
inline uint1 PackedDecode::getNextByte(Position &pos)

{
  uint1 res = *pos.current;
  pos.current += 1;
  if (pos.current != pos.end)
    return res;
  ++pos.seqIter;
  if (pos.seqIter == inStream.end())
    throw DecoderError("Unexpected end of stream");
  pos.current = (*pos.seqIter).start;
  pos.end = (*pos.seqIter).end;
  return res;
}

/// An exception is thrown of position is advanced past the end of the stream
/// \param pos is the position being advanced
/// \param skip is the number of bytes to advance
inline void PackedDecode::advancePosition(Position &pos,int4 skip)

{
  while(pos.end - pos.current <= skip) {
    skip -= (pos.end - pos.current);
    ++pos.seqIter;
    if (pos.seqIter == inStream.end())
      throw DecoderError("Unexpected end of stream");
    pos.current = (*pos.seqIter).start;
    pos.end = (*pos.seqIter).end;
  }
  pos.current += skip;
}

/// Allocate an array of BUFFER_SIZE bytes and add it to the in-memory stream
/// \param pad is the number of bytes of padding to add to the allocation size, above BUFFER_SIZE
/// \return the newly allocated buffer
inline uint1 *PackedDecode::allocateNextInputBuffer(int4 pad)

{
  uint1 *buf = new uint1[BUFFER_SIZE + pad];
  inStream.emplace_back(buf,buf+BUFFER_SIZE);
  return buf;
}

/// \param header is the type of header
/// \param id is the id associated with the element or attribute
inline void PackedEncode::writeHeader(uint1 header,uint4 id)

{
  if (id > 0x1f) {
    header |= PackedFormat::HEADEREXTEND_MASK;
    header |= (id >> PackedFormat::RAWDATA_BITSPERBYTE);
    uint1 extendByte = (id & PackedFormat::RAWDATA_MASK) | PackedFormat::RAWDATA_MARKER;
    outStream.put(header);
    outStream.put(extendByte);
  }
  else {
    header |= id;
    outStream.put(header);
  }
}

extern ElementId ELEM_UNKNOWN;		///< Special element to represent an element with an unrecognized name
extern AttributeId ATTRIB_UNKNOWN;	///< Special attribute  to represent an attribute with an unrecognized name
extern AttributeId ATTRIB_CONTENT;	///< Special attribute for XML text content of an element

/// The name is looked up in the scoped list of attributes.  If the attribute is not in the list, a special
/// placeholder attribute, ATTRIB_UNKNOWN, is returned as a placeholder for attributes with unrecognized names.
/// \param nm is the name of the attribute
/// \param scope is the id of the scope in which to lookup of the name
/// \return the associated id
inline uint4 AttributeId::find(const string &nm,int4 scope)

{
  if (scope == 0) {		// Current only support reverse look up for scope 0
    unordered_map<string,uint4>::const_iterator iter = lookupAttributeId.find(nm);
    if (iter != lookupAttributeId.end())
      return (*iter).second;
  }
  return ATTRIB_UNKNOWN.id;
}

/// The name is looked up in the scoped list of elements.  If the element is not in the list, a special
/// placeholder element, ELEM_UNKNOWN, is returned as a placeholder for elements with unrecognized names.
/// \param nm is the name of the element
/// \param scope is the id of the scope in which to search
/// \return the associated id
inline uint4 ElementId::find(const string &nm,int4 scope)

{
  if (scope == 0) {
    unordered_map<string,uint4>::const_iterator iter = lookupElementId.find(nm);
    if (iter != lookupElementId.end())
      return (*iter).second;
  }
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
extern AttributeId ATTRIB_STORAGE;	///< Marshaling attribute "storage"
extern AttributeId ATTRIB_STACKSPILL;	///< Marshaling attribute "stackspill"

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

} // End namespace ghidra
#endif

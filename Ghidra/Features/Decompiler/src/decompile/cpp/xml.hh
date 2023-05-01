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
/// \file xml.hh
/// \brief Lightweight (and incomplete) XML parser for marshaling data to and from the decompiler
#ifndef __XML_HH__
#define __XML_HH__

#include "types.h"
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>

namespace ghidra {

using std::string;
using std::vector;
using std::map;
using std::istream;
using std::ostream;
using std::ifstream;
using std::dec;
using std::hex;

/// \brief The \e attributes for a single XML element
///
/// A container for name/value pairs (of strings) for the formal attributes, as collected during parsing.
/// This object is used to initialize the Element object but is not part of the final, in memory, DOM model.
/// This also holds other properties of the element that are unused in this implementation,
/// including the \e namespace URI.
class Attributes {
  static string bogus_uri;		///< A placeholder for the namespace URI that should be attached to the element
//  static string prefix;
  string *elementname;			///< The name of the XML element
  vector<string *> name;		///< List of names for each formal XML attribute
  vector<string *> value;		///< List of values for each formal XML attribute
public:
  Attributes(string *el) { elementname = el; }	///< Construct from element name string
  ~Attributes(void) { 
    for(uint4 i=0;i<name.size();++i) { delete name[i]; delete value[i]; }
    delete elementname;
  }	///< Destructor
  const string &getelemURI(void) const { return bogus_uri; }	///< Get the namespace URI associated with this element
  const string &getelemName(void) const { return *elementname; }	///< Get the name of this element
  void add_attribute(string *nm,string *vl) { name.push_back(nm); value.push_back(vl); }	///< Add a formal attribute
				// The official SAX interface
  int4 getLength(void) const { return name.size(); }		///< Get the number of attributes associated with the element
  const string &getURI(int4 i) const { return bogus_uri; }	///< Get the namespace URI associated with the i-th attribute
  const string &getLocalName(int4 i) const { return *name[i]; }	///< Get the local name of the i-th attribute
  const string &getQName(int4 i) const { return *name[i]; }	///< Get the qualified name of the i-th attribute
  //  int4 getIndex(const string &uri,const string &localName) const;
  //  int4 getIndex(const string &qualifiedName) const;
  //  const string &getType(int4 index) const;
  //  const string &getType(const string &uri,const string &localName) const;
  //  const string &getType(const string &qualifiedName) const;
  const string &getValue(int4 i) const { return *value[i]; }	///< Get the value of the i-th attribute
  //const string &getValue(const string &uri,const string &localName) const;
  /// \brief Get the value of the attribute with the given qualified name
  const string &getValue(const string &qualifiedName) const {
    for(uint4 i=0;i<name.size();++i)
      if (*name[i] == qualifiedName) return *value[i];
    return bogus_uri;
  }
};

typedef void *Locator;		///< Placeholder for a document locator object

/// \brief The SAX interface for parsing XML documents
///
/// This is the formal interface for handling the low-level string pieces of an XML document as
/// they are scanned by the parser.
class ContentHandler {
public:
  virtual ~ContentHandler(void) {}			///< Destructor
  virtual void setDocumentLocator(Locator locator)=0;	///< Set the Locator object for documents
  virtual void startDocument(void)=0;			///< Start processing a new XML document
  virtual void endDocument(void)=0;			///< End processing for the current XML document
  virtual void startPrefixMapping(const string &prefix,const string &uri)=0;	///< Start a new prefix to namespace URI mapping
  virtual void endPrefixMapping(const string &prefix)=0;			///< Finish the current prefix

  /// \brief Callback indicating a new XML element has started.
  ///
  /// \param namespaceURI is the namespace to which the new element belongs
  /// \param localName is the local name of the new element
  /// \param qualifiedName is the fully qualified name of the new element
  /// \param atts is the set of (previously parsed) attributes to attach to the new element
  virtual void startElement(const string &namespaceURI,const string &localName,
			    const string &qualifiedName,const Attributes &atts)=0;

  /// \brief Callback indicating parsing of the current XML element is finished.
  ///
  /// \param namespaceURI is the namespace to which the element belongs
  /// \param localName is the local name of the new element
  /// \param qualifiedName is the fully qualified name of the element.
  virtual void endElement(const string &namespaceURI,const string &localName,
			  const string &qualifiedName)=0;

  /// \brief Callback with raw characters to be inserted in the current XML element
  ///
  /// \param text is an array of character data being inserted.
  /// \param start is the first character within the array to insert.
  /// \param length is the number of characters to insert.
  virtual void characters(const char *text,int4 start,int4 length)=0;

  /// \brief Callback with whitespace character data for the current XML element
  ///
  /// \param text is an array of character data that can be inserted.
  /// \param start is the first character within the array to insert.
  /// \param length is the number of characters to insert.
  virtual void ignorableWhitespace(const char *text,int4 start,int4 length)=0;

  /// \brief Set the XML version as specified by the current document
  ///
  /// \param version is the parsed version string
  virtual void setVersion(const string &version)=0;

  /// \brief Set the character encoding as specified by the current document
  ///
  /// \param encoding is the parsed encoding string
  virtual void setEncoding(const string &encoding)=0;

  /// \brief Callback for a formal \e processing \e instruction seen in the current document
  ///
  /// \param target is the target instruction to process
  /// \param data is (optional) character data for the instruction
  virtual void processingInstruction(const string &target,const string &data)=0;

  /// \brief Callback for an XML entity skipped by the parser
  ///
  /// \param name is the name of the entity being skipped
  virtual void skippedEntity(const string &name)=0;

  /// \brief Callback for handling an error condition during XML parsing
  ///
  /// \param errmsg is a message describing the error condition
  virtual void setError(const string &errmsg)=0;
};

class Element;
typedef vector<Element *> List;		///< A list of XML elements

/// \brief An XML element.  A node in the DOM tree.
///
/// This is the main node for the in-memory representation of the XML (DOM) tree.
class Element {
  string name;			///< The (local) name of the element
  string content;		///< Character content of the element
  vector<string> attr;		///< A list of attribute names for \b this element
  vector<string> value;		///< a (corresponding) list of attribute values for \b this element
protected:
  Element *parent;		///< The parent Element (or null)
  List children;		///< A list of child Element objects
public:
  Element(Element *par) { parent = par; }	///< Constructor given a parent Element
  ~Element(void);				///< Destructor
  void setName(const string &nm) { name = nm; }	///< Set the local name of the element

  /// \brief Append new character content to \b this element
  ///
  /// \param str is an array of character data
  /// \param start is the index of the first character to append
  /// \param length is the number of characters to append
  void addContent(const char *str,int4 start,int4 length) { 
    //    for(int4 i=0;i<length;++i) content += str[start+i]; }
    content.append(str+start,length); }

  /// \brief Add a new child Element to the model, with \b this as the parent
  ///
  /// \param child is the new child Element
  void addChild(Element *child) { children.push_back(child); }

  /// \brief Add a new name/value attribute pair to \b this element
  ///
  /// \param nm is the name of the attribute
  /// \param vl is the value of the attribute
  void addAttribute(const string &nm,const string &vl) {
    attr.push_back(nm); value.push_back(vl); }

  Element *getParent(void) const { return parent; }		///< Get the parent Element
  const string &getName(void) const { return name; }		///< Get the local name of \b this element
  const List &getChildren(void) const { return children; }	///< Get the list of child elements
  const string &getContent(void) const { return content; }	///< Get the character content of \b this element

  /// \brief Get an attribute value by name
  ///
  /// Look up the value for the given attribute name and return it. An exception is
  /// thrown if the attribute does not exist.
  /// \param nm is the name of the attribute
  /// \return the corresponding attribute value
  const string &getAttributeValue(const string &nm) const;

  int4 getNumAttributes(void) const { return attr.size(); }	///< Get the number of attributes for \b this element
  const string &getAttributeName(int4 i) const { return attr[i]; }	///< Get the name of the i-th attribute
  const string &getAttributeValue(int4 i) const { return value[i]; }	///< Get the value of the i-th attribute
};

/// \brief A complete in-memory XML document.
///
/// This is actually just an Element object itself, with the document's \e root element
/// as its only child, which owns all the child documents below it in DOM the hierarchy.
class Document : public Element {
public:
  Document(void) : Element((Element *)0) {}	///< Construct an (empty) document
  Element *getRoot(void) const { return *children.begin(); }	///< Get the root Element of the document
};

/// \brief A SAX interface implementation for constructing an in-memory DOM model.
///
/// This implementation builds a DOM model of the XML stream being parsed, creating an
/// Element object for each XML element tag in the stream.  This handler is initialized with
/// a root Element object, which after parsing is complete will own all parsed elements.
class TreeHandler : public ContentHandler {
  Element *root;		///< The root XML element being processed by \b this handler
  Element *cur;			///< The \e current XML element being processed by \b this handler
  string error;			///< The last error condition returned by the parser (if not empty)
public:
  TreeHandler(Element *rt) { root = rt; cur = root; }	///< Constructor given root Element
  virtual ~TreeHandler(void) {}
  virtual void setDocumentLocator(Locator locator) {}
  virtual void startDocument(void) {}
  virtual void endDocument(void) {}
  virtual void startPrefixMapping(const string &prefix,const string &uri) {}
  virtual void endPrefixMapping(const string &prefix) {}
  virtual void startElement(const string &namespaceURI,const string &localName,
			    const string &qualifiedName,const Attributes &atts);
  virtual void endElement(const string &namespaceURI,const string &localName,
			  const string &qualifiedName);
  virtual void characters(const char *text,int4 start,int4 length);
  virtual void ignorableWhitespace(const char *text,int4 start,int4 length) {}
  virtual void processingInstruction(const string &target,const string &data) {}
  virtual void setVersion(const string &val) {}
  virtual void setEncoding(const string &val) {}
  virtual void skippedEntity(const string &name) {}
  virtual void setError(const string &errmsg) { error = errmsg; }
  const string &getError(void) const { return error; }	///< Get the current error message
};

/// \brief A container for parsed XML documents
///
/// This holds multiple XML documents that have already been parsed. Documents
/// can be put in this container, either by handing it a stream via parseDocument()
/// or a filename via openDocument().  If they are explicitly registered, specific
/// XML Elements can be looked up by name via getTag().
class DocumentStorage {
  vector<Document *> doclist;		///< The list of documents held by this container
  map<string,const Element *> tagmap;	///< The map from name to registered XML elements
public:
  ~DocumentStorage(void);		///< Destructor

  /// \brief Parse an XML document from the given stream
  ///
  /// Parsing starts immediately on the stream, attempting to make an in-memory DOM tree.
  /// An XmlException is thrown for any parsing error.
  /// \param s is the given stream to parse
  /// \return the in-memory DOM tree
  Document *parseDocument(istream &s);

  /// \brief Open and parse an XML file
  ///
  /// The given filename is opened on the local filesystem and an attempt is made to parse
  /// its contents into an in-memory DOM tree. An XmlException is thrown for any parsing error.
  /// \param filename is the name of the XML document file
  /// \return the in-memory DOM tree
  Document *openDocument(const string &filename);

  /// \brief Register the given XML Element object under its tag name
  ///
  /// Only one Element can be stored on \b this object per tag name.
  /// \param el is the given XML element
  void registerTag(const Element *el);

  /// \brief Retrieve a registered XML Element by name
  ///
  /// \param nm is the XML tag name
  /// \return the matching registered Element or null
  const Element *getTag(const string &nm) const;
};

/// \brief An exception thrown by the XML parser
///
/// This object holds the error message as passed to the SAX interface callback
/// and is thrown as a formal exception.
struct DecoderError {
  string explain;		///< Explanatory string
  DecoderError(const string &s) { explain = s; }	///< Constructor
};

/// \brief Start-up the XML parser given a stream and a handler
///
/// This runs the low-level XML parser.
/// \param i is the given stream to get character data from
/// \param hand is the ContentHandler that stores or processes the XML content events
/// \param dbg is non-zero if the parser should output debug information during its parse
/// \return 0 if there is no error during parsing or a (non-zero) error condition
extern int4 xml_parse(istream &i,ContentHandler *hand,int4 dbg=0);

/// \brief Parse the given XML stream into an in-memory document
///
/// The stream is parsed using the standard ContentHandler for producing an in-memory
/// DOM representation of the XML document.
/// \param i is the given stream
/// \return the in-memory XML document
extern Document *xml_tree(istream &i);

/// \brief Send the given character array to a stream, escaping characters with special XML meaning
///
/// This makes the following character substitutions:
///   - '<' =>  "&lt;"
///   - '>' =>  "&gt;"
///   - '&' =>  "&amp;"
///   - '"' =>  "&quot;"
///   - '\'' => "&apos;"
///
/// \param s is the stream to write to
/// \param str is the given character array to escape
extern void xml_escape(ostream &s,const char *str);

// Some helper functions for writing XML documents directly to a stream

/// \brief Output an XML attribute name/value pair to stream
///
/// \param s is the output stream
/// \param attr is the name of the attribute
/// \param val is the attribute value
inline void a_v(ostream &s,const string &attr,const string &val)

{
  s << ' ' << attr << "=\"";
  xml_escape(s,val.c_str());
  s << "\"";
}

/// \brief Output the given signed integer as an XML attribute value
///
/// \param s is the output stream
/// \param attr is the name of the attribute
/// \param val is the given integer value
inline void a_v_i(ostream &s,const string &attr,intb val)

{
  s << ' ' << attr << "=\"" << dec << val << "\"";
}

/// \brief Output the given unsigned integer as an XML attribute value
///
/// \param s is the output stream
/// \param attr is the name of the attribute
/// \param val is the given unsigned integer value
inline void a_v_u(ostream &s,const string &attr,uintb val)

{
  s << ' ' << attr << "=\"0x" << hex << val << "\"";
}

/// \brief Output the given boolean value as an XML attribute
///
/// \param s is the output stream
/// \param attr is the name of the attribute
/// \param val is the given boolean value
inline void a_v_b(ostream &s,const string &attr,bool val)

{
  s << ' ' << attr << "=\"";
  if (val)
    s << "true";
  else
    s << "false";
  s << "\"";
}

/// \brief Read an XML attribute value as a boolean
///
/// This method is intended to recognize the strings, "true", "yes", and "1"
/// as a \b true value.  Anything else is returned as \b false.
/// \param attr is the given XML attribute value (as a string)
/// \return either \b true or \b false
inline bool xml_readbool(const string &attr)

{
  if (attr.size()==0) return false;
  char firstc = attr[0];
  if (firstc=='t') return true;
  if (firstc=='1') return true;
  if (firstc=='y') return true;         // For backward compatibility
  return false;
}

} // End namespace ghidra
#endif

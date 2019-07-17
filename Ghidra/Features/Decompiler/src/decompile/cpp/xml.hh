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
#ifndef __CPUI_XML__
#define __CPUI_XML__

#include "types.h"
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>

using namespace std;

class Attributes {
  string *elementname;
  string bogus_uri;
  string prefix;
  vector<string *> name;
  vector<string *> value;
public:
  Attributes(string *el) { elementname = el; }
  ~Attributes(void) { 
    for(uint4 i=0;i<name.size();++i) { delete name[i]; delete value[i]; }
    delete elementname;
  }
  const string &getelemURI(void) const { return bogus_uri; }
  const string &getelemName(void) const { return *elementname; }
  void add_attribute(string *nm,string *vl) { name.push_back(nm); value.push_back(vl); }
				// The official SAX interface
  int4 getLength(void) const { return name.size(); }
  const string &getURI(int4 index) const { return bogus_uri; }
  const string &getLocalName(int4 index) const { return *name[index]; }
  const string &getQName(int4 index) const { return *name[index]; }
  //  int4 getIndex(const string &uri,const string &localName) const;
  //  int4 getIndex(const string &qualifiedName) const;
  //  const string &getType(int4 index) const;
  //  const string &getType(const string &uri,const string &localName) const;
  //  const string &getType(const string &qualifiedName) const;
  const string &getValue(int4 index) const { return *value[index]; }
  //const string &getValue(const string &uri,const string &localName) const;
  const string &getValue(const string &qualifiedName) const {
    for(uint4 i=0;i<name.size();++i)
      if (*name[i] == qualifiedName) return *value[i];
    return bogus_uri;
  }
};

typedef void *Locator;

class ContentHandler {
public:
  virtual ~ContentHandler(void) {}
  virtual void setDocumentLocator(Locator locator)=0;
  virtual void startDocument(void)=0;
  virtual void endDocument(void)=0;
  virtual void startPrefixMapping(const string &prefix,const string &uri)=0;
  virtual void endPrefixMapping(const string &prefix)=0;
  virtual void startElement(const string &namespaceURI,const string &localName,
			    const string &qualifiedName,const Attributes &atts)=0;
  virtual void endElement(const string &namespaceURI,const string &localName,
			  const string &qualifiedName)=0;
  virtual void characters(const char *text,int4 start,int4 length)=0;
  virtual void ignorableWhitespace(const char *text,int4 start,int4 length)=0;
  virtual void setVersion(const string &version)=0;
  virtual void setEncoding(const string &encoding)=0;
  virtual void processingInstruction(const string &target,const string &data)=0;
  virtual void skippedEntity(const string &name)=0;
  virtual void setError(const string &errmsg)=0;
};

class Element;
typedef vector<Element *> List;

class Element {
  string name;
  string content;
  vector<string> attr;
  vector<string> value;
protected:
  Element *parent;
  List children;
public:
  Element(Element *par) { parent = par; }
  ~Element(void);
  void setName(const string &nm) { name = nm; }
  void addContent(const char *str,int4 start,int4 length) { 
    //    for(int4 i=0;i<length;++i) content += str[start+i]; }
    content.append(str+start,length); }
  void addChild(Element *child) { children.push_back(child); }
  void addAttribute(const string &nm,const string &vl) {
    attr.push_back(nm); value.push_back(vl); }
  Element *getParent(void) const { return parent; }
  const string &getName(void) const { return name; }
  const List &getChildren(void) const { return children; }
  const string &getContent(void) const { return content; }
  const string &getAttributeValue(const string &nm) const;
  int4 getNumAttributes(void) const { return attr.size(); }
  const string &getAttributeName(int4 i) const { return attr[i]; }
  const string &getAttributeValue(int4 i) const { return value[i]; }
};

class Document : public Element {
public:
  Document(void) : Element((Element *)0) {}
  Element *getRoot(void) const { return *children.begin(); }
};

class TreeHandler : public ContentHandler {
  Element *root;
  Element *cur;
  string error;
public:
  TreeHandler(Element *rt) { root = rt; cur = root; }
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
  const string &getError(void) const { return error; }
};

// Class for managing xml documents during initialization
class DocumentStorage {
  vector<Document *> doclist;
  map<string,const Element *> tagmap;
public:
  ~DocumentStorage(void);
  Document *parseDocument(istream &s);
  Document *openDocument(const string &filename);
  void registerTag(const Element *el);
  const Element *getTag(const string &nm) const;
};

struct XmlError {
  string explain;		// Explanatory string
  XmlError(const string &s) { explain = s; }
};

extern int4 xml_parse(istream &i,ContentHandler *hand,int4 dbg=0);
extern Document *xml_tree(istream &i);
extern void xml_escape(ostream &s,const char *str);

// Some helper functions for producing XML
inline void a_v(ostream &s,const string &attr,const string &val)

{
  s << ' ' << attr << "=\"";
  xml_escape(s,val.c_str());
  s << "\"";
}

inline void a_v_i(ostream &s,const string &attr,intb val)

{
  s << ' ' << attr << "=\"" << dec << val << "\"";
}

inline void a_v_u(ostream &s,const string &attr,uintb val)

{
  s << ' ' << attr << "=\"0x" << hex << val << "\"";
}

inline void a_v_b(ostream &s,const string &attr,bool val)

{
  s << ' ' << attr << "=\"";
  if (val)
    s << "true";
  else
    s << "false";
  s << "\"";
}

inline bool xml_readbool(const string &attr)

{
  if (attr.size()==0) return false;
  char firstc = attr[0];
  if (firstc=='t') return true;
  if (firstc=='1') return true;
  if (firstc=='y') return true;         // For backward compatibility
  return false;
}
#endif

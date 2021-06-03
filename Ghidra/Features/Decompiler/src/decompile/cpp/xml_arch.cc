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
#include "xml_arch.hh"

// Constructing the singleton registers the capability
XmlArchitectureCapability XmlArchitectureCapability::xmlArchitectureCapability;

XmlArchitectureCapability::XmlArchitectureCapability(void)

{
  name = "xml";
}

Architecture *XmlArchitectureCapability::buildArchitecture(const string &filename,const string &target,ostream *estream)

{
  return new XmlArchitecture(filename,target,estream);
}

bool XmlArchitectureCapability::isFileMatch(const string &filename) const

{
  ifstream s(filename.c_str());
  if (!s)
    return false;
  int4 val1,val2,val3;
  s >> ws;
  val1 = s.get();
  val2 = s.get();
  val3 = s.get();
  s.close();
  if ((val1=='<')&&(val2=='b')&&(val3=='i')) // Probably <binaryimage> tag
    return true;
  return false;
}

bool XmlArchitectureCapability::isXmlMatch(Document *doc) const

{
  return (doc->getRoot()->getName() == "xml_savefile");
}

void XmlArchitecture::buildLoader(DocumentStorage &store)

{
  collectSpecFiles(*errorstream);
  const Element *el = store.getTag("binaryimage");
  if (el == (const Element *)0) {
    Document *doc = store.openDocument(getFilename());
    store.registerTag(doc->getRoot());
    el = store.getTag("binaryimage");
  }
  if (el == (const Element *)0)
    throw LowlevelError("Could not find binaryimage tag");
  loader = new LoadImageXml(getFilename(),el);
}

/// Read in image information (which uses translator)
void XmlArchitecture::postSpecFile(void)

{
  Architecture::postSpecFile();
  ((LoadImageXml *)loader)->open(translate);
  if (adjustvma != 0)
    loader->adjustVma(adjustvma);
}

/// This just wraps the base constructor
/// \param fname is the path to the executable file (containing XML)
/// \param targ is the (optional) language id
/// \param estream is the stream to use for the error console
XmlArchitecture::XmlArchitecture(const string &fname,const string &targ,ostream *estream)
  : SleighArchitecture(fname,targ,estream)

{
  adjustvma = 0;
}

/// Prepend extra stuff to specify binary file and spec
/// \param s is the stream to write to
void XmlArchitecture::saveXml(ostream &s) const

{
  s << "<xml_savefile";
  saveXmlHeader(s);
  a_v_u(s,"adjustvma",adjustvma);
  s << ">\n";
  ((LoadImageXml *)loader)->saveXml(s); // Save the LoadImage
  types->saveXmlCoreTypes(s);
  SleighArchitecture::saveXml(s); // Save the rest of the state
  s << "</xml_savefile>\n";
}

void XmlArchitecture::restoreXml(DocumentStorage &store)

{
  const Element *el = store.getTag("xml_savefile");
  if (el == (const Element *)0)
    throw LowlevelError("Could not find xml_savefile tag");

  restoreXmlHeader(el);
  {
    istringstream s( el->getAttributeValue("adjustvma"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> adjustvma;
  }    
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  if (iter!=list.end()) {
    if ((*iter)->getName() == "binaryimage") {
      store.registerTag(*iter);
      ++iter;
    }
  }
  if (iter != list.end()) {
    if ((*iter)->getName() == "specextensions") {
      store.registerTag(*iter);
      ++iter;
    }
  }
  if (iter!=list.end()) {
    if ((*iter)->getName() == "coretypes") {
      store.registerTag(*iter);
      ++iter;
    }
  }
  init(store);			// Load the image and configure

  if (iter != list.end()) {
    store.registerTag(*iter);
    SleighArchitecture::restoreXml(store);
  }
}

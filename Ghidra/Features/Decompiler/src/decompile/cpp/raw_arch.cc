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
#include "raw_arch.hh"

// Constructing this object registers the capability
RawBinaryArchitectureCapability RawBinaryArchitectureCapability::rawBinaryArchitectureCapability;

RawBinaryArchitectureCapability::RawBinaryArchitectureCapability(void)

{
  name = "raw";
}

RawBinaryArchitectureCapability::~RawBinaryArchitectureCapability(void)

{
  SleighArchitecture::shutdown();
}

Architecture *RawBinaryArchitectureCapability::buildArchitecture(const string &filename,const string &target,ostream *estream)

{
  return new RawBinaryArchitecture(filename,target,estream);
}

bool RawBinaryArchitectureCapability::isFileMatch(const string &filename) const

{
  return true;			// File can always be opened as raw binary
}

bool RawBinaryArchitectureCapability::isXmlMatch(Document *doc) const

{
  return (doc->getRoot()->getName() == "raw_savefile");
}

void RawBinaryArchitecture::buildLoader(DocumentStorage &store)

{
  RawLoadImage *ldr;

  collectSpecFiles(*errorstream);
  ldr = new RawLoadImage(getFilename());
  ldr->open();
  if (adjustvma != 0)
    ldr->adjustVma(adjustvma);
  loader = ldr;
}

void RawBinaryArchitecture::resolveArchitecture(void)

{
  archid = getTarget();	// Nothing to derive from the image itself, we just copy in the passed in target
  SleighArchitecture::resolveArchitecture();
}

void RawBinaryArchitecture::postSpecFile(void)

{
  Architecture::postSpecFile();
  ((RawLoadImage *)loader)->attachToSpace(getDefaultCodeSpace());	 // Attach default space to loader
}

RawBinaryArchitecture::RawBinaryArchitecture(const string &fname,const string &targ,ostream *estream)
  : SleighArchitecture(fname,targ,estream)
{
  adjustvma = 0;
}

void RawBinaryArchitecture::saveXml(ostream &s) const

{
  s << "<raw_savefile";
  saveXmlHeader(s);
  a_v_u(s,"adjustvma",adjustvma);
  s << ">\n";
  types->saveXmlCoreTypes(s);
  SleighArchitecture::saveXml(s);
  s << "</raw_savefile>\n";
}

void RawBinaryArchitecture::restoreXml(DocumentStorage &store)

{
  const Element *el = store.getTag("raw_savefile");
  if (el == (const Element *)0)
    throw LowlevelError("Could not find raw_savefile tag");

  restoreXmlHeader(el);
  {
    istringstream s( el->getAttributeValue("adjustvma"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> adjustvma;
  }
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  if (iter != list.end()) {
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

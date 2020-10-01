/* ###
 * IP: GHIDRA
 * NOTE: Excluded from Build.  Used for development only in support of console mode - Links to GNU BFD library which is GPL 3
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
#include "bfd_arch.hh"

// Constructing this object registers capability
BfdArchitectureCapability BfdArchitectureCapability::bfdArchitectureCapability;

BfdArchitectureCapability::BfdArchitectureCapability(void)

{
  name = "bfd";
}

BfdArchitectureCapability::~BfdArchitectureCapability(void)

{
  SleighArchitecture::shutdown();
}

Architecture *BfdArchitectureCapability::buildArchitecture(const string &filename,const string &target,ostream *estream)

{
  return new BfdArchitecture(filename,target,estream);
}

bool BfdArchitectureCapability::isFileMatch(const string &filename) const

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
  if ((val1=='<')&&(val2=='b')&&(val3=='i'))
    return false;		// Probably XML, not BFD
  return true;
}

bool BfdArchitectureCapability::isXmlMatch(Document *doc) const

{
  return (doc->getRoot()->getName() == "bfd_savefile");
}

void BfdArchitecture::buildLoader(DocumentStorage &store)

{
  LoadImageBfd *ldr;

  collectSpecFiles(*errorstream);
  if (getTarget().find("binary")==0)
    ldr = new LoadImageBfd(getFilename(),"binary");
  else if (getTarget().find("default")==0)
    ldr = new LoadImageBfd(getFilename(),"default");
  else
    ldr = new LoadImageBfd(getFilename(),getTarget());
  ldr->open();
  if (adjustvma!=0)
    ldr->adjustVma(adjustvma);
  loader = ldr;
}

void BfdArchitecture::resolveArchitecture(void)

{
  archid = getTarget();
  if (archid.find(':')==string::npos) {
    archid = loader->getArchType();
    // kludge to distinguish windows binaries from linux/gcc
    if (archid.find("efi-app-ia32") != string::npos)
      archid = "x86:LE:32:default:windows";
    else if (archid.find("pe-i386") != string::npos)
      archid = "x86:LE:32:default:windows";
    else if (archid.find("pei-i386") != string::npos)
      archid = "x86:LE:32:default:windows";
    else if (archid.find("pei-x86-64") != string::npos)
      archid = "x86:LE:64:default:windows";
    else if (archid.find("sparc") != string::npos)
      archid = "sparc:BE:32:default:default";
    else if (archid.find("elf64") != string::npos)
      archid = "x86:LE:64:default:gcc";
    else if (archid.find("elf") != string::npos)
      archid = "x86:LE:32:default:gcc";
    else if (archid.find("mach-o") != string::npos)
      archid = "PowerPC:BE:32:default:macosx";
    else
      throw LowlevelError("Cannot convert bfd target to sleigh target: "+archid);
  }
  SleighArchitecture::resolveArchitecture();
}

void BfdArchitecture::postSpecFile(void)

{ // Attach default space to loader
  Architecture::postSpecFile();
  ((LoadImageBfd *)loader)->attachToSpace(getDefaultCodeSpace());
}

/// This just wraps the base class constructor
/// \param fname is the path to the executable file
/// \param targ is the (optional) language id to use for the file
/// \param estream is the stream to use for the error console
BfdArchitecture::BfdArchitecture(const string &fname,const string &targ,ostream *estream)
  : SleighArchitecture(fname,targ,estream)

{				// Select architecture from string
  adjustvma = 0;
}

void BfdArchitecture::saveXml(ostream &s) const

{				// prepend extra stuff to specify binary file and spec
  s << "<bfd_savefile";
  saveXmlHeader(s);
  a_v_u(s,"adjustvma",adjustvma);
  s << ">\n";
  types->saveXmlCoreTypes(s);
  SleighArchitecture::saveXml(s); // Save the rest of the state
  s << "</bfd_savefile>\n";
}

void BfdArchitecture::restoreXml(DocumentStorage &store)

{
  const Element *el = store.getTag("bfd_savefile");
  if (el == (const Element *)0)
    throw LowlevelError("Could not find bfd_savefile tag");

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
  init(store); // Load the image and configure

  if (iter != list.end()) {
    store.registerTag(*iter);
    SleighArchitecture::restoreXml(store);
  }
}

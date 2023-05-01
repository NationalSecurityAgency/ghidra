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
#include "sleigh_arch.hh"
#include "inject_sleigh.hh"

namespace ghidra {

AttributeId ATTRIB_DEPRECATED = AttributeId("deprecated",136);
AttributeId ATTRIB_ENDIAN = AttributeId("endian",137);
AttributeId ATTRIB_PROCESSOR = AttributeId("processor",138);
AttributeId ATTRIB_PROCESSORSPEC = AttributeId("processorspec",139);
AttributeId ATTRIB_SLAFILE = AttributeId("slafile",140);
AttributeId ATTRIB_SPEC = AttributeId("spec",141);
AttributeId ATTRIB_TARGET = AttributeId("target",142);
AttributeId ATTRIB_VARIANT = AttributeId("variant",143);
AttributeId ATTRIB_VERSION = AttributeId("version",144);

ElementId ELEM_COMPILER = ElementId("compiler",232);
ElementId ELEM_DESCRIPTION = ElementId("description",233);
ElementId ELEM_LANGUAGE = ElementId("language",234);
ElementId ELEM_LANGUAGE_DEFINITIONS = ElementId("language_definitions",235);

map<int4,Sleigh *> SleighArchitecture::translators;
vector<LanguageDescription> SleighArchitecture::description;

FileManage SleighArchitecture::specpaths; // Global specfile manager

/// Parse file attributes from a \<compiler> element
/// \param decoder is the stream decoder
void CompilerTag::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_COMPILER);
  name = decoder.readString(ATTRIB_NAME);
  spec = decoder.readString(ATTRIB_SPEC);
  id = decoder.readString(ATTRIB_ID);
  decoder.closeElement(elemId);
}

/// Parse an ldefs \<language> element
/// \param decoder is the stream decoder
void LanguageDescription::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_LANGUAGE);
  processor = decoder.readString(ATTRIB_PROCESSOR);
  isbigendian = (decoder.readString(ATTRIB_ENDIAN)=="big");
  size = decoder.readSignedInteger(ATTRIB_SIZE);
  variant = decoder.readString(ATTRIB_VARIANT);
  version = decoder.readString(ATTRIB_VERSION);
  slafile = decoder.readString(ATTRIB_SLAFILE);
  processorspec = decoder.readString(ATTRIB_PROCESSORSPEC);
  id = decoder.readString(ATTRIB_ID);
  deprecated = false;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId==ATTRIB_DEPRECATED)
      deprecated = decoder.readBool();
  }
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_DESCRIPTION) {
      decoder.openElement();
      description = decoder.readString(ATTRIB_CONTENT);
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_COMPILER) {
      compilers.emplace_back();
      compilers.back().decode(decoder);
    }
    else if (subId == ELEM_TRUNCATE_SPACE) {
      truncations.emplace_back();
      truncations.back().decode(decoder);
    }
    else {	// Ignore other child elements
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
  }
  decoder.closeElement(elemId);
}

/// Pick out the CompilerTag associated with the desired \e compiler \e id string
/// \param nm is the desired id string
/// \return a reference to the matching CompilerTag
const CompilerTag &LanguageDescription::getCompiler(const string &nm) const

{
  int4 defaultind = -1;
  for(int4 i=0;i<compilers.size();++i) {
    if (compilers[i].getId() == nm)
      return compilers[i];
    if (compilers[i].getId() == "default")
      defaultind = i;
  }
  if (defaultind != -1)                 // If can't match compiler, return default
    return compilers[defaultind];
  return compilers[0];
}

/// \brief Read a SLEIGH .ldefs file
///
/// Any \<language> tags are added to the LanguageDescription array
/// \param specfile is the filename of the .ldefs file
/// \param errs is an output stream for printing error messages
void SleighArchitecture::loadLanguageDescription(const string &specfile,ostream &errs)

{
  ifstream s(specfile.c_str());
  if (!s) return;

  XmlDecode decoder((const AddrSpaceManager *)0);
  try {
    decoder.ingestStream(s);
  }
  catch(DecoderError &err) {
    errs << "WARNING: Unable to parse sleigh specfile: " << specfile;
    return;
  }

  uint4 elemId = decoder.openElement(ELEM_LANGUAGE_DEFINITIONS);
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_LANGUAGE) {
      description.emplace_back();
      description.back().decode( decoder );
    }
    else {
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
  }
  decoder.closeElement(elemId);
}

SleighArchitecture::~SleighArchitecture(void)

{
  translate = (const Translate *)0;
}

string SleighArchitecture::getDescription(void) const

{
  return description[languageindex].getDescription();
}

/// If the current \b languageindex matches the \b last_languageindex,
/// try to reuse the previous Sleigh object, so we don't reload
/// the .sla file.
/// \return \b true if it can be reused
bool SleighArchitecture::isTranslateReused(void)

{
  return (translators.find(languageindex) != translators.end());
}

Translate *SleighArchitecture::buildTranslator(DocumentStorage &store)

{				// Build a sleigh translator
  map<int4,Sleigh *>::const_iterator iter;
  Sleigh *sleigh;
  iter = translators.find(languageindex);
  if (iter != translators.end()) {
    sleigh = (*iter).second;
    sleigh->reset(loader,context);
    return sleigh;
  }
  sleigh = new Sleigh(loader,context);
  translators[languageindex] = sleigh;
  return sleigh;
}

PcodeInjectLibrary *SleighArchitecture::buildPcodeInjectLibrary(void)

{ // Build the pcode injector based on sleigh
  PcodeInjectLibrary *res;

  res = new PcodeInjectLibrarySleigh(this);
  return res;
}

void SleighArchitecture::buildTypegrp(DocumentStorage &store)

{
  const Element *el = store.getTag("coretypes");
  types = new TypeFactory(this); // Initialize the object
  if (el != (const Element *)0) {
    XmlDecode decoder(this,el);
    types->decodeCoreTypes(decoder);
  }
  else {
    // Put in the core types
    types->setCoreType("void",1,TYPE_VOID,false);
    types->setCoreType("bool",1,TYPE_BOOL,false);
    types->setCoreType("uint1",1,TYPE_UINT,false);
    types->setCoreType("uint2",2,TYPE_UINT,false);
    types->setCoreType("uint4",4,TYPE_UINT,false);
    types->setCoreType("uint8",8,TYPE_UINT,false);
    types->setCoreType("int1",1,TYPE_INT,false);
    types->setCoreType("int2",2,TYPE_INT,false);
    types->setCoreType("int4",4,TYPE_INT,false);
    types->setCoreType("int8",8,TYPE_INT,false);
    types->setCoreType("float4",4,TYPE_FLOAT,false);
    types->setCoreType("float8",8,TYPE_FLOAT,false);
    types->setCoreType("float10",10,TYPE_FLOAT,false);
    types->setCoreType("float16",16,TYPE_FLOAT,false);
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->setCoreType("code",1,TYPE_CODE,false);
    types->setCoreType("char",1,TYPE_INT,true);
    types->setCoreType("wchar2",2,TYPE_INT,true);
    types->setCoreType("wchar4",4,TYPE_INT,true);
    types->cacheCoreTypes();
  }
}

void SleighArchitecture::buildCommentDB(DocumentStorage &store)

{
  commentdb = new CommentDatabaseInternal();
}

void SleighArchitecture::buildStringManager(DocumentStorage &store)

{
  stringManager = new StringManagerUnicode(this,2048);
}

void SleighArchitecture::buildConstantPool(DocumentStorage &store)

{
  cpool = new ConstantPoolInternal();
}

void SleighArchitecture::buildContext(DocumentStorage &store)

{
  context = new ContextInternal();
}

void SleighArchitecture::buildSymbols(DocumentStorage &store)

{
  const Element *symtag = store.getTag(ELEM_DEFAULT_SYMBOLS.getName());
  if (symtag == (const Element *)0) return;
  XmlDecode decoder(this,symtag);
  uint4 el = decoder.openElement(ELEM_DEFAULT_SYMBOLS);
  while(decoder.peekElement() != 0) {
    uint4 subel = decoder.openElement(ELEM_SYMBOL);
    Address addr;
    string name;
    int4 size = 0;
    int4 volatileState = -1;
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_NAME)
	name = decoder.readString();
      else if (attribId == ATTRIB_ADDRESS) {
	addr = parseAddressSimple(decoder.readString());
      }
      else if (attribId == ATTRIB_VOLATILE) {
	volatileState = decoder.readBool() ? 1 : 0;
      }
      else if (attribId == ATTRIB_SIZE)
	size = decoder.readSignedInteger();
    }
    decoder.closeElement(subel);
    if (name.size() == 0)
      throw LowlevelError("Missing name attribute in <symbol> element");
    if (addr.isInvalid())
      throw LowlevelError("Missing address attribute in <symbol> element");
    if (size == 0)
      size = addr.getSpace()->getWordSize();
    if (volatileState >= 0) {
      Range range(addr.getSpace(),addr.getOffset(),addr.getOffset() + (size-1));
      if (volatileState == 0)
	symboltab->clearPropertyRange(Varnode::volatil, range);
      else
	symboltab->setPropertyRange(Varnode::volatil, range);
    }
    Datatype *ct = types->getBase(size, TYPE_UNKNOWN);
    Address usepoint;
    symboltab->getGlobalScope()->addSymbol(name, ct, addr, usepoint);
  }
  decoder.closeElement(el);
}

void SleighArchitecture::resolveArchitecture(void)

{ // Find best architecture
  if (archid.size() == 0) {
    if ((target.size()==0)||(target=="default"))
      archid = loader->getArchType();
    else
      archid = target;
  }
  if (archid.find("binary-")==0)
    archid.erase(0,7);
  else if (archid.find("default-")==0)
    archid.erase(0,8);
  
  archid = normalizeArchitecture(archid);
  string baseid = archid.substr(0,archid.rfind(':'));
  int4 i;
  languageindex = -1;
  for(i=0;i<description.size();++i) {
    if (description[i].getId() == baseid) {
      languageindex = i;
      if (description[i].isDeprecated())
        printMessage("WARNING: Language "+baseid+" is deprecated");
      break;
    }
  }
  
  if (languageindex == -1)
    throw LowlevelError("No sleigh specification for "+baseid);
}

void SleighArchitecture::buildSpecFile(DocumentStorage &store)

{ // Given a specific language, make sure relevant spec files are loaded
  bool language_reuse = isTranslateReused();
  const LanguageDescription &language(description[languageindex]);
  string compiler = archid.substr(archid.rfind(':')+1);
  const CompilerTag &compilertag( language.getCompiler(compiler));
  
  string processorfile;
  string compilerfile;
  string slafile;
  
  specpaths.findFile(processorfile,language.getProcessorSpec());
  specpaths.findFile(compilerfile,compilertag.getSpec());
  if (!language_reuse)
    specpaths.findFile(slafile,language.getSlaFile());
  
  try {
    Document *doc = store.openDocument(processorfile);
    store.registerTag(doc->getRoot());
  }
  catch(DecoderError &err) {
    ostringstream serr;
    serr << "XML error parsing processor specification: " << processorfile;
    serr << "\n " << err.explain;
    throw SleighError(serr.str());
  }
  catch(LowlevelError &err) {
    ostringstream serr;
    serr << "Error reading processor specification: " << processorfile;
    serr << "\n " << err.explain;
    throw SleighError(serr.str());
  }
  
  try {
    Document *doc = store.openDocument(compilerfile);
    store.registerTag(doc->getRoot());
  }
  catch(DecoderError &err) {
    ostringstream serr;
    serr << "XML error parsing compiler specification: " << compilerfile;
    serr << "\n " << err.explain;
    throw SleighError(serr.str());
  }
  catch(LowlevelError &err) {
    ostringstream serr;
    serr << "Error reading compiler specification: " << compilerfile;
    serr << "\n " << err.explain;
    throw SleighError(serr.str());
  }

  if (!language_reuse) {
    try {
      Document *doc = store.openDocument(slafile);
      store.registerTag(doc->getRoot());
    }
    catch(DecoderError &err) {
      ostringstream serr;
      serr << "XML error parsing SLEIGH file: " << slafile;
      serr << "\n " << err.explain;
      throw SleighError(serr.str());
    }
    catch(LowlevelError &err) {
      ostringstream serr;
      serr << "Error reading SLEIGH file: " << slafile;
      serr << "\n " << err.explain;
      throw SleighError(serr.str());
    }
  }
}

void SleighArchitecture::modifySpaces(Translate *trans)

{
  const LanguageDescription &language(description[languageindex]);
  for(int4 i=0;i<language.numTruncations();++i) {
    trans->truncateSpace(language.getTruncation(i));
  }
}

/// Prepare \b this SleighArchitecture for analyzing the given executable image.
/// Full initialization, including creation of the Translate object, still must be
/// performed by calling the init() method.
/// \param fname is the filename of the given executable image
/// \param targ is the optional \e language \e id or other target information
/// \param estream is a pointer to an output stream for writing error messages
SleighArchitecture::SleighArchitecture(const string &fname,const string &targ,ostream *estream)
  : Architecture()

{
  filename = fname;
  target = targ;
  errorstream = estream;
}

/// This is run once when spinning up the decompiler.
/// Look for the root .ldefs files within the normal directories and parse them.
/// Use these to populate the list of \e language \e ids that are supported.
/// \param errs is an output stream for writing error messages
void SleighArchitecture::collectSpecFiles(ostream &errs)

{
  if (!description.empty()) return; // Have we already collected before

  vector<string> testspecs;
  vector<string>::iterator iter;
  specpaths.matchList(testspecs,".ldefs",true);
  for(iter=testspecs.begin();iter!=testspecs.end();++iter)
    loadLanguageDescription(*iter,errs);
}

/// \param encoder is the stream encoder
void SleighArchitecture::encodeHeader(Encoder &encoder) const

{
  encoder.writeString(ATTRIB_NAME, filename);
  encoder.writeString(ATTRIB_TARGET, target);
}

/// \param el is the root XML element
void SleighArchitecture::restoreXmlHeader(const Element *el)

{
  filename = el->getAttributeValue("name");
  target = el->getAttributeValue("target");
}

/// Given an architecture target string try to recover an
/// appropriate processor name for use in a normalized \e language \e id.
/// \param nm is the given target string
/// \return the processor field
string SleighArchitecture::normalizeProcessor(const string &nm)

{
  if (nm.find("386")!=string::npos)
    return "x86";
  return nm;
}

/// Given an architecture target string try to recover an
/// appropriate endianness string for use in a normalized \e language \e id.
/// \param nm is the given target string
/// \return the endianness field
string SleighArchitecture::normalizeEndian(const string &nm)

{
  if (nm.find("big")!=string::npos)
    return "BE";
  if (nm.find("little")!=string::npos)
    return "LE";
  return nm;
}

/// Given an architecture target string try to recover an
/// appropriate size string for use in a normalized \e language \e id.
/// \param nm is the given target string
/// \return the size field
string SleighArchitecture::normalizeSize(const string &nm)

{
  string res = nm;
  string::size_type pos;
  
  pos = res.find("bit");
  if (pos != string::npos)
    res.erase(pos,3);
  pos = res.find('-');
  if (pos != string::npos)
    res.erase(pos,1);
  return res;
}

/// Try to normalize the target string into a valid \e language \e id.
/// In general the target string must already look like a \e language \e id,
/// but it can drop the compiler field and be a little sloppier in its format.
/// \param nm is the given target string
/// \return the normalized \e language \e id
string SleighArchitecture::normalizeArchitecture(const string &nm)

{
  string processor;
  string endian;
  string size;
  string variant;
  string compile;
  
  string::size_type pos[4];
  int4 i;
  string::size_type curpos=0;
  for(i=0;i<4;++i) {
    curpos = nm.find(':',curpos+1);
    if (curpos == string::npos) break;
    pos[i] = curpos;
  }
  if ((i!=3)&&(i!=4))
    throw LowlevelError("Architecture string does not look like sleigh id: "+nm);
  processor = nm.substr(0,pos[0]);
  endian = nm.substr(pos[0]+1,pos[1]-pos[0]-1);
  size = nm.substr(pos[1]+1,pos[2]-pos[1]-1);
  
  if (i==4) {
    variant = nm.substr(pos[2]+1,pos[3]-pos[2]-1);
    compile = nm.substr(pos[3]+1);
  }
  else {
    variant = nm.substr(pos[2]+1);
    compile = "default";
  }
  
  processor = normalizeProcessor(processor);
  endian = normalizeEndian(endian);
  size = normalizeSize(size);
  return processor + ':' + endian + ':' + size + ':' + variant + ':' + compile;
}

/// \brief Scan directories for SLEIGH specification files
///
/// This assumes a standard "Ghidra/Processors/*/data/languages" layout.  It
/// scans for all matching directories and prepares for reading .ldefs files.
/// \param rootpath is the root path of the Ghidra installation
void SleighArchitecture::scanForSleighDirectories(const string &rootpath)

{
  vector<string> ghidradir;
  vector<string> procdir;
  vector<string> procdir2;
  vector<string> languagesubdirs;

  FileManage::scanDirectoryRecursive(ghidradir,"Ghidra",rootpath,2);
  for(uint4 i=0;i<ghidradir.size();++i) {
    FileManage::scanDirectoryRecursive(procdir,"Processors",ghidradir[i],1); // Look for Processors structure
    FileManage::scanDirectoryRecursive(procdir,"contrib",ghidradir[i],1);
  }
  if (procdir.size()!=0) {
    for(uint4 i=0;i<procdir.size();++i)
      FileManage::directoryList(procdir2,procdir[i]);

    vector<string> datadirs;
    for(uint4 i=0;i<procdir2.size();++i)
      FileManage::scanDirectoryRecursive(datadirs,"data",procdir2[i],1);
    
    vector<string> languagedirs;
    for(uint4 i=0;i<datadirs.size();++i)
      FileManage::scanDirectoryRecursive(languagedirs,"languages",datadirs[i],1);
    
    for(uint4 i=0;i<languagedirs.size();++i)
      languagesubdirs.push_back( languagedirs[i] );

    // In the old version we have to go down one more level to get to the ldefs
    for(uint4 i=0;i<languagedirs.size();++i)
      FileManage::directoryList(languagesubdirs,languagedirs[i]);
  }
  // If we haven't matched this directory structure, just use the rootpath as the directory containing
  // the ldef
  if (languagesubdirs.size() == 0)
    languagesubdirs.push_back( rootpath );

  for(uint4 i=0;i<languagesubdirs.size();++i)
    specpaths.addDir2Path(languagesubdirs[i]);
}

/// Parse all .ldef files and a return the list of all LanguageDescription objects
/// If there are any parse errors in the .ldef files, an exception is thrown
/// \return the list of LanguageDescription objects
const vector<LanguageDescription> &SleighArchitecture::getDescriptions(void)

{
  ostringstream s;
  collectSpecFiles(s);
  if (!s.str().empty())
    throw LowlevelError(s.str());
  return description;
}

void SleighArchitecture::shutdown(void)

{
  if (translators.empty()) return;	// Already cleared
  for(map<int4,Sleigh *>::const_iterator iter=translators.begin();iter!=translators.end();++iter)
    delete (*iter).second;
  translators.clear();
  // description.clear();  // static vector is destroyed by the normal exit handler
}

} // End namespace ghidra

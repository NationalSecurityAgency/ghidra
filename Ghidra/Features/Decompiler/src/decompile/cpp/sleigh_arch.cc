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

Sleigh *SleighArchitecture::last_sleigh = (Sleigh *)0;
int4 SleighArchitecture::last_languageindex;
vector<LanguageDescription> SleighArchitecture::description;

FileManage SleighArchitecture::specpaths; // Global specfile manager

/// Read file attributes from an XML \<compiler> tag
/// \param el is the XML element
void CompilerTag::restoreXml(const Element *el)

{
  name = el->getAttributeValue("name");
  spec = el->getAttributeValue("spec");
  id = el->getAttributeValue("id");
}

/// Parse an ldefs \<language> tag
/// \param el is the XML element
void LanguageDescription::restoreXml(const Element *el)

{
  processor = el->getAttributeValue("processor");
  isbigendian = (el->getAttributeValue("endian")=="big");
  istringstream s1(el->getAttributeValue("size"));
  s1.unsetf(ios::dec | ios::hex | ios::oct);
  s1 >> size;
  variant = el->getAttributeValue("variant");
  version = el->getAttributeValue("version");
  slafile = el->getAttributeValue("slafile");
  processorspec = el->getAttributeValue("processorspec");
  id = el->getAttributeValue("id");
  deprecated = false;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i)=="deprecated")
      deprecated = xml_readbool(el->getAttributeValue(i)); 
  }
  const List &sublist(el->getChildren());
  List::const_iterator subiter;
  for(subiter=sublist.begin();subiter!=sublist.end();++subiter) {
    const Element *subel = *subiter;
    if (subel->getName() == "description")
      description = subel->getContent();
    else if (subel->getName() == "compiler") {
      compilers.emplace_back();
      compilers.back().restoreXml(subel);
    }
    else if (subel->getName() == "truncate_space") {
      truncations.emplace_back();
      truncations.back().restoreXml(subel);
    }
  }
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

  Document *doc;
  Element *el;
  try {
    doc = xml_tree(s);
  }
  catch(XmlError &err) {
    errs << "WARNING: Unable to parse sleigh specfile: " << specfile;
    return;
  }

  el = doc->getRoot();
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) {
    if ((*iter)->getName() != "language") continue;
    description.emplace_back();
    description.back().restoreXml( *iter );
  }
  delete doc;
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
  if (last_sleigh == (Sleigh *)0) return false;
  if (last_languageindex == languageindex) return true;
  delete last_sleigh;		// It doesn't match so free old Translate
  last_sleigh = (Sleigh *)0;
  return false;
}

Translate *SleighArchitecture::buildTranslator(DocumentStorage &store)

{				// Build a sleigh translator
  if (isTranslateReused()) {
    last_sleigh->reset(loader,context);
    return last_sleigh;
  }
  else {
    last_sleigh = new Sleigh(loader,context);
    last_languageindex = languageindex;
    return last_sleigh;
  }
}

PcodeInjectLibrary *SleighArchitecture::buildPcodeInjectLibrary(void)

{ // Build the pcode injector based on sleigh
  PcodeInjectLibrary *res;

  res = new PcodeInjectLibrarySleigh(this,translate->getUniqueBase());
  return res;
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
  catch(XmlError &err) {
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
  catch(XmlError &err) {
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
    catch(XmlError &err) {
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

/// \param s is the XML output stream
void SleighArchitecture::saveXmlHeader(ostream &s) const

{
  a_v(s,"name",filename);
  a_v(s,"target",target);
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

void SleighArchitecture::shutdown(void)

{
  if (last_sleigh != (Sleigh *)0) {
    delete last_sleigh;
    last_sleigh = (Sleigh *)0;
  }
  // description.clear();  // static vector is destroyed by the normal exit handler
}

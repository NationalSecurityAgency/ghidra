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
// Set up decompiler for specific architectures

#include "coreaction.hh"
#include "flow.hh"
#ifdef CPUI_RULECOMPILE
#include "rulecompile.hh"
#endif
#ifdef CPUI_STATISTICS
#include <cmath>
#endif

namespace ghidra {

#ifdef CPUI_STATISTICS
using std::sqrt;
#endif

vector<ArchitectureCapability *> ArchitectureCapability::thelist;

const uint4 ArchitectureCapability::majorversion = 5;
const uint4 ArchitectureCapability::minorversion = 0;

AttributeId ATTRIB_ADDRESS = AttributeId("address",148);
AttributeId ATTRIB_ADJUSTVMA = AttributeId("adjustvma",103);
AttributeId ATTRIB_ENABLE = AttributeId("enable",104);
AttributeId ATTRIB_GROUP = AttributeId("group",105);
AttributeId ATTRIB_GROWTH = AttributeId("growth",106);
AttributeId ATTRIB_KEY = AttributeId("key",107);
AttributeId ATTRIB_LOADERSYMBOLS = AttributeId("loadersymbols",108);
AttributeId ATTRIB_PARENT = AttributeId("parent",109);
AttributeId ATTRIB_REGISTER = AttributeId("register",110);
AttributeId ATTRIB_REVERSEJUSTIFY = AttributeId("reversejustify",111);
AttributeId ATTRIB_SIGNEXT = AttributeId("signext",112);
AttributeId ATTRIB_STYLE = AttributeId("style",113);

ElementId ELEM_ADDRESS_SHIFT_AMOUNT = ElementId("address_shift_amount",130);
ElementId ELEM_AGGRESSIVETRIM = ElementId("aggressivetrim",131);
ElementId ELEM_COMPILER_SPEC = ElementId("compiler_spec",132);
ElementId ELEM_DATA_SPACE = ElementId("data_space",133);
ElementId ELEM_DEFAULT_MEMORY_BLOCKS = ElementId("default_memory_blocks",134);
ElementId ELEM_DEFAULT_PROTO = ElementId("default_proto",135);
ElementId ELEM_DEFAULT_SYMBOLS = ElementId("default_symbols",136);
ElementId ELEM_EVAL_CALLED_PROTOTYPE = ElementId("eval_called_prototype",137);
ElementId ELEM_EVAL_CURRENT_PROTOTYPE = ElementId("eval_current_prototype",138);
ElementId ELEM_EXPERIMENTAL_RULES = ElementId("experimental_rules",139);
ElementId ELEM_FLOWOVERRIDELIST = ElementId("flowoverridelist",140);
ElementId ELEM_FUNCPTR = ElementId("funcptr",141);
ElementId ELEM_GLOBAL = ElementId("global",142);
ElementId ELEM_INCIDENTALCOPY = ElementId("incidentalcopy",143);
ElementId ELEM_INFERPTRBOUNDS = ElementId("inferptrbounds",144);
ElementId ELEM_MODELALIAS = ElementId("modelalias",145);
ElementId ELEM_NOHIGHPTR = ElementId("nohighptr",146);
ElementId ELEM_PROCESSOR_SPEC = ElementId("processor_spec",147);
ElementId ELEM_PROGRAMCOUNTER = ElementId("programcounter",148);
ElementId ELEM_PROPERTIES = ElementId("properties",149);
ElementId ELEM_PROPERTY = ElementId("property",150);
ElementId ELEM_READONLY = ElementId("readonly",151);
ElementId ELEM_REGISTER_DATA = ElementId("register_data",152);
ElementId ELEM_RULE = ElementId("rule",153);
ElementId ELEM_SAVE_STATE = ElementId("save_state",154);
ElementId ELEM_SEGMENTED_ADDRESS = ElementId("segmented_address",155);
ElementId ELEM_SPACEBASE = ElementId("spacebase",156);
ElementId ELEM_SPECEXTENSIONS = ElementId("specextensions",157);
ElementId ELEM_STACKPOINTER = ElementId("stackpointer",158);
ElementId ELEM_VOLATILE = ElementId("volatile",159);

/// This builds a list of just the ArchitectureCapability extensions
void ArchitectureCapability::initialize(void)

{
  thelist.push_back(this);
}

/// Given a specific file, find an ArchitectureCapability that can handle it.
/// \param filename is the path to the file
/// \return an ArchitectureCapability that can handle it or NULL
ArchitectureCapability *ArchitectureCapability::findCapability(const string &filename)

{
  for(uint4 i=0;i<thelist.size();++i) {
    ArchitectureCapability *capa = thelist[i];
    if (capa->isFileMatch(filename))
      return capa;
  }
  return (ArchitectureCapability *)0;
}

/// Given a parsed XML document, find an ArchitectureCapability that can handle it.
/// \param doc is the parsed XML document
/// \return an ArchitectureCapability that can handle it or NULL
ArchitectureCapability *ArchitectureCapability::findCapability(Document *doc)

{
  for(uint4 i=0;i<thelist.size();++i) {
    ArchitectureCapability *capa = thelist[i];
    if (capa->isXmlMatch(doc))
      return capa;
  }
  return (ArchitectureCapability *)0;
}

/// Return the ArchitectureCapability object with the matching name
/// \param name is the name to match
/// \return the ArchitectureCapability or null if no match is found
ArchitectureCapability *ArchitectureCapability::getCapability(const string &name)

{
  for(int4 i=0;i<thelist.size();++i) {
    ArchitectureCapability *res = thelist[i];
    if (res->getName() == name)
      return res;
  }
  return (ArchitectureCapability *)0;
}

/// Modify order that extensions are searched, to effect which gets a chance
/// to run first.
/// Right now all we need to do is make sure the raw architecture comes last
void ArchitectureCapability::sortCapabilities(void)

{
  uint4 i;
  for(i=0;i<thelist.size();++i) {
    if (thelist[i]->getName() == "raw") break;
  }
  if (i==thelist.size()) return;
  ArchitectureCapability *capa = thelist[i];
  for(uint4 j=i+1;j<thelist.size();++j)
    thelist[j-1] = thelist[j];
  thelist[ thelist.size()-1 ] = capa;
}

/// Set most sub-components to null pointers. Provide reasonable defaults
/// for the configurable options
Architecture::Architecture(void)

{
  //  endian = -1;
  resetDefaultsInternal();
  min_funcsymbol_size = 1;
  aggressive_ext_trim = false;
  funcptr_align = 0;
  defaultfp = (ProtoModel *)0;
  defaultReturnAddr.space = (AddrSpace *)0;
  evalfp_current = (ProtoModel *)0;
  evalfp_called = (ProtoModel *)0;
  types = (TypeFactory *)0;
  translate = (Translate *)0;
  loader = (LoadImage *)0;
  pcodeinjectlib = (PcodeInjectLibrary *)0;
  commentdb = (CommentDatabase *)0;
  stringManager = (StringManager *)0;
  cpool = (ConstantPool *)0;
  symboltab = (Database *)0;
  context = (ContextDatabase *)0;
  print = PrintLanguageCapability::getDefault()->buildLanguage(this);
  printlist.push_back(print);
  options = new OptionDatabase(this);
  loadersymbols_parsed = false;
#ifdef CPUI_STATISTICS
  stats = new Statistics();
#endif
#ifdef OPACTION_DEBUG
  debugstream = (ostream *)0;
#endif
}

/// Release resources for all sub-components
Architecture::~Architecture(void)

{				// Delete anything that was allocated
  vector<TypeOp *>::iterator iter;
  TypeOp *t_op;

  for(iter=inst.begin();iter!=inst.end();++iter) {
    t_op = *iter;
    if (t_op != (TypeOp *)0)
      delete t_op;
  }
  for(int4 i=0;i<extra_pool_rules.size();++i)
    delete extra_pool_rules[i];

  if (symboltab != (Database *)0)
    delete symboltab;
  for(int4 i=0;i<(int4)printlist.size();++i)
    delete printlist[i];
  delete options;
#ifdef CPUI_STATISTICS
  delete stats;
#endif

  map<string,ProtoModel *>::const_iterator piter;
  for(piter=protoModels.begin();piter!=protoModels.end();++piter)
    delete (*piter).second;

  if (types != (TypeFactory *)0)
    delete types;
  if (translate != (Translate *)0)
    delete translate;
  if (loader != (LoadImage *)0)
    delete loader;
  if (pcodeinjectlib != (PcodeInjectLibrary *)0)
    delete pcodeinjectlib;
  if (commentdb != (CommentDatabase *)0)
    delete commentdb;
  if (stringManager != (StringManager *)0)
    delete stringManager;
  if (cpool != (ConstantPool *)0)
    delete cpool;
  if (context != (ContextDatabase *)0)
    delete context;
}

/// The Architecture maintains the set of prototype models that can
/// be applied for this particular executable. Retrieve one by name.
/// If the model doesn't exist, null is returned.
/// \param nm is the name
/// \return the matching model or null
ProtoModel *Architecture::getModel(const string &nm) const

{
  map<string,ProtoModel *>::const_iterator iter;

  iter = protoModels.find(nm);
  if (iter==protoModels.end())
    return (ProtoModel *)0;
  return (*iter).second;
}

/// \param nm is the name of the model
/// \return \b true if this Architecture supports a model with that name
bool Architecture::hasModel(const string &nm) const

{ // Does this architecture have a prototype model of this name
  map<string,ProtoModel *>::const_iterator iter;

  iter = protoModels.find(nm);
  return (iter != protoModels.end());
}

/// Get the address space associated with the indicated
/// \e spacebase register. I.e. if the location of the
/// \e stack \e pointer is passed in, this routine would return
/// a pointer to the \b stack space. An exception is thrown
/// if no corresponding space is found.
/// \param loc is the location of the \e spacebase register
/// \param size is the size of the register in bytes
/// \return a pointer to the address space
AddrSpace *Architecture::getSpaceBySpacebase(const Address &loc,int4 size) const

{
  AddrSpace *id;
  int4 sz = numSpaces();
  for(int4 i=0;i<sz;++i) {
    id = getSpace(i);
    if (id == (AddrSpace *)0) continue;
    int4 numspace = id->numSpacebase();
    for(int4 j=0;j<numspace;++j) {
      const VarnodeData &point(id->getSpacebase(j));
      if (point.size != size) continue;
      if (point.space != loc.getSpace()) continue;
      if (point.offset != loc.getOffset()) continue;
      return id;
    }
  }
  throw LowlevelError("Unable to find entry for spacebase register");
}

/// Look-up the laned register record associated with a specific storage location. Currently, the
/// record is only associated with the \e size of the storage, not its address. If there is no
/// associated record, null is returned.
/// \param loc is the starting address of the storage location
/// \param size is the size of the storage in bytes
/// \return the matching LanedRegister record or null
const LanedRegister *Architecture::getLanedRegister(const Address &loc,int4 size) const

{
  int4 min = 0;
  int4 max = lanerecords.size() - 1;
  while(min <= max) {
    int4 mid = (min + max) / 2;
    int4 sz = lanerecords[mid].getWholeSize();
    if (sz < size)
      min = mid + 1;
    else if (size < sz)
      max = mid - 1;
    else
      return &lanerecords[mid];
  }
  return (const LanedRegister *)0;
}

/// Return a size intended for comparison with a Varnode size to immediately determine if
/// the Varnode is a potential laned register. If there are no laned registers for the architecture,
/// -1 is returned.
/// \return the size in bytes of the smallest laned register or -1.
int4 Architecture::getMinimumLanedRegisterSize(void) const

{
  if (lanerecords.empty())
    return -1;
  return lanerecords[0].getWholeSize();
}

/// The default model is used whenever an explicit model is not known
/// or can't be determined.
/// \param model is the ProtoModel object to make the default
void Architecture::setDefaultModel(ProtoModel *model)

{
  if (defaultfp != (ProtoModel *)0)
    defaultfp->setPrintInDecl(true);
  model->setPrintInDecl(false);
  defaultfp = model;
}

/// Throw out the syntax tree, (unlocked) symbols, comments, and other derived information
/// about a single function.
/// \param fd is the function to clear
void Architecture::clearAnalysis(Funcdata *fd)

{
  fd->clear();			// Clear stuff internal to function
  // Clear out any analysis generated comments
  commentdb->clearType(fd->getAddress(),Comment::warning|Comment::warningheader);
}

/// Symbols do not necessarily need to be available for the decompiler.
/// This routine loads all the \e load \e image knows about into the symbol table
/// \param delim is the delimiter separating namespaces from symbol base names
void Architecture::readLoaderSymbols(const string &delim)

{
  if (loadersymbols_parsed) return; // already read
  loader->openSymbols();
  loadersymbols_parsed = true;
  LoadImageFunc record;
  while(loader->getNextSymbol(record)) {
    string basename;
    Scope *scope = symboltab->findCreateScopeFromSymbolName(record.name, delim, basename, (Scope *)0);
    scope->addFunction(record.address,basename);
  }
  loader->closeSymbols();
}

/// For all registered p-code opcodes, return the corresponding OpBehavior object.
/// The object pointers are provided in a list indexed by OpCode.
/// \param behave is the list to be populated
void Architecture::collectBehaviors(vector<OpBehavior *> &behave) const

{
  behave.resize(inst.size(), (OpBehavior *)0);
  for(int4 i=0;i<inst.size();++i) {
    TypeOp *op = inst[i];
    if (op == (TypeOp *)0) continue;
    behave[i] = op->getBehavior();
  }
}

/// This method searches for a user-defined segment op registered
/// for the given space.
/// \param spc is the address space to check
/// \return the SegmentOp object or null
SegmentOp *Architecture::getSegmentOp(AddrSpace *spc) const

{
  if (spc->getIndex() >= userops.numSegmentOps()) return (SegmentOp *)0;
  SegmentOp *segdef = userops.getSegmentOp(spc->getIndex());
  if (segdef == (SegmentOp *)0) return (SegmentOp *)0;
  if (segdef->getResolve().space != (AddrSpace *)0)
    return segdef;
  return (SegmentOp *)0;
}

/// Establish details of the prototype for a given function symbol
/// \param pieces holds the raw prototype information and the symbol name
void Architecture::setPrototype(const PrototypePieces &pieces)

{
  string basename;
  Scope *scope = symboltab->resolveScopeFromSymbolName(pieces.name, "::", basename, (Scope *)0);
  if (scope == (Scope *)0)
    throw ParseError("Unknown namespace: " + pieces.name);
  Funcdata *fd = scope->queryFunction( basename );
  if (fd == (Funcdata *)0)
    throw ParseError("Unknown function name: " + pieces.name);

  fd->getFuncProto().setPieces(pieces);
}

/// The decompiler supports one or more output languages (C, Java). This method
/// does the main work of selecting one of the supported languages.
/// In addition to selecting the main PrintLanguage object, this triggers
/// configuration of the cast strategy and p-code op behaviors.
/// \param nm is the name of the language
void Architecture::setPrintLanguage(const string &nm)

{
  for(int4 i=0;i<(int4)printlist.size();++i) {
    if (printlist[i]->getName() == nm) {
      print = printlist[i];
      print->adjustTypeOperators();
      return;
    }
  }
  PrintLanguageCapability *capa = PrintLanguageCapability::findCapability(nm);
  if (capa == (PrintLanguageCapability *)0)
    throw LowlevelError("Unknown print language: "+nm);
  bool printMarkup = print->emitsMarkup(); // Copy settings for current print language
  ostream *t = print->getOutputStream();
  print = capa->buildLanguage(this);
  print->setOutputStream(t);	// Restore settings from previous language
  print->initializeFromArchitecture();
  if (printMarkup)
    print->setMarkup(true);
  printlist.push_back(print);
  print->adjustTypeOperators();
  return;
}

/// Set all IPTR_PROCESSOR and IPTR_SPACEBASE spaces to be global
void Architecture::globalify(void)

{
  Scope *scope = symboltab->getGlobalScope();
  int4 nm = numSpaces();

  for(int4 i=0;i<nm;++i) {
    AddrSpace *spc = getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    if ((spc->getType() != IPTR_PROCESSOR)&&(spc->getType() != IPTR_SPACEBASE)) continue;
    symboltab->addRange(scope,spc,(uintb)0,spc->getHighest());
  }
}

/// Insert a series of out-of-band flow overrides based on a \<flowoverridelist> element.
/// \param decoder is the stream decoder
void Architecture::decodeFlowOverride(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_FLOWOVERRIDELIST);
  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId != ELEM_FLOW) break;
    string flowType = decoder.readString(ATTRIB_TYPE);
    Address funcaddr = Address::decode(decoder);
    Address overaddr = Address::decode(decoder);
    Funcdata *fd = symboltab->getGlobalScope()->queryFunction(funcaddr);
    if (fd != (Funcdata *)0)
      fd->getOverride().insertFlowOverride(overaddr,Override::stringToType(flowType));
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

/// Write the current state of all types, symbols, functions, etc. to a stream.
/// \param encoder is the stream encoder
void Architecture::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_SAVE_STATE);
  encoder.writeBool(ATTRIB_LOADERSYMBOLS, loadersymbols_parsed);
  types->encode(encoder);
  symboltab->encode(encoder);
  context->encode(encoder);
  commentdb->encode(encoder);
  stringManager->encode(encoder);
  if (!cpool->empty())
    cpool->encode(encoder);
  encoder.closeElement(ELEM_SAVE_STATE);
}

/// Read in all the sub-component state from a \<save_state> XML tag
/// When adding stuff to this BEWARE: The spec file has already initialized stuff
/// \param store is document store containing the parsed root tag
void Architecture::restoreXml(DocumentStorage &store)

{
  const Element *el = store.getTag(ELEM_SAVE_STATE.getName());
  if (el == (const Element *)0)
    throw LowlevelError("Could not find save_state tag");
  XmlDecode decoder(this,el);
  uint4 elemId = decoder.openElement(ELEM_SAVE_STATE);
  loadersymbols_parsed = false;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_LOADERSYMBOLS)
      loadersymbols_parsed = decoder.readBool();
  }

  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_TYPEGRP)
      types->decode(decoder);
    else if (subId == ELEM_DB)
      symboltab->decode(decoder);
    else if (subId == ELEM_CONTEXT_POINTS)
      context->decode(decoder);
    else if (subId == ELEM_COMMENTDB)
      commentdb->decode(decoder);
    else if (subId == ELEM_STRINGMANAGE)
      stringManager->decode(decoder);
    else if (subId == ELEM_CONSTANTPOOL)
      cpool->decode(decoder,*types);
    else if (subId == ELEM_OPTIONSLIST)
      options->decode(decoder);
    else if (subId == ELEM_FLOWOVERRIDELIST)
      decodeFlowOverride(decoder);
    else if (subId == ELEM_INJECTDEBUG)
      pcodeinjectlib->decodeDebug(decoder);
    else
      throw LowlevelError("XML error restoring architecture");
  }
  decoder.closeElement(elemId);
}

/// If no better name is available, this method can be used to generate
/// a function name based on its address
/// \param addr is the address of the function
/// \param name will hold the constructed name
void Architecture::nameFunction(const Address &addr,string &name) const

{
  ostringstream defname;
  defname << "func_";
  addr.printRaw(defname);
  name = defname.str();
}

/// \brief Create a new address space associated with a pointer register
///
/// This process sets up a \e register \e relative"space for this architecture.
/// If indicated, this space takes on the role of the \e formal stack space.
/// Should only be called once during initialization.
/// \param basespace is the address space underlying the stack
/// \param nm is the name of the new space
/// \param ptrdata is the register location acting as a pointer into the new space
/// \param truncSize is the (possibly truncated) size of the register that fits the space
/// \param isreversejustified is \b true if small variables are justified opposite of endianness
/// \param stackGrowth is \b true if a stack implemented in this space grows in the negative direction
/// \param isFormal is the indicator for the \b formal stack space
void Architecture::addSpacebase(AddrSpace *basespace,const string &nm,const VarnodeData &ptrdata,
				int4 truncSize,bool isreversejustified,bool stackGrowth,bool isFormal)

{
  int4 ind = numSpaces();
  
  SpacebaseSpace *spc = new SpacebaseSpace(this,translate,nm,ind,truncSize,basespace,ptrdata.space->getDelay()+1,isFormal);
  if (isreversejustified)
    setReverseJustified(spc);
  insertSpace(spc);
  addSpacebasePointer(spc,ptrdata,truncSize,stackGrowth);
}

/// This routine is used by the initialization process to add
/// address ranges to which there is never an (indirect) pointer
/// Should only be called during initialization
/// \param rng is the new range with no aliases to be added
void Architecture::addNoHighPtr(const Range &rng)

{
  nohighptr.insertRange(rng.getSpace(),rng.getFirst(),rng.getLast());
}

/// This builds the \e universal Action for function transformation
/// and instantiates the "decompile" root Action
/// \param store may hold configuration information
void Architecture::buildAction(DocumentStorage &store)

{
  parseExtraRules(store);	// Look for any additional rules
  allacts.universalAction(this);
  allacts.resetDefaults();
}

/// Create the database object, which currently doesn't not depend on any configuration
/// data.  Then create the root (global) scope and attach it to the database.
/// \param store is the storage for any configuration data
/// \return the global Scope object
Scope *Architecture::buildDatabase(DocumentStorage &store)

{
  symboltab = new Database(this,true);
  Scope *globscope = new ScopeInternal(0,"",this);
  symboltab->attachScope(globscope,(Scope *)0);
  return globscope;
}

/// This registers the OpBehavior objects for all known p-code OpCodes.
/// The Translate and TypeFactory object should already be built.
/// \param store may hold configuration information
void Architecture::buildInstructions(DocumentStorage &store)

{
  TypeOp::registerInstructions(inst,types,translate);
}

void Architecture::postSpecFile(void)

{
  cacheAddrSpaceProperties();
}

/// Once the processor is known, the Translate object can be built and
/// fully initialized. Processor and compiler specific configuration is performed
/// \param store will hold parsed configuration information
void Architecture::restoreFromSpec(DocumentStorage &store)

{
  Translate *newtrans = buildTranslator(store); // Once language is described we can build translator
  newtrans->initialize(store);
  translate = newtrans;
  modifySpaces(newtrans);	// Give architecture chance to modify spaces, before copying
  copySpaces(newtrans);
  insertSpace( new FspecSpace(this,translate,numSpaces()));
  insertSpace( new IopSpace(this,translate,numSpaces()));
  insertSpace( new JoinSpace(this,translate,numSpaces()));
  userops.initialize(this);
  if (translate->getAlignment() <= 8)
    min_funcsymbol_size = translate->getAlignment();
  pcodeinjectlib = buildPcodeInjectLibrary();
  parseProcessorConfig(store);
  newtrans->setDefaultFloatFormats(); // If no explicit formats registered, put in defaults
  parseCompilerConfig(store);
  // Action stuff will go here
  buildAction(store);
}

/// If any address space supports near pointers and segment operators,
/// setup SegmentedResolver objects that can be used to recover full pointers in context.
void Architecture::initializeSegments(void)

{
  int4 sz = userops.numSegmentOps();
  for(int4 i=0;i<sz;++i) {
    SegmentOp *sop = userops.getSegmentOp(i);
    if (sop == (SegmentOp *)0) continue;
    SegmentedResolver *rsolv = new SegmentedResolver(this,sop->getSpace(),sop);
    insertResolver(sop->getSpace(),rsolv);
  }
}

/// Determine the minimum pointer size for the space and whether or not there are near pointers.
/// Set up an ordered list of inferable spaces (where constant pointers can be infered).
/// Inferable spaces include the default space and anything explicitly listed
/// in the cspec \<global> tag that is not a register space. An initial list of potential spaces is
/// passed in that needs to be ordered, filtered, and deduplicated.
void Architecture::cacheAddrSpaceProperties(void)

{
  vector<AddrSpace *> copyList = inferPtrSpaces;
  copyList.push_back(getDefaultCodeSpace());	// Make sure the default code space is present
  copyList.push_back(getDefaultDataSpace());	// Make sure the default data space is present
  inferPtrSpaces.clear();
  sort(copyList.begin(),copyList.end(),AddrSpace::compareByIndex);
  AddrSpace *lastSpace = (AddrSpace *)0;
  for(int4 i=0;i<copyList.size();++i) {
    AddrSpace *spc = copyList[i];
    if (spc == lastSpace) continue;
    lastSpace = spc;
    if (spc->getDelay() == 0) continue;		// Don't put in a register space
    if (spc->getType() == IPTR_SPACEBASE) continue;
    if (spc->isOtherSpace()) continue;
    if (spc->isOverlay()) continue;
    inferPtrSpaces.push_back(spc);
  }

  int4 defPos = -1;
  for(int4 i=0;i<inferPtrSpaces.size();++i) {
    AddrSpace *spc = inferPtrSpaces[i];
    if (spc == getDefaultDataSpace())		// Make the default for inferring pointers the data space
      defPos = i;
    SegmentOp *segOp = getSegmentOp(spc);
    if (segOp != (SegmentOp *)0) {
      int4 val = segOp->getInnerSize();
      markNearPointers(spc, val);
    }
  }
  if (defPos > 0) {		// Make sure the default space comes first
    AddrSpace *tmp = inferPtrSpaces[0];
    inferPtrSpaces[0] = inferPtrSpaces[defPos];
    inferPtrSpaces[defPos] = tmp;
  }
}

/// Recover information out of a \<rule> element and build the new Rule object.
/// \param decoder is the stream decoder
void Architecture::decodeDynamicRule(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_RULE);
  string rulename,groupname;
  bool enabled = false;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_NAME)
      rulename = decoder.readString();
    else if (attribId == ATTRIB_GROUP)
      groupname = decoder.readString();
    else if (attribId == ATTRIB_ENABLE)
      enabled = decoder.readBool();
    else
      throw LowlevelError("Dynamic rule tag contains illegal attribute");
  }
  if (rulename.size()==0)
    throw LowlevelError("Dynamic rule has no name");
  if (groupname.size()==0)
    throw LowlevelError("Dynamic rule has no group");
  if (!enabled) return;
#ifdef CPUI_RULECOMPILE
  Rule *dynrule = RuleGeneric::build(rulename,groupname,el->getContent());
  extra_pool_rules.push_back(dynrule);
#else
  throw LowlevelError("Dynamic rules have not been enabled for this decompiler");
#endif
  decoder.closeElement(elemId);
}

/// This handles the \<prototype> and \<resolveprototype> elements. It builds the
/// ProtoModel object based on the tag and makes it available generally to the decompiler.
/// \param decoder is the stream decoder
/// \return the new ProtoModel object
ProtoModel *Architecture::decodeProto(Decoder &decoder)

{
  ProtoModel *res;
  uint4 elemId = decoder.peekElement();
  if (elemId == ELEM_PROTOTYPE)
    res = new ProtoModel(this);
  else if (elemId == ELEM_RESOLVEPROTOTYPE)
    res = new ProtoModelMerged(this);
  else
    throw LowlevelError("Expecting <prototype> or <resolveprototype> tag");

  res->decode(decoder);
  
  ProtoModel *other = getModel(res->getName());
  if (other != (ProtoModel *)0) {
    string errMsg = "Duplicate ProtoModel name: " + res->getName();
    delete res;
    throw LowlevelError(errMsg);
  }
  protoModels[res->getName()] = res;
  return res;
}

/// This decodes the \<eval_called_prototype> and \<eval_current_prototype> elements.
/// This determines which prototype model to assume when recovering the prototype
/// for a \e called function and the \e current function respectively.
/// \param decoder is the stream decoder
void Architecture::decodeProtoEval(Decoder &decoder)

{
  uint4 elemId = decoder.openElement();
  string modelName = decoder.readString(ATTRIB_NAME);
  ProtoModel *res = getModel(modelName);
  if (res == (ProtoModel *)0)
    throw LowlevelError("Unknown prototype model name: "+modelName);

  if (elemId == ELEM_EVAL_CALLED_PROTOTYPE) {
    if (evalfp_called != (ProtoModel *)0)
      throw LowlevelError("Duplicate <eval_called_prototype> tag");
    evalfp_called = res;
  }
  else {
    if (evalfp_current != (ProtoModel *)0)
      throw LowlevelError("Duplicate <eval_current_prototype> tag");
    evalfp_current = res;
  }
  decoder.closeElement(elemId);
}

/// There should be exactly one \<default_proto> element that specifies what the
/// default prototype model is. This builds the ProtoModel object and sets it
/// as the default.
/// \param decoder is the stream decoder
void Architecture::decodeDefaultProto(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_DEFAULT_PROTO);
  while(decoder.peekElement() != 0) {
    if (defaultfp != (ProtoModel *)0)
      throw LowlevelError("More than one default prototype model");
    ProtoModel *model = decodeProto(decoder);
    setDefaultModel(model);
  }
  decoder.closeElement(elemId);
}

/// Parse a \<global> element for child \<range> elements that will be added to the global scope.
/// Ranges are stored in partial form so that elements can be parsed before all address spaces exist.
/// \param decoder is the stream decoder
/// \param rangeProps is where the partially parsed ranges are stored
void Architecture::decodeGlobal(Decoder &decoder,vector<RangeProperties> &rangeProps)

{
  uint4 elemId = decoder.openElement(ELEM_GLOBAL);
  while(decoder.peekElement() != 0) {
    rangeProps.emplace_back();
    rangeProps.back().decode(decoder);
  }
  decoder.closeElement(elemId);
}

/// Add a memory range parse from a \<global> tag to the global scope.
/// Varnodes in this region will be assumed to be global variables.
/// \param props is information about a specific range
void Architecture::addToGlobalScope(const RangeProperties &props)

{
  Scope *scope = symboltab->getGlobalScope();
  Range range(props,this);
  AddrSpace *spc = range.getSpace();
  inferPtrSpaces.push_back(spc);
  symboltab->addRange(scope,spc,range.getFirst(),range.getLast());
  if (range.getSpace()->isOverlayBase()) { // If the address space is overlayed
    // We need to duplicate the range being marked as global into the overlay space(s)
    int4 num = numSpaces();
    for(int4 i=0;i<num;++i) {
      AddrSpace *ospc = getSpace(i);
      if (ospc == (AddrSpace *)0 || !ospc->isOverlay()) continue;
      if (ospc->getContain() != range.getSpace()) continue;
      symboltab->addRange(scope,ospc,range.getFirst(),range.getLast());
    }
  }
}

//explictly add the OTHER space and any overlays to the global scope
void Architecture::addOtherSpace(void)

{
  Scope *scope = symboltab->getGlobalScope();
  AddrSpace *otherSpace = getSpaceByName(OtherSpace::NAME);
  symboltab->addRange(scope,otherSpace,0,otherSpace->getHighest());
  if (otherSpace->isOverlayBase()) {
    int4 num = numSpaces();
    for(int4 i=0;i<num;++i){
      AddrSpace *ospc = getSpace(i);
      if (!ospc->isOverlay()) continue;
      if (ospc->getContain() != otherSpace) continue;
      symboltab->addRange(scope,ospc,0,otherSpace->getHighest());
    }
  }
}

/// This applies info from a \<readonly> element marking a specific region
/// of the executable as \e read-only.
/// \param decoder is the stream decoder
void Architecture::decodeReadOnly(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_READONLY);
  while(decoder.peekElement() != 0) {
    Range range;
    range.decode(decoder);
    symboltab->setPropertyRange(Varnode::readonly,range);
  }
  decoder.closeElement(elemId);
}

/// This applies info from a \<volatile> element marking specific regions
/// of the executable as holding \e volatile memory or registers.
/// \param decoder is the stream decoder
void Architecture::decodeVolatile(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_VOLATILE);
  userops.decodeVolatile(decoder,this);
  while(decoder.peekElement() != 0) {
    Range range;
    range.decode(decoder); // Tag itself is range
    symboltab->setPropertyRange(Varnode::volatil,range);
  }
  decoder.closeElement(elemId);
}

/// This applies info from \<returnaddress> element and sets the default
/// storage location for the \e return \e address of a function.
/// \param decoder is the stream decoder
void Architecture::decodeReturnAddress(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_RETURNADDRESS);
  uint4 subId = decoder.peekElement();
  if (subId != 0) {
    if (defaultReturnAddr.space != (AddrSpace *)0)
      throw LowlevelError("Multiple <returnaddress> tags in .cspec");
    defaultReturnAddr.decode(decoder);
  }
  decoder.closeElement(elemId);
}

/// Apply information from an \<incidentalcopy> element, which marks a set of addresses
/// as being copied to incidentally. This allows the decompiler to ignore certain side-effects.
/// \param decoder is the stream decoder
void Architecture::decodeIncidentalCopy(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_INCIDENTALCOPY);
  while(decoder.peekElement() != 0) {
    VarnodeData vdata;
    vdata.decode(decoder);
    Range range( vdata.space, vdata.offset, vdata.offset+vdata.size-1);
    symboltab->setPropertyRange(Varnode::incidental_copy,range);
  }
  decoder.closeElement(elemId);
}

/// Look for \<register> elements that have a \e vector_lane_size attribute.
/// Record these so that the decompiler can split large registers into appropriate lane size pieces.
/// \param decoder is the stream decoder
void Architecture::decodeLaneSizes(Decoder &decoder)

{
  vector<uint4> maskList;
  LanedRegister lanedRegister;		// Only allocate once

  uint4 elemId = decoder.openElement(ELEM_REGISTER_DATA);
  while(decoder.peekElement() != 0) {
    if (lanedRegister.decode(decoder)) {
      int4 sizeIndex = lanedRegister.getWholeSize();
      while (maskList.size() <= sizeIndex)
	maskList.push_back(0);
      maskList[sizeIndex] |= lanedRegister.getSizeBitMask();
    }
  }
  decoder.closeElement(elemId);
  lanerecords.clear();
  for(int4 i=0;i<maskList.size();++i) {
    if (maskList[i] == 0) continue;
    lanerecords.push_back(LanedRegister(i,maskList[i]));
  }
}

/// Create a stack space and a stack-pointer register from a \<stackpointer> element
/// \param decoder is the stream decoder
void Architecture::decodeStackPointer(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_STACKPOINTER);

  string registerName;
  bool stackGrowth = true;		// Default stack growth is in negative direction
  bool isreversejustify = false;
  AddrSpace *basespace = (AddrSpace *)0;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_REVERSEJUSTIFY)
      isreversejustify = decoder.readBool();
    else if (attribId == ATTRIB_GROWTH)
      stackGrowth = decoder.readString() == "negative";
    else if (attribId == ATTRIB_SPACE)
      basespace = decoder.readSpace();
    else if (attribId == ATTRIB_REGISTER)
      registerName = decoder.readString();
  }

  if (basespace == (AddrSpace *)0)
    throw LowlevelError(ELEM_STACKPOINTER.getName() + " element missing \"space\" attribute");

  VarnodeData point = translate->getRegister(registerName);
  decoder.closeElement(elemId);

  // If creating a stackpointer to a truncated space, make sure to truncate the stackpointer
  int4 truncSize = point.size;
  if (basespace->isTruncated() && (point.size > basespace->getAddrSize())) {
    truncSize = basespace->getAddrSize();
  }

  addSpacebase(basespace,"stack",point,truncSize,isreversejustify,stackGrowth,true); // Create the "official" stackpointer
}

/// Manually alter the dead-code delay for a specific address space,
/// based on a \<deadcodedelay> element.
/// \param decoder is the stream decoder
void Architecture::decodeDeadcodeDelay(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_DEADCODEDELAY);
  AddrSpace *spc = decoder.readSpace(ATTRIB_SPACE);
  int4 delay = decoder.readSignedInteger(ATTRIB_DELAY);
  if (delay >= 0)
    setDeadcodeDelay(spc,delay);
  else
    throw LowlevelError("Bad <deadcodedelay> tag");
  decoder.closeElement(elemId);
}

/// Alter the range of addresses for which a pointer is allowed to be inferred.
void Architecture::decodeInferPtrBounds(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_INFERPTRBOUNDS);
  while(decoder.peekElement() != 0) {
    Range range;
    range.decode(decoder);
    setInferPtrBounds(range);
  }
  decoder.closeElement(elemId);
}

/// Pull information from a \<funcptr> element. Turn on alignment analysis of
/// function pointers, some architectures have aligned function pointers
/// and encode extra information in the unused bits.
/// \param decoder is the stream decoder
void Architecture::decodeFuncPtrAlign(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_FUNCPTR);
  int4 align = decoder.readSignedInteger(ATTRIB_ALIGN);
  decoder.closeElement(elemId);
  
  if (align == 0) {
    funcptr_align = 0;		// No alignment
    return;
  }
  int4 bits = 0;
  while((align&1)==0) {		// Find position of first 1 bit
    bits += 1;
    align >>= 1;
  }
  funcptr_align = bits;
}

/// Designate a new index register and create a new address space associated with it,
/// based on a \<spacebase> element.
/// \param decoder is the stream decoder
void Architecture::decodeSpacebase(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_SPACEBASE);
  string nameString = decoder.readString(ATTRIB_NAME);
  string registerName = decoder.readString(ATTRIB_REGISTER);
  AddrSpace *basespace = decoder.readSpace(ATTRIB_SPACE);
  decoder.closeElement(elemId);
  const VarnodeData &point(translate->getRegister(registerName));
  addSpacebase(basespace,nameString,point,point.size,false,false,false);
}

/// Configure memory based on a \<nohighptr> element. Mark specific address ranges
/// to indicate the decompiler will not encounter pointers (aliases) into the range.
/// \param decoder is the stream decoder
void Architecture::decodeNoHighPtr(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_NOHIGHPTR);
  while(decoder.peekElement() != 0) { // Iterate over every range tag in the list
    Range range;
    range.decode(decoder);
    addNoHighPtr(range);
  }
  decoder.closeElement(elemId);
}

/// Configure registers based on a \<prefersplit> element. Mark specific varnodes that
/// the decompiler should automatically split when it first sees them.
/// \param decoder is the stream decoder
void Architecture::decodePreferSplit(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_PREFERSPLIT);
  string style = decoder.readString(ATTRIB_STYLE);
  if (style != "inhalf")
    throw LowlevelError("Unknown prefersplit style: "+style);

  while(decoder.peekElement() != 0) {
    splitrecords.emplace_back();
    PreferSplitRecord &record( splitrecords.back() );
    record.storage.decode( decoder );
    record.splitoffset = record.storage.size/2;
  }
  decoder.closeElement(elemId);
}

/// Configure, based on the \<aggressivetrim> element, how aggressively the
/// decompiler will remove extension operations.
/// \param decoder is the stream decoder
void Architecture::decodeAggressiveTrim(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_AGGRESSIVETRIM);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_SIGNEXT) {
      aggressive_ext_trim = decoder.readBool();
    }
  }
  decoder.closeElement(elemId);
}

/// Clone the named ProtoModel, attaching it to another name.
/// \param aliasName is the new name to assign
/// \param parentName is the name of the parent model
void Architecture::createModelAlias(const string &aliasName,const string &parentName)

{
  map<string,ProtoModel *>::const_iterator iter = protoModels.find(parentName);
  if (iter == protoModels.end())
    throw LowlevelError("Requesting non-existent prototype model: "+parentName);
  ProtoModel *model = (*iter).second;
  if (model->isMerged())
    throw LowlevelError("Cannot make alias of merged model: "+parentName);
  if (model->getAliasParent() != (const ProtoModel *)0)
    throw LowlevelError("Cannot make alias of an alias: "+parentName);
  iter = protoModels.find(aliasName);
  if (iter != protoModels.end())
    throw LowlevelError("Duplicate ProtoModel name: "+aliasName);
  protoModels[aliasName] = new ProtoModel(aliasName,*model);
}

/// A new UnknownProtoModel, which clones its behavior from the default model, is created and associated with the
/// unrecognized name.  Subsequent queries of the name return this new model.
/// \param modelName is the unrecognized name
/// \return the new \e unknown prototype model associated with the name
ProtoModel *Architecture::createUnknownModel(const string &modelName)

{
  UnknownProtoModel *model = new UnknownProtoModel(modelName,defaultfp);
  protoModels[modelName] = model;
  if (modelName == "unknown")		// "unknown" is a reserved/internal name
    model->setPrintInDecl(false);	// don't print it in declarations
  return model;
}

/// This looks for the \<processor_spec> tag and and sets configuration
/// parameters based on it.
/// \param store is the document store holding the tag
void Architecture::parseProcessorConfig(DocumentStorage &store)

{
  const Element *el = store.getTag("processor_spec");
  if (el == (const Element *)0)
    throw LowlevelError("No processor configuration tag found");
  XmlDecode decoder(this,el);
  
  uint4 elemId = decoder.openElement(ELEM_PROCESSOR_SPEC);
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_PROGRAMCOUNTER) {
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
    else if (subId == ELEM_VOLATILE)
      decodeVolatile(decoder);
    else if (subId == ELEM_INCIDENTALCOPY)
      decodeIncidentalCopy(decoder);
    else if (subId == ELEM_CONTEXT_DATA)
      context->decodeFromSpec(decoder);
    else if (subId == ELEM_JUMPASSIST)
      userops.decodeJumpAssist(decoder, this);
    else if (subId == ELEM_SEGMENTOP)
      userops.decodeSegmentOp(decoder,this);
    else if (subId == ELEM_REGISTER_DATA) {
      decodeLaneSizes(decoder);
    }
    else if (subId == ELEM_DATA_SPACE) {
      uint4 elemId = decoder.openElement();
      AddrSpace *spc = decoder.readSpace(ATTRIB_SPACE);
      decoder.closeElement(elemId);
      setDefaultDataSpace(spc->getIndex());
    }
    else if (subId == ELEM_INFERPTRBOUNDS) {
      decodeInferPtrBounds(decoder);
    }
    else if (subId == ELEM_SEGMENTED_ADDRESS) {
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
    else if (subId == ELEM_DEFAULT_SYMBOLS) {
      decoder.openElement();
      store.registerTag(decoder.getCurrentXmlElement());
      decoder.closeElementSkipping(subId);
    }
    else if (subId == ELEM_DEFAULT_MEMORY_BLOCKS) {
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
    else if (subId == ELEM_ADDRESS_SHIFT_AMOUNT) {
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
    else if (subId == ELEM_PROPERTIES) {
      decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
    else
      throw LowlevelError("Unknown element in <processor_spec>");
  }
  decoder.closeElement(elemId);
}

/// This looks for the \<compiler_spec> tag and sets configuration parameters based on it.
/// \param store is the document store holding the tag
void Architecture::parseCompilerConfig(DocumentStorage &store)

{
  vector<RangeProperties> globalRanges;
  const Element *el = store.getTag("compiler_spec");
  if (el == (const Element *)0)
    throw LowlevelError("No compiler configuration tag found");
  XmlDecode decoder(this,el);

  uint4 elemId = decoder.openElement(ELEM_COMPILER_SPEC);
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_DEFAULT_PROTO)
      decodeDefaultProto(decoder);
    else if (subId == ELEM_PROTOTYPE)
      decodeProto(decoder);
    else if (subId == ELEM_STACKPOINTER)
      decodeStackPointer(decoder);
    else if (subId == ELEM_RETURNADDRESS)
      decodeReturnAddress(decoder);
    else if (subId == ELEM_SPACEBASE)
      decodeSpacebase(decoder);
    else if (subId == ELEM_NOHIGHPTR)
      decodeNoHighPtr(decoder);
    else if (subId == ELEM_PREFERSPLIT)
      decodePreferSplit(decoder);
    else if (subId == ELEM_AGGRESSIVETRIM)
      decodeAggressiveTrim(decoder);
    else if (subId == ELEM_DATA_ORGANIZATION)
      types->decodeDataOrganization(decoder);
    else if (subId == ELEM_ENUM)
      types->parseEnumConfig(decoder);
    else if (subId == ELEM_GLOBAL)
      decodeGlobal(decoder, globalRanges);
    else if (subId == ELEM_SEGMENTOP)
      userops.decodeSegmentOp(decoder,this);
    else if (subId == ELEM_READONLY)
      decodeReadOnly(decoder);
    else if (subId == ELEM_CONTEXT_DATA)
      context->decodeFromSpec(decoder);
    else if (subId == ELEM_RESOLVEPROTOTYPE)
      decodeProto(decoder);
    else if (subId == ELEM_EVAL_CALLED_PROTOTYPE)
      decodeProtoEval(decoder);
    else if (subId == ELEM_EVAL_CURRENT_PROTOTYPE)
      decodeProtoEval(decoder);
    else if (subId == ELEM_CALLFIXUP) {
      pcodeinjectlib->decodeInject(archid+" : compiler spec", "", InjectPayload::CALLFIXUP_TYPE, decoder);
    }
    else if (subId == ELEM_CALLOTHERFIXUP) {
      userops.decodeCallOtherFixup(decoder,this);
    }
    else if (subId == ELEM_FUNCPTR)
      decodeFuncPtrAlign(decoder);
    else if (subId == ELEM_DEADCODEDELAY)
      decodeDeadcodeDelay(decoder);
    else if (subId == ELEM_INFERPTRBOUNDS)
      decodeInferPtrBounds(decoder);
    else if (subId == ELEM_MODELALIAS) {
      uint4 elemId = decoder.openElement();
      string aliasName = decoder.readString(ATTRIB_NAME);
      string parentName = decoder.readString(ATTRIB_PARENT);
      decoder.closeElement(elemId);
      createModelAlias(aliasName, parentName);
    }
  }
  decoder.closeElement(elemId);

  el = store.getTag("specextensions");		// Look for any user-defined configuration document
  if (el != (const Element *)0) {
    XmlDecode decoderExt(this,el);
    elemId = decoderExt.openElement(ELEM_SPECEXTENSIONS);
    for(;;) {
      uint4 subId = decoderExt.peekElement();
      if (subId == 0) break;
      if (subId == ELEM_PROTOTYPE)
        decodeProto(decoderExt);
      else if (subId == ELEM_CALLFIXUP) {
        pcodeinjectlib->decodeInject(archid+" : compiler spec", "",InjectPayload::CALLFIXUP_TYPE, decoder);
      }
      else if (subId == ELEM_CALLOTHERFIXUP) {
        userops.decodeCallOtherFixup(decoder,this);
      }
      else if (subId == ELEM_GLOBAL)
        decodeGlobal(decoder,globalRanges);
    }
    decoderExt.closeElement(elemId);
  }

  // <global> tags instantiate the base symbol table
  // They need to know about all spaces, so it must come
  // after parsing of <stackpointer> and <spacebase>
  for(int4 i=0;i<globalRanges.size();++i)
    addToGlobalScope(globalRanges[i]);

  addOtherSpace();
      
  if (defaultfp == (ProtoModel *)0) {
    if (protoModels.size() > 0)
      setDefaultModel((*protoModels.begin()).second);
    else
      throw LowlevelError("No default prototype specified");
  }
  // We must have a __thiscall calling convention
  map<string,ProtoModel *>::iterator miter = protoModels.find("__thiscall");
  if (miter == protoModels.end()) { // If __thiscall doesn't exist we clone it off of the default
    createModelAlias("__thiscall",defaultfp->getName());
  }
  userops.setDefaults(this);
  initializeSegments();
  PreferSplitManager::initialize(splitrecords);
  types->setupSizes();		// If no data_organization was registered, set up default values
}

/// Look for the \<experimental_rules> tag and create any dynamic Rule objects it specifies.
/// \param store is the document store containing the tag
void Architecture::parseExtraRules(DocumentStorage &store)

{
  const Element *expertag = store.getTag("experimental_rules");
  if (expertag != (const Element *)0) {
    XmlDecode decoder(this,expertag);
    uint4 elemId = decoder.openElement(ELEM_EXPERIMENTAL_RULES);
    while(decoder.peekElement() != 0)
      decodeDynamicRule( decoder );
    decoder.closeElement(elemId);
  }
}

/// The LoadImage may have access information about the executables
/// sections. Query for any read-only ranges and
/// store this information in the property database
void Architecture::fillinReadOnlyFromLoader(void)

{
  RangeList rangelist;
  loader->getReadonly(rangelist); // Get read only ranges
  set<Range>::const_iterator iter,eiter;
  iter = rangelist.begin();
  eiter = rangelist.end();
  while(iter != eiter) {
    symboltab->setPropertyRange(Varnode::readonly,*iter);
    ++iter;
  }
}

/// Create the LoadImage and load the executable to be analyzed.
/// Using this and possibly other initialization information, create
/// all the sub-components necessary for a complete Architecture
/// The DocumentStore may hold previously gleaned configuration information
/// and is used to read in other configuration files while initializing.
/// \param store is the XML document store
void Architecture::init(DocumentStorage &store)

{
  buildLoader(store);		// Loader is built first
  resolveArchitecture();
  buildSpecFile(store);

  buildContext(store);
  buildTypegrp(store);
  buildCommentDB(store);
  buildStringManager(store);
  buildConstantPool(store);
  buildDatabase(store);

  restoreFromSpec(store);
  print->initializeFromArchitecture();
  symboltab->adjustCaches();	// In case the specs created additional address spaces
  buildSymbols(store);
  postSpecFile();		// Let subclasses do things after translate is ready

  buildInstructions(store); // Must be called after translate is built
  fillinReadOnlyFromLoader();
}

void Architecture::resetDefaultsInternal(void)

{
  trim_recurse_max = 5;
  max_implied_ref = 2;		// 2 is best, in specific cases a higher number might be good
  max_term_duplication = 2;	// 2 and 3 (4) are reasonable
  max_basetype_size = 10;	// Needs to be 8 or bigger
  flowoptions = FlowInfo::error_toomanyinstructions;
  max_instructions = 100000;
  infer_pointers = true;
  analyze_for_loops = true;
  readonlypropagate = false;
  alias_block_level = 2;	// Block structs and arrays by default, but not more primitive data-types
  split_datatype_config = OptionSplitDatatypes::option_struct | OptionSplitDatatypes::option_array
      | OptionSplitDatatypes::option_pointer;
}

/// Reset options that can be modified by the OptionDatabase. This includes
/// options specific to this class and options under PrintLanguage and ActionDatabase
void Architecture::resetDefaults(void)

{
  resetDefaultsInternal();
  allacts.resetDefaults();
  for(int4 i=0;i<printlist.size();++i)
    printlist[i]->resetDefaults();
}

Address SegmentedResolver::resolve(uintb val,int4 sz,const Address &point,uintb &fullEncoding)

{
  int4 innersz = segop->getInnerSize();
  if (sz >= 0 && sz <= innersz) { // If -sz- matches the inner size, consider the value a "near" pointer
  // In this case the address offset is not fully specified
  // we check if the rest is stored in a context variable
  // (as with near pointers)
    if (segop->getResolve().space != (AddrSpace *)0) {
      uintb base = glb->context->getTrackedValue(segop->getResolve(),point);
      fullEncoding = (base << 8 * innersz) + (val & calc_mask(innersz));
      vector<uintb> seginput;
      seginput.push_back(base);
      seginput.push_back(val);
      val = segop->execute(seginput);
      return Address(spc,AddrSpace::addressToByte(val,spc->getWordSize()));
    }
  }
  else { // For anything else, consider it a "far" pointer
    fullEncoding = val;
    int4 outersz = segop->getBaseSize();
    uintb base = (val >> 8*innersz) & calc_mask(outersz);
    val = val & calc_mask(innersz);
    vector<uintb> seginput;
    seginput.push_back(base);
    seginput.push_back(val);
    val = segop->execute(seginput);
    return Address(spc,AddrSpace::addressToByte(val,spc->getWordSize()));
  }
  return Address();		// Return invalid address
}

#ifdef CPUI_STATISTICS

Statistics::Statistics(void)

{
  numfunc = 0;
//   numvar = 0;
//   coversum = 0;
//   coversumsq = 0;
  castcount = 0;
  lastcastcount = 0;
  castcountsq = 0;
}

Statistics::~Statistics(void)

{
}

// void Statistics::process_cover(const Funcdata &data)

// {
//   if (data.getBasicBlocks().getSize() < 100) return;
//   VarnodeLocSet::const_iterator iter;
//   for(iter=data.beginLoc();iter!=data.endLoc();++iter) {
//     Varnode *vn = *iter;

//     if (!vn->hasCover()) continue;
//     Cover *cover = vn->getCover();
//     if (cover == (Cover *)0) continue;
//     numvar += 1;
    
//     int4 size = cover->getSize();
//     int4 count = 0;
//     for(int4 i=0;i<size;++i) {
//       if (!cover->getCoverBlock(i).empty())
// 	count += 1;
//     }
//     coversum += count;		// Number of non-empty covers
//     coversumsq += ((uintb)count)*((uintb)count);
//   }
// }

/// Calculate number of casts seen since last function, update variance
/// \param data is the function being analyzed
void Statistics::process_cast(const Funcdata &data)

{
  uintb perfunc = castcount - lastcastcount;
  lastcastcount = castcount;
  castcountsq += perfunc*perfunc;
}

/// Gather various statistics for a single function and accumulate in global counts
/// \param data is the function being analyzed
void Statistics::process(const Funcdata &data)

{
  numfunc += 1;
  //  process_cover(data);
  process_cast(data);
}

/// Complete calculations on running sums then print them to a stream
/// \param s is the output stream
void Statistics::printResults(ostream &s)

{
  s << "Number of functions: " << dec << numfunc << endl;
  //  s << "Number of variables: " << dec << numvar << endl;

  //  double average = ((double)coversum)/numvar;
  //  double variance = ((double)coversumsq)/numvar;
  //  double stddev = sqrt(variance);

  //  s << "Average number of non-empty covers: " << average << endl;
  //  s << "Standard deviation: " << stddev << endl;

  double average = ((double)castcount)/numfunc;
  double variance = ((double)castcountsq)/numfunc;
  variance -= average*average;
  double stddev = sqrt(variance);

  s << "Total functions = " << dec << numfunc << endl;
  s << "Total casts = " << dec << castcount << endl;
  s << "Average casts per function = " << average << endl;
  s << "        Standard deviation = " << stddev << endl;
}

#endif

} // End namespace ghidra

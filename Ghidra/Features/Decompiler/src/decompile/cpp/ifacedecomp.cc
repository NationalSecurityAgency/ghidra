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
#include "ifacedecomp.hh"
extern "C" {
#include <time.h>
}
#include "pcodeparse.hh"
#include "blockaction.hh"

// Constructing this registers the capability
IfaceDecompCapability IfaceDecompCapability::ifaceDecompCapability;

IfaceDecompCapability::IfaceDecompCapability(void)

{
  name = "decomp";
}

void IfaceDecompCapability::registerCommands(IfaceStatus *status)

{
  status->registerCom(new IfcComment(),"//"); //Note: A space must follow this when used.
  status->registerCom(new IfcComment(),"#"); //Note: A space must follow this when used.
  status->registerCom(new IfcComment(),"%"); //Note: A space must follow this when used.
  status->registerCom(new IfcQuit(),"quit");
  status->registerCom(new IfcHistory(),"history");
  status->registerCom(new IfcOpenfile(),"openfile");
  status->registerCom(new IfcOpenfile(),"openfile", "write");
  status->registerCom(new IfcOpenfileAppend(),"openfile","append");
  status->registerCom(new IfcClosefile(),"closefile");
  status->registerCom(new IfcEcho(),"echo");

  status->registerCom(new IfcSource(),"source");
  status->registerCom(new IfcOption(),"option");
  status->registerCom(new IfcParseFile(),"parse","file");
  status->registerCom(new IfcParseLine(),"parse","line");
  status->registerCom(new IfcAdjustVma(),"adjust","vma");
  status->registerCom(new IfcFuncload(),"load","function");
  status->registerCom(new IfcAddrrangeLoad(),"load","addr");
  status->registerCom(new IfcReadSymbols(),"read","symbols");
  status->registerCom(new IfcCleararch(),"clear","architecture");
  status->registerCom(new IfcMapaddress(),"map","address");
  status->registerCom(new IfcMaphash(),"map","hash");
  status->registerCom(new IfcMapfunction(),"map","function");
  status->registerCom(new IfcMapexternalref(),"map","externalref");
  status->registerCom(new IfcMaplabel(),"map","label");
  status->registerCom(new IfcPrintdisasm(),"disassemble");
  status->registerCom(new IfcDecompile(),"decompile");
  status->registerCom(new IfcDump(),"dump");
  status->registerCom(new IfcDumpbinary(),"binary");
  status->registerCom(new IfcForcegoto(),"force","goto");
  status->registerCom(new IfcForceHex(),"force","hex");
  status->registerCom(new IfcForceDec(),"force","dec");
  status->registerCom(new IfcProtooverride(),"override","prototype");
  status->registerCom(new IfcJumpOverride(),"override","jumptable");
  status->registerCom(new IfcFlowOverride(),"override","flow");
  status->registerCom(new IfcDeadcodedelay(),"deadcode","delay");
  status->registerCom(new IfcGlobalAdd(),"global","add");
  status->registerCom(new IfcGlobalRemove(),"global","remove");
  status->registerCom(new IfcGlobalify(),"global","spaces");
  status->registerCom(new IfcGlobalRegisters(),"global","registers");
  status->registerCom(new IfcGraphDataflow(),"graph","dataflow");
  status->registerCom(new IfcGraphControlflow(),"graph","controlflow");
  status->registerCom(new IfcGraphDom(),"graph","dom");
  status->registerCom(new IfcPrintLanguage(),"print","language");
  status->registerCom(new IfcPrintCStruct(),"print","C");
  status->registerCom(new IfcPrintCFlat(),"print","C","flat");
  status->registerCom(new IfcPrintCGlobals(),"print","C","globals");
  status->registerCom(new IfcPrintCTypes(),"print","C","types");
  status->registerCom(new IfcPrintCXml(),"print","C","xml");
  status->registerCom(new IfcPrintParamMeasures(),"print","parammeasures");
  status->registerCom(new IfcPrintParamMeasuresXml(),"print","parammeasures","xml");
  status->registerCom(new IfcProduceC(),"produce","C");
  status->registerCom(new IfcProducePrototypes(),"produce","prototypes");
  status->registerCom(new IfcPrintRaw(),"print","raw");
  status->registerCom(new IfcPrintInputs(),"print","inputs");
  status->registerCom(new IfcPrintInputsAll(),"print","inputs","all");
  status->registerCom(new IfcListaction(),"list","action");
  status->registerCom(new IfcListOverride(),"list","override");
  status->registerCom(new IfcListprototypes(),"list","prototypes");
  status->registerCom(new IfcSetcontextrange(),"set","context");
  status->registerCom(new IfcSettrackedrange(),"set","track");
  status->registerCom(new IfcBreakstart(),"break","start");
  status->registerCom(new IfcBreakaction(),"break","action");
  status->registerCom(new IfcPrintSpaces(),"print","spaces");
  status->registerCom(new IfcPrintHigh(),"print","high");
  status->registerCom(new IfcParamIDAnalysis(),"paramid","analysis");
  status->registerCom(new IfcPrintTree(),"print","tree","varnode");
  status->registerCom(new IfcPrintBlocktree(),"print","tree","block");
  status->registerCom(new IfcPrintLocalrange(),"print","localrange");
  status->registerCom(new IfcPrintMap(),"print","map");
  status->registerCom(new IfcPrintVarnode(),"print","varnode");
  status->registerCom(new IfcPrintCover(),"print","cover","high");
  status->registerCom(new IfcVarnodeCover(),"print","cover","varnode");
  status->registerCom(new IfcVarnodehighCover(),"print","cover","varnodehigh");
  status->registerCom(new IfcPrintExtrapop(),"print","extrapop");
  status->registerCom(new IfcPrintActionstats(),"print","actionstats");
  status->registerCom(new IfcResetActionstats(),"reset","actionstats");
  status->registerCom(new IfcCountPcode(),"count","pcode");
  status->registerCom(new IfcTypeVarnode(),"type","varnode");
  status->registerCom(new IfcNameVarnode(),"name","varnode");
  status->registerCom(new IfcRename(),"rename");
  status->registerCom(new IfcRetype(),"retype");
  status->registerCom(new IfcRemove(),"remove");
  status->registerCom(new IfcLockPrototype(),"prototype","lock");
  status->registerCom(new IfcUnlockPrototype(),"prototype","unlock");
  status->registerCom(new IfcCommentInstr(),"comment","instruction");
  status->registerCom(new IfcDuplicateHash(),"duplicate","hash");
  status->registerCom(new IfcCallGraphBuild(),"callgraph","build");
  status->registerCom(new IfcCallGraphBuildQuick(),"callgraph","build","quick");
  status->registerCom(new IfcCallGraphDump(),"callgraph","dump");
  status->registerCom(new IfcCallGraphLoad(),"callgraph","load");
  status->registerCom(new IfcCallGraphList(),"callgraph","list");
  status->registerCom(new IfcCallFixup(),"fixup","call");
  status->registerCom(new IfcCallOtherFixup(),"fixup","callother");
  status->registerCom(new IfcVolatile(),"volatile");
  status->registerCom(new IfcReadonly(),"readonly");
  status->registerCom(new IfcPreferSplit(),"prefersplit");
  status->registerCom(new IfcStructureBlocks(),"structure","blocks");
  status->registerCom(new IfcAnalyzeRange(), "analyze","range");
#ifdef CPUI_RULECOMPILE
  status->registerCom(new IfcParseRule(),"parse","rule");
  status->registerCom(new IfcExperimentalRules(),"experimental","rules");
#endif
  status->registerCom(new IfcContinue(),"continue");
#ifdef OPACTION_DEBUG
  status->registerCom(new IfcDebugAction(),"debug","action");
  status->registerCom(new IfcTraceBreak(),"trace","break");
  status->registerCom(new IfcTraceAddress(),"trace","address");
  status->registerCom(new IfcTraceEnable(),"trace","enable");
  status->registerCom(new IfcTraceDisable(),"trace","disable");
  status->registerCom(new IfcTraceClear(),"trace","clear");
  status->registerCom(new IfcTraceList(),"trace","list");
  status->registerCom(new IfcBreakjump(),"break","jumptable");
#endif
}

void IfaceDecompCommand::iterateScopesRecursive(Scope *scope)

{
  if (!scope->isGlobal()) return;
  iterateFunctionsAddrOrder(scope);
  ScopeMap::const_iterator iter,enditer;
  iter = scope->childrenBegin();
  enditer = scope->childrenEnd();
  for(;iter!=enditer;++iter) {
    iterateScopesRecursive((*iter).second);
  }
}

void IfaceDecompCommand::iterateFunctionsAddrOrder(Scope *scope)

{
  MapIterator miter,menditer;
  miter = scope->begin();
  menditer = scope->end();
  while(miter != menditer) {
    Symbol *sym = (*miter)->getSymbol();
    FunctionSymbol *fsym = dynamic_cast<FunctionSymbol *>(sym);
    ++miter;
    if (fsym != (FunctionSymbol *)0)
	iterationCallback(fsym->getFunction());
  }
}

void IfaceDecompCommand::iterateFunctionsAddrOrder(void)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No architecture loaded");
  iterateScopesRecursive(dcp->conf->symboltab->getGlobalScope());
}

void IfaceDecompCommand::iterateFunctionsLeafOrder(void)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No architecture loaded");

  if (dcp->cgraph == (CallGraph *)0)
    throw IfaceExecutionError("No callgraph present");

  CallGraphNode *node;
  node = dcp->cgraph->initLeafWalk();
  while(node != (CallGraphNode *)0) {
    if (node->getName().size()==0) continue; // Skip if has no name
    Funcdata *fd = node->getFuncdata();
    if (fd != (Funcdata *)0)
      iterationCallback(fd);
    node = dcp->cgraph->nextLeaf(node);
  }
}

IfaceDecompData::IfaceDecompData(void)

{
  conf = (Architecture *)0;
  fd = (Funcdata *)0;
  cgraph = (CallGraph *)0;
#ifdef OPACTION_DEBUG
  jumptabledebug = false;
#endif
}

IfaceDecompData::~IfaceDecompData(void)

{
  if (cgraph != (CallGraph *)0)
    delete cgraph;
  if (conf != (Architecture *)0)
    delete conf;
// fd will get deleted with Database
}

void IfaceDecompData::allocateCallGraph(void)

{
  if (cgraph != (CallGraph *)0)
    delete cgraph;
  cgraph = new CallGraph(conf);
}

void IfaceDecompData::abortFunction(ostream &s)

{				// Clear references to current function
  if (fd == (Funcdata *)0) return;
  s << "Unable to proceed with function: " << fd->getName() << endl;
  conf->clearAnalysis(fd);
  fd = (Funcdata *)0;
}

void IfaceDecompData::clearArchitecture(void)

{
  if (conf != (Architecture *)0)
    delete conf;
  conf = (Architecture *)0;
  fd = (Funcdata *)0;
}

void IfcComment::execute(istream &s)
{
  //Do nothing
}

void IfcOption::execute(istream &s)

{ // Adjust a generic option
  string optname;
  string p1,p2,p3;
  
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  s >> ws >> optname >> ws;
  if (optname.size()==0)
    throw IfaceParseError("Missing option name");
  if (!s.eof()) {
    s >> p1 >> ws;
    if (!s.eof()) {
      s >> p2 >> ws;
      if (!s.eof()) {
	s >> p3 >> ws;
	if (!s.eof())
	  throw IfaceParseError("Too many option parameters");
      }
    }
  }
  
  try {
    string res = dcp->conf->options->set(optname,p1,p2,p3);
    *status->optr << res << endl;
  }
  catch(ParseError &err) {
    *status->optr << err.explain << endl;
    throw IfaceParseError("Bad option");
  }
  catch(RecovError &err) {
    *status->optr << err.explain << endl;
    throw IfaceExecutionError("Bad option");
  }
}

void IfcParseFile::execute(istream &s)

{  
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");

  string filename;
  ifstream fs;

  s >> ws >> filename;
  if (filename.empty())
    throw IfaceParseError("Missing filename");

  fs.open( filename.c_str() );
  if (!fs)
    throw IfaceExecutionError("Unable to open file: "+filename);

  try {				// Try to parse the file
    parse_C(dcp->conf,fs);
  }
  catch(ParseError &err) {
    *status->optr << "Error in C syntax: " << err.explain << endl;
    throw IfaceExecutionError("Bad C syntax");
  }
  fs.close();
}

void IfcParseLine::execute(istream &s)

{  
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");

  s >> ws;
  if (s.eof())
    throw IfaceParseError("No input");

  try {				// Try to parse the line
    parse_C(dcp->conf,s);
  }
  catch(ParseError &err) {
    *status->optr << "Error in C syntax: " << err.explain << endl;
    throw IfaceExecutionError("Bad C syntax");
  }
}

void IfcAdjustVma::execute(istream &s)

{
  unsigned long adjust;

  adjust = 0uL;
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  s >> ws >> adjust;
  if (adjust == 0uL)
    throw IfaceParseError("No adjustment parameter");
  dcp->conf->loader->adjustVma(adjust);
}

#ifdef OPACTION_DEBUG
static void jump_callback(Funcdata &orig,Funcdata &fd);
#endif

static void IfcFollowFlow(ostream &s,IfaceDecompData *dcp,const Address &offset,int4 size)

{
#ifdef OPACTION_DEBUG
  if (dcp->jumptabledebug)
    dcp->fd->enableJTCallback(jump_callback);
#endif
  try {
    if (size==0) {
      Address baddr(dcp->fd->getAddress().getSpace(),0);
      Address eaddr(dcp->fd->getAddress().getSpace(),dcp->fd->getAddress().getSpace()->getHighest());
      dcp->fd->followFlow(baddr,eaddr);
    }
    else
      dcp->fd->followFlow(offset,offset+size);
    s << "Function " << dcp->fd->getName() << ": ";
    dcp->fd->getAddress().printRaw(s);
    s << endl;
  } catch(RecovError &err) {
    s << "Function " << dcp->fd->getName() << ": " << err.explain << endl;
  }
}

void IfcFuncload::execute(istream &s)

{				// Load a function into memory
  string funcname;
  Address offset;

  s >> funcname;

  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No image loaded");

  string basename;
  Scope *funcscope = dcp->conf->symboltab->resolveScopeFromSymbolName(funcname,"::",basename,(Scope *)0);
  if (funcscope == (Scope *)0)
    throw IfaceExecutionError("Bad namespace: "+funcname);
  dcp->fd = funcscope->queryFunction( basename ); // Is function already in database
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("Unknown function name: "+funcname);

  if (!dcp->fd->hasNoCode())
    IfcFollowFlow(*status->optr,dcp,dcp->fd->getAddress(),0);
}

void IfcAddrrangeLoad::execute(istream &s)

{				// Load address range as function
  int4 size;
  string name;
  Address offset=parse_machaddr(s,size,*dcp->conf->types); // Read required address

  s >> ws;
  if (size <= offset.getAddrSize()) // Was a real size specified
    size = 0;
  if (dcp->conf->loader == (LoadImage *)0)
    throw IfaceExecutionError("No binary loaded");

  s >> name;			// Read optional name
  if (name.empty())
    dcp->conf->nameFunction(offset,name); // Pick default name if necessary
  dcp->fd = dcp->conf->symboltab->getGlobalScope()->addFunction( offset,name)->getFunction();
  IfcFollowFlow(*status->optr,dcp,offset,size);
}

void IfcCleararch::execute(istream &s)

{
  dcp->clearArchitecture();
}

void IfcReadSymbols::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");
  if (dcp->conf->loader == (LoadImage *)0)
    throw IfaceExecutionError("No binary loaded");

  dcp->conf->readLoaderSymbols("::");
}

void IfcMapaddress::execute(istream &s)

{
  Datatype *ct;
  string name;
  int4 size;
  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read required address;

  s >> ws;
  ct = parse_type(s,name,dcp->conf); // Parse the required type
  if (dcp->fd != (Funcdata *)0) {
    Symbol *sym;
    sym = dcp->fd->getScopeLocal()->addSymbol(name,ct,addr,Address())->getSymbol();
    sym->getScope()->setAttribute(sym,Varnode::namelock|Varnode::typelock);
  }
  else {
    Symbol *sym;
    uint4 flags = Varnode::namelock|Varnode::typelock;
    flags |= dcp->conf->symboltab->getProperty(addr); // Inherit existing properties
    string basename;
    Scope *scope = dcp->conf->symboltab->findCreateScopeFromSymbolName(name, "::", basename, (Scope *)0);
    sym = scope->addSymbol(basename,ct,addr,Address())->getSymbol();
    sym->getScope()->setAttribute(sym,flags);
    if (scope->getParent() != (Scope *)0) {		// If this is a global namespace scope
      SymbolEntry *e = sym->getFirstWholeMap();		// Adjust range
      dcp->conf->symboltab->addRange(scope,e->getAddr().getSpace(),e->getFirst(),e->getLast());
    }
  }

}

void IfcMaphash::execute(istream &s)

{ // Add a dynamic entry to the current function's symbol table given a known hash and pc address
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function loaded");
  Datatype *ct;
  string name;
  uint8 hash;
  int4 size;
  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read pc address of hash

  s >> hex >> hash;		// Parse the hash value
  s >> ws;
  ct = parse_type(s,name,dcp->conf); // Parse the required type and name

  Symbol *sym = dcp->fd->getScopeLocal()->addDynamicSymbol(name,ct,addr,hash);
  sym->getScope()->setAttribute(sym,Varnode::namelock|Varnode::typelock);
}

void IfcMapfunction::execute(istream &s)

{				// Notate a function start with loading the instructions
  string name;
  int4 size;
  if ((dcp->conf == (Architecture *)0)||(dcp->conf->loader == (LoadImage *)0))
    throw IfaceExecutionError("No binary loaded");

  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read required address;

  s >> name;			// Read optional name
  if (name.empty())
    dcp->conf->nameFunction(addr,name); // Pick default name if necessary
  string basename;
  Scope *scope = dcp->conf->symboltab->findCreateScopeFromSymbolName(name, "::", basename, (Scope *)0);
  dcp->fd = scope->addFunction(addr,name)->getFunction();

  string nocode;
  s >> ws >> nocode;
  if (nocode == "nocode")
    dcp->fd->setNoCode(true);
}

void IfcMapexternalref::execute(istream &s)

{				// Link one address as reference to another address
  int4 size1,size2;
  Address addr1 = parse_machaddr(s,size1,*dcp->conf->types); // Read externalref address
  Address addr2 = parse_machaddr(s,size2,*dcp->conf->types); // Read referred to address
  string name;

  s >> name;			// Read optional name

  dcp->conf->symboltab->getGlobalScope()->addExternalRef(addr1,addr2,name);
}

void IfcMaplabel::execute(istream &s)

{ // Put a code label at a given address
  string name;
  s >> name;
  if (name.size()==0)
    throw IfaceParseError("Need label name and address");
  int4 size;
  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read address

  Scope *scope;
  if (dcp->fd != (Funcdata *)0)
    scope = dcp->fd->getScopeLocal();
  else
    scope = dcp->conf->symboltab->getGlobalScope();

  Symbol *sym = scope->addCodeLabel(addr,name);
  scope->setAttribute(sym,Varnode::namelock|Varnode::typelock);
}

void IfcPrintdisasm::execute(istream &s)

{				// Print disassembly of a function
  Architecture *glb;
  Address addr;
  int4 size;
  // TODO add partial listings

  s >> ws;
  if (s.eof()) {
    if (dcp->fd == (Funcdata *)0)
      throw IfaceExecutionError("No function selected");
    *status->fileoptr << "Assembly listing for " << dcp->fd->getName() << endl;
    addr = dcp->fd->getAddress();
    size = dcp->fd->getSize();
    glb = dcp->fd->getArch();
  }
  else {
    addr = parse_machaddr(s,size,*dcp->conf->types); // Read beginning address
    s >> ws;
    Address offset2=parse_machaddr(s,size,*dcp->conf->types);
    size = offset2.getOffset() - addr.getOffset();
    glb = dcp->conf;
  }
  IfaceAssemblyEmit assem(status->fileoptr,10);
  while(size > 0) {
    int4 sz;
    sz = glb->translate->printAssembly(assem,addr);
    addr = addr + sz;
    size -= sz;
  }
}

void IfcDump::execute(istream &s)

{				// Do hex listing of memory region
  int4 size;
  uint1 *buffer;
  Address offset = parse_machaddr(s,size,*dcp->conf->types);

  buffer = dcp->conf->loader->load(size,offset);
  print_data(*status->fileoptr,buffer,size,offset);
  delete [] buffer;
}

void IfcDumpbinary::execute(istream &s)

{				// Write part of load image to file
  int4 size;
  uint1 *buffer;
  Address offset = parse_machaddr(s,size,*dcp->conf->types);
  string filename;

  s >> ws;
  if (s.eof())
    throw IfaceParseError("Missing file name for binary dump");
  s >> filename;
  ofstream os;
  os.open(filename.c_str());
  if (!os)
    throw IfaceExecutionError("Unable to open file "+filename);

  buffer = dcp->conf->loader->load(size,offset);
  os.write((const char *)buffer,size);
  delete [] buffer;
  os.close();
}
  
void IfcDecompile::execute(istream &s)

{				// Do decompilation of current function
  int4 res;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  if (dcp->fd->hasNoCode()) {
    *status->optr << "No code for " << dcp->fd->getName() << endl;
    return;
  }
  if (dcp->fd->isProcStarted()) { // Free up old decompile
    *status->optr << "Clearing old decompilation" << endl;
    dcp->conf->clearAnalysis(dcp->fd);
  }
    
  *status->optr << "Decompiling " << dcp->fd->getName() << endl;
  dcp->conf->allacts.getCurrent()->reset(*dcp->fd);
  res = dcp->conf->allacts.getCurrent()->perform( *dcp->fd );
  if (res<0) {
    *status->optr << "Break at ";
    dcp->conf->allacts.getCurrent()->printState(*status->optr);
  }
  else {
    *status->optr << "Decompilation complete";
    if (res==0)
      *status->optr << " (no change)";
  }
  *status->optr << endl;
}

void IfcPrintCFlat::execute(istream &s)

{				// Print current decompilation as C
				// Do not print block structure
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->setFlat(true);
  dcp->conf->print->docFunction(dcp->fd);
  dcp->conf->print->setFlat(false);
}

void IfcPrintCGlobals::execute(istream &s)

{				// Print all global variable declarations we know
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->docAllGlobals();
}

void IfcPrintCTypes::execute(istream &s)

{				// Print all type definitions
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");

  if (dcp->conf->types != (TypeFactory *)0) {
    dcp->conf->print->setOutputStream(status->fileoptr);
    dcp->conf->print->docTypeDefinitions(dcp->conf->types);
  }
}

void IfcPrintCXml::execute(istream &s)

{				// Print current decompilation as C
				// Do not print block structure
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->setXML(true);
  dcp->conf->print->docFunction(dcp->fd);
  dcp->conf->print->setXML(false);
}

void IfcPrintCStruct::execute(istream &s)

{				// Print current decompilation as C
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->docFunction(dcp->fd);
}

void IfcPrintLanguage::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws;
  if (s.eof())
    throw IfaceParseError("No print language specified");
  string langroot;
  s >> langroot;
  langroot = langroot + "-language";

  string curlangname = dcp->conf->print->getName();
  dcp->conf->setPrintLanguage(langroot);
  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->docFunction(dcp->fd);
  dcp->conf->setPrintLanguage(curlangname); // Reset to original language
}

void IfcPrintRaw::execute(istream &s)

{				// Print current decompilation as cpui
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->printRaw(*status->fileoptr);
}

void IfcListaction::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");
  dcp->conf->allacts.getCurrent()->print(*status->fileoptr,0,0);
}

void IfcListOverride::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  *status->optr << "Function: " << dcp->fd->getName() << endl;
  dcp->fd->getOverride().printRaw(*status->optr,dcp->conf);
}

void IfcListprototypes::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  
  map<string,ProtoModel *>::const_iterator iter;
  for(iter=dcp->conf->protoModels.begin();iter!=dcp->conf->protoModels.end();++iter) {
    ProtoModel *model = (*iter).second;
    *status->optr << model->getName();
    if (model == dcp->conf->defaultfp)
      *status->optr << " default";
    else if (model == dcp->conf->evalfp_called)
      *status->optr << " eval called";
    else if (model == dcp->conf->evalfp_current)
      *status->optr << " eval current";
    *status->optr << endl;
  }
}

void IfcSetcontextrange::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");

  string name;
  s >> name >> ws;

  if (name.size()==0)
    throw IfaceParseError("Missing context variable name");

  s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  uintm value = 0xbadbeef;
  s >> value;
  if (value == 0xbadbeef)
    throw IfaceParseError("Missing context value");

  s >> ws;

  if (s.eof()) {		// No range indicates default value
    dcp->conf->context->setVariableDefault(name,value);
    return;
  }

  // Otherwise parse the range
  int4 size1,size2;
  Address addr1 = parse_machaddr(s,size1,*dcp->conf->types); // Read begin address
  Address addr2 = parse_machaddr(s,size2,*dcp->conf->types); // Read end address

  if (addr1.isInvalid() || addr2.isInvalid())
    throw IfaceParseError("Invalid address range");
  if (addr2 <= addr1)
    throw IfaceParseError("Bad address range");

  dcp->conf->context->setVariableRegion(name,addr1,addr2,value);
}

void IfcSettrackedrange::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");

  string name;
  s >> name >> ws;
  if (name.size() ==0)
    throw IfaceParseError("Missing tracked register name");

  s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  uintb value = 0xbadbeef;
  s >> value;
  if (value == 0xbadbeef)
    throw IfaceParseError("Missing context value");

  s >> ws;
  if (s.eof()) {		// No range indicates default value
    TrackedSet &track(dcp->conf->context->getTrackedDefault());
    track.push_back( TrackedContext() );
    track.back().loc = dcp->conf->translate->getRegister(name);
    track.back().val = value;
    return;
  }

  int4 size1,size2;
  Address addr1 = parse_machaddr(s,size1,*dcp->conf->types);
  Address addr2 = parse_machaddr(s,size2,*dcp->conf->types);
  
  if (addr1.isInvalid() || addr2.isInvalid())
    throw IfaceParseError("Invalid address range");
  if (addr2 <= addr1)
    throw IfaceParseError("Bad address range");

  TrackedSet &track(dcp->conf->context->createSet(addr1,addr2));
  TrackedSet &def(dcp->conf->context->getTrackedDefault());
  track = def;			// Start with default as base
  track.push_back( TrackedContext() );
  track.back().loc = dcp->conf->translate->getRegister(name);
  track.back().val = value;
}

void IfcBreakaction::execute(istream &s)

{				// Set an action breakpoint
  bool res;
  string specify;

  s >> specify >> ws;		// Which action or rule to put breakpoint on

  if (specify.empty())
    throw IfaceExecutionError("No action/rule specified");

  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");

  res = dcp->conf->allacts.getCurrent()->setBreakPoint(Action::break_action, specify);
  if (!res)
    throw IfaceExecutionError("Bad action/rule specifier: "+specify);
}

void IfcBreakstart::execute(istream &s)

{				// Set a start breakpoint
  bool res;
  string specify;

  s >> specify >> ws;		// Which action or rule to put breakpoint on

  if (specify.empty())
    throw IfaceExecutionError("No action/rule specified");

  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");

  res = dcp->conf->allacts.getCurrent()->setBreakPoint(Action::break_start, specify);
  if (!res)
    throw IfaceExecutionError("Bad action/rule specifier: "+specify);
}

void IfcPrintTree::execute(istream &s)

{
  dcp->fd->printVarnodeTree(*status->fileoptr);
}

void IfcPrintBlocktree::execute(istream &s)

{
  dcp->fd->printBlockTree(*status->fileoptr);
}

void IfcPrintSpaces::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");

  const AddrSpaceManager *manage = dcp->conf;
  int4 num = manage->numSpaces();
  for(int4 i=0;i<num;++i) {
    AddrSpace *spc = manage->getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    *status->fileoptr << dec << spc->getIndex() << " : '" << spc->getShortcut() << "' " << spc->getName();
    if (spc->getType() == IPTR_CONSTANT)
      *status->fileoptr << " constant ";
    else if (spc->getType() == IPTR_PROCESSOR)
      *status->fileoptr << " processor";
    else if (spc->getType() == IPTR_SPACEBASE)
      *status->fileoptr << " spacebase";
    else if (spc->getType() == IPTR_INTERNAL)
      *status->fileoptr << " internal ";
    else
      *status->fileoptr << " special  ";
    if (spc->isBigEndian())
      *status->fileoptr << " big  ";
    else
      *status->fileoptr << " small";
    *status->fileoptr << " addrsize=" << spc->getAddrSize() << " wordsize=" << spc->getWordSize();
    *status->fileoptr << " delay=" << spc->getDelay();
    *status->fileoptr << endl;
  }
}

void IfcPrintHigh::execute(istream &s)

{				// List varnodes under one high
  string varname;
  HighVariable *high;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> varname >> ws;

  high = dcp->fd->findHigh(varname);
  if (high == (HighVariable *)0)	// Didn't find this name
    throw IfaceExecutionError("Unknown variable name: "+varname);

  high->printInfo(*status->optr);
}

void IfcParamIDAnalysis::execute(istream &s)
{
  ParamIDAnalysis pidanalysis( dcp->fd, false );
  pidanalysis.saveXml( *status->optr, true );
  *status->optr << "\n"; //tmp
  //dcp->fd->saveXml( *status->optr, true ); //temporary until I write a new one with results.
}
void IfcPrintParamMeasures::execute(istream &s)
{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  ParamIDAnalysis pidanalysis( dcp->fd, false );
  pidanalysis.savePretty( *status->fileoptr, true );
  *status->fileoptr << "\n";

//  dcp->conf->print->setOutputStream(status->fileoptr);
//  dcp->conf->print->docFunction(dcp->fd);
}
void IfcPrintParamMeasuresXml::execute(istream &s)
{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  ParamIDAnalysis pidanalysis( dcp->fd, false );
  pidanalysis.saveXml( *status->fileoptr, true );
  *status->fileoptr << "\n";

//  dcp->conf->print->setOutputStream(status->fileoptr);
//  dcp->conf->print->setXML(true);
//  dcp->conf->print->docFunction(dcp->fd);
//  dcp->conf->print->setXML(false);
}

void IfcRename::execute(istream &s)

{				// Change the name of a symbol
  string oldname,newname;
  
  s >> ws >> oldname >> ws >> newname >> ws;
  if (oldname.size()==0)
    throw IfaceParseError("Missing old symbol name");
  if (newname.size()==0)
    throw IfaceParseError("Missing new name");
    
  Symbol *sym;
  vector<Symbol *> symList;
  if (dcp->fd != (Funcdata *)0)
    dcp->fd->getScopeLocal()->queryByName(oldname,symList);
  else
    dcp->conf->symboltab->getGlobalScope()->queryByName(oldname,symList);
  
  if (symList.empty())
    throw IfaceExecutionError("No symbol named: "+oldname);
  if (symList.size() == 1)
    sym = symList[0];
  else
    throw IfaceExecutionError("More than one symbol named: "+oldname);

  if (sym->getCategory() == 0)
    dcp->fd->getFuncProto().setInputLock(true);
  sym->getScope()->renameSymbol(sym,newname);
  sym->getScope()->setAttribute(sym,Varnode::namelock|Varnode::typelock);
}

void IfcRemove::execute(istream &s)

{				// Remove a symbol
  string name;
  
  s >> ws >> name;
  if (name.size()==0)
    throw IfaceParseError("Missing symbol name");

  vector<Symbol *> symList;
  if (dcp->fd != (Funcdata *)0)
    dcp->fd->getScopeLocal()->queryByName(name,symList);
  else
    dcp->conf->symboltab->getGlobalScope()->queryByName(name,symList);
  
  if (symList.empty())
    throw IfaceExecutionError("No symbol named: "+name);
  if (symList.size() > 1)
    throw IfaceExecutionError("More than one symbol named: "+name);
  symList[0]->getScope()->removeSymbol(symList[0]);
}

void IfcRetype::execute(istream &s)

{				// Change the type of a symbol
  Datatype *ct;
  string name,newname;

  s >> ws >> name;
  if (name.size()==0)
    throw IfaceParseError("Must specify name of symbol");
  ct = parse_type(s,newname,dcp->conf);

  Symbol *sym;
  vector<Symbol *> symList;
  if (dcp->fd != (Funcdata *)0)
    dcp->fd->getScopeLocal()->queryByName(name,symList);
  else
    dcp->conf->symboltab->getGlobalScope()->queryByName(name,symList);
  
  if (symList.empty())
    throw IfaceExecutionError("No symbol named: "+name);
  if (symList.size() > 1)
    throw IfaceExecutionError("More than one symbol named : "+name);
  else
    sym = symList[0];

  if (sym->getCategory()==0)
    dcp->fd->getFuncProto().setInputLock(true);
  sym->getScope()->retypeSymbol(sym,ct);
  sym->getScope()->setAttribute(sym,Varnode::typelock);
  if ((newname.size()!=0)&&(newname != name)) {
    sym->getScope()->renameSymbol(sym,newname);
    sym->getScope()->setAttribute(sym,Varnode::namelock);
  }
}
  
static Varnode *iface_read_varnode(IfaceDecompData *dcp,istream &s)

{				// Return varnode identified by input stream
  uintm uq;
  int4 defsize;
  Varnode *vn = (Varnode *)0;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Address pc;
  Address loc(parse_varnode(s,defsize,pc,uq,*dcp->conf->types));
  if (pc.isInvalid()&&(uq==~((uintm)0)))
    vn = dcp->fd->findVarnodeInput(defsize,loc);
  else if ((!pc.isInvalid())&&(uq!=~((uintm)0)))
    vn = dcp->fd->findVarnodeWritten(defsize,loc,pc,uq);
  else {
    VarnodeLocSet::const_iterator iter,enditer;
    iter = dcp->fd->beginLoc(defsize,loc);
    enditer = dcp->fd->endLoc(defsize,loc);
    while(iter != enditer) {
      vn = *iter++;
      if (vn->isFree()) continue;
      if (vn->isWritten()) {
	if ((!pc.isInvalid()) && (vn->getDef()->getAddr()==pc)) break;
	if ((uq!=~((uintm)0))&&(vn->getDef()->getTime()==uq)) break;
      }
    }
  }

  if (vn == (Varnode *)0)
    throw IfaceExecutionError("Requested varnode does not exist");
  return vn;
}

void IfcPrintVarnode::execute(istream &s)

{				// Print information about a varnode
  Varnode *vn;

  vn = iface_read_varnode(dcp,s);
  if (vn->isAnnotation()||(!dcp->fd->isHighOn()))
    vn->printInfo(*status->optr);
  else
    vn->getHigh()->printInfo(*status->optr);
}
  
void IfcPrintCover::execute(istream &s)

{				// Print4 coverage information about a high
  HighVariable *high;
  string name;

  s >> ws >> name;
  if (name.size()==0)
    throw IfaceParseError("Missing variable name");
  high = dcp->fd->findHigh(name);
  if (high == (HighVariable *)0)
    throw IfaceExecutionError("Unable to find variable: "+name);
  
  high->printCover(*status->optr);
}

void IfcVarnodehighCover::execute(istream &s)

{				// Print4 coverage information about a varnode's high
  Varnode *vn;

  vn = iface_read_varnode(dcp,s);
  if (vn == (Varnode *)0)
    throw IfaceParseError("Unknown varnode");
  if (vn->getHigh() != (HighVariable *)0)
    vn->getHigh()->printCover(*status->optr);
  else
    *status->optr << "Unmerged" << endl;
}

void IfcPrintExtrapop::execute(istream &s)

{
  string name;

  s >> ws >> name;
  if (name.size() == 0) {
    if (dcp->fd != (Funcdata *)0) {
      int4 num = dcp->fd->numCalls();
      for(int4 i=0;i<num;++i) {
	FuncCallSpecs *fc = dcp->fd->getCallSpecs(i);
	*status->optr << "ExtraPop for " << fc->getName() << '(';
	*status->optr << fc->getOp()->getAddr() << ')';
	int4 expop = fc->getEffectiveExtraPop();
	*status->optr << " ";
	if (expop == ProtoModel::extrapop_unknown)
	  *status->optr << "unknown";
	else
	  *status->optr << dec << expop;
	*status->optr << '(';
	expop = fc->getExtraPop();
	if (expop == ProtoModel::extrapop_unknown)
	  *status->optr << "unknown";
	else
	  *status->optr << dec << expop;
	*status->optr << ')' << endl;
      }
    }
    else {
      int4 expop = dcp->conf->defaultfp->getExtraPop();
      *status->optr << "Default extra pop = ";
      if (expop == ProtoModel::extrapop_unknown)
	*status->optr << "unknown" << endl;
      else
	*status->optr << dec << expop << endl;
    }
  }
  else {
    Funcdata *fd;
    fd = dcp->conf->symboltab->getGlobalScope()->queryFunction( name );
    if (fd == (Funcdata *)0)
      throw IfaceExecutionError("Unknown function: "+name);
    int4 expop = fd->getFuncProto().getExtraPop();
    *status->optr << "ExtraPop for function " << name << " is ";
    if (expop == ProtoModel::extrapop_unknown)
      *status->optr << "unknown" << endl;
    else
      *status->optr << dec << expop << endl;
    if (dcp->fd != (Funcdata *)0) {
      int4 num = dcp->fd->numCalls();
      for(int4 i=0;i<num;++i) {
	FuncCallSpecs *fc = dcp->fd->getCallSpecs(i);
	if (fc->getName() == fd->getName()) {
	  expop = fc->getEffectiveExtraPop();
	  *status->optr << "For this function, extrapop = ";
	  if (expop == ProtoModel::extrapop_unknown)
	    *status->optr << "unknown";
	  else
	    *status->optr << dec << expop;
	  *status->optr << '(';
	  expop = fc->getExtraPop();
	  if (expop == ProtoModel::extrapop_unknown)
	    *status->optr << "unknown";
	  else
	    *status->optr << dec << expop;
	  *status->optr << ')' << endl;
	}
      }
    }
  }
}

void IfcVarnodeCover::execute(istream &s)

{				// Print4 coverage information about a varnode
  Varnode *vn;

  vn = iface_read_varnode(dcp,s);
  if (vn == (Varnode *)0)
    throw IfaceParseError("Unknown varnode");
  vn->printCover(*status->optr);
}

void IfcNameVarnode::execute(istream &s)

{
  string token;
  int4 size;
  uintm uq;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Address pc;
  Address loc(parse_varnode(s,size,pc,uq,*dcp->conf->types)); // Get specified varnode

  s >> ws >> token;		// Get the new name of the varnode
  if (token.size()==0)
    throw IfaceParseError("Must specify name");

  Datatype *ct = dcp->conf->types->getBase(size,TYPE_UNKNOWN);

  dcp->conf->clearAnalysis(dcp->fd); // Make sure varnodes are cleared

  Scope *scope = dcp->fd->getScopeLocal()->discoverScope(loc,size,pc);
  if (scope == (Scope *)0)	// Variable does not have natural scope
    scope = dcp->fd->getScopeLocal();	// force it to be in function scope
  Symbol *sym = scope->addSymbol(token,ct,loc,pc)->getSymbol();
  scope->setAttribute(sym,Varnode::namelock);

  *status->fileoptr << "Successfully added " << token;
  *status->fileoptr << " to scope " << scope->getFullName() << endl;
}

void IfcTypeVarnode::execute(istream &s)

{				// Set the type of a varnode
  int4 size;
  uintm uq;
  Datatype *ct;
  string name;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Address pc;
  Address loc(parse_varnode(s,size,pc,uq,*dcp->conf->types)); // Get specified varnode
  ct = parse_type(s,name,dcp->conf);

  dcp->conf->clearAnalysis(dcp->fd); // Make sure varnodes are cleared
    
  Scope *scope = dcp->fd->getScopeLocal()->discoverScope(loc,size,pc);
  if (scope == (Scope *)0)	// Variable does not have natural scope
    scope = dcp->fd->getScopeLocal();	// force it to be in function scope
  Symbol *sym = scope->addSymbol(name,ct,loc,pc)->getSymbol();
  scope->setAttribute(sym,Varnode::typelock);
  sym->setIsolated(true);
  if (name.size() > 0)
    scope->setAttribute(sym,Varnode::namelock);
  
  *status->fileoptr << "Successfully added " << sym->getName();
  *status->fileoptr << " to scope " << scope->getFullName() << endl;
}

static Varnode *find_varnode_via_op(istream &s,Funcdata *fd,const TypeFactory &typegrp)

{
  uintm uq;
  Address pc(parse_op(s,uq,typegrp));
  PcodeOp *op = fd->findOp(SeqNum(pc,uq));
  if (op == (PcodeOp *)0)
    throw IfaceExecutionError("Unable to find indicated op");

  int4 slot;
  slot = -2;
  s >> dec >> slot;
  if (slot == -2)
    throw IfaceParseError("Missing op slot number");
  Varnode *vn;
  if (slot == -1)
    vn = op->getOut();
  else {
    if (slot >= op->numInput())
      throw IfaceExecutionError("op slot number is out of range");
    vn = op->getIn(slot);
  }
  return vn;
}

void IfcForceHex::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Varnode *vn = find_varnode_via_op(s,dcp->fd,*dcp->conf->types);
  if (!vn->isConstant())
    throw IfaceExecutionError("Can only force hex on a constant");
  type_metatype mt = vn->getType()->getMetatype();
  if ((mt!=TYPE_INT)&&(mt!=TYPE_UINT)&&(mt!=TYPE_UNKNOWN))
    throw IfaceExecutionError("Can only force hex on integer type constant");
  dcp->fd->buildDynamicSymbol(vn);
  Symbol *sym = vn->getHigh()->getSymbol();
  if (sym == (Symbol *)0)
    throw IfaceExecutionError("Unable to create symbol");
  sym->getScope()->setDisplayFormat(sym,Symbol::force_hex);
  sym->getScope()->setAttribute(sym,Varnode::typelock);
  *status->optr << "Successfully forced hex display" << endl;
}

void IfcForceDec::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Varnode *vn = find_varnode_via_op(s,dcp->fd,*dcp->conf->types);
  if (!vn->isConstant())
    throw IfaceExecutionError("Can only force hex on a constant");
  type_metatype mt = vn->getType()->getMetatype();
  if ((mt!=TYPE_INT)&&(mt!=TYPE_UINT)&&(mt!=TYPE_UNKNOWN))
    throw IfaceExecutionError("Can only force dec on integer type constant");
  dcp->fd->buildDynamicSymbol(vn);
  Symbol *sym = vn->getHigh()->getSymbol();
  if (sym == (Symbol *)0)
    throw IfaceExecutionError("Unable to create symbol");
  sym->getScope()->setDisplayFormat(sym,Symbol::force_dec);
  sym->getScope()->setAttribute(sym,Varnode::typelock);
  *status->optr << "Successfully forced dec display" << endl;
}

void IfcForcegoto::execute(istream &s)

{
  int4 discard;
  
  s >> ws;
  Address target(parse_machaddr(s,discard,*dcp->conf->types));
  s >> ws;
  Address dest(parse_machaddr(s,discard,*dcp->conf->types));
  dcp->fd->getOverride().insertForceGoto(target,dest);
}

void IfcProtooverride::execute(istream &s)

{
  int4 discard;
  
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws;
  Address callpoint(parse_machaddr(s,discard,*dcp->conf->types));
  int4 i;
  for(i=0;dcp->fd->numCalls();++i)
    if (dcp->fd->getCallSpecs(i)->getOp()->getAddr() == callpoint) break;
  if (i == dcp->fd->numCalls())
    throw IfaceExecutionError("No call is made at this address");

  PrototypePieces pieces;
  parse_protopieces(pieces,s,dcp->conf); // Parse the prototype from stream

  FuncProto *newproto = new FuncProto();

  // Make proto whose storage is internal, not backed by a real scope
  newproto->setInternal(pieces.model,dcp->conf->types->getTypeVoid());
  newproto->setPieces(pieces);
  dcp->fd->getOverride().insertProtoOverride(callpoint,newproto);
  dcp->fd->clear();		// Clear any analysis (this leaves overrides intact)
}

void IfcJumpOverride::execute(istream &s)

{
  int4 discard;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws;
  Address jmpaddr( parse_machaddr(s,discard,*dcp->conf->types));
  JumpTable *jt = dcp->fd->installJumpTable(jmpaddr);
  vector<Address> adtable;
  Address naddr;
  uintb h=0;
  uintb sv = 0;
  string token;
  s >> token;
//   if (token == "norm") {
//     naddr = parse_machaddr(s,discard,*dcp->conf->types);
//     s >> ws;
//     s >> h;
//     s >> token;
//   }
  if (token == "startval") {
    s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
    s >> sv;
    s >> token;
  }
  if (token == "table") {
    s >> ws;
    while(!s.eof()) {
      Address addr( parse_machaddr(s,discard,*dcp->conf->types));
      adtable.push_back(addr);
    }
  }
  if (adtable.empty())
    throw IfaceExecutionError("Missing jumptable address entries");
  jt->setOverride(adtable,naddr,h,sv);
  *status->optr << "Successfully installed jumptable override" << endl;
}

void IfcFlowOverride::execute(istream &s)

{
  int4 discard;
  uint4 type;
  string token;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws;
  Address addr( parse_machaddr(s,discard,*dcp->conf->types));
  s >> token;
  if (token.size() == 0)
    throw IfaceParseError("Missing override type");
  type = Override::stringToType(token);
  if (type == Override::NONE)
    throw IfaceParseError("Bad override type");

  dcp->fd->getOverride().insertFlowOverride(addr,type);
  *status->optr << "Successfully added override" << endl;
}

void IfcDeadcodedelay::execute(istream &s)

{
  string name;
  int4 delay = -1;
  AddrSpace *spc;
  
  s >> name;
  s >> ws;
  s >> delay;

  spc = dcp->conf->getSpaceByName(name);
  if (spc == (AddrSpace *)0)
    throw IfaceParseError("Bad space: "+name);
  if (delay == -1)
    throw IfaceParseError("Need delay integer");
  if (dcp->fd != (Funcdata *)0) {
    dcp->fd->getOverride().insertDeadcodeDelay(spc,delay);
    *status->optr << "Successfully overrided deadcode delay for single function" << endl;
  }
  else {
    dcp->conf->setDeadcodeDelay(spc,delay);
    *status->optr << "Successfully overrided deadcode delay for all functions" << endl;
  }
}

void IfcGlobalAdd::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No image loaded");
  
  int4 size;
  Address addr = parse_machaddr(s,size,*dcp->conf->types);
  uintb first = addr.getOffset();
  uintb last = first + (size-1);

  Scope *scope = dcp->conf->symboltab->getGlobalScope();
  dcp->conf->symboltab->addRange(scope,addr.getSpace(),first,last);
}

void IfcGlobalRemove::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No image loaded");
  
  int4 size;
  Address addr = parse_machaddr(s,size,*dcp->conf->types);
  uintb first = addr.getOffset();
  uintb last = first + (size-1);

  Scope *scope = dcp->conf->symboltab->getGlobalScope();
  dcp->conf->symboltab->removeRange(scope,addr.getSpace(),first,last);
}

void IfcGlobalify::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  dcp->conf->globalify();
  *status->optr << "Successfully made all registers/memory locations global" << endl;
}

void IfcGlobalRegisters::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  map<VarnodeData,string> reglist;
  dcp->conf->translate->getAllRegisters(reglist);
  map<VarnodeData,string>::const_iterator iter;
  AddrSpace *spc = (AddrSpace *)0;
  uintb lastoff=0;
  Scope *globalscope = dcp->conf->symboltab->getGlobalScope();
  int4 count = 0;
  for(iter=reglist.begin();iter!=reglist.end();++iter) {
    const VarnodeData &dat( (*iter).first );
    if (dat.space == spc) {
      if (dat.offset<=lastoff) continue; // Nested register def
    }
    spc = dat.space;
    lastoff = dat.offset+dat.size-1;
    Address addr(spc,dat.offset);
    uint4 flags=0;
    // Check if the register location is global
    globalscope->queryProperties(addr,dat.size,Address(),flags);
    if ((flags & Varnode::persist)!=0) {
      Datatype *ct = dcp->conf->types->getBase(dat.size,TYPE_UINT);
      globalscope->addSymbol((*iter).second,ct,addr,Address());
      count += 1;
    }
  }
  if (count == 0)
    *status->optr << "No global registers" << endl;
  else
    *status->optr << "Successfully made a global symbol for " << count << " registers" << endl;
}

static bool nontrivial_use(Varnode *vn)

{
  vector<Varnode *> vnlist;
  bool res = false;
  vnlist.push_back(vn);
  uint4 proc = 0;
  while(proc < vnlist.size()) {
    Varnode *tmpvn = vnlist[proc];
    proc += 1;
    list<PcodeOp *>::const_iterator iter;
    for(iter=tmpvn->beginDescend();iter!=tmpvn->endDescend();++iter) {
      PcodeOp *op = *iter;
      if ((op->code() == CPUI_COPY)||
	  (op->code() == CPUI_CAST)||
	  (op->code() == CPUI_INDIRECT) ||
	  (op->code() == CPUI_MULTIEQUAL)) {
	Varnode *outvn = op->getOut();
	if (!outvn->isMark()) {
	  outvn->setMark();
	  vnlist.push_back(outvn);
	}
      }
      else {
	res = true;
	break;
      }
    }
  }
  for(int4 i=0;i<vnlist.size();++i)
    vnlist[i]->clearMark();
  return res;
}

static int4 check_restore(Varnode *vn)

{ // Return 0 if vn is written to from an input at the same location
  vector<Varnode *> vnlist;
  int4 res = 0;
  vnlist.push_back(vn);
  uint4 proc = 0;
  while(proc < vnlist.size()) {
    Varnode *tmpvn = vnlist[proc];
    proc += 1;
    if (tmpvn->isInput()) {
      if ((tmpvn->getSize() != vn->getSize()) ||
	  (tmpvn->getAddr() != vn->getAddr())) {
	res = 1;
	break;
      }
    }
    else if (!tmpvn->isWritten()) {
      res = 1;
      break;
    }
    else {
      PcodeOp *op = tmpvn->getDef();
      if ((op->code() == CPUI_COPY)||(op->code()==CPUI_CAST)) {
	tmpvn = op->getIn(0);
	if (!tmpvn->isMark()) {
	  tmpvn->setMark();
	  vnlist.push_back(tmpvn);
	}
      }
      else if (op->code() == CPUI_INDIRECT) {
	tmpvn = op->getIn(0);
	if (!tmpvn->isMark()) {
	  tmpvn->setMark();
	  vnlist.push_back(tmpvn);
	}
      }
      else if (op->code() == CPUI_MULTIEQUAL) {
	for(int4 i=0;i<op->numInput();++i) {
	  tmpvn = op->getIn(i);
	  if (!tmpvn->isMark()) {
	    tmpvn->setMark();
	    vnlist.push_back(tmpvn);
	  }
	}
      }
      else {
	res = 1;
	break;
      }
    }
  }
  for(int4 i=0;i<vnlist.size();++i)
    vnlist[i]->clearMark();
  return res;
}

static bool find_restore(Varnode *vn,Funcdata *fd)

{
  VarnodeLocSet::const_iterator iter,enditer;

  iter = fd->beginLoc(vn->getAddr());
  enditer = fd->endLoc(vn->getAddr());
  int4 count = 0;
  while(iter != enditer) {
    Varnode *vn = *iter;
    ++iter;
    if (!vn->hasNoDescend()) continue;
    if (!vn->isWritten()) continue;
    PcodeOp *op = vn->getDef();
    if (op->code() == CPUI_INDIRECT) continue; // Not a global return address force
    int4 res = check_restore(vn);
    if (res != 0) return false;
    count += 1;
  }
  return (count>0);
}

static void print_function_inputs(Funcdata *fd,ostream &s)

{
  VarnodeDefSet::const_iterator iter,enditer;

  s << "Function: " << fd->getName() << endl;
  iter = fd->beginDef(Varnode::input);
  enditer = fd->endDef(Varnode::input);
  while(iter != enditer) {
    Varnode *vn = *iter;
    ++iter;
    vn->printRaw(s);
    if (fd->isHighOn()) {
      Symbol *sym = vn->getHigh()->getSymbol();
      if (sym != (Symbol *)0)
	s << "    " << sym->getName();
    }
    bool findres = find_restore(vn,fd);
    bool nontriv = nontrivial_use(vn);
    if (findres && !nontriv)
      s << "     restored";
    else if (nontriv)
      s << "     nontriv";
    s << endl;
  }
}

void IfcPrintInputs::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  print_function_inputs(dcp->fd,*status->fileoptr);
}

void IfcPrintInputsAll::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");

  iterateFunctionsAddrOrder();
}

void IfcPrintInputsAll::iterationCallback(Funcdata *fd)

{
  if (fd->hasNoCode()) {
    *status->optr << "No code for " << fd->getName() << endl;
    return;
  }
  try {
    dcp->conf->clearAnalysis(fd); // Clear any old analysis
    dcp->conf->allacts.getCurrent()->reset(*fd);
    dcp->conf->allacts.getCurrent()->perform( *fd );
    print_function_inputs(fd,*status->fileoptr);
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
  }
  dcp->conf->clearAnalysis(fd);
}

void IfcLockPrototype::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->getFuncProto().setInputLock(true);
  dcp->fd->getFuncProto().setOutputLock(true);
}

void IfcUnlockPrototype::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->getFuncProto().setInputLock(false);
  dcp->fd->getFuncProto().setOutputLock(false);
}

void IfcPrintLocalrange::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->printLocalRange( *status->optr );
}

void IfcPrintMap::execute(istream &s)

{
  string name;
  Scope *scope;

  s >> name;
  
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image");
  if (name.size() != 0 || dcp->fd==(Funcdata *)0) {
    string fullname = name + "::a";		// Add fake variable name
    scope = dcp->conf->symboltab->resolveScopeFromSymbolName(fullname, "::", fullname, (Scope *)0);
  }
  else
    scope = dcp->fd->getScopeLocal();
    
  if (scope == (Scope *)0)
    throw IfaceExecutionError("No map named: "+name);

  *status->fileoptr << scope->getFullName() << endl;
  scope->printBounds(*status->fileoptr);
  scope->printEntries(*status->fileoptr);
}
  
void IfcProduceC::execute(istream &s)

{				// Produce C output of every known function
  string name;
  
  s >> ws >> name;
  if (name.size()==0)
    throw IfaceParseError("Need file name to write to");
  
  ofstream os;
  os.open(name.c_str());
  dcp->conf->print->setOutputStream(&os);

  iterateFunctionsAddrOrder();

  os.close();
}

void IfcProduceC::iterationCallback(Funcdata *fd)

{
  clock_t start_time,end_time;
  float duration;

  if (fd->hasNoCode()) {
    *status->optr << "No code for " << fd->getName() << endl;
    return;
  }
  try {
    dcp->conf->clearAnalysis(fd); // Clear any old analysis
    dcp->conf->allacts.getCurrent()->reset(*fd);
    start_time = clock();
    dcp->conf->allacts.getCurrent()->perform( *fd );
    end_time = clock();
    *status->optr << "Decompiled " << fd->getName();
    //	  *status->optr << ": " << hex << fd->getAddress().getOffset();
    *status->optr << '(' << dec << fd->getSize() << ')';
    duration = ((float)(end_time-start_time))/CLOCKS_PER_SEC;
    duration *= 1000.0;
    *status->optr << " time=" << fixed << setprecision(0) << duration << " ms" << endl;
    dcp->conf->print->docFunction(fd);
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
  }
  dcp->conf->clearAnalysis(fd);
}

void IfcProducePrototypes::execute(istream &s)

{  // Walk callgraph in leaf-first order, calculate prototype
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image");
  if (dcp->cgraph == (CallGraph *)0)
    throw IfaceExecutionError("Callgraph has not been built");
  if (dcp->conf->evalfp_current == (ProtoModel *)0) {
    *status->optr << "Always using default prototype" << endl;
    return;
  }

  if (!dcp->conf->evalfp_current->isMerged()) {
    *status->optr << "Always using prototype " << dcp->conf->evalfp_current->getName() << endl;
    return;
  }
  ProtoModelMerged *model = (ProtoModelMerged *)dcp->conf->evalfp_current;
  *status->optr << "Trying to distinguish between prototypes:" << endl;
  for(int4 i=0;i<model->numModels();++i)
    *status->optr << "  " << model->getModel(i)->getName() << endl;

  iterateFunctionsLeafOrder();
}

void IfcProducePrototypes::iterationCallback(Funcdata *fd)

{
  clock_t start_time,end_time;
  float duration;

  *status->optr << fd->getName() << ' ';
  if (fd->hasNoCode()) {
    *status->optr << "has no code" << endl;
    return;
  }
  if (fd->getFuncProto().isInputLocked()) {
    *status->optr << "has locked prototype" << endl;
    return;
  }
  try {
    dcp->conf->clearAnalysis(fd); // Clear any old analysis
    dcp->conf->allacts.getCurrent()->reset(*fd);
    start_time = clock();
    dcp->conf->allacts.getCurrent()->perform( *fd );
    end_time = clock();
    //    *status->optr << "Decompiled " << fd->getName();
    //    *status->optr << '(' << dec << fd->getSize() << ')';
    *status->optr << "proto=" << fd->getFuncProto().getModelName();
    fd->getFuncProto().setModelLock(true);
    duration = ((float)(end_time-start_time))/CLOCKS_PER_SEC;
    duration *= 1000.0;
    *status->optr << " time=" << fixed << setprecision(0) << duration << " ms" << endl;
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
  }
  dcp->conf->clearAnalysis(fd);
}

void IfcContinue::execute(istream &s)

{				// Continue decompilation after breakpoint
  int4 res;

  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  if (dcp->conf->allacts.getCurrent()->getStatus() == Action::status_start)
    throw IfaceExecutionError("Decompilation has not been started");
  if (dcp->conf->allacts.getCurrent()->getStatus() == Action::status_end)
    throw IfaceExecutionError("Decompilation is already complete");

  res = dcp->conf->allacts.getCurrent()->perform( *dcp->fd ); // Try to continue decompilation
  if (res<0) {
    *status->optr << "Break at ";
    dcp->conf->allacts.getCurrent()->printState(*status->optr);
  }
  else {
    *status->optr << "Decompilation complete";
    if (res==0)
      *status->optr << " (no change)";
  }
  *status->optr << endl;
}

void IfcGraphDataflow::execute(istream &s)

{				// Dump data-flow graph
  string filename;

  s >> filename;
  if (filename.size()==0)
    throw IfaceParseError("Missing output file");
  if (!dcp->fd->isProcStarted())
    throw IfaceExecutionError("Syntax tree not calculated");
  ofstream thefile( filename.c_str());
  if (!thefile)
    throw IfaceExecutionError("Unable to open output file: "+filename);

  dump_dataflow_graph(*dcp->fd,thefile);
  thefile.close();
}

void IfcGraphControlflow::execute(istream &s)

{				// Dump control-flow graph
  string filename;

  s >> filename;
  if (filename.size()==0)
    throw IfaceParseError("Missing output file");
  if (dcp->fd->getBasicBlocks().getSize()==0)
    throw IfaceExecutionError("Basic block structure not calculated");
  ofstream thefile( filename.c_str());
  if (!thefile)
    throw IfaceExecutionError("Unable to open output file: "+filename);

  dump_controlflow_graph(dcp->fd->getName(),dcp->fd->getBasicBlocks(),thefile);
  thefile.close();
}

void IfcGraphDom::execute(istream &s)

{				// Dump forward dominator graph
  string filename;

  s >> filename;
  if (filename.size()==0)
    throw IfaceParseError("Missing output file");
  if (!dcp->fd->isProcStarted())
    throw IfaceExecutionError("Basic block structure not calculated");
  ofstream thefile( filename.c_str());
  if (!thefile)
    throw IfaceExecutionError("Unable to open output file: "+filename);

  dump_dom_graph(dcp->fd->getName(),dcp->fd->getBasicBlocks(),thefile);
  thefile.close();
}

void IfcCommentInstr::execute(istream &s)

{ // Comment on a particular address within current function
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  int4 size;
  Address addr = parse_machaddr(s,size,*dcp->conf->types);
  s >> ws;
  string comment;
  char tok;
  s.get(tok);
  while(!s.eof()) {
    comment += tok;
    s.get(tok);
  }
  uint4 type = dcp->conf->print->getInstructionComment();
  dcp->conf->commentdb->addComment(type,
				  dcp->fd->getAddress(),addr,comment);
}

static void duplicate_hash(Funcdata *fd,ostream &s)

{ // Make sure no two varnodes of -fd- have the same hash
  DynamicHash dhash;

  VarnodeLocSet::const_iterator iter,enditer;
  pair<set<uint8>::iterator,bool> res;
  iter = fd->beginLoc();
  enditer = fd->endLoc();
  while(iter != enditer) {
    Varnode *vn = *iter;
    ++iter;
    if (vn->isAnnotation()) continue;
    if (vn->isConstant()) {
      PcodeOp *op = vn->loneDescend();
      int4 slot = op->getSlot(vn);
      if (slot == 0) {
	if (op->code() == CPUI_LOAD) continue;
	if (op->code() == CPUI_STORE) continue;
	if (op->code() == CPUI_RETURN) continue;
      }
    }
    else if (vn->getSpace()->getType() != IPTR_INTERNAL)
      continue;
    else if (vn->isImplied())
      continue;
    dhash.uniqueHash(vn,fd);
    if (dhash.getHash() == 0) {
      // We have a duplicate
      const PcodeOp *op;
      if (vn->beginDescend() != vn->endDescend())
	op = *vn->beginDescend();
      else
	op = vn->getDef();
      s << "Could not get unique hash for : ";
      vn->printRaw(s);
      s << " : ";
      op->printRaw(s);
      s << endl;
      return;
    }
    uint4 total = DynamicHash::getTotalFromHash(dhash.getHash());
    if (total != 1) {
      const PcodeOp *op;
      if (vn->beginDescend() != vn->endDescend())
	op = *vn->beginDescend();
      else
	op = vn->getDef();
      s << "Duplicate : ";
      s << dec << DynamicHash::getPositionFromHash(dhash.getHash()) << " out of " << total << " : ";
      vn->printRaw(s);
      s << " : ";
      op->printRaw(s);
      s << endl;
    }
  }
}

void IfcDuplicateHash::execute(istream &s)

{ // Make sure no two varnodes in the 
  iterateFunctionsAddrOrder();
}

void IfcDuplicateHash::iterationCallback(Funcdata *fd)

{
  clock_t start_time,end_time;
  float duration;

  if (fd->hasNoCode()) {
    *status->optr << "No code for " << fd->getName() << endl;
    return;
  }
  try {
    dcp->conf->clearAnalysis(fd); // Clear any old analysis
    dcp->conf->allacts.getCurrent()->reset(*fd);
    start_time = clock();
    dcp->conf->allacts.getCurrent()->perform( *fd );
    end_time = clock();
    *status->optr << "Decompiled " << fd->getName();
    //	  *status->optr << ": " << hex << fd->getAddress().getOffset();
    *status->optr << '(' << dec << fd->getSize() << ')';
    duration = ((float)(end_time-start_time))/CLOCKS_PER_SEC;
    duration *= 1000.0;
    *status->optr << " time=" << fixed << setprecision(0) << duration << " ms" << endl;
    duplicate_hash(fd,*status->optr);
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
  }
  dcp->conf->clearAnalysis(fd);
}


void IfcCallGraphBuild::execute(istream &s)

{ // Build call graph from existing function starts
  dcp->allocateCallGraph();

  dcp->cgraph->buildAllNodes();		// Build a node in the graph for existing symbols
  quick = false;
  iterateFunctionsAddrOrder();
  *status->optr << "Successfully built callgraph" << endl;
}

void IfcCallGraphBuild::iterationCallback(Funcdata *fd)

{
  clock_t start_time,end_time;
  float duration;

  if (fd->hasNoCode()) {
    *status->optr << "No code for " << fd->getName() << endl;
    return;
  }
  if (quick) {
    dcp->fd = fd;
    IfcFollowFlow(*status->optr,dcp,fd->getAddress(),0);
  }
  else {
    try {
      dcp->conf->clearAnalysis(fd); // Clear any old analysis
      dcp->conf->allacts.getCurrent()->reset(*fd);
      start_time = clock();
      dcp->conf->allacts.getCurrent()->perform( *fd );
      end_time = clock();
      *status->optr << "Decompiled " << fd->getName();
      //	  *status->optr << ": " << hex << fd->getAddress().getOffset();
      *status->optr << '(' << dec << fd->getSize() << ')';
      duration = ((float)(end_time-start_time))/CLOCKS_PER_SEC;
      duration *= 1000.0;
      *status->optr << " time=" << fixed << setprecision(0) << duration << " ms" << endl;
    }
    catch(LowlevelError &err) {
      *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
    }
  }
  dcp->cgraph->buildEdges(fd);
  dcp->conf->clearAnalysis(fd);
}

void IfcCallGraphBuildQuick::execute(istream &s)

{ // Build call graph from existing function starts, do only disassembly
  dcp->allocateCallGraph();
  dcp->cgraph->buildAllNodes();	// Build a node in the graph for existing symbols
  quick = true;
  iterateFunctionsAddrOrder();
  *status->optr << "Successfully built callgraph" << endl;
}

void IfcCallGraphDump::execute(istream &s)

{
  if (dcp->cgraph == (CallGraph *)0)
    throw IfaceExecutionError("No callgraph has been built");

  string name;
  s >> ws >> name;
  if (name.size() == 0)
    throw IfaceParseError("Need file name to write callgraph to");

  ofstream os;
  os.open(name.c_str());
  if (!os)
    throw IfaceExecutionError("Unable to open file "+name);

  dcp->cgraph->saveXml(os);
  os.close();
  *status->optr << "Successfully saved callgraph to " << name << endl;
}

void IfcCallGraphLoad::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");
  if (dcp->cgraph != (CallGraph *)0)
    throw IfaceExecutionError("Callgraph already loaded");

  string name;

  s >> ws >> name;
  if (name.size() == 0)
    throw IfaceExecutionError("Need name of file to read callgraph from");

  ifstream is(name.c_str());
  if (!is)
    throw IfaceExecutionError("Unable to open callgraph file "+name);

  DocumentStorage store;
  Document *doc = store.parseDocument(is);

  dcp->allocateCallGraph();
  dcp->cgraph->restoreXml(doc->getRoot());
  *status->optr << "Successfully read in callgraph" << endl;

  Scope *gscope = dcp->conf->symboltab->getGlobalScope();
  map<Address,CallGraphNode>::iterator iter,enditer;
  iter = dcp->cgraph->begin();
  enditer = dcp->cgraph->end();

  for(;iter!=enditer;++iter) {
    CallGraphNode *node = &(*iter).second;
    Funcdata *fd;
    fd = gscope->queryFunction(node->getName());
    if (fd == (Funcdata *)0)
      throw IfaceExecutionError("Function:" + node->getName() +" in callgraph has not been loaded");
    node->setFuncdata(fd);
  }

  *status->optr << "Successfully associated functions with callgraph nodes" << endl;
}

void IfcCallGraphList::execute(istream &s)

{ // List all functions in leaf-first order
  if (dcp->cgraph == (CallGraph *)0)
    throw IfaceExecutionError("Callgraph not generated");

  iterateFunctionsLeafOrder();
}

void IfcCallGraphList::iterationCallback(Funcdata *fd)

{
  *status->optr << fd->getName() << endl;
}

static void readPcodeSnippet(istream &s,string &name,string &outname,vector<string> &inname,string &pcodestring)

{
  char bracket;
  s >> outname;
  parse_toseparator(s,name);
  s >> bracket;
  if (outname == "void")
    outname = "";
  if (bracket != '(')
    throw IfaceParseError("Missing '('");
  while(bracket != ')') {
    string param;
    parse_toseparator(s,param);
    s >> bracket;
    if (param.size() != 0)
      inname.push_back(param);
  }
  s >> ws >> bracket;
  if (bracket != '{')
    throw IfaceParseError("Missing '{'");
  getline(s,pcodestring,'}');
}

void IfcCallFixup::execute(istream &s)

{
  string name,outname,pcodestring;
  vector<string> inname;

  readPcodeSnippet(s,name,outname,inname,pcodestring);
  int4 id = -1;
  try {
    id = dcp->conf->pcodeinjectlib->manualCallFixup(name,pcodestring);
  } catch(LowlevelError &err) {
    *status->optr << "Error compiling pcode: " << err.explain << endl;
    return;
  }
  InjectPayload *payload = dcp->conf->pcodeinjectlib->getPayload(id);
  payload->printTemplate(*status->optr);
}

void IfcCallOtherFixup::execute(istream &s)

{
  string useropname,outname,pcodestring;
  vector<string> inname;

  readPcodeSnippet(s,useropname,outname,inname,pcodestring);
  dcp->conf->userops.manualCallOtherFixup(useropname,outname,inname,pcodestring,dcp->conf);

  *status->optr << "Successfully registered callotherfixup" << endl;
}

void IfcVolatile::execute(istream &s)

{ // Mark a range as volatile
  int4 size = 0;
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read required address

  if (size == 0)
    throw IfaceExecutionError("Must specify a size");
  Range range( addr.getSpace(), addr.getOffset(), addr.getOffset() + (size-1));
  dcp->conf->symboltab->setPropertyRange(Varnode::volatil,range);

  *status->optr << "Successfully marked range as volatile" << endl;
}

void IfcReadonly::execute(istream &s)

{
  int4 size = 0;
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read required address

  if (size == 0)
    throw IfaceExecutionError("Must specify a size");
  Range range( addr.getSpace(), addr.getOffset(), addr.getOffset() + (size-1));
  dcp->conf->symboltab->setPropertyRange(Varnode::readonly,range);

  *status->optr << "Successfully marked range as readonly" << endl;
}

void IfcPreferSplit::execute(istream &s)

{ // Mark a particular storage location as something we would prefer to split
  int4 size = 0;
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  Address addr = parse_machaddr(s,size,*dcp->conf->types); // Read storage location
  if (size == 0)
    throw IfaceExecutionError("Must specify a size");
  int4 split = -1;

  s >> ws; 
  if (s.eof())
    throw IfaceParseError("Missing split offset");
  s >> dec >> split;
  if (split == -1)
    throw IfaceParseError("Bad split offset");
  dcp->conf->splitrecords.push_back(PreferSplitRecord());
  PreferSplitRecord &rec( dcp->conf->splitrecords.back() );

  rec.storage.space = addr.getSpace();
  rec.storage.offset = addr.getOffset();
  rec.storage.size = size;
  rec.splitoffset = split;

  *status->optr << "Successfully added split record" << endl;
}

void IfcStructureBlocks::execute(istream &s)

{ // Read in a control description file, structure the result and write it out
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");

  string infile,outfile;
  s >> infile;
  s >> outfile;

  if (infile.empty())
    throw IfaceParseError("Missing input file");
  if (outfile.empty())
    throw IfaceParseError("Missing output file");

  ifstream fs;
  fs.open(infile.c_str());
  if (!fs)
    throw IfaceExecutionError("Unable to open file: "+infile);
  
  DocumentStorage store;
  Document *doc = store.parseDocument(fs);
  fs.close();

  try {
    BlockGraph ingraph;
    ingraph.restoreXml(doc->getRoot(),dcp->conf);
    
    BlockGraph resultgraph;
    vector<FlowBlock *> rootlist;
    
    resultgraph.buildCopy(ingraph);
    resultgraph.structureLoops(rootlist);
    resultgraph.calcForwardDominator(rootlist);

    CollapseStructure collapse(resultgraph);
    collapse.collapseAll();

    ofstream sout;
    sout.open(outfile.c_str());
    if (!sout)
      throw IfaceExecutionError("Unable to open output file: "+outfile);
    resultgraph.saveXml(sout);
    sout.close();
  }
  catch(LowlevelError &err) {
    *status->optr << err.explain << endl;
  }
}

#ifdef CPUI_RULECOMPILE
void IfcParseRule::execute(istream &s)

{ // Parse a rule and print it out as a C routine
  string filename;
  bool debug = false;

  s >> filename;
  if (filename.size() == 0)
    throw IfaceParseError("Missing rule input file");

  s >> ws;
  if (!s.eof()) {
    string val;
    s >> val;
    if ((val=="true")||(val=="debug"))
      debug = true;
  }
  ifstream thefile( filename.c_str());
  if (!thefile)
    throw IfaceExecutionError("Unable to open rule file: "+filename);

  RuleCompile ruler;
  ruler.setErrorStream(*status->optr);
  ruler.run(thefile,debug);
  if (ruler.numErrors() != 0) {
    *status->optr << "Parsing aborted on error" << endl;
    return;
  }
  int4 opparam;
  vector<OpCode> opcodelist;
  opparam = ruler.postProcessRule(opcodelist);
  UnifyCPrinter cprinter;
  cprinter.initializeRuleAction(ruler.getRule(),opparam,opcodelist);
  cprinter.addNames(ruler.getNameMap());
  cprinter.print(*status->optr);
}

void IfcExperimentalRules::execute(istream &s)

{
  string filename;

  if (dcp->conf != (Architecture *)0)
    throw IfaceExecutionError("Experimental rules must be registered before loading architecture");
  s >> filename;
  if (filename.size() == 0)
    throw IfaceParseError("Missing name of file containing experimental rules");
  dcp->experimental_file = filename;
  *status->optr << "Successfully registered experimental file " << filename << endl;
}
#endif

void IfcPrintActionstats::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Image not loaded");
  if (dcp->conf->allacts.getCurrent() == (Action *)0)
    throw IfaceExecutionError("No action set");

  dcp->conf->allacts.getCurrent()->printStatistics(*status->fileoptr);
}

void IfcResetActionstats::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Image not loaded");
  if (dcp->conf->allacts.getCurrent() == (Action *)0)
    throw IfaceExecutionError("No action set");

  dcp->conf->allacts.getCurrent()->resetStats();
}

void IfcCountPcode::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Image not loaded");

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  uint4 count = 0;
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = dcp->fd->beginOpAlive();
  enditer = dcp->fd->endOpAlive();
  while(iter != enditer) {
    count += 1;
    ++iter;
  }
  *status->optr << "Count - pcode = " << dec << count << endl;
}

void IfcAnalyzeRange::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Image not loaded");
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  bool useFullWidener;
  string token;
  s >> ws >> token;
  if (token == "full")
    useFullWidener = true;
  else if (token == "partial") {
    useFullWidener = false;
  }
  else
    throw IfaceParseError("Must specify \"full\" or \"partial\" widening");
  Varnode *vn = iface_read_varnode(dcp,s);
  vector<Varnode *> sinks;
  vector<PcodeOp *> reads;
  sinks.push_back(vn);
  for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->code() == CPUI_LOAD || op->code() == CPUI_STORE)
      reads.push_back(op);
  }
  Varnode *stackReg = dcp->fd->findSpacebaseInput(dcp->conf->getStackSpace());
  ValueSetSolver vsSolver;
  vsSolver.establishValueSets(sinks, reads, stackReg, false);
  if (useFullWidener) {
    WidenerFull widener;
    vsSolver.solve(10000,widener);
  }
  else {
    WidenerNone widener;
    vsSolver.solve(10000,widener);
  }
  list<ValueSet>::const_iterator iter;
  for(iter=vsSolver.beginValueSets();iter!=vsSolver.endValueSets();++iter) {
    (*iter).printRaw(*status->optr);
    *status->optr << endl;
  }
  map<SeqNum,ValueSetRead>::const_iterator riter;
  for(riter=vsSolver.beginValueSetReads();riter!=vsSolver.endValueSetReads();++riter) {
    (*riter).second.printRaw(*status->optr);
    *status->optr << endl;
  }
}

#ifdef OPACTION_DEBUG

void IfcDebugAction::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");
  string actionname;
  s >> ws >> actionname;
  if (actionname.empty())
    throw IfaceParseError("Missing name of action to debug");
  if (!dcp->conf->allacts.getCurrent()->turnOnDebug(actionname))
    throw IfaceParseError("Unable to find action "+actionname);
}

void IfcTraceBreak::execute(istream &s)

{				// Set a opactdbg trace break point
  int4 count;
  
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws;
  s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  count = -1;
  s >> count;
  if (count == -1)
    throw IfaceParseError("Missing trace count");

  dcp->fd->debugSetBreak(count);
}

void IfcTraceAddress::execute(istream &s)

{				// Set a opactdbg trace point
  uintm uqlow,uqhigh;
  int4 discard;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Address pclow,pchigh;
  s >> ws;
  if (!s.eof()) {
    pclow = parse_machaddr(s,discard,*dcp->conf->types);
    s >> ws;
  }
  pchigh = pclow;
  if (!s.eof()) {
    pchigh = parse_machaddr(s,discard,*dcp->conf->types);
    s >> ws;
  }
  uqhigh = uqlow = ~((uintm)0);
  if (!s.eof()) {
    s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
    s >> uqlow >> uqhigh >> ws;
  }
  dcp->fd->debugSetRange(pclow,pchigh,uqlow,uqhigh);
  *status->optr << "OK (" << dec << dcp->fd->debugSize() << " ranges)\n";
}

void IfcTraceEnable::execute(istream &s)

{				// Turn on trace
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->debugEnable();
  *status->optr << "OK\n";
}

void IfcTraceDisable::execute(istream &s)

{				// Turn off trace
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->debugDisable();
  *status->optr << "OK\n";
}

void IfcTraceClear::execute(istream &s)

{				// Clear existing debug trace ranges
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  *status->optr << dec << dcp->fd->debugSize() << " ranges cleared\n";
  dcp->fd->debugDisable();
  dcp->fd->debugClear();
}

void IfcTraceList::execute(istream &s)

{				// List debug trace ranges
  int4 size,i;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  size = dcp->fd->debugSize();
  if (dcp->fd->opactdbg_on)
    *status->optr << "Trace enabled (";
  else
    *status->optr << "Trace disabled (";
  *status->optr << dec << size << " total ranges)\n";
  for(i=0;i<size;++i)
    dcp->fd->debugPrintRange(i);
}
    
static vector<Funcdata *> jumpstack;
static IfaceDecompData *dcp_callback;
static IfaceStatus *status_callback;

static void jump_callback(Funcdata &orig,Funcdata &fd)

{ // Replaces reset/perform in Funcdata::stageJumpTable
  IfaceDecompData *newdcp = dcp_callback;
  IfaceStatus *newstatus = status_callback;
  jumpstack.push_back(newdcp->fd);

  // We create a new "sub" interface using the same input output
  ostringstream s1;
  s1 << fd.getName() << "> ";
  // We keep the commands already registered.
  // We should probably "de"-register some of the commands
  // that can't really be used in this subcontext.
  newdcp->fd = &fd;
  Action *rootaction = newdcp->conf->allacts.getCurrent();
  rootaction->reset(*newdcp->fd);

  // Set a break point right at the start
  rootaction->setBreakPoint(Action::tmpbreak_start,rootaction->getName());
  // Start up the action
  int4 res = rootaction->perform( *newdcp->fd );
  if (res >= 0)
    throw LowlevelError("Did not catch jumptable breakpoint");
  *newstatus->optr << "Breaking for jumptable partial function" << endl;
  *newstatus->optr << newdcp->fd->getName() << endl;
  *newstatus->optr << "Type \"cont\" to continue debugging." << endl;
  *newstatus->optr << "After completion type \"quit\" to continue in parent." << endl;
  mainloop(newstatus);
  newstatus->done = false;	// "quit" only terminates one level
  *newstatus->optr << "Finished jumptable partial function" << endl;
  newdcp->fd = jumpstack.back();
  jumpstack.pop_back();
}

void IfcBreakjump::execute(istream &s)

{
  dcp->jumptabledebug = true;
  dcp_callback = dcp;
  status_callback = status;
  *status->optr << "Jumptable debugging enabled" << endl;
  if (dcp->fd != (Funcdata *)0)
    dcp->fd->enableJTCallback(jump_callback);
}

#endif

void execute(IfaceStatus *status,IfaceDecompData *dcp)

{				// Execute and catch exceptions
  try {
    status->runCommand();	// Try to run one commandline
    return;
  }
  catch(IfaceParseError &err) {
    *status->optr << "Command parsing error: " << err.explain << endl;
  }
  catch(IfaceExecutionError &err) {
    *status->optr << "Execution error: " << err.explain << endl;
  }
  catch(IfaceError &err) {
    *status->optr << "ERROR: " << err.explain << endl;
  }
  catch(ParseError &err) {
    *status->optr << "Parse ERROR: " << err.explain << endl;
  }
  catch(RecovError &err) {
    *status->optr << "Function ERROR: " << err.explain << endl;
  }
  catch(LowlevelError &err) {
    *status->optr << "Low-level ERROR: " << err.explain << endl;
    dcp->abortFunction(*status->optr);
  }
  catch(XmlError &err) {
    *status->optr << "XML ERROR: " << err.explain << endl;
    dcp->abortFunction(*status->optr);
  }
  status->evaluateError();
}

void mainloop(IfaceStatus *status) {
  IfaceDecompData *dcp = (IfaceDecompData *)status->getData("decompile");
  for(;;) {
    while(!status->isStreamFinished()) {
      status->writePrompt();
      status->optr->flush();
      execute(status,dcp);
    }
    if (status->done) break;
    if (status->getNumInputStreamSize()==0) break;
    status->popScript();
  }
}

void IfcSource::execute(istream &s)

{
  string filename;

  s >> ws;
  if (s.eof())
    throw IfaceParseError("filename parameter required for source");

  s >> filename;
  status->pushScript(filename,filename+"> ");
}

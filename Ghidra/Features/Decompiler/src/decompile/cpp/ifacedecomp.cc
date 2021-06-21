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

/// Runs over every function in the scope, or any sub-scope , calling
/// iterationCallback()
/// \param scope is the given scope
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

/// Runs over every function in the scope calling iterationCallback().
/// \param scope is the given scope
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

/// Scopes are traversed depth-first, then within a scope, functions are
/// traversed in address order.
void IfaceDecompCommand::iterateFunctionsAddrOrder(void)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No architecture loaded");
  iterateScopesRecursive(dcp->conf->symboltab->getGlobalScope());
}

/// Traversal is based on the current CallGraph for the program.
/// Child functions are traversed before their parents.
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

/// This is called if a command throws a low-level error.
/// It clears any analysis on the function, sets the current function
/// to null, and issues a warning.
/// \param s is the stream to write the warning to
void IfaceDecompData::abortFunction(ostream &s)

{
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

/// \class IfcComment
/// \brief A comment within a command script: `% A comment in a script`
///
/// This commands does nothing but attaches to comment tokens like:
///   - \#
///   - %
///   - //
///
/// allowing comment lines in a script file
void IfcComment::execute(istream &s)
{
  //Do nothing
}

/// \class IfcOption
/// \brief Adjust a decompiler option: `option <optionname> [<param1>] [<param2>] [<param3>]`
///
/// Passes command-line parameters to an ArchOption object registered with
/// the current architecture's OptionDatabase.  Options are looked up by name
/// and can be configure with up to 3 parameters.  Options generally report success
/// or failure back to the console.
void IfcOption::execute(istream &s)

{
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

/// \class IfcParseFile
/// \brief Parse a file with C declarations: `parse file <filename>`
///
/// The file must contain C syntax data-type and function declarations.
/// Data-types become part of the program, and function declarations,
/// if the symbol already exists, associate the prototype with the symbol.
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

/// \class IfcParseLine
/// \brief Parse a line of C syntax: `parse line ...`
///
/// The line can contain a declaration either a data-type or a function prototype:
///    - `parse line typedef int4 *specialint;`
///    - `parse line struct mystruct { int4 a; int4 b; }`
///    - `parse line extern void myfunc(int4 a,int4 b);`
///
/// Data-types go straight into the program.  For a prototype, the function symbol
/// must already exist.
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

/// \class IfcAdjustVma
/// \brief Change the base address of the load image: `adjust vma 0xabcd0123`
///
/// The provided parameter is added to the current base address of the image.
/// This only affects the address of bytes in the image and so should be done
/// before functions and other symbols are layed down.
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

/// \brief Generate raw p-code for the current function
///
/// Follow flow from the entry point of the function and generate the
/// raw p-code ops for all instructions, up to \e return instructions.
/// If a \e size in bytes is provided, it bounds the memory region where flow
/// can be followed.  Otherwise, a zero \e size allows unbounded flow tracing.
/// \param s is a output stream for reporting function details or errors
/// \param size (if non-zero) is the maximum number of bytes to disassemble
void IfaceDecompData::followFlow(ostream &s,int4 size)

{
#ifdef OPACTION_DEBUG
  if (jumptabledebug)
    fd->enableJTCallback(jump_callback);
#endif
  try {
    if (size==0) {
      Address baddr(fd->getAddress().getSpace(),0);
      Address eaddr(fd->getAddress().getSpace(),fd->getAddress().getSpace()->getHighest());
      fd->followFlow(baddr,eaddr);
    }
    else
      fd->followFlow(fd->getAddress(),fd->getAddress()+size);
    s << "Function " << fd->getName() << ": ";
    fd->getAddress().printRaw(s);
    s << endl;
  } catch(RecovError &err) {
    s << "Function " << fd->getName() << ": " << err.explain << endl;
  }
}

/// \class IfcFuncload
/// \brief Make a specific function current: `load function <functionname>`
///
/// The name must be a fully qualified symbol with "::" separating namespaces.
/// If the symbol represents a function, that function becomes \e current for
/// the console. If there are bytes for the function, raw p-code and control-flow
/// are calculated.
void IfcFuncload::execute(istream &s)

{
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
    dcp->followFlow(*status->optr,0);
}

/// \class IfcAddrrangeLoad
/// \brief Create a new function at an address: `load addr <address> [<funcname>]`
///
/// A new function is created at the provided address.  If a name is provided, this
/// becomes the function symbol, otherwise a default name is generated.
/// The function becomes \e current for the interface, and if bytes are present,
/// raw p-code and control-flow are generated.
void IfcAddrrangeLoad::execute(istream &s)

{
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
  dcp->followFlow(*status->optr,size);
}

/// \class IfcCleararch
/// \brief Clear the current architecture/program: `clear architecture`
void IfcCleararch::execute(istream &s)

{
  dcp->clearArchitecture();
}

/// \class IfcReadSymbols
/// \brief Read in symbols from the load image: `read symbols`
///
/// If the load image format encodes symbol information.  These are
/// read in and attached to the appropriate address.
void IfcReadSymbols::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");
  if (dcp->conf->loader == (LoadImage *)0)
    throw IfaceExecutionError("No binary loaded");

  dcp->conf->readLoaderSymbols("::");
}

/// \class IfcMapaddress
/// \brief Map a new symbol into the program: `map address <address> <typedeclaration>`
///
/// Create a new variable in the current scope
/// \code
///    map address r0x1000 int4 globalvar
/// \endcode
/// The symbol specified in the type declaration can qualify the namespace using the "::"
/// specifier.  If there is a current function, the variable is local to the function.
/// Otherwise the symbol is created relative to the global scope.
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

/// \class IfcMaphash
/// \brief Add a dynamic symbol to the current function: `map hash <address> <hash> <typedeclaration>`
///
/// The command only creates local variables for the current function.
/// The name and data-type are taken from a C syntax type declaration.  The symbol is
/// not associated with a particular storage address but with a specific Varnode in the data-flow,
/// specified by a code address and hash of the local data-flow structure.
void IfcMaphash::execute(istream &s)

{
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

/// \class IfcMapfunction
/// \brief Create a new function: `map function <address> [<functionname>] [nocode]`
///
/// Create a new function symbol at the provided address.
/// A symbol name can be provided, otherwise a default name is selected.
/// The new function becomes \e current for the console.
/// The provided address gives the entry point for the function.  Unless the final keyword
/// "nocode" is provided, the underlying bytes in the load image are used for any
/// future disassembly or decompilation.
void IfcMapfunction::execute(istream &s)

{
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

/// \class IfcMapexternalref
/// \brief Create an external ref symbol `map externalref <address> <refaddress> [<name>]`
///
/// Creates a symbol for a function pointer and associates a specific address as
/// a value for that symbol.  The first address specified is the address of the symbol,
/// The second address is the address referred to by the pointer.  Indirect calls
/// through the function pointer will be converted to direct calls to the referred address.
/// A symbol name can be provided, otherwise a default one is generated.
void IfcMapexternalref::execute(istream &s)

{
  int4 size1,size2;
  Address addr1 = parse_machaddr(s,size1,*dcp->conf->types); // Read externalref address
  Address addr2 = parse_machaddr(s,size2,*dcp->conf->types); // Read referred to address
  string name;

  s >> name;			// Read optional name

  dcp->conf->symboltab->getGlobalScope()->addExternalRef(addr1,addr2,name);
}

/// \class IfcMaplabel
/// \brief Create a code label: `map label <name> <address>`
///
/// Label a specific code address.  This creates a LabSymbol which is usually
/// an internal control-flow target.  The symbol is local to the \e current function
/// if it exists, otherwise the symbol is added to the global scope.
void IfcMaplabel::execute(istream &s)

{
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

/// \class IfcPrintdisasm
/// \brief Print disassembly of a memory range: `disassemble [<address1> <address2>]`
///
/// If no addresses are provided, disassembly for the current function is displayed.
/// Otherwise disassembly is between the two provided addresses.
void IfcPrintdisasm::execute(istream &s)

{
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

/// \class IfcDump
/// \brief Display bytes in the load image: `dump <address+size>`
///
/// The command does a hex listing of the specific memory region.
void IfcDump::execute(istream &s)

{
  int4 size;
  uint1 *buffer;
  Address offset = parse_machaddr(s,size,*dcp->conf->types);

  buffer = dcp->conf->loader->load(size,offset);
  print_data(*status->fileoptr,buffer,size,offset);
  delete [] buffer;
}

/// \class IfcDumpbinary
/// \brief Dump a memory to file: `binary <address+size> <filename>`
///
/// Raw bytes from the specified memory region in the load image are written
/// to a file.
void IfcDumpbinary::execute(istream &s)

{
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

/// \class IfcDecompile
/// \brief Decompile the current function: `decompile`
///
/// Decompilation is started for the current function. Any previous decompilation
/// analysis on the function is cleared first.  The process respects
/// any active break points or traces, so decompilation may not complete.
void IfcDecompile::execute(istream &s)

{
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

/// \class IfcPrintCFlat
/// \brief Print current function without control-flow: `print C flat`
void IfcPrintCFlat::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->setFlat(true);
  dcp->conf->print->docFunction(dcp->fd);
  dcp->conf->print->setFlat(false);
}

/// \class IfcPrintCGlobals
/// \brief Print declarations for any known global variables: `print C globals`
void IfcPrintCGlobals::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->docAllGlobals();
}

/// \class IfcPrintCTypes
/// \brief Print any known type definitions: `print C types`
void IfcPrintCTypes::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0) 
    throw IfaceExecutionError("No load image present");

  if (dcp->conf->types != (TypeFactory *)0) {
    dcp->conf->print->setOutputStream(status->fileoptr);
    dcp->conf->print->docTypeDefinitions(dcp->conf->types);
  }
}

/// \class IfcPrintCXml
/// \brief Print the current function with C syntax and XML markup:`print C xml`
void IfcPrintCXml::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->setXML(true);
  dcp->conf->print->docFunction(dcp->fd);
  dcp->conf->print->setXML(false);
}

/// \class IfcPrintCStruct
/// \brief Print the current function using C syntax:`print C`
void IfcPrintCStruct::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->conf->print->setOutputStream(status->fileoptr);
  dcp->conf->print->docFunction(dcp->fd);
}

/// \class IfcPrintLanguage
/// \brief Print current output using a specific language: `print language <langname>`
///
/// The current function must already be decompiled.
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

/// \class IfcPrintRaw
/// \brief Print the raw p-code for the \e current function: `print raw`
///
/// Each p-code op, in its present state, is printed to the console, labeled
/// with the address of its original instruction and any output and input varnodes.
void IfcPrintRaw::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->printRaw(*status->fileoptr);
}

/// \class IfcListaction
/// \brief List all current actions and rules for the decompiler: `list action`
void IfcListaction::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");
  dcp->conf->allacts.getCurrent()->print(*status->fileoptr,0,0);
}

/// \class IfcListOverride
/// \brief Display any overrides for the current function: `list override`
///
/// Overrides include:
///   - Forced gotos
///   - Dead code delays
///   - Indirect call overrides
///   - Indirect prototype overrides
void IfcListOverride::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  *status->optr << "Function: " << dcp->fd->getName() << endl;
  dcp->fd->getOverride().printRaw(*status->optr,dcp->conf);
}

/// \class IfcListprototypes
/// \brief List known prototype models: `list prototypes`
///
/// All prototype models are listed with markup indicating the
/// \e default, the evaluation model for the active function, and
/// the evaluation model for called functions.
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

/// \class IfcSetcontextrange
/// \brief Set a context variable: `set context <name> <value> [<startaddress> <endaddress>]`
///
/// The named context variable is set to the provided value.
/// If a start and end address is provided, the context variable is set over this range,
/// otherwise the value is set as a default.
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

/// \class IfcSettrackedrange
/// \brief Set the value of a register: `set track <name> <value> [<startaddress> <endaddress>]`
///
/// The value for the register is picked up by the decompiler for functions in the tracked range.
/// The register is specified by name.  A specific range can be provided, otherwise the value is
/// treated as a default.
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

/// \class IfcBreakaction
/// \brief Set a breakpoint when a Rule or Action executes: `break action <actionname>`
///
/// The break point can be on either an Action or Rule.  The name can specify
/// partial path information to distinguish the Action/Rule.  The breakpoint causes
/// the decompilation process to stop and return control to the console immediately
/// \e after the Action or Rule has executed, but only if there was an active transformation
/// to the function.
void IfcBreakaction::execute(istream &s)

{
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

/// \class IfcBreakstart
/// \brief Set a break point at the start of an Action: `break start <actionname>`
///
/// The break point can be on either an Action or a Rule.  The name can specify
/// partial path information to distinguish the Action/Rule.  The breakpoint causes
/// the decompilation process to stop and return control to the console just before
/// the Action/Rule would have executed.
void IfcBreakstart::execute(istream &s)

{
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

/// \class IfcPrintTree
/// \brief Print all Varnodes in the \e current function: `print tree varnode`
///
/// Information about every Varnode in the data-flow graph for the function is displayed.
void IfcPrintTree::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->printVarnodeTree(*status->fileoptr);
}

/// \class IfcPrintBlocktree
/// \brief Print a description of the \e current functions control-flow: `print tree block`
///
/// The recovered control-flow structure is displayed as a hierarchical list of blocks,
/// showing the nesting and code ranges covered by the blocks.
void IfcPrintBlocktree::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->printBlockTree(*status->fileoptr);
}

/// \class IfcPrintSpaces
/// \brief Print all address spaces: `print spaces`
///
/// Information about every address space in the architecture/program is written
/// to the console.
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

/// \class IfcPrintHigh
/// \brief Display all Varnodes in a HighVariable: `print high <name>`
///
/// A HighVariable associated with the current function is specified by name.
/// Information about every Varnode merged into the variable is displayed.
void IfcPrintHigh::execute(istream &s)

{
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

/// \class IfcPrintParamMeasures
/// \brief Perform parameter-id analysis on the \e current function: `print parammeasures`
void IfcPrintParamMeasures::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  ParamIDAnalysis pidanalysis( dcp->fd, false );
  pidanalysis.savePretty( *status->fileoptr, true );
  *status->fileoptr << "\n";
}

/// \class IfcRename
/// \brief Rename a variable: `rename <oldname> <newname>`
///
/// Change the name of a symbol.  The provided name is searched for starting
/// in the scope of the current function.
void IfcRename::execute(istream &s)

{
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

/// \class IfcRemove
/// \brief Remove a symbol by name: `remove <varname>`
///
/// The symbol is searched for starting in the current function's scope.
/// The resulting symbol is removed completely from the symbol table.
void IfcRemove::execute(istream &s)

{
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

/// \class IfcRetype
/// \brief Change the data-type of a symbol: `retype <varname> <typedeclaration>`
///
/// The symbol is searched for by name starting in the current function's scope.
/// If the type declaration includes a new name for the variable, the
/// variable is renamed as well.
void IfcRetype::execute(istream &s)

{
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

/// The Varnode is selected from the \e current function.  It is specified as a
/// storage location with info about its defining p-code in parantheses.
///   - `%EAX(r0x10000:0x65)`
///   - `%ECX(i)`
///   - `r0x10001000:4(:0x96)`
///   - `u0x00001100:1(:0x102)`
///   - `#0x1(0x10205:0x27)`
///
/// The storage address space is given as the \e short-cut character followed by the
/// address offset.  For register spaces, the name of the register can be given instead of the
/// offset.  After the offset, a size can be specified with a ':' followed by the size in bytes.
/// If size is not provided and there is no register name, a default word size is assigned based
/// on the address space.
///
/// The defining p-code op is specified either as:
///   - An address and sequence number: `%EAX(r0x10000:0x65)`
///   - Just a sequence number: `%EAX(:0x65)`  or
///   - An "i" token for inputs: `%EAX(i)`
///
/// For a constant Varnode, the storage offset is the actual value of the constant, and
/// the p-code address and sequence number must both be present and specify the p-code op
/// that \e reads the constant.
/// \param s is the given input stream
/// \return the Varnode object
Varnode *IfaceDecompData::readVarnode(istream &s)

{
  uintm uq;
  int4 defsize;
  Varnode *vn = (Varnode *)0;

  if (fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Address pc;
  Address loc(parse_varnode(s,defsize,pc,uq,*conf->types));
  if (loc.getSpace()->getType() == IPTR_CONSTANT) {
    if (pc.isInvalid() || (uq == ~((uintm)0)))
      throw IfaceParseError("Missing p-code sequence number");
    SeqNum seq(pc,uq);
    PcodeOp *op = fd->findOp(seq);
    if (op != (PcodeOp *)0) {
      for(int4 i=0;i<op->numInput();++i) {
	Varnode *tmpvn = op->getIn(i);
	if (tmpvn->getAddr() == loc) {
	  vn = tmpvn;
	  break;
	}
      }
    }
  }
  else if (pc.isInvalid()&&(uq==~((uintm)0)))
    vn = fd->findVarnodeInput(defsize,loc);
  else if ((!pc.isInvalid())&&(uq!=~((uintm)0)))
    vn = fd->findVarnodeWritten(defsize,loc,pc,uq);
  else {
    VarnodeLocSet::const_iterator iter,enditer;
    iter = fd->beginLoc(defsize,loc);
    enditer = fd->endLoc(defsize,loc);
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

/// \class IfcPrintVarnode
/// \brief Print information about a Varnode: `print varnode <varnode>`
///
/// Attributes of the indicated Varnode from the \e current function are printed
/// to the console.  If the Varnode belongs to a HighVariable, information about
/// it and all its Varnodes are printed as well.
void IfcPrintVarnode::execute(istream &s)

{
  Varnode *vn;

  vn = dcp->readVarnode(s);
  if (vn->isAnnotation()||(!dcp->fd->isHighOn()))
    vn->printInfo(*status->optr);
  else
    vn->getHigh()->printInfo(*status->optr);
}

/// \class IfcPrintCover
/// \brief Print cover info about a HighVariable: `print cover high <name>`
///
/// A HighVariable is specified by its symbol name in the current function's scope.
/// Information about the code ranges where the HighVariable is in scope is printed.
void IfcPrintCover::execute(istream &s)

{
  HighVariable *high;
  string name;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws >> name;
  if (name.size()==0)
    throw IfaceParseError("Missing variable name");
  high = dcp->fd->findHigh(name);
  if (high == (HighVariable *)0)
    throw IfaceExecutionError("Unable to find variable: "+name);
  
  high->printCover(*status->optr);
}

/// \class IfcVarnodehighCover
/// \brief Print cover info about a HighVariable: `print cover varnodehigh <varnode>`
///
/// The HighVariable is selected by specifying one of its Varnodes.
/// Information about the code ranges where the HighVariable is in scope is printed.
void IfcVarnodehighCover::execute(istream &s)

{
  Varnode *vn;

  vn = dcp->readVarnode(s);
  if (vn == (Varnode *)0)
    throw IfaceParseError("Unknown varnode");
  if (vn->getHigh() != (HighVariable *)0)
    vn->getHigh()->printCover(*status->optr);
  else
    *status->optr << "Unmerged" << endl;
}

/// \class IfcPrintExtrapop
/// \brief Print change to stack pointer for called function: `print extrapop [<functionname>]`
///
/// For the selected function, the extra amount each called function changes the stack pointer
/// (over popping the return value) is printed to console.  The function is selected by
/// name, or if no name is given, the \e current function is selected.
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

/// \class IfcVarnodeCover
/// \brief Print cover information about a Varnode: `print cover varnode <varnode>`
///
/// Information about code ranges where the single Varnode is in scope are printed.
void IfcVarnodeCover::execute(istream &s)

{
  Varnode *vn;

  vn = dcp->readVarnode(s);
  if (vn == (Varnode *)0)
    throw IfaceParseError("Unknown varnode");
  vn->printCover(*status->optr);
}

/// \class IfcNameVarnode
/// \brief Attach a named symbol to a specific Varnode: `name varnode <varnode> <name>`
///
/// A new local symbol is created for the \e current function, and
/// is attached to the specified Varnode. The \e current function must be decompiled
/// again to see the effects.  The new symbol is \e name-locked with the specified
/// name, but the data-type of the symbol is allowed to float.
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

/// \class IfcTypeVarnode
/// \brief Attach a typed symbol to a specific Varnode: `type varnode <varnode> <typedeclaration>`
///
/// A new local symbol is created for the \e current function, and
/// is attached to the specified Varnode. The \e current function must be decompiled
/// again to see the effects.  The new symbol is \e type-locked with the data-type specified
/// in the type declaration.  If a name is specified in the declaration, the symbol
/// is \e name-locked as well.
void IfcTypeVarnode::execute(istream &s)

{
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

/// \class IfcForceHex
/// \brief Mark a constant to be printed in hex format: `force hex <varnode>`
///
/// A selected constant Varnode in the \e current function is marked so
/// that it will be printed in hexadecimal format in decompiler output.
void IfcForceHex::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Varnode *vn = dcp->readVarnode(s);
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

/// \class IfcForceDec
/// \brief Mark a constant to be printed in decimal format: `force dec <varnode>`
///
/// A selected constant Varnode in the \e current function is marked so
/// that it will be printed in decimal format in decompiler output.
void IfcForceDec::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  Varnode *vn = dcp->readVarnode(s);
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

/// \class IfcForcegoto
/// \brief Force a branch to be an unstructured \b goto: `force goto <branchaddr> <targetaddr>`
///
/// Create an override that forces the decompiler to treat the specified branch
/// as unstructured. The branch will be modeled as a \b goto statement.
/// The branch is specified by first providing the address of the branching instruction,
/// then the destination address.
void IfcForcegoto::execute(istream &s)

{
  int4 discard;
  
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  s >> ws;
  Address target(parse_machaddr(s,discard,*dcp->conf->types));
  s >> ws;
  Address dest(parse_machaddr(s,discard,*dcp->conf->types));
  dcp->fd->getOverride().insertForceGoto(target,dest);
}

/// \class IfcProtooverride
/// \brief Override the prototype of a called function: `override prototype <address> <declaration>`
///
/// Force a specified prototype declaration on a called function when decompiling
/// the current function. The current function must be decompiled again to see the effect.
/// The called function is indicated by the address of its calling instruction.
/// The prototype only affects decompilation for the \e current function.
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

/// \class IfcJumpOverride
/// \brief Provide an overriding jump-table for an indirect branch: `override jumptable ...`
///
/// The command expects the address of an indirect branch in the \e current function,
/// followed by the keyword \b table then a list of possible target addresses of the branch.
/// \code
///    override jumptable r0x1000 table r0x1020 r0x1030 r0x1043 ...
/// \endcode
/// The command can optionally take the keyword \b startval followed by an
/// integer indicating the value taken by the \e normalized switch variable that
/// produces the first address in the table.
/// \code
///    override jumptable startval 10 table r0x1020 r0x1030 ...
/// \endcode
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

/// \class IfcFlowOverride
/// \brief Create a control-flow override: `override flow <address> branch|call|callreturn|return`
///
/// Change the nature of the control-flow at the specified address, as indicated by the
/// final token on the command-line:
///   - branch     -  Change the CALL or RETURN to a BRANCH
///   - call       -  Change a BRANCH or RETURN to a CALL
///   - callreturn -  Change a BRANCH or RETURN to a CALL followed by a RETURN
///   - return     -  Change a CALLIND or BRANCHIND to a RETURN
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

/// \class IfcDeadcodedelay
/// \brief Change when dead code elimination starts: `deadcode delay <name> <delay>`
///
/// An address space is selected by name, along with a pass number.
/// Dead code elimination for Varnodes in that address space is changed to start
/// during that pass.  If there is a \e current function, the delay is altered only for
/// that function, otherwise the delay is set globally for all functions.
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

/// \class IfcGlobalAdd
/// \brief Add a memory range as discoverable global variables: `global add <address+size>`
///
/// The decompiler will treat Varnodes stored in the new memory range as persistent
/// global variables.
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

/// \class IfcGlobalRemove
/// \brief Remove a memory range from discoverable global variables: `global remove <address+size>`
///
/// The will no longer treat Varnodes stored in the memory range as persistent global
/// variables.  The will be treated as local or temporary storage.
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

/// \class IfcGlobalify
/// \brief Treat all normal memory as discoverable global variables: `global spaces`
///
/// This has the drastic effect that the decompiler will treat all registers and stack
/// locations as global variables.
void IfcGlobalify::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No load image present");
  dcp->conf->globalify();
  *status->optr << "Successfully made all registers/memory locations global" << endl;
}

/// \class IfcGlobalRegisters
/// \brief Name global registers: `global registers`
///
/// Name any global symbol stored in a register with the name of the register.
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

/// The use is non-trivial if it can be traced to any p-code operation except
/// a COPY, CAST, INDIRECT, or MULTIEQUAL.
/// \param vn is the given Varnode
/// \return \b true if there is a non-trivial use
bool IfcPrintInputs::nonTrivialUse(Varnode *vn)

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

/// Look for any value flowing into the Varnode coming from anything
/// other than an input Varnode with the same storage.  The value can flow through
/// a COPY, CAST, INDIRECT, or MULTIEQUAL
/// \param vn is the given Varnode
/// \return 0 if Varnode is restored, 1 otherwise
int4 IfcPrintInputs::checkRestore(Varnode *vn)

{
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

/// For the given storage location, check that it is \e restored
/// from its original input value.
/// \param vn is the given storage location
/// \param fd is the function being analyzed
bool IfcPrintInputs::findRestore(Varnode *vn,Funcdata *fd)

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
    int4 res = checkRestore(vn);
    if (res != 0) return false;
    count += 1;
  }
  return (count>0);
}

/// For each input Varnode, print information about the Varnode,
/// any explicit symbol it represents, and info about how the value is used.
/// \param fd is the function
/// \param s is the output stream to write to
void IfcPrintInputs::print(Funcdata *fd,ostream &s)

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
    bool findres = findRestore(vn,fd);
    bool nontriv = nonTrivialUse(vn);
    if (findres && !nontriv)
      s << "     restored";
    else if (nontriv)
      s << "     nontriv";
    s << endl;
  }
}

/// \class IfcPrintInputs
/// \brief Print info about the current function's input Varnodes: `print inputs`
void IfcPrintInputs::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  print(dcp->fd,*status->fileoptr);
}

/// \class IfcPrintInputsAll
/// \brief Print info about input Varnodes for all functions: `print inputs all`
///
/// Each function is decompiled, and info about its input Varnodes are printed.
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
    IfcPrintInputs::print(fd,*status->fileoptr);
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
  }
  dcp->conf->clearAnalysis(fd);
}

/// \class IfcLockPrototype
/// \brief Lock in the \e current function's prototype: `prototype lock`
///
/// Lock in the existing formal parameter names and data-types for any future
/// decompilation.  Both input parameters and the return value are locked.
void IfcLockPrototype::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->getFuncProto().setInputLock(true);
  dcp->fd->getFuncProto().setOutputLock(true);
}

/// \class IfcUnlockPrototype
/// \brief Unlock the \e current function's prototype: `prototype unlock`
///
/// Unlock all input parameters and the return value, so future decompilation
/// is not constrained with their data-type or name.
void IfcUnlockPrototype::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->getFuncProto().setInputLock(false);
  dcp->fd->getFuncProto().setOutputLock(false);
}

/// \class IfcPrintLocalrange
/// \brief Print range of locals on the stack: `print localrange`
///
/// Print the memory range(s) on the stack is or could be used for
///
void IfcPrintLocalrange::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

  dcp->fd->printLocalRange( *status->optr );
}

/// \class IfcPrintMap
/// \brief Print info about a scope/namespace: `print map <name>`
///
/// Prints information about the discoverable memory ranges for the scope,
/// and prints a description of every symbol in the scope.
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

/// \class IfcProduceC
/// \brief Write decompilation for all functions to a file: `produce C <filename>`
///
/// Iterate over all functions in the program.  For each function, decompilation is
/// performed and output is appended to the file.
void IfcProduceC::execute(istream &s)

{
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

/// \class IfcProducePrototypes
/// \brief Determine the prototype model for all functions: `produce prototypes`
///
/// Functions are walked in leaf order.
void IfcProducePrototypes::execute(istream &s)

{
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

/// \class IfcContinue
/// \brief Continue decompilation after a break point: `continue`
///
/// This command assumes decompilation has been started and has hit a break point.
void IfcContinue::execute(istream &s)

{
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

/// \class IfcGraphDataflow
/// \brief Write a graph representation of data-flow to a file: `graph dataflow <filename>`
///
/// The data-flow graph for the \e current function, in its current state of transform,
/// is written to the indicated file.
void IfcGraphDataflow::execute(istream &s)

{
  string filename;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

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

/// \class IfcGraphControlflow
/// \brief Write a graph representation of control-flow to a file: `graph controlflow <filename>`
///
/// The control-flow graph for the \e current function, in its current state of transform,
/// is written to the indicated file.
void IfcGraphControlflow::execute(istream &s)

{
  string filename;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

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

/// \class IfcGraphDom
/// \brief Write the forward dominance graph to a file: `graph dom <filename>`
///
/// The dominance tree, associated with the control-flow graph of the \e current function
/// in its current state of transform, is written to the indicated file.
void IfcGraphDom::execute(istream &s)

{
  string filename;

  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");

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

/// \class IfcCommentInstr
/// \brief Attach a comment to an address: `comment <address> comment text...`
///
/// Add a comment to the database, suitable for integration into decompiler output
/// for the \e current function.  The command-line takes the address of the
/// machine instruction which the comment will be attached to and is followed by
/// the text of the comment.
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

/// For each duplicate discovered, a message is written to the provided stream.
/// \param fd is the given function to search
/// \param s is the stream to write messages to
void IfcDuplicateHash::check(Funcdata *fd,ostream &s)

{
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

/// \class IfcDuplicateHash
/// \brief Check for duplicate hashes in functions: `duplicate hash`
///
/// All functions in the architecture/program are decompiled, and for each
/// a check is made for Varnode pairs with identical hash values.
void IfcDuplicateHash::execute(istream &s)

{
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
    check(fd,*status->optr);
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
  }
  dcp->conf->clearAnalysis(fd);
}

/// \class IfcCallGraphBuild
/// \brief Build the call-graph for the architecture/program: `callgraph build`
///
/// Build, or rebuild, the call-graph with nodes for all existing functions.
/// Functions are to decompiled to recover destinations of indirect calls.
/// Going forward, the graph is held in memory and is accessible by other commands.
void IfcCallGraphBuild::execute(istream &s)

{
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
    dcp->followFlow(*status->optr,0);
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

/// \class IfcCallGraphBuildQuick
/// \brief Build the call-graph using quick analysis: `callgraph build quick`
///
/// Build the call-graph for the architecture/program.  For each function, disassembly
/// is performed to discover call edges, rather then full decompilation.  Some forms
/// of direct call may not be discovered.
void IfcCallGraphBuildQuick::execute(istream &s)

{
  dcp->allocateCallGraph();
  dcp->cgraph->buildAllNodes();	// Build a node in the graph for existing symbols
  quick = true;
  iterateFunctionsAddrOrder();
  *status->optr << "Successfully built callgraph" << endl;
}

/// \class IfcCallGraphDump
/// \brief Write the current call-graph to a file: `callgraph dump <filename>`
///
/// The existing call-graph object is written to the provided file as an
/// XML document.
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

/// \class IfcCallGraphLoad
/// \brief Load the call-graph from a file: `callgraph load <filename>`
///
/// A call-graph is loaded from the provided XML document.  Nodes in the
/// call-graph are linked to existing functions by symbol name.  This command
/// reports call-graph nodes that could not be linked.
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

/// \class IfcCallGraphList
/// \brief List all functions in \e leaf order: `callgraph list`
///
/// The existing call-graph is walked, displaying function names to the console.
/// Child functions are displayed before their parents.
void IfcCallGraphList::execute(istream &s)

{
  if (dcp->cgraph == (CallGraph *)0)
    throw IfaceExecutionError("Callgraph not generated");

  iterateFunctionsLeafOrder();
}

void IfcCallGraphList::iterationCallback(Funcdata *fd)

{
  *status->optr << fd->getName() << endl;
}

/// \brief Scan a single-line p-code snippet declaration from the given stream
///
/// A declarator is scanned first, providing a name to associate with the snippet, as well
/// as potential names of the formal \e output Varnode and \e input Varnodes.
/// The body of the snippet is then surrounded by '{' and '}'  The snippet name,
/// input/output names, and the body are passed back to the caller.
/// \param s is the given stream to scan
/// \param name passes back the name of the snippet
/// \param outname passes back the formal output parameter name, or is empty
/// \param inname passes back an array of the formal input parameter names
/// \param pcodestring passes back the snippet body
void IfcCallFixup::readPcodeSnippet(istream &s,string &name,string &outname,vector<string> &inname,
				    string &pcodestring)
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

/// \class IfcCallFixup
/// \brief Add a new call fix-up to the program: `fixup call ...`
///
/// Create a new call fixup-up for the architecture/program, suitable for
/// replacing called functions.  The fix-up is specified as a function-style declarator,
/// which also provides the formal name of the fix-up.
/// A "void" return-type and empty parameter list must be given.
/// \code
///   fixup call void myfixup1() { EAX = 0; RBX = RCX + RDX + 1; }
/// \endcode
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

/// \class IfcCallOtherFixup
/// \brief Add a new callother fix-up to the program: `fixup callother ...`
///
/// The new fix-up is suitable for replacing specific user-defined (CALLOTHER)
/// p-code operations. The declarator provides the name of the fix-up and can also
/// provide formal input and output parameters.
/// \code
///   fixup callother outvar myfixup2(invar1,invar2) { outvar = invar1 + invar2; }
/// \endcode
void IfcCallOtherFixup::execute(istream &s)

{
  string useropname,outname,pcodestring;
  vector<string> inname;

  IfcCallFixup::readPcodeSnippet(s,useropname,outname,inname,pcodestring);
  dcp->conf->userops.manualCallOtherFixup(useropname,outname,inname,pcodestring,dcp->conf);

  *status->optr << "Successfully registered callotherfixup" << endl;
}

/// \class IfcVolatile
/// \brief Mark a memory range as volatile: `volatile <address+size>`
///
/// The memory range provided on the command-line is marked as \e volatile, warning
/// the decompiler analysis that values in the range my change unexpectedly.
void IfcVolatile::execute(istream &s)

{
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

/// \class IfcReadonly
/// \brief Mark a memory range as read-only: `readonly <address+size>`
///
/// The memory range provided on the command-line is marked as \e read-only, which
/// allows the decompiler to propagate values pulled from the LoadImage for the range
/// as constants.
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

/// \class IfcPreferSplit
/// \brief Mark a storage location to be split: `prefersplit <address+size> <splitsize>`
///
/// The storage location is marked for splitting in any future decompilation.
/// During decompilation, any Varnode matching the storage location on the command-line
/// will be generally split into two pieces, where the final command-line parameter
/// indicates the number of bytes in the first piece.  A Varnode is split only if operations
/// involving it can also be split.  See PreferSplitManager.
void IfcPreferSplit::execute(istream &s)

{
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
  dcp->conf->splitrecords.emplace_back();
  PreferSplitRecord &rec( dcp->conf->splitrecords.back() );

  rec.storage.space = addr.getSpace();
  rec.storage.offset = addr.getOffset();
  rec.storage.size = size;
  rec.splitoffset = split;

  *status->optr << "Successfully added split record" << endl;
}

/// \class IfcStructureBlocks
/// \brief Structure an external control-flow graph: `structure blocks <infile> <outfile>`
///
/// The control-flow graph is read in from XML file, structuring is performed, and the
/// result is written out to a separate XML file.
void IfcStructureBlocks::execute(istream &s)

{
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

/// \class IfcPrintActionstats
/// \brief Print transform statistics for the decompiler engine: `print actionstats`
///
/// Counts for each Action and Rule are displayed; showing the number of attempts,
/// both successful and not, that were made to apply each one.  Counts can accumulate
/// over multiple decompilations.
void IfcPrintActionstats::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Image not loaded");
  if (dcp->conf->allacts.getCurrent() == (Action *)0)
    throw IfaceExecutionError("No action set");

  dcp->conf->allacts.getCurrent()->printStatistics(*status->fileoptr);
}

/// \class IfcResetActionstats
/// \brief Reset transform statistics for the decompiler engine: `reset actionstats`
///
/// Counts for each Action and Rule are reset to zero.
void IfcResetActionstats::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Image not loaded");
  if (dcp->conf->allacts.getCurrent() == (Action *)0)
    throw IfaceExecutionError("No action set");

  dcp->conf->allacts.getCurrent()->resetStats();
}

/// \class IfcCountPcode
/// \brief Count p-code in the \e current function: `count pcode`
///
/// The count is based on the number of existing p-code operations in
/// the current function, which may vary depending on the state of it transformation.
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

/// \class IfcAnalyzeRange
/// \brief Run value-set analysis on the \e current function: `analyze range full|partial <varnode>`
///
/// The analysis targets a single varnode as specified on the command-line and is based on
/// the existing data-flow graph for the current function.
/// The possible values that can reach the varnode at its point of definition, and
/// at any point it is involved in a LOAD or STORE, are displayed.
/// The keywords \b full and \b partial choose whether the value-set analysis uses
/// full or partial widening.
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
  Varnode *vn = dcp->readVarnode(s);
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

/// Execute one command and handle any exceptions.
/// Error messages are printed to the console.  For low-level errors,
/// the current function is reset to null
/// \param status is the console interface
/// \param dcp is the shared program data
void execute(IfaceStatus *status,IfaceDecompData *dcp)

{
  try {
    status->runCommand();	// Try to run one command-line
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

/// Execution loops until either the \e done field in the console is set
/// or if all streams have ended.  This handles popping script states pushed
/// on by the IfcSource command.
/// \param status is the console interface
void mainloop(IfaceStatus *status)

{
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

/// \class IfcSource
/// \brief Execute a command script : `source <filename>`
///
/// A file is opened as a new streaming source of command-lines.
/// The stream is pushed onto the stack for the console.
void IfcSource::execute(istream &s)

{
  string filename;

  s >> ws;
  if (s.eof())
    throw IfaceParseError("filename parameter required for source");

  s >> filename;
  status->pushScript(filename,filename+"> ");
}

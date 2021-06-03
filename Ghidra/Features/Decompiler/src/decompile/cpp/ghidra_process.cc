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
#include "ghidra_process.hh"
#include "flow.hh"
#include "blockaction.hh"

#ifdef __REMOTE_SOCKET__

#include "ifacedecomp.hh"

static IfaceStatus *ghidra_dcp = (IfaceStatus *)0;
static RemoteSocket *remote = (RemoteSocket *)0;

/// \brief Establish a debug console for decompilation of the given function
///
/// Attempt to connect to a UNIX domain socket and direct the i/o streams to
/// the decompiler console interface.  The socket must have been previously established
/// by another process.
/// From the command-line,  `nc -l -U /tmp/ghidrasocket` for example.
void connect_to_console(Funcdata *fd)

{
  if (remote == (RemoteSocket *)0) {
    remote = new RemoteSocket();
    if (remote->open("/tmp/ghidrasocket")) {
      ghidra_dcp = new IfaceStatus("[ghidradbg]> ",*remote->getInputStream(),*remote->getOutputStream());
      IfaceCapability::registerAllCommands(ghidra_dcp);
    }
  }
  if (!remote->isSocketOpen())
    return;

  IfaceDecompData *decomp_data = (IfaceDecompData *)ghidra_dcp->getData("decompile");
  decomp_data->fd = fd;
  decomp_data->conf = fd->getArch();
  ostream *oldPrintStream = decomp_data->conf->print->getOutputStream();
  bool emitXml = decomp_data->conf->print->emitsXml();
  decomp_data->conf->setDebugStream(remote->getOutputStream());
  decomp_data->conf->print->setOutputStream(remote->getOutputStream());
  decomp_data->conf->print->setXML(false);
  ghidra_dcp->reset();
  mainloop(ghidra_dcp);
  decomp_data->conf->clearAnalysis(fd);
  decomp_data->conf->print->setOutputStream(oldPrintStream);
  decomp_data->conf->print->setXML(emitXml);
  fd->debugDisable();
  decomp_data->conf->allacts.getCurrent()->clearBreakPoints();
}

#endif

vector<ArchitectureGhidra *> archlist; // List of architectures currently running

map<string,GhidraCommand *> GhidraCapability::commandmap; // List of commands we can receive from Ghidra proper

// Constructing the singleton registers the capability
GhidraDecompCapability GhidraDecompCapability::ghidraDecompCapability;

/// This method reads an id selecting the Architecture to act on, but it can be overloaded
/// to read any set of data from the Ghidra client to configure how the command is executed.
/// Individual parameters are read using the method protocol.
void GhidraCommand::loadParameters(void)

{
  int4 id = -1;
  int4 type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 14)
    throw JavaError("alignment","Expecting arch id start");
  sin >> dec >> id;
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 15)
    throw JavaError("alignment","Expecting arch id end");
  if ((id>=0)&&(id<archlist.size()))
    ghidra = archlist[id];

  if (ghidra == (ArchitectureGhidra *)0)
    throw JavaError("decompiler","No architecture registered with decompiler");
  ghidra->clearWarnings();
}

/// This method sends any warnings accumulated during execution back, but it can be overloaded
/// to send back any kind of information. Individual records are sent using
/// the message protocol.
void GhidraCommand::sendResult(void)

{
  if (ghidra != (ArchitectureGhidra *)0) {
    sout.write("\000\000\001\020",4);
    sout << ghidra->getWarnings();
    sout.write("\000\000\001\021",4);
  }
}

/// This method calls the main overloaded methods:
///   - loadParameters()
///   - rawAction()
///   - sendResult()
///
/// It wraps the sequence with appropriate error handling and message protocol.
/// \return the meta-command (0=continue, 1=terminate) as issued by the command.
int4 GhidraCommand::doit(void)

{
  status = 0;
  sout.write("\000\000\001\006",4); // Command response header
  try {
    loadParameters();
    int4 type = ArchitectureGhidra::readToAnyBurst(sin);
    if (type != 3)
      throw JavaError("alignment","Missing end of command");
    rawAction();
  }
  catch(XmlError &err) {
    string errmsg;
    errmsg = "XML processing error: " + err.explain;
    ghidra->printMessage( errmsg );
  }
  catch(JavaError &err) {
    ArchitectureGhidra::passJavaException(sout,err.type,err.explain);
    return status;			// Abort sending any results
  }
  catch(RecovError &err) {
    string errmsg;
    errmsg = "Recoverable Error: " + err.explain;
    ghidra->printMessage( errmsg );
  }
  catch(LowlevelError &err) {
    string errmsg;
    errmsg = "Low-level Error: " + err.explain;
    ghidra->printMessage( errmsg );
  }
  sendResult();
  sout.write("\000\000\001\007",4); // Command response closer
  sout.flush();
  return status;
}

void RegisterProgram::loadParameters(void)

{
  pspec.clear();
  cspec.clear();
  tspec.clear();
  corespec.clear();
  ArchitectureGhidra::readStringStream(sin,pspec);
  ArchitectureGhidra::readStringStream(sin,cspec);
  ArchitectureGhidra::readStringStream(sin,tspec);
  ArchitectureGhidra::readStringStream(sin,corespec);
}


void RegisterProgram::rawAction(void)

{
  int4 i;
  int4 open = -1;
  for(i=0;i<archlist.size();++i) {
    ghidra = archlist[i];
    if (ghidra == (ArchitectureGhidra *)0) {
      open = i;			// Found open slot
    }
  }
  ghidra = new ArchitectureGhidra(pspec,cspec,tspec,corespec,sin,sout);
  pspec.clear();
  cspec.clear();
  tspec.clear();
  corespec.clear();

  DocumentStorage store;	// temp storage of initialization xml docs
  ghidra->init(store);
  if (open == -1) {
    open = archlist.size();
    archlist.push_back((ArchitectureGhidra *)0);
  }
  archlist[open] = ghidra;
  archid = open;
}

void RegisterProgram::sendResult(void)

{
  sout.write("\000\000\001\016",4);
  sout << dec << archid;
  sout.write("\000\000\001\017",4);
  GhidraCommand::sendResult();
}

void DeregisterProgram::loadParameters(void)

{
  inid = -1;
  int4 type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type!=14)
    throw JavaError("alignment","Expecting deregister id start");
  sin >> dec >> inid;
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type!=15)
    throw JavaError("alignment","Expecting deregister id end");
  if ((inid>=0)&&(inid<archlist.size()))
    ghidra = archlist[inid];

  if (ghidra == (ArchitectureGhidra *)0)
    throw JavaError("decompiler","No architecture registered with decompiler");
  ghidra->clearWarnings();
}

void DeregisterProgram::rawAction(void)

{
#ifdef __REMOTE_SOCKET__
    if (ghidra_dcp != (IfaceStatus *)0)
      delete ghidra_dcp;
    if (remote != (RemoteSocket *)0)
      delete remote;
    ghidra_dcp = (IfaceStatus *)0;
    remote = (RemoteSocket *)0;
#endif
  if (ghidra != (ArchitectureGhidra *)0) {
    res = 1;
    archlist[inid] = (ArchitectureGhidra *)0;
    delete ghidra;
    ghidra = (ArchitectureGhidra *)0;
    status = 1;
  }
  else
    res = 0;
}

void DeregisterProgram::sendResult(void)

{
  sout.write("\000\000\001\016",4);
  sout << dec << res;
  sout.write("\000\000\001\017",4);
  GhidraCommand::sendResult();
}

void FlushNative::rawAction(void)

{
  Scope *globscope = ghidra->symboltab->getGlobalScope();
  globscope->clear();		// Clear symbols first as this may delete scopes
  ghidra->symboltab->deleteSubScopes(globscope); // Flush cached function and globals database
  ghidra->types->clearNoncore(); // Reset type information
  ghidra->commentdb->clear();	// Clear any comments
  ghidra->stringManager->clear();	// Clear string decodings
  ghidra->cpool->clear();
  res = 0;
}

void FlushNative::sendResult(void)

{
  sout.write("\000\000\001\016",4);
  sout << dec << res;
  sout.write("\000\000\001\017",4);
  GhidraCommand::sendResult();
}

void DecompileAt::loadParameters(void)

{
  GhidraCommand::loadParameters();
  Document *doc;
  doc = ArchitectureGhidra::readXMLStream(sin);	// Read XML of address directly from in stream
  addr = Address::restoreXml(doc->getRoot(),ghidra); // Parse XML for functions address
  addr.toPhysical(); 		// Only for backward compatibility
                                // with SLED
  delete doc;
}

void DecompileAt::rawAction(void) 

{
  Funcdata *fd = ghidra->symboltab->getGlobalScope()->queryFunction(addr);
  if (fd == (Funcdata *)0) {
    ostringstream s;
    s << "Bad decompile address: " << addr.getShortcut();
    addr.printRaw(s);
    s << "\n";
    s << addr.getSpace()->getName() << " may not be a global space in the spec file.";
    throw LowlevelError(s.str());
  }
  if (!fd->isProcStarted()) {
#ifdef __REMOTE_SOCKET__
    connect_to_console(fd);
#endif
    ghidra->allacts.getCurrent()->reset( *fd );
    ghidra->allacts.getCurrent()->perform( *fd );
  }

  sout.write("\000\000\001\016",4);
				// Write output XML directly to outstream
  if (fd->isProcComplete()) {
    //bool v1 = ghidra->getSendParamMeasures();
    //sout << "value: " << ghidra->getSendParamMeasures() << "\n";
    //bool v2 = (ghidra->allacts.getCurrentName() == "paramid");
    //sout << "value: " << (ghidra->allacts.getCurrentName() == "paramid") << "\n";
    //bool v3 = v1 && v2;

    sout << "<doc>\n";
    //sout << (v1?"1":"0") << "(" << (int4)v1 << ")\n" << (v2?"1":"0") << "\n" << (v3?"1":"0") << "\n";

    if (ghidra->getSendParamMeasures() && (ghidra->allacts.getCurrentName() == "paramid")) {
      ParamIDAnalysis pidanalysis( fd, true ); // Only send back final prototype
      pidanalysis.saveXml( sout, true );
    }
    else {
      if (ghidra->getSendParamMeasures()) {
	ParamIDAnalysis pidanalysis( fd, false );
	pidanalysis.saveXml( sout, true );
      }
      fd->saveXml(sout,0,ghidra->getSendSyntaxTree());
      if (ghidra->getSendCCode()&&
	  (ghidra->allacts.getCurrentName() == "decompile"))
        ghidra->print->docFunction(fd);
    }
    sout << "</doc>\n";
  }
  sout.write("\000\000\001\017",4);
}

void StructureGraph::loadParameters(void)

{
  GhidraCommand::loadParameters();
  Document *doc;
  doc = ArchitectureGhidra::readXMLStream(sin);
  ingraph.restoreXml(doc->getRoot(),ghidra);
  delete doc;
}

void StructureGraph::rawAction(void)

{
  BlockGraph resultgraph;
  vector<FlowBlock *> rootlist;

  resultgraph.buildCopy(ingraph);
  resultgraph.structureLoops(rootlist);
  resultgraph.calcForwardDominator(rootlist);

  CollapseStructure collapse(resultgraph);
  collapse.collapseAll();
  resultgraph.orderBlocks();

  sout.write("\000\000\001\016",4);
  resultgraph.saveXml(sout);
  sout.write("\000\000\001\017",4);
  ingraph.clear();
}

void SetAction::loadParameters(void)

{
  GhidraCommand::loadParameters();
  actionstring.clear();
  printstring.clear();
  ArchitectureGhidra::readStringStream(sin,actionstring);
  ArchitectureGhidra::readStringStream(sin,printstring);
}

void SetAction::rawAction(void)

{
  res = false;
  
  if (actionstring.size() != 0)
    ghidra->allacts.setCurrent(actionstring);
  if (printstring.size() != 0) {
    if (printstring == "tree")
      ghidra->setSendSyntaxTree(true);
    else if (printstring == "notree")
      ghidra->setSendSyntaxTree(false);
    else if (printstring == "c")
      ghidra->setSendCCode(true);
    else if (printstring == "noc")
      ghidra->setSendCCode(false);
    else if (printstring == "parammeasures")
      ghidra->setSendParamMeasures(true);
    else if (printstring == "noparammeasures")
      ghidra->setSendParamMeasures(false);
    else if (printstring == "jumpload")
      ghidra->flowoptions |= FlowInfo::record_jumploads;
    else if (printstring == "nojumpload")
      ghidra->flowoptions &= ~((uint4)FlowInfo::record_jumploads);
    else
      throw LowlevelError("Unknown print action: "+printstring);
  }
  res = true;
}

void SetAction::sendResult(void)

{
  if (res)
    ArchitectureGhidra::writeStringStream(sout,"t");
  else
    ArchitectureGhidra::writeStringStream(sout,"f");
  GhidraCommand::sendResult();
}

SetOptions::SetOptions(void) : GhidraCommand()

{
  doc = (Document *)0;
}

SetOptions::~SetOptions(void)

{
  if (doc != (Document *)0)
    delete doc;
}

void SetOptions::loadParameters(void)

{
  GhidraCommand::loadParameters();
  if (doc != (Document *)0) {
    delete doc;
    doc = (Document *)0;
  }
  doc = ArchitectureGhidra::readXMLStream(sin);
}

void SetOptions::rawAction(void)

{
  res = false;

  ghidra->resetDefaults();
  ghidra->options->restoreXml(doc->getRoot());
  delete doc;
  doc = (Document *)0;
  res = true;
}

void SetOptions::sendResult(void)

{
  if (res)
    ArchitectureGhidra::writeStringStream(sout,"t");
  else
    ArchitectureGhidra::writeStringStream(sout,"f");
  GhidraCommand::sendResult();
}

/// A command is read from the Ghidra client.  The matching GhidraCommand object is
/// looked up in the \b commandmap, and control is handed over to the command,
/// with the i/o streams.  The command must be issued following the proper
/// message protocol (see ArchitectureGhidra::readToAnyBurst) or an exception is thrown.
/// \param sin is the input stream from the client
/// \param out is the output stream to the client
/// \return the result code of the command
int4 GhidraCapability::readCommand(istream &sin,ostream &out)

{
  string function;
  int4 type;

  do {
    type = ArchitectureGhidra::readToAnyBurst(sin); // Align ourselves
  } while(type != 2);
  ArchitectureGhidra::readStringStream(sin,function);
  map<string,GhidraCommand *>::const_iterator iter;
  iter = commandmap.find(function);
  if (iter == commandmap.end()) {
    out.write("\000\000\001\006",4); // Command response header
    out.write("\000\000\001\020",4);
    out << "Bad command: " << function;
    out.write("\000\000\001\021",4);
    out.write("\000\000\001\007",4); // Command response closer
    out.flush();
    return 0;
  }
  return (*iter).second->doit();
}

void GhidraCapability::shutDown(void)

{
  map<string,GhidraCommand *>::iterator iter;
  for(iter=commandmap.begin();iter!=commandmap.end();++iter)
    delete (*iter).second;
}

void GhidraDecompCapability::initialize(void)

{
  commandmap["registerProgram"] = new RegisterProgram();
  commandmap["deregisterProgram"] = new DeregisterProgram();
  commandmap["flushNative"] = new FlushNative();
  commandmap["decompileAt"] = new DecompileAt();
  commandmap["structureGraph"] = new StructureGraph();
  commandmap["setAction"] = new SetAction();
  commandmap["setOptions"] = new SetOptions();
}

int main(int argc,char **argv)

{
  signal(SIGSEGV, &ArchitectureGhidra::segvHandler);  // Exit on SEGV errors
  CapabilityPoint::initializeAll();
  int4 status = 0;
  while(status == 0) {
    status = GhidraCapability::readCommand(cin,cout);
  }
  GhidraCapability::shutDown();
}


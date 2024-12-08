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
#include "analyzesigs.hh"
#include "loadimage_bfd.hh"

namespace ghidra {

// Constructing this registers the capability
IfaceAnalyzeSigsCapability IfaceAnalyzeSigsCapability::ifaceAnalyzeSigsCapability;

IfaceAnalyzeSigsCapability::IfaceAnalyzeSigsCapability(void)

{
  name = "analyzesigs";
}

void IfaceAnalyzeSigsCapability::registerCommands(IfaceStatus *status)

{
  status->registerCom(new IfcSignatureSettings(), "signature", "settings");
  status->registerCom(new IfcPrintSignatures(),"print","signatures");
  status->registerCom(new IfcSaveSignatures(),"save","signatures");
  status->registerCom(new IfcSaveAllSignatures(),"saveall","signatures");
  status->registerCom(new IfcProduceSignatures(),"produce","signatures");
}

/// \class IfcSignatureSettings
/// \brief Change global settings for signature generation : `signature settings <val>`
///
/// The provided integer value establishes the settings for any future signature generation
void IfcSignatureSettings::execute(istream &s)

{
  uint4 mysetting = 0;

  s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  s >> mysetting;
  if (mysetting == 0)
    throw IfaceParseError("Must specify settings integer");
  SigManager::setSettings(mysetting);
  *status->optr << "Signature settings set to " << hex << mysetting << endl;
}

/// \class IfcPrintSignatures
/// \brief Calculate and print signatures for the current function: `print signatures [...]`
///
/// Decompilation must already be complete.  Features are extracted from the function and are
/// printed, one per line.  The command optionally takes additional parameters that can alter
/// signature generation.
void IfcPrintSignatures::execute(istream &s)

{ //
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");
  if (!dcp->fd->isProcComplete())
    throw IfaceExecutionError("Function has not been fully analyzed");

  GraphSigManager smanage;
  
  smanage.initializeFromStream(s);

  *status->fileoptr << "Signatures for " << dcp->fd->getName() << endl;
  
  smanage.setCurrentFunction(dcp->fd);
  smanage.generate();
  smanage.print(*status->fileoptr);
}

/// \class IfcSaveSignatures
/// \brief Calculate signatures and save them to a file: `save signatures <filename> [...]`
///
/// The features/signatures are extracted from the current function, which must already be
/// decompiled, and are written out in XML format.  The first parameter must be the file name.
/// The command optionally takes additional parameters that can alter signature generation.
void IfcSaveSignatures::execute(istream &s)

{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");
  if (!dcp->fd->isProcComplete())
    throw IfaceExecutionError("Function has not been fully analyzed");

  string sigfilename;

  s >> sigfilename;
  if (sigfilename.size()==0)
    throw IfaceExecutionError("Need name of file to save signatures to");
  
  GraphSigManager smanage;
  smanage.initializeFromStream(s);

  smanage.setCurrentFunction(dcp->fd);
  smanage.generate();
  ofstream t( sigfilename.c_str() );

  if (!t)
    throw IfaceExecutionError("Unable to open signature save file: "+sigfilename);

  XmlEncode encoder(t);
  smanage.encode(encoder);
  t.close();

  *status->fileoptr << "Successfully saved signatures for " << dcp->fd->getName() << endl;
}

/// \class IfcSaveAllSignatures
/// \brief Calculate signatures and save them to a file: `saveall signatures <filename> [...]`
///
/// For every known function entry point, the function is decompiled (using the current action)
/// and features/signatures are extracted.  Features are written out in XML format to the
/// file indicated by the first parameter. The command optionally takes additional parameters
/// that can alter signature generation.
void IfcSaveAllSignatures::execute(istream &s)

{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("No architecture loaded");

  string sigfilename;

  s >> sigfilename;
  if (sigfilename.size() == 0)
    throw IfaceExecutionError("Need name of file to save signatures to");

  if (smanage != (GraphSigManager *)0)
    delete smanage;
  smanage = new GraphSigManager();
  smanage->initializeFromStream(s); // configure the manager;

  ostream *saveoldfileptr = status->fileoptr;
  status->fileoptr = new ofstream;
  ((ofstream *)status->fileoptr)->open(sigfilename.c_str());
  if (!*status->fileoptr) {
    delete status->fileoptr;
    status->fileoptr = saveoldfileptr;
    throw IfaceExecutionError("Unable to open signature save file: "+sigfilename);
  }

  string oldactname = dcp->conf->allacts.getCurrentName();
  dcp->conf->allacts.setCurrent("normalize");
  iterateFunctionsAddrOrder();

  ((ofstream *)status->fileoptr)->close();
  delete status->fileoptr;
  status->fileoptr = saveoldfileptr;

  dcp->conf->allacts.setCurrent(oldactname);
  delete smanage;
  smanage = (GraphSigManager *)0;
}

void IfcSaveAllSignatures::iterationCallback(Funcdata *fd)

{
  if (fd->hasNoCode()) {
    *status->optr << "No code for " << fd->getName() << endl;
    return;
  }
  try {
    dcp->conf->clearAnalysis(fd); // Clear any old analysis
    dcp->conf->allacts.getCurrent()->reset(*fd);
    dcp->conf->allacts.getCurrent()->perform( *fd );
    *status->optr << "Decompiled " << fd->getName();
    *status->optr << '(' << dec << fd->getSize() << ')' << endl;
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
    return;
  }

  smanage->setCurrentFunction(fd);
  smanage->generate();

  uint4 numsigs = smanage->numSignatures();
  if (numsigs != 0) {
    Address addr = fd->getAddress();
    uint4 spcindex = addr.getSpace()->getIndex();
    uintb off = addr.getOffset();
    status->fileoptr->write((char *)&spcindex,4);
    status->fileoptr->write((char *)&off,sizeof(uintb));
    status->fileoptr->write((char *)&numsigs,4);
    uint4 namelen = fd->getName().size();
    status->fileoptr->write((char *)&namelen,4);
    status->fileoptr->write(fd->getName().c_str(),namelen);
    XmlEncode encoder(*status->fileoptr);
    smanage->encode(encoder);
  }
  smanage->clear();

  dcp->conf->clearAnalysis(fd);
}

/// \class IfcProduceSignatures
/// \brief Calculate signatures and save combined hashes to a file: `produce signatures <filename> [...]`
///
/// For every known function entry point, the function is decompiled (using the current action)
/// and features/signatures are extracted. Features for a single function are combined using an
/// overall hash and written out to the file indicated by the first parameter.  The file will contain
/// one line per function, with the name of the function followed by the overall hash.  The command
/// optionally takes additional parameters that can alter signature generation.
void IfcProduceSignatures::iterationCallback(Funcdata *fd)

{
  if (fd->hasNoCode()) {
    *status->optr << "No code for " << fd->getName() << endl;
    return;
  }
  try {
    dcp->conf->clearAnalysis(fd); // Clear any old analysis
    dcp->conf->allacts.getCurrent()->reset(*fd);
    dcp->conf->allacts.getCurrent()->perform( *fd );
    *status->optr << "Decompiled " << fd->getName();
    *status->optr << '(' << dec << fd->getSize() << ')' << endl;
  }
  catch(LowlevelError &err) {
    *status->optr << "Skipping " << fd->getName() << ": " << err.explain << endl;
    return;
  }

  smanage->setCurrentFunction(fd);
  smanage->generate();
  hashword finalsig = smanage->getOverallHash();
  (*status->fileoptr) << fd->getName() << " = 0x" << hex << setfill('0') << setw(16) << finalsig << endl;

  smanage->clear();

  dcp->conf->clearAnalysis(fd);
}

} // End namespace ghidra

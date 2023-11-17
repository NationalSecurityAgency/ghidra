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
#include "signature_ghidra.hh"
#include "signature.hh"

namespace ghidra {

// Constructing the singleton registers the capability
GhidraSignatureCapability GhidraSignatureCapability::ghidraSignatureCapability;

void GhidraSignatureCapability::initialize(void)

{
  commandmap["generateSignatures"] = new SignaturesAt(false);
  commandmap["debugSignatures"] = new SignaturesAt(true);
  commandmap["getSignatureSettings"] = new GetSignatureSettings();
  commandmap["setSignatureSettings"] = new SetSignatureSettings();
}

void SignaturesAt::loadParameters(void)

{
  GhidraCommand::loadParameters();
  PackedDecode decoder(ghidra);
  ArchitectureGhidra::readStringStream(sin,decoder);
  addr = Address::decode(decoder); // Parse XML for functions address
}

void SignaturesAt::rawAction(void)

{
  Funcdata *fd = ghidra->symboltab->getGlobalScope()->queryFunction(addr);
  if (fd == (Funcdata *)0) {
    ostringstream s;
    s << "Bad address for signatures: " << addr.getShortcut();
    addr.printRaw(s);
    s << '\n';
    throw LowlevelError(s.str());
  }
  if (!fd->isProcStarted()) {
    string curname = ghidra->allacts.getCurrentName();
    Action *sigact;
    if (curname != "normalize")
      sigact = ghidra->allacts.setCurrent("normalize");
    else
      sigact = ghidra->allacts.getCurrent();
#ifdef __REMOTE_SOCKET__
    connect_to_console(fd);
#endif
    sigact->reset(*fd);
    sigact->perform(*fd);
    if (curname != "normalize")
      ghidra->allacts.setCurrent(curname);
  }

  sout.write("\000\000\001\016",4);
  PackedEncode encoder(sout);	// Write output XML directly to outstream
  if (debug)
    debugSignature(fd,encoder);
  else
    simpleSignature(fd,encoder);
  sout.write("\000\000\001\017",4);
}

void GetSignatureSettings::rawAction(void)

{
  sout.write("\000\000\001\016",4); // Write output XML directly to outstream
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_SIGSETTINGS);
  encoder.openElement(ELEM_MAJOR);
  encoder.writeSignedInteger(ATTRIB_CONTENT, ArchitectureCapability::getMajorVersion());
  encoder.closeElement(ELEM_MAJOR);
  encoder.openElement(ELEM_MINOR);
  encoder.writeSignedInteger(ATTRIB_CONTENT, ArchitectureCapability::getMinorVersion());
  encoder.closeElement(ELEM_MINOR);
  encoder.openElement(ELEM_SETTINGS);
  encoder.writeUnsignedInteger(ATTRIB_CONTENT, SigManager::getSettings());
  encoder.closeElement(ELEM_SETTINGS);
  encoder.closeElement(ELEM_SIGSETTINGS);
  sout.write("\000\000\001\017",4);
}

void SetSignatureSettings::loadParameters(void)

{
  string settingString;
  GhidraCommand::loadParameters();
  ArchitectureGhidra::readStringStream(sin,settingString);
  istringstream s(settingString);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  s >> settings;
}

void SetSignatureSettings::rawAction(void)

{
  if (GraphSigManager::testSettings(settings)) {
    SigManager::setSettings(settings);
    ArchitectureGhidra::writeStringStream(sout,"t");
  }
  else
    ArchitectureGhidra::writeStringStream(sout,"f");
}

} // End namespace ghidra

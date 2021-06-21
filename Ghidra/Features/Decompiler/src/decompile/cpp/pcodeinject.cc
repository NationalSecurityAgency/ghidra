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
#include "pcodeinject.hh"
#include "architecture.hh"

/// \brief Read in an \<input> or \<output> XML tag describing an injection parameter
///
/// \param el is the XML element
/// \param name is used to pass back the parameter name
/// \param size is used to pass back the parameter size
void InjectPayload::readParameter(const Element *el,string &name,uint4 &size)

{
  name = "";
  size = 0;
  int4 num = el->getNumAttributes();
  for(int4 i=0;i<num;++i) {
    if (el->getAttributeName(i) == "name")
      name = el->getAttributeValue(i);
    else if (el->getAttributeName(i) == "size") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> size;
    }
  }
  if (name.size()==0)
    throw LowlevelError("Missing inject parameter name");
}

/// Input and output parameters are assigned a unique index
void InjectPayload::orderParameters(void)

{
  int4 id = 0;
  for(int4 i=0;i<inputlist.size();++i) {
    inputlist[i].index = id;
    id += 1;
  }
  for(int4 i=0;i<output.size();++i) {
    output[i].index = id;
    id += 1;
  }
}

/// The base class version of this method restores from a \<pcode> tag.
/// Derived classes may restore from a parent tag and then invoke the
/// base class method.
/// \param el is the XML element
void InjectPayload::restoreXml(const Element *el)

{
  paramshift = 0;
  dynamic = false;
  int4 num = el->getNumAttributes();
  for(int4 i=0;i<num;++i) {
    const string &elname(el->getAttributeName(i));
    if (elname == "paramshift") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> paramshift;
    }
    else if (elname == "dynamic")
      dynamic = xml_readbool(el->getAttributeValue(i));
    else if (elname == "incidentalcopy")
      incidentalCopy = xml_readbool(el->getAttributeValue(i));
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    if (subel->getName() == "input") {
      string paramName;
      uint4 size;
      readParameter(subel,paramName,size);
      inputlist.push_back(InjectParameter(paramName,size));
    }
    else if (subel->getName() == "output") {
      string paramName;
      uint4 size;
      readParameter(subel,paramName,size);
      output.push_back(InjectParameter(paramName,size));
    }
  }
  orderParameters();
}

/// \param g is the Architecture owning \b snippet
/// \param src is a string describing the \e source of the snippet
/// \param nm is the formal name of the snippet
ExecutablePcode::ExecutablePcode(Architecture *g,const string &src,const string &nm)
  : InjectPayload(nm,EXECUTABLEPCODE_TYPE), emulator(g)
{
  glb = g;
  emitter = (PcodeEmit *)0;
  source = src;
  built = false;
}

void ExecutablePcode::build(void)

{
  if (built) return;
  InjectContext &icontext(glb->pcodeinjectlib->getCachedContext());
  icontext.clear();
  uintb uniqReserve = 0x10;			// Temporary register space reserved for inputs and output
  Architecture *glb = emulator.getArch();
  AddrSpace *codeSpace = glb->getDefaultCodeSpace();
  AddrSpace *uniqSpace = glb->getUniqueSpace();
  icontext.baseaddr = Address(codeSpace,0x1000);	// Fake address
  icontext.nextaddr = icontext.baseaddr;
  for(int4 i=0;i<sizeInput();++i) {	// Skip the first operand containing the injectid
    InjectParameter &param( getInput(i) );
    icontext.inputlist.emplace_back();
    icontext.inputlist.back().space = uniqSpace;
    icontext.inputlist.back().offset = uniqReserve;
    icontext.inputlist.back().size = param.getSize();
    inputList.push_back(uniqReserve);
    uniqReserve += 0x20;
  }
  for(int4 i=0;i<sizeOutput();++i) {
    InjectParameter &param( getOutput(i) );
    icontext.output.emplace_back();
    icontext.output.back().space = uniqSpace;
    icontext.output.back().offset = uniqReserve;
    icontext.output.back().size = param.getSize();
    outputList.push_back(uniqReserve);
    uniqReserve += 0x20;
  }
  emitter = emulator.buildEmitter(glb->pcodeinjectlib->getBehaviors(),uniqReserve);
  inject(icontext,*emitter);
  delete emitter;
  emitter = (PcodeEmit *)0;
  if (!emulator.checkForLegalCode())
    throw LowlevelError("Illegal p-code in executable snippet");
  built = true;
}

/// The caller provides a list of concrete values that are assigned to the
/// input parameters.  The number of values and input parameters must match,
/// and values are assigned in order. Input parameter order is determined either
/// by the order of tags in the defining XML.  This method assumes there is
/// exactly 1 relevant output parameter. Once the snippet is executed the
/// value of this parameter is read from the emulator state and returned.
/// \param input is the ordered list of input values to feed to \b this script
/// \return the value of the output parameter after script execution
uintb ExecutablePcode::evaluate(const vector<uintb> &input)

{
  build();		// Build the PcodeOpRaws (if we haven't before)
  emulator.resetMemory();
  if (input.size() != inputList.size())
    throw LowlevelError("Wrong number of input parameters to executable snippet");
  if (outputList.size() == 0)
    throw LowlevelError("No registered outputs to executable snippet");
  for(int4 i=0;i<input.size();++i)
    emulator.setVarnodeValue(inputList[i], input[i]);
  while(!emulator.getHalt())
    emulator.executeCurrentOp();
  return emulator.getTempValue(outputList[0]);
}

PcodeInjectLibrary::~PcodeInjectLibrary(void)

{
  vector<InjectPayload *>::iterator iter;
  for(iter=injection.begin();iter!=injection.end();++iter)
    delete *iter;
}

/// \brief Map a \e call-fixup name to a payload id
///
/// \param fixupName is the formal name of the call-fixup
/// \param injectid is the integer id
void PcodeInjectLibrary::registerCallFixup(const string &fixupName,int4 injectid/* , vector<string> targets */)

{
  pair<map<string,int4>::iterator,bool> check;
  check = callFixupMap.insert( pair<string,int4>(fixupName,injectid) );
  if (!check.second)		// This symbol is already mapped
    throw LowlevelError("Duplicate <callfixup>: "+fixupName);
  while(callFixupNames.size() <= injectid)
    callFixupNames.push_back("");
  callFixupNames[injectid] = fixupName;
}

/// \brief Map a \e callother-fixup name to a payload id
///
/// \param fixupName is the formal name of the callother-fixup
/// \param injectid is the integer id
void PcodeInjectLibrary::registerCallOtherFixup(const string &fixupName,int4 injectid)

{
  pair<map<string,int4>::iterator,bool> check;
  check = callOtherFixupMap.insert( pair<string,int4>(fixupName,injectid) );
  if (!check.second)		// This symbol is already mapped
    throw LowlevelError("Duplicate <callotherfixup>: "+fixupName);
  while(callOtherTarget.size() <= injectid)
    callOtherTarget.push_back("");
  callOtherTarget[injectid] = fixupName;
}

/// \brief Map a \e call \e mechanism name to a payload id
///
/// \param fixupName is the formal name of the call mechanism
/// \param injectid is the integer id
void PcodeInjectLibrary::registerCallMechanism(const string &fixupName,int4 injectid)

{
  pair<map<string,int4>::iterator,bool> check;
  check = callMechFixupMap.insert( pair<string,int4>(fixupName,injectid) );
  if (!check.second)		// This symbol is already mapped
    throw LowlevelError("Duplicate <callmechanism>: "+fixupName);
  while(callMechTarget.size() <= injectid)
    callMechTarget.push_back("");
  callMechTarget[injectid] = fixupName;
}

/// \brief Map a \e p-code \e script name to a payload id
///
/// \param scriptName is the formal name of the p-code script
/// \param injectid is the integer id
void PcodeInjectLibrary::registerExeScript(const string &scriptName,int4 injectid)

{
  pair<map<string,int4>::iterator,bool> check;
  check = scriptMap.insert( pair<string,int4>(scriptName,injectid) );
  if (!check.second)		// This symbol is already mapped
    throw LowlevelError("Duplicate <script>: "+scriptName);
  while(scriptNames.size() <= injectid)
    scriptNames.push_back("");
  scriptNames[injectid] = scriptName;
}

/// The given name is looked up in a symbol table depending on the given type.
/// The integer id of the matching InjectPayload is returned.
/// \param type is the payload type
/// \param nm is the formal name of the payload
/// \return the payload id or -1 if there is no matching payload
int4 PcodeInjectLibrary::getPayloadId(int4 type,const string &nm) const

{
  map<string,int4>::const_iterator iter;
  if (type == InjectPayload::CALLFIXUP_TYPE) {
    iter = callFixupMap.find(nm);
    if (iter == callFixupMap.end())
      return -1;
  }
  else if (type == InjectPayload::CALLOTHERFIXUP_TYPE) {
    iter = callOtherFixupMap.find(nm);
    if (iter == callOtherFixupMap.end())
      return -1;
  }
  else if (type == InjectPayload::CALLMECHANISM_TYPE) {
    iter = callMechFixupMap.find(nm);
    if (iter == callMechFixupMap.end())
      return -1;
  }
  else {
    iter = scriptMap.find(nm);
    if (iter == scriptMap.end())
      return -1;
  }
  return (*iter).second;
}

/// \param injectid is an integer id of a call-fixup payload
/// \return the name of the payload or the empty string
string PcodeInjectLibrary::getCallFixupName(int4 injectid) const

{
  if ((injectid < 0)||(injectid >= callFixupNames.size()))
    return "";
  return callFixupNames[injectid];
}

/// \param injectid is an integer id of a callother-fixup payload
/// \return the name of the payload or the empty string
string PcodeInjectLibrary::getCallOtherTarget(int4 injectid) const

{
  if ((injectid < 0)||(injectid >= callOtherTarget.size()))
    return "";
  return callOtherTarget[injectid];
}

/// \param injectid is an integer id of a call mechanism payload
/// \return the name of the payload or the empty string
string PcodeInjectLibrary::getCallMechanismName(int4 injectid) const

{
  if ((injectid < 0)||(injectid >= callMechTarget.size()))
    return "";
  return callMechTarget[injectid];
}

/// \brief Read in and register an injection payload from an XML stream
///
/// The root XML element describing the payload is given (\<pcode>, \<callfixup>
/// \<callotherfixup>, etc.), the InjectPayload is allocated and then
/// initialized using the element.  Then the InjectPayload is finalized with the library.
/// \param src is a string describing the source of the payload being restored
/// \param nm is the name of the payload
/// \param tp is the type of the payload (CALLFIXUP_TYPE, EXECUTABLEPCODE_TYPE, etc.)
/// \param el is the given XML element
/// \return the id of the newly registered payload
int4 PcodeInjectLibrary::restoreXmlInject(const string &src,const string &nm,int4 tp,const Element *el)

{
  int4 injectid = allocateInject(src, nm, tp);
  getPayload(injectid)->restoreXml(el);
  registerInject(injectid);
  return injectid;
}

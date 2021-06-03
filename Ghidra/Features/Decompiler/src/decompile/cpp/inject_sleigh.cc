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
#include "inject_sleigh.hh"
#include "pcodeparse.hh"
#include "architecture.hh"

InjectContextSleigh::~InjectContextSleigh(void)

{
  if (pos != (ParserContext *)0)
    delete pos;
}

InjectPayloadSleigh::~InjectPayloadSleigh(void)

{
  if (tpl != (ConstructTpl *)0)
    delete tpl;
}

InjectPayloadSleigh::InjectPayloadSleigh(const string &src,const string &nm,int4 tp)
  : InjectPayload(nm,tp)
{
  source = src;
  tpl = (ConstructTpl *)0;
  paramshift = 0;
}

void InjectPayloadSleigh::inject(InjectContext &context,PcodeEmit &emit) const

{
  InjectContextSleigh &con((InjectContextSleigh &)context);

  con.cacher.clear();

  con.pos->setAddr(con.baseaddr);
  con.pos->setNaddr(con.nextaddr);
  con.pos->setCalladdr(con.calladdr);

  ParserWalkerChange walker(con.pos);
  con.pos->deallocateState(walker);
  setupParameters(con,walker,inputlist,output,source);
  // delayslot and crossbuild directives are not allowed in snippets, so we don't need the DisassemblyCache
  // and we don't need a unique allocation mask
  SleighBuilder builder(&walker,(DisassemblyCache *)0,&con.cacher,con.glb->getConstantSpace(),con.glb->getUniqueSpace(),0);
  builder.build(tpl,-1);
  con.cacher.resolveRelatives();
  con.cacher.emit(con.baseaddr,&emit);
}

void InjectPayloadSleigh::restoreXml(const Element *el)

{
  InjectPayload::restoreXml(el);
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    if (subel->getName() == "body") {
      parsestring = subel->getContent();
    }
  }
  if (parsestring.size() == 0 && (!dynamic))
    throw LowlevelError("Missing <body> subtag in <pcode>: "+getSource());
}

void InjectPayloadSleigh::printTemplate(ostream &s) const

{
  tpl->saveXml(s,-1);
}

void InjectPayloadSleigh::checkParameterRestrictions(InjectContextSleigh &con,
						     const vector<InjectParameter> &inputlist,
						     const vector<InjectParameter> &output,
						     const string &source)
{ // Verify that the storage locations passed in -con- match the restrictions set for this payload
  if (inputlist.size() != con.inputlist.size())
    throw LowlevelError("Injection parameter list has different number of parameters than p-code operation: "+source);
  for(int4 i=0;i<inputlist.size();++i) {
    uint4 sz = inputlist[i].getSize();
    if ((sz != 0) && (sz != con.inputlist[i].size))
      throw LowlevelError("P-code input parameter size does not match injection specification: "+source);
  }
  if (output.size() != con.output.size())
    throw LowlevelError("Injection output does not match output of p-code operation: "+source);
  for(int4 i=0;i<output.size();++i) {
    uint4 sz = output[i].getSize();
    if ((sz != 0) && (sz != con.output[i].size))
      throw LowlevelError("P-code output size does not match injection specification: "+source);
  }
}

void InjectPayloadSleigh::setupParameters(InjectContextSleigh &con,ParserWalkerChange &walker,
					  const vector<InjectParameter> &inputlist,
					  const vector<InjectParameter> &output,
					  const string &source)
{ // Set-up operands in the parser state so that they pick up storage locations in InjectContext
  checkParameterRestrictions(con,inputlist,output,source);
  ParserContext *pos = walker.getParserContext();
  for(int4 i=0;i<inputlist.size();++i) {
    pos->allocateOperand(inputlist[i].getIndex(),walker);
    VarnodeData &data( con.inputlist[i] );
    FixedHandle &hand(walker.getParentHandle());
    hand.space = data.space;
    hand.offset_offset = data.offset;
    hand.size = data.size;
    hand.offset_space = (AddrSpace *)0;
    walker.popOperand();
  }
  for(int4 i=0;i<output.size();++i) {
    pos->allocateOperand(output[i].getIndex(),walker);
    VarnodeData &data( con.output[i] );
    FixedHandle &hand(walker.getParentHandle());
    hand.space = data.space;
    hand.offset_offset = data.offset;
    hand.size = data.size;
    hand.offset_space = (AddrSpace *)0;
    walker.popOperand();
  }
}

InjectPayloadCallfixup::InjectPayloadCallfixup(const string &sourceName)
  : InjectPayloadSleigh(sourceName,"unknown",CALLFIXUP_TYPE)
{
}

void InjectPayloadCallfixup::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  name = el->getAttributeValue("name");
  bool pcodeSubtag = false;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    if (subel->getName() == "pcode") {
      InjectPayloadSleigh::restoreXml(subel);
      pcodeSubtag = true;
    }
    else if (subel->getName() == "target")
      targetSymbolNames.push_back(subel->getAttributeValue("name"));
  }
  if (!pcodeSubtag)
    throw LowlevelError("<callfixup> is missing <pcode> subtag: "+name);
}

InjectPayloadCallother::InjectPayloadCallother(const string &sourceName)
  : InjectPayloadSleigh(sourceName,"unknown",CALLOTHERFIXUP_TYPE)
{
}

void InjectPayloadCallother::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  name = el->getAttributeValue("targetop");
  iter = list.begin();
  if ((iter == list.end()) || ((*iter)->getName() != "pcode"))
    throw LowlevelError("<callotherfixup> does not contain a <pcode> tag");
  InjectPayloadSleigh::restoreXml(*iter);
}

ExecutablePcodeSleigh::ExecutablePcodeSleigh(Architecture *g,const string &src,const string &nm)
  : ExecutablePcode(g,src,nm)
{
  tpl = (ConstructTpl *)0;
}

ExecutablePcodeSleigh::~ExecutablePcodeSleigh(void)

{
  if (tpl != (ConstructTpl *)0)
    delete tpl;
}

void ExecutablePcodeSleigh::inject(InjectContext &context,PcodeEmit &emit) const

{
  InjectContextSleigh &con((InjectContextSleigh &)context);

  con.cacher.clear();

  con.pos->setAddr(con.baseaddr);
  con.pos->setNaddr(con.nextaddr);
  con.pos->setCalladdr(con.calladdr);

  ParserWalkerChange walker(con.pos);
  con.pos->deallocateState(walker);
  InjectPayloadSleigh::setupParameters(con,walker,inputlist,output,getSource());
  // delayslot and crossbuild directives are not allowed in snippets, so we don't need the DisassemblyCache
  // and we don't need a unique allocation mask
  SleighBuilder builder(&walker,(DisassemblyCache *)0,&con.cacher,con.glb->getConstantSpace(),con.glb->getUniqueSpace(),0);
  builder.build(tpl,-1);
  con.cacher.resolveRelatives();
  con.cacher.emit(con.baseaddr,&emit);
}

void ExecutablePcodeSleigh::restoreXml(const Element *el)

{
  InjectPayload::restoreXml(el);
  const List &list(el->getChildren());
  List::const_iterator iter;
  bool hasbody = false;
  for (iter = list.begin(); iter != list.end(); ++iter) {
    const Element *subel = *iter;
    if (subel->getName() == "body") {
      hasbody = true;
      parsestring = subel->getContent();
    }
  }
  if (!hasbody)
    throw LowlevelError("Missing <body> subtag in <pcode>: " + getSource());
}

void ExecutablePcodeSleigh::printTemplate(ostream &s) const

{
  tpl->saveXml(s,-1);
}

InjectPayloadDynamic::~InjectPayloadDynamic(void)

{
  map<Address,Document *>::iterator iter;
  for(iter=addrMap.begin();iter!=addrMap.end();++iter)
    delete (*iter).second;
}

void InjectPayloadDynamic::restoreEntry(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  Address addr = Address::restoreXml(*iter,glb);
  ++iter;
  istringstream s((*iter)->getContent());
  try {
    Document *doc = xml_tree(s);
    map<Address,Document *>::iterator iter = addrMap.find(addr);
    if (iter != addrMap.end())
      delete (*iter).second;		// Delete any preexisting document
    addrMap[addr] = doc;
  }
  catch(XmlError &err) {
    throw LowlevelError("Error in dynamic payload XML");
  }
}

void InjectPayloadDynamic::inject(InjectContext &context,PcodeEmit &emit) const

{
  map<Address,Document *>::const_iterator eiter = addrMap.find(context.baseaddr);
  if (eiter == addrMap.end())
    throw LowlevelError("Missing dynamic inject");
  const Element *el = (*eiter).second->getRoot();
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter)
    emit.restoreXmlOp(*iter,glb->translate);
}

PcodeInjectLibrarySleigh::PcodeInjectLibrarySleigh(Architecture *g,uintb tmpbase)
  : PcodeInjectLibrary(g,tmpbase)
{
  slgh = (const SleighBase *)g->translate;
  contextCache.glb = g;
}

int4 PcodeInjectLibrarySleigh::registerDynamicInject(InjectPayload *payload)

{
  int4 id = injection.size();
  injection.push_back(payload);
  return id;
}

/// \brief Force a payload to be dynamic for debug purposes
///
/// Debug information may include inject information for payloads that aren't dynamic.
/// We substitute a dynamic payload so that analysis uses the debug info to inject, rather
/// than the hard-coded payload information.
/// \param injectid is the id of the payload to treat dynamic
/// \return the new dynamic payload object
InjectPayloadDynamic *PcodeInjectLibrarySleigh::forceDebugDynamic(int4 injectid)

{
  InjectPayload *oldPayload = injection[injectid];
  InjectPayloadDynamic *newPayload = new InjectPayloadDynamic(glb,oldPayload->getName(),oldPayload->getType());
  delete oldPayload;
  injection[injectid] = newPayload;
  return newPayload;
}

void PcodeInjectLibrarySleigh::parseInject(InjectPayload *payload)

{
  if (payload->isDynamic())
    return;
  if (slgh == (const SleighBase *)0) { // Make sure we have the sleigh AddrSpaceManager
    slgh = (const SleighBase *)glb->translate;
    if (slgh == (const SleighBase *)0)
      throw LowlevelError("Registering pcode snippet before language is instantiated");
  }
  if (contextCache.pos == (ParserContext *)0) {	// Make sure we have a context
    contextCache.pos = new ParserContext((ContextCache *)0);
    contextCache.pos->initialize(8,8,slgh->getConstantSpace());
  }
  PcodeSnippet compiler(slgh);
//  compiler.clear();			// Not necessary unless we reuse
  for(int4 i=0;i<payload->sizeInput();++i) {
    InjectParameter &param( payload->getInput(i) );
    compiler.addOperand(param.getName(),param.getIndex());
  }
  for(int4 i=0;i<payload->sizeOutput();++i) {
    InjectParameter &param( payload->getOutput(i) );
    compiler.addOperand(param.getName(),param.getIndex());
  }
  if (payload->getType() == InjectPayload::EXECUTABLEPCODE_TYPE) {
    compiler.setUniqueBase(0x2000);	// Don't need to deconflict with anything other injects
    ExecutablePcodeSleigh *sleighpayload = (ExecutablePcodeSleigh *)payload;
    istringstream s(sleighpayload->parsestring);
    if (!compiler.parseStream(s))
      throw LowlevelError(payload->getSource() + ": Unable to compile pcode: "+compiler.getErrorMessage());
    sleighpayload->tpl = compiler.releaseResult();
    sleighpayload->parsestring = "";		// No longer need the memory
  }
  else {
    compiler.setUniqueBase(tempbase);
    InjectPayloadSleigh *sleighpayload = (InjectPayloadSleigh *)payload;
    istringstream s(sleighpayload->parsestring);
    if (!compiler.parseStream(s))
      throw LowlevelError(payload->getSource() + ": Unable to compile pcode: "+compiler.getErrorMessage());
    tempbase = compiler.getUniqueBase();
    sleighpayload->tpl = compiler.releaseResult();
    sleighpayload->parsestring = "";		// No longer need the memory
  }
}

int4 PcodeInjectLibrarySleigh::allocateInject(const string &sourceName,const string &name,int4 type)

{
  int4 injectid = injection.size();
  if (type == InjectPayload::CALLFIXUP_TYPE)
    injection.push_back(new InjectPayloadCallfixup(sourceName));
  else if (type == InjectPayload::CALLOTHERFIXUP_TYPE)
    injection.push_back(new InjectPayloadCallother(sourceName));
  else if (type == InjectPayload::EXECUTABLEPCODE_TYPE)
    injection.push_back(new ExecutablePcodeSleigh(glb,sourceName,name));
  else
    injection.push_back(new InjectPayloadSleigh(sourceName,name,type));
  return injectid;
}

void PcodeInjectLibrarySleigh::registerInject(int4 injectid)

{
  InjectPayload *payload = injection[injectid];
  if (payload->isDynamic()) {
    InjectPayload *sub = new InjectPayloadDynamic(glb,payload->getName(),payload->getType());
    delete payload;
    payload = sub;
    injection[injectid] = payload;
  }
  switch(payload->getType()) {
    case InjectPayload::CALLFIXUP_TYPE:
      registerCallFixup(payload->getName(), injectid);
      parseInject(payload);
      break;
    case InjectPayload::CALLOTHERFIXUP_TYPE:
      registerCallOtherFixup(payload->getName(), injectid);
      parseInject(payload);
      break;
    case InjectPayload::CALLMECHANISM_TYPE:
      registerCallMechanism(payload->getName(), injectid);
      parseInject(payload);
      break;
    case InjectPayload::EXECUTABLEPCODE_TYPE:
      registerExeScript(payload->getName(), injectid);
      parseInject(payload);
     break;
    default:
      throw LowlevelError("Unknown p-code inject type");
  }
}

void PcodeInjectLibrarySleigh::restoreDebug(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    const string &name( subel->getAttributeValue("name") );
    istringstream s( subel->getAttributeValue("type") );
    int4 type = -1;
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> type;
    int4 id = getPayloadId(type,name);
    InjectPayloadDynamic *payload = dynamic_cast<InjectPayloadDynamic *>(getPayload(id));
    if (payload == (InjectPayloadDynamic *)0) {
      payload = forceDebugDynamic(id);
    }
    payload->restoreEntry(subel);
  }
}

const vector<OpBehavior *> &PcodeInjectLibrarySleigh::getBehaviors(void)

{
  if (inst.empty())
    glb->collectBehaviors(inst);
  return inst;
}

int4 PcodeInjectLibrarySleigh::manualCallFixup(const string &name,const string &snippetstring)

{
  string sourceName = "(manual callfixup name=\"" + name + "\")";
  int4 injectid = allocateInject(sourceName, name, InjectPayload::CALLFIXUP_TYPE);
  InjectPayloadSleigh *payload = (InjectPayloadSleigh *)getPayload(injectid);
  payload->parsestring = snippetstring;
  registerInject(injectid);
  return injectid;
}

int4 PcodeInjectLibrarySleigh::manualCallOtherFixup(const string &name,const string &outname,
						    const vector<string> &inname,const string &snippet)
{
  string sourceName = "<manual callotherfixup name=\"" + name + "\")";
  int4 injectid = allocateInject(sourceName, name, InjectPayload::CALLOTHERFIXUP_TYPE);
  InjectPayloadSleigh *payload = (InjectPayloadSleigh *)getPayload(injectid);
  for(int4 i=0;i<inname.size();++i)
    payload->inputlist.push_back(InjectParameter(inname[i],0));
  if (outname.size() != 0)
    payload->output.push_back(InjectParameter(outname,0));
  payload->orderParameters();
  payload->parsestring = snippet;
  registerInject(injectid);
  return injectid;
}

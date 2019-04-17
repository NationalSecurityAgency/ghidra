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
#include "inject_ghidra.hh"

void InjectContextGhidra::saveXml(ostream &s) const

{
  s << "<context>\n";
  baseaddr.saveXml(s);
  calladdr.saveXml(s);
  if (!inputlist.empty()) {
    s << "<input>\n";
    for(int4 i=0;i<inputlist.size();++i) {
      const VarnodeData &vn( inputlist[i] );
      s << "<addr";
      vn.space->saveXmlAttributes(s,vn.offset,vn.size);
      s << "/>\n";
    }
    s << "</input>\n";
  }
  if (!output.empty()) {
    s << "<output>\n";
    for(int4 i=0;i<output.size();++i) {
      const VarnodeData &vn( output[i] );
      s << "<addr";
      vn.space->saveXmlAttributes(s,vn.offset,vn.size);
      s << "/>\n";
    }
    s << "</output>\n";
  }
  s << "</context>\n";
}

void InjectPayloadGhidra::inject(InjectContext &con,PcodeEmit &emit) const

{
  Document *doc;
  ArchitectureGhidra *ghidra = (ArchitectureGhidra *)con.glb;
  try {
    doc = ghidra->getPcodeInject(name,type,con);
  }
  catch(JavaError &err) {
    throw LowlevelError("Error getting pcode snippet: " + err.explain);
  }
  catch(XmlError &err) {
    throw LowlevelError("Error in pcode snippet xml: "+err.explain);
  }
  if (doc == (Document *)0) {
    throw LowlevelError("Could not retrieve pcode snippet: "+name);
  }
  const Element *el = doc->getRoot();
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter)
    emit.restoreXmlOp(*iter,ghidra->translate);
  delete doc;
}

void InjectPayloadGhidra::printTemplate(ostream &s) const

{
  throw LowlevelError("Printing not supported");
}

InjectCallfixupGhidra::InjectCallfixupGhidra(const string &src,const string &nm)
  : InjectPayloadGhidra(src,nm,InjectPayload::CALLFIXUP_TYPE)
{
}

void InjectCallfixupGhidra::restoreXml(const Element *el)

{
  name = el->getAttributeValue("name");
}

InjectCallotherGhidra::InjectCallotherGhidra(const string &src,const string &nm)
  : InjectPayloadGhidra(src,nm,InjectPayload::CALLOTHERFIXUP_TYPE)
{
}

void InjectCallotherGhidra::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  name = el->getAttributeValue("targetop");
  iter = list.begin();
  if ((iter == list.end()) || ((*iter)->getName() != "pcode"))
    throw LowlevelError("<callotherfixup> does not contain a <pcode> tag");
  InjectPayload::restoreXml(*iter);
}

ExecutablePcodeGhidra::ExecutablePcodeGhidra(Architecture *g,const string &src,const string &nm)
  : ExecutablePcode(g,src,nm)
{
}

void ExecutablePcodeGhidra::inject(InjectContext &con,PcodeEmit &emit) const

{
  Document *doc;
  ArchitectureGhidra *ghidra = (ArchitectureGhidra *)con.glb;
  try {
    doc = ghidra->getPcodeInject(name,type,con);
  }
  catch(JavaError &err) {
    throw LowlevelError("Error getting pcode snippet: " + err.explain);
  }
  catch(XmlError &err) {
    throw LowlevelError("Error in pcode snippet xml: "+err.explain);
  }
  if (doc == (Document *)0) {
    throw LowlevelError("Could not retrieve pcode snippet: "+name);
  }
  const Element *el = doc->getRoot();
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter)
    emit.restoreXmlOp(*iter,ghidra->translate);
  delete doc;
}

void ExecutablePcodeGhidra::restoreXml(const Element *el)

{
  InjectPayload::restoreXml(el);	// Read parameters
  // But ignore rest of body
}

void ExecutablePcodeGhidra::printTemplate(ostream &s) const

{
  throw LowlevelError("Printing not supported");
}

int4 PcodeInjectLibraryGhidra::allocateInject(const string &sourceName,const string &name,int4 type)

{
  int4 injectid = injection.size();
  InjectPayload *payload;
  switch(type) {
    case InjectPayload::CALLFIXUP_TYPE:
      payload = new InjectCallfixupGhidra(sourceName,name);
      break;
    case InjectPayload::CALLOTHERFIXUP_TYPE:
      payload = new InjectCallotherGhidra(sourceName,name);
      break;
    case InjectPayload::CALLMECHANISM_TYPE:
      payload = new InjectPayloadGhidra(sourceName,name,InjectPayload::CALLMECHANISM_TYPE);
      break;
    case InjectPayload::EXECUTABLEPCODE_TYPE:
      payload = new ExecutablePcodeGhidra(contextCache.glb,sourceName,name);
      break;
    default:
      throw LowlevelError("Bad injection type");
  }
  injection.push_back(payload);
  return injectid;
}

void PcodeInjectLibraryGhidra::registerInject(int4 injectid)

{
  InjectPayload *payload = injection[injectid];
  switch(payload->getType()) {
    case InjectPayload::CALLFIXUP_TYPE:
      registerCallFixup(payload->getName(), injectid);
      break;
    case InjectPayload::CALLOTHERFIXUP_TYPE:
      registerCallOtherFixup(payload->getName(), injectid);
      break;
    case InjectPayload::CALLMECHANISM_TYPE:
      registerCallMechanism(payload->getName(), injectid);
      break;
    case InjectPayload::EXECUTABLEPCODE_TYPE:
      registerExeScript(payload->getName(), injectid);
     break;
    default:
      throw LowlevelError("Unknown p-code inject type");
  }
}

PcodeInjectLibraryGhidra::PcodeInjectLibraryGhidra(ArchitectureGhidra *ghi)
  : PcodeInjectLibrary(ghi,0)
{
  contextCache.glb = ghi;
}

const vector<OpBehavior *> &PcodeInjectLibraryGhidra::getBehaviors(void)

{
  if (inst.empty())
    glb->collectBehaviors(inst);
  return inst;
}

int4 PcodeInjectLibraryGhidra::manualCallFixup(const string &name,const string &snippet)

{
  return 0;	 // We don't have to do anything, because ghidra is keeping track of the snippets
}

int4 PcodeInjectLibraryGhidra::manualCallOtherFixup(const string &name,const string &outname,
						    const vector<string> &inname,const string &snippet)
{
  return 0;	 // We don't have to do anything
}

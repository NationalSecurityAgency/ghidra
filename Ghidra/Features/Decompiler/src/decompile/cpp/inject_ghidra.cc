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

namespace ghidra {

void InjectContextGhidra::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_CONTEXT);
  baseaddr.encode(encoder);
  calladdr.encode(encoder);
  if (!inputlist.empty()) {
    encoder.openElement(ELEM_INPUT);
    for(int4 i=0;i<inputlist.size();++i) {
      const VarnodeData &vn( inputlist[i] );
      encoder.openElement(ELEM_ADDR);
      vn.space->encodeAttributes(encoder,vn.offset,vn.size);
      encoder.closeElement(ELEM_ADDR);
    }
    encoder.closeElement(ELEM_INPUT);
  }
  if (!output.empty()) {
    encoder.openElement(ELEM_OUTPUT);
    for(int4 i=0;i<output.size();++i) {
      const VarnodeData &vn( output[i] );
      encoder.openElement(ELEM_ADDR);
      vn.space->encodeAttributes(encoder,vn.offset,vn.size);
      encoder.closeElement(ELEM_ADDR);
    }
    encoder.closeElement(ELEM_OUTPUT);
  }
  encoder.closeElement(ELEM_CONTEXT);
}

void InjectPayloadGhidra::inject(InjectContext &con,PcodeEmit &emit) const

{
  ArchitectureGhidra *ghidra = (ArchitectureGhidra *)con.glb;
  PackedDecode decoder(ghidra);
  try {
    if (!ghidra->getPcodeInject(name,type,con,decoder))
      throw LowlevelError("Could not retrieve injection: "+name);
  }
  catch(JavaError &err) {
    throw LowlevelError("Injection error: " + err.explain);
  }
  catch(DecoderError &err) {
    throw LowlevelError("Error decoding injection: "+err.explain);
  }
  uint4 elemId = decoder.openElement();
  Address addr = Address::decode(decoder);
  while(decoder.peekElement() != 0)
    emit.decodeOp(addr,decoder);
  decoder.closeElement(elemId);
}

void InjectPayloadGhidra::decode(Decoder &decoder)

{
  // Restore a raw <pcode> tag.  Used for uponentry, uponreturn
  uint4 elemId = decoder.openElement(ELEM_PCODE);
  decodePayloadAttributes(decoder);
  decoder.closeElementSkipping(elemId);
}

void InjectPayloadGhidra::printTemplate(ostream &s) const

{
  throw LowlevelError("Printing not supported");
}

InjectCallfixupGhidra::InjectCallfixupGhidra(const string &src,const string &nm)
  : InjectPayloadGhidra(src,nm,InjectPayload::CALLFIXUP_TYPE)
{
}

void InjectCallfixupGhidra::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CALLFIXUP);
  name = decoder.readString(ATTRIB_NAME);
  decoder.closeElementSkipping(elemId);		// Skip processing the body, let ghidra handle this
}

InjectCallotherGhidra::InjectCallotherGhidra(const string &src,const string &nm)
  : InjectPayloadGhidra(src,nm,InjectPayload::CALLOTHERFIXUP_TYPE)
{
}

void InjectCallotherGhidra::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CALLOTHERFIXUP);
  name = decoder.readString(ATTRIB_TARGETOP);
  uint4 subId = decoder.openElement();
  if (subId != ELEM_PCODE)
    throw LowlevelError("<callotherfixup> does not contain a <pcode> tag");
  decodePayloadAttributes(decoder);
  decodePayloadParams(decoder);
  decoder.closeElementSkipping(subId);		// Skip processing the body, let ghidra handle this
  decoder.closeElement(elemId);
}

ExecutablePcodeGhidra::ExecutablePcodeGhidra(Architecture *g,const string &src,const string &nm)
  : ExecutablePcode(g,src,nm)
{
}

void ExecutablePcodeGhidra::inject(InjectContext &con,PcodeEmit &emit) const

{
  ArchitectureGhidra *ghidra = (ArchitectureGhidra *)con.glb;
  PackedDecode decoder(ghidra);
  try {
    if (!ghidra->getPcodeInject(name,type,con,decoder))
      throw LowlevelError("Could not retrieve pcode snippet: "+name);
  }
  catch(JavaError &err) {
    throw LowlevelError("Error getting pcode snippet: " + err.explain);
  }
  catch(DecoderError &err) {
    throw LowlevelError("Error in pcode snippet xml: "+err.explain);
  }
  uint4 elemId = decoder.openElement();
  Address addr = Address::decode(decoder);
  while(decoder.peekElement() != 0)
    emit.decodeOp(addr,decoder);
  decoder.closeElement(elemId);
}

void ExecutablePcodeGhidra::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement();
  if (elemId != ELEM_PCODE && elemId != ELEM_CASE_PCODE && elemId != ELEM_ADDR_PCODE &&
      elemId != ELEM_DEFAULT_PCODE && elemId != ELEM_SIZE_PCODE)
    throw DecoderError("Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>");
  decodePayloadAttributes(decoder);
  decodePayloadParams(decoder);		// Parse the parameters
  decoder.closeElementSkipping(elemId);	// But skip rest of body
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

} // End namespace ghidra

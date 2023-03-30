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
#include "ghidra_translate.hh"
#include "funcdata.hh"

namespace ghidra {

/// \brief Associate a Varnode with a register name
///
/// \param nm is the register name
/// \param data is the Varnode description
/// \return a reference to the cached VarnodeData
const VarnodeData &GhidraTranslate::cacheRegister(const string &nm,const VarnodeData &data) const

{
  VarnodeData &res(nm2addr[nm]);
  res = data;
  addr2nm[data] = nm;
  return res;
}

void GhidraTranslate::initialize(DocumentStorage &store)

{
  const Element *el = store.getTag("sleigh");
  if (el == (const Element *)0)
    throw LowlevelError("Could not find ghidra sleigh tag");
  XmlDecode decoder(this,el);
  decode(decoder);
}

const VarnodeData &GhidraTranslate::getRegister(const string &nm) const

{
  map<string,VarnodeData>::const_iterator iter = nm2addr.find(nm);
  if (iter != nm2addr.end())
    return (*iter).second;
  PackedDecode decoder(glb);
  try {
    if (!glb->getRegister(nm,decoder))		// Ask Ghidra client about the register
      throw LowlevelError("No register named "+nm);
  }
  catch(DecoderError &err) {
    ostringstream errmsg;
    errmsg << "Error decoding response for query of register: " << nm;
    errmsg << " -- " << err.explain;
    throw LowlevelError(errmsg.str());
  }
  Address regaddr;
  int4 regsize;
  regaddr = Address::decode( decoder, regsize);
  VarnodeData vndata;
  vndata.space = regaddr.getSpace();
  vndata.offset = regaddr.getOffset();
  vndata.size = regsize;
  return cacheRegister(nm,vndata);
}

string GhidraTranslate::getRegisterName(AddrSpace *base,uintb off,int4 size) const

{
  if (base->getType() != IPTR_PROCESSOR) return "";
  VarnodeData vndata;
  vndata.space = base;
  vndata.offset = off;
  vndata.size = size;
  map<VarnodeData,string>::const_iterator iter = addr2nm.find(vndata);
  if (iter != addr2nm.end())
    return (*iter).second;
  string res = glb->getRegisterName(vndata);
  if (res.size()!=0)		// Cause this register to be cached if not already
    getRegister(res);		// but make sure we get full register, vndata may be truncated
  return res;
}

void GhidraTranslate::getUserOpNames(vector<string> &res) const

{
  int4 i=0;
  for(;;) {
    string nm = glb->getUserOpName(i);	// Ask for the next user-defined operator
    if (nm.size()==0) break;
    res.push_back(nm);
    i += 1;
  }
}

int4 GhidraTranslate::oneInstruction(PcodeEmit &emit,const Address &baseaddr) const

{
  int4 offset;
  PackedDecode decoder(glb);
  bool success;
  try {
    success = glb->getPcode(baseaddr,decoder);	// Request p-code for one instruction
  }
  catch(JavaError &err) {
    ostringstream s;
    s << "Error generating pcode at address: " << baseaddr.getShortcut();
    baseaddr.printRaw(s);
    throw LowlevelError(s.str());
  }
  if (!success) {
    ostringstream s;
    s << "No pcode could be generated at address: " << baseaddr.getShortcut();
    baseaddr.printRaw(s);
    throw BadDataError(s.str());
  }

  int4 el = decoder.openElement();
  offset = decoder.readSignedInteger(ATTRIB_OFFSET);
  if (el == ELEM_UNIMPL) {
    ostringstream s;
    s << "Instruction not implemented in pcode:\n ";
    baseaddr.printRaw(s);
    throw UnimplError(s.str(),offset);
  }

  Address pc = Address::decode(decoder);
  
  while(decoder.peekElement() != 0)
    emit.decodeOp(pc,decoder);
  return offset;
}

/// Parse the \<sleigh> element passed back by the Ghidra client, describing address spaces
/// and other information that needs to be cached by the decompiler.
/// \param decoder is the stream decoder
void GhidraTranslate::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_SLEIGH);
  setBigEndian(decoder.readBool(ATTRIB_BIGENDIAN));
  setUniqueBase(decoder.readUnsignedInteger(ATTRIB_UNIQBASE));
  decodeSpaces(decoder,this);
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId != ELEM_TRUNCATE_SPACE) break;
    TruncationTag tag;
    tag.decode(decoder);
    truncateSpace(tag);
  }
  decoder.closeElement(elemId);
}

} // End namespace ghidra

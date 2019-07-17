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
  restoreXml(el);
}

const VarnodeData &GhidraTranslate::getRegister(const string &nm) const

{
  map<string,VarnodeData>::const_iterator iter = nm2addr.find(nm);
  if (iter != nm2addr.end())
    return (*iter).second;
  Document *doc;
  try {
    doc = glb->getRegister(nm);		// Ask Ghidra client about the register
  }
  catch(XmlError &err) {
    ostringstream errmsg;
    errmsg << "Error parsing XML response for query of register: " << nm;
    errmsg << " -- " << err.explain;
    throw LowlevelError(errmsg.str());
  }
  if (doc == (Document *)0)
    throw LowlevelError("No register named "+nm);
  Address regaddr;
  int4 regsize;
  regaddr = Address::restoreXml( doc->getRoot(), this, regsize);
  VarnodeData vndata;
  vndata.space = regaddr.getSpace();
  vndata.offset = regaddr.getOffset();
  vndata.size = regsize;
  delete doc;
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
  uint1 *doc;
  try {
    doc = glb->getPcodePacked(baseaddr);	// Request p-code for one instruction
  }
  catch(JavaError &err) {
    ostringstream s;
    s << "Error generating pcode at address: " << baseaddr.getShortcut();
    baseaddr.printRaw(s);
    throw LowlevelError(s.str());
  }
  if (doc == (uint1 *)0) {
    ostringstream s;
    s << "No pcode could be generated at address: " << baseaddr.getShortcut();
    baseaddr.printRaw(s);
    throw BadDataError(s.str());
  }

  uintb val;
  const uint1 *ptr = PcodeEmit::unpackOffset(doc+1,val);
  offset = (int4)val;

  if (*doc == PcodeEmit::unimpl_tag) {
    ostringstream s;
    s << "Instruction not implemented in pcode:\n ";
    baseaddr.printRaw(s);
    delete [] doc;
    throw UnimplError(s.str(),offset);
  }

  int4 spcindex = (int4)(*ptr++ - 0x20);
  AddrSpace *spc = getSpace(spcindex);
  uintb instoffset;
  ptr = PcodeEmit::unpackOffset(ptr,instoffset);
  Address pc(spc,instoffset);
  
  while(*ptr == PcodeEmit::op_tag)
    ptr = emit.restorePackedOp(pc,ptr,this);
  delete [] doc;
  return offset;
}

/// The Ghidra client passes descriptions of address spaces and other
/// information that needs to be cached by the decompiler
/// \param el is the element of the initialization tag
void GhidraTranslate::restoreXml(const Element *el)

{
  setBigEndian(xml_readbool(el->getAttributeValue("bigendian")));
  {
    istringstream s(el->getAttributeValue("uniqbase"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    uintm ubase;
    s >> ubase;
    setUniqueBase(ubase);
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  restoreXmlSpaces(*iter,this);
  ++iter;
  while(iter != list.end()) {
    const Element *subel = *iter;
    if (subel->getName() == "truncate_space") {
      TruncationTag tag;
      tag.restoreXml(subel);
      truncateSpace(tag);
    }
    ++iter;
  }
}


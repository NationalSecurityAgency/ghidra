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
#include "sleighbase.hh"

namespace ghidra {

const uint4 SleighBase::MAX_UNIQUE_SIZE = 128;

int4 SourceFileIndexer::index(const string filename){
	auto it = fileToIndex.find(filename);
	if (fileToIndex.end() != it){
		return it->second;
	}
	fileToIndex[filename] = leastUnusedIndex;
	indexToFile[leastUnusedIndex] = filename;
	return leastUnusedIndex++;
}

int4 SourceFileIndexer::getIndex(string filename){
	return fileToIndex[filename];
}

string SourceFileIndexer::getFilename(int4 index){
	return indexToFile[index];
}

void SourceFileIndexer::decode(Decoder &decoder)

{
  uint4 el = decoder.openElement(sla::ELEM_SOURCEFILES);
  while(decoder.peekElement() == sla::ELEM_SOURCEFILE) {
    int4 subel = decoder.openElement();
    string filename = decoder.readString(sla::ATTRIB_NAME);
    int4 index = decoder.readSignedInteger(sla::ATTRIB_INDEX);
    decoder.closeElement(subel);
    fileToIndex[filename] = index;
    indexToFile[index] = filename;
  }
  decoder.closeElement(el);
}

void SourceFileIndexer::encode(Encoder &encoder) const

{
  encoder.openElement(sla::ELEM_SOURCEFILES);
  for (int4 i = 0; i < leastUnusedIndex; ++i){
    encoder.openElement(sla::ELEM_SOURCEFILE);
    encoder.writeString(sla::ATTRIB_NAME, indexToFile.at(i));
    encoder.writeSignedInteger(sla::ATTRIB_INDEX, i);
    encoder.closeElement(sla::ELEM_SOURCEFILE);
  }
  encoder.closeElement(sla::ELEM_SOURCEFILES);
}

SleighBase::SleighBase(void)

{
  root = (SubtableSymbol *)0;
  maxdelayslotbytes = 0;
  unique_allocatemask = 0;
  numSections = 0;
}

/// Assuming the symbol table is populated, iterate through the table collecting
/// registers (for the map), user-op names, and context fields.
void SleighBase::buildXrefs(vector<string> &errorPairs)

{
  SymbolScope *glb = symtab.getGlobalScope();
  SymbolTree::const_iterator iter;
  SleighSymbol *sym;
  ostringstream s;

  for(iter=glb->begin();iter!=glb->end();++iter) {
    sym = *iter;
    if (sym->getType() == SleighSymbol::varnode_symbol) {
      pair<VarnodeData,string> ins(((VarnodeSymbol *)sym)->getFixedVarnode(),sym->getName());
      pair<map<VarnodeData,string>::iterator,bool> res = varnode_xref.insert(ins);
      if (!res.second) {
	errorPairs.push_back(sym->getName());
	errorPairs.push_back((*(res.first)).second);
      }
    }
    else if (sym->getType() == SleighSymbol::userop_symbol) {
      int4 index = ((UserOpSymbol *)sym)->getIndex();
      while(userop.size() <= index)
	userop.push_back("");
      userop[index] = sym->getName();
    }
    else if (sym->getType() == SleighSymbol::context_symbol) {
      ContextSymbol *csym = (ContextSymbol *)sym;
      ContextField *field = (ContextField *)csym->getPatternValue();
      int4 startbit = field->getStartBit();
      int4 endbit = field->getEndBit();
      registerContext(csym->getName(),startbit,endbit);
    }
  }
}

/// If \b this SleighBase is being reused with a new program, the context
/// variables need to be registered with the new program's database
void SleighBase::reregisterContext(void)

{
  SymbolScope *glb = symtab.getGlobalScope();
  SymbolTree::const_iterator iter;
  SleighSymbol *sym;
  for(iter=glb->begin();iter!=glb->end();++iter) {
    sym = *iter;
    if (sym->getType() == SleighSymbol::context_symbol) {
      ContextSymbol *csym = (ContextSymbol *)sym;
      ContextField *field = (ContextField *)csym->getPatternValue();
      int4 startbit = field->getStartBit();
      int4 endbit = field->getEndBit();
      registerContext(csym->getName(),startbit,endbit);
    }
  }
}

const VarnodeData &SleighBase::getRegister(const string &nm) const

{
  VarnodeSymbol *sym = (VarnodeSymbol *)findSymbol(nm);
  if (sym == (VarnodeSymbol *)0)
    throw SleighError("Unknown register name: "+nm);
  if (sym->getType() != SleighSymbol::varnode_symbol)
    throw SleighError("Symbol is not a register: "+nm);
  return sym->getFixedVarnode();
}

string SleighBase::getRegisterName(AddrSpace *base,uintb off,int4 size) const

{
  VarnodeData sym;
  sym.space = base;
  sym.offset = off;
  sym.size = size;
  map<VarnodeData,string>::const_iterator iter = varnode_xref.upper_bound(sym); // First point greater than offset
  if (iter == varnode_xref.begin()) return "";
  iter--;
  const VarnodeData &point((*iter).first);
  if (point.space != base) return "";
  uintb offbase = point.offset;
  if (point.offset+point.size >= off+size)
    return (*iter).second;
  
  while(iter != varnode_xref.begin()) {
    --iter;
    const VarnodeData &point((*iter).first);
    if ((point.space != base)||(point.offset != offbase)) return "";
    if (point.offset+point.size >= off+size)
      return (*iter).second;
  }
  return "";
}

void SleighBase::getAllRegisters(map<VarnodeData,string> &reglist) const

{
  reglist = varnode_xref;
}

void SleighBase::getUserOpNames(vector<string> &res) const

{
  res = userop;		// Return list of all language defined user ops (with index)
}

/// Write a tag fully describing the details of the space.
/// \param encoder is the stream being written
/// \param spc is the given address space
void SleighBase::encodeSlaSpace(Encoder &encoder,AddrSpace *spc) const

{
  if (spc->getType() == IPTR_INTERNAL)
    encoder.openElement(sla::ELEM_SPACE_UNIQUE);
  else if (spc->isOtherSpace())
    encoder.openElement(sla::ELEM_SPACE_OTHER);
  else
    encoder.openElement(sla::ELEM_SPACE);
  encoder.writeString(sla::ATTRIB_NAME,spc->getName());
  encoder.writeSignedInteger(sla::ATTRIB_INDEX, spc->getIndex());
  encoder.writeBool(sla::ATTRIB_BIGENDIAN, isBigEndian());
  encoder.writeSignedInteger(sla::ATTRIB_DELAY, spc->getDelay());
//  if (spc->getDelay() != spc->getDeadcodeDelay())
//    encoder.writeSignedInteger(sla::ATTRIB_DEADCODEDELAY, spc->getDeadcodeDelay());
  encoder.writeSignedInteger(sla::ATTRIB_SIZE, spc->getAddrSize());
  if (spc->getWordSize() > 1)
    encoder.writeSignedInteger(sla::ATTRIB_WORDSIZE, spc->getWordSize());
  encoder.writeBool(sla::ATTRIB_PHYSICAL, spc->hasPhysical());
  if (spc->getType() == IPTR_INTERNAL)
    encoder.closeElement(sla::ELEM_SPACE_UNIQUE);
  else if (spc->isOtherSpace())
    encoder.closeElement(sla::ELEM_SPACE_OTHER);
  else
    encoder.closeElement(sla::ELEM_SPACE);
}

/// This does the bulk of the work of creating a .sla file
/// \param encoder is the stream encoder
void SleighBase::encode(Encoder &encoder) const

{
  encoder.openElement(sla::ELEM_SLEIGH);
  encoder.writeSignedInteger(sla::ATTRIB_VERSION, sla::FORMAT_VERSION);
  encoder.writeBool(sla::ATTRIB_BIGENDIAN, isBigEndian());
  encoder.writeSignedInteger(sla::ATTRIB_ALIGN, alignment);
  encoder.writeUnsignedInteger(sla::ATTRIB_UNIQBASE, getUniqueBase());
  if (maxdelayslotbytes > 0)
    encoder.writeUnsignedInteger(sla::ATTRIB_MAXDELAY, maxdelayslotbytes);
  if (unique_allocatemask != 0)
    encoder.writeUnsignedInteger(sla::ATTRIB_UNIQMASK, unique_allocatemask);
  if (numSections != 0)
    encoder.writeUnsignedInteger(sla::ATTRIB_NUMSECTIONS, numSections);
  indexer.encode(encoder);
  encoder.openElement(sla::ELEM_SPACES);
  encoder.writeString(sla::ATTRIB_DEFAULTSPACE, getDefaultCodeSpace()->getName());
  for(int4 i=0;i<numSpaces();++i) {
    AddrSpace *spc = getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    if ((spc->getType()==IPTR_CONSTANT) || 
	(spc->getType()==IPTR_FSPEC)||
	(spc->getType()==IPTR_IOP)||
	(spc->getType()==IPTR_JOIN))
      continue;
    encodeSlaSpace(encoder,spc);
  }
  encoder.closeElement(sla::ELEM_SPACES);
  symtab.encode(encoder);
  encoder.closeElement(sla::ELEM_SLEIGH);
}

/// This is identical to the functionality of decodeSpace, but the AddrSpace information is stored
/// in the .sla file format.
/// \param decoder is the stream decoder
/// \param trans is the translator object to be associated with the new space
/// \return a pointer to the initialized AddrSpace
AddrSpace *SleighBase::decodeSlaSpace(Decoder &decoder,const Translate *trans)

{
  uint4 elemId = decoder.openElement();
  AddrSpace *res;
  int4 index = 0;
  int4 addressSize = 0;
  int4 delay = -1;
  int4 deadcodedelay = -1;
  string name;
  int4 wordsize = 1;
  bool bigEnd = false;
  uint4 flags = 0;
  for (;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == sla::ATTRIB_NAME) {
      name = decoder.readString();
    }
    if (attribId == sla::ATTRIB_INDEX)
      index = decoder.readSignedInteger();
    else if (attribId == sla::ATTRIB_SIZE)
      addressSize = decoder.readSignedInteger();
    else if (attribId == sla::ATTRIB_WORDSIZE)
      wordsize = decoder.readSignedInteger();
    else if (attribId == sla::ATTRIB_BIGENDIAN) {
      bigEnd = decoder.readBool();
    }
    else if (attribId == sla::ATTRIB_DELAY)
      delay = decoder.readSignedInteger();
    else if (attribId == sla::ATTRIB_PHYSICAL) {
      if (decoder.readBool())
	flags |= AddrSpace::hasphysical;
    }
  }
  decoder.closeElement(elemId);
  if (deadcodedelay == -1)
    deadcodedelay = delay;	// If deadcodedelay attribute not present, set it to delay
  if (index == 0)
    throw LowlevelError("Expecting index attribute");
  if (elemId == sla::ELEM_SPACE_UNIQUE)
    res = new UniqueSpace(this,trans,index,flags);
  else if (elemId == sla::ELEM_SPACE_OTHER)
    res = new OtherSpace(this,trans,index);
  else {
    if (addressSize == 0 || delay == -1 || name.size() == 0)
      throw LowlevelError("Expecting size/delay/name attributes");
    res = new AddrSpace(this,trans,IPTR_PROCESSOR,name,bigEnd,addressSize,wordsize,index,flags,delay,deadcodedelay);
  }

  return res;
}

/// This is identical in functionality to decodeSpaces but the AddrSpace information
/// is stored in the .sla file format.
/// \param decoder is the stream decoder
/// \param trans is the processor translator to be associated with the spaces
void SleighBase::decodeSlaSpaces(Decoder &decoder,const Translate *trans)

{
  // The first space should always be the constant space
  insertSpace(new ConstantSpace(this,trans));

  uint4 elemId = decoder.openElement(sla::ELEM_SPACES);
  string defname = decoder.readString(sla::ATTRIB_DEFAULTSPACE);
  while(decoder.peekElement() != 0) {
    AddrSpace *spc = decodeSlaSpace(decoder,trans);
    insertSpace(spc);
  }
  decoder.closeElement(elemId);
  AddrSpace *spc = getSpaceByName(defname);
  if (spc == (AddrSpace *)0)
    throw LowlevelError("Bad 'defaultspace' attribute: "+defname);
  setDefaultCodeSpace(spc->getIndex());
}

/// This parses the main \<sleigh> tag (from a .sla file), which includes the description
/// of address spaces and the symbol table, with its associated decoding tables
/// \param decoder is the stream to decode
void SleighBase::decode(Decoder &decoder)

{
  maxdelayslotbytes = 0;
  unique_allocatemask = 0;
  numSections = 0;
  int4 version = 0;
  uint4 el = decoder.openElement(sla::ELEM_SLEIGH);
  uint4 attrib = decoder.getNextAttributeId();
  while(attrib != 0) {
    if (attrib == sla::ATTRIB_BIGENDIAN)
      setBigEndian(decoder.readBool());
    else if (attrib == sla::ATTRIB_ALIGN)
      alignment = decoder.readSignedInteger();
    else if (attrib == sla::ATTRIB_UNIQBASE)
      setUniqueBase(decoder.readUnsignedInteger());
    else if (attrib == sla::ATTRIB_MAXDELAY)
      maxdelayslotbytes = decoder.readUnsignedInteger();
    else if (attrib == sla::ATTRIB_UNIQMASK)
      unique_allocatemask = decoder.readUnsignedInteger();
    else if (attrib == sla::ATTRIB_NUMSECTIONS)
      numSections = decoder.readUnsignedInteger();
    else if (attrib == sla::ATTRIB_VERSION)
      version = decoder.readSignedInteger();
    attrib = decoder.getNextAttributeId();
  }
  if (version != sla::FORMAT_VERSION)
    throw LowlevelError(".sla file has wrong format");
  indexer.decode(decoder);
  decodeSlaSpaces(decoder,this);
  symtab.decode(decoder,this);
  decoder.closeElement(el);
  root = (SubtableSymbol *)symtab.getGlobalScope()->findSymbol("instruction");
  vector<string> errorPairs;
  buildXrefs(errorPairs);
  if (!errorPairs.empty())
    throw SleighError("Duplicate register pairs");
}

} // End namespace ghidra

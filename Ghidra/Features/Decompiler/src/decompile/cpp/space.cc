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
#include "space.hh"
#include "translate.hh"

/// Calculate \e highest based on \e addressSize, and \e wordsize.
/// This also calculates the default pointerLowerBound
void AddrSpace::calcScaleMask(void)

{
  pointerLowerBound = (addressSize < 3) ? 0x100: 0x1000;
  highest = calc_mask(addressSize); // Maximum address
  highest = highest * wordsize + (wordsize-1); // Maximum byte address
  pointerUpperBound = highest;
}

/// Initialize an address space with its basic attributes
/// \param m is the space manager associated with the new space
/// \param t is the processor translator associated with the new space
/// \param tp is the type of the new space (PROCESSOR, CONSTANT, INTERNAL,...)
/// \param nm is the name of the new space
/// \param size is the (offset encoding) size of the new space
/// \param ws is the number of bytes in an addressable unit
/// \param ind is the integer identifier for the new space
/// \param fl can be 0 or AddrSpace::hasphysical
/// \param dl is the number of rounds to delay heritage for the new space
AddrSpace::AddrSpace(AddrSpaceManager *m,const Translate *t,spacetype tp,const string &nm,
		     uint4 size,uint4 ws, int4 ind,uint4 fl,int4 dl)
{
  refcount = 0;			// No references to this space yet
  manage = m;
  trans = t;
  type = tp;
  name = nm;
  addressSize = size;
  wordsize = ws;
  index = ind;
  delay = dl;
  deadcodedelay = dl;		// Deadcode delay initially starts the same as heritage delay
  minimumPointerSize = 0;	// (initially) assume pointers must match the space size exactly
  shortcut = ' ';		// Placeholder meaning shortcut is unassigned

  // These are the flags we allow to be set from constructor
  flags = (fl & hasphysical);
  if (t->isBigEndian())
    flags |= big_endian;
  flags |= (heritaged | does_deadcode);		// Always on unless explicitly turned off in derived constructor
  
  calcScaleMask();
}

/// This is a partial constructor, for initializing a space
/// via XML
/// \param m the associated address space manager
/// \param t is the processor translator
/// \param tp the basic type of the space
AddrSpace::AddrSpace(AddrSpaceManager *m,const Translate *t,spacetype tp)

{
  refcount = 0;
  manage = m;
  trans = t;
  type = tp;
  flags = (heritaged | does_deadcode);		// Always on unless explicitly turned off in derived constructor
  wordsize = 1;
  minimumPointerSize = 0;
  shortcut = ' ';
  // We let big_endian get set by attribute
}

/// Save the \e name, \e index, \e bigendian, \e delay,
/// \e size, \e wordsize, and \e physical attributes which
/// are common with all address spaces derived from AddrSpace
/// \param s the stream where the attributes are written
void AddrSpace::saveBasicAttributes(ostream &s) const

{
  a_v(s,"name",name);
  a_v_i(s,"index",index);
  a_v_b(s,"bigendian",isBigEndian());
  a_v_i(s,"delay",delay);
  if (delay != deadcodedelay)
    a_v_i(s,"deadcodedelay",deadcodedelay);
  a_v_i(s,"size",addressSize);
  if (wordsize > 1) a_v_i(s,"wordsize",wordsize);
  a_v_b(s,"physical",hasPhysical());
}

/// The logical form of the space is truncated from its actual size
/// Pointers may refer to this original size put the most significant bytes are ignored
/// \param newsize is the size (in bytes) of the truncated (logical) space
void AddrSpace::truncateSpace(uint4 newsize)

{
  setFlags(truncated);
  addressSize = newsize;
  minimumPointerSize = newsize;
  calcScaleMask();
}

/// Write the main XML attributes for an address within this space
/// The caller provides only the \e offset, and this routine fills
/// in other details pertaining to this particular space.
/// \param s is the stream to write to
/// \param offset is the offset of the address
void AddrSpace::saveXmlAttributes(ostream &s,uintb offset) const

{
  a_v(s,"space",getName());	// Just append the proper attributes
  s << ' ' << "offset=\"";
  printOffset(s,offset);
  s << "\"";
}

/// Write the main XML attributes of an address with this space
/// and a size. The caller provides the \e offset and \e size,
/// and other details about this particular space are filled in.
/// \param s is the stream to write to
/// \param offset is the offset of the address
/// \param size is the size of the memory location
void AddrSpace::saveXmlAttributes(ostream &s,uintb offset,int4 size) const

{
  a_v(s,"space",getName());	// Just append the proper attributes
  s << ' ' << "offset=\"";
  printOffset(s,offset);
  s << "\"";
  a_v_i(s,"size",size);
}

/// For an XML tag describing an address in this space, this routine
/// recovers the offset and possibly the size described by the tag
/// \param el is the XML address tag
/// \param size is a reference where the recovered size should be stored
/// \return the recovered offset
uintb AddrSpace::restoreXmlAttributes(const Element *el,uint4 &size) const

{
  uintb offset;
  int4 num = el->getNumAttributes();
  bool foundoffset = false;
  for(int4 i=0;i<num;++i) {
    if (el->getAttributeName(i)=="offset") {
      foundoffset = true;
      istringstream s1(el->getAttributeValue(i));
      s1.unsetf(ios::dec | ios::hex | ios::oct);
      s1 >> offset;
    }
    else if (el->getAttributeName(i)=="size") {
      istringstream s2(el->getAttributeValue(i));
      s2.unsetf(ios::dec | ios::hex | ios::oct);
      s2 >> size;
    }
  }
  if (!foundoffset)
    throw LowlevelError("Address is missing offset");

  return offset;
}

/// Print the \e offset as hexidecimal digits.
/// \param s is the stream to write to
/// \param offset is the offset to be printed
void AddrSpace::printOffset(ostream &s,uintb offset) const

{
  s << "0x" << hex << offset;
}

/// This is a printing method for the debugging routines. It
/// prints taking into account the \e wordsize, adding a
/// "+n" if the offset is not on-cut with wordsize. It also
/// returns the expected/typical size of values from this space.
/// \param s is the stream being written
/// \param offset is the offset to be printed
void AddrSpace::printRaw(ostream &s,uintb offset) const

{
  int4 sz = getAddrSize();
  if (sz > 4) {
    if ((offset>>32) == 0)
      sz = 4;			// Don't print a bunch of zeroes at front of address
    else if ((offset>>48) == 0)
      sz = 6;
  }
  s << "0x" << setfill('0') << setw(2*sz) << hex << byteToAddress(offset,wordsize);
  if (wordsize>1) {
    int4 cut = offset % wordsize;
    if (cut != 0)
      s << '+' << dec << cut;
  }
}

static int4 get_offset_size(const char *ptr,uintb &offset)

{				// Get optional size and offset fields from string
  int4 size;
  uint4 val;
  char *ptr2;

  val = 0;			// Defaults
  size = -1;
  if (*ptr == ':') {
    size = strtoul(ptr+1,&ptr2,0);
    if (*ptr2 == '+')
      val = strtoul(ptr2+1,&ptr2,0);
  }
  if (*ptr == '+')
    val = strtoul(ptr+1,&ptr2,0);

  offset += val;		// Adjust offset
  return size;
}

/// For the console mode, an address space can tailor how it
/// converts user strings into offsets within the space. The
/// base routine can read and convert register names as well
/// as absolute hex addresses.  A size can be indicated by
/// appending a ':' and integer, .i.e.  0x1000:2.  Offsets within
/// a register can be indicated by appending a '+' and integer,
/// i.e. eax+2
/// \param s is the string to be parsed
/// \param size is a reference to the size being returned
/// \return the parsed offset
uintb AddrSpace::read(const string &s,int4 &size) const

{
  const char *enddata;
  char *tmpdata;
  int4 expsize;
  string::size_type append;
  string frontpart;
  uintb offset;
  
  append = s.find_first_of(":+");
  try {
    if (append == string::npos) {
      const VarnodeData &point(trans->getRegister(s));
      offset = point.offset;
      size = point.size;
    }
    else {
      frontpart = s.substr(0,append);
      const VarnodeData &point(trans->getRegister(frontpart));
      offset = point.offset;
      size = point.size;
    }
  }
  catch(LowlevelError &err) {	// Name doesn't exist
    offset = strtoul(s.c_str(),&tmpdata,0);
    offset = addressToByte(offset,wordsize);
    enddata = (const char *) tmpdata;
    if (enddata - s.c_str() == s.size()) { // If no size or offset override
      size = manage->getDefaultSize();	// Return "natural" size
      return offset;
    }
    size = manage->getDefaultSize();
  }
  if (append != string::npos) {
    enddata = s.c_str()+append;
    expsize = get_offset_size( enddata, offset );
    if (expsize!=-1) {
      size = expsize;
      return offset;
    }
  }
  return offset;
}

/// Write a tag fully describing the details of this space
/// suitable for later recovery via restoreXml.
/// \param s is the stream being written
void AddrSpace::saveXml(ostream &s) const

{
  s << "<space";		// This implies type=processor
  saveBasicAttributes(s);
  s << "/>\n";
}

/// Walk a parsed XML tag and recover all the properties defining
/// this space.  The processor translator, \e trans, and the
/// \e type must already be filled in.
/// \param el is the parsed XML tag
void AddrSpace::restoreXml(const Element *el)

{
  int4 numAttribs = el->getNumAttributes();
  deadcodedelay = -1;
  for (int4 i=0; i < numAttribs; i++) {
    string attrName = el->getAttributeName(i);
    string attrValue = el->getAttributeValue(i);
    
    if (attrName == "name") {
      name = attrValue;
    }
    if (attrName == "index")
      {
	istringstream s1(attrValue);
	s1.unsetf(ios::dec | ios::hex | ios::oct);
	s1 >> index;
      }
    if (attrName == "size")
      {
	istringstream s1(attrValue);
	s1.unsetf(ios::dec | ios::hex | ios::oct);
	s1 >> addressSize;
      }
    if (attrName == "wordsize")
      {
	istringstream s1(attrValue);
	s1.unsetf(ios::dec | ios::hex | ios::oct);
	s1 >> wordsize;
      }
    if (attrName == "bigendian") {
      if (xml_readbool(attrValue))
	flags |= big_endian;
    }
    if (attrName == "delay") {
      istringstream s1(attrValue);
      s1.unsetf(ios::dec | ios::hex | ios::oct);
      s1 >> delay;
    }
    if (attrName == "deadcodedelay") {
      istringstream s1(attrValue);
      s1.unsetf(ios::dec | ios::hex | ios::oct);
      s1 >> deadcodedelay;
    }      
    if (attrName == "physical") {
      if (xml_readbool(attrValue))
	flags |= hasphysical;
    }
    
  }
  if (deadcodedelay == -1)
    deadcodedelay = delay;	// If deadcodedelay attribute not present, set it to delay
  calcScaleMask();
}

/// This constructs the unique constant space
/// By convention, the name is always "const" and the index
/// is always 0.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param nm is the name
/// \param ind is the integer identifier
ConstantSpace::ConstantSpace(AddrSpaceManager *m,const Translate *t,
			     const string &nm,int4 ind)
  : AddrSpace(m,t,IPTR_CONSTANT,nm,sizeof(uintb),1,ind,0,0)
{
  clearFlags(heritaged|does_deadcode|big_endian);
  if (HOST_ENDIAN==1)		// Endianness always matches host
    setFlags(big_endian);
}

/// Constants are always printed as hexidecimal values in
/// the debugger and console dumps
void ConstantSpace::printRaw(ostream &s,uintb offset) const

{
  s << "0x" << hex << offset;
}

/// The ConstantSpace should never be explicitly saved as it is
/// always built automatically
void ConstantSpace::saveXml(ostream &s) const

{
  throw LowlevelError("Should never save the constant space as XML");
}

/// As the ConstantSpace is never saved, it should never get
/// restored either.
void ConstantSpace::restoreXml(const Element *el)

{
  throw LowlevelError("Should never restore the constant space from XML");
}

/// Construct the \b other space, which is automatically constructed
/// by the compiler, and is only constructed once.  The name should
/// always by \b OTHER.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param nm is the name of the space
/// \param ind is the integer identifier
OtherSpace::OtherSpace(AddrSpaceManager *m,const Translate *t,
		       const string &nm,int4 ind)
  : AddrSpace(m,t,IPTR_PROCESSOR,nm,sizeof(uintb),1,ind,0,0)
{
  clearFlags(heritaged|does_deadcode);
  setFlags(is_otherspace);
}

OtherSpace::OtherSpace(AddrSpaceManager *m,const Translate *t)
  : AddrSpace(m,t,IPTR_PROCESSOR)
{
  clearFlags(heritaged|does_deadcode);
  setFlags(is_otherspace);
}

void OtherSpace::printRaw(ostream &s,uintb offset) const

{
  s << "0x" << hex << offset;
}

void OtherSpace::saveXml(ostream &s) const

{
  s << "<space_other";
  saveBasicAttributes(s);
  s << "/>\n";
}

/// This is the constructor for the \b unique space, which is
/// automatically constructed by the analysis engine, and
/// constructed only once.  The name should always be \b unique.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param nm is the name of the space
/// \param ind is the integer identifier
/// \param fl are attribute flags (currently unused)
UniqueSpace::UniqueSpace(AddrSpaceManager *m,const Translate *t,const string &nm,
			 int4 ind,uint4 fl)
  : AddrSpace(m,t,IPTR_INTERNAL,nm,sizeof(uintm),1,ind,fl,0)
{
  setFlags(hasphysical);
}

UniqueSpace::UniqueSpace(AddrSpaceManager *m,const Translate *t)
  : AddrSpace(m,t,IPTR_INTERNAL)
{
  setFlags(hasphysical);
}

void UniqueSpace::saveXml(ostream &s) const

{
  s << "<space_unique";
  saveBasicAttributes(s);
  s << "/>\n";
}

/// This is the constructor for the \b join space, which is automatically constructed by the
/// analysis engine, and constructed only once. The name should always be \b join.
/// \param m is the associated address space manager
/// \param t is the associated processor translator
/// \param nm is the name of the space
/// \param ind is the integer identifier
JoinSpace::JoinSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind)
  : AddrSpace(m,t,IPTR_JOIN,nm,sizeof(uintm),1,ind,0,0)
{
  // This is a virtual space
  // setFlags(hasphysical);
  clearFlags(heritaged); // This space is never heritaged, but does dead-code analysis
}

/// Save a join address to the stream as XML.  This method in the interface only
/// outputs XML attributes for a single tag, so we are forced to encode what should probably
/// be recursive tags into an attribute
/// \param s is the stream being written to
/// \param offset is the offset within the address space to encode
void JoinSpace::saveXmlAttributes(ostream &s,uintb offset) const

{
  JoinRecord *rec = getManager()->findJoin(offset); // Record must already exist
  a_v(s,"space",getName());
  int4 num = rec->numPieces();
  for(int4 i=0;i<num;++i) {
    const VarnodeData &vdata( rec->getPiece(i) );
    ostringstream t;
    t << " piece" << dec << (i+1) << "=\"";
    t << vdata.space->getName() << ":0x";
    t << hex << vdata.offset << ':' << dec << vdata.size << '\"';
    s << t.str();
  }
  if (num == 1)
    a_v_i(s,"logicalsize",rec->getUnified().size);

}

/// Save a join address to the stream as XML.  This method in the interface only
/// outputs XML attributes for a single tag, so we are forced to encode what should probably
/// be recursive tags into an attribute
/// \param s is the stream being written to
/// \param offset is the offset within the address space to encode
/// \param size is the size of the memory location being encoded
void JoinSpace::saveXmlAttributes(ostream &s,uintb offset,int4 size) const

{
  JoinRecord *rec = getManager()->findJoin(offset); // Record must already exist
  a_v(s,"space",getName());
  int4 num = rec->numPieces();
  int4 count = 0;
  for(int4 i=0;i<num;++i) {
    const VarnodeData &vdata( rec->getPiece(i) );
    ostringstream t;
    t << " piece" << dec << (i+1) << "=\"";
    t << vdata.space->getName() << ":0x";
    t << hex << vdata.offset << ':' << dec << vdata.size << '\"';
    count += vdata.size;
    s << t.str();
  }
  if (num == 1)
    a_v_i(s,"logicalsize",rec->getUnified().size);
  if ((count != size)&&(num>1))
    throw LowlevelError("size attribute in join tag does not match size of pieces");
}

/// Restore a join address from an XML tag.  Pieces of the join are encoded as a sequence
/// of tag attributes.  The Translate::findAddJoin method is used to construct a logical
/// address within the join space.
/// \param el is the parsed XML element to extract the address from
/// \param size is a reference to be filled in as the size encoded by the tag
/// \return the offset of the final address encoded by the tag
uintb JoinSpace::restoreXmlAttributes(const Element *el,uint4 &size) const

{
  vector<VarnodeData> pieces;
  int4 numAttribs = el->getNumAttributes();
  uint4 sizesum = 0;
  uint4 logicalsize = 0;
  for(int4 i=0;i<numAttribs;++i) {
    string attrName = el->getAttributeName(i);
    if (0!=attrName.compare(0,5,"piece")) {
      if (attrName == "logicalsize") {
	istringstream s3(el->getAttributeValue(i));
	s3.unsetf(ios::dec | ios::hex | ios::oct);
	s3 >> logicalsize;
      }
      continue;
    }
    int4 pos = (int4)(attrName[5] - '1');
    while(pieces.size() <= pos)
      pieces.emplace_back();
    VarnodeData &vdat( pieces[pos] );

    string attrVal = el->getAttributeValue(i);
    string::size_type offpos = attrVal.find(':');
    if (offpos == string::npos) {
      const Translate *tr = getTrans();
      const VarnodeData &point(tr->getRegister(attrVal));
      vdat = point;
    }
    else {
      string::size_type szpos = attrVal.find(':',offpos+1);
      if (szpos==string::npos)
	throw LowlevelError("join address piece attribute is malformed");
      string spcname = attrVal.substr(0,offpos);
      vdat.space = getManager()->getSpaceByName(spcname);
      istringstream s1(attrVal.substr(offpos+1,szpos));
      s1.unsetf(ios::dec | ios::hex | ios::oct);
      s1 >> vdat.offset;
      istringstream s2(attrVal.substr(szpos+1));
      s2.unsetf(ios::dec | ios::hex | ios::oct);
      s2 >> vdat.size;
    }
    sizesum += vdat.size;
  }
  JoinRecord *rec = getManager()->findAddJoin(pieces,logicalsize);
  size = rec->getUnified().size;
  return rec->getUnified().offset;
}

void JoinSpace::printRaw(ostream &s,uintb offset) const

{
  JoinRecord *rec = getManager()->findJoin(offset);
  int4 szsum = 0;
  int4 num = rec->numPieces();
  s << '{';
  for(int4 i=0;i<num;++i) {
    const VarnodeData &vdat( rec->getPiece(i) );
    szsum += vdat.size;
    if (i!=0)
      s << ',';
    vdat.space->printRaw(s,vdat.offset);
  }
  if (num == 1) {
    szsum = rec->getUnified().size;
    s << ':' << szsum;
  }
  s << '}';
}

uintb JoinSpace::read(const string &s,int4 &size) const

{
  vector<VarnodeData> pieces;
  int4 szsum = 0;
  int4 i=0;
  while(i < s.size()) {
    pieces.emplace_back();	// Prepare to read next VarnodeData
    string token;
    while((i<s.size())&&(s[i]!=',')) {
      token += s[i];
      i += 1;
    }
    i += 1;			// Skip the comma
    try {
      pieces.back() = getTrans()->getRegister(token);
    }
    catch(LowlevelError &err) {	// Name doesn't exist
      char tryShortcut = token[0];
      AddrSpace *spc = getManager()->getSpaceByShortcut(tryShortcut);
      if (spc == (AddrSpace *)0)
	throw LowlevelError("Could not parse join string");

      int4 subsize;
      pieces.back().space = spc;
      pieces.back().offset = spc->read(token.substr(1),subsize);
      pieces.back().size = subsize;
    }
    szsum += pieces.back().size;
  }
  JoinRecord *rec = getManager()->findAddJoin(pieces,0);
  size = szsum;
  return rec->getUnified().offset;
}

void JoinSpace::saveXml(ostream &s) const

{
  throw LowlevelError("Should never save join space to XML");
}

void JoinSpace::restoreXml(const Element *el)

{
  throw LowlevelError("Should never restore join space from XML");
}

/// \param m is the address space manager
/// \param t is the processor translator
OverlaySpace::OverlaySpace(AddrSpaceManager *m,const Translate *t)
  : AddrSpace(m,t,IPTR_PROCESSOR)
{
  baseSpace = (AddrSpace *)0;
  setFlags(overlay);
}

/// \return the base address space
AddrSpace *OverlaySpace::getBaseSpace(void) const

{
  return baseSpace;
}

void OverlaySpace::saveXml(ostream &s) const

{
  s << "<space_overlay";
  a_v(s,"name",name);
  a_v_i(s,"index",index);
  a_v(s,"base",baseSpace->getName());
  s << "/>\n";
}

void OverlaySpace::restoreXml(const Element *el)

{
  name = el->getAttributeValue("name");
  istringstream s1(el->getAttributeValue("index"));
  s1.unsetf(ios::dec | ios::hex | ios::oct);
  s1 >> index;
  
  string basename = el->getAttributeValue("base");
  baseSpace = getManager()->getSpaceByName(basename);
  if (baseSpace == (AddrSpace *)0)
    throw LowlevelError("Base space does not exist for overlay space: "+name);
  addressSize = baseSpace->getAddrSize();
  wordsize = baseSpace->getWordSize();
  delay = baseSpace->getDelay();
  deadcodedelay = baseSpace->getDeadcodeDelay();
  calcScaleMask();

  if (baseSpace->isBigEndian())
    setFlags(big_endian);
  if (baseSpace->hasPhysical())
    setFlags(hasphysical);
}

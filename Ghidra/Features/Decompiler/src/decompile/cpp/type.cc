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
#include "type.hh"
#include "funcdata.hh"

// Some default routines for displaying data

/// Display an array of bytes as a hex dump at a given address.
/// Each line displays an address and 16 bytes in hexadecimal
/// \param s is the stream to write to
/// \param buffer is a pointer to the bytes
/// \param size is the number of bytes
/// \param baseaddr is the address of the first byte in the buffer
void print_data(ostream &s,uint1 *buffer,int4 size,const Address &baseaddr)

{
  int4 i;
  uintb start,addr,endaddr;

  if (buffer == (uint1 *)0) {
    s << "Address not present in binary image\n";
    return;
  }

  addr = baseaddr.getOffset();
  endaddr = addr + size;
  start = addr & ~((uintb)0xf);

  while(start < endaddr) {
    s << setfill('0') << setw(8) << hex << start << ": ";
    for(i=0;i<16;++i) {
      if ((start+i < addr)||(start+i>=endaddr))
	s << "   ";
      else
	s << setfill('0') << setw(2) << hex << (uint4) buffer[start+i-addr] << ' ';

    }
    s << "  ";
    for(i=0;i<16;++i)
      if ((start+i < addr)||(start+i>=endaddr))
	s << ' ';
      else {
	if (isprint( buffer[start+i-addr] ))
	  s << buffer[start+i-addr];
	else
	  s << '.';
      }
    s << endl;
    start += 16;
  }
}

/// If \b this and the other given data-type are both variable length and come from the
/// the same base data-type, return \b true.
/// \param ct is the other given data-type to compare with \b this
/// \return \b true if they are the same variable length data-type.
bool Datatype::hasSameVariableBase(const Datatype *ct) const

{
  if (!isVariableLength()) return false;
  if (!ct->isVariableLength()) return false;
  uint8 thisId = hashSize(id, size);
  uint8 themId = hashSize(ct->id, ct->size);
  return (thisId == themId);
}

/// Print a raw description of the type to stream. Intended for debugging.
/// Not intended to produce parsable C.
/// \param s is the output stream
void Datatype::printRaw(ostream &s) const

{
  if (name.size()>0)
    s << name;
  else
    s << "unkbyte" << dec << size;
}

/// Given an offset into \b this data-type, return the component data-type at that offset.
/// Also, pass back a "renormalized" offset suitable for recursize getSubType() calls:
/// i.e. if the original offset hits the exact start of the sub-type, 0 is passed back.
/// If there is no valid component data-type at the offset,
/// return NULL and pass back the original offset
/// \param off is the offset into \b this data-type
/// \param newoff is a pointer to the passed-back offset
/// \return a pointer to the component data-type or NULL
Datatype *Datatype::getSubType(uintb off,uintb *newoff) const

{				// There is no subtype
  *newoff = off;
  return (Datatype *)0;
}

/// Find the first component data-type after the given offset that is (or contains)
/// an array, and pass back the difference between the component's start and the given offset.
/// Return the component data-type or null if no array is found.
/// \param off is the given offset into \b this data-type
/// \param newoff is used to pass back the offset difference
/// \param elSize is used to pass back the array element size
/// \return the component data-type or null
Datatype *Datatype::nearestArrayedComponentForward(uintb off,uintb *newoff,int4 *elSize) const

{
  return (TypeArray *)0;
}

/// Find the first component data-type before the given offset that is (or contains)
/// an array, and pass back the difference between the component's start and the given offset.
/// Return the component data-type or null if no array is found.
/// \param off is the given offset into \b this data-type
/// \param newoff is used to pass back the offset difference
/// \param elSize is used to pass back the array element size
/// \return the component data-type or null
Datatype *Datatype::nearestArrayedComponentBackward(uintb off,uintb *newoff,int4 *elSize) const

{
  return (TypeArray *)0;
}

// Compare \b this with another data-type.
/// 0 (equality) means the data-types are functionally equivalent (even if names differ)
/// Smaller types come earlier. More specific types come earlier.
/// \param op is the data-type to compare with \b this
/// \param level is maximum level to descend when recursively comparing
/// \return negative, 0, positive depending on ordering of types
int4 Datatype::compare(const Datatype &op,int4 level) const

{
  return compareDependency(op);
}

/// Ordering of data-types for the main TypeFactory container.
/// Comparison only goes down one-level in the component structure,
/// before just comparing pointers.
/// \param op is the data-type to compare with \b this
/// \return negative, 0, positive depending on ordering of types
int4 Datatype::compareDependency(const Datatype &op) const

{
  if (size != op.size) return (op.size-size);
  if (metatype != op.metatype) return (metatype < op.metatype) ? -1 : 1;
  uint4 fl = flags & (~coretype);
  uint4 opfl = op.flags & (~coretype);
  // We need to be careful here, we compare flags so that enum types are more specific than base int or uint,
  // we also want UTF16 and UTF32 to be more specific than int, BUT
  // we don't want char to be more specific than int1 because char is the default size 1 integer type.
  fl ^= chartype;
  opfl ^= chartype;
  if (fl != opfl) return (opfl < fl) ? -1 : 1;
  return 0;
}

/// Convert a type \b meta-type into the string name of the meta-type
/// \param metatype is the encoded type meta-type
/// \param res will hold the resulting string
void metatype2string(type_metatype metatype,string &res)

{
  switch(metatype) {
  case TYPE_VOID:
    res = "void";
    break;
  case TYPE_PTR:
    res = "ptr";
    break;
  case TYPE_ARRAY:
    res = "array";
    break;
  case TYPE_STRUCT:
    res = "struct";
    break;
  case TYPE_SPACEBASE:
    res = "spacebase";
    break;
  case TYPE_UNKNOWN:
    res = "unknown";
    break;
  case TYPE_UINT:
    res = "uint";
    break;
  case TYPE_INT:
    res = "int";
    break;
  case TYPE_BOOL:
    res = "bool";
    break;
  case TYPE_CODE:
    res = "code";
    break;
  case TYPE_FLOAT:
    res = "float";
    break;
  default:
    throw LowlevelError("Unknown metatype");
  }
}

/// Given a string description of a type \b meta-type. Return the meta-type.
/// \param metastring is the description of the meta-type
/// \return the encoded type meta-type
type_metatype string2metatype(const string &metastring)

{
  switch(metastring[0]) {
  case 'p':
    if (metastring=="ptr")
      return TYPE_PTR;
    break;
  case 'a':
    if (metastring=="array")
      return TYPE_ARRAY;
    break;
  case 's':
    if (metastring=="struct")
      return TYPE_STRUCT;
    if (metastring=="spacebase")
      return TYPE_SPACEBASE;
    break;
  case 'u':
    if (metastring=="unknown")
      return TYPE_UNKNOWN;
    else if (metastring=="uint")
      return TYPE_UINT;
    break;
  case 'i':
    if (metastring == "int")
      return TYPE_INT;
    break;
  case 'f':
    if (metastring == "float")
      return TYPE_FLOAT;
    break;
  case 'b':
    if (metastring == "bool")
      return TYPE_BOOL;
    break;
  case 'c':
    if (metastring == "code")
      return TYPE_CODE;
    break;
  case 'v':
    if (metastring == "void")
      return TYPE_VOID;
    break;
  default:
    break;
  }
  throw LowlevelError("Unknown metatype: "+metastring);
}

/// Write out a formal description of the data-type as an XML \<type> tag.
/// For composite data-types, the description goes down one level, describing
/// the component types only by reference.
/// \param s is the stream to write to
void Datatype::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  s << "/>";
}

/// Write out basic data-type properties (name,size,id) as XML attributes.
/// This routine presumes the initial tag is already written to the stream.
/// \param s is the stream to write to
void Datatype::saveXmlBasic(ostream &s) const

{
  a_v(s,"name",name);
  uint8 saveId;
  if (isVariableLength())
    saveId = hashSize(id, size);
  else
    saveId = id;
  if (saveId != 0) {
    s << " id=\"0x" << hex << saveId << '\"';
  }
  a_v_i(s,"size",size);
  string metastring;
  metatype2string(metatype,metastring);
  a_v(s,"metatype",metastring);
  if ((flags & coretype)!=0)
    a_v_b(s,"core",true);
  if (isVariableLength())
    a_v_b(s,"varlength",true);
  if ((flags & opaque_string)!=0)
    a_v_b(s,"opaquestring",true);
}

/// Write a simple reference to \b this data-type as an XML \<typeref> tag,
/// which only encodes the name and id.
/// \param s is the stream to write to
void Datatype::saveXmlRef(ostream &s) const

{				// Save just a name reference if possible
  if ((id!=0)&&(metatype != TYPE_VOID)) {
    s << "<typeref";
    a_v(s,"name",name);
    if (isVariableLength()) {			// For a type with a "variable length" base
      uintb origId = hashSize(id, size);	// Emit the size independent version of the id
      s << " id=\"0x" << hex << origId << '\"';
      s << " size=\"" << dec << size << '\"';	// but also emit size of this instance
    }
    else {
      s << " id=\"0x" << hex << id << '\"';
    }
    s << "/>";
  }
  else
    saveXml(s);
}

/// A CPUI_PTRSUB must act on a pointer data-type where the given offset addresses a component.
/// Perform this check.
/// \param offset is the given offset
/// \return \b true if \b this is a suitable PTRSUB data-type
bool Datatype::isPtrsubMatching(uintb offset) const

{
  if (metatype != TYPE_PTR)
    return false;

  Datatype *basetype = ((TypePointer *)this)->getPtrTo();
  uint4 wordsize = ((TypePointer *)this)->getWordSize();
  if (basetype->metatype==TYPE_SPACEBASE) {
    uintb newoff = AddrSpace::addressToByte(offset,wordsize);
    basetype->getSubType(newoff,&newoff);
    if (newoff != 0)
      return false;
  }
  else {
    int4 size = offset;
    int4 typesize = basetype->getSize();
    if ((basetype->metatype != TYPE_ARRAY)&&(basetype->metatype != TYPE_STRUCT))
      return false;	// Not a pointer to a structured type
    else if ((typesize <= AddrSpace::addressToByteInt(size,wordsize))&&(typesize!=0))
      return false;
  }
  return true;
}

/// Restore the basic properties (name,size,id) of a data-type from an XML element
/// Properties are read from the attributes of the element
/// \param el is the XML element
void Datatype::restoreXmlBasic(const Element *el)

{
  name = el->getAttributeValue("name");
  istringstream i(el->getAttributeValue("size"));
  i.unsetf(ios::dec | ios::hex | ios::oct);
  size = -1;
  i >> size;
  if (size < 0)
    throw LowlevelError("Bad size for type "+name);
  metatype = string2metatype( el->getAttributeValue("metatype") );
  id = 0;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    const string &attribName( el->getAttributeName(i) );
    if (attribName == "core") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= coretype;
    }
    else if (attribName == "id") {
      istringstream i1(el->getAttributeValue(i));
      i1.unsetf(ios::dec | ios::hex | ios::oct);
      i1 >> id;
    }
    else if (attribName == "varlength") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= variable_length;
    }
    else if (attribName == "opaquestring") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= opaque_string;
    }
  }
  if ((id==0)&&(name.size()>0))	// If there is a type name
    id = hashName(name);	// There must be some kind of id
  if (isVariableLength()) {
    // Id needs to be unique compared to another data-type with the same name
    id = hashSize(id, size);
  }
}

/// Restore a Datatype object from an XML element
/// \param el is the XML element
/// \param typegrp is the underlying TypeFactory that will hold the new object
void Datatype::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
}

/// If a type id is explicitly provided for a data-type, this routine is used
/// to produce an id based on a hash of the name.  IDs produced this way will
/// have their sign-bit set to distinguish it from other IDs.
/// \param nm is the type name to be hashed
uint8 Datatype::hashName(const string &nm)

{
  uint8 res = 123;
  for(uint4 i=0;i<nm.size();++i) {
    res = (res<<8) | (res >> 56);
    res += (uint8)nm[i];
    if ((res&1)==0)
      res ^= 0xfeabfeab;	// Some kind of feedback
  }
  uint8 tmp=1;
  tmp <<= 63;
  res |= tmp;	// Make sure the hash is negative (to distinguish it from database id's)
  return res;
}

/// This allows IDs for variable length structures to be uniquefied based on size.
/// A base ID is given and a size of the specific instance. A unique ID is returned.
/// The hashing is reversible by feeding the output ID back into this function with the same size.
/// \param id is the given ID to (de)uniquify
/// \param size is the instance size of the structure
/// \return the (de)uniquified id
uint8 Datatype::hashSize(uint8 id,int4 size)

{
  uint8 sizeHash = size;
  sizeHash *= 0x98251033aecbabaf;	// Hash the size
  id ^= sizeHash;
  return id;
}

void TypeChar::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  a_v_b(s,"char",true);
  s << "/>";
}

/// Properties that specify which encoding this type uses are set based
/// on the size of the data-type. I.e. select UTF8, UTF16, or UTF32
void TypeUnicode::setflags(void)

{
  if (size==2)
    flags |= Datatype::utf16;	// 16-bit UTF16 encoding of unicode character
  else if (size==4)
    flags |= Datatype::utf32;	// 32-bit UTF32 encoding of unicode character
  else if (size==1)
    flags |= Datatype::chartype; // This ultimately should be UTF8 but we default to basic char
}

void TypeUnicode::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
  // Get endianness flag from architecture, rather than specific type encoding
  setflags();
}

TypeUnicode::TypeUnicode(const string &nm,int4 sz,type_metatype m)
  : TypeBase(sz,m,nm)
{
  setflags();			// Set special unicode UTF flags
}

void TypeUnicode::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  a_v_b(s,"utf",true);
  s << "/>";
}

void TypeVoid::saveXml(ostream &s) const

{
  s << "<void/>";
}

void TypePointer::printRaw(ostream &s) const

{
  ptrto->printRaw(s);
  s << " *";
}

int4 TypePointer::compare(const Datatype &op,int4 level) const

{
  TypePointer *tp;

  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;
  // Both must be pointers
  tp = (TypePointer *) &op;
  if (wordsize != tp->wordsize) return (wordsize < tp->wordsize) ? -1 : 1;
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  return ptrto->compare(*tp->ptrto,level); // Compare whats pointed to
}

int4 TypePointer::compareDependency(const Datatype &op) const

{
  TypePointer *tp;

  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;
  // Both must be pointers
  tp = (TypePointer *) &op;
  if (wordsize != tp->wordsize) return (wordsize < tp->wordsize) ? -1 : 1;
  if (ptrto == tp->ptrto) return 0;
  return (ptrto < tp->ptrto) ? -1 : 1; // Compare the absolute pointers
}

void TypePointer::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  if (wordsize != 1)
    a_v_i(s,"wordsize",wordsize);
  s << '>';
  ptrto->saveXmlRef(s);
  s << "</type>";
}

void TypePointer::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
  for(int4 i=0;i<el->getNumAttributes();++i)
    if (el->getAttributeName(i) == "wordsize") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> wordsize;
    }
  ptrto = typegrp.restoreXmlType( *el->getChildren().begin() );
  if (name.size() == 0)		// Inherit only coretype only if no name
    flags = ptrto->getInheritable();
}

void TypeArray::printRaw(ostream &s) const

{
  arrayof->printRaw(s);
  s << " [" << dec << arraysize << ']';
}

int4 TypeArray::compare(const Datatype &op,int4 level) const

{
  TypeArray *ta;

  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  ta = (TypeArray *) &op;	// Both must be arrays
  return arrayof->compare(*ta->arrayof,level); // Compare array elements
}

int4 TypeArray::compareDependency(const Datatype &op) const

{
  TypeArray *ta;

  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;
  ta = (TypeArray *) &op;	// Both must be arrays
  if (arrayof == ta->arrayof) return 0;
  return (arrayof < ta->arrayof) ? -1 : 1;
}

Datatype *TypeArray::getSubType(uintb off,uintb *newoff) const

{				// Go down exactly one level, to type of element
  *newoff = off % arrayof->getSize();
  return arrayof;
}

/// Given some contiguous piece of the array, figure out which element overlaps
/// the piece, and pass back the element index and the renormalized offset
/// \param off is the offset into the array
/// \param sz is the size of the piece (in bytes)
/// \param newoff is a pointer to the renormalized offset to pass back
/// \param el is a pointer to the array index to pass back
/// \return the element data-type or NULL if the piece overlaps more than one
Datatype *TypeArray::getSubEntry(int4 off,int4 sz,int4 *newoff,int4 *el) const

{
  int4 noff = off % arrayof->getSize();
  int4 nel = off / arrayof->getSize();
  if (noff+sz > arrayof->getSize()) // Requesting parts of more then one element
    return (Datatype *)0;
  *newoff = noff;
  *el = nel;
  return arrayof;
}

void TypeArray::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  a_v_i(s,"arraysize",arraysize);
  s << '>';
  arrayof->saveXmlRef(s);
  s << "</type>";
}

void TypeArray::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
  arraysize = -1;
  istringstream j(el->getAttributeValue("arraysize"));
  j.unsetf(ios::dec | ios::hex | ios::oct);
  j >> arraysize;
  arrayof  = typegrp.restoreXmlType(*el->getChildren().begin());
  if ((arraysize<=0)||(arraysize*arrayof->getSize()!=size))
    throw LowlevelError("Bad size for array of type "+arrayof->getName());
}

TypeEnum::TypeEnum(const TypeEnum &op) : TypeBase(op)

{
  namemap = op.namemap;
  masklist = op.masklist;
  flags |= (op.flags&poweroftwo)|enumtype;
}

/// Set the map. Calculate the independent bit-fields within the named values of the enumeration
/// Two bits are in the same bit-field if there is a name in the map whose value
/// has those two bits set.  Bit-fields must be a contiguous range of bits.
void TypeEnum::setNameMap(const map<uintb,string> &nmap)

{
  map<uintb,string>::const_iterator iter;
  uintb curmask,lastmask;
  int4 maxbit;
  int4 curmaxbit;
  bool fieldisempty;

  namemap = nmap;
  masklist.clear();

  flags &= ~((uint4)poweroftwo);

  maxbit = 8 * size - 1;

  curmaxbit = 0;
  while(curmaxbit <= maxbit) {
    curmask = 1;
    curmask <<= curmaxbit;
    lastmask = 0;
    fieldisempty = true;
    while(curmask != lastmask) {	// Repeat until there is no change in the current mask
      lastmask = curmask;		// Note changes from last time through

      for(iter=namemap.begin();iter!=namemap.end();++iter) { // For every named enumeration value
	uintb val = (*iter).first;
	if ((val & curmask) != 0) {	// If the value shares ANY bits in common with the current mask
	  curmask |= val;		// Absorb ALL defined bits of the value into the current mask
	  fieldisempty = false;
	}
      }

      // Fill in any holes in the mask (bit field must consist of contiguous bits
      int4 lsb = leastsigbit_set(curmask);
      int4 msb = mostsigbit_set(curmask);
      if (msb > curmaxbit)
	curmaxbit = msb;

      uintb mask1 = 1;
      mask1 = (mask1 << lsb) - 1;     // every bit below lsb is set to 1
      uintb mask2 = 1;
      mask2 <<= msb;
      mask2 <<= 1;
      mask2 -= 1;                  // every bit below or equal to msb is set to 1
      curmask = mask1 ^ mask2;
    }
    if (fieldisempty) {		// If no value hits this bit
      if (!masklist.empty())
	masklist.back() |= curmask; // Include the bit with the previous mask
      else
	masklist.push_back(curmask);
    }
    else
      masklist.push_back(curmask);
    curmaxbit += 1;
  }
  if (masklist.size() > 1)
    flags |= poweroftwo;
}

/// Given a specific value of the enumeration, calculate the named representation of that value.
/// The representation is returned as a list of names that must logically ORed and possibly complemented.
/// If no representation is possible, no names will be returned.
/// \param val is the value to find the representation for
/// \param valnames will hold the returned list of names
/// \return true if the representation needs to be complemented
bool TypeEnum::getMatches(uintb val,vector<string> &valnames) const

{
  map<uintb,string>::const_iterator iter;
  int4 count;

  for(count=0;count<2;++count) {
    bool allmatch = true;
    if (val == 0) {	// Zero handled specially, it crosses all masks
      iter = namemap.find(val);
      if (iter != namemap.end())
	valnames.push_back( (*iter).second );
      else
	allmatch = false;
    }
    else {
      for(int4 i=0;i<masklist.size();++i) {
	uintb maskedval = val & masklist[i];
	if (maskedval == 0)	// No component of -val- in this mask
	  continue;		// print nothing
	iter = namemap.find(maskedval);
	if (iter != namemap.end())
	  valnames.push_back( (*iter).second );	// Found name for this component
	else {					// If no name for this component
	  allmatch = false;			// Give up on representation
	  break;				// Stop searching for other components
	}
      }
    }
    if (allmatch)			// If we have a complete representation
      return (count==1);		// Return whether we represented original value or complement
    val = val ^ calc_mask(size);	// Switch value we are trying to represent (to complement)
    valnames.clear();			// Clear out old attempt
  }
  return false;	// If we reach here, no representation was possible, -valnames- is empty
}

int4 TypeEnum::compare(const Datatype &op,int4 level) const

{
  return compareDependency(op);
}

int4 TypeEnum::compareDependency(const Datatype &op) const

{
  int4 res = TypeBase::compareDependency(op); // Compare as basic types first
  if (res != 0) return res;

  const TypeEnum *te = (const TypeEnum *) &op;
  map<uintb,string>::const_iterator iter1,iter2;

  if (namemap.size() != te->namemap.size()) {
    return (namemap.size() < te->namemap.size()) ? -1 : 1;
  }
  iter1 = namemap.begin();
  iter2 = te->namemap.begin();
  while(iter1 != namemap.end()) {
    if ((*iter1).first != (*iter2).first)
      return ((*iter1).first < (*iter2).first) ? -1:1;
    if ((*iter1).second != (*iter2).second)
      return ((*iter1).second < (*iter2).second) ? -1:1;
    ++iter1;
    ++iter2;
  }
  return 0;
}

void TypeEnum::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  a_v(s,"enum","true");
  s << ">\n";
  map<uintb,string>::const_iterator iter;
  for(iter=namemap.begin();iter!=namemap.end();++iter) {
    s << "<val";
    a_v(s,"name",(*iter).second);
    a_v_u(s,"value",(*iter).first);
    s << "/>\n";
  }
  s << "</type>";
}

void TypeEnum::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
  const List &list(el->getChildren());
  List::const_iterator iter;
  map<uintb,string> nmap;

  for(iter=list.begin();iter!=list.end();++iter) {
    uintb val;
    Element *subel = *iter;
    istringstream is(subel->getAttributeValue("value"));
    is.unsetf(ios::dec|ios::hex|ios::oct);
    intb valsign;		// Value might be negative
    is >> valsign;
    val = (uintb)valsign & calc_mask(size);
    nmap[val] = subel->getAttributeValue("name");
  }
  setNameMap(nmap);
}

TypeStruct::TypeStruct(const TypeStruct &op)
  : Datatype(op)
{
  setFields(op.field);
  size = op.size;		// setFields might have changed the size
}

/// Copy a list of fields into this structure, establishing its size.
/// Should only be called once when constructing the type
/// \param fd is the list of fields to copy in
void TypeStruct::setFields(const vector<TypeField> &fd)

{
  vector<TypeField>::const_iterator iter;
  int4 end;
				// Need to calculate size
  size = 0;
  for(iter=fd.begin();iter!=fd.end();++iter) {
    field.push_back(*iter);
    end = (*iter).offset + (*iter).type->getSize();
    if (end > size)
      size = end;
  }
}

/// Find the proper subfield given an offset. Return the index of that field
/// or -1 if the offset is not inside a field.
/// \param off is the offset into the structure
/// \return the index into the field list or -1
int4 TypeStruct::getFieldIter(int4 off) const

{
  int4 min = 0;
  int4 max = field.size()-1;

  while(min <= max) {
    int4 mid = (min + max)/2;
    const TypeField &curfield( field[mid] );
    if (curfield.offset > off)
      max = mid - 1;
    else {			// curfield.offset <= off
      if ((curfield.offset + curfield.type->getSize()) > off)
	return mid;
      min = mid + 1;
    }
  }
  return -1;
}

/// The field returned may or may not contain the offset.  If there are no fields
/// that occur earlier than the offset, return -1.
/// \param off is the given offset
/// \return the index of the nearest field or -1
int4 TypeStruct::getLowerBoundField(int4 off) const

{
  if (field.empty()) return -1;
  int4 min = 0;
  int4 max = field.size()-1;

  while(min < max) {
    int4 mid = (min + max + 1)/2;
    if (field[mid].offset > off)
      max = mid - 1;
    else {			// curfield.offset <= off
      min = mid;
    }
  }
  if (min == max && field[min].offset <= off)
    return min;
  return -1;
}

/// Given a byte range within \b this data-type, determine the field it is contained in
/// and pass back the renormalized offset.
/// \param off is the byte offset into \b this
/// \param sz is the size of the byte range
/// \param newoff points to the renormalized offset to pass back
/// \return the containing field or NULL if the range is not contained
const TypeField *TypeStruct::getField(int4 off,int4 sz,int4 *newoff) const

{
  int4 i;
  int4 noff;

  i = getFieldIter(off);
  if (i < 0) return (const TypeField *)0;
  const TypeField &curfield( field[i] );
  noff = off - curfield.offset;
  if (noff+sz > curfield.type->getSize()) // Requested piece spans more than one field
    return (const TypeField *)0;
  *newoff = noff;
  return &curfield;
}

Datatype *TypeStruct::getSubType(uintb off,uintb *newoff) const

{				// Go down one level to field that contains offset
  int4 i;

  i = getFieldIter(off);
  if (i < 0) return Datatype::getSubType(off,newoff);
  const TypeField &curfield( field[i] );
  *newoff = off - curfield.offset;
  return curfield.type;
}

Datatype *TypeStruct::nearestArrayedComponentBackward(uintb off,uintb *newoff,int4 *elSize) const

{
  int4 i = getLowerBoundField(off);
  while(i >= 0) {
    const TypeField &subfield( field[i] );
    int4 diff = (int4)off - subfield.offset;
    if (diff > 128) break;
    Datatype *subtype = subfield.type;
    if (subtype->getMetatype() == TYPE_ARRAY) {
      *newoff = (intb)diff;
      *elSize = ((TypeArray *)subtype)->getBase()->getSize();
      return subtype;
    }
    else {
      uintb suboff;
      Datatype *res = subtype->nearestArrayedComponentBackward(subtype->getSize(), &suboff, elSize);
      if (res != (Datatype *)0) {
	*newoff = (intb)diff;
	return subtype;
      }
    }
    i -= 1;
  }
  return (Datatype *)0;
}

Datatype *TypeStruct::nearestArrayedComponentForward(uintb off,uintb *newoff,int4 *elSize) const

{
  int4 i = getLowerBoundField(off);
  i += 1;
  while(i<field.size()) {
    const TypeField &subfield( field[i] );
    int4 diff = subfield.offset - off;
    if (diff > 128) break;
    Datatype *subtype = subfield.type;
    if (subtype->getMetatype() == TYPE_ARRAY) {
      *newoff = (intb)-diff;
      *elSize = ((TypeArray *)subtype)->getBase()->getSize();
      return subtype;
    }
    else {
      uintb suboff;
      Datatype *res = subtype->nearestArrayedComponentForward(0, &suboff, elSize);
      if (res != (Datatype *)0) {
	*newoff = (intb)-diff;
	return subtype;
      }
    }
    i += 1;
  }
  return (Datatype *)0;
}

int4 TypeStruct::compare(const Datatype &op,int4 level) const
{
  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;

  const TypeStruct *ts = (const TypeStruct *)&op;
  vector<TypeField>::const_iterator iter1,iter2;

  if (field.size() != ts->field.size()) return (ts->field.size()-field.size());
  iter1 = field.begin();
  iter2 = ts->field.begin();
  // Test only the name and first level metatype first
  while(iter1 != field.end()) {
    if ((*iter1).offset != (*iter2).offset)
      return ((*iter1).offset < (*iter2).offset) ? -1:1;
    if ((*iter1).name != (*iter2).name)
      return ((*iter1).name < (*iter2).name) ? -1:1;
    if ((*iter1).type->getMetatype() != (*iter2).type->getMetatype())
      return ((*iter1).type->getMetatype() < (*iter2).type->getMetatype()) ? -1 : 1;
    ++iter1;
    ++iter2;
  }
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  // If we are still equal, now go down deep into each field type
  iter1 = field.begin();
  iter2 = ts->field.begin();
  while(iter1 != field.end()) {
    if ((*iter1).type != (*iter2).type) { // Short circuit recursive loops
      int4 c = (*iter1).type->compare( *(*iter2).type, level );
      if (c != 0) return c;
    }
    ++iter1;
    ++iter2;
  }
  return 0;
}

int4 TypeStruct::compareDependency(const Datatype &op) const

{
  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;

  const TypeStruct *ts = (const TypeStruct *)&op;
  vector<TypeField>::const_iterator iter1,iter2;

  if (field.size() != ts->field.size()) return (ts->field.size()-field.size());
  iter1 = field.begin();
  iter2 = ts->field.begin();
  // Test only the name and first level metatype first
  while(iter1 != field.end()) {
    if ((*iter1).offset != (*iter2).offset)
      return ((*iter1).offset < (*iter2).offset) ? -1:1;
    if ((*iter1).name != (*iter2).name)
      return ((*iter1).name < (*iter2).name) ? -1:1;
    Datatype *fld1 = (*iter1).type;
    Datatype *fld2 = (*iter2).type;
    if (fld1 != fld2)
      return (fld1 < fld2) ? -1 : 1; // compare the pointers directly
    ++iter1;
    ++iter2;
  }
  return 0;
}

void TypeStruct::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  s << ">\n";
  vector<TypeField>::const_iterator iter;
  for(iter=field.begin();iter!=field.end();++iter) {
    s << "<field";
    a_v(s,"name",(*iter).name);
    a_v_i(s,"offset",(*iter).offset);
    s << '>';
    (*iter).type->saveXmlRef(s);
    s << "</field>\n";
  }
  s << "</type>";
}

void TypeStruct::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
  const List &list(el->getChildren());
  List::const_iterator iter;
  int4 maxoffset = 0;
  for(iter=list.begin();iter!=list.end();++iter) {
    field.push_back( TypeField() );
    field.back().name = (*iter)->getAttributeValue("name");
    istringstream j((*iter)->getAttributeValue("offset"));
    j.unsetf(ios::dec | ios::hex | ios::oct);
    j >> field.back().offset;
    field.back().type = typegrp.restoreXmlType( *(*iter)->getChildren().begin() );
    int4 trialmax = field.back().offset + field.back().type->getSize();
    if (trialmax > maxoffset)
      maxoffset = trialmax;
    if (field.back().name.size()==0) {
      ostringstream s;
      s << "unlabelled" << dec << field.back().offset;
      field.back().name = s.str();
    }
  }
  if (maxoffset > size)
    throw LowlevelError("Size too small for fields of structure "+name);
}

/// Turn on the data-type's function prototype
/// \param tfact is the factory that owns \b this
/// \param model is the prototype model
/// \param outtype is the return type of the prototype
/// \param intypes is the list of input parameters
/// \param dotdotdot is true if the prototype takes variable arguments
/// \param voidtype is the reference "void" data-type
void TypeCode::set(TypeFactory *tfact,ProtoModel *model,
		    Datatype *outtype,const vector<Datatype *> &intypes,
		    bool dotdotdot,Datatype *voidtype)
{
  factory = tfact;
  flags |= variable_length;
  if (proto != (FuncProto *)0)
    delete proto;
  proto = new FuncProto();
  proto->setInternal(model,voidtype);
  vector<Datatype *> typelist;
  vector<string> blanknames(intypes.size()+1);
  if (outtype == (Datatype *)0)
    typelist.push_back(voidtype);
  else
    typelist.push_back(outtype);
  for(int4 i=0;i<intypes.size();++i)
    typelist.push_back(intypes[i]);

  proto->updateAllTypes(blanknames,typelist,dotdotdot);
  proto->setInputLock(true);
  proto->setOutputLock(true);
}

TypeCode::TypeCode(const TypeCode &op) : Datatype(op)

{
  proto = (FuncProto *)0;
  factory = op.factory;
  if (op.proto != (FuncProto *)0) {
    proto = new FuncProto();
    proto->copy(*op.proto);
  }
}

TypeCode::TypeCode(const string &nm) : Datatype(1,TYPE_CODE,nm)

{
  proto = (FuncProto *)0;
  factory = (TypeFactory *)0;
}

TypeCode::~TypeCode(void)

{
  if (proto != (FuncProto *)0)
    delete proto;
}

void TypeCode::printRaw(ostream &s) const

{
  if (name.size()>0)
    s << name;
  else
    s << "funcptr";
  s << "()";
}

/// Assuming \b this has an underlying function prototype, set some of its boolean properties
/// \param isConstructor toggles whether the function is a constructor
/// \param isDestructor toggles whether the function is a destructor
void TypeCode::setProperties(bool isConstructor,bool isDestructor)

{
  proto->setConstructor(isConstructor);
  proto->setDestructor(isDestructor);
}


/// Compare basic characteristics of \b this with another TypeCode, not including the prototype
///    -  -1 or 1 if -this- and -op- are different in surface characteristics
///    -   0 if they are exactly equal and have no parameters
///    -   2 if they are equal on the surface, but additional comparisons must be made on parameters
/// \param op is the other data-type to compare to
/// \return the comparison value
int4 TypeCode::compareBasic(const TypeCode *op) const

{
  if (size != op->getSize()) return (op->getSize() < size) ? -1 : 1;
  if (metatype != op->getMetatype()) return (metatype < op->getMetatype()) ? -1 : 1;

  if (proto == (FuncProto *)0) {
    if (op->proto == (FuncProto *)0) return 0;
    return 1;
  }
  if (op->proto == (FuncProto *)0)
    return -1;

  if (!proto->hasModel()) {
    if (op->proto->hasModel()) return 1;
  }
  else {
    if (!op->proto->hasModel()) return -1;
    const string &model1(proto->getModelName());
    const string &model2(op->proto->getModelName());
    if (model1 != model2)
      return (model1 < model2) ? -1 : 1;
  }
  int4 nump = proto->numParams();
  int4 opnump = op->proto->numParams();
  if (nump != opnump)
    return (opnump < nump) ? -1 : 1;
  uint4 flags = proto->getComparableFlags();
  uint4 opflags = op->proto->getComparableFlags();
  if (flags != opflags)
    return (flags < opflags) ? -1 : 1;

  return 2;			// Carry on with comparison of parameters
}

Datatype *TypeCode::getSubType(uintb off,uintb *newoff) const

{
  if (factory == (TypeFactory *)0) return (Datatype *)0;
  *newoff = 0;
  return factory->getBase(1, TYPE_CODE);	// Return code byte unattached to function prototype
}

int4 TypeCode::compare(const Datatype &op,int4 level) const

{
  const TypeCode *tc = (const TypeCode *)&op;
  int4 res = compareBasic(tc);
  if (res != 2) return res;

  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  int4 nump = proto->numParams();
  for(int4 i=0;i<nump;++i) {
    Datatype *param = proto->getParam(i)->getType();
    Datatype *opparam = tc->proto->getParam(i)->getType();
    int4 c = param->compare(*opparam,level);
    if (c != 0)
      return c;
  }
  Datatype *otype = proto->getOutputType();
  Datatype *opotype = tc->proto->getOutputType();
  if (otype == (Datatype *)0) {
    if (opotype == (Datatype *)0) return 0;
    return 1;
  }
  if (opotype == (Datatype *)0) return -1;
  return otype->compare(*opotype,level);
}

int4 TypeCode::compareDependency(const Datatype &op) const

{
  const TypeCode *tc = (const TypeCode *)&op;
  int4 res = compareBasic(tc);
  if (res != 2) return res;

  int4 nump = proto->numParams();
  for(int4 i=0;i<nump;++i) {
    Datatype *param = proto->getParam(i)->getType();
    Datatype *opparam = tc->proto->getParam(i)->getType();
    if (param != opparam)
      return (param < opparam) ? -1 : 1; // Compare pointers directly
  }
  Datatype *otype = proto->getOutputType();
  Datatype *opotype = tc->proto->getOutputType();
  if (otype == (Datatype *)0) {
    if (opotype == (Datatype *)0) return 0;
    return 1;
  }
  if (opotype == (Datatype *)0) return -1;
  if (otype != opotype)
    return (otype < opotype) ? -1 : 1;
  return 0;
}

void TypeCode::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  s << ">\n";
  if (proto != (FuncProto *)0)
    proto->saveXml(s);
  s << "</type>";
}

void TypeCode::restoreXml(const Element *el,TypeFactory &typegrp)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  if (iter != list.end()) {
    // Traditionally a <prototype> tag implies variable length, without a "varlength" attribute
    flags |= variable_length;
  }
  restoreXmlBasic(el);
  if (proto != (FuncProto *)0) {
    delete proto;
    proto = (FuncProto *)0;
  }
  if (iter == list.end()) return; // No underlying prototype
  Architecture *glb = typegrp.getArch();
  factory = &typegrp;
  proto = new FuncProto();
  proto->setInternal( glb->defaultfp, typegrp.getTypeVoid() );
  proto->restoreXml(*iter,glb);
}

/// This data-type can index either a local or the global scope
/// \return the symbol table Scope
Scope *TypeSpacebase::getMap(void) const

{
  Scope *res = glb->symboltab->getGlobalScope();
  if (!localframe.isInvalid()) { // If this spacebase is for a localframe
    Funcdata *fd = res->queryFunction(localframe);
    if (fd != (Funcdata *)0)
      res = fd->getScopeLocal();
  }
  return res;
}

Datatype *TypeSpacebase::getSubType(uintb off,uintb *newoff) const

{
  Scope *scope = getMap();
  off = AddrSpace::byteToAddress(off, spaceid->getWordSize());	// Convert from byte offset to address unit
  // It should always be the case that the given offset represents a full encoding of the
  // pointer, so the point of context is unused and the size is given as -1
  Address nullPoint;
  uintb fullEncoding;
  Address addr = glb->resolveConstant(spaceid, off, -1, nullPoint, fullEncoding);
  SymbolEntry *smallest;

  // Assume symbol being referenced is address tied so we use a null point of context
  // FIXME: A valid point of context may be necessary in the future
  smallest = scope->queryContainer(addr,1,nullPoint);

  if (smallest == (SymbolEntry *)0) {
    *newoff = 0;
    return glb->types->getBase(1,TYPE_UNKNOWN);
  }
  *newoff = (addr.getOffset() - smallest->getAddr().getOffset()) + smallest->getOffset();
  return smallest->getSymbol()->getType();
}

Datatype *TypeSpacebase::nearestArrayedComponentForward(uintb off,uintb *newoff,int4 *elSize) const

{
  Scope *scope = getMap();
  off = AddrSpace::byteToAddress(off, spaceid->getWordSize());	// Convert from byte offset to address unit
  // It should always be the case that the given offset represents a full encoding of the
  // pointer, so the point of context is unused and the size is given as -1
  Address nullPoint;
  uintb fullEncoding;
  Address addr = glb->resolveConstant(spaceid, off, -1, nullPoint, fullEncoding);
  SymbolEntry *smallest = scope->queryContainer(addr,1,nullPoint);
  Address nextAddr;
  Datatype *symbolType;
  if (smallest == (SymbolEntry *)0 || smallest->getOffset() != 0)
    nextAddr = addr + 32;
  else {
    symbolType = smallest->getSymbol()->getType();
    if (symbolType->getMetatype() == TYPE_STRUCT) {
      uintb structOff = addr.getOffset() - smallest->getAddr().getOffset();
      uintb dummyOff;
      Datatype *res = symbolType->nearestArrayedComponentForward(structOff, &dummyOff, elSize);
      if (res != (Datatype *)0) {
	*newoff = structOff;
	return symbolType;
      }
    }
    int4 size = AddrSpace::byteToAddressInt(smallest->getSize(), spaceid->getWordSize());
    nextAddr = smallest->getAddr() + size;
  }
  if (nextAddr < addr)
    return (Datatype *)0;		// Don't let the address wrap
  smallest = scope->queryContainer(nextAddr,1,nullPoint);
  if (smallest == (SymbolEntry *)0 || smallest->getOffset() != 0)
    return (Datatype *)0;
  symbolType = smallest->getSymbol()->getType();
  *newoff = addr.getOffset() - smallest->getAddr().getOffset();
  if (symbolType->getMetatype() == TYPE_ARRAY) {
    *elSize = ((TypeArray *)symbolType)->getBase()->getSize();
    return symbolType;
  }
  if (symbolType->getMetatype() == TYPE_STRUCT) {
    uintb dummyOff;
    Datatype *res = symbolType->nearestArrayedComponentForward(0, &dummyOff, elSize);
    if (res != (Datatype *)0)
      return symbolType;
  }
  return (Datatype *)0;
}

Datatype *TypeSpacebase::nearestArrayedComponentBackward(uintb off,uintb *newoff,int4 *elSize) const

{
  Datatype *subType = getSubType(off, newoff);
  if (subType == (Datatype *)0)
    return (Datatype *)0;
  if (subType->getMetatype() == TYPE_ARRAY) {
    *elSize = ((TypeArray *)subType)->getBase()->getSize();
    return subType;
  }
  if (subType->getMetatype() == TYPE_STRUCT) {
    uintb dummyOff;
    Datatype *res = subType->nearestArrayedComponentBackward(*newoff,&dummyOff,elSize);
    if (res != (Datatype *)0)
      return subType;
  }
  return (Datatype *)0;
}

int4 TypeSpacebase::compare(const Datatype &op,int4 level) const

{
  return compareDependency(op);
}

int4 TypeSpacebase::compareDependency(const Datatype &op) const

{
  if (size != op.getSize()) return (op.getSize()-size);
  if (metatype != op.getMetatype()) return (metatype < op.getMetatype()) ? -1 : 1;
  TypeSpacebase *tsb = (TypeSpacebase *) &op;
  if (spaceid != tsb->spaceid) return (spaceid < tsb->spaceid) ? -1:1;
  if (localframe.isInvalid()) return 0; // Global space base
  if (localframe != tsb->localframe) return (localframe < tsb->localframe) ? -1:1;
  return 0;
}

/// Return the Address being referred to by a specific offset relative
/// to a pointer with \b this Datatype
/// \param off is the offset relative to the pointer
/// \param sz is the size of offset (as a pointer)
/// \param point is a "context" reference for the request
/// \return the referred to Address
Address TypeSpacebase::getAddress(uintb off,int4 sz,const Address &point) const

{
  uintb fullEncoding;
  // Currently a constant off of a global spacebase must be a full pointer encoding
  if (localframe.isInvalid())
    sz = -1;	// Set size to -1 to guarantee that full encoding recovery isn't launched
  return glb->resolveConstant(spaceid,off,sz,point,fullEncoding);
}

void TypeSpacebase::saveXml(ostream &s) const

{
  s << "<type";
  saveXmlBasic(s);
  a_v(s,"space",spaceid->getName());
  s << '>';
  localframe.saveXml(s);
  s << "</type>";
}

void TypeSpacebase::restoreXml(const Element *el,TypeFactory &typegrp)

{
  restoreXmlBasic(el);
  spaceid = glb->getSpaceByName(el->getAttributeValue("space"));
  const List &list(el->getChildren());
  localframe = Address::restoreXml(list.front(),typegrp.getArch());
}


/// Initialize an empty container
/// \param g is the owning Architecture
TypeFactory::TypeFactory(Architecture *g)

{
  glb = g;
  sizeOfInt = 0;
  align = 0;
  enumsize = 0;

  clearCache();
}

/// Clear the matrix of commonly used atomic types
void TypeFactory::clearCache(void)

{
  int4 i,j;
  for(i=0;i<9;++i)
    for(j=0;j<8;++j)
      typecache[i][j] = (Datatype *)0;
  typecache10 = (Datatype *)0;
  typecache16 = (Datatype *)0;
  type_nochar = (Datatype *)0;
}

/// Set up default values for size of "int", structure alignment, and enums
void TypeFactory::setupSizes(void)

{
  if (sizeOfInt == 0) {
    sizeOfInt = 1;			// Default if we can't find a better value
    AddrSpace *spc = glb->getStackSpace();
    if (spc != (AddrSpace *)0) {
      const VarnodeData &spdata(spc->getSpacebase(0));		// Use stack pointer as likely indicator of "int" size
      sizeOfInt = spdata.size;
      if (sizeOfInt > 4)					// "int" is rarely bigger than 4 bytes
	sizeOfInt = 4;
    }
  }
  if (align == 0)
    align = glb->getDefaultSize();
  if (enumsize == 0) {
    enumsize = align;
    enumtype = TYPE_UINT;
  }
}

/// Manually create a "base" core type. This currently must be called before
/// any pointers or arrays are defined off of the type.
/// \param name is the data-type name
/// \param size is the size of the data-type
/// \param meta is the meta-type of the data-type
/// \param chartp is true if a character type should be created
void TypeFactory::setCoreType(const string &name,int4 size,
			      type_metatype meta,bool chartp)
{
  Datatype *ct;
  if (chartp) {
    if (size == 1)
      ct = getTypeChar(name);
    else
      ct = getTypeUnicode(name,size,meta);
  }
  else if (meta == TYPE_CODE)
    ct = getTypeCode(name);
  else if (meta == TYPE_VOID)
    ct = getTypeVoid();
  else
    ct = getBase(size,meta,name);
  ct->flags |= Datatype::coretype;
}

/// Run through the list of "core" data-types and cache the most commonly
/// accessed ones for quick access (avoiding the tree lookup).
/// The "core" data-types must have been previously initialized.
void TypeFactory::cacheCoreTypes(void)

{
  DatatypeSet::iterator iter;

  for(iter=tree.begin();iter!=tree.end();++iter) {
    Datatype *ct = *iter;
    Datatype *testct;
    if (!ct->isCoreType()) continue;
    if (ct->getSize() > 8) {
      if (ct->getMetatype() == TYPE_FLOAT) {
	if (ct->getSize() == 10)
	  typecache10 = ct;
	else if (ct->getSize() == 16)
	  typecache16 = ct;
      }
      continue;
    }
    switch(ct->getMetatype()) {
    case TYPE_INT:
      if ((ct->getSize()==1)&&(!ct->isASCII()))
	type_nochar = ct;
      // fallthru
    case TYPE_UINT:
      if (ct->isEnumType()) break; // Conceivably an enumeration
      if (ct->isASCII()) { 	// Char is preferred over other int types
	typecache[ct->getSize()][ct->getMetatype()-TYPE_FLOAT] = ct;
	break;
      }
      if (ct->isCharPrint()) break; // Other character types (UTF16,UTF32) are not preferred
      // fallthru
    case TYPE_VOID:
    case TYPE_UNKNOWN:
    case TYPE_BOOL:
    case TYPE_CODE:
    case TYPE_FLOAT:
      testct = typecache[ct->getSize()][ct->getMetatype()-TYPE_FLOAT];
      if (testct == (Datatype *)0)
	typecache[ct->getSize()][ct->getMetatype()-TYPE_FLOAT] = ct;
      break;
    default:
      break;
    }
  }
}

/// Remove all Datatype objects owned by this TypeFactory
void TypeFactory::clear(void)

{
  DatatypeSet::iterator iter;

  for(iter=tree.begin();iter!=tree.end();++iter)
    delete *iter;
  tree.clear();
  nametree.clear();
  clearCache();
}

/// Delete anything that isn't a core type
void TypeFactory::clearNoncore(void)

{
  DatatypeSet::iterator iter;
  Datatype *ct;

  iter = tree.begin();
  while(iter != tree.end()) {
    ct = *iter;
    if (ct->isCoreType()) {
      ++iter;
      continue;
    }
    nametree.erase(ct);
    tree.erase(iter++);
    delete ct;
  }
}

TypeFactory::~TypeFactory(void)

{
  clear();
}

/// Looking just within this container, find a Datatype by \b name and/or \b id.
/// \param n is the name of the data-type
/// \param id is the type id of the data-type
/// \return the matching Datatype object
Datatype *TypeFactory::findByIdLocal(const string &n,uint8 id) const

{				// Get type of given name
  DatatypeNameSet::const_iterator iter;

  TypeBase ct(1,TYPE_UNKNOWN,n);
  if (id != 0) {		// Search for an exact type
    ct.id = id;
    iter = nametree.find((Datatype *)&ct);
    if (iter == nametree.end()) return (Datatype *)0; // Didn't find it
  }
  else {			// Allow for the fact that the name may not be unique
    ct.id = 0;
    iter = nametree.lower_bound((Datatype *)&ct);
    if (iter == nametree.end()) return (Datatype *)0; // Didn't find it
    if ((*iter)->getName() != n) return (Datatype *)0; // Found at least one datatype with this name
  }
  return *iter;
}

/// The id is expected to resolve uniquely.  Internally, different length instances
/// of a variable length data-type are stored as separate Datatype objects. A non-zero
/// size can be given to distinguish these cases.
/// Derived classes may search outside this container.
/// \param n is the name of the data-type
/// \param id is the type id of the data-type
/// \param sz is the given distinguishign size if non-zero
/// \return the matching Datatype object
Datatype *TypeFactory::findById(const string &n,uint8 id,int4 sz)

{
  if (sz > 0) {				// If the id is for a "variable length" base data-type
    id = Datatype::hashSize(id, sz);	// Construct the id for the "sized" variant
  }
  return findByIdLocal(n,id);
}

/// Find type with given name. If there are more than, return first.
/// \param n is the name to search for
/// \return a Datatype object with the name or NULL
Datatype *TypeFactory::findByName(const string &n)

{
  return findById(n,0,0);
}

/// Find data-type without reference to name, using the functional comparators
/// For this to work, the type must be built out of dependencies that are already
/// present in \b this type factory
/// \param ct is the data-type to match
/// \return the matching Datatype or NULL
Datatype *TypeFactory::findNoName(Datatype &ct)

{
  DatatypeSet::const_iterator iter;
  Datatype *res = (Datatype *)0;
  iter = tree.find(&ct);
  if (iter != tree.end())
    res = *iter;
  return res;
}

/// Use quickest method (name or id is possible) to locate the matching data-type.
/// If its not currently in \b this container, clone the data-type and add it to the container.
/// \param ct is the data-type to match
/// \return the matching Datatype object in this container
Datatype *TypeFactory::findAdd(Datatype &ct)

{
  Datatype *newtype,*res;

  if (ct.name.size()!=0) {	// If there is a name
    if (ct.id == 0)		// There must be an id
      throw LowlevelError("Datatype must have a valid id");
    res = findByIdLocal(ct.name,ct.id); // Lookup type by it
    if (res != (Datatype *)0) { // If a type has this name
      if (0!=res->compareDependency( ct )) // Check if it is the same type
	throw LowlevelError("Trying to alter definition of type: "+ct.name);
      return res;
    }
  }
  else {
    res = findNoName(ct);
    if (res != (Datatype *)0) return res; // Found it
  }

  newtype = ct.clone();		// Add the new type to trees
  pair<DatatypeSet::iterator,bool> insres = tree.insert(newtype);
  if (!insres.second) {
    ostringstream s;
    s << "Shared type id: " << hex << newtype->getId() << endl;
    s << "  ";
    newtype->printRaw(s);
    s << " : ";
    (*insres.first)->printRaw(s);
    throw LowlevelError(s.str());
  }
  if (newtype->id!=0)
    nametree.insert(newtype);
  return newtype;
}

/// This routine renames a Datatype object and fixes up cross-referencing
/// \param ct is the data-type to rename
/// \param n is the new name
/// \return the renamed Datatype object
Datatype *TypeFactory::setName(Datatype *ct,const string &n)

{
  if (ct->id != 0)
    nametree.erase( ct );	// Erase any name reference
  tree.erase(ct);		// Remove new type completely from trees
  ct->name = n;			// Change the name
  if (ct->id == 0)
    ct->id = Datatype::hashName(n);
				// Insert type with new name
  tree.insert(ct);
  nametree.insert( ct );	// Re-insert name reference
  return ct;
}

/// Make sure all the offsets are fully established then set fields of the structure
/// If -fixedsize- is greater than 0, force the final structure to have that size
/// \param fd is the list of fields to set
/// \param ot is the TypeStruct object to modify
/// \param fixedsize is 0 or the forced size of the structure
/// \param flags are other flags to set on the structure
/// \return true if modification was successful
bool TypeFactory::setFields(vector<TypeField> &fd,TypeStruct *ot,int4 fixedsize,uint4 flags)

{
  int4 offset,cursize,curalign;

  offset = 0;
  vector<TypeField>::iterator iter;

  // Find the maximum offset, from the explicitly set offsets
  for(iter=fd.begin();iter!=fd.end();++iter) {
    Datatype *ct = (*iter).type;
    // Do some sanity checks on the field
    if (ct->getMetatype() == TYPE_VOID) return false;
    if ((*iter).name.size() == 0) return false;

    if ((*iter).offset != -1) {
      int4 end = (*iter).offset + ct->getSize();
      if (end > offset)
	offset = end;
    }
  }

  // Assign offsets, respecting alignment, where not explicitly set
  for(iter=fd.begin();iter!=fd.end();++iter) {
    if ((*iter).offset != -1) continue;
    cursize = (*iter).type->getSize();
    curalign = 0;
    if (align > 1) {
      curalign = align;
      while((curalign>>1) >= cursize)
	curalign >>= 1;
      curalign -= 1;
    }
    if ((offset & curalign)!=0)
      offset = (offset-(offset & curalign) + (curalign+1));
    (*iter).offset = offset;
    offset += cursize;
  }

  sort(fd.begin(),fd.end());	// Sort fields by offset

  // We could check field overlapping here

  tree.erase(ot);
  ot->setFields(fd);
  ot->flags |= (flags & (Datatype::opaque_string | Datatype::variable_length));
  if (fixedsize > 0) {		// If the caller is trying to force a size
    if (fixedsize > ot->size)	// If the forced size is bigger than the size required for fields
      ot->size = fixedsize;	//     Force the bigger size
    else if (fixedsize < ot->size) // If the forced size is smaller, this is an error
      throw LowlevelError("Trying to force too small a size on "+ot->getName());
  }
  tree.insert(ot);
  return true;
}

/// Set the list of enumeration values and identifiers for a TypeEnum
/// Fill in any values for any names that weren't explicitly assigned
/// and check for duplicates.
/// \param namelist is the list of names in the enumeration
/// \param vallist is the corresponding list of values assigned to names in namelist
/// \param assignlist is true if the corresponding name in namelist has an assigned value
/// \param te is the enumeration object to modify
/// \return true if the modification is successful (no duplicate names)
bool TypeFactory::setEnumValues(const vector<string> &namelist,
				const vector<uintb> &vallist,
				const vector<bool> &assignlist,
				TypeEnum *te)
{
  map<uintb,string> nmap;
  map<uintb,string>::iterator mapiter;

  uintb mask = calc_mask(te->getSize());
  uintb maxval = 0;
  for(uint4 i=0;i<namelist.size();++i) {
    uintb val;
    if (assignlist[i]) {	// Did the user explicitly set value
      val = vallist[i];
      if (val > maxval)
	maxval = val;
      val &= mask;
      mapiter = nmap.find(val);
      if (mapiter != nmap.end()) return false; // Duplicate value
      nmap[val] = namelist[i];
    }
  }
  for(uint4 i=0;i<namelist.size();++i) {
    uintb val;
    if (!assignlist[i]) {
      val = maxval;
      maxval += 1;
      val &= mask;
      mapiter = nmap.find(val);
      if (mapiter != nmap.end()) return false;
      nmap[val] = namelist[i];
    }
  }

  tree.erase(te);
  te->setNameMap(nmap);
  tree.insert(te);
  return true;
}

/// Recursively write out all the components of a data-type in dependency order
/// Component data-types will come before the data-type containing them in the list.
/// \param deporder holds the ordered list of data-types to construct
/// \param mark is a "marking" container to prevent cycles
/// \param ct is the data-type to have written out
void TypeFactory::orderRecurse(vector<Datatype *> &deporder,DatatypeSet &mark,
			       Datatype *ct) const

{				// Make sure dependants of ct are in order, then add ct
  pair<DatatypeSet::iterator,bool> res = mark.insert(ct);
  if (!res.second) return;	// Already inserted before
  int4 size = ct->numDepend();
  for(int4 i=0;i<size;++i)
    orderRecurse(deporder,mark,ct->getDepend(i));
  deporder.push_back(ct);
}

/// Place data-types in an order such that if the
/// definition of data-type "a" depends on the definition of
/// data-type "b", then "b" occurs earlier in the order
/// \param deporder will hold the generated dependency list of data-types
void TypeFactory::dependentOrder(vector<Datatype *> &deporder) const

{
  DatatypeSet mark;
  DatatypeSet::const_iterator iter;

  for(iter=tree.begin();iter!=tree.end();++iter)
    orderRecurse(deporder,mark,*iter);
}

/// There should be exactly one instance of the "void" Datatype object, which this fetches
/// \return the "void" data-type
TypeVoid *TypeFactory::getTypeVoid(void)

{
  TypeVoid *ct = (TypeVoid *)typecache[0][TYPE_VOID-TYPE_FLOAT];
  if (ct != (TypeVoid *)0)
    return ct;
  TypeVoid tv;
  tv.id = Datatype::hashName(tv.getName());
  ct = (TypeVoid *)tv.clone();
  tree.insert(ct);
  nametree.insert(ct);
  typecache[0][TYPE_VOID-TYPE_FLOAT] = ct; // Cache this particular type ourselves
  return ct;
}

/// This creates a 1-byte character datatype (assumed to use UTF8 encoding)
/// \param n is the name to give the data-type
/// \return the new character Datatype object
TypeChar *TypeFactory::getTypeChar(const string &n)

{
  TypeChar tc(n);
  tc.id = Datatype::hashName(n);
  return (TypeChar *) findAdd(tc);
}

/// This creates a multi-byte character data-type (using UTF16 or UTF32 encoding)
/// \param nm is the name to give the data-type
/// \param sz is the size of the data-type in bytes
/// \param m is the presumed \b meta-type when treating the character as an integer
/// \return the new character Datatype object
TypeUnicode *TypeFactory::getTypeUnicode(const string &nm,int4 sz,type_metatype m)

{
  TypeUnicode tu(nm,sz,m);
  tu.id = Datatype::hashName(nm);
  return (TypeUnicode *) findAdd(tu);
}

/// Get a "base" data-type, given its size and \b metatype.
/// If a 1-byte integer is requested, do NOT return a TypeChar
/// \param s is the size of the data-type
/// \param m is the meta-type of the data-type
/// \return the Datatype object
Datatype *TypeFactory::getBaseNoChar(int4 s,type_metatype m)

{
  if ((s==1)&&(m == TYPE_INT)&&(type_nochar != (Datatype *)0)) // Jump in and return
    return type_nochar;		// the non character based type (as the main getBase would return char)
  return getBase(s,m);		// otherwise do the main getBase
}

/// Get one of the "base" datatypes. This routine is called a lot, so we go through a cache first.
/// \param s is the desired size
/// \param m is the desired meta-type
/// \return the Datatype object
Datatype *TypeFactory::getBase(int4 s,type_metatype m)

{
  Datatype *ct;
  if (s<9) {
    if (m >= TYPE_FLOAT) {
      ct = typecache[s][m-TYPE_FLOAT];
      if (ct != (Datatype *)0)
	return ct;
    }
  }
  else if (m==TYPE_FLOAT) {
    if (s==10)
      ct = typecache10;
    else if (s==16)
      ct = typecache16;
    else
      ct = (Datatype *)0;
    if (ct != (Datatype *)0)
      return ct;
  }
  if (s > glb->max_basetype_size) {
    // Create array of unknown bytes to match size
    ct = typecache[1][TYPE_UNKNOWN-TYPE_FLOAT];
    ct = getTypeArray(s,ct);
    return findAdd(*ct);
  }
  TypeBase tmp(s,m);
  return findAdd(tmp);
}

/// Get or create a "base" type with a specified name and properties
/// \param s is the desired size
/// \param m is the desired meta-type
/// \param n is the desired name
/// \return the Database object
Datatype *TypeFactory::getBase(int4 s,type_metatype m,const string &n)

{
  TypeBase tmp(s,m,n);
  tmp.id = Datatype::hashName(n);
  return findAdd(tmp);
}

/// Retrieve or create the core "code" Datatype object
/// This has no prototype attached to it and is appropriate for anonymous function pointers.
/// \return the TypeCode object
TypeCode *TypeFactory::getTypeCode(void)

{
  Datatype *ct = typecache[1][TYPE_CODE-TYPE_FLOAT];
  if (ct != (Datatype *)0)
    return (TypeCode *)ct;
  TypeCode tmp("");
  return (TypeCode *) findAdd(tmp);
}

/// Create a "function" or "executable" Datatype object
/// This is used for anonymous function pointers with no prototype
/// \param nm is the name of the data-type
/// \return the new Datatype object
TypeCode *TypeFactory::getTypeCode(const string &nm)

{
  if (nm.size()==0) return getTypeCode();
  TypeCode tmp(nm);
  tmp.id = Datatype::hashName(nm);
  return (TypeCode *) findAdd(tmp);
}

/// This creates a pointer to a given data-type.  If the given data-type is
/// an array, the TYPE_ARRAY property is stripped off, and a pointer to
/// the array element data-type is returned.
/// \param s is the size of the pointer
/// \param pt is the pointed-to data-type
/// \param ws is the wordsize associated with the pointer
/// \return the TypePointer object
TypePointer *TypeFactory::getTypePointerStripArray(int4 s,Datatype *pt,uint4 ws)

{
  if (pt->getMetatype() == TYPE_ARRAY)
    pt = ((TypeArray *)pt)->getBase();		// Strip the first ARRAY type
  TypePointer tmp(s,pt,ws);
  return (TypePointer *) findAdd(tmp);
}

/// Allows "pointer to array" to be constructed
/// \param s is the size of the pointer
/// \param pt is the pointed-to data-type
/// \param ws is the wordsize associated with the pointer
/// \return the TypePointer object
TypePointer *TypeFactory::getTypePointer(int4 s,Datatype *pt,uint4 ws)

{
  TypePointer tmp(s,pt,ws);
  return (TypePointer *) findAdd(tmp);
}

// Don't create more than a depth of 2, i.e. ptr->ptr->ptr->...
/// \param s is the size of the pointer
/// \param pt is the pointed-to data-type
/// \param ws is the wordsize associated with the pointer
/// \return the TypePointer object
TypePointer *TypeFactory::getTypePointerNoDepth(int4 s,Datatype *pt,uint4 ws)

{
  if (pt->getMetatype()==TYPE_PTR) {
    Datatype *basetype = ((TypePointer *)pt)->getPtrTo();
    type_metatype meta = basetype->getMetatype();
    // Make sure that at least we return a pointer to something the size of -pt-
    if (meta == TYPE_PTR)
      return (TypePointer *)pt;
    else if (meta == TYPE_UNKNOWN) {
      if (basetype->getSize() == pt->getSize())	// If -pt- is pointer to UNKNOWN of the size of a pointer
	return (TypePointer *)pt; // Just return pt, don't add another pointer
      pt = getBase(pt->getSize(),TYPE_UNKNOWN);	// Otherwise construct pointer to UNKNOWN of size of pointer
    }
  }
  return getTypePointer(s,pt,ws);
}

/// \param as is the number of elements in the desired array
/// \param ao is the data-type of the array element
/// \return the TypeArray object
TypeArray *TypeFactory::getTypeArray(int4 as,Datatype *ao)

{
  TypeArray tmp(as,ao);
  return (TypeArray *) findAdd(tmp);
}

/// The created structure will have no fields. They must be added later.
/// \param n is the name of the structure
/// \return the TypeStruct object
TypeStruct *TypeFactory::getTypeStruct(const string &n)

{
				// We should probably strip offsets here
				// But I am currently choosing not to
  TypeStruct tmp(n);
  tmp.id = Datatype::hashName(n);
  return (TypeStruct *) findAdd(tmp);
}

/// The created enumeration will have no named values and a default configuration
/// Named values must be added later.
/// \param n is the name of the enumeration
/// \return the TypeEnum object
TypeEnum *TypeFactory::getTypeEnum(const string &n)

{
  TypeEnum tmp(enumsize,enumtype,n);
  tmp.id = Datatype::hashName(n);
  return (TypeEnum *) findAdd(tmp);
}

/// Creates the special TypeSpacebase with an associated address space and scope
/// \param id is the address space
/// \param addr specifies the function scope, or isInvalid() for global scope
/// \return the TypeSpacebase object
TypeSpacebase *TypeFactory::getTypeSpacebase(AddrSpace *id,const Address &addr)

{
  TypeSpacebase tsb(id,addr,glb);
  return (TypeSpacebase *) findAdd(tsb);
}

/// Creates a TypeCode object and associates a specific function prototype with it.
/// \param model is the prototype model associated with the function
/// \param outtype is the return type of the function
/// \param intypes is the array of input parameters of the function
/// \param dotdotdot is true if the function takes variable arguments
/// \return the TypeCode object
TypeCode *TypeFactory::getTypeCode(ProtoModel *model,Datatype *outtype,
				   const vector<Datatype *> &intypes,
				   bool dotdotdot)
{
  TypeCode tc("");		// getFuncdata type with no name
  tc.set(this,model,outtype,intypes,dotdotdot,getTypeVoid());
  return (TypeCode *) findAdd(tc);
}

/// The indicated Datatype object is removed from this container.
/// Indirect references (via TypeArray TypeStruct etc.) are not affected
/// \param ct is the data-type to destroy
void TypeFactory::destroyType(Datatype *ct)

{
  if (ct->isCoreType())
    throw LowlevelError("Cannot destroy core type");
  nametree.erase(ct);
  tree.erase(ct);
  delete ct;
}

/// Add a constant offset to a pointer with known data-type.
/// If there is a valid component at that offset, return a pointer
/// to the data-type of the component or NULL otherwise.
/// This routine only goes down one level at most. Pass back the
/// renormalized offset relative to the new data-type
/// \param ptrtype is the pointer data-type being added to
/// \param off is a reference to the offset to add
/// \return a pointer datatype for the component or NULL
Datatype *TypeFactory::downChain(Datatype *ptrtype,uintb &off)

{				// Change ptr->struct =>  ptr->substruct
				// where substruct starts at offset off
  if (ptrtype->metatype != TYPE_PTR) return (Datatype *)0;
  TypePointer *ptype = (TypePointer *)ptrtype;
  Datatype *pt = ptype->ptrto;
  // If we know we have exactly one of an array, strip the array to get pointer to element
  bool doStrip = (pt->getMetatype() != TYPE_ARRAY);
  pt = pt->getSubType(off,&off);
  if (pt == (Datatype *)0)
    return (Datatype *)0;
  if (doStrip)
    return getTypePointerStripArray(ptype->size, pt, ptype->getWordSize());
  return getTypePointer(ptype->size,pt,ptype->getWordSize());
}

/// The data-type propagation system can push around data-types that are \e partial or are
/// otherwise unrepresentable in the source language.  This method substitutes those data-types
/// with a concrete data-type that is representable, or returns the same data-type if is already concrete.
/// Its important that the returned data-type have the same size as the original data-type regardless.
/// \param ct is the given data-type
/// \return the concrete data-type
Datatype *TypeFactory::concretize(Datatype *ct)

{
  type_metatype metatype = ct->getMetatype();
  if (metatype == TYPE_CODE) {
    if (ct->getSize() != 1)
      throw LowlevelError("Primitive code data-type that is not size 1");
    ct = getBase(1, TYPE_UNKNOWN);
  }
  return ct;
}

/// Restore a Datatype object from an XML tag description: either \<type>, \<typeref>, or \<void>
/// \param el is the XML element describing the data-type
/// \return the restored Datatype object
Datatype *TypeFactory::restoreXmlType(const Element *el)

{
  Datatype *ct;
  if (el->getName() == "typeref") {
    uint8 newid = 0;
    int4 size = -1;
    int4 num = el->getNumAttributes();
    for(int4 i=0;i<num;++i) {
      const string &nm(el->getAttributeName(i));
      if (nm == "id") {
	istringstream s(el->getAttributeValue(i));
	s.unsetf(ios::dec | ios::hex | ios::oct);
	s >> newid;
      }
      else if (nm == "size") {		// A "size" attribute indicates a "variable length" base
	istringstream s(el->getAttributeValue(i));
	s.unsetf(ios::dec | ios::hex | ios::oct);
	s >> size;
      }
    }
    const string &newname( el->getAttributeValue("name"));
    if (newid == 0)		// If there was no id, use the name hash
      newid = Datatype::hashName(newname);
    ct = findById(newname,newid,size);
    if (ct == (Datatype *)0)
      throw LowlevelError("Unable to resolve type: "+newname);
    return ct;
  }
  return restoreXmlTypeNoRef(el,false);
}

/// \brief Restore data-type from XML with extra "code" flags
///
/// Kludge to get flags into code pointer types, when they can't come through XML
/// \param el is the XML element describing the Datatype
/// \param isConstructor toggles "constructor" property on "function" datatypes
/// \param isDestructor toggles "destructor" property on "function" datatypes
/// \return the restored Datatype object
Datatype *TypeFactory::restoreXmlTypeWithCodeFlags(const Element *el,bool isConstructor,bool isDestructor)

{
  TypePointer tp;
  tp.restoreXmlBasic(el);
  if (tp.getMetatype() != TYPE_PTR)
    throw LowlevelError("Special type restoreXml does not see pointer");
  for(int4 i=0;i<el->getNumAttributes();++i)
    if (el->getAttributeName(i) == "wordsize") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> tp.wordsize;
    }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  const Element *subel = *iter;
  if (subel->getAttributeValue("metatype") != "code")
    throw LowlevelError("Special type restoreXml does not see code");
  TypeCode tc("");
  tc.restoreXml(subel,*this);
  tc.setProperties(isConstructor,isDestructor);		// Add in flags
  tp.ptrto = findAdd(tc);				// THEN add to container
  return findAdd(tp);
}

/// All data-types, in dependency order, are written out to an XML stream
/// \param s is the output stream
void TypeFactory::saveXml(ostream &s) const

{
  vector<Datatype *> deporder;
  vector<Datatype *>::iterator iter;

  dependentOrder(deporder);	// Put types in correct order
  s << "<typegrp";
  a_v_i(s,"intsize",sizeOfInt);
  a_v_i(s,"structalign",align);
  a_v_i(s,"enumsize",enumsize);
  a_v_b(s,"enumsigned",(enumtype==TYPE_INT));
  s << ">\n";
  for(iter=deporder.begin();iter!=deporder.end();++iter) {
    if ((*iter)->getName().size()==0) continue;	// Don't save anonymous types
    if ((*iter)->isCoreType()) { // If this would be saved as a coretype
      type_metatype meta = (*iter)->getMetatype();
      if ((meta != TYPE_PTR)&&(meta != TYPE_ARRAY)&&
	  (meta != TYPE_STRUCT))
	continue;		// Don't save it here
    }
    s << ' ';
    (*iter)->saveXml(s);
    s << '\n';
  }
  s << "</typegrp>\n";
}

/// Any data-type within this container marked as "core" will
/// be written to an XML \<coretypes> stream.
/// \param s is the output stream
void TypeFactory::saveXmlCoreTypes(ostream &s) const

{
  DatatypeSet::const_iterator iter;
  Datatype *ct;

  s << "<coretypes>\n";
  for(iter=tree.begin();iter!=tree.end();++iter) {
    ct = *iter;
    if (!ct->isCoreType()) continue;
    type_metatype meta = ct->getMetatype();
    if ((meta==TYPE_PTR)||(meta==TYPE_ARRAY)||
	(meta==TYPE_STRUCT))
      continue;
    s << ' ';
    ct->saveXml(s);
    s << '\n';
  }
  s << "</coretypes>\n";
}

/// Restore a Datatype object from an XML \<type> tag. (Don't use for \<typeref> tags)
/// The new Datatype is added to \b this container
/// \param el is the XML element
/// \param forcecore is true if the new type should be labeled as a core type
/// \return the new Datatype object
Datatype *TypeFactory::restoreXmlTypeNoRef(const Element *el,bool forcecore)

{
  string metastring;
  Datatype *ct;

  if (el->getNumAttributes() == 0) {
    if (el->getName() == "void")
      return getTypeVoid();	// Automatically a coretype
  }
  metastring = el->getAttributeValue("metatype");
  type_metatype meta = string2metatype(metastring);
  switch(meta) {
  case TYPE_PTR:
    {
      TypePointer tp;
      tp.restoreXml(el,*this);
      if (forcecore)
	tp.flags |= Datatype::coretype;
      ct = findAdd(tp);
    }
    break;
  case TYPE_ARRAY:
    {
      TypeArray ta;
      ta.restoreXml(el,*this);
      if (forcecore)
	ta.flags |= Datatype::coretype;
      ct = findAdd(ta);
    }
    break;
  case TYPE_STRUCT:
    {
      string structname = el->getAttributeValue("name");
      TypeStruct ts(structname);
      int4 num = el->getNumAttributes();
      uint8 newid = 0;
      int4 structsize = 0;
      bool isVarLength = false;
      for(int4 i=0;i<num;++i) {
	const string &attribName(el->getAttributeName(i));
	if (attribName == "id") {
	  istringstream s(el->getAttributeValue(i));
	  s.unsetf(ios::dec | ios::hex | ios::oct);
	  s >> newid;
	}
	else if (attribName == "size") {
	  istringstream s(el->getAttributeValue(i));
	  s.unsetf(ios::dec | ios::hex | ios::oct);
	  s >> structsize;
	}
	else if (attribName == "varlength") {
	  isVarLength = xml_readbool(el->getAttributeValue(i));
	}
      }
      if (newid == 0)
	newid = Datatype::hashName(structname);
      if (isVarLength)
	newid = Datatype::hashSize(newid, structsize);
      ct = findByIdLocal(structname,newid);
      bool stubfirst = false;
      if (ct == (Datatype *)0) {
	ts.id = newid;
	ts.size = structsize;	// Include size if we have it, so arrays can be defined without knowing struct fields
	ct = findAdd(ts);	// Create stub to allow recursive definitions
	stubfirst = true;
      }
      else if (ct->getMetatype() != TYPE_STRUCT)
	throw LowlevelError("Trying to redefine type: "+structname);
      ts.restoreXml(el,*this);
      if (forcecore)
	ts.flags |= Datatype::coretype;
      if ((ct->getSize() != 0)&&(!stubfirst)) {	// Structure of this name was already present
	if (0!=ct->compareDependency(ts))
	  throw LowlevelError("Redefinition of structure: "+structname);
      }
      else			// If structure is a placeholder stub
	if (!setFields(ts.field,(TypeStruct *)ct,ts.size,ts.flags)) // Define structure now by copying fields
	  throw LowlevelError("Bad structure definition");
    }
    break;
  case TYPE_SPACEBASE:
    {
      TypeSpacebase tsb((AddrSpace *)0,Address(),glb);
      tsb.restoreXml(el,*this);
      if (forcecore)
	tsb.flags |= Datatype::coretype;
      ct = findAdd(tsb);
    }
    break;
  case TYPE_CODE:
    {
      TypeCode tc("");
      tc.restoreXml(el,*this);
      if (forcecore)
	tc.flags |= Datatype::coretype;
      ct = findAdd(tc);
    }
    break;
  default:
    for(int4 i=0;i<el->getNumAttributes();++i) {
      if ((el->getAttributeName(i) == "char") &&
	  xml_readbool(el->getAttributeValue(i))) {
	TypeChar tc(el->getAttributeValue("name"));
	tc.restoreXml(el,*this);
	if (forcecore)
	  tc.flags |= Datatype::coretype;
	ct = findAdd(tc);
	return ct;
      }
      else if ((el->getAttributeName(i) == "enum") &&
	       xml_readbool(el->getAttributeValue(i))) {
	TypeEnum te(1,TYPE_INT); // size and metatype are replaced
	te.restoreXml(el,*this);
	if (forcecore)
	  te.flags |= Datatype::coretype;
	ct = findAdd(te);
	return ct;
      }
      else if ((el->getAttributeName(i) == "utf") &&
	       xml_readbool(el->getAttributeValue(i))) {
	TypeUnicode tu;
	tu.restoreXml(el,*this);
	if (forcecore)
	  tu.flags |= Datatype::coretype;
	ct = findAdd(tu);
	return ct;
      }
    }
    {
      TypeBase tb(0,TYPE_UNKNOWN);
      tb.restoreXml(el,*this);
      if (forcecore)
	tb.flags |= Datatype::coretype;
      ct = findAdd(tb);
    }
    break;
  }
  return ct;
}

/// Read data-types into this container from an XML stream
/// \param el is the root XML element
void TypeFactory::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  string metastring;

  istringstream i3(el->getAttributeValue("intsize"));
  i3.unsetf(ios::dec | ios::hex | ios::oct);
  i3 >> sizeOfInt;
  istringstream i(el->getAttributeValue("structalign"));
  i.unsetf(ios::dec | ios::hex | ios::oct);
  i >> align;
  istringstream i2(el->getAttributeValue("enumsize"));
  i2.unsetf(ios::dec | ios::hex | ios::oct);
  i2 >> enumsize;
  if (xml_readbool(el->getAttributeValue("enumsigned")))
    enumtype = TYPE_INT;
  else
    enumtype = TYPE_UINT;
  for(iter=list.begin();iter!=list.end();++iter)
    restoreXmlTypeNoRef(*iter,false);
}

/// Restore data-types from an XML stream into this container
/// This stream is presumed to contain "core" datatypes and the
/// cached matrix will be populated from this set.
/// \param el is the root XML element
void TypeFactory::restoreXmlCoreTypes(const Element *el)

{
  clear();			// Make sure this routine flushes

  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter)
    restoreXmlTypeNoRef(*iter,true);
  cacheCoreTypes();
}

/// Recover various sizes relevant to \b this container, such as
/// the default size of "int" and structure alignment, by parsing
/// the \<data_organization> tag.
/// \param el is the XML element
void TypeFactory::parseDataOrganization(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    if (subel->getName() == "integer_size") {
      istringstream i(subel->getAttributeValue("value"));
      i.unsetf(ios::dec | ios::hex | ios::oct);
      i >> sizeOfInt;
    }
    else if (subel->getName() == "size_alignment_map") {
      const List &childlist(subel->getChildren());
      List::const_iterator iter2;
      align = 0;
      for(iter2=childlist.begin();iter2!=childlist.end();++iter2) {
	const Element *childel = *iter2;
	int4 val;
	istringstream i2(childel->getAttributeValue("alignment"));
	i2.unsetf(ios::dec | ios::hex | ios::oct);
	i2 >> val;
	if (val > align)		// Take maximum size alignment
	  align = val;
      }
    }
  }
}

/// Recover default enumeration properties (size and meta-type) from
/// an \<enum> XML tag.  Should probably consider this deprecated. These
/// values are only used by the internal C parser.
/// param el is the XML element
void TypeFactory::parseEnumConfig(const Element *el)

{
  istringstream s(el->getAttributeValue("size"));
  s.unsetf(ios::dec | ios::hex | ios::oct);
  s >> enumsize;
  if (xml_readbool(el->getAttributeValue("signed")))
    enumtype = TYPE_INT;
  else
    enumtype = TYPE_UINT;
}

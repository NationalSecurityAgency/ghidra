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

namespace ghidra {

/// The base propagation ordering associated with each meta-type.
/// The array elements correspond to the ordering of #type_metatype.
sub_metatype Datatype::base2sub[18] = {
    SUB_PARTIALUNION, SUB_PARTIALSTRUCT, SUB_UINT_ENUM, SUB_UNION, SUB_STRUCT, SUB_INT_ENUM, SUB_UINT_ENUM,
    SUB_ARRAY, SUB_PTRREL, SUB_PTR, SUB_FLOAT, SUB_CODE, SUB_BOOL, SUB_UINT_PLAIN, SUB_INT_PLAIN, SUB_UNKNOWN,
    SUB_SPACEBASE, SUB_VOID
};

AttributeId ATTRIB_ALIGNMENT = AttributeId("alignment",47);
AttributeId ATTRIB_ARRAYSIZE = AttributeId("arraysize",48);
AttributeId ATTRIB_CHAR = AttributeId("char",49);
AttributeId ATTRIB_CORE = AttributeId("core",50);
//AttributeId ATTRIB_ENUM = AttributeId("enum",51);	// deprecated
AttributeId ATTRIB_INCOMPLETE = AttributeId("incomplete",52);
//AttributeId ATTRIB_ENUMSIZE = AttributeId("enumsize",53);  // deprecated
//AttributeId ATTRIB_INTSIZE = AttributeId("intsize",54);  // deprecated
//AttributeId ATTRIB_LONGSIZE = AttributeId("longsize",55);  // deprecated
AttributeId ATTRIB_OPAQUESTRING = AttributeId("opaquestring",56);
AttributeId ATTRIB_SIGNED = AttributeId("signed",57);
AttributeId ATTRIB_STRUCTALIGN = AttributeId("structalign",58);
AttributeId ATTRIB_UTF = AttributeId("utf",59);
AttributeId ATTRIB_VARLENGTH = AttributeId("varlength",60);

//ElementId ELEM_ABSOLUTE_MAX_ALIGNMENT = ElementId("absolute_max_alignment", 37);
//ElementId ELEM_BITFIELD_PACKING = ElementId("bitfield_packing", 38);
ElementId ELEM_CHAR_SIZE = ElementId("char_size", 39);
//ElementId ELEM_CHAR_TYPE = ElementId("char_type", 40);
ElementId ELEM_CORETYPES = ElementId("coretypes",41);
ElementId ELEM_DATA_ORGANIZATION = ElementId("data_organization", 42);
ElementId ELEM_DEF = ElementId("def",43);
//ElementId ELEM_DEFAULT_ALIGNMENT = ElementId("default_alignment", 44);
//ElementId ELEM_DEFAULT_POINTER_ALIGNMENT = ElementId("default_pointer_alignment", 45);
//ElementId ELEM_DOUBLE_SIZE = ElementId("double_size", 46);
ElementId ELEM_ENTRY = ElementId("entry",47);
ElementId ELEM_ENUM = ElementId("enum",48);
ElementId ELEM_FIELD = ElementId("field",49);
//ElementId ELEM_FLOAT_SIZE = ElementId("float_size", 50);
ElementId ELEM_INTEGER_SIZE = ElementId("integer_size",51);
//ElementId ELEM_LONG_DOUBLE_SIZE = ElementId("long_double_size", 52);
//ElementId ELEM_LONG_LONG_SIZE = ElementId("long_long_size", 53);
ElementId ELEM_LONG_SIZE = ElementId("long_size", 54);
//ElementId ELEM_MACHINE_ALIGNMENT = ElementId("machine_alignment", 55);
//ElementId ELEM_POINTER_SHIFT = ElementId("pointer_shift", 56);
ElementId ELEM_POINTER_SIZE = ElementId("pointer_size", 57);
//ElementId ELEM_SHORT_SIZE = ElementId("short_size", 58);
ElementId ELEM_SIZE_ALIGNMENT_MAP = ElementId("size_alignment_map", 59);
ElementId ELEM_TYPE = ElementId("type",60);
//ElementId ELEM_TYPE_ALIGNMENT_ENABLED = ElementId("type_alignment_enabled", 61);
ElementId ELEM_TYPEGRP = ElementId("typegrp",62);
ElementId ELEM_TYPEREF = ElementId("typeref",63);
//ElementId ELEM_USE_MS_CONVENTION = ElementId("use_MS_convention", 64);
ElementId ELEM_WCHAR_SIZE = ElementId("wchar_size", 65);
//ElementId ELEM_ZERO_LENGTH_BOUNDARY = ElementId("zero_length_boundary", 66);

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

/// \brief Find an immediate subfield of \b this data-type
///
/// Given a byte range within \b this data-type, determine the field it is contained in
/// and pass back the renormalized offset. This method applies to TYPE_STRUCT, TYPE_UNION, and
/// TYPE_PARTIALUNION, data-types that have field components. For TYPE_UNION and TYPE_PARTIALUNION, the
/// field may depend on the p-code op extracting or writing the value.
/// \param off is the byte offset into \b this
/// \param sz is the size of the byte range
/// \param op is the PcodeOp reading/writing the data-type
/// \param slot is the index of the Varnode being accessed, -1 for the output, >=0 for an input
/// \param newoff points to the renormalized offset to pass back
/// \return the containing field or NULL if the range is not contained
const TypeField *Datatype::findTruncation(int8 off,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const

{
  return (const TypeField *)0;
}

/// Given an offset into \b this data-type, return the component data-type at that offset.
/// Also, pass back a "renormalized" offset suitable for recursize getSubType() calls:
/// i.e. if the original offset hits the exact start of the sub-type, 0 is passed back.
/// If there is no valid component data-type at the offset,
/// return NULL and pass back the original offset
/// \param off is the offset into \b this data-type
/// \param newoff is a pointer to the passed-back offset
/// \return a pointer to the component data-type or NULL
Datatype *Datatype::getSubType(int8 off,int8 *newoff) const

{				// There is no subtype
  *newoff = off;
  return (Datatype *)0;
}

/// Find the first component data-type that is (or contains) an array starting after the given
/// offset, and pass back the difference between the component's start and the given offset.
/// Return the component data-type or null if no array is found.
/// \param off is the given offset into \b this data-type
/// \param newoff is used to pass back the offset difference
/// \param elSize is used to pass back the array element size
/// \return the component data-type or null
Datatype *Datatype::nearestArrayedComponentForward(int8 off,int8 *newoff,int8 *elSize) const

{
  return (TypeArray *)0;
}

/// Find the last component data-type that is (or contains) an array starting before the given
/// offset, and pass back the difference between the component's start and the given offset.
/// Return the component data-type or null if no array is found.
/// \param off is the given offset into \b this data-type
/// \param newoff is used to pass back the offset difference
/// \param elSize is used to pass back the array element size
/// \return the component data-type or null
Datatype *Datatype::nearestArrayedComponentBackward(int8 off,int8 *newoff,int8 *elSize) const

{
  return (TypeArray *)0;
}

/// Order \b this with another data-type, in a way suitable for the type propagation algorithm.
/// Bigger types come earlier. More specific types come earlier.
/// \param op is the data-type to compare with \b this
/// \param level is maximum level to descend when recursively comparing
/// \return negative, 0, positive depending on ordering of types
int4 Datatype::compare(const Datatype &op,int4 level) const

{
  if (submeta != op.submeta) return (submeta < op.submeta) ? -1 : 1;
  if (size != op.size) return (op.size - size);
  return 0;
}

/// Sort data-types for the main TypeFactory container.  The sort needs to be based on
/// the data-type structure so that an example data-type, constructed outside the factory,
/// can be used to find the equivalent object inside the factory.  This means the
/// comparison should not examine the data-type id. In practice, the comparison only needs
/// to go down one level in the component structure before just comparing component pointers.
/// \param op is the data-type to compare with \b this
/// \return negative, 0, positive depending on ordering of types
int4 Datatype::compareDependency(const Datatype &op) const

{
  if (submeta != op.submeta) return (submeta < op.submeta) ? -1 : 1;
  if (size != op.size) return (op.size-size);
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
  case TYPE_PTRREL:
    res = "ptrrel";
    break;
  case TYPE_ARRAY:
    res = "array";
    break;
  case TYPE_PARTIALENUM:
    res = "partenum";
    break;
  case TYPE_PARTIALSTRUCT:
    res = "partstruct";
    break;
  case TYPE_PARTIALUNION:
    res = "partunion";
    break;
  case TYPE_ENUM_INT:
    res = "enum_int";
    break;
  case TYPE_ENUM_UINT:
    res = "enum_uint";
    break;
  case TYPE_STRUCT:
    res = "struct";
    break;
  case TYPE_UNION:
    res = "union";
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
    else if (metastring=="ptrrel")
      return TYPE_PTRREL;
    else if (metastring=="partunion")
      return TYPE_PARTIALUNION;
    else if (metastring=="partstruct")
      return TYPE_PARTIALSTRUCT;
    break;
  case 'a':
    if (metastring=="array")
      return TYPE_ARRAY;
    break;
  case 'e':
    if (metastring=="enum_int")
      return TYPE_ENUM_INT;
    else if (metastring == "enum_uint")
      return TYPE_ENUM_UINT;
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
    else if (metastring=="union")
      return TYPE_UNION;
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

/// Given a description of a data-type \e class, return the \b type_class.
/// \param classstring is the description of the class
/// \return the encoded type_class
type_class string2typeclass(const string &classstring)

{
  switch(classstring[0]) {
    case 'c':
      if (classstring == "class1")
	return TYPECLASS_CLASS1;
      else if (classstring == "class2")
	return TYPECLASS_CLASS2;
      else if (classstring == "class3")
	return TYPECLASS_CLASS3;
      else if (classstring == "class4")
	return TYPECLASS_CLASS4;
      break;
    case 'g':
      if (classstring == "general")
	return TYPECLASS_GENERAL;
      break;
    case 'h':
      if (classstring == "hiddenret")
	return TYPECLASS_HIDDENRET;
      break;
    case 'f':
      if (classstring == "float")
	return TYPECLASS_FLOAT;
      break;
    case 'p':
      if (classstring == "ptr" || classstring == "pointer")
	return TYPECLASS_PTR;
      break;
    case 'v':
      if (classstring == "vector")
	return TYPECLASS_VECTOR;
      break;
    case 'u':
      if (classstring == "unknown")
	return TYPECLASS_GENERAL;
      break;
  }
  throw LowlevelError("Unknown data-type class: " + classstring);
}

/// Assign the basic storage class based on a metatype:
///   - TYPE_FLOAT  ->  TYPECLASS_FLOAT
///   - TYPE_PTR    ->  TYPECLASS_PTR
///
/// Everything else returns the general purpose TYPECLASS_GENERAL
/// \param meta is the metatype
/// \return the storage class
type_class metatype2typeclass(type_metatype meta)

{
  switch(meta) {
    case TYPE_FLOAT:
      return TYPECLASS_FLOAT;
    case TYPE_PTR:
      return TYPECLASS_PTR;
    default:
      break;
  }
  return TYPECLASS_GENERAL;
}

/// Encode a formal description of the data-type as a \<type> element.
/// For composite data-types, the description goes down one level, describing
/// the component types only by reference.
/// \param encoder is the stream encoder
void Datatype::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  encoder.closeElement(ELEM_TYPE);
}

/// Encode basic data-type properties (name,size,id) as attributes.
/// This routine presumes the initial element is already written to the stream.
/// \param meta is the metatype attribute to encode
/// \param align is the byte alignment to encode (-1 to not encode alignment)
/// \param encoder is the stream encoder
void Datatype::encodeBasic(type_metatype meta,int4 align,Encoder &encoder) const

{
  encoder.writeString(ATTRIB_NAME, name);
  uint8 saveId = getUnsizedId();
  if (saveId != 0) {
    encoder.writeUnsignedInteger(ATTRIB_ID, saveId);
  }
  encoder.writeSignedInteger(ATTRIB_SIZE, size);
  string metastring;
  metatype2string(meta,metastring);
  encoder.writeString(ATTRIB_METATYPE,metastring);
  if (align > 0)
    encoder.writeSignedInteger(ATTRIB_ALIGNMENT, align);
  if ((flags & coretype)!=0)
    encoder.writeBool(ATTRIB_CORE,true);
  if (isVariableLength())
    encoder.writeBool(ATTRIB_VARLENGTH,true);
  if ((flags & opaque_string)!=0)
    encoder.writeBool(ATTRIB_OPAQUESTRING,true);
  uint4 format = getDisplayFormat();
  if (format != 0)
    encoder.writeString(ATTRIB_FORMAT,decodeIntegerFormat(format));
}

/// Encode a simple reference to \b this data-type as a \<typeref> element,
/// including only the name and id.
/// \param encoder is the stream encoder
void Datatype::encodeRef(Encoder &encoder) const

{				// Save just a name reference if possible
  if ((id!=0)&&(metatype != TYPE_VOID)) {
    encoder.openElement(ELEM_TYPEREF);
    encoder.writeString(ATTRIB_NAME,name);
    if (isVariableLength()) {			// For a type with a "variable length" base
      encoder.writeUnsignedInteger(ATTRIB_ID, hashSize(id,size));	// Emit the size independent version of the id
      encoder.writeSignedInteger(ATTRIB_SIZE, size);			// but also emit size of this instance
    }
    else {
      encoder.writeUnsignedInteger(ATTRIB_ID, id);
    }
    encoder.closeElement(ELEM_TYPEREF);
  }
  else
    encode(encoder);
}

/// If \b this has no component data-types, return \b true.
/// If \b this has only a single primitive component filling the whole data-type, also return \b true.
/// \return \b true if \b this data-type is made up of a single primitive
bool Datatype::isPrimitiveWhole(void) const

{
  if (!isPieceStructured()) return true;
  if (metatype == TYPE_ARRAY || metatype == TYPE_STRUCT) {
    if (numDepend() > 0) {
      Datatype *component = getDepend(0);
      if (component->getSize() == getSize())
	return component->isPrimitiveWhole();
    }
  }
  return false;
}

/// Called only if the \b typedefImm field is non-null.  Encode the data-type to the
/// stream as a simple \<typedef> element including only the names and ids of \b this and
/// the data-type it typedefs.
/// \param encoder is the stream encoder
void Datatype::encodeTypedef(Encoder &encoder) const

{
  encoder.openElement(ELEM_DEF);
  encoder.writeString(ATTRIB_NAME, name);
  encoder.writeUnsignedInteger(ATTRIB_ID, id);
  uint4 format = getDisplayFormat();
  if (format != 0)
    encoder.writeString(ATTRIB_FORMAT,Datatype::decodeIntegerFormat(format));
  typedefImm->encodeRef(encoder);
  encoder.closeElement(ELEM_DEF);
}

/// Calculate size rounded up to be a multiple of \b align.
/// \param sz is the number of bytes in the data-type before padding
/// \param align is the alignment of the data-type
/// \return the aligned size
int4 Datatype::calcAlignSize(int4 sz,int4 align)

{
  int4 mod = sz % align;
  if (mod != 0)
    return sz + (align - mod);
  return sz;
}

/// A CPUI_PTRSUB must act on a pointer data-type where the given offset addresses a component.
/// Perform this check.
/// \param off is the given offset
/// \param extra is any additional constant being added to the pointer
/// \param multiplier is the size of any index multiplier being added to the pointer
/// \return \b true if \b this is a suitable PTRSUB data-type
bool Datatype::isPtrsubMatching(int8 off,int8 extra,int8 multiplier) const

{
  return false;
}

/// Some data-types are ephemeral, and, in the final decompiler output, get replaced with a formal version
/// that is a stripped down version of the original.  This method returns this stripped down version, if it
/// exists, or null otherwise.  A non-null return should correspond with hasStripped returning \b true.
/// \return the stripped version or null
Datatype *Datatype::getStripped(void) const

{
  return (Datatype *)0;
}

/// For certain data-types, particularly \e union, variables of that data-type are transformed into a subtype
/// depending on the particular use.  Each read or write of the variable may use a different subtype.
/// This method returns the particular subtype required based on a specific PcodeOp. A slot index >=0
/// indicates which operand \e reads the variable, or if the index is -1, the variable is \e written.
/// \param op is the specific PcodeOp
/// \param slot indicates the input operand, or the output
/// \return the resolved sub-type
Datatype *Datatype::resolveInFlow(PcodeOp *op,int4 slot)

{
  return this;
}

/// This is the constant version of resolveInFlow.  If a resulting subtype has already been calculated,
/// for the particular read (\b slot >= 0) or write (\b slot == -1), then return it.
/// Otherwise return the original data-type.
/// \param op is the PcodeOp using the Varnode assigned with \b this data-type
/// \param slot is the slot reading or writing the Varnode
/// \return the resolved subtype or the original data-type
Datatype* Datatype::findResolve(const PcodeOp *op,int4 slot)

{
  return this;
}

/// If \b this data-type has an alternate data-type form that matches the given data-type,
/// return an index indicating this form, otherwise return -1.
/// \param ct is the given data-type
/// \return the index of the matching form or -1
int4 Datatype::findCompatibleResolve(Datatype *ct) const

{
  return -1;
}

/// \brief Resolve which union field is being used for a given PcodeOp when a truncation is involved
///
/// This method applies to the TYPE_UNION and TYPE_PARTIALUNION data-types, when a Varnode is backed
/// by a larger Symbol with a union data-type, or if the Varnode is produced by a CPUI_SUBPIECE where
/// the input Varnode has a union data-type.
/// Scoring is done to compute the best field and the result is cached with the function.
/// The record of the best field is returned or null if there is no appropriate field
/// \param offset is the byte offset into the union we are truncating to
/// \param op is either the PcodeOp reading the truncated Varnode or the CPUI_SUBPIECE doing the truncation
/// \param slot is either the input slot of the reading PcodeOp or the artificial SUBPIECE slot: 1
/// \param newoff is used to pass back how much offset is left to resolve
/// \return the field of the union best associated with the truncation or null
const TypeField *Datatype::resolveTruncation(int8 offset,PcodeOp *op,int4 slot,int8 &newoff)

{
  return (const TypeField *)0;
}

/// Restore the basic properties (name,size,id) of a data-type from a stream.
/// Properties are read from the attributes of the element.
/// \param decoder is the stream decoder
void Datatype::decodeBasic(Decoder &decoder)

{
  size = -1;
  metatype = TYPE_VOID;
  id = 0;
  for(;;) {
    uint4 attrib = decoder.getNextAttributeId();
    if (attrib == 0) break;
    if (attrib == ATTRIB_NAME) {
      name = decoder.readString();
    }
    else if (attrib == ATTRIB_SIZE) {
      size = decoder.readSignedInteger();
    }
    else if (attrib == ATTRIB_METATYPE) {
      metatype = string2metatype(decoder.readString());
    }
    else if (attrib == ATTRIB_CORE) {
      if (decoder.readBool())
	flags |= coretype;
    }
    else if (attrib == ATTRIB_ID) {
      id = decoder.readUnsignedInteger();
    }
    else if (attrib == ATTRIB_VARLENGTH) {
      if (decoder.readBool())
	flags |= variable_length;
    }
    else if (attrib == ATTRIB_ALIGNMENT) {
      alignment = decoder.readSignedInteger();
    }
    else if (attrib == ATTRIB_OPAQUESTRING) {
      if (decoder.readBool())
	flags |= opaque_string;
    }
    else if (attrib == ATTRIB_FORMAT) {
      uint4 val = encodeIntegerFormat(decoder.readString());
      setDisplayFormat(val);
    }
    else if (attrib == ATTRIB_LABEL) {
      displayName = decoder.readString();
    }
    else if (attrib == ATTRIB_INCOMPLETE) {
      if (decoder.readBool())
	flags |= type_incomplete;
    }
  }
  if (size < 0)
    throw LowlevelError("Bad size for type "+name);
  alignSize = size;
  submeta = base2sub[metatype];
  if ((id==0)&&(name.size()>0))	// If there is a type name
    id = hashName(name);	// There must be some kind of id
  if (isVariableLength()) {
    // Id needs to be unique compared to another data-type with the same name
    id = hashSize(id, size);
  }
  if (displayName.empty())
    displayName = name;
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
  res |= 0xC000000000000000;	// Add header bits indicating a name hash
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
/// \brief Encode the \b format attribute from an XML element
///
/// Possible values are:
///   - 1  - \b hex
///   - 2  - \b dec
///   - 3  - \b oct
///   - 4  - \b bin
///   - 5 - \b char
///
/// \param val is the string to encode
/// \return the encoded value
uint4 Datatype::encodeIntegerFormat(const string &val)

{
  if (val == "hex")
    return 1;
  else if (val == "dec")
    return 2;
  else if (val == "oct")
    return 3;
  else if (val == "bin")
    return 4;
  else if (val == "char")
    return 5;
  throw LowlevelError("Unrecognized integer format: " + val);
}

/// \brief Decode the given format value into an XML attribute string
///
/// Possible encoded values are 1-5 corresponding to "hex", "dec", "oct", "bin", "char"
/// \param val is the value to decode
/// \return the decoded string
string Datatype::decodeIntegerFormat(uint4 val)

{
  if (val == 1)
    return "hex";
  else if (val == 2)
    return "dec";
  else if (val == 3)
    return "oct";
  else if (val == 4)
    return "bin";
  else if (val == 5)
    return "char";
  throw LowlevelError("Unrecognized integer format encoding");
}

/// Construct from a \<field> element.
/// \param decoder is the stream decoder
/// \param typegrp is the TypeFactory for parsing data-type info
TypeField::TypeField(Decoder &decoder,TypeFactory &typegrp)

{
  uint4 elemId = decoder.openElement(ELEM_FIELD);
  ident = -1;
  offset = -1;
  for(;;) {
    uint4 attrib = decoder.getNextAttributeId();
    if (attrib == 0) break;
    if (attrib == ATTRIB_NAME)
      name = decoder.readString();
    else if (attrib == ATTRIB_OFFSET) {
      offset = decoder.readSignedInteger();
    }
    else if (attrib == ATTRIB_ID) {
      ident = decoder.readSignedInteger();
    }
  }
  type = typegrp.decodeType( decoder );
  if (name.size()==0)
    throw LowlevelError("name attribute must not be empty in <field> tag");
  if (offset < 0)
    throw LowlevelError("offset attribute invalid for <field> tag");
  if (ident < 0)
    ident = offset;	// By default the id is the offset
  decoder.closeElement(elemId);
}

/// Encode a formal description of \b this as a \<field> element.
/// \param encoder is the stream encoder
void TypeField::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_FIELD);
  encoder.writeString(ATTRIB_NAME,name);
  encoder.writeSignedInteger(ATTRIB_OFFSET, offset);
  if (ident != offset)
    encoder.writeSignedInteger(ATTRIB_ID, ident);
  type->encodeRef(encoder);
  encoder.closeElement(ELEM_FIELD);
}

/// Parse a \<type> element for attributes of the character data-type
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypeChar::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  decodeBasic(decoder);
  submeta = (metatype == TYPE_INT) ? SUB_INT_CHAR : SUB_UINT_CHAR;
//  decoder.closeElement(elemId);
}

void TypeChar::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  encoder.writeBool(ATTRIB_CHAR, true);
  encoder.closeElement(ELEM_TYPE);
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

/// Parse a \<type> tag for properties of the data-type.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypeUnicode::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  decodeBasic(decoder);
  // Get endianness flag from architecture, rather than specific type encoding
  setflags();
  submeta = (metatype == TYPE_INT) ? SUB_INT_UNICODE : SUB_UINT_UNICODE;
//  decoder.closeElement(elemId);
}

TypeUnicode::TypeUnicode(const string &nm,int4 sz,type_metatype m)
  : TypeBase(sz,m,nm)
{
  setflags();			// Set special unicode UTF flags
  submeta = (m == TYPE_INT) ? SUB_INT_UNICODE : SUB_UINT_UNICODE;
}

void TypeUnicode::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  encoder.writeBool(ATTRIB_UTF, true);
  encoder.closeElement(ELEM_TYPE);
}

/// Parse a \<type> element for the \b id attributes of the \b void data-type.
/// The \b void data-type is usually marshaled with the \<void> element, but this is an alternate
/// encoding that allows a specific id to be associated with the data-type when core data-types are specified.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypeVoid::decode(Decoder &decoder,TypeFactory &typegrp)

{
  for(;;) {
    uint4 attrib = decoder.getNextAttributeId();
    if (attrib == 0) break;
    if (attrib == ATTRIB_ID) {
      id = decoder.readUnsignedInteger();
    }
  }
}

void TypeVoid::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_VOID);
  encoder.closeElement(ELEM_VOID);
}

void TypePointer::printRaw(ostream &s) const

{
  ptrto->printRaw(s);
  s << " *";
  if (spaceid != (AddrSpace *)0) {
    s << '(' << spaceid->getName() << ')';
  }
}

Datatype *TypePointer::getSubType(int8 off,int8 *newoff) const

{
  if (truncate != (TypePointer *)0) {
    int8 min = ((flags & truncate_bigendian) != 0) ? size - truncate->getSize() : 0;
    if (off >= min && off < min + truncate->getSize()) {
      *newoff = off - min;
      return truncate;
    }
  }
  return Datatype::getSubType(off, newoff);
}

int4 TypePointer::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  // Both must be pointers
  TypePointer *tp = (TypePointer *) &op;
  if (wordsize != tp->wordsize) return (wordsize < tp->wordsize) ? -1 : 1;
  if (spaceid != tp->spaceid) {
    if (spaceid == (AddrSpace *)0) return 1;	// Pointers with address space come earlier
    if (tp->spaceid == (AddrSpace *)0) return -1;
    return (spaceid->getIndex() < tp->spaceid->getIndex()) ? -1 : 1;
  }
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  return ptrto->compare(*tp->ptrto,level); // Compare whats pointed to
}

int4 TypePointer::compareDependency(const Datatype &op) const

{
  if (submeta != op.getSubMeta()) return (submeta < op.getSubMeta()) ? -1 : 1;
  TypePointer *tp = (TypePointer *) &op;	// Both must be pointers
  if (ptrto != tp->ptrto) return (ptrto < tp->ptrto) ? -1 : 1;	// Compare absolute pointers
  if (wordsize != tp->wordsize) return (wordsize < tp->wordsize) ? -1 : 1;
  if (spaceid != tp->spaceid) {
    if (spaceid == (AddrSpace *)0) return 1;	// Pointers with address space come earlier
    if (tp->spaceid == (AddrSpace *)0) return -1;
    return (spaceid->getIndex() < tp->spaceid->getIndex()) ? -1 : 1;
  }
  return (op.getSize()-size);
}

void TypePointer::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  if (wordsize != 1)
    encoder.writeUnsignedInteger(ATTRIB_WORDSIZE, wordsize);
  if (spaceid != (AddrSpace *)0)
    encoder.writeSpace(ATTRIB_SPACE, spaceid);
  ptrto->encodeRef(encoder);
  encoder.closeElement(ELEM_TYPE);
}

/// If the given data-type is an array, or has an arrayed component, return \b true.
/// \param dt is the given data-type to check
/// \param off is the out-of-bounds offset
/// \return \b true is an array is present
bool TypePointer::testForArraySlack(Datatype *dt,int8 off)

{
  int8 newoff;
  int8 elSize;
  if (dt->getMetatype() == TYPE_ARRAY)
    return true;
  Datatype *compType;
  if (off < 0) {
    compType = dt->nearestArrayedComponentForward(off, &newoff, &elSize);
  }
  else {
    compType = dt->nearestArrayedComponentBackward(off, &newoff, &elSize);
  }
  return (compType != (Datatype *)0);
}

/// Parse a \<type> element with a child describing the data-type being pointed to
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypePointer::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  decodeBasic(decoder);;
  decoder.rewindAttributes();
  for(;;) {
    uint4 attrib = decoder.getNextAttributeId();
    if (attrib == 0) break;
    if (attrib == ATTRIB_WORDSIZE) {
      wordsize = decoder.readUnsignedInteger();
    }
    else if (attrib == ATTRIB_SPACE) {
      spaceid = decoder.readSpace();
    }
  }
  ptrto = typegrp.decodeType( decoder );
  calcSubmeta();
  if (name.size() == 0)		// Inherit only if no name
    flags |= ptrto->getInheritable();
  calcTruncate(typegrp);
//  decoder.closeElement(elemId);
}

/// Pointers to structures may require a specific \b submeta
void TypePointer::calcSubmeta(void)

{
  type_metatype ptrtoMeta = ptrto->getMetatype();
  if (ptrtoMeta == TYPE_STRUCT) {
    if (ptrto->numDepend() > 1 || ptrto->isIncomplete())
      submeta = SUB_PTR_STRUCT;
    else
      submeta = SUB_PTR;
  }
  else if (ptrtoMeta == TYPE_UNION) {
    submeta = SUB_PTR_STRUCT;
  }
  else if (ptrtoMeta == TYPE_ARRAY) {
    flags |= pointer_to_array;
  }
  if (ptrto->needsResolution() && ptrtoMeta != TYPE_PTR)
    flags |= needs_resolution;		// Inherit needs_resolution, but only if not a pointer
}

/// If \b this pointer has a size of \b sizeOfAltPointer, a smaller (\b sizeOfPointer) pointer
/// data-type is created and assigned to \b this as a subcomponent.
/// \param typegrp is the factory \b this belongs to
void TypePointer::calcTruncate(TypeFactory &typegrp)

{
  if (truncate != (TypePointer *)0 || size != typegrp.getSizeOfAltPointer())
    return;

  truncate = typegrp.resizePointer(this, typegrp.getSizeOfPointer());
  if (typegrp.getArch()->getDefaultDataSpace()->isBigEndian())
    flags |= Datatype::truncate_bigendian;
}

/// \brief Find a sub-type pointer given an offset into \b this
///
/// Add a constant offset to \b this pointer.
/// If there is a valid component at that offset, return a pointer
/// to the data-type of the component or NULL otherwise.
/// This routine only goes down one level at most. Pass back the
/// renormalized offset relative to the new data-type.  If \b this is
/// a pointer to (into) a container, the data-type of the container is passed back,
/// with the offset into the container.
/// \param off is a reference to the offset to add
/// \param par is used to pass back the container
/// \param parOff is used to pass back the offset into the container
/// \param allowArrayWrap is \b true if the pointer should be treated as a pointer to an array
/// \param typegrp is the factory producing the (possibly new) data-type
/// \return a pointer datatype for the component or NULL
TypePointer *TypePointer::downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap,TypeFactory &typegrp)

{
  int4 ptrtoSize = ptrto->getAlignSize();
  if (off < 0 || off >= ptrtoSize) {	// Check if we are wrapping
    if (ptrtoSize != 0 && !ptrto->isVariableLength()) {	// Check if pointed-to is wrappable
      if (!allowArrayWrap)
        return (TypePointer *)0;
      intb signOff = sign_extend(off,size*8-1);
      signOff = signOff % ptrtoSize;
      if (signOff < 0)
	signOff = signOff + ptrtoSize;
      off = signOff;
      if (off == 0)		// If we've wrapped and are now at zero
        return this;		// consider this going down one level
    }
  }

  if (ptrto->isEnumType()) {
    // Go "into" the enumeration
    Datatype *tmp = typegrp.getBase(1, TYPE_UINT);
    off = 0;
    return typegrp.getTypePointer(size,tmp,wordsize);
  }
  type_metatype meta = ptrto->getMetatype();
  bool isArray = (meta == TYPE_ARRAY);
  if (isArray || meta == TYPE_STRUCT) {
    par = this;
    parOff = off;
  }

  Datatype *pt = ptrto->getSubType(off,&off);
  if (pt == (Datatype *)0)
    return (TypePointer *)0;
  if (!isArray)
    return typegrp.getTypePointerStripArray(size, pt, wordsize);
  return typegrp.getTypePointer(size,pt,wordsize);
}

bool TypePointer::isPtrsubMatching(int8 off,int8 extra,int8 multiplier) const

{
  type_metatype meta = ptrto->getMetatype();
  if (meta==TYPE_SPACEBASE) {
    int8 newoff = AddrSpace::addressToByteInt(off,wordsize);
    Datatype *subType = ptrto->getSubType(newoff,&newoff);
    if (subType == (Datatype *)0 || newoff != 0)
      return false;
    extra = AddrSpace::addressToByteInt(extra,wordsize);
    if (extra < 0 || extra >= subType->getSize()) {
      if (!testForArraySlack(subType, extra))
	return false;
    }
  }
  else if (meta == TYPE_ARRAY) {
    if (off != 0)
      return false;
    multiplier = AddrSpace::addressToByteInt(multiplier,wordsize);
    if (multiplier >= ptrto->getAlignSize())
      return false;
  }
  else if (meta == TYPE_STRUCT) {
    int4 typesize = ptrto->getSize();
    multiplier = AddrSpace::addressToByteInt(multiplier,wordsize);
    if (multiplier >= ptrto->getAlignSize())
      return false;
    int8 newoff = AddrSpace::addressToByteInt(off,wordsize);
    extra = AddrSpace::addressToByteInt(extra, wordsize);
    Datatype *subType = ptrto->getSubType(newoff,&newoff);
    if (subType != (Datatype *)0) {
      if (newoff != 0)
	return false;
      if (extra < 0 || extra >= subType->getSize()) {
	if (!testForArraySlack(subType, extra))
	  return false;
      }
    }
    else {
      extra += newoff;
      if ((extra < 0 || extra >= typesize)&&(typesize!=0))
        return false;
    }
  }
  else if (ptrto->getMetatype() == TYPE_UNION) {
    // A PTRSUB reaching here cannot be used for a union field resolution
    // These are created by ActionSetCasts::resolveUnion
    return false;	// So we always return false
  }
  else
    return false;	// Not a pointer to a structured data-type
  return true;
}

Datatype *TypePointer::resolveInFlow(PcodeOp *op,int4 slot)

{
  if (ptrto->getMetatype() == TYPE_UNION) {
    Funcdata *fd = op->getParent()->getFuncdata();
    const ResolvedUnion *res = fd->getUnionField(this,op,slot);
    if (res != (ResolvedUnion*)0)
      return res->getDatatype();
    ScoreUnionFields scoreFields(*fd->getArch()->types,this,op,slot);
    fd->setUnionField(this,op,slot,scoreFields.getResult());
    return scoreFields.getResult().getDatatype();
  }
  return this;
}

Datatype* TypePointer::findResolve(const PcodeOp *op,int4 slot)

{
  if (ptrto->getMetatype() == TYPE_UNION) {
    const Funcdata *fd = op->getParent()->getFuncdata();
    const ResolvedUnion *res = fd->getUnionField(this,op,slot);
    if (res != (ResolvedUnion*)0)
      return res->getDatatype();
  }
  return this;
}

void TypeArray::printRaw(ostream &s) const

{
  arrayof->printRaw(s);
  s << " [" << dec << arraysize << ']';
}

int4 TypeArray::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  TypeArray *ta = (TypeArray *) &op;	// Both must be arrays
  return arrayof->compare(*ta->arrayof,level); // Compare array elements
}

int4 TypeArray::compareDependency(const Datatype &op) const

{
  if (submeta != op.getSubMeta()) return (submeta < op.getSubMeta()) ? -1 : 1;
  TypeArray *ta = (TypeArray *) &op;	// Both must be arrays
  if (arrayof != ta->arrayof) return (arrayof < ta->arrayof) ? -1 : 1;	// Compare absolute pointers
  return (op.getSize()-size);
}

Datatype *TypeArray::getSubType(int8 off,int8 *newoff) const

{				// Go down exactly one level, to type of element
  if (off >= size)
    return Datatype::getSubType(off, newoff);
  *newoff = off % arrayof->getAlignSize();
  return arrayof;
}

int4 TypeArray::getHoleSize(int4 off) const

{
  int4 newOff = off % arrayof->getAlignSize();
  return arrayof->getHoleSize(newOff);
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
  int4 noff = off % arrayof->getAlignSize();
  int4 nel = off / arrayof->getAlignSize();
  if (noff+sz > arrayof->getAlignSize()) // Requesting parts of more then one element
    return (Datatype *)0;
  *newoff = noff;
  *el = nel;
  return arrayof;
}

void TypeArray::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, arraysize);
  arrayof->encodeRef(encoder);
  encoder.closeElement(ELEM_TYPE);
}

Datatype *TypeArray::resolveInFlow(PcodeOp *op,int4 slot)

{
  Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0)
    return res->getDatatype();

  int4 fieldNum = TypeStruct::scoreSingleComponent(this,op,slot);

  ResolvedUnion compFill(this,fieldNum,*fd->getArch()->types);
  fd->setUnionField(this, op, slot, compFill);
  return compFill.getDatatype();
}

Datatype* TypeArray::findResolve(const PcodeOp *op,int4 slot)

{
  const Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0)
    return res->getDatatype();
  return arrayof;		// If not calculated before, assume referring to the element
}

int4 TypeArray::findCompatibleResolve(Datatype *ct) const

{
  if (ct->needsResolution() && !arrayof->needsResolution()) {
    if (ct->findCompatibleResolve(arrayof) >= 0)
      return 0;
  }
  if (arrayof == ct)
    return 0;
  return -1;
}

/// Parse a \<type> element with a child describing the array element data-type.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypeArray::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  decodeBasic(decoder);
  arraysize = -1;
  decoder.rewindAttributes();
  for(;;) {
    uint4 attrib = decoder.getNextAttributeId();
    if (attrib == 0) break;
    if (attrib == ATTRIB_ARRAYSIZE) {
      arraysize = decoder.readSignedInteger();
    }
  }
  arrayof = typegrp.decodeType(decoder);
  if ((arraysize<=0)||(arraysize*arrayof->getAlignSize()!=size))
    throw LowlevelError("Bad size for array of type "+arrayof->getName());
  alignment = arrayof->getAlignment();
  if (arraysize == 1)
    flags |= needs_resolution;		// Array of size 1 needs special treatment
//  decoder.closeElement(elemId);
}

TypeEnum::TypeEnum(const TypeEnum &op) : TypeBase(op)

{
  namemap = op.namemap;
}

/// \param val is the given value to test
/// \return \b true if \b this enumeration has a name with the value
bool TypeEnum::hasNamedValue(uintb val) const

{
  return (namemap.find(val) != namemap.end());
}

/// Given a specific value of the enumeration, calculate the named representation of that value.
/// The representation is returned as a list of names that must logically ORed and possibly complemented.
/// If no representation is possible, no names will be returned.
/// \param val is the value to find the representation for
/// \param rep will contain the individual names in the representation and other transforms
void TypeEnum::getMatches(uintb val,Representation &rep) const

{
  map<uintb,string>::const_iterator iter;
  int4 count;

  for(count=0;count<2;++count) {
    bool allmatch = true;
    if (val == 0) {	// Zero handled specially
      iter = namemap.find(val);
      if (iter != namemap.end())
	rep.matchname.push_back( (*iter).second );
      else
	allmatch = false;
    }
    else {
      uintb bitsleft = val;
      uintb target = val;
      while(target != 0) {
	// Find named value that matches the largest number of most significant bits in bitsleft
	iter = namemap.upper_bound(target);
	if (iter == namemap.begin()) break;	// All named values are greater than target
	--iter;					// Biggest named value less than or equal to target
	uintb curval = (*iter).first;
	uintb diff = coveringmask(bitsleft ^ curval);
	if (diff >= bitsleft) break;		// Could not match most significant bit of bitsleft
	if ((curval & diff) == 0) {
	  // Found a named value that matches at least most significant bit of bitsleft
	  rep.matchname.push_back( (*iter).second );	// Accept the name
	  bitsleft ^= curval;				// Remove the bits from bitsleft
	  target = bitsleft;				// Continue searching for named value that match the new bitsleft
	}
	else {
	  // Not all the (one) bits of curval match into bitsleft, but we can restrict a further search.
	  // Bits above diff in curval are the maximum we can hope to match with one named value.
	  // Zero out bits below this and prepare to search at or below this value
	  target = curval & ~diff;
	}
      }
      allmatch = (bitsleft == 0);
    }
    if (allmatch) {			// If we have a complete representation
      rep.complement = (count==1);	// Set whether we represented original value or complement
      return;
    }
    val = val ^ calc_mask(size);	// Switch value we are trying to represent (to complement)
    rep.matchname.clear();		// Clear out old attempt
  }
  // If we reach here, no representation was possible, -matchname- is empty
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

void TypeEnum::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic((metatype == TYPE_INT) ? TYPE_ENUM_INT : TYPE_ENUM_UINT,-1,encoder);
  map<uintb,string>::const_iterator iter;
  for(iter=namemap.begin();iter!=namemap.end();++iter) {
    encoder.openElement(ELEM_VAL);
    encoder.writeString(ATTRIB_NAME,(*iter).second);
    encoder.writeUnsignedInteger(ATTRIB_VALUE, (*iter).first);
    encoder.closeElement(ELEM_VAL);
  }
  encoder.closeElement(ELEM_TYPE);
}

/// Parse a \<type> element with children describing each specific enumeration value.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
/// \return any warning associated with the enum
string TypeEnum::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  decodeBasic(decoder);
  metatype = (metatype == TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT;	// Use TYPE_INT or TYPE_UINT internally
  map<uintb,string> nmap;
  string warning;

  for(;;) {
    uint4 childId = decoder.openElement();
    if (childId == 0) break;
    uintb val = 0;
    string nm;
    for(;;) {
      uint4 attrib = decoder.getNextAttributeId();
      if (attrib == 0) break;
      if (attrib == ATTRIB_VALUE) {
	intb valsign = decoder.readSignedInteger();	// Value might be negative
	val = (uintb)valsign & calc_mask(size);
      }
      else if (attrib == ATTRIB_NAME)
	nm = decoder.readString();
    }
    if (nm.size() == 0)
      throw LowlevelError(name + ": TypeEnum field missing name attribute");
    if (nmap.find(val) != nmap.end()) {
      if (warning.empty())
	warning = "Enum \"" + name + "\": Some values do not have unique names";
    }
    else
      nmap[val] = nm;
    decoder.closeElement(childId);
  }
  setNameMap(nmap);
//  decoder.closeElement(elemId);
  return warning;
}

/// Establish unique enumeration values for a TypeEnum.
/// Fill in any values for any names that weren't explicitly assigned and check for duplicates.
/// \param nmap will contain the map from values to names
/// \param namelist is the list of names in the enumeration
/// \param vallist is the corresponding list of values assigned to names in namelist
/// \param assignlist is true if the corresponding name in namelist has an assigned value
/// \param te is the TypeEnum that will eventually hold the enumeration values
void TypeEnum::assignValues(map<uintb,string> &nmap,const vector<string> &namelist,vector<uintb> &vallist,
			    const vector<bool> &assignlist,const TypeEnum *te)
{
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
      if (mapiter != nmap.end()) {
	throw LowlevelError("Enum \""+te->name+"\": \""+namelist[i]+"\" is a duplicate value");
      }
      nmap[val] = namelist[i];
    }
  }
  for(uint4 i=0;i<namelist.size();++i) {
    uintb val;
    if (!assignlist[i]) {
      do {
	maxval += 1;
	val = maxval;
	val &= mask;
	mapiter = nmap.find(val);
      } while(mapiter != nmap.end());
      nmap[val] = namelist[i];
    }
  }
}

TypeStruct::TypeStruct(const TypeStruct &op)
  : Datatype(op)
{
  setFields(op.field,op.size,op.alignment);
  alignSize = op.alignSize;
}

/// Copy a list of fields into this structure, establishing its size and alignment.
/// Should only be called once when constructing the type.
/// \param fd is the list of fields to copy in
/// \param newSize is the final size of the structure in bytes
/// \param newAlign is the final alignment of the structure
void TypeStruct::setFields(const vector<TypeField> &fd,int4 newSize,int4 newAlign)

{
  field = fd;
  size = newSize;
  alignment = newAlign;
  if (field.size() == 1) {			// A single field
    if (field[0].type->getSize() == size)	// that fills the whole structure
      flags |= needs_resolution;		// needs special attention
  }
  alignSize = calcAlignSize(size,alignment);
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

const TypeField *TypeStruct::findTruncation(int8 off,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const

{
  int4 i;
  int4 noff;

  i = getFieldIter(off);
  if (i < 0) return (const TypeField *)0;
  const TypeField &curfield( field[i] );
  noff = off - curfield.offset;
  if (noff+sz > curfield.type->getSize()) // Requested piece spans more than one field
    return (const TypeField *)0;
  newoff = noff;
  return &curfield;
}

Datatype *TypeStruct::getSubType(int8 off,int8 *newoff) const

{				// Go down one level to field that contains offset
  int4 i;

  i = getFieldIter(off);
  if (i < 0) return Datatype::getSubType(off,newoff);
  const TypeField &curfield( field[i] );
  *newoff = off - curfield.offset;
  return curfield.type;
}

int4 TypeStruct::getHoleSize(int4 off) const

{
  int4 i = getLowerBoundField(off);
  if (i >= 0) {
    const TypeField &curfield( field[i] );
    int4 newOff = off - curfield.offset;
    if (newOff < curfield.type->getSize())
      return curfield.type->getHoleSize(newOff);
  }
  i += 1;				// advance to first field following off
  if (i < field.size()) {
    return field[i].offset - off;	// Distance to following field
  }
  return getSize() - off;		// Distance to end of structure
}

Datatype *TypeStruct::nearestArrayedComponentBackward(int8 off,int8 *newoff,int8 *elSize) const

{
  int4 firstIndex = getLowerBoundField(off);
  int4 i = firstIndex;
  while(i >= 0) {
    const TypeField &subfield( field[i] );
    int8 diff = off - subfield.offset;
    if (diff > 128) break;
    Datatype *subtype = subfield.type;
    if (subtype->getMetatype() == TYPE_ARRAY) {
      *newoff = diff;
      *elSize = ((TypeArray *)subtype)->getBase()->getAlignSize();
      return subtype;
    }
    else {
      int8 suboff;
      int8 remain = (i == firstIndex) ? diff : subtype->getSize() - 1;
      Datatype *res = subtype->nearestArrayedComponentBackward(remain, &suboff, elSize);
      if (res != (Datatype *)0) {
	*newoff = diff;
	return subtype;
      }
    }
    i -= 1;
  }
  return (Datatype *)0;
}

Datatype *TypeStruct::nearestArrayedComponentForward(int8 off,int8 *newoff,int8 *elSize) const

{
  int4 i = getLowerBoundField(off);
  int8 remain;
  if (i < 0) {		// No component starting before off
    i += 1;		// First component starting after
    remain = 0;
  }
  else {
    const TypeField &subfield( field[i] );
    remain = off - subfield.offset;
    if (remain != 0 && (subfield.type->getMetatype() != TYPE_STRUCT || remain >= subfield.type->getSize())) {
      i += 1;		// Middle of non-structure that we must go forward from, skip over it
      remain = 0;
    }
  }
  while(i<field.size()) {
    const TypeField &subfield( field[i] );
    int8 diff = subfield.offset - off;		// The first struct field examined may have a negative diff
    if (diff > 128) break;
    Datatype *subtype = subfield.type;
    if (subtype->getMetatype() == TYPE_ARRAY) {
      *newoff = -diff;
      *elSize = ((TypeArray *)subtype)->getBase()->getAlignSize();
      return subtype;
    }
    else {
      int8 suboff;
      Datatype *res = subtype->nearestArrayedComponentForward(remain, &suboff, elSize);
      if (res != (Datatype *)0) {
	*newoff = -diff;
	return subtype;
      }
    }
    i += 1;
    remain = 0;
  }
  return (Datatype *)0;
}

int4 TypeStruct::compare(const Datatype &op,int4 level) const
{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
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
  int4 res = Datatype::compareDependency(op);
  if (res != 0) return res;
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

void TypeStruct::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,alignment,encoder);
  vector<TypeField>::const_iterator iter;
  for(iter=field.begin();iter!=field.end();++iter) {
    (*iter).encode(encoder);
  }
  encoder.closeElement(ELEM_TYPE);
}

/// Read children of the structure element describing each field.  Alignment is calculated from fields unless
/// the \b alignment field is already >0. The fields must be in order, fit within the \b size field, have a
/// valid name, and have a valid data-type, or an exception is thrown. Any fields that overlap their previous
/// field are thrown out and a warning message is returned.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning the new structure
/// \return any warning associated with the structure
string TypeStruct::decodeFields(Decoder &decoder,TypeFactory &typegrp)

{
  int4 calcAlign = 1;
  int4 calcSize = 0;
  int4 lastOff = -1;
  string warning;
  while(decoder.peekElement() != 0) {
    field.emplace_back(decoder,typegrp);
    TypeField &curField(field.back());
    if (curField.type == (Datatype *)0 || curField.type->getMetatype() == TYPE_VOID)
      throw LowlevelError("Bad field data-type for structure: "+getName());
    if (curField.name.size() == 0)
      throw LowlevelError("Bad field name for structure: "+getName());
    if (curField.offset < lastOff)
      throw LowlevelError("Fields are out of order");
    lastOff = curField.offset;
    if (curField.offset < calcSize) {
      ostringstream s;
      if (warning.empty()) {
  	s << "Struct \"" << name << "\": ignoring overlapping field \"" << curField.name << "\"";
      }
      else {
  	s << "Struct \"" << name << "\": ignoring multiple overlapping fields";
      }
      warning = s.str();
      field.pop_back();		// Throw out the overlapping field
      continue;
    }
    calcSize = curField.offset + curField.type->getSize();
    if (calcSize > size) {
      ostringstream s;
      s << "Field " << curField.name << " does not fit in structure " + name;
      throw LowlevelError(s.str());
    }
    int4 curAlign = curField.type->getAlignment();
    if (curAlign > calcAlign)
      calcAlign = curAlign;
  }
  if (size == 0)		// Old way to indicate an incomplete structure
    flags |= type_incomplete;
  if (field.size() > 0)
    markComplete();		// If we have fields, mark as complete
  if (field.size() == 1) {			// A single field
    if (field[0].type->getSize() == size)	// that fills the whole structure
      flags |= needs_resolution;		// needs special resolution
  }
  if (alignment < 1)
    alignment = calcAlign;
  alignSize = calcAlignSize(size, alignment);
  return warning;
}

/// If this method is called, the given data-type has a single component that fills it entirely
/// (either a field or an element). The indicated Varnode can be resolved either by naming the
/// data-type or naming the component. This method returns an indication of the best fit:
/// either 0 for the component or -1 for the data-type.
/// \param parent is the given data-type with a single component
/// \param op is the given PcodeOp using the Varnode
/// \param slot is -1 if the Varnode is an output or >=0 indicating the input slot
/// \return either 0 to indicate the field or -1 to indicate the structure
int4 TypeStruct::scoreSingleComponent(Datatype *parent,PcodeOp *op,int4 slot)

{
  if (op->code() == CPUI_COPY || op->code() == CPUI_INDIRECT) {
    Varnode *vn;
    if (slot == 0)
      vn = op->getOut();
    else
      vn = op->getIn(0);
    if (vn->isTypeLock() && vn->getType() == parent)
      return -1;	// COPY of the structure directly, use whole structure
  }
  else if ((op->code() == CPUI_LOAD && slot == -1)||(op->code() == CPUI_STORE && slot == 2)) {
    Varnode *vn = op->getIn(1);
    if (vn->isTypeLock()) {
      Datatype *ct = vn->getTypeReadFacing(op);
      if (ct->getMetatype() == TYPE_PTR && ((TypePointer *)ct)->getPtrTo() == parent)
	return -1;	// LOAD or STORE of the structure directly, use whole structure
    }
  }
  else if (op->isCall()) {
    Funcdata *fd = op->getParent()->getFuncdata();
    FuncCallSpecs *fc = fd->getCallSpecs(op);
    if (fc != (FuncCallSpecs *)0) {
      ProtoParameter *param = (ProtoParameter *)0;
      if (slot >= 1 && fc->isInputLocked())
	param = fc->getParam(slot-1);
      else if (slot < 0 && fc->isOutputLocked())
	param = fc->getOutput();
      if (param != (ProtoParameter *)0 && param->getType() == parent)
	return -1;	// Function signature refers to parent directly, resolve to parent
    }
  }
  return 0;	// In all other cases resolve to the component
}

Datatype *TypeStruct::resolveInFlow(PcodeOp *op,int4 slot)

{
  Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0)
    return res->getDatatype();

  int4 fieldNum = scoreSingleComponent(this,op,slot);

  ResolvedUnion compFill(this,fieldNum,*fd->getArch()->types);
  fd->setUnionField(this, op, slot, compFill);
  return compFill.getDatatype();
}

Datatype *TypeStruct::findResolve(const PcodeOp *op,int4 slot)

{
  const Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0)
    return res->getDatatype();
  return field[0].type;		// If not calculated before, assume referring to field
}

int4 TypeStruct::findCompatibleResolve(Datatype *ct) const

{
  Datatype *fieldType = field[0].type;
  if (ct->needsResolution() && !fieldType->needsResolution()) {
    if (ct->findCompatibleResolve(fieldType) >= 0)
      return 0;
  }
  if (fieldType == ct)
    return 0;
  return -1;
}

/// Assign an offset to fields in order so that each field starts at an aligned offset within the structure
/// \param list is the list of fields
/// \param newSize passes back the calculated size of the structure
/// \param newAlign passes back the calculated alignment
void TypeStruct::assignFieldOffsets(vector<TypeField> &list,int4 &newSize,int4 &newAlign)

{
  int4 offset = 0;
  newAlign = 1;
  vector<TypeField>::iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) {
    if ((*iter).type->getMetatype() == TYPE_VOID)
      throw LowlevelError("Illegal field data-type: void");
    if ((*iter).offset != -1) continue;
    int4 cursize = (*iter).type->getAlignSize();
    int4 align = (*iter).type->getAlignment();
    if (align > newAlign)
      newAlign = align;
    align -= 1;
    if (align > 0 && (offset & align)!=0)
      offset = (offset-(offset & align) + (align+1));
    (*iter).offset = offset;
    (*iter).ident = offset;
    offset += cursize;
  }
  newSize = calcAlignSize(offset, newAlign);
}

/// Copy a list of fields into this union, establishing its size.
/// Should only be called once when constructing the type.  TypeField \b offset is assumed to be 0.
/// Size is calculated from the fields unless a \b fixedSize (>0) is passed in.
/// Alignment is calculated from fields unless a \b fixedAlign (>0) is passed in.
/// \param fd is the list of fields to copy in
/// \param newSize is new size in bytes of the union
/// \param newAlign is the new alignment
void TypeUnion::setFields(const vector<TypeField> &fd,int4 newSize,int4 newAlign)

{
  field = fd;
  size = newSize;
  alignment = newAlign;
  alignSize = calcAlignSize(size,alignment);
}

/// Parse children of the \<type> element describing each field.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning the new union
void TypeUnion::decodeFields(Decoder &decoder,TypeFactory &typegrp)

{
  int4 calcAlign = 1;
  while(decoder.peekElement() != 0) {
    field.emplace_back(decoder,typegrp);
    if (field.back().offset + field.back().type->getSize() > size) {
      ostringstream s;
      s << "Field " << field.back().name << " does not fit in union " << name;
      throw LowlevelError(s.str());
    }
    int4 curAlign = field.back().type->getAlignment();
    if (curAlign > calcAlign)
      calcAlign = curAlign;
  }
  if (size == 0)		// Old way to indicate union is incomplete
    flags |= type_incomplete;
  if (field.size() > 0)
    markComplete();		// If we have fields, the union is complete
  if (alignment < 1)
    alignment = calcAlign;
  alignSize = calcAlignSize(size,alignment);
}

TypeUnion::TypeUnion(const TypeUnion &op)
  : Datatype(op)
{
  setFields(op.field,op.size,op.alignment);
  alignSize = op.alignSize;
}

int4 TypeUnion::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  const TypeUnion *tu = (const TypeUnion *)&op;
  vector<TypeField>::const_iterator iter1,iter2;

  if (field.size() != tu->field.size()) return (tu->field.size()-field.size());
  iter1 = field.begin();
  iter2 = tu->field.begin();
  // Test only the name and first level metatype first
  while(iter1 != field.end()) {
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
  iter2 = tu->field.begin();
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

int4 TypeUnion::compareDependency(const Datatype &op) const

{
  int4 res = Datatype::compareDependency(op);
  if (res != 0) return res;
  const TypeUnion *tu = (const TypeUnion *)&op;
  vector<TypeField>::const_iterator iter1,iter2;

  if (field.size() != tu->field.size()) return (tu->field.size()-field.size());
  iter1 = field.begin();
  iter2 = tu->field.begin();
  // Test only the name and first level metatype first
  while(iter1 != field.end()) {
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

void TypeUnion::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,alignment,encoder);
  vector<TypeField>::const_iterator iter;
  for(iter=field.begin();iter!=field.end();++iter) {
    (*iter).encode(encoder);
  }
  encoder.closeElement(ELEM_TYPE);
}

Datatype *TypeUnion::resolveInFlow(PcodeOp *op,int4 slot)

{
  Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0)
    return res->getDatatype();
  ScoreUnionFields scoreFields(*fd->getArch()->types,this,op,slot);
  fd->setUnionField(this, op, slot, scoreFields.getResult());
  return scoreFields.getResult().getDatatype();
}

Datatype* TypeUnion::findResolve(const PcodeOp *op,int4 slot)

{
  const Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0)
    return res->getDatatype();
  return this;
}

const TypeField *TypeUnion::resolveTruncation(int8 offset,PcodeOp *op,int4 slot,int8 &newoff)

{
  Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0) {
    if (res->getFieldNum() >= 0) {
      const TypeField *field = getField(res->getFieldNum());
      newoff = offset - field->offset;
      return field;
    }
  }
  else if (op->code() == CPUI_SUBPIECE && slot == 1) {	// The slot is artificial in this case
    ScoreUnionFields scoreFields(*fd->getArch()->types,this,offset,op);
    fd->setUnionField(this, op, slot, scoreFields.getResult());
    if (scoreFields.getResult().getFieldNum() >= 0) {
      newoff = 0;
      return getField(scoreFields.getResult().getFieldNum());
    }
  }
  else {
    ScoreUnionFields scoreFields(*fd->getArch()->types,this,offset,op,slot);
    fd->setUnionField(this, op, slot, scoreFields.getResult());
    if (scoreFields.getResult().getFieldNum() >= 0) {
      const TypeField *field = getField(scoreFields.getResult().getFieldNum());
      newoff = offset - field->offset;
      return field;
    }
  }
  return (const TypeField *)0;
}

/// \param offset is the byte offset of the truncation
/// \param sz is the number of bytes in the resulting truncation
/// \param op is the PcodeOp reading the truncated value
/// \param slot is the input slot being read
/// \param newoff is used to pass back any remaining offset into the field which still must be resolved
/// \return the field to use with truncation or null if there is no appropriate field
const TypeField *TypeUnion::findTruncation(int8 offset,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const

{
  // No new scoring is done, but if a cached result is available, return it.
  const Funcdata *fd = op->getParent()->getFuncdata();
  const ResolvedUnion *res = fd->getUnionField(this, op, slot);
  if (res != (ResolvedUnion *)0 && res->getFieldNum() >= 0) {
    const TypeField *field = getField(res->getFieldNum());
    newoff = offset - field->offset;
    if (newoff + sz > field->type->getSize())
      return (const TypeField *)0;	// Truncation spans more than one field
    return field;
  }
  return (const TypeField *)0;
}

int4 TypeUnion::findCompatibleResolve(Datatype *ct) const

{
  if (!ct->needsResolution()) {
    for(int4 i=0;i<field.size();++i) {
      if (field[i].type == ct && field[i].offset == 0)
	return i;
    }
  }
  else {
    for(int4 i=0;i<field.size();++i) {
      if (field[i].offset != 0) continue;
      Datatype *fieldType = field[i].type;
      if (fieldType->getSize() != ct->getSize()) continue;
      if (fieldType->needsResolution()) continue;
      if (ct->findCompatibleResolve(fieldType) >= 0)
	return i;
    }
  }
  return -1;
}

void TypeUnion::assignFieldOffsets(vector<TypeField> &list,int4 &newSize,int4 &newAlign,TypeUnion *tu)

{
  vector<TypeField>::iterator iter;

  newSize = 0;
  newAlign = 1;
  for(iter=list.begin();iter!=list.end();++iter) {
    Datatype *ct = (*iter).type;
    // Do some sanity checks on the field
    if (ct == (Datatype *)0 || ct->getMetatype() == TYPE_VOID)
      throw LowlevelError("Bad field data-type for union: "+tu->getName());
    else if ((*iter).name.size() == 0)
      throw LowlevelError("Bad field name for union: "+tu->getName());
    (*iter).offset = 0;
    int4 end = ct->getSize();
    if (end > newSize)
      newSize = end;
    int4 curAlign = ct->getAlignment();
    if (curAlign > newAlign)
      newAlign = curAlign;
  }
}

TypePartialEnum::TypePartialEnum(const TypePartialEnum &op)
  : TypeEnum(op)
{
  stripped = op.stripped;
  parent = op.parent;
  offset = op.offset;
}

TypePartialEnum::TypePartialEnum(TypeEnum *par,int4 off,int4 sz,Datatype *strip)
  : TypeEnum(sz, TYPE_PARTIALENUM)
{
  flags |= has_stripped;
  stripped = strip;
  parent = par;
  offset = off;
}

void TypePartialEnum::printRaw(ostream &s) const

{
  parent->printRaw(s);
  s << "[off=" << dec << offset << ",sz=" << size << ']';
}

bool TypePartialEnum::hasNamedValue(uintb val) const

{
  val <<= 8*offset;
  return parent->hasNamedValue(val);
}

void TypePartialEnum::getMatches(uintb val,Representation &rep) const

{
  val <<= 8*offset;
  rep.shiftAmount = offset * 8;
  parent->getMatches(val,rep);
}

int4 TypePartialEnum::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  // Both must be partial
  TypePartialEnum *tp = (TypePartialEnum *) &op;
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  return parent->compare(*tp->parent,level); // Compare the underlying union
}

int4 TypePartialEnum::compareDependency(const Datatype &op) const

{
  if (submeta != op.getSubMeta()) return (submeta < op.getSubMeta()) ? -1 : 1;
  TypePartialEnum *tp = (TypePartialEnum *) &op;	// Both must be partial
  if (parent != tp->parent) return (parent < tp->parent) ? -1 : 1;	// Compare absolute pointers
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  return (op.getSize()-size);
}

void TypePartialEnum::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_TYPE);
  encodeBasic(TYPE_PARTIALENUM,-1,encoder);
  encoder.writeSignedInteger(ATTRIB_OFFSET, offset);
  parent->encodeRef(encoder);
  encoder.closeElement(ELEM_TYPE);
}

TypePartialStruct::TypePartialStruct(const TypePartialStruct &op)
  : Datatype(op)
{
  stripped = op.stripped;
  container = op.container;
  offset = op.offset;
}

TypePartialStruct::TypePartialStruct(Datatype *contain,int4 off,int4 sz,Datatype *strip)
  : Datatype(sz,1,TYPE_PARTIALSTRUCT)
{
#ifdef CPUI_DEBUG
  if (contain->getMetatype() != TYPE_STRUCT && contain->getMetatype() != TYPE_ARRAY)
    throw LowlevelError("Parent of partial struct is not a structure or array");
#endif
  flags |= has_stripped;
  stripped = strip;
  container = contain;
  offset = off;
}

/// If the parent is an array, return the element data-type. Otherwise return the \b stripped data-type.
/// \return the array element data-type or the \b stripped data-type.
Datatype *TypePartialStruct::getComponentForPtr(void) const

{
  if (container->getMetatype() == TYPE_ARRAY) {
    Datatype *eltype = ((TypeArray *)container)->getBase();
    if (eltype->getMetatype() != TYPE_UNKNOWN && (offset % eltype->getAlignSize()) == 0)
      return eltype;
  }
  return stripped;
}

void TypePartialStruct::printRaw(ostream &s) const

{
  container->printRaw(s);
  s << "[off=" << dec << offset << ",sz=" << size << ']';
}

Datatype *TypePartialStruct::getSubType(int8 off,int8 *newoff) const

{
  int8 sizeLeft = size - off;
  off += offset;
  Datatype *ct = container;
  do {
    ct = ct->getSubType(off, newoff);
    if (ct == (Datatype *)0)
      break;
    off = *newoff;
    // Component can extend beyond range of this partial, in which case we go down another level
  } while(ct->getSize() - off > sizeLeft);
  return ct;
}

int4 TypePartialStruct::getHoleSize(int4 off) const

{
  int4 sizeLeft = size-off;
  off += offset;
  int4 res = container->getHoleSize(off);
  if (res > sizeLeft)
    res = sizeLeft;
  return res;
}

int4 TypePartialStruct::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  // Both must be partial
  TypePartialStruct *tp = (TypePartialStruct *) &op;
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  return container->compare(*tp->container,level); // Compare the underlying union
}

int4 TypePartialStruct::compareDependency(const Datatype &op) const

{
  if (submeta != op.getSubMeta()) return (submeta < op.getSubMeta()) ? -1 : 1;
  TypePartialStruct *tp = (TypePartialStruct *) &op;	// Both must be partial
  if (container != tp->container) return (container < tp->container) ? -1 : 1;	// Compare absolute pointers
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  return (op.getSize()-size);
}

TypePartialUnion::TypePartialUnion(const TypePartialUnion &op)
  : Datatype(op)
{
  stripped = op.stripped;
  container = op.container;
  offset = op.offset;
}

TypePartialUnion::TypePartialUnion(TypeUnion *contain,int4 off,int4 sz,Datatype *strip)
  : Datatype(sz,1,TYPE_PARTIALUNION)
{
  flags |= (needs_resolution | has_stripped);
  stripped = strip;
  container = contain;
  offset = off;
}

void TypePartialUnion::printRaw(ostream &s) const

{
  container->printRaw(s);
  s << "[off=" << dec << offset << ",sz=" << size << ']';
}

const TypeField *TypePartialUnion::findTruncation(int8 off,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const

{
  return container->findTruncation(off + offset, sz, op, slot, newoff);
}

int4 TypePartialUnion::numDepend(void) const

{
  return container->numDepend();
}

Datatype *TypePartialUnion::getDepend(int4 index) const

{
  // Treat dependents as coming from the underlying union
  Datatype *res = container->getDepend(index);
  if (res->getSize() != size)	// But if the size doesn't match
    return stripped;		// Return the stripped data-type
  return res;
}

int4 TypePartialUnion::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  // Both must be partial unions
  TypePartialUnion *tp = (TypePartialUnion *) &op;
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  level -= 1;
  if (level < 0) {
    if (id == op.getId()) return 0;
    return (id < op.getId()) ? -1 : 1;
  }
  return container->compare(*tp->container,level); // Compare the underlying union
}

int4 TypePartialUnion::compareDependency(const Datatype &op) const

{
  if (submeta != op.getSubMeta()) return (submeta < op.getSubMeta()) ? -1 : 1;
  TypePartialUnion *tp = (TypePartialUnion *) &op;	// Both must be partial unions
  if (container != tp->container) return (container < tp->container) ? -1 : 1;	// Compare absolute pointers
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  return (op.getSize()-size);
}

void TypePartialUnion::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  encoder.writeSignedInteger(ATTRIB_OFFSET, offset);
  container->encodeRef(encoder);
  encoder.closeElement(ELEM_TYPE);
}

Datatype *TypePartialUnion::resolveInFlow(PcodeOp *op,int4 slot)

{
  Datatype *curType = container;
  int8 curOff = offset;
  while(curType != (Datatype *)0 && curType->getSize() > size) {
    if (curType->getMetatype() == TYPE_UNION) {
      const TypeField *field = curType->resolveTruncation(curOff, op, slot, curOff);
      curType = (field == (const TypeField *)0) ? (Datatype *)0 : field->type;
    }
    else {
      curType = curType->getSubType(curOff, &curOff);
    }
  }
  if (curType != (Datatype *)0 && curType->getSize() == size)
    return curType;
  return stripped;
}

Datatype* TypePartialUnion::findResolve(const PcodeOp *op,int4 slot)

{
  Datatype *curType = container;
  int8 curOff = offset;
  while(curType != (Datatype *)0 && curType->getSize() > size) {
    if (curType->getMetatype() == TYPE_UNION) {
      Datatype *newType = curType->findResolve(op, slot);
      curType = (newType == curType) ? (Datatype *)0 : newType;
    }
    else {
      curType = curType->getSubType(curOff, &curOff);
    }
  }
  if (curType != (Datatype *)0 && curType->getSize() == size)
    return curType;
  return stripped;
}

int4 TypePartialUnion::findCompatibleResolve(Datatype *ct) const

{
  return container->findCompatibleResolve(ct);
}

const TypeField *TypePartialUnion::resolveTruncation(int8 off,PcodeOp *op,int4 slot,int8 &newoff)

{
  return container->resolveTruncation(off + offset, op, slot, newoff);
}

/// Parse a \<type> element with children describing the data-type being pointed to
/// and the parent data-type.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypePointerRel::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  flags |= is_ptrrel;
  decodeBasic(decoder);
  metatype = TYPE_PTR;		// Don't use TYPE_PTRREL internally
  decoder.rewindAttributes();
  for(;;) {
    uint4 attrib = decoder.getNextAttributeId();
    if (attrib == 0) break;
    if (attrib == ATTRIB_WORDSIZE) {
      wordsize = decoder.readUnsignedInteger();
    }
    else if (attrib == ATTRIB_SPACE) {
      spaceid = decoder.readSpace();
    }
  }
  ptrto = typegrp.decodeType( decoder );
  parent = typegrp.decodeType( decoder );
  uint4 subId = decoder.openElement(ELEM_OFF);
  offset = decoder.readSignedInteger(ATTRIB_CONTENT);
  decoder.closeElement(subId);
  if (offset == 0)
    throw LowlevelError("For metatype=\"ptrstruct\", <off> tag must not be zero");
  submeta = SUB_PTRREL;
  if (name.size() == 0)		// If the data-type is not named
    markEphemeral(typegrp);	// it is considered ephemeral
//  decoder.closeElement(elemId);
}

/// For a variable that is a relative pointer, constant offsets relative to the variable can be
/// displayed either as coming from the variable itself or from the parent object.
/// \param addrOff is the given offset in address units
/// \return \b true if the variable should be displayed as coming from the parent
bool TypePointerRel::evaluateThruParent(uintb addrOff) const

{
  uintb byteOff = AddrSpace::addressToByte(addrOff, wordsize);
  if (ptrto->getMetatype() == TYPE_STRUCT && byteOff < ptrto->getSize())
    return false;
  byteOff = (byteOff + offset) & calc_mask(size);
  return (byteOff < parent->getSize());
}

void TypePointerRel::printRaw(ostream &s) const

{
  ptrto->printRaw(s);
  s << " *+";
  s << dec << offset;
  s << '[' ;
  parent->printRaw(s);
  s << ']';
}

int4 TypePointerRel::compare(const Datatype &op,int4 level) const

{
  int4 res = TypePointer::compare(op,level);	// Compare as plain pointers first
  if (res != 0) return res;
  // Both must be relative pointers
  TypePointerRel *tp = (TypePointerRel *) &op;
  // Its possible a formal relative pointer gets compared to its equivalent ephemeral version.
  // In which case, we prefer the formal version.
  if (stripped == (TypePointer *)0) {
    if (tp->stripped != (TypePointer *)0)
      return -1;
  }
  else {
    if (tp->stripped == (TypePointer *)0)
      return 1;
  }
  return 0;
}

int4 TypePointerRel::compareDependency(const Datatype &op) const

{
  if (submeta != op.getSubMeta()) return (submeta < op.getSubMeta()) ? -1 : 1;
  const TypePointerRel *tp = (const TypePointerRel*)&op;	// Both must be TypePointerRel
  if (ptrto != tp->ptrto) return (ptrto < tp->ptrto) ? -1 : 1;	// Compare absolute pointers
  if (offset != tp->offset) return (offset < tp->offset) ? -1 : 1;
  if (parent != tp->parent) return (parent < tp->parent) ? -1 : 1;

  if (wordsize != tp->wordsize) return (wordsize < tp->wordsize) ? -1 : 1;
  return (op.getSize()-size);
}

void TypePointerRel::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_TYPE);
  encodeBasic(TYPE_PTRREL,-1,encoder);	// Override the metatype for XML
  if (wordsize != 1)
    encoder.writeUnsignedInteger(ATTRIB_WORDSIZE, wordsize);
  ptrto->encode(encoder);
  parent->encodeRef(encoder);
  encoder.openElement(ELEM_OFF);
  encoder.writeSignedInteger(ATTRIB_CONTENT, offset);
  encoder.closeElement(ELEM_OFF);
  encoder.closeElement(ELEM_TYPE);
}

TypePointer *TypePointerRel::downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap,
				       TypeFactory &typegrp)
{
  type_metatype ptrtoMeta = ptrto->getMetatype();
  if (off >= 0 && off < ptrto->getSize() && (ptrtoMeta == TYPE_STRUCT || ptrtoMeta == TYPE_ARRAY)) {
    return TypePointer::downChain(off,par,parOff,allowArrayWrap,typegrp);
  }
  int8 relOff = (off + offset) & calc_mask(size);		// Convert off to be relative to the parent container
  if (relOff < 0 || relOff >= parent->getSize())
    return (TypePointer *)0;			// Don't let pointer shift beyond original container

  TypePointer *origPointer = typegrp.getTypePointer(size, parent, wordsize);
  off = relOff;
  if (relOff == 0 && offset != 0)	// Recovering the start of the parent is still downchaining, even though the parent may be the container
    return origPointer;	// So we return the pointer to the parent and don't drill down to field at offset 0
  return origPointer->downChain(off,par,parOff,allowArrayWrap,typegrp);
}

bool TypePointerRel::isPtrsubMatching(int8 off,int8 extra,int8 multiplier) const

{
  if (stripped != (TypePointer *)0)
    return TypePointer::isPtrsubMatching(off,extra,multiplier);
  int4 iOff = AddrSpace::addressToByteInt(off,wordsize);
  extra = AddrSpace::addressToByteInt(extra, wordsize);
  iOff += offset + extra;
  return (iOff >= 0 && iOff <= parent->getSize());
}

/// \brief Given a containing data-type and offset, find the "pointed to" data-type suitable for a TypePointerRel
///
/// The biggest contained data-type that starts at the exact offset is returned. If the offset is negative
/// or the is no data-type starting exactly there, an \b xunknown1 data-type is returned.
/// \param base is the given container data-type
/// \param off is the offset relative to the start of the container
/// \param typegrp is the factory owning the data-types
/// \return the "pointed to" data-type
Datatype *TypePointerRel::getPtrToFromParent(Datatype *base,int4 off,TypeFactory &typegrp)

{
  if (off > 0) {
    int8 curoff = off;
    do {
      base = base->getSubType(curoff,&curoff);
    } while(curoff != 0 && base != (Datatype *)0);
    if (base == (Datatype *)0)
      base = typegrp.getBase(1, TYPE_UNKNOWN);
  }
  else
    base = typegrp.getBase(1, TYPE_UNKNOWN);
  return base;
}

/// Turn on the data-type's function prototype
/// \param tfact is the factory that owns \b this
/// \param sig is the list of names and data-types making up the prototype
/// \param voidtype is the reference "void" data-type
void TypeCode::setPrototype(TypeFactory *tfact,const PrototypePieces &sig,Datatype *voidtype)

{
  factory = tfact;
  flags |= variable_length;
  if (proto != (FuncProto *)0)
    delete proto;
  proto = new FuncProto();
  proto->setInternal(sig.model,voidtype);

  proto->updateAllTypes(sig);
  proto->setInputLock(true);
  proto->setOutputLock(true);
}

/// The prototype is copied in.
/// \param typegrp is the factory owning \b this
/// \param fp is the prototype to set (may be null)
void TypeCode::setPrototype(TypeFactory *typegrp,const FuncProto *fp)

{
  if (proto != (FuncProto *)0) {
    delete proto;
    proto = (FuncProto *)0;
    factory = (TypeFactory *)0;
  }
  if (fp != (const FuncProto *)0) {
    factory = typegrp;
    proto = new FuncProto();
    proto->copy(*fp);
  }
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

TypeCode::TypeCode(void) : Datatype(1,1,TYPE_CODE)

{
  proto = (FuncProto *)0;
  factory = (TypeFactory *)0;
  flags |= type_incomplete;
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

/// Compare basic characteristics of \b this with another TypeCode, not including the prototype
///    -  -1 or 1 if -this- and -op- are different in surface characteristics
///    -   0 if they are exactly equal and have no parameters
///    -   2 if they are equal on the surface, but additional comparisons must be made on parameters
/// \param op is the other data-type to compare to
/// \return the comparison value
int4 TypeCode::compareBasic(const TypeCode *op) const

{
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
  uint4 myflags = proto->getComparableFlags();
  uint4 opflags = op->proto->getComparableFlags();
  if (myflags != opflags)
    return (myflags < opflags) ? -1 : 1;

  return 2;			// Carry on with comparison of parameters
}

Datatype *TypeCode::getSubType(int8 off,int8 *newoff) const

{
  if (factory == (TypeFactory *)0) return (Datatype *)0;
  *newoff = 0;
  return factory->getBase(1, TYPE_CODE);	// Return code byte unattached to function prototype
}

int4 TypeCode::compare(const Datatype &op,int4 level) const

{
  int4 res = Datatype::compare(op,level);
  if (res != 0) return res;
  const TypeCode *tc = (const TypeCode *)&op;
  res = compareBasic(tc);
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
  int4 res = Datatype::compareDependency(op);
  if (res != 0) return res;
  const TypeCode *tc = (const TypeCode *)&op;
  res = compareBasic(tc);
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

void TypeCode::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  if (proto != (FuncProto *)0)
    proto->encode(encoder);
  encoder.closeElement(ELEM_TYPE);
}

/// \param decoder is the stream decoder
void TypeCode::decodeStub(Decoder &decoder)

{
  if (decoder.peekElement() != 0) {
    // Traditionally a <prototype> tag implies variable length, without a "varlength" attribute
    flags |= variable_length;
  }
  decodeBasic(decoder);
}

/// A single child element indicates a full function prototype.
/// \param decoder is the stream decoder
/// \param isConstructor is \b true if the prototype is a constructor
/// \param isDestructor is \b true if the prototype is a destructor
/// \param typegrp is the factory owning the code object
void TypeCode::decodePrototype(Decoder &decoder,bool isConstructor,bool isDestructor,TypeFactory &typegrp)

{
  if (decoder.peekElement() != 0) {
    Architecture *glb = typegrp.getArch();
    factory = &typegrp;
    proto = new FuncProto();
    proto->setInternal( glb->defaultfp, typegrp.getTypeVoid() );
    proto->decode(decoder,glb);
    proto->setConstructor(isConstructor);
    proto->setDestructor(isDestructor);
  }
  markComplete();
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

Datatype *TypeSpacebase::getSubType(int8 off,int8 *newoff) const

{
  Scope *scope = getMap();
  uintb addrOff = AddrSpace::byteToAddress(off, spaceid->getWordSize());	// Convert from byte offset to address unit
  // It should always be the case that the given offset represents a full encoding of the
  // pointer, so the point of context is unused and the size is given as -1
  Address nullPoint;
  uintb fullEncoding;
  Address addr = glb->resolveConstant(spaceid, addrOff, -1, nullPoint, fullEncoding);
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

Datatype *TypeSpacebase::nearestArrayedComponentForward(int8 off,int8 *newoff,int8 *elSize) const

{
  Scope *scope = getMap();
  uintb addrOff = AddrSpace::byteToAddress(off, spaceid->getWordSize());	// Convert from byte offset to address unit
  // It should always be the case that the given offset represents a full encoding of the
  // pointer, so the point of context is unused and the size is given as -1
  Address nullPoint;
  uintb fullEncoding;
  Address addr = glb->resolveConstant(spaceid, addrOff, -1, nullPoint, fullEncoding);
  SymbolEntry *smallest = scope->queryContainer(addr,1,nullPoint);
  Address nextAddr;
  Datatype *symbolType;
  if (smallest == (SymbolEntry *)0 || smallest->getOffset() != 0)
    nextAddr = addr + 32;
  else {
    symbolType = smallest->getSymbol()->getType();
    if (symbolType->getMetatype() == TYPE_STRUCT) {
      int8 structOff = addr.getOffset() - smallest->getAddr().getOffset();
      int8 dummyOff;
      Datatype *res = symbolType->nearestArrayedComponentForward(structOff, &dummyOff, elSize);
      if (res != (Datatype *)0) {
	*newoff = structOff;
	return symbolType;
      }
    }
    int8 sz = AddrSpace::byteToAddressInt(smallest->getSize(), spaceid->getWordSize());
    nextAddr = smallest->getAddr() + sz;
  }
  if (nextAddr < addr)
    return (Datatype *)0;		// Don't let the address wrap
  smallest = scope->queryContainer(nextAddr,1,nullPoint);
  if (smallest == (SymbolEntry *)0 || smallest->getOffset() != 0)
    return (Datatype *)0;
  symbolType = smallest->getSymbol()->getType();
  *newoff = addr.getOffset() - smallest->getAddr().getOffset();
  if (symbolType->getMetatype() == TYPE_ARRAY) {
    *elSize = ((TypeArray *)symbolType)->getBase()->getAlignSize();
    return symbolType;
  }
  if (symbolType->getMetatype() == TYPE_STRUCT) {
    int8 dummyOff;
    Datatype *res = symbolType->nearestArrayedComponentForward(0, &dummyOff, elSize);
    if (res != (Datatype *)0)
      return symbolType;
  }
  return (Datatype *)0;
}

Datatype *TypeSpacebase::nearestArrayedComponentBackward(int8 off,int8 *newoff,int8 *elSize) const

{
  Datatype *subType = getSubType(off, newoff);
  if (subType == (Datatype *)0)
    return (Datatype *)0;
  if (subType->getMetatype() == TYPE_ARRAY) {
    *elSize = ((TypeArray *)subType)->getBase()->getAlignSize();
    return subType;
  }
  if (subType->getMetatype() == TYPE_STRUCT) {
    int8 dummyOff;
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
  int4 res = Datatype::compareDependency(op);
  if (res != 0) return res;
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

void TypeSpacebase::encode(Encoder &encoder) const

{
  if (typedefImm != (Datatype *)0) {
    encodeTypedef(encoder);
    return;
  }
  encoder.openElement(ELEM_TYPE);
  encodeBasic(metatype,-1,encoder);
  encoder.writeSpace(ATTRIB_SPACE, spaceid);
  localframe.encode(encoder);
  encoder.closeElement(ELEM_TYPE);
}

/// Parse the \<type> tag.
/// \param decoder is the stream decoder
/// \param typegrp is the factory owning \b this data-type
void TypeSpacebase::decode(Decoder &decoder,TypeFactory &typegrp)

{
//  uint4 elemId = decoder.openElement();
  decodeBasic(decoder);
  spaceid = decoder.readSpace(ATTRIB_SPACE);
  localframe = Address::decode(decoder);
//  decoder.closeElement(elemId);
}

#ifdef TYPEPROP_DEBUG
bool TypeFactory::propagatedbg_on = false;
#endif

/// Initialize an empty container
/// \param g is the owning Architecture
TypeFactory::TypeFactory(Architecture *g)

{
  glb = g;
  sizeOfInt = 0;
  sizeOfLong = 0;
  sizeOfChar = 0;
  sizeOfWChar = 0;
  sizeOfPointer = 0;
  sizeOfAltPointer = 0;
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
  for(i=0;i<5;++i)
    charcache[i] = (Datatype *)0;
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
  if (sizeOfLong == 0) {
    sizeOfLong = (sizeOfInt == 4) ? 8 : sizeOfInt;
  }
  if (sizeOfChar == 0)
    sizeOfChar = 1;
  if (sizeOfWChar == 0)
    sizeOfWChar = 2;
  if (sizeOfPointer == 0)
    sizeOfPointer = glb->getDefaultDataSpace()->getAddrSize();
  SegmentOp *segOp = glb->getSegmentOp(glb->getDefaultDataSpace());
  if (segOp != (SegmentOp *)0 && segOp->hasFarPointerSupport()) {
    sizeOfPointer = segOp->getInnerSize();
    sizeOfAltPointer = sizeOfPointer + segOp->getBaseSize();
  }
  if (alignMap.empty())
    setDefaultAlignmentMap();
  if (enumsize == 0) {
    enumsize = glb->getDefaultSize();
    enumtype = TYPE_ENUM_UINT;
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
      if (ct->isCharPrint()) {
	if (ct->getSize() < 5)
	  charcache[ct->getSize()] = ct;
	if (ct->isASCII()) { 	// Char is preferred over other int types
	  typecache[ct->getSize()][ct->getMetatype()-TYPE_FLOAT] = ct;
	}
	// Other character types (UTF16,UTF32) are not preferred
	break;
      }
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
  warnings.clear();
  incompleteTypedef.clear();
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
  warnings.clear();
  incompleteTypedef.clear();
}

TypeFactory::~TypeFactory(void)

{
  clear();
}

/// Return the alignment associated with a primitive data-type of the given size
/// \param size is the aligned size in bytes of the primitive
/// \return the expected alignment in bytes
int4 TypeFactory::getAlignment(uint4 size) const

{
  if (size >= alignMap.size()) {
    if (alignMap.empty())
      throw LowlevelError("TypeFactory alignment map not initialized");
    return alignMap[alignMap.size()-1];
  }
  return alignMap[size];
}

/// Return the amount of room a data-type takes up in memory, which may be larger than the
/// raw number of bytes in the data-type.  This is the size consistent with the \b sizeof operator
/// in C.
/// \param size is the raw number of bytes in the data-type
/// \return the aligned size
int4 TypeFactory::getPrimitiveAlignSize(uint4 size) const

{
  int4 align = getAlignment(size);
  uint4 mod = size % align;
  if (mod != 0)
    size += (align-mod);
  return size;
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
/// \param sz is the given distinguishing size if non-zero
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

/// Internal method for finally inserting a new Datatype pointer
/// \param newtype is the new pointer
void TypeFactory::insert(Datatype *newtype)

{
  pair<DatatypeSet::iterator,bool> insres = tree.insert(newtype);
  if (!insres.second) {
    ostringstream s;
    s << "Shared type id: " << hex << newtype->getId() << endl;
    s << "  ";
    newtype->printRaw(s);
    s << " : ";
    (*insres.first)->printRaw(s);
    delete newtype;
    throw LowlevelError(s.str());
  }
  if (newtype->id!=0)
    nametree.insert(newtype);
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
      throw LowlevelError("Datatype must have a valid id: "+ct.name);
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
  if (newtype->alignment < 0) {
    newtype->alignSize = getPrimitiveAlignSize(newtype->size);
    newtype->alignment = getAlignment(newtype->alignSize);
  }
  insert(newtype);
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
  ct->displayName = n;
  if (ct->id == 0)
    ct->id = Datatype::hashName(n);
				// Insert type with new name
  tree.insert(ct);
  nametree.insert( ct );	// Re-insert name reference
  return ct;
}

/// The display format for the data-type is changed based on the given format.  A value of
/// zero clears any preexisting format.  Otherwise the value can be one of:
/// 1=\b hex, 2=\b dec, 4=\b oct, 8=\b bin, 16=\b char
/// \param ct is the given data-type to change
/// \param format is the given format
void TypeFactory::setDisplayFormat(Datatype *ct,uint4 format)

{
  ct->setDisplayFormat(format);
}

/// Set fields on a structure data-type, establishing its size, alignment, and other properties.
/// This method should only be used on an incomplete structure. It will mark the structure as complete.
/// \param fd is the list of fields to set
/// \param ot is the TypeStruct object to modify
/// \param newSize is the new size of the structure in bytes
/// \param newAlign is the new alignment of the structure
/// \param flags are other flags to set on the structure
void TypeFactory::setFields(const vector<TypeField> &fd,TypeStruct *ot,int4 newSize,int4 newAlign,uint4 flags)

{
  if (!ot->isIncomplete())
    throw LowlevelError("Can only set fields on an incomplete structure");

  tree.erase(ot);
  ot->setFields(fd,newSize,newAlign);
  ot->flags &= ~(uint4)Datatype::type_incomplete;
  ot->flags |= (flags & (Datatype::opaque_string | Datatype::variable_length | Datatype::type_incomplete));
  tree.insert(ot);
  recalcPointerSubmeta(ot, SUB_PTR);
  recalcPointerSubmeta(ot, SUB_PTR_STRUCT);
}

/// This method should only be used on an incomplete union. It will mark the union as complete.
/// \param fd is the list of fields to set
/// \param ot is the TypeUnion object to modify
/// \param newSize is the size to associate with the union in bytes
/// \param newAlign is the alignment to set
/// \param flags are other flags to set on the union
void TypeFactory::setFields(const vector<TypeField> &fd,TypeUnion *ot,int4 newSize,int4 newAlign,uint4 flags)

{
  if (!ot->isIncomplete())
    throw LowlevelError("Can only set fields on an incomplete union");

  tree.erase(ot);
  ot->setFields(fd,newSize,newAlign);
  ot->flags &= ~(uint4)Datatype::type_incomplete;
  ot->flags |= (flags & (Datatype::variable_length | Datatype::type_incomplete));
  tree.insert(ot);
}

/// The given prototype is copied into the given code data-type
/// This method should only be used on an incomplete TypeCode. It will mark the TypeCode as complete.
/// \param fp is the given prototype to copy
/// \param newCode is the given code data-type
/// \param flags are additional flags to transfer into the code data-type
void TypeFactory::setPrototype(const FuncProto *fp,TypeCode *newCode,uint4 flags)

{
  if (!newCode->isIncomplete())
    throw LowlevelError("Can only set prototype on incomplete data-type");
  tree.erase(newCode);
  newCode->setPrototype(this,fp);
  newCode->flags &= ~(uint4)Datatype::type_incomplete;
  newCode->flags |= (flags & (Datatype::variable_length | Datatype::type_incomplete));
  tree.insert(newCode);
}

/// \param nmap is the mapping from integer value to name string
/// \param te is the enumeration whose values/names are set
void TypeFactory::setEnumValues(const map<uintb,string> &nmap,TypeEnum *te)

{
  tree.erase(te);
  te->setNameMap(nmap);
  tree.insert(te);
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
  if (ct->typedefImm != (Datatype *)0)
    orderRecurse(deporder,mark,ct->typedefImm);
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
  tv.id = Datatype::hashName(tv.name);
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

/// If a \e core character data-type of the given size exists, it is returned.
/// Otherwise an exception is thrown
/// \param s is the size in bytes of the desired character data-type
Datatype *TypeFactory::getTypeChar(int4 s)

{
  if (s < 5) {
    Datatype *res = charcache[s];
    if (res != (Datatype *)0)
      return res;
  }
  throw LowlevelError("Request for unsupported character data-type");
}

/// Retrieve or create the core "code" Datatype object
/// This has no prototype attached to it and is appropriate for anonymous function pointers.
/// \return the TypeCode object
TypeCode *TypeFactory::getTypeCode(void)

{
  Datatype *ct = typecache[1][TYPE_CODE-TYPE_FLOAT];
  if (ct != (Datatype *)0)
    return (TypeCode *)ct;
  TypeCode tmp;		// A generic code object
  tmp.markComplete();	// which is considered complete
  return (TypeCode *) findAdd(tmp);
}

/// Create a "function" or "executable" Datatype object
/// This is used for anonymous function pointers with no prototype
/// \param nm is the name of the data-type
/// \return the new Datatype object
TypeCode *TypeFactory::getTypeCode(const string &nm)

{
  if (nm.size()==0) return getTypeCode();
  TypeCode tmp;					// Generic code data-type
  tmp.name = nm;				// with a name
  tmp.displayName = nm;
  tmp.id = Datatype::hashName(nm);
  tmp.markComplete();	// considered complete
  return (TypeCode *) findAdd(tmp);
}

/// Search for pointers that match the given \b ptrto and sub-metatype and change it to
/// the current calculated sub-metatype.
/// A change in the sub-metatype may involve reinserting the pointer data-type in the functional tree.
/// \param base is the given base data-type
/// \param sub is the type of pointer to search for
void TypeFactory::recalcPointerSubmeta(Datatype *base,sub_metatype sub)

{
  DatatypeSet::const_iterator iter;
  TypePointer top(1,base,0);		// This will calculate the current proper sub-meta for pointers to base
  sub_metatype curSub = top.submeta;
  if (curSub == sub) return;		// Don't need to search for pointers with correct submeta
  top.submeta = sub;			// Search on the incorrect submeta
  iter = tree.lower_bound(&top);
  while(iter != tree.end()) {
    TypePointer *ptr = (TypePointer *)*iter;
    if (ptr->getMetatype() != TYPE_PTR) break;
    if (ptr->ptrto != base) break;
    ++iter;
    if (ptr->submeta == sub) {
      tree.erase(ptr);
      ptr->submeta = curSub;		// Change to correct submeta
      tree.insert(ptr);			// Reinsert
    }
  }
}

/// Add the data-type and string to the \b warnings container.
/// \param dt is the data-type associated with the warning
/// \param warn is the warning string to be displayed to the user
void TypeFactory::insertWarning(Datatype *dt,string warn)

{
  if (dt->getId() == 0)
    throw LowlevelError("Can only issue warnings for named data-types");
  dt->flags |= Datatype::warning_issued;
  warnings.emplace_back(dt,warn);
}

/// Run through the \b warnings and delete any matching the given data-type
/// \param dt is the given data-type
void TypeFactory::removeWarning(Datatype *dt)

{
  list<DatatypeWarning>::iterator iter = warnings.begin();
  while(iter != warnings.end()) {
    if ((*iter).dataType->getId() == dt->getId() && (*iter).dataType->getName() == dt->getName()) {
      iter = warnings.erase(iter);
    }
    else {
      ++iter;
    }
  }
}

/// Run through typedefs that were initially defined on incomplete data-types.  If the data-type is now complete,
/// copy the fields or prototype into the typedef and remove it from the list.
void TypeFactory::resolveIncompleteTypedefs(void)

{
  list<Datatype *>::iterator iter = incompleteTypedef.begin();
  while(iter != incompleteTypedef.end()) {
    Datatype *dt = *iter;
    Datatype *defedType = dt->getTypedef();
    if (!defedType->isIncomplete()) {
      if (dt->getMetatype() == TYPE_STRUCT) {
  	TypeStruct *prevStruct = (TypeStruct *)dt;
  	TypeStruct *defedStruct = (TypeStruct *)defedType;
  	setFields(defedStruct->field,prevStruct,defedStruct->size,defedStruct->alignment,defedStruct->flags);
  	iter = incompleteTypedef.erase(iter);
      }
      else if (dt->getMetatype() == TYPE_UNION) {
  	TypeUnion *prevUnion = (TypeUnion *)dt;
  	TypeUnion *defedUnion = (TypeUnion *)defedType;
  	setFields(defedUnion->field,prevUnion,defedUnion->size,defedUnion->alignment,defedUnion->flags);
  	iter = incompleteTypedef.erase(iter);
      }
      else if (dt->getMetatype() == TYPE_CODE) {
	TypeCode *prevCode = (TypeCode *)dt;
	TypeCode *defedCode = (TypeCode *)defedType;
	setPrototype(defedCode->proto, prevCode, defedCode->flags);
	iter = incompleteTypedef.erase(iter);
      }
      else
	++iter;
    }
    else
      ++iter;
  }
}

/// Find or create a data-type identical to the given data-type except for its name and id.
/// If the name and id already describe an incompatible data-type, an exception is thrown.
/// \param ct is the given data-type to clone
/// \param name is the new name for the clone
/// \param id is the new id for the clone (or 0)
/// \param format is a particular format to force when printing (or zero)
/// \return the (found or created) \e typedef data-type
Datatype *TypeFactory::getTypedef(Datatype *ct,const string &name,uint8 id,uint4 format)

{
  if (id == 0)
    id = Datatype::hashName(name);
  Datatype *res = findByIdLocal(name, id);
  if (res != (Datatype *)0) {
    if (ct != res->getTypedef())
      throw LowlevelError("Trying to create typedef of existing type: " + name);
    return res;
  }
  res = ct->clone();		// Clone everything
  res->name = name;		// But a new name
  res->displayName = name;
  res->id = id;			// and new id
  res->flags &= ~((uint4)Datatype::coretype);	// Not a core type
  res->typedefImm = ct;
  res->setDisplayFormat(format);
  insert(res);
  if (res->isIncomplete())
    incompleteTypedef.push_back(res);
  return res;
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
  if (pt->hasStripped())
    pt = pt->getStripped();
  if (pt->getMetatype() == TYPE_ARRAY)
    pt = ((TypeArray *)pt)->getBase();		// Strip the first ARRAY type
  TypePointer tmp(s,pt,ws);
  TypePointer *res = (TypePointer *) findAdd(tmp);
  res->calcTruncate(*this);
  return res;
}

/// Allows "pointer to array" to be constructed
/// \param s is the size of the pointer
/// \param pt is the pointed-to data-type
/// \param ws is the wordsize associated with the pointer
/// \return the TypePointer object
TypePointer *TypeFactory::getTypePointer(int4 s,Datatype *pt,uint4 ws)

{
  if (pt->hasStripped())
    pt = pt->getStripped();
  TypePointer tmp(s,pt,ws);
  TypePointer *res = (TypePointer *) findAdd(tmp);
  res->calcTruncate(*this);
  return res;
}

/// The given name is attached, which distinguishes the returned data-type from
/// other unnamed (or differently named) pointers that otherwise have the same attributes.
/// \param s is the size of the pointer
/// \param pt is the pointed-to data-type
/// \param ws is the wordsize associated with the pointer
/// \param n is the given name to attach to the pointer
/// \return the TypePointer object
TypePointer *TypeFactory::getTypePointer(int4 s,Datatype *pt,uint4 ws,const string &n)

{
  if (pt->hasStripped())
    pt = pt->getStripped();
  TypePointer tmp(s,pt,ws);
  tmp.name = n;
  tmp.displayName = n;
  tmp.id = Datatype::hashName(n);
  TypePointer *res = (TypePointer *) findAdd(tmp);
  res->calcTruncate(*this);
  return res;
}

/// \param as is the number of elements in the desired array
/// \param ao is the data-type of the array element
/// \return the TypeArray object
TypeArray *TypeFactory::getTypeArray(int4 as,Datatype *ao)

{
  if (ao->hasStripped())
    ao = ao->getStripped();
  TypeArray tmp(as,ao);
  return (TypeArray *) findAdd(tmp);
}

/// The created structure will be incomplete and have no fields. They must be added later.
/// \param n is the name of the structure
/// \return the TypeStruct object
TypeStruct *TypeFactory::getTypeStruct(const string &n)

{
  TypeStruct tmp;
  tmp.name = n;
  tmp.displayName = n;
  tmp.id = Datatype::hashName(n);
  return (TypeStruct *) findAdd(tmp);
}

/// Create a data-type representing storage of part of an \e array or \e structure.
/// \param contain is the parent \e array or \e structure data-type that we are taking a part of.
/// \param off is the offset (in bytes) within the parent that the partial data-type starts at
/// \param sz is the number of bytes in the partial data-type
/// \return the TypePartialStruct object
TypePartialStruct *TypeFactory::getTypePartialStruct(Datatype *contain,int4 off,int4 sz)

{
  Datatype *strip = getBase(sz, TYPE_UNKNOWN);
  TypePartialStruct tps(contain,off,sz,strip);
  return (TypePartialStruct *) findAdd(tps);
}

/// The created union will be incomplete and have no fields. They must be added later.
/// \param n is the name of the union
/// \return the TypeUnion object
TypeUnion *TypeFactory::getTypeUnion(const string &n)

{
  TypeUnion tmp;
  tmp.name = n;
  tmp.displayName = n;
  tmp.id = Datatype::hashName(n);
  return (TypeUnion *) findAdd(tmp);
}

/// Create a data-type representing storage of part of a \e union data-type.
/// \param contain is the parent \e union data-type that we are taking a part of.
/// \param off is the offset (in bytes) within the parent that the partial data-type starts at
/// \param sz is the number of bytes in the partial data-type
/// \return the TypePartialUnion object
TypePartialUnion *TypeFactory::getTypePartialUnion(TypeUnion *contain,int4 off,int4 sz)

{
  Datatype *strip = getBase(sz, TYPE_UNKNOWN);
  TypePartialUnion tpu(contain,off,sz,strip);
  return (TypePartialUnion *) findAdd(tpu);
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

/// Create a data-type representing storage of part of an \e enumeration.
/// \param contain is the parent \e enumeration data-type that we are taking a part of.
/// \param off is the offset (in bytes) within the parent that the partial data-type starts at
/// \param sz is the number of bytes in the partial data-type
/// \return the TypePartialEnum object
TypePartialEnum *TypeFactory::getTypePartialEnum(TypeEnum *contain,int4 off,int4 sz)

{
  Datatype *strip = getBase(sz, TYPE_UNKNOWN);
  TypePartialEnum tpe(contain,off,sz,strip);
  return (TypePartialEnum *) findAdd(tpe);
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
/// \param proto is the list of names, data-types, and other attributes of the prototype
/// \return the TypeCode object
TypeCode *TypeFactory::getTypeCode(const PrototypePieces &proto)
{
  TypeCode tc;		// getFuncdata type with no name
  tc.setPrototype(this,proto,getTypeVoid());
  tc.markComplete();
  return (TypeCode *) findAdd(tc);
}

/// Find/create a pointer data-type that points at a known offset relative to a containing data-type.
/// The resulting data-type is unnamed and ephemeral.
/// \param parentPtr is a model pointer data-type, pointing to the containing data-type
/// \param ptrTo is the data-type being pointed directly to
/// \param off is the offset of the pointed-to data-type relative to the \e container
/// \return the new/matching pointer
TypePointerRel *TypeFactory::getTypePointerRel(TypePointer *parentPtr,Datatype *ptrTo,int4 off)

{
  TypePointerRel tp(parentPtr->size,ptrTo,parentPtr->wordsize,parentPtr->ptrto,off);
  tp.markEphemeral(*this);		// Mark as ephemeral
  TypePointerRel *res = (TypePointerRel *) findAdd(tp);
  return res;
}

/// \brief Build a named pointer offset into a larger container
///
/// The resulting data-type is named and not ephemeral and will display as a formal data-type
/// in decompiler output.
/// \param sz is the size in bytes of the pointer
/// \param parent is data-type of the parent container being indirectly pointed to
/// \param ptrTo is the data-type being pointed directly to
/// \param ws is the addressable unit size of pointed to data
/// \param off is the offset of the pointed-to data-type relative to the \e container
/// \param nm is the name to associate with the pointer
/// \return the new/matching pointer
TypePointerRel *TypeFactory::getTypePointerRel(int4 sz,Datatype *parent,Datatype *ptrTo,int4 ws,int4 off,const string &nm)

{
  TypePointerRel tp(sz,ptrTo,ws,parent,off);
  tp.name = nm;
  tp.displayName = nm;
  tp.id = Datatype::hashName(nm);
  TypePointerRel *res = (TypePointerRel *)findAdd(tp);
  return res;
}

/// \brief Build a named pointer with an address space attribute
///
/// The new data-type acts like a typedef of a normal pointer but can affect the resolution of
/// constants by the type propagation system.
/// \param ptrTo is the data-type being pointed directly to
/// \param spc is the address space to associate with the pointer
/// \param nm is the name to associate with the pointer
/// \return the new/matching pointer
TypePointer *TypeFactory::getTypePointerWithSpace(Datatype *ptrTo,AddrSpace *spc,const string &nm)

{
  TypePointer tp(ptrTo,spc);
  tp.name = nm;
  tp.displayName = nm;
  tp.id = Datatype::hashName(nm);
  TypePointer *res = (TypePointer *)findAdd(tp);
  res->calcTruncate(*this);
  return res;
}

/// All the properties of the original pointer are preserved, except the size is changed.
/// \param ptr is the original pointer
/// \param newSize is the size of the new pointer in bytes
/// \return the resized pointer
TypePointer *TypeFactory::resizePointer(TypePointer *ptr,int4 newSize)

{
  Datatype *pt = ptr->ptrto;
  if (pt->hasStripped())
    pt = pt->getStripped();
  TypePointer tmp(newSize,pt,ptr->wordsize);
  return (TypePointer *) findAdd(tmp);
}

/// Drill down into nested data-types until we get to a data-type that exactly matches the
/// given offset and size, and return this data-type.  Any \e union data-type encountered
/// terminates the process and a partial union data-type is constructed and returned.
/// If the range indicated by the offset and size contains only a partial field or crosses
/// field boundaries, null is returned.
/// \param ct is the structured data-type
/// \param offset is the starting byte offset for the piece
/// \param size is the number of bytes in the piece
/// \return the data-type of the piece or null
Datatype *TypeFactory::getExactPiece(Datatype *ct,int4 offset,int4 size)

{
  Datatype *lastType = (Datatype *)0;
  int8 lastOff = 0;
  int8 curOff = offset;
  do {
    if (ct->getSize() < size + curOff) {	// Range is beyond end of current data-type
      break;					// Construct partial around last data-type
    }
    if (ct->getSize() == size)
	return ct;				// Perfect size match
    if (ct->getMetatype() == TYPE_UNION) {
      return getTypePartialUnion((TypeUnion *)ct, curOff, size);
    }
    lastType = ct;
    lastOff = curOff;
    ct = ct->getSubType(curOff,&curOff);
  } while(ct != (Datatype *)0);
  if (lastType != (Datatype *)0) {
    // If we reach here, lastType is bigger than size
    if (lastType->getMetatype() == TYPE_STRUCT || lastType->getMetatype() == TYPE_ARRAY)
      return getTypePartialStruct(lastType, lastOff, size);
    else if (lastType->isEnumType() && !lastType->hasStripped())
      return getTypePartialEnum((TypeEnum *)lastType, lastOff, size);
  }
  return (Datatype *)0;
}

/// The indicated Datatype object is removed from this container.
/// Indirect references (via TypeArray TypeStruct etc.) are not affected
/// \param ct is the data-type to destroy
void TypeFactory::destroyType(Datatype *ct)

{
  if (ct->isCoreType())
    throw LowlevelError("Cannot destroy core type");
  if (ct->hasWarning())
    removeWarning(ct);
  nametree.erase(ct);
  tree.erase(ct);
  delete ct;
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

/// Restore a Datatype object from an element: either \<type>, \<typeref>, or \<void>
/// \param decoder is the stream decoder
/// \return the decoded Datatype object
Datatype *TypeFactory::decodeType(Decoder &decoder)

{
  Datatype *ct;
  uint4 elemId = decoder.peekElement();
  if (ELEM_TYPEREF == elemId) {
    elemId = decoder.openElement();
    uint8 newid = 0;
    int4 size = -1;
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_ID) {
	newid = decoder.readUnsignedInteger();
      }
      else if (attribId == ATTRIB_SIZE) {		// A "size" attribute indicates a "variable length" base
	size = decoder.readSignedInteger();
      }
    }
    string newname = decoder.readString(ATTRIB_NAME);
    if (newid == 0)		// If there was no id, use the name hash
      newid = Datatype::hashName(newname);
    ct = findById(newname,newid,size);
    if (ct == (Datatype *)0)
      throw LowlevelError("Unable to resolve type: "+newname);
    decoder.closeElement(elemId);
    return ct;
  }
  return decodeTypeNoRef(decoder,false);
}

/// \brief Restore data-type from an element and extra "code" flags
///
/// Kludge to get flags into code pointer types, when they can't come through the stream
/// \param decoder is the stream decoder
/// \param isConstructor toggles "constructor" property on "function" datatypes
/// \param isDestructor toggles "destructor" property on "function" datatypes
/// \return the decoded Datatype object
Datatype *TypeFactory::decodeTypeWithCodeFlags(Decoder &decoder,bool isConstructor,bool isDestructor)

{
  TypePointer tp;
  uint4 elemId = decoder.openElement();
  tp.decodeBasic(decoder);
  if (tp.getMetatype() != TYPE_PTR)
    throw LowlevelError("Special type decode does not see pointer");
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_WORDSIZE) {
      tp.wordsize = decoder.readUnsignedInteger();
    }
  }
  tp.ptrto = decodeCode(decoder, isConstructor, isDestructor, false);
  decoder.closeElement(elemId);
  tp.calcTruncate(*this);
  return findAdd(tp);
}

/// All data-types, in dependency order, are encoded to a stream
/// \param encoder is the stream encoder
void TypeFactory::encode(Encoder &encoder) const

{
  vector<Datatype *> deporder;
  vector<Datatype *>::iterator iter;

  dependentOrder(deporder);	// Put types in correct order
  encoder.openElement(ELEM_TYPEGRP);
  for(iter=deporder.begin();iter!=deporder.end();++iter) {
    if ((*iter)->getName().size()==0) continue;	// Don't save anonymous types
    if ((*iter)->isCoreType()) { // If this would be saved as a coretype
      type_metatype meta = (*iter)->getMetatype();
      if ((meta != TYPE_PTR)&&(meta != TYPE_ARRAY)&&
	  (meta != TYPE_STRUCT)&&(meta != TYPE_UNION))
	continue;		// Don't save it here
    }
    (*iter)->encode(encoder);
  }
  encoder.closeElement(ELEM_TYPEGRP);
}

/// Any data-type within this container marked as \e core will
/// be encodeded as a \<coretypes> element.
/// \param encoder is the stream encoder
void TypeFactory::encodeCoreTypes(Encoder &encoder) const

{
  DatatypeSet::const_iterator iter;
  Datatype *ct;

  encoder.openElement(ELEM_CORETYPES);
  for(iter=tree.begin();iter!=tree.end();++iter) {
    ct = *iter;
    if (!ct->isCoreType()) continue;
    type_metatype meta = ct->getMetatype();
    if ((meta==TYPE_PTR)||(meta==TYPE_ARRAY)||
	(meta==TYPE_STRUCT)||(meta==TYPE_UNION))
      continue;
    ct->encode(encoder);
  }
  encoder.closeElement(ELEM_CORETYPES);
}

/// Scan the new id and name.  A subtag references the data-type being typedefed.
/// Construct the new data-type based on the referenced data-type but with new name and id.
/// \param decoder is the stream decoder
/// \return the constructed typedef data-type
Datatype *TypeFactory::decodeTypedef(Decoder &decoder)

{
  uint8 id = 0;
  string nm;
  uint4 format = 0;		// No forced display format by default
//  uint4 elemId = decoder.openElement();
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_ID) {
      id = decoder.readUnsignedInteger();
    }
    else if (attribId == ATTRIB_NAME) {
      nm = decoder.readString();
    }
    else if (attribId == ATTRIB_FORMAT) {
      format = Datatype::encodeIntegerFormat(decoder.readString());
    }
  }
  if (id == 0) {			// Its possible the typedef is a builtin
    id = Datatype::hashName(nm);	// There must be some kind of id
  }
  Datatype *defedType = decodeType( decoder );
//  decoder.closeElement(elemId);
  if (defedType->isVariableLength())
    id = Datatype::hashSize(id, defedType->size);
  if (defedType->getMetatype() == TYPE_STRUCT || defedType->getMetatype() == TYPE_UNION) {
    // Its possible that a typedef of a struct/union is recursively defined, in which case
    // an incomplete version may already be in the container
    Datatype *prev = findByIdLocal(nm, id);
    if (prev != (Datatype *)0) {
      if (defedType != prev->getTypedef())
        throw LowlevelError("Trying to create typedef of existing type: " + prev->name);
      if (prev->getMetatype() == TYPE_STRUCT) {
	TypeStruct *prevStruct = (TypeStruct *)prev;
	TypeStruct *defedStruct = (TypeStruct *)defedType;
	if (prevStruct->field.size() != defedStruct->field.size())
	  setFields(defedStruct->field,prevStruct,defedStruct->size,defedStruct->alignment,defedStruct->flags);
      }
      else {
	TypeUnion *prevUnion = (TypeUnion *)prev;
	TypeUnion *defedUnion = (TypeUnion *)defedType;
	if (prevUnion->field.size() != defedUnion->field.size())
	  setFields(defedUnion->field,prevUnion,defedUnion->size,defedUnion->alignment,defedUnion->flags);
      }
      return prev;
    }
  }
  return getTypedef(defedType, nm, id, format);
}

/// \param decoder is the stream decoder
/// \param forcecore is \b true if the data-type is considered core
/// \return the newly minted enumeration data-type
Datatype *TypeFactory::decodeEnum(Decoder &decoder,bool forcecore)

{
  TypeEnum te(1,TYPE_ENUM_INT); // metatype and size are replaced
  string warning = te.decode(decoder,*this);
  if (forcecore)
    te.flags |= Datatype::coretype;
  Datatype *res = findAdd(te);
  if (!warning.empty())
    insertWarning(res, warning);
  return res;
}

/// If necessary create a stub object before parsing the field descriptions, to deal with recursive definitions
/// \param decoder is the stream decoder
/// \param forcecore is \b true if the data-type is considered core
/// \return the newly minted structure data-type
Datatype* TypeFactory::decodeStruct(Decoder &decoder,bool forcecore)

{
  TypeStruct ts;
//  uint4 elemId = decoder.openElement();
  ts.decodeBasic(decoder);
  if (forcecore)
    ts.flags |= Datatype::coretype;
  Datatype *ct = findByIdLocal(ts.name,ts.id);
  if (ct == (Datatype*)0) {
    ct = findAdd(ts);	// Create stub to allow recursive definitions
  }
  else if (ct->getMetatype() != TYPE_STRUCT)
    throw LowlevelError("Trying to redefine type: " + ts.name);
  string warning = ts.decodeFields(decoder,*this);
  if (!ct->isIncomplete()) {	// Structure of this name was already present
    if (0 != ct->compareDependency(ts))
      throw LowlevelError("Redefinition of structure: " + ts.name);
  }
  else {		// If structure is a placeholder stub
    setFields(ts.field,(TypeStruct*)ct,ts.size,ts.alignment,ts.flags);	// Define structure now by copying fields
  }
  if (!warning.empty())
    insertWarning(ct, warning);
  resolveIncompleteTypedefs();
//  decoder.closeElement(elemId);
  return ct;
}

/// If necessary create a stub object before parsing the field descriptions, to deal with recursive definitions
/// \param decoder is the stream decoder
/// \param forcecore is \b true if the data-type is considered core
/// \return the newly minted union data-type
Datatype* TypeFactory::decodeUnion(Decoder &decoder,bool forcecore)

{
  TypeUnion tu;
//  uint4 elemId = decoder.openElement();
  tu.decodeBasic(decoder);
  if (forcecore)
    tu.flags |= Datatype::coretype;
  Datatype *ct = findByIdLocal(tu.name,tu.id);
  if (ct == (Datatype*)0) {
    ct = findAdd(tu);	// Create stub to allow recursive definitions
  }
  else if (ct->getMetatype() != TYPE_UNION)
    throw LowlevelError("Trying to redefine type: " + tu.name);
  tu.decodeFields(decoder,*this);
  if (!ct->isIncomplete()) {	// Structure of this name was already present
    if (0 != ct->compareDependency(tu))
      throw LowlevelError("Redefinition of union: " + tu.name);
  }
  else {		// If structure is a placeholder stub
    setFields(tu.field,(TypeUnion*)ct,tu.size,tu.alignment,tu.flags);	// Define structure now by copying fields
  }
  resolveIncompleteTypedefs();
//  decoder.closeElement(elemId);
  return ct;
}

/// If necessary create a stub object before parsing the prototype description, to deal with recursive definitions
/// \param decoder is the stream decoder
/// \param isConstructor is \b true if any prototype should be treated as a constructor
/// \param isDestructor is \b true if any prototype should be treated as a destructor
/// \param forcecore is \b true if the data-type is considered core
/// \return the newly minted code data-type
Datatype *TypeFactory::decodeCode(Decoder &decoder,bool isConstructor,bool isDestructor,bool forcecore)

{
  TypeCode tc;
//  uint4 elemId = decoder.openElement();
  tc.decodeStub(decoder);
  if (tc.getMetatype() != TYPE_CODE) {
    throw LowlevelError("Expecting metatype=\"code\"");
  }
  if (forcecore)
    tc.flags |= Datatype::coretype;
  Datatype *ct = findByIdLocal(tc.name,tc.id);
  if (ct == (Datatype *)0) {
    ct = findAdd(tc);	// Create stub to allow recursive definitions
  }
  else if (ct->getMetatype() != TYPE_CODE)
    throw LowlevelError("Trying to redefine type: " + tc.name);
  tc.decodePrototype(decoder, isConstructor, isDestructor, *this);
  if (!ct->isIncomplete()) {	// Code data-type of this name was already present
    if (0 != ct->compareDependency(tc))
      throw LowlevelError("Redefinition of code data-type: " + tc.name);
  }
  else {	// If there was a placeholder stub
    setPrototype(tc.proto, (TypeCode *)ct, tc.flags);
  }
  resolveIncompleteTypedefs();
//  decoder.closeElement(elemId);
  return ct;
}

/// Restore a Datatype object from a \<type> element. (Don't use for \<typeref> elements)
/// The new Datatype is added to \b this container.
/// \param decoder is the stream decoder
/// \param forcecore is true if the new type should be labeled as a core type
/// \return the new Datatype object
Datatype *TypeFactory::decodeTypeNoRef(Decoder &decoder,bool forcecore)

{
  string metastring;
  Datatype *ct;

  uint4 elemId = decoder.openElement();
  if (elemId == ELEM_VOID) {
    ct = getTypeVoid();	// Automatically a coretype
    decoder.closeElement(elemId);
    return ct;
  }
  if (elemId == ELEM_DEF) {
    ct = decodeTypedef(decoder);
    decoder.closeElement(elemId);
    return ct;
  }
  type_metatype meta = string2metatype(decoder.readString(ATTRIB_METATYPE));
  switch(meta) {
  case TYPE_PTR:
    {
      TypePointer tp;
      tp.decode(decoder,*this);
      if (forcecore)
	tp.flags |= Datatype::coretype;
      ct = findAdd(tp);
    }
    break;
  case TYPE_PTRREL:
    {
      TypePointerRel tp;
      tp.decode(decoder, *this);
      if (forcecore)
	tp.flags |= Datatype::coretype;
      ct = findAdd(tp);
    }
    break;
  case TYPE_ARRAY:
    {
      TypeArray ta;
      ta.decode(decoder,*this);
      if (forcecore)
	ta.flags |= Datatype::coretype;
      ct = findAdd(ta);
    }
    break;
  case TYPE_ENUM_INT:
  case TYPE_ENUM_UINT:
    ct = decodeEnum(decoder,forcecore);
    break;
  case TYPE_STRUCT:
    ct = decodeStruct(decoder,forcecore);
    break;
  case TYPE_UNION:
    ct = decodeUnion(decoder,forcecore);
    break;
  case TYPE_SPACEBASE:
    {
      TypeSpacebase tsb(glb);
      tsb.decode(decoder,*this);
      if (forcecore)
	tsb.flags |= Datatype::coretype;
      ct = findAdd(tsb);
    }
    break;
  case TYPE_CODE:
    ct = decodeCode(decoder,false, false, forcecore);
    break;
  case TYPE_VOID:
    {
      TypeVoid voidType;
      voidType.decode(decoder,*this);
      ct = findAdd(voidType);
    }
    break;
  default:
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_CHAR && decoder.readBool()) {
	TypeChar tc(decoder.readString(ATTRIB_NAME));
	decoder.rewindAttributes();
	tc.decode(decoder,*this);
	if (forcecore)
	  tc.flags |= Datatype::coretype;
	ct = findAdd(tc);
	decoder.closeElement(elemId);
	return ct;
      }
      else if (attribId == ATTRIB_UTF && decoder.readBool()) {
	TypeUnicode tu;
	decoder.rewindAttributes();
	tu.decode(decoder,*this);
	if (forcecore)
	  tu.flags |= Datatype::coretype;
	ct = findAdd(tu);
	decoder.closeElement(elemId);
	return ct;
      }
    }
    {
      decoder.rewindAttributes();
      TypeBase tb(0,TYPE_UNKNOWN);
      tb.decodeBasic(decoder);
      if (forcecore)
	tb.flags |= Datatype::coretype;
      ct = findAdd(tb);
    }
    break;
  }
  decoder.closeElement(elemId);
  return ct;
}

/// Scan configuration parameters of the factory and parse elements describing data-types
/// into this container.
/// \param decoder is the stream decoder
void TypeFactory::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_TYPEGRP);

  while(decoder.peekElement() != 0)
    decodeTypeNoRef(decoder,false);
  decoder.closeElement(elemId);
}

/// Parse data-type elements into this container.
/// This stream is presumed to contain "core" datatypes and the
/// cached matrix will be populated from this set.
/// \param decoder is the stream decoder
void TypeFactory::decodeCoreTypes(Decoder &decoder)

{
  clear();			// Make sure this routine flushes

  uint4 elemId = decoder.openElement(ELEM_CORETYPES);
  while(decoder.peekElement() != 0)
    decodeTypeNoRef(decoder,true);
  decoder.closeElement(elemId);
  cacheCoreTypes();
}

/// Recover various sizes relevant to \b this container, such as
/// the default size of "int" and structure alignment, by parsing
/// a \<data_organization> element.
/// \param decoder is the stream decoder
void TypeFactory::decodeDataOrganization(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_DATA_ORGANIZATION);
  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId == 0) break;
    if (subId == ELEM_INTEGER_SIZE) {
      sizeOfInt = decoder.readSignedInteger(ATTRIB_VALUE);
    }
    else if (subId == ELEM_LONG_SIZE) {
      sizeOfLong = decoder.readSignedInteger(ATTRIB_VALUE);
    }
    else if (subId == ELEM_POINTER_SIZE) {
      sizeOfPointer = decoder.readSignedInteger(ATTRIB_VALUE);
    }
    else if (subId == ELEM_CHAR_SIZE) {
      sizeOfChar = decoder.readSignedInteger(ATTRIB_VALUE);
    }
    else if (subId == ELEM_WCHAR_SIZE) {
      sizeOfWChar = decoder.readSignedInteger(ATTRIB_VALUE);
    }
    else if (subId == ELEM_SIZE_ALIGNMENT_MAP) {
      decodeAlignmentMap(decoder);
    }
    else {
      decoder.closeElementSkipping(subId);
      continue;
    }
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

/// Recover the map from data-type size to preferred alignment.
/// \param decoder is the stream decoder
void TypeFactory::decodeAlignmentMap(Decoder &decoder)

{
  alignMap.clear();
  for(;;) {
    uint4 mapId = decoder.openElement();
    if (mapId != ELEM_ENTRY) break;
    int4 sz = decoder.readSignedInteger(ATTRIB_SIZE);
    int4 val = decoder.readSignedInteger(ATTRIB_ALIGNMENT);
    while(alignMap.size() <= sz)
      alignMap.push_back(-1);
    alignMap[sz] = val;
    decoder.closeElement(mapId);
  }
  int4 curAlign = 1;
  for(int4 sz=1;sz < alignMap.size();++sz) {
    int4 tmpAlign = alignMap[sz];
    if (tmpAlign == -1)
      alignMap[sz] = curAlign;	// Copy alignment from nearest explicitly set value
    else
      curAlign = tmpAlign;
  }
}

/// The default is used if the compiler spec does not contain a \<size_alignment_map> element.
void TypeFactory::setDefaultAlignmentMap(void)

{
  alignMap.resize(9,0);
  alignMap[1] = 1;
  alignMap[2] = 2;
  alignMap[3] = 2;
  alignMap[4] = 4;
  alignMap[5] = 4;
  alignMap[6] = 4;
  alignMap[7] = 4;
  alignMap[8] = 8;
}

/// Recover default enumeration properties (size and meta-type) from
/// an \<enum> XML tag.  Should probably consider this deprecated. These
/// values are only used by the internal C parser.
/// param el is the XML element
void TypeFactory::parseEnumConfig(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_ENUM);
  enumsize = decoder.readSignedInteger(ATTRIB_SIZE);
  if (decoder.readBool(ATTRIB_SIGNED))
    enumtype = TYPE_ENUM_INT;
  else
    enumtype = TYPE_ENUM_UINT;
  decoder.closeElement(elemId);
}

} // End namespace ghidra

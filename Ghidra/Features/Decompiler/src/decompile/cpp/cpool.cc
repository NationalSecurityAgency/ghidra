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
#include "cpool.hh"

namespace ghidra {

AttributeId ATTRIB_A = AttributeId("a",80);
AttributeId ATTRIB_B = AttributeId("b",81);
AttributeId ATTRIB_LENGTH = AttributeId("length",82);
AttributeId ATTRIB_TAG = AttributeId("tag",83);

ElementId ELEM_CONSTANTPOOL = ElementId("constantpool",109);
ElementId ELEM_CPOOLREC = ElementId("cpoolrec",110);
ElementId ELEM_REF = ElementId("ref",111);
ElementId ELEM_TOKEN = ElementId("token",112);

/// Encode the constant pool object description as a \<cpoolrec> element.
/// \param encoder is the stream encoder
void CPoolRecord::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_CPOOLREC);
  if (tag == pointer_method)
    encoder.writeString(ATTRIB_TAG, "method");
  else if (tag == pointer_field)
    encoder.writeString(ATTRIB_TAG, "field");
  else if (tag == instance_of)
    encoder.writeString(ATTRIB_TAG, "instanceof");
  else if (tag == array_length)
    encoder.writeString(ATTRIB_TAG, "arraylength");
  else if (tag == check_cast)
    encoder.writeString(ATTRIB_TAG, "checkcast");
  else if (tag == string_literal)
    encoder.writeString(ATTRIB_TAG, "string");
  else if (tag == class_reference)
    encoder.writeString(ATTRIB_TAG, "classref");
  else
    encoder.writeString(ATTRIB_TAG, "primitive");
  if (isConstructor())
    encoder.writeBool(ATTRIB_CONSTRUCTOR, true);
  if (isDestructor())
    encoder.writeBool(ATTRIB_DESTRUCTOR, true);
  if (tag == primitive) {
    encoder.openElement(ELEM_VALUE);
    encoder.writeUnsignedInteger(ATTRIB_CONTENT, value);
    encoder.closeElement(ELEM_VALUE);
  }
  if (byteData != (uint1 *)0) {
    encoder.openElement(ELEM_DATA);
    encoder.writeSignedInteger(ATTRIB_LENGTH, byteDataLen);
    int4 wrap = 0;
    ostringstream s;
    for(int4 i=0;i<byteDataLen;++i) {
      s << setfill('0') << setw(2) << hex << byteData[i] << ' ';
      wrap += 1;
      if (wrap > 15) {
	s << '\n';
	wrap = 0;
      }
    }
    encoder.writeString(ATTRIB_CONTENT, s.str());
    encoder.closeElement(ELEM_DATA);
  }
  else {
    encoder.openElement(ELEM_TOKEN);
    encoder.writeString(ATTRIB_CONTENT, token);
    encoder.closeElement(ELEM_TOKEN);
  }
  type->encode(encoder);
  encoder.closeElement(ELEM_CPOOLREC);
}

/// Initialize \b this CPoolRecord instance from a \<cpoolrec> element.
/// \param decoder is the stream decoder
/// \param typegrp is the TypeFactory used to resolve data-types
void CPoolRecord::decode(Decoder &decoder,TypeFactory &typegrp)

{
  tag = primitive;	// Default tag
  value = 0;
  flags = 0;
  uint4 elemId = decoder.openElement(ELEM_CPOOLREC);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_TAG) {
      string tagstring = decoder.readString();
      if (tagstring == "method")
	tag = pointer_method;
      else if (tagstring == "field")
	tag = pointer_field;
      else if (tagstring == "instanceof")
	tag = instance_of;
      else if (tagstring == "arraylength")
	tag = array_length;
      else if (tagstring == "checkcast")
	tag = check_cast;
      else if (tagstring == "string")
	tag = string_literal;
      else if (tagstring == "classref")
	tag = class_reference;
    }
    else if (attribId == ATTRIB_CONSTRUCTOR) {
      if (decoder.readBool())
	flags |= CPoolRecord::is_constructor;
    }
    else if (attribId == ATTRIB_DESTRUCTOR) {
      if (decoder.readBool())
	flags |= CPoolRecord::is_destructor;
    }
  }
  uint4 subId;
  if (tag == primitive) {	// First tag must be value
    subId = decoder.openElement(ELEM_VALUE);
    value = decoder.readUnsignedInteger(ATTRIB_CONTENT);
    decoder.closeElement(subId);
  }
  subId = decoder.openElement();
  if (subId == ELEM_TOKEN)
    token = decoder.readString(ATTRIB_CONTENT);
  else {
    byteDataLen = decoder.readSignedInteger(ATTRIB_LENGTH);
    istringstream s3(decoder.readString(ATTRIB_CONTENT));
    byteData = new uint1[byteDataLen];
    for(int4 i=0;i<byteDataLen;++i) {
      uint4 val;
      s3 >> ws >> hex >> val;
      byteData[i] = (uint1)val;
    }
  }
  decoder.closeElement(subId);
  if (tag == string_literal && (byteData == (uint1 *)0))
    throw LowlevelError("Bad constant pool record: missing <data>");
  if (flags != 0) {
    bool isConstructor = ((flags & is_constructor)!=0);
    bool isDestructor = ((flags & is_destructor)!=0);
    type = typegrp.decodeTypeWithCodeFlags(decoder,isConstructor,isDestructor);
  }
  else
    type = typegrp.decodeType(decoder);
  decoder.closeElement(elemId);
}

void ConstantPool::putRecord(const vector<uintb> &refs,uint4 tag,const string &tok,Datatype *ct)

{
  CPoolRecord *newrec = createRecord(refs);
  newrec->tag = tag;
  newrec->token = tok;
  newrec->type = ct;
}

const CPoolRecord *ConstantPool::decodeRecord(const vector<uintb> &refs,Decoder &decoder,TypeFactory &typegrp)

{
  CPoolRecord *newrec = createRecord(refs);
  newrec->decode(decoder,typegrp);
  return newrec;
}

/// The reference is encoded as a \<ref> element.
/// \param encoder is the stream encoder
void ConstantPoolInternal::CheapSorter::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_REF);
  encoder.writeUnsignedInteger(ATTRIB_A, a);
  encoder.writeUnsignedInteger(ATTRIB_B, b);
  encoder.closeElement(ELEM_REF);
}

/// Restore \b this \e reference from a \<ref> element
/// \param decoder is the stream decoder
void ConstantPoolInternal::CheapSorter::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_REF);
  a = decoder.readUnsignedInteger(ATTRIB_A);
  b = decoder.readUnsignedInteger(ATTRIB_B);
  decoder.closeElement(elemId);
}

CPoolRecord *ConstantPoolInternal::createRecord(const vector<uintb> &refs)

{
  CheapSorter sorter(refs);
  pair<map<CheapSorter,CPoolRecord>::iterator,bool> res;
  res = cpoolMap.emplace(piecewise_construct,forward_as_tuple(sorter),forward_as_tuple());
  if (res.second == false)
    throw LowlevelError("Creating duplicate entry in constant pool: "+(*res.first).second.getToken());
  return &(*res.first).second;
}

const CPoolRecord *ConstantPoolInternal::getRecord(const vector<uintb> &refs) const

{
  CheapSorter sorter(refs);
  map<CheapSorter,CPoolRecord>::const_iterator iter = cpoolMap.find(sorter);
  if (iter == cpoolMap.end())
    return (CPoolRecord *)0;

  return &(*iter).second;
}

void ConstantPoolInternal::encode(Encoder &encoder) const

{
  map<CheapSorter,CPoolRecord>::const_iterator iter;
  encoder.openElement(ELEM_CONSTANTPOOL);
  for(iter=cpoolMap.begin();iter!=cpoolMap.end();++iter) {
    (*iter).first.encode(encoder);
    (*iter).second.encode(encoder);
  }
  encoder.closeElement(ELEM_CONSTANTPOOL);
}

void ConstantPoolInternal::decode(Decoder &decoder,TypeFactory &typegrp)

{
  uint4 elemId = decoder.openElement(ELEM_CONSTANTPOOL);
  while(decoder.peekElement() != 0) {
    CheapSorter sorter;
    sorter.decode(decoder);
    vector<uintb> refs;
    sorter.apply(refs);
    CPoolRecord *newrec = createRecord(refs);
    newrec->decode(decoder,typegrp);
  }
  decoder.closeElement(elemId);
}

} // End namespace ghidra

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

/// Save the constant pool object description as a \<cpoolrec> tag.
/// \param s is the output stream
void CPoolRecord::saveXml(ostream &s) const

{
  s << "<cpoolrec";
  if (tag == pointer_method)
    a_v(s,"tag","method");
  else if (tag == pointer_field)
    a_v(s,"tag","field");
  else if (tag == instance_of)
    a_v(s,"tag","instanceof");
  else if (tag == array_length)
    a_v(s,"tag","arraylength");
  else if (tag == check_cast)
    a_v(s,"tag","checkcast");
  else if (tag == string_literal)
    a_v(s,"tag","string");
  else if (tag == class_reference)
    a_v(s,"tag","classref");
  else
    a_v(s,"tag","primitive");
  if (isConstructor())
    a_v_b(s,"constructor",true);
  if (isDestructor())
    a_v_b(s,"destructor",true);
  s << ">\n";
  if (tag == primitive) {
    s << "  <value>0x";
    s << hex << value;
    s << "</value>\n";
  }
  if (byteData != (uint1 *)0) {
    s << "  <data length=\"" << dec << byteDataLen << "\">\n";
    int4 wrap = 0;
    for(int4 i=0;i<byteDataLen;++i) {
      s << setfill('0') << setw(2) << hex << byteData[i] << ' ';
      wrap += 1;
      if (wrap > 15) {
	s << '\n';
	wrap = 0;
      }
    }
    s << "  </data>\n";
  }
  else {
    s << "  <token>";
    xml_escape(s,token.c_str());
    s << "  </token>\n";
  }
  type->saveXml(s);
  s << "</cpoolrec>\n";
}

/// Initialize \b this CPoolRecord instance from a \<cpoolrec> tag.
/// \param el is the \<cpoolrec> element
/// \param typegrp is the TypeFactory used to resolve data-types
void CPoolRecord::restoreXml(const Element *el,TypeFactory &typegrp)

{
  tag = primitive;	// Default tag
  value = 0;
  flags = 0;
  int4 num = el->getNumAttributes();
  for(int4 i=0;i<num;++i) {
    const string &attr(el->getAttributeName(i));
    if (attr == "tag") {
      const string &tagstring(el->getAttributeValue(i));
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
    else if (attr == "constructor") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= CPoolRecord::is_constructor;
    }
    else if (attr == "destructor") {
      if (xml_readbool(el->getAttributeValue(i)))
	flags |= CPoolRecord::is_destructor;
    }
  }
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  const Element *subel;
  if (tag == primitive) {	// First tag must be value
    subel = *iter;
    istringstream s1(subel->getContent());
    s1.unsetf(ios::dec | ios::hex | ios::oct);
    s1 >> value;
    ++iter;
  }
  subel = *iter;
  ++iter;
  if (subel->getName() == "token")
    token = subel->getContent();
  else {
    istringstream s2(subel->getAttributeValue("length"));
    s2.unsetf(ios::dec | ios::hex | ios::oct);
    s2 >> byteDataLen;
    istringstream s3(subel->getContent());
    byteData = new uint1[byteDataLen];
    for(int4 i=0;i<byteDataLen;++i) {
      uint4 val;
      s3 >> ws >> hex >> val;
      byteData[i] = (uint1)val;
    }
  }
  if (tag == string_literal && (byteData == (uint1 *)0))
    throw LowlevelError("Bad constant pool record: missing <data>");
  subel = *iter;
  if (flags != 0) {
    bool isConstructor = ((flags & is_constructor)!=0);
    bool isDestructor = ((flags & is_destructor)!=0);
    type = typegrp.restoreXmlTypeWithCodeFlags(subel,isConstructor,isDestructor);
  }
  else
    type = typegrp.restoreXmlType(subel);
}

void ConstantPool::putRecord(const vector<uintb> &refs,uint4 tag,const string &tok,Datatype *ct)

{
  CPoolRecord *newrec = createRecord(refs);
  newrec->tag = tag;
  newrec->token = tok;
  newrec->type = ct;
}

const CPoolRecord *ConstantPool::restoreXmlRecord(const vector<uintb> &refs,const Element *el,TypeFactory &typegrp)

{
  CPoolRecord *newrec = createRecord(refs);
  newrec->restoreXml(el,typegrp);
  return newrec;
}

/// The reference is output as a \<ref> tag.
/// \param s is the output stream
void ConstantPoolInternal::CheapSorter::saveXml(ostream &s) const

{
  s << "<ref";
  a_v_u(s,"a",a);
  a_v_u(s,"b",b);
  s << "/>\n";
}

/// Restore \b this \e reference from a \<ref> XML tag
/// \param el is the XML element
void ConstantPoolInternal::CheapSorter::restoreXml(const Element *el)

{
  istringstream s1(el->getAttributeValue("a"));
  s1.unsetf(ios::dec | ios::hex | ios::oct);
  s1 >> a;
  istringstream s2(el->getAttributeValue("b"));
  s2.unsetf(ios::dec | ios::hex | ios::oct);
  s2 >> b;
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

void ConstantPoolInternal::saveXml(ostream &s) const

{
  map<CheapSorter,CPoolRecord>::const_iterator iter;
  s << "<constantpool>\n";
  for(iter=cpoolMap.begin();iter!=cpoolMap.end();++iter) {
    (*iter).first.saveXml(s);
    (*iter).second.saveXml(s);
  }
  s << "</constantpool>\n";
}

void ConstantPoolInternal::restoreXml(const Element *el,TypeFactory &typegrp)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    CheapSorter sorter;
    sorter.restoreXml(subel);
    vector<uintb> refs;
    sorter.apply(refs);
    ++iter;
    subel = *iter;
    CPoolRecord *newrec = createRecord(refs);
    newrec->restoreXml(subel,typegrp);
  }
}

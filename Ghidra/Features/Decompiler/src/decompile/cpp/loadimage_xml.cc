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
#include "loadimage_xml.hh"
#include "translate.hh"

/// \param f is the (path to the) underlying XML file
/// \param el is the parsed form of the file
LoadImageXml::LoadImageXml(const string &f,const Element *el) : LoadImage(f)

{
  manage = (const AddrSpaceManager *)0;
  rootel = el;
  
  // Extract architecture information
  if (rootel->getName() != "binaryimage")
    throw LowlevelError("Missing binaryimage tag in "+filename);
  archtype = el->getAttributeValue("arch");
}

/// Write out the byte chunks and symbols as XML tags
/// \param s is the output stream
void LoadImageXml::saveXml(ostream &s) const

{
  s << "<binaryimage arch=\"" << archtype << "\">\n";

  map<Address,vector<uint1> >::const_iterator iter1;
  for(iter1=chunk.begin();iter1!=chunk.end();++iter1) {
    const vector<uint1> &vec((*iter1).second);
    if (vec.size() == 0) continue;
    s << " <bytechunk";
    (*iter1).first.getSpace()->saveXmlAttributes(s,(*iter1).first.getOffset());
    if (readonlyset.find((*iter1).first) != readonlyset.end())
      s << " readonly=\"true\"";
    s << ">\n  " << setfill('0');
    for(int4 i=0;i<vec.size();++i) {
      s << hex << setw(2) << (int4)vec[i];
      if (i%20 == 19)
	s << "\n  ";
    }
    s << "\n </bytechunk>\n";
  }

  map<Address,string>::const_iterator iter2;
  for(iter2=addrtosymbol.begin();iter2!=addrtosymbol.end();++iter2) {
    s << " <symbol";
    (*iter2).first.getSpace()->saveXmlAttributes(s,(*iter2).first.getOffset());
    s << " name=\"" << (*iter2).second << "\"/>\n";
  }
  s << "</binaryimage>\n";
}

/// \param m is for looking up address space
void LoadImageXml::open(const AddrSpaceManager *m)

{
  manage = m;
  uint4 sz;			// unused size

  // Read parsed xml file
  const List &list(rootel->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  while(iter != list.end()) {
    Element *subel = *iter++;
    if (subel->getName()=="symbol") {
      AddrSpace *base = (AddrSpace *)0;
      base = manage->getSpaceByName(subel->getAttributeValue("space"));
      if (base == (AddrSpace *)0)
	throw LowlevelError("Unknown space name: "+subel->getAttributeValue("space"));
      Address addr(base,base->restoreXmlAttributes(subel,sz));
      const string &nm(subel->getAttributeValue("name"));
      addrtosymbol[addr] = nm;
    }
    else if (subel->getName() == "bytechunk") {
      AddrSpace *base = (AddrSpace *)0;
      base = manage->getSpaceByName(subel->getAttributeValue("space"));
      if (base == (AddrSpace *)0)
	throw LowlevelError("Unknown space name: "+subel->getAttributeValue("space"));
      Address addr(base,base->restoreXmlAttributes(subel,sz));
      map<Address,vector<uint1> >::iterator chnkiter;
      vector<uint1> &vec( chunk[addr] );
      vec.clear();
      for(int4 i=0;i<subel->getNumAttributes();++i) {
	if (subel->getAttributeName(i) == "readonly")
	  if (xml_readbool(subel->getAttributeValue(i)))
	    readonlyset.insert(addr);
      }
      istringstream is(subel->getContent());
      int4 val;
      char c1,c2;
      is >> ws;
      c1 = is.get();
      c2 = is.get();
      while((c1>0)&&(c2>0)) {
	if (c1 <= '9')
	  c1 = c1 - '0';
	else if (c1 <= 'F')
	  c1 = c1 + 10 - 'A';
	else
	  c1 = c1 + 10 - 'a';
	if (c2 <= '9')
	  c2 = c2 - '0';
	else if (c2 <= 'F')
	  c2 = c2 + 10 - 'A';
	else
	  c2 = c2 + 10 - 'a';
	val = c1*16 + c2;
	vec.push_back((uint1)val);
	is >> ws;
	c1 = is.get();
	c2 = is.get();
      }
    }
    else
      throw LowlevelError("Unknown LoadImageXml tag: "+subel->getName());
  }
  pad();
}

void LoadImageXml::clear(void)

{
  archtype.clear();
  manage = (const AddrSpaceManager *)0;
  chunk.clear();
  addrtosymbol.clear();
}

void LoadImageXml::pad(void)

{
  map<Address,vector<uint1> >::iterator iter,lastiter;

  // Search for completely redundant chunks
  if (chunk.empty()) return;
  lastiter = chunk.begin();
  iter = lastiter;
  ++iter;
  while(iter!=chunk.end()) {
    if ((*lastiter).first.getSpace() == (*iter).first.getSpace()) {
      uintb end1 = (*lastiter).first.getOffset() + (*lastiter).second.size() - 1;
      uintb end2 = (*iter).first.getOffset() + (*iter).second.size() - 1;
      if (end1 >= end2) {
	chunk.erase(iter);
	iter = lastiter;
	++iter;
	continue;
      }
    }
    lastiter = iter;
    ++iter;
  }

  iter = chunk.begin();
  while(iter!=chunk.end()) {
    Address endaddr = (*iter).first + (*iter).second.size();
    if (endaddr < (*iter).first) {
      ++iter;
      continue; // All the way to end of space
    }
    ++iter;
    int4 maxsize = 512;
    uintb room = endaddr.getSpace()->getHighest() - endaddr.getOffset() + 1;
    if ((uintb)maxsize > room)
      maxsize = (int4)room;
    if ((iter!=chunk.end())&&((*iter).first.getSpace()==endaddr.getSpace())) {
      if (endaddr.getOffset() >= (*iter).first.getOffset()) continue;
      room = (*iter).first.getOffset() - endaddr.getOffset();
      if ((uintb)maxsize > room)
	maxsize = (int4)room;
    }
    vector<uint1> &vec( chunk[endaddr] );
    for(int4 i=0;i<maxsize;++i)
      vec.push_back(0);
  }
}

void LoadImageXml::loadFill(uint1 *ptr,int4 size,const Address &addr)

{
  map<Address,vector<uint1> >::const_iterator iter;
  Address curaddr;
  bool emptyhit = false;
  
  curaddr = addr;
  iter = chunk.upper_bound(curaddr); // First one greater than
  if (iter != chunk.begin())
    --iter;			// Last one less or equal
  while((size>0)&&(iter!=chunk.end())) {
    const vector<uint1> &chnk((*iter).second);
    int4 chnksize = chnk.size();
    int4 over = curaddr.overlap(0,(*iter).first,chnksize);
    if (over!=-1) {
      if (chnksize-over > size)
	chnksize = over+size;
      for(int4 i=over;i<chnksize;++i)
	*ptr++ = chnk[i];
      size -= (chnksize-over);
      curaddr = curaddr + (chnksize-over);
      ++iter;
    }
    else {
      emptyhit = true;
      break;
    }
  }
  if ((size>0)||emptyhit) {
    ostringstream errmsg;
    errmsg << "Bytes at ";
    curaddr.printRaw(errmsg);
    errmsg << " are not mapped";
    throw DataUnavailError(errmsg.str());
  }
}

void LoadImageXml::openSymbols(void) const

{
  cursymbol = addrtosymbol.begin();
}

bool LoadImageXml::getNextSymbol(LoadImageFunc &record) const

{
  if (cursymbol == addrtosymbol.end()) return false;
  record.name = (*cursymbol).second;
  record.address = (*cursymbol).first;
  ++cursymbol;
  return true;
}

void LoadImageXml::getReadonly(RangeList &list) const

{
  map<Address,vector<uint1> >::const_iterator iter;

  // List all the readonly chunks
  for(iter=chunk.begin();iter!=chunk.end();++iter) {
    if (readonlyset.find((*iter).first) != readonlyset.end()) {
      const vector<uint1> &chnk((*iter).second);
      uintb start = (*iter).first.getOffset();
      uintb stop = start + chnk.size() - 1;
      list.insertRange((*iter).first.getSpace(),start,stop);
    }
  }
}

void LoadImageXml::adjustVma(long adjust)

{
  map<Address,vector<uint1> >::iterator iter1;
  map<Address,string>::iterator iter2;

  map<Address,vector<uint1> > newchunk;
  map<Address,string> newsymbol;

  for(iter1=chunk.begin();iter1!=chunk.end();++iter1) {
    AddrSpace *spc = (*iter1).first.getSpace();
    int4 off = AddrSpace::addressToByte(adjust,spc->getWordSize());
    Address newaddr = (*iter1).first + off;
    newchunk[newaddr] = (*iter1).second;
  }
  chunk = newchunk;
  for(iter2=addrtosymbol.begin();iter2!=addrtosymbol.end();++iter2) {
    AddrSpace *spc = (*iter2).first.getSpace();
    int4 off = AddrSpace::addressToByte(adjust,spc->getWordSize());
    Address newaddr = (*iter2).first + off;
    newsymbol[newaddr] = (*iter2).second;
  }
  addrtosymbol = newsymbol;
}

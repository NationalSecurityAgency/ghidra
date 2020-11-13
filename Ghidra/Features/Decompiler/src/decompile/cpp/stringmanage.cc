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
#include "stringmanage.hh"
#include "architecture.hh"

/// \param max is the maximum number of characters to allow before truncating string
StringManager::StringManager(int4 max)

{
  maximumChars = max;
}

StringManager::~StringManager(void)

{
  clear();
}

/// Encode the given unicode codepoint as UTF8 (1, 2, 3, or 4 bytes) and
/// write the bytes to the stream.
/// \param s is the output stream
/// \param codepoint is the unicode codepoint
void StringManager::writeUtf8(ostream &s,int4 codepoint)

{
  uint1 bytes[4];
  int4 size;

  if (codepoint < 0)
    throw LowlevelError("Negative unicode codepoint");
  if (codepoint < 128) {
    s.put((uint1)codepoint);
    return;
  }
  int4 bits = mostsigbit_set(codepoint) + 1;
  if (bits > 21)
    throw LowlevelError("Bad unicode codepoint");
  if (bits < 12) {	// Encode with two bytes
    bytes[0] = 0xc0 ^ ((codepoint >> 6)&0x1f);
    bytes[1] = 0x80 ^ (codepoint & 0x3f);
    size = 2;
  }
  else if (bits < 17) {
    bytes[0] = 0xe0 ^ ((codepoint >> 12)&0xf);
    bytes[1] = 0x80 ^ ((codepoint >> 6)&0x3f);
    bytes[2] = 0x80 ^ (codepoint & 0x3f);
    size = 3;
  }
  else {
    bytes[0] = 0xf0 ^ ((codepoint >> 18) & 7);
    bytes[1] = 0x80 ^ ((codepoint >> 12) & 0x3f);
    bytes[2] = 0x80 ^ ((codepoint >> 6) & 0x3f);
    bytes[3] = 0x80 ^ (codepoint & 0x3f);
    size = 4;
  }
  s.write((char *)bytes, size);
}

/// Returns \b true if the data is some kind of complete string.
/// A given character data-type can be used as a hint for the encoding.
/// The string decoding can be cached internally.
/// \param addr is the given address
/// \param charType is the given character data-type
/// \return \b true if the address represents string data
bool StringManager::isString(const Address &addr,Datatype *charType)

{
  bool isTrunc;		// unused here
  const vector<uint1> &buffer(getStringData(addr,charType,isTrunc));
  return !buffer.empty();
}

/// Write \<stringmanage> tag, with \<string> sub-tags.
/// \param s is the stream to write to
void StringManager::saveXml(ostream &s) const

{
  s << "<stringmanage>\n";

  map<Address,StringData>::const_iterator iter1;
  for(iter1=stringMap.begin();iter1!=stringMap.end();++iter1) {
    s << "<string>\n";
    (*iter1).first.saveXml(s);
    const StringData &stringData( (*iter1).second );
    s << " <bytes";
    a_v_b(s, "trunc", stringData.isTruncated);
    s << ">\n" << setfill('0');
    for(int4 i=0;stringData.byteData.size();++i) {
      s << hex << setw(2) << (int4)stringData.byteData[i];
      if (i%20 == 19)
	s << "\n  ";
    }
    s << "\n </bytes>\n";
  }
  s << "</stringmanage>\n";
}

/// Read \<stringmanage> tag, with \<string> sub-tags.
/// \param el is the root tag element
/// \param m is the manager for looking up AddressSpaces
void StringManager::restoreXml(const Element *el, const AddrSpaceManager *m)

{
  const List &list(el->getChildren());
  List::const_iterator iter1;
  for (iter1 = list.begin(); iter1 != list.end(); ++iter1) {
    List::const_iterator iter2 = (*iter1)->getChildren().begin();
    Address addr = Address::restoreXml(*iter2, m);
    ++iter2;
    StringData &stringData(stringMap[addr]);
    stringData.isTruncated = xml_readbool((*iter2)->getAttributeValue("trunc"));
    istringstream is((*iter2)->getContent());
    int4 val;
    char c1, c2;
    is >> ws;
    c1 = is.get();
    c2 = is.get();
    while ((c1 > 0) && (c2 > 0)) {
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
      val = c1 * 16 + c2;
      stringData.byteData.push_back((uint1) val);
      is >> ws;
      c1 = is.get();
      c2 = is.get();
    }
  }
}

/// \param buffer is the byte buffer
/// \param size is the number of bytes in the buffer
/// \param charsize is the presumed size (in bytes) of character elements
/// \return \b true if a string terminator is found
bool StringManager::hasCharTerminator(const uint1 *buffer,int4 size,int4 charsize)

{
  for(int4 i=0;i<size;i+=charsize) {
    bool isTerminator = true;
    for(int4 j=0;j<charsize;++j) {
      if (buffer[i+j] != 0) {	// Non-zero bytes means character can't be a null terminator
	isTerminator = false;
	break;
      }
    }
    if (isTerminator) return true;
  }
  return false;
}

/// Pull the first two bytes from the byte array and combine them in the indicated endian order
/// \param buf is the byte array
/// \param bigend is \b true to request big endian encoding
/// \return the decoded UTF16 element
inline int4 StringManager::readUtf16(const uint1 *buf,bool bigend)

{
  int4 codepoint;
  if (bigend) {
    codepoint = buf[0];
    codepoint <<= 8;
    codepoint += buf[1];
  }
  else {
    codepoint = buf[1];
    codepoint <<= 8;
    codepoint += buf[0];
  }
  return codepoint;
}

/// One or more bytes is consumed from the array, and the number of bytes used is passed back.
/// \param buf is a pointer to the bytes in the character array
/// \param charsize is 1 for UTF8, 2 for UTF16, or 4 for UTF32
/// \param bigend is \b true for big endian encoding of the UTF element
/// \param skip is a reference for passing back the number of bytes consumed
/// \return the codepoint or -1 if the encoding is invalid
int4 StringManager::getCodepoint(const uint1 *buf,int4 charsize,bool bigend,int4 &skip)

{
  int4 codepoint;
  int4 sk = 0;
  if (charsize==2) {		// UTF-16
    codepoint = readUtf16(buf,bigend);
    sk += 2;
    if ((codepoint>=0xD800)&&(codepoint<=0xDBFF)) { // high surrogate
      int4 trail=readUtf16(buf+2,bigend);
      sk += 2;
      if ((trail<0xDC00)||(trail>0xDFFF)) return -1; // Bad trail
      codepoint = (codepoint<<10) + trail + (0x10000 - (0xD800 << 10) - 0xDC00);
    }
    else if ((codepoint>=0xDC00)&&(codepoint<=0xDFFF)) return -1; // trail before high
  }
  else if (charsize==1) {	// UTF-8
    int4 val = buf[0];
    if ((val&0x80)==0) {
      codepoint = val;
      sk = 1;
    }
    else if ((val&0xe0)==0xc0) {
      int4 val2 = buf[1];
      sk = 2;
      if ((val2&0xc0)!=0x80) return -1; // Not a valid UTF8-encoding
      codepoint = ((val&0x1f)<<6) | (val2 & 0x3f);
    }
    else if ((val&0xf0)==0xe0) {
      int4 val2 = buf[1];
      int4 val3 = buf[2];
      sk = 3;
      if (((val2&0xc0)!=0x80)||((val3&0xc0)!=0x80)) return -1; // invalid encoding
      codepoint = ((val&0xf)<<12) | ((val2&0x3f)<<6) | (val3 & 0x3f);
    }
    else if ((val&0xf8)==0xf0) {
      int4 val2 = buf[1];
      int4 val3 = buf[2];
      int4 val4 = buf[3];
      sk = 4;
      if (((val2&0xc0)!=0x80)||((val3&0xc0)!=0x80)||((val4&0xc0)!=0x80)) return -1;	// invalid encoding
      codepoint = ((val&7)<<18) | ((val2&0x3f)<<12) | ((val3&0x3f)<<6) | (val4 & 0x3f);
    }
    else
      return -1;
  }
  else if (charsize == 4) {	// UTF-32
    sk = 4;
    if (bigend)
      codepoint = (buf[0]<<24) + (buf[1]<<16) + (buf[2]<<8) + buf[3];
    else
      codepoint = (buf[3]<<24) + (buf[2]<<16) + (buf[1]<<8) + buf[0];
  }
  else
    return -1;
  if (codepoint >= 0xd800 && codepoint <= 0xdfff)
    return -1;		// Reserved for surrogates, invalid codepoints
  skip = sk;
  return codepoint;
}

/// \param g is the underlying architecture (and loadimage)
/// \param max is the maximum number of bytes to allow in a decoded string
StringManagerUnicode::StringManagerUnicode(Architecture *g,int4 max)
  : StringManager(max)
{
  glb = g;
  testBuffer = new uint1[max];
}

StringManagerUnicode::~StringManagerUnicode(void)

{
  delete [] testBuffer;
}

const vector<uint1> &StringManagerUnicode::getStringData(const Address &addr,Datatype *charType,bool &isTrunc)

{
  map<Address,StringData>::iterator iter;
  iter = stringMap.find(addr);
  if (iter != stringMap.end()) {
    isTrunc = (*iter).second.isTruncated;
    return (*iter).second.byteData;
  }

  StringData &stringData(stringMap[addr]);		// Allocate (initially empty) byte vector
  stringData.isTruncated = false;
  isTrunc = false;

  if (charType->isOpaqueString())		// Cannot currently test for an opaque encoding
    return stringData.byteData;			// Return the empty buffer

  int4 curBufferSize = 0;
  int4 charsize = charType->getSize();
  bool foundTerminator = false;

  try {
    do {
      int4 amount = 32;	// Grab 32 bytes of image at a time
      uint4 newBufferSize = curBufferSize + amount;
      if (newBufferSize > maximumChars) {
	newBufferSize = maximumChars;
	amount = newBufferSize - curBufferSize;
	if (amount == 0) {
	  return stringData.byteData;		// Could not find terminator
	}
      }
      glb->loader->loadFill(testBuffer + curBufferSize, amount,
			    addr + curBufferSize);
      foundTerminator = hasCharTerminator(testBuffer + curBufferSize, amount,
					  charsize);
      curBufferSize = newBufferSize;
    } while (!foundTerminator);
  } catch (DataUnavailError &err) {
    return stringData.byteData;			// Return the empty buffer
  }

  int4 numChars = checkCharacters(testBuffer, curBufferSize, charsize);
  if (numChars < 0)
    return stringData.byteData;		// Return the empty buffer (invalid encoding)
  if (charsize == 1 && numChars < maximumChars) {
    stringData.byteData.reserve(curBufferSize);
    stringData.byteData.assign(testBuffer,testBuffer+curBufferSize);
  }
  else {
    // We need to translate to UTF8 and/or truncate
    ostringstream s;
    if (!writeUnicode(s, testBuffer, curBufferSize, charsize))
      return stringData.byteData;		// Return the empty buffer
    string resString = s.str();
    int4 newSize = resString.size();
    stringData.byteData.reserve(newSize + 1);
    const uint1 *ptr = (const uint1 *)resString.c_str();
    stringData.byteData.assign(ptr,ptr+newSize);
    stringData.byteData[newSize] = 0;		// Make sure there is a null terminator
  }
  stringData.isTruncated = (numChars >= maximumChars);
  isTrunc = stringData.isTruncated;
  return stringData.byteData;
}

/// Check that the given buffer contains valid unicode.
/// If the string is encoded in UTF8 or ASCII, we get (on average) a bit of check
/// per character.  For UTF16, the surrogate reserved area gives at least some check.
/// \param buf is the byte array to check
/// \param size is the size of the buffer in bytes
/// \param charsize is the UTF encoding (1=UTF8, 2=UTF16, 4=UTF32)
/// \return the number of characters or -1 if there is an invalid encoding
int4 StringManagerUnicode::checkCharacters(const uint1 *buf,int4 size,int4 charsize) const

{
  if (buf == (const uint1 *)0) return -1;
  bool bigend = glb->translate->isBigEndian();
  int4 i=0;
  int4 count=0;
  int4 skip = charsize;
  while(i<size) {
    int4 codepoint = getCodepoint(buf+i,charsize,bigend,skip);
    if (codepoint < 0) return -1;
    if (codepoint == 0) break;
    count += 1;
    i += skip;
  }
  return count;
}

/// Assume the buffer contains a null terminated unicode encoded string.
/// Write the characters out (as UTF8) to the stream.
/// \param s is the output stream
/// \param buffer is the given byte buffer
/// \param size is the number of bytes in the buffer
/// \param charsize specifies the encoding (1=UTF8 2=UTF16 4=UTF32)
/// \return \b true if the byte array contains valid unicode
bool StringManagerUnicode::writeUnicode(ostream &s,uint1 *buffer,int4 size,int4 charsize)

{
  bool bigend = glb->translate->isBigEndian();
  int4 i=0;
  int4 count=0;
  int4 skip = charsize;
  while(i<size) {
    int4 codepoint = getCodepoint(buffer+i,charsize,bigend,skip);
    if (codepoint < 0) return false;
    if (codepoint == 0) break;		// Terminator
    writeUtf8(s, codepoint);
    i += skip;
    count += 1;
    if (count >= maximumChars)
      break;
  }
  return true;
}

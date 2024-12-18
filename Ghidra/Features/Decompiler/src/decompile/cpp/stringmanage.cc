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
#include "crc32.hh"

namespace ghidra {

AttributeId ATTRIB_TRUNC = AttributeId("trunc",69);

ElementId ELEM_BYTES = ElementId("bytes",83);
ElementId ELEM_STRING = ElementId("string",84);
ElementId ELEM_STRINGMANAGE = ElementId("stringmanage",85);

/// Assume the buffer contains a null terminated unicode encoded string.
/// Write the characters out (as UTF8) to the stream.
/// \param s is the output stream
/// \param buffer is the given byte buffer
/// \param size is the number of bytes in the buffer
/// \param charsize specifies the encoding (1=UTF8 2=UTF16 4=UTF32)
/// \param bigend is \b true if (UTF16 and UTF32) are big endian encoded
/// \return \b true if the byte array contains valid unicode
bool StringManager::writeUnicode(ostream &s,const uint1 *buffer,int4 size,int4 charsize,bool bigend)

{
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

/// \brief Translate and assign raw string data to a StringData object
///
/// The string data is provided as raw bytes.  The data is translated to UTF-8 and truncated
/// to the \b maximumChars allowed by the manager.  The encoding must be legal unicode as performed
/// by checkCharacters().
/// \param data is the StringData object to populate
/// \param buf is the raw byte array
/// \param size is the number of bytes in the array
/// \param charsize is the size of unicode encoding
/// \param numChars is the number of characters in the encoding as returned by checkCharacters()
/// \param bigend is \b true if UTF-16 and UTF-32 elements are big endian encoded
void StringManager::assignStringData(StringData &data,const uint1 *buf,int4 size,int4 charsize,int4 numChars,bool bigend)

{
  if (charsize == 1 && numChars < maximumChars) {
    data.byteData.reserve(size);
    data.byteData.assign(buf,buf+size);
  }
  else {
    // We need to translate to UTF8 and/or truncate
    ostringstream s;
    if (!writeUnicode(s, buf, size, charsize, bigend))
      return;
    string resString = s.str();
    int4 newSize = resString.size();
    data.byteData.reserve(newSize + 1);
    const uint1 *ptr = (const uint1 *)resString.c_str();
    data.byteData.assign(ptr,ptr+newSize);
    data.byteData[newSize] = 0;		// Make sure there is a null terminator
  }
  data.isTruncated = (numChars >= maximumChars);
}

/// \brief Calculate hash of a specific Address and contents of a byte array
///
/// Calculate a 32-bit CRC of the bytes and XOR into the upper part of the Address offset.
/// \param addr is the specific Address
/// \param buf is a pointer to the array of bytes
/// \param size is the number of bytes in the array
/// \return the 64-bit hash
uint8 StringManager::calcInternalHash(const Address &addr,const uint1 *buf,int4 size)

{
  uint4 reg = 0x7b7c66a9;
  for(int4 i=0;i<size;++i) {
    reg = crc_update(reg, buf[i]);
  }
  uint8 res = addr.getOffset();
  res ^= ((uint8)reg) << 32;
  return res;
}

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

/// \brief Associate string data at a code address or other location that doesn't hold string data normally
///
/// The given byte buffer is decoded, and if it represents a legal string, a non-zero hash is returned,
/// constructed from an Address associated with the string and the string data itself. The registered string
/// can be retrieved via the getStringData() method using this hash as a constant Address.  If the string is not
/// legal, 0 is returned.
/// \param addr is the address to associate with the string data
/// \param buf is a pointer to the array of raw bytes encoding the string
/// \param size is the number of bytes in the array
/// \param charType is a character data-type indicating the encoding
/// \return a hash associated with the string or 0
uint8 StringManager::registerInternalStringData(const Address &addr,const uint1 *buf,int4 size,Datatype *charType)

{
  int4 charsize = charType->getSize();
  int4 numChars = checkCharacters(buf, size, charsize, addr.isBigEndian());
  if (numChars < 0)
    return 0;	// Not a legal encoding
  uint8 hash = calcInternalHash(addr, buf, size);
  Address constAddr = addr.getSpace()->getManager()->getConstant(hash);
  StringData &stringData( stringMap[constAddr] );
  stringData.byteData.clear();
  stringData.isTruncated = false;
  assignStringData(stringData, buf, size, charsize, numChars, addr.isBigEndian());
  return hash;
}

/// Encode \<stringmanage> element, with \<string> children.
/// \param encoder is the stream encoder
void StringManager::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_STRINGMANAGE);

  map<Address,StringData>::const_iterator iter1;
  for(iter1=stringMap.begin();iter1!=stringMap.end();++iter1) {
    encoder.openElement(ELEM_STRING);
    (*iter1).first.encode(encoder);
    const StringData &stringData( (*iter1).second );
    encoder.openElement(ELEM_BYTES);
    encoder.writeBool(ATTRIB_TRUNC, stringData.isTruncated);
    ostringstream s;
    s << '\n' << setfill('0');
    for(int4 i=0;i<stringData.byteData.size();++i) {
      s << hex << setw(2) << (int4)stringData.byteData[i];
      if (i%20 == 19)
	s << "\n  ";
    }
    s << '\n';
    encoder.writeString(ATTRIB_CONTENT, s.str());
    encoder.closeElement(ELEM_BYTES);
  }
  encoder.closeElement(ELEM_STRINGMANAGE);
}

/// Parse a \<stringmanage> element, with \<string> children.
/// \param decoder is the stream decoder
void StringManager::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_STRINGMANAGE);
  for (;;) {
    uint4 subId = decoder.openElement();
    if (subId != ELEM_STRING) break;
    Address addr = Address::decode(decoder);
    StringData &stringData(stringMap[addr]);
    uint4 subId2 = decoder.openElement(ELEM_BYTES);
    stringData.isTruncated = decoder.readBool(ATTRIB_TRUNC);
    istringstream is(decoder.readString(ATTRIB_CONTENT));
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
    decoder.closeElement(subId2);
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
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

/// \brief Make sure buffer has valid bounded set of unicode
///
/// Check that the given buffer contains valid unicode.
/// If the string is encoded in UTF8 or ASCII, we get (on average) a bit of check
/// per character.  For UTF16, the surrogate reserved area gives at least some check.
/// \param buf is the byte array to check
/// \param size is the size of the buffer in bytes
/// \param charsize is the UTF encoding (1=UTF8, 2=UTF16, 4=UTF32)
/// \param bigend is \b true if the (UTF16 and UTF32) characters are big endian encoded
/// \return the number of characters or -1 if there is an invalid encoding
int4 StringManager::checkCharacters(const uint1 *buf,int4 size,int4 charsize,bool bigend)

{
  if (buf == (const uint1 *)0) return -1;
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
  if (codepoint >= 0xd800) {
    if (codepoint > 0x10ffff)	// Bigger than maximum codepoint
      return -1;
    if (codepoint <= 0xdfff)
      return -1;		// Reserved for surrogates, invalid codepoints
  }
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

  int4 numChars = checkCharacters(testBuffer, curBufferSize, charsize, addr.isBigEndian());
  if (numChars < 0)
    return stringData.byteData;		// Return the empty buffer (invalid encoding)
  assignStringData(stringData, testBuffer, curBufferSize, charsize, numChars, addr.isBigEndian());
  isTrunc = stringData.isTruncated;
  return stringData.byteData;
}

} // End namespace ghidra

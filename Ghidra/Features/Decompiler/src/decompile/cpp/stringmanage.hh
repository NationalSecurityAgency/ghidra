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
/// \file stringmanage.hh
/// \brief Classes for decoding and storing string data

#ifndef __STRINGMANAGE_HH__
#define __STRINGMANAGE_HH__

#include "type.hh"

namespace ghidra {

class Architecture;

extern AttributeId ATTRIB_TRUNC;	///< Marshaling attribute "trunc"

extern ElementId ELEM_BYTES;		///< Marshaling element \<bytes>
extern ElementId ELEM_STRING;		///< Marshaling element \<string>
extern ElementId ELEM_STRINGMANAGE;	///< Marshaling element \<stringmanage>

/// \brief Storage for decoding and storing strings associated with an address
///
/// Looks at data in the loadimage to determine if it represents a "string". Decodes the string for
/// presentation in the output. Stores the decoded string until its needed for presentation.  Strings are
/// associated with their starting address in memory.  An \e internal string (that is not in the loadimage) can
/// be registered with the manager and will be associated with a constant.
class StringManager {
protected:
  /// \brief String data (a sequence of bytes) stored by StringManager
  class StringData {
  public:
    bool isTruncated;		///< \b true if the string is truncated
    vector<uint1> byteData;	///< UTF8 encoded string data
  };
  map<Address,StringData> stringMap;	///< Map from address to string data
  int4 maximumChars;			///< Maximum characters in a string before truncating
  bool writeUnicode(ostream &s,const uint1 *buffer,int4 size,int4 charsize,bool bigend);	///< Translate/copy unicode to UTF8
  void assignStringData(StringData &data,const uint1 *buf,int4 size,int4 charsize,int4 numChars,bool bigend);
  static uint8 calcInternalHash(const Address &addr,const uint1 *buf,int4 size);
public:
  StringManager(int4 max);		///< Constructor
  virtual ~StringManager(void);		///< Destructor

  void clear(void) { stringMap.clear(); }			///< Clear out any cached strings

  bool isString(const Address &addr,Datatype *charType);	// Determine if data at the given address is a string

  /// \brief Retrieve string data at the given address as a UTF8 byte array
  ///
  /// If the address does not represent string data, a zero length vector is returned. Otherwise,
  /// the string data is fetched, converted to a UTF8 encoding, cached and returned.
  /// \param addr is the given address
  /// \param charType is a character data-type indicating the encoding
  /// \param isTrunc passes back whether the string is truncated
  /// \return the byte array of UTF8 data
  virtual const vector<uint1> &getStringData(const Address &addr,Datatype *charType,bool &isTrunc)=0;

  uint8 registerInternalStringData(const Address &addr,const uint1 *buf,int4 size,Datatype *charType);
  void encode(Encoder &encoder) const;	///< Encode cached strings to a stream
  void decode(Decoder &decoder);	///< Restore string cache from a stream

  static bool hasCharTerminator(const uint1 *buffer,int4 size,int4 charsize);	///< Check for a unicode string terminator
  static int4 readUtf16(const uint1 *buf,bool bigend);	///< Read a UTF16 code point from a byte array
  static void writeUtf8(ostream &s,int4 codepoint);	///< Write unicode character to stream in UTF8 encoding
  static int4 checkCharacters(const uint1 *buf,int4 size,int4 charsize,bool bigend);
  static int4 getCodepoint(const uint1 *buf,int4 charsize,bool bigend,int4 &skip);	///< Extract next \e unicode \e codepoint
};

/// \brief An implementation of StringManager that understands terminated unicode strings
///
/// This class understands UTF8, UTF16, and UTF32 encodings.  It reports a string if its
/// sees a valid encoding that is null terminated.
class StringManagerUnicode : public StringManager {
  Architecture *glb;		///< Underlying architecture
  uint1 *testBuffer;		///< Temporary buffer for pulling in loadimage bytes
public:
  StringManagerUnicode(Architecture *g,int4 max);	///< Constructor
  virtual ~StringManagerUnicode(void);

  virtual const vector<uint1> &getStringData(const Address &addr,Datatype *charType,bool &isTrunc);
};

} // End namespace ghidra
#endif

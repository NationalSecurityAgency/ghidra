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

#ifndef __STRING_MANAGE__
#define __STRING_MANAGE__

#include "type.hh"

class Architecture;

/// \brief Storage for decoding and storing strings associated with an address
///
/// Looks at data in the loadimage to determine if it represents a "string".
/// Decodes the string for presentation in the output.
/// Stores the decoded string until its needed for presentation.
class StringManager {
protected:
  map<Address,vector<uint1> > stringMap;	///< Map from address to string (in UTF8 format)
  int4 maximumBytes;				///< Maximum bytes (in UTF8 encoding) allowed
public:
  StringManager(int4 max);		///< Constructor
  virtual ~StringManager(void);		///< Destructor

  int4 getMaximumBytes(void) const { return maximumBytes; }	///< Return the maximum bytes allowed in a string decoding
  void clear(void) { stringMap.clear(); }			///< Clear out any cached strings

  bool isString(const Address &addr,Datatype *charType);	// Determine if data at the given address is a string

  /// \brief Retrieve string data at the given address as a UTF8 byte array
  ///
  /// If the address does not represent string data, a zero length vector is returned. Otherwise,
  /// the string data is fetched, converted to a UTF8 encoding, cached and returned.
  /// \param addr is the given address
  /// \param charType is a character data-type indicating the encoding
  /// \return the byte array of UTF8 data
  virtual const vector<uint1> &getStringData(const Address &addr,Datatype *charType)=0;

  void saveXml(ostream &s) const;	///< Save cached strings to a stream as XML
  void restoreXml(const Element *el,const AddrSpaceManager *m);	///< Restore string cache from XML

  static bool hasCharTerminator(const uint1 *buffer,int4 size,int4 charsize);	///< Check for a unicode string terminator
  static int4 readUtf16(const uint1 *buf,bool bigend);	///< Read a UTF16 code point from a byte array
  static void writeUtf8(ostream &s,int4 codepoint);	///< Write unicode character to stream in UTF8 encoding
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

  virtual const vector<uint1> &getStringData(const Address &addr,Datatype *charType);
  bool isCharacterConstant(const uint1 *buf,int4 size,int4 charsize) const;	///< Return \b true if buffer looks like unicode
  bool writeUnicode(ostream &s,uint1 *buffer,int4 size,int4 charsize);	///< Write unicode byte array to stream (as UTF8)
};

#endif

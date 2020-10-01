/* ###
 * IP: GHIDRA
 * NOTE: Interface to GNU BFD library which is GPL 3
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
// Use the GNU bfd library to manipulate a load image

#ifndef __LOADIMAGE_BFD__
#define __LOADIMAGE_BFD__

#include "loadimage.hh"
#include <bfd.h>

struct ImportRecord {
  string dllname;
  string funcname;
  int ordinal;
  Address address;
  Address thunkaddress;
};

class LoadImageBfd : public LoadImage {
  static int4 bfdinit;		// Is the library (globally) initialized
  string target;		// File format (supported by BFD)
  bfd *thebfd;
  AddrSpace *spaceid;		// We need to map space id to segments but since
				// we are currently ignoring segments anyway...
  uintb bufoffset;		// Starting offset of byte buffer
  uint4 bufsize;		// Number of bytes in the buffer
  uint1 *buffer;		// The actual buffer
  mutable asymbol **symbol_table;
  mutable long number_of_symbols;
  mutable long cursymbol;
  mutable asection *secinfoptr;
  asection *findSection(uintb offset,uintb &ssize) const; // Find section containing given offset
  void advanceToNextSymbol(void) const;
public:
  LoadImageBfd(const string &f,const string &t);
  void attachToSpace(AddrSpace *id) { spaceid = id; }
  void open(void);		// Open any descriptors
  void close(void);		// Close any descriptor
  void getImportTable(vector<ImportRecord> &irec) { throw LowlevelError("Not implemented"); }
  virtual ~LoadImageBfd(void);
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr); // Load a chunk of image
  virtual void openSymbols(void) const;
  virtual void closeSymbols(void) const;
  virtual bool getNextSymbol(LoadImageFunc &record) const;
  virtual void openSectionInfo(void) const;
  virtual void closeSectionInfo(void) const;
  virtual bool getNextSection(LoadImageSection &sec) const;
  virtual void getReadonly(RangeList &list) const;
  virtual string getArchType(void) const;
  virtual void adjustVma(long adjust);
};

#endif

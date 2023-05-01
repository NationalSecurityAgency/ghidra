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
#include "loadimage.hh"

namespace ghidra {

/// This is a convenience method wrapped around the core
/// loadFill() routine.  It automatically allocates an array
/// of the desired size, and then fills it with load image data.
/// If the array cannot be allocated, an exception is thrown.
/// The caller assumes the responsibility of freeing the
/// array after it has been used.
/// \param size is the number of bytes to read from the image
/// \param addr is the address of the first byte being read
/// \return a pointer to the desired bytes
uint1 *LoadImage::load(int4 size,const Address &addr)

{
  uint1 *buf = new uint1[ size ];
  if (buf == (uint1 *)0)
    throw LowlevelError("Out of memory");
  loadFill(buf,size,addr);
  return buf;
}

RawLoadImage::RawLoadImage(const string &f) : LoadImage(f)

{
  vma = 0;
  thefile = (ifstream *)0;
  spaceid = (AddrSpace *)0;
  filesize = 0;
}

RawLoadImage::~RawLoadImage(void)

{
  if (thefile != (ifstream *)0) {
    thefile->close();
    delete thefile;
  }
}

/// The file is opened and its size immediately recovered.
void RawLoadImage::open(void)

{
  if (thefile != (ifstream *)0) throw LowlevelError("loadimage is already open");
  thefile = new ifstream(filename.c_str());
  if (!(*thefile)) {
    string errmsg = "Unable to open raw image file: "+filename;
    throw LowlevelError(errmsg);
  }
  thefile->seekg(0,ios::end);
  filesize = thefile->tellg();
}

string RawLoadImage::getArchType(void) const

{
  return "unknown";
}

void RawLoadImage::adjustVma(long adjust)

{
  adjust = AddrSpace::addressToByte(adjust,spaceid->getWordSize());
  vma += adjust;
}

void RawLoadImage::loadFill(uint1 *ptr,int4 size,const Address &addr)

{
  uintb curaddr = addr.getOffset();
  uintb offset = 0;
  uintb readsize;

  curaddr -= vma;		// Get relative offset of first byte
  while(size>0) {
    if (curaddr >= filesize) {
      if (offset == 0)		// Initial address not within file
	break;
      memset(ptr+offset,0,size); // Fill out the rest of the buffer with 0
      return;
    }
    readsize = size;
    if (curaddr + readsize > filesize) // Adjust to biggest possible read
      readsize = filesize - curaddr;
    thefile->seekg(curaddr);
    thefile->read((char *)(ptr+offset),readsize);
    offset += readsize;
    size -= readsize;
    curaddr += readsize;
  }
  if (size > 0) {
    ostringstream errmsg;
    errmsg << "Unable to load " << dec << size << " bytes at " << addr.getShortcut();
    addr.printRaw(errmsg);
    throw DataUnavailError(errmsg.str());
  }
}

} // End namespace ghidra

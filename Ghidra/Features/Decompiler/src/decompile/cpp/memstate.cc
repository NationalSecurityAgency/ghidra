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
#include "memstate.hh"
#include "translate.hh"

/// This is a static convenience routine for decoding a value from a sequence of bytes depending
/// on the desired endianness
/// \param ptr is the pointer to the bytes to decode
/// \param size is the number of bytes
/// \param bigendian is \b true if the bytes are encoded in big endian form
/// \return the decoded value
uintb MemoryBank::constructValue(const uint1 *ptr,int4 size,bool bigendian)

{ 
  uintb res = 0;

  if (bigendian) {
    for(int4 i=0;i<size;++i) {
      res <<= 8;
      res += (uintb) ptr[i];
    }
  }
  else {
    for(int4 i=size-1;i>=0;--i) {
      res <<= 8;
      res += (uintb) ptr[i];
    }
  }
  return res;
}

/// This is a static convenience routine for encoding bytes from a given value, depending on
/// the desired endianness
/// \param ptr is a pointer to the location to write the encoded bytes
/// \param val is the value to be encoded
/// \param size is the number of bytes to encode
/// \param bigendian is \b true if a big endian encoding is desired
void MemoryBank::deconstructValue(uint1 *ptr,uintb val,int4 size,bool bigendian)

{
  if (bigendian) {
    for(int4 i=size-1;i>=0;--i) {
      ptr[i] = (uint1) (val & 0xff);
      val >>= 8;
    }
  }
  else {
    for(int4 i=0;i<size;++i) {
      ptr[i] = (uint1) (val & 0xff);
      val >>= 8;
    }
  }
}

/// A MemoryBank must be associated with a specific address space, have a preferred or natural
/// \e wordsize and a natural \e pagesize.  Both the \e wordsize and \e pagesize must be a power of 2.
/// \param spc is the associated address space
/// \param ws is the number of bytes in the preferred wordsize
/// \param ps is the number of bytes in a page
MemoryBank::MemoryBank(AddrSpace *spc,int4 ws,int4 ps)

{
  space = spc;
  wordsize = ws;
  pagesize = ps;
}

/// This routine only retrieves data from a single \e page in the memory bank. Bytes need not
/// be retrieved from the exact start of a page, but all bytes must come from \e one page.
/// A page is a fixed number of bytes, and the address of a page is always aligned based
/// on that number of bytes.  This routine may be overridden for a page based implementation
/// of the MemoryBank.  The default implementation retrieves the page as aligned words
/// using the find method.
/// \param addr is the \e aligned offset of the desired page
/// \param res is a pointer to where fetched data should be written
/// \param skip is the offset \e into \e the \e page to get the bytes from
/// \param size is the number of bytes to retrieve
void MemoryBank::getPage(uintb addr,uint1 *res,int4 skip,int4 size) const

{ // Default implementation just iterates using find
  // but could be optimized
  uintb ptraddr = addr + skip;
  uintb endaddr = ptraddr + size;
  uintb startalign = ptraddr & ~((uintb)(wordsize-1));
  uintb endalign = endaddr & ~((uintb)(wordsize-1));
  if ((endaddr & ((uintb)(wordsize-1))) != 0)
    endalign += wordsize;

  uintb curval;
  bool bswap = ((HOST_ENDIAN==1) != space->isBigEndian());
  uint1 *ptr;
  do {
    curval = find(startalign);
    if (bswap)
      curval = byte_swap(curval,wordsize);
    ptr = (uint1 *)&curval;
    int4 sz = wordsize;
    if (startalign < addr) {
      ptr += (addr-startalign);
      sz = wordsize - (addr-startalign);
    }
    if (startalign + wordsize > endaddr)
      sz -= (startalign + wordsize -endaddr);
    memcpy(res,ptr,sz);
    res += sz;
    startalign += wordsize;
  } while(startalign != endalign);
}

/// This routine writes data only to a single \e page of the memory bank. Bytes need not be
/// written to the exact start of the page, but all bytes must be written to only one page
/// when using this routine. A page is a
/// fixed number of bytes, and the address of a page is always aligned based on this size.
/// This routine may be overridden for a page based implementation of the MemoryBank. The
/// default implementation writes the page as a sequence of aligned words, using the
/// insert method.
/// \param addr is the \e aligned offset of the desired page
/// \param val is a pointer to the bytes to be written into the page
/// \param skip is the offset \e into \e the \e page where bytes will be written
/// \param size is the number of bytes to be written
void MemoryBank::setPage(uintb addr,const uint1 *val,int4 skip,int4 size)
  
{  // Default implementation just iterates using insert
   // but could be optimized
  uintb ptraddr = addr + skip;
  uintb endaddr = ptraddr + size;
  uintb startalign = ptraddr & ~((uintb)(wordsize-1));
  uintb endalign = endaddr & ~((uintb)(wordsize-1));
  if ((endaddr & ((uintb)(wordsize-1))) != 0)
    endalign += wordsize;

  uintb curval;
  bool bswap = ((HOST_ENDIAN==1) != space->isBigEndian());
  uint1 *ptr;
  do {
    ptr = (uint1 *)&curval;
    int4 sz = wordsize;
    if (startalign < addr) {
      ptr += (addr-startalign);
      sz = wordsize - (addr-startalign);
    }
    if (startalign + wordsize > endaddr)
      sz -= (startalign + wordsize - endaddr);
    if (sz != wordsize) {
      curval = find(startalign); // Part of word is copied from underlying
      memcpy(ptr,val,sz);	 // Rest is taken from -val-
    }
    else
      curval = *((const uintb *)val); // -val- supplies entire word
    if (bswap)
      curval = byte_swap(curval,wordsize);
    insert(startalign,curval);
    val += sz;
    startalign += wordsize;
  } while(startalign != endalign);
}

/// This routine is used to set a single value in the memory bank at an arbitrary address
/// It takes into account the endianness of the associated address space when encoding the
/// value as bytes in the bank.  The value is broken up into aligned pieces of \e wordsize and
/// the actual \b write is performed with the insert routine.  If only parts of aligned words
/// are written to, then the remaining parts are filled in with the original value, via the
/// find routine.
/// \param offset is the start of the byte range to write
/// \param size is the number of bytes in the range to write
/// \param val is the value to be written
void MemoryBank::setValue(uintb offset,int4 size,uintb val)

{
  uintb alignmask = (uintb)(wordsize-1);
  uintb ind = offset & (~alignmask);
  int4 skip = offset & alignmask;
  int4 size1 = wordsize-skip;
  int4 size2;
  int4 gap;
  uintb val1,val2;

  if (size > size1) {		// We have spill over
    size2 = size - size1;
    val1 = find(ind);
    val2 = find(ind+wordsize);
    gap = wordsize - size2;
  }
  else {
    if (size == wordsize) {
      insert(ind,val);
      return;
    }
    val1 = find(ind);
    val2 = 0;
    gap = size1-size;
    size1 = size;
    size2 = 0;
  }

  skip = skip * 8;		// Convert from byte skip to bit skip
  gap = gap * 8;		// Convert from byte to bits
  if (space->isBigEndian()) {
    if (size2 == 0) {
      val1 &= ~(calc_mask(size1)<<gap);
      val1 |= val << gap;
      insert(ind,val1);
    }
    else {
      val1 &= (~((uintb)0)) << 8*size1;
      val1 |= val >> 8*size2;
      insert(ind,val1);
      val2 &= (~((uintb)0)) >> 8*size2;
      val2 |= val << gap;
      insert(ind+wordsize,val2);
    }
  }
  else {
    if (size2 == 0) {
      val1 &= ~(calc_mask(size1)<<skip);
      val1 |= val << skip;
      insert(ind,val1);
    }
    else {
      val1 &= (~((uintb)0)) >> 8*size1;
      val1 |= val << skip;
      insert(ind,val1);
      val2 &= (~((uintb)0)) << 8*size2;
      val2 |= val >> 8*size1;
      insert(ind+wordsize,val2);
    }
  }
}

/// This routine gets the value from a range of bytes at an arbitrary address.
/// It takes into account the endianness of the underlying space when decoding the value.
/// The value is constructed by making one or more aligned word queries, using the find method.
/// The desired value may span multiple words and is reconstructed properly.
/// \param offset is the start of the byte range encoding the value
/// \param size is the number of bytes in the range
/// \return the decoded value
uintb MemoryBank::getValue(uintb offset,int4 size) const

{
  uintb res;
 
  uintb alignmask = (uintb) (wordsize-1);
  uintb ind = offset & (~alignmask);
  int4 skip = offset & alignmask;
  int4 size1 = wordsize-skip;
  int4 size2;
  int4 gap;
  uintb val1,val2;
  if (size > size1) {		// We have spill over
    size2 = size - size1;
    val1 = find(ind);
    val2 = find(ind+wordsize);
    gap = wordsize - size2;
  }
  else {
    val1 = find(ind);
    val2 = 0;
    if (size == wordsize)
      return val1;
    gap = size1-size;
    size1 = size;
    size2 = 0;
  }

  if (space->isBigEndian()) {
    if (size2 == 0)
      res = val1>>(8*gap);
    else
      res = (val1<<(8*size2)) | (val2 >> (8*gap));
  }
  else {
    if (size2 == 0)
      res = val1 >> (skip*8);
    else
      res = (val1>>(skip*8)) | (val2<<(size1*8) );
  }
  res &= (uintb)calc_mask(size);
  return res;
}

/// This the most general method for writing a sequence of bytes into the memory bank.
/// There is no restriction on the offset to write to or the number of bytes to be written,
/// except that the range must be contained in the address space.
/// \param offset is the start of the byte range to be written
/// \param size is the number of bytes to write
/// \param val is a pointer to the sequence of bytes to be written into the bank
void MemoryBank::setChunk(uintb offset,int4 size,const uint1 *val)

{
  int4 cursize;
  int4 count;
  uintb pagemask = (uintb) (pagesize - 1);
  uintb offalign;
  int4 skip;

  count = 0;
  while(count < size) {
    cursize = pagesize;
    offalign = offset & ~pagemask;
    skip = 0;
    if (offalign != offset) {
      skip = offset - offalign;
      cursize -= skip;
    }
    if (size - count < cursize)
      cursize = size - count;
    setPage(offalign,val,skip,cursize);
    count += cursize;
    offset += cursize;
    val += cursize;
  }
}

/// This is the most general method for reading a sequence of bytes from the memory bank.
/// There is no restriction on the offset or the number of bytes to read, except that the
/// range must be contained in the address space.
/// \param offset is the start of the byte range to read
/// \param size is the number of bytes to read
/// \param res is a pointer to where the retrieved bytes should be stored
void MemoryBank::getChunk(uintb offset,int4 size,uint1 *res) const

{
  int4 cursize,count;
  uintb pagemask = (uintb) (pagesize-1);
  uintb offalign;
  int4 skip;

  count = 0;
  while(count < size) {
    cursize = pagesize;
    offalign = offset & ~pagemask;
    skip = 0;
    if (offalign != offset) {
      skip = offset-offalign;
      cursize -= skip;
    }
    if (size - count < cursize)
      cursize = size - count;
    getPage(offalign,res,skip,cursize);
    count += cursize;
    offset += cursize;
    res += cursize;
  }
}

/// Find an aligned word from the bank.  First an attempt is made to fetch the data from the
/// LoadImage.  If this fails, the value is returned as 0.
/// \param addr is the address of the word to fetch
/// \return the fetched value
uintb MemoryImage::find(uintb addr) const

{ // Assume that -addr- is word aligned
  uintb res = 0;		// Make sure all bytes start as 0, as load may not fill all bytes
  AddrSpace *spc = getSpace();
  try {
    uint1 *ptr = (uint1 *)&res;
    ptr += (HOST_ENDIAN==1) ? (sizeof(uintb) - getWordSize()) : 0;
    loader->loadFill(ptr,getWordSize(),Address(spc,addr));
  } catch(DataUnavailError &err) {
    // Pages not mapped in the load image, are assumed to be zero
    res = 0;
  }
  if ((HOST_ENDIAN==1) != spc->isBigEndian())
    res = byte_swap(res,getWordSize());
  return res;
}

/// Retrieve an aligned page from the bank.  First an attempt is made to retrieve the
/// page from the LoadImage, which may do its own zero filling.  If the attempt fails, the
/// page is entirely filled in with zeros.
void MemoryImage::getPage(uintb addr,uint1 *res,int4 skip,int4 size) const

{  // Assume that -addr- is page aligned
  AddrSpace *spc = getSpace();

  try {
    loader->loadFill(res,size,Address(spc,addr+skip));
  }
  catch(DataUnavailError &err) {
    // Pages not mapped in the load image, are assumed to be zero
    for(int4 i=0;i<size;++i)
      res[i] = 0;
  }
}

/// A MemoryImage needs everything a basic memory bank needs and is needs to know
/// the underlying LoadImage object to forward read reqests to.
/// \param spc is the address space associated with the memory bank
/// \param ws is the number of bytes in the preferred wordsize (must be power of 2)
/// \param ps is the number of bytes in a page (must be power of 2)
/// \param ld is the underlying LoadImage
MemoryImage::MemoryImage(AddrSpace *spc,int4 ws,int4 ps,LoadImage *ld)
  : MemoryBank(spc,ws,ps)
{
  loader = ld;
}

/// This derived method looks for a previously cached page of the underlying memory bank.
/// If the cached page does not exist, it creates it and fills in its initial value by
/// retrieving the page from the underlying bank.  The new value is then written into
/// cached page.
/// \param addr is the aligned address of the word to be written
/// \param val is the value to be written at that word
void MemoryPageOverlay::insert(uintb addr,uintb val)

{
  uintb pageaddr = addr & ~((uintb)(getPageSize()-1));
  map<uintb,uint1 *>::iterator iter;

  uint1 *pageptr;

  iter = page.find(pageaddr);
  if (iter != page.end())
    pageptr = (*iter).second;
  else {
    pageptr = new uint1[getPageSize()];
    page[pageaddr] = pageptr;
    if (underlie == (MemoryBank *)0) {
      for(int4 i=0;i<getPageSize();++i)
	pageptr[i] = 0;
    }
    else
      underlie->getPage(pageaddr,pageptr,0,getPageSize());
  }
  
  uintb pageoffset = addr & ((uintb)(getPageSize()-1));
  deconstructValue(pageptr + pageoffset,val,getWordSize(),getSpace()->isBigEndian());
}

/// This derived method first looks for the aligned word in the mapped pages. If the
/// address is not mapped, the search is forwarded to the \e underlying memory bank.
/// If there is no underlying bank, zero is returned.
/// \param addr is the aligned offset of the word
/// \return the retrieved value
uintb MemoryPageOverlay::find(uintb addr) const

{
  uintb pageaddr = addr & ~((uintb)(getPageSize()-1));
  map<uintb,uint1 *>::const_iterator iter;

  iter = page.find(pageaddr);
  if (iter == page.end()) {
    if (underlie == (MemoryBank *)0)
      return (uintb)0;
    return underlie->find(addr);
  }

  const uint1 *pageptr = (*iter).second;

  uintb pageoffset = addr & ((uintb)(getPageSize()-1));
  return constructValue(pageptr+pageoffset,getWordSize(),getSpace()->isBigEndian());
}

/// The desired page is looked for in the page cache.  If it doesn't exist, the
/// request is forwarded to \e underlying bank.  If there is no underlying bank, the
/// result buffer is filled with zeros.
/// \param addr is the aligned offset of the page
/// \param res is the pointer to where retrieved bytes should be stored
/// \param skip is the offset \e into \e the \e page from where bytes should be retrieved
/// \param size is the number of bytes to retrieve
void MemoryPageOverlay::getPage(uintb addr,uint1 *res,int4 skip,int4 size) const

{
  map<uintb,uint1 *>::const_iterator iter;

  iter = page.find(addr);
  if (iter == page.end()) {
    if (underlie == (MemoryBank *)0) {
      for(int4 i=0;i<size;++i)
	res[i] = 0;
      return;
    }
    underlie->getPage(addr,res,skip,size);
    return;
  }
  const uint1 *pageptr = (*iter).second;
  memcpy(res,pageptr+skip,size);
}

/// First, a cached version of the desired page is searched for via its address. If it doesn't
/// exist, it is created, and its initial value is filled via the \e underlying bank. The bytes
/// to be written are then copied into the cached page.
/// \param addr is the aligned offset of the page to write
/// \param val is a pointer to bytes to be written into the page
/// \param skip is the offset \e into \e the \e page where bytes should be written
/// \param size is the number of bytes to write
void MemoryPageOverlay::setPage(uintb addr,const uint1 *val,int4 skip,int4 size)

{
  map<uintb,uint1 *>::iterator iter;
  uint1 *pageptr;

  iter = page.find(addr);
  if (iter == page.end()) {
    pageptr = new uint1[getPageSize()];
    page[addr] = pageptr;
    if (size != getPageSize()) {
      if (underlie == (MemoryBank *)0) {
	for(int4 i=0;i<getPageSize();++i)
	  pageptr[i] = 0;
      }
      else
	underlie->getPage(addr,pageptr,0,getPageSize());
    }
  }
  else
    pageptr = (*iter).second;

  memcpy(pageptr+skip,val,size);
}

/// A page overlay memory bank needs all the parameters for a generic memory bank
/// and it needs to know the underlying memory bank being overlayed.
/// \param spc is the address space associated with the memory bank
/// \param ws is the number of bytes in the preferred wordsize (must be power of 2)
/// \param ps is the number of bytes in a page (must be power of 2)
/// \param ul is the underlying MemoryBank
MemoryPageOverlay::MemoryPageOverlay(AddrSpace *spc,int4 ws,int4 ps,MemoryBank *ul)
  : MemoryBank(spc,ws,ps)
{
  underlie = ul;
}

MemoryPageOverlay::~MemoryPageOverlay(void)

{
  map<uintb,uint1 *>::iterator iter;

  for(iter=page.begin();iter!=page.end();++iter)
    delete [] (*iter).second;
}

/// Write the value into the hashtable, using \b addr as a key.
/// \param addr is the aligned address of the word being written
/// \param val is the value of the word to write
void MemoryHashOverlay::insert(uintb addr,uintb val)

{
  int4 size = address.size();
  uintb offset = (addr>>alignshift) % size;
  for(int4 i=0;i<size;++i) {
    if (address[offset] == addr) { // Address has been seen before
      value[offset] = val;	   // Replace old value
      return;
    }
    else if (address[offset] == (uintb)0xBADBEEF) { // Address not seen before
      address[offset] = addr;			    // Claim this hash slot
      value[offset] = val;			    // Set value
      return;
    }
    offset = (offset + collideskip) % size;
  }
  throw LowlevelError("Memory state hash_table is full");
}

/// First search for an entry in the hashtable using \b addr as a key.  If there is no
/// entry, forward the query to the underlying memory bank, or return 0 if there is no underlying bank
/// \param addr is the aligned address of the word to retrieve
/// \return the retrieved value
uintb MemoryHashOverlay::find(uintb addr) const

{ // Find address in hash-table, or return find from underlying memory
  int4 size = address.size();
  uintb offset = (addr>>alignshift) % size;
  for(int4 i=0;i<size;++i) {
    if (address[offset] == addr) // Address has been seen before
      return value[offset];
    else if (address[offset] == 0xBADBEEF) // Address not seen before
      break;
    offset = (offset + collideskip) % size;
  }

  // We didn't find the address in the hashtable
  if (underlie == (MemoryBank *)0)
    return (uintb)0;
  return underlie->find(addr);
}

/// A MemoryBank implemented as a hash table needs everything associated with a generic
/// memory bank, but the constructor also needs to know the size of the hashtable and
/// the underlying memorybank to forward reads and writes to.
/// \param spc is the address space associated with the memory bank
/// \param ws is the number of bytes in the preferred wordsize (must be power of 2)
/// \param ps is the number of bytes in a page (must be a power of 2)
/// \param hashsize is the maximum number of entries in the hashtable
/// \param ul is the underlying memory bank being overlayed
MemoryHashOverlay::MemoryHashOverlay(AddrSpace *spc,int4 ws,int4 ps,int4 hashsize,MemoryBank *ul)
  : MemoryBank(spc,ws,ps), address(hashsize,0xBADBEEF), value(hashsize,0)
{
  underlie = ul;
  collideskip = 1023;

  uint4 tmp = ws - 1;
  alignshift = 0;
  while(tmp != 0) {
    alignshift += 1;
    tmp >>= 1;
  }
}

/// MemoryBanks associated with specific address spaces must be registers with this MemoryState
/// via this method.  Each address space that will be used during emulation must be registered
/// separately.  The MemoryState object does \e not assume responsibility for freeing the MemoryBank
/// \param bank is a pointer to the MemoryBank to be registered
void MemoryState::setMemoryBank(MemoryBank *bank)

{
  AddrSpace *spc = bank->getSpace();
  int4 index = spc->getIndex();

  while(index >= memspace.size())
    memspace.push_back((MemoryBank *)0);

  memspace[index] = bank;
}

/// Any MemoryBank that has been registered with this MemoryState can be retrieved via this
/// method if the MemoryBank's associated address space is known.
/// \param spc is the address space of the desired MemoryBank
/// \return a pointer to the MemoryBank or \b null if no bank is associated with \e spc.
MemoryBank *MemoryState::getMemoryBank(AddrSpace *spc) const

{
  int4 index = spc->getIndex();
  if (index >= memspace.size())
    return (MemoryBank *)0;
  return memspace[index];
}

/// This is the main interface for writing values to the MemoryState.
/// If there is no registered MemoryBank for the desired address space, or
/// if there is some other error, an exception is thrown.
/// \param spc is the address space to write to
/// \param off is the offset where the value should be written
/// \param size is the number of bytes to be written
/// \param cval is the value to be written
void MemoryState::setValue(AddrSpace *spc,uintb off,int4 size,uintb cval)

{
  MemoryBank *mspace = getMemoryBank(spc);
  if (mspace == (MemoryBank *)0)
    throw LowlevelError("Setting value for unmapped memory space: "+spc->getName());
  mspace->setValue(off,size,cval);
}

/// This is the main interface for reading values from the MemoryState.
/// If there is no registered MemoryBank for the desired address space, or
/// if there is some other error, an exception is thrown.
/// \param spc is the address space being queried
/// \param off is the offset of the value being queried
/// \param size is the number of bytes to query
/// \return the queried value
uintb MemoryState::getValue(AddrSpace *spc,uintb off,int4 size) const

{
  if (spc->getType() == IPTR_CONSTANT) return off;
  MemoryBank *mspace = getMemoryBank(spc);
  if (mspace == (MemoryBank *)0)
    throw LowlevelError("Getting value from unmapped memory space: "+spc->getName());
  return mspace->getValue(off,size);
}

/// This is a convenience method for setting registers by name.
/// Any register name known to the Translate object can be used as a write location.
/// The associated address space, offset, and size is looked up and automatically
/// passed to the main setValue routine.
/// \param nm is the name of the register
/// \param cval is the value to write to the register
void MemoryState::setValue(const string &nm,uintb cval)

{ // Set a "register" value
  const VarnodeData &vdata( trans->getRegister(nm) );
  setValue(vdata.space,vdata.offset,vdata.size,cval);
}

/// This is a convenience method for reading registers by name.
/// Any register name known to the Translate object can be used as a read location.
/// The associated address space, offset, and size is looked up and automatically
/// passed to the main getValue routine.
/// \param nm is the name of the register
/// \return the value associated with that register
uintb MemoryState::getValue(const string &nm) const

{ // Get a "register" value
  const VarnodeData &vdata( trans->getRegister(nm) );
  return getValue(vdata.space,vdata.offset,vdata.size);
}

/// This is the main interface for reading a range of bytes from the MemorySate.
/// The MemoryBank associated with the address space of the query is looked up
/// and the request is forwarded to the getChunk method on the MemoryBank. If there
/// is no registered MemoryBank or some other error, an exception is thrown
/// \param res is a pointer to the result buffer for storing retrieved bytes
/// \param spc is the desired address space
/// \param off is the starting offset of the byte range being queried
/// \param size is the number of bytes being queried
void MemoryState::getChunk(uint1 *res,AddrSpace *spc,uintb off,int4 size) const

{
  MemoryBank *mspace = getMemoryBank(spc);
  if (mspace == (MemoryBank *)0)
    throw LowlevelError("Getting chunk from unmapped memory space: "+spc->getName());
  mspace->getChunk(off,size,res);
}

/// This is the main interface for setting values for a range of bytes in the MemoryState.
/// The MemoryBank associated with the desired address space is looked up and the
/// write is forwarded to the setChunk method on the MemoryBank. If there is no
/// registered MemoryBank or some other error, an exception  is throw.
/// \param val is a pointer to the byte values to be written into the MemoryState
/// \param spc is the address space being written
/// \param off is the starting offset of the range being written
/// \param size is the number of bytes to write
void MemoryState::setChunk(const uint1 *val,AddrSpace *spc,uintb off,int4 size)

{
  MemoryBank *mspace = getMemoryBank(spc);
  if (mspace == (MemoryBank *)0)
    throw LowlevelError("Setting chunk of unmapped memory space: "+spc->getName());
  mspace->setChunk(off,size,val);
}


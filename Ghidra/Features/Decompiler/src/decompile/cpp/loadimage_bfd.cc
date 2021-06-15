/* ###
 * IP: GHIDRA
 * NOTE: Excluded from Build.  Used for development only in support of console mode - Links to GNU BFD library which is GPL 3
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
#include "loadimage_bfd.hh"

int4 LoadImageBfd::bfdinit = 0;	// Global initialization variable

LoadImageBfd::LoadImageBfd(const string &f,const string &t) : LoadImage(f)

{
  target = t;

  if (bfdinit == 0) {
    bfdinit = 1;
    bfd_init();
  }
  thebfd = (bfd *)0;
  spaceid = (AddrSpace *)0;
  symbol_table = (asymbol **)0;

  bufsize = 512;		// Default buffer size
  bufoffset = ~((uintb)0);
  buffer = new uint1[ bufsize ];
}

LoadImageBfd::~LoadImageBfd(void)

{
  if (symbol_table != (asymbol **)0)
    delete [] symbol_table;
  if (thebfd != (bfd *) 0)
    close();
  delete [] buffer;
}

string LoadImageBfd::getArchType(void) const

{
  string type;
  string targ;
  type = bfd_printable_name(thebfd);
  type += ':';
  targ = thebfd->xvec->name;
  type += targ;
  return type;
}

void LoadImageBfd::adjustVma(long adjust)

{
  asection *s;
  adjust = AddrSpace::addressToByte(adjust,spaceid->getWordSize());
  for(s=thebfd->sections;s!=(asection *)NULL;s = s->next) {
    s->vma += adjust;
    s->lma += adjust;
  }
}

void LoadImageBfd::open(void)

{
  if (thebfd != (bfd *)0) throw LowlevelError("BFD library did not initialize");
  thebfd = bfd_openr(filename.c_str(),target.c_str());
  if (thebfd == (bfd *)0) {
    string errmsg="Unable to open image file: ";
    errmsg += filename;
    throw LowlevelError(errmsg);
  }
  if (!bfd_check_format( thebfd, bfd_object)) {
    string errmsg="File: ";
    errmsg += filename;
    errmsg += " : not in recognized object file format";
    throw LowlevelError(errmsg);
  }
}

void LoadImageBfd::close(void)

{
  bfd_close(thebfd);
  thebfd = (bfd *)0;
}

asection *LoadImageBfd::findSection(uintb offset,uintb &secsize) const

{ // Return section containing offset, or closest greater section
  asection *p;
  uintb start,stop;

  for(p = thebfd->sections; p != (asection *)NULL; p = p->next) {
    start = p->vma;
    secsize = (p->size!=0) ? p->size : p->rawsize;
    stop = start + secsize;
    if ((offset>=start)&&(offset<stop))
      return p;
  }
  asection *champ = (asection *)0;
  for(p = thebfd->sections; p != (asection *)NULL; p = p->next) {
    if (p->vma > offset) {
      if (champ == (asection *)0)
	champ = p;
      else if (p->vma < champ->vma)
	champ = p;
    }
  }
  return champ;
}

void LoadImageBfd::loadFill(uint1 *ptr,int4 size,const Address &addr)

{
  asection *p;
  uintb secsize;
  uintb curaddr,offset;
  bfd_size_type readsize;
  int4 cursize;

  if (addr.getSpace() != spaceid)
    throw DataUnavailError("Trying to get loadimage bytes from space: "+addr.getSpace()->getName());
  curaddr = addr.getOffset();
  if ((curaddr>=bufoffset)&&(curaddr+size<bufoffset+bufsize)) {	// Requested bytes were previously buffered
    uint1 *bufptr = buffer + (curaddr-bufoffset);
    memcpy(ptr,bufptr,size);
    return;
  }
  bufoffset = curaddr;		// Load buffer with bytes from new address
  offset = 0;
  cursize = bufsize;		// Read an entire buffer

  while(cursize>0) {
    p = findSection(curaddr,secsize);
    if (p == (asection *)0) {
      if (offset==0)		// Initial address not mapped
	break;
      memset(buffer+offset,0,cursize); // Fill out the rest of the buffer with 0
      memcpy(ptr,buffer,size);
      return;
    }
    if (p->vma > curaddr) {	// No section matches
      if (offset==0)		// Initial address not mapped
	break;
      readsize = p->vma - curaddr;
      if (readsize > cursize)
	readsize = cursize;
      memset(buffer+offset,0,readsize); // Fill in with zeroes to next section
    }
    else {
      readsize = cursize;
      if (curaddr+readsize>p->vma+secsize)	// Adjust to biggest possible read
	readsize = (bfd_size_type)(p->vma+secsize-curaddr);
      bfd_get_section_contents(thebfd,p,buffer+offset,(file_ptr)(curaddr-p->vma),readsize);
    }
    offset += readsize;
    cursize -= readsize;
    curaddr += readsize;
  }
  if (cursize > 0) {
    ostringstream errmsg;
    errmsg << "Unable to load " << dec << cursize << " bytes at " << addr.getShortcut();
    addr.printRaw(errmsg);
    throw DataUnavailError(errmsg.str());
  }
  memcpy(ptr,buffer,size);	// Copy requested bytes from the buffer
}

void LoadImageBfd::advanceToNextSymbol(void) const

{
  while(cursymbol < number_of_symbols) {
    const asymbol *a = symbol_table[cursymbol];
    if ((a->flags & BSF_FUNCTION)!=0) {
      if (a->name != (const char *)0)
	return;
    }
    cursymbol += 1;
  }
}

void LoadImageBfd::openSymbols(void) const

{
  long storage_needed;
  cursymbol = 0;
  if (symbol_table != (asymbol **)0) {
    advanceToNextSymbol();
    return;
  }

  if (!(bfd_get_file_flags(thebfd) & HAS_SYMS)) { // There are no symbols
    number_of_symbols = 0;
    return;
  }

  storage_needed = bfd_get_symtab_upper_bound(thebfd);
  if (storage_needed <= 0) {
    number_of_symbols = 0;
    return;
  }

  symbol_table = (asymbol **) new uint1[storage_needed]; // Storage needed in bytes
  number_of_symbols = bfd_canonicalize_symtab(thebfd,symbol_table);
  if (number_of_symbols <= 0) {
    delete [] symbol_table;
    symbol_table = (asymbol **)0;
    number_of_symbols = 0;
    return;
  }
  advanceToNextSymbol();
  //  sort(symbol_table,symbol_table+number_of_symbols,compare_symbols);
}

bool LoadImageBfd::getNextSymbol(LoadImageFunc &record) const

{ // Get record for next symbol if it exists, otherwise return false
  if (cursymbol >= number_of_symbols) return false;

  const asymbol *a = symbol_table[cursymbol];
  cursymbol += 1;
  advanceToNextSymbol();
  record.name = a->name;
  uintb val = bfd_asymbol_value(a);
  record.address = Address(spaceid,val);
  return true;
}

void LoadImageBfd::openSectionInfo(void) const

{
  secinfoptr = thebfd->sections;
}

void LoadImageBfd::closeSectionInfo(void) const

{
  secinfoptr = (asection *)0;
}

bool LoadImageBfd::getNextSection(LoadImageSection &record) const

{
  if (secinfoptr == (asection *)0)
    return false;
  
  record.address = Address(spaceid,secinfoptr->vma);
  record.size = (secinfoptr->size!=0) ? secinfoptr->size : secinfoptr->rawsize;
  record.flags = 0;
  if ((secinfoptr->flags & SEC_ALLOC)==0)
    record.flags |= LoadImageSection::unalloc;
  if ((secinfoptr->flags & SEC_LOAD)==0)
    record.flags |= LoadImageSection::noload;
  if ((secinfoptr->flags & SEC_READONLY)!=0)
    record.flags |= LoadImageSection::readonly;
  if ((secinfoptr->flags & SEC_CODE)!=0)
    record.flags |= LoadImageSection::code;
  if ((secinfoptr->flags & SEC_DATA)!=0)
    record.flags |= LoadImageSection::data;
  secinfoptr = secinfoptr->next;
  return (secinfoptr != (asection *)0);
}

void LoadImageBfd::closeSymbols(void) const

{
  if (symbol_table != (asymbol **)0)
    delete [] symbol_table;
  symbol_table = (asymbol **)0;
  number_of_symbols = 0;
  cursymbol = 0;
}

void LoadImageBfd::getReadonly(RangeList &list) const

{ // List all ranges that are read only
  uintb start,stop,secsize;
  asection *p;

  for(p = thebfd->sections; p != (asection *)NULL; p = p->next) {
    if ((p->flags & SEC_READONLY)!=0) {
      start = p->vma;
      secsize = (p->size!=0) ? p->size : p->rawsize;
      if (secsize == 0) continue;
      stop = start + secsize - 1;
      list.insertRange(spaceid,start,stop);
    }
  }
}

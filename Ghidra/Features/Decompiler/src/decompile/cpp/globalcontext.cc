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
#include "globalcontext.hh"

namespace ghidra {

ElementId ELEM_CONTEXT_DATA = ElementId("context_data",120);
ElementId ELEM_CONTEXT_POINTS = ElementId("context_points",121);
ElementId ELEM_CONTEXT_POINTSET = ElementId("context_pointset",122);
ElementId ELEM_CONTEXT_SET = ElementId("context_set",123);
ElementId ELEM_SET = ElementId("set",124);
ElementId ELEM_TRACKED_POINTSET = ElementId("tracked_pointset",125);
ElementId ELEM_TRACKED_SET = ElementId("tracked_set",126);

/// Bits within the whole context blob are labeled starting with 0 as the most significant bit
/// in the first word in the sequence. The new context value must be contained within a single
/// word.
/// \param sbit is the starting (most significant) bit of the new value
/// \param ebit is the ending (least significant) bit of the new value
ContextBitRange::ContextBitRange(int4 sbit,int4 ebit)

{
  word = sbit/(8*sizeof(uintm));
  startbit = sbit - word*8*sizeof(uintm);
  endbit = ebit - word*8*sizeof(uintm);
  shift = 8*sizeof(uintm)-endbit-1;
  mask = (~((uintm)0))>>(startbit+shift);
}

/// The register storage and value are encoded as a \<set> element.
/// \param encoder is the stream encoder
void TrackedContext::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_SET);
  loc.space->encodeAttributes(encoder,loc.offset,loc.size);
  encoder.writeUnsignedInteger(ATTRIB_VAL, val);
  encoder.closeElement(ELEM_SET);
}

/// Parse a \<set> element to fill in the storage and value details.
/// \param decoder is the stream decoder
void TrackedContext::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_SET);
  loc.decodeFromAttributes(decoder);

  val = decoder.readUnsignedInteger(ATTRIB_VAL);
  decoder.closeElement(elemId);
}

/// \brief Encode all tracked register values for a specific address to a stream
///
/// Encode all the tracked register values associated with a specific target address
/// as a \<tracked_pointset> tag.
/// \param encoder is the stream encoder
/// \param addr is the specific address we have tracked values for
/// \param vec is the list of tracked values
void ContextDatabase::encodeTracked(Encoder &encoder,const Address &addr,const TrackedSet &vec)

{
  if (vec.empty()) return;
  encoder.openElement(ELEM_TRACKED_POINTSET);
  addr.getSpace()->encodeAttributes(encoder,addr.getOffset() );
  for(int4 i=0;i<vec.size();++i) {
    vec[i].encode(encoder);
  }
  encoder.closeElement(ELEM_TRACKED_POINTSET);
}

/// \brief Restore a sequence of tracked register values from the given stream decoder
///
/// Parse a \<tracked_pointset> element, decoding each child in turn to populate a list of
/// TrackedContext objects.
/// \param decoder is the given stream decoder
/// \param vec is the container that will hold the new TrackedContext objects
void ContextDatabase::decodeTracked(Decoder &decoder,TrackedSet &vec)

{
  vec.clear();			// Clear out any old stuff
  while(decoder.peekElement() != 0) {
    vec.emplace_back();
    vec.back().decode(decoder);
  }
}

/// The default value is returned for addresses that have not been overlaid with other values.
/// \param nm is the name of the context variable
/// \param val is the default value to establish
void ContextDatabase::setVariableDefault(const string &nm,uintm val)

{
  ContextBitRange &var( getVariable(nm) );
  var.setValue(getDefaultValue(),val);
}

/// This will return the default value used for addresses that have not been overlaid with other values.
/// \param nm is the name of the context variable
/// \return the variable's default value
uintm ContextDatabase::getDefaultValue(const string &nm) const

{
  const ContextBitRange &var( getVariable(nm) );
  return var.getValue(getDefaultValue());
}

/// The variable will be changed to the new value, starting at the given address up to the next
/// point of change.
/// \param nm is the name of the context variable
/// \param addr is the given address
/// \param value is the new value to set
void ContextDatabase::setVariable(const string &nm,const Address &addr,
			       uintm value)
{
  const ContextBitRange &bitrange( getVariable(nm) );
  int4 num = bitrange.getWord();
  uintm mask = bitrange.getMask()<<bitrange.getShift();

  vector<uintm *> contvec;
  getRegionToChangePoint(contvec,addr,num,mask);
  for(uint4 i=0;i<contvec.size();++i)
    bitrange.setValue(contvec[i],value);
}

/// If a value has not been explicit set for an address range containing the given address,
/// the default value for the variable is returned
/// \param nm is the name of the context variable
/// \param addr is the address for which the specific value is needed
/// \return the context variable value for the address
uintm ContextDatabase::getVariable(const string &nm,const Address &addr) const

{
  const ContextBitRange &bitrange( getVariable(nm) );

  const uintm *context = getContext(addr);
  return bitrange.getValue(context);
}

/// \brief Set a specific context value starting at the given address
///
/// The new value is \e painted across an address range starting, starting with the given address
/// up to the point where another change for the variable was specified. No other context variable
/// is changed, inside (or outside) the range.
/// \param addr is the given starting address
/// \param num is the index of the word (within the context blob) of the context variable
/// \param mask is the mask delimiting the context variable (within its word)
/// \param value is the (already shifted) value being set
void ContextDatabase::setContextChangePoint(const Address &addr,int4 num,uintm mask,uintm value)

{
  vector<uintm *> contvec;
  getRegionToChangePoint(contvec,addr,num,mask);
  for(uint4 i=0;i<contvec.size();++i) {
    uintm *newcontext = contvec[i];
    uintm val = newcontext[ num ];
    val &= ~mask;			// Clear range to zero
    val |= value;
    newcontext[ num ] = val;
  }
}

/// \brief Set a context variable value over a given range of addresses
///
/// The new value is \e painted over an explicit range of addresses. No other context variable is
/// changed inside (or outside) the range.
/// \param addr1 is the starting address of the given range
/// \param addr2 is the ending address of the given range
/// \param num is the index of the word (within the context blob) of the context variable
/// \param mask is the mask delimiting the context variable (within its word)
/// \param value is the (already shifted) value being set
void ContextDatabase::setContextRegion(const Address &addr1,const Address &addr2,
				       int4 num,uintm mask,uintm value)
{
  vector<uintm *> vec;
  getRegionForSet(vec,addr1,addr2,num,mask);
  for(uint4 i=0;i<vec.size();++i)
    vec[i][num] = (vec[i][num] & ~mask) | value;
}

/// \brief Set a context variable by name over a given range of addresses
///
/// The new value is \e painted over an explicit range of addresses. No other context variable is
/// changed inside (or outside) the range.
/// \param nm is the name of the context variable to set
/// \param begad is the starting address of the given range
/// \param endad is the ending address of the given range
/// \param value is the new value to set
void ContextDatabase::setVariableRegion(const string &nm,
				     const Address &begad,
				     const Address &endad,
				     uintm value)
{
  const ContextBitRange &bitrange( getVariable(nm) );

  vector<uintm *> vec;
  getRegionForSet(vec,begad,endad,bitrange.getWord(),bitrange.getMask() << bitrange.getShift());
  for(int4 i=0;i<vec.size();++i)
    bitrange.setValue(vec[i],value);
}

/// \brief Get the value of a tracked register at a specific address
///
/// A specific storage region and code address is given.  If the region is tracked the value at
/// the address is retrieved.  If the specified storage region is contained in the tracked region,
/// the retrieved value is trimmed to match the containment before returning it. If the region is not
/// tracked, a value of 0 is returned.
/// \param mem is the specified storage region
/// \param point is the code address
/// \return the tracked value or zero
uintb ContextDatabase::getTrackedValue(const VarnodeData &mem,const Address &point) const

{
  const TrackedSet &tset(getTrackedSet(point));
  uintb endoff = mem.offset + mem.size - 1;
  uintb tendoff;
  for(int4 i=0;i<tset.size();++i) {
    const TrackedContext &tcont( tset[i] );
    // tcont must contain -mem-
    if (tcont.loc.space != mem.space) continue;
    if (tcont.loc.offset > mem.offset) continue;
    tendoff = tcont.loc.offset + tcont.loc.size - 1;
    if (tendoff < endoff) continue;
    uintb res = tcont.val;
    // If we have proper containment, trim value based on endianness
    if (tcont.loc.space->isBigEndian()) {
      if (endoff != tendoff)
	res >>= (8* (tendoff - mem.offset));
    }
    else {
      if (mem.offset != tcont.loc.offset)
	res >>= (8* (mem.offset-tcont.loc.offset));
    }
    res &= calc_mask( mem.size ); // Final trim based on size
    return res;
  }
  return (uintb)0;
}

/// The "array of words" and mask array are resized to the given value. Old values are preserved,
/// chopping off the last values, or appending zeroes, as needed.
/// \param sz is the new number of words to resize array to
void ContextInternal::FreeArray::reset(int4 sz)

{
  uintm *newarray = (uintm *)0;
  uintm *newmask = (uintm *)0;
  if (sz != 0) {
    newarray = new uintm[sz];
    newmask = new uintm[sz];
    int4 min;
    if (sz > size) {
      min = size;
      for(int4 i=min;i<sz;++i) {
	newarray[i] = 0;	// Pad new part with zero
	newmask[i] = 0;
      }
    }
    else
      min = sz;
    for(int4 i=0;i<min;++i) {	// Copy old part
      newarray[i] = array[i];
      newmask[i] = mask[i];
    }
  }
  if (size!=0) {
    delete [] array;
    delete [] mask;
  }
  array = newarray;
  mask = newmask;
  size = sz;
}

/// Clone a context blob into \b this.
/// \param op2 is the context blob being cloned/copied
/// \return a reference to \b this
ContextInternal::FreeArray &ContextInternal::FreeArray::operator=(const FreeArray &op2)

{
  if (size!=0) {
    delete [] array;
    delete [] mask;
  }
  array = (uintm *)0;
  mask = (uintm *)0;
  size = op2.size;
  if (size != 0) {
    array = new uintm[size];
    mask = new uintm[size];
    for(int4 i=0;i<size;++i) {
      array[i] = op2.array[i];		// Copy value at split point
      mask[i] = 0;			// but not fact that value is being set
    }
  }
  return *this;
}

/// \brief Encode a single context block to a stream
///
/// The blob is broken up into individual values and written out as a series
/// of \<set> elements within a parent \<context_pointset> element.
/// \param encoder is the stream encoder
/// \param addr is the address of the split point where the blob is valid
/// \param vec is the array of words holding the blob values
void ContextInternal::encodeContext(Encoder &encoder,const Address &addr,const uintm *vec) const
{
  encoder.openElement(ELEM_CONTEXT_POINTSET);
  addr.getSpace()->encodeAttributes(encoder,addr.getOffset() );
  map<string,ContextBitRange>::const_iterator iter;
  for(iter=variables.begin();iter!=variables.end();++iter) {
    uintm val = (*iter).second.getValue(vec);
    encoder.openElement(ELEM_SET);
    encoder.writeString(ATTRIB_NAME, (*iter).first);
    encoder.writeUnsignedInteger(ATTRIB_VAL, val);
    encoder.closeElement(ELEM_SET);
  }
  encoder.closeElement(ELEM_CONTEXT_POINTSET);
}

/// \brief Restore a context blob for given address range from a stream decoder
///
/// Parse either a \<context_pointset> or \<context_set> element. In either case,
/// children are parsed to get context variable values.  Then a context blob is
/// reconstructed from the values.  The new blob is added to the interval map based
/// on the address range.  If the start address is invalid, the default value of
/// the context variables are painted.  The second address can be invalid, if
/// only a split point is known.
/// \param decoder is the stream decoder
/// \param addr1 is the starting address of the given range
/// \param addr2 is the ending address of the given range
void ContextInternal::decodeContext(Decoder &decoder,const Address &addr1,const Address &addr2)

{
  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId != ELEM_SET) break;
    uintm val = decoder.readUnsignedInteger(ATTRIB_VAL);
    ContextBitRange &var(getVariable(decoder.readString(ATTRIB_NAME)));
    vector<uintm *> vec;
    if (addr1.isInvalid()) {		// Invalid addr1, indicates we should set default value
      uintm *defaultBuffer = getDefaultValue();
      for(int4 i=0;i<size;++i)
	defaultBuffer[i] = 0;
      vec.push_back(defaultBuffer);
    }
    else
      getRegionForSet(vec,addr1,addr2,var.getWord(),var.getMask()<<var.getShift());
    for(int4 i=0;i<vec.size();++i)
      var.setValue(vec[i],val);
    decoder.closeElement(subId);
  }
}

void ContextInternal::registerVariable(const string &nm,int4 sbit,int4 ebit)

{
  if (!database.empty())
    throw LowlevelError("Cannot register new context variables after database is initialized");

  ContextBitRange bitrange(sbit,ebit);
  int4 sz = sbit/(8*sizeof(uintm)) + 1;
  if ((ebit/(8*sizeof(uintm)) + 1) != sz)
    throw LowlevelError("Context variable does not fit in one word");
  if (sz > size) {
    size = sz;
    database.defaultValue().reset(size);
  }
  variables[nm] = bitrange;
}

ContextBitRange &ContextInternal::getVariable(const string &nm)

{
  map<string,ContextBitRange>::iterator iter;

  iter = variables.find(nm);
  if (iter == variables.end())
    throw LowlevelError("Non-existent context variable: "+nm);
  return (*iter).second;
}

const ContextBitRange &ContextInternal::getVariable(const string &nm) const

{
  map<string,ContextBitRange>::const_iterator iter;

  iter = variables.find(nm);
  if (iter == variables.end())
    throw LowlevelError("Non-existent context variable: "+nm);
  return (*iter).second;
}

const uintm *ContextInternal::getContext(const Address &addr,
					       uintb &first,uintb &last) const
{
  int4 valid;
  Address before,after;
  const uintm *res = database.bounds(addr,before,after,valid).array;
  if (((valid&1)!=0)||(before.getSpace() != addr.getSpace()))
    first = 0;
  else
    first = before.getOffset();
  if (((valid&2)!=0)||(after.getSpace() != addr.getSpace()))
    last = addr.getSpace()->getHighest();
  else
    last = after.getOffset()-1;
  return res;
}

void ContextInternal::getRegionForSet(vector<uintm *> &res,const Address &addr1,const Address &addr2,
				      int4 num,uintm mask)
{
  database.split(addr1);
  partmap<Address,FreeArray>::iterator aiter,biter;

  aiter = database.begin(addr1);
  if (!addr2.isInvalid()) {
    database.split(addr2);
    biter = database.begin(addr2);
  }
  else
    biter = database.end();
  while(aiter != biter) {
    uintm *context = (*aiter).second.array;
    uintm *maskPtr = (*aiter).second.mask;
    res.push_back(context);
    maskPtr[num] |= mask;		// Mark that this value is being definitely set
    ++aiter;
  }
}

void ContextInternal::getRegionToChangePoint(vector<uintm *> &res,const Address &addr,int4 num,uintm mask)

{
  database.split(addr);
  partmap<Address,FreeArray>::iterator aiter,biter;
  uintm *maskArray,*vecArray;

  aiter = database.begin(addr);
  biter = database.end();
  if (aiter == biter) return;
  vecArray = (*aiter).second.array;
  res.push_back(vecArray);
  maskArray = (*aiter).second.mask;
  maskArray[num] |= mask;
  ++aiter;
  while(aiter != biter) {
    vecArray = (*aiter).second.array;
    maskArray = (*aiter).second.mask;
    if ((maskArray[num] & mask) != 0) break; // Reached point where this value was definitively set before
    res.push_back(vecArray);
    ++aiter;
  }
}

TrackedSet &ContextInternal::createSet(const Address &addr1,const Address &addr2)

{
  TrackedSet &res(trackbase.clearRange(addr1,addr2));
  res.clear();
  return res;
}

void ContextInternal::encode(Encoder &encoder) const

{
  if (database.empty() && trackbase.empty()) return;

  encoder.openElement(ELEM_CONTEXT_POINTS);

  partmap<Address,FreeArray>::const_iterator fiter,fenditer;
  fiter = database.begin();
  fenditer = database.end();
  for(;fiter!=fenditer;++fiter)	// Save context at each changepoint
    encodeContext(encoder,(*fiter).first,(*fiter).second.array);
  
  partmap<Address,TrackedSet>::const_iterator titer,tenditer;
  titer = trackbase.begin();
  tenditer = trackbase.end();
  for(;titer!=tenditer;++titer) 
    encodeTracked(encoder,(*titer).first,(*titer).second);

  encoder.closeElement(ELEM_CONTEXT_POINTS);
}

void ContextInternal::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CONTEXT_POINTS);
  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId == 0) break;
    if (subId == ELEM_CONTEXT_POINTSET) {
      uint4 attribId = decoder.getNextAttributeId();
      decoder.rewindAttributes();
      if (attribId==0) {
	decodeContext(decoder,Address(),Address());	// Restore the default value
      }
      else {
	VarnodeData vData;
	vData.decodeFromAttributes(decoder);
	decodeContext(decoder,vData.getAddr(),Address());
      }
    }
    else if (subId == ELEM_TRACKED_POINTSET) {
      VarnodeData vData;
      vData.decodeFromAttributes(decoder);
      decodeTracked(decoder,trackbase.split(vData.getAddr()) );
    }
    else
      throw LowlevelError("Bad <context_points> tag");
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

void ContextInternal::decodeFromSpec(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CONTEXT_DATA);
  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId == 0) break;
    Range range;
    range.decodeFromAttributes(decoder);	// There MUST be a range
    Address addr1 = range.getFirstAddr();
    Address addr2 = range.getLastAddrOpen(decoder.getAddrSpaceManager());
    if (subId == ELEM_CONTEXT_SET) {
      decodeContext(decoder,addr1,addr2);
    }
    else if (subId == ELEM_TRACKED_SET) {
      decodeTracked(decoder,createSet(addr1,addr2));
    }
    else
      throw LowlevelError("Bad <context_data> tag");
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

/// \param db is the context database that will be encapsulated
ContextCache::ContextCache(ContextDatabase *db)

{
  database = db;
  curspace = (AddrSpace *)0;	// Mark cache as invalid
  allowset = true;
}

/// Check if the address is in the current valid range. If it is, return the cached
/// blob.  Otherwise, make a call to the database and cache a new block and valid range.
/// \param addr is the given address
/// \param buf is where the blob should be stored
void ContextCache::getContext(const Address &addr,uintm *buf) const

{
  if ((addr.getSpace()!=curspace)||(first>addr.getOffset())||(last<addr.getOffset())) {
    curspace = addr.getSpace();
    context = database->getContext(addr,first,last);
  }
  for(int4 i=0;i<database->getContextSize();++i) 
    buf[i] = context[i];
}

/// \brief Change the value of a context variable at the given address with no bound
///
/// The context value is set starting at the given address and \e paints memory up
/// to the next explicit change point.
/// \param addr is the given starting address
/// \param num is the word index of the context variable
/// \param mask is the mask delimiting the context variable
/// \param value is the (already shifted) value to set
void ContextCache::setContext(const Address &addr,int4 num,uintm mask,uintm value)

{
  if (!allowset) return;
  database->setContextChangePoint(addr,num,mask,value);
  if ((addr.getSpace()==curspace)&&(first<=addr.getOffset())&&(last>=addr.getOffset()))
    curspace = (AddrSpace *)0;	// Invalidate cache
}

/// \brief Change the value of a context variable across an explicit address range
///
/// The context value is \e painted across the range. The context variable is marked as
/// explicitly changing at the starting address of the range.
/// \param addr1 is the starting address of the given range
/// \param addr2 is the ending address of the given range
/// \param num is the word index of the context variable
/// \param mask is the mask delimiting the context variable
/// \param value is the (already shifted) value to set
void ContextCache::setContext(const Address &addr1,const Address &addr2,int4 num,uintm mask,uintm value)

{
  if (!allowset) return;
  database->setContextRegion(addr1,addr2,num,mask,value);
  if ((addr1.getSpace()==curspace)&&(first<=addr1.getOffset())&&(last>=addr1.getOffset()))
    curspace = (AddrSpace *)0;	// Invalidate cache
  if ((first<=addr2.getOffset())&&(last>=addr2.getOffset()))
    curspace = (AddrSpace *)0;	// Invalidate cache
  if ((first>=addr1.getOffset())&&(first<=addr2.getOffset()))
    curspace = (AddrSpace *)0;	// Invalidate cache
}

} // End namespace ghidra

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
#include "translate.hh"

namespace ghidra {

AttributeId ATTRIB_CODE = AttributeId("code",43);
AttributeId ATTRIB_CONTAIN = AttributeId("contain",44);
AttributeId ATTRIB_DEFAULTSPACE = AttributeId("defaultspace",45);
AttributeId ATTRIB_UNIQBASE = AttributeId("uniqbase",46);

ElementId ELEM_OP = ElementId("op",27);
ElementId ELEM_SLEIGH = ElementId("sleigh",28);
ElementId ELEM_SPACE = ElementId("space",29);
ElementId ELEM_SPACEID = ElementId("spaceid",30);
ElementId ELEM_SPACES = ElementId("spaces",31);
ElementId ELEM_SPACE_BASE = ElementId("space_base",32);
ElementId ELEM_SPACE_OTHER = ElementId("space_other",33);
ElementId ELEM_SPACE_OVERLAY = ElementId("space_overlay",34);
ElementId ELEM_SPACE_UNIQUE = ElementId("space_unique",35);
ElementId ELEM_TRUNCATE_SPACE = ElementId("truncate_space",36);

/// Parse a \<truncate_space> element to configure \b this object
/// \param decoder is the stream decoder
void TruncationTag::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_TRUNCATE_SPACE);
  spaceName = decoder.readString(ATTRIB_SPACE);
  size = decoder.readUnsignedInteger(ATTRIB_SIZE);
  decoder.closeElement(elemId);
}

/// Construct a virtual space.  This is usually used for the stack
/// space, which is indicated by the \b isFormal parameters, but multiple such spaces are allowed.
/// \param m is the manager for this \b program \b specific address space
/// \param t is associated processor translator
/// \param nm is the name of the space
/// \param ind is the integer identifier
/// \param sz is the size of the space
/// \param base is the containing space
/// \param dl is the heritage delay
/// \param isFormal is the formal stack space indicator
SpacebaseSpace::SpacebaseSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind,int4 sz,
			       AddrSpace *base,int4 dl,bool isFormal)
  : AddrSpace(m,t,IPTR_SPACEBASE,nm,t->isBigEndian(),sz,base->getWordSize(),ind,0,dl,dl)
{
  contain = base;
  hasbaseregister = false;	// No base register assigned yet
  isNegativeStack = true;	// default stack growth
  if (isFormal)
    setFlags(formal_stackspace);
}

/// This is a partial constructor, which must be followed up
/// with decode in order to fillin the rest of the spaces
/// attributes
/// \param m is the associated address space manager
/// \param t is the associated processor translator
SpacebaseSpace::SpacebaseSpace(AddrSpaceManager *m,const Translate *t)
  : AddrSpace(m,t,IPTR_SPACEBASE)
{
  hasbaseregister = false;
  isNegativeStack = true;
  setFlags(programspecific);
}

/// This routine sets the base register associated with this \b virtual space
/// It will throw an exception if something tries to set two (different) base registers
/// \param data is the location data for the base register
/// \param truncSize is the size of the space covered by the register
/// \param stackGrowth is \b true if the stack which this register manages grows in a negative direction
void SpacebaseSpace::setBaseRegister(const VarnodeData &data,int4 truncSize,bool stackGrowth)

{
  if (hasbaseregister) {
    if ((baseloc != data)||(isNegativeStack != stackGrowth))
      throw LowlevelError("Attempt to assign more than one base register to space: "+getName());
  }
  hasbaseregister = true;
  isNegativeStack = stackGrowth;
  baseOrig = data;
  baseloc = data;
  if (truncSize != baseloc.size) {
    if (baseloc.space->isBigEndian())
      baseloc.offset += (baseloc.size - truncSize);
    baseloc.size = truncSize;
  }
}

int4 SpacebaseSpace::numSpacebase(void) const

{
  return hasbaseregister ? 1 : 0;
}

const VarnodeData &SpacebaseSpace::getSpacebase(int4 i) const

{
  if ((!hasbaseregister)||(i!=0))
    throw LowlevelError("No base register specified for space: "+getName());
  return baseloc;
}

const VarnodeData &SpacebaseSpace::getSpacebaseFull(int4 i) const

{
  if ((!hasbaseregister)||(i!=0))
    throw LowlevelError("No base register specified for space: "+getName());
  return baseOrig;
}

void SpacebaseSpace::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_SPACE_BASE);
  decodeBasicAttributes(decoder);
  contain = decoder.readSpace(ATTRIB_CONTAIN);
  decoder.closeElement(elemId);
}

/// The \e join space range maps to the underlying pieces in a natural endian aware way.
/// Given an offset in the range, figure out what address it is mapping to.
/// The particular piece is passed back as an index, and the Address is returned.
/// \param offset is the offset within \b this range to map
/// \param pos will hold the passed back piece index
/// \return the Address mapped to
Address JoinRecord::getEquivalentAddress(uintb offset,int4 &pos) const

{
  if (offset < unified.offset)
    return Address();		// offset comes before this range
  int4 smallOff = (int4)(offset - unified.offset);
  if (pieces[0].space->isBigEndian()) {
    for(pos=0;pos<pieces.size();++pos) {
      int4 pieceSize = pieces[pos].size;
      if (smallOff < pieceSize)
	break;
      smallOff -= pieceSize;
    }
    if (pos == pieces.size())
      return Address();		// offset comes after this range
  }
  else {
    for (pos = pieces.size() - 1; pos >= 0; --pos) {
      int4 pieceSize = pieces[pos].size;
      if (smallOff < pieceSize)
	break;
      smallOff -= pieceSize;
    }
    if (pos < 0)
      return Address();		// offset comes after this range
  }
  return Address(pieces[pos].space,pieces[pos].offset + smallOff);
}

/// Allow sorting on JoinRecords so that a collection of pieces can be quickly mapped to
/// its logical whole, specified with a join address
bool JoinRecord::operator<(const JoinRecord &op2) const

{
  // Some joins may have same piece but different unified size  (floating point)
  if (unified.size != op2.unified.size) // Compare size first
    return (unified.size < op2.unified.size);
  // Lexigraphic sort on pieces
  int4 i=0;
  for(;;) {
    if (pieces.size()==i) {
      return (op2.pieces.size()>i); // If more pieces in op2, it is bigger (return true), if same number this==op2, return false
    }
    if (op2.pieces.size()==i) return false; // More pieces in -this-, so it is bigger, return false
    if (pieces[i] != op2.pieces[i])
      return (pieces[i] < op2.pieces[i]);
    i += 1;
  }
}

/// Assuming the given list of VarnodeData go from most significant to least significant,
/// merge any contiguous elements in the list.  Varnodes that are not in the \e stack address space
/// are only merged if the resulting byte range has a formal register name.
/// \param seq is the given list of VarnodeData
/// \param trans is the language to use for register names
void JoinRecord::mergeSequence(vector<VarnodeData> &seq,const Translate *trans)

{
  int4 i=1;
  while(i<seq.size()) {
    VarnodeData &hi(seq[i-1]);
    VarnodeData &lo(seq[i]);
    if (hi.isContiguous(lo))
      break;
    i += 1;
  }
  if (i >= seq.size()) return;
  vector<VarnodeData> res;
  i = 1;
  res.push_back(seq.front());
  bool lastIsInformal = false;
  while(i<seq.size()) {
    VarnodeData &hi(res.back());
    VarnodeData &lo(seq[i]);
    if (hi.isContiguous(lo)) {
      hi.offset = hi.space->isBigEndian() ? hi.offset : lo.offset;
      hi.size += lo.size;
      if (hi.space->getType() != IPTR_SPACEBASE) {
	lastIsInformal = trans->getExactRegisterName(hi.space, hi.offset, hi.size).size() == 0;
      }
    }
    else {
      if (lastIsInformal)
	break;
      res.push_back(lo);
    }
    i += 1;
  }
  if (lastIsInformal)	// If the merge contains an informal register
    return;		// throw it out and keep the original sequence
  seq = res;
}

/// Initialize manager containing no address spaces. All the cached space slots are set to null
AddrSpaceManager::AddrSpaceManager(void)

{
  defaultcodespace = (AddrSpace *)0;
  defaultdataspace = (AddrSpace *)0;
  constantspace = (AddrSpace *)0;
  iopspace = (AddrSpace *)0;
  fspecspace = (AddrSpace *)0;
  joinspace = (AddrSpace *)0;
  stackspace = (AddrSpace *)0;
  uniqspace = (AddrSpace *)0;
  joinallocate = 0;
}

/// The initialization of address spaces is the same across all
/// variants of the Translate object.  This routine initializes
/// a single address space from a decoder element.  It knows
/// which class derived from AddrSpace to instantiate based on
/// the ElementId.
/// \param decoder is the stream decoder
/// \param trans is the translator object to be associated with the new space
/// \return a pointer to the initialized AddrSpace
AddrSpace *AddrSpaceManager::decodeSpace(Decoder &decoder,const Translate *trans)

{
  uint4 elemId = decoder.peekElement();
  AddrSpace *res;
  if (elemId == ELEM_SPACE_BASE)
    res = new SpacebaseSpace(this,trans);
  else if (elemId == ELEM_SPACE_UNIQUE)
    res = new UniqueSpace(this,trans);
  else if (elemId == ELEM_SPACE_OTHER)
    res = new OtherSpace(this,trans);
  else if (elemId == ELEM_SPACE_OVERLAY)
    res = new OverlaySpace(this,trans);
  else
    res = new AddrSpace(this,trans,IPTR_PROCESSOR);

  res->decode(decoder);
  return res;
}

/// This routine initializes (almost) all the address spaces used
/// for a particular processor by using a \b \<spaces\> element,
/// which contains child elements for the specific address spaces.
/// This also instantiates the builtin \e constant space. It
/// should probably also instantiate the \b iop, \b fspec, and \b join
/// spaces, but this is currently done by the Architecture class.
/// \param decoder is the stream decoder
/// \param trans is the processor translator to be associated with the spaces
void AddrSpaceManager::decodeSpaces(Decoder &decoder,const Translate *trans)

{
  // The first space should always be the constant space
  insertSpace(new ConstantSpace(this,trans));

  uint4 elemId = decoder.openElement(ELEM_SPACES);
  string defname = decoder.readString(ATTRIB_DEFAULTSPACE);
  while(decoder.peekElement() != 0) {
    AddrSpace *spc = decodeSpace(decoder,trans);
    insertSpace(spc);
  }
  decoder.closeElement(elemId);
  AddrSpace *spc = getSpaceByName(defname);
  if (spc == (AddrSpace *)0)
    throw LowlevelError("Bad 'defaultspace' attribute: "+defname);
  setDefaultCodeSpace(spc->getIndex());
}

/// Once all the address spaces have been initialized, this routine
/// should be called once to establish the official \e default
/// space for the processor, via its index. Should only be
/// called during initialization.
/// \param index is the index of the desired default space
void AddrSpaceManager::setDefaultCodeSpace(int4 index)

{
  if (defaultcodespace != (AddrSpace *)0)
    throw LowlevelError("Default space set multiple times");
  if (baselist.size()<=index || baselist[index] == (AddrSpace *)0)
    throw LowlevelError("Bad index for default space");
  defaultcodespace = baselist[index];
  defaultdataspace = defaultcodespace;		// By default the default data space is the same
}

/// If the architecture has different code and data spaces, this routine can be called
/// to set the \e data space after the \e code space has been set.
/// \param index is the index of the desired default space
void AddrSpaceManager::setDefaultDataSpace(int4 index)

{
  if (defaultcodespace == (AddrSpace *)0)
    throw LowlevelError("Default data space must be set after the code space");
  if (baselist.size()<=index || baselist[index] == (AddrSpace *)0)
    throw LowlevelError("Bad index for default data space");
  defaultdataspace = baselist[index];
}

/// For spaces with alignment restrictions, the address of a small variable must be justified
/// within a larger aligned memory word, usually either to the left boundary for little endian encoding
/// or to the right boundary for big endian encoding.  Some compilers justify small variables to
/// the opposite side of the one indicated by the endianness. Setting this property on a space
/// causes the decompiler to use this justification
void AddrSpaceManager::setReverseJustified(AddrSpace *spc)

{
  spc->setFlags(AddrSpace::reverse_justification);
}

/// This adds a previously instantiated address space (AddrSpace)
/// to the model for this processor.  It checks a set of
/// indexing and naming conventions for the space and throws
/// an exception if the conventions are violated. Should
/// only be called during initialization.
/// \todo This really shouldn't be public.  Need to move the
/// allocation of \b iop, \b fspec, and \b join out of Architecture
/// \param spc the address space to insert
void AddrSpaceManager::insertSpace(AddrSpace *spc)

{
  bool nameTypeMismatch = false;
  bool duplicateName = false;
  bool duplicateId = false;
  switch(spc->getType()) {
  case IPTR_CONSTANT:
    if (spc->getName() != ConstantSpace::NAME)
      nameTypeMismatch = true;
    if (spc->index != ConstantSpace::INDEX)
      throw LowlevelError("const space must be assigned index 0");
    constantspace = spc;
    break;
  case IPTR_INTERNAL:
    if (spc->getName() != UniqueSpace::NAME)
      nameTypeMismatch = true;
    if (uniqspace != (AddrSpace *)0)
      duplicateName = true;
    uniqspace = spc;
    break;
  case IPTR_FSPEC:
    if (spc->getName() != "fspec")
      nameTypeMismatch = true;
    if (fspecspace != (AddrSpace *)0)
      duplicateName = true;
    fspecspace = spc;
    break;
  case IPTR_JOIN:
    if (spc->getName() != JoinSpace::NAME)
      nameTypeMismatch = true;
    if (joinspace != (AddrSpace *)0)
      duplicateName = true;
    joinspace = spc;
    break;
  case IPTR_IOP:
    if (spc->getName() != "iop")
      nameTypeMismatch = true;
    if (iopspace != (AddrSpace *)0)
      duplicateName = true;
    iopspace = spc;
    break;
  case IPTR_SPACEBASE:
    if (spc->getName() == "stack") {
      if (stackspace != (AddrSpace *)0)
	duplicateName = true;
      stackspace = spc;
    }
    // fallthru
  case IPTR_PROCESSOR:
    if (spc->isOverlay()) {	// If this is a new overlay space
      spc->getContain()->setFlags(AddrSpace::overlaybase); // Mark the base as being overlayed
    }
    else if (spc->isOtherSpace()) {
      if (spc->index != OtherSpace::INDEX)
        throw LowlevelError("OTHER space must be assigned index 1");
    }
    break;
  }

  if (baselist.size() <= spc->index)
    baselist.resize(spc->index+1, (AddrSpace *)0);

  duplicateId = baselist[spc->index] != (AddrSpace *)0;

  if (!nameTypeMismatch && !duplicateName && !duplicateId) {
    duplicateName = !name2Space.insert(pair<string,AddrSpace *>(spc->getName(),spc)).second;
  }

  if (nameTypeMismatch || duplicateName || duplicateId) {
    string errMsg = "Space " + spc->getName();
    if (nameTypeMismatch)
      errMsg = errMsg + " was initialized with wrong type";
    if (duplicateName)
      errMsg = errMsg + " was initialized more than once";
    if (duplicateId)
      errMsg = errMsg + " was assigned as id duplicating: "+baselist[spc->index]->getName();
    if (spc->refcount == 0)
      delete spc;
    spc = (AddrSpace *)0;
    throw LowlevelError(errMsg);
  }
  baselist[spc->index] = spc;
  spc->refcount += 1;
  assignShortcut(spc);
}

/// Different managers may need to share the same spaces. I.e. if different programs being
/// analyzed share the same processor. This routine pulls in a reference of every space in -op2-
/// in order to manage it from within -this-
/// \param op2 is a pointer to space manager being copied
void AddrSpaceManager::copySpaces(const AddrSpaceManager *op2)

{ // Insert every space in -op2- into -this- manager
  for(int4 i=0;i<op2->baselist.size();++i) {
    AddrSpace *spc = op2->baselist[i];
    if (spc != (AddrSpace *)0)
      insertSpace(spc);
  }
  setDefaultCodeSpace(op2->getDefaultCodeSpace()->getIndex());
  setDefaultDataSpace(op2->getDefaultDataSpace()->getIndex());
}

/// Perform the \e privileged act of associating a base register with an existing \e virtual space
/// \param basespace is the virtual space
/// \param ptrdata is the location data for the base register
/// \param truncSize is the size of the space covered by the base register
/// \param stackGrowth is true if the stack grows "normally" towards address 0
void AddrSpaceManager::addSpacebasePointer(SpacebaseSpace *basespace,const VarnodeData &ptrdata,int4 truncSize,bool stackGrowth)

{
  basespace->setBaseRegister(ptrdata,truncSize,stackGrowth);
}

/// Provide a new specialized resolver for a specific AddrSpace.  The manager takes ownership of resolver.
/// \param spc is the space to which the resolver is associated
/// \param rsolv is the new resolver object
void AddrSpaceManager::insertResolver(AddrSpace *spc,AddressResolver *rsolv)

{
  int4 ind = spc->getIndex();
  while(resolvelist.size() <= ind)
    resolvelist.push_back((AddressResolver *)0);
  if (resolvelist[ind] != (AddressResolver *)0)
    delete resolvelist[ind];
  resolvelist[ind] = rsolv;
}

/// This method establishes for a single address space, what range of constants are checked
/// as possible symbol starts, when it is not known apriori that a constant is a pointer.
/// \param range is the range of values for a single address space
void AddrSpaceManager::setInferPtrBounds(const Range &range)

{
  range.getSpace()->pointerLowerBound = range.getFirst();
  range.getSpace()->pointerUpperBound = range.getLast();
}

/// Base destructor class, cleans up AddrSpace pointers which
/// must be explicited created via \e new
AddrSpaceManager::~AddrSpaceManager(void)

{
  for(vector<AddrSpace *>::iterator iter=baselist.begin();iter!=baselist.end();++iter) {
    AddrSpace *spc = *iter;
    if (spc == (AddrSpace *)0) continue;
    if (spc->refcount > 1)
      spc->refcount -= 1;
    else
      delete spc;
  }
  for(int4 i=0;i<resolvelist.size();++i) {
    if (resolvelist[i] != (AddressResolver *)0)
      delete resolvelist[i];
  }
  for(int4 i=0;i<splitlist.size();++i)
    delete splitlist[i];	// Delete any join records
}

/// Assign a \e shortcut character to the given address space.
/// This routine makes use of the desired type of the new space
/// and info about shortcuts for spaces that already exist to
/// pick a unique and consistent character.  This method also builds
/// up a map from short to AddrSpace object.
/// \param spc is the given AddrSpace
void AddrSpaceManager::assignShortcut(AddrSpace *spc)

{
  if (spc->shortcut != ' ') {	// If the shortcut is already assigned
    shortcut2Space.insert(pair<int4,AddrSpace *>(spc->shortcut,spc));
    return;
  }
  char shortcut;
  switch(spc->getType()) {
  case IPTR_CONSTANT:
    shortcut = '#';
    break;
  case IPTR_PROCESSOR:
    if (spc->getName() == "register")
      shortcut = '%';
    else
      shortcut = spc->getName()[0];
    break;
  case IPTR_SPACEBASE:
    shortcut = 's';
    break;
  case IPTR_INTERNAL:
    shortcut = 'u';
    break;
  case IPTR_FSPEC:
    shortcut = 'f';
    break;
  case IPTR_JOIN:
    shortcut = 'j';
    break;
  case IPTR_IOP:
    shortcut = 'i';
    break;
  default:
    shortcut = 'x';
    break;
  }

  if (shortcut >= 'A' && shortcut <= 'Z')
    shortcut += 0x20;

  int4 collisionCount = 0;
  while(!shortcut2Space.insert(pair<int4,AddrSpace *>(shortcut,spc)).second) {
    collisionCount += 1;
    if (collisionCount >26) {
      // Could not find a unique shortcut, but we just re-use 'z' as we
      // can always use the long form to specify the address if there are really so many
      // spaces that need to be distinguishable (in the console mode)
      spc->shortcut = 'z';
      return;
    }
    shortcut += 1;
    if (shortcut < 'a' || shortcut > 'z')
      shortcut = 'a';
  }
  spc->shortcut = (char)shortcut;
}

/// \param spc is the AddrSpace to mark
/// \param size is the (minimum) size of a near pointer in bytes
void AddrSpaceManager::markNearPointers(AddrSpace *spc,int4 size)

{
  spc->setFlags(AddrSpace::has_nearpointers);
  if (spc->minimumPointerSize == 0 && spc->addressSize != size)
    spc->minimumPointerSize = size;
}

/// All address spaces have a unique name associated with them.
/// This routine retrieves the AddrSpace object based on the
/// desired name.
/// \param nm is the name of the address space
/// \return a pointer to the AddrSpace object
AddrSpace *AddrSpaceManager::getSpaceByName(const string &nm) const

{
  map<string,AddrSpace *>::const_iterator iter = name2Space.find(nm);
  if (iter == name2Space.end())
    return (AddrSpace *)0;
  return (*iter).second;
}

/// All address spaces have a unique shortcut (ASCII) character
/// assigned to them. This routine retrieves an AddrSpace object
/// given a specific shortcut.
/// \param sc is the shortcut character
/// \return a pointer to an AddrSpace
AddrSpace *AddrSpaceManager::getSpaceByShortcut(char sc) const

{
  map<int4,AddrSpace *>::const_iterator iter;
  iter = shortcut2Space.find(sc);
  if (iter == shortcut2Space.end())
    return (AddrSpace *)0;
  return (*iter).second;
}

/// \brief Resolve a native constant into an Address
///
/// If there is a special resolver for the AddrSpace, this is invoked, otherwise
/// basic wordsize conversion and wrapping is performed. If the address encoding is
/// partial (as in a \e near pointer) and the full encoding can be recovered, it is passed back.
/// The \e sz parameter indicates the number of bytes in constant and is used to determine if
/// the constant is a partial or full pointer encoding. A value of -1 indicates the value is
/// known to be a full encoding.
/// \param spc is the space to generate the address from
/// \param val is the constant encoding of the address
/// \param sz is the size of the constant encoding (or -1)
/// \param point is the context address (for recovering full encoding info if necessary)
/// \param fullEncoding is used to pass back the recovered full encoding of the pointer
/// \return the formal Address associated with the encoding
Address AddrSpaceManager::resolveConstant(AddrSpace *spc,uintb val,int4 sz,const Address &point,uintb &fullEncoding) const

{
  int4 ind = spc->getIndex();
  if (ind < resolvelist.size()) {
    AddressResolver *resolve = resolvelist[ind];
    if (resolve != (AddressResolver *)0)
      return resolve->resolve(val,sz,point,fullEncoding);
  }
  fullEncoding = val;
  val = AddrSpace::addressToByte(val,spc->getWordSize());
  val = spc->wrapOffset(val);
  return Address(spc,val);
}

/// Get the next space in the absolute order of addresses.
/// This ordering is determined by the AddrSpace index.
/// \param spc is the pointer to the space being queried
/// \return the pointer to the next space in absolute order
AddrSpace *AddrSpaceManager::getNextSpaceInOrder(AddrSpace *spc) const
{
  if (spc == (AddrSpace *)0) {
    return baselist[0];
  }
  if (spc == (AddrSpace *) ~((uintp)0)) {
    return (AddrSpace *)0;
  }
  int4 index = spc->getIndex() + 1;
  while (index < baselist.size()) {
    AddrSpace *res = baselist[index];
    if (res != (AddrSpace *)0)
      return res;
    index += 1;
  }
  return (AddrSpace *) ~((uintp)0);
}

/// Given a list of memory locations, the \e pieces, either find a pre-existing JoinRecord or
/// create a JoinRecord that represents the logical joining of the pieces.  The pieces must
/// be in order from most significant to least significant.
/// \param pieces if the list memory locations to be joined
/// \param logicalsize of a \e single \e piece join, or zero
/// \return a pointer to the JoinRecord
JoinRecord *AddrSpaceManager::findAddJoin(const vector<VarnodeData> &pieces,uint4 logicalsize)

{ // Find a pre-existing split record, or create a new one corresponding to the input -pieces-
  // If -logicalsize- is 0, calculate logical size as sum of pieces
  if (pieces.size() == 0)
    throw LowlevelError("Cannot create a join without pieces");
  if ((pieces.size()==1)&&(logicalsize==0))
    throw LowlevelError("Cannot create a single piece join without a logical size");

  uint4 totalsize;
  if (logicalsize != 0) {
    if (pieces.size() != 1)
      throw LowlevelError("Cannot specify logical size for multiple piece join");
    totalsize = logicalsize;
  }
  else {
    totalsize = 0;
    for(int4 i=0;i<pieces.size();++i) // Calculate sum of the sizes of all pieces
      totalsize += pieces[i].size;
    if (totalsize == 0)
      throw LowlevelError("Cannot create a zero size join");
  }

  JoinRecord testnode;

  testnode.pieces = pieces;
  testnode.unified.size = totalsize;
  set<JoinRecord *,JoinRecordCompare>::const_iterator iter;
  iter = splitset.find(&testnode);
  if (iter != splitset.end())		// If already in the set
    return *iter;

  JoinRecord *newjoin = new JoinRecord();
  newjoin->pieces = pieces;
  
  uint4 roundsize = (totalsize + 15) & ~((uint4)0xf);	// Next biggest multiple of 16

  newjoin->unified.space = joinspace;
  newjoin->unified.offset = joinallocate;
  joinallocate += roundsize;
  newjoin->unified.size = totalsize;
  splitset.insert(newjoin);
  splitlist.push_back(newjoin);
  return splitlist.back();
}

/// Given a specific \e offset into the \e join address space, recover the JoinRecord that
/// contains the offset, as a range in the \e join address space.  If there is no existing
/// record, null is returned.
/// \param offset is an offset into the join space
/// \return the JoinRecord containing that offset or null
JoinRecord *AddrSpaceManager::findJoinInternal(uintb offset) const

{
  int4 min=0;
  int4 max=splitlist.size()-1;
  while(min<=max) {		// Binary search
    int4 mid = (min+max)/2;
    JoinRecord *rec = splitlist[mid];
    uintb val = rec->unified.offset;
    if (val + rec->unified.size <= offset)
      min = mid + 1;
    else if (val > offset)
      max = mid - 1;
    else
      return rec;
  }
  return (JoinRecord *)0;
}

/// Given a specific \e offset into the \e join address space, recover the JoinRecord that
/// lists the pieces corresponding to that offset.  The offset must originally have come from
/// a JoinRecord returned by \b findAddJoin, otherwise this method throws an exception.
/// \param offset is an offset into the join space
/// \return the JoinRecord for that offset
JoinRecord *AddrSpaceManager::findJoin(uintb offset) const

{
  int4 min=0;
  int4 max=splitlist.size()-1;
  while(min<=max) {		// Binary search
    int4 mid = (min+max)/2;
    JoinRecord *rec = splitlist[mid];
    uintb val = rec->unified.offset;
    if (val == offset) return rec;
    if (val < offset)
      min = mid + 1;
    else
      max = mid - 1;
  }
  throw LowlevelError("Unlinked join address");
}

/// Set the number of passes for a specific AddrSpace before deadcode removal is allowed
/// for that space.
/// \param spc is the AddrSpace to change
/// \param delaydelta is the number of rounds to the delay should be set to
void AddrSpaceManager::setDeadcodeDelay(AddrSpace *spc,int4 delaydelta)

{
  spc->deadcodedelay = delaydelta;
}

/// Mark the named space as truncated from its original size
/// \param tag is a description of the space and how it should be truncated
void AddrSpaceManager::truncateSpace(const TruncationTag &tag)

{
  AddrSpace *spc = getSpaceByName(tag.getName());
  if (spc == (AddrSpace *)0)
    throw LowlevelError("Unknown space in <truncate_space> command: "+tag.getName());
  spc->truncateSpace(tag.getSize());
}

/// This handles the situation where we need to find a logical address to hold the lower
/// precision floating-point value that is stored in a bigger register
/// If the logicalsize (precision) requested matches the -realsize- of the register
/// just return the real address.  Otherwise construct a join address to hold the logical value
/// \param realaddr is the address of the real floating-point register
/// \param realsize is the size of the real floating-point register
/// \param logicalsize is the size (lower precision) size of the logical value
Address AddrSpaceManager::constructFloatExtensionAddress(const Address &realaddr,int4 realsize,
							 int4 logicalsize)
{
  if (logicalsize == realsize)
    return realaddr;
  vector<VarnodeData> pieces;
  pieces.emplace_back();
  pieces.back().space = realaddr.getSpace();
  pieces.back().offset = realaddr.getOffset();
  pieces.back().size = realsize;

  JoinRecord *join = findAddJoin(pieces,logicalsize);
  return join->getUnified().getAddr();
}

/// This handles the common case, of trying to find a join address given a high location and a low
/// location. This may not return an address in the \e join address space.  It checks for the case
/// where the two pieces are contiguous locations in a mappable space, in which case it just returns
/// the containing address
/// \param translate is the Translate object used to find registers
/// \param hiaddr is the address of the most significant piece to be joined
/// \param hisz is the size of the most significant piece
/// \param loaddr is the address of the least significant piece
/// \param losz is the size of the least significant piece
/// \return an address representing the start of the joined range
Address AddrSpaceManager::constructJoinAddress(const Translate *translate,
					       const Address &hiaddr,int4 hisz,
					       const Address &loaddr,int4 losz)
{
  spacetype hitp = hiaddr.getSpace()->getType();
  spacetype lotp = loaddr.getSpace()->getType();
  bool usejoinspace = true;
  if (((hitp != IPTR_SPACEBASE)&&(hitp != IPTR_PROCESSOR))||
      ((lotp != IPTR_SPACEBASE)&&(lotp != IPTR_PROCESSOR)))
    throw LowlevelError("Trying to join in appropriate locations");
  if ((hitp == IPTR_SPACEBASE)||(lotp == IPTR_SPACEBASE)||
      (hiaddr.getSpace() == getDefaultCodeSpace())||
      (loaddr.getSpace() == getDefaultCodeSpace()))
    usejoinspace = false;
  if (hiaddr.isContiguous(hisz,loaddr,losz)) { // If we are contiguous
    if (!usejoinspace) { // and in a mappable space, just return the earliest address
      if (hiaddr.isBigEndian())
	return hiaddr;
      return loaddr;
    }
    else {			// If we are in a non-mappable (register) space, check to see if a parent register exists
      if (hiaddr.isBigEndian()) {
	if (translate->getRegisterName(hiaddr.getSpace(),hiaddr.getOffset(),(hisz+losz)).size() != 0)
	  return hiaddr;
      }
      else {
	if (translate->getRegisterName(loaddr.getSpace(),loaddr.getOffset(),(hisz+losz)).size() != 0)
	  return loaddr;
      }
    }
  }
  // Otherwise construct a formal JoinRecord
  vector<VarnodeData> pieces;
  pieces.emplace_back();
  pieces.emplace_back();
  pieces[0].space = hiaddr.getSpace();
  pieces[0].offset = hiaddr.getOffset();
  pieces[0].size = hisz;
  pieces[1].space = loaddr.getSpace();
  pieces[1].offset = loaddr.getOffset();
  pieces[1].size = losz;
  JoinRecord *join = findAddJoin(pieces,0);
  return join->getUnified().getAddr();
}

/// If an Address in the \e join AddressSpace is shifted from its original offset, it may no
/// longer have a valid JoinRecord.  The shift or size change may even make the address of
/// one of the pieces a more natural representation.  Given a new Address and size, this method
/// decides if there is a matching JoinRecord. If not it either constructs a new JoinRecord or
/// computes the address within the containing piece.  The given Address is changed if necessary
/// either to the offset corresponding to the new JoinRecord or to a normal \e non-join Address.
/// \param addr is the given Address
/// \param size is the size of the range in bytes
void AddrSpaceManager::renormalizeJoinAddress(Address &addr,int4 size)

{
  JoinRecord *joinRecord = findJoinInternal(addr.getOffset());
  if (joinRecord == (JoinRecord *)0)
    throw LowlevelError("Join address not covered by a JoinRecord");
  if (addr.getOffset() == joinRecord->unified.offset && size == joinRecord->unified.size)
    return;		// JoinRecord matches perfectly, no change necessary
  int4 pos1;
  Address addr1 = joinRecord->getEquivalentAddress(addr.getOffset(), pos1);
  int4 pos2;
  Address addr2 = joinRecord->getEquivalentAddress(addr.getOffset() + (size-1), pos2);
  if (addr2.isInvalid())
    throw LowlevelError("Join address range not covered");
  if (pos1 == pos2) {
    addr = addr1;
    return;
  }
  vector<VarnodeData> newPieces;
  int4 sizeTrunc1 = (int4)(addr1.getOffset() - joinRecord->pieces[pos1].offset);
  int4 sizeTrunc2 = joinRecord->pieces[pos2].size - (int4)(addr2.getOffset() - joinRecord->pieces[pos2].offset) - 1;

  if (pos2 < pos1) {		// Little endian
    newPieces.push_back(joinRecord->pieces[pos2]);
    pos2 += 1;
    while(pos2 <= pos1) {
      newPieces.push_back(joinRecord->pieces[pos2]);
      pos2 += 1;
    }
    newPieces.back().offset = addr1.getOffset();
    newPieces.back().size -= sizeTrunc1;
    newPieces.front().size -= sizeTrunc2;
  }
  else {
    newPieces.push_back(joinRecord->pieces[pos1]);
    pos1 += 1;
    while(pos1 <= pos2) {
      newPieces.push_back(joinRecord->pieces[pos1]);
      pos1 += 1;
    }
    newPieces.front().offset = addr1.getOffset();
    newPieces.front().size -= sizeTrunc1;
    newPieces.back().size -= sizeTrunc2;
  }
  JoinRecord *newJoinRecord = findAddJoin(newPieces, 0);
  addr = Address(newJoinRecord->unified.space,newJoinRecord->unified.offset);
}

/// The string \e must contain a hexadecimal offset.  The offset may be optionally prepended with "0x".
/// The string may optionally start with the name of the address space to associate with the offset, followed
/// by ':' to separate it from the offset.  If the name is not present, the default data space is assumed.
/// \param val is the string to parse
/// \return the parsed address
Address AddrSpaceManager::parseAddressSimple(const string &val)

{
  string::size_type col = val.find(':');
  AddrSpace *spc;
  if (col==string::npos) {
    spc = getDefaultDataSpace();
    col = 0;
  }
  else {
    string spcName = val.substr(0,col);
    spc = getSpaceByName(spcName);
    if (spc == (AddrSpace *)0)
      throw LowlevelError("Unknown address space: " + spcName);
    col += 1;
  }
  if (col + 2 <= val.size()) {
    if (val[col] == '0' && val[col+1] == 'x')
      col += 2;
  }
  istringstream s(val.substr(col));
  uintb off;
  s >> hex >> off;
  return Address(spc,AddrSpace::addressToByte(off, spc->getWordSize()));
}

/// This constructs only a shell for the Translate object.  It
/// won't be usable until it is initialized for a specific processor
/// The main entry point for this is the Translate::initialize method,
/// which must be overridden by a derived class
Translate::Translate(void)

{
  target_isbigendian = false;
  unique_base=0;
  alignment = 1;
}

/// If no floating-point format objects were registered by the \b initialize method, this
/// method will fill in some suitable default formats.  These defaults are based on
/// the 4-byte and 8-byte encoding specified by the IEEE 754 standard.
void Translate::setDefaultFloatFormats(void)

{
  if (floatformats.empty()) {	// Default IEEE 754 float formats
    floatformats.push_back(FloatFormat(4));
    floatformats.push_back(FloatFormat(8));
  }
}

/// The pcode model for floating point encoding assumes that a
/// consistent encoding is used for all values of a given size.
/// This routine fetches the FloatFormat object given the size,
/// in bytes, of the desired encoding.
/// \param size is the size of the floating-point value in bytes
/// \return a pointer to the floating-point format
const FloatFormat *Translate::getFloatFormat(int4 size) const

{
  vector<FloatFormat>::const_iterator iter;

  for(iter=floatformats.begin();iter!=floatformats.end();++iter) {
    if ((*iter).getSize() == size)
      return &(*iter);
  }
  return (const FloatFormat *)0;
}

/// A convenience method for passing around p-code operations via stream.
/// A single p-code operation is parsed from an \<op> element and
/// returned to the application via the PcodeEmit::dump method.
/// \param addr is the address (of the instruction) to associate with the p-code op
/// \param decoder is the stream decoder
void PcodeEmit::decodeOp(const Address &addr,Decoder &decoder)

{
  int4 opcode;
  int4 isize;
  VarnodeData outvar;
  VarnodeData invar[16];
  VarnodeData *outptr;

  uint4 elemId = decoder.openElement(ELEM_OP);
  isize = decoder.readSignedInteger(ATTRIB_SIZE);
  outptr = &outvar;
  if (isize <= 16)
    opcode = PcodeOpRaw::decode(decoder, isize, invar, &outptr);
  else {
    vector<VarnodeData> varStorage(isize,VarnodeData());
    opcode = PcodeOpRaw::decode(decoder, isize, varStorage.data(), &outptr);
  }
  decoder.closeElement(elemId);
  dump(addr,(OpCode)opcode,outptr,invar,isize);
}

} // End namespace ghidra

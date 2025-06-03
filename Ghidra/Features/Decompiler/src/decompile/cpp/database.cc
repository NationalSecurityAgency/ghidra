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
#include "database.hh"
#include "funcdata.hh"
#include "crc32.hh"
#include <ctype.h>

namespace ghidra {

AttributeId ATTRIB_CAT = AttributeId("cat",61);
AttributeId ATTRIB_FIELD = AttributeId("field",62);
AttributeId ATTRIB_MERGE = AttributeId("merge",63);
AttributeId ATTRIB_SCOPEIDBYNAME = AttributeId("scopeidbyname",64);
AttributeId ATTRIB_VOLATILE = AttributeId("volatile",65);

ElementId ELEM_COLLISION = ElementId("collision",67);
ElementId ELEM_DB = ElementId("db",68);
ElementId ELEM_EQUATESYMBOL = ElementId("equatesymbol",69);
ElementId ELEM_EXTERNREFSYMBOL = ElementId("externrefsymbol",70);
ElementId ELEM_FACETSYMBOL = ElementId("facetsymbol",71);
ElementId ELEM_FUNCTIONSHELL = ElementId("functionshell",72);
ElementId ELEM_HASH = ElementId("hash",73);
ElementId ELEM_HOLE = ElementId("hole",74);
ElementId ELEM_LABELSYM = ElementId("labelsym",75);
ElementId ELEM_MAPSYM = ElementId("mapsym",76);
ElementId ELEM_PARENT = ElementId("parent",77);
ElementId ELEM_PROPERTY_CHANGEPOINT = ElementId("property_changepoint",78);
ElementId ELEM_RANGEEQUALSSYMBOLS = ElementId("rangeequalssymbols",79);
ElementId ELEM_SCOPE = ElementId("scope",80);
ElementId ELEM_SYMBOLLIST = ElementId("symbollist",81);

uint8 Symbol::ID_BASE = 0x4000000000000000L;

/// This SymbolEntry is unintegrated. An address or hash must be provided
/// either directly or via decode().
/// \param sym is the Symbol \b this will be a map for
SymbolEntry::SymbolEntry(Symbol *sym)
  : symbol(sym)
{
  extraflags = 0;
  offset = 0;
  hash = 0;
  size = -1;
}

/// This is used specifically for \e dynamic Symbol objects, where the storage location
/// is attached to a temporary register or a constant. The main address field (\b addr)
/// is set to \e invalid, and the \b hash becomes the primary location information.
/// \param sym is the underlying Symbol
/// \param exfl are the Varnode flags associated with the storage location
/// \param h is the hash
/// \param off if the offset into the Symbol for this (piece of) storage
/// \param sz is the size in bytes of this (piece of) storage
/// \param rnglist is the set of code addresses where \b this SymbolEntry represents the Symbol
SymbolEntry::SymbolEntry(Symbol *sym,uint4 exfl,uint8 h,int4 off,int4 sz,const RangeList &rnglist)

{
  symbol = sym;
  extraflags = exfl;
  addr = Address();
  hash = h;
  offset = off;
  size = sz;
  uselimit = rnglist;
}

/// Establish the boundary offsets and fill in additional data
/// \param data contains the raw initialization data
/// \param a is the starting offset of the entry
/// \param b is the ending offset of the entry
SymbolEntry::SymbolEntry(const EntryInitData &data,uintb a,uintb b)

{
  addr = Address(data.space,a);
  size = (b-a)+1;
  symbol = data.symbol;
  extraflags = data.extraflags;
  offset = data.offset;
  uselimit = data.uselimit;
}

/// Get data used to sub-sort entries (in a rangemap) at the same address
/// \return the sub-sort object
SymbolEntry::subsorttype SymbolEntry::getSubsort(void) const

{
  subsorttype res;		// Minimal subsort
  if ((symbol->getFlags()&Varnode::addrtied)==0) {
    const Range *range = uselimit.getFirstRange();
    if (range == (const Range *)0)
      throw LowlevelError("Map entry with empty uselimit");
    res.useindex = range->getSpace()->getIndex();
    res.useoffset = range->getFirst();
  }
  return res;
}

/// This storage location may only hold the Symbol value for a limited portion of the code.
/// \param usepoint is the given code address to test
/// \return \b true if \b this storage is valid at the given address
bool SymbolEntry::inUse(const Address &usepoint) const

{
  if (isAddrTied()) return true; // Valid throughout scope
  if (usepoint.isInvalid()) return false;
  return uselimit.inRange(usepoint,1);
}

Address SymbolEntry::getFirstUseAddress(void) const

{
  const Range *rng = uselimit.getFirstRange();
  if (rng == (const Range *)0)
    return Address();
  return rng->getFirstAddr();
}

/// If the Symbol associated with \b this is type-locked, change the given
/// Varnode's attached data-type to match the Symbol
/// \param vn is the Varnode to modify
/// \return true if the data-type was changed
bool SymbolEntry::updateType(Varnode *vn) const

{
  if ((symbol->getFlags()&Varnode::typelock)!=0) { // Type will just get replaced if not locked
    Datatype *dt = getSizedType(vn->getAddr(),vn->getSize());
    if (dt != (Datatype *)0)
      return vn->updateType(dt,true,true);
  }
  return false;
}

/// Return the data-type that matches the given size and address within \b this storage.
/// NULL is returned if there is no valid sub-type matching the size.
/// \param inaddr is the given address
/// \param sz is the given size (in bytes)
/// \return the matching data-type or NULL
Datatype *SymbolEntry::getSizedType(const Address &inaddr,int4 sz) const

{
  int4 off;

  if (isDynamic())
    off = offset;
  else
    off = (int4)(inaddr.getOffset() - addr.getOffset()) + offset;
  Datatype *cur = symbol->getType();
  return symbol->getScope()->getArch()->types->getExactPiece(cur, off, sz);
}

/// Give a contained one-line description of \b this storage, suitable for a debug console
/// \param s is the output stream
void SymbolEntry::printEntry(ostream &s) const

{
  s << symbol->getName() << " : ";
  if (addr.isInvalid())
    s << "<dynamic>";
  else {
    s << addr.getShortcut();
    addr.printRaw(s);
  }
  s << ':' << dec << (uint4) symbol->getType()->getSize();
  s << ' ';
  symbol->getType()->printRaw(s);
  s << " : ";
  uselimit.printBounds(s);
}

/// This writes elements internal to the \<mapsym> element associated with the Symbol.
/// It encodes the address element (or the \<hash> element for dynamic symbols) and
/// a \<rangelist> element associated with the \b uselimit.
/// \param encoder is the stream encoder
void SymbolEntry::encode(Encoder &encoder) const

{
  if (isPiece()) return;	// Don't save a piece
  if (addr.isInvalid()) {
    encoder.openElement(ELEM_HASH);
    encoder.writeUnsignedInteger(ATTRIB_VAL, hash);
    encoder.closeElement(ELEM_HASH);
  }
  else
    addr.encode(encoder);
  uselimit.encode(encoder);
}

/// Parse either an \<addr> element for storage information or a \<hash> element
/// if the symbol is dynamic. Then parse the \b uselimit describing the valid
/// range of code addresses.
/// \param decoder is the stream decoder
/// \return the advanced iterator
void SymbolEntry::decode(Decoder &decoder)

{
  uint4 elemId = decoder.peekElement();
  if (elemId == ELEM_HASH) {
    decoder.openElement();
    hash = decoder.readUnsignedInteger(ATTRIB_VAL);
    addr = Address();
    decoder.closeElement(elemId);
  }
  else {
    addr = Address::decode(decoder);
    hash = 0;
  }
  uselimit.decode(decoder);
}

/// Examine the data-type to decide if the Symbol has the special property
/// called \b size_typelock, which indicates the \e size of the Symbol
/// is locked, but the data-type is not locked (and can float)
void Symbol::checkSizeTypeLock(void)

{
  dispflags &= ~((uint4)size_typelock);
  if (isTypeLocked() && (type->getMetatype() == TYPE_UNKNOWN))
    dispflags |= size_typelock;
}

/// \param val is \b true if we are the "this" pointer
void Symbol::setThisPointer(bool val)

{
  if (val)
    dispflags |= is_this_ptr;
  else
    dispflags &= ~((uint4)is_this_ptr);
}

/// The name for a Symbol can be unspecified.  See ScopeInternal::buildUndefinedName
/// \return \b true if the name of \b this is undefined
bool Symbol::isNameUndefined(void) const

{
  return ((name.size()==15)&&(0==name.compare(0,7,"$$undef")));
}

/// If the given value is \b true, any Varnodes that map directly to \b this Symbol,
/// will not be speculatively merged with other Varnodes.  (Required merges will still happen).
/// \param val is the given boolean value
void Symbol::setIsolated(bool val)

{
  if (val) {
    dispflags |= isolate;
    flags |= Varnode::typelock;		// Isolated Symbol must be typelocked
    checkSizeTypeLock();
  }
  else
    dispflags &= ~((uint4)isolate);
}

/// \return the first SymbolEntry
SymbolEntry *Symbol::getFirstWholeMap(void) const

{
  if (mapentry.empty())
    throw LowlevelError("No mapping for symbol: "+name);
  return &(*mapentry[0]);
}

/// This method may return a \e partial entry, where the SymbolEntry is only holding
/// part of the whole Symbol.
/// \param addr is an address within the desired storage location of the Symbol
/// \return the first matching SymbolEntry
SymbolEntry *Symbol::getMapEntry(const Address &addr) const

{
  SymbolEntry *res;
  for(int4 i=0;i<mapentry.size();++i) {
    res = &(*mapentry[i]);
    const Address &entryaddr( res->getAddr() );
    if (addr.getSpace() != entryaddr.getSpace()) continue;
    if (addr.getOffset() < entryaddr.getOffset()) continue;
    int4 diff = (int4) (addr.getOffset() - entryaddr.getOffset());
    if (diff >= res->getSize()) continue;
    return res;
  }
  //  throw LowlevelError("No mapping at desired address for symbol: "+name);
  return (SymbolEntry *)0;
}

/// Among all the SymbolEntrys that map \b this entire Symbol, calculate
/// the position of the given SymbolEntry within the list.
/// \param entry is the given SymbolEntry
/// \return its position within the list or -1 if it is not in the list
int4 Symbol::getMapEntryPosition(const SymbolEntry *entry) const

{
  int4 pos = 0;
  for(int4 i=0;i<mapentry.size();++i) {
    const SymbolEntry *tmp = &(*mapentry[i]);
    if (tmp == entry)
      return pos;
    if (entry->getSize() == type->getSize())
      pos += 1;
  }
  return -1;
}

/// For a given context scope where \b this Symbol is used, determine how many elements of
/// the full namespace path need to be printed to correctly distinguish it.
/// A value of 0 means the base symbol name is visible and not overridden in the context scope.
/// A value of 1 means the base name may be overridden, but the parent scope name is not.
/// The minimal number of names that distinguishes the symbol name uniquely within the
/// use scope is returned.
/// \param useScope is the given scope where the symbol is being used
/// \return the number of (extra) names needed to distinguish the symbol
int4 Symbol::getResolutionDepth(const Scope *useScope) const

{
  if (scope == useScope) return 0;	// Symbol is in scope where it is used
  if (useScope == (const Scope *)0) {	// Treat null useScope as resolving the full path
    const Scope *point = scope;
    int4 count = 0;
    while(point != (const Scope *)0) {
      count += 1;
      point = point->getParent();
    }
    return count-1;	// Don't print global scope
  }
  if (depthScope == useScope)
    return depthResolution;
  depthScope = useScope;
  const Scope *distinguishScope = scope->findDistinguishingScope(useScope);
  depthResolution = 0;
  string distinguishName;
  const Scope *terminatingScope;
  if (distinguishScope == (const Scope *)0) {	// Symbol scope is ancestor of use scope
    distinguishName = name;
    terminatingScope = scope;
  }
  else {
    distinguishName = distinguishScope->getName();
    const Scope *currentScope = scope;
    while(currentScope != distinguishScope) {	// For any scope up to the distinguishing scope
      depthResolution += 1;			// Print its name
      currentScope = currentScope->getParent();
    }
    depthResolution += 1;		// Also print the distinguishing scope name
    terminatingScope = distinguishScope->getParent();
  }
  if (useScope->isNameUsed(distinguishName,terminatingScope))
    depthResolution += 1;		// Name was overridden, we need one more distinguishing name
  return depthResolution;
}

/// \param encoder is the stream encoder
void Symbol::encodeHeader(Encoder &encoder) const

{
  encoder.writeString(ATTRIB_NAME, name);
  encoder.writeUnsignedInteger(ATTRIB_ID, getId());
  if ((flags&Varnode::namelock)!=0)
    encoder.writeBool(ATTRIB_NAMELOCK, true);
  if ((flags&Varnode::typelock)!=0)
    encoder.writeBool(ATTRIB_TYPELOCK, true);
  if ((flags&Varnode::readonly)!=0)
    encoder.writeBool(ATTRIB_READONLY, true);
  if ((flags&Varnode::volatil)!=0)
    encoder.writeBool(ATTRIB_VOLATILE, true);
  if ((flags&Varnode::indirectstorage)!=0)
    encoder.writeBool(ATTRIB_INDIRECTSTORAGE, true);
  if ((flags&Varnode::hiddenretparm)!=0)
    encoder.writeBool(ATTRIB_HIDDENRETPARM, true);
  if ((dispflags&isolate)!=0)
    encoder.writeBool(ATTRIB_MERGE, false);
  if ((dispflags&is_this_ptr)!=0)
    encoder.writeBool(ATTRIB_THISPTR, true);
  int4 format = getDisplayFormat();
  if (format != 0) {
    encoder.writeString(ATTRIB_FORMAT, Datatype::decodeIntegerFormat(format));
  }
  encoder.writeSignedInteger(ATTRIB_CAT, category);
  if (category >= 0)
    encoder.writeUnsignedInteger(ATTRIB_INDEX, catindex);
}

/// \param decoder is the stream decoder
void Symbol::decodeHeader(Decoder &decoder)

{
  name.clear();
  displayName.clear();
  category = no_category;
  symbolId = 0;
  for(;;) {
    uintb attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_CAT) {
      category = decoder.readSignedInteger();
    }
    else if (attribId == ATTRIB_FORMAT) {
      dispflags |= Datatype::encodeIntegerFormat(decoder.readString());
    }
    else if (attribId == ATTRIB_HIDDENRETPARM) {
      if (decoder.readBool())
	flags |= Varnode::hiddenretparm;
    }
    else if (attribId == ATTRIB_ID) {
      symbolId = decoder.readUnsignedInteger();
      if ((symbolId >> 56) == (ID_BASE >> 56))
	symbolId = 0;		// Don't keep old internal id's
    }
    else if (attribId == ATTRIB_INDIRECTSTORAGE) {
      if (decoder.readBool())
	flags |= Varnode::indirectstorage;
    }
    else if (attribId == ATTRIB_MERGE) {
      if (!decoder.readBool()) {
	dispflags |= isolate;
	flags |= Varnode::typelock;
      }
    }
    else if (attribId == ATTRIB_NAME)
      name = decoder.readString();
    else if (attribId == ATTRIB_NAMELOCK) {
      if (decoder.readBool())
	flags |= Varnode::namelock;
    }
    else if (attribId == ATTRIB_READONLY) {
      if (decoder.readBool())
	flags |= Varnode::readonly;
    }
    else if (attribId == ATTRIB_TYPELOCK) {
      if (decoder.readBool())
	flags |= Varnode::typelock;
    }
    else if (attribId == ATTRIB_THISPTR) {
      if (decoder.readBool())
	dispflags |= is_this_ptr;
    }
    else if (attribId == ATTRIB_VOLATILE) {
      if (decoder.readBool())
	flags |= Varnode::volatil;
    }
    else if (attribId == ATTRIB_LABEL) {
      displayName = decoder.readString();
    }
  }
  if (category == function_parameter) {
    catindex = decoder.readUnsignedInteger(ATTRIB_INDEX);
  }
  else
    catindex = 0;
  if (displayName.size() == 0)
    displayName = name;
}

/// Encode the data-type for the Symbol
/// \param encoder is the stream encoder
void Symbol::encodeBody(Encoder &encoder) const

{
  type->encodeRef(encoder);
}

/// \param decoder is the stream decoder
void Symbol::decodeBody(Decoder &decoder)

{
  type = scope->getArch()->types->decodeType(decoder);
  checkSizeTypeLock();
}

/// \param encoder is the stream encoder
void Symbol::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_SYMBOL);
  encodeHeader(encoder);
  encodeBody(encoder);
  encoder.closeElement(ELEM_SYMBOL);
}

/// Parse a Symbol from the next element in the stream
/// \param decoder is the stream decoder
void Symbol::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_SYMBOL);
  decodeHeader(decoder);

  decodeBody(decoder);
  decoder.closeElement(elemId);
}

/// Get the number of bytes consumed by a SymbolEntry representing \b this Symbol.
/// By default, this is the number of bytes consumed by the Symbol's data-type.
/// This gives the amount of leeway a search has when the address queried does not match
/// the exact address of the Symbol. With functions, the bytes consumed by a SymbolEntry
/// may not match the data-type size.
/// \return the number of bytes in a default SymbolEntry
int4 Symbol::getBytesConsumed(void) const

{
  return type->getSize();
}

void FunctionSymbol::buildType(void)

{
  TypeFactory *types = scope->getArch()->types;
  type = types->getTypeCode();
  flags |= Varnode::namelock | Varnode::typelock;
}

/// Build a function \e shell, made up of just the name of the function and
/// a placeholder data-type, without the underlying Funcdata object.
/// A SymbolEntry for a function has a small size starting at the entry address,
/// in order to deal with non-contiguous functions.
/// We need a size (slightly) larger than 1 to accommodate pointer constants that encode
/// extra information in the lower bit(s) of an otherwise aligned pointer.
/// If the encoding is not initially detected, it is interpreted
/// as a straight address that comes up 1 (or more) bytes off of the start of the function
/// In order to detect this, we need to lay down a slightly larger size than 1
/// \param sc is the Scope that will contain the new Symbol
/// \param nm is the name of the new Symbol
/// \param size is the number of bytes a SymbolEntry should consume
FunctionSymbol::FunctionSymbol(Scope *sc,const string &nm,int4 size)
  : Symbol(sc)
{
  fd = (Funcdata *)0;
  consumeSize = size;
  buildType();
  name = nm;
  displayName = nm;
}

FunctionSymbol::FunctionSymbol(Scope *sc,int4 size)
  : Symbol(sc)
{
  fd = (Funcdata *)0;
  consumeSize = size;
  buildType();
}

FunctionSymbol::~FunctionSymbol(void) {
  if (fd != (Funcdata *)0)
    delete fd;
}

Funcdata *FunctionSymbol::getFunction(void)

{
  if (fd != (Funcdata *)0) return fd;
  SymbolEntry *entry = getFirstWholeMap();
  fd = new Funcdata(name,displayName,scope,entry->getAddr(),this);
  return fd;
}

void FunctionSymbol::encode(Encoder &encoder) const

{
  if (fd != (Funcdata *)0)
    fd->encode(encoder,symbolId,false);	// Save the function itself
  else {
    encoder.openElement(ELEM_FUNCTIONSHELL);
    encoder.writeString(ATTRIB_NAME, name);
    if (symbolId != 0)
      encoder.writeUnsignedInteger(ATTRIB_ID, symbolId);
    encoder.closeElement(ELEM_FUNCTIONSHELL);
  }
}

void FunctionSymbol::decode(Decoder &decoder)

{
  uint4 elemId = decoder.peekElement();
  if (elemId == ELEM_FUNCTION) {
    fd = new Funcdata("","",scope,Address(),this);
    try {
      symbolId = fd->decode(decoder);
    } catch(RecovError &err) {
      // Caused by a duplicate scope name. Preserve the address so we can find the original symbol
      throw DuplicateFunctionError(fd->getAddress(),fd->getName());
    }
    name = fd->getName();
    displayName = fd->getDisplayName();
    if (consumeSize < fd->getSize()) {
      if ((fd->getSize()>1)&&(fd->getSize() <= 8))
	consumeSize = fd->getSize();
    }
  }
  else {			// functionshell
    decoder.openElement();
    symbolId = 0;
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_NAME)
	name = decoder.readString();
      else if (attribId == ATTRIB_ID) {
	symbolId = decoder.readUnsignedInteger();
      }
      else if (attribId == ATTRIB_LABEL) {
	displayName = decoder.readString();
      }
    }
    decoder.closeElement(elemId);
  }
}

/// Create a symbol either to associate a name with a constant or to force a display conversion
///
/// \param sc is the scope owning the new symbol
/// \param nm is the name of the equate (an empty string can be used for a convert)
/// \param format is the desired display conversion (0 for no conversion)
/// \param val is the constant value whose display is being altered
EquateSymbol::EquateSymbol(Scope *sc,const string &nm,uint4 format,uintb val)
  : Symbol(sc, nm, (Datatype *)0)
{
  value = val;
  category = equate;
  type = sc->getArch()->types->getBase(1,TYPE_UNKNOWN);
  dispflags |= format;
}

/// An EquateSymbol should survive certain kinds of transforms during decompilation,
/// such as negation, twos-complementing, adding or subtracting 1.
/// Return \b true if the given value looks like a transform of this type relative
/// to the underlying value of \b this equate.
/// \param op2Value is the given value
/// \param size is the number of bytes of precision
/// \return \b true if it is a transformed form
bool EquateSymbol::isValueClose(uintb op2Value,int4 size) const

{
  if (value == op2Value) return true;
  uintb mask = calc_mask(size);
  uintb maskValue = value & mask;
  if (maskValue != value) {		// If '1' bits are getting masked off
    // Make sure only sign-extension is getting masked off
    if (value != sign_extend(maskValue,size,sizeof(uintb)))
	return false;
  }
  if (maskValue == (op2Value & mask)) return true;
  if (maskValue == (~op2Value & mask)) return true;
  if (maskValue == (-op2Value & mask)) return true;
  if (maskValue == ((op2Value + 1) & mask)) return true;
  if (maskValue == ((op2Value -1) & mask)) return true;
  return false;
}

void EquateSymbol::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_EQUATESYMBOL);
  encodeHeader(encoder);
  encoder.openElement(ELEM_VALUE);
  encoder.writeUnsignedInteger(ATTRIB_CONTENT, value);
  encoder.closeElement(ELEM_VALUE);
  encoder.closeElement(ELEM_EQUATESYMBOL);
}

void EquateSymbol::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_EQUATESYMBOL);
  decodeHeader(decoder);

  uint4 subId = decoder.openElement(ELEM_VALUE);
  value = decoder.readUnsignedInteger(ATTRIB_CONTENT);
  decoder.closeElement(subId);

  TypeFactory *types = scope->getArch()->types;
  type = types->getBase(1,TYPE_UNKNOWN);
  decoder.closeElement(elemId);
}

/// Create a symbol that forces a particular field of a union to propagate
///
/// \param sc is the scope owning the new symbol
/// \param nm is the name of the symbol
/// \param unionDt is the union data-type being forced
/// \param fldNum is the particular field to force (-1 indicates the whole union)
UnionFacetSymbol::UnionFacetSymbol(Scope *sc,const string &nm,Datatype *unionDt,int4 fldNum)
  : Symbol(sc, nm, unionDt)
{
  fieldNum = fldNum;
  category = union_facet;
}

void UnionFacetSymbol::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_FACETSYMBOL);
  encodeHeader(encoder);
  encoder.writeSignedInteger(ATTRIB_FIELD, fieldNum);
  encodeBody(encoder);
  encoder.closeElement(ELEM_FACETSYMBOL);
}

void UnionFacetSymbol::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_FACETSYMBOL);
  decodeHeader(decoder);
  fieldNum = decoder.readSignedInteger(ATTRIB_FIELD);

  decodeBody(decoder);
  decoder.closeElement(elemId);
  Datatype *testType = type;
  if (testType->getMetatype() == TYPE_PTR)
    testType = ((TypePointer *)testType)->getPtrTo();
  if (testType->getMetatype() != TYPE_UNION)
    throw LowlevelError("<unionfacetsymbol> does not have a union type");
  if (fieldNum < -1 || fieldNum >= testType->numDepend())
    throw LowlevelError("<unionfacetsymbol> field attribute is out of bounds");
}

/// Label symbols don't really have a data-type, so we just put
/// a size 1 placeholder.
void LabSymbol::buildType(void)

{
  type = scope->getArch()->types->getBase(1,TYPE_UNKNOWN);
}

/// \param sc is the Scope that will contain the new Symbol
/// \param nm is the name of the new Symbol
LabSymbol::LabSymbol(Scope *sc,const string &nm)
  : Symbol(sc)
{
  buildType();
  name = nm;
  displayName = nm;
}

/// \param sc is the Scope that will contain the new Symbol
LabSymbol::LabSymbol(Scope *sc)
  : Symbol(sc)
{
  buildType();
}

void LabSymbol::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_LABELSYM);
  encodeHeader(encoder);		// We never set category
  encoder.closeElement(ELEM_LABELSYM);
}

void LabSymbol::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_LABELSYM);
  decodeHeader(decoder);
  decoder.closeElement(elemId);
}

/// Build name, type, and flags based on the placeholder address
void ExternRefSymbol::buildNameType(void)

{
  TypeFactory *typegrp = scope->getArch()->types;
  type = typegrp->getTypeCode();
  type = typegrp->getTypePointer(refaddr.getAddrSize(),type,refaddr.getSpace()->getWordSize());
  if (name.size() == 0) {	// If a name was not already provided
    ostringstream s;		// Give the reference a unique name
    s << refaddr.getShortcut();
    refaddr.printRaw(s);
    name = s.str();
    name += "_exref"; // Indicate this is an external reference variable
  }
  if (displayName.size() == 0)
    displayName = name;
  flags |= Varnode::externref | Varnode::typelock;
}

/// \param sc is the Scope containing the Symbol
/// \param ref is the placeholder address where the system will hold meta-data
/// \param nm is the name of the Symbol
ExternRefSymbol::ExternRefSymbol(Scope *sc,const Address &ref,const string &nm)
  : Symbol(sc,nm,(Datatype *)0)
{
  refaddr = ref;
  buildNameType();
}

void ExternRefSymbol::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_EXTERNREFSYMBOL);
  encoder.writeString(ATTRIB_NAME, name);
  refaddr.encode(encoder);
  encoder.closeElement(ELEM_EXTERNREFSYMBOL);
}

void ExternRefSymbol::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_EXTERNREFSYMBOL);
  name.clear();			// Name is empty
  displayName.clear();
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_NAME) // Unless we see it explicitly
      name = decoder.readString();
    else if (attribId == ATTRIB_LABEL)
      displayName = decoder.readString();
  }
  refaddr = Address::decode(decoder);
  decoder.closeElement(elemId);
  buildNameType();
}

/// The iterator is advanced by one
/// \return a reference to the (advanced) iterator
MapIterator &MapIterator::operator++(void) {
  ++curiter;
  while((curmap!=map->end())&&(curiter==(*curmap)->end_list())) {
    do {
      ++curmap;
    } while((curmap!=map->end())&&((*curmap)==(EntryMap *)0));
    if (curmap!=map->end())
      curiter = (*curmap)->begin_list();
  }
  return *this;
}

/// The iterator is advanced by one
/// \param i is a dummy variable
/// \return a copy of the iterator before it was advanced
MapIterator MapIterator::operator++(int4 i) {
  MapIterator tmp(*this);
  ++curiter;
  while((curmap!=map->end())&&(curiter==(*curmap)->end_list())) {
    do {
      ++curmap;
    } while((curmap!=map->end())&&((*curmap)==(EntryMap *)0));
    if (curmap!=map->end())
      curiter = (*curmap)->begin_list();
  }
  return tmp;
}

/// Attach the child as an immediate sub-scope of \b this.
/// Take responsibility of the child's memory: the child will be freed when this is freed.
/// \param child is the Scope to make a child
void Scope::attachScope(Scope *child)

{
  child->parent = this;
  children[child->uniqueId] = child;	// uniqueId is guaranteed to be unique by Database
}

/// The indicated child Scope is deleted
/// \param iter points to the Scope to delete
void Scope::detachScope(ScopeMap::iterator iter)

{
  Scope *child = (*iter).second;
  children.erase(iter);
  delete child;
}

/// \brief Create a Scope id based on the scope's name and its parent's id
///
/// Create a globally unique id for a scope simply from its name.
/// \param baseId is the scope id of the parent scope
/// \param nm is the name of scope
/// \return the hash of the parent id and name
uint8 Scope::hashScopeName(uint8 baseId,const string &nm)

{
  uint4 reg1 = (uint4)(baseId>>32);
  uint4 reg2 = (uint4)baseId;
  reg1 = crc_update(reg1, 0xa9);
  reg2 = crc_update(reg2, reg1);
  for(int4 i=0;i<nm.size();++i) {
    uint4 val = nm[i];
    reg1 = crc_update(reg1, val);
    reg2 = crc_update(reg2, reg1);
  }
  uint8 res = reg1;
  res = (res << 32) | reg2;
  return res;
}

/// \brief Query for Symbols starting at a given address, which match a given \b usepoint
///
/// Searching starts at a first scope, continuing thru parents up to a second scope,
/// which is not queried.  If a Scope \e controls the memory at that address, the Scope
/// object is returned. Additionally, if a symbol matching the criterion is found,
/// the matching SymbolEntry is passed back.
/// \param scope1 is the first Scope where searching starts
/// \param scope2 is the second Scope where searching ends
/// \param addr is the given address to search for
/// \param usepoint is the given point at which the memory is being accessed (can be an invalid address)
/// \param addrmatch is used to pass-back any matching SymbolEntry
/// \return the Scope owning the address or NULL if none found
const Scope *Scope::stackAddr(const Scope *scope1,
			      const Scope *scope2,
			      const Address &addr,
			      const Address &usepoint,
			      SymbolEntry **addrmatch)
{
  SymbolEntry *entry;
  if (addr.isConstant()) return (const Scope *)0;
  while((scope1 != (const Scope *)0)&&(scope1 != scope2)) {
    entry = scope1->findAddr(addr,usepoint);
    if (entry != (SymbolEntry *)0) {
      *addrmatch = entry;
      return scope1;
    }
    if (scope1->inScope(addr,1,usepoint))
      return scope1;		// Discovery of new variable
    scope1 = scope1->getParent();
  }
  return (const Scope *)0;
}

/// Query for a Symbol containing a given range which is accessed at a given \b usepoint
///
/// Searching starts at a first scope, continuing thru parents up to a second scope,
/// which is not queried.  If a Scope \e controls the memory in the given range, the Scope
/// object is returned. If a known Symbol contains the range,
/// the matching SymbolEntry is passed back.
/// \param scope1 is the first Scope where searching starts
/// \param scope2 is the second Scope where searching ends
/// \param addr is the starting address of the given range
/// \param size is the number of bytes in the given range
/// \param usepoint is the point at which the memory is being accessed (can be an invalid address)
/// \param addrmatch is used to pass-back any matching SymbolEntry
/// \return the Scope owning the address or NULL if none found
const Scope *Scope::stackContainer(const Scope *scope1,
				   const Scope *scope2,
				   const Address &addr,int4 size,
				   const Address &usepoint,
				   SymbolEntry **addrmatch)
{
  SymbolEntry *entry;
  if (addr.isConstant()) return (const Scope *)0;
  while((scope1 != (const Scope *)0)&&(scope1 != scope2)) {
    entry = scope1->findContainer(addr,size,usepoint);
    if (entry != (SymbolEntry *)0) {
      *addrmatch = entry;
      return scope1;
    }
    if (scope1->inScope(addr,size,usepoint))
      return scope1;		// Discovery of new variable
    scope1 = scope1->getParent();
  }
  return (const Scope *)0;
}

/// Query for a Symbol which most closely matches a given range and \b usepoint
///
/// Searching starts at a first scope, continuing thru parents up to a second scope,
/// which is not queried.  If a Scope \e controls the memory in the given range, the Scope
/// object is returned. Among symbols that overlap the given range, the SymbolEntry
/// which most closely matches the starting address and size is passed back.
/// \param scope1 is the first Scope where searching starts
/// \param scope2 is the second Scope where searching ends
/// \param addr is the starting address of the given range
/// \param size is the number of bytes in the given range
/// \param usepoint is the point at which the memory is being accessed (can be an invalid address)
/// \param addrmatch is used to pass-back any matching SymbolEntry
/// \return the Scope owning the address or NULL if none found
const Scope *Scope::stackClosestFit(const Scope *scope1,
					      const Scope *scope2,
					      const Address &addr,int4 size,
					      const Address &usepoint,
					      SymbolEntry **addrmatch)
{
  SymbolEntry *entry;
  if (addr.isConstant()) return (const Scope *)0;
  while((scope1 != (const Scope *)0)&&(scope1 != scope2)) {
    entry = scope1->findClosestFit(addr,size,usepoint);
    if (entry != (SymbolEntry *)0) {
      *addrmatch = entry;
      return scope1;
    }
    if (scope1->inScope(addr,size,usepoint))
      return scope1;		// Discovery of new variable
    scope1 = scope1->getParent();
  }
  return (const Scope *)0;
}

/// Query for a function Symbol starting at the given address
///
/// Searching starts at a first scope, continuing thru parents up to a second scope,
/// which is not queried.  If a Scope \e controls the memory in the given range, the Scope
/// object is returned. If a FunctionSymbol is found at the given address, the
/// corresponding Funcdata object is passed back.
/// \param scope1 is the first Scope where searching starts
/// \param scope2 is the second Scope where searching ends
/// \param addr is the given address where the function should start
/// \param addrmatch is used to pass-back any matching function
/// \return the Scope owning the address or NULL if none found
const Scope *Scope::stackFunction(const Scope *scope1,
					    const Scope *scope2,
					    const Address &addr,
					    Funcdata **addrmatch)
{
  Funcdata *fd;
  if (addr.isConstant()) return (const Scope *)0;
  while((scope1 != (const Scope *)0)&&(scope1 != scope2)) {
    fd = scope1->findFunction(addr);
    if (fd != (Funcdata *)0) {
      *addrmatch = fd;
      return scope1;
    }
    if (scope1->inScope(addr,1,Address()))
      return scope1;		// Discovery of new variable
    scope1 = scope1->getParent();
  }
  return (const Scope *)0;
}

/// Query for an \e external \e reference Symbol starting at the given address
///
/// Searching starts at a first scope, continuing thru parents up to a second scope,
/// which is not queried.  If a Scope \e controls the memory in the given range, the Scope
/// object is returned. If an \e external \e reference is found at the address,
/// pass back the matching ExternRefSymbol
/// \param scope1 is the first Scope where searching starts
/// \param scope2 is the second Scope where searching ends
/// \param addr is the given address
/// \param addrmatch is used to pass-back any matching Symbol
/// \return the Scope owning the address or NULL if none found
const Scope *Scope::stackExternalRef(const Scope *scope1,
					       const Scope *scope2,
					       const Address &addr,
					       ExternRefSymbol **addrmatch)
{
  ExternRefSymbol *sym;
  if (addr.isConstant()) return (const Scope *)0;
  while((scope1 != (const Scope *)0)&&(scope1 != scope2)) {
    sym = scope1->findExternalRef(addr);
    if (sym != (ExternRefSymbol *)0) {
      *addrmatch = sym;
      return scope1;
    }
    // When searching for externalref, don't do discovery
    // As the function in a lower scope may be masking the
    // external reference symbol that refers to it
    //    if (scope1->inScope(addr,1,Address()))
    //      return scope1;		// Discovery of new variable
    scope1 = scope1->getParent();
  }
  return (const Scope *)0;
}

/// Query for a label Symbol for a given address.
///
/// Searching starts at a first scope, continuing thru parents up to a second scope,
/// which is not queried.  If a Scope \e controls the memory in the given range, the Scope
/// object is returned. If there is a label at that address, pass back the
/// corresponding LabSymbol object
/// \param scope1 is the first Scope where searching starts
/// \param scope2 is the second Scope where searching ends
/// \param addr is the given address
/// \param addrmatch is used to pass-back any matching Symbol
/// \return the Scope owning the address or NULL if none found
const Scope *Scope::stackCodeLabel(const Scope *scope1,
					     const Scope *scope2,
					     const Address &addr,
					     LabSymbol **addrmatch)
{
  LabSymbol *sym;
  if (addr.isConstant()) return (const Scope *)0;
  while((scope1 != (const Scope *)0)&&(scope1 != scope2)) {
    sym = scope1->findCodeLabel(addr);
    if (sym != (LabSymbol *)0) {
      *addrmatch = sym;
      return scope1;
    }
    if (scope1->inScope(addr,1,Address()))
      return scope1;		// Discovery of new variable
    scope1 = scope1->getParent();
  }
  return (const Scope *)0;
}

/// Attach \b this to the given function, which makes \b this the local scope for the function
/// \param f is the given function to attach to
void Scope::restrictScope(Funcdata *f)

{
  fd = f;
}

/// \param spc is the address space of the range
/// \param first is the offset of the first byte in the range
/// \param last is the offset of the last byte in the range
void Scope::addRange(AddrSpace *spc,uintb first,uintb last)

{
  rangetree.insertRange(spc,first,last);
}

/// \param spc is the address space of the range
/// \param first is the offset of the first byte in the range
/// \param last is the offset of the last byte in the range
void Scope::removeRange(AddrSpace *spc,uintb first,uintb last)

{
  rangetree.removeRange(spc,first,last);
}

/// The mapping is given as an unintegrated SymbolEntry object. Memory
/// may be specified in terms of join addresses, which this method must unravel.
/// The \b offset, \b size, and \b extraflags fields of the SymbolEntry are not used.
/// In particular, the SymbolEntry is assumed to map the entire Symbol.
/// \param entry is the given SymbolEntry
/// \return a SymbolEntry which has been fully integrated
SymbolEntry *Scope::addMap(SymbolEntry &entry)

{
  // First set properties of this symbol based on scope
  //  entry.symbol->flags |= Varnode::mapped;
  if (isGlobal())
    entry.symbol->flags |= Varnode::persist;
  else if (!entry.addr.isInvalid()) {
    // If this is not a global scope, but the address is in the global discovery range
    // we still mark the symbol as persistent
    Scope *glbScope = glb->symboltab->getGlobalScope();
    Address addr;
    if (glbScope->inScope(entry.addr, 1, addr)) {
      entry.symbol->flags |= Varnode::persist;
      entry.uselimit.clear();	// FIXME: Kludge for incorrectly generated XML
    }
  }

  SymbolEntry *res;
  int4 consumeSize = entry.symbol->getBytesConsumed();
  if (entry.addr.isInvalid())
    res = addDynamicMapInternal(entry.symbol,Varnode::mapped,entry.hash,0,consumeSize,entry.uselimit);
  else {
    if (entry.uselimit.empty()) {
      entry.symbol->flags |= Varnode::addrtied;
      // Global properties (like readonly and volatile)
      // can only happen if use is not limited
      entry.symbol->flags |= glb->symboltab->getProperty(entry.addr);
    }
    res = addMapInternal(entry.symbol,Varnode::mapped,entry.addr,0,consumeSize,entry.uselimit);
    if (entry.addr.isJoin()) {
      // The address is a join,  we add extra SymbolEntry maps for each of the pieces
      JoinRecord *rec = glb->findJoin(entry.addr.getOffset());
      uint4 exfl;
      int4 num = rec->numPieces();
      uintb off = 0;
      bool bigendian = entry.addr.isBigEndian();
      for(int4 j=0;j<num;++j) {
	int4 i = bigendian ? j : (num-1-j); // Take pieces in endian order
	const VarnodeData &vdat(rec->getPiece(i));
	if (i==0)		// i==0 is most signif
	  exfl = Varnode::precishi;
	else if (i==num-1)
	  exfl = Varnode::precislo;
	else
	  exfl = Varnode::precislo | Varnode::precishi; // Middle pieces have both flags set
	// NOTE: we do not turn on the mapped flag for the pieces
	addMapInternal(entry.symbol,exfl,vdat.getAddr(),off,vdat.size,entry.uselimit);
	off += vdat.size;
      }
      // Note: we fall thru here so that we return a SymbolEntry for the unified symbol
    }
  }
  return res;
}

Scope::~Scope(void)

{
  ScopeMap::iterator iter = children.begin();
  while(iter != children.end()) {
    delete (*iter).second;
    ++iter;
  }
}

/// Starting from \b this Scope, look for a Symbol with the given name.
/// If there are no Symbols in \b this Scope, recurse into the parent Scope.
/// If there are 1 (or more) Symbols matching in \b this Scope, add them to
/// the result list
/// \param nm is the name to search for
/// \param res is the result list
void Scope::queryByName(const string &nm,vector<Symbol *> &res) const

{
  findByName(nm,res);
  if (!res.empty())
    return;
  if (parent != (Scope *)0)
    parent->queryByName(nm,res);
}

/// Starting with \b this Scope, find a function with the given name.
/// If there are no Symbols with that name in \b this Scope at all, recurse into the parent Scope.
/// \param nm if the name to search for
/// \return the Funcdata object of the matching function, or NULL if it doesn't exist
Funcdata *Scope::queryFunction(const string &nm) const

{
  vector<Symbol *> symList;
  queryByName(nm,symList);
  for(int4 i=0;i<symList.size();++i) {
    Symbol *sym = symList[i];
    FunctionSymbol *funcsym = dynamic_cast<FunctionSymbol *>(sym);
    if (funcsym != (FunctionSymbol *)0)
      return funcsym->getFunction();
  }
  return (Funcdata *)0;
}

/// Within a sub-scope or containing Scope of \b this, find a Symbol
/// that is mapped to the given address, where the mapping is valid at a specific \b usepoint.
/// \param addr is the given address
/// \param usepoint is the point at which code accesses that address (may be \e invalid)
/// \return the matching SymbolEntry
SymbolEntry *Scope::queryByAddr(const Address &addr,
					const Address &usepoint) const
{
  SymbolEntry *res = (SymbolEntry *)0;
  const Scope *basescope = glb->symboltab->mapScope(this,addr,usepoint);
  stackAddr(basescope,(const Scope *)0,addr,usepoint,&res);
  return res;
}

/// Within a sub-scope or containing Scope of \b this, find the smallest Symbol
/// that contains a given memory range and can be accessed at a given \b usepoint.
/// \param addr is the given starting address of the memory range
/// \param size is the number of bytes in the range
/// \param usepoint is a point at which the Symbol is accessed (may be \e invalid)
/// \return the matching SymbolEntry or NULL
SymbolEntry *Scope::queryContainer(const Address &addr,int4 size,
					   const Address &usepoint) const
{
  SymbolEntry *res = (SymbolEntry *)0;
  const Scope *basescope = glb->symboltab->mapScope(this,addr,usepoint);
  stackContainer(basescope,(const Scope *)0,addr,size,usepoint,&res);
  return res;
}

/// Similarly to queryContainer(), this searches for the smallest containing Symbol,
/// but whether a known Symbol is found or not, boolean properties associated
/// with the memory range are also search for and passed back.
/// \param addr is the starting address of the range
/// \param size is the number of bytes in the range
/// \param usepoint is a point at which the memory range is accessed (may be \e invalid)
/// \param flags is a reference used to pass back the boolean properties of the memory range
/// \return the smallest SymbolEntry containing the range, or NULL
SymbolEntry *Scope::queryProperties(const Address &addr,int4 size,
				    const Address &usepoint,uint4 &flags) const
{
  SymbolEntry *res = (SymbolEntry *)0;
  const Scope *basescope = glb->symboltab->mapScope(this,addr,usepoint);
  const Scope *finalscope = stackContainer(basescope,(const Scope *)0,addr,size,usepoint,&res);
  if (res != (SymbolEntry *)0) // If we found a symbol
    flags = res->getAllFlags(); // use its flags
  else if (finalscope != (Scope *)0) { // If we found just a scope
    // set flags just based on scope
    flags = Varnode::mapped | Varnode::addrtied;
    if (finalscope->isGlobal())
      flags |= Varnode::persist;
    flags |= glb->symboltab->getProperty(addr);
  }
  else
    flags = glb->symboltab->getProperty(addr);
  return res;
}

/// Within a sub-scope or containing Scope of \b this, find a function starting
/// at the given address.
/// \param addr is the starting address of the function
/// \return the Funcdata object of the matching function, or NULL if it doesn't exist
Funcdata *Scope::queryFunction(const Address &addr) const

{
  Funcdata *res = (Funcdata *)0;
  // We have no usepoint, so try to map from addr
  const Scope *basescope = glb->symboltab->mapScope(this,addr,Address());
  stackFunction(basescope,(const Scope *)0,addr,&res);
  return res;
}

/// Within a sub-scope or containing Scope of \b this, find a label Symbol
/// at the given address.
/// \param addr is the given address
/// \return the LabSymbol object, or NULL if it doesn't exist
LabSymbol *Scope::queryCodeLabel(const Address &addr) const

{
  LabSymbol *res = (LabSymbol *)0;
  // We have no usepoint, so try to map from addr
  const Scope *basescope = glb->symboltab->mapScope(this,addr,Address());
  stackCodeLabel(basescope,(const Scope *)0,addr,&res);
  return res;
}

/// Look for the immediate child of \b this with a given name
/// \param nm is the child's name
/// \param strategy is \b true if hash of the name determines id
/// \return the child Scope or NULL if there is no child with that name
Scope *Scope::resolveScope(const string &nm,bool strategy) const

{
  if (strategy) {
    uint8 key = hashScopeName(uniqueId, nm);
    ScopeMap::const_iterator iter = children.find(key);
    if (iter == children.end()) return (Scope *)0;
    Scope *scope = (*iter).second;
    if (scope->name == nm)
      return scope;
  }
  else if (nm.length() > 0 && nm[0] <= '9' && nm[0] >= '0') {
    // Allow the string to directly specify the id
    istringstream s(nm);
    s.unsetf(ios::dec | ios::hex | ios::oct);
    uint8 key;
    s >> key;
    ScopeMap::const_iterator iter = children.find(key);
    if (iter == children.end()) return (Scope *)0;
    return (*iter).second;
  }
  else {
    ScopeMap::const_iterator iter;
    for(iter=children.begin();iter!=children.end();++iter) {
      Scope *scope = (*iter).second;
      if (scope->name == nm)
	return scope;
    }
  }
  return (Scope *)0;
}

/// Discover a sub-scope or containing Scope of \b this, that \e owns the given
/// memory range at a specific \b usepoint. Note that ownership does not necessarily
/// mean there is a known symbol there.
/// \param addr is the starting address of the memory range
/// \param sz is the number of bytes in the range
/// \param usepoint is a point at which the memory is getting accesses
Scope *Scope::discoverScope(const Address &addr,int4 sz,const Address &usepoint)

{				// Which scope "should" this range belong to
  if (addr.isConstant())
    return (Scope *)0;
  Scope *basescope = glb->symboltab->mapScope(this,addr,usepoint);
  while(basescope != (Scope *)0) {
    if (basescope->inScope(addr,sz,usepoint))
      return basescope;
    basescope = basescope->getParent();
  }
  return (Scope *)0;
}

/// This Scope and all of its sub-scopes are encoded as a sequence of \<scope> elements
/// in post order.  For each Scope, the encode() method is invoked.
/// \param encoder is the stream encoder
/// \param onlyGlobal is \b true if only non-local Scopes should be saved
void Scope::encodeRecursive(Encoder &encoder,bool onlyGlobal) const

{
  if (onlyGlobal && (!isGlobal())) return;		// Only save global scopes
  encode(encoder);
  ScopeMap::const_iterator iter = children.begin();
  ScopeMap::const_iterator enditer = children.end();
  for(;iter!=enditer;++iter) {
    (*iter).second->encodeRecursive(encoder,onlyGlobal);
  }
}

/// Change (override) the data-type of a \e sizelocked Symbol, while preserving the lock.
/// An exception is thrown if the new data-type doesn't fit the size.
/// \param sym is the locked Symbol
/// \param ct is the data-type to change the Symbol to
void Scope::overrideSizeLockType(Symbol *sym,Datatype *ct)

{
  if (sym->type->getSize() == ct->getSize()) {
    if (!sym->isSizeTypeLocked())
      throw LowlevelError("Overriding symbol that is not size locked");
    sym->type = ct;
    return;
  }
  throw LowlevelError("Overriding symbol with different type size");
}

/// Replace any overriding data-type type with the locked UNKNOWN type
/// of the correct size. The data-type is \e cleared, but the lock is preserved.
/// \param sym is the Symbol to clear
void Scope::resetSizeLockType(Symbol *sym)

{
  if (sym->type->getMetatype() == TYPE_UNKNOWN) return;	// Nothing to do
  int4 size = sym->type->getSize();
  sym->type = glb->types->getBase(size,TYPE_UNKNOWN);
}

/// Given an address, search for an \e external \e reference. If no Symbol is
/// found and \b this Scope does not own the address, recurse searching in the parent Scope.
/// If an \e external \e reference is found, try to resolve the function it refers to
/// and return it.
/// \param addr is the given address where an \e external \e reference might be
/// \return the referred to Funcdata object or NULL if not found
Funcdata *Scope::queryExternalRefFunction(const Address &addr) const

{
  ExternRefSymbol *sym = (ExternRefSymbol *)0;
  // We have no usepoint, so try to map from addr
  const Scope *basescope = glb->symboltab->mapScope(this,addr,Address());
  basescope = stackExternalRef(basescope,(const Scope *)0,addr,&sym);
  // Resolve the reference from the same scope we found the reference
  if (sym != (ExternRefSymbol *)0)
    return basescope->resolveExternalRefFunction(sym);
  return (Funcdata *)0;
}

/// Does the given Scope contain \b this as a sub-scope.
/// \param scp is the given Scope
/// \return \b true if \b this is a sub-scope
bool Scope::isSubScope(const Scope *scp) const

{
  const Scope *tmp = this;
  do {
    if (tmp == scp) return true;
    tmp = tmp->parent;
  } while(tmp != (const Scope *)0);
  return false;
}

string Scope::getFullName(void) const

{
  if (parent == (Scope *)0) return "";
  string fname = name;
  Scope *scope = parent;
  while(scope->parent != (Scope *)0) {
    fname = scope->name + "::" + fname;
    scope = scope->parent;
  }
  return fname;
}

/// Put the parent scopes of \b this into an array in order, starting with the global scope.
/// \param vec is storage for the array of scopes
void Scope::getScopePath(vector<const Scope *> &vec) const

{
  int4 count = 0;
  const Scope *cur = this;
  while(cur != (const Scope *)0) {	// Count number of elements in path
    count += 1;
    cur = cur->parent;
  }
  vec.resize(count);
  cur = this;
  while(cur != (const Scope *)0) {
    count -= 1;
    vec[count] = cur;
    cur = cur->parent;
  }
}

/// Any two scopes share at least the \e global scope as a common ancestor. We find the first scope
/// that is \e not in common.  The scope returned will always be an ancestor of \b this.
/// If \b this is an ancestor of the other given scope, then null is returned.
/// \param op2 is the other given Scope
/// \return the first ancestor Scope that is not in common or null
const Scope *Scope::findDistinguishingScope(const Scope *op2) const

{
  if (this == op2) return (const Scope *)0;	// Quickly check most common cases
  if (parent == op2) return this;
  if (op2->parent == this) return (const Scope *)0;
  if (parent == op2->parent) return this;
  vector<const Scope *> thisPath;
  vector<const Scope *> op2Path;
  getScopePath(thisPath);
  op2->getScopePath(op2Path);
  int4 min = thisPath.size();
  if (op2Path.size() < min)
    min = op2Path.size();
  for(int4 i=0;i<min;++i) {
    if (thisPath[i] != op2Path[i])
      return thisPath[i];
  }
  if (min < thisPath.size())
    return thisPath[min];	// thisPath matches op2Path but is longer
  if (min < op2Path.size())
    return (const Scope *)0;	// op2Path matches thisPath but is longer
  return this;			// ancestor paths are identical (only base scopes differ)
}

/// The Symbol is created and added to any name map, but no SymbolEntry objects are created for it.
/// \param nm is the name of the new Symbol
/// \param ct is a data-type to assign to the new Symbol
/// \return the new Symbol object
Symbol *Scope::addSymbol(const string &nm,Datatype *ct)

{
  Symbol *sym;

  sym = new Symbol(owner,nm,ct);
  addSymbolInternal(sym);		// Let this scope lay claim to the new object
  return sym;
}

/// \brief Add a new Symbol to \b this Scope, given a name, data-type, and a single mapping
///
/// The Symbol object will be created with the given name and data-type.  A single mapping (SymbolEntry)
/// will be created for the Symbol based on a given storage address for the symbol
/// and an address for code that accesses the Symbol at that storage location.
/// \param nm is the new name of the Symbol
/// \param ct is the data-type of the new Symbol
/// \param addr is the starting address of the Symbol storage
/// \param usepoint is the point accessing that storage (may be \e invalid)
/// \return the SymbolEntry matching the new mapping
SymbolEntry *Scope::addSymbol(const string &nm,Datatype *ct,
			      const Address &addr,
			      const Address &usepoint)
{
  Symbol *sym;

  if (ct->hasStripped())
    ct = ct->getStripped();
  sym = new Symbol(owner,nm,ct);
  addSymbolInternal(sym);
  return addMapPoint(sym,addr,usepoint);
}

/// Create a new SymbolEntry that maps the whole Symbol to the given address
/// \param sym is the Symbol
/// \param addr is the given address to map to
/// \param usepoint is a point at which the Symbol is accessed at that address
/// \return the SymbolEntry representing the new mapping
SymbolEntry *Scope::addMapPoint(Symbol *sym,
				const Address &addr,
				const Address &usepoint)
{
  SymbolEntry entry(sym);
  if (!usepoint.isInvalid())	// Restrict maps use if necessary
    entry.uselimit.insertRange(usepoint.getSpace(),usepoint.getOffset(),usepoint.getOffset());
  entry.addr = addr;
  return addMap(entry);
}

/// A Symbol element is parsed first, followed by sequences of \<addr> elements or
/// \<hash> and \<rangelist> elements which define 1 or more mappings of the Symbol.
/// The new Symbol and SymbolEntry mappings are integrated into \b this Scope.
/// \param decoder is the stream decoder
/// \return the new Symbol
Symbol *Scope::addMapSym(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_MAPSYM);
  uint4 subId = decoder.peekElement();
  Symbol *sym;
  if (subId == ELEM_SYMBOL)
    sym = new Symbol(owner);
  else if (subId == ELEM_EQUATESYMBOL)
    sym = new EquateSymbol(owner);
  else if (subId == ELEM_FUNCTION)
    sym = new FunctionSymbol(owner,glb->min_funcsymbol_size);
  else if (subId == ELEM_FUNCTIONSHELL)
    sym = new FunctionSymbol(owner,glb->min_funcsymbol_size);
  else if (subId == ELEM_LABELSYM)
    sym = new LabSymbol(owner);
  else if (subId == ELEM_EXTERNREFSYMBOL)
    sym = new ExternRefSymbol(owner);
  else if (subId == ELEM_FACETSYMBOL)
    sym = new UnionFacetSymbol(owner);
  else
    throw LowlevelError("Unknown symbol type");
  try {		// Protect against duplicate scope errors
    sym->decode(decoder);
  } catch(RecovError &err) {
    delete sym;
    throw;
  }
  addSymbolInternal(sym);	// This routine may throw, but it will delete sym in this case
  while(decoder.peekElement() != 0) {
    SymbolEntry entry(sym);
    entry.decode(decoder);
    if (entry.isInvalid()) {
      glb->printMessage("WARNING: Throwing out symbol with invalid mapping: "+sym->getName());
      removeSymbol(sym);
      decoder.closeElement(elemId);
      return (Symbol *)0;
    }
    addMap(entry);
  }
  decoder.closeElement(elemId);
  return sym;
}

/// \brief Create a function Symbol at the given address in \b this Scope
///
/// The FunctionSymbol is created and mapped to the given address.
/// A Funcdata object is only created once FunctionSymbol::getFunction() is called.
/// \param addr is the entry address of the function
/// \param nm is the name of the function, within \b this Scope
/// \return the new FunctionSymbol object
FunctionSymbol *Scope::addFunction(const Address &addr,const string &nm)

{
  FunctionSymbol *sym;

  SymbolEntry *overlap = queryContainer(addr,1,Address());
  if (overlap != (SymbolEntry *)0) {
    string errmsg = "WARNING: Function "+name;
    errmsg += " overlaps object: "+overlap->getSymbol()->getName();
    glb->printMessage(errmsg);
  }
  sym = new FunctionSymbol(owner,nm,glb->min_funcsymbol_size);
  addSymbolInternal(sym);
  // Map symbol to base address of function
  // there is no limit on the applicability of this map within scope
  addMapPoint(sym,addr,Address());
  return sym;
}

/// Create an \e external \e reference at the given address in \b this Scope
///
/// An ExternRefSymbol is created and mapped to the given address and stores a reference
/// address to the actual function.
/// \param addr is the given address to map the Symbol to
/// \param refaddr is the reference address
/// \param nm is the name of the symbol/function
/// \return the new ExternRefSymbol
ExternRefSymbol *Scope::addExternalRef(const Address &addr,const Address &refaddr,const string &nm)

{
  ExternRefSymbol *sym;

  sym = new ExternRefSymbol(owner,refaddr,nm);
  addSymbolInternal(sym);
  // Map symbol to given address
  // there is no limit on applicability of this map within scope
  SymbolEntry *ret = addMapPoint(sym,addr,Address());
  // Even if the external reference is in a readonly region, treat it as not readonly
  // As the value in the image probably isn't valid
  ret->symbol->flags &= ~((uint4)Varnode::readonly);
  return sym;
}

/// \brief Create a code label at the given address in \b this Scope
///
/// A LabSymbol is created and mapped to the given address.
/// \param addr is the given address to map to
/// \param nm is the name of the symbol/label
/// \return the new LabSymbol
LabSymbol *Scope::addCodeLabel(const Address &addr,const string &nm)

{
  LabSymbol *sym;

  SymbolEntry *overlap = queryContainer(addr,1,addr);
  if (overlap != (SymbolEntry *)0) {
    string errmsg = "WARNING: Codelabel "+nm;
    errmsg += " overlaps object: "+overlap->getSymbol()->getName();
    glb->printMessage(errmsg);
  }
  sym = new LabSymbol(owner,nm);
  addSymbolInternal(sym);
  addMapPoint(sym,addr,Address());
  return sym;
}

/// \brief Create a dynamically mapped Symbol attached to a specific data-flow
///
/// The Symbol is created and mapped to a dynamic \e hash and a code address where
/// the Symbol is being used.
/// \param nm is the name of the Symbol
/// \param ct is the data-type of the Symbol
/// \param caddr is the code address where the Symbol is being used
/// \param hash is the dynamic hash
/// \return the new Symbol
Symbol *Scope::addDynamicSymbol(const string &nm,Datatype *ct,const Address &caddr,uint8 hash)

{
  Symbol *sym;

  sym = new Symbol(owner,nm,ct);
  addSymbolInternal(sym);
  RangeList rnglist;
  if (!caddr.isInvalid())
    rnglist.insertRange(caddr.getSpace(),caddr.getOffset(),caddr.getOffset());
  addDynamicMapInternal(sym,Varnode::mapped,hash,0,ct->getSize(),rnglist);
  return sym;
}

/// \brief Create a symbol that forces display conversion on a constant
///
/// \param nm is the equate name to display, which may be empty for an integer conversion
/// \param format is the type of integer conversion (Symbol::force_hex, Symbol::force_dec, etc.)
/// \param value is the constant value being converted
/// \param addr is the address of the p-code op reading the constant
/// \param hash is the dynamic hash identifying the constant
/// \return the new EquateSymbol
Symbol *Scope::addEquateSymbol(const string &nm,uint4 format,uintb value,const Address &addr,uint8 hash)

{
  Symbol *sym;

  sym = new EquateSymbol(owner,nm,format,value);
  addSymbolInternal(sym);
  RangeList rnglist;
  if (!addr.isInvalid())
    rnglist.insertRange(addr.getSpace(),addr.getOffset(),addr.getOffset());
  addDynamicMapInternal(sym,Varnode::mapped,hash,0,1,rnglist);
  return sym;
}

/// \brief Create a symbol forcing a field interpretation for a specific access to a variable with \e union data-type
///
/// The symbol is attached to a specific Varnode and a PcodeOp that reads or writes to it.  The Varnode,
/// in the context of the PcodeOp, is forced to have the data-type of the selected field, and field's name is used
/// to represent the Varnode in output.
/// \param nm is the name of the symbol
/// \param dt is the union data-type containing the field to force
/// \param fieldNum is the index of the desired field, or -1 if the whole union should be forced
/// \param addr is the address of the p-code op reading/writing the Varnode
/// \param hash is the dynamic hash identifying the Varnode
/// \return the new UnionFacetSymbol
Symbol *Scope::addUnionFacetSymbol(const string &nm,Datatype *dt,int4 fieldNum,const Address &addr,uint8 hash)

{
  Symbol *sym = new UnionFacetSymbol(owner,nm,dt,fieldNum);
  addSymbolInternal(sym);
  RangeList rnglist;
  if (!addr.isInvalid())
    rnglist.insertRange(addr.getSpace(),addr.getOffset(),addr.getOffset());
  addDynamicMapInternal(sym,Varnode::mapped,hash,0,1,rnglist);
  return sym;
}

/// Create default name given information in the Symbol and possibly a representative Varnode.
/// This method extracts the crucial properties and then uses the buildVariableName method to
/// construct the actual name.
/// \param sym is the given Symbol to name
/// \param base is an index (which may get updated) used to uniquify the name
/// \param vn is an optional (may be null) Varnode representative of the Symbol
/// \return the default name
string Scope::buildDefaultName(Symbol *sym,int4 &base,Varnode *vn) const

{
  if (vn != (Varnode *)0 && !vn->isConstant()) {
    Address usepoint;
    if (!vn->isAddrTied() && fd != (Funcdata *)0)
      usepoint = vn->getUsePoint(*fd);
    HighVariable *high = vn->getHigh();
    if (sym->getCategory() == Symbol::function_parameter || high->isInput()) {
      int4 index = -1;
      if (sym->getCategory()==Symbol::function_parameter)
	index = sym->getCategoryIndex()+1;
      return buildVariableName(vn->getAddr(),usepoint,sym->getType(),index,vn->getFlags() | Varnode::input);
    }
    return buildVariableName(vn->getAddr(),usepoint,sym->getType(),base,vn->getFlags());
  }
  if (sym->numEntries() != 0) {
    SymbolEntry *entry = sym->getMapEntry(0);
    Address addr = entry->getAddr();
    Address usepoint = entry->getFirstUseAddress();
    uint4 flags = usepoint.isInvalid() ? Varnode::addrtied : 0;
    if (sym->getCategory() == Symbol::function_parameter) {
	flags |= Varnode::input;
	int4 index = sym->getCategoryIndex() + 1;
	return buildVariableName(addr, usepoint, sym->getType(), index, flags);
    }
    return buildVariableName(addr, usepoint, sym->getType(), base, flags);
  }
  // Should never reach here
  return buildVariableName(Address(), Address(), sym->getType(), base, 0);
}

/// \brief Is the given memory range marked as \e read-only
///
/// Check for Symbols relative to \b this Scope that are marked as \e read-only,
/// and look-up properties of the memory in general.
/// \param addr is the starting address of the given memory range
/// \param size is the number of bytes in the range
/// \param usepoint is a point where the range is getting accessed
/// \return \b true if the memory is marked as \e read-only
bool Scope::isReadOnly(const Address &addr,int4 size,const Address &usepoint) const

{
  uint4 flags;
  queryProperties(addr,size,usepoint,flags);
  return ((flags & Varnode::readonly)!=0);
}

Scope *ScopeInternal::buildSubScope(uint8 id,const string &nm)

{
  return new ScopeInternal(id,nm,glb);
}

void ScopeInternal::addSymbolInternal(Symbol *sym)

{
  if (sym->symbolId == 0) {
    sym->symbolId = Symbol::ID_BASE + ((uniqueId & 0xffff) << 40) + nextUniqueId;
    nextUniqueId += 1;
  }
  try {
    if (sym->name.size() == 0) {
      sym->name = buildUndefinedName();
      sym->displayName = sym->name;
    }
    if (sym->getType() == (Datatype *)0)
      throw LowlevelError(sym->getName() + " symbol created with no type");
    if (sym->getType()->getSize() < 1)
      throw LowlevelError(sym->getName() + " symbol created with zero size type");
    insertNameTree(sym);
    if (sym->category >= 0) {
      while(category.size() <= sym->category)
	category.push_back(vector<Symbol *>());
      vector<Symbol *> &list(category[sym->category]);
      if (sym->category > 0)
	sym->catindex = list.size();
      while(list.size() <= sym->catindex)
	list.push_back((Symbol *)0);
      list[sym->catindex] = sym;
    }
  } catch(LowlevelError &err) {
    delete sym;			// Symbol must be deleted to avoid orphaning its memory
    throw err;
  }
}

SymbolEntry *ScopeInternal::addMapInternal(Symbol *sym,uint4 exfl,const Address &addr,int4 off,int4 sz,
					   const RangeList &uselim)
{
  // Find or create the appropriate rangemap
  AddrSpace *spc = addr.getSpace();
  EntryMap *rangemap = maptable[spc->getIndex()];
  if (rangemap == (EntryMap *)0) {
    rangemap = new EntryMap();
    maptable[spc->getIndex()] = rangemap;
  }
  // Insert the new map
  SymbolEntry::inittype initdata(sym,exfl,addr.getSpace(),off,uselim);
  Address lastaddress = addr + (sz-1);
  if (lastaddress.getOffset() < addr.getOffset()) {
    string msg = "Symbol ";
    msg += sym->getName();
    msg += " extends beyond the end of the address space";
    throw LowlevelError(msg);
  }
    
  list<SymbolEntry>::iterator iter = rangemap->insert(initdata,addr.getOffset(),lastaddress.getOffset());
  // Store reference to map in symbol
  sym->mapentry.push_back(iter);
  if (sz == sym->type->getSize()) {
    sym->wholeCount += 1;
    if (sym->wholeCount == 2)
      multiEntrySet.insert(sym);
  }
  return &(*iter);
}

SymbolEntry *ScopeInternal::addDynamicMapInternal(Symbol *sym,uint4 exfl,uint8 hash,int4 off,int4 sz,
						  const RangeList &uselim)
{
  dynamicentry.push_back(SymbolEntry(sym,exfl,hash,off,sz,uselim));
  list<SymbolEntry>::iterator iter = dynamicentry.end();
  --iter;
  sym->mapentry.push_back(iter); // Store reference to map entry in symbol
  if (sz == sym->type->getSize()) {
    sym->wholeCount += 1;
    if (sym->wholeCount == 2)
      multiEntrySet.insert(sym);
  }
  return &dynamicentry.back();
}

MapIterator ScopeInternal::begin(void) const

{
  // The symbols are ordered via their mapping address
  vector<EntryMap *>::const_iterator iter;
  iter = maptable.begin();
  while((iter!=maptable.end())&&((*iter)==(EntryMap *)0))
    ++iter;
  list<SymbolEntry>::const_iterator curiter;
  if (iter!=maptable.end()) {
    curiter = (*iter)->begin_list();
    if (curiter == (*iter)->end_list()) {
      while((iter!=maptable.end())&&(curiter==(*iter)->end_list())) {
	do {
	  ++iter;
	} while((iter!=maptable.end())&&((*iter)==(EntryMap *)0));
	if (iter!=maptable.end())
	  curiter = (*iter)->begin_list();
      }
      
    }
  }
  return MapIterator(&maptable,iter,curiter);
}

MapIterator ScopeInternal::end(void) const

{
  list<SymbolEntry>::const_iterator curiter;
  return MapIterator(&maptable,maptable.end(),curiter);
}

list<SymbolEntry>::const_iterator ScopeInternal::beginDynamic(void) const

{
  return dynamicentry.begin();
}

list<SymbolEntry>::const_iterator ScopeInternal::endDynamic(void) const

{
  return dynamicentry.end();
}

list<SymbolEntry>::iterator ScopeInternal::beginDynamic(void)

{
  return dynamicentry.begin();
}

list<SymbolEntry>::iterator ScopeInternal::endDynamic(void)

{
  return dynamicentry.end();
}

/// \param id is the globally unique id associated with the scope
/// \param nm is the name of the Scope
/// \param g is the Architecture it belongs to
ScopeInternal::ScopeInternal(uint8 id,const string &nm,Architecture *g)
  : Scope(id,nm,g,this)
{
  nextUniqueId = 0;
  maptable.resize(g->numSpaces(),(EntryMap *)0);
}

ScopeInternal::ScopeInternal(uint8 id,const string &nm,Architecture *g, Scope *own)
  : Scope(id,nm,g,own)
{
  nextUniqueId = 0;
  maptable.resize(g->numSpaces(),(EntryMap *)0);
}

ScopeInternal::~ScopeInternal(void)

{
  vector<EntryMap *>::iterator iter1;

  for(iter1=maptable.begin();iter1!=maptable.end();++iter1)
    if ((*iter1) != (EntryMap *)0)
      delete *iter1;

  SymbolNameTree::iterator iter2;

  for(iter2=nametree.begin();iter2!=nametree.end();++iter2)
    delete *iter2;
}

void ScopeInternal::clear(void)

{
  SymbolNameTree::iterator iter;

  iter = nametree.begin();
  while(iter!=nametree.end()) {
    Symbol *sym = *iter++;
    removeSymbol(sym);
  }
  nextUniqueId = 0;
}

/// Look for NULL entries in the category tables. If there are,
/// clear out the entire category, marking all symbols as uncategorized
void ScopeInternal::categorySanity(void)

{
  for(int4 i=0;i<category.size();++i) {
    int4 num = category[i].size();
    if (num == 0) continue;
    bool nullsymbol = false;
    for(int4 j=0;j<num;++j) {
      Symbol *sym = category[i][j];
      if (sym == (Symbol *)0) {
	nullsymbol = true;	// There can be no null symbols
	break;
      }
    }
    if (nullsymbol) {		// Clear entire category
      vector<Symbol *> list;
      for(int4 j=0;j<num;++j)
	list.push_back(category[i][j]);
      for(int4 j=0;j<list.size();++j) {
	Symbol *sym = list[j];
	if (sym == (Symbol *)0) continue;
	setCategory(sym,Symbol::no_category,0);
      }
    }
  }

}

void ScopeInternal::clearCategory(int4 cat)

{
  if (cat >= 0) {
    if (cat >= category.size()) return;	// Category doesn't exist
    int4 sz = category[cat].size();
    for(int4 i=0;i<sz;++i) {
      Symbol *sym = category[cat][i];
      removeSymbol(sym);
    }
  }
  else {
    SymbolNameTree::iterator iter;
    iter = nametree.begin();
    while(iter!=nametree.end()) {
      Symbol *sym = *iter++;
      if (sym->getCategory() >= 0) continue;
      removeSymbol(sym);
    }
  }
}

void ScopeInternal::clearUnlocked(void)

{
  SymbolNameTree::iterator iter;

  iter = nametree.begin();
  while(iter!=nametree.end()) {
    Symbol *sym = *iter++;
    if (sym->isTypeLocked()) {	// Only hold if TYPE locked
      if (!sym->isNameLocked()) { // Clear an unlocked name
	if (!sym->isNameUndefined()) {
	  renameSymbol(sym,buildUndefinedName());
	}
      }
      clearAttribute(sym, Varnode::nolocalalias);	// Clear any calculated attributes
      if (sym->isSizeTypeLocked())
	resetSizeLockType(sym);
    }
    else if (sym->getCategory() == Symbol::equate) {
      // Note we treat EquateSymbols as locked for purposes of this method
      // as a typelock (which traditionally prevents a symbol from being cleared)
      // does not make sense for an equate
      continue;
    }
    else
      removeSymbol(sym);
  }
}

void ScopeInternal::clearUnlockedCategory(int4 cat)

{
  if (cat >= 0) {
    if (cat >= category.size()) return;	// Category doesn't exist
    int4 sz = category[cat].size();
    for(int4 i=0;i<sz;++i) {
      Symbol *sym = category[cat][i];
      if (sym->isTypeLocked()) { // Only hold if TYPE locked
	if (!sym->isNameLocked()) { // Clear an unlocked name
	  if (!sym->isNameUndefined()) {
	    renameSymbol(sym,buildUndefinedName());
	  }
	}
	if (sym->isSizeTypeLocked())
	  resetSizeLockType(sym);
      }
      else
	removeSymbol(sym);
    }
  }
  else {
    SymbolNameTree::iterator iter;
    iter = nametree.begin();
    while(iter!=nametree.end()) {
      Symbol *sym = *iter++;
      if (sym->getCategory() >= 0) continue;
      if (sym->isTypeLocked()) {
	if (!sym->isNameLocked()) { // Clear an unlocked name
	  if (!sym->isNameUndefined()) {
	    renameSymbol(sym,buildUndefinedName());
	  }
	}
      }
      else
	removeSymbol(sym);
    }
  }
}

void ScopeInternal::adjustCaches(void)

{
  maptable.resize(glb->numSpaces(),(EntryMap *)0);
}

void ScopeInternal::removeSymbolMappings(Symbol *symbol)

{
  vector<list<SymbolEntry>::iterator>::iterator iter;

  if (symbol->wholeCount > 1)
    multiEntrySet.erase(symbol);
  // Remove each mapping of the symbol
  for(iter=symbol->mapentry.begin();iter!=symbol->mapentry.end();++iter) {
    AddrSpace *spc = (*(*iter)).getAddr().getSpace();
    if (spc == (AddrSpace *)0) // A null address indicates a dynamic mapping
      dynamicentry.erase( *iter );
    else {
      EntryMap *rangemap = maptable[spc->getIndex()];
      rangemap->erase( *iter );
    }
  }
  symbol->wholeCount = 0;
  symbol->mapentry.clear();
}

void ScopeInternal::removeSymbol(Symbol *symbol)

{
  if (symbol->category >= 0) {
    vector<Symbol *> &list(category[symbol->category]);
    list[symbol->catindex] = (Symbol *)0;
    while((!list.empty())&&(list.back() == (Symbol *)0))
      list.pop_back();
  }
  removeSymbolMappings(symbol);
  nametree.erase(symbol);
  delete symbol;
}

void ScopeInternal::renameSymbol(Symbol *sym,const string &newname)

{
  nametree.erase(sym);		// Erase under old name
  if (sym->wholeCount > 1)
    multiEntrySet.erase(sym);	// The multi-entry set is sorted by name, remove
  string oldname = sym->name;
  sym->name = newname;
  sym->displayName = newname;
  insertNameTree(sym);
  if (sym->wholeCount > 1)
    multiEntrySet.insert(sym);	// Reenter into the multi-entry set now that name is changed
}

void ScopeInternal::retypeSymbol(Symbol *sym,Datatype *ct)

{
  if (ct->hasStripped())
    ct = ct->getStripped();
  if ((sym->type->getSize() == ct->getSize())||(sym->mapentry.empty())) { 
// If size is the same, or no mappings nothing special to do
    sym->type = ct;
    sym->checkSizeTypeLock();
    return;
  }
  else if (sym->mapentry.size()==1) {
    list<SymbolEntry>::iterator iter = sym->mapentry.back();
    if ((*iter).isAddrTied()) {
      // Save the starting address of map
      Address addr((*iter).getAddr());
      
      // Find the correct rangemap
      EntryMap *rangemap = maptable[ (*iter).getAddr().getSpace()->getIndex() ];
      // Remove the map entry
      rangemap->erase(iter);
      sym->mapentry.pop_back();	// Remove reference to map entry
      sym->wholeCount = 0;

      // Now we are ready to change the type
      sym->type = ct;
      sym->checkSizeTypeLock();
      addMapPoint(sym,addr,Address()); // Re-add map with new size
      return;
    }
  }
  throw RecovError("Unable to retype symbol: "+sym->name);
}

void ScopeInternal::setAttribute(Symbol *sym,uint4 attr)

{
  attr &= (Varnode::typelock | Varnode::namelock | Varnode::readonly | Varnode::incidental_copy |
	   Varnode::nolocalalias | Varnode::volatil | Varnode::indirectstorage | Varnode::hiddenretparm);
  sym->flags |= attr;
  sym->checkSizeTypeLock();
}

void ScopeInternal::clearAttribute(Symbol *sym,uint4 attr)

{
  attr &= (Varnode::typelock | Varnode::namelock | Varnode::readonly | Varnode::incidental_copy |
	   Varnode::nolocalalias | Varnode::volatil | Varnode::indirectstorage | Varnode::hiddenretparm);
  sym->flags &= ~attr;
  sym->checkSizeTypeLock();
}

void ScopeInternal::setDisplayFormat(Symbol *sym,uint4 attr)

{
  sym->setDisplayFormat(attr);
}

SymbolEntry *ScopeInternal::findAddr(const Address &addr,const Address &usepoint) const

{
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    pair<EntryMap::const_iterator,EntryMap::const_iterator> res;
    if (usepoint.isInvalid())
      res = rangemap->find(addr.getOffset(),
			   EntryMap::subsorttype(false),
			   EntryMap::subsorttype(true));
    else
      res = rangemap->find(addr.getOffset(),
			   EntryMap::subsorttype(false),
			   EntryMap::subsorttype(usepoint));
    while(res.first != res.second) {
      --res.second;
      SymbolEntry *entry = &(*res.second);
      if (entry->getAddr().getOffset() == addr.getOffset()) {
	if (entry->inUse(usepoint))
	  return entry;
      }
    }
  }
  return (SymbolEntry *)0;
}

SymbolEntry *ScopeInternal::findContainer(const Address &addr,int4 size,
						   const Address &usepoint) const
{
  SymbolEntry *bestentry = (SymbolEntry *)0;
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    pair<EntryMap::const_iterator,EntryMap::const_iterator> res;
    if (usepoint.isInvalid())
      res = rangemap->find(addr.getOffset(),
			   EntryMap::subsorttype(false),
			   EntryMap::subsorttype(true));
    else
      res = rangemap->find(addr.getOffset(),
			   EntryMap::subsorttype(false),
			   EntryMap::subsorttype(usepoint));
    int4 oldsize = -1;
    uintb end = addr.getOffset() + size -1;
    while(res.first != res.second) {
      --res.second;
      SymbolEntry *entry = &(*res.second);
      if (entry->getLast() >= end) { // We contain the range
	if ((entry->getSize()<oldsize)||(oldsize==-1)) {
	  if (entry->inUse(usepoint)) {
	    bestentry = entry;
	    if (entry->getSize() == size) break;
	    oldsize = entry->getSize();
	  }
	}
      }
    }
  }
  return bestentry;
}

SymbolEntry *ScopeInternal::findClosestFit(const Address &addr,int4 size,
					   const Address &usepoint) const
{
  SymbolEntry *bestentry = (SymbolEntry *)0;
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    pair<EntryMap::const_iterator,EntryMap::const_iterator> res;
    if (usepoint.isInvalid())
      res = rangemap->find(addr.getOffset(),
			   EntryMap::subsorttype(false),
			   EntryMap::subsorttype(true));
    else
      res = rangemap->find(addr.getOffset(),
			   EntryMap::subsorttype(false),
			   EntryMap::subsorttype(usepoint));
    int4 olddiff = -10000;
    int4 newdiff;

    while(res.first != res.second) {
      --res.second;
      SymbolEntry *entry = &(*res.second);
      if (entry->getLast() >= addr.getOffset()) { // We contain start
	newdiff = entry->getSize() - size;
	if (((olddiff<0)&&(newdiff>olddiff))||
	    ((olddiff>=0)&&(newdiff>=0)&&(newdiff<olddiff))) {
	  if (entry->inUse(usepoint)) {
	    bestentry = entry;
	    if (newdiff == 0) break;
	    olddiff = newdiff;
	  }
	}
      }
    }
  }
  return bestentry;
}

Funcdata *ScopeInternal::findFunction(const Address &addr) const

{
  FunctionSymbol *sym;
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    pair<EntryMap::const_iterator,EntryMap::const_iterator> res;
    res = rangemap->find(addr.getOffset());
    while(res.first != res.second) {
      SymbolEntry *entry = &(*res.first);
      if (entry->getAddr().getOffset() == addr.getOffset()) {
	sym = dynamic_cast<FunctionSymbol *>(entry->getSymbol());
	if (sym != (FunctionSymbol *)0)
	  return sym->getFunction();
      }
      ++res.first;
    }
  }
  return (Funcdata *)0;
}

ExternRefSymbol *ScopeInternal::findExternalRef(const Address &addr) const

{
  ExternRefSymbol *sym = (ExternRefSymbol *)0;
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    pair<EntryMap::const_iterator,EntryMap::const_iterator> res;
    res = rangemap->find(addr.getOffset());
    while(res.first != res.second) {
      SymbolEntry *entry = &(*res.first);
      if (entry->getAddr().getOffset() == addr.getOffset()) {
	sym = dynamic_cast<ExternRefSymbol *>(entry->getSymbol());
	break;
      }
      ++res.first;
    }
  }
  return sym;
}

Funcdata *ScopeInternal::resolveExternalRefFunction(ExternRefSymbol *sym) const

{
  return queryFunction(sym->getRefAddr());
}

LabSymbol *ScopeInternal::findCodeLabel(const Address &addr) const

{
  LabSymbol *sym = (LabSymbol *)0;
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    pair<EntryMap::const_iterator,EntryMap::const_iterator> res;
    res = rangemap->find(addr.getOffset(),
			 EntryMap::subsorttype(false),
			 EntryMap::subsorttype(addr));
    while(res.first != res.second) {
      --res.second;
      SymbolEntry *entry = &(*res.second);
      if (entry->getAddr().getOffset() == addr.getOffset()) {
	if (entry->inUse(addr)) {
	  sym = dynamic_cast<LabSymbol *>(entry->getSymbol());
	  break;
	}
      }
    }
  }
  return sym;
}

SymbolEntry *ScopeInternal::findOverlap(const Address &addr,int4 size) const

{
  EntryMap *rangemap = maptable[ addr.getSpace()->getIndex() ];
  if (rangemap != (EntryMap *)0) {
    EntryMap::const_iterator iter;
    iter = rangemap->find_overlap(addr.getOffset(),addr.getOffset()+size-1);
    if (iter != rangemap->end())
      return &(*iter);
  }
  return (SymbolEntry *)0;
}

void ScopeInternal::findByName(const string &nm,vector<Symbol *> &res) const

{
  SymbolNameTree::const_iterator iter = findFirstByName(nm);
  while(iter != nametree.end()) {
    Symbol *sym = *iter;
    if (sym->name != nm) break;
    res.push_back(sym);
    ++iter;
  }
}

bool ScopeInternal::isNameUsed(const string &nm,const Scope *op2) const

{
  Symbol sym((Scope *)0,nm,(Datatype *)0);
  SymbolNameTree::const_iterator iter = nametree.lower_bound(&sym);
  if (iter != nametree.end()) {
    if ((*iter)->getName() == nm)
      return true;
  }
  Scope *par = getParent();
  if (par == (Scope *)0 || par == op2)
    return false;
  if (par->getParent() == (Scope *)0)	// Never recurse into global scope
    return false;
  return par->isNameUsed(nm, op2);
}

string ScopeInternal::buildVariableName(const Address &addr,
					const Address &pc,
					Datatype *ct,int4 &index,uint4 flags) const
{
  ostringstream s;
  int4 sz = (ct == (Datatype *)0) ? 1 : ct->getSize();

  if ((flags & Varnode::unaffected)!=0) {
    if ((flags & Varnode::return_address)!=0)
      s << "unaff_retaddr";
    else {
      string unaffname;
      unaffname = glb->translate->getRegisterName(addr.getSpace(),addr.getOffset(),sz);
      if (unaffname.empty()) {
	s << "unaff_";
	s << setw(8) << setfill('0') << hex << addr.getOffset();
      }
      else
	s << "unaff_" << unaffname;
    }
  }
  else if ((flags & Varnode::persist)!=0) {
    string spacename;
    spacename = glb->translate->getRegisterName(addr.getSpace(),addr.getOffset(),sz);
    if (!spacename.empty())
      s << spacename;
    else {
      if (ct != (Datatype *)0)
	ct->printNameBase(s);
      spacename = addr.getSpace()->getName();
      spacename[0] = toupper( spacename[0] ); // Capitalize space
      s << spacename;
      s << hex << setfill('0') << setw(2*addr.getAddrSize());
      s << AddrSpace::byteToAddress( addr.getOffset(), addr.getSpace()->getWordSize() );
    }
  }
  else if (((flags & Varnode::input)!=0)&&(index<0)) { // Irregular input
    string regname;
    regname = glb->translate->getRegisterName(addr.getSpace(),addr.getOffset(),sz);
    if (regname.empty()) {
      s << "in_" << addr.getSpace()->getName() << '_';
      s << setw(8) << setfill('0') << hex << addr.getOffset();
    }
    else
      s << "in_" << regname;
  }
  else if ((flags & Varnode::input)!=0) { // Regular parameter
    s << "param_" << dec << index;
  }
  else if ((flags & Varnode::addrtied)!=0) {
    if (ct != (Datatype *)0)
      ct->printNameBase(s);
    string spacename = addr.getSpace()->getName();
    spacename[0] = toupper( spacename[0] ); // Capitalize space
    s << spacename;
    s << hex << setfill('0') << setw(2*addr.getAddrSize());
    s << AddrSpace::byteToAddress(addr.getOffset(),addr.getSpace()->getWordSize());
  }
  else if ((flags & Varnode::indirect_creation)!=0) {
    string regname;
    s << "extraout_";
    regname = glb->translate->getRegisterName(addr.getSpace(),addr.getOffset(),sz);
    if (!regname.empty())
      s << regname;
    else
      s << "var";
  }
  else {			// Some sort of local variable
    if (ct != (Datatype *)0)
      ct->printNameBase(s);
    s << "Var" << dec << index++;
    if (findFirstByName(s.str()) != nametree.end()) {	// If the name already exists
      for(int4 i=0;i<10;++i) {	// Try bumping up the index a few times before calling makeNameUnique
	ostringstream s2;
	if (ct != (Datatype *)0)
	  ct->printNameBase(s2);
	s2 << "Var" << dec << index++;
	if (findFirstByName(s2.str()) == nametree.end()) {
	  return s2.str();
	}
      }
    }
  }
  return makeNameUnique(s.str());
}

string ScopeInternal::buildUndefinedName(void) const

{ // We maintain a family of officially undefined names
  // so that symbols can be stored in the database without
  // having their name defined
  // We generate a name of the form '$$undefXXXXXXXX'
  // The dollar signs indicate a special name (not a legal identifier)
  // undef indicates an undefined name and the remaining
  // characters are hex digits which make the name unique
  SymbolNameTree::const_iterator iter;

  Symbol testsym((Scope *)0,"$$undefz",(Datatype *)0);

  iter = nametree.lower_bound(&testsym);
  if (iter != nametree.begin())
    --iter;
  if (iter != nametree.end()) {
    const string &symname((*iter)->getName());
    if ((symname.size() == 15) && (0==symname.compare(0,7,"$$undef"))) {
      istringstream s( symname.substr(7,8) );
      uint4 uniq = ~((uint4)0);
      s >> hex >> uniq;
      if (uniq == ~((uint4)0))
	throw LowlevelError("Error creating undefined name");
      uniq += 1;
      ostringstream s2;
      s2 << "$$undef" << hex << setw(8) << setfill('0') << uniq;
      return s2.str();
    }
  }
  return "$$undef00000000";
}

string ScopeInternal::makeNameUnique(const string &nm) const

{
  SymbolNameTree::const_iterator iter = findFirstByName(nm);
  if (iter == nametree.end()) return nm; // nm is already unique

  Symbol boundsym((Scope *)0,nm+"_x99999",(Datatype *)0);
  boundsym.nameDedup = 0xffffffff;
  SymbolNameTree::const_iterator iter2 = nametree.lower_bound(&boundsym);
  uint4 uniqid;
  do {
    uniqid = 0xffffffff;
    --iter2;			// Last symbol whose name starts with nm
    if (iter == iter2) break;
    Symbol *bsym = *iter2;
    string bname = bsym->getName();
    bool isXForm = false;
    int4 digCount = 0;
    if ((bname.size() >= (nm.size() + 3)) && (bname[nm.size()] == '_')) {
      // Collect the last id
      int4 i = nm.size()+1;
      if (bname[i] == 'x') {
	i += 1;			// 5 digit form
	isXForm = true;
      }
      uniqid = 0;
      for(;i<bname.size();++i) {
	char dig = bname[i];
	if (!isdigit(dig)) {	// Everything after '_' must be a digit, or not in our format
	  uniqid = 0xffffffff;
	  break;
	}
	uniqid *= 10;
	uniqid += (dig-'0');
	digCount += 1;
      }
    }
    if (isXForm && (digCount != 5))	// x form, but not right number of digits
      uniqid = 0xffffffff;
    else if ((!isXForm) && (digCount != 2))
      uniqid = 0xffffffff;
  } while(uniqid == 0xffffffff);

  string resString;
  if (uniqid == 0xffffffff) {
    // no other names matching our convention
    resString = nm + "_00";		// Start a new sequence
  }
  else {
    uniqid += 1;
    ostringstream s;
    s << nm << '_' << dec << setfill('0');
    if (uniqid < 100)
      s << setw(2) << uniqid;
    else
      s << 'x' << setw(5) << uniqid;
    resString = s.str();
  }
  if (findFirstByName(resString) != nametree.end())
    throw LowlevelError("Unable to uniquify name: "+resString);
  return resString;
}

void ScopeInternal::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_SCOPE);
  encoder.writeString(ATTRIB_NAME, name);
  encoder.writeUnsignedInteger(ATTRIB_ID, uniqueId);
  if (getParent() != (const Scope *)0) {
    encoder.openElement(ELEM_PARENT);
    encoder.writeUnsignedInteger(ATTRIB_ID, getParent()->getId());
    encoder.closeElement(ELEM_PARENT);
  }
  getRangeTree().encode(encoder);

  if (!nametree.empty()) {
    encoder.openElement(ELEM_SYMBOLLIST);
    SymbolNameTree::const_iterator iter;
    for(iter=nametree.begin();iter!=nametree.end();++iter) {
      Symbol *sym = *iter;
      int4 symbolType = 0;
      if (!sym->mapentry.empty()) {
	const SymbolEntry &entry( *sym->mapentry.front() );
	if (entry.isDynamic()) {
	  if (sym->getCategory() == Symbol::union_facet)
	    continue;		// Don't save override
	  symbolType = (sym->getCategory() == Symbol::equate) ? 2 : 1;
	}
      }
      encoder.openElement(ELEM_MAPSYM);
      if (symbolType == 1)
	encoder.writeString(ATTRIB_TYPE, "dynamic");
      else if (symbolType == 2)
	encoder.writeString(ATTRIB_TYPE, "equate");
      sym->encode(encoder);
      vector<list<SymbolEntry>::iterator>::const_iterator miter;
      for(miter=sym->mapentry.begin();miter!=sym->mapentry.end();++miter) {
	const SymbolEntry &entry((*(*miter)));
	entry.encode(encoder);
      }
      encoder.closeElement(ELEM_MAPSYM);
    }
    encoder.closeElement(ELEM_SYMBOLLIST);
  }
  encoder.closeElement(ELEM_SCOPE);
}

/// \brief Parse a \<hole> element describing boolean properties of a memory range.
///
/// The \<scope> element is allowed to contain \<hole> elements, which are really descriptions
/// of memory globally. This method parses them and passes the info to the Database
/// object.
/// \param decoder is the stream decoder
void ScopeInternal::decodeHole(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_HOLE);
  uint4 flags = 0;
  Range range;
  range.decodeFromAttributes(decoder);
  decoder.rewindAttributes();
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if ((attribId==ATTRIB_READONLY) && decoder.readBool())
      flags |= Varnode::readonly;
    else if ((attribId==ATTRIB_VOLATILE) && decoder.readBool())
      flags |= Varnode::volatil;
  }
  if (flags != 0) {
    glb->symboltab->setPropertyRange(flags,range);
  }
  decoder.closeElement(elemId);
}

/// \brief Parse a \<collision> element indicating a named symbol with no storage or data-type info
///
/// Let the decompiler know that a name is occupied within the scope for isNameUsed queries, without
/// specifying storage and data-type information about the symbol.  This is modeled currently by
/// creating an unmapped symbol.
/// \param decoder is the stream decoder
void ScopeInternal::decodeCollision(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_COLLISION);
  string nm = decoder.readString(ATTRIB_NAME);
  decoder.closeElement(elemId);
  SymbolNameTree::const_iterator iter = findFirstByName(nm);
  if (iter == nametree.end()) {
    Datatype *ct = glb->types->getBase(1,TYPE_INT);
    addSymbol(nm,ct);
  }
}

/// \brief Insert a Symbol into the \b nametree
///
/// Duplicate symbol names are allowed for by establishing a deduplication id for the Symbol.
/// \param sym is the Symbol to insert
void ScopeInternal::insertNameTree(Symbol *sym)

{
  sym->nameDedup = 0;
  pair<SymbolNameTree::iterator,bool> nameres;
  nameres = nametree.insert(sym);
  if (!nameres.second) {
    sym->nameDedup = 0xffffffff;
    SymbolNameTree::iterator iter = nametree.upper_bound(sym);
    --iter;	// Last symbol with this name
    sym->nameDedup = (*iter)->nameDedup + 1;		// increment the dedup counter
    nameres = nametree.insert(sym);
    if (!nameres.second)
      throw LowlevelError("Could  not deduplicate symbol: "+sym->name);
  }
}

/// \brief Find an iterator pointing to the first Symbol in the ordering with a given name
///
/// \param nm is the name to search for
/// \return iterator pointing to the first Symbol or nametree.end() if there is no matching Symbol
SymbolNameTree::const_iterator ScopeInternal::findFirstByName(const string &nm) const

{
  Symbol sym((Scope *)0,nm,(Datatype *)0);
  SymbolNameTree::const_iterator iter = nametree.lower_bound(&sym);
  if (iter == nametree.end()) return iter;
  if ((*iter)->getName() != nm)
    return nametree.end();
  return iter;
}

void ScopeInternal::decode(Decoder &decoder)

{
//  uint4 elemId = decoder.openElement(ELEM_SCOPE);
//  name = el->getAttributeValue("name");	// Name must already be set in the constructor
  bool rangeequalssymbols = false;

  uint4 subId = decoder.peekElement();
  if (subId == ELEM_PARENT) {
    decoder.skipElement();	// Skip <parent> tag processed elsewhere
    subId = decoder.peekElement();
  }
  if (subId== ELEM_RANGELIST) {
    RangeList newrangetree;
    newrangetree.decode(decoder);
    glb->symboltab->setRange(this,newrangetree);
  }
  else if (subId == ELEM_RANGEEQUALSSYMBOLS) {
    decoder.openElement();
    decoder.closeElement(subId);
    rangeequalssymbols = true;
  }
  subId = decoder.openElement(ELEM_SYMBOLLIST);
  if (subId != 0) {
    for(;;) {
      uint4 symId = decoder.peekElement();
      if (symId == 0) break;
      if (symId == ELEM_MAPSYM) {
	Symbol *sym = addMapSym(decoder);
	if (rangeequalssymbols) {
	  SymbolEntry *e = sym->getFirstWholeMap();
	  glb->symboltab->addRange(this,e->getAddr().getSpace(),e->getFirst(),e->getLast());
	}
      }
      else if (symId == ELEM_HOLE)
	decodeHole(decoder);
      else if (symId == ELEM_COLLISION)
	decodeCollision(decoder);
      else
	throw LowlevelError("Unknown symbollist tag");
    }
    decoder.closeElement(subId);
  }
//  decoder.closeElement(elemId);
  categorySanity();
}

void ScopeInternal::printEntries(ostream &s) const

{
  s << "Scope " << name << endl;
  for(int4 i=0;i<maptable.size();++i) {
    EntryMap *rangemap = maptable[i];
    if (rangemap == (EntryMap *)0) continue;
    list<SymbolEntry>::const_iterator iter,enditer;
    iter = rangemap->begin_list();
    enditer = rangemap->end_list();
    for(;iter!=enditer;++iter)
      (*iter).printEntry(s);
  }
}

int4 ScopeInternal::getCategorySize(int4 cat) const

{
  if ((cat >= category.size())||(cat<0))
    return 0;
  return category[cat].size();
}

Symbol *ScopeInternal::getCategorySymbol(int4 cat,int4 ind) const

{
  if ((cat >= category.size())||(cat<0))
    return (Symbol *)0;
  if ((ind < 0)||(ind >= category[cat].size()))
    return (Symbol *)0;
  return category[cat][ind];
}

void ScopeInternal::setCategory(Symbol *sym,int4 cat,int4 ind)

{
  if (sym->category >= 0) {
    vector<Symbol *> &list(category[sym->category]);
    list[sym->catindex] = (Symbol *)0;
    while((!list.empty())&&(list.back() == (Symbol *)0))
      list.pop_back();
  }

  sym->category = cat;
  sym->catindex = ind;
  if (cat < 0) return;
  while(category.size() <= sym->category)
    category.push_back(vector<Symbol *>());
  vector<Symbol *> &list(category[sym->category]);
  if (cat > 0)
    sym->catindex = list.size();
  while(list.size() <= sym->catindex)
    list.push_back((Symbol *)0);
  list[sym->catindex] = sym;
}

/// Run through all the symbols whose name is undefined. Build a variable name, uniquify it, and
/// rename the variable.
/// \param base is the base index to start at for generating generic names
void ScopeInternal::assignDefaultNames(int4 &base)

{
  SymbolNameTree::const_iterator iter;

  Symbol testsym((Scope *)0,"$$undef",(Datatype *)0);

  iter = nametree.upper_bound(&testsym);
  while(iter != nametree.end()) {
    Symbol *sym = *iter;
    if (!sym->isNameUndefined()) break;
    ++iter;		// Advance before renaming
    string nm = buildDefaultName(sym, base, (Varnode *)0);
    renameSymbol(sym, nm);
  }
}

/// Check to make sure the Scope is a \e namespace then remove all
/// its address ranges from the map.
/// \param scope is the given Scope
void Database::clearResolve(Scope *scope)

{
  if (scope == globalscope) return;		// Does not apply to the global scope
  if (scope->fd != (Funcdata *)0) return;	// Does not apply to functional scopes

  set<Range>::const_iterator iter;

  for(iter=scope->rangetree.begin();iter!=scope->rangetree.end();++iter) {
    const Range &rng(*iter);
    pair<ScopeResolve::const_iterator,ScopeResolve::const_iterator> res;
    res = resolvemap.find(rng.getFirstAddr());
    while(res.first != res.second) {
      if ((*res.first).scope == scope) {
	resolvemap.erase(res.first);
	break;
      }
    }
  }
}

/// This recursively clears references in idmap or in resolvemap.
/// \param scope is the given Scope to clear
void Database::clearReferences(Scope *scope)

{
  ScopeMap::const_iterator iter = scope->children.begin();
  ScopeMap::const_iterator enditer = scope->children.end();
  while(iter != enditer) {
    clearReferences((*iter).second);
    ++iter;
  }
  idmap.erase(scope->uniqueId);
  clearResolve(scope);
}

/// If the Scope is a \e namespace, iterate through all its ranges, adding each to the map
/// \param scope is the given Scope to add
void Database::fillResolve(Scope *scope)

{
  if (scope == globalscope) return;		// Does not apply to the global scope
  if (scope->fd != (Funcdata *)0) return;	// Does not apply to functional scopes

  set<Range>::const_iterator iter;
  for(iter=scope->rangetree.begin();iter!=scope->rangetree.end();++iter) {
    const Range &rng( *iter );
    resolvemap.insert(scope,rng.getFirstAddr(),rng.getLastAddr());
  }
}

/// Initialize a new symbol table, with no initial scopes or symbols.
/// \param g is the Architecture that owns the symbol table
/// \param idByName is \b true if scope ids are calculated as a hash of the scope name.
Database::Database(Architecture *g,bool idByName)

{
  glb=g;
  globalscope=(Scope *)0;
  flagbase.defaultValue()=0;
  idByNameHash=idByName;
}

Database::~Database(void)

{
  if (globalscope != (Scope *)0)
    deleteScope(globalscope);
}

/// The new Scope must be initially empty and \b this Database takes over ownership.
/// Practically, this is just setting up the new Scope as a sub-scope of its parent.
/// The parent Scope should already be registered with \b this Database, or
/// NULL can be passed to register the global Scope.
/// \param newscope is the new Scope being registered
/// \param parent is the parent Scope or NULL
void Database::attachScope(Scope *newscope,Scope *parent)

{
  if (parent == (Scope *)0) {
    if (globalscope != (Scope *)0)
      throw LowlevelError("Multiple global scopes");
    if (newscope->name.size() != 0)
      throw LowlevelError("Global scope does not have empty name");
    globalscope = newscope;
    idmap[globalscope->uniqueId] = globalscope;
    return;
  }
  if (newscope->name.size()==0)
    throw LowlevelError("Non-global scope has empty name");
  pair<uint8,Scope *> value(newscope->uniqueId,newscope);
  pair<ScopeMap::iterator,bool> res;
  res = idmap.insert(value);
  if (res.second==false) {
    ostringstream s;
    s << "Duplicate scope id: ";
    s << newscope->getFullName();
    delete newscope;
    throw RecovError(s.str());
  }
  parent->attachScope(newscope);
}

/// Give \b this database the chance to inform existing scopes of any change to the
/// configuration, which may have changed since the initial scopes were created.
void Database::adjustCaches(void)

{
  ScopeMap::iterator iter;
  for(iter=idmap.begin();iter!=idmap.end();++iter) {
    (*iter).second->adjustCaches();
  }
}

/// \param scope is the given Scope
void Database::deleteScope(Scope *scope)

{
  clearReferences(scope);
  if (globalscope == scope) {
    globalscope = (Scope *)0;
    delete scope;
  }
  else {
    ScopeMap::iterator iter = scope->parent->children.find(scope->uniqueId);
    if (iter == scope->parent->children.end())
      throw LowlevelError("Could not remove parent reference to: "+scope->name);
    scope->parent->detachScope(iter);
  }
}

/// The given Scope is not deleted, only its children.
/// \param scope is the given Scope
void Database::deleteSubScopes(Scope *scope)

{
  ScopeMap::iterator iter = scope->children.begin();
  ScopeMap::iterator enditer = scope->children.end();
  ScopeMap::iterator curiter;
  while(iter != enditer) {
    curiter = iter;
    ++iter;
    clearReferences((*curiter).second);
    scope->detachScope(curiter);
  }
}

/// All unlocked symbols in \b this Scope, and recursively into its sub-scopes,
/// are removed.
/// \param scope is the given Scope
void Database::clearUnlocked(Scope *scope)

{
  ScopeMap::iterator iter = scope->children.begin();
  ScopeMap::iterator enditer = scope->children.end();
  while(iter != enditer) {
    Scope *subscope = (*iter).second;
    clearUnlocked(subscope);
    ++iter;
  }
  scope->clearUnlocked();
}

/// Any existing \e ownership is completely replaced.  The address to Scope map is updated.
/// \param scope is the given Scope
/// \param rlist is the set of addresses to mark as owned
void Database::setRange(Scope *scope,const RangeList &rlist)

{
  clearResolve(scope);
  scope->rangetree = rlist;	// Overwrite whole tree
  fillResolve(scope);
}

/// The new range will be merged with the existing \e ownership.
/// The address to Scope map is updated
/// \param scope is the given Scope
/// \param spc is the address space of the memory range being added
/// \param first is the offset of the first byte in the array
/// \param last is the offset of the last byte
void Database::addRange(Scope *scope,AddrSpace *spc,uintb first,uintb last)

{
  clearResolve(scope);
  scope->addRange(spc,first,last);
  fillResolve(scope);
}

/// Addresses owned by the Scope that are disjoint from the given range are
/// not affected.
/// \param scope is the given Scope
/// \param spc is the address space of the memory range being removed
/// \param first is the offset of the first byte in the array
/// \param last is the offset of the last byte
void Database::removeRange(Scope *scope,AddrSpace *spc,uintb first,uintb last)

{
  clearResolve(scope);
  scope->removeRange(spc,first,last);
  fillResolve(scope);
}

/// Look for a Scope by id.  If it does not exist, create a new scope
/// with the given name and parent scope.
/// \param id is the global id of the Scope
/// \param nm is the given name of the Scope
/// \param parent is the given parent scope to search
/// \return the subscope object either found or created
Scope *Database::findCreateScope(uint8 id,const string &nm,Scope *parent)

{
  Scope *res = resolveScope(id);
  if (res != (Scope *)0)
    return res;
  res = globalscope->buildSubScope(id,nm);
  attachScope(res, parent);
  return res;
}

/// Find a Scope object, given its global id.  Return null if id is not mapped to a Scope.
/// \param id is the global id
/// \return the matching Scope or null
Scope *Database::resolveScope(uint8 id) const

{
  ScopeMap::const_iterator iter = idmap.find(id);
  if (iter != idmap.end())
    return (*iter).second;
  return (Scope *)0;
}

/// \brief Get the Scope (and base name) associated with a qualified Symbol name
///
/// The name is parsed using a \b delimiter that is passed in. The name can
/// be only partially qualified by passing in a starting Scope, which the
/// name is assumed to be relative to. If the starting scope is \b null, or the name
/// starts with the delimiter, the name is assumed to be relative to the global Scope.
/// The unqualified (base) name of the Symbol is passed back to the caller.
/// \param fullname is the qualified Symbol name
/// \param delim is the delimiter separating names
/// \param basename will hold the passed back base Symbol name
/// \param start is the Scope to start drilling down from, or NULL for the global scope
/// \return the Scope being referred to by the name
Scope *Database::resolveScopeFromSymbolName(const string &fullname,const string &delim,string &basename,
					    Scope *start) const
{
  if (start == (Scope *)0)
    start = globalscope;
  
  string::size_type mark = 0;
  string::size_type endmark;
  for(;;) {
    endmark = fullname.find(delim,mark);
    if (endmark == string::npos) break;
    if (endmark == 0) {		// Path is "absolute"
      start = globalscope;	// Start from the global scope
    }
    else {
      string scopename = fullname.substr(mark,endmark-mark);
      start = start->resolveScope(scopename,idByNameHash);
      if (start == (Scope *)0)	// Was the scope name bad
	return start;
    }
    mark = endmark + delim.size();
  }
  basename = fullname.substr(mark,endmark);
  return start;
}

/// \brief Find and/or create Scopes associated with a qualified Symbol name
///
/// The name is parsed using a \b delimiter that is passed in. The name can
/// be only partially qualified by passing in a starting Scope, which the
/// name is assumed to be relative to. Otherwise the name is assumed to be
/// relative to the global Scope.  The unqualified (base) name of the Symbol
/// is passed back to the caller.  Any missing scope in the path is created.
/// \param fullname is the qualified Symbol name
/// \param delim is the delimiter separating names
/// \param basename will hold the passed back base Symbol name
/// \param start is the Scope to start drilling down from, or NULL for the global scope
/// \return the Scope being referred to by the name
Scope *Database::findCreateScopeFromSymbolName(const string &fullname,const string &delim,string &basename,
					       Scope *start)
{
  if (start == (Scope *)0)
    start = globalscope;

  string::size_type mark = 0;
  string::size_type endmark;
  for(;;) {
    endmark = fullname.find(delim,mark);
    if (endmark == string::npos) break;
    if (!idByNameHash)
      throw LowlevelError("Scope name hashes not allowed");
    string scopename = fullname.substr(mark,endmark-mark);
    uint8 nameId = Scope::hashScopeName(start->uniqueId, scopename);
    start = findCreateScope(nameId, scopename, start);
    mark = endmark + delim.size();
  }
  basename = fullname.substr(mark,endmark);
  return start;
}

/// \brief Determine the lowest-level Scope which might contain the given address as a Symbol
///
/// As currently implemented, this method can only find a \e namespace Scope.
/// When searching for a Symbol by Address, the global Scope is always
/// searched because it is the terminating Scope when recursively walking scopes through
/// the \e parent relationship, so it isn't entered in this map.  A function level Scope,
/// also not entered in the map, is only returned as the Scope passed in as a default,
/// when no \e namespace Scope claims the address.
/// \param qpoint is the default Scope returned if no \e owner is found
/// \param addr is the address whose owner should be searched for
/// \param usepoint is a point in code where the address is being accessed (may be \e invalid)
/// \return a Scope to act as a starting point for a hierarchical search
const Scope *Database::mapScope(const Scope *qpoint,const Address &addr,
				const Address &usepoint) const
{  if (resolvemap.empty())	// If there are no namespace scopes
    return qpoint;		// Start querying from scope placing query
  pair<ScopeResolve::const_iterator,ScopeResolve::const_iterator> res;
  res = resolvemap.find(addr);
  if (res.first != res.second)
    return (*res.first).getScope();
  return qpoint;
}

/// \brief A non-constant version of mapScope()
///
/// \param qpoint is the default Scope returned if no \e owner is found
/// \param addr is the address whose owner should be searched for
/// \param usepoint is a point in code where the address is being accessed (may be \e invalid)
/// \return a Scope to act as a starting point for a hierarchical search
Scope *Database::mapScope(Scope *qpoint,const Address &addr,
			  const Address &usepoint)
{
  if (resolvemap.empty())	// If there are no namespace scopes
    return qpoint;		// Start querying from scope placing query
  pair<ScopeResolve::const_iterator,ScopeResolve::const_iterator> res;
  res = resolvemap.find(addr);
  if (res.first != res.second)
    return (*res.first).getScope();
  return qpoint;
}

/// This allows the standard boolean Varnode properties like
/// \e read-only and \e volatile to be put an a memory range, independent
/// of whether a Symbol is there or not.  These get picked up by the
/// Scope::queryProperties() method in particular.
/// \param flags is the set of boolean properties
/// \param range is the memory range to label
void Database::setPropertyRange(uint4 flags,const Range &range)

{
  Address addr1 = range.getFirstAddr();
  Address addr2 = range.getLastAddrOpen(glb);
  flagbase.split(addr1);
  partmap<Address,uint4>::iterator aiter,biter;

  aiter = flagbase.begin(addr1);
  if (!addr2.isInvalid()) {
    flagbase.split(addr2);
    biter = flagbase.begin(addr2);
  }
  else
    biter = flagbase.end();
  while(aiter != biter) {	// Update bits across whole range
    (*aiter).second |= flags;
    ++aiter;
  }
}

/// The non-zero bits in the \b flags parameter indicate the boolean properties to be cleared.
/// No other properties are altered.
/// \param flags is the set of properties to clear
/// \param range is the memory range to clear
void Database::clearPropertyRange(uint4 flags,const Range &range)

{
  Address addr1 = range.getFirstAddr();
  Address addr2 = range.getLastAddrOpen(glb);
  flagbase.split(addr1);
  partmap<Address,uint4>::iterator aiter,biter;

  aiter = flagbase.begin(addr1);
  if (!addr2.isInvalid()) {
    flagbase.split(addr2);
    biter = flagbase.begin(addr2);
  }
  else
    biter = flagbase.end();
  flags = ~flags;
  while(aiter != biter) {	// Update bits across whole range
    (*aiter).second &= flags;
    ++aiter;
  }
}

/// Encode a single \<db> element to the stream, which contains child elements
/// for each Scope (which contain Symbol children in turn).
/// \param encoder is the stream encoder
void Database::encode(Encoder &encoder) const

{
  partmap<Address,uint4>::const_iterator piter,penditer;

  encoder.openElement(ELEM_DB);
  if (idByNameHash)
    encoder.writeBool(ATTRIB_SCOPEIDBYNAME, true);
  // Save the property change points
  piter = flagbase.begin();
  penditer = flagbase.end();
  for(;piter!=penditer;++piter) {
    const Address &addr( (*piter).first );
    uint4 val = (*piter).second;
    encoder.openElement(ELEM_PROPERTY_CHANGEPOINT);
    addr.getSpace()->encodeAttributes(encoder,addr.getOffset() );
    encoder.writeUnsignedInteger(ATTRIB_VAL, val);
    encoder.closeElement(ELEM_PROPERTY_CHANGEPOINT);
  }

  if (globalscope != (Scope *)0)
    globalscope->encodeRecursive(encoder,true);		// Save the global scopes
  encoder.closeElement(ELEM_DB);
}

/// Parse a \<parent> element for the scope id of the parent namespace.
/// Look up the parent scope and return it.
/// Throw an error if there is no matching scope
/// \param decoder is the stream decoder
/// \return the matching scope
Scope *Database::parseParentTag(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_PARENT);
  uint8 id = decoder.readUnsignedInteger(ATTRIB_ID);
  Scope *res = resolveScope(id);
  if (res == (Scope *)0)
    throw LowlevelError("Could not find scope matching id");
  decoder.closeElement(elemId);
  return res;
}

/// Parse a \<db> element to recover Scope and Symbol objects.
/// \param decoder is the stream decoder
void Database::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_DB);
  idByNameHash = false;		// Default
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_SCOPEIDBYNAME)
      idByNameHash = decoder.readBool();
  }
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId != ELEM_PROPERTY_CHANGEPOINT) break;
    decoder.openElement();
    uint4 val = decoder.readUnsignedInteger(ATTRIB_VAL);
    VarnodeData vData;
    vData.decodeFromAttributes(decoder);
    Address addr = vData.getAddr();
    decoder.closeElement(subId);
    flagbase.split(addr) = val;
  }

  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId != ELEM_SCOPE) break;
    string name;		// Name of global scope by default
    string displayName;
    uint8 id = 0;		// Id of global scope by default
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_NAME)
	name = decoder.readString();
      else if (attribId == ATTRIB_ID) {
	id = decoder.readUnsignedInteger();
      }
      else if (attribId == ATTRIB_LABEL)
	displayName = decoder.readString();
    }
    Scope *parentScope = (Scope *)0;
    uint4 parentId = decoder.peekElement();
    if (parentId == ELEM_PARENT) {
      parentScope = parseParentTag(decoder);
    }
    Scope *newScope = findCreateScope(id, name, parentScope);
    if (!displayName.empty())
      newScope->setDisplayName(displayName);
    newScope->decode(decoder);
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

/// This allows incremental building of the Database from multiple stream sources.
/// An empty Scope must already be allocated.  It is registered with \b this Database,
/// and then populated with Symbol objects based as the content of a given element.
/// The element can either be a \<scope> itself, or another element that wraps a \<scope>
/// element as its first child.
/// \param decoder is the stream decoder
/// \param newScope is the empty Scope
void Database::decodeScope(Decoder &decoder,Scope *newScope)

{
  uint4 elemId = decoder.openElement();
  if (elemId == ELEM_SCOPE) {
    Scope *parentScope = parseParentTag(decoder);
    attachScope(newScope,parentScope);
    newScope->decode(decoder);
  }
  else {
    newScope->decodeWrappingAttributes(decoder);
    uint4 subId = decoder.openElement(ELEM_SCOPE);
    Scope *parentScope = parseParentTag(decoder);
    attachScope(newScope,parentScope);
    newScope->decode(decoder);
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

/// Some namespace objects may already exist.  Create those that don't.
/// \param decoder is the stream to decode the path from
/// \return the namespace described by the path
Scope *Database::decodeScopePath(Decoder &decoder)

{
  Scope *curscope = getGlobalScope();
  uint4 elemId = decoder.openElement(ELEM_PARENT);
  uint4 subId = decoder.openElement();
  decoder.closeElementSkipping(subId);		// Skip element describing the root scope
  for(;;) {
    subId = decoder.openElement();
    if (subId != ELEM_VAL) break;
    string displayName;
    uint8 scopeId = 0;
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_ID)
	scopeId = decoder.readUnsignedInteger();
      else if (attribId == ATTRIB_LABEL)
	displayName = decoder.readString();
    }
    string name = decoder.readString(ATTRIB_CONTENT);
    if (scopeId == 0)
      throw DecoderError("Missing name and id in scope");
    curscope = findCreateScope(scopeId, name, curscope);
    if (!displayName.empty())
      curscope->setDisplayName(displayName);
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
  return curscope;
}

} // End namespace ghidra

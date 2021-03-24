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
#include "varnode.hh"
#include "funcdata.hh"

/// Compare by location then by definition.
/// This is the same as the normal varnode compare, but we distinguish identical frees by their
/// pointer address.  Thus varsets defined with this comparison act like multisets for free varnodes
/// and like unique sets for everything else (with respect to the standard varnode comparison)
/// \param a is the first Varnode to compare
/// \param b is the second Varnode to compare
/// \return true if \b a occurs earlier than \b b
inline bool VarnodeCompareLocDef::operator()(const Varnode *a,const Varnode *b) const

{
  uint4 f1,f2;

  if (a->getAddr() != b->getAddr()) return (a->getAddr() < b->getAddr());
  if (a->getSize() != b->getSize()) return (a->getSize() < b->getSize());
  f1 = a->getFlags()&(Varnode::input|Varnode::written);
  f2 = b->getFlags()&(Varnode::input|Varnode::written);
  if (f1!=f2) return ((f1-1)<(f2-1)); // -1 forces free varnodes to come last
  if (f1==Varnode::written) {
    if (a->getDef()->getSeqNum() != b->getDef()->getSeqNum())
      return (a->getDef()->getSeqNum() < b->getDef()->getSeqNum());
  }
  else if (f1 == 0)		// both are free
    //    return (a < b);		// compare pointers
    return (a->getCreateIndex() < b->getCreateIndex());
  
  return false;
}

/// Compare by definition then by location.
/// This is different than the standard ordering but we still allow multiple identical frees.
/// \param a is the first Varnode to compare
/// \param b is the second Varnode to compare
/// \return true if \b a occurs earlier than \b b
inline bool VarnodeCompareDefLoc::operator()(const Varnode *a,const Varnode *b) const

{
  uint4 f1,f2;

  f1 = (a->getFlags() & (Varnode::input|Varnode::written));
  f2 = (b->getFlags() & (Varnode::input|Varnode::written));
  if (f1!=f2) return ((f1-1)<(f2-1));
				// NOTE: The -1 forces free varnodes to come last
  if (f1==Varnode::written) {
    if (a->getDef()->getSeqNum() != b->getDef()->getSeqNum())
      return (a->getDef()->getSeqNum() < b->getDef()->getSeqNum());
  }
  if (a->getAddr() != b->getAddr()) return (a->getAddr() < b->getAddr());
  if (a->getSize() != b->getSize()) return (a->getSize() < b->getSize());
  if (f1==0)			// both are free
    //    return (a<b);		// Compare pointers
    return (a->getCreateIndex() < b->getCreateIndex());
  return false;
}

/// During the course of analysis Varnodes are merged into high-level variables that are intended
/// to be closer to the concept of variables in C source code. For a large portion of the decompiler
/// analysis this concept hasn't been built yet, and this routine will return \b null.
/// But after a certain point, every Varnode managed by the Funcdata object, with the exception
/// of ones that are marked as \e annotations, is associated with some HighVariable
/// and will return a non-null result.
/// \return the associated HighVariable
HighVariable *Varnode::getHigh(void) const

{
  if (high==(HighVariable *)0) 
    throw LowlevelError("Requesting non-existent high-level");
  return high;
}

/// Return various values depending on the containment of another Varnode within \b this.
/// Return
///         -  -1 if op.loc starts before -this-
///         -   0 if op is contained in -this-
///         -   1 if op.start is contained in -this-
///         -   2 if op.loc comes after -this- or
///         -   3 if op and -this- are in non-comparable spaces
/// \param op is the Varnode to test for containment
/// \return the integer containment code
int4 Varnode::contains(const Varnode &op) const

{
  if (loc.getSpace() != op.loc.getSpace()) return 3;
  if (loc.getSpace()->getType()==IPTR_CONSTANT) return 3;
  uintb a = loc.getOffset();
  uintb b = op.loc.getOffset();
  if (b<a) return -1;
  if (b>=a+size) return 2;
  if (b+op.size > a+size) return 1;
  return 0;
}

/// Check whether the storage locations of two varnodes intersect
/// \param op is the Varnode to compare with \b this
/// \return \b true if the locations intersect
bool Varnode::intersects(const Varnode &op) const

{
  if (loc.getSpace() != op.loc.getSpace()) return false;
  if (loc.getSpace()->getType()==IPTR_CONSTANT) return false;
  uintb a = loc.getOffset();
  uintb b = op.loc.getOffset();
  if (b<a) {
    if (a>=b+op.size) return false;
    return true;
  }
  if (b>=a+size) return false;
  return true;
}

/// Check if \b this intersects the given Address range
/// \param op2loc is the start of the range
/// \param op2size is the size of the range in bytes
/// \return \b true if \b this intersects the range
bool Varnode::intersects(const Address &op2loc,int4 op2size) const

{
  if (loc.getSpace() != op2loc.getSpace()) return false;
  if (loc.getSpace()->getType()==IPTR_CONSTANT) return false;
  uintb a = loc.getOffset();
  uintb b = op2loc.getOffset();
  if (b<a) {
    if (a>=b+op2size) return false;
    return true;
  }
  if (b>=a+size) return false;
  return true;
}

int4 Varnode::characterizeOverlap(const Varnode &op) const

{
  if (loc.getSpace() != op.loc.getSpace())
    return 0;
  if (loc.getOffset() == op.loc.getOffset())		// Left sides match
    return (size == op.size) ? 2 : 1;	// Either total match or partial
  else if (loc.getOffset() < op.loc.getOffset()) {
    uintb thisright = loc.getOffset() + (size-1);
    return (thisright < op.loc.getOffset()) ? 0: 1;		// Test if this ends before op begins
  }
  else {
    uintb opright = op.loc.getOffset() + (op.size-1);
    return (opright < loc.getOffset()) ? 0: 1;			// Test if op ends before this begins
  }
}

/// Return whether \e Least \e Signifigant \e Byte of \b this occurs in \b op
/// I.e. return
///     - 0 if it overlaps op's lsb
///     - 1 if it overlaps op's second lsb  and so on
/// \param op is Varnode to test for overlap
/// \return the relative overlap point or -1
int4 Varnode::overlap(const Varnode &op) const

{  
  if (!loc.isBigEndian())	// Little endian
    return loc.overlap(0,op.loc,op.size);
  else {			// Big endian
    int4 over = loc.overlap(size-1,op.loc,op.size);
    if (over != -1)
      return op.size-1-over;
  }
  return -1;
}

/// Return whether \e Least \e Signifigant \e Byte of \b this occurs in an Address range
/// I.e. return
///     - 0 if it overlaps op's lsb
///     - 1 if it overlaps op's second lsb  and so on
/// \param op2loc is the starting Address of the range
/// \param op2size is the size of the range in bytes
/// \return the relative overlap point or -1
int4 Varnode::overlap(const Address &op2loc,int4 op2size) const

{
  if (!loc.isBigEndian())	// Little endian
    return loc.overlap(0,op2loc,op2size);
  else {			// Big endian
    int4 over = loc.overlap(size-1,op2loc,op2size);
    if (over != -1)
      return op2size-1-over;
  }
  return -1;
}

/// Rebuild variable cover based on where the Varnode
/// is defined and read. This is \e only called by the
/// Merge class which knows when to call it properly
void Varnode::updateCover(void) const

{
  if ((flags & Varnode::coverdirty)!=0) {
    if (hasCover()&&(cover!=(Cover *)0))
      cover->rebuild(this);
    clearFlags(Varnode::coverdirty);
  }
}

/// Delete the Cover object.  Used for dead Varnodes before full deletion.
void Varnode::clearCover(void) const

{
  if (cover != (Cover *)0) {
    delete cover;
    cover = (Cover *)0;
  }
}

/// Initialize a new Cover and set dirty bit so that updateCover will rebuild
void Varnode::calcCover(void) const

{
  if (hasCover()) {
    if (cover != (Cover *)0)
      delete cover;
    cover = new Cover;
    setFlags(Varnode::coverdirty);
  }
}

/// Print, to a stream, textual information about where \b this Varnode is in scope within its
/// particular Funcdata. This amounts to a list of address ranges bounding the writes and reads
/// of the Varnode
/// \param s is the output stream
void Varnode::printCover(ostream &s) const

{
  if (cover == (Cover *)0)
    throw LowlevelError("No cover to print");
  if ((flags & Varnode::coverdirty)!=0)
    s << "Cover is dirty" << endl;
  else
    cover->print(s);
}

/// Print boolean attribute information about \b this as keywords to a stream
/// \param s is the output stream
void Varnode::printInfo(ostream &s) const

{
  type->printRaw(s);
  s << " = ";
  printRaw(s);
  if (isAddrTied())
    s << " tied";
  if (isMapped())
    s << " mapped";
  if (isPersist())
    s << " persistent";
  if (isTypeLock())
    s << " tlock";
  if (isNameLock())
    s << " nlock";
  if (isSpacebase())
    s << " base";
  if (isUnaffected())
    s << " unaff";
  if (isImplied())
    s << " implied";
  if (isAddrForce())
    s << " addrforce";
  if (isReadOnly())
    s << " readonly";
  s << " (consumed=0x" << hex << consumed << ')';
  s << " (internal=" << hex << this << ')';
  s << " (create=0x" << hex << create_index << ')';
  s << endl;
}

/// Erase the operation from our descendant list and set the cover dirty flag
/// \param op is the PcodeOp to remove
void Varnode::eraseDescend(PcodeOp *op)

{
  list<PcodeOp *>::iterator iter;

  iter = descend.begin();
  while (*iter != op)		// Find this op in list of vn's descendants
    iter++;
  descend.erase(iter);		// Remove it from list
  setFlags(Varnode::coverdirty);
}

/// Put a new operator in the descendant list and set the cover dirty flag
/// \param op is PcodeOp to add
void Varnode::addDescend(PcodeOp *op)

{
  //  if (!heritageknown()) {
  if (isFree()&&(!isSpacebase())) {
    if (!descend.empty())
      throw LowlevelError("Free varnode has multiple descendants");
  }
  descend.push_back(op);
  setFlags(Varnode::coverdirty);
}

/// Completely clear the descendant list
/// Only called if Varnode is about to be irrevocably destroyed
void Varnode::destroyDescend(void)

{
  descend.clear();
}

/// Set desired boolean attributes on this Varnode and then set dirty bits if appropriate
/// \param fl is the mask containing the list of attributes to set
void Varnode::setFlags(uint4 fl) const

{
  flags |= fl;
  if (high != (HighVariable *)0) {
    high->flagsDirty();
    if ((fl&Varnode::coverdirty)!=0)
      high->coverDirty();
  }
}

/// Clear desired boolean attributes on this Varnode and then set dirty bits if appropriate
/// \param fl is the mask containing the list of attributes to clear
void Varnode::clearFlags(uint4 fl) const

{
  flags &= ~fl;
  if (high != (HighVariable *)0) {
    high->flagsDirty();
    if ((fl&Varnode::coverdirty)!=0)
      high->coverDirty();
  }
}

/// Directly change the defining PcodeOp and set appropriate dirty bits
/// \param op is the pointer to the new PcodeOp, which can be \b null
void Varnode::setDef(PcodeOp *op)

{				// Set the defining op
  def = op;
  if (op==(PcodeOp *)0) {
    setFlags(Varnode::coverdirty);
    clearFlags(Varnode::written);
  }
  else
    setFlags(Varnode::coverdirty|Varnode::written);
}

/// The given Symbol's data-type and flags are inherited by \b this Varnode.
/// If the Symbol is \e type-locked, a reference to the Symbol is set on \b this Varnode.
/// \param entry is a mapping to the given Symbol
/// \return \b true if any properties have changed
bool Varnode::setSymbolProperties(SymbolEntry *entry)

{
  bool res = entry->updateType(this);
  if (entry->getSymbol()->isTypeLocked()) {
    if (mapentry != entry) {
      mapentry = entry;
      if (high != (HighVariable *)0)
	high->setSymbol(this);
      res = true;
    }
  }
  setFlags(entry->getAllFlags() & ~Varnode::typelock);
  return res;
}

/// A reference to the given Symbol is set on \b this Varnode.
/// The data-type on \b this Varnode is not changed.
/// \param entry is a mapping to the given Symbol
void Varnode::setSymbolEntry(SymbolEntry *entry)

{
  mapentry = entry;
  uint4 fl = Varnode::mapped;	// Flags are generally not changed, but we do mark this as mapped
  if (entry->getSymbol()->isNameLocked())
    fl |= Varnode::namelock;
  setFlags(fl);
  if (high != (HighVariable *)0)
    high->setSymbol(this);
}

/// Link Symbol information to \b this as a \b reference. This only works for a constant Varnode.
/// This used when there is a constant address reference to the Symbol and the Varnode holds the
/// reference, not the actual value of the Symbol.
/// \param entry is a mapping to the given Symbol
/// \param off is the byte offset into the Symbol of the reference
void Varnode::setSymbolReference(SymbolEntry *entry,int4 off)

{
  if (high != (HighVariable *)0) {
    high->setSymbolReference(entry->getSymbol(), off);
  }
}

/// Change the Datatype and lock state associated with this Varnode if various conditions are met
///    - Don't change a previously locked Datatype (unless \b override flag is \b true)
///    - Don't consider an \b undefined type to be locked
///    - Don't change to an identical Datatype
/// \param ct is the Datatype to change to
/// \param lock is \b true if the new Datatype should be locked
/// \param override is \b true if an old lock should be overridden
/// \return \b true if the Datatype or the lock setting was changed
bool Varnode::updateType(Datatype *ct,bool lock,bool override)

{
  if (ct->getMetatype() == TYPE_UNKNOWN) // Unknown data type is ALWAYS unlocked
    lock = false;

  if (isTypeLock()&&(!override)) return false; // Type is locked
  if ((type == ct)&&(isTypeLock()==lock)) return false; // No change
  flags &= ~Varnode::typelock;
  if (lock)
    flags |= Varnode::typelock;
  type = ct;
  if (high != (HighVariable *)0)
    high->typeDirty();
  return true;
}

/// Copy any symbol and type information from -vn- into this
/// \param vn is the Varnode to copy from
void Varnode::copySymbol(const Varnode *vn)

{
  type = vn->type;		// Copy any type
  mapentry = vn->mapentry;	// Copy any symbol
  flags &= ~(Varnode::typelock | Varnode::namelock);
  flags |= (Varnode::typelock | Varnode::namelock) & vn->flags;
  if (high != (HighVariable *)0) {
    high->typeDirty();
    if (mapentry != (SymbolEntry *)0)
      high->setSymbol(this);
  }
}

/// Symbol information (if present) is copied from the given constant Varnode into \b this,
/// which also must be constant, but only if the two constants are \e close in the sense of an equate.
/// \param vn is the given constant Varnode
void Varnode::copySymbolIfValid(const Varnode *vn)

{
  SymbolEntry *mapEntry = vn->getSymbolEntry();
  if (mapEntry == (SymbolEntry *)0)
    return;
  EquateSymbol *sym = dynamic_cast<EquateSymbol *>(mapEntry->getSymbol());
  if (sym == (EquateSymbol *) 0)
    return;
  if (sym->isValueClose(loc.getOffset(), size)) {
    copySymbol(vn);	// Propagate the markup into our new constant
  }
}

/// Compare two Varnodes
///    - First by storage location
///    - Second by size
///    - Then by defining PcodeOp SeqNum if appropriate
///
/// \e Input Varnodes come before \e written Varnodes
/// \e Free Varnodes come after everything else
/// \param op2 is the Varnode to compare \b this to
/// \return \b true if \b this is less than \b op2
bool Varnode::operator<(const Varnode &op2) const

{
  uint4 f1,f2;

  if (loc != op2.loc) return (loc < op2.loc);
  if (size != op2.size) return (size < op2.size);
  f1 = flags&(Varnode::input|Varnode::written);
  f2 = op2.flags&(Varnode::input|Varnode::written);
  if (f1!=f2) return ((f1-1)<(f2-1)); // -1 forces free varnodes to come last
  if (f1==Varnode::written)
    if (def->getSeqNum() != op2.def->getSeqNum())
      return (def->getSeqNum() < op2.def->getSeqNum());
  return false;
}

/// Determine if two Varnodes are equivalent.  They must match
///    - Storage location
///    - Size
///    - Defining PcodeOp if it exists
///
/// \param op2 is the Varnode to compare \b this to
/// \return true if they are equivalent
bool Varnode::operator==(const Varnode &op2) const

{				// Compare two varnodes
  uint4 f1,f2;

  if (loc != op2.loc) return false;
  if (size != op2.size) return false;
  f1 = flags&(Varnode::input|Varnode::written);
  f2 = op2.flags&(Varnode::input|Varnode::written);
  if (f1!=f2) return false;
  if (f1==Varnode::written)
    if (def->getSeqNum() != op2.def->getSeqNum()) return false;
  
  return true;
}

/// This is the constructor for making an unmanaged Varnode
/// It creates a \b free Varnode with possibly a Datatype attribute.
/// Most applications create Varnodes through the Funcdata interface
/// \param s is the size of the new Varnode
/// \param m is the starting storage Address
/// \param dt is the Datatype
Varnode::Varnode(int4 s,const Address &m,Datatype *dt)
  : loc(m)
{				// Construct a varnode
  size = s;
  def = (PcodeOp *)0;		// No defining op yet
  type = dt;
  high = (HighVariable *)0;
  mapentry = (SymbolEntry *)0;
  consumed = ~((uintb)0);
  cover = (Cover *)0;
  mergegroup = 0;
  addlflags = 0;
  if (m.getSpace() == (AddrSpace *)0) {
    flags = 0;
    return;
  }
  spacetype tp = m.getSpace()->getType();
  if (tp==IPTR_CONSTANT) {
    flags = Varnode::constant;
    nzm = m.getOffset();
  }
  else if ((tp==IPTR_FSPEC)||(tp==IPTR_IOP)) {
    flags = Varnode::annotation|Varnode::coverdirty;
    nzm = ~((uintb)0);
  }
  else {
    flags = Varnode::coverdirty;
    nzm = ~((uintb)0);
  }
}

/// Delete the Varnode object. This routine assumes all other cross-references have been removed.
Varnode::~Varnode(void)

{
  if (cover != (Cover *)0)
    delete cover;
  if (high != (HighVariable *)0) {
    high->remove(this);
    if (high->isUnattached())
      delete high;
  }
}

/// This is a convenience method for quickly finding the unique PcodeOp that reads this Varnode
/// \return only descendant (if there is 1 and ONLY 1) or \b null otherwise
PcodeOp *Varnode::loneDescend(void) const

{
  PcodeOp *op;

  if (descend.empty()) return (PcodeOp *)0; // No descendants

  list<PcodeOp *>::const_iterator iter;

  iter = descend.begin();
  op = *iter++;			// First descendant
  if (iter != descend.end()) return (PcodeOp *)0; // More than 1 descendant
  return op;
}

/// A Varnode can be defined as "coming into scope" at the Address of the first PcodeOp that
/// writes to that storage location.  Within SSA form this \b first-use address always exists and
/// is unique if we consider inputs to come into scope at the start Address of the function they are in
/// \param fd is the Funcdata containing the tree
/// \return the first-use Address
Address Varnode::getUsePoint(const Funcdata &fd) const

{
  if (isWritten())
    return def->getAddr();
  return fd.getAddress()+-1;
  //  return loc.getSpace()->getTrans()->constant(0);
}

/// Print to the stream either the name of the Varnode, such as a register name, if it exists
/// or print a shortcut character representing the AddrSpace and a hex representation of the offset.
/// This function also computes and returns the \e expected size of the identifier it prints
/// to facilitate the printing of size modifiers by other print routines
/// \param s is the output stream
/// \return the expected size
int4 Varnode::printRawNoMarkup(ostream &s) const

{
  AddrSpace *spc = loc.getSpace();
  const Translate *trans = spc->getTrans();
  string name;
  int4 expect;

  name = trans->getRegisterName(spc,loc.getOffset(),size);
  if (name.size()!=0) {
    const VarnodeData &point(trans->getRegister(name));
    uintb off = loc.getOffset()-point.offset;
    s << name;
    expect = point.size;
    if (off != 0)
      s << '+' << dec << off;
  }
  else {
    s << loc.getShortcut();	// Print type shortcut character
    expect = trans->getDefaultSize();
    loc.printRaw(s);
  }
  return expect;
}

/// Print textual information about this Varnode including a base identifier along with enough
/// size and attribute information to uniquely identify the Varnode within a text SSA listing
/// In particular, the identifiers have either "i" or defining op SeqNum information appended
/// to them in parantheses.
/// \param s is the output stream
void Varnode::printRaw(ostream &s) const

{
  int4 expect = printRawNoMarkup(s);

  if (expect != size)
    s << ':' << setw(1) << size;
  if ((flags&Varnode::input)!=0)
    s << "(i)";
  if (isWritten())
    s << '(' << def->getSeqNum() << ')';
  if ((flags&(Varnode::insert|Varnode::constant))==0) {
    s << "(free)";
    return;
  }
}

/// Recursively print a terse textual representation of the data-flow (SSA) tree rooted at this Varnode
/// \param s is the output stream
/// \param depth is the current depth of the tree we are at
void Varnode::printRawHeritage(ostream &s,int4 depth) const

{
  for(int4 i=0;i<depth;++i)
    s << ' ';

  if (isConstant()) {
    printRaw(s);
    s << endl;
    return;
  }
  printRaw(s);
  s << ' ';
  if (def != (PcodeOp *)0)
    def->printRaw(s);
  else
    printRaw(s);

  if ((flags & Varnode::input)!=0)
    s << " Input";
  if ((flags & Varnode::constant)!=0)
    s << " Constant";
  if ((flags & Varnode::annotation)!=0)
    s << " Code";

  if (def != (PcodeOp *)0) {
    s << "\t\t" << def->getSeqNum() << endl;
    for(int4 i=0;i<def->numInput();++i)
      def->getIn(i)->printRawHeritage(s,depth+5);
  }
  else 
    s << endl;
}

/// If \b this is a constant, or is extended (INT_ZEXT,INT_SEXT) from a constant,
/// the \e value of the constant is passed back and a non-negative integer is returned, either:
///   - 0 for a normal constant Varnode
///   - 1 for a zero extension (INT_ZEXT) of a normal constant
///   - 2 for a sign extension (INT_SEXT) of a normal constant
/// \param val is a reference to the constant value that is passed back
/// \return the extension code (or -1 if \b this cannot be interpreted as a constant)
int4 Varnode::isConstantExtended(uintb &val) const

{
  if (isConstant()) {
    val = getOffset();
    return 0;
  }
  if (!isWritten()) return -1;
  OpCode opc = def->code();
  if (opc == CPUI_INT_ZEXT) {
    Varnode *vn0 = def->getIn(0);
    if (vn0->isConstant()) {
      val = vn0->getOffset();
      return 1;
    }
  }
  else if (opc == CPUI_INT_SEXT) {
    Varnode *vn0 = def->getIn(0);
    if (vn0->isConstant()) {
      val = vn0->getOffset();
      return 2;
    }
  }
  return -1;
}

/// Make an initial determination of the Datatype of this Varnode. If a Datatype is already
/// set and locked return it. Otherwise look through all the read PcodeOps and the write PcodeOp
/// to determine if the Varnode is getting used as an \b int, \b float, or \b pointer, etc.
/// Throw an exception if no Datatype can be found at all.
/// \return the determined Datatype
Datatype *Varnode::getLocalType(void) const

{
  Datatype *ct;
  Datatype *newct;

  if (isTypeLock())			// Our type is locked, don't change
    return type;		// Not a partial lock, return the locked type

  ct = (Datatype *)0;
  if (def != (PcodeOp *)0)
    ct = def->outputTypeLocal();

  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  int4 i;
  for(iter=descend.begin();iter!=descend.end();++iter) {
    op = *iter;
    i = op->getSlot(this);
    newct = op->inputTypeLocal(i);

    if (ct == (Datatype *)0)
      ct = newct;
    else {
      if (0>newct->typeOrder(*ct))
	ct = newct;
    }
  }
  if (ct == (Datatype *)0)
    throw LowlevelError("NULL local type");
  return ct;
}

/// Make a local determination if \b this and \b op2 hold the same value. We check if
/// there is a common ancester for which both \b this and \b op2 are created from a direct
/// sequence of COPY operations. NOTE: This is a transitive relationship
/// \param op2 is the Varnode to compare to \b this
/// \return \b true if the Varnodes are copied from a common ancestor
bool Varnode::copyShadow(const Varnode *op2) const

{
  const Varnode *vn;

  if (this==op2) return true;
				// Trace -this- to the source of the copy chain
  vn = this;
  while( (vn->isWritten()) && (vn->getDef()->code() == CPUI_COPY)) {
    vn = vn->getDef()->getIn(0);
    if (vn == op2) return true;	// If we hit op2 then this and op2 must be the same
  }
				// Trace op2 to the source of copy chain
  while( (op2->isWritten()) && (op2->getDef()->code() == CPUI_COPY)) {
    op2 = op2->getDef()->getIn(0);
    if (vn == op2) return true;	// If the source is the same then this and op2 are same
  }
  return false;
}

/// Compare term order of two Varnodes. Used in Term Rewriting strategies to order operands of commutative ops
/// \param op is the Varnode to order against \b this
/// \return -1 if \b this comes before \b op, 1 if op before this, or 0
int4 Varnode::termOrder(const Varnode *op) const

{
  if (isConstant()) {
    if (!op->isConstant()) return 1;
  }
  else {
    if (op->isConstant()) return -1;
    const Varnode *vn = this;
    if (vn->isWritten()&&(vn->getDef()->code() == CPUI_INT_MULT))
      if (vn->getDef()->getIn(1)->isConstant())
	vn = vn->getDef()->getIn(0);
    if (op->isWritten()&&(op->getDef()->code() == CPUI_INT_MULT))
      if (op->getDef()->getIn(1)->isConstant())
	op = op->getDef()->getIn(0);
    
    if (vn->getAddr() < op->getAddr()) return -1;
    if (op->getAddr() < vn->getAddr()) return 1;
  }
  return 0;
}

/// Write an XML tag, \b \<addr>, with at least the following attributes:
///   - \b space describes the AddrSpace
///   - \b offset of the Varnode within the space
///   - \b size of the Varnode is bytes
///
/// Additionally the tag will contain other optional attributes.
/// \param s is the stream to write the tag to
void Varnode::saveXml(ostream &s) const

{
  s << "<addr";
  loc.getSpace()->saveXmlAttributes(s,loc.getOffset(),size);
  a_v_u(s,"ref",getCreateIndex());
  if (mergegroup != 0)
    a_v_i(s,"grp",getMergeGroup());
  if (isPersist())
    s << " persists=\"true\"";
  if (isAddrTied())
    s << " addrtied=\"true\"";
  if (isUnaffected())
    s << " unaff=\"true\"";
  if (isInput())
    s << " input=\"true\"";
  s << "/>";
}

/// Invoke the printRaw method on the given Varnode pointer, but take into account that it
/// might be null.
/// \param s is the output stream to write to
/// \param vn is the given Varnode pointer (may be null)
void Varnode::printRaw(ostream &s,const Varnode *vn)

{
  if (vn == (const Varnode *)0) {
    s << "<null>";
    return;
  }
  vn->printRaw(s);
}

/// \param m is the underlying address space manager
/// \param uspace is the \e unique space
/// \param ubase is the base offset for allocating temporaries
VarnodeBank::VarnodeBank(AddrSpaceManager *m,AddrSpace *uspace,uintm ubase)
  : searchvn(0,Address(Address::m_minimal),(Datatype *)0)

{
  manage = m;
  searchvn.flags = Varnode::input; // searchvn is always an input varnode of size 0
  uniq_space = uspace;
  uniqbase = ubase;
  uniqid = ubase;
  create_index = 0;
}

void VarnodeBank::clear(void)

{
  VarnodeLocSet::iterator iter;

  for(iter=loc_tree.begin();iter!=loc_tree.end();++iter)
    delete *iter;

  loc_tree.clear();
  def_tree.clear();
  uniqid = uniqbase;		// Reset counter to base value
  create_index = 0;		// Reset varnode creation index
}

/// The Varnode is created and inserted into the maps as \e free: not
/// defined as the output of a p-code op or the input to a function.
/// \param s is the size of the Varnode in bytes
/// \param m is the starting address
/// \param ct is the data-type of the new varnode (must not be NULL)
/// \return the newly allocated Varnode object
Varnode *VarnodeBank::create(int4 s,const Address &m,Datatype *ct)

{
  Varnode *vn = new Varnode(s,m,ct);
  
  vn->create_index = create_index++;
  vn->lociter = loc_tree.insert(vn).first; // Frees can always be inserted without duplication
  vn->defiter = def_tree.insert(vn).first;
  return vn;
}

/// The Varnode is allocated in the \e unique space and automatically
/// assigned an offset.  The Varnode is initially \e free.
/// \param s is the size of the Varnode in bytes
/// \param ct is the data-type to assign (must not be NULL)
Varnode *VarnodeBank::createUnique(int4 s,Datatype *ct)

{
  Address addr(uniq_space,uniqid); // Generate a unique address
  uniqid += s;			// Update counter for next call
  return create(s,addr,ct);	// Build varnode with our generated address
}

/// The Varnode object is removed from the sorted lists and
/// its memory reclaimed
/// \param vn is the Varnode to remove
void VarnodeBank::destroy(Varnode *vn)

{
  if ((vn->getDef() != (PcodeOp *)0)||(!vn->hasNoDescend()))
    throw LowlevelError("Deleting integrated varnode");

  loc_tree.erase(vn->lociter);
  def_tree.erase(vn->defiter);
  delete vn;
}

/// Enter the Varnode into both the \e location and \e definition based trees.
/// Update the Varnode iterators and flags
/// \param vn is the Varnode object to insert
/// \return the inserted object, which may not be the same as the input Varnode
Varnode *VarnodeBank::xref(Varnode *vn)

{
  pair<VarnodeLocSet::iterator,bool> check;
  Varnode *othervn;

  check = loc_tree.insert( vn );
  if (!check.second) {		// Set already contains this varnode
    othervn = *(check.first);
    replace(vn,othervn); // Patch ops using the old varnode
    delete vn;
    return othervn;
  }
				// Otherwise a new insertion
  vn->lociter = check.first;
  vn->setFlags(Varnode::insert);
  vn->defiter = def_tree.insert(vn).first; // Insertion should also be new in def_tree

  return vn;
}

/// The Varnode is removed from the cross-referencing lists and reinserted as
/// as if it were not defined by any PcodeOp and not an input to the function.
/// If the Varnode was originally a PcodeOp output, this must be explicitly cleared.
/// \param vn is the Varnode to modify
void VarnodeBank::makeFree(Varnode *vn)

{
  loc_tree.erase(vn->lociter);
  def_tree.erase(vn->defiter);

  vn->setDef((PcodeOp *)0);	// Clear things that make vn non-free
  vn->clearFlags(Varnode::insert|Varnode::input|Varnode::indirect_creation);

  vn->lociter = loc_tree.insert(vn).first; // Re-insert as free varnode
  vn->defiter = def_tree.insert(vn).first;
}

/// Any PcodeOps that read \b oldvn are changed to read \b newvn
/// \param oldvn is the old Varnode
/// \param newvn is the Varnode to replace it with
void VarnodeBank::replace(Varnode *oldvn,Varnode *newvn)

{
  list<PcodeOp *>::iterator iter,tmpiter;
  PcodeOp *op;
  int4 i;

  iter = oldvn->descend.begin();
  while(iter!=oldvn->descend.end()) {
    op = *iter;
    tmpiter = iter++;
    if (op->output == newvn) continue; // Cannot be input to your own definition
    i = op->getSlot(oldvn);
    oldvn->descend.erase(tmpiter);	// Sever the link fully
    op->clearInput(i); // Before attempting to build the new link
    newvn->addDescend(op);
    op->setInput(newvn,i); // This must be called AFTER descend is updated
  }
  oldvn->setFlags(Varnode::coverdirty);
  newvn->setFlags(Varnode::coverdirty);
}

/// Define the Varnode as an input formally; it is no longer considered \e free.
/// Its position in the cross-referencing lists will change
/// \param vn is the Varnode to mark
/// \return the modified Varnode, which be a different object than the original
Varnode *VarnodeBank::setInput(Varnode *vn)

{
  if (!vn->isFree())
    throw LowlevelError("Making input out of varnode which is not free");
  if (vn->isConstant())
    throw LowlevelError("Making input out of constant varnode");

  loc_tree.erase(vn->lociter);	// Erase the free version of varnode
  def_tree.erase(vn->defiter);

  vn->setInput();		// Set the input flag
  return xref(vn);
}

/// The Varnode must initially be \e free. It will be removed
/// from the cross-referencing lists and reinserted as if its were
/// the output of the given PcodeOp.  It still must be explicitly set
/// as the output.
/// \param vn is the Varnode to modify
/// \param op is the given PcodeOp
/// \return the modified Varnode, which may be a different object than the original
Varnode *VarnodeBank::setDef(Varnode *vn,PcodeOp *op)

{
  if (!vn->isFree()) {
    ostringstream s;
    const Address &addr(op->getAddr());
    s << "Defining varnode which is not free at " << addr.getShortcut();
    addr.printRaw(s);
    throw LowlevelError(s.str());
  }
  if (vn->isConstant()) {
    ostringstream s;
    const Address &addr(op->getAddr());
    s << "Assignment to constant at " << addr.getShortcut();
    addr.printRaw(s);
    throw LowlevelError(s.str());
  }

  loc_tree.erase(vn->lociter);
  def_tree.erase(vn->defiter);

  vn->setDef(op);		// Change the varnode to be defined
  return xref(vn);
}

/// The new Varnode object will already be put in the \e definition list as if
/// it were the output of the given PcodeOp. The Varnode must still be set as the output.
/// \param s is the size in bytes
/// \param m is the starting address
/// \param ct is the data-type to associate
/// \param op is the given PcodeOp
Varnode *VarnodeBank::createDef(int4 s,const Address &m, Datatype *ct,PcodeOp *op)

{
  Varnode *vn = new Varnode(s,m,ct);
  vn->create_index = create_index++;
  vn->setDef(op);
  return xref(vn);
}

/// The new Varnode will be assigned from the \e unique space, and
/// it will already be put in the \e definition list as if
/// it were the output of the given PcodeOp. The Varnode must still be set as the output.
/// \param s is the size in bytes
/// \param ct is the data-type to associate
/// \param op is the given PcodeOp
Varnode *VarnodeBank::createDefUnique(int4 s,Datatype *ct,PcodeOp *op)

{ // Create unique varnode as output of op
  Address addr(uniq_space,uniqid);
  uniqid += s;
  return createDef(s,addr,ct,op);
}

/// Find a Varnode given its (loc,size) and the address where it is defined.
/// \param s is the size of the Varnode
/// \param loc is its starting address
/// \param pc is the address where it is defined
/// \param uniq is the sequence number or -1 if not specified
/// \return the matching Varnode or NULL
Varnode *VarnodeBank::find(int4 s,const Address &loc,const Address &pc,uintm uniq) const

{
  VarnodeLocSet::const_iterator iter;
  Varnode *vn;
  PcodeOp *op;

  iter = beginLoc(s,loc,pc,uniq);
  while(iter != loc_tree.end()) {
    vn = *iter;
    if (vn->getSize() != s) break;
    if (vn->getAddr() != loc) break;
    op = vn->getDef();
    if ((op!=(PcodeOp *)0)&&(op->getAddr() == pc)) {
      if ((uniq==~((uintm)0))||(op->getTime()==uniq)) return vn;
    }
    ++iter;
  }
  return (Varnode *)0;
}

/// Find a Varnode marked as a function input given its size and address
/// \param s is the size
/// \param loc is the starting address
/// \return the match Varnode object or NULL
Varnode *VarnodeBank::findInput(int4 s,const Address &loc) const

{
  VarnodeLocSet::const_iterator iter;
  Varnode *vn;

  iter = beginLoc(s,loc,Varnode::input);
  if (iter != loc_tree.end()) {	// There is only one possible varnode matching this
    vn = *iter;
    if (vn->isInput() && (vn->getSize()==s) && (vn->getAddr()==loc))
      return vn;
  }
  return (Varnode *)0;
}

/// Find the first Varnode completely contained within the given range, which is
/// also marked as a function input.
/// \param s is the size of the range
/// \param loc is the starting address of the range
/// \return the Varnode object or NULL if no Varnode met the conditions
Varnode *VarnodeBank::findCoveredInput(int4 s,const Address &loc) const

{
  VarnodeDefSet::const_iterator iter,enditer;
  Varnode *vn;
  uintb highest = loc.getSpace()->getHighest();
  uintb end = loc.getOffset() + s - 1;

  iter = beginDef(Varnode::input,loc);
  if (end==highest) {	// Check for wrap around of address
    Address tmp(loc.getSpace(),highest);
    enditer = endDef(Varnode::input,tmp);
  }
  else
    enditer = beginDef(Varnode::input,loc+s);

  while(iter!=enditer) {
    vn = *iter++;		// we know vn is input with vn->Loc in (loc,loc+s)
    if (vn->getOffset()+vn->getSize()-1 <= end) // vn is completely contained
      return vn;
  }
  return (Varnode *)0;
}

/// Search for the Varnode that completely contains the given range and is marked
/// as an input to the function. If it exists, it is unique.
/// \param s is the size of the range
/// \param loc is the starting address of the range
Varnode *VarnodeBank::findCoveringInput(int4 s,const Address &loc) const

{
  VarnodeDefSet::const_iterator iter;
  Varnode *vn;
  iter = beginDef(Varnode::input,loc);
  if (iter != def_tree.end()) {
    vn = *iter;
    if ((vn->getAddr() != loc)&&(iter!=def_tree.begin())) {
      --iter;
      vn = *iter;
    }
    if (vn->isInput() && (vn->getSpace() == loc.getSpace()) &&
	(vn->getOffset() <= loc.getOffset()) &&
	(vn->getOffset() + vn->getSize()-1 >= loc.getOffset() + s -1))
      return vn;
  }
  return (Varnode *)0;
}

/// \brief Beginning of Varnodes in given address space sorted by location
///
/// \param spaceid is the given address space
/// \return the beginning iterator
VarnodeLocSet::const_iterator VarnodeBank::beginLoc(AddrSpace *spaceid) const

{
  searchvn.loc = Address(spaceid,0);
  return loc_tree.lower_bound(&searchvn);
}

/// \brief Ending of Varnodes in given address space sorted by location
///
/// \param spaceid is the given address space
/// \return the ending iterator
VarnodeLocSet::const_iterator VarnodeBank::endLoc(AddrSpace *spaceid) const

{
  searchvn.loc = Address(manage->getNextSpaceInOrder(spaceid),0);
  return loc_tree.lower_bound(&searchvn);
}

/// \brief Beginning of Varnodes starting at a given address sorted by location
///
/// \param addr is the given starting address
/// \return the beginning iterator
VarnodeLocSet::const_iterator VarnodeBank::beginLoc(const Address &addr) const

{
  searchvn.loc = addr;
  return loc_tree.lower_bound(&searchvn);
}

/// \brief End of Varnodes starting at a given address sorted by location
///
/// \param addr is the given starting address
/// \return the ending iterator
VarnodeLocSet::const_iterator VarnodeBank::endLoc(const Address &addr) const

{
  if (addr.getOffset() == addr.getSpace()->getHighest()) {
    AddrSpace* space = addr.getSpace();
    searchvn.loc = Address(manage->getNextSpaceInOrder(space),0);
  }
  else
    searchvn.loc = addr+1;
  return loc_tree.lower_bound(&searchvn);
}

/// \brief Beginning of Varnodes of given size and starting address sorted by location
///
/// \param s is the given size
/// \param addr is the given starting address
/// \return the beginning iterator
VarnodeLocSet::const_iterator VarnodeBank::beginLoc(int4 s,const Address &addr) const

{
  searchvn.size = s;
  searchvn.loc = addr;
  VarnodeLocSet::const_iterator iter = loc_tree.lower_bound(&searchvn);
  searchvn.size = 0;		// Return size to 0
  return iter;
}

/// \brief End of Varnodes of given size and starting address sorted by location
///
/// \param s is the given size
/// \param addr is the given starting address
/// \return the ending iterator
VarnodeLocSet::const_iterator VarnodeBank::endLoc(int4 s,const Address &addr) const

{
  searchvn.size = s+1;
  searchvn.loc = addr;
  VarnodeLocSet::const_iterator iter = loc_tree.lower_bound(&searchvn);
  searchvn.size = 0;		// Return size to 0
  return iter;
}

/// \brief Beginning of Varnodes sorted by location
///
/// Varnodes are restricted by a given size and location and by the property
///    - Varnode::input for Varnodes that are inputs to the function
///    - Varnode::written for Varnodes that are defined by a PcodeOp
///    - 0 for \e free Varnodes
/// \param s is the given size
/// \param addr is the given starting address
/// \param fl is the property restriction
/// \return the beginning iterator
VarnodeLocSet::const_iterator VarnodeBank::beginLoc(int4 s,const Address &addr,
						    uint4 fl) const
{
  VarnodeLocSet::const_iterator iter;

  if (fl == Varnode::input) {
    searchvn.size = s;
    searchvn.loc = addr;
    iter = loc_tree.lower_bound(&searchvn);
    searchvn.size = 0;
    return iter;
  }
  if (fl == Varnode::written) {
    SeqNum sq(Address::m_minimal); // Minimal sequence number
    PcodeOp searchop(0,sq);
    searchvn.size = s;
    searchvn.loc = addr;
    searchvn.flags = Varnode::written;
    searchvn.def = &searchop;
    iter = loc_tree.lower_bound(&searchvn);
    searchvn.size = 0;
    searchvn.flags = Varnode::input;
    return iter;
  }

  SeqNum sq(Address::m_maximal); // Maximal sequence number
  PcodeOp searchop(0,sq);
  searchvn.size = s;
  searchvn.loc = addr;
  searchvn.flags = Varnode::written;
  searchvn.def = &searchop;
  iter = loc_tree.upper_bound(&searchvn);
  searchvn.size = 0;
  searchvn.flags = Varnode::input;

  return iter;
}

/// \brief End of Varnodes sorted by location
///
/// Varnodes are restricted by a given size and location and by the property
///    - Varnode::input for Varnodes that are inputs to the function
///    - Varnode::written for Varnodes that are defined by a PcodeOp
///    - 0 for \e free Varnodes
/// \param s is the given size
/// \param addr is the given starting address
/// \param fl is the property restriction
/// \return the ending iterator
VarnodeLocSet::const_iterator VarnodeBank::endLoc(int4 s,const Address &addr,
						  uint4 fl) const
{
  VarnodeLocSet::const_iterator iter;
  searchvn.loc = addr;
  
  if (fl == Varnode::written) {
    searchvn.size = s;
    searchvn.flags = Varnode::written;
    SeqNum sq(Address::m_maximal); // Maximal sequence number
    PcodeOp searchop(0,sq);
    searchvn.def = &searchop;
    iter = loc_tree.upper_bound(&searchvn);
    searchvn.size = 0;
    searchvn.flags = Varnode::input;
    return iter;
  }
  else if (fl == Varnode::input) {
    searchvn.size = s;
    iter = loc_tree.upper_bound(&searchvn);
    searchvn.size = 0;
    return iter;
  }

  searchvn.size = s+1;
  iter = loc_tree.lower_bound(&searchvn); // Find following input varnode
  searchvn.size = 0;
  return iter;
}

/// \brief Beginning of Varnodes sorted by location
///
/// Varnodes are restricted by a given size and location and by the
/// sequence number of the PcodeOp defining it
/// \param s is the given size
/// \param addr is the given starting address
/// \param pc is the address of the PcodeOp defining the Varnode
/// \param uniq is the sequence number of the PcodeOp or -1 for now sequence number restriction
/// \return the beginning iterator
VarnodeLocSet::const_iterator VarnodeBank::beginLoc(int4 s,const Address &addr,
						    const Address &pc,uintm uniq) const

{				// Find first varnode of given loc and size
				// defined at a particular location
  VarnodeLocSet::const_iterator iter;
  searchvn.size = s;
  searchvn.loc = addr;
  searchvn.flags = Varnode::written;
  if (uniq==~((uintm)0))	// If don't care about uniq
    uniq = 0;			// find earliest
  SeqNum sq(pc,uniq);
  PcodeOp searchop(0,sq);
  searchvn.def = &searchop;
  iter = loc_tree.lower_bound(&searchvn);

  searchvn.size = 0;
  searchvn.flags = Varnode::input;
  return iter;
}

/// \brief End of Varnodes sorted by location
///
/// Varnodes are restricted by a given size and location and by the
/// sequence number of the PcodeOp defining it
/// \param s is the given size
/// \param addr is the given starting address
/// \param pc is the address of the PcodeOp defining the Varnode
/// \param uniq is the sequence number of the PcodeOp or -1 for now sequence number restriction
/// \return the ending iterator
VarnodeLocSet::const_iterator VarnodeBank::endLoc(int4 s,const Address &addr,
						  const Address &pc,uintm uniq) const

{
  VarnodeLocSet::const_iterator iter;
  searchvn.size = s;
  searchvn.loc = addr;
  searchvn.flags = Varnode::written;
  //  if (uniq==~((uintm)0))
  //    uniq = 0;
  SeqNum sq(pc,uniq);
  PcodeOp searchop(0,sq);
  searchvn.def = &searchop;
  iter = loc_tree.upper_bound(&searchvn);

  searchvn.size = 0;
  searchvn.flags = Varnode::input;
  return iter;
}

/// \brief Beginning of varnodes with set definition property
///
/// Get an iterator to Varnodes in definition order restricted with the
/// following properties:
///    - Varnode::input for Varnodes which are inputs to the function
///    - Varnode::written for Varnodes that are defined by a PcodeOp
///    - 0 for \e free Varnodes
/// \param fl is the property restriction
/// \return the beginning iterator
VarnodeDefSet::const_iterator VarnodeBank::beginDef(uint4 fl) const

{
  VarnodeDefSet::const_iterator iter;

  if (fl == Varnode::input)
    return def_tree.begin();	// Inputs occur first with def_tree
  else if (fl == Varnode::written) {
    searchvn.loc = Address(Address::m_minimal); // Lowest possible location
    searchvn.flags = Varnode::written;
    SeqNum sq(Address::m_minimal); // Lowest possible seqnum
    PcodeOp searchop(0,sq);
    searchvn.def = &searchop;
    iter = def_tree.lower_bound(&searchvn);
    searchvn.flags = Varnode::input; // Reset flags
    return iter;
  }

  // Find the start of the frees
  searchvn.loc = Address(Address::m_maximal); // Maximal possible location
  searchvn.flags = Varnode::written;
  SeqNum sq(Address::m_maximal); // Maximal seqnum
  PcodeOp searchop(0,sq);
  searchvn.def = &searchop;
  iter = def_tree.upper_bound(&searchvn);
  searchvn.flags = Varnode::input; // Reset flags
  return iter;
}

/// \brief End of varnodes with set definition property
///
/// Get an iterator to Varnodes in definition order restricted with the
/// following properties:
///    - Varnode::input for Varnodes which are inputs to the function
///    - Varnode::written for Varnodes that are defined by a PcodeOp
///    - 0 for \e free Varnodes
/// \param fl is the property restriction
/// \return the ending iterator
VarnodeDefSet::const_iterator VarnodeBank::endDef(uint4 fl) const

{
  VarnodeDefSet::const_iterator iter;

  if (fl == Varnode::input) {	// Highest input is lowest written
    searchvn.loc = Address(Address::m_minimal); // Lowest possible location
    searchvn.flags = Varnode::written;
    SeqNum sq(Address::m_minimal); // Lowest possible seqnum
    PcodeOp searchop(0,sq);
    searchvn.def = &searchop;
    iter = def_tree.lower_bound(&searchvn);
    searchvn.flags = Varnode::input; // Reset flags
    return iter;
  }
  else if (fl == Varnode::written) { // Highest written
    searchvn.loc = Address(Address::m_maximal); // Maximal possible location
    searchvn.flags = Varnode::written;
    SeqNum sq(Address::m_maximal); // Maximal seqnum
    PcodeOp searchop(0,sq);
    searchvn.def = &searchop;
    iter = def_tree.upper_bound(&searchvn);
    searchvn.flags = Varnode::input; // Reset flags
    return iter;
  }
  return def_tree.end();	// Highest free is end of def_tree
}

/// \brief Beginning of varnodes starting at a given address with a set definition property
///
/// Get an iterator to Varnodes in definition order.  The starting address of the Varnodes
/// must match the given address, and they are further restricted by the
/// following properties:
///    - Varnode::input for Varnodes which are inputs to the function
///    - Varnode::written for Varnodes that are defined by a PcodeOp
///    - 0 for \e free Varnodes
/// \param fl is the property restriction
/// \param addr is the given starting address
/// \return the beginning iterator
VarnodeDefSet::const_iterator VarnodeBank::beginDef(uint4 fl,const Address &addr) const

{				// Get varnodes with addr and with definition type
  VarnodeDefSet::const_iterator iter;

  if (fl == Varnode::written)
    throw LowlevelError("Cannot get contiguous written AND addressed");
  else if (fl == Varnode::input) {
    searchvn.loc = addr;
    iter = def_tree.lower_bound(&searchvn);
    return iter;
  }

  // Find the start of the frees with a given address
  searchvn.loc = addr;
  searchvn.flags = 0;
				// Since a size 0 object shouldn't exist, an upper bound
				// should bump up to first free of addr with non-zero size
  iter = def_tree.upper_bound(&searchvn);
  searchvn.flags = Varnode::input; // Reset flags
  return iter;
}

/// \brief End of varnodes starting at a given address with a set definition property
///
/// Get an iterator to Varnodes in definition order.  The starting address of the Varnodes
/// must match the given address, and they are further restricted by the
/// following properties:
///    - Varnode::input for Varnodes which are inputs to the function
///    - Varnode::written for Varnodes that are defined by a PcodeOp
///    - 0 for \e free Varnodes
/// \param fl is the property restriction
/// \param addr is the given starting address
/// \return the ending iterator
VarnodeDefSet::const_iterator VarnodeBank::endDef(uint4 fl,const Address &addr) const

{
  VarnodeDefSet::const_iterator iter;

  if (fl == Varnode::written)
    throw LowlevelError("Cannot get contiguous written AND addressed");
  else if (fl == Varnode::input) {
    searchvn.loc = addr;
    searchvn.size = 1000000;
    iter = def_tree.lower_bound(&searchvn);
    searchvn.size = 0;
    return iter;
  }

  // Find the start of the frees with a given address
  searchvn.loc = addr;
  searchvn.size = 1000000;
  searchvn.flags = 0;
				// Since a size 0 object shouldn't exist, an upper bound
				// should bump up to first free of addr with non-zero size
  iter = def_tree.lower_bound(&searchvn);
  searchvn.flags = Varnode::input; // Reset flags
  searchvn.size = 0;
  return iter;
}

#ifdef VARBANK_DEBUG
/// Check tree order is still accurate
void VarnodeBank::verifyIntegrity(void) const

{
  VarnodeLocSet::iterator iter;
  Varnode *vn,*lastvn;

  if (loc_tree.empty()) return;
  iter = loc_tree.begin();
  lastvn = *iter++;
  if (def_tree.end() == def_tree.find(lastvn))
    throw LowlevelError("Varbank first loc missing in def");
  for(;iter!=loc_tree.end();++iter) {
    vn = *iter;
    if (def_tree.end() == def_tree.find(vn))
      throw LowlevelError("Varbank loc missing in def");
    if (*vn < *lastvn)
      throw LowlevelError("Varbank locdef integrity test failed");
    lastvn = vn;
  }

  VarnodeDefSet::iterator diter;
  VarnodeCompareDefLoc cmp;

  diter = def_tree.begin();
  lastvn = *diter++;
  if (loc_tree.end() == loc_tree.find(lastvn))
    throw LowlevelError("Varbank first def missing in loc");
  for(;diter!=def_tree.end();++diter) {
    vn = *diter;
    if (loc_tree.end() == loc_tree.find(vn))
      throw LowlevelError("Varbank def missing in loc");
    if (cmp(vn,lastvn))
      throw LowlevelError("Varbank defloc integrity test failed");
    lastvn = vn;
  }
}
#endif

/// Return true if \b vn1 contains the high part and \b vn2 the low part
/// of what was(is) a single value.
/// \param vn1 is the putative high Varnode
/// \param vn2 is the putative low Varnode
/// \return \b true if they are pieces of a whole
bool contiguous_test(Varnode *vn1,Varnode *vn2)

{
  if (vn1->isInput()||vn2->isInput()) {
    return false;
  }
  if ((!vn1->isWritten())||(!vn2->isWritten())) return false;
  PcodeOp *op1 = vn1->getDef();
  PcodeOp *op2 = vn2->getDef();
  Varnode *vnwhole;
  switch(op1->code()) {
  case CPUI_SUBPIECE:
    if (op2->code() != CPUI_SUBPIECE) return false;
    vnwhole = op1->getIn(0);
    if (op2->getIn(0) != vnwhole) return false;
    if (op2->getIn(1)->getOffset() != 0) 
      return false;		// Must be least sig
    if (op1->getIn(1)->getOffset() != vn2->getSize())
      return false;		// Must be contiguous
    return true;
  default:
    return false;
  }
}

/// Assuming vn1,vn2 has passed the contiguous_test(), return
/// the Varnode containing the whole value.
/// \param data is the underlying function
/// \param vn1 is the high Varnode
/// \param vn2 is the low Varnode
/// \return the whole Varnode
Varnode *findContiguousWhole(Funcdata &data,Varnode *vn1,Varnode *vn2)

{  if (vn1->isWritten())
    if (vn1->getDef()->code() == CPUI_SUBPIECE)
      return vn1->getDef()->getIn(0);
  return (Varnode *)0;
}


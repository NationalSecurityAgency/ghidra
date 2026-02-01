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
/// \file variable.hh
/// \brief Definitions for high-level variables

#ifndef __VARIABLE_HH__
#define __VARIABLE_HH__

#include "varnode.hh"

namespace ghidra {

class Symbol;

extern AttributeId ATTRIB_CLASS;	///< Marshaling attribute "class"
extern AttributeId ATTRIB_REPREF;	///< Marshaling attribute "repref"
extern AttributeId ATTRIB_SYMREF;	///< Marshaling attribute "symref"

extern ElementId ELEM_HIGH;		///< Marshaling element \<high>

class HighVariable;			///< Forward declaration
class VariablePiece;			///< Forward declaration

/// \brief A collection of HighVariable objects that overlap
///
/// A HighVariable represents a variable or partial variable that is manipulated as a unit by the (de)compiler.
/// A formal Symbol may be manipulated using multiple HighVariables that in principal can overlap. For a set of
/// HighVariable objects that mutually overlap, a VariableGroup is a central access point for information about
/// the intersections.  The information is used in particular to extend HighVariable Cover objects to take into
/// account the intersections.
class VariableGroup {
  friend class VariablePiece;

  /// \brief Compare two VariablePiece pointers by offset then by size
  struct PieceCompareByOffset {
    bool operator()(const VariablePiece *a,const VariablePiece *b) const;	///< Comparison operator
  };

  set<VariablePiece *,PieceCompareByOffset> pieceSet;	///< The set of VariablePieces making up \b this group
  int4 size;					///< Number of contiguous bytes covered by the whole group
  int4 symbolOffset;				///< Byte offset of \b this group within its containing Symbol
public:
  VariableGroup(void) { size = 0; symbolOffset = 0; }
  bool empty(void) const { return pieceSet.empty(); }	///< Return \b true if \b this group has no pieces
  void addPiece(VariablePiece *piece);		///< Add a new piece to \b this group
  void adjustOffsets(int4 amt);			///< Adjust offset for every piece by the given amount
  void removePiece(VariablePiece *piece);	///< Remove a piece from \b this group
  int4 getSize(void) const { return size; }	///< Get the number of bytes \b this group covers
  void setSymbolOffset(int4 val) { symbolOffset = val; }	///< Cache the symbol offset for the group
  int4 getSymbolOffset(void) const { return symbolOffset; }	///< Get offset of \b this group within its Symbol
  void combineGroups(VariableGroup *op2);	///< Combine given VariableGroup into \b this
};

/// \brief Information about how a HighVariable fits into a larger group or Symbol
///
/// This is an extension to a HighVariable object that is assigned if the HighVariable is part of a
/// group of mutually overlapping HighVariables. It describes the overlaps and how they affect the HighVariable Cover.
class VariablePiece {
  friend class VariableGroup;
  VariableGroup *group;			///< Group to which \b this piece belongs
  HighVariable *high;			///< HighVariable owning \b this piece
  int4 groupOffset;			///< Byte offset of \b this piece within the group
  int4 size;				///< Number of bytes in \b this piece
  mutable vector<const VariablePiece *> intersection;	///< List of VariablePieces \b this piece intersects with
  mutable Cover cover;			///< Extended cover for the piece, taking into account intersections
public:
  VariablePiece(HighVariable *h,int4 offset,HighVariable *grp=(HighVariable *)0);
  ~VariablePiece(void);			///< Destructor
  HighVariable *getHigh(void) const { return high; }	///< Get the HighVariable associate with \b this piece
  VariableGroup *getGroup(void) const { return group; }	///< Get the central group
  int4 getOffset(void) const { return groupOffset; }	///< Get the offset of \b this within its group
  int4 getSize(void) const { return size; }		///< Return the number of bytes in \b this piece.
  const Cover &getCover(void) const { return cover; }	///< Get the cover associated with \b this piece.
  int4 numIntersection(void) const { return intersection.size(); }	///< Get number of pieces \b this intersects with
  const VariablePiece *getIntersection(int4 i) const { return intersection[i]; }	///< Get i-th piece \b this intersects with
  void markIntersectionDirty(void) const;	///< Mark all pieces as needing intersection recalculation
  void markExtendCoverDirty(void) const;	///< Mark all intersecting pieces as having a dirty extended cover
  void updateIntersections(void) const;	///< Calculate intersections with other pieces in the group
  void updateCover(void) const;	///< Calculate extended cover based on intersections
  void transferGroup(VariableGroup *newGroup);	///< Transfer \b this piece to another VariableGroup
  void setHigh(HighVariable *newHigh) { high = newHigh; }	///< Move ownership of \b this to another HighVariable
  void mergeGroups(VariablePiece *op2,vector<HighVariable *> &mergePairs);	///< Combine two VariableGroups
};

class HighIntersectTest;

/// \brief A high-level variable modeled as a list of low-level variables, each written once
///
/// In the Static Single Assignment (SSA) representation of a function's data-flow, the Varnode
/// object represents a variable node. This is a \b low-level \b variable: it is written to
/// at most once, and there is 1 or more reads.  A \b high-level \b variable, in the source
/// language may be written to multiple times. We model this idea as a list of Varnode objects, where
/// a different Varnode holds the value of the variable for different parts of the code. The range(s)
/// of code for which a single Varnode holds the high-level variable's value is the \b cover or \b range
/// of that Varnode and is modeled by the class Cover.  Within a high-level variable, HighVariable,
/// the covers of member Varnode objects should not intersect, as that represents the variable holding
/// two or more different values at the same place in the code. The HighVariable inherits a cover
/// which is the union of the covers of its Varnodes.
class HighVariable {
public:
  /// \brief Dirtiness flags for a HighVariable
  ///
  /// The HighVariable inherits its Cover, its data-type, and other boolean properties from its Varnodes.
  /// The object holds these explicitly, but the values may become stale as the data-flow transforms.
  /// So we keep track of when these inherited values are \e dirty
  enum {
    flagsdirty = 1,		///< Boolean properties for the HighVariable are dirty
    namerepdirty = 2,		///< The name representative for the HighVariable is dirty
    typedirty = 4,		///< The data-type for the HighVariable is dirty
    coverdirty = 8,		///< The cover for the HighVariable is dirty
    symboldirty = 0x10,		///< The symbol attachment is dirty
    copy_in1 = 0x20,		///< There exists at least 1 COPY into \b this HighVariable from other HighVariables
    copy_in2 = 0x40,		///< There exists at least 2 COPYs into \b this HighVariable from other HighVariables
    type_finalized = 0x80,	///< Set if a final data-type is locked in and dirtying is disabled
    unmerged = 0x100,		///< Set if part of a multi-entry Symbol but did not get merged with other SymbolEntrys
    intersectdirty = 0x200,	///< Set if intersections with other HighVariables needs to be recomputed
    extendcoverdirty = 0x400	///< Set if extended cover needs to be recomputed
  };
private:
  friend class Varnode;
  friend class Merge;
  friend class VariablePiece;
  friend class HighIntersectTest;
  vector<Varnode *> inst;		///< The member Varnode objects making up \b this HighVariable
  int4 numMergeClasses;			///< Number of different speculative merge classes in \b this
  mutable uint4 highflags;		///< Dirtiness flags
  mutable uint4 flags;			///< Boolean properties inherited from Varnode members
  mutable Datatype *type;		///< The data-type for \b this
  mutable Varnode *nameRepresentative;	///< The storage location used to generate a Symbol name
  mutable Cover internalCover;		///< The ranges of code addresses covered by this HighVariable
  mutable VariablePiece *piece;		///< Additional info about intersections with other pieces (if non-null)
  mutable Symbol *symbol;		///< The Symbol \b this HighVariable is tied to
  mutable int4 symboloffset;		///< -1=perfect symbol match >=0, offset
  int4 instanceIndex(const Varnode *vn) const;	///< Find the index of a specific Varnode member
  void updateFlags(void) const;		///< (Re)derive boolean properties of \b this from the member Varnodes
  void updateInternalCover(void) const;	///< (Re)derive the internal cover of \b this from the member Varnodes
  void updateCover(void) const;		///< (Re)derive the external cover of \b this, as a union of internal covers
  void updateType(void) const;		///< (Re)derive the data-type for \b this from the member Varnodes
  void updateSymbol(void) const;	///< (Re)derive the Symbol and offset for \b this from member Varnodes
  void setCopyIn1(void) const { highflags |= copy_in1; }	///< Mark the existence of one COPY into \b this
  void setCopyIn2(void) const { highflags |= copy_in2; }	///< Mark the existence of two COPYs into \b this
  void clearCopyIns(void) const { highflags &= ~(copy_in1 | copy_in2); }	///< Clear marks indicating COPYs into \b this
  bool hasCopyIn1(void) const { return ((highflags&copy_in1)!=0); }	///< Is there at least one COPY into \b this
  bool hasCopyIn2(void) const { return ((highflags&copy_in2)!=0); }	///< Is there at least two COPYs into \b this
  void remove(Varnode *vn);				///< Remove a member Varnode from \b this
  void mergeInternal(HighVariable *tv2,bool isspeculative);	///< Merge another HighVariable into \b this
  void merge(HighVariable *tv2,HighIntersectTest *testCache,bool isspeculative);	///< Merge with another HighVariable taking into account groups
  void setSymbol(Varnode *vn) const;		///< Update Symbol information for \b this from the given member Varnode
  void setSymbolReference(Symbol *sym,int4 off);	///< Attach a reference to a Symbol to \b this
  void transferPiece(HighVariable *tv2);		///< Transfer ownership of another's VariablePiece to \b this
  void flagsDirty(void) const { highflags |= flagsdirty | namerepdirty; }	///< Mark the boolean properties as \e dirty
  void coverDirty(void) const;					///< Mark the cover as \e dirty
  void typeDirty(void) const { highflags |= typedirty; }	///< Mark the data-type as \e dirty
  void symbolDirty(void) const { highflags |= symboldirty; }	///< Mark the symbol as \e dirty
  void setUnmerged(void) const { highflags |= unmerged; }	///< Mark \b this as having merge problems
  bool isCoverDirty(void) const;	///< Is the cover returned by getCover() up-to-date
  void stripType(void) const;		///< Take the stripped form of the current data-type.
public:
  HighVariable(Varnode *vn);		///< Construct a HighVariable with a single member Varnode
  ~HighVariable(void);			///< Destructor
  Datatype *getType(void) const { updateType(); return type; }	///< Get the data-type
  const Cover &getCover(void) const;	///< Get cover data for \b this variable
  Symbol *getSymbol(void) const { updateSymbol(); return symbol; }	///< Get the Symbol associated with \b this or null
  SymbolEntry *getSymbolEntry(void) const;			/// Get the SymbolEntry mapping to \b this or null
  int4 getSymbolOffset(void) const { return symboloffset; }	///< Get the Symbol offset associated with \b this
  int4 numInstances(void) const { return inst.size(); }		///< Get the number of member Varnodes \b this has
  Varnode *getInstance(int4 i) const { return inst[i]; }	///< Get the i-th member Varnode
  void finalizeDatatype(TypeFactory *typeFactory);		///< Set a final data-type matching the associated Symbol
  void groupWith(int4 off,HighVariable *hi2);		///< Put \b this and another HighVariable in the same intersection group
  void establishGroupSymbolOffset(void);	///< Transfer \b symbol offset of \b this to the VariableGroup

  /// \brief Print details of the cover for \b this (for debug purposes)
  ///
  /// \param s is the output stream
  void printCover(ostream &s) const { if ((highflags&HighVariable::coverdirty)==0) internalCover.print(s); else s << "Cover dirty"; }

  void printInfo(ostream &s) const;		///< Print information about \b this HighVariable to stream
  bool hasName(void) const;			///< Check if \b this HighVariable can be named
  Varnode *getTiedVarnode(void) const;		///< Find the first address tied member Varnode
  Varnode *getInputVarnode(void) const;		///< Find (the) input member Varnode
  Varnode *getTypeRepresentative(void) const;	///< Get a member Varnode with the strongest data-type
  Varnode *getNameRepresentative(void) const;	///< Get a member Varnode that dictates the naming of \b this HighVariable
  int4 getNumMergeClasses(void) const { return numMergeClasses; }	///< Get the number of speculative merges for \b this
  bool isMapped(void) const { updateFlags(); return ((flags&Varnode::mapped)!=0); }	///< Return \b true if \b this is mapped
  bool isPersist(void) const { updateFlags(); return ((flags&Varnode::persist)!=0); }	///< Return \b true if \b this is a global variable
  bool isAddrTied(void) const { updateFlags(); return ((flags&Varnode::addrtied)!=0); }	///< Return \b true if \b this is \e address \e ties
  bool isInput(void) const { updateFlags(); return ((flags&Varnode::input)!=0); }	///< Return \b true if \b this is an input variable
  bool isImplied(void) const { updateFlags(); return ((flags&Varnode::implied)!=0); }	///< Return \b true if \b this is an implied variable
  bool isSpacebase(void) const { updateFlags(); return ((flags&Varnode::spacebase)!=0); }	///< Return \b true if \b this is a \e spacebase
  bool isConstant(void) const { updateFlags(); return ((flags&Varnode::constant)!=0); }	///< Return \b true if \b this is a constant
  bool isUnaffected(void) const { updateFlags(); return ((flags&Varnode::unaffected)!=0); }	///< Return \b true if \b this is an \e unaffected register
  bool isExtraOut(void) const { updateFlags(); return ((flags&(Varnode::indirect_creation|Varnode::addrtied))==Varnode::indirect_creation); }	///< Return \b true if \b this is an extra output
  bool isProtoPartial(void) const { updateFlags(); return ((flags&Varnode::proto_partial)!=0); }	///< Return \b true if \b this is a piece concatenated into a larger whole
  void setMark(void) const { flags |= Varnode::mark; }		///< Set the mark on this variable
  void clearMark(void) const { flags &= ~Varnode::mark; }	///< Clear the mark on this variable
  bool isMark(void) const { return ((flags&Varnode::mark)!=0); }	///< Return \b true if \b this is marked
  bool isUnmerged(void) const { return ((highflags&unmerged)!=0); }	///< Return \b true if \b this has merge problems
  bool isSameGroup(const HighVariable *op2) const;	///< Is \b this part of the same VariableGroup as \b op2

  /// \brief Determine if \b this HighVariable has an associated cover.
  ///
  /// Constant and annotation variables do not have a cover
  /// \return \b true if \b this has a cover
  bool hasCover(void) const {
    updateFlags();
    return ((flags&(Varnode::constant|Varnode::annotation|Varnode::insert))==Varnode::insert); }

  bool isUnattached(void) const { return inst.empty(); }	///< Return \b true if \b this has no member Varnode
  bool isTypeLock(void) const { updateType(); return ((flags & Varnode::typelock)!=0); }	///< Return \b true if \b this is \e typelocked
  bool isNameLock(void) const { updateFlags(); return ((flags & Varnode::namelock)!=0); }	///< Return \b true if \b this is \e namelocked
  void encode(Encoder &encoder) const;		///< Encode \b this variable to stream as a \<high> element
#ifdef MERGEMULTI_DEBUG
  void verifyCover(void) const;
#endif
  //  Varnode *findGlobalRep(void) const;
  static bool compareName(Varnode *vn1,Varnode *vn2);	///< Determine which given Varnode is most nameable
  static bool compareJustLoc(const Varnode *a,const Varnode *b);	///< Compare based on storage location
  static int4 markExpression(Varnode *vn,vector<HighVariable *> &highList);	///< Mark and collect variables in expression
};

/// \brief A record for caching a Cover intersection test between two HighVariable objects
///
/// This is just a pair of HighVariable objects that can be used as a map key. The HighIntersectTest
/// class uses it to cache intersection test results between the two variables in a map.
class HighEdge {
  friend class HighIntersectTest;
  HighVariable *a;		///< First HighVariable of the pair
  HighVariable *b;		///< Second HighVariable of the pair
public:
  /// \brief Comparator
  bool operator<(const HighEdge &op2) const { if (a==op2.a) return (b<op2.b); return (a<op2.a); }
  HighEdge(HighVariable *c,HighVariable *d) { a=c; b=d; } ///< Constructor
};

/// \brief A cache of Cover intersection tests for HighVariables
///
/// An test is performed by calling the intersect() method, which returns the result of a full
/// Cover intersection test, taking into account, overlapping pieces, shadow Varnodes etc. The
/// results of the test are cached in \b this object, so repeated calls do not need to perform the
/// full calculation.  The cache examines HighVariable dirtiness flags to determine if its Cover
/// and cached tests are stale.  The Cover can be externally updated, without performing a test,
/// and still keeping the cached tests accurate, by calling the updateHigh() method.  If two HighVariables
/// to be merged, the cached tests can be updated by calling moveIntersectTest() before merging.
class HighIntersectTest {
  PcodeOpSet &affectingOps;		///< PcodeOps that may indirectly affect the intersection test
  map<HighEdge,bool> highedgemap; ///< A cache of intersection tests, sorted by HighVariable pair
  static void gatherBlockVarnodes(HighVariable *a,int4 blk,const Cover &cover,vector<Varnode *> &res);
  static bool testBlockIntersection(HighVariable *a,int4 blk,const Cover &cover,int4 relOff,const vector<Varnode *> &blist);
  bool blockIntersection(HighVariable *a,HighVariable *b,int4 blk);
  void purgeHigh(HighVariable *high); ///< Remove cached intersection tests for a given HighVariable
  bool testUntiedCallIntersection(HighVariable *tied,HighVariable *untied);
public:
  HighIntersectTest(PcodeOpSet &cCover) : affectingOps(cCover) {}	///< Constructor
  void moveIntersectTests(HighVariable *high1,HighVariable *high2);
  bool updateHigh(HighVariable *a); ///< Make sure given HighVariable's Cover is up-to-date
  bool intersection(HighVariable *a,HighVariable *b);
  void clear(void) { highedgemap.clear(); }	///< Clear any cached tests
};

/// The internal cover is marked as dirty. If \b this is a piece of a VariableGroup, it and all the other
/// HighVariables it intersects with are marked as having a dirty extended cover.
inline void HighVariable::coverDirty(void) const

{
  highflags |= coverdirty;
  if (piece != (VariablePiece *)0)
    piece->markExtendCoverDirty();
}

/// The cover could either by the internal one or the extended one if \b this is part of a Variable Group.
/// \return \b true if the cover needs to be recomputed.
inline bool HighVariable::isCoverDirty(void) const

{
  return ((highflags & (coverdirty | extendcoverdirty)) != 0);
}

/// The returns the internal cover unless \b this is part of a VariableGroup, in which case the
/// extended cover is returned.
/// \return the cover associated with \b this variable
inline const Cover &HighVariable::getCover(void) const

{
  if (piece == (VariablePiece *)0)
    return internalCover;
  return piece->getCover();
}

/// Test if the two HighVariables should be pieces of the same symbol.
/// \param op2 is the other HighVariable to compare with \b this
/// \return \b true if they share the same underlying VariableGroup
inline bool HighVariable::isSameGroup(const HighVariable *op2) const

{
  if (piece == (VariablePiece *)0 || op2->piece == (VariablePiece *)0)
    return false;
  return piece->getGroup() == op2->piece->getGroup();
}

} // End namespace ghidra
#endif

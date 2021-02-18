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

#ifndef __CPUI_TYPEVAR__
#define __CPUI_TYPEVAR__

#include "varnode.hh"

class Symbol;

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
    unmerged = 0x100		///< Set if part of a multi-entry Symbol but did not get merged with other SymbolEntrys
  };
private:
  friend class Varnode;
  friend class Merge;
  vector<Varnode *> inst;		///< The member Varnode objects making up \b this HighVariable
  int4 numMergeClasses;			///< Number of different speculative merge classes in \b this
  mutable uint4 highflags;		///< Dirtiness flags
  mutable uint4 flags;			///< Boolean properties inherited from Varnode members
  mutable Datatype *type;		///< The data-type for \b this
  mutable Varnode *nameRepresentative;	///< The storage location used to generate a Symbol name
  mutable Cover wholecover;		///< The ranges of code addresses covered by this HighVariable
  mutable Symbol *symbol;		///< The Symbol \b this HighVariable is tied to
  mutable int4 symboloffset;		///< -1=perfect symbol match >=0, offset
  int4 instanceIndex(const Varnode *vn) const;	///< Find the index of a specific Varnode member
  void updateFlags(void) const;		///< (Re)derive boolean properties of \b this from the member Varnodes
  void updateCover(void) const;		///< (Re)derive the cover of \b this from the member Varnodes
  void updateType(void) const;		///< (Re)derive the data-type for \b this from the member Varnodes
  void updateSymbol(void) const;	///< (Re)derive the Symbol and offset for \b this from member Varnodes
  void setCopyIn1(void) const { highflags |= copy_in1; }	///< Mark the existence of one COPY into \b this
  void setCopyIn2(void) const { highflags |= copy_in2; }	///< Mark the existence of two COPYs into \b this
  void clearCopyIns(void) const { highflags &= ~(copy_in1 | copy_in2); }	///< Clear marks indicating COPYs into \b this
  bool hasCopyIn1(void) const { return ((highflags&copy_in1)!=0); }	///< Is there at least one COPY into \b this
  bool hasCopyIn2(void) const { return ((highflags&copy_in2)!=0); }	///< Is there at least two COPYs into \b this
  void remove(Varnode *vn);				///< Remove a member Varnode from \b this
  void merge(HighVariable *tv2,bool isspeculative);	///< Merge another HighVariable into \b this
  void setSymbol(Varnode *vn) const;		///< Update Symbol information for \b this from the given member Varnode
  void setSymbolReference(Symbol *sym,int4 off);	///< Attach a reference to a Symbol to \b this
  void flagsDirty(void) const { highflags |= flagsdirty | namerepdirty; }	///< Mark the boolean properties as \e dirty
  void coverDirty(void) const { highflags |= coverdirty; }	///< Mark the cover as \e dirty
  void typeDirty(void) const { highflags |= typedirty; }	///< Mark the data-type as \e dirty
  void setUnmerged(void) const { highflags |= unmerged; }	///< Mark \b this as having merge problems
public:
  HighVariable(Varnode *vn);		///< Construct a HighVariable with a single member Varnode
  Datatype *getType(void) const { updateType(); return type; }	///< Get the data-type
  Symbol *getSymbol(void) const { updateSymbol(); return symbol; }	///< Get the Symbol associated with \b this or null
  SymbolEntry *getSymbolEntry(void) const;			/// Get the SymbolEntry mapping to \b this or null
  int4 getSymbolOffset(void) const { return symboloffset; }	///< Get the Symbol offset associated with \b this
  int4 numInstances(void) const { return inst.size(); }		///< Get the number of member Varnodes \b this has
  Varnode *getInstance(int4 i) const { return inst[i]; }	///< Get the i-th member Varnode
  void finalizeDatatype(Datatype *tp);		///< Set a final datatype for \b this variable

  /// \brief Print details of the cover for \b this (for debug purposes)
  ///
  /// \param s is the output stream
  void printCover(ostream &s) const { if ((highflags&HighVariable::coverdirty)==0) wholecover.print(s); else s << "Cover dirty"; }

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
  void setMark(void) const { flags |= Varnode::mark; }		///< Set the mark on this variable
  void clearMark(void) const { flags &= ~Varnode::mark; }	///< Clear the mark on this variable
  bool isMark(void) const { return ((flags&Varnode::mark)!=0); }	///< Return \b true if \b this is marked
  bool isUnmerged(void) const { return ((highflags&unmerged)!=0); }	///< Return \b true if \b this has merge problems

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
  void saveXml(ostream &s) const;		///< Save the variable to stream as an XML \<high\> tag
#ifdef MERGEMULTI_DEBUG
  void verifyCover(void) const;
#endif
  //  Varnode *findGlobalRep(void) const;
  static bool compareName(Varnode *vn1,Varnode *vn2);	///< Determine which given Varnode is most nameable
  static bool compareJustLoc(const Varnode *a,const Varnode *b);	///< Compare based on storage location
  static int4 markExpression(Varnode *vn,vector<HighVariable *> &highList);	///< Mark and collect variables in expression
};

#endif

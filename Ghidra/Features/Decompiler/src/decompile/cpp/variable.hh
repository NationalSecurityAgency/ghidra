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
    typedirty = 2,		///< The data-type for the HighVariable is dirty
    coverdirty = 4		///< The cover for the HighVariable is dirty
  };
private:
  friend class Merge;
  vector<Varnode *> inst;		///< The member Varnode objects making up \b this HighVariable
  int4 numMergeClasses;			///< Number of different speculative merge classes in \b this
  mutable uint4 highflags;		///< Dirtiness flags
  mutable uint4 flags;			///< Boolean properties inherited from Varnode members
  mutable Datatype *type;		///< The data-type for this
  mutable Cover wholecover;		///< The ranges of code addresses covered by this HighVariable
  mutable Symbol *symbol;		///< The Symbol \b this HighVariable is tied to
  mutable int4 symboloffset;		///< -1=perfect symbol match >=0, offset
  int4 instanceIndex(const Varnode *vn) const;	///< Find the index of a specific Varnode member
  void updateFlags(void) const;		///< (Re)derive boolean properties of \b this from the member Varnodes
  void updateCover(void) const;		///< (Re)derive the cover of \b this from the member Varnodes
  void updateType(void) const;		///< (Re)derive the data-type for \b this from the member Varnodes
public:
  HighVariable(Varnode *vn);		///< Construct a HighVariable with a single member Varnode
  Datatype *getType(void) const { updateType(); return type; }	///< Get the data-type

  /// \brief Set the Symbol associated with \b this HighVariable.
  ///
  /// This HighVariable does not need to be associated with the whole symbol. It can be associated with
  /// a part, like a sub-field, if the size of the member Varnodes and the Symbol don't match. In this case
  /// a non-zero offset may be passed in with the Symbol to indicate what part is represented by the \b this.
  /// \param sym is the Symbol to associate with \b this
  /// \param off is the offset in bytes, relative to the Symbol, where \b this HighVariable starts
  void setSymbol(Symbol *sym,int4 off) const {
    symbol = sym; symboloffset = off; }

  Symbol *getSymbol(void) const { return symbol; }		///< Get the Symbol associated with \b this
  int4 getSymbolOffset(void) const { return symboloffset; }	///< Get the Symbol offset associated with \b this
  int4 numInstances(void) const { return inst.size(); }		///< Get the number of member Varnodes \b this has
  Varnode *getInstance(int4 i) const { return inst[i]; }	///< Get the i-th member Varnode
  void flagsDirty(void) const { highflags |= HighVariable::flagsdirty; }	///< Mark the boolean properties as \e dirty
  void coverDirty(void) const { highflags |= HighVariable::coverdirty; }	///< Mark the cover as \e dirty
  void typeDirty(void) const { highflags |= HighVariable::typedirty; }		///< Mark the data-type as \e dirty
  void remove(Varnode *vn);					///< Remove a member Varnode from \b this

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
  void merge(HighVariable *tv2,bool isspeculative);	///< Merge another HighVariable into \b this
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
  //  Varnode *findGlobalRep(void) const;
  static bool compareName(Varnode *vn1,Varnode *vn2);	///< Determine which given Varnode is most nameable
  static bool compareJustLoc(const Varnode *a,const Varnode *b);	///< Compare based on storage location
};

#endif

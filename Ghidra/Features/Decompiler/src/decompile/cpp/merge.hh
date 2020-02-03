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
#ifndef __CPUI_MERGE__
#define __CPUI_MERGE__

/// \file merge.hh
/// \brief Utilities for merging low-level Varnodes into high-level variables

#include "op.hh"

/// \brief A record for caching a Cover intersection test between two HighVariable objects
///
/// This is just a pair of HighVariable objects that can be used as a map key. The main
/// Merge class uses it to cache intersection test results between the two variables in
/// a map.
class HighEdge {
  friend class Merge;
  HighVariable *a;		///< First HighVariable of the pair
  HighVariable *b;		///< Second HighVariable of the pair
public:
  /// \brief Comparator
  bool operator<(const HighEdge &op2) const { if (a==op2.a) return (b<op2.b); return (a<op2.a); }
  HighEdge(HighVariable *c,HighVariable *d) { a=c; b=d; } ///< Constructor
};

/// \brief Helper class associating a Varnode with the block where it is defined
///
/// This class explicitly stores a Varnode with the index of the BlockBasic that defines it.
/// If a Varnode does not have a defining PcodeOp it is assigned an index of 0.
/// This facilitates quicker sorting of Varnodes based on their defining block.
class BlockVarnode {
  int4 index;		///< Index of BlockBasic defining Varnode
  Varnode *vn;		///< The Varnode itself
public:
  void set(Varnode *v);		///< Set \b this as representing the given Varnode
  bool operator<(const BlockVarnode &op2) const { return (index < op2.index); } ///< Comparator
  Varnode *getVarnode(void) const { return vn; } ///< Get the Varnode represented by \b this
  int4 getIndex(void) const { return index; }	 ///< Get the Varnode's defining block index
  static int4 findFront(int4 blocknum,const vector<BlockVarnode> &list);
};

class Funcdata;

/// \brief Class for merging low-level Varnodes into high-level HighVariables
///
/// As a node in Single Static Assignment (SSA) form, a Varnode has at most one defining
/// operation. To get a suitable notion of a single high-level variable (HighVariable) that
/// may be reassigned at multiple places in a single function, individual Varnode objects
/// can be \e merged into a HighVariable object. Varnode objects may be merged in this way
/// if there is no pairwise intersection between each Varnode's Cover, the ranges of code
/// where the Varnode holds its value.
///
/// For a given function, this class attempts to merge Varnodes using various strategies
/// and keeps track of Cover intersections to facilitate the process. Merge strategies break up
/// into two general categories: \b forced merges, and \b speculative merges. Forced merges
/// \e must happen, and extra Varnodes may be added to split up problematic covers to enforce it.
/// Forced merges include:
///    - Merging inputs and outputs of MULTIEQUAL and INDIRECT operations
///    - Merging Varnodes at global (persistent) storage locations
///    - Merging Varnodes at mapped stack locations
///
/// Speculative merges are attempted to reduce the overall number of variables defined by a
/// function, but any given merge attempt is abandoned if there are Cover intersections. No
/// modification is made to the data-flow to force the merge.  Speculative merges include:
///   - Merging an input and output Varnode of a single p-code op
///   - Merging Varnodes that hold the same data-type
class Merge {
  Funcdata &data;		///< The function containing the Varnodes to be merged
  map<HighEdge,bool> highedgemap; ///< A cache of intersection tests, sorted by HighVariable pair
  vector<PcodeOp *> copyTrims;	///< COPY ops inserted to facilitate merges
  bool updateHigh(HighVariable *a); ///< Make sure given HighVariable's Cover is up-to-date
  void purgeHigh(HighVariable *high); ///< Remove cached intersection tests for a given HighVariable
  bool blockIntersection(HighVariable *a,HighVariable *b,int4 blk);
  static bool mergeTestRequired(HighVariable *high_out,HighVariable *high_in);
  static bool mergeTestAdjacent(HighVariable *high_out,HighVariable *high_in);
  static bool mergeTestSpeculative(HighVariable *high_out,HighVariable *high_in);
  static bool mergeTestBasic(Varnode *vn);
  static void findSingleCopy(HighVariable *high,vector<Varnode *> &singlelist);
  static bool compareHighByBlock(const HighVariable *a,const HighVariable *b);
  static bool compareCopyByInVarnode(PcodeOp *op1,PcodeOp *op2);
  static bool shadowedVarnode(const Varnode *vn);
  static void findAllIntoCopies(HighVariable *high,vector<PcodeOp *> &copyIns,bool filterTemps);
  void collectCovering(vector<Varnode *> &vlist,HighVariable *high,PcodeOp *op);
  bool collectCorrectable(const vector<Varnode *> &vlist,list<PcodeOp *> &oplist,vector<int4> &slotlist,
			   PcodeOp *op);
  PcodeOp *allocateCopyTrim(Varnode *inVn,Datatype *ct,const Address &addr);
  void snipReads(Varnode *vn,list<PcodeOp *> &markedop);
  void snipIndirect(PcodeOp *indop);
  void eliminateIntersect(Varnode *vn,const vector<BlockVarnode> &blocksort);
  void unifyAddress(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer);
  void trimOpOutput(PcodeOp *op);
  void trimOpInput(PcodeOp *op,int4 slot);
  void mergeRangeMust(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer);
  void mergeOp(PcodeOp *op);
  void mergeIndirect(PcodeOp *indop);
  void mergeLinear(vector<HighVariable *> &highvec);
  bool merge(HighVariable *high1,HighVariable *high2,bool isspeculative);
  bool checkCopyPair(HighVariable *high,PcodeOp *domOp,PcodeOp *subOp);
  void buildDominantCopy(HighVariable *high,vector<PcodeOp *> &copy,int4 pos,int4 size);
  void markRedundantCopies(HighVariable *high,vector<PcodeOp *> &copy,int4 pos,int4 size);
  void processHighDominantCopy(HighVariable *high);
  void processHighRedundantCopy(HighVariable *high);
public:
  Merge(Funcdata &fd) : data(fd) {} ///< Construct given a specific function
  bool intersection(HighVariable *a,HighVariable *b);
  bool inflateTest(Varnode *a,HighVariable *high);
  void inflate(Varnode *a,HighVariable *high);
  bool mergeTest(HighVariable *high,vector<HighVariable *> &tmplist);

  void mergeOpcode(OpCode opc);
  void mergeByDatatype(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer);
  void mergeAddrTied(void);
  void mergeMarker(void);
  void mergeAdjacent(void);
  void mergeMultiEntry(void);
  bool hideShadows(HighVariable *high);
  void processCopyTrims(void);
  void markInternalCopies(void);
#ifdef MERGEMULTI_DEBUG
  void verifyHighCovers(void);
#endif
};

/// \brief Compare HighVariables by the blocks they cover
///
/// This comparator sorts, based on:
///   - Index of the first block containing cover for the HighVariable
///   - Address of the first instance
///   - Address of the defining p-code op
///   - Storage address
///
/// \param a is the first HighVariable to compare
/// \param b is the second HighVariable
/// \return \b true if the first HighVariable should be ordered before the second
inline bool Merge::compareHighByBlock(const HighVariable *a,const HighVariable *b)

{
  int4 result = a->wholecover.compareTo(b->wholecover);
  if ( result == 0 ) {
    Varnode *v1 = a->getInstance( 0 );
    Varnode *v2 = b->getInstance( 0 );
    
    if ( v1->getAddr() == v2->getAddr() ) {
      PcodeOp *def1 = v1->getDef();
      PcodeOp *def2 = v2->getDef();
      if ( def1 == (PcodeOp *) 0 ) {
	return true;
      }
      else if ( def2 == (PcodeOp *) 0 ) {
	return false;
      }
      return (def1->getAddr() < def2->getAddr());
    }
    return (v1->getAddr() < v2->getAddr());
  }
  return (result < 0);
}

#endif

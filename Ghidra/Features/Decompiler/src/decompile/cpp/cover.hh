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
/// \file cover.hh
/// \brief Classes describing the topological scope of variables within a function
#ifndef __COVER_HH__
#define __COVER_HH__

#include "type.hh"

namespace ghidra {

class PcodeOp;
class FlowBlock;
class Varnode;

/// \brief A set of PcodeOps that can be tested for Cover intersections
///
/// This is a set of PcodeOp objects, designed for quick intersection tests with a Cover.  The set is
/// lazily constructed via its populate() method at the time the first intersection test is needed.
/// Once an intersection has been established between a PcodeOp in \b this set and a Varnode Cover,
/// affectsTest() can do secondary testing to determine if the intersection should prevent merging.
class PcodeOpSet {
  friend class Cover;
  vector<PcodeOp *> opList;		///< Ops in this set, sorted on block index, then SeqNum::order
  vector<int4> blockStart;		///< Index of first op in each non-empty block
  bool is_pop;				///< Has the populate() method been called
protected:
  void addOp(PcodeOp *op) { opList.push_back(op); }	///< Add a PcodeOp into the set
  void finalize(void);			///< Sort ops in the set into blocks
public:
  PcodeOpSet(void) { is_pop = false; }
  bool isPopulated(void) const { return is_pop; }	///< Return \b true if \b this set is populated
  virtual ~PcodeOpSet(void) {}

  /// \brief Populate the PcodeOp object in \b this set
  ///
  /// Call-back to the owner to lazily add PcodeOps to \b this set.  The override method calls addOp() for
  /// each PcodeOp it wants to add, then calls finalize() to make \b this set ready for intersection tests.
  virtual void populate(void)=0;

  /// \brief (Secondary) test that the given PcodeOp affects the Varnode
  ///
  /// This method is called after an intersection of a PcodeOp in \b this set with a Varnode Cover has been
  /// determined.  This allows the owner to make a final determination if merging should be prevented.
  /// \param op is the PcodeOp that intersects with the Varnode Cover
  /// \param vn is the Varnode whose Cover is intersected
  /// \return \b true if merging should be prevented
  virtual bool affectsTest(PcodeOp *op,Varnode *vn) const=0;

  void clear(void) { is_pop = false; opList.clear(); blockStart.clear(); }	///< Clear all PcodeOps in \b this
  static bool compareByBlock(const PcodeOp *a,const PcodeOp *b);	///< Compare PcodeOps for \b this set
};

/// \brief The topological scope of a variable within a basic block
///
/// Within a basic block, the topological scope of a variable can be considered
/// a contiguous range of p-code operations. This range can be described with
/// a \e start and \e stop PcodeOp object, indicating all p-code operations between
/// the two inclusive.  The \e start and \e stop may hold special encodings meaning:
///   - From the beginning of the block
///   - To the end of the block
class CoverBlock {
  const PcodeOp *start;		///< Beginning of the range
  const PcodeOp *stop;		///< End of the range
public:
  CoverBlock(void) { start = (const PcodeOp *)0; stop = (const PcodeOp *)0; }	///< Construct empty/uncovered block
  static uintm getUIndex(const PcodeOp *op);					///< Get the comparison index for a PcodeOp
  const PcodeOp *getStart(void) const { return start; }				///< Get the start of the range
  const PcodeOp *getStop(void) const { return stop; }				///< Get the end of the range
  void clear(void) { start = (const PcodeOp *)0; stop = (const PcodeOp *)0; }	///< Clear \b this block to empty/uncovered
  void setAll(void) {
    start = (const PcodeOp *)0; stop = (const PcodeOp *)1; }			///< Mark whole block as covered
  void setBegin(const PcodeOp *begin) {
    start = begin; if (stop==(const PcodeOp *)0) stop = (const PcodeOp *)1; }	///< Reset start of range
  void setEnd(const PcodeOp *end) { stop = end; }				///< Reset end of range
  int4 intersect(const CoverBlock &op2) const;					///< Compute intersection with another CoverBlock
  bool empty(void) const {
    return ((start==(const PcodeOp *)0)&&(stop==(const PcodeOp *)0)); }		///< Return \b true if \b this is empty/uncovered
  bool contain(const PcodeOp *point) const;					///< Check containment of given point
  int4 boundary(const PcodeOp *point) const;					///< Characterize given point as boundary
  void merge(const CoverBlock &op2);					///< Merge another CoverBlock into \b this
  void print(ostream &s) const;						///< Dump a description to stream
};

/// \brief A description of the topological scope of a single variable object
///
/// The \b topological \b scope of a variable within a function is the set of
/// locations within the code of the function where that variable holds a variable.
/// For the decompiler, a high-level variable in this sense, HighVariable, is a collection
/// of Varnode objects.  In order to merge Varnodes into a HighVariable, the topological
/// scope of each Varnode must not intersect because that would mean the high-level variable
/// holds different values at the same point in the function.
///
/// Internally this is implemented as a map from basic block to their non-empty CoverBlock
class Cover {
  map<int4,CoverBlock> cover; 			///< block index -> CoverBlock
  static const CoverBlock emptyBlock;		///< Global empty CoverBlock for blocks not covered by \b this
  void addRefRecurse(const FlowBlock *bl);	///< Fill-in \b this recursively from the given block
public:
  void clear(void) { cover.clear(); }		///< Clear \b this to an empty Cover
  int4 compareTo(const Cover &op2) const;	///< Give ordering of \b this and another Cover
  const CoverBlock &getCoverBlock(int4 i) const;	///< Get the CoverBlock corresponding to the i-th block
  int4 intersect(const Cover &op2) const;	///< Characterize the intersection between \b this and another Cover.
  int4 intersectByBlock(int4 blk,const Cover &op2) const;	///< Characterize the intersection on a specific block
  void intersectList(vector<int4> &listout,const Cover &op2,int4 level) const;
  bool intersect(const PcodeOpSet &opSet,Varnode *rep) const;	///< Does \b this cover any PcodeOp in the given PcodeOpSet
  bool contain(const PcodeOp *op,int4 max) const;
  int4 containVarnodeDef(const Varnode *vn) const;
  void merge(const Cover &op2);			///< Merge \b this with another Cover block by block
  void rebuild(const Varnode *vn);		///< Reset \b this based on def-use of a single Varnode
  void addDefPoint(const Varnode *vn);		///< Reset to the single point where the given Varnode is defined
  void addRefPoint(const PcodeOp *ref,const Varnode *vn);	///< Add a variable read to \b this Cover
  //  void remove_refpoint(const PcodeOp *ref,const Varnode *vn) {
  //    rebuild(vn); }		// Cheap but inefficient
  void print(ostream &s) const;			///< Dump a description of \b this cover to stream
  map<int4,CoverBlock>::const_iterator begin(void) const { return cover.begin(); }	///< Get beginning of CoverBlocks
  map<int4,CoverBlock>::const_iterator end(void) const { return cover.end(); }		///< Get end of CoverBlocks
};

} // End namespace ghidra
#endif

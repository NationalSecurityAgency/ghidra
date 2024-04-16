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
/// \file constseq.hh
/// \brief Classes for combining constants written to a contiguous region of memory
#ifndef __CONSTSEQ_HH__
#define __CONSTSEQ_HH__

#include "ruleaction.hh"

namespace ghidra {

/// \brief A class for collecting sequences of COPY ops that hold string data
///
/// Given a starting Address and a Symbol with a character array as a component, a class instance collects
/// a maximal set of COPY ops that can be treated as writing a single string into memory.  Then, if the
/// transform() method is called, an explicit string is constructed, and the COPYs are replaced with a
/// \b memcpy CALLOTHER that takes the string as its source input.
class StringSequence {
public:
  static const int4 MINIMUM_SEQUENCE_LENGTH;	///< Minimum number of sequential characters to trigger replacement with CALLOTHER
  /// \brief Helper class holding a data-flow edge and optionally a memory offset being COPYed into or from
  class WriteNode {
    friend class StringSequence;
    uintb offset;		///< Offset into the memory region
    PcodeOp *op;		///< PcodeOp moving into/outof memory region
    int4 slot;			///< either input slot (>=0) or output (-1)
  public:
    WriteNode(uintb off,PcodeOp *o,int4 sl) { offset = off; op = o; slot = sl; }	///< Constructor

    /// \brief Compare two nodes by their order within a basic block
    bool operator<(const WriteNode &node2) const { return op->getSeqNum().getOrder() < node2.op->getSeqNum().getOrder(); }
  };
private:
  Funcdata &data;		///< Function being analyzed
  PcodeOp *rootOp;		///< The root PcodeOp
  Address rootAddr;		///< Address within the memory region associated with the root PcodeOp
  Address startAddr;		///< Starting address of the memory region
  SymbolEntry *entry;		///< Symbol at the root Address
  int4 size;			///< Size of the memory region in bytes
  Datatype *charType;		///< Element data-type
  BlockBasic *block;		///< Basic block containing all the COPY ops
  vector<WriteNode> moveOps;	///< COPYs into the array memory region
  vector<uint1> byteArray;	///< Constants collected in a single array
  bool collectCopyOps(void);	///< Collect ops COPYing constants into the memory region
  bool checkBetweenCopy(PcodeOp *startOp,PcodeOp *endOp);	///< Check for interfering ops between the two given COPYs
  bool checkCopyInterference(void);	///< Find maximal set of COPYs containing the root COPY with no interfering ops in between
  bool formByteArray(void);	///< Put constant values from COPYs into a single byte array
  uint4 selectStringCopyFunction(int4 &index);	///< Pick either strncpy, wcsncpy, or memcpy function used to copy string
  PcodeOp *buildStringCopy(void);	///< Build the strncpy,wcsncpy, or memcpy function with string as input
  static void removeForward(const WriteNode &curNode,map<PcodeOp *,list<WriteNode>::iterator> &xref,
			    list<WriteNode> &points,vector<WriteNode> &deadOps);
  void removeCopyOps(PcodeOp *replaceOp);	///< Remove all the COPY ops from the basic block
  Varnode *constructTypedPointer(PcodeOp *insertPoint);
public:
  StringSequence(Funcdata &fdata,Datatype *ct,SymbolEntry *ent,PcodeOp *root,const Address &addr);
  bool isValid(void) const { return size != 0; }	///< Return \b true if COPYs are found that look like a valid string
  void clear(void);		///< Clear any resources used and mark the sequence as invalid
  bool transform(void);		///< Transform COPYs into a single memcpy user-op
};

class RuleStringSequence : public Rule {
public:
  RuleStringSequence(const string &g) : Rule( g, 0, "stringsequence") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleStringSequence(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

} // End namespace ghidra
#endif

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

/// \brief A sequence of PcodeOps that move data in-to/out-of an array data-type.
///
/// A container for a sequence of PcodeOps within a basic block where we are trying to determine if the sequence
/// can be replaced with a single \b memcpy style user-op.
class ArraySequence {
public:
  static const int4 MINIMUM_SEQUENCE_LENGTH;	///< Minimum number of sequential characters to trigger replacement with CALLOTHER
  static const int4 MAXIMUM_SEQUENCE_LENGTH;	///< Maximum number of characters in replacement string
  /// \brief Helper class holding a data-flow edge and optionally a memory offset being COPYed into or from
  class WriteNode {
  public:
    uint8 offset;		///< Offset into the memory region
    PcodeOp *op;		///< PcodeOp moving into/outof memory region
    int4 slot;			///< either input slot (>=0) or output (-1)
    WriteNode(uint8 off,PcodeOp *o,int4 sl) { offset = off; op = o; slot = sl; }	///< Constructor
    /// \brief Compare two nodes by their order within a basic block
    bool operator<(const WriteNode &node2) const { return op->getSeqNum().getOrder() < node2.op->getSeqNum().getOrder(); }
  };
protected:
  Funcdata &data;		///< The function containing the sequence
  PcodeOp *rootOp;		///< The root PcodeOp
  Datatype *charType;		///< Element data-type
  BlockBasic *block;		///< Basic block containing all the COPY/STORE ops
  int4 numElements;		///< Number of elements in the final sequence
  vector<WriteNode> moveOps;	///< COPY/STORE into the array memory region
  vector<uint1> byteArray;	///< Constants collected in a single array
  static bool interfereBetween(PcodeOp *startOp,PcodeOp *endOp);	///< Check for interfering ops between the two given ops
  bool checkInterference(void);	///< Find maximal set of ops containing the root with no interfering ops in between
  int4 formByteArray(int4 sz,int4 slot,uint8 rootOff,bool bigEndian);	///< Put constant values from COPYs into a single byte array
  uint4 selectStringCopyFunction(int4 &index);	///< Pick either strncpy, wcsncpy, or memcpy function used to copy string
public:
  ArraySequence(Funcdata &fdata,Datatype *ct,PcodeOp *root);	///< Constructor
  bool isValid(void) const { return numElements != 0; }	///< Return \b true if sequence is found
};

/// \brief A class for collecting sequences of COPY ops writing characters to the same string
///
/// Given a starting Address and a Symbol with a character array as a component, a class instance collects
/// a maximal set of COPY ops that can be treated as writing a single string into memory.  Then, if the
/// transform() method is called, an explicit string is constructed, and the COPYs are replaced with a
/// \b strncpy or similar CALLOTHER that takes the string as its source input.
class StringSequence : public ArraySequence {
  Address rootAddr;		///< Address within the memory region associated with the root PcodeOp
  Address startAddr;		///< Starting address of the memory region
  SymbolEntry *entry;		///< Symbol at the root Address
  bool collectCopyOps(int size);	///< Collect ops COPYing constants into the memory region
  PcodeOp *buildStringCopy(void);	///< Build the strncpy,wcsncpy, or memcpy function with string as input
  static void removeForward(const WriteNode &curNode,map<PcodeOp *,list<WriteNode>::iterator> &xref,
			    list<WriteNode> &points,vector<WriteNode> &deadOps);
  void removeCopyOps(PcodeOp *replaceOp);	///< Remove all the COPY ops from the basic block
  Varnode *constructTypedPointer(PcodeOp *insertPoint);
public:
  StringSequence(Funcdata &fdata,Datatype *ct,SymbolEntry *ent,PcodeOp *root,const Address &addr);
  bool transform(void);		///< Transform COPYs into a single memcpy user-op
};

/// \brief A sequence of STORE operations writing characters through the same string pointer
///
/// Given an initial STORE, a class instance collects a maximal set of STORE ops that can be treated as writing
/// a single string into memory.  If the transform() method is called, an explicit string is constructed, and
/// the STOREs are replaced with a \b strncpy or similar CALLOTHER that takes the string as its source input.
class HeapSequence : public ArraySequence {
  Varnode *basePointer;			///< Pointer that sequence is stored to
  uint8 baseOffset;			///< Offset relative to pointer to root STORE
  AddrSpace *storeSpace;		///< Address space being STOREed to
  int4 ptrAddMult;			///< Required multiplier for PTRADD ops
  vector<Varnode *> nonConstAdds;	///< non-constant Varnodes being added into pointer calculation
  void findBasePointer(Varnode *initPtr);	///< Find the base pointer for the sequence
  void findDuplicateBases(vector<Varnode *> &duplist);	///< Find any duplicates of \b basePointer
  void findInitialStores(vector<PcodeOp *> &stores);
  static uint8 calcAddElements(Varnode *vn,vector<Varnode *> &nonConst,int4 maxDepth);
  uint8 calcPtraddOffset(Varnode *vn,vector<Varnode *> &nonConst);
  static bool setsEqual(const vector<Varnode *> &op1,const vector<Varnode *> &op2);
  bool testValue(PcodeOp *op);		///< Test if a STORE value has the matching form for the sequence
  bool collectStoreOps(void);		///< Collect ops STOREing into a memory region from the same root pointer
  PcodeOp *buildStringCopy(void);	///< Build the strncpy,wcsncpy, or memcpy function with string as input
  void gatherIndirectPairs(vector<PcodeOp *> &indirects,vector<Varnode *> &pairs);
  void removeStoreOps(PcodeOp *replaceOp);	///< Remove all STORE ops from the basic block
public:
  HeapSequence(Funcdata &fdata,Datatype *ct,PcodeOp *root);
  bool transform(void);		///< Transform STOREs into a single memcpy user-op
};

class RuleStringCopy : public Rule {
public:
  RuleStringCopy(const string &g) : Rule( g, 0, "stringcopy") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleStringCopy(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

class RuleStringStore : public Rule {
public:
  RuleStringStore(const string &g) : Rule( g, 0, "stringstore") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleStringStore(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

} // End namespace ghidra
#endif

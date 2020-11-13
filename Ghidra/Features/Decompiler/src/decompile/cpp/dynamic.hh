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
/// \file dynamic.hh
/// \brief Utilities for making references to \b dynamic variables: defined as
/// locations and constants that can only be identified by their context within the data-flow graph.

#ifndef __CPUI_DYNAMIC__
#define __CPUI_DYNAMIC__

#include "varnode.hh"

/// \brief An edge between a Varnode and a PcodeOp
///
/// A DynamicHash is defined on a sub-graph of the data-flow, and this defines an edge
/// in the sub-graph.  The edge can either be from an input Varnode to the PcodeOp
/// that reads it, or from a PcodeOp to the Varnode it defines.
class ToOpEdge {
  const PcodeOp *op;		///< The PcodeOp defining the edge
  int4 slot;			///< Slot containing the input Varnode or -1 for the p-code op output
public:
  ToOpEdge(const PcodeOp *o,int4 s) { op = o; slot = s; }	///< Constructor
  const PcodeOp *getOp(void) const { return op; }		///< Get the PcodeOp defining the edge
  int4 getSlot(void) const { return slot; }			///< Get the slot of the starting Varnode
  bool operator<(const ToOpEdge &op2) const;			///< Compare two edges based on PcodeOp
  uint4 hash(uint4 reg) const;					///< Hash \b this edge into an accumulator
};

/// \brief A hash utility to uniquely identify a temporary Varnode in data-flow
///
/// Most Varnodes can be identified within the data-flow graph by their storage address
/// and the address of the PcodeOp that defines them.  For temporary registers,
/// this does not work because the storage address is ephemeral. This class allows
/// Varnodes like temporary registers (and constants) to be robustly identified
/// by hashing details of the local data-flow.
///
/// This class, when presented a Varnode via calcHash(), calculates a hash (getHash())
/// and an address (getAddress()) of the PcodeOp most closely associated with the Varnode,
/// either the defining op or the op directly reading the Varnode.
/// There are actually four hash variants that can be calculated, labeled 0, 1, 2, or 3,
/// which incrementally hash in a larger portion of data-flow.  The method uniqueHash() selects
/// the simplest variant that causes the hash to be unique for the Varnode, among all
/// the Varnodes that share the same address.
///
/// The variant index is encoded in the hash, so the hash and the address are enough information
/// to uniquely identify the Varnode. This is what is stored in the symbol table for
/// a \e dynamic Symbol.
class DynamicHash {
  uint4 vnproc;			///< Number of Varnodes processed in the \b markvn list so far
  uint4 opproc;			///< Number of PcodeOps processed in the \b markop list so far
  uint4 opedgeproc;		///< Number of edges processed in the \b opedge list

  vector<const PcodeOp *> markop;	///< List of PcodeOps in the sub-graph being hashed
  vector<const Varnode *> markvn;	///< List of Varnodes is the sub-graph being hashed
  vector<const Varnode *> vnedge;	///< A staging area for Varnodes before formally adding to the sub-graph
  vector<ToOpEdge> opedge;		///< The edges in the sub-graph

  Address addrresult;			///< Address most closely associated with variable
  uint8 hash;				///< The calculated hash value
  void buildVnUp(const Varnode *vn);	///< Add in the edge between the given Varnode and its defining PcodeOp
  void buildVnDown(const Varnode *vn);	///< Add in edges between the given Varnode and any PcodeOp that reads it
  void buildOpUp(const PcodeOp *op);	///< Move input Varnodes for the given PcodeOp into staging
  void buildOpDown(const PcodeOp *op);	///< Move the output Varnode for the given PcodeOp into staging
  void gatherUnmarkedVn(void);		///< Move staged Varnodes into the sub-graph and mark them
  void gatherUnmarkedOp(void);		///< Mark any new PcodeOps in the sub-graph
public:
  void clear(void);			///< Called for each additional hash (after the first)
  void calcHash(const Varnode *root,uint4 method);	///< Calculate the hash for given Varnode and method
  void uniqueHash(const Varnode *root,Funcdata *fd);	///< Select a unique hash for the given Varnode
  Varnode *findVarnode(const Funcdata *fd,const Address &addr,uint8 h);
  uint8 getHash(void) const { return hash; }		///< Get the (current) hash
  
  const Address &getAddress(void) const { return addrresult; }	///< Get the (current) address
  static void gatherFirstLevelVars(vector<Varnode *> &varlist,const Funcdata *fd,const Address &addr,uint8 h);
  static int4 getSlotFromHash(uint8 h);			///< Retrieve the encoded slot from a hash
  static uint4 getMethodFromHash(uint8 h);		///< Retrieve the encoded method from a hash
  static OpCode getOpCodeFromHash(uint8 h);		///< Retrieve the encoded op-code from a hash
  static uint4 getPositionFromHash(uint8 h);		///< Retrieve the encoded position from a hash
  static uint4 getTotalFromHash(uint8 h);		///< Retrieve the encoded collision total from a hash
  static bool getIsNotAttached(uint8 h);		///< Retrieve the attachment boolean from a hash
  static void clearTotalPosition(uint8 &h);		///< Clear the collision total and position fields within a hash
  static uint4 transtable[];				///< Translation of op-codes to hash values
};

#endif

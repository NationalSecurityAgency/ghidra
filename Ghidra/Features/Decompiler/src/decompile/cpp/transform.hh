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
#ifndef __TRANSFORM__
#define __TRANSFORM__

#include "varnode.hh"
class Funcdata;			// Forward declaration
class TransformOp;

/// \brief Placeholder node for Varnode that will exist after a transform is applied to a function
class TransformVar {
  friend class TransformManager;
public:
  /// Types of replacement Varnodes
  enum {
    piece = 1,			///< New Varnode is a piece of an original Varnode
    preexisting = 2,		///< Varnode preexisted in the original data-flow
    normal_temp = 3,		///< A new temporary (unique space) Varnode
    constant = 4,		///< A new constant Varnode
    constant_iop = 5,		///< Special iop constant encoding a PcodeOp reference
  };
private:
  Varnode *vn;		///< Original \b big Varnode of which \b this is a component
  Varnode *replacement;	///< The new explicit lane Varnode
  int4 size;			///< Size of the lane Varnode in bytes
  uintb val;			///< Value of constant or position within the original big Varnode
  TransformOp *def;		///< Defining op for new Varnode
  uint4 type;			///< Type of new Varnode
  void createReplacement(Funcdata *fd);	///< Create the new/modified variable this placeholder represents
};

/// \brief Placeholder node for PcodeOp that will exist after a transform is applied to a function
class TransformOp {
  friend class TransformManager;
public:
  /// Special annotations on new pcode ops
  enum {
    op_replacement = 1,		///< Op replaces an existing op
    op_preexisting = 2,		///< Op already exists (but will be transformed)
    indirect_creation = 4,	///< Mark op as indirect creation
    indirect_creation_possible_out = 8	///< Mark op as indirect creation and possible call output
  };
private:
  PcodeOp *op;			///< Original op which \b this is splitting (or null)
  PcodeOp *replacement;		///< The new replacement op
  OpCode opc;			///< Opcode of the new op
  uint4 special;		///< Special handling code when creating
  TransformVar *output;	///< Varnode output
  vector<TransformVar *> input; ///< Varnode inputs
  TransformOp *follow;		///< The following op after \b this (if not null)
  void createReplacement(Funcdata *fd);	///< Create the new/modified op this placeholder represents
  bool attemptInsertion(Funcdata *fd);	///< Try to put the new PcodeOp into its basic block
};

/// \brief Description of logical lanes within a \b big Varnode
///
/// A \b lane is a byte offset and size within a Varnode. Lanes within a
/// Varnode are disjoint. In general, we expect a Varnode to be tiled with
/// lanes all of the same size, but the API allows for possibly non-uniform lanes.
class LaneDescription {
  int4 size;		///< Size of (all) lanes
  int4 numLanes;	///< Number of distinct lanes
public:
  LaneDescription(int4 origSize,int4 sz) { size = sz; numLanes = origSize / sz; }	///< Constructor
  int4 getNumLanes(void) const { return numLanes; }	///< Get the total number of lanes
  int4 getSize(int4 i) const { return size; }		///< Get the size of the i-th lane
  int4 getPosition(int4 i) const { return size * i; }	///< Get the significance offset of the i-th lane
};

/// \brief Class for splitting larger registers holding smaller logical lanes
///
/// Given a starting Varnode in the data-flow, look for evidence of the Varnode
/// being interpreted as disjoint logical values concatenated together (lanes).
/// If the interpretation is consistent for data-flow involving the Varnode, split
/// Varnode and data-flow into explicit operations on the lanes.
class TransformManager {
  /// \brief Key for mapping from a \b big Varnode to its pieces
  class MapKey {
    uint4 create_index;		///< Creation index of Varnode being split
    int4 position;		///< Position within the Varnode
  public:
    MapKey(uint4 index,int4 pos) { create_index = index; position = pos; }	///< Constructor
    uint4 getCreateIndex(void) const { return create_index; }	///< Return the creation index part of \b this key
    bool operator<(const MapKey &op2) const;	///< Comparator function for \b this key
  };

  Funcdata *fd;					///< Function being operated on
  map<MapKey,TransformVar *> pieceMap;	///< Map from large Varnodes to their new pieces
  list<TransformVar> newVarnodes;		///< Storage for Varnode placeholder nodes
  list<TransformOp> newOps;			///< Storage for PcodeOp placeholder nodes

  void specialHandling(TransformOp &rop);
  void createOps(void);		///< Create a new op for each placeholder
  void createVarnodes(void);	///< Create a Varnode for each placeholder
  void removeOld(void);		///< Remove old preexisting PcodeOps and Varnodes that are now obsolete
  void transformInputVarnodes(void);	///< Remove old input Varnodes, mark new input Varnodes
  void placeInputs(void);	///< Set input Varnodes for all new ops
public:
  TransformManager(Funcdata *f) { fd = f; }	///< Constructor
  TransformVar *newPreexistingVarnode(Varnode *vn);	///< Make placeholder for preexisting Varnode
  TransformVar *newUnique(int4 size);		///< Make placeholder for new unique space Varnode
  TransformVar *newConstant(int4 size,uintb val);	///< Make placeholder for constant Varnode
  TransformVar *newIop(Varnode *vn);	///< Make placeholder for special iop constant
  TransformVar *newPiece(Varnode *vn,int4 size,int4 lsbOffset);	///< Make placeholder for piece of a Varnode
  void newSplit(vector<TransformVar *> &res,Varnode *vn,const LaneDescription &description);
  TransformOp *newOpReplace(int4 numParams,OpCode opc,PcodeOp *replace);
  TransformOp *newOp(int4 numParams,OpCode opc,TransformOp *follow);
  TransformOp *newPreexistingOp(int4 numParams,OpCode opc,PcodeOp *originalOp);

  TransformVar *getPreexistingVarnode(Varnode *vn);	///< Get (or create) placeholder for preexisting Varnode
  TransformVar *getPiece(Varnode *vn,int4 size,int4 lsbOffset);	///< Get (or create) placeholder piece
  void getSplit(vector<TransformVar *> &res,Varnode *vn,const LaneDescription &description);
  void opSetInput(TransformOp *rop,TransformVar *rvn,int4 slot);	///< Mark given variable as input to given op
  void opSetOutput(TransformOp *rop,TransformVar *rvn);		///< Mark given variable as output of given op

  void apply(void);		///< Apply the full transform to the function
};

/// \param op2 is the other key to compare with \b this
/// \return \b true if \b this should come before the other key
inline bool TransformManager::MapKey::operator<(const TransformManager::MapKey &op2) const

{
  if (create_index != op2.create_index)
    return (create_index < op2.create_index);
  return (position < op2.position);
}

/// \param rop is the given placeholder op whose input is set
/// \param rvn is the placeholder variable to set
/// \param slot is the input position to set
inline void TransformManager::opSetInput(TransformOp *rop,TransformVar *rvn,int4 slot)

{
  rop->input[slot] = rvn;
}

/// Establish that the given op produces the given var as output.
/// Mark both the \e output field of the TransformOp and the \e def field of the TransformVar.
/// \param rop is the given op
/// \param rvn is the given variable
inline void TransformManager::opSetOutput(TransformOp *rop,TransformVar *rvn)

{
  rop->output = rvn;
  rvn->def = rop;
}

#endif

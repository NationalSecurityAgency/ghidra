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
/// \file transform.hh
/// \brief Classes for building large scale transforms of function data-flow
#ifndef __TRANSFORM__
#define __TRANSFORM__

#include "varnode.hh"
class Funcdata;			// Forward declaration
class TransformOp;

/// \brief Placeholder node for Varnode that will exist after a transform is applied to a function
class TransformVar {
  friend class TransformManager;
  friend class TransformOp;
public:
  /// \brief Types of replacement Varnodes
  enum {
    piece = 1,			///< New Varnode is a piece of an original Varnode
    preexisting = 2,		///< Varnode preexisted in the original data-flow
    normal_temp = 3,		///< A new temporary (unique space) Varnode
    piece_temp = 4,		///< A temporary representing a piece of an original Varnode
    constant = 5,		///< A new constant Varnode
    constant_iop = 6,		///< Special iop constant encoding a PcodeOp reference
  };
  /// \brief Flags for a TransformVar
  enum {
    split_terminator = 1,	///< The last (most significant piece) of a split array
    input_duplicate = 2		///< This is a piece of an input that has already been visited
  };
private:
  Varnode *vn;			///< Original \b big Varnode of which \b this is a component
  Varnode *replacement;		///< The new explicit lane Varnode
  uint4 type;			///< Type of new Varnode
  uint4 flags;			///< Boolean properties of the placeholder
  int4 byteSize;		///< Size of the lane Varnode in bytes
  int4 bitSize;			///< Size of the logical value in bits
  uintb val;			///< Value of constant or (bit) position within the original big Varnode
  TransformOp *def;		///< Defining op for new Varnode
  void createReplacement(Funcdata *fd);	///< Create the new/modified variable this placeholder represents
  void initialize(uint4 tp,Varnode *v,int4 bits,int4 bytes,uintb value);
public:
  Varnode *getOriginal(void) const { return vn; }	///< Get the original Varnode \b this placeholder models
  TransformOp *getDef(void) const { return def; }	///< Get the operator that defines this placeholder variable
};

/// \brief Placeholder node for PcodeOp that will exist after a transform is applied to a function
class TransformOp {
  friend class TransformManager;
  friend class TransformVar;
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
public:
  TransformVar *getOut(void) const { return output; }	///< Get the output placeholder variable for \b this operator
  TransformVar *getIn(int4 i) const { return input[i]; }	///< Get the i-th input placeholder variable for \b this
};

/// \brief Describes a (register) storage location and the ways it might be split into lanes
class LanedRegister {
  friend class LanedIterator;
public:
  /// \brief Class for iterating over possible lane sizes
  class LanedIterator {
    int4 size;		///< Current lane size
    uint4 mask;		///< Collection being iterated over
    void normalize(void);	///< Normalize the iterator, after increment or initialization
  public:
    LanedIterator(const LanedRegister *lanedR) { size = 0; mask = lanedR->sizeBitMask; normalize(); }	///< Constructor
    LanedIterator(void) { size = -1; mask = 0; }	///< Constructor for ending iterator
    LanedIterator &operator++(void) { size += 1; normalize(); return *this; }	///< Preincrement operator
    int4 operator*(void) const { return size; }		///< Dereference operator
    LanedIterator &operator=(const LanedIterator &op2) { size = op2.size; mask = op2.mask; return *this; }	///< Assignment
    bool operator==(const LanedIterator &op2) const { return (size == op2.size); }	///< Equal operator
    bool operator!=(const LanedIterator &op2) const { return (size != op2.size); }	///< Not-equal operator
  };
  typedef LanedIterator const_iterator;		///< Iterator over possible lane sizes for this register
private:
  int4 wholeSize;		///< Size of the whole register
  uint4 sizeBitMask;		///< A 1-bit for every permissible lane size
public:
  LanedRegister(void) { wholeSize = 0; sizeBitMask = 0; }	///< Constructor for use with restoreXml
  LanedRegister(int4 sz,uint4 mask) { wholeSize = sz; sizeBitMask = mask; }	///< Constructor
  bool restoreXml(const Element *el,const AddrSpaceManager *manage);	///< Restore object from XML stream
  int4 getWholeSize(void) const { return wholeSize; }	///< Get the size in bytes of the whole laned register
  uint4 getSizeBitMask(void) const { return sizeBitMask; }	///< Get the bit mask of possible lane sizes
  void addLaneSize(int4 size) { sizeBitMask |= ((uint4)1 << size); }	///< Add a new \e size to the allowed list
  bool allowedLane(int4 size) const { return (((sizeBitMask >> size) & 1) != 0); }	///< Is \e size among the allowed lane sizes
  const_iterator begin(void) const { return LanedIterator(this); }	///< Starting iterator over possible lane sizes
  const_iterator end(void) const { return LanedIterator(); }	///< Ending iterator over possible lane sizes
};

/// \brief Description of logical lanes within a \b big Varnode
///
/// A \b lane is a byte offset and size within a Varnode. Lanes within a
/// Varnode are disjoint. In general, we expect a Varnode to be tiled with
/// lanes all of the same size, but the API allows for possibly non-uniform lanes.
class LaneDescription {
  int4 wholeSize;		///< Size of the region being split in bytes
  vector<int4> laneSize;	///< Size of lanes in bytes
  vector<int4> lanePosition;	///< Significance positions of lanes in bytes
public:
  LaneDescription(const LaneDescription &op2);	///< Copy constructor
  LaneDescription(int4 origSize,int4 sz);	///< Construct uniform lanes
  LaneDescription(int4 origSize,int4 lo,int4 hi);	///< Construct two lanes of arbitrary size
  bool subset(int4 lsbOffset,int4 size);	///< Trim \b this to a subset of the original lanes
  int4 getNumLanes(void) const { return laneSize.size(); }	///< Get the total number of lanes
  int4 getWholeSize(void) const { return wholeSize; }		///< Get the size of the region being split
  int4 getSize(int4 i) const { return laneSize[i]; }		///< Get the size of the i-th lane
  int4 getPosition(int4 i) const { return lanePosition[i]; }	///< Get the significance offset of the i-th lane
  int4 getBoundary(int4 bytePos) const;		///< Get index of lane that starts at the given byte position
  bool restriction(int4 numLanes,int4 skipLanes,int4 bytePos,int4 size,int4 &resNumLanes,int4 &resSkipLanes) const;
  bool extension(int4 numLanes,int4 skipLanes,int4 bytePos,int4 size,int4 &resNumLanes,int4 &resSkipLanes) const;
};

/// \brief Class for splitting larger registers holding smaller logical lanes
///
/// Given a starting Varnode in the data-flow, look for evidence of the Varnode
/// being interpreted as disjoint logical values concatenated together (lanes).
/// If the interpretation is consistent for data-flow involving the Varnode, split
/// Varnode and data-flow into explicit operations on the lanes.
class TransformManager {
  Funcdata *fd;					///< Function being operated on
  map<int4,TransformVar *> pieceMap;		///< Map from large Varnodes to their new pieces
  list<TransformVar> newVarnodes;		///< Storage for Varnode placeholder nodes
  list<TransformOp> newOps;			///< Storage for PcodeOp placeholder nodes

  void specialHandling(TransformOp &rop);
  void createOps(void);		///< Create a new op for each placeholder
  void createVarnodes(vector<TransformVar *> &inputList);	///< Create a Varnode for each placeholder
  void removeOld(void);		///< Remove old preexisting PcodeOps and Varnodes that are now obsolete
  void transformInputVarnodes(vector<TransformVar *> &inputList);	///< Remove old input Varnodes, mark new input Varnodes
  void placeInputs(void);	///< Set input Varnodes for all new ops
public:
  TransformManager(Funcdata *f) { fd = f; }	///< Constructor
  virtual ~TransformManager(void);		///< Destructor
  virtual bool preserveAddress(Varnode *vn,int4 bitSize,int4 lsbOffset) const;
  Funcdata *getFunction(void) const { return fd; }	///< Get function being transformed
  void clearVarnodeMarks(void);			///< Clear mark for all Varnodes in the map
  TransformVar *newPreexistingVarnode(Varnode *vn);	///< Make placeholder for preexisting Varnode
  TransformVar *newUnique(int4 size);		///< Make placeholder for new unique space Varnode
  TransformVar *newConstant(int4 size,int4 lsbOffset,uintb val);	///< Make placeholder for constant Varnode
  TransformVar *newIop(Varnode *vn);	///< Make placeholder for special iop constant
  TransformVar *newPiece(Varnode *vn,int4 bitSize,int4 lsbOffset);	///< Make placeholder for piece of a Varnode
  TransformVar *newSplit(Varnode *vn,const LaneDescription &description);
  TransformVar *newSplit(Varnode *vn,const LaneDescription &description,int4 numLanes,int4 startLane);
  TransformOp *newOpReplace(int4 numParams,OpCode opc,PcodeOp *replace);
  TransformOp *newOp(int4 numParams,OpCode opc,TransformOp *follow);
  TransformOp *newPreexistingOp(int4 numParams,OpCode opc,PcodeOp *originalOp);

  TransformVar *getPreexistingVarnode(Varnode *vn);	///< Get (or create) placeholder for preexisting Varnode
  TransformVar *getPiece(Varnode *vn,int4 bitSize,int4 lsbOffset);	///< Get (or create) placeholder piece
  TransformVar *getSplit(Varnode *vn,const LaneDescription &description);
  TransformVar *getSplit(Varnode *vn,const LaneDescription &description,int4 numLanes,int4 startLane);
  void opSetInput(TransformOp *rop,TransformVar *rvn,int4 slot);	///< Mark given variable as input to given op
  void opSetOutput(TransformOp *rop,TransformVar *rvn);		///< Mark given variable as output of given op
  static bool preexistingGuard(int4 slot,TransformVar *rvn);	///< Should newPreexistingOp be called

  void apply(void);		///< Apply the full transform to the function
};

/// \brief Initialize \b this variable from raw data
///
/// \param tp is the type of variable to create
/// \param v is the underlying Varnode of which this is a piece (may be null)
/// \param bits is the number of bits in the variable
/// \param bytes is the number of bytes in the variable
/// \param value is the associated value
inline void TransformVar::initialize(uint4 tp,Varnode *v,int4 bits,int4 bytes,uintb value)

{
  type = tp;
  vn = v;
  val = value;
  bitSize = bits;
  byteSize = bytes;
  flags = 0;
  def = (TransformOp *)0;
  replacement = (Varnode *)0;
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

/// Varnode marking prevents duplicate TransformOp (and TransformVar) records from getting
/// created, except in the case of a preexisting PcodeOp with 2 (or more) non-constant inputs.
/// Because the op is preexisting the output Varnode doesn't get marked, and the op will
/// be visited for each input.  This method determines when the TransformOp object should be
/// created, with the goal of creating it exactly once even though the op is visited more than once.
/// It currently assumes the PcodeOp is binary, and the slot along which the op is
/// currently visited is passed in, along with the TransformVar for the \e other input. It returns
/// \b true if the TransformOp should be created.
/// \param slot is the incoming slot along which the op is visited
/// \param rvn is the other input
inline bool TransformManager::preexistingGuard(int4 slot,TransformVar *rvn)

{
  if (slot == 0) return true;	// If we came in on the first slot, build the TransformOp
  if (rvn->type == TransformVar::piece || rvn->type == TransformVar::piece_temp)
    return false;		// The op was/will be visited on slot 0, don't create TransformOp now
  return true;			// The op was not (will not be) visited on slot 0, build now
}

#endif

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
/// \file pcoderaw.hh
/// \brief Raw descriptions of varnodes and p-code ops
#ifndef __PCODERAW_HH__
#define __PCODERAW_HH__

#include "address.hh"
#include "opbehavior.hh"

namespace ghidra {

/// \brief Data defining a specific memory location
///
/// Within the decompiler's model of a processor, any register,
/// memory location, or other variable can always be represented
/// as an address space, an offset within the space, and the
/// size of the sequence of bytes.  This is more commonly referred
/// to as a Varnode, but this is a bare-bones container
/// for the data that doesn't have the cached attributes and
/// the dataflow links of the Varnode within its syntax tree.
struct VarnodeData {
  AddrSpace *space;		///< The address space
  uintb offset;			///< The offset within the space
  uint4 size;                   ///< The number of bytes in the location
  bool operator<(const VarnodeData &op2) const;  ///< An ordering for VarnodeData
  bool operator==(const VarnodeData &op2) const; ///< Compare for equality
  bool operator!=(const VarnodeData &op2) const; ///< Compare for inequality

  /// Get the location of the varnode as an address
  Address getAddr(void) const;

  /// Treat \b this as a constant and recover encoded address space
  AddrSpace *getSpaceFromConst(void) const;

  /// Recover this object from a stream
  void decode(Decoder &decoder);

  /// Recover \b this object from attributes of the current open element
  void decodeFromAttributes(Decoder &decoder);

  /// Does \b this container another given VarnodeData
  bool contains(const VarnodeData &op2) const;

  /// Is \b this contiguous (as the most significant piece) with the given VarnodeData
  bool isContiguous(const VarnodeData &lo) const;
};

/// VarnodeData can be sorted in terms of the space its in
/// (the space's \e index), the offset within the space,
/// and finally by the size.
/// \param op2 is the object being compared to
/// \return true if \e this is less than \e op2
inline bool VarnodeData::operator<(const VarnodeData &op2) const {
  if (space != op2.space) return (space->getIndex() < op2.space->getIndex());
  if (offset != op2.offset) return (offset < op2.offset);
  return (size > op2.size);	// BIG sizes come first
}

/// Compare VarnodeData for equality. The space, offset, and size
/// must all be exactly equal
/// \param op2 is the object being compared to
/// \return true if \e this is equal to \e op2
inline bool VarnodeData::operator==(const VarnodeData &op2) const {
  if (space != op2.space) return false;
  if (offset != op2.offset) return false;
  return (size == op2.size);
}

/// Compare VarnodeData for inequality. If either the space,
/// offset, or size is not equal, return \b true.
/// \param op2 is the object being compared to
/// \return true if \e this is not equal to \e op2
inline bool VarnodeData::operator!=(const VarnodeData &op2) const {
  if (space != op2.space) return true;
  if (offset != op2.offset) return true;
  return (size != op2.size);
}

/// This is a convenience function to construct a full Address from the
/// VarnodeData's address space and offset
/// \return the address of the varnode
inline Address VarnodeData::getAddr(void) const {
  return Address(space,offset);
}

/// \return the encoded AddrSpace
inline AddrSpace *VarnodeData::getSpaceFromConst(void) const {
  return (AddrSpace *)(uintp)offset;
}

/// \brief A low-level representation of a single pcode operation
///
/// This is just the minimum amount of data to represent a pcode operation
/// An opcode, sequence number, optional output varnode
/// and input varnodes
class PcodeOpRaw {
  OpBehavior *behave;		///< The opcode for this operation
  SeqNum seq;	                ///< Identifying address and index of this operation
  VarnodeData *out;		///< Output varnode triple
  vector<VarnodeData *> in;	///< Raw varnode inputs to this op
public:
  void setBehavior(OpBehavior *be); ///< Set the opcode for this op
  OpBehavior *getBehavior(void) const; ///< Retrieve the behavior for this op
  OpCode getOpcode(void) const;	///< Get the opcode for this op
  void setSeqNum(const Address &a,uintm b); ///< Set the sequence number
  const SeqNum &getSeqNum(void) const; ///< Retrieve the sequence number
  const Address &getAddr(void) const; ///< Get address of this operation
  void setOutput(VarnodeData *o); ///< Set the output varnode for this op
  VarnodeData *getOutput(void) const; ///< Retrieve the output varnode for this op
  void addInput(VarnodeData *i); ///< Add an additional input varnode to this op
  void clearInputs(void);	///< Remove all input varnodes to this op
  int4 numInput(void) const;	///< Get the number of input varnodes to this op
  VarnodeData *getInput(int4 i) const; ///< Get the i-th input varnode for this op

  /// \brief Decode the raw OpCode and input/output Varnode data for a PcodeOp
  static OpCode decode(Decoder &decoder,int4 isize,VarnodeData *invar,VarnodeData **outvar);
};

/// The core behavior for this operation is controlled by an OpBehavior object
/// which knows how output is determined given inputs. This routine sets that object
/// \param be is the behavior object
inline void PcodeOpRaw::setBehavior(OpBehavior *be)

{
  behave = be;
}

/// Get the underlying behavior object for this pcode operation.  From this
/// object you can determine how the object evaluates inputs to get the output
/// \return the behavior object
inline OpBehavior *PcodeOpRaw::getBehavior(void) const

{
  return behave;
}

/// The possible types of pcode operations are enumerated by OpCode
/// This routine retrieves the enumeration value for this particular op
/// \return the opcode value
inline OpCode PcodeOpRaw::getOpcode(void) const

{
  return behave->getOpcode();
}

/// Every pcode operation has a \b sequence \b number
/// which associates the operation with the address of the machine instruction
/// being translated and an order number which provides an index for this
/// particular operation within the entire translation of the machine instruction
/// \param a is the instruction address
/// \param b is the order number
inline void PcodeOpRaw::setSeqNum(const Address &a,uintm b)

{
  seq = SeqNum(a,b);
}

/// Every pcode operation has a \b sequence \b number which associates
/// the operation with the address of the machine instruction being translated
/// and an index number for this operation within the translation.
/// \return a reference to the sequence number
inline const SeqNum &PcodeOpRaw::getSeqNum(void) const

{
  return seq;
}

/// This is a convenience function to get the address of the machine instruction
/// (of which this pcode op is a translation)
/// \return the machine instruction address
inline const Address &PcodeOpRaw::getAddr(void) const

{
  return seq.getAddr();
}

/// Most pcode operations output to a varnode.  This routine sets what that varnode is.
/// \param o is the varnode to set as output
inline void PcodeOpRaw::setOutput(VarnodeData *o)

{
  out = o;
}

/// Most pcode operations have an output varnode. This routine retrieves that varnode.
/// \return the output varnode or \b null if there is no output
inline VarnodeData *PcodeOpRaw::getOutput(void) const

{
  return out;
}

/// A PcodeOpRaw is initially created with no input varnodes.  Inputs are added with this method.
/// Varnodes are added in order, so the first addInput call creates input 0, for example.
/// \param i is the varnode to be added as input
inline void PcodeOpRaw::addInput(VarnodeData *i)

{
  in.push_back(i);
}

/// If the inputs to a pcode operation need to be changed, this routine clears the existing
/// inputs so new ones can be added.
inline void PcodeOpRaw::clearInputs(void)

{
  in.clear();
}

/// \return the number of inputs
inline int4 PcodeOpRaw::numInput(void) const

{
  return in.size();
}

/// Input varnodes are indexed starting at 0.  This retrieves the input varnode by index.
/// The index \e must be in range, or unpredicatable behavior will result. Use the numInput method
/// to get the number of inputs.
/// \param i is the index of the desired input
/// \return the desired input varnode
inline VarnodeData *PcodeOpRaw::getInput(int4 i) const

{
  return in[i];
}

} // End namespace ghidra
#endif

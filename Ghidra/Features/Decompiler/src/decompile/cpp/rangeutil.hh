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
/// \file rangeutil.hh
/// \brief Documentation for the CircleRange class
#ifndef __RANGEUTIL__
#define __RANGEUTIL__

#include "op.hh"

/// \brief A class for manipulating integer value ranges.
///
/// The idea is to have a representation of common sets of
/// values that a varnode might take on in analysis so that
/// the representation can be manipulated symbolically to
/// some extent.  The representation is a circular range
/// (determined by a half-open interval [left,right)), over
/// the integers mod 2^n,  where mask = 2^n-1.
/// The range can support a step, if some of the
/// least significant bits of the mask are set to zero.
///
/// The class then can
///   - Generate ranges based on a pcode condition:
///      -    x < 2      =>   left=0  right=2  mask=sizeof(x)
///      -    5 >= x     =>   left=5  right=0  mask=sizeof(x)
///
///   - Intersect and union ranges, if the result is another range
///   - Pull-back a range through a transformation operation
///   - Iterate
///
///   \code
///     val = range.getMin();
///     do {
///     } while(range.getNext(val));
///   \endcode
class CircleRange {
  uintb left;			///< Left boundary of the open range [left,right)
  uintb right;			///< Right boundary of the open range [left,right)
  uintb mask;			///< Bit mask defining the size (modulus) and stop of the range
  bool isempty;			///< \b true if set is empty
  int4 step;			///< Explicit step size
  int4 shift;			///< Number of bits in step.  Equal to log2(step)
  static const char arrange[];	///< Map from raw overlaps to normalized overlap code
  void calcStepShift(void);	///< Calculate explicit \b step and \b skip from \b mask
  void complement(void);	///< Set \b this to the complement of itself
  void convertToBoolean(void);	///< Convert \b this to boolean.
  static bool newStride(uintb newmask,uintb &myleft,uintb &myright);	///< Recalculate range based on new size and stride
  static char encodeRangeOverlaps(uintb op1left,uintb op1right,uintb op2left,uintb op2right);	///< Calculate overlap code
public:
  CircleRange(void) { isempty=true; }		///< Construct an empty range
  CircleRange(uintb mn,uintb mx,uintb m);	///< Construct given specific boundaries.
  CircleRange(bool val);			///< Construct a boolean range
  CircleRange(uintb val,int4 size);		///< Construct range with single value
  bool isEmpty(void) const { return isempty; }	///< Return \b true if \b this range is empty
  uintb getMin(void) const { return left; }	///< Get the left boundary of the range
  uintb getMax(void) const { return (right-step)&mask; }	///< Get the right-most integer contained in the range
  uintb getEnd(void) const { return right; }	///< Get the right boundary of the range
  uintb getMask(void) const { return mask; }	///< Get the mask
  uintb getSize(void) const;			///< Get the size of this range
  bool getNext(uintb &val) const { val = (val+step)&mask; return (val!=right); }	///< Advance an integer within the range
  bool contains(const CircleRange &op2) const;	///< Check containment of another range in \b this.
  bool contains(uintb val) const;		///< Check containment of a specific integer.
  int4 intersect(const CircleRange &op2);	///< Intersect \b this with another range
  bool setNZMask(uintb nzmask,int4 size);	///< Set the range based on a putative mask.
  int4 circleUnion(const CircleRange &op2);	///< Union two ranges.
  void setStride(int4 newshift);		///< Set a new stride on \b this range.
  Varnode *pullBack(PcodeOp *op,Varnode **constMarkup,bool usenzmask);	///< Pull-back \b this range through given PcodeOp.
  int4 translate2Op(OpCode &opc,uintb &c,int4 &cslot) const;	///< Translate range to a comparison op
};

/// If two ranges are labeled [l , r) and  [op2.l, op2.r), the
/// overlap of the ranges can be characterized by listing the four boundary
/// values  in order, as the circle is traversed in a clock-wise direction.  This characterization can be
/// further normalized by starting the list at op2.l, unless op2.l is contained in the range [l, r).
/// In which case, the list should start with l.  You get the following 6 categories
///    - a  = (l r op2.l op2.r)
///    - b  = (l op2.l r op2.r)
///    - c  = (l op2.l op2.r r)
///    - d  = (op2.l l r op2.r)
///    - e  = (op2.l l op2.r r)
///    - f  = (op2.l op2.r l r)
///    - g  = (l op2.r op2.l r)
///
/// Given 2 ranges, this method calculates the category code for the overlap.
/// \param op1left is left boundary of the first range
/// \param op1right is the right boundary of the first range
/// \param op2left is the left boundary of the second range
/// \param op2right is the right boundary of the second range
/// \return the character code of the normalized overlap category
inline char CircleRange::encodeRangeOverlaps(uintb op1left, uintb op1right, uintb op2left, uintb op2right)

{
  int4 val = (op1left <= op1right) ? 0x20 : 0;
  val |= (op1left <= op2left) ? 0x10 : 0;
  val |= (op1left <= op2right) ? 0x8 : 0;
  val |= (op1right <= op2left) ? 4 : 0;
  val |= (op1right <= op2right) ? 2 : 0;
  val |= (op2left <= op2right) ? 1 : 0;
  return arrange[val];
}

#endif

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
#include "rangeutil.hh"
#include "block.hh"

const char CircleRange::arrange[] = "gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

/// All the instantiations where left == right represent the same set. We
/// normalize the representation so we can compare sets easily.
void CircleRange::normalize(void)

{
  if (left == right) {
    if (step != 1)
      left = left % step;
    else
      left = 0;
    right = left;
  }
}

/// This method \b only works if \b step is 1
void CircleRange::complement(void)

{
  if (isempty) {
    left=0;
    right=0;
    isempty = false;
    return;
  }
  if (left==right) {
    isempty = true;
    return;
  }
  uintb tmp = left;
  left = right;
  right = tmp;
}

/// If the original range contained
///   - 0 and 1   => the new range is [0,2)
///   - 0 only    => the new range is [0,1)
///   - 1 only    => the new range is [1,2)
///   - neither 0 or 1  =>  the new range is empty
///
/// \return \b true if the range contains both 0 and 1
bool CircleRange::convertToBoolean(void)

{
  if (isempty) return false;
  bool contains_zero = contains(0);
  bool contains_one = contains(1);
  mask = 0xff;
  step = 1;
  if (contains_zero && contains_one) {
    left = 0;
    right = 2;
    isempty = false;
    return true;
  }
  else if (contains_zero) {
    left = 0;
    right = 1;
    isempty = false;
  }
  else if (contains_one) {
    left = 1;
    right = 2;
    isempty = false;
  }
  else
    isempty = true;
  return false;
}

/// \brief  Recalculate range based on new stride
///
/// Restrict a left/right specified range to a new stride, given the step and
/// remainder it needs to match. This assumes the specified range is not empty.
/// \param mask is the domain mask
/// \param step is the new stride
/// \param oldStep is the original step (always smaller)
/// \param rem is the given remainder to match
/// \param myleft is a reference to the left boundary of the specified range
/// \param myright is a reference to the right boundary of the specified range
/// \return \b true if result is empty
bool CircleRange::newStride(uintb mask,int4 step,int4 oldStep,uint4 rem,uintb &myleft,uintb &myright)

{
  if (oldStep != 1) {
    uint4 oldRem = (uint4)(myleft % oldStep);
    if (oldRem != (rem % oldStep))
      return true;			// Step is completely off
  }
  bool origOrder = (myleft < myright);
  uint4 leftRem = (uint4)(myleft % step);
  uint4 rightRem = (uint4)(myright % step);
  if (leftRem > rem)
    myleft += rem + step - leftRem;
  else
    myleft += rem - leftRem;

  if (rightRem > rem)
    myright += rem + step - rightRem;
  else
    myright += rem - rightRem;
  myleft &= mask;
  myright &= mask;

  bool newOrder = (myleft < myright);
  if (origOrder != newOrder)
    return true;

  return false;			// not empty
}

/// \brief Make \b this range fit in a new domain
///
/// Truncate any part of the range outside of the new domain.
/// If the original range is completely outside of the new domain,
/// return \b true (empty). Step information is preserved.
/// \param newMask is the mask for the new domain
/// \param newStep is the step associated with the range
/// \param myleft is a reference to the left edge of the range to fit
/// \param myright is a reference to the right edge of the range to fit
/// \return \b true if the truncated domain is empty
bool CircleRange::newDomain(uintb newMask,int4 newStep,uintb &myleft,uintb &myright)

{
  uintb rem;
  if (newStep != 1)
    rem = myleft % newStep;
  else
    rem = 0;
  if (myleft > newMask) {
    if (myright > newMask) {	// Both bounds out of range of newMask
      if (myleft < myright) return true; // Old range is completely out of bounds of new mask
      myleft = rem;
      myright = rem;		// Old range contained everything in newMask
      return false;
    }
    myleft = rem;		// Take everything up to left edge of new range
  }
  if (myright > newMask) {
    myright = rem;		// Take everything up to right edge of new range
  }
  if (myleft == myright) {
    myleft = rem;		// Normalize the everything
    myright = rem;
  }
  return false;			// not empty
}

/// Give specific left/right boundaries and step information.
/// The first element in the set is given left boundary. The sequence
/// then proceeds by the given \e step up to (but not including) the given
/// right boundary.  Care should be taken to make sure the remainders of the
/// left and right boundaries modulo the step are equal.
/// \param lft is the left boundary of the range
/// \param rgt is the right boundary of the range
/// \param size is the domain size in bytes (1,2,4,8,..)
/// \param stp is the desired step (1,2,4,8,..)
CircleRange::CircleRange(uintb lft,uintb rgt,int4 size,int4 stp)

{
  mask = calc_mask(size);
  step = stp;
  left = lft;
  right = rgt;
  isempty = false;
}

/// The range contains only a single integer, 0 or 1, depending on the boolean parameter.
/// \param val is the boolean parameter
CircleRange::CircleRange(bool val)

{
  mask = 0xff;
  step = 1;
  left = val ? 1: 0;
  right = val + 1;
  isempty = false;
}

/// A size specifies the number of bytes (*8 to get number of bits) in the mask.
/// The stride is assumed to be 1.
/// \param val is is the single value
/// \param size is the size of the mask in bytes
CircleRange::CircleRange(uintb val,int4 size)

{
  mask = calc_mask(size);
  step = 1;
  left = val;
  right = (left+1)&mask;
  isempty = false;
}

/// \param lft is the left boundary of the range
/// \param rgt is the right boundary of the range
/// \param size is the size of the range domain in bytes
/// \param stp is the step/stride of the range
void CircleRange::setRange(uintb lft,uintb rgt,int4 size,int4 stp)

{
  mask = calc_mask(size);
  left = lft;
  right = rgt;
  step = stp;
  isempty = false;
}

/// A size specifies the number of bytes (*8 to get number of bits) in the mask.
/// The stride is assumed to be 1.
/// \param val is is the single value
/// \param size is the size of the mask in bytes
void CircleRange::setRange(uintb val,int4 size)

{
  mask = calc_mask(size);
  step = 1;
  left = val;
  right = (left+1)&mask;
  isempty = false;
}

/// Make a range of values that holds everything.
/// \param size is the size (in bytes) of the range
void CircleRange::setFull(int4 size)

{
  mask = calc_mask(size);
  step = 1;
  left = 0;
  right = 0;
  isempty = false;
}

/// \return the number of integers contained in this range
uintb CircleRange::getSize(void) const

{
  if (isempty) return 0;
  uintb val;
  if (left < right)
    val = (right-left) / step;
  else {
    val = (mask - (left-right) + step) / step;
    if (val == 0) {		// This is an overflow, when all uintb values are in the range
      val = mask;               // We lie by one, which shouldn't matter for our jumptable application
      if (step > 1) {
	val = val / step;
	val += 1;
      }
    }
  }
  return val;
}

/// In this context, the information content of a value is the index (+1) of the
/// most significant non-zero bit (of the absolute value). This routine returns
/// the maximum information across all values in the range.
/// \return the maximum information
int4 CircleRange::getMaxInfo(void) const

{
  uintb halfPoint = mask ^ (mask >> 1);
  if (contains(halfPoint))
    return 8*sizeof(uintb) - count_leading_zeros(halfPoint);
  int4 sizeLeft,sizeRight;
  if ((halfPoint & left) == 0)
    sizeLeft = count_leading_zeros(left);
  else
    sizeLeft = count_leading_zeros(~left & mask);
  if ((halfPoint & right) == 0)
    sizeRight = count_leading_zeros(right);
  else
    sizeRight = count_leading_zeros(~right & mask);
  int4 size1 = 8*sizeof(uintb) - (sizeRight < sizeLeft ? sizeRight : sizeLeft);
  return size1;
}

/// \param op2 is the specific range to test for containment.
/// \return \b true if \b this contains the interval \b op2
bool CircleRange::contains(const CircleRange &op2) const

{
  if (isempty)
    return op2.isempty;
  if (op2.isempty)
    return true;
  if (step > op2.step) {
    // This must have a smaller or equal step to op2 or containment is impossible
    // except in the corner case where op2 consists of a single element (its step is meaningless)
    if (!op2.isSingle())
      return false;
  }
  if (left == right) return true;
  if (op2.left == op2.right) return false;
  if (left % step != op2.left % step) return false;	// Wrong phase
  if (left == op2.left && right == op2.right) return true;

  char overlapCode = encodeRangeOverlaps(left, right, op2.left, op2.right);

  if (overlapCode == 'c')
    return true;
  if (overlapCode == 'b' && (right == op2.right))
    return true;
  return false;

  // Missing one case where op2.step > this->step, and the boundaries don't show containment,
  // but there is containment because the lower step size UP TO right still contains the edge points
}

/// Check if a specific integer is a member of \b this range.
/// \param val is the specific integer
/// \return \b true if it is contained in \b this
bool CircleRange::contains(uintb val) const

{
  if (isempty) return false;
  if (step != 1) {
    if ((left % step)!=(val%step))
      return false;	// Phase is wrong
  }
  if (left < right) {
    if (val < left) return false;
    if (right <= val) return false;
  }
  else if (right < left) {
    if (val<right) return true;
    if (val>=left) return true;
    return false;
  }
  return true;
}

/// Set \b this to the union of \b this and \b op2 as a single interval.
/// Return 0 if the result is valid.
/// Return 2 if the union is two pieces.
/// If result is not zero, \b this is not modified.
/// \param op2 is the range to union with
/// \return the result code
int4 CircleRange::circleUnion(const CircleRange &op2)

{
  if (op2.isempty) return 0;
  if (isempty) {
    *this = op2;
    return 0;
  }
  if (mask != op2.mask) return 2;	// Cannot do proper union with different domains
  uintb aRight = right;
  uintb bRight = op2.right;
  int4 newStep = step;
  if (step < op2.step) {
    if (isSingle()) {
      newStep = op2.step;
      aRight = (left + newStep) & mask;
    }
    else
      return 2;
  }
  else if (op2.step < step) {
    if (op2.isSingle()) {
      newStep = step;
      bRight = (op2.left + newStep) & mask;
    }
    else
      return 2;
  }
  uintb rem;
  if (newStep != 1) {
    rem = left % newStep;
    if (rem != (op2.left % newStep))
      return 2;
  }
  else
    rem = 0;
  if ((left==aRight)||(op2.left==bRight)) {
    left = rem;
    right = rem;
    step = newStep;
    return 0;
  }

  char overlapCode = encodeRangeOverlaps(left, aRight, op2.left, bRight);
  switch(overlapCode) {
  case 'a':			// order (l r op2.l op2.r)
  case 'f':			// order (op2.l op2.r l r)
    if (aRight==op2.left) {
      right = bRight;
      step = newStep;
      return 0;
    }
    if (left==bRight) {
      left = op2.left;
      right = aRight;
      step = newStep;
      return 0;
    }
    return 2;			// 2 pieces;
  case 'b':			// order (l op2.l r op2.r)
    right = bRight;
    step = newStep;
    return 0;
  case 'c':			// order (l op2.l op2.r r)
    right = aRight;
    step = newStep;
    return 0;
  case 'd':			// order (op2.l l r op2.r)
    left = op2.left;
    right = bRight;
    step = newStep;
    return 0;
  case 'e':		       // order (op2.l l op2.r r)
    left = op2.left;
    right = aRight;
    step = newStep;
    return 0;
  case 'g':			// either impossible or covers whole circle
    left = rem;
    right = rem;
    step = newStep;
    return 0;			// entire circle is covered
  }
  return -1;			// Never reach here
}

/// Turn \b this into a range that contains both the original range and
/// the other given range. The resulting range may contain values that were in neither
/// of the original ranges (not a strict union). But the number of added values will be
/// minimal. This method will create a range with step if the input ranges hold single values
/// and the distance between them is a power of 2 and less or equal than a given bound.
/// \param op2 is the other given range to combine with \b this
/// \param maxStep is the step bound that can be induced for a container with two singles
/// \return \b true if the container is everything (full)
bool CircleRange::minimalContainer(const CircleRange &op2,int4 maxStep)

{
  if (isSingle() && op2.isSingle()) {
    uintb min,max;
    if (getMin() < op2.getMin()) {
      min = getMin();
      max = op2.getMin();
    }
    else {
      min = op2.getMin();
      max = getMin();
    }
    uintb diff = max - min;
    if (diff > 0 && diff <= maxStep) {
      if (leastsigbit_set(diff) == mostsigbit_set(diff)) {
	step = (int4) diff;
	left = min;
	right = (max + step) & mask;
	return false;
      }
    }
  }

  uintb aRight = right - step + 1;		// Treat original ranges as having step=1
  uintb bRight = op2.right - op2.step + 1;
  step = 1;
  mask |= op2.mask;
  uintb vacantSize1,vacantSize2;

  char overlapCode = encodeRangeOverlaps(left, aRight, op2.left, bRight);
  switch(overlapCode) {
  case 'a':			// order (l r op2.l op2.r)
    vacantSize1 = left + (mask - bRight) + 1;
    vacantSize2 = op2.left - aRight;
    if (vacantSize1 < vacantSize2) {
      left = op2.left;
      right = aRight;
    }
    else {
      right = bRight;
    }
    break;
  case 'f':			// order (op2.l op2.r l r)
    vacantSize1 = op2.left + (mask-aRight) + 1;
    vacantSize2 = left - bRight;
    if (vacantSize1 < vacantSize2) {
      right = bRight;
    }
    else {
      left = op2.left;
      right = aRight;
    }
    break;
  case 'b':			// order (l op2.l r op2.r)
    right = bRight;
    break;
  case 'c':			// order (l op2.l op2.r r)
    right = aRight;
    break;
  case 'd':			// order (op2.l l r op2.r)
    left = op2.left;
    right = bRight;
    break;
  case 'e':			// order (op2.l l op2.r r)
    left = op2.left;
    right = aRight;
    break;
  case 'g':			// order (l op2.r op2.l r)
    left = 0;			// Entire circle is covered
    right = 0;
    break;
  }
  normalize();
  return (left == right);
}

/// Convert range to its complement.  The step is automatically converted to 1 first.
/// \return the original step size
int4 CircleRange::invert(void)

{
  int4 res = step;
  step = 1;
  complement();
  return res;
}

/// Set \b this to the intersection of \b this and \b op2 as a
/// single interval if possible.
/// Return 0 if the result is valid
/// Return 2 if the intersection is two pieces
/// If result is not zero, \b this is not modified
/// \param op2 is the second range
/// \return the intersection code
int4 CircleRange::intersect(const CircleRange &op2)

{
  int4 retval,newStep;
  uintb newMask,myleft,myright,op2left,op2right;

  if (isempty) return 0;	// Intersection with empty is empty
  if (op2.isempty) {
    isempty = true;
    return 0;
  }
  myleft = left;
  myright = right;
  op2left = op2.left;
  op2right = op2.right;
  if (step < op2.step) {
    newStep = op2.step;
    uint4 rem = (uint4)(op2left % newStep);
    if (newStride(mask,newStep,step,rem,myleft,myright)) {	// Increase the smaller stride
      isempty = true;
      return 0;
    }
  }
  else if (op2.step < step) {
    newStep = step;
    uint4 rem = (uint4)(myleft % newStep);
    if (newStride(op2.mask,newStep,op2.step,rem,op2left,op2right)) {
      isempty = true;
      return 0;
    }
  }
  else
    newStep = step;
  newMask = mask & op2.mask;
  if (mask != newMask) {
    if (newDomain(newMask,newStep,myleft,myright)) {
      isempty = true;
      return 0;
    }
  }
  else if (op2.mask != newMask) {
    if (newDomain(newMask,newStep,op2left,op2right)) {
      isempty = true;
      return 0;
    }
  }
  if (myleft==myright) {	// Intersect with this everything
    left = op2left;
    right = op2right;
    retval = 0;
  }
  else if (op2left == op2right) { // Intersect with op2 everything
    left = myleft;
    right = myright;
    retval = 0;
  }
  else {
    char overlapCode = encodeRangeOverlaps(myleft, myright, op2left, op2right);
    switch(overlapCode) {
    case 'a':			// order (l r op2.l op2.r)
    case 'f':			// order (op2.l op2.r l r)
      isempty = true;
      retval = 0;		// empty set
      break;
    case 'b':			// order (l op2.l r op2.r)
      left = op2left;
      right = myright;
      if (left==right)
	isempty = true;
      retval = 0;
      break;
    case 'c':			// order (l op2.l op2.r r)
      left = op2left;
      right = op2right;
      retval = 0;
      break;
    case 'd':			// order (op2.l l r op2.r)
      left = myleft;
      right = myright;
      retval = 0;
      break;
    case 'e':			// order (op2.l l op2.r r)
      left = myleft;
      right = op2right;
      if (left==right)
	isempty = true;
      retval = 0;
      break;
    case 'g':			// order (l op2.r op2.l r)
      if (myleft==op2right) {
	left = op2left;
	right = myright;
	if (left==right)
	  isempty = true;
	retval = 0;
      }
      else if (op2left==myright) {
	left = myleft;
	right = op2right;
	if (left==right)
	  isempty = true;
	retval = 0;
      }
      else
	retval = 2;			// 2 pieces
      break;
    default:
      retval = 2;		// Will never reach here
      break;
    }
  }
  if (retval != 0) return retval;
  mask = newMask;
  step = newStep;
  return 0;
}

/// Try to create a range given a value that is not necessarily a valid mask.
/// If the mask is valid, range is set to all possible values that whose non-zero
/// bits are contained in the mask. If the mask is invalid, \b this range is  not modified.
/// \param nzmask is the putative mask
/// \param size is a maximum size (in bytes) for the mask
/// \return \b true if the mask is valid
bool CircleRange::setNZMask(uintb nzmask,int4 size)

{
  int4 trans = bit_transitions(nzmask,size);
  if (trans>2) return false;	// Too many transitions to form a valid range
  bool hasstep = ((nzmask&1)==0);
  if ((!hasstep)&&(trans==2)) return false; // Two sections of non-zero bits
  isempty = false;
  if (trans == 0) {
    mask = calc_mask(size);
    if (hasstep) {		// All zeros
      step = 1;
      left = 0;
      right = 1;		// Range containing only zero
    }
    else {			// All ones
      step = 1;
      left = 0;
      right = 0;		// Everything
    }
    return true;
  }
  int4 shift = leastsigbit_set(nzmask);
  step = 1;
  step <<= shift;
  mask = calc_mask(size);
  left = 0;
  right = (nzmask + step) & mask;
  return true;
}

/// This method changes the step for \b this range, i.e. elements are removed.
/// The boundaries of the range do not change except for the remainder modulo the new step.
/// \param newStep is the new step amount
/// \param rem is the desired phase (remainder of the values modulo the step)
void CircleRange::setStride(int4 newStep,uintb rem)

{
  bool iseverything = (!isempty) && (left==right);
  if (newStep == step) return;
  uintb aRight = right - step;
  step = newStep;
  if (step == 1) return;		// No remainder to fill in
  uintb curRem = left % step;
  left = (left - curRem) + rem;
  curRem = aRight % step;
  aRight = (aRight - curRem) + rem;
  right = aRight + step;
  if ((!iseverything)&&(left == right))
    isempty = true;
}

/// \param opc is the OpCode to pull the range back through
/// \param inSize is the storage size in bytes of the resulting input
/// \param outSize is the storage size in bytes of the range to pull-back
/// \return \b true if a valid range is formed in the pull-back
bool CircleRange::pullBackUnary(OpCode opc,int4 inSize,int4 outSize)

{
  uintb val;
  // If there is nothing in the output set, no input will map to it
  if (isempty) return true;

  switch(opc) {
    case CPUI_BOOL_NEGATE:
      if (convertToBoolean())
	break;			// Both outputs possible => both inputs possible
      left = left ^ 1;		// Flip the boolean range
      right = left +1;
      break;
    case CPUI_COPY:
      break;			// Identity transform on range
    case CPUI_INT_2COMP:
      val = (~left + 1 + step) & mask;
      left = (~right + 1 + step) & mask;
      right = val;
      break;
    case CPUI_INT_ZEXT:
    {
      val = calc_mask(inSize); // (smaller) input mask
      CircleRange zextrange;
      zextrange.left = 0;
      zextrange.right = val + 1;	// Biggest possible range of ZEXT
      zextrange.mask = mask;
      zextrange.step = step;	// Keep the same stride
      zextrange.isempty = false;
      if (0 != intersect(zextrange))
	return false;
      left &= val;
      right &= val;
      mask &= val;		// Preserve the stride
      break;
    }
    case CPUI_INT_SEXT:
    {
      val = calc_mask(inSize); // (smaller) input mask
      CircleRange sextrange;
      sextrange.left = val ^ (val >> 1); // High order bit for (small) input space
      sextrange.right = sign_extend(sextrange.left, inSize, outSize);
      sextrange.mask = mask;
      sextrange.step = step;	// Keep the same stride
      sextrange.isempty = false;
      if (sextrange.intersect(*this) != 0)
	return false;
      else {
	if (!sextrange.isEmpty())
	  return false;
	else {
	  left &= val;
	  right &= val;
	  mask &= val;		// Preserve the stride
	}
      }
      break;
    }
    default:
      return false;
  }
  return true;
}

/// \param opc is the OpCode to pull the range back through
/// \param val is the constant value of the other input parameter (if present)
/// \param slot is the slot of the input variable whose range gets produced
/// \param inSize is the storage size in bytes of the resulting input
/// \param outSize is the storage size in bytes of the range to pull-back
/// \return \b true if a valid range is formed in the pull-back
bool CircleRange::pullBackBinary(OpCode opc,uintb val,int4 slot,int4 inSize,int4 outSize)

{
  bool yescomplement;
  bool bothTrueFalse;

  // If there is nothing in the output set, no input will map to it
  if (isempty) return true;

  switch(opc) {
    case CPUI_INT_EQUAL:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse)
	break;	// All possible outs => all possible ins
      yescomplement = (left == 0);
      left = val;
      right = (val + 1) & mask;
      if (yescomplement)
	complement();
      break;
    case CPUI_INT_NOTEQUAL:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse) break;	// All possible outs => all possible ins
      yescomplement = (left==0);
      left = (val+1)&mask;
      right = val;
      if (yescomplement)
        complement();
      break;
    case CPUI_INT_LESS:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse) break;	// All possible outs => all possible ins
      yescomplement = (left==0);
      if (slot==0) {
        if (val==0)
          isempty = true;		// X < 0  is always false
        else {
          left = 0;
          right = val;
        }
      }
      else {
        if (val==mask)
          isempty = true;		// 0xffff < X  is always false
        else {
          left = (val+1)&mask;
          right = 0;
        }
      }
      if (yescomplement)
        complement();
      break;
    case CPUI_INT_LESSEQUAL:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse) break;	// All possible outs => all possible ins
      yescomplement = (left==0);
      if (slot==0) {
        left = 0;
        right = (val+1)&mask;
      }
      else {
        left = val;
        right = 0;
      }
      if (yescomplement)
        complement();
      break;
    case CPUI_INT_SLESS:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse) break;	// All possible outs => all possible ins
      yescomplement = (left==0);
      if (slot==0) {
        if (val == (mask>>1)+1)
          isempty = true;		// X < -infinity, is always false
        else {
          left = (mask >> 1)+1;	// -infinity
          right = val;
        }
      }
      else {
        if ( val == (mask>>1) )
          isempty = true;		// infinity < X, is always false
        else {
          left = (val+1)&mask;
          right = (mask >> 1)+1;	// -infinity
        }
      }
      if (yescomplement)
        complement();
      break;
    case CPUI_INT_SLESSEQUAL:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse) break;	// All possible outs => all possible ins
      yescomplement = (left==0);
      if (slot==0) {
        left = (mask >> 1)+1;	// -infinity
        right = (val+1)&mask;
      }
      else {
        left = val;
        right = (mask >> 1)+1;	// -infinity
      }
      if (yescomplement)
        complement();
      break;
    case CPUI_INT_CARRY:
      bothTrueFalse = convertToBoolean();
      mask = calc_mask(inSize);
      if (bothTrueFalse) break;	// All possible outs => all possible ins
      yescomplement = (left==0);
      if (val==0)
        isempty = true;		// Nothing carries adding zero
      else {
        left = ((mask-val)+1)&mask;
        right = 0;
      }
      if (yescomplement)
        complement();
      break;
    case CPUI_INT_ADD:
      left = (left-val)&mask;
      right = (right-val)&mask;
      break;
    case CPUI_INT_SUB:
      if (slot==0) {
  	left = (left+val)&mask;
  	right = (right+val)&mask;
      }
      else {
  	left = (val-left)&mask;
  	right = (val-right)&mask;
      }
      break;
    case CPUI_INT_RIGHT:
    {
      if (step == 1) {
	uintb rightBound = (calc_mask(inSize) >> val) + 1; // The maximal right bound
	if (((left >= rightBound) && (right >= rightBound) && (left >= right))
	    || ((left == 0) && (right >= rightBound)) || (left == right)) {
	  // covers everything in range of shift
	  left = 0;		// So domain is everything
	  right = 0;
	}
	else {
	  if (left > rightBound)
	    left = rightBound;
	  if (right > rightBound)
	    right = 0;
	  left = (left << val) & mask;
	  right = (right << val) & mask;
	  if (left == right)
	    isempty = true;
	}
      }
      else
	return false;
      break;
    }
    case CPUI_INT_SRIGHT:
    {
      if (step == 1) {
	uintb rightb = calc_mask(inSize);
	uintb leftb = rightb >> (val + 1);
	rightb = leftb ^ rightb; // Smallest negative possible
	leftb += 1;		// Biggest positive (+1) possible
	if (((left >= leftb) && (left <= rightb) && (right >= leftb)
	    && (right <= rightb) && (left >= right)) || (left == right)) {
	  // covers everything in range of shift
	  left = 0;		// So domain is everything
	  right = 0;
	}
	else {
	  if ((left > leftb) && (left < rightb))
	    left = leftb;
	  if ((right > leftb) && (right < rightb))
	    right = rightb;
	  left = (left << val) & mask;
	  right = (right << val) & mask;
	  if (left == right)
	    isempty = true;
	}
      }
      else
	return false;
      break;
    }
    default:
      return false;
  }
  return true;
}

/// The pull-back is performed through a given p-code \b op and set \b this
/// to the resulting range (if possible).
/// If there is a single unknown input, and the set of values
/// for this input that cause the output of \b op to fall
/// into \b this form a range, then set \b this to the
/// range (the "pullBack") and return the unknown varnode.
/// Return null otherwise.
///
/// We may know something about the input varnode in the form of its NZMASK, which can further
/// restrict the range we return.  If \b usenzmask is true, and NZMASK forms a range, intersect
/// \b this with the result.
///
/// If there is Symbol markup on any constant passed into the op, pass that information back.
/// \param op is the given PcodeOp
/// \param constMarkup is the reference for passing back the constant relevant to the pull-back
/// \param usenzmask specifies whether to use the NZMASK
/// \return the input Varnode or NULL
Varnode *CircleRange::pullBack(PcodeOp *op,Varnode **constMarkup,bool usenzmask)

{
  Varnode *res;

  if (op->numInput() == 1) {
    res = op->getIn(0);
    if (res->isConstant()) return (Varnode *)0;
    if (!pullBackUnary(op->code(),res->getSize(),op->getOut()->getSize()))
      return (Varnode *)0;
  }
  else if (op->numInput() == 2) {
    Varnode *constvn;
    uintb val;
    // Find non-constant varnode input, and slot
    // Make sure second input is constant
    int4 slot = 0;
    res = op->getIn(slot);
    constvn = op->getIn(1 - slot);
    if (res->isConstant()) {
      slot = 1;
      constvn = res;
      res = op->getIn(slot);
      if (res->isConstant())
	return (Varnode *) 0;
    }
    else if (!constvn->isConstant())
      return (Varnode *) 0;
    val = constvn->getOffset();
    OpCode opc = op->code();
    if (!pullBackBinary(opc, val, slot, res->getSize(), op->getOut()->getSize())) {
      if (usenzmask && opc == CPUI_SUBPIECE && val == 0) {
	// If everything we are truncating is known to be zero, we may still have a range
	int4 msbset = mostsigbit_set(res->getNZMask());
	msbset = (msbset + 8) / 8;
	if (op->getOut()->getSize() < msbset) // Some bytes we are chopping off might not be zero
	  return (Varnode *) 0;
	else {
	  mask = calc_mask(res->getSize()); // Keep the range but make the mask bigger
	  // If the range wraps (left>right) then, increasing the mask adds all the new space into
	  // the range, and it would be an inaccurate pullback by itself, but with the nzmask intersection
	  // all the new space will get intersected away again.
	}
      }
      else
	return (Varnode *) 0;
    }
    if (constvn->getSymbolEntry() != (SymbolEntry *) 0)
      *constMarkup = constvn;
  }
  else	// Neither unary or binary
    return (Varnode *)0;

  if (usenzmask) {
    CircleRange nzrange;
    if (!nzrange.setNZMask(res->getNZMask(),res->getSize()))
      return res;
    intersect(nzrange);
    // If the intersect does not succeed (i.e. produces 2 pieces) the original range is
    // preserved and we still consider this pullback successful.
  }
  return res;
}

/// Push all values in the given range through a p-code operator.
/// If the output set of values forms a range, then set \b this to the range and return \b true.
/// \param opc is the given p-code operator
/// \param in1 is the given input range
/// \param inSize is the storage space in bytes for the input
/// \param outSize is the storage space in bytes for the output
/// \return \b true if the result is known and forms a range
bool CircleRange::pushForwardUnary(OpCode opc,const CircleRange &in1,int4 inSize,int4 outSize)

{
  if (in1.isempty) {
    isempty = true;
    return true;
  }
  switch(opc) {
    case CPUI_CAST:
    case CPUI_COPY:
      *this = in1;
      break;
    case CPUI_INT_ZEXT:
      isempty = false;
      step = in1.step;
      mask = calc_mask(outSize);
      left = in1.left;
      right = (in1.right - in1.step) & in1.mask;
      if (right < left) {	// Extending causes 2 pieces
	left = left % step;
	right = in1.mask + 1 + left;
      }
      else {
	right += step;	// Impossible for it to wrap with bigger mask
      }
      break;
    case CPUI_INT_SEXT:
      isempty = false;
      step = in1.step;
      mask = calc_mask(outSize);
      left = sign_extend(in1.left, inSize, outSize);
      right = sign_extend((in1.right - in1.step)&in1.mask, inSize, outSize);
      if ((intb)right < (intb)left) {
	uintb rem = left % step;
	right = calc_mask(inSize) >> 1;
	left = (calc_mask(outSize) ^ right) + rem;
	right = right + 1 + rem;
      }
      else
	right += step;
      break;
    case CPUI_INT_2COMP:
      isempty = false;
      step = in1.step;
      mask = in1.mask;
      right = (~in1.left + 1 + step) & mask;
      left = (~in1.right + 1 + step) & mask;
      normalize();
      break;
    case CPUI_INT_NEGATE:
      isempty = false;
      step = in1.step;
      mask = in1.mask;
      left = -in1.right & mask;
      right = -in1.left & mask;
      normalize();
      break;
    case CPUI_BOOL_NEGATE:
    case CPUI_FLOAT_NAN:
      isempty = false;
      mask = 0xff;
      step = 1;
      left = 0;
      right = 2;
      break;
    default:
      return false;
  }
  return true;
}

/// \brief Push \b this range forward through a binary operation
///
/// Push all values in the given ranges through a binary p-code operator.
/// If the output set of values forms a range, then set \b this to the range and return \b true.
/// \param opc is the given p-code operator
/// \param in1 is the first given input range
/// \param in2 is the second given input range
/// \param inSize is the storage space in bytes for the input
/// \param outSize is the storage space in bytes for the output
/// \param maxStep is the maximum to allow step to grow via multiplication
/// \return \b true if the result is known and forms a range
bool CircleRange::pushForwardBinary(OpCode opc,const CircleRange &in1,const CircleRange &in2,int4 inSize,int4 outSize,int4 maxStep)

{
  if (in1.isempty || in2.isempty) {
    isempty = true;
    return true;
  }
  switch(opc) {
    case CPUI_PTRSUB:
    case CPUI_INT_ADD:
      isempty = false;
      mask = in1.mask | in2.mask;
      if (in1.left == in1.right || in2.left == in2.right) {
	step = (in1.step < in2.step) ? in1.step : in2.step;	// Smaller step
	left = (in1.left + in2.left) % step;
	right = left;
      }
      else if (in2.isSingle()) {
	step = in1.step;
	left = (in1.left + in2.left) & mask;
	right = (in1.right + in2.left) & mask;
      }
      else if (in1.isSingle()) {
	step = in2.step;
	left = (in2.left + in1.left) & mask;
	right = (in2.right +in1.left) & mask;
      }
      else {
	step = (in1.step < in2.step) ? in1.step : in2.step;	// Smaller step
	uintb size1 = (in1.left < in1.right) ? (in1.right-in1.left) : (in1.mask - (in1.left-in1.right) + in1.step);
	left = (in1.left + in2.left) & mask;
	right = (in1.right - in1.step + in2.right - in2.step + step) & mask;
	uintb sizenew = (left < right) ? (right-left) : (mask - (left-right) + step);
	if (sizenew < size1) {
	  right = left;	// Over-flow, we covered everything
	}
	normalize();
      }
      break;
    case CPUI_INT_MULT:
    {
      isempty = false;
      mask = in1.mask | in2.mask;
      uintb constVal;
      if (in1.isSingle()) {
	constVal = in1.getMin();
	step = in2.step;
      }
      else if (in2.isSingle()) {
	constVal = in2.getMin();
	step = in1.step;
      }
      else
	return false;
      uint4 tmp = (uint4)constVal;
      while(step < maxStep) {
	if ((tmp & 1) != 0) break;
	step <<= 1;
	tmp >>= 1;
      }
      int4 wholeSize = 8*sizeof(uintb) - count_leading_zeros(mask);
      if (in1.getMaxInfo() + in2.getMaxInfo() > wholeSize) {
	left = in1.left;	// Covered everything
	right = in1.left;
	normalize();
	return true;
      }
      if ((constVal & (mask ^ (mask >> 1))) != 0) {	// Multiplying by negative number
	left = ((in1.right - in1.step) * (in2.right - in2.step)) & mask;
	right = ((in1.left * in2.left) + step) & mask;
      }
      else {
	left = (in1.left * in2.left)&mask;
	right = ((in1.right - in1.step) * (in2.right - in2.step) + step) & mask;
      }
      break;
    }
    case CPUI_INT_LEFT:
    {
      if (!in2.isSingle()) return false;
      isempty = false;
      mask = in1.mask;
      step = in1.step;
      uint4 sa = (uint4)in2.getMin();
      uint4 tmp = sa;
      while(step < maxStep && tmp > 0) {
	step <<= 1;
	sa -= 1;
      }
      left = (in1.left << sa)&mask;
      right = (in1.right << sa)&mask;
      int4 wholeSize = 8*sizeof(uintb) - count_leading_zeros(mask);
      if (in1.getMaxInfo() + sa > wholeSize) {
	right = left;	// Covered everything
	normalize();
	return true;
      }
      break;
    }
    case CPUI_SUBPIECE:
    {
      if (!in2.isSingle()) return false;
      isempty = false;
      int4 sa = (int4)in2.left * 8;
      mask = calc_mask(outSize);
      step = (sa == 0) ? in1.step : 1;

      left = (in1.left >> sa)&mask;
      right = (in1.right >> sa)&mask;
      if ((left& ~mask) != (right & ~mask)) {	// Truncated part is different
	left = right = 0;	// We cover everything
      }
      else {
	left &= mask;
	right &= mask;
	normalize();
      }
      break;
    }
    case CPUI_INT_RIGHT:
    {
      if (!in2.isSingle()) return false;
      isempty = false;
      int4 sa = (int4)in2.left;
      mask = calc_mask(outSize);
      step = 1;			// Lose any step
      if (in1.left < in1.right) {
	left = in1.left >> sa;
	right = ((in1.right - in1.step) >> sa) + 1;
      }
      else {
	left = 0;
	right = in1.mask >> sa;
      }
      if (left == right)	// Don't truncate accidentally to everything
	right = (left + 1)&mask;
      break;
    }
    case CPUI_INT_SRIGHT:
    {
      if (!in2.isSingle()) return false;
      isempty = false;
      int4 sa = (int4)in2.left;
      mask = calc_mask(outSize);
      step = 1;			// Lose any step
      intb valLeft = in1.left;
      intb valRight = in1.right;
      int4 bitPos = 8*inSize - 1;
      sign_extend(valLeft,bitPos);
      sign_extend(valRight,bitPos);
      if (valLeft >= valRight) {
	valRight = (intb)(mask >> 1);	// Max positive
	valLeft = valRight + 1;		// Min negative
	sign_extend(valLeft,bitPos);
      }
      left = (valLeft >> sa) & mask;
      right = (valRight >> sa) & mask;
      if (left == right)	// Don't truncate accidentally to everything
	right = (left + 1)&mask;
      break;
    }
    case CPUI_INT_EQUAL:
    case CPUI_INT_NOTEQUAL:
    case CPUI_INT_SLESS:
    case CPUI_INT_SLESSEQUAL:
    case CPUI_INT_LESS:
    case CPUI_INT_LESSEQUAL:
    case CPUI_INT_CARRY:
    case CPUI_INT_SCARRY:
    case CPUI_INT_SBORROW:
    case CPUI_BOOL_XOR:
    case CPUI_BOOL_AND:
    case CPUI_BOOL_OR:
    case CPUI_FLOAT_EQUAL:
    case CPUI_FLOAT_NOTEQUAL:
    case CPUI_FLOAT_LESS:
    case CPUI_FLOAT_LESSEQUAL:
      // Ops with boolean outcome.  We don't try to eliminate outcomes here.
      isempty = false;
      mask = 0xff;
      step = 1;
      left = 0;		// Both true and false are possible
      right = 2;
      break;
    default:
      return false;
  }
  return true;
}

/// \brief Push \b this range forward through a trinary operation
///
/// Push all values in the given ranges through a trinary p-code operator (currenly only CPUI_PTRADD).
/// If the output set of values forms a range, then set \b this to the range and return \b true.
/// \param opc is the given p-code operator
/// \param in1 is the first given input range
/// \param in2 is the second given input range
/// \param in3 is the third given input range
/// \param inSize is the storage space in bytes for the input
/// \param outSize is the storage space in bytes for the output
/// \param maxStep is the maximum to allow step to grow via multiplication
/// \return \b true if the result is known and forms a range
bool CircleRange::pushForwardTrinary(OpCode opc,const CircleRange &in1,const CircleRange &in2,const CircleRange &in3,
				     int4 inSize,int4 outSize,int4 maxStep)
{
  if (opc != CPUI_PTRADD) return false;
  CircleRange tmpRange;
  if (!tmpRange.pushForwardBinary(CPUI_INT_MULT, in2, in3, inSize, inSize, maxStep))
    return false;
  return pushForwardBinary(CPUI_INT_ADD, in1, tmpRange, inSize, outSize, maxStep);
}

/// Widen \b this range so at least one of the boundaries matches with the given
/// range, which must contain \b this.
/// \param op2 is the given containing range
/// \param leftIsStable is \b true if we want to match right boundaries
void CircleRange::widen(const CircleRange &op2,bool leftIsStable)

{
  if (leftIsStable) {
    uintb lmod = left % step;
    uintb mod = op2.right % step;
    if (mod <= lmod)
      right = op2.right + (lmod - mod);
    else
      right = op2.right - (mod - lmod);
    right &= mask;
  }
  else {
    left = op2.left & mask;
  }
  normalize();
}

/// Recover parameters for a comparison PcodeOp, that returns true for
/// input values exactly in \b this range.
/// Return:
///    - 0 on success
///    - 1 if all inputs must return true
///    - 2 if this is not possible
///    - 3 if no inputs must return true
/// \param opc will contain the OpCode for the comparison PcodeOp
/// \param c will contain the constant input to the op
/// \param cslot will indicate the slot holding the constant
/// \return the success code
int4 CircleRange::translate2Op(OpCode &opc,uintb &c,int4 &cslot) const

{
  if (isempty) return 3;
  if (step != 1) return 2;	// Not possible with a stride
  if (right==((left+1)&mask)) {	// Single value
    opc = CPUI_INT_EQUAL;
    cslot = 0;
    c = left;
    return 0;
  }
  if (left==((right+1)&mask)) {	// All but one value
    opc = CPUI_INT_NOTEQUAL;
    cslot = 0;
    c = right;
    return 0;
  }
  if (left==right) return 1;	// All outputs are possible
  if (left==0) {
    opc = CPUI_INT_LESS;
    cslot = 1;
    c = right;
    return 0;
  }
  if (right==0) {
    opc = CPUI_INT_LESS;
    cslot = 0;
    c = (left-1)&mask;
    return 0;
  }
  if (left==(mask>>1)+1) {
    opc = CPUI_INT_SLESS;
    cslot = 1;
    c = right;
    return 0;
  }
  if (right==(mask>>1)+1) {
    opc = CPUI_INT_SLESS;
    cslot = 0;
    c = (left-1)&mask;
    return 0;
  }
  return 2;			// Cannot represent
}

/// \param s is the stream to write to
void CircleRange::printRaw(ostream &s) const

{
  if (isempty) {
    s << "(empty)";
    return;
  }
  if (left == right) {
    s << "(full";
    if (step != 1)
      s << ',' << dec << step;
    s << ')';
  }
  else if (right == ((left+1)&mask)) {
    s << '[' << hex << left << ']';
  }
  else {
    s << '[' << hex << left << ',' << right;
    if (step != 1)
      s << ',' << dec << step;
    s << ')';
  }
}

const int4 ValueSet::MAX_STEP = 32;

/// The initial values in \b this are set based on the type of Varnode:
///   - Constant gets the single value
///   - Input gets all possible values
///   - Other Varnodes that are written start with an empty set
///
/// \param v is the given Varnode to attach to
/// \param tCode indicates whether to treat values as constants are relative offsets
void ValueSet::setVarnode(Varnode *v,int4 tCode)

{
  typeCode = tCode;
  vn = v;
  vn->setValueSet(this);
  if (typeCode != 0) {
    opCode = CPUI_MAX;
    numParams = 0;
    range.setRange(0,vn->getSize());	// Treat as offset of 0 relative to special value
    leftIsStable = true;
    rightIsStable = true;
  }
  else if (vn->isWritten()) {
    PcodeOp *op = vn->getDef();
    opCode = op->code();
    if (opCode == CPUI_INDIRECT) {	// Treat CPUI_INDIRECT as CPUI_COPY
      numParams = 1;
      opCode = CPUI_COPY;
    }
    else
      numParams = op->numInput();
    leftIsStable = false;
    rightIsStable = false;
  }
  else if (vn->isConstant()) {
    opCode = CPUI_MAX;
    numParams = 0;
    range.setRange(vn->getOffset(),vn->getSize());
    leftIsStable = true;
    rightIsStable = true;
  }
  else {	// Some other form of input
    opCode = CPUI_MAX;
    numParams = 0;
    typeCode = 0;
    range.setFull(vn->getSize());
    leftIsStable = false;
    rightIsStable = false;
  }
}

/// Equations are stored as an array of (slot,range) pairs, ordered on slot.
/// \param slot is the given slot
/// \param type is the constraint characteristic
/// \param constraint is the given range
void ValueSet::addEquation(int4 slot,int4 type,const CircleRange &constraint)

{
  vector<Equation>::iterator iter;
  iter = equations.begin();
  while(iter != equations.end()) {
    if ((*iter).slot > slot)
      break;
    ++iter;
  }
  equations.insert(iter,Equation(slot,type,constraint));
}

/// Examine the input value sets that determine \b this set and decide if it
/// is relative. In general, \b this will be relative if any of its inputs are.
/// Certain combinations are indeterminate, which this method flags by
/// returning \b true. The Varnode attached to \b this must have a defining op.
/// \return \b true if there is an indeterminate combination
bool ValueSet::computeTypeCode(void)

{
  int4 relCount = 0;
  int4 lastTypeCode = 0;
  PcodeOp *op = vn->getDef();
  for(int4 i=0;i<numParams;++i) {
    ValueSet *valueSet = op->getIn(i)->getValueSet();
    if (valueSet->typeCode != 0) {
      relCount += 1;
      lastTypeCode = valueSet->typeCode;
    }
  }
  if (relCount == 0) {
    typeCode = 0;
    return false;
  }
  // Only certain operations can propagate a relative value set
  switch(opCode) {
    case CPUI_PTRSUB:
    case CPUI_PTRADD:
    case CPUI_INT_ADD:
    case CPUI_INT_SUB:
      if (relCount == 1)
	typeCode = lastTypeCode;
      else
	return true;
      break;
    case CPUI_CAST:
    case CPUI_COPY:
    case CPUI_INDIRECT:
    case CPUI_MULTIEQUAL:
      typeCode = lastTypeCode;
      break;
    default:
      return true;
  }
  return false;
}

/// Recalculate \b this value set by grabbing the value sets of the inputs to the
/// operator defining the Varnode attached to \b this value set and pushing them
/// forward through the operator.
/// \return \b true if there was a change to \b this value set
bool ValueSet::iterate(Widener &widener)

{
  if (!vn->isWritten()) return false;
  if (widener.checkFreeze(*this)) return false;
  if (count == 0) {
    if (computeTypeCode()) {
      setFull();
      return true;
    }
  }
  count += 1;		// Count this iteration
  CircleRange res;
  PcodeOp *op = vn->getDef();
  int4 eqPos = 0;
  if (opCode == CPUI_MULTIEQUAL) {
    int4 pieces = 0;
    for(int4 i=0;i<numParams;++i) {
      ValueSet *inSet = op->getIn(i)->getValueSet();
      if (doesEquationApply(eqPos, i)) {
	CircleRange rangeCopy(inSet->range);
	if (0 !=rangeCopy.intersect(equations[eqPos].range)) {
	  rangeCopy = equations[eqPos].range;
	}
	pieces = res.circleUnion(rangeCopy);
	eqPos += 1;	// Equation was used
      }
      else {
	pieces = res.circleUnion(inSet->range);
      }
      if (pieces == 2) {
	if (res.minimalContainer(inSet->range,MAX_STEP))	// Could not get clean union, force it
	  break;
      }
    }
    if (0 != res.circleUnion(range)) {	// Union with the previous iteration's set
      res.minimalContainer(range,MAX_STEP);
    }
    if (!range.isEmpty() && !res.isEmpty()) {
      leftIsStable = range.getMin() == res.getMin();
      rightIsStable = range.getEnd() == res.getEnd();
    }
  }
  else if (numParams == 1) {
    ValueSet *inSet1 = op->getIn(0)->getValueSet();
    if (doesEquationApply(eqPos, 0)) {
      CircleRange rangeCopy(inSet1->range);
      if (0 != rangeCopy.intersect(equations[eqPos].range)) {
	rangeCopy = equations[eqPos].range;
      }
      if (!res.pushForwardUnary(opCode, rangeCopy, inSet1->vn->getSize(), vn->getSize())) {
	setFull();
	return true;
      }
      eqPos += 1;
    }
    else if (!res.pushForwardUnary(opCode, inSet1->range, inSet1->vn->getSize(), vn->getSize())) {
      setFull();
      return true;
    }
    leftIsStable = inSet1->leftIsStable;
    rightIsStable = inSet1->rightIsStable;
  }
  else if (numParams == 2) {
    ValueSet *inSet1 = op->getIn(0)->getValueSet();
    ValueSet *inSet2 = op->getIn(1)->getValueSet();
    if (equations.size() == 0) {
      if (!res.pushForwardBinary(opCode, inSet1->range, inSet2->range, inSet1->vn->getSize(), vn->getSize(), MAX_STEP)) {
	setFull();
	return true;
      }
    }
    else {
      CircleRange range1 = inSet1->range;
      CircleRange range2 = inSet2->range;
      if (doesEquationApply(eqPos, 0)) {
	if (0 != range1.intersect(equations[eqPos].range))
	  range1 = equations[eqPos].range;
	eqPos += 1;
      }
      if (doesEquationApply(eqPos, 1)) {
	if (0 != range2.intersect(equations[eqPos].range))
	  range2 = equations[eqPos].range;
      }
      if (!res.pushForwardBinary(opCode, range1, range2, inSet1->vn->getSize(), vn->getSize(), MAX_STEP)) {
	setFull();
	return true;
      }
    }
    leftIsStable = inSet1->leftIsStable && inSet2->leftIsStable;
    rightIsStable = inSet1->rightIsStable && inSet2->rightIsStable;
  }
  else if (numParams == 3) {
    ValueSet *inSet1 = op->getIn(0)->getValueSet();
    ValueSet *inSet2 = op->getIn(1)->getValueSet();
    ValueSet *inSet3 = op->getIn(2)->getValueSet();
    CircleRange range1 = inSet1->range;
    CircleRange range2 = inSet2->range;
    if (doesEquationApply(eqPos, 0)) {
      if (0 != range1.intersect(equations[eqPos].range))
	range1 = equations[eqPos].range;
      eqPos += 1;
    }
    if (doesEquationApply(eqPos, 1)) {
      if (0 != range2.intersect(equations[eqPos].range))
	range2 = equations[eqPos].range;
    }
    if (!res.pushForwardTrinary(opCode, range1, range2, inSet3->range, inSet1->vn->getSize(), vn->getSize(), MAX_STEP)) {
      setFull();
      return true;
    }
    leftIsStable = inSet1->leftIsStable && inSet2->leftIsStable;
    rightIsStable = inSet1->rightIsStable && inSet2->rightIsStable;
  }
  else
    return false;		// No way to change this value set

  if (res == range)
    return false;
  if (partHead != (Partition *)0) {
    if (!widener.doWidening(*this, range, res))
      setFull();
  }
  else
    range = res;
  return true;
}

/// If a landmark was associated with \b this value set, return its range,
/// otherwise return null.
/// \return the landmark range or null
const CircleRange *ValueSet::getLandMark(void) const

{
  // Any equation can serve as a landmark.  We prefer the one restricting the
  // value of an input branch, as these usually give a tighter approximation
  // of the stable point.
  for(int4 i=0;i<equations.size();++i) {
    if (equations[i].typeCode == typeCode)
      return &equations[i].range;
  }
  return (const CircleRange *)0;
}

/// \param s is the stream to print to
void ValueSet::printRaw(ostream &s) const

{
  if (vn == (Varnode *)0)
    s << "root";
  else
    vn->printRaw(s);
  if (typeCode == 0)
    s << " absolute";
  else
    s << " stackptr";
  if (opCode == CPUI_MAX) {
    if (vn->isConstant())
      s << " const";
    else
      s << " input";
  }
  else
    s << ' ' << get_opname(opCode);
  s << ' ';
  range.printRaw(s);
}

/// \param o is the PcodeOp reading the value set
/// \param slt is the input slot the values are coming in from
void ValueSetRead::setPcodeOp(PcodeOp *o,int4 slt)

{
  typeCode = 0;
  op = o;
  slot = slt;
  equationTypeCode = -1;
}

/// \param slt is the given slot
/// \param type is the constraint characteristic
/// \param constraint is the given range
void ValueSetRead::addEquation(int4 slt,int4 type,const CircleRange &constraint)

{
  if (slot == slt) {
    equationTypeCode = type;
    equationConstraint = constraint;
  }
}

/// This value set will be the same as the ValueSet of the Varnode being read but may
/// be modified due to additional control-flow constraints
void ValueSetRead::compute(void)

{
  Varnode *vn = op->getIn(slot);
  ValueSet *valueSet = vn->getValueSet();
  typeCode = valueSet->getTypeCode();
  range = valueSet->getRange();
  leftIsStable = valueSet->isLeftStable();
  rightIsStable = valueSet->isRightStable();
  if (typeCode == equationTypeCode) {
    if (0 != range.intersect(equationConstraint)) {
      range = equationConstraint;
    }
  }
}

/// \param s is the stream to print to
void ValueSetRead::printRaw(ostream &s) const

{
  s << "Read: " << get_opname(op->code());
  s << '(' << op->getSeqNum() << ')';
  if (typeCode == 0)
    s << " absolute ";
  else
    s << " stackptr ";
  range.printRaw(s);
}

int4 WidenerFull::determineIterationReset(const ValueSet &valueSet)

{
  if (valueSet.getCount() >= widenIteration)
    return widenIteration;	// Reset to point just after any widening
  return 0;			// Delay widening, if we haven't performed it yet
}

bool WidenerFull::checkFreeze(const ValueSet &valueSet)

{
  return valueSet.getRange().isFull();
}

bool WidenerFull::doWidening(const ValueSet &valueSet,CircleRange &range,const CircleRange &newRange)

{
  if (valueSet.getCount() < widenIteration) {
    range = newRange;
    return true;
  }
  else if (valueSet.getCount() == widenIteration) {
    const CircleRange *landmark = valueSet.getLandMark();
    if (landmark != (const CircleRange *)0) {
      bool leftIsStable = range.getMin() == newRange.getMin();
      range = newRange;	// Preserve any new step information
      if (landmark->contains(range)) {
	range.widen(*landmark,leftIsStable);
	return true;
      }
      else {
	CircleRange constraint = *landmark;
	constraint.invert();
	if (constraint.contains(range)) {
	  range.widen(constraint,leftIsStable);
	  return true;
	}
      }
    }
  }
  else if (valueSet.getCount() < fullIteration) {
    range = newRange;
    return true;
  }
  return false;		// Indicate that constrained widening failed (set to full)
}

int4 WidenerNone::determineIterationReset(const ValueSet &valueSet)

{
  if (valueSet.getCount() >= freezeIteration)
    return freezeIteration;	// Reset to point just after any widening
  return valueSet.getCount();
}

bool WidenerNone::checkFreeze(const ValueSet &valueSet)

{
  if (valueSet.getRange().isFull())
    return true;
  return (valueSet.getCount() >= freezeIteration);
}

bool WidenerNone::doWidening(const ValueSet &valueSet,CircleRange &range,const CircleRange &newRange)

{
  range = newRange;
  return true;
}

/// \brief Construct an iterator over the outbound edges of the given ValueSet node
///
/// Mostly this just forwards the ValueSets attached to output Varnodes
/// of the descendant ops of the Varnode attached to the given node, but this
/// allows for an artificial root node so we can simulate multiple input nodes.
/// \param node is the given ValueSet node (NULL if this is the simulated root)
/// \param roots is the list of input ValueSets to use for the simulated root
ValueSetSolver::ValueSetEdge::ValueSetEdge(ValueSet *node,const vector<ValueSet *> &roots)

{
  vn = node->getVarnode();
  if (vn == (Varnode *)0) {		// Assume this is the simulated root
    rootEdges = &roots;			// Set up for simulated edges
    rootPos = 0;
  }
  else {
    rootEdges = (const vector<ValueSet *> *)0;
    iter = vn->beginDescend();
  }
}

/// \brief Get the ValueSet pointed to by this iterator and advance the iterator
///
/// This method assumes all Varnodes with an attached ValueSet have been marked.
/// \return the next ValueSet or NULL if the end of the list is reached
ValueSet *ValueSetSolver::ValueSetEdge::getNext(void)

{
  if (vn == (Varnode *)0) {
    if (rootPos < rootEdges->size()) {
      ValueSet *res = (*rootEdges)[rootPos];
      rootPos += 1;
      return res;
    }
    return (ValueSet *)0;
  }
  while(iter != vn->endDescend()) {
    PcodeOp *op = *iter;
    ++iter;
    Varnode *outVn = op->getOut();
    if (outVn != (Varnode *)0 && outVn->isMark()) {
      return outVn->getValueSet();
    }
  }
  return (ValueSet *)0;
}

/// The new ValueSet is attached to the given Varnode
/// \param vn is the given Varnode
/// \param tCode is the type to associate with the Varnode
void ValueSetSolver::newValueSet(Varnode *vn,int4 tCode)

{
  valueNodes.emplace_back();
  valueNodes.back().setVarnode(vn, tCode);
}

/// This method saves a Partition to permanent storage. It marks the
/// starting node of the partition and sets up for the iterating algorithm.
/// \param part is the partition to store
void ValueSetSolver::partitionSurround(Partition &part)

{
  recordStorage.push_back(part);
  part.startNode->partHead = &recordStorage.back();
}

/// Knowing that the given Varnode is the head of a partition, generate
/// the partition recursively and generate the formal Partition object.
/// \param vertex is the given ValueSet (attached to the head Varnode)
/// \param part will hold the constructed Partition
void ValueSetSolver::component(ValueSet *vertex,Partition &part)

{
  ValueSetEdge edgeIterator(vertex,rootNodes);
  ValueSet *succ = edgeIterator.getNext();
  while(succ != (ValueSet *)0) {
    if (succ->count == 0)
      visit(succ,part);
    succ = edgeIterator.getNext();
  }
  partitionPrepend(vertex, part);
  partitionSurround(part);
}

/// \param vertex is the current Varnode being walked
/// \param part is the current Partition being constructed
/// \return the index of calculated head ValueSet for the current Parition
int4 ValueSetSolver::visit(ValueSet *vertex,Partition &part)

{
  nodeStack.push_back(vertex);
  depthFirstIndex += 1;
  vertex->count = depthFirstIndex;
  int4 head = depthFirstIndex;
  bool loop = false;
  ValueSetEdge edgeIterator(vertex,rootNodes);
  ValueSet *succ = edgeIterator.getNext();
  while(succ != (ValueSet *)0) {
    int4 min;
    if (succ->count == 0)
      min = visit(succ,part);
    else
      min = succ->count;
    if (min <= head) {
      head = min;
      loop = true;
    }
    succ = edgeIterator.getNext();
  }
  if (head == vertex->count) {
    vertex->count = 0x7fffffff;	// Set to "infinity"
    ValueSet *element = nodeStack.back();
    nodeStack.pop_back();
    if (loop) {
      while(element != vertex) {
	element->count = 0;
	element = nodeStack.back();
	nodeStack.pop_back();
      }
      Partition compPart;			// empty partition
      component(vertex,compPart);
      partitionPrepend(compPart, part);
    }
    else {
      partitionPrepend(vertex, part);
    }
  }
  return head;
}

/// \brief Establish the recursive node ordering for iteratively solving the value set system.
///
/// This algorithm is based on "Efficient chaotic iteration strategies with widenings" by
/// Francois Bourdoncle.  The Varnodes in the system are ordered and a set of nested
/// Partition components are generated.  Iterating the ValueSets proceeds in this order,
/// looping through the components recursively until a fixed point is reached.
/// This implementation assumes all Varnodes in the system are distinguished by
/// Varnode::isMark() returning \b true.
void ValueSetSolver::establishTopologicalOrder(void)

{
  for(list<ValueSet>::iterator iter=valueNodes.begin();iter!=valueNodes.end();++iter) {
    (*iter).count = 0;
    (*iter).next = (ValueSet *)0;
    (*iter).partHead = (Partition *)0;
  }
  ValueSet rootNode;
  rootNode.vn = (Varnode *)0;
  depthFirstIndex = 0;
  visit(&rootNode,orderPartition);
  orderPartition.startNode = orderPartition.startNode->next;	// Remove simulated root
}

/// \brief Generate an equation given a \b true constraint and the input/output Varnodes it affects
///
/// The equation is expressed as: only \b true values can reach the indicated input to a specific PcodeOp.
/// The equation is attached to the output of the PcodeOp.
/// \param vn is the output Varnode the equation will be attached to
/// \param op is the specific PcodeOp
/// \param slot is the input slot of the constrained input Varnode
/// \param type is the type of values
/// \param range is the range of \b true values
void ValueSetSolver::generateTrueEquation(Varnode *vn,PcodeOp *op,int4 slot,int4 type,const CircleRange &range)

{
  if (vn != (Varnode *) 0)
    vn->getValueSet()->addEquation(slot, type, range);
  else
    readNodes[op->getSeqNum()].addEquation(slot, type, range);// Special read site
}

/// \brief Generate the complementary equation given a \b true constraint and the input/output Varnodes it affects
///
/// The equation is expressed as: only \b false values can reach the indicated input to a specific PcodeOp.
/// The equation is attached to the output of the PcodeOp.
/// \param vn is the output Varnode the equation will be attached to
/// \param op is the specific PcodeOp
/// \param slot is the input slot of the constrained input Varnode
/// \param type is the type of values
/// \param range is the range of \b true values, which must be complemented
void ValueSetSolver::generateFalseEquation(Varnode *vn,PcodeOp *op,int4 slot,int4 type,const CircleRange &range)

{
  CircleRange falseRange(range);
  falseRange.invert();
  if (vn != (Varnode *) 0)
    vn->getValueSet()->addEquation(slot, type, falseRange);
  else
    readNodes[op->getSeqNum()].addEquation(slot, type, falseRange);// Special read site
}

/// \brief Look for PcodeOps where the given constraint range applies and instantiate an equation
///
/// If a read of the given Varnode is in a basic block dominated by the condition producing the
/// constraint, then either the constraint or its complement applies to the PcodeOp reading
/// the Varnode.  An equation holding the constraint is added to the ValueSet of the Varnode
/// output of the PcodeOp.
/// \param vn is the given Varnode
/// \param type is the constraint characteristic
/// \param range is the known constraint (assuming the \b true branch was taken)
/// \param cbranch is conditional branch creating the constraint
void ValueSetSolver::applyConstraints(Varnode *vn,int4 type,const CircleRange &range,PcodeOp *cbranch)

{
  FlowBlock *splitPoint = cbranch->getParent();
  FlowBlock *trueBlock,*falseBlock;
  if (cbranch->isBooleanFlip()) {
    trueBlock = splitPoint->getFalseOut();
    falseBlock = splitPoint->getTrueOut();
  }
  else {
    trueBlock = splitPoint->getTrueOut();
    falseBlock = splitPoint->getFalseOut();
  }
  // Check if the only path to trueBlock or falseBlock is via a splitPoint out-edge induced by the condition
  bool trueIsRestricted = trueBlock->restrictedByConditional(splitPoint);
  bool falseIsRestricted = falseBlock->restrictedByConditional(splitPoint);

  list<PcodeOp *>::const_iterator iter;
  if (vn->isWritten()) {
    ValueSet *vSet = vn->getValueSet();
    if (vSet->opCode == CPUI_MULTIEQUAL) {
      vSet->addLandmark(type,range);		// Leave landmark for widening
    }
  }
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    Varnode *outVn = (Varnode *)0;
    if (!op->isMark()) {	// If this is not a special read site
      outVn = op->getOut();	// Make sure there is a Varnode in the system
      if (outVn == (Varnode *)0) continue;
      if (!outVn->isMark()) continue;
    }
    FlowBlock *curBlock = op->getParent();
    int4 slot = op->getSlot(vn);
    if (op->code() == CPUI_MULTIEQUAL) {
      if (curBlock == trueBlock) {
	// If its possible that both the true and false edges can reach trueBlock
	// then the only input we can restrict is a MULTIEQUAL input along the exact true edge
	if (trueIsRestricted || trueBlock->getIn(slot) == splitPoint)
	  generateTrueEquation(outVn, op, slot, type, range);
	continue;
      }
      else if (curBlock == falseBlock) {
	// If its possible that both the true and false edges can reach falseBlock
	// then the only input we can restrict is a MULTIEQUAL input along the exact false edge
	if (falseIsRestricted || falseBlock->getIn(slot) == splitPoint)
	  generateFalseEquation(outVn, op, slot, type, range);
	continue;
      }
      else
	curBlock = curBlock->getIn(slot);	// MULTIEQUAL input is really only from one in-block
    }
    for(;;) {
      if (curBlock == trueBlock) {
	if (trueIsRestricted)
	  generateTrueEquation(outVn, op, slot, type, range);
	break;
      }
      else if (curBlock == falseBlock) {
	if (falseIsRestricted)
	  generateFalseEquation(outVn, op, slot, type, range);
	break;
      }
      else if (curBlock == splitPoint || curBlock == (FlowBlock *)0)
	break;
      curBlock = curBlock->getImmedDom();
    }
  }
}

/// \brief Generate constraints given a Varnode path
///
/// Knowing that there is a lifting path from the given starting Varnode to an ending Varnode
/// in the system, go ahead and lift the given range to a final constraint on the ending
/// Varnode.  Then look for reads of the Varnode where the constraint applies.
/// \param type is the constraint characteristic
/// \param lift is the given range that will be lifted
/// \param startVn is the starting Varnode
/// \param endVn is the given ending Varnode in the system
/// \param cbranch is the PcodeOp causing the control-flow split
void ValueSetSolver::constraintsFromPath(int4 type,CircleRange &lift,Varnode *startVn,Varnode *endVn,PcodeOp *cbranch)

{
  while(startVn != endVn) {
    Varnode *constVn;
    startVn = lift.pullBack(startVn->getDef(),&constVn,false);
    if (startVn == (Varnode *)0) return;	// Couldn't pull all the way back to our value set
  }
  for(;;) {
    Varnode *constVn;
    applyConstraints(endVn,type,lift,cbranch);
    if (!endVn->isWritten()) break;
    PcodeOp *op = endVn->getDef();
    if (op->isCall() || op->isMarker()) break;
    endVn = lift.pullBack(op,&constVn,false);
    if (endVn == (Varnode *)0) break;
    if (!endVn->isMark()) break;
  }
}

/// Lift the set of values on the condition for the given CBRANCH to any
/// Varnode in the system, and label (the reads) of any such Varnode with
/// the constraint. If the values cannot be lifted or no Varnode in the system
/// is found, no constraints are generated.
/// \param cbranch is the given condition branch
void ValueSetSolver::constraintsFromCBranch(PcodeOp *cbranch)

{
  Varnode *vn = cbranch->getIn(1); // Get Varnode deciding the condition
  while(!vn->isMark()) {
    if (!vn->isWritten()) break;
    PcodeOp *op = vn->getDef();
    if (op->isCall() || op->isMarker())
      break;
    int4 num = op->numInput();
    if (num == 0 || num > 2) break;
    vn = op->getIn(0);
    if (num == 2) {
      if (vn->isConstant())
	vn = op->getIn(1);
      else if (!op->getIn(1)->isConstant()) {
	// If we reach here, both inputs are non-constant
	generateRelativeConstraint(op, cbranch);
	return;
      }
      // If we reach here, vn is non-constant, other input is constant
    }
  }
  if (vn->isMark()) {
    CircleRange lift(true);
    Varnode *startVn = cbranch->getIn(1);
    constraintsFromPath(0,lift,startVn,vn,cbranch);
  }
}

/// Given a complete data-flow system of Varnodes, look for any \e constraint:
///   - For a particular Varnode
///   - A limited set of values
///   - Due to its involvement in a branch condition
///   - Which applies at a particular \e read of the Varnode
///
/// \param worklist is the set of Varnodes in the data-flow system (all marked)
/// \param reads is the additional set of PcodeOps that read a Varnode from the system
void ValueSetSolver::generateConstraints(const vector<Varnode *> &worklist,const vector<PcodeOp *> &reads)

{
  vector<FlowBlock *> blockList;
  // Collect all blocks that contain a system op (input) or dominate a container
  for(int4 i=0;i<worklist.size();++i) {
    PcodeOp *op = worklist[i]->getDef();
    if (op == (PcodeOp *)0) continue;
    FlowBlock *bl = op->getParent();
    if (op->code() == CPUI_MULTIEQUAL) {
      for(int4 j=0;j<bl->sizeIn();++j) {
	FlowBlock *curBl = bl->getIn(j);
	do {
	  if (curBl->isMark()) break;
	  curBl->setMark();
	  blockList.push_back(curBl);
	  curBl = curBl->getImmedDom();
	} while(curBl != (FlowBlock *)0);
      }
    }
    else {
      do {
	if (bl->isMark()) break;
	bl->setMark();
	blockList.push_back(bl);
	bl = bl->getImmedDom();
      } while(bl != (FlowBlock *)0);
    }
  }
  for(int4 i=0;i<reads.size();++i) {
    FlowBlock *bl = reads[i]->getParent();
    do {
      if (bl->isMark()) break;
      bl->setMark();
      blockList.push_back(bl);
      bl = bl->getImmedDom();
    } while(bl != (FlowBlock *)0);
  }
  for(int4 i=0;i<blockList.size();++i)
    blockList[i]->clearMark();

  vector<FlowBlock *> finalList;
  // Now go through input blocks to the previously calculated blocks
  for(int4 i=0;i<blockList.size();++i) {
    FlowBlock *bl = blockList[i];
    for(int4 j=0;j<bl->sizeIn();++j) {
      BlockBasic *splitPoint = (BlockBasic *)bl->getIn(j);
      if (splitPoint->isMark()) continue;
      if (splitPoint->sizeOut() != 2) continue;
      PcodeOp *lastOp = splitPoint->lastOp();
      if (lastOp != (PcodeOp *)0 && lastOp->code() == CPUI_CBRANCH) {
	splitPoint->setMark();
	finalList.push_back(splitPoint);
	constraintsFromCBranch(lastOp);		// Try to generate constraints from this splitPoint
      }
    }
  }
  for(int4 i=0;i<finalList.size();++i)
    finalList[i]->clearMark();
}

/// Verify that the given Varnode is produced by a straight line sequence of
/// COPYs, INT_ADDs with a constant, from the base register marked as \e relative
/// for our system.
/// \param vn is the given Varnode
/// \param typeCode will hold the base register code (if found)
/// \param value will hold the additive value relative to the base register (if found)
/// \return \b true if the Varnode is a \e relative constant
bool ValueSetSolver::checkRelativeConstant(Varnode *vn,int4 &typeCode,uintb &value) const

{
  value = 0;
  for(;;) {
    if (vn->isMark()) {
      ValueSet *valueSet = vn->getValueSet();
      if (valueSet->typeCode != 0) {
	typeCode = valueSet->typeCode;
	break;
      }
    }
    if (!vn->isWritten()) return false;
    PcodeOp *op = vn->getDef();
    OpCode opc = op->code();
    if (opc == CPUI_COPY || opc == CPUI_INDIRECT)
      vn = op->getIn(0);
    else if (opc == CPUI_INT_ADD || opc == CPUI_PTRSUB) {
      Varnode *constVn = op->getIn(1);
      if (!constVn->isConstant())
	return false;
      value = (value + constVn->getOffset()) & calc_mask(constVn->getSize());
      vn = op->getIn(0);
    }
    else
      return false;
  }
  return true;
}

/// Given a binary PcodeOp producing a conditional branch, check if it can be interpreted
/// as a constraint relative to (the) base register specified for this system. If it can
/// be, a \e relative Equation is generated, which will apply to \e relative ValueSets.
/// \param compOp is the comparison PcodeOp
/// \param cbranch is the conditional branch
void ValueSetSolver::generateRelativeConstraint(PcodeOp *compOp,PcodeOp *cbranch)

{
  OpCode opc = compOp->code();
  switch(opc) {
    case CPUI_INT_LESS:
      opc = CPUI_INT_SLESS;	// Treat unsigned pointer comparisons as signed relative to the base register
      break;
    case CPUI_INT_LESSEQUAL:
      opc = CPUI_INT_SLESSEQUAL;
      break;
    case CPUI_INT_SLESS:
    case CPUI_INT_SLESSEQUAL:
    case CPUI_INT_EQUAL:
    case CPUI_INT_NOTEQUAL:
      break;
    default:
      return;
  }
  int4 typeCode;
  uintb value;
  Varnode *vn;
  Varnode *inVn0 = compOp->getIn(0);
  Varnode *inVn1 = compOp->getIn(1);
  CircleRange lift(true);
  if (checkRelativeConstant(inVn0, typeCode, value)) {
    vn = inVn1;
    if (!lift.pullBackBinary(opc, value, 1, vn->getSize(), 1))
      return;
  }
  else if (checkRelativeConstant(inVn1,typeCode,value)) {
    vn = inVn0;
    if (!lift.pullBackBinary(opc, value, 0, vn->getSize(), 1))
      return;
  }
  else
    return;		// Neither side looks like a relative constant

  Varnode *endVn = vn;
  while(!endVn->isMark()) {
    if (!endVn->isWritten()) return;
    PcodeOp *op = endVn->getDef();
    opc = op->code();
    if (opc == CPUI_COPY || opc == CPUI_PTRSUB) {
      endVn = op->getIn(0);
    }
    else if (opc == CPUI_INT_ADD) {	// Can pull-back through INT_ADD
      if (!op->getIn(1)->isConstant())	// if second param is constant
	return;
      endVn = op->getIn(0);
    }
    else
      return;
  }
  constraintsFromPath(typeCode,lift,vn,endVn,cbranch);
}

/// \brief Build value sets for a data-flow system
///
/// Given a set of sinks, find all the Varnodes that flow directly into them and set up their
/// initial ValueSet objects.
/// \param sinks is the list terminating Varnodes
/// \param reads are add-on PcodeOps where we would like to know input ValueSets at the point of read
/// \param stackReg (if non-NULL) gives the stack pointer (for keeping track of relative offsets)
/// \param indirectAsCopy is \b true if solver should treat CPUI_INDIRECT as CPUI_COPY operations
void ValueSetSolver::establishValueSets(const vector<Varnode *> &sinks,const vector<PcodeOp *> &reads,Varnode *stackReg,
					bool indirectAsCopy)

{
  vector<Varnode *> worklist;
  int4 workPos = 0;
  if (stackReg != (Varnode *)0) {
    newValueSet(stackReg,1);		// Establish stack pointer as special
    stackReg->setMark();
    worklist.push_back(stackReg);
    workPos += 1;
    rootNodes.push_back(stackReg->getValueSet());
  }
  for(int4 i=0;i<sinks.size();++i) {
    Varnode *vn = sinks[i];
    newValueSet(vn,0);
    vn->setMark();
    worklist.push_back(vn);
  }
  while(workPos < worklist.size()) {
    Varnode *vn = worklist[workPos];
    workPos += 1;
    if (!vn->isWritten()) {
      if (vn->isConstant()) {
	// Constant inputs to binary ops should not be treated as root nodes as they
	// get picked up during iteration by the other input, except in the case of a
	// a PTRSUB from a spacebase constant.
	if (vn->isSpacebase() || vn->loneDescend()->numInput() == 1)
	  rootNodes.push_back(vn->getValueSet());
      }
      else
	rootNodes.push_back(vn->getValueSet());
      continue;
    }
    PcodeOp *op = vn->getDef();
    switch(op->code()) {	// Distinguish ops where we can never predict an integer range
      case CPUI_INDIRECT:
	if (indirectAsCopy || op->isIndirectStore()) {
	  Varnode *inVn = op->getIn(0);
	  if (!inVn->isMark()) {
	    newValueSet(inVn,0);
	    inVn->setMark();
	    worklist.push_back(inVn);
	  }
	}
	else {
	  vn->getValueSet()->setFull();
	  rootNodes.push_back(vn->getValueSet());
	}
	break;
      case CPUI_CALL:
      case CPUI_CALLIND:
      case CPUI_CALLOTHER:
      case CPUI_LOAD:
      case CPUI_NEW:
      case CPUI_SEGMENTOP:
      case CPUI_CPOOLREF:
      case CPUI_FLOAT_ADD:
      case CPUI_FLOAT_DIV:
      case CPUI_FLOAT_MULT:
      case CPUI_FLOAT_SUB:
      case CPUI_FLOAT_NEG:
      case CPUI_FLOAT_ABS:
      case CPUI_FLOAT_SQRT:
      case CPUI_FLOAT_INT2FLOAT:
      case CPUI_FLOAT_FLOAT2FLOAT:
      case CPUI_FLOAT_TRUNC:
      case CPUI_FLOAT_CEIL:
      case CPUI_FLOAT_FLOOR:
      case CPUI_FLOAT_ROUND:
	vn->getValueSet()->setFull();
	rootNodes.push_back(vn->getValueSet());
	break;
      default:
	for(int4 i=0;i<op->numInput();++i) {
	  Varnode *inVn = op->getIn(i);
	  if (inVn->isMark() || inVn->isAnnotation()) continue;
	  newValueSet(inVn,0);
	  inVn->setMark();
	  worklist.push_back(inVn);
	}
	break;
    }
  }
  for(int4 i=0;i<reads.size();++i) {
    PcodeOp *op = reads[i];
    for(int4 slot=0;slot<op->numInput();++slot) {
      Varnode *vn = op->getIn(slot);
      if (vn->isMark()) {
	readNodes[op->getSeqNum()].setPcodeOp(op, slot);
	op->setMark();			// Mark read ops for equation generation stage
	break;			// Only 1 read allowed
      }
    }
  }
  generateConstraints(worklist,reads);
  for(int4 i=0;i<reads.size();++i)
    reads[i]->clearMark();		// Clear marks on read ops

  establishTopologicalOrder();
  for(int4 i=0;i<worklist.size();++i)
    worklist[i]->clearMark();
}

/// The ValueSets are recalculated in the established topological ordering, with looping
/// at various levels until a fixed point is reached.
/// \param max is the maximum number of iterations to allow before forcing termination
/// \param widener is the Widening strategy to use to accelerate stabilization
void ValueSetSolver::solve(int4 max,Widener &widener)

{
  maxIterations = max;
  numIterations = 0;
  for(list<ValueSet>::iterator iter=valueNodes.begin();iter!=valueNodes.end();++iter)
    (*iter).count = 0;

  vector<Partition *> componentStack;
  Partition *curComponent = (Partition *)0;
  ValueSet *curSet = orderPartition.startNode;

  while(curSet != (ValueSet *)0) {
    numIterations += 1;
    if (numIterations > maxIterations) break;	// Quit if max iterations exceeded
    if (curSet->partHead != (Partition *)0 && curSet->partHead != curComponent) {
      componentStack.push_back(curSet->partHead);
      curComponent = curSet->partHead;
      curComponent->isDirty = false;
      // Reset component counter upon entry
      curComponent->startNode->count = widener.determineIterationReset(*curComponent->startNode);
    }
    if (curComponent != (Partition *)0) {
      if (curSet->iterate(widener))
	curComponent->isDirty = true;
      if (curComponent->stopNode != curSet) {
	curSet = curSet->next;
      }
      else {
	for(;;) {
	  if (curComponent->isDirty) {
	    curComponent->isDirty = false;
	    curSet = curComponent->startNode;
	    if (componentStack.size() > 1) {	// Mark parent as dirty if we are restarting dirty child
	      componentStack[componentStack.size()-2]->isDirty = true;
	    }
	    break;
	  }

	  componentStack.pop_back();
	  if (componentStack.empty()) {
	    curComponent = (Partition *)0;
	    curSet = curSet->next;
	    break;
	  }
	  curComponent = componentStack.back();
	  if (curComponent->stopNode != curSet) {
	    curSet = curSet->next;
	    break;
	  }
	}
      }
    }
    else {
      curSet->iterate(widener);
      curSet = curSet->next;
    }
  }
  map<SeqNum,ValueSetRead>::iterator riter;
  for(riter=readNodes.begin();riter!=readNodes.end();++riter)
    (*riter).second.compute();				// Calculate any follow-on value sets
}

#ifdef CPUI_DEBUG
void ValueSetSolver::dumpValueSets(ostream &s) const

{
  list<ValueSet>::const_iterator iter;
  for(iter=valueNodes.begin();iter!=valueNodes.end();++iter) {
    (*iter).printRaw(s);
    s << endl;
  }
  map<SeqNum,ValueSetRead>::const_iterator riter;
  for(riter=readNodes.begin();riter!=readNodes.end();++riter) {
    (*riter).second.printRaw(s);
    s << endl;
  }
}

#endif

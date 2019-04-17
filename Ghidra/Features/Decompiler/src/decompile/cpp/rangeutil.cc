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

const char CircleRange::arrange[] = "gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

void CircleRange::calcStepShift(void)

{
  shift = 0;
  step = 1;
  uintb maskcopy = mask;
  while((maskcopy & 1)==0) {
    maskcopy >>= 1;
    shift += 1;
    step <<= 1;
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
///   - 0 and 1   => the new range is everything
///   - 0 only    => the new range is [0,1)
///   - 1 only    => the new range is [1,0)
///   - neither 0 or 1  =>  the new range is empty
void CircleRange::convertToBoolean(void)

{
  if (isempty) return;
  bool contains_zero = contains(0);
  bool contains_one = contains(1);
  mask = 1;
  step = 1;
  shift = 0;
  if (contains_zero && contains_one) {
    left = right = 0;
    isempty = false;
  }
  else if (contains_zero) {
    left = 0;
    right = 1;
    isempty = false;
  }
  else if (contains_one) {
    left = 1;
    right = 0;
    isempty = false;
  }
  else
    isempty = true;
}

/// Given a range mask, restrict a left/right specified range to a new size and stride.
/// This assumes the specified range is not empty.
/// \param newmask is the mask encoding the new size and stride
/// \param myleft is a reference to the left boundary of the specified range
/// \param myright is a reference to the right boundary of the specified range
/// \return \b true if result is empty
bool CircleRange::newStride(uintb newmask,uintb &myleft,uintb &myright)

{
  if (myleft > newmask) {
    if (myright > newmask) {	// Both bounds out of range of newmask
      if (myleft < myright) return true; // Old range is completely out of bounds of new mask
      myleft = 0;
      myright = 0;		// Old range contained everything in newmask
      return false; 
    }
    myleft = 0;			// Take everything up to left edge of new range
  }
  if (myright > newmask) {
    myright = 0;		// Take everything up to right edge of new range
  }
  if (myleft == myright) {
    myleft = 0;			// Normalize the everything
    myright = 0;
    return false;
  }
  uintb tmp = (myleft + (~newmask)) & newmask; // Bump boundaries up to proper stride post
  uintb tmpr = (myright + (~newmask)) & newmask;
  if (tmpr==tmp) {		// If the bounds are now equal
    if (tmp!=myleft) return true; // We cut elements out from left end and now nothing is left
    myleft = 0;
    myright = 0;		// Or all missing missing elements in old range, were off-stride,
    return false;		//   and now we have everything
  }
  myleft = tmp;
  myright = tmpr;
  return false;			// not empty
}

/// Give specific left/right boundaries and a mask.
/// \param mn is the left boundary of the range
/// \param mx is the right boundary of the range
/// \param m is the mask encoding a size and stride
CircleRange::CircleRange(uintb mn,uintb mx,uintb m)

{
  mask = m;
  calcStepShift();
  left = mn;
  right = (mx+step)&mask;
  isempty = false;
}

/// The range contains only a single integer, 0 or 1, depending on the boolean parameter.
/// \param val is the boolean parameter
CircleRange::CircleRange(bool val)

{
  left = val ? 1: 0;
  mask = 1;
  step = 1;
  shift = 0;
  right = val ? 0 : 1;
  isempty = false;
}

/// A size specifies the number of bytes (*8 to get number of bits) in the mask.
/// The stride is assumed to be 1.
/// \param val is is the single value
/// \param size is the size of the mask in bytes
CircleRange::CircleRange(uintb val,int4 size)

{
  mask = calc_mask(size);
  shift = 0;
  step = 1;
  left = val;
  right = (left+1)&mask;
  isempty = false;
}

/// \return the number of integers contained in this range
uintb CircleRange::getSize(void) const

{
  if (isempty) return 0;
  uintb val;
  if (left < right)
    val = (right-left) >> shift;
  else {
    val = (mask - (left-right) + step) >> shift;
    if (val == 0) {		// This is an overflow, when all uintb values are in the range
      val = mask;               // We lie by one, which shouldn't matter for our jumptable application
      if (shift > 0) {
	val = val >> shift;
	val += 1;
      }
    }
  }
  return val;
}

/// \param op2 is the specific range to test for containment.
/// \return \b true if \b true contains the interval \b op2
bool CircleRange::contains(const CircleRange &op2) const

{
  if (isempty)
    return op2.isempty;
  if (op2.isempty)
    return true;
  if (shift > op2.shift) return false; // Cannot be containment because step is wrong
  if (left == right) return true;
  if (op2.left == op2.right) return false;

  char overlapCode = encodeRangeOverlaps(left, right, op2.left, op2.right);

  return (overlapCode == 'c');

  // Missing one case where op2.step > this->step, and the boundaries don't show containment,
  // but there is containment because the lower step size UP TO right still contains the edge points
}

/// Check if a specific integer is a member of \b this range.
/// \param val is the specific integer
/// \return \b true if it is contained in \b this
bool CircleRange::contains(uintb val) const

{
  if (isempty) return false;
  if ((mask & val)!=val) return false; // Step is wrong
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
    left = op2.left;
    right = op2.right;
    isempty = op2.isempty;
    mask = op2.mask;
    step = op2.step;
    shift = op2.shift;
    return 0;
  }
  if (mask != op2.mask) return 2; // Cannot do proper union with different strides
  if ((left==right)||(op2.left==op2.right)) {
    left = 0;
    right = 0;
    return 0;
  }

  char overlapCode = encodeRangeOverlaps(left, right, op2.left, op2.right);
  switch(overlapCode) {
  case 'a':			// order (l r op2.l op2.r)
  case 'f':			// order (op2.l op2.r l r)
    if (right==op2.left) {
      //      left = left;
      right = op2.right;
      return 0;
    }
    if (left==op2.right) {
      left = op2.left;
      //      right = right;
      return 0;
    }
    return 2;			// 2 pieces;
  case 'b':			// order (l op2.l r op2.r)
    //    left = left;
    right = op2.right;
    return 0;
  case 'c':			// order (l op2.l op2.r r)
    //    left = left;
    //    right = right;
    return 0;
  case 'd':			// order (op2.l l r op2.r)
    left = op2.left;
    right = op2.right;
    return 0;
  case 'e':		       // order (op2.l l op2.r r)
    left = op2.left;
    //    right = right;
    return 0;
  case 'g':			// either impossible or covers whole circle
    left = 0;
    right = 0;
    return 0;			// entire circle is covered
  }
  return -1;			// Never reach here
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
  int4 retval;
  uintb myleft,myright,op2left,op2right;
  uintb newmask;
  bool myisempty,op2isempty;

  if (isempty) return 0;	// Intersection with empty is empty
  if (op2.isempty) {
    isempty = true;
    return 0;
  }
  newmask = mask & op2.mask;
  myleft = left;
  myright = right;
  op2left = op2.left;
  op2right = op2.right;
  myisempty = newStride(newmask,myleft,myright);
  op2isempty = newStride(newmask,op2left,op2right);
  if (myisempty || op2isempty) {
    isempty = true;
    return 0;
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
  if (mask != newmask) {
    mask = newmask;
    step = op2.step;
    shift = op2.shift;
  }
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
      shift = 0;
      step = 1;
      left = 0;
      right = 1;		// Range containing only zero
    }
    else {			// All ones
      shift = 0;
      step = 1;
      left = 0;
      right = 0;		// Everything
    }
    return true;
  }
  shift = leastsigbit_set(nzmask);
  step = 1;
  step <<= shift;
  mask = calc_mask(size);
  mask = mask & (mask << shift);
  left = 0;
  right = (nzmask + step) & mask;
  return true;
}

/// The new stride is specified by giving the number of bits of shift (log2(stride))
/// \param newshift is the number of bits of shift
void CircleRange::setStride(int4 newshift)

{
  bool iseverything = (!isempty) && (left==right);
  if (newshift == shift) return;
  if (newshift < shift) {
    while(newshift < shift) {
      step >>= 1;
      mask = mask | (mask >> 1); // Add a bit to mask
      shift -= 1;
    }
  }
  else {
    while(newshift > shift) {
      step <<= 1;
      mask = mask & (mask << 1); // Remove a bit from mask
      shift += 1;
    }
  }
  left &= mask;
  right &= mask;
  if ((!iseverything)&&(left == right))
    isempty = true;
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
  Varnode *res,*constvn;
  uintb val;
  bool yescomplement;

  if ((op->numInput()==0)||(op->numInput()>2))
    return (Varnode *)0;

  // Find non-constant varnode input, and slot
  // If there are two inputs, make sure second is constant
  int4 slot = 0;
  res = op->getIn(slot);
  if (op->numInput()==2)
    constvn = op->getIn(1-slot);
  else
    constvn = (Varnode *)0;
  if (res->isConstant()) {
    if (op->numInput()==1) return (Varnode *)0;
    slot = 1;
    constvn = res;
    res = op->getIn(slot);
    if (res->isConstant())
      return (Varnode *)0;
  }
  else if ((op->numInput()==2)&&(!constvn->isConstant()))
    return (Varnode *)0;

  // If there is nothing in the output set, no input will map to it
  if (isempty) return res;

  switch(op->code()) {
  case CPUI_BOOL_NEGATE:
    convertToBoolean();
    if (left==right) break;	// Both outputs possible => both inputs possible
    left = left ^ 1;		// Flip the boolean range
    right = right ^ 1;
    break;
  case CPUI_INT_EQUAL:
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
    left = val;
    right = (val+1)&mask;
    if (yescomplement)
      complement();
    break;
  case CPUI_INT_NOTEQUAL:
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
    left = (val+1)&mask;
    right = val;
    if (yescomplement)
      complement();
    break;
  case CPUI_INT_LESS:
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
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
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
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
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
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
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
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
    convertToBoolean();
    mask = calc_mask(res->getSize());
    if (left==right) break;	// All possible outs => all possible ins
    yescomplement = (left==0);
    val = constvn->getOffset();
    if (val==0)
      isempty = true;		// Nothing carries adding zero
    else {
      left = ((mask-val)+1)&mask;
      right = 0;
    }
    if (yescomplement)
      complement();
    break;
  case CPUI_COPY:
    break;			// Identity transform on range
  case CPUI_INT_ADD:
    val = constvn->getOffset();
    if ((val&mask) == val) { // Constant must match the stride
      left = (left-val)&mask;
      right = (right-val)&mask;
    }
    else
      res = (Varnode *)0;
    break;
  case CPUI_INT_SUB:
    val = constvn->getOffset();
    if ((val&mask) == val) {	// Constant must match the stride
      if (slot==0) {
	left = (left+val)&mask;
	right = (right+val)&mask;
      }
      else {
	left = (val-left)&mask;
	right = (val-right)&mask;
      }
    }
    else
      res = (Varnode *)0;
    break;
  case CPUI_INT_2COMP:
    val = (~left + 1 + step) & mask;
    left = (~right + 1 + step) & mask;
    right = val;
    break;
  case CPUI_SUBPIECE:
    if ((!usenzmask)||(constvn->getOffset() != 0))
      res = (Varnode *)0;
    else {			// If everything we are truncating is known to be zero, we may still have a range
      int4 msbset = mostsigbit_set(res->getNZMask());
      msbset = (msbset + 8)/8;
      if (op->getOut()->getSize() < msbset) // Some bytes we are chopping off might not be zero
	res = (Varnode *)0;
      else {
	mask = calc_mask(res->getSize()); // Keep the range but mask the mask bigger
	// If the range wraps (left>right) then, increasing the mask adds all the new space into
	// the range, and it would be an inaccurate pullback by itself, but with the nzmask intersection
	// all the new space will get intersected away again.
      }
    }
    break;
  case CPUI_INT_ZEXT:
    {
      val = calc_mask(res->getSize()); // (smaller) input mask
      CircleRange zextrange;
      zextrange.left = 0;
      zextrange.right = val+1;	// Biggest possible range of ZEXT
      zextrange.mask = mask;
      zextrange.step = step;	// Keep the same stride
      zextrange.shift = shift;
      zextrange.isempty = false;
      if (0!=intersect(zextrange))
	res = (Varnode *)0;
      left &= val;
      right &= val;
      mask &= val;		// Preserve the stride
    }
    break;
  case CPUI_INT_SEXT:
    {
      val = calc_mask(res->getSize()); // (smaller) input mask
      CircleRange sextrange;
      sextrange.left = val ^ (val>>1); // High order bit for (small) input space
      sextrange.right = sign_extend(sextrange.left,res->getSize(),op->getOut()->getSize());
      sextrange.mask = mask;
      sextrange.step = step;	// Keep the same stride
      sextrange.shift = shift;
      sextrange.isempty = false;
      if (sextrange.intersect(*this) != 0)
	res = (Varnode *)0;
      else {
	if (!sextrange.isEmpty())
	  res = (Varnode *)0;
	else {
	  left &= val;
	  right &= val;
	  mask &= val;		// Preserve the stride
	}
      }
    }
    break;
  case CPUI_INT_RIGHT:
    {
      if (step == 1) {
	val = (calc_mask(res->getSize()) >> constvn->getOffset()) + 1; // The maximal right bound
	if (((left >= val)&&(right >= val)&&(left>=right))||
	    ((left == 0)&&(right>=val))||
	    (left == right)) {
	  // covers everything in range of shift
	  left=0;		// So domain is everything
	  right=0;
	}
	else {
	  if (left > val)
	    left = val;
	  if (right > val)
	    right = 0;
	  left = (left << constvn->getOffset()) & mask;
	  right = (right << constvn->getOffset()) & mask;
	  if (left == right)
	    isempty = true;
	}
      }
      else
	res = (Varnode *)0;
    }
    break;
  case CPUI_INT_SRIGHT:
    {
      if (step == 1) {
	uintb rightb = calc_mask(res->getSize());
	uintb leftb = rightb >> (constvn->getOffset()+1);
	rightb = leftb ^ rightb; // Smallest negative possible
	leftb += 1;		// Biggest positive (+1) possible
	if (((left >= leftb)&&(left <= rightb)&&
	     (right >= leftb)&&(right <= rightb)&&
	     (left >= right))
	    || (left==right)) {
	  // covers everything in range of shift
	  left = 0;		// So domain is everything
	  right = 0;
	}
	else {
	  if ((left > leftb)&&(left < rightb))
	    left = leftb;
	  if ((right > leftb)&&(right < rightb))
	    right = rightb;
	  left = (left << constvn->getOffset()) &mask;
	  right = (right << constvn->getOffset()) & mask;
	  if (left == right)
	    isempty = true;
	}
      }
      else
	res = (Varnode *)0;
    }
    break;
  default:
    res = (Varnode *)0;
    break;
  }
  if ((constvn != (Varnode *)0)&&(constvn->getSymbolEntry() != (SymbolEntry *)0))
    *constMarkup = constvn;
  if ((res != (Varnode *)0)&&usenzmask) {
    CircleRange nzrange;
    if (!nzrange.setNZMask(res->getNZMask(),res->getSize()))
      return res;
    if (0!=intersect(nzrange))
      return (Varnode *)0;
  }
  return res;
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

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
#include "cast.hh"
#include "op.hh"

/// Sets the TypeFactory used to produce data-types for the arithmeticOutputStandard() method
/// \param t is the TypeFactory
void CastStrategy::setTypeFactory(TypeFactory *t)

{
  tlst = t;
  promoteSize = tlst->getSizeOfInt();
}

bool CastStrategyC::checkIntPromotionForCompare(const PcodeOp *op,int4 slot) const

{
  const Varnode *vn = op->getIn(slot);
  int4 exttype1 = intPromotionType(vn);
  if (exttype1 == NO_PROMOTION) return false;
  if (exttype1 == UNKNOWN_PROMOTION) return true;	// If there is promotion and we don't know type, we need a cast

  int4 exttype2 = intPromotionType(op->getIn(1-slot));
  if ((exttype1 & exttype2) != 0)	// If both sides share a common extension, then these bits aren't determining factor
    return false;
  if (exttype2 == NO_PROMOTION) {
    // other side would not have integer promotion, but our side is forcing it
    // but both sides get extended in the same way
    return false;
  }
  return true;
}

bool CastStrategyC::checkIntPromotionForExtension(const PcodeOp *op) const

{
  const Varnode *vn = op->getIn(0);
  int4 exttype = intPromotionType(vn);
  if (exttype == NO_PROMOTION) return false;
  if (exttype == UNKNOWN_PROMOTION) return true;	// If there is an extension and we don't know type, we need a cast

  // Test if the promotion extension matches the explicit extension
  if (((exttype & UNSIGNED_EXTENSION) != 0) && (op->code() == CPUI_INT_ZEXT)) return false;
  if (((exttype & SIGNED_EXTENSION) != 0) && (op->code() == CPUI_INT_SEXT)) return false;
  return true;		// Otherwise we need a cast before we extend
}

int4 CastStrategyC::localExtensionType(const Varnode *vn) const

{
  type_metatype meta = vn->getHigh()->getType()->getMetatype();
  int4 natural;		// 1= natural zero extension, 2= natural sign extension
  if ((meta == TYPE_UINT)||(meta == TYPE_BOOL)||(meta == TYPE_UNKNOWN))
    natural = UNSIGNED_EXTENSION;
  else if (meta == TYPE_INT)
    natural = SIGNED_EXTENSION;
  else
    return UNKNOWN_PROMOTION;
  if (vn->isConstant()) {
    if (!signbit_negative(vn->getOffset(),vn->getSize()))	// If the high-bit is zero
      return EITHER_EXTENSION;					// Can be viewed as either extension
    return natural;
  }
  if (vn->isExplicit())
    return natural;
  if (!vn->isWritten())
    return UNKNOWN_PROMOTION;
  const PcodeOp *op = vn->getDef();
  if (op->isBoolOutput())
    return EITHER_EXTENSION;
  OpCode opc = op->code();
  if ((opc == CPUI_CAST)||(opc == CPUI_LOAD)||op->isCall())
    return natural;
  if (opc == CPUI_INT_AND) {		// This is kind of recursing
    const Varnode *tmpvn = op->getIn(1);
    if (tmpvn->isConstant()) {
      if (!signbit_negative(tmpvn->getOffset(),tmpvn->getSize()))
	return EITHER_EXTENSION;
      return natural;
    }
  }
  return UNKNOWN_PROMOTION;
}

int4 CastStrategyC::intPromotionType(const Varnode *vn) const

{
  int4 val;
  if (vn->getSize() >= promoteSize)
    return NO_PROMOTION;
  if (vn->isConstant())
    return localExtensionType(vn);
  if (vn->isExplicit())
    return NO_PROMOTION;
  if (!vn->isWritten()) return UNKNOWN_PROMOTION;
  const PcodeOp *op = vn->getDef();
  const Varnode *othervn;
  switch(op->code()) {
  case CPUI_INT_AND:
    othervn = op->getIn(1);
    if ((localExtensionType(othervn) & UNSIGNED_EXTENSION) != 0)
      return UNSIGNED_EXTENSION;
    othervn = op->getIn(0);
    if ((localExtensionType(othervn) & UNSIGNED_EXTENSION) != 0)
      return UNSIGNED_EXTENSION;	// If either side has zero extension, result has zero extension
    break;
  case CPUI_INT_RIGHT:
    othervn = op->getIn(0);
    val = localExtensionType(othervn);
    if ((val & UNSIGNED_EXTENSION) != 0)	// If the input provably zero extends
      return val;				// then the result is a zero extension (plus possibly a sign extension)
    break;
  case CPUI_INT_SRIGHT:
    othervn = op->getIn(0);
    val = localExtensionType(othervn);
    if ((val & SIGNED_EXTENSION) != 0)		// If input can be construed as a sign-extension
      return val;				// then the result is a sign extension (plus possibly a zero extension)
    break;
  case CPUI_INT_XOR:
  case CPUI_INT_OR:
  case CPUI_INT_DIV:
  case CPUI_INT_REM:
    othervn = op->getIn(0);
    if ((localExtensionType(othervn) & UNSIGNED_EXTENSION) == 0)
      return UNKNOWN_PROMOTION;
    othervn = op->getIn(1);
    if ((localExtensionType(othervn) & UNSIGNED_EXTENSION) == 0)
      return UNKNOWN_PROMOTION;
    return UNSIGNED_EXTENSION;		// If both sides have zero extension, result has zero extension
  case CPUI_INT_SDIV:
  case CPUI_INT_SREM:
    othervn = op->getIn(0);
    if ((localExtensionType(othervn) & SIGNED_EXTENSION) == 0)
      return UNKNOWN_PROMOTION;
    othervn = op->getIn(1);
    if ((localExtensionType(othervn) & SIGNED_EXTENSION) == 0)
      return UNKNOWN_PROMOTION;
    return SIGNED_EXTENSION;		// If both sides have sign extension, result has sign extension
  case CPUI_INT_NEGATE:
  case CPUI_INT_2COMP:
    othervn = op->getIn(0);
    if ((localExtensionType(othervn) & SIGNED_EXTENSION) != 0)
      return SIGNED_EXTENSION;
    break;
  case CPUI_INT_ADD:
  case CPUI_INT_SUB:
  case CPUI_INT_LEFT:
  case CPUI_INT_MULT:
    break;
  default:
    return NO_PROMOTION;		// No integer promotion at all
  }
  return UNKNOWN_PROMOTION;
}

bool CastStrategyC::isExtensionCastImplied(const PcodeOp *op,const PcodeOp *readOp) const

{
  const Varnode *outVn = op->getOut();
  if (outVn->isExplicit()) {

  }
  else {
    if (readOp == (PcodeOp *) 0)
      return false;
    type_metatype metatype = outVn->getHigh()->getType()->getMetatype();
    const Varnode *otherVn;
    int4 slot;
    switch (readOp->code()) {
      case CPUI_PTRADD:
	break;
      case CPUI_INT_ADD:
      case CPUI_INT_SUB:
      case CPUI_INT_MULT:
      case CPUI_INT_DIV:
      case CPUI_INT_AND:
      case CPUI_INT_OR:
      case CPUI_INT_XOR:
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
      case CPUI_INT_LESS:
      case CPUI_INT_LESSEQUAL:
      case CPUI_INT_SLESS:
      case CPUI_INT_SLESSEQUAL:
	slot = readOp->getSlot(outVn);
	otherVn = readOp->getIn(1 - slot);
	// Check if the expression involves an explicit variable of the right integer type
	if (otherVn->isConstant()) {
	  // Integer tokens do not naturally indicate their size, and
	  // integers that are bigger than the promotion size are NOT naturally extended.
	  if (otherVn->getSize() > promoteSize)	// So if the integer is bigger than the promotion size
	    return false;			// The extension cast on the other side must be explicit
	}
	else if (!otherVn->isExplicit())
	  return false;
	if (otherVn->getHigh()->getType()->getMetatype() != metatype)
	  return false;
	break;
      default:
	return false;
    }
    return true;	// Everything is integer promotion
  }
  return false;
}

Datatype *CastStrategyC::castStandard(Datatype *reqtype,Datatype *curtype,
				      bool care_uint_int,bool care_ptr_uint) const

{				// Generic casting rules that apply for most ops
  if (curtype == reqtype) return (Datatype *)0; // Types are equal, no cast required
  Datatype *reqbase = reqtype;
  Datatype *curbase = curtype;
  bool isptr = false;
  while((reqbase->getMetatype()==TYPE_PTR)&&(curbase->getMetatype()==TYPE_PTR)) {
    reqbase = ((const TypePointer *)reqbase)->getPtrTo();
    curbase = ((const TypePointer *)curbase)->getPtrTo();
    care_uint_int = true;
    isptr = true;
  }
  if (curtype == reqtype) return (Datatype *)0;	// Different typedefs could point to the same type
  if ((reqbase->getMetatype()==TYPE_VOID)||(curtype->getMetatype()==TYPE_VOID))
    return (Datatype *)0;	// Don't cast from or to VOID
  if (reqbase->getSize() != curbase->getSize()) {
    if (reqbase->isVariableLength() && isptr && reqbase->hasSameVariableBase(curbase)) {
      return (Datatype *)0;	// Don't need a cast
    }
    return reqtype; // Otherwise, always cast change in size
  }
  switch(reqbase->getMetatype()) {
  case TYPE_UNKNOWN:
    return (Datatype *)0;
  case TYPE_UINT:
    if (!care_uint_int) {
      type_metatype meta = curbase->getMetatype();
      // Note: meta can be TYPE_UINT if curbase is typedef/enumerated
      if ((meta==TYPE_UNKNOWN)||(meta==TYPE_INT)||(meta==TYPE_UINT)||(meta==TYPE_BOOL))
	return (Datatype *)0;
    }
    else {
      type_metatype meta = curbase->getMetatype();
      if ((meta == TYPE_UINT)||(meta==TYPE_BOOL))	// Can be TYPE_UINT for typedef/enumerated
	return (Datatype *)0;
      if (isptr && (meta==TYPE_UNKNOWN)) // Don't cast pointers to unknown
	return (Datatype *)0;
    }
    if ((!care_ptr_uint)&&(curbase->getMetatype()==TYPE_PTR))
      return (Datatype *)0;
    break;
  case TYPE_INT:
    if (!care_uint_int) {
      type_metatype meta = curbase->getMetatype();
      // Note: meta can be TYPE_INT if curbase is an enumerated type
      if ((meta==TYPE_UNKNOWN)||(meta==TYPE_INT)||(meta==TYPE_UINT)||(meta==TYPE_BOOL))
	return (Datatype *)0;
    }
    else {
      type_metatype meta = curbase->getMetatype();
      if ((meta == TYPE_INT)||(meta == TYPE_BOOL))
	return (Datatype *)0;	// Can be TYPE_INT for typedef/enumerated/char
      if (isptr && (meta==TYPE_UNKNOWN)) // Don't cast pointers to unknown
	return (Datatype *)0;
    }
    break;
  case TYPE_CODE:
    if (curbase->getMetatype() == TYPE_CODE) {
      // Don't cast between function pointer and generic code pointer
      if (((TypeCode *)reqbase)->getPrototype() == (const FuncProto *)0)
	return (Datatype *)0;
      if (((TypeCode *)curbase)->getPrototype() == (const FuncProto *)0)
	return (Datatype *)0;
    }
    break;
  default:
    break;
  }

  return reqtype;
}

Datatype *CastStrategyC::arithmeticOutputStandard(const PcodeOp *op)

{
  Datatype *res1 = op->getIn(0)->getHigh()->getType();
  if (res1->getMetatype() == TYPE_BOOL)	// Treat boolean as if it is cast to an integer
    res1 = tlst->getBase(res1->getSize(),TYPE_INT);
  Datatype *res2;

  for(int4 i=1;i<op->numInput();++i) {
    res2 = op->getIn(i)->getHigh()->getType();
    if (res2->getMetatype() == TYPE_BOOL) continue;
    if (0>res2->typeOrder(*res1))
      res1 = res2;
  }
  return res1;
}

bool CastStrategyC::isSubpieceCast(Datatype *outtype,Datatype *intype,uint4 offset) const

{
  if (offset != 0) return false;
  type_metatype inmeta = intype->getMetatype();
  if ((inmeta!=TYPE_INT)&&
      (inmeta!=TYPE_UINT)&&
      (inmeta!=TYPE_UNKNOWN)&&
      (inmeta!=TYPE_PTR))
    return false;
  type_metatype outmeta = outtype->getMetatype();
  if ((outmeta!=TYPE_INT)&&
      (outmeta!=TYPE_UINT)&&
      (outmeta!=TYPE_UNKNOWN)&&
      (outmeta!=TYPE_PTR)&&
      (outmeta!=TYPE_FLOAT))
    return false;
  if (inmeta==TYPE_PTR) {
    if (outmeta == TYPE_PTR) {
      if (outtype->getSize() < intype->getSize())
	return true;		// Cast from far pointer to near pointer
    }
    if ((outmeta!=TYPE_INT) && (outmeta!=TYPE_UINT))
      return false; //other casts don't make sense for pointers
  }
  return true;
}

bool CastStrategyC::isSubpieceCastEndian(Datatype *outtype,Datatype *intype,uint4 offset,bool isbigend) const

{
  uint4 tmpoff = offset;
  if (isbigend)
    tmpoff = intype->getSize()-1-offset;
  return isSubpieceCast(outtype,intype,tmpoff);
}

bool CastStrategyC::isSextCast(Datatype *outtype,Datatype *intype) const

{
  if (outtype->getMetatype()!=TYPE_INT) return false;
  type_metatype metain = intype->getMetatype();
  if ((metain!=TYPE_INT)&&(metain!=TYPE_UINT)&&(metain!=TYPE_BOOL))
    return false;
  return true;
}

bool CastStrategyC::isZextCast(Datatype *outtype,Datatype *intype) const

{
  if (outtype->getMetatype()!=TYPE_UINT) return false;
  type_metatype metain = intype->getMetatype();
  if ((metain!=TYPE_INT)&&(metain!=TYPE_UINT)&&(metain!=TYPE_BOOL))
    return false;
  return true;
}

Datatype *CastStrategyJava::castStandard(Datatype *reqtype,Datatype *curtype,
					 bool care_uint_int,bool care_ptr_uint) const

{
  if (curtype == reqtype) return (Datatype *)0; // Types are equal, no cast required
  Datatype *reqbase = reqtype;
  Datatype *curbase = curtype;
  if ((reqbase->getMetatype()==TYPE_PTR)||(curbase->getMetatype()==TYPE_PTR))
    return (Datatype *)0;		// There must be explicit cast op between objects, so assume no cast necessary

  if ((reqbase->getMetatype()==TYPE_VOID)||(curtype->getMetatype()==TYPE_VOID))
    return (Datatype *)0;	// Don't cast from or to VOID
  if (reqbase->getSize() != curbase->getSize()) return reqtype; // Always cast change in size
  switch(reqbase->getMetatype()) {
  case TYPE_UNKNOWN:
    return (Datatype *)0;
  case TYPE_UINT:
    if (!care_uint_int) {
      type_metatype meta = curbase->getMetatype();
      // Note: meta can be TYPE_UINT if curbase is typedef/enumerated
      if ((meta==TYPE_UNKNOWN)||(meta==TYPE_INT)||(meta==TYPE_UINT)||(meta==TYPE_BOOL))
	return (Datatype *)0;
    }
    else {
      type_metatype meta = curbase->getMetatype();
      if ((meta == TYPE_UINT)||(meta==TYPE_BOOL))	// Can be TYPE_UINT for typedef/enumerated
	return (Datatype *)0;
    }
    break;
  case TYPE_INT:
    if (!care_uint_int) {
      type_metatype meta = curbase->getMetatype();
      // Note: meta can be TYPE_INT if curbase is an enumerated type
      if ((meta==TYPE_UNKNOWN)||(meta==TYPE_INT)||(meta==TYPE_UINT)||(meta==TYPE_BOOL))
	return (Datatype *)0;
    }
    else {
      type_metatype meta = curbase->getMetatype();
      if ((meta == TYPE_INT)||(meta == TYPE_BOOL))
	return (Datatype *)0;	// Can be TYPE_INT for typedef/enumerated/char
    }
    break;
  case TYPE_CODE:
    if (curbase->getMetatype() == TYPE_CODE) {
      // Don't cast between function pointer and generic code pointer
      if (((TypeCode *)reqbase)->getPrototype() == (const FuncProto *)0)
	return (Datatype *)0;
      if (((TypeCode *)curbase)->getPrototype() == (const FuncProto *)0)
	return (Datatype *)0;
    }
    break;
  default:
    break;
  }

  return reqtype;
}

bool CastStrategyJava::isZextCast(Datatype *outtype,Datatype *intype) const

{
  type_metatype outmeta = outtype->getMetatype();
  if ((outmeta!=TYPE_INT)&&(outmeta!=TYPE_UINT)&&(outmeta!=TYPE_BOOL)) return false;
  type_metatype inmeta = intype->getMetatype();
  if ((inmeta!=TYPE_INT)&&(inmeta!=TYPE_UINT)&&(inmeta!=TYPE_BOOL)) return false;	// Non-integer types, print functional ZEXT
  if ((intype->getSize() == 2)&&(!intype->isCharPrint())) return false;		// cast is not zext for short
  if ((intype->getSize()==1)&&(inmeta==TYPE_INT)) return false;	// cast is not zext for byte
  if (intype->getSize()>=4) return false;		// cast is not zext for int and long
  return true;
}

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
#include "subflow.hh"
#include "funcdata.hh"

namespace ghidra {

/// \brief Return \e slot of constant if INT_OR op sets all bits in mask, otherwise -1
///
/// \param orop is the given CPUI_INT_OR op
/// \param mask is the given mask
/// \return constant slot or -1
int4 SubvariableFlow::doesOrSet(PcodeOp *orop,uintb mask)

{
  int4 index = (orop->getIn(1)->isConstant() ? 1 : 0);
  if (!orop->getIn(index)->isConstant())
    return -1;
  uintb orval = orop->getIn(index)->getOffset();
  if ((mask&(~orval))==(uintb)0) // Are all masked bits one
    return index;
  return -1;
}

/// \brief Return \e slot of constant if INT_AND op clears all bits in mask, otherwise -1
///
/// \param andop is the given CPUI_INT_AND op
/// \param mask is the given mask
/// \return constant slot or -1
int4 SubvariableFlow::doesAndClear(PcodeOp *andop,uintb mask)

{
  int4 index = (andop->getIn(1)->isConstant() ? 1 : 0);
  if (!andop->getIn(index)->isConstant())
    return -1;
  uintb andval = andop->getIn(index)->getOffset();
  if ((mask&andval)==(uintb)0) // Are all masked bits zero
    return index;
  return -1;
}

/// \brief Add the given Varnode as a new node in the logical subgraph
///
/// A new ReplaceVarnode object is created, representing the given Varnode within
/// the logical subgraph, and returned.  If an object representing the Varnode already
/// exists it is returned.  A mask describing the subset of bits within the Varnode
/// representing the logical value is also passed in. This method also determines if
/// the new node needs to be added to the worklist for continued tracing.
/// \param vn is the given Varnode holding the logical value
/// \param mask is the given mask describing the bits of the logical value
/// \param inworklist will hold \b true if the new node should be traced further
/// \return the new subgraph variable node
SubvariableFlow::ReplaceVarnode *SubvariableFlow::setReplacement(Varnode *vn,uintb mask,bool &inworklist)

{
  ReplaceVarnode *res;
  if (vn->isMark()) {		// Already seen before
    map<Varnode *,ReplaceVarnode>::iterator iter;
    iter = varmap.find(vn);
    res = &(*iter).second;
    inworklist = false;
    if (res->mask != mask)
      return (ReplaceVarnode *)0;
    return res;
  }

  if (vn->isConstant()) {
    inworklist = false;
    if (sextrestrictions) {	// Check that -vn- is a sign extension
      uintb cval = vn->getOffset();
      uintb smallval = cval & mask; // From its logical size
      uintb sextval = sign_extend(smallval,flowsize,vn->getSize());// to its fullsize
      if (sextval != cval)
	return (ReplaceVarnode *)0;
    }
    return addConstant((ReplaceOp *)0,mask,0,vn);
  }

  if (vn->isFree())
    return (ReplaceVarnode *)0; // Abort

  if (vn->isAddrForce() && (vn->getSize() != flowsize))
    return (ReplaceVarnode *)0;

  if (sextrestrictions) {
    if (vn->getSize() != flowsize) {
      if ((!aggressive)&& vn->isInput()) return (ReplaceVarnode *)0; // Cannot assume input is sign extended
      if (vn->isPersist()) return (ReplaceVarnode *)0;
    }
    if (vn->isTypeLock() && vn->getType()->getMetatype() != TYPE_PARTIALSTRUCT) {
      if (vn->getType()->getSize() != flowsize)
	return (ReplaceVarnode *)0;
    }
  }
  else {
    if (bitsize >= 8) {		// Not a flag
      // If the logical variable is not a flag, don't consider the case where multiple variables
      // are packed into a single location, i.e. always consider it a single variable
      if ((!aggressive)&&((vn->getConsume()&~mask)!=0)) // If there is any use of value outside of the logical variable
	return (ReplaceVarnode *)0; // This probably means the whole thing is a variable, i.e. quit
      if (vn->isTypeLock() && vn->getType()->getMetatype() != TYPE_PARTIALSTRUCT) {
	int4 sz = vn->getType()->getSize();
	if (sz != flowsize)
	  return (ReplaceVarnode *)0;
      }
    }

    if (vn->isInput()) {		// Must be careful with inputs
      // Inputs must come in from the right register/memory
      if (bitsize < 8) return (ReplaceVarnode *)0; // Dont create input flag
      if ((mask&1)==0) return (ReplaceVarnode *)0; // Dont create unique input
      // Its extremely important that the code (above) which doesn't allow packed variables be applied
      // or the mechanisms we use for inputs will give us spurious temporary inputs
    }
  }

  res = & varmap[ vn ];
  vn->setMark();
  res->vn = vn;
  res->replacement = (Varnode *)0;
  res->mask = mask;
  res->def = (ReplaceOp *)0;
  inworklist = true;
  // Check if vn already represents the logical variable being traced
  if (vn->getSize() == flowsize) {
    if (mask == calc_mask(flowsize)) {
      inworklist = false;
      res->replacement = vn;
    }
    else if (mask == 1) {
      if ((vn->isWritten())&&(vn->getDef()->isBoolOutput())) {
	inworklist = false;
	res->replacement = vn;
      }
    }
  }
  return res;
}

/// \brief Create a logical subgraph operator node given its output variable node
///
/// \param opc is the opcode of the new logical operator
/// \param numparam is the number of parameters in the new operator
/// \param outrvn is the given output variable node
/// \return the new logical subgraph operator object
SubvariableFlow::ReplaceOp *SubvariableFlow::createOp(OpCode opc,int4 numparam,ReplaceVarnode *outrvn)

{
  if (outrvn->def != (ReplaceOp *)0)
    return outrvn->def;
  oplist.emplace_back();
  ReplaceOp *rop = &oplist.back();
  outrvn->def = rop;
  rop->op = outrvn->vn->getDef();
  rop->numparams = numparam;
  rop->opc = opc;
  rop->output = outrvn;

  return rop;
}


/// \brief Create a logical subgraph operator node given one of its input variable nodes
///
/// \param opc is the opcode of the new logical operator
/// \param numparam is the number of parameters in the new operator
/// \param op is the original PcodeOp being replaced
/// \param inrvn is the given input variable node
/// \param slot is the input slot of the variable node
/// \return the new logical subgraph operator objects
SubvariableFlow::ReplaceOp *SubvariableFlow::createOpDown(OpCode opc,int4 numparam,PcodeOp *op,ReplaceVarnode *inrvn,int4 slot)

{
  oplist.emplace_back();
  ReplaceOp *rop = &oplist.back();
  rop->op = op;
  rop->opc = opc;
  rop->numparams = numparam;
  rop->output = (ReplaceVarnode *)0;
  while(rop->input.size() <= slot)
    rop->input.push_back((ReplaceVarnode *)0);
  rop->input[slot] = inrvn;
  return rop;
}

/// \brief Determine if the given subgraph variable can act as a parameter to the given CALL op
///
/// We assume the variable flows as a parameter to the CALL. If the CALL doesn't lock the parameter
/// size, create a PatchRecord within the subgraph that allows the CALL to take the parameter
/// with its smaller logical size.
/// \param op is the given CALL op
/// \param rvn is the given subgraph variable acting as a parameter
/// \param slot is the input slot of the variable within the CALL
/// \return \b true if the parameter can be successfully trimmed to its logical size
bool SubvariableFlow::tryCallPull(PcodeOp *op,ReplaceVarnode *rvn,int4 slot)

{
  if (slot == 0) return false;
  if (!aggressive) {
    if ((rvn->vn->getConsume()&~rvn->mask)!=0)	// If there's something outside the mask being consumed
      return false;				// Don't truncate
  }
  FuncCallSpecs *fc = fd->getCallSpecs(op);
  if (fc == (FuncCallSpecs *)0) return false;
  if (fc->isInputActive()) return false; // Don't trim while in the middle of figuring out params
  if (fc->isInputLocked() && (!fc->isDotdotdot())) return false;

  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::parameter_patch;
  patchlist.back().patchOp = op;
  patchlist.back().in1 = rvn;
  patchlist.back().slot = slot;
  pullcount += 1;		// A true terminal modification
  return true;
}

/// \brief Determine if the given subgraph variable can act as return value for the given RETURN op
///
/// We assume the variable flows the RETURN. If the return value size is not locked. Create a
/// PatchRecord within the subgraph that allows the RETURN to take a smaller logical value.
/// \param op is the given RETURN op
/// \param rvn is the given subgraph variable flowing to the RETURN
/// \param slot is the input slot of the subgraph variable
/// \return \b true if the return value can be successfully trimmed to its logical size
bool SubvariableFlow::tryReturnPull(PcodeOp *op,ReplaceVarnode *rvn,int4 slot)

{
  if (slot == 0) return false;	// Don't deal with actual return address container
  if (fd->getFuncProto().isOutputLocked()) return false;
  if (!aggressive) {
    if ((rvn->vn->getConsume()&~rvn->mask)!=0)	// If there's something outside the mask being consumed
      return false;				// Don't truncate
  }

  if (!returnsTraversed) {
    // If we plan to truncate the size of a return variable, we need to propagate the logical size to any other
    // return variables so that there can still be a single return value type for the function
    list<PcodeOp *>::const_iterator iter,enditer;
    iter = fd->beginOp(CPUI_RETURN);
    enditer = fd->endOp(CPUI_RETURN);
    while(iter != enditer) {
      PcodeOp *retop = *iter;
      ++iter;
      if (retop->getHaltType() != 0) continue;		// Artificial halt
      Varnode *retvn = retop->getIn(slot);
      bool inworklist;
      ReplaceVarnode *rep = setReplacement(retvn,rvn->mask,inworklist);
      if (rep == (ReplaceVarnode *)0)
	return false;
      if (inworklist)
	worklist.push_back(rep);
      else if (retvn->isConstant() && retop != op) {
	// Trace won't revisit this RETURN, so we need to generate patch now
	patchlist.emplace_back();
	patchlist.back().type = PatchRecord::parameter_patch;
	patchlist.back().patchOp = retop;
	patchlist.back().in1 = rep;
	patchlist.back().slot = slot;
	pullcount += 1;
      }
    }
    returnsTraversed = true;
  }
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::parameter_patch;
  patchlist.back().patchOp = op;
  patchlist.back().in1 = rvn;
  patchlist.back().slot = slot;
  pullcount += 1;		// A true terminal modification
  return true;
}

/// \brief Determine if the given subgraph variable can act as a \e created value for the given INDIRECT op
///
/// Check if the INDIRECT is an \e indirect \e creation and is not representing a locked return value.
/// If we can, create the INDIRECT node in the subgraph representing the logical \e indirect \e creation.
/// \param op is the given INDIRECT
/// \param rvn is the given subgraph variable acting as the output of the INDIRECT
/// \return \b true if we can successfully trim the value to its logical size
bool SubvariableFlow::tryCallReturnPush(PcodeOp *op,ReplaceVarnode *rvn)

{
  if (!aggressive) {
    if ((rvn->vn->getConsume()&~rvn->mask)!=0)	// If there's something outside the mask being consumed
      return false;				// Don't truncate
  }
  if ((rvn->mask & 1) == 0) return false;	// Verify the logical value is the least significant part
  if (bitsize < 8) return false;		// Make sure logical value is at least a byte
  FuncCallSpecs *fc = fd->getCallSpecs(op);
  if (fc == (FuncCallSpecs *)0) return false;
  if (fc->isOutputLocked()) return false;
  if (fc->isOutputActive()) return false;	// Don't trim while in the middle of figuring out return value

  addPush(op,rvn);
  // pullcount += 1;		// This is a push NOT a pull
  return true;
}

/// \brief Determine if the subgraph variable can act as a switch variable for the given BRANCHIND
///
/// We query the JumpTable associated with the BRANCHIND to see if its switch variable
/// can be trimmed as indicated by the logical flow.
/// \param op is the given BRANCHIND op
/// \param rvn is the subgraph variable flowing to the BRANCHIND
/// \return \b true if the switch variable can be successfully trimmed to its logical size
bool SubvariableFlow::trySwitchPull(PcodeOp *op,ReplaceVarnode *rvn)

{
  if ((rvn->mask & 1) == 0) return false;	// Logical value must be justified
  if ((rvn->vn->getConsume()&~rvn->mask)!=0)	// If there's something outside the mask being consumed
    return false;				//  we can't trim
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::parameter_patch;
  patchlist.back().patchOp = op;
  patchlist.back().in1 = rvn;
  patchlist.back().slot = 0;
  pullcount += 1;		// A true terminal modification
  return true;
}

/// \brief Determine if the subgraph variable flows naturally into a terminal FLOAT_INT2FLOAT operation
///
/// The original data-flow must pad the logical value with zero bits, making the conversion to
/// floating-point unsigned.  A PatchRecord is created that preserves the FLOAT_INT2FLOAT but inserts an
/// additional INT_ZEXT operation to preserve the unsigned nature of the conversion.
/// \param op is the FLOAT_INT2FLOAT conversion operation
/// \param rvn is the logical value flowing into the conversion
bool SubvariableFlow::tryInt2FloatPull(PcodeOp *op,ReplaceVarnode *rvn)

{
  if ((rvn->mask & 1) == 0) return false;	// Logical value must be justified
  if ((rvn->vn->getNZMask()&~rvn->mask)!=0)
    return false;				// Everything outside the logical value must be zero
  if (rvn->vn->getSize() == flowsize)
    return false;				// There must be some (zero) extension
  bool pullModification = true;
  if (rvn->vn->isWritten() && rvn->vn->getDef()->code() == CPUI_INT_ZEXT) {
    if (rvn->vn->getSize() == TypeOpFloatInt2Float::preferredZextSize(flowsize)) {
      if (rvn->vn->loneDescend() == op) {
	pullModification = false;		// This patch does not count as a modification
	// The INT_ZEXT -> FLOAT_INT2FLOAT has the correct form and does not need to be modified.
	// We indicate this by NOT incrementing pullcount, so there has to be at least one other
	// terminal patch in order for doTrace() to return true.
      }
    }
  }
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::int2float_patch;
  patchlist.back().patchOp = op;
  patchlist.back().in1 = rvn;
  if (pullModification)
    pullcount += 1;
  return true;
}

/// Try to trace the logical variable through descendant Varnodes
/// creating new nodes in the logical subgraph and updating the worklist.
/// \param rvn is the given subgraph variable to trace
/// \return \b true if the logical value can be traced forward one level
bool SubvariableFlow::traceForward(ReplaceVarnode *rvn)

{
  ReplaceOp *rop;
  PcodeOp *op;
  Varnode *outvn;
  int4 slot;
  int4 sa;
  uintb newmask;
  bool booldir;
  int4 dcount = 0;
  int4 hcount = 0;
  int4 callcount = 0;

  list<PcodeOp *>::const_iterator iter,enditer;
  enditer = rvn->vn->endDescend();
  for(iter = rvn->vn->beginDescend();iter != enditer;++iter) {
    op = *iter;
    outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&outvn->isMark()&&!op->isCall())
      continue;
    dcount += 1;		// Count this descendant
    slot = op->getSlot(rvn->vn);
    switch(op->code()) {
    case CPUI_COPY:
    case CPUI_MULTIEQUAL:
    case CPUI_INT_NEGATE:
    case CPUI_INT_XOR:
      rop = createOpDown(op->code(),op->numInput(),op,rvn,slot);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_OR:
      if (doesOrSet(op,rvn->mask)!=-1) break; // Subvar set to 1s, truncate flow
      rop = createOpDown(CPUI_INT_OR,2,op,rvn,slot);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_AND:
      if ((op->getIn(1)->isConstant())&&(op->getIn(1)->getOffset() == rvn->mask)) {
	if ((outvn->getSize() == flowsize)&&((rvn->mask & 1)!=0)) {
	  addTerminalPatch(op,rvn);
	  hcount += 1;		// Dealt with this descendant
	  break;
	}
	// Is the small variable getting zero padded into something that is fully consumed
	if ((!aggressive)&&((outvn->getConsume() & rvn->mask) != outvn->getConsume())) {
	  addSuggestedPatch(rvn,op,-1);
	  hcount += 1;		// Dealt with this descendant
	  break;
	}
      }
      if (doesAndClear(op,rvn->mask)!=-1) break; // Subvar set to zero, truncate flow
      rop = createOpDown(CPUI_INT_AND,2,op,rvn,slot);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_ZEXT:
    case CPUI_INT_SEXT:
      rop = createOpDown(CPUI_COPY,1,op,rvn,0);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_MULT:
      if ((rvn->mask & 1)==0)
	return false;		// Cannot account for carry
      sa = leastsigbit_set(op->getIn(1-slot)->getNZMask());
      sa &= ~7;			// Should be nearest multiple of 8
      if (bitsize + sa > 8*rvn->vn->getSize()) return false;
      rop = createOpDown(CPUI_INT_MULT,2,op,rvn,slot);
      if (!createLink(rop,rvn->mask<<sa,-1,outvn)) return false;
      hcount += 1;
      break;
    case CPUI_INT_ADD:
      if ((rvn->mask & 1)==0)
	return false;		// Cannot account for carry
      rop = createOpDown(CPUI_INT_ADD,2,op,rvn,slot);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_LEFT:
      if (slot == 1) {		// Logical flow is into shift amount
	if ((rvn->mask & 1)==0) return false;	// Cannot account for effect of extraneous bits
	if (bitsize <8) return false;
	// Its possible that truncating to the logical value could have an effect, if there were non-zero bits
	// being truncated.  Non-zero bits here would mean the shift-amount was very large (>255), indicating the
	// the result was undefined
	addTerminalPatchSameOp(op,rvn,slot);
	hcount += 1;
	break;
      }
      if (!op->getIn(1)->isConstant()) return false; // Dynamic shift
      sa = (int4)op->getIn(1)->getOffset();
      newmask = (rvn->mask << sa) & calc_mask( outvn->getSize() );
      if (newmask == 0) break;	// Subvar is cleared, truncate flow
      if (rvn->mask != (newmask >> sa)) return false; // subvar is clipped
	// Is the small variable getting zero padded into something that is fully consumed
      if (((rvn->mask & 1)!=0)&&(sa + bitsize == 8*outvn->getSize())
	  &&(calc_mask(outvn->getSize()) == outvn->getConsume())) {
	addSuggestedPatch(rvn,op,sa);
	hcount += 1;
	break;
      }
      rop = createOpDown(CPUI_COPY,1,op,rvn,0);
      if (!createLink(rop,newmask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_RIGHT:
    case CPUI_INT_SRIGHT:
      if (slot == 1) {		// Logical flow is into shift amount
	if ((rvn->mask & 1)==0) return false;	// Cannot account for effect of extraneous bits
	if (bitsize <8) return false;
	addTerminalPatchSameOp(op,rvn,slot);
	hcount += 1;
	break;
      }
      if (!op->getIn(1)->isConstant()) return false;
      sa = (int4)op->getIn(1)->getOffset();
      newmask = rvn->mask >> sa;
      if (newmask == 0) {
	if (op->code()==CPUI_INT_RIGHT) break; // subvar is set to zero, truncate flow
	return false;
      }
      if (rvn->mask != (newmask << sa)) return false;
      if ((outvn->getSize()==flowsize)&&((newmask&1)==1)&&
	  (op->getIn(0)->getNZMask()==rvn->mask)) {
	addTerminalPatch(op,rvn);
	hcount += 1;		// Dealt with this descendant
	break;
      }
	// Is the small variable getting zero padded into something that is fully consumed
      if (((newmask&1)==1)&&(sa + bitsize == 8*outvn->getSize())
	  &&(calc_mask(outvn->getSize()) == outvn->getConsume())) {
	addSuggestedPatch(rvn,op,0);
	hcount += 1;
	break;
      }
      rop = createOpDown(CPUI_COPY,1,op,rvn,0);
      if (!createLink(rop,newmask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_SUBPIECE:
      sa = (int4)op->getIn(1)->getOffset() * 8;
      newmask = (rvn->mask >> sa) & calc_mask(outvn->getSize());
      if (newmask == 0) break;	// subvar is set to zero, truncate flow
      if (rvn->mask != (newmask << sa)) {	// Some kind of truncation of the logical value
	if (flowsize > ((sa/8) + outvn->getSize()) && (rvn->mask & 1) != 0) {
	  // Only a piece of the logical value remains
	  addTerminalPatchSameOp(op, rvn, 0);
	  hcount += 1;
	  break;
	}
	return false;
      }
      if (((newmask & 1)!=0)&&(outvn->getSize()==flowsize)) {
	addTerminalPatch(op,rvn);
	hcount += 1;		// Dealt with this descendant
	break;
      }
      rop = createOpDown(CPUI_COPY,1,op,rvn,0);
      if (!createLink(rop,newmask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_PIECE:
      if (rvn->vn == op->getIn(0))
	newmask = rvn->mask << (8*op->getIn(1)->getSize());
      else
	newmask = rvn->mask;
      rop = createOpDown(CPUI_COPY,1,op,rvn,0);
      if (!createLink(rop,newmask,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_LESS:
    case CPUI_INT_LESSEQUAL:
      outvn = op->getIn(1-slot); // The OTHER side of the comparison
      if ((!aggressive)&&(((rvn->vn->getNZMask() | rvn->mask) != rvn->mask)))
	return false;		// Everything but logical variable must definitely be zero (unless we are aggressive)
      if (outvn->isConstant()) {
	if ((rvn->mask | outvn->getOffset()) != rvn->mask)
	  return false;		// Must compare only bits of logical variable
      }
      else {
	if ((!aggressive)&&(((rvn->mask | outvn->getNZMask()) != rvn->mask))) // unused bits of otherside must be zero
	  return false;
      }
      if (!createCompareBridge(op,rvn,slot,outvn))
	return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_INT_NOTEQUAL:
    case CPUI_INT_EQUAL:
      outvn = op->getIn(1-slot); // The OTHER side of the comparison
      if (bitsize != 1) {
	if ((!aggressive)&&(((rvn->vn->getNZMask() | rvn->mask) != rvn->mask)))
	  return false;	// Everything but logical variable must definitely be zero (unless we are aggressive)
	if (outvn->isConstant()) {
	  if ((rvn->mask | outvn->getOffset()) != rvn->mask)
	    return false;	// Not comparing to just bits of the logical variable
	}
	else {
	  if ((!aggressive)&&(((rvn->mask | outvn->getNZMask()) != rvn->mask))) // unused bits must be zero
	    return false;
	}
	if (!createCompareBridge(op,rvn,slot,outvn))
	  return false;
      }
      else {			// Movement of boolean variables
	if (!outvn->isConstant()) return false;
	newmask = rvn->vn->getNZMask();
	if (newmask != rvn->mask) return false;
	if (op->getIn(1-slot)->getOffset() == (uintb)0)
	  booldir = true;
	else if (op->getIn(1-slot)->getOffset() == newmask)
	  booldir = false;
	else
	  return false;
	if (op->code() == CPUI_INT_EQUAL)
	  booldir = !booldir;
	if (booldir)
	  addTerminalPatch(op,rvn);
	else {
	  rop = createOpDown(CPUI_BOOL_NEGATE,1,op,rvn,0);
	  createNewOut(rop,(uintb)1);
	  addTerminalPatch(op,rop->output);
	}
      }
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_CALL:
    case CPUI_CALLIND:
      callcount += 1;
      if (callcount > 1)
	slot = op->getRepeatSlot(rvn->vn, slot, iter);
      if (!tryCallPull(op,rvn,slot)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_RETURN:
      if (!tryReturnPull(op,rvn,slot)) return false;
      hcount += 1;
      break;
    case CPUI_BRANCHIND:
      if (!trySwitchPull(op, rvn)) return false;
      hcount += 1;
      break;
    case CPUI_BOOL_NEGATE:
    case CPUI_BOOL_AND:
    case CPUI_BOOL_OR:
    case CPUI_BOOL_XOR:
      if (bitsize != 1) return false;
      if (rvn->mask != 1) return false;
      addBooleanPatch(op,rvn,slot);
      break;
    case CPUI_FLOAT_INT2FLOAT:
      if (!tryInt2FloatPull(op, rvn)) return false;
      hcount += 1;
      break;
    case CPUI_CBRANCH:
      if ((bitsize != 1)||(slot != 1)) return false;
      if (rvn->mask != 1) return false;
      addBooleanPatch(op,rvn,1);
      hcount += 1;
      break;
    default:
      return false;
    }
  }
  if (dcount != hcount) {
    // Must account for all descendants of an input
    if (rvn->vn->isInput()) return false;
  }
  return true;
}

/// Trace the logical value backward through one PcodeOp adding new nodes to the
/// logical subgraph and updating the worklist.
/// \param rvn is the given logical value to trace
/// \return \b true if the logical value can be traced backward one level
bool SubvariableFlow::traceBackward(ReplaceVarnode *rvn)

{
  PcodeOp *op = rvn->vn->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input
  int4 sa;
  uintb newmask;
  ReplaceOp *rop;

  switch(op->code()) {
  case CPUI_COPY:
  case CPUI_MULTIEQUAL:
  case CPUI_INT_NEGATE:
  case CPUI_INT_XOR:
    rop = createOp(op->code(),op->numInput(),rvn);
    for(int4 i=0;i<op->numInput();++i)
      if (!createLink(rop,rvn->mask,i,op->getIn(i))) // Same inputs and mask
	return false;
    return true;
  case CPUI_INT_AND:
    sa = doesAndClear(op,rvn->mask);
    if (sa != -1) {
      rop = createOp(CPUI_COPY,1,rvn);
      addConstant(rop,rvn->mask,0,op->getIn(sa));
    }
    else {
      rop = createOp(CPUI_INT_AND,2,rvn);
      if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
      if (!createLink(rop,rvn->mask,1,op->getIn(1))) return false;
    }
    return true;
  case CPUI_INT_OR:
    sa = doesOrSet(op,rvn->mask);
    if (sa != -1) {
      rop = createOp(CPUI_COPY,1,rvn);
      addConstant(rop,rvn->mask,0,op->getIn(sa));
    }
    else {
      rop = createOp(CPUI_INT_OR,2,rvn);
      if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
      if (!createLink(rop,rvn->mask,1,op->getIn(1))) return false;
    }
    return true;
  case CPUI_INT_ZEXT:
  case CPUI_INT_SEXT:
    if ((rvn->mask & calc_mask(op->getIn(0)->getSize())) != rvn->mask) {
      if ((rvn->mask & 1)!=0 && flowsize > op->getIn(0)->getSize()) {
	addPush(op,rvn);
	return true;
      }
      break;	       // Check if subvariable comes through extension
    }
    rop = createOp(CPUI_COPY,1,rvn);
    if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
    return true;
  case CPUI_INT_ADD:
    if ((rvn->mask & 1)==0)
      break;			// Cannot account for carry
    if (rvn->mask == (uintb)1)
      rop = createOp(CPUI_INT_XOR,2,rvn); // Single bit add
    else
      rop = createOp(CPUI_INT_ADD,2,rvn);
    if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
    if (!createLink(rop,rvn->mask,1,op->getIn(1))) return false;
    return true;
  case CPUI_INT_LEFT:
    if (!op->getIn(1)->isConstant()) break; // Dynamic shift
    sa = (int4)op->getIn(1)->getOffset();
    newmask = rvn->mask >> sa;	// What mask looks like before shift
    if (newmask == 0) {		// Subvariable filled with shifted zero
      rop = createOp(CPUI_COPY,1,rvn);
      addNewConstant(rop,0,(uintb)0);
      return true;
    }
    if ((newmask<<sa) != rvn->mask)
      break;			// subvariable is truncated by shift
    rop = createOp(CPUI_COPY,1,rvn);
    if (!createLink(rop,newmask,0,op->getIn(0))) return false;
    return true;
  case CPUI_INT_RIGHT:
    if (!op->getIn(1)->isConstant()) break; // Dynamic shift
    sa = (int4)op->getIn(1)->getOffset();
    newmask = (rvn->mask << sa) & calc_mask(op->getIn(0)->getSize());
    if (newmask == 0) {		// Subvariable filled with shifted zero
      rop = createOp(CPUI_COPY,1,rvn);
      addNewConstant(rop,0,(uintb)0);
      return true;
    }
    if ((newmask>>sa) != rvn->mask)
      break;			// subvariable is truncated by shift
    rop = createOp(CPUI_COPY,1,rvn);
    if (!createLink(rop,newmask,0,op->getIn(0))) return false;
    return true;
  case CPUI_INT_SRIGHT:
    if (!op->getIn(1)->isConstant()) break; // Dynamic shift
    sa = (int4)op->getIn(1)->getOffset();
    newmask = (rvn->mask << sa) & calc_mask(op->getIn(0)->getSize());
    if ((newmask>>sa) != rvn->mask)
      break;			// subvariable is truncated by shift
    rop = createOp(CPUI_COPY,1,rvn);
    if (!createLink(rop,newmask,0,op->getIn(0))) return false;
    return true;
  case CPUI_INT_MULT:
    sa = leastsigbit_set(rvn->mask);
    if (sa!=0) {
      int4 sa2 = leastsigbit_set(op->getIn(1)->getNZMask());
      if (sa2 < sa) return false; // Cannot deal with carries into logical multiply
      newmask = rvn->mask >> sa;
      rop = createOp(CPUI_INT_MULT,2,rvn);
      if (!createLink(rop,newmask,0,op->getIn(0))) return false;
      if (!createLink(rop,rvn->mask,1,op->getIn(1))) return false;
    }
    else {
      if (rvn->mask == (uintb)1)
	rop = createOp(CPUI_INT_AND,2,rvn); // Single bit multiply
      else
	rop = createOp(CPUI_INT_MULT,2,rvn);
      if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
      if (!createLink(rop,rvn->mask,1,op->getIn(1))) return false;
    }
    return true;
  case CPUI_SUBPIECE:
    sa = (int4)op->getIn(1)->getOffset() * 8;
    newmask = rvn->mask << sa;
    rop = createOp(CPUI_COPY,1,rvn);
    if (!createLink(rop,newmask,0,op->getIn(0))) return false;
    return true;
  case CPUI_PIECE:
    if ((rvn->mask & calc_mask(op->getIn(1)->getSize()))==rvn->mask) {
      rop = createOp(CPUI_COPY,1,rvn);
      if (!createLink(rop,rvn->mask,0,op->getIn(1))) return false;
      return true;
    }
    sa = op->getIn(1)->getSize() * 8;
    newmask = rvn->mask>>sa;
    if (newmask<<sa == rvn->mask) {
      rop = createOp(CPUI_COPY,1,rvn);
      if (!createLink(rop,newmask,0,op->getIn(0))) return false;
      return true;
    }
    break;
  case CPUI_CALL:
  case CPUI_CALLIND:
    if (tryCallReturnPush(op,rvn))
      return true;
    break;
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_CARRY:
  case CPUI_INT_SCARRY:
  case CPUI_INT_SBORROW:
  case CPUI_BOOL_NEGATE:
  case CPUI_BOOL_XOR:
  case CPUI_BOOL_AND:
  case CPUI_BOOL_OR:
  case CPUI_FLOAT_EQUAL:
  case CPUI_FLOAT_NOTEQUAL:
  case CPUI_FLOAT_LESSEQUAL:
  case CPUI_FLOAT_NAN:
    // Mask won't be 1, because setReplacement takes care of it
    if ((rvn->mask&1)==1) break; // Not normal variable flow
    // Variable is filled with zero
    rop = createOp(CPUI_COPY,1,rvn);
    addNewConstant(rop,0,(uintb)0);
    return true;
  default:
    break;			// Everything else we abort
  }

  return false;
}

/// Try to trace the logical variable through descendant Varnodes, updating the logical subgraph.
/// We assume (and check) that the logical variable has always been sign extended (sextstate) into its container.
/// \param rvn is the given subgraph variable to trace
/// \return \b true if the logical value can successfully traced forward one level
bool SubvariableFlow::traceForwardSext(ReplaceVarnode *rvn)

{
  ReplaceOp *rop;
  PcodeOp *op;
  Varnode *outvn;
  int4 slot;
  int4 dcount = 0;
  int4 hcount = 0;
  int4 callcount = 0;

  list<PcodeOp *>::const_iterator iter,enditer;
  enditer = rvn->vn->endDescend();
  for(iter=rvn->vn->beginDescend();iter != enditer;++iter) {
    op = *iter;
    outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&outvn->isMark()&&!op->isCall())
      continue;
    dcount += 1;		// Count this descendant
    slot = op->getSlot(rvn->vn);
    switch(op->code()) {
    case CPUI_COPY:
    case CPUI_MULTIEQUAL:
    case CPUI_INT_NEGATE:
    case CPUI_INT_XOR:
    case CPUI_INT_OR:
    case CPUI_INT_AND:
      rop = createOpDown(op->code(),op->numInput(),op,rvn,slot);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;
      break;
    case CPUI_INT_SEXT:		// extended logical variable into even larger container
      rop = createOpDown(CPUI_COPY,1,op,rvn,0);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false;
      hcount += 1;
      break;
    case CPUI_INT_SRIGHT:
      if (!op->getIn(1)->isConstant()) return false; // Right now we only deal with constant shifts
      rop = createOpDown(CPUI_INT_SRIGHT,2,op,rvn,0);
      if (!createLink(rop,rvn->mask,-1,outvn)) return false; // Keep the same mask size
      addConstant(rop,calc_mask(op->getIn(1)->getSize()),1,op->getIn(1)); // Preserve the shift amount
      hcount += 1;
      break;
    case CPUI_SUBPIECE:
      if (op->getIn(1)->getOffset() != 0) return false;	// Only allow proper truncation
      if (outvn->getSize() > flowsize) return false;
      if (outvn->getSize() == flowsize)
	addTerminalPatch(op,rvn);		// Termination of flow, convert SUBPIECE to COPY
      else
	addTerminalPatchSameOp(op,rvn,0);	// Termination of flow, SUBPIECE truncates even more
      hcount +=1;
      break;
    case CPUI_INT_LESS:		// Unsigned comparisons are equivalent at the 2 sizes on sign extended values
    case CPUI_INT_LESSEQUAL:
    case CPUI_INT_SLESS:
    case CPUI_INT_SLESSEQUAL:
    case CPUI_INT_EQUAL:	// Everything works if both sides are sign extended
    case CPUI_INT_NOTEQUAL:
      outvn = op->getIn(1-slot); // The OTHER side of the comparison
      if (!createCompareBridge(op,rvn,slot,outvn)) return false;
      hcount += 1;
      break;
    case CPUI_CALL:
    case CPUI_CALLIND:
      callcount += 1;
      if (callcount > 1)
	slot = op->getRepeatSlot(rvn->vn, slot, iter);
      if (!tryCallPull(op,rvn,slot)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_RETURN:
      if (!tryReturnPull(op,rvn,slot)) return false;
      hcount += 1;
      break;
    case CPUI_BRANCHIND:
      if (!trySwitchPull(op,rvn)) return false;
      hcount += 1;
      break;
    default:
      return false;
    }
  }
  if (dcount != hcount) {
    // Must account for all descendants of an input
    if (rvn->vn->isInput()) return false;
  }
  return true;
}

/// Try to trace the logical variable up through its defining op, updating the logical subgraph.
/// We assume (and check) that the logical variable has always been sign extended (sextstate) into its container.
/// \param rvn is the given subgraph variable to trace
/// \return \b true if the logical value can successfully traced backward one level
bool SubvariableFlow::traceBackwardSext(ReplaceVarnode *rvn)

{
  PcodeOp *op = rvn->vn->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input
  ReplaceOp *rop;

  switch(op->code()) {
  case CPUI_COPY:
  case CPUI_MULTIEQUAL:
  case CPUI_INT_NEGATE:
  case CPUI_INT_XOR:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
    rop = createOp(op->code(),op->numInput(),rvn);
    for(int4 i=0;i<op->numInput();++i)
      if (!createLink(rop,rvn->mask,i,op->getIn(i))) // Same inputs and mask
	return false;
    return true;
  case CPUI_INT_ZEXT:
    if (op->getIn(0)->getSize() < flowsize) {
      // zero extension from a smaller size still acts as a signed extension
      addPush(op,rvn);
      return true;
    }
    break;
  case CPUI_INT_SEXT:
    if (flowsize != op->getIn(0)->getSize()) return false;
    rop = createOp(CPUI_COPY,1,rvn);
    if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
    return true;
  case CPUI_INT_SRIGHT:
    // A sign-extended logical value is arithmetically right-shifted
    // we can replace with the logical value, keeping the same shift amount
    if (!op->getIn(1)->isConstant()) return false;
    rop = createOp(CPUI_INT_SRIGHT,2,rvn);
    if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false; // Keep the same mask
    if (rop->input.size()==1)
      addConstant(rop,calc_mask(op->getIn(1)->getSize()),1,op->getIn(1)); // Preserve the shift amount
    return true;
  case CPUI_CALL:
  case CPUI_CALLIND:
    if (tryCallReturnPush(op,rvn))
      return true;
    break;
  default:
    break;
  }
  return false;
}

/// \brief Add a new variable to the logical subgraph as an input to the given operation
///
/// The subgraph is extended by the specified input edge, and a new variable node is created
/// if necessary or a preexisting node corresponding to the Varnode is used.
/// If the logical value described by the given mask cannot be made to line up with the
/// subgraph variable node, \b false is returned.
/// \param rop is the given operation
/// \param mask is the mask describing the logical value within the input Varnode
/// \param slot is the input slot of the Varnode to the operation
/// \param vn is the original input Varnode holding the logical value
/// \return \b true is the subgraph is successfully extended to the input
bool SubvariableFlow::createLink(ReplaceOp *rop,uintb mask,int4 slot,Varnode *vn)

{
  bool inworklist;
  ReplaceVarnode *rep = setReplacement(vn,mask,inworklist);
  if (rep == (ReplaceVarnode *)0) return false;

  if (rop != (ReplaceOp *)0) {
    if (slot == -1) {
      rop->output = rep;
      rep->def = rop;
    }
    else {
      while(rop->input.size() <= slot)
	rop->input.push_back((ReplaceVarnode *)0);
      rop->input[slot] = rep;
    }
  }

  if (inworklist)
    worklist.push_back(rep);
  return true;
}

/// \brief Extend the logical subgraph through a given comparison operator if possible
///
/// Given the variable already in the subgraph that is compared and the other side of the
/// comparison, add the other side as a logical value to the subgraph and create a PatchRecord
/// for the comparison operation.
/// \param op is the given comparison operation
/// \param inrvn is the variable already in the logical subgraph
/// \param slot is the input slot to the comparison of the variable already in the subgraph
/// \param othervn is the Varnode holding the other side of the comparison
/// \return \b true if the logical subgraph can successfully be extended through the comparison
bool SubvariableFlow::createCompareBridge(PcodeOp *op,ReplaceVarnode *inrvn,int4 slot,Varnode *othervn)

{
  bool inworklist;
  ReplaceVarnode *rep = setReplacement(othervn,inrvn->mask,inworklist);
  if (rep == (ReplaceVarnode *)0) return false;

  if (slot==0)
    addComparePatch(inrvn,rep,op);
  else
    addComparePatch(rep,inrvn,op);

  if (inworklist)
    worklist.push_back(rep);
  return true;
}

/// \brief Add a constant variable node to the logical subgraph
///
/// \param rop is the logical operation taking the constant as input
/// \param mask is the set of bits holding the logical value (within a bigger value)
/// \param slot is the input slot to the operation
/// \param constvn is the original constant
/// \return the new constant variable node
SubvariableFlow::ReplaceVarnode *SubvariableFlow::addConstant(ReplaceOp *rop,uintb mask,
					      uint4 slot,Varnode *constvn)
{
  newvarlist.emplace_back();
  ReplaceVarnode *res = &newvarlist.back();
  res->vn = constvn;
  res->replacement = (Varnode *)0;
  res->mask = mask;

  // Calculate the actual constant value
  int4 sa = leastsigbit_set(mask);
  res->val = (mask & constvn->getOffset()) >> sa;
  res->def = (ReplaceOp *)0;
  if (rop != (ReplaceOp *)0) {
    while(rop->input.size() <= slot)
      rop->input.push_back((ReplaceVarnode *)0);
    rop->input[slot] = res;
  }
  return res;
}

/// \brief Add a new constant variable node as an input to a logical operation.
///
/// The constant is new and isn't associated with a constant in the original graph.
/// \param rop is the logical operation taking the constant as input
/// \param slot is the input slot to the operation
/// \param val is the constant value
/// \return the new constant variable node
SubvariableFlow::ReplaceVarnode *SubvariableFlow::addNewConstant(ReplaceOp *rop,uint4 slot,uintb val)

{
  newvarlist.emplace_back();
  ReplaceVarnode *res = &newvarlist.back();
  res->vn = (Varnode *)0;
  res->replacement = (Varnode *)0;
  res->mask = 0;
  res->val = val;
  res->def = (ReplaceOp *)0;
  if (rop != (ReplaceOp *)0) {
    while(rop->input.size() <= slot)
      rop->input.push_back((ReplaceVarnode *)0);
    rop->input[slot] = res;
  }
  return res;
}

/// \brief Create a new, non-shadowing, subgraph variable node as an operation output
///
/// The new node does not shadow a preexisting Varnode. Because the ReplaceVarnode record
/// is defined by rop (the -def- field is filled in) this can still be distinguished from a constant.
/// \param rop is the logical operation taking the new output
/// \param mask describes the logical value
void SubvariableFlow::createNewOut(ReplaceOp *rop,uintb mask)

{
  newvarlist.emplace_back();
  ReplaceVarnode *res = &newvarlist.back();
  res->vn = (Varnode *)0;
  res->replacement = (Varnode *)0;
  res->mask = mask;

  rop->output = res;
  res->def = rop;
}

/// \brief Mark an operation where original data-flow is being pushed into a subgraph variable
///
/// The operation is not manipulating the logical value, but it produces a variable containing
/// the logical value. The original op will not change but will just produce a smaller value.
/// \param pushOp is the operation to mark
/// \param rvn is the output variable holding the logical value
void SubvariableFlow::addPush(PcodeOp *pushOp,ReplaceVarnode *rvn)

{
  patchlist.push_front(PatchRecord());		// Push to the front of the patch list
  patchlist.front().type = PatchRecord::push_patch;
  patchlist.front().patchOp = pushOp;
  patchlist.front().in1 = rvn;
}

/// \brief Mark an operation where a subgraph variable is naturally copied into the original data-flow
///
/// If the operations naturally takes the given logical value as input but the output
/// doesn't need to be traced as a logical value, a subgraph terminator (PatchRecord) is created
/// noting this. The original PcodeOp will be converted to a COPY.
/// \param pullop is the PcodeOp pulling the logical value out of the subgraph
/// \param rvn is the given subgraph variable holding the logical value
void SubvariableFlow::addTerminalPatch(PcodeOp *pullop,ReplaceVarnode *rvn)

{
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::copy_patch;	// Ultimately gets converted to a COPY
  patchlist.back().patchOp = pullop;	// Operation pulling the variable out
  patchlist.back().in1 = rvn;	// Point in container flow for pull
  pullcount += 1;		// a true terminal modification
}

/// \brief Mark an operation where a subgraph variable is naturally pulled into the original data-flow
///
/// If the operations naturally takes the given logical value as input but the output
/// doesn't need to be traced as a logical value, a subgraph terminator (PatchRecord) is created
/// noting this. The opcode of the operation will not change.
/// \param pullop is the PcodeOp pulling the logical value out of the subgraph
/// \param rvn is the given subgraph variable holding the logical value
/// \param slot is the input slot to the operation
void SubvariableFlow::addTerminalPatchSameOp(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot)

{
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::parameter_patch;	// Keep the original op, just change input
  patchlist.back().patchOp = pullop;	// Operation pulling the variable out
  patchlist.back().in1 = rvn;	// Point in container flow for pull
  patchlist.back().slot = slot;
  pullcount += 1;		// a true terminal modification
}

/// \brief Mark a subgraph bit variable flowing into an operation taking a boolean input
///
/// This doesn't count as a Varnode holding a logical value that needs to be patched (by itself).
/// A PatchRecord terminating the logical subgraph along the given edge is created.
/// \param pullop is the operation taking the boolean input
/// \param rvn is the given bit variable
/// \param slot is the input slot of the variable to the operation
void SubvariableFlow::addBooleanPatch(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot)

{
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::parameter_patch;	// Make no change to the operator, just put in the new input
  patchlist.back().patchOp = pullop;	// Operation pulling the variable out
  patchlist.back().in1 = rvn;	// Point in container flow for pull
  patchlist.back().slot = slot;
  // this is not a true modification
}

/// \brief Mark a subgraph variable flowing to an operation that expands it by padding with zero bits.
///
/// Data-flow along the specified edge within the logical subgraph is terminated by added a PatchRecord.
/// This doesn't count as a logical value that needs to be patched (by itself).
/// \param rvn is the given subgraph variable
/// \param pushop is the operation that pads the variable
/// \param sa is the amount the logical value is shifted to the left
void SubvariableFlow::addSuggestedPatch(ReplaceVarnode *rvn,PcodeOp *pushop,int4 sa)

{
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::extension_patch;
  patchlist.back().in1 = rvn;
  patchlist.back().patchOp = pushop;
  if (sa == -1)
    sa = leastsigbit_set(rvn->mask);
  patchlist.back().slot = sa;
  // This is not a true modification because the output is still the expanded size
}

/// \brief Mark subgraph variables flowing into a comparison operation
///
/// The operation accomplishes the logical comparison by comparing the larger containers.
/// A PatchRecord is created indicating that data-flow from the subgraph terminates at the comparison.
/// \param in1 is the first logical value to the comparison
/// \param in2 is the second logical value
/// \param op is the comparison operation
void SubvariableFlow::addComparePatch(ReplaceVarnode *in1,ReplaceVarnode *in2,PcodeOp *op)

{
  patchlist.emplace_back();
  patchlist.back().type = PatchRecord::compare_patch;
  patchlist.back().patchOp = op;
  patchlist.back().in1 = in1;
  patchlist.back().in2 = in2;
  pullcount += 1;
}

/// \brief Replace an input Varnode in the subgraph with a temporary register
///
/// This is used to avoid overlapping input Varnode errors. The temporary register
/// is typically short lived and gets quickly eliminated in favor of the new
/// logically sized Varnode.
/// \param rvn is the logical variable to replace
void SubvariableFlow::replaceInput(ReplaceVarnode *rvn)

{
  Varnode *newvn = fd->newUnique(rvn->vn->getSize());
  newvn = fd->setInputVarnode(newvn);
  fd->totalReplace(rvn->vn,newvn);
  fd->deleteVarnode(rvn->vn);
  rvn->vn = newvn;
}

/// \brief Decide if we use the same memory range of the original Varnode for the logical replacement
///
/// Usually the logical Varnode can use the \e true storage bytes that hold the value,
/// but there are a few corner cases where we want to use a new temporary register to hold the value.
/// \param rvn is the subgraph variable
/// \return \b true if the same memory range can be used to hold the value
bool SubvariableFlow::useSameAddress(ReplaceVarnode *rvn)

{
  if (rvn->vn->isInput()) return true;
  // If we trim an addrtied varnode, because of required merges, we increase chance of conflicting forms for one variable
  if (rvn->vn->isAddrTied()) return false;
  if ((rvn->mask&1)==0) return false; // Not aligned
  if (bitsize >= 8) return true;
  if (aggressive) return true;
  uint4 bitmask = 1;
  // Try to decide if this is the ONLY subvariable passing through
  // this container
  bitmask = (bitmask<<bitsize)-1;
  uintb mask = rvn->vn->getConsume();
  mask |= (uintb)bitmask;
  if (mask == rvn->mask) return true;
  return false;			// If more of the varnode is consumed than is in just this flow
}

/// \brief Calculcate address of replacement Varnode for given subgraph variable node
///
/// \param rvn is the given subgraph variable node
/// \return the address of the new logical Varnode
Address SubvariableFlow::getReplacementAddress(ReplaceVarnode *rvn) const

{
  Address addr = rvn->vn->getAddr();
  int4 sa = leastsigbit_set(rvn->mask) / 8; // Number of bytes value is shifted into container
  if (addr.isBigEndian())
    addr = addr + (rvn->vn->getSize() - flowsize - sa);
  else
    addr = addr + sa;
  addr.renormalize(flowsize);
  return addr;
}

/// \brief Build the logical Varnode which will replace its original containing Varnode
///
/// This is the main routine for converting a logical variable in the subgraph into
/// an actual Varnode object.
/// \param rvn is the logical variable
/// \return the (new or existing) Varnode object
Varnode *SubvariableFlow::getReplaceVarnode(ReplaceVarnode *rvn)

{
  if (rvn->replacement != (Varnode *)0)
    return rvn->replacement;
  if (rvn->vn == (Varnode *)0) {
    if (rvn->def==(ReplaceOp *)0) // A constant that did not come from an original Varnode
      return fd->newConstant(flowsize,rvn->val);
    rvn->replacement = fd->newUnique(flowsize);
    return rvn->replacement;
  }
  if (rvn->vn->isConstant()) {
    Varnode *newVn = fd->newConstant(flowsize,rvn->val);
    newVn->copySymbolIfValid(rvn->vn);
    return newVn;
  }

  bool isinput = rvn->vn->isInput();
  if (useSameAddress(rvn)) {
    Address addr = getReplacementAddress(rvn);
    if (isinput)
      replaceInput(rvn);	// Replace input to avoid overlap errors
    rvn->replacement = fd->newVarnode(flowsize,addr);
  }
  else
    rvn->replacement = fd->newUnique(flowsize);
  if (isinput)	// Is this an input
    rvn->replacement = fd->setInputVarnode(rvn->replacement);
  return rvn->replacement;
}

/// The subgraph is extended from the variable node at the top of the worklist.
/// Data-flow is traced forward and backward one level, possibly extending the subgraph
/// and adding new nodes to the worklist.
/// \return \b true if the node was successfully processed
bool SubvariableFlow::processNextWork(void)

{
  ReplaceVarnode *rvn = worklist.back();

  worklist.pop_back();

  if (sextrestrictions) {
    if (!traceBackwardSext(rvn)) return false;
    return traceForwardSext(rvn);
  }
  if (!traceBackward(rvn)) return false;
  return traceForward(rvn);
}

/// \param f is the function to attempt the subvariable transform on
/// \param root is a starting Varnode containing a smaller logical value
/// \param mask is a mask where 1 bits indicate the position of the logical value within the \e root Varnode
/// \param aggr is \b true if we should use aggressive (less restrictive) tests during the trace
/// \param sext is \b true if we should assume sign extensions from the logical value into its container
/// \param big is \b true if we look for subvariable flow for \e big (8-byte) logical values
SubvariableFlow::SubvariableFlow(Funcdata *f,Varnode *root,uintb mask,bool aggr,bool sext,bool big)

{
  fd = f;
  returnsTraversed = false;
  if (mask == (uintb)0) {
    fd = (Funcdata *)0;
    return;
  }
  aggressive = aggr;
  sextrestrictions = sext;
  bitsize = (mostsigbit_set(mask)-leastsigbit_set(mask))+1;
  if (bitsize <= 8)
    flowsize = 1;
  else if (bitsize <= 16)
    flowsize = 2;
  else if (bitsize <= 24)
    flowsize = 3;
  else if (bitsize <= 32)
    flowsize = 4;
  else if (bitsize <= 64) {
    if (!big) {
      fd = (Funcdata *)0;
      return;
    }
    flowsize = 8;
  }
  else {
    fd = (Funcdata *)0;
    return;
  }
  createLink((ReplaceOp *)0,mask,0,root);
}

/// Push the logical value around, setting up explicit transforms as we go that convert them
/// into explicit Varnodes. If at any point, we cannot naturally interpret the flow of the
/// logical value, return \b false.
/// \return \b true if a full transform has been constructed that can make logical values into explicit Varnodes
bool SubvariableFlow::doTrace(void)

{
  pullcount = 0;
  bool retval = false;
  if (fd != (Funcdata *)0) {
    retval = true;
    while(!worklist.empty()) {
      if (!processNextWork()) {
	retval = false;
	break;
      }
    }
  }

  // Clear marks
  map<Varnode *,ReplaceVarnode>::iterator iter;
  for(iter=varmap.begin();iter!=varmap.end();++iter)
    (*iter).first->clearMark();

  if (!retval) return false;
  if (pullcount == 0) return false;
  return true;
}

void SubvariableFlow::doReplacement(void)

{
  list<PatchRecord>::iterator piter;
  list<ReplaceOp>::iterator iter;

  // Do up front processing of the call return patches, which will be at the front of the list
  for(piter=patchlist.begin();piter!=patchlist.end();++piter) {
    if ((*piter).type != PatchRecord::push_patch) break;
    PcodeOp *pushOp = (*piter).patchOp;
    Varnode *newVn = getReplaceVarnode((*piter).in1);
    Varnode *oldVn = pushOp->getOut();
    fd->opSetOutput(pushOp, newVn);

    // Create placeholder defining op for old Varnode, until dead code cleans it up
    PcodeOp *newZext = fd->newOp(1, pushOp->getAddr());
    fd->opSetOpcode(newZext, CPUI_INT_ZEXT);
    fd->opSetInput(newZext,newVn,0);
    fd->opSetOutput(newZext,oldVn);
    fd->opInsertAfter(newZext, pushOp);
  }

  // Define all the outputs first
  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    PcodeOp *newop = fd->newOp((*iter).numparams,(*iter).op->getAddr());
    (*iter).replacement = newop;
    fd->opSetOpcode(newop,(*iter).opc);
    ReplaceVarnode *rout = (*iter).output;
    //      if (rout != (ReplaceVarnode *)0) {
    //	if (rout->replacement == (Varnode *)0)
    //	  rout->replacement = fd->newUniqueOut(flowsize,newop);
    //	else
    //	  fd->opSetOutput(newop,rout->replacement);
    //      }
    fd->opSetOutput(newop,getReplaceVarnode(rout));
    fd->opInsertAfter(newop,(*iter).op);
  }

  // Set all the inputs
  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    PcodeOp *newop = (*iter).replacement;
    for(uint4 i=0;i<(*iter).input.size();++i)
      fd->opSetInput(newop,getReplaceVarnode((*iter).input[i]),i);
  }

  // These are operations that carry flow from the small variable into an existing
  // variable of the correct size
  for(;piter!=patchlist.end();++piter) {
    PcodeOp *pullop = (*piter).patchOp;
    switch((*piter).type) {
    case PatchRecord::copy_patch:
      while(pullop->numInput() > 1)
	fd->opRemoveInput(pullop,pullop->numInput()-1);
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in1),0);
      fd->opSetOpcode(pullop,CPUI_COPY);
      break;
    case PatchRecord::compare_patch:
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in1),0);
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in2),1);
      break;
    case PatchRecord::parameter_patch:
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in1),(*piter).slot);
      break;
    case PatchRecord::extension_patch:
      {
	// These are operations that flow the small variable into a bigger variable but
	// where all the remaining bits are zero
	int4 sa = (*piter).slot;
	vector<Varnode *> invec;
	Varnode *inVn = getReplaceVarnode((*piter).in1);
	int4 outSize = pullop->getOut()->getSize();
	if (sa == 0) {
	  invec.push_back(inVn);
	  OpCode opc = (inVn->getSize() == outSize) ? CPUI_COPY : CPUI_INT_ZEXT;
	  fd->opSetOpcode(pullop, opc);
	  fd->opSetAllInput(pullop, invec);
	}
	else {
	  if (inVn->getSize() != outSize) {
	    PcodeOp *zextop = fd->newOp(1, pullop->getAddr());
	    fd->opSetOpcode(zextop, CPUI_INT_ZEXT);
	    Varnode *zextout = fd->newUniqueOut(outSize, zextop);
	    fd->opSetInput(zextop, inVn, 0);
	    fd->opInsertBefore(zextop, pullop);
	    invec.push_back(zextout);
	  }
	  else
	    invec.push_back(inVn);
	  invec.push_back(fd->newConstant(4, sa));
	  fd->opSetAllInput(pullop, invec);
	  fd->opSetOpcode(pullop, CPUI_INT_LEFT);
	}
	break;
      }
    case PatchRecord::push_patch:
      break;	// Shouldn't see these here, handled earlier
    case PatchRecord::int2float_patch:
      {
	PcodeOp *zextOp = fd->newOp(1, pullop->getAddr());
	fd->opSetOpcode(zextOp, CPUI_INT_ZEXT);
	Varnode *invn = getReplaceVarnode((*piter).in1);
	fd->opSetInput(zextOp,invn,0);
	int4 sizeout = TypeOpFloatInt2Float::preferredZextSize(invn->getSize());
	Varnode *outvn = fd->newUniqueOut(sizeout, zextOp);
	fd->opInsertBefore(zextOp, pullop);
	fd->opSetInput(pullop, outvn, 0);
	break;
      }
    }
  }
}

void RuleSubvarAnd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleSubvarAnd::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  Varnode *vn = op->getIn(0);
  Varnode *outvn = op->getOut();
  //  if (vn->getSize() != 1) return 0; // Only for bitsize variables
  if (outvn->getConsume() != op->getIn(1)->getOffset()) return 0;
  if ((outvn->getConsume() & 1)==0) return 0;
  uintb cmask;
  if (outvn->getConsume() == (uintb)1)
    cmask = (uintb)1;
  else {
    cmask = calc_mask(vn->getSize());
    cmask >>=8;
    while(cmask != 0) {
      if (cmask == outvn->getConsume()) break;
      cmask >>=8;
    }
  }
  if (cmask == 0) return 0;
  //  if (vn->getConsume() == 0) return 0;
  //  if ((vn->getConsume() & 0xff)==0xff) return 0;
  //  if (op->getIn(1)->getOffset() != (uintb)1) return 0;
  if (op->getOut()->hasNoDescend()) return 0;
  SubvariableFlow subflow(&data,vn,cmask,false,false,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

void RuleSubvarSubpiece::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSubvarSubpiece::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  Varnode *outvn = op->getOut();
  int4 flowsize = outvn->getSize();
  uintb mask = calc_mask( flowsize );
  mask <<= 8*((int4)op->getIn(1)->getOffset());
  bool aggressive = outvn->isPtrFlow();
  if (!aggressive) {
    if ((vn->getConsume() & mask) != vn->getConsume()) return 0;
    if (op->getOut()->hasNoDescend()) return 0;
  }
  bool big = false;
  if (flowsize >= 8 && vn->isInput()) {
    // Vector register inputs getting truncated to what actually gets used
    // happens occasionally.  We let SubvariableFlow deal with this special case
    // to avoid overlapping inputs
    // TODO: ActionLaneDivide should be handling this
    if (vn->loneDescend() == op)
      big = true;
  }
  SubvariableFlow subflow(&data,vn,mask,aggressive,false,big);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

void RuleSubvarCompZero::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_NOTEQUAL);
  oplist.push_back(CPUI_INT_EQUAL);
}

int4 RuleSubvarCompZero::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  Varnode *vn = op->getIn(0);
  uintb mask = vn->getNZMask();
  int4 bitnum = leastsigbit_set(mask);
  if (bitnum == -1) return 0;
  if ((mask >> bitnum) != 1) return 0; // Check if only one bit active

  // Check if the active bit is getting tested
  if ((op->getIn(1)->getOffset()!=mask)&&
      (op->getIn(1)->getOffset()!=0))
    return 0;

  if (op->getOut()->hasNoDescend()) return 0;
  // We do a basic check that the stream from which it looks like
  // the bit is getting pulled is not fully consumed
  if (vn->isWritten()) {
    PcodeOp *andop = vn->getDef();
    if (andop->numInput()==0) return 0;
    Varnode *vn0 = andop->getIn(0);
    switch(andop->code()) {
    case CPUI_INT_AND:
    case CPUI_INT_OR:
    case CPUI_INT_RIGHT:
      {
	if (vn0->isConstant()) return 0;
	uintb mask0 = vn0->getConsume() & vn0->getNZMask();
	uintb wholemask = calc_mask(vn0->getSize()) & mask0;
	// We really need a popcnt here
	// We want: if the number of bits that are both consumed
	// and not known to be zero are "big" then don't continue
	// because it doesn't look like a few bits getting manipulated
	// within a status register
	if ((wholemask & 0xff)==0xff) return 0;
	if ((wholemask & 0xff00)==0xff00) return 0;
      }
      break;
    default:
      break;
    }
  }

  SubvariableFlow subflow(&data,vn,mask,false,false,false);
  if (!subflow.doTrace()) {
    return 0;
  }
  subflow.doReplacement();
  return 1;
}

void RuleSubvarShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
}

int4 RuleSubvarShift::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  if (vn->getSize() != 1) return 0;
  if (!op->getIn(1)->isConstant()) return 0;
  int4 sa = (int4)op->getIn(1)->getOffset();
  uintb mask = vn->getNZMask();
  if ((mask >> sa) != (uintb)1) return 0; // Pulling out a single bit
  mask = (mask >> sa) << sa;
  if (op->getOut()->hasNoDescend()) return 0;

  SubvariableFlow subflow(&data,vn,mask,false,false,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

void RuleSubvarZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ZEXT);
}

int4 RuleSubvarZext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getOut();
  Varnode *invn = op->getIn(0);
  uintb mask = calc_mask(invn->getSize());

  SubvariableFlow subflow(&data,vn,mask,invn->isPtrFlow(),false,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

void RuleSubvarSext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SEXT);
}

int4 RuleSubvarSext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getOut();
  Varnode *invn = op->getIn(0);
  uintb mask = calc_mask(invn->getSize());

  SubvariableFlow subflow(&data,vn,mask,isaggressive,true,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

void RuleSubvarSext::reset(Funcdata &data)

{
  isaggressive = data.getArch()->aggressive_ext_trim;
}

/// \brief Find or build the placeholder objects for a Varnode that needs to be split
///
/// Mark the Varnode so it doesn't get revisited.
/// Decide if the Varnode needs to go into the worklist.
/// \param vn is the Varnode that needs to be split
/// \return the array of placeholders describing the split or null
TransformVar *SplitFlow::setReplacement(Varnode *vn)

{
  TransformVar *res;
  if (vn->isMark()) {		// Already seen before
    res = getSplit(vn, laneDescription);
    return res;
  }

  if (vn->isTypeLock() && vn->getType()->getMetatype() != TYPE_PARTIALSTRUCT)
    return (TransformVar *)0;
  if (vn->isInput())
    return (TransformVar *)0;		// Right now we can't split inputs
  if (vn->isFree() && (!vn->isConstant()))
    return (TransformVar *)0;		// Abort

  res = newSplit(vn, laneDescription);	// Create new ReplaceVarnode and put it in map
  vn->setMark();
  if (!vn->isConstant())
    worklist.push_back(res);

  return res;
}

/// \brief Split given op into its lanes.
///
/// We assume op is a logical operation, or a COPY, or an INDIRECT. It must have an output.
/// All inputs and output have their placeholders generated and added to the worklist
/// if appropriate.
/// \param op is the given op
/// \param rvn is a known parameter of the op
/// \param slot is the incoming slot of the known parameter (-1 means parameter is output)
/// \return \b true if the op is successfully split
bool SplitFlow::addOp(PcodeOp *op,TransformVar *rvn,int4 slot)

{
  TransformVar *outvn;
  if (slot == -1)
    outvn = rvn;
  else {
    outvn = setReplacement(op->getOut());
    if (outvn == (TransformVar *)0)
      return false;
  }

  if (outvn->getDef() != (TransformOp *)0)
    return true;	// Already traversed

  TransformOp *loOp = newOpReplace(op->numInput(), op->code(), op);
  TransformOp *hiOp = newOpReplace(op->numInput(), op->code(), op);
  int4 numParam = op->numInput();
  if (op->code() == CPUI_INDIRECT) {
    opSetInput(loOp,newIop(op->getIn(1)),1);
    opSetInput(hiOp,newIop(op->getIn(1)),1);
    loOp->inheritIndirect(op);
    hiOp->inheritIndirect(op);
    numParam = 1;
  }
  for(int4 i=0;i<numParam;++i) {
    TransformVar *invn;
    if (i == slot)
      invn = rvn;
    else {
      invn = setReplacement(op->getIn(i));
      if (invn == (TransformVar *)0)
	return false;
    }
    opSetInput(loOp,invn,i);		// Low piece with low op
    opSetInput(hiOp,invn+1,i);		// High piece with high op
  }
  opSetOutput(loOp,outvn);
  opSetOutput(hiOp,outvn+1);
  return true;
}

/// \brief Try to trace the pair of logical values, forward, through ops that read them
///
/// Try to trace pieces of TransformVar pair forward, through reading ops, update worklist
/// \param rvn is the TransformVar pair to trace, as an array
/// \return \b true if logical pieces can be naturally traced, \b false otherwise
bool SplitFlow::traceForward(TransformVar *rvn)

{
  Varnode *origvn = rvn->getOriginal();
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = origvn->beginDescend();
  enditer = origvn->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter++;
    Varnode *outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&(outvn->isMark()))
      continue;
    switch(op->code()) {
    case CPUI_COPY:
    case CPUI_MULTIEQUAL:
    case CPUI_INDIRECT:
    case CPUI_INT_AND:
    case CPUI_INT_OR:
    case CPUI_INT_XOR:
  //  case CPUI_INT_NEGATE:
      if (!addOp(op,rvn,op->getSlot(origvn)))
	return false;
      break;
    case CPUI_SUBPIECE:
    {
      if (outvn->isPrecisLo() || outvn->isPrecisHi())
	return false;		// Do not split if we know value comes from double precision pieces
      uintb val = op->getIn(1)->getOffset();
      if ((val==0)&&(outvn->getSize() == laneDescription.getSize(0))) {
	TransformOp *rop = newPreexistingOp(1,CPUI_COPY,op);	// Grabs the low piece
	opSetInput(rop, rvn, 0);
      }
      else if ((val == laneDescription.getSize(0))&&(outvn->getSize() == laneDescription.getSize(1))) {
	TransformOp *rop = newPreexistingOp(1,CPUI_COPY,op);	// Grabs the high piece
	opSetInput(rop, rvn+1, 0);
      }
      else
	return false;
      break;
    }
    case CPUI_INT_LEFT:
    {
      Varnode *tmpvn = op->getIn(1);
      if (!tmpvn->isConstant())
	return false;
      uintb val = tmpvn->getOffset();
      if (val < laneDescription.getSize(1) * 8)
	return false;			// Must obliterate all high bits
      TransformOp *rop = newPreexistingOp(2,CPUI_INT_LEFT,op);		// Keep original shift
      TransformOp *zextrop = newOp(1, CPUI_INT_ZEXT, rop);
      opSetInput(zextrop, rvn, 0);		// Input is just the low piece
      opSetOutput(zextrop, newUnique(laneDescription.getWholeSize()));
      opSetInput(rop, zextrop->getOut(), 0);
      opSetInput(rop, newConstant(op->getIn(1)->getSize(), 0, op->getIn(1)->getOffset()), 1);	// Original shift amount
      break;
    }
    case CPUI_INT_SRIGHT:
    case CPUI_INT_RIGHT:
    {
      Varnode *tmpvn = op->getIn(1);
      if (!tmpvn->isConstant())
	return false;
      uintb val = tmpvn->getOffset();
      if (val < laneDescription.getSize(0) * 8)
	return false;
      OpCode extOpCode = (op->code() == CPUI_INT_RIGHT) ? CPUI_INT_ZEXT : CPUI_INT_SEXT;
      if (val == laneDescription.getSize(0) * 8) {	// Shift of exactly loSize bytes
	TransformOp *rop = newPreexistingOp(1,extOpCode,op);
	opSetInput(rop, rvn+1, 0);	// Input is the high piece
      }
      else {
	uintb remainShift = val - laneDescription.getSize(0) * 8;
	TransformOp *rop = newPreexistingOp(2,op->code(),op);
	TransformOp *extrop = newOp(1, extOpCode, rop);
	opSetInput(extrop, rvn+1, 0);	// Input is the high piece
	opSetOutput(extrop, newUnique(laneDescription.getWholeSize()));
	opSetInput(rop, extrop->getOut(), 0);
	opSetInput(rop, newConstant(op->getIn(1)->getSize(), 0, remainShift), 1);	// Shift any remaining bits
      }
      break;
    }
    default:
      return false;
    }
  }
  return true;
}

/// \brief Try to trace the pair of logical values, backward, through the defining op
///
/// Create part of transform related to the defining op, and update the worklist as necessary.
/// \param rvn is the logical value to examine
/// \return \b false if the trace is not possible
bool SplitFlow::traceBackward(TransformVar *rvn)

{
  PcodeOp *op = rvn->getOriginal()->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input

  switch(op->code()) {
  case CPUI_COPY:
  case CPUI_MULTIEQUAL:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_XOR:
  case CPUI_INDIRECT:
//  case CPUI_INT_NEGATE:
    if (!addOp(op,rvn,-1))
      return false;
    break;
  case CPUI_PIECE:
  {
    if (op->getIn(0)->getSize() != laneDescription.getSize(1))
      return false;
    if (op->getIn(1)->getSize() != laneDescription.getSize(0))
      return false;
    TransformOp *loOp = newOpReplace(1, CPUI_COPY, op);
    TransformOp *hiOp = newOpReplace(1, CPUI_COPY, op);
    opSetInput(loOp,getPreexistingVarnode(op->getIn(1)),0);
    opSetOutput(loOp,rvn);	// Least sig -> low
    opSetInput(hiOp,getPreexistingVarnode(op->getIn(0)),0);
    opSetOutput(hiOp,rvn+1);	// Most sig -> high
    break;
  }
  case CPUI_INT_ZEXT:
  {
    if (op->getIn(0)->getSize() != laneDescription.getSize(0))
      return false;
    if (op->getOut()->getSize() != laneDescription.getWholeSize())
      return false;
    TransformOp *loOp = newOpReplace(1, CPUI_COPY, op);
    TransformOp *hiOp = newOpReplace(1, CPUI_COPY, op);
    opSetInput(loOp,getPreexistingVarnode(op->getIn(0)),0);
    opSetOutput(loOp,rvn);	// ZEXT input -> low
    opSetInput(hiOp,newConstant(laneDescription.getSize(1), 0, 0), 0);
    opSetOutput(hiOp,rvn+1);	// zero -> high
    break;
  }
  case CPUI_INT_LEFT:
  {
    Varnode *cvn = op->getIn(1);
    if (!cvn->isConstant()) return false;
    if (cvn->getOffset() != laneDescription.getSize(0) * 8) return false;
    Varnode *invn = op->getIn(0);
    if (!invn->isWritten()) return false;
    PcodeOp *zextOp = invn->getDef();
    if (zextOp->code() != CPUI_INT_ZEXT) return false;
    invn = zextOp->getIn(0);
    if (invn->getSize() != laneDescription.getSize(1)) return false;
    if (invn->isFree()) return false;
    TransformOp *loOp = newOpReplace(1, CPUI_COPY, op);
    TransformOp *hiOp = newOpReplace(1, CPUI_COPY, op);
    opSetInput(loOp,newConstant(laneDescription.getSize(0), 0, 0), 0);
    opSetOutput(loOp, rvn);	// zero -> low
    opSetInput(hiOp,getPreexistingVarnode(invn), 0);
    opSetOutput(hiOp, rvn+1);	// invn -> high
    break;
  }
//  case CPUI_LOAD:		// We could split into two different loads
  default:
    return false;
  }
  return true;
}

/// \return \b true if the logical split was successfully pushed through its local operators
bool SplitFlow::processNextWork(void)

{
  TransformVar *rvn = worklist.back();

  worklist.pop_back();

  if (!traceBackward(rvn)) return false;
  return traceForward(rvn);
}

SplitFlow::SplitFlow(Funcdata *f,Varnode *root,int4 lowSize)
  : TransformManager(f), laneDescription(root->getSize(),lowSize,root->getSize()-lowSize)

{
  setReplacement(root);
}

/// Push the logical split around, setting up the explicit transforms as we go.
/// If at any point, the split cannot be naturally pushed, return \b false.
/// \return \b true if a full transform has been constructed that can perform the split
bool SplitFlow::doTrace(void)

{
  if (worklist.empty())
    return false;		// Nothing to do
  bool retval = true;
  while(!worklist.empty()) {	// Process the worklist until its done
    if (!processNextWork()) {
      retval = false;
      break;
    }
  }

  clearVarnodeMarks();
  if (!retval) return false;
  return true;
}

void RuleSplitFlow::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSplitFlow::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 loSize = (int4)op->getIn(1)->getOffset();
  if (loSize == 0)			// Make sure SUBPIECE doesn't take least significant part
    return 0;
  Varnode *vn = op->getIn(0);
  if (!vn->isWritten())
    return 0;
  if (vn->isPrecisLo() || vn->isPrecisHi())
    return 0;
  if (op->getOut()->getSize() + loSize != vn->getSize())
    return 0;				// Make sure SUBPIECE is taking most significant part
  PcodeOp *concatOp = (PcodeOp *)0;
  PcodeOp *multiOp = vn->getDef();
  while(multiOp->code() == CPUI_INDIRECT) {	// PIECE may come through INDIRECT
    Varnode *tmpvn = multiOp->getIn(0);
    if (!tmpvn->isWritten()) return 0;
    multiOp = tmpvn->getDef();
  }
  if (multiOp->code() == CPUI_PIECE) {
    if (vn->getDef() != multiOp)
      concatOp = multiOp;
  }
  else if (multiOp->code() == CPUI_MULTIEQUAL) {	// Otherwise PIECE comes through MULTIEQUAL
    for(int4 i=0;i<multiOp->numInput();++i) {
      Varnode *invn = multiOp->getIn(i);
      if (!invn->isWritten()) continue;
      PcodeOp *tmpOp = invn->getDef();
      if (tmpOp->code() == CPUI_PIECE) {
	concatOp = tmpOp;
	break;
      }
    }
  }
  if (concatOp == (PcodeOp *)0)			// Didn't find the concatenate
    return 0;
  if (concatOp->getIn(1)->getSize() != loSize)
    return 0;
  SplitFlow splitFlow(&data,vn,loSize);
  if (!splitFlow.doTrace()) return 0;
  splitFlow.apply();
  return 1;
}

/// If \b pointer Varnode is written by a COPY, INT_ADD, PTRSUB, or PTRADD from another pointer to a
///   - structure
///   - array OR
///   - to an implied array with the given base type
///
/// then update \b pointer Varnode, \b baseOffset, and \b ptrType to this.
/// \param impliedBase if non-null is the allowed element data-type for an implied array
/// \return \b true if \b pointer was successfully updated
bool SplitDatatype::RootPointer::backUpPointer(Datatype *impliedBase)

{
  if (!pointer->isWritten())
    return false;
  int4 off;
  PcodeOp *addOp = pointer->getDef();
  OpCode opc = addOp->code();
  if (opc == CPUI_PTRSUB || opc == CPUI_INT_ADD || opc == CPUI_PTRADD) {
    Varnode *cvn = addOp->getIn(1);
    if (!cvn->isConstant())
      return false;
    off = (int4)cvn->getOffset();
  }
  else if (opc == CPUI_COPY)
    off = 0;
  else {
    return false;
  }
  Varnode *tmpPointer = addOp->getIn(0);
  Datatype *ct = tmpPointer->getTypeReadFacing(addOp);
  if (ct->getMetatype() != TYPE_PTR)
    return false;
  Datatype *parent = ((TypePointer *)ct)->getPtrTo();
  type_metatype meta = parent->getMetatype();
  if (meta != TYPE_STRUCT && meta != TYPE_ARRAY) {
    if ((opc != CPUI_PTRADD && opc != CPUI_COPY) || parent != impliedBase)
      return false;
  }
  ptrType = (TypePointer *)ct;
  if (opc == CPUI_PTRADD)
    off *= (int4)addOp->getIn(2)->getOffset();
  off = AddrSpace::addressToByteInt(off, ptrType->getWordSize());
  baseOffset += off;
  pointer = tmpPointer;
  return true;
}

/// We search for a pointer to the specified data-type starting with the LOAD/STORE. If we don't immediately
/// find it, we back up one level (through a PTRSUB, PTRADD, or INT_ADD). If it isn't found after 1 hop,
/// \b false is returned.  Once this pointer is found, we back up through any single path of nested TYPE_STRUCT
/// and TYPE_ARRAY offsets to establish the final root \b pointer, and \b true is returned. Any accumulated offset,
/// relative to the original LOAD or STORE pointer is recorded in the \b baseOffset.
/// \param op is the LOAD or STORE
/// \param valueType is the specific data-type to match
/// \return \b true if the root pointer is found
bool SplitDatatype::RootPointer::find(PcodeOp *op,Datatype *valueType)

{
  Datatype *impliedBase = (Datatype *)0;
  if (valueType->getMetatype() == TYPE_PARTIALSTRUCT)		// Strip off partial to get containing struct or array
    valueType = ((TypePartialStruct *)valueType)->getParent();
  if (valueType->getMetatype() == TYPE_ARRAY) {		// If the data-type is an array
    valueType = ((TypeArray *)valueType)->getBase();
    impliedBase = valueType;				// we allow an implied array (pointer to element) as a match
  }
  loadStore = op;
  baseOffset = 0;
  firstPointer = pointer = op->getIn(1);
  Datatype *ct = pointer->getTypeReadFacing(op);
  if (ct->getMetatype() != TYPE_PTR)
    return false;
  ptrType = (TypePointer *)ct;
  if (ptrType->getPtrTo() != valueType) {
    if (impliedBase != (Datatype *)0)
      return false;
    if (!backUpPointer(impliedBase))
      return false;
    if (ptrType->getPtrTo() != valueType)
      return false;
  }
  // The required pointer is found.  We try to back up to pointers to containing structures or arrays
  for(int4 i=0;i<3;++i) {
    if (pointer->isAddrTied() || pointer->loneDescend() == (PcodeOp *)0) break;
    if (!backUpPointer(impliedBase))
      break;
  }
  return true;
}

/// Add a COPY op from the \b pointer Varnode to temporary register and make it the new root \b pointer.
/// This guarantees that the \b pointer Varnode will not be modified by subsequent STOREs and
/// can be implicit in the expressions.
/// \param data is the containing function
/// \param followOp is the point where the COPY should be inserted
void SplitDatatype::RootPointer::duplicateToTemp(Funcdata &data,PcodeOp *followOp)

{
  Varnode *newRoot = data.buildCopyTemp(pointer, followOp);
  newRoot->updateType(ptrType, false, false);
  pointer = newRoot;
}

/// If the pointer Varnode is no longer used, recursively check and remove the op producing it,
/// which will be either an INT_ADD or PTRSUB, until the root \b pointer is reached or
/// a Varnode still being used is encountered.
/// \param data is the containing function
void SplitDatatype::RootPointer::freePointerChain(Funcdata &data)

{
  while (firstPointer != pointer && !firstPointer->isAddrTied() && firstPointer->hasNoDescend()) {
    PcodeOp *tmpOp = firstPointer->getDef();
    firstPointer = tmpOp->getIn(0);
    data.opDestroy(tmpOp);
  }
}

/// \brief Obtain the component of the given data-type at the specified offset
///
/// The data-type must be a composite of some form. This method finds a component data-type
/// starting exactly at the offset, if it exists.  The component may be nested more than 1 level deep.
/// If the given data-type is of composite form and has no component defined at the specified offset,
/// an undefined data-type matching the size of the \e hole is returned and \b isHole is set to \b true.
/// \param ct is the given data-type
/// \param offset is the specified offset
/// \param isHole passes back whether a hole in the composite was encountered
/// \return the component data-type at the offset or null, if no such component exists
Datatype *SplitDatatype::getComponent(Datatype *ct,int4 offset,bool &isHole)

{
  isHole = false;
  Datatype *curType = ct;
  int8 curOff = offset;
  do {
    curType = curType->getSubType(curOff,&curOff);
    if (curType == (Datatype *)0) {
      int4 hole = ct->getHoleSize(offset);
      if (hole > 0) {
	if (hole > 8)
	  hole = 8;
	isHole = true;
	return types->getBase(hole, TYPE_UNKNOWN);
      }
      return curType;
    }
  } while(curOff != 0 || curType->getMetatype() == TYPE_ARRAY);
  return curType;
}

/// For the given data-type, taking into account configuration options, return:
///   - -1 for not splittable
///   - 0 for struct based data-type that needs to be split
///   - 1 for array based data-type that needs to be split
///   - 2 for primitive data-type that can be split multiple ways
/// \param ct is the given data-type
/// \return the categorization
int4 SplitDatatype::categorizeDatatype(Datatype *ct)

{
  Datatype *subType;
  switch(ct->getMetatype()) {
    case TYPE_ARRAY:
      if (!splitArrays) break;
      subType = ((TypeArray *)ct)->getBase();
      if (subType->getMetatype() != TYPE_UNKNOWN || subType->getSize() != 1)
	return 1;
      else
	return 2;	// unknown1 array does not need splitting and acts as (large) primitive
    case TYPE_PARTIALSTRUCT:
      subType = ((TypePartialStruct *)ct)->getParent();
      if (subType->getMetatype() == TYPE_ARRAY) {
	if (!splitArrays) break;
	subType = ((TypeArray *)subType)->getBase();
	if (subType->getMetatype() != TYPE_UNKNOWN || subType->getSize() != 1)
	  return 1;
	else
	  return 2;	// unknown1 array does not need splitting and acts as (large) primitive
      }
      else if (subType->getMetatype() == TYPE_STRUCT) {
	if (!splitStructures) break;
	return 0;
      }
      break;
    case TYPE_STRUCT:
      if (!splitStructures) break;
      if (ct->numDepend() > 1)
	return 0;
      break;
    case TYPE_INT:
    case TYPE_UINT:
    case TYPE_UNKNOWN:
      return 2;
    default:
      break;
  }
  return -1;
}

/// \brief Can the two given data-types be mutually split into matching logical components
///
/// Test if the data-types have components with matching size and offset. If so, the component
/// data-types and offsets are saved to the \b pieces array and \b true is returned.
/// At least one of the data-types must be a partial data-type, but the other may be a
/// TYPE_UNKNOWN, which this method assumes can be split into components of arbitrary size.
/// \param inBase is the data-type coming into the operation
/// \param outBase is the data-type coming out of the operation
/// \param inConstant is \b true if the incoming data-type labels a constant
/// \return \b true if the data-types have compatible components, \b false otherwise
bool SplitDatatype::testDatatypeCompatibility(Datatype *inBase,Datatype *outBase,bool inConstant)

{
  int4 inCategory = categorizeDatatype(inBase);
  if (inCategory < 0)
    return false;
  int4 outCategory = categorizeDatatype(outBase);
  if (outCategory < 0)
    return false;
  if (outCategory == 2 && inCategory == 2)
    return false;
  if (!inConstant && inBase == outBase && inBase->getMetatype() == TYPE_STRUCT)
    return false;	// Don't split a whole structure unless it is getting initialized from a constant
  if (isLoadStore && outCategory == 2 && inCategory == 1)
    return false;	// Don't split array pointer writing into primitive
  if (isLoadStore && inCategory == 2 && !inConstant && outCategory == 1)
    return false;	// Don't split primitive into an array pointer, TODO: We could check if primitive is defined by PIECE
  if (isLoadStore && inCategory == 1 && outCategory == 1 && !inConstant)
    return false;	// Don't split copies between arrays
  bool inHole;
  bool outHole;
  int4 curOff = 0;
  int4 sizeLeft = inBase->getSize();
  if (inCategory == 2) {		// If input is primitive
    while(sizeLeft > 0) {
      Datatype *curOut = getComponent(outBase,curOff,outHole);
      if (curOut == (Datatype *)0) return false;
      // Throw away primitive data-type if it is a constant
      Datatype *curIn = inConstant ? curOut : types->getBase(curOut->getSize(), TYPE_UNKNOWN);
      dataTypePieces.emplace_back(curIn,curOut,curOff);
      sizeLeft -= curOut->getSize();
      curOff += curOut->getSize();
      if (outHole) {
	if (dataTypePieces.size() == 1)
	  return false;		// Initial offset into structure is at a hole
	if (sizeLeft == 0 && dataTypePieces.size() == 2)
	  return false;		// Two pieces, one is a hole.  Likely padding.
      }
    }
  }
  else if (outCategory == 2) {		// If output is primitive
    while(sizeLeft > 0) {
      Datatype *curIn = getComponent(inBase,curOff,inHole);
      if (curIn == (Datatype *)0) return false;
      Datatype *curOut = types->getBase(curIn->getSize(), TYPE_UNKNOWN);
      dataTypePieces.emplace_back(curIn,curOut,curOff);
      sizeLeft -= curIn->getSize();
      curOff += curIn->getSize();
      if (inHole) {
	if (dataTypePieces.size() == 1)
	  return false;		// Initial offset into structure is at a hole
	if (sizeLeft == 0 && dataTypePieces.size() == 2)
	  return false;		// Two pieces, one is a hole.  Likely padding.
      }
    }
  }
  else {	// Both in and out data-types have components
    while(sizeLeft > 0) {
      Datatype *curIn = getComponent(inBase,curOff,inHole);
      if (curIn == (Datatype *)0) return false;
      Datatype *curOut = getComponent(outBase,curOff,outHole);
      if (curOut == (Datatype *)0) return false;
      while(curIn->getSize() != curOut->getSize()) {
	if (curIn->getSize() > curOut->getSize()) {
	  if (inHole)
	    curIn = types->getBase(curOut->getSize(), TYPE_UNKNOWN);
	  else
	    curIn = getComponent(curIn,0,inHole);
	  if (curIn == (Datatype *)0) return false;
	}
	else {
	  if (outHole)
	    curOut = types->getBase(curIn->getSize(), TYPE_UNKNOWN);
	  else
	    curOut = getComponent(curOut,0,outHole);
	  if (curOut == (Datatype *)0) return false;
	}
      }
      dataTypePieces.emplace_back(curIn,curOut,curOff);
      sizeLeft -= curIn->getSize();
      curOff += curIn->getSize();
    }
  }
  return dataTypePieces.size() > 1;
}

/// \brief Test specific constraints for splitting the given COPY operation into pieces
///
/// Don't split function inputs.  Don't split hidden COPYs.
/// \return \b true if the split can proceed
bool SplitDatatype::testCopyConstraints(PcodeOp *copyOp)

{
  Varnode *inVn = copyOp->getIn(0);
  if (inVn->isInput()) return false;
  if (inVn->isAddrTied()) {
    Varnode *outVn = copyOp->getOut();
    if (outVn->isAddrTied() && outVn->getAddr() == inVn->getAddr())
      return false;
  }
  else if (inVn->isWritten() && inVn->getDef()->code() == CPUI_LOAD) {
    if (inVn->loneDescend() == copyOp)
      return false;		// This situation is handled by splitCopy()
  }
  return true;
}

/// \brief If the given Varnode is an extended precision constant, create split constants
///
/// Look for ZEXT(c) and CONCAT(c1,c2) forms. Try to split into single precision Varnodes.
/// \param vn is the given Varnode
/// \param inVarnodes will contain the split constant Varnodes
/// \return \b true if the Varnode is an extended precision constant and the split is successful
bool SplitDatatype::generateConstants(Varnode *vn,vector<Varnode *> &inVarnodes)

{
  if (vn->loneDescend() == (PcodeOp *)0) return false;
  if (!vn->isWritten()) return false;
  PcodeOp *op = vn->getDef();
  OpCode opc = op->code();
  if (opc == CPUI_INT_ZEXT) {
    if (!op->getIn(0)->isConstant()) return false;
  }
  else if (opc == CPUI_PIECE) {
    if (!op->getIn(0)->isConstant() || !op->getIn(1)->isConstant())
      return false;
  }
  else
    return false;
  uintb lo,hi;
  int4 losize;
  int4 fullsize = vn->getSize();
  bool isBigEndian = vn->getSpace()->isBigEndian();
  if (opc == CPUI_INT_ZEXT) {
    hi = 0;
    lo = op->getIn(0)->getOffset();
    losize = op->getIn(0)->getSize();
  }
  else {
    hi = op->getIn(0)->getOffset();
    lo = op->getIn(1)->getOffset();
    losize = op->getIn(1)->getSize();
  }
  for(int4 i=0;i<dataTypePieces.size();++i) {
    Datatype *dt = dataTypePieces[i].inType;
    if (dt->getSize() > sizeof(uintb)) {
      inVarnodes.clear();
      return false;
    }
    int4 sa;
    if (isBigEndian)
      sa = fullsize - (dataTypePieces[i].offset + dt->getSize());
    else
      sa = dataTypePieces[i].offset;
    uintb val;
    if (sa >= losize)
      val = hi >> (sa-losize);
    else {
      val = lo >> sa * 8;
      if (sa + dt->getSize() > losize)
	val |= hi << (losize - sa)*8;
    }
    val &= calc_mask(dt->getSize());
    Varnode *outVn = data.newConstant(dt->getSize(), val);
    inVarnodes.push_back(outVn);
    outVn->updateType(dt, false, false);
  }
  data.opDestroy(op);
  return true;
}

/// \brief Assuming the input is a constant, build split constants
///
/// Build constant input Varnodes, extracting the constant value from the given root constant
/// based on the input offsets in \b dataTypePieces.
/// \param rootVn is the given root constant
/// \param inVarnodes is the container for the new Varnodes
/// \param bigEndian is \b true if the output address space is big endian
void SplitDatatype::buildInConstants(Varnode *rootVn,vector<Varnode *> &inVarnodes,bool bigEndian)

{
  uintb baseVal = rootVn->getOffset();
  for(int4 i=0;i<dataTypePieces.size();++i) {
    Datatype *dt = dataTypePieces[i].inType;
    int4 off = dataTypePieces[i].offset;
    if (bigEndian)
      off = rootVn->getSize() - off - dt->getSize();
    uintb val = (baseVal >> (8*off)) & calc_mask(dt->getSize());
    Varnode *outVn = data.newConstant(dt->getSize(), val);
    inVarnodes.push_back(outVn);
    outVn->updateType(dt, false, false);
  }
}

/// \brief Build input Varnodes by extracting SUBPIECEs from the root
///
/// Extract different pieces from the given root based on the offsets and
/// input data-types in \b dataTypePieces.
/// \param rootVn is the given root Varnode
/// \param followOp is the point at which the SUBPIECEs should be inserted (before)
/// \param inVarnodes is the container for the new Varnodes
void SplitDatatype::buildInSubpieces(Varnode *rootVn,PcodeOp *followOp,vector<Varnode *> &inVarnodes)

{
  if (generateConstants(rootVn, inVarnodes))
    return;
  Address baseAddr = rootVn->getAddr();
  for(int4 i=0;i<dataTypePieces.size();++i) {
    Datatype *dt = dataTypePieces[i].inType;
    int4 off = dataTypePieces[i].offset;
    Address addr = baseAddr + off;
    addr.renormalize(dt->getSize());
    if (addr.isBigEndian())
      off = rootVn->getSize() - off - dt->getSize();
    PcodeOp *subpiece = data.newOp(2, followOp->getAddr());
    data.opSetOpcode(subpiece, CPUI_SUBPIECE);
    data.opSetInput(subpiece,rootVn,0);
    data.opSetInput(subpiece,data.newConstant(4, off), 1);
    Varnode *outVn = data.newVarnodeOut(dt->getSize(), addr, subpiece);
    inVarnodes.push_back(outVn);
    outVn->updateType(dt, false, false);
    data.opInsertBefore(subpiece, followOp);
  }
}

/// \brief Build output Varnodes with storage based on the given root
///
/// Extract different pieces from the given root based on the offsets and
/// output data-types in \b dataTypePieces.
/// \param rootVn is the given root Varnode
/// \param outVarnodes is the container for the new Varnodes
void SplitDatatype::buildOutVarnodes(Varnode *rootVn,vector<Varnode *> &outVarnodes)

{
  Address baseAddr = rootVn->getAddr();
  for(int4 i=0;i<dataTypePieces.size();++i) {
    Datatype *dt = dataTypePieces[i].outType;
    int4 off = dataTypePieces[i].offset;
    Address addr = baseAddr + off;
    addr.renormalize(dt->getSize());
    Varnode *outVn = data.newVarnode(dt->getSize(), addr, dt);
    outVarnodes.push_back(outVn);
  }
}

/// \brief Concatenate output Varnodes into given root Varnode
///
/// Insert PIECE operators concatenating all output Varnodes from most significant to least significant
/// producing the root Varnode as the final result.
/// \param rootVn is the given root Varnode
/// \param previousOp is the point at which to insert (after)
/// \param outVarnodes is the list of output Varnodes
void SplitDatatype::buildOutConcats(Varnode *rootVn,PcodeOp *previousOp,vector<Varnode *> &outVarnodes)

{
  if (rootVn->hasNoDescend())
    return;				// Don't need to produce concatenation if its unused
  Address baseAddr = rootVn->getAddr();
  Varnode *vn;
  PcodeOp *concatOp;
  PcodeOp *preOp = previousOp;
  bool addressTied = rootVn->isAddrTied();
  // We are creating a CONCAT stack, mark varnodes appropriately
  for(int4 i=0;i<outVarnodes.size();++i) {
    if (!addressTied)
      outVarnodes[i]->setProtoPartial();
  }
  if (baseAddr.isBigEndian()) {
    vn = outVarnodes[0];
    for(int4 i=1;;++i) {				// Traverse most to least significant
      concatOp = data.newOp(2,previousOp->getAddr());
      data.opSetOpcode(concatOp,CPUI_PIECE);
      data.opSetInput(concatOp,vn,0);			// Most significant
      data.opSetInput(concatOp,outVarnodes[i],1);	// Least significant
      data.opInsertAfter(concatOp, preOp);
      if (i + 1 >= outVarnodes.size()) break;
      preOp = concatOp;
      int4 sz = vn->getSize() + outVarnodes[i]->getSize();
      Address addr = baseAddr;
      addr.renormalize(sz);
      vn = data.newVarnodeOut(sz,addr,concatOp);
      if (!addressTied)
	vn->setProtoPartial();
    }
  }
  else {
    vn = outVarnodes[outVarnodes.size()-1];
    for(int4 i=outVarnodes.size()-2;;--i) {		// Traverse most to least significant
      concatOp = data.newOp(2,previousOp->getAddr());
      data.opSetOpcode(concatOp,CPUI_PIECE);
      data.opSetInput(concatOp,vn,0);			// Most significant
      data.opSetInput(concatOp,outVarnodes[i],1);	// Least significant
      data.opInsertAfter(concatOp, preOp);
      if (i<=0) break;
      preOp = concatOp;
      int4 sz = vn->getSize() + outVarnodes[i]->getSize();
      Address addr = outVarnodes[i]->getAddr();
      addr.renormalize(sz);
      vn = data.newVarnodeOut(sz,addr,concatOp);
      if (!addressTied)
	vn->setProtoPartial();
    }
  }
  concatOp->setPartialRoot();
  data.opSetOutput(concatOp, rootVn);
  if (!addressTied)
    data.getMerge().registerProtoPartialRoot(rootVn);
}

/// \brief Build a a series of PTRSUB ops at different offsets, given a root pointer
///
/// Offsets and data-types are based on \b dataTypePieces, taking input data-types if \b isInput is \b true,
/// output data-types otherwise.  The data-types, relative to the root pointer, are assumed to start at
/// the given base offset.
/// \param rootVn is the root pointer
/// \param ptrType is the pointer data-type associated with the root
/// \param baseOffset is the given base offset
/// \param followOp is the point at which the new PTRSUB ops are inserted (before)
/// \param ptrVarnodes is the container for the new pointer Varnodes
/// \param isInput specifies either input (\b true) or output (\b false) data-types
void SplitDatatype::buildPointers(Varnode *rootVn,TypePointer *ptrType,int4 baseOffset,PcodeOp *followOp,
				  vector<Varnode *> &ptrVarnodes,bool isInput)
{
  Datatype *baseType = ptrType->getPtrTo();
  for(int4 i=0;i<dataTypePieces.size();++i) {
    Datatype *matchType = isInput ? dataTypePieces[i].inType : dataTypePieces[i].outType;
    int8 curOff = baseOffset + dataTypePieces[i].offset;
    Datatype *tmpType = baseType;
    Varnode *inPtr = rootVn;
    do {
      int8 newOff;
      PcodeOp *newOp;
      Datatype *newType;
      if (curOff < 0 || curOff >= tmpType->getSize()) {	// An offset not within the data-type indicates an array
	newType = tmpType;			// The new data-type will be the same as current data-type
	newOff = curOff % tmpType->getSize();	// But new offset will be old offset modulo data-type size
	newOff = (newOff < 0) ? (newOff + tmpType->getSize()) : newOff;
      }
      else {
	newType = tmpType->getSubType(curOff, &newOff);
	if (newType == (Datatype *)0) {
	  // Null should only be returned for a hole in a structure, in which case use precomputed data-type
	  newType = matchType;
	  newOff = 0;
	}
      }
      if (tmpType == newType || tmpType->getMetatype() == TYPE_ARRAY) {
	int8 finalOffset = curOff - newOff;
	int4 sz = newType->getSize();		// Element size in bytes
	finalOffset = finalOffset / sz;		// Number of elements
	sz = AddrSpace::byteToAddressInt(sz, ptrType->getWordSize());
	newOp = data.newOp(3,followOp->getAddr());
	data.opSetOpcode(newOp, CPUI_PTRADD);
	data.opSetInput(newOp, inPtr, 0);
	Varnode *indexVn = data.newConstant(inPtr->getSize(), finalOffset);
	data.opSetInput(newOp, indexVn, 1);
	data.opSetInput(newOp, data.newConstant(inPtr->getSize(), sz), 2);
	Datatype *indexType = types->getBase(indexVn->getSize(),TYPE_INT);
	indexVn->updateType(indexType, false, false);
      }
      else {
	int8 finalOffset = AddrSpace::byteToAddressInt(curOff - newOff,ptrType->getWordSize());
	newOp = data.newOp(2,followOp->getAddr());
	data.opSetOpcode(newOp, CPUI_PTRSUB);
	data.opSetInput(newOp, inPtr, 0);
	data.opSetInput(newOp, data.newConstant(inPtr->getSize(), finalOffset), 1);
      }
      inPtr = data.newUniqueOut(inPtr->getSize(), newOp);
      Datatype *tmpPtr = types->getTypePointerStripArray(ptrType->getSize(), newType, ptrType->getWordSize());
      inPtr->updateType(tmpPtr, false, false);
      data.opInsertBefore(newOp, followOp);
      tmpType = newType;
      curOff = newOff;
    } while(tmpType->getSize() > matchType->getSize());
    ptrVarnodes.push_back(inPtr);
  }
}

/// Iterate through descendants of the given Varnode, looking for arithmetic ops.
/// \param vn is the given Varnode
/// \return \b true if the Varnode has an arithmetic op as a descendant
bool SplitDatatype::isArithmeticInput(Varnode *vn)

{
   list<PcodeOp *>::const_iterator iter = vn->beginDescend();
   while(iter != vn->endDescend()) {
     PcodeOp *op = *iter;
     if (op->getOpcode()->isArithmeticOp())
       return true;
     ++iter;
   }
   return false;
}

/// Check if the defining PcodeOp is arithmetic.
/// \param vn is the given Varnode
/// \return \b true if the defining op is arithemetic
bool SplitDatatype::isArithmeticOutput(Varnode *vn)

{
  if (!vn->isWritten())
      return false;
  return vn->getDef()->getOpcode()->isArithmeticOp();
}

SplitDatatype::SplitDatatype(Funcdata &func)
  : data(func)
{
  Architecture *glb = func.getArch();
  types = glb->types;
  splitStructures = (glb->split_datatype_config & OptionSplitDatatypes::option_struct) != 0;
  splitArrays = (glb->split_datatype_config & OptionSplitDatatypes::option_array) != 0;
  isLoadStore = false;
}

/// Based on the input and output data-types, determine if and how the given COPY operation
/// should be split into pieces. Then if possible, perform the split.
/// \param copyOp is the given COPY
/// \param inType is the data-type of the COPY input
/// \param outType is the data-type of the COPY output
/// \return \b true if the split was performed
bool SplitDatatype::splitCopy(PcodeOp *copyOp,Datatype *inType,Datatype *outType)

{
  if (!testCopyConstraints(copyOp))
    return false;
  Varnode *inVn = copyOp->getIn(0);
  if (!testDatatypeCompatibility(inType, outType, inVn->isConstant()))
    return false;
  if (isArithmeticOutput(inVn))		// Sanity check on input
    return false;
  Varnode *outVn = copyOp->getOut();
  if (isArithmeticInput(outVn))	// Sanity check on output
    return false;
  vector<Varnode *> inVarnodes;
  vector<Varnode *> outVarnodes;
  if (inVn->isConstant())
    buildInConstants(inVn,inVarnodes,outVn->getSpace()->isBigEndian());
  else
    buildInSubpieces(inVn,copyOp,inVarnodes);
  buildOutVarnodes(outVn,outVarnodes);
  buildOutConcats(outVn,copyOp,outVarnodes);
  for(int4 i=0;i<inVarnodes.size();++i) {
    PcodeOp *newCopyOp = data.newOp(1,copyOp->getAddr());
    data.opSetOpcode(newCopyOp,CPUI_COPY);
    data.opSetInput(newCopyOp,inVarnodes[i],0);
    data.opSetOutput(newCopyOp,outVarnodes[i]);
    data.opInsertBefore(newCopyOp, copyOp);
  }
  data.opDestroy(copyOp);
  return true;
}

/// Based on the LOAD data-type, determine if the given LOAD can be split into smaller LOADs.
/// Then, if possible, perform the split.  The input data-type describes the size and composition of
/// the value being loaded. Check for the special case where, the LOAD output is a lone input to a COPY,
/// and split the outputs of the COPY as well.
/// \param loadOp is the given LOAD to split
/// \param inType is the data-type associated with the value being loaded
/// \return \b true if the split was performed
bool SplitDatatype::splitLoad(PcodeOp *loadOp,Datatype *inType)

{
  isLoadStore = true;
  Varnode *outVn = loadOp->getOut();
  PcodeOp *copyOp = (PcodeOp *)0;
  if (!outVn->isAddrTied())
    copyOp = outVn->loneDescend();
  if (copyOp != (PcodeOp *)0) {
    OpCode opc = copyOp->code();
    if (opc == CPUI_STORE) return false;	// Handled by RuleSplitStore
    if (opc != CPUI_COPY)
      copyOp = (PcodeOp *)0;
  }
  if (copyOp != (PcodeOp *)0)
    outVn = copyOp->getOut();
  Datatype *outType = outVn->getTypeDefFacing();
  if (!testDatatypeCompatibility(inType, outType, false))
    return false;
  if (isArithmeticInput(outVn))			// Sanity check on output
    return false;
  RootPointer root;
  if (!root.find(loadOp,inType))
    return false;
  vector<Varnode *> ptrVarnodes;
  vector<Varnode *> outVarnodes;
  PcodeOp *insertPoint = (copyOp == (PcodeOp *)0) ? loadOp:copyOp;
  buildPointers(root.pointer, root.ptrType, root.baseOffset, loadOp, ptrVarnodes, true);
  buildOutVarnodes(outVn, outVarnodes);
  buildOutConcats(outVn, insertPoint, outVarnodes);
  AddrSpace *spc = loadOp->getIn(0)->getSpaceFromConst();
  for(int4 i=0;i<ptrVarnodes.size();++i) {
    PcodeOp *newLoadOp = data.newOp(2,insertPoint->getAddr());
    data.opSetOpcode(newLoadOp,CPUI_LOAD);
    data.opSetInput(newLoadOp,data.newVarnodeSpace(spc),0);
    data.opSetInput(newLoadOp,ptrVarnodes[i],1);
    data.opSetOutput(newLoadOp,outVarnodes[i]);
    data.opInsertBefore(newLoadOp, insertPoint);
  }
  if (copyOp != (PcodeOp *)0)
    data.opDestroy(copyOp);
  data.opDestroy(loadOp);
  root.freePointerChain(data);
  return true;
}

/// Based on the STORE data-type, determine if the given STORE can be split into smaller STOREs.
/// Then, if possible, perform the split.  The output data-type describes the size and composition of
/// the value being stored.
/// \param storeOp is the given STORE to split
/// \param outType is the data-type associated with the value being stored
/// \return \b true if the split was performed
bool SplitDatatype::splitStore(PcodeOp *storeOp,Datatype *outType)

{
  isLoadStore = true;
  Varnode *inVn = storeOp->getIn(2);
  PcodeOp *loadOp = (PcodeOp *)0;
  Datatype *inType = (Datatype *)0;
  if (inVn->isWritten() && inVn->getDef()->code() == CPUI_LOAD && inVn->loneDescend() == storeOp) {
    loadOp = inVn->getDef();
    inType = getValueDatatype(loadOp, inVn->getSize(), data.getArch()->types);
    if (inType == (Datatype *)0)
      loadOp = (PcodeOp *)0;
  }
  if (inType == (Datatype *)0) {
    inType = inVn->getTypeReadFacing(storeOp);
  }
  if (!testDatatypeCompatibility(inType, outType, inVn->isConstant())) {
    if (loadOp != (PcodeOp *)0) {
      // If not compatible while considering the LOAD, check again, but without the LOAD
      loadOp = (PcodeOp *)0;
      inType = inVn->getTypeReadFacing(storeOp);
      dataTypePieces.clear();
      if (!testDatatypeCompatibility(inType, outType, inVn->isConstant()))
	return false;
    }
    else
      return false;
  }

  if (isArithmeticOutput(inVn))		// Sanity check
    return false;

  RootPointer storeRoot;
  if (!storeRoot.find(storeOp,outType))
    return false;

  RootPointer loadRoot;
  if (loadOp != (PcodeOp *)0) {
    if (!loadRoot.find(loadOp,inType))
      return false;
  }

  AddrSpace *storeSpace = storeOp->getIn(0)->getSpaceFromConst();
  vector<Varnode *> inVarnodes;
  if (inVn->isConstant())
    buildInConstants(inVn,inVarnodes,storeSpace->isBigEndian());
  else if (loadOp != (PcodeOp *)0) {
    vector<Varnode *> loadPtrs;
    buildPointers(loadRoot.pointer, loadRoot.ptrType, loadRoot.baseOffset, loadOp, loadPtrs, true);
    AddrSpace *loadSpace = loadOp->getIn(0)->getSpaceFromConst();
    for(int4 i=0;i<loadPtrs.size();++i) {
      PcodeOp *newLoadOp = data.newOp(2,loadOp->getAddr());
      data.opSetOpcode(newLoadOp,CPUI_LOAD);
      data.opSetInput(newLoadOp,data.newVarnodeSpace(loadSpace),0);
      data.opSetInput(newLoadOp,loadPtrs[i],1);
      Datatype *dt = dataTypePieces[i].inType;
      Varnode *vn = data.newUniqueOut(dt->getSize(), newLoadOp);
      vn->updateType(dt, false, false);
      inVarnodes.push_back(vn);
      data.opInsertBefore(newLoadOp, loadOp);
    }
  }
  else
    buildInSubpieces(inVn,storeOp,inVarnodes);

  vector<Varnode *> storePtrs;
  if (storeRoot.pointer->isAddrTied())
    storeRoot.duplicateToTemp(data, storeOp);
  buildPointers(storeRoot.pointer, storeRoot.ptrType, storeRoot.baseOffset, storeOp, storePtrs, false);
  // Preserve original STORE object, so that INDIRECT references are still valid
  // but convert it into the first of the smaller STOREs
  data.opSetInput(storeOp,storePtrs[0],1);
  data.opSetInput(storeOp,inVarnodes[0],2);
  PcodeOp *lastStore = storeOp;
  for(int4 i=1;i<storePtrs.size();++i) {
    PcodeOp *newStoreOp = data.newOp(3,storeOp->getAddr());
    data.opSetOpcode(newStoreOp,CPUI_STORE);
    data.opSetInput(newStoreOp,data.newVarnodeSpace(storeSpace),0);
    data.opSetInput(newStoreOp,storePtrs[i],1);
    data.opSetInput(newStoreOp,inVarnodes[i],2);
    data.opInsertAfter(newStoreOp, lastStore);
    lastStore = newStoreOp;
  }

  if (loadOp != (PcodeOp *)0) {
    data.opDestroy(loadOp);
    loadRoot.freePointerChain(data);
  }
  storeRoot.freePointerChain(data);
  return true;
}

/// \brief Get a data-type description of the value being pointed at by the given LOAD or STORE
///
/// Take the data-type of the pointer and construct the data-type of the thing being pointed at
/// so that it matches a specific size.  This takes into account TypePointerRel and can produce
/// TypePartialStruct in order to match the size.  If no interpretation of the value as a
/// splittable data-type is possible, null is returned.
/// \param loadStore is the given LOAD or STORE
/// \param size is the number of bytes in the value being pointed at
/// \param tlst is the TypeFactory for constructing partial data-types if necessary
/// \return the data-type description of the value or null
Datatype *SplitDatatype::getValueDatatype(PcodeOp *loadStore,int4 size,TypeFactory *tlst)

{
  Datatype *resType;
  Datatype *ptrType = loadStore->getIn(1)->getTypeReadFacing(loadStore);
  if (ptrType->getMetatype() != TYPE_PTR)
    return (Datatype *)0;
  int4 baseOffset;
  if (ptrType->isPointerRel()) {
    TypePointerRel *ptrRel = (TypePointerRel *)ptrType;
    resType = ptrRel->getParent();
    baseOffset = ptrRel->getByteOffset();
  }
  else {
    resType = ((TypePointer *)ptrType)->getPtrTo();
    baseOffset = 0;
  }
  type_metatype metain = resType->getMetatype();
  if (resType->getAlignSize() < size) {
    if (metain == TYPE_INT || metain == TYPE_UINT || metain == TYPE_BOOL || metain == TYPE_FLOAT || metain == TYPE_PTR) {
      if ((size % resType->getAlignSize()) == 0) {
	int4 numEl = size / resType->getAlignSize();
	return tlst->getTypeArray(numEl, resType);
      }
    }
  }
  else if (metain == TYPE_STRUCT || metain == TYPE_ARRAY)
    return tlst->getExactPiece(resType, baseOffset, size);
  return (Datatype *)0;
}

void RuleSplitCopy::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_COPY);
}

int4 RuleSplitCopy::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *inType = op->getIn(0)->getTypeReadFacing(op);
  Datatype *outType = op->getOut()->getTypeDefFacing();
  type_metatype metain = inType->getMetatype();
  type_metatype metaout = outType->getMetatype();
  if (metain != TYPE_PARTIALSTRUCT && metaout != TYPE_PARTIALSTRUCT &&
      metain != TYPE_ARRAY && metaout != TYPE_ARRAY &&
      metain != TYPE_STRUCT && metaout != TYPE_STRUCT)
    return false;
  SplitDatatype splitter(data);
  if (splitter.splitCopy(op, inType, outType))
    return 1;
  return 0;
}

void RuleSplitLoad::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_LOAD);
}

int4 RuleSplitLoad::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *inType = SplitDatatype::getValueDatatype(op, op->getOut()->getSize(), data.getArch()->types);
  if (inType == (Datatype *)0)
    return 0;
  type_metatype metain = inType->getMetatype();
  if (metain != TYPE_STRUCT && metain != TYPE_ARRAY && metain != TYPE_PARTIALSTRUCT)
    return 0;
  SplitDatatype splitter(data);
  if (splitter.splitLoad(op, inType))
    return 1;
  return 0;
}

void RuleSplitStore::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_STORE);
}

int4 RuleSplitStore::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *outType = SplitDatatype::getValueDatatype(op, op->getIn(2)->getSize(), data.getArch()->types);
  if (outType == (Datatype *)0)
    return 0;
  type_metatype metain = outType->getMetatype();
  if (metain != TYPE_STRUCT && metain != TYPE_ARRAY && metain != TYPE_PARTIALSTRUCT)
    return 0;
  SplitDatatype splitter(data);
  if (splitter.splitStore(op, outType))
    return 1;
  return 0;
}

/// This method distinguishes between a floating-point variable with \e full precision, where all the
/// storage can vary (or is unknown), versus a value that is extended from a floating-point variable with
/// smaller storage.  Within the data-flow above the given Varnode, we search for the maximum
/// precision coming through MULTIEQUAL, COPY, and unary floating-point operations. Binary operations
/// like FLOAT_ADD and FLOAT_MULT are not traversed and are assumed to produce a smaller precision.
/// If the method indicates \e full precision for the given Varnode, or if the data-flow does not involve
/// binary floating-point operations, it is accurate, otherwise it may under report the precision.
/// \param vn is the given Varnode
/// \return an approximation of the maximum precision
int4 SubfloatFlow::maxPrecision(Varnode *vn)

{
  if (!vn->isWritten())
    return vn->getSize();
  PcodeOp *op = vn->getDef();
  switch(op->code()) {
    case CPUI_MULTIEQUAL:
    case CPUI_FLOAT_NEG:
    case CPUI_FLOAT_ABS:
    case CPUI_FLOAT_SQRT:
    case CPUI_FLOAT_CEIL:
    case CPUI_FLOAT_FLOOR:
    case CPUI_FLOAT_ROUND:
    case CPUI_COPY:
      break;
    case CPUI_FLOAT_ADD:
    case CPUI_FLOAT_SUB:
    case CPUI_FLOAT_MULT:
    case CPUI_FLOAT_DIV:
      return 0;			// Delay checking other binary ops
    case CPUI_FLOAT_FLOAT2FLOAT:
    case CPUI_FLOAT_INT2FLOAT:	// Treat integer as having precision matching its size
      if (op->getIn(0)->getSize() > vn->getSize())
	return vn->getSize();
      return op->getIn(0)->getSize();
    default:
      return vn->getSize();
  }

  map<PcodeOp *,int4>::const_iterator iter = maxPrecisionMap.find(op);
  if (iter != maxPrecisionMap.end()) {
    return (*iter).second;
  }
  vector<State> opStack;
  opStack.emplace_back(op);
  op->setMark();
  int4 max = 0;
  while(!opStack.empty()) {
    State &state(opStack.back());
    if (state.slot >= state.op->numInput()) {
      max = state.maxPrecision;
      state.op->clearMark();
      maxPrecisionMap[state.op] = state.maxPrecision;
      opStack.pop_back();
      if (!opStack.empty()) {
	opStack.back().incorporateInputSize(max);
      }
      continue;
    }
    Varnode *nextVn = state.op->getIn(state.slot);
    state.slot += 1;
    if (!nextVn->isWritten()) {
      state.incorporateInputSize(nextVn->getSize());
      continue;
    }
    PcodeOp *nextOp = nextVn->getDef();
    if (nextOp->isMark()) {
      continue;			// Truncate the cycle edge
    }
    switch(nextOp->code()) {
      case CPUI_MULTIEQUAL:
      case CPUI_FLOAT_NEG:
      case CPUI_FLOAT_ABS:
      case CPUI_FLOAT_SQRT:
      case CPUI_FLOAT_CEIL:
      case CPUI_FLOAT_FLOOR:
      case CPUI_FLOAT_ROUND:
      case CPUI_COPY:
	iter = maxPrecisionMap.find(nextOp);
	if (iter != maxPrecisionMap.end()) {
	  // Seen the op before, incorporate its cached precision information
	  state.incorporateInputSize((*iter).second);
	  break;
	}
	nextOp->setMark();
	opStack.emplace_back(nextOp);	// Recursively push into the new op
	break;
      case CPUI_FLOAT_ADD:
      case CPUI_FLOAT_SUB:
      case CPUI_FLOAT_MULT:
      case CPUI_FLOAT_DIV:
	break;
      case CPUI_FLOAT_FLOAT2FLOAT:
      case CPUI_FLOAT_INT2FLOAT:		// Treat integer as having precision matching its size
	if (nextOp->getIn(0)->getSize() > nextVn->getSize())
	  state.incorporateInputSize(nextVn->getSize());
	else
	  state.incorporateInputSize(nextOp->getIn(0)->getSize());
	break;
      default:
	state.incorporateInputSize(nextVn->getSize());
	break;
    }
  }
  return max;
}

/// This is called only for binary floating-point ops: FLOAT_ADD, FLOAT_MULT, FLOAT_LESS, etc.
/// If the maximum precision reaching both input operands exceeds the \b precision established
/// for \b this Rule, \b true is returned, indicating the op cannot be truncated without losing precision.
/// We count on the fact that this test is applied to all binary operations encountered during Rule application.
/// This method will correctly return \b true for the earliest operations whose inputs both exceed the
/// \b precision, but, because of the way maxPrecision() is calculated, it may incorrectly return \b false
/// for later operations.
/// \param op is the given binary floating-point PcodeOp
/// \return \b true if both input operands exceed the established \b precision
bool SubfloatFlow::exceedsPrecision(PcodeOp *op)

{
  int4 val1 = maxPrecision(op->getIn(0));
  int4 val2 = maxPrecision(op->getIn(1));
  int4 min = (val1 < val2) ? val1 : val2;
  return (min > precision);
}

/// \brief Create and return a placeholder associated with the given Varnode
///
/// Add the placeholder to the worklist if it hasn't been visited before
/// \param vn is the given Varnode
/// \return the placeholder or null if the Varnode is not suitable for replacement
TransformVar *SubfloatFlow::setReplacement(Varnode *vn)

{
  if (vn->isMark())		// Already seen before
    return getPiece(vn, precision*8, 0);

  if (vn->isConstant()) {
    const FloatFormat *form2 = getFunction()->getArch()->translate->getFloatFormat(vn->getSize());
    if (form2 == (const FloatFormat *)0)
      return (TransformVar *)0;	// Unsupported constant format
    // Return the converted form of the constant
    return newConstant(precision, 0, format->convertEncoding(vn->getOffset(),form2));
  }

  if (vn->isFree())
    return (TransformVar *)0; // Abort

  if (vn->isAddrForce() && (vn->getSize() != precision))
    return (TransformVar *)0;

  if (vn->isTypeLock() && vn->getType()->getMetatype() != TYPE_PARTIALSTRUCT) {
    int4 sz = vn->getType()->getSize();
    if (sz != precision)
      return (TransformVar *)0;
  }

  if (vn->isInput()) {		// Must be careful with inputs
    if (vn->getSize() != precision) return (TransformVar *)0;
  }

  vn->setMark();
  TransformVar *res;
  // Check if vn already represents the logical variable being traced
  if (vn->getSize() == precision)
    res = newPreexistingVarnode(vn);
  else {
    res = newPiece(vn, precision*8, 0);
    worklist.push_back(res);
  }
  return res;
}

/// \brief Try to trace logical variable through descendant Varnodes
///
/// Given a Varnode placeholder, look at all descendant PcodeOps and create
/// placeholders for the op and its output Varnode.  If appropriate add the
/// output placeholder to the worklist.
/// \param rvn is the given Varnode placeholder
/// \return \b true if tracing the logical variable forward was possible
bool SubfloatFlow::traceForward(TransformVar *rvn)

{
  list<PcodeOp *>::const_iterator iter,enditer;
  Varnode *vn = rvn->getOriginal();
  iter = vn->beginDescend();
  enditer = vn->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter++;
    Varnode *outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&(outvn->isMark()))
      continue;
    switch(op->code()) {
    case CPUI_FLOAT_ADD:
    case CPUI_FLOAT_SUB:
    case CPUI_FLOAT_MULT:
    case CPUI_FLOAT_DIV:
      if (exceedsPrecision(op))
  	return false;
      // fall through
    case CPUI_MULTIEQUAL:
    case CPUI_COPY:
    case CPUI_FLOAT_CEIL:
    case CPUI_FLOAT_FLOOR:
    case CPUI_FLOAT_ROUND:
    case CPUI_FLOAT_NEG:
    case CPUI_FLOAT_ABS:
    case CPUI_FLOAT_SQRT:
    {
      TransformOp *rop = newOpReplace(op->numInput(), op->code(), op);
      TransformVar *outrvn = setReplacement(outvn);
      if (outrvn == (TransformVar *)0) return false;
      opSetInput(rop,rvn,op->getSlot(vn));
      opSetOutput(rop,outrvn);
      break;
    }
    case CPUI_FLOAT_FLOAT2FLOAT:
    {
      if (outvn->getSize() < precision)
	return false;
      TransformOp *rop = newPreexistingOp(1, (outvn->getSize() == precision) ? CPUI_COPY : CPUI_FLOAT_FLOAT2FLOAT, op);
      opSetInput(rop,rvn,0);
      terminatorCount += 1;
      break;
    }
    case CPUI_FLOAT_EQUAL:
    case CPUI_FLOAT_NOTEQUAL:
    case CPUI_FLOAT_LESS:
    case CPUI_FLOAT_LESSEQUAL:
    {
      if (exceedsPrecision(op))
	return false;
      int4 slot = op->getSlot(vn);
      TransformVar *rvn2 = setReplacement(op->getIn(1-slot));
      if (rvn2 == (TransformVar *)0) return false;
      if (rvn == rvn2) {
	list<PcodeOp *>::const_iterator ourIter = iter;
	--ourIter;	// Back up one to our original iterator
	slot = op->getRepeatSlot(vn, slot, ourIter);
      }
      if (preexistingGuard(slot, rvn2)) {
	TransformOp *rop = newPreexistingOp(2, op->code(), op);
	opSetInput(rop, rvn, slot);
	opSetInput(rop, rvn2, 1 - slot);
	terminatorCount += 1;
      }
      break;
    }
    case CPUI_FLOAT_TRUNC:
    case CPUI_FLOAT_NAN:
    {
      TransformOp *rop = newPreexistingOp(1,op->code(), op);
      opSetInput(rop,rvn,0);
      terminatorCount += 1;
      break;
    }
    default:
      return false;
    }
  }
  return true;
}

/// \brief Trace a logical value backward through defining op one level
///
/// Given an existing variable placeholder look at the op defining it and
/// define placeholder variables for all its inputs.  Put the new placeholders
/// onto the worklist if appropriate.
/// \param rvn is the given variable placeholder
/// \return \b true if the logical value can be traced properly
bool SubfloatFlow::traceBackward(TransformVar *rvn)

{
  PcodeOp *op = rvn->getOriginal()->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input

  switch(op->code()) {
  case CPUI_FLOAT_ADD:
  case CPUI_FLOAT_SUB:
  case CPUI_FLOAT_MULT:
  case CPUI_FLOAT_DIV:
    if (exceedsPrecision(op))
      return false;
    // fallthru
  case CPUI_COPY:
  case CPUI_FLOAT_CEIL:
  case CPUI_FLOAT_FLOOR:
  case CPUI_FLOAT_ROUND:
  case CPUI_FLOAT_NEG:
  case CPUI_FLOAT_ABS:
  case CPUI_FLOAT_SQRT:
  case CPUI_MULTIEQUAL:
  {
    TransformOp *rop = rvn->getDef();
    if (rop == (TransformOp *)0) {
      rop = newOpReplace(op->numInput(), op->code(), op);
      opSetOutput(rop, rvn);
    }
    for(int4 i=0;i<op->numInput();++i) {
      TransformVar *newvar = rop->getIn(i);
      if (newvar == (TransformVar *)0) {
	newvar = setReplacement(op->getIn(i));
	if (newvar == (TransformVar *)0)
	  return false;
	opSetInput(rop,newvar,i);
      }
    }
    return true;
  }
  case CPUI_FLOAT_INT2FLOAT:
  {
    Varnode *vn = op->getIn(0);
    if (!vn->isConstant() && vn->isFree())
      return false;
    TransformOp *rop = newOpReplace(1, CPUI_FLOAT_INT2FLOAT, op);
    opSetOutput(rop, rvn);
    TransformVar *newvar = getPreexistingVarnode(vn);
    opSetInput(rop,newvar,0);
    return true;
  }
  case CPUI_FLOAT_FLOAT2FLOAT:
  {
    Varnode *vn = op->getIn(0);
    TransformVar *newvar;
    OpCode opc;
    if (vn->isConstant()) {
      opc = CPUI_COPY;
      if (vn->getSize() == precision)
	newvar = newConstant(precision, 0, vn->getOffset());
      else {
	newvar = setReplacement(vn);	// Convert constant to precision size
	if (newvar == (TransformVar *)0)
	  return false;			// Unsupported float format
      }
    }
    else {
      if (vn->isFree()) return false;
      opc = (vn->getSize() == precision) ? CPUI_COPY : CPUI_FLOAT_FLOAT2FLOAT;
      newvar = getPreexistingVarnode(vn);
    }
    TransformOp *rop = newOpReplace(1, opc, op);
    opSetOutput(rop, rvn);
    opSetInput(rop,newvar,0);
    return true;
  }
  default:
    break;			// Everything else we abort
  }

  return false;
}

/// \brief Push the trace one hop from the placeholder at the top of the worklist
///
/// The logical value for the value on top of the worklist stack is pushed back
/// to the input Varnodes of the operation defining it.  Then the value is pushed
/// forward through all operations that read it.
/// \return \b true if the trace is successfully pushed
bool SubfloatFlow::processNextWork(void)

{
  TransformVar *rvn = worklist.back();

  worklist.pop_back();

  if (!traceBackward(rvn)) return false;
  return traceForward(rvn);
}

/// \param f is the function being transformed
/// \param root is the start Varnode containing the logical value
/// \param prec is the precision to assume for the logical value
SubfloatFlow::SubfloatFlow(Funcdata *f,Varnode *root,int4 prec)
  : TransformManager(f)
{
  precision = prec;
  format = f->getArch()->translate->getFloatFormat(precision);
  if (format == (const FloatFormat *)0)
    return;
  setReplacement(root);
}

bool SubfloatFlow::preserveAddress(Varnode *vn,int4 bitSize,int4 lsbOffset) const

{
  return vn->isInput();		// Only try to preserve address for input varnodes
}

/// The interpretation that the root Varnode contains a logical value with
/// smaller precision is pushed through the data-flow.  If the interpretation is
/// inconsistent, \b false is returned.  Otherwise a transform is constructed that
/// makes the smaller precision the explicit size of Varnodes within the data-flow.
/// \return \b true if a transform consistent with the given precision can be built
bool SubfloatFlow::doTrace(void)

{
  if (format == (const FloatFormat *)0)
    return false;
  terminatorCount = 0;	// Have seen no terminators
  bool retval = true;
  while(!worklist.empty()) {
    if (!processNextWork()) {
      retval = false;
      break;
    }
  }

  clearVarnodeMarks();

  if (!retval) return false;
  if (terminatorCount == 0) return false;	// Must see at least 1 terminator
  return true;
}

void RuleSubfloatConvert::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_FLOAT_FLOAT2FLOAT);
}

int4 RuleSubfloatConvert::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *invn = op->getIn(0);
  Varnode *outvn = op->getOut();
  int4 insize = invn->getSize();
  int4 outsize = outvn->getSize();
  if (outsize > insize) {
    SubfloatFlow subflow(&data,outvn,insize);
    if (!subflow.doTrace()) return 0;
    subflow.apply();
  }
  else {
    SubfloatFlow subflow(&data,invn,outsize);
    if (!subflow.doTrace()) return 0;
    subflow.apply();
  }
  return 1;
}

/// \brief Find or build the placeholder objects for a Varnode that needs to be split into lanes
///
/// The Varnode is split based on the given subset of the lane description.
/// Constants can be split. Decide if the Varnode needs to go into the work list.
/// If the Varnode cannot be acceptably split, return null.
/// \param vn is the Varnode that needs to be split
/// \param numLanes is the number of lanes in the subset
/// \param skipLanes is the start (least significant) lane in the subset
/// \return the array of placeholders describing the split or null
TransformVar *LaneDivide::setReplacement(Varnode *vn,int4 numLanes,int4 skipLanes)

{
  if (vn->isMark())		// Already seen before
    return getSplit(vn, description, numLanes, skipLanes);

  if (vn->isConstant()) {
    return newSplit(vn,description, numLanes, skipLanes);
  }

  // Allow free varnodes to be split
//  if (vn->isFree())
//    return (TransformVar *)0;

  if (vn->isTypeLock()) {
    type_metatype meta = vn->getType()->getMetatype();
    if (meta > TYPE_ARRAY)
      return (TransformVar *)0;		// Don't split a primitive type
    if (meta == TYPE_STRUCT || meta == TYPE_UNION)
      return (TransformVar *)0;
  }

  vn->setMark();
  TransformVar *res = newSplit(vn, description, numLanes, skipLanes);
  if (!vn->isFree()) {
    workList.emplace_back();
    workList.back().lanes = res;
    workList.back().numLanes = numLanes;
    workList.back().skipLanes = skipLanes;
  }
  return res;
}

/// \brief Build unary op placeholders with the same opcode across a set of lanes
///
/// We assume the input and output placeholder variables have already been collected
/// \param opc is the desired opcode for the new op placeholders
/// \param op is the PcodeOp getting replaced
/// \param inVars is the array of input variables, 1 for each unary op
/// \param outVars is the array of output variables, 1 for each unary op
/// \param numLanes is the number of unary ops to create
void LaneDivide::buildUnaryOp(OpCode opc,PcodeOp *op,TransformVar *inVars,TransformVar *outVars,int4 numLanes)

{
  for(int4 i=0;i<numLanes;++i) {
    TransformOp *rop = newOpReplace(1, opc, op);
    opSetOutput(rop, outVars + i);
    opSetInput(rop,inVars + i,0);
  }
}

/// \brief Build binary op placeholders with the same opcode across a set of lanes
///
/// We assume the input and output placeholder variables have already been collected
/// \param opc is the desired opcode for the new op placeholders
/// \param op is the PcodeOp getting replaced
/// \param in0Vars is the array of input[0] variables, 1 for each binary op
/// \param in1Vars is the array of input[1] variables, 1 for each binar op
/// \param outVars is the array of output variables, 1 for each binary op
/// \param numLanes is the number of binary ops to create
void LaneDivide::buildBinaryOp(OpCode opc,PcodeOp *op,TransformVar *in0Vars,TransformVar *in1Vars,
			       TransformVar *outVars,int4 numLanes)
{
  for(int4 i=0;i<numLanes;++i) {
    TransformOp *rop = newOpReplace(2, opc, op);
    opSetOutput(rop, outVars + i);
    opSetInput(rop,in0Vars + i, 0);
    opSetInput(rop,in1Vars + i, 1);
  }
}

/// \brief Convert a CPUI_PIECE operation into copies between placeholders, given the output lanes
///
/// Model the given CPUI_PIECE either as either copies from preexisting Varnodes into the
/// output lanes, or as copies from placeholder variables into the output lanes.  Return \b false
/// if the operation cannot be modeled as natural copies between lanes.
/// \param op is the original CPUI_PIECE PcodeOp
/// \param outVars is the placeholder variables making up the lanes of the output
/// \param numLanes is the number of lanes in the output
/// \param skipLanes is the index of the least significant output lane within the global description
/// \return \b true if the CPUI_PIECE was modeled as natural lane copies
bool LaneDivide::buildPiece(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  int4 highLanes,highSkip;
  int4 lowLanes,lowSkip;
  Varnode *highVn = op->getIn(0);
  Varnode *lowVn = op->getIn(1);

  if (!description.restriction(numLanes,skipLanes,lowVn->getSize(),highVn->getSize(),highLanes,highSkip))
    return false;
  if (!description.restriction(numLanes,skipLanes,0,lowVn->getSize(),lowLanes,lowSkip))
    return false;
  if (highLanes == 1) {
    TransformVar *highRvn = getPreexistingVarnode(highVn);
    TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
    opSetInput(rop,highRvn,0);
    opSetOutput(rop,outVars + (numLanes-1));
  }
  else {	// Multi-lane high
    TransformVar *highRvn = setReplacement(highVn, highLanes, highSkip);
    if (highRvn == (TransformVar *)0) return false;
    int4 outHighStart = numLanes - highLanes;
    for(int4 i=0;i<highLanes;++i) {
      TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
      opSetInput(rop,highRvn+i,0);
      opSetOutput(rop,outVars + (outHighStart + i));
    }
  }
  if (lowLanes == 1) {
    TransformVar *lowRvn = getPreexistingVarnode(lowVn);
    TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
    opSetInput(rop,lowRvn,0);
    opSetOutput(rop,outVars);
  }
  else {	// Multi-lane low
    TransformVar *lowRvn = setReplacement(lowVn, lowLanes, lowSkip);
    if (lowRvn == (TransformVar *)0) return false;
    for(int4 i=0;i<lowLanes;++i) {
      TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
      opSetInput(rop,lowRvn+i,0);
      opSetOutput(rop,outVars + i);
    }
  }
  return true;
}

/// \brief Split a given CPUI_MULTIEQUAL operation into placeholders given the output lanes
///
/// Model the single given CPUI_MULTIEQUAL as a sequence of smaller MULTIEQUALs on
/// each individual lane. Return \b false if the operation cannot be modeled as naturally.
/// \param op is the original CPUI_MULTIEQUAL PcodeOp
/// \param outVars is the placeholder variables making up the lanes of the output
/// \param numLanes is the number of lanes in the output
/// \param skipLanes is the index of the least significant output lane within the global description
/// \return \b true if the operation was fully modeled
bool LaneDivide::buildMultiequal(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  vector<TransformVar *> inVarSets;
  int4 numInput = op->numInput();
  for(int4 i=0;i<numInput;++i) {
    TransformVar *inVn = setReplacement(op->getIn(i), numLanes, skipLanes);
    if (inVn == (TransformVar *)0) return false;
    inVarSets.push_back(inVn);
  }
  for(int4 i=0;i<numLanes;++i) {
    TransformOp *rop = newOpReplace(numInput, CPUI_MULTIEQUAL, op);
    opSetOutput(rop, outVars + i);
    for(int4 j=0;j<numInput;++j)
      opSetInput(rop, inVarSets[j] + i, j);
  }
  return true;
}

/// \brief Split a given CPUI_INDIRECT operation into placeholders given the output lanes
///
/// Create the CPUI_INDIRECTs for each lane, sharing the same affecting \e iop.
/// \param op is the original CPUI_MULTIEQUAL PcodeOp
/// \param outVars is the placeholder variables making up the lanes of the output
/// \param numLanes is the number of lanes in the output
/// \param skipLanes is the index of the least significant output lane within the global description
/// \return \b true if the operation was fully modeled
bool LaneDivide::buildIndirect(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  TransformVar *inVn = setReplacement(op->getIn(0), numLanes, skipLanes);
  if (inVn == (TransformVar *)0) return false;
  for(int4 i=0;i<numLanes;++i) {
    TransformOp *rop = newOpReplace(2, CPUI_INDIRECT, op);
    opSetOutput(rop, outVars + i);
    opSetInput(rop,inVn + i, 0);
    opSetInput(rop,newIop(op->getIn(1)),1);
    rop->inheritIndirect(op);
  }
  return true;
}

/// \brief Split a given CPUI_STORE operation into a sequence of STOREs of individual lanes
///
/// A new pointer is constructed for each individual lane into a temporary, then a
/// STORE is created using the pointer that stores an individual lane.
/// \param op is the given CPUI_STORE PcodeOp
/// \param numLanes is the number of lanes the STORE is split into
/// \param skipLanes is the starting lane (within the global description) of the value being stored
/// \return \b true if the CPUI_STORE was successfully modeled on lanes
bool LaneDivide::buildStore(PcodeOp *op,int4 numLanes,int4 skipLanes)

{
  TransformVar *inVars = setReplacement(op->getIn(2), numLanes, skipLanes);
  if (inVars == (TransformVar *)0) return false;
  uintb spaceConst = op->getIn(0)->getOffset();
  int4 spaceConstSize = op->getIn(0)->getSize();
  AddrSpace *spc = op->getIn(0)->getSpaceFromConst();	// Address space being stored to
  Varnode *origPtr = op->getIn(1);
  if (origPtr->isFree()) {
    if (!origPtr->isConstant()) return false;
  }
  TransformVar *basePtr = getPreexistingVarnode(origPtr);
  int4 ptrSize = origPtr->getSize();
  Varnode *valueVn = op->getIn(2);
  for(int4 i=0;i<numLanes;++i) {
    TransformOp *ropStore = newOpReplace(3, CPUI_STORE, op);
    int4 bytePos = description.getPosition(skipLanes + i);
    int4 sz = description.getSize(skipLanes + i);
    if (spc->isBigEndian())
      bytePos = valueVn->getSize() - (bytePos + sz);	// Convert position to address order

    // Construct the pointer
    TransformVar *ptrVn;
    if (bytePos == 0)
      ptrVn = basePtr;
    else {
      ptrVn = newUnique(ptrSize);
      TransformOp *addOp = newOp(2, CPUI_INT_ADD, ropStore);
      opSetOutput(addOp,ptrVn);
      opSetInput(addOp,basePtr,0);
      opSetInput(addOp,newConstant(ptrSize, 0, bytePos), 1);
    }

    opSetInput(ropStore,newConstant(spaceConstSize,0,spaceConst),0);
    opSetInput(ropStore,ptrVn,1);
    opSetInput(ropStore,inVars+i,2);
  }
  return true;
}

/// \brief Split a given CPUI_LOAD operation into a sequence of LOADs of individual lanes
///
/// A new pointer is constructed for each individual lane into a temporary, then a
/// LOAD is created using the pointer that loads an individual lane.
/// \param op is the given CPUI_LOAD PcodeOp
/// \param outVars is the output placeholders for the LOAD
/// \param numLanes is the number of lanes the LOAD is split into
/// \param skipLanes is the starting lane (within the global description) of the value being loaded
/// \return \b true if the CPUI_LOAD was successfully modeled on lanes
bool LaneDivide::buildLoad(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  uintb spaceConst = op->getIn(0)->getOffset();
  int4 spaceConstSize = op->getIn(0)->getSize();
  AddrSpace *spc = op->getIn(0)->getSpaceFromConst();	// Address space being stored to
  Varnode *origPtr = op->getIn(1);
  if (origPtr->isFree()) {
    if (!origPtr->isConstant()) return false;
  }
  TransformVar *basePtr = getPreexistingVarnode(origPtr);
  int4 ptrSize = origPtr->getSize();
  int4 outSize = op->getOut()->getSize();
  for(int4 i=0;i<numLanes;++i) {
    TransformOp *ropLoad = newOpReplace(2, CPUI_LOAD, op);
    int4 bytePos = description.getPosition(skipLanes + i);
    int4 sz = description.getSize(skipLanes + i);
    if (spc->isBigEndian())
      bytePos = outSize - (bytePos + sz);	// Convert position to address order

    // Construct the pointer
    TransformVar *ptrVn;
    if (bytePos == 0)
      ptrVn = basePtr;
    else {
      ptrVn = newUnique(ptrSize);
      TransformOp *addOp = newOp(2, CPUI_INT_ADD, ropLoad);
      opSetOutput(addOp,ptrVn);
      opSetInput(addOp,basePtr,0);
      opSetInput(addOp,newConstant(ptrSize, 0, bytePos), 1);
    }

    opSetInput(ropLoad,newConstant(spaceConstSize,0,spaceConst),0);
    opSetInput(ropLoad,ptrVn,1);
    opSetOutput(ropLoad,outVars+i);
  }
  return true;
}

/// \brief Check that a CPUI_INT_RIGHT respects the lanes then generate lane placeholders
///
/// For the given lane scheme, check that the RIGHT shift is copying whole lanes to each other.
/// If so, generate the placeholder COPYs that model the shift.
/// \param op is the given CPUI_INT_RIGHT PcodeOp
/// \param outVars is the output placeholders for the RIGHT shift
/// \param numLanes is the number of lanes the shift is split into
/// \param skipLanes is the starting lane (within the global description) of the output value
/// \return \b true if the CPUI_INT_RIGHT was successfully modeled on lanes
bool LaneDivide::buildRightShift(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  if (!op->getIn(1)->isConstant()) return false;
  int4 shiftSize = (int4)op->getIn(1)->getOffset();
  if ((shiftSize & 7) != 0) return false;		// Not a multiple of 8
  shiftSize /= 8;
  int4 startPos = shiftSize + description.getPosition(skipLanes);
  int4 startLane = description.getBoundary(startPos);
  if (startLane < 0) return false;		// Shift does not end on a lane boundary
  int4 srcLane = startLane;
  int4 destLane = skipLanes;
  while(srcLane - skipLanes < numLanes) {
    if (description.getSize(srcLane) != description.getSize(destLane)) return false;
    srcLane += 1;
    destLane += 1;
  }
  TransformVar *inVars = setReplacement(op->getIn(0), numLanes, skipLanes);
  if (inVars == (TransformVar *)0) return false;
  buildUnaryOp(CPUI_COPY, op, inVars + (startLane - skipLanes), outVars, numLanes - (startLane - skipLanes));
  for(int4 zeroLane=numLanes - (startLane - skipLanes);zeroLane < numLanes;++zeroLane) {
    TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
    opSetOutput(rop,outVars + zeroLane);
    opSetInput(rop,newConstant(description.getSize(zeroLane), 0, 0),0);
  }
  return true;
}

/// \brief Check that a CPUI_INT_LEFT respects the lanes then generate lane placeholders
///
/// For the given lane scheme, check that the LEFT shift is copying whole lanes to each other.
/// If so, generate the placeholder COPYs that model the shift.
/// \param op is the given CPUI_INT_LEFT PcodeOp
/// \param outVars is the output placeholders for the LEFT shift
/// \param numLanes is the number of lanes the shift is split into
/// \param skipLanes is the starting lane (within the global description) of the output value
/// \return \b true if the CPUI_INT_RIGHT was successfully modeled on lanes
bool LaneDivide::buildLeftShift(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  if (!op->getIn(1)->isConstant()) return false;
  int4 shiftSize = (int4)op->getIn(1)->getOffset();
  if ((shiftSize & 7) != 0) return false;		// Not a multiple of 8
  shiftSize /= 8;
  int4 startPos = shiftSize + description.getPosition(skipLanes);
  int4 startLane = description.getBoundary(startPos);
  if (startLane < 0) return false;		// Shift does not end on a lane boundary
  int4 destLane = startLane;
  int4 srcLane = skipLanes;
  while(destLane - skipLanes < numLanes) {
    if (description.getSize(srcLane) != description.getSize(destLane)) return false;
    srcLane += 1;
    destLane += 1;
  }
  TransformVar *inVars = setReplacement(op->getIn(0), numLanes, skipLanes);
  if (inVars == (TransformVar *)0) return false;
  for(int4 zeroLane=0;zeroLane < (startLane - skipLanes);++zeroLane) {
    TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
    opSetOutput(rop,outVars + zeroLane);
    opSetInput(rop,newConstant(description.getSize(zeroLane), 0, 0),0);
  }
  buildUnaryOp(CPUI_COPY, op, inVars, outVars + (startLane - skipLanes), numLanes - (startLane - skipLanes));
  return true;
}

/// \brief Split a CPUI_INT_ZEXT into COPYs of lanes and COPYs of zero into lanes
///
/// If the input to the INT_ZEXT matches the lane boundaries.  Placeholder COPYs are generated from
/// the input Varnode to the least significant lanes.  Additional COPYs are generated which place a zero
/// in the remaining most significant lanes.
/// \param op is the given CPUI_INT_ZEXT PcodeOp
/// \param outVars is the output placeholders for the extension
/// \param numLanes is the number of lanes the extension is split into
/// \param skipLanes is the starting lane (within the global description) of the output of the extension
/// \return \b true if the CPUI_INT_ZEXT was successfully modeled on lanes
bool LaneDivide::buildZext(PcodeOp *op,TransformVar *outVars,int4 numLanes,int4 skipLanes)

{
  int4 inLanes,inSkip;
  Varnode *invn = op->getIn(0);
  if (!description.restriction(numLanes, skipLanes, 0, invn->getSize(), inLanes, inSkip)) {
    return false;
  }
  // inSkip should always come back as equal to skipLanes
  if (inLanes == 1) {
    TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
    TransformVar *inVar = getPreexistingVarnode(invn);
    opSetInput(rop,inVar,0);
    opSetOutput(rop,outVars);
  }
  else {
    TransformVar *inRvn = setReplacement(invn,inLanes,inSkip);
    if (inRvn == (TransformVar *)0) return false;
    for(int4 i=0;i<inLanes;++i) {
      TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
      opSetInput(rop,inRvn+i,0);
      opSetOutput(rop,outVars + i);
    }
  }
  for(int4 i=0;i<numLanes-inLanes;++i) {			// Write 0 constants to remaining lanes
    TransformOp *rop = newOpReplace(1, CPUI_COPY, op);
    opSetInput(rop,newConstant(description.getSize(skipLanes + inLanes + i), 0, 0),0);
    opSetOutput(rop,outVars + inLanes + i);
  }
  return true;
}

/// \brief Push the logical lanes forward through any PcodeOp reading the given variable
///
/// Determine if the logical lanes can be pushed forward naturally, and create placeholder
/// variables and ops representing the logical data-flow.  Update the worklist with any
/// new Varnodes that the lanes get pushed into.
/// \param rvn is the placeholder variable to push forward from
/// \param numLanes is the number of lanes represented by the placeholder variable
/// \param skipLanes is the index of the starting lane within the global description of the placeholder variable
/// \return \b true if the lanes can be naturally pushed forward
bool LaneDivide::traceForward(TransformVar *rvn,int4 numLanes,int4 skipLanes)

{
  Varnode *origvn = rvn->getOriginal();
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = origvn->beginDescend();
  enditer = origvn->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter++;
    Varnode *outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&(outvn->isMark()))
      continue;
    switch(op->code()) {
      case CPUI_SUBPIECE:
      {
	int4 bytePos = (int4)op->getIn(1)->getOffset();
	int4 outLanes,outSkip;
	if (!description.restriction(numLanes, skipLanes, bytePos, outvn->getSize(), outLanes, outSkip)) {
	  if (allowSubpieceTerminator) {
	    int4 laneIndex = description.getBoundary(bytePos);
	    if (laneIndex < 0 || laneIndex >= description.getNumLanes())	// Does piece start on lane boundary?
	      return false;
	    if (description.getSize(laneIndex) <= outvn->getSize())		// Is the piece smaller than a lane?
	      return false;
	    // Treat SUBPIECE as terminating
	    TransformOp *rop = newPreexistingOp(2, CPUI_SUBPIECE, op);
	    opSetInput(rop, rvn + (laneIndex - skipLanes), 0);
	    opSetInput(rop, newConstant(4, 0, 0), 1);
	    break;
	  }
	  return false;
	}
	if (outLanes == 1) {
	  TransformOp *rop = newPreexistingOp(1, CPUI_COPY, op);
	  opSetInput(rop,rvn + (outSkip-skipLanes), 0);
	}
	else {
	  TransformVar *outRvn = setReplacement(outvn,outLanes,outSkip);
	  if (outRvn == (TransformVar *)0) return false;
	  // Don't create the placeholder ops, let traceBackward make them
	}
	break;
      }
      case CPUI_PIECE:
      {
	int4 outLanes,outSkip;
	int4 bytePos = (op->getIn(0) == origvn) ? op->getIn(1)->getSize() : 0;
	if (!description.extension(numLanes, skipLanes, bytePos, outvn->getSize(), outLanes, outSkip))
	  return false;
	TransformVar *outRvn = setReplacement(outvn,outLanes,outSkip);
	if (outRvn == (TransformVar *)0) return false;
	// Don't create the placeholder ops, let traceBackward make them
	break;
      }
      case CPUI_COPY:
      case CPUI_INT_NEGATE:
      case CPUI_INT_AND:
      case CPUI_INT_OR:
      case CPUI_INT_XOR:
      case CPUI_MULTIEQUAL:
      case CPUI_INDIRECT:
      {
	TransformVar *outRvn = setReplacement(outvn,numLanes,skipLanes);
	if (outRvn == (TransformVar *)0) return false;
	// Don't create the placeholder ops, let traceBackward make them
	break;
      }
      case CPUI_INT_RIGHT:
      {
	if (!op->getIn(1)->isConstant()) return false;	// Trace must come through op->getIn(0)
	TransformVar *outRvn = setReplacement(outvn, numLanes, skipLanes);
	if (outRvn == (TransformVar *)0) return false;
	// Don't create the placeholder ops, let traceBackward make them
	break;
      }
      case CPUI_STORE:
	if (op->getIn(2) != origvn) return false;	// Can only propagate through value being stored
	if (!buildStore(op,numLanes,skipLanes))
	  return false;
	break;
      default:
	return false;
    }
  }
  return true;
}

/// \brief Pull the logical lanes back through the defining PcodeOp of the given variable
///
/// Determine if the logical lanes can be pulled back naturally, and create placeholder
/// variables and ops representing the logical data-flow.  Update the worklist with any
/// new Varnodes that the lanes get pulled back into.
/// \param rvn is the placeholder variable to pull back
/// \param numLanes is the number of lanes represented by the placeholder variable
/// \param skipLanes is the index of the starting lane within the global description of the placeholder variable
/// \return \b true if the lanes can be naturally pulled back
bool LaneDivide::traceBackward(TransformVar *rvn,int4 numLanes,int4 skipLanes)

{
  PcodeOp *op = rvn->getOriginal()->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input

  switch(op->code()) {
    case CPUI_INT_NEGATE:
    case CPUI_COPY:
    {
      TransformVar *inVars = setReplacement(op->getIn(0),numLanes,skipLanes);
      if (inVars == (TransformVar *)0) return false;
      buildUnaryOp(op->code(), op, inVars, rvn, numLanes);
      break;
    }
    case CPUI_INT_AND:
    case CPUI_INT_OR:
    case CPUI_INT_XOR:
    {
      TransformVar *in0Vars = setReplacement(op->getIn(0),numLanes,skipLanes);
      if (in0Vars == (TransformVar *)0) return false;
      TransformVar *in1Vars = setReplacement(op->getIn(1),numLanes,skipLanes);
      if (in1Vars == (TransformVar *)0) return false;
      buildBinaryOp(op->code(),op,in0Vars,in1Vars,rvn,numLanes);
      break;
    }
    case CPUI_MULTIEQUAL:
      if (!buildMultiequal(op, rvn, numLanes, skipLanes))
	return false;
      break;
    case CPUI_INDIRECT:
      if (!buildIndirect(op, rvn, numLanes, skipLanes))
	return false;
      break;
    case CPUI_SUBPIECE:
    {
      Varnode *inVn = op->getIn(0);
      int4 bytePos = (int4)op->getIn(1)->getOffset();
      int4 inLanes,inSkip;
      if (!description.extension(numLanes, skipLanes, bytePos, inVn->getSize(), inLanes, inSkip))
	return false;
      TransformVar *inVars = setReplacement(inVn,inLanes,inSkip);
      if (inVars == (TransformVar *)0) return false;
      buildUnaryOp(CPUI_COPY,op,inVars + (skipLanes - inSkip), rvn, numLanes);
      break;
    }
    case CPUI_PIECE:
      if (!buildPiece(op, rvn, numLanes, skipLanes))
	return false;
      break;
    case CPUI_LOAD:
      if (!buildLoad(op, rvn, numLanes, skipLanes))
	return false;
      break;
    case CPUI_INT_RIGHT:
      if (!buildRightShift(op, rvn, numLanes, skipLanes))
	return false;
      break;
    case CPUI_INT_LEFT:
      if (!buildLeftShift(op, rvn, numLanes, skipLanes))
	return false;
      break;
    case CPUI_INT_ZEXT:
      if (!buildZext(op, rvn, numLanes, skipLanes))
	return false;
      break;
    default:
      return false;
  }
  return true;
}

/// \return \b true if the lane split for the top Varnode on the work list is propagated through local operators
bool LaneDivide::processNextWork(void)

{
  TransformVar *rvn = workList.back().lanes;
  int4 numLanes = workList.back().numLanes;
  int4 skipLanes = workList.back().skipLanes;

  workList.pop_back();

  if (!traceBackward(rvn,numLanes,skipLanes)) return false;
  return traceForward(rvn,numLanes,skipLanes);
}

/// \param f is the function being transformed
/// \param root is the root Varnode to start tracing lanes from
/// \param desc is a description of the lanes on the root Varnode
/// \param allowDowncast is \b true if we all SUBPIECE to be treated as terminating
LaneDivide::LaneDivide(Funcdata *f,Varnode *root,const LaneDescription &desc,bool allowDowncast)
  : TransformManager(f), description(desc)
{
  allowSubpieceTerminator = allowDowncast;
  setReplacement(root, desc.getNumLanes(), 0);
}

/// Push the lanes around from the root, setting up the explicit transforms as we go.
/// If at any point, the lanes cannot be naturally pushed, return \b false.
/// \return \b true if a full transform has been constructed that can split into explicit lanes
bool LaneDivide::doTrace(void)

{
  if (workList.empty())
    return false;		// Nothing to do
  bool retval = true;
  while(!workList.empty()) {	// Process the work list until its done
    if (!processNextWork()) {
      retval = false;
      break;
    }
  }

  clearVarnodeMarks();
  if (!retval) return false;
  return true;
}

} // End namespace ghidra

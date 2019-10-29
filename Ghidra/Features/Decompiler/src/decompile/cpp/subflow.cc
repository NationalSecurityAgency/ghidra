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
    return addConstant((ReplaceOp *)0,mask,0,vn->getOffset());
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
    if (vn->isTypeLock()) {
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
      if (vn->isTypeLock()) {
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
  oplist.push_back(ReplaceOp());
  ReplaceOp *rop = &oplist.back();
  outrvn->def = rop;
  rop->op = outrvn->vn->getDef();
  rop->numparams = numparam;
  rop->opc = opc;
  rop->output = outrvn;

  return rop;
}


/// \brief Create a logical subraph operator node given one of its input variable nodes
///
/// \param opc is the opcode of the new logical operator
/// \param numparam is the number of parameters in the new operator
/// \param inrvn is the given input variable node
/// \param slot is the input slot of the variable node
/// \return the new logical subgraph operator objects
SubvariableFlow::ReplaceOp *SubvariableFlow::createOpDown(OpCode opc,int4 numparam,PcodeOp *op,ReplaceVarnode *inrvn,int4 slot)

{
  oplist.push_back(ReplaceOp());
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

/// \brief Convert a new INDIRECT op into the logically trimmed variant of the given original PcodeOp
///
/// This method assumes the original op was an \e indirect \e creation. The input and output
/// Varnode for the new INDIRECT are not provided by this method. It only provides the
/// \e indirect \e effect input and patches up any active parameter recovery process.
/// \param newop is the new INDIRECT op to convert
/// \param oldop is the original INDIRECT op
/// \param out is the subgraph output variable node of the new INDIRECT
void SubvariableFlow::patchIndirect(PcodeOp *newop,PcodeOp *oldop, ReplaceVarnode *out)

{
  PcodeOp *indop = PcodeOp::getOpFromConst(oldop->getIn(1)->getAddr());
  bool possibleout = !oldop->getIn(0)->isIndirectZero();
  Varnode *outvn = getReplaceVarnode(out);
  fd->setIndirectCreation(newop,indop,outvn,possibleout);
  FuncCallSpecs *fc = fd->getCallSpecs(indop);
  if (fc == (FuncCallSpecs *)0) return;
  if (fc->isOutputActive()) {
    ParamActive *active = fc->getActiveOutput();
    int4 trial = active->whichTrial( out->vn->getAddr(), out->vn->getSize() );
    if (trial < 0)
      throw LowlevelError("Cannot trim output trial to subflow");
    Address addr = getReplacementAddress(out);
    active->shrink(trial,addr,flowsize);
  }
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
  FuncCallSpecs *fc = fd->getCallSpecs(op);
  if (fc == (FuncCallSpecs *)0) return false;
  if (fc->isInputActive()) return false; // Don't trim while in the middle of figuring out params
  if (fc->isInputLocked() && (!fc->isDotdotdot())) return false;

  patchlist.push_back(PatchRecord());
  patchlist.back().type = 2;
  patchlist.back().pullop = op;
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
    }
    returnsTraversed = true;
  }
  patchlist.push_back(PatchRecord());
  patchlist.back().type = 2;
  patchlist.back().pullop = op;
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
bool SubvariableFlow::tryCallReturnPull(PcodeOp *op,ReplaceVarnode *rvn)

{
  if (!op->isIndirectCreation()) return false;
  PcodeOp *indop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
  FuncCallSpecs *fc = fd->getCallSpecs(indop);
  if (fc == (FuncCallSpecs *)0) return false;
  if (fc->isOutputLocked()) return false;
  
  if (fc->isOutputActive()) {
    ParamActive *active = fc->getActiveOutput();
    int4 trial = active->whichTrial( rvn->vn->getAddr(), rvn->vn->getSize() );
    if (trial < 0) return false;
    Address newaddr = getReplacementAddress(rvn);
    if (!active->testShrink(trial,newaddr, flowsize ))
      return false;
  }
  createOp(CPUI_INDIRECT,2,rvn);
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

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = rvn->vn->beginDescend();
  enditer = rvn->vn->endDescend();
  while(iter != enditer) {
    op = *iter++;
    outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&(outvn->isMark()))
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
	if ((!aggressive)&&(calc_mask(outvn->getSize()) == outvn->getConsume())) {
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
      if (rvn->mask != (newmask << sa)) return false;
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
      if (!aggressive) return false;
      if (!tryCallPull(op,rvn,slot)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_RETURN:
      if (!aggressive) return false;
      if (!tryReturnPull(op,rvn,slot)) return false;
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
      addConstant(rop,rvn->mask,0,op->getIn(sa)->getOffset());
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
      addConstant(rop,rvn->mask,0,op->getIn(sa)->getOffset());
    }
    else {
      rop = createOp(CPUI_INT_OR,2,rvn);
      if (!createLink(rop,rvn->mask,0,op->getIn(0))) return false;
      if (!createLink(rop,rvn->mask,1,op->getIn(1))) return false;
    }
    return true;
  case CPUI_INT_ZEXT:
  case CPUI_INT_SEXT:
    if ((rvn->mask & calc_mask(op->getIn(0)->getSize())) != rvn->mask)
      break;	       // Check if subvariable comes through extension
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
      addConstant(rop,rvn->mask,0,(uintb)0);
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
      addConstant(rop,rvn->mask,0,(uintb)0);
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
  case CPUI_INDIRECT:
    // TODO: This assumes that the INDIRECT is CALL-based.  Add STORE-based logic.
    if (aggressive) {
      if (tryCallReturnPull(op,rvn))
	return true;
    }
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
    addConstant(rop,rvn->mask,0,(uintb)0);
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

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = rvn->vn->beginDescend();
  enditer = rvn->vn->endDescend();
  while(iter != enditer) {
    op = *iter++;
    outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&(outvn->isMark()))
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
      addConstant(rop,calc_mask(op->getIn(1)->getSize()),1,op->getIn(1)->getOffset()); // Preserve the shift amount
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
      if (!aggressive) return false;
      if (!tryCallPull(op,rvn,slot)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_RETURN:
      if (!aggressive) return false;
      if (!tryReturnPull(op,rvn,slot)) return false;
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
      addConstant(rop,calc_mask(op->getIn(1)->getSize()),1,op->getIn(1)->getOffset()); // Preserve the shift amount
    return true;
  case CPUI_INDIRECT:
    if (aggressive) {
      if (tryCallReturnPull(op,rvn))
	return true;
    }
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
/// Unlike other subgraph variable nodes, this one does not maintain a mirror with the original containing Varnode.
/// \param rop is the logical operation taking the constant as input
/// \param mask is the set of bits holding the logical value (within a bigger value)
/// \param slot is the input slot to the operation
/// \param val is the bigger constant value holding the logical value
SubvariableFlow::ReplaceVarnode *SubvariableFlow::addConstant(ReplaceOp *rop,uintb mask,
					      uint4 slot,uintb val)
{ // Add a constant to the replacement tree
  newvarlist.push_back(ReplaceVarnode());
  ReplaceVarnode *res = &newvarlist.back();
  res->vn = (Varnode *)0;
  res->replacement = (Varnode *)0;
  res->mask = mask;

  // Calculate the actual constant value
  int4 sa = leastsigbit_set(mask);
  res->val = (mask & val) >> sa;
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
  newvarlist.push_back(ReplaceVarnode());
  ReplaceVarnode *res = &newvarlist.back();
  res->vn = (Varnode *)0;
  res->replacement = (Varnode *)0;
  res->mask = mask;

  rop->output = res;
  res->def = rop;
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
  patchlist.push_back(PatchRecord());
  patchlist.back().type = 0;	// Ultimately gets converted to a COPY
  patchlist.back().pullop = pullop;	// Operation pulling the variable out
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
  patchlist.push_back(PatchRecord());
  patchlist.back().type = 2;	// Keep the original op, just change input
  patchlist.back().pullop = pullop;	// Operation pulling the variable out
  patchlist.back().in1 = rvn;	// Point in container flow for pull
  patchlist.back().slot = slot;
  pullcount += 1;		// a true terminal modification
}

/// \brief Mark a subgraph bit variable flowing into an operation taking a boolean input
///
/// This doesn't count as a Varnode holding a logical value that needs to be patched (by itself).
/// A PatchRecord terminating the logical subgraph along the given edge is created.
/// \param pullup is the operation taking the boolean input
/// \param rvn is the given bit variable
/// \param slot is the input slot of the variable to the operation
void SubvariableFlow::addBooleanPatch(PcodeOp *pullop,ReplaceVarnode *rvn,int4 slot)

{
  patchlist.push_back(PatchRecord());
  patchlist.back().type = 2;	// Make no change to the operator, just put in the new input
  patchlist.back().pullop = pullop;	// Operation pulling the variable out
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
  patchlist.push_back(PatchRecord());
  patchlist.back().type = 3;
  patchlist.back().in1 = rvn;
  patchlist.back().pullop = pushop;
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
  patchlist.push_back(PatchRecord());
  patchlist.back().type = 1;
  patchlist.back().pullop = op;
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
  // Only a constant if BOTH replacement and vn fields are null
  if (rvn->vn == (Varnode *)0) {
    if (rvn->def==(ReplaceOp *)0) // A constant
      return fd->newConstant(flowsize,rvn->val);
    rvn->replacement = fd->newUnique(flowsize);
    return rvn->replacement;
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

SubvariableFlow::SubvariableFlow(Funcdata *f,Varnode *root,uintb mask,bool aggr,bool sext)

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
  else {
    fd = (Funcdata *)0;
    return;
  }
  createLink((ReplaceOp *)0,mask,0,root);
}

bool SubvariableFlow::doTrace(void)

{ // Process worklist until its done
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

{ // Create the actual replacement data-flow with -fd-
  list<ReplaceOp>::iterator iter;

  // Define all the outputs first
  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    PcodeOp *newop = fd->newOp((*iter).numparams,(*iter).op->getAddr());
    (*iter).replacement = newop;
    if ((*iter).opc == CPUI_INDIRECT) {
      patchIndirect( newop, (*iter).op, (*iter).output );
    }
    else {
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
  }

  // Set all the inputs
  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    PcodeOp *newop = (*iter).replacement;
    for(uint4 i=0;i<(*iter).input.size();++i)
      fd->opSetInput(newop,getReplaceVarnode((*iter).input[i]),i);
  }

  // These are operations that carry flow from the small variable into an existing
  // variable of the correct size
  list<PatchRecord>::iterator piter;
  for(piter=patchlist.begin();piter!=patchlist.end();++piter) {
    PcodeOp *pullop = (*piter).pullop;
    int4 type = (*piter).type;
    if (type == 0) {
      while(pullop->numInput() > 1)
	fd->opRemoveInput(pullop,pullop->numInput()-1);
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in1),0);
      fd->opSetOpcode(pullop,CPUI_COPY);
    }
    else if (type == 1) {	// A comparison
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in1),0);
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in2),1);
    }
    else if (type == 2) {	// A call parameter or return value
      fd->opSetInput(pullop,getReplaceVarnode((*piter).in1),(*piter).slot);
    }
    else if (type == 3) {
      // These are operations that flow the small variable into a bigger variable but
      // where all the remaining bits are zero
      int4 sa = (*piter).slot;
      vector<Varnode *> invec;
      if (sa == 0) {
	invec.push_back( getReplaceVarnode((*piter).in1) );
	fd->opSetOpcode( pullop, CPUI_INT_ZEXT );
	fd->opSetAllInput(pullop,invec);
      }
      else {
	PcodeOp *zextop = fd->newOp(1,pullop->getAddr());
	fd->opSetOpcode( zextop, CPUI_INT_ZEXT );
	Varnode *zextout = fd->newUniqueOut(pullop->getOut()->getSize(),zextop);
	fd->opSetInput(zextop,getReplaceVarnode((*piter).in1),0);
	fd->opInsertBefore(zextop,pullop);
	invec.push_back(zextout);
	invec.push_back(fd->newConstant(4,sa));
	fd->opSetAllInput(pullop,invec);
	fd->opSetOpcode( pullop, CPUI_INT_LEFT);
      }
    }
  }
}

SplitFlow::ReplaceVarnode::ReplaceVarnode(void)

{
  replaceLo = (Varnode *)0;
  replaceHi = (Varnode *)0;
  defTraversed = false;
}

SplitFlow::ReplaceOp::ReplaceOp(bool isLogic,PcodeOp *o,OpCode opc,int4 num)

{
  op = o;
  opcode = opc;
  loOp = (PcodeOp *)0;
  hiOp = (PcodeOp *)0;
  numParams = num;
  doDelete = false;
  isLogicalInput = isLogic;
  output = (ReplaceVarnode *)0;
}

void SplitFlow::assignReplaceOp(bool isLogicalInput,PcodeOp *op,OpCode opc,int4 numParam,ReplaceVarnode *outrvn)

{
  if (outrvn != (ReplaceVarnode *)0) {
    if (!outrvn->defTraversed) {
      oplist.push_back(ReplaceOp(isLogicalInput,op,opc,numParam));
      oplist.back().output = outrvn;
      outrvn->defTraversed = true;
    }
  }
  else {
    oplist.push_back(ReplaceOp(isLogicalInput,op,opc,numParam));
  }
}

void SplitFlow::assignLogicalPieces(ReplaceVarnode *rvn)

{ // Create the logical pieces of -rvn- as actual Varnodes
  if (rvn->replaceLo != (Varnode *)0) return;
  if (rvn->vn->isConstant()) {
    uintb val1 = rvn->vn->getOffset() & calc_mask(loSize);
    uintb val2 = (rvn->vn->getOffset() >> (loSize * 8)) & calc_mask(hiSize);
    rvn->replaceLo = fd->newConstant(loSize,val1);
    rvn->replaceHi = fd->newConstant(hiSize,val2);
    return;
  }
  if (rvn->vn->getSpace()->getType() == IPTR_INTERNAL) {
    rvn->replaceLo = fd->newUnique(loSize);
    rvn->replaceHi = fd->newUnique(hiSize);
    return;
  }
  fd->splitVarnode(rvn->vn,loSize,rvn->replaceLo,rvn->replaceHi);
  if (rvn->vn->isInput()) {		// Right now this shouldn't happen
    fd->setInputVarnode(rvn->replaceLo);
    fd->setInputVarnode(rvn->replaceHi);
  }
}

void SplitFlow::buildReplaceOutputs(ReplaceOp *rop)

{
  if (rop->output == (ReplaceVarnode *)0) return;
  assignLogicalPieces(rop->output);
  rop->loOp = fd->newOp(rop->numParams,rop->op->getAddr());
  rop->hiOp = fd->newOp(rop->numParams,rop->op->getAddr());
  fd->opSetOpcode(rop->loOp,rop->opcode);
  fd->opSetOpcode(rop->hiOp,rop->opcode);
  fd->opSetOutput(rop->loOp,rop->output->replaceLo);
  fd->opSetOutput(rop->hiOp,rop->output->replaceHi);
}

void SplitFlow::replacePiece(ReplaceOp *rop)

{ // Finish replacing the CPUI_PIECE operation with two COPY operations
  PcodeOp *op = rop->op;
  Varnode *invn0 = op->getIn(0);
  Varnode *invn1 = op->getIn(1);
  fd->opUnsetInput(op,0);
  fd->opUnsetInput(op,1);
  fd->opSetInput(rop->loOp,invn1,0);
  fd->opSetInput(rop->hiOp,invn0,0);
  fd->opInsertBefore(rop->loOp,op);	// insert at the same place as original op
  fd->opInsertBefore(rop->hiOp,op);
  rop->doDelete = true;		// Mark this op to be deleted
}

void SplitFlow::replaceZext(ReplaceOp *rop)

{ // Finish replacing the CPUI_INT_ZEXT operation with a COPY and a COPY zero
  PcodeOp *op = rop->op;
  Varnode *invn0 = op->getIn(0);
  fd->opUnsetInput(op,0);
  fd->opSetInput(rop->loOp,invn0,0);		// Input to first COPY is original input to ZEXT
  fd->opSetInput(rop->hiOp,fd->newConstant(hiSize,0),0);	// Input to second COPY is 0 constant
  fd->opInsertBefore(rop->loOp,op);		// insert at the same place as original op
  fd->opInsertBefore(rop->hiOp,op);
  rop->doDelete = true;		// Mark this op to be deleted
}

void SplitFlow::replaceLeftInput(ReplaceOp *rop)

{
  PcodeOp *op = rop->op;
  // Presence of ZEXT operation has already been verified
  Varnode *invn0 = op->getIn(0)->getDef()->getIn(0);	// Grab the input to ZEXT
  fd->opUnsetInput(op,0);
  fd->opSetInput(rop->loOp,fd->newConstant(loSize,0),0);	// Input to first COPY is 0 constant
  fd->opSetInput(rop->hiOp,invn0,0);				// Input to second COPY is original input to ZEXT
  fd->opInsertBefore(rop->loOp,op);		// insert at the same place as original op
  fd->opInsertBefore(rop->hiOp,op);
  rop->doDelete = true;
}

void SplitFlow::replaceLeftTerminal(ReplaceOp *rop)

{
  PcodeOp *op = rop->op;
  ReplaceVarnode *rvn1 = &varmap[op->getIn(0)];
  assignLogicalPieces(rvn1);
  PcodeOp *otherOp = fd->newOp(1,op->getAddr());
  Varnode *otherVn = fd->newUniqueOut(concatSize,otherOp);
  fd->opSetOpcode(otherOp,CPUI_INT_ZEXT);			// Extension of low piece
  fd->opSetInput(otherOp,rvn1->replaceLo,0);
  fd->opInsertBefore(otherOp,op);
  fd->opSetInput(op,otherVn,0);				// Original shift is unchanged
}

void SplitFlow::replaceOp(ReplaceOp *rop)

{ // Finish splitting -rop- into two separate operations on the logical pieces at the same point in the code
  // Build the logical Varnodes or reuse previously built ones as necessary
  // going through ReplaceVarnodes and -varmap-
  vector<ReplaceVarnode *> inputs;

  PcodeOp *op = rop->op;
  int4 numParam = op->numInput();
  if (op->code() == CPUI_INDIRECT)		// Slightly special handling if this is an INDIRECT
    numParam = 1;				// We don't split the "indirect effect" varnode
  for(int4 i=0;i<numParam;++i) {
    ReplaceVarnode *invn = &varmap[op->getIn(i)];
    assignLogicalPieces(invn);			// Make sure logical pieces are built
    inputs.push_back(invn);
  }
  for(int4 i=0;i<numParam;++i) {
    ReplaceVarnode *invn = inputs[i];
    fd->opSetInput(rop->loOp,invn->replaceLo,i);	// Set inputs of component ops
    fd->opSetInput(rop->hiOp,invn->replaceHi,i);
  }
  if (op->code() == CPUI_INDIRECT) {
    PcodeOp *indeffect = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
    fd->opSetInput(rop->loOp,fd->newVarnodeIop(indeffect),1);		// Add in the "indirect effect" parameter
    fd->opSetInput(rop->hiOp,fd->newVarnodeIop(indeffect),1);
    fd->opInsertBefore(rop->loOp,indeffect);				// Insert right before the indirect effect
    fd->opInsertBefore(rop->hiOp,indeffect);
  }
  else if (op->code() == CPUI_MULTIEQUAL) {
    BlockBasic *bb = op->getParent();		// Make sure MULTIEQUALs get inserted at the beginning of the block
    fd->opInsertBegin(rop->loOp,bb);
    fd->opInsertBegin(rop->hiOp,bb);
  }
  else {
    fd->opInsertBefore(rop->loOp,op);		// Otherwise, insert at the same place as original op
    fd->opInsertBefore(rop->hiOp,op);
  }
  rop->doDelete = true;		// Mark this op to be deleted
}

SplitFlow::ReplaceVarnode *SplitFlow::setReplacement(Varnode *vn,bool &inworklist)

{ // Find the matching placeholder object for a varnode that needs to be split, OR build the placeholder object
  // Mark the varnode so it doesn't get revisited
  // Decide if the varnode needs to go into the worklist by setting -inworklist-
  // Return null if this won't work
  ReplaceVarnode *res;
  if (vn->isMark()) {		// Already seen before
    map<Varnode *,ReplaceVarnode>::iterator iter;
    iter = varmap.find(vn);
    res = &(*iter).second;
    inworklist = false;
    return res;
  }

  if (vn->isTypeLock())
    return (ReplaceVarnode *)0;
  if (vn->isInput())
    return (ReplaceVarnode *)0;		// Right now we can't split inputs
  if (vn->isFree() && (!vn->isConstant()))
    return (ReplaceVarnode *)0;		// Abort

  res = & varmap[ vn ];			// Create new ReplaceVarnode and put it in map
  vn->setMark();
  res->vn = vn;
  inworklist = !vn->isConstant();

  return res;
}

bool SplitFlow::addOpOutput(PcodeOp *op)

{ // Save off -op- for replacement
  // Make sure the output will be replaced and add it to the worklist
  // Return false if this is not possible
  bool inworklist;
  ReplaceVarnode *newvn = setReplacement(op->getOut(),inworklist);
  if (newvn == (ReplaceVarnode *)0)
    return false;
  assignReplaceOp(false,op,op->code(),op->numInput(),newvn);
  if (inworklist)
    worklist.push_back(newvn);
  return true;
}

bool SplitFlow::addOpInputs(PcodeOp *op,ReplaceVarnode *outrvn,int4 numParam)

{ // Save off -op- for replacement
  // Make sure the inputs will be replaced and add them to the worklist
  // Return false if this is not possible
  bool inworklist;
  ReplaceVarnode *newvn;

  for(int4 i=0;i<numParam;++i) {
    Varnode *vn = op->getIn(i);
    newvn = setReplacement(vn,inworklist);
    if (newvn == (ReplaceVarnode *)0)
      return false;
    if (inworklist)
      worklist.push_back(newvn);
  }
  assignReplaceOp(false,op,op->code(),op->numInput(),outrvn);
  return true;
}

bool SplitFlow::traceForward(ReplaceVarnode *rvn)

{ // Try to trace pieces of -rvn- forward, through reading ops, update worklist
  // Return true if logical pieces can be naturally traced, false otherwise
  PcodeOp *op;
  Varnode *outvn,*tmpvn;
  uintb val;

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = rvn->vn->beginDescend();
  enditer = rvn->vn->endDescend();
  while(iter != enditer) {
    op = *iter++;
    outvn = op->getOut();
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
      if (!addOpOutput(op))
	return false;
      break;
    case CPUI_SUBPIECE:
      val = op->getIn(1)->getOffset();
      if ((val==0)&&(outvn->getSize() == loSize))
	assignReplaceOp(false,op,CPUI_COPY,1,(ReplaceVarnode *)0);	// Grabs the low piece
      else if ((val == loSize)&&(outvn->getSize() == hiSize))
	assignReplaceOp(false,op,CPUI_COPY,1,(ReplaceVarnode *)0);	// Grabs the high piece
      else
	return false;
      break;
    case CPUI_INT_LEFT:
      tmpvn = op->getIn(1);
      if (!tmpvn->isConstant())
	return false;
      val = tmpvn->getOffset();
      if (val < hiSize * 8)
	return false;			// Must obliterate all high bits
      assignReplaceOp(false,op,CPUI_INT_LEFT,2,(ReplaceVarnode *)0);	// Good, but terminating op
      break;
    case CPUI_INT_SRIGHT:
    case CPUI_INT_RIGHT:
      tmpvn = op->getIn(1);
      if (!tmpvn->isConstant())
	return false;
      val = tmpvn->getOffset();
      if (val < loSize * 8)
	return false;
      assignReplaceOp(false,op,(op->code() == CPUI_INT_RIGHT) ? CPUI_INT_ZEXT : CPUI_INT_SEXT,2,(ReplaceVarnode *)0);		// Good, but terminating op
      break;
    default:
      return false;
    }
  }
  return true;
}

bool SplitFlow::traceBackward(ReplaceVarnode *rvn)

{ // Try to trace the pair of logical values, backward, through the op defining -rvn-
  // Update list of Varnodes and PcodeOps to replace and the worklist as necessary
  // Return false if this is not possible
  PcodeOp *op = rvn->vn->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input

  switch(op->code()) {
  case CPUI_COPY:
  case CPUI_MULTIEQUAL:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_XOR:
//  case CPUI_INT_NEGATE:
    if (!addOpInputs(op,rvn,op->numInput()))
      return false;
    break;
  case CPUI_INDIRECT:
    if (!addOpInputs(op,rvn,1))		// Only backtrack through the first input
      return false;
    break;
  case CPUI_PIECE:
    if (op->getIn(0)->getSize() != hiSize)
      return false;
    if (op->getIn(1)->getSize() != loSize)
      return false;
    assignReplaceOp(true,op,CPUI_COPY,1,rvn);
    break;
  case CPUI_INT_ZEXT:
    if (op->getIn(0)->getSize() != loSize)
      return false;
    if (op->getOut()->getSize() != (loSize + hiSize))
      return false;
    assignReplaceOp(true,op,CPUI_COPY,1,rvn);
    break;
  case CPUI_INT_LEFT:
    {
      Varnode *cvn = op->getIn(1);
      if (!cvn->isConstant()) return false;
      if (cvn->getOffset() != loSize * 8) return false;
      Varnode *invn = op->getIn(0);
      if (!invn->isWritten()) return false;
      PcodeOp *zextOp = invn->getDef();
      if (zextOp->code() != CPUI_INT_ZEXT) return false;
      invn = zextOp->getIn(0);
      if (invn->getSize() != hiSize) return false;
      if (invn->isFree()) return false;
      assignReplaceOp(true,op,CPUI_COPY,1,rvn);
    }
    break;
//  case CPUI_LOAD:		// We could split into two different loads
  default:
    return false;
  }
  return true;
}

bool SplitFlow::processNextWork(void)

{
  ReplaceVarnode *rvn = worklist.back();

  worklist.pop_back();

  if (!traceBackward(rvn)) return false;
  return traceForward(rvn);
}

SplitFlow::SplitFlow(Funcdata *f,Varnode *root,int4 lowSize)

{
  fd = f;
  concatSize = root->getSize();
  loSize = lowSize;
  hiSize = concatSize - loSize;
  bool inworklist;
  ReplaceVarnode *rvn = setReplacement(root,inworklist);
  if (rvn == (ReplaceVarnode *)0)
    return;
  if (inworklist)
    worklist.push_back(rvn);
}

void SplitFlow::doReplacement(void)

{
  ReplaceVarnode *rvn1;

  list<ReplaceOp>::iterator iter;
  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    buildReplaceOutputs(&(*iter));		// Build the raw replacement ops for anything needing an output
  }

  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    ReplaceOp *rop = &(*iter);
    PcodeOp *op = rop->op;
    switch(op->code()) {
    case CPUI_SUBPIECE:
      rvn1 = &varmap[op->getIn(0)];
      assignLogicalPieces(rvn1);
      fd->opSetOpcode(op,CPUI_COPY);		// This becomes a COPY
      if (op->getIn(1)->getOffset() == 0)	// Grabbing the low piece
	fd->opSetInput(op,rvn1->replaceLo,0);
      else
	fd->opSetInput(op,rvn1->replaceHi,0);	// Grabbing the high piece
      fd->opRemoveInput(op,1);
      break;
    case CPUI_INT_LEFT:
      if (rop->isLogicalInput)
	replaceLeftInput(rop);
      else
	replaceLeftTerminal(rop);
      break;
    case CPUI_INT_RIGHT:
    case CPUI_INT_SRIGHT:
      rvn1 = &varmap[op->getIn(0)];
      assignLogicalPieces(rvn1);
      if (op->getIn(1)->getOffset() == loSize * 8) {			// Shift of exactly loSize bytes
	fd->opSetOpcode(op,rop->opcode);				// is equivalent to an extension
	fd->opRemoveInput(op,1);
	fd->opSetInput(op,rvn1->replaceHi,0);				//    of the high part
      }
      else {
	PcodeOp *otherOp = fd->newOp(1,op->getAddr());
	Varnode *otherVn = fd->newUniqueOut(concatSize,otherOp);
	uintb remainShift = op->getIn(1)->getOffset() - loSize * 8;
	fd->opSetOpcode(otherOp,rop->opcode);			// Extension of high piece
	fd->opSetInput(otherOp,rvn1->replaceHi,0);		// Equivalent of INT_RIGHT by loSize * 8
	fd->opInsertBefore(otherOp,op);
	fd->opSetInput(op,otherVn,0);				// Original shift
	fd->opSetInput(op,fd->newConstant(4,remainShift),1);	//   now shifts any remaining bits
      }
      break;
    case CPUI_PIECE:
      replacePiece(rop);
      break;
    case CPUI_INT_ZEXT:
      replaceZext(rop);
      break;
    default:
      replaceOp(rop);
      break;
    }
  }

  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    if ((*iter).doDelete) {		// Marked for deletion
      fd->opDestroy((*iter).op);
    }
  }
}

bool SplitFlow::doTrace(void)

{ // Process worklist until its done
  if (worklist.empty())
    return false;		// Nothing to do
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
  return true;
}

SubfloatFlow::ReplaceVarnode *SubfloatFlow::setReplacement(Varnode *vn,bool &inworklist)

{ // Create and return a ReplaceVarnode associated with vn, if vn is suitable for replacement
  // Set inworklist to true if the varnode has not been in the worklist before
  // Return NULL if the vn is not suitable for replacement
  ReplaceVarnode *res;
  if (vn->isMark()) {		// Already seen before
    map<Varnode *,ReplaceVarnode>::iterator iter;
    iter = varmap.find(vn);
    res = &(*iter).second;
    inworklist = false;
    return res;
  }

  if (vn->isConstant()) {
    inworklist = false;
    return addConstant(vn);
  }

  if (vn->isFree())
    return (ReplaceVarnode *)0; // Abort

  if (vn->isAddrForce() && (vn->getSize() != precision))
    return (ReplaceVarnode *)0;

  if (vn->isTypeLock()) {
    int4 sz = vn->getType()->getSize();
    if (sz != precision)
      return (ReplaceVarnode *)0;
  }

  if (vn->isInput()) {		// Must be careful with inputs
    if (vn->getSize() != precision) return (ReplaceVarnode *)0;
  }

  res = & varmap[ vn ];
  vn->setMark();
  res->vn = vn;
  res->replacement = (Varnode *)0;
  res->def = (ReplaceOp *)0;
  inworklist = true;
  // Check if vn already represents the logical variable being traced
  if (vn->getSize() == precision) {
    inworklist = false;
    res->replacement = vn;
  }
  return res;
}

SubfloatFlow::ReplaceVarnode *SubfloatFlow::setReplacementNoFlow(Varnode *vn)

{ // Create and return a ReplaceVarnode associated with vn, where we assume -vn- is not going to change
  // and there will be no further logical flow through -vn-
  ReplaceVarnode *res;
  if (vn->isMark()) {		// Already seen before
    map<Varnode *,ReplaceVarnode>::iterator iter;
    iter = varmap.find(vn);
    res = &(*iter).second;
    return res;
  }

  if (!vn->isConstant()) {
    if (vn->isFree())		// If we have an unheritaged value
      return (ReplaceVarnode *)0; // Abort
  }

  res = &varmap[ vn ];
  vn->setMark();
  res->vn = vn;
  res->replacement = vn;	// NOTE: we set replacement as itself, even if it is a constant
  res->def = (ReplaceOp *)0;
  return res;
}

SubfloatFlow::ReplaceOp *SubfloatFlow::createOp(OpCode opc,int4 numparam,ReplaceVarnode *outrvn)

{ // Create record for replacement op, given its replacement varnode output
  if (outrvn->def != (ReplaceOp *)0)
    return outrvn->def;
  oplist.push_back(ReplaceOp());
  ReplaceOp *rop = &oplist.back();
  outrvn->def = rop;
  rop->op = outrvn->vn->getDef();
  rop->numparams = numparam;
  rop->opc = opc;
  rop->output = outrvn;

  return rop;
}

SubfloatFlow::ReplaceOp *SubfloatFlow::createOpDown(OpCode opc,int4 numparam,PcodeOp *op,ReplaceVarnode *inrvn,int4 slot)

{ // Create record for replacement op, given one of its input replacement varnodes
  oplist.push_back(ReplaceOp());
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

bool SubfloatFlow::traceForward(ReplaceVarnode *rvn)

{ // Try to trace logical variable through descendant varnodes
  // updating list/map of replace_ops and replace_varnodes
  // and the worklist
  ReplaceVarnode *rvn2;
  ReplaceOp *rop;
  PcodeOp *op;
  Varnode *outvn;
  int4 slot;
  bool inworklist;
  int4 dcount = 0;
  int4 hcount = 0;

  list<PcodeOp *>::const_iterator iter,enditer;
  iter = rvn->vn->beginDescend();
  enditer = rvn->vn->endDescend();
  while(iter != enditer) {
    op = *iter++;
    outvn = op->getOut();
    if ((outvn!=(Varnode *)0)&&(outvn->isMark()))
      continue;
    dcount += 1;		// Count this descendant
    slot = op->getSlot(rvn->vn);
    switch(op->code()) {
    case CPUI_COPY:
    case CPUI_FLOAT_CEIL:
    case CPUI_FLOAT_FLOOR:
    case CPUI_FLOAT_ROUND:
    case CPUI_FLOAT_NEG:
    case CPUI_FLOAT_ABS:
    case CPUI_FLOAT_SQRT:
    case CPUI_FLOAT_ADD:
    case CPUI_FLOAT_SUB:
    case CPUI_FLOAT_MULT:
    case CPUI_FLOAT_DIV:
    case CPUI_MULTIEQUAL:
      rop = createOpDown(op->code(),op->numInput(),op,rvn,slot);
      if (!createLink(rop,-1,outvn)) return false;
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_FLOAT_FLOAT2FLOAT:
      if (outvn->getSize() < precision)
	return false;
      addtopulllist(op,rvn);
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_FLOAT_EQUAL:
    case CPUI_FLOAT_NOTEQUAL:
    case CPUI_FLOAT_LESS:
    case CPUI_FLOAT_LESSEQUAL:
      rvn2 = setReplacement(op->getIn(1-slot),inworklist);
      if (rvn2 == (ReplaceVarnode *)0) return false;
      if (inworklist)
	worklist.push_back(rvn2);
      if (slot == 0)
	addtocomplist(rvn,rvn2,op);
      else
	addtocomplist(rvn2,rvn,op);
      hcount += 1;		// Dealt with this descendant
      break;
    case CPUI_FLOAT_TRUNC:
    case CPUI_FLOAT_NAN:
      addtopulllist(op,rvn);
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

bool SubfloatFlow::traceBackward(ReplaceVarnode *rvn)

{ // Trace backward through defining op one level
  // Update worklist, varmap, and oplist
  // return false if the trace is aborted
  PcodeOp *op = rvn->vn->getDef();
  if (op == (PcodeOp *)0) return true; // If vn is input
  ReplaceOp *rop;

  switch(op->code()) {
  case CPUI_COPY:
  case CPUI_FLOAT_CEIL:
  case CPUI_FLOAT_FLOOR:
  case CPUI_FLOAT_ROUND:
  case CPUI_FLOAT_NEG:
  case CPUI_FLOAT_ABS:
  case CPUI_FLOAT_SQRT:
  case CPUI_FLOAT_ADD:
  case CPUI_FLOAT_SUB:
  case CPUI_FLOAT_MULT:
  case CPUI_FLOAT_DIV:
  case CPUI_MULTIEQUAL:
    rop = createOp(op->code(),op->numInput(),rvn);
    for(int4 i=0;i<op->numInput();++i)
      if (!createLink(rop,i,op->getIn(i))) // Same inputs and mask
	return false;
    return true;
  case CPUI_FLOAT_INT2FLOAT:
    if (addtopushlist(op,rvn))
      return true;
    break;
  case CPUI_FLOAT_FLOAT2FLOAT:
    //    if ((op->getIn(0)->getSize() <= precision)||op->getIn(0)->isConstant())
    if (addtopushlist(op,rvn))
      return true;
    break;
  default:
    break;			// Everything else we abort
  }
  
  return false;
}

bool SubfloatFlow::createLink(ReplaceOp *rop,int4 slot,Varnode *vn)

{ // Add a new varnode (and the edge which traced to it) to the worklist
  bool inworklist;
  ReplaceVarnode *rep = setReplacement(vn,inworklist);
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

SubfloatFlow::ReplaceVarnode *SubfloatFlow::addConstant(Varnode *vn)

{ // Add a constant to the replacement tree
  const FloatFormat *form2 = fd->getArch()->translate->getFloatFormat(vn->getSize());
  if (form2 == (const FloatFormat *)0)
    return (ReplaceVarnode *)0;	// Unsupported constant format
  newvarlist.push_back(ReplaceVarnode());
  ReplaceVarnode *res = &newvarlist.back();
  res->vn = vn;
  res->replacement = (Varnode *)0;
  res->def = (ReplaceOp *)0;
  return res;
}

void SubfloatFlow::addtopulllist(PcodeOp *pullop,ReplaceVarnode *rvn)

{ // Exit point of the logical flow
  // Add a reference to the logical variable getting pulled
  // out of container flow
  pulllist.push_back(PulloutRecord());
  pulllist.back().pullop = pullop;	// Operation pulling the variable out
  if (pullop->code() == CPUI_FLOAT_FLOAT2FLOAT) {
    if (pullop->getOut()->getSize() == precision)
      pulllist.back().opc = CPUI_COPY;
    else
      pulllist.back().opc = CPUI_FLOAT_FLOAT2FLOAT;
  }
  else
    pulllist.back().opc = pullop->code();
  pulllist.back().input = rvn;	// Point in container flow for pull
}

bool SubfloatFlow::addtopushlist(PcodeOp *pushop,ReplaceVarnode *rvn)

{				// Entry point of the logical flow
  Varnode *invn = pushop->getIn(0);
  OpCode opc = pushop->code();
  if (opc == CPUI_FLOAT_FLOAT2FLOAT) {
    if ((invn->getSize() == precision)||invn->isConstant())
      opc = CPUI_COPY;
  }
  ReplaceOp *rop = createOp(opc,1,rvn);
  if ((opc == CPUI_FLOAT_INT2FLOAT)||
      ((opc == CPUI_FLOAT_FLOAT2FLOAT)&&(invn->getSize() > precision))) {
    // We do not want to create a new input replacement, but want to keep the old
    ReplaceVarnode *rvn = setReplacementNoFlow(invn);
    if (rvn == (ReplaceVarnode *)0)
      return false;
    rop->input.push_back(rvn);
    return true;
  }
  return createLink(rop,0,invn);
}

void SubfloatFlow::addtocomplist(ReplaceVarnode *in1,ReplaceVarnode *in2,PcodeOp *op)

{
  complist.push_back(CompareRecord());
  complist.back().in1 = in1;
  complist.back().in2 = in2;
  complist.back().compop = op;
}

void SubfloatFlow::replaceInput(ReplaceVarnode *rvn)

{ // Replace ORIGINAL input in the subgraph with temporaries, so
  // we don't get overlapping varnode errors
  Varnode *newvn = fd->newUnique(rvn->vn->getSize());
  newvn = fd->setInputVarnode(newvn);
  fd->totalReplace(rvn->vn,newvn);
  fd->deleteVarnode(rvn->vn);
  rvn->vn = newvn;
}

Varnode *SubfloatFlow::getReplaceVarnode(ReplaceVarnode *rvn)

{ // Get the actual varnode associated with a replacement varnode
  // either by recycling a previously built one or creating
  // one on the spot
  if (rvn->replacement != (Varnode *)0) {
    if (!rvn->replacement->isConstant())
      return rvn->replacement;
    // if replacement is a constant (this was generated in setReplacementNoFlow) create copy of original constant
    return fd->newConstant(rvn->replacement->getSize(),rvn->replacement->getOffset());
  }
  if (rvn->vn->isConstant()) { // A constant
    const FloatFormat *formin = fd->getArch()->translate->getFloatFormat(rvn->vn->getSize());
    // addConstant makes sure that formin is not null
    return fd->newConstant(precision,format->convertEncoding(rvn->vn->getOffset(),formin));
  }

  bool isinput = rvn->vn->isInput();
  if (isinput) {
    Address addr = rvn->vn->getAddr();
    // This is sort of fundemental problem:  how do we represent an input variable that
    // is lower precision than its storage location
    // Here we artificially truncate the location, which isn't realistic
    if (addr.isBigEndian())
      addr = addr + (rvn->vn->getSize() - precision);
    replaceInput(rvn);	// Replace input to avoid overlap errors
    rvn->replacement = fd->newVarnode(precision,addr);
  }
  else
    rvn->replacement = fd->newUnique(precision);
  if (isinput)	// Is this an input
    rvn->replacement = fd->setInputVarnode(rvn->replacement);
  return rvn->replacement;
}

bool SubfloatFlow::processNextWork(void)

{
  ReplaceVarnode *rvn = worklist.back();

  worklist.pop_back();

  if (!traceBackward(rvn)) return false;
  return traceForward(rvn);
}

SubfloatFlow::SubfloatFlow(Funcdata *f,Varnode *root,int4 prec)

{
  fd = f;
  precision = prec;
  format = fd->getArch()->translate->getFloatFormat(precision);
  createLink((ReplaceOp *)0,0,root);
}

bool SubfloatFlow::doTrace(void)

{ // Process worklist until its done
  bool retval = false;
  if ((fd != (Funcdata *)0)&&
      (format != (const FloatFormat *)0)) {
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
  if (pulllist.empty()&&complist.empty()) return false;
  return true;
}

void SubfloatFlow::doReplacement(void)

{ // Create the actual replacement data-flow with -fd-
  list<ReplaceOp>::iterator iter;

  // Define all the outputs first
  for(iter=oplist.begin();iter!=oplist.end();++iter) {
    PcodeOp *newop = fd->newOp((*iter).numparams,(*iter).op->getAddr());
    (*iter).replacement = newop;
    fd->opSetOpcode(newop,(*iter).opc);
    ReplaceVarnode *rout = (*iter).output;
    if (rout != (ReplaceVarnode *)0) {
      if (rout->replacement == (Varnode *)0)
	rout->replacement = fd->newUniqueOut(precision,newop);
      else
	fd->opSetOutput(newop,rout->replacement);
    }
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
  list<PulloutRecord>::iterator piter;
  for(piter=pulllist.begin();piter!=pulllist.end();++piter) {
    PcodeOp *pullop = (*piter).pullop;
    while(pullop->numInput() > 1)
      fd->opRemoveInput(pullop,pullop->numInput()-1);
    fd->opSetInput(pullop,getReplaceVarnode((*piter).input),0);
    if (pullop->code() != (*piter).opc)
      fd->opSetOpcode(pullop,(*piter).opc);
  }

  list<CompareRecord>::iterator citer;
  for(citer=complist.begin();citer!=complist.end();++citer) {
    PcodeOp *op = (*citer).compop;
    fd->opSetInput(op,getReplaceVarnode((*citer).in1),0);
    fd->opSetInput(op,getReplaceVarnode((*citer).in2),1);
  }
}


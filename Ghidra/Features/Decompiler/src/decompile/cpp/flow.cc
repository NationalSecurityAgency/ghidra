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
#include "flow.hh"

/// Prepare for tracing flow for a new function.
/// The Funcdata object and references to its internal containers must be explicitly given.
/// \param d is the new function to trace
/// \param o is the internal p-code container for the function
/// \param b is the internal basic block container
/// \param q is the internal container of call sites
FlowInfo::FlowInfo(Funcdata &d,PcodeOpBank &o,BlockGraph &b,vector<FuncCallSpecs *> &q) :
  data(d), obank(o), bblocks(b), qlst(q),
  baddr(d.getAddress().getSpace(),0),
  eaddr(d.getAddress().getSpace(),~((uintb)0)),
  minaddr(d.getAddress()),
  maxaddr(d.getAddress())

{
  glb = data.getArch();
  flags = 0;
  emitter.setFuncdata(&d);
  inline_head = (Funcdata *)0;
  inline_recursion = (set<Address> *)0;
  insn_count = 0;
  insn_max = ~((uint4)0);
  flowoverride_present = data.getOverride().hasFlowOverride();
}

/// Prepare a new flow cloned from an existing flow.
/// Configuration from the existing flow is copied, but the actual PcodeOps must already be
/// cloned within the new function.
/// \param d is the new function that has been cloned
/// \param o is the internal p-code container for the function
/// \param b is the internal basic block container
/// \param q is the internal container of call sites
/// \param op2 is the existing flow
FlowInfo::FlowInfo(Funcdata &d,PcodeOpBank &o,BlockGraph &b,vector<FuncCallSpecs *> &q,const FlowInfo *op2) :
  data(d), obank(o), bblocks(b), qlst(q),
  baddr(op2->baddr),
  eaddr(op2->eaddr),
  minaddr(d.getAddress()),
  maxaddr(d.getAddress())

{
  glb = data.getArch();
  flags = op2->flags;
  emitter.setFuncdata(&d);
  unprocessed = op2->unprocessed; // Clone the flow address information
  addrlist = op2->addrlist;
  visited = op2->visited;
  inline_head = op2->inline_head;
  if (inline_head != (Funcdata *)0) {
    inline_base = op2->inline_base;
    inline_recursion = &inline_base;
  }
  else
    inline_recursion = (set<Address> *)0;
  insn_count = op2->insn_count;
  insn_max = op2->insn_max;
  flowoverride_present = data.getOverride().hasFlowOverride();
}

void FlowInfo::clearProperties(void)

{
  flags &= ~((uint4)(unimplemented_present|baddata_present|outofbounds_present));
  insn_count = 0;
}

/// For efficiency, this method assumes the given op can actually fall-thru.
/// \param op is the given PcodeOp
/// \return the PcodeOp that fall-thru flow would reach (or NULL if there is no possible p-code op)
PcodeOp *FlowInfo::fallthruOp(PcodeOp *op) const

{
  PcodeOp *retop;
  list<PcodeOp *>::const_iterator iter = op->getInsertIter();
  ++iter;
  if (iter != obank.endDead()) {
    retop = *iter;
    if (!retop->isInstructionStart()) // If within same instruction
      return retop;		// Then this is the fall thru
  }
  // Find address of instruction containing this op
  map<Address,VisitStat>::const_iterator miter;
  miter = visited.upper_bound(op->getAddr());
  if (miter == visited.begin()) return (PcodeOp *)0;
  --miter;
  if ((*miter).first + (*miter).second.size <= op->getAddr())
    return (PcodeOp *)0;
  return target( (*miter).first + (*miter).second.size);
}

/// The first p-code op associated with the machine instruction at the
/// given address is returned.  If the instruction generated no p-code,
/// an attempt is made to fall-thru to the next instruction.
/// If no p-code op is ultimately found, an exception is thrown.
/// \param addr is the given address of the instruction
/// \return the targetted p-code op
PcodeOp *FlowInfo::target(const Address &addr) const

{
  map<Address,VisitStat>::const_iterator iter;

  iter = visited.find(addr);
  while(iter != visited.end()) {
    const SeqNum &seq( (*iter).second.seqnum );
    if (!seq.getAddr().isInvalid()) {
      PcodeOp *retop = obank.findOp(seq);
      if (retop != (PcodeOp *)0)
	return retop;
      break;
    }
    // Visit fall thru address in case of no-op
    iter = visited.find( (*iter).first + (*iter).second.size );
  }
  ostringstream errmsg;
  errmsg << "Could not find op at target address: (";
  errmsg << addr.getSpace()->getName() << ',';
  addr.printRaw(errmsg);
  errmsg << ')';
  throw LowlevelError(errmsg.str());
}

/// \brief Generate the target PcodeOp for a relative branch
///
/// Assuming the given op is a relative branch, find the existing target PcodeOp if the
/// branch is properly internal, or return the fall-thru address in \b res (which may not have
/// PcodeOps generated for it yet) if the relative branch is really a branch to the next instruction.
/// Otherwise an exception is thrown.
/// \param op is the given branching p-code op
/// \param res is a reference to the fall-thru address being passed back
/// \return the target PcodeOp or NULL if the fall-thru address is passed back instead
PcodeOp *FlowInfo::findRelTarget(PcodeOp *op,Address &res) const

{
  const Address &addr(op->getIn(0)->getAddr());
  uintm id = op->getTime() + addr.getOffset();
  SeqNum seqnum(op->getAddr(),id);
  PcodeOp *retop = obank.findOp(seqnum);
  if (retop != (PcodeOp *)0)	// Is this a "properly" internal branch
    return retop;

  // Now we check if the relative branch is really to the next instruction
  SeqNum seqnum1(op->getAddr(),id-1);
  retop = obank.findOp(seqnum1); // We go back one sequence number
  if (retop != (PcodeOp *)0) {
    // If the PcodeOp exists here then branch was indeed to next instruction
    map<Address,VisitStat>::const_iterator miter;
    miter = visited.upper_bound(retop->getAddr());
    if (miter != visited.begin()) {
      --miter;
      res = (*miter).first + (*miter).second.size;
      if (op->getAddr() < res)
	return (PcodeOp *)0;	// Indicate that res has the fallthru address
    }
  }
  ostringstream errmsg;
  errmsg << "Bad relative branch at instruction : (";
  errmsg << op->getAddr().getSpace()->getName() << ',';
  op->getAddr().printRaw(errmsg);
  errmsg << ')';
  throw LowlevelError(errmsg.str());
}

/// The \e code \e reference passed as the first parameter to the branch
/// is examined, and the p-code op it refers to is returned.
/// The reference may be a normal direct address or a relative offset.
/// If no target p-code can be found, an exception is thrown.
/// \param op is the given branch op
/// \return the targetted p-code op
PcodeOp *FlowInfo::branchTarget(PcodeOp *op) const

{
  const Address &addr(op->getIn(0)->getAddr());
  if (addr.isConstant()) {	// This is a relative sequence number
    Address res;
    PcodeOp *retop = findRelTarget(op,res);
    if (retop != (PcodeOp *)0)
      return retop;
    return target(res);
  }
  return target(addr);	// Otherwise a normal address target
}

/// Check to see if the new target has been seen before. Otherwise
/// add it to the list of addresses that need to be processed.
/// Also check range bounds and update basic block information.
/// \param from is the PcodeOp issuing the branch
/// \param to is the target address of the branch
void FlowInfo::newAddress(PcodeOp *from,const Address &to)

{
  if ((to < baddr)||(eaddr < to)) {
    handleOutOfBounds(from->getAddr(),to);
    unprocessed.push_back(to);
    return;
  }

  if (seenInstruction(to)) {	// If we have seen this address before
    PcodeOp *op = target(to);
    data.opMarkStartBasic(op);
    return;
  }
  addrlist.push_back(to);
}

/// \brief Delete any remaining ops at the end of the instruction
///
/// (because they have been predetermined to be dead)
/// \param oiter is the point within the raw p-code list where deletion should start
void FlowInfo::deleteRemainingOps(list<PcodeOp *>::const_iterator oiter)

{
  while(oiter != obank.endDead()) {
    PcodeOp *op = *oiter;
    ++oiter;
    data.opDestroyRaw(op);
  }
}

/// \brief Analyze control-flow within p-code for a single instruction
///
/// Walk through the raw p-code (from the given iterator to the end of the list)
/// looking for control flow operations (BRANCH,CBRANCH,BRANCHIND,CALL,CALLIND,RETURN)
/// and add appropriate annotations (startbasic, callspecs, new addresses).
/// As it iterates through the p-code, the method maintains a reference to a boolean
/// indicating whether the current op is the start of a basic block. This value
/// persists across calls. The method also passes back a boolean value indicating whether
/// the instruction as a whole has fall-thru flow.
/// \param oiter is the given iterator starting the list of p-code ops
/// \param startbasic is the reference holding whether the current op starts a basic block
/// \param isfallthru passes back if the instruction has fall-thru flow
/// \param fc if the p-code is generated from an \e injection, this holds the reference to the injecting sub-function
/// \return the last processed PcodeOp (or NULL if there were no ops in the instruction)
PcodeOp *FlowInfo::xrefControlFlow(list<PcodeOp *>::const_iterator oiter,bool &startbasic,bool &isfallthru,FuncCallSpecs *fc)

{
  PcodeOp *op = (PcodeOp *)0;
  isfallthru = false;
  uintm maxtime=0;	// Deepest internal relative branch
  while(oiter != obank.endDead()) {
    op = *oiter++;
    if (startbasic) {
      data.opMarkStartBasic(op);
      startbasic = false;
    }
    switch(op->code()) {
    case CPUI_CBRANCH:
    {
	const Address &destaddr( op->getIn(0)->getAddr() );
	if (destaddr.isConstant()) {
	  Address fallThruAddr;
	  PcodeOp *destop = findRelTarget(op,fallThruAddr);
	  if (destop != (PcodeOp *)0) {
	    data.opMarkStartBasic(destop);	// Make sure the target op is a basic block start
	    uintm newtime = destop->getTime();
	    if (newtime > maxtime)
	      maxtime = newtime;
	  }
	  else
	    isfallthru = true;		// Relative branch is to end of instruction
	}
	else
	  newAddress(op,destaddr); // Generate branch address
	startbasic = true;
    }
    break;
    case CPUI_BRANCH:
      {
	const Address &destaddr( op->getIn(0)->getAddr() );
	if (destaddr.isConstant()) {
	  Address fallThruAddr;
	  PcodeOp *destop = findRelTarget(op,fallThruAddr);
	  if (destop != (PcodeOp *)0) {
	    data.opMarkStartBasic(destop);	// Make sure the target op is a basic block start
	    uintm newtime = destop->getTime();
	    if (newtime > maxtime)
	      maxtime = newtime;
	  }
	  else
	    isfallthru = true;		// Relative branch is to end of instruction
	}
	else
	  newAddress(op,destaddr); // Generate branch address
	if (op->getTime() >= maxtime) {
	  deleteRemainingOps(oiter);
	  oiter = obank.endDead();
	}
	startbasic = true;
      }
      break;
    case CPUI_BRANCHIND:
      tablelist.push_back(op);	// Put off trying to recover the table
      if (op->getTime() >= maxtime) {
	deleteRemainingOps(oiter);
	oiter = obank.endDead();
      }
      startbasic = true;
      break;
    case CPUI_RETURN:
      if (op->getTime() >= maxtime) {
	deleteRemainingOps(oiter);
	oiter = obank.endDead();
      }
      startbasic = true;
      break;
    case CPUI_CALL:
      if (setupCallSpecs(op,fc))
	--oiter;		// Backup one op, to pickup halt
      break;
    case CPUI_CALLIND:
      if (setupCallindSpecs(op,true,fc))
	--oiter;		// Backup one op, to pickup halt
      break;
    case CPUI_CALLOTHER:
    {
      InjectedUserOp *userop = dynamic_cast<InjectedUserOp *>(glb->userops.getOp(op->getIn(0)->getOffset()));
      if (userop != (InjectedUserOp *)0)
	injectlist.push_back(op);
      break;
    }
    default:
      break;
    }
  }
  if (isfallthru)		// We have seen an explicit relative branch to end of instruction
    startbasic = true;		// So we know next instruction starts a basicblock
  else {			// If we haven't seen a relative branch, calculate fallthru by looking at last op
    if (op == (PcodeOp *)0)
      isfallthru = true;	// No ops at all, mean a fallthru
    else {
      switch(op->code()) {
      case CPUI_BRANCH:
      case CPUI_BRANCHIND:
      case CPUI_RETURN:
	break;			// If the last instruction is a branch, then no fallthru
      default:
	isfallthru = true;	// otherwise it is a fallthru
	break;
      }
    }
  }
  return op;
}

/// \brief Generate p-code for a single machine instruction and process discovered flow information
///
/// P-code is generated (to the raw \e dead list in PcodeOpBank). Errors for unimplemented
/// instructions or inaccessible data are handled.  The p-code is examined for control-flow,
/// and annotations are made.  The set of visited instructions and the set of
/// addresses still needing to be processed are updated.
/// \param curaddr is the address of the instruction to process
/// \param startbasic indicates of the instruction starts a basic block and passes back whether the next instruction does
/// \return \b true if the processed instruction has a fall-thru flow
bool FlowInfo::processInstruction(const Address &curaddr,bool &startbasic)

{
  bool emptyflag;
  bool isfallthru = true;
  //  JumpTable *jt;
  list<PcodeOp *>::const_iterator oiter;
  int4 step;
  uint4 flowoverride;

  if (insn_count >= insn_max) {
    if ((flags & error_toomanyinstructions)!=0)
      throw LowlevelError("Flow exceeded maximum allowable instructions");
    else {
      step = 1;
      artificialHalt(curaddr,PcodeOp::badinstruction);
      data.warning("Too many instructions -- Truncating flow here",curaddr);
      if (!hasTooManyInstructions()) {
	flags |= toomanyinstructions_present;
	data.warningHeader("Exceeded maximum allowable instructions: Some flow is truncated");
      }
    }
  }
  insn_count += 1;

  if (obank.empty())
    emptyflag = true;
  else {
    emptyflag = false;
    oiter = obank.endDead();
    --oiter;
  }
  if (flowoverride_present)
    flowoverride = data.getOverride().getFlowOverride(curaddr);
  else
    flowoverride = Override::NONE;

  try {
    step = glb->translate->oneInstruction(emitter,curaddr); // Generate ops for instruction
  }
  catch(UnimplError &err) {	// Instruction is unimplemented
    if ((flags & ignore_unimplemented)!=0) {
      step = err.instruction_length;
      if (!hasUnimplemented()) {
	flags |= unimplemented_present;
	data.warningHeader("Control flow ignored unimplemented instructions");
      }
    }
    else if ((flags & error_unimplemented)!=0)
      throw err;		// rethrow
    else {
      // Add infinite loop instruction
      step = 1;			// Pretend size 1
      artificialHalt(curaddr,PcodeOp::unimplemented);
      data.warning("Unimplemented instruction - Truncating control flow here",curaddr);
      if (!hasUnimplemented()) {
	flags |= unimplemented_present;
	data.warningHeader("Control flow encountered unimplemented instructions");
      }
    }
  }
  catch(BadDataError &err) {
    if ((flags & error_unimplemented)!=0)
      throw err;		// rethrow
    else {
      // Add infinite loop instruction
      step = 1;			// Pretend size 1
      artificialHalt(curaddr,PcodeOp::badinstruction);
      data.warning("Bad instruction - Truncating control flow here",curaddr);
      if (!hasBadData()) {
	flags |= baddata_present;
	data.warningHeader("Control flow encountered bad instruction data");
      }
    }
  }
  VisitStat &stat(visited[curaddr]); // Mark that we visited this instruction
  stat.size = step;		// Record size of instruction

  if (curaddr < minaddr)	// Update minimum and maximum address
    minaddr = curaddr;
  if (maxaddr < curaddr+step)	// Keep track of biggest and smallest address
    maxaddr = curaddr+step;

  if (emptyflag)		// Make sure oiter points at first new op
    oiter = obank.beginDead();
  else
    ++oiter;
  
  if (oiter != obank.endDead()) {
    stat.seqnum = (*oiter)->getSeqNum();
    data.opMarkStartInstruction(*oiter); // Mark the first op in the instruction
    if (flowoverride != Override::NONE)
      data.overrideFlow(curaddr,flowoverride);
    xrefControlFlow(oiter,startbasic,isfallthru,(FuncCallSpecs *)0);
  }

  if (isfallthru)
    addrlist.push_back(curaddr+step);
  return isfallthru;
}

/// From the address at the top of the \b addrlist stack
/// Figure out how far we could follow fall-thru instructions
/// before hitting something we've already seen
/// \param bound passes back the first address encountered that we have already seen
/// \return \b false if the address has already been visited
bool FlowInfo::setFallthruBound(Address &bound)

{
  map<Address,VisitStat>::const_iterator iter;
  const Address &addr( addrlist.back() );

  iter = visited.upper_bound(addr); // First range greater than addr
  if (iter!=visited.begin()) {
    --iter;			// Last range less than or equal to us
    if (addr == (*iter).first) { // If we have already visited this address
      PcodeOp *op = target(addr); // But make sure the address
      data.opMarkStartBasic(op); // starts a basic block
      addrlist.pop_back();	// Throw it away
      return false;
    }
    if (addr < (*iter).first + (*iter).second.size)
      reinterpreted(addr);
    ++iter;
  }
  if (iter!=visited.end())	// Whats the maximum distance we can go
    bound = (*iter).first;
  else
    bound = eaddr;
  return true;
}

/// \brief Generate warning message or throw exception for given flow that is out of bounds
///
/// \param fromaddr is the source address of the flow (presumably in bounds)
/// \param toaddr is the given destination address that is out of bounds
void FlowInfo::handleOutOfBounds(const Address &fromaddr,const Address &toaddr)

{
  if ((flags&ignore_outofbounds)==0) { // Should we throw an error for out of bounds
    ostringstream errmsg;
    errmsg << "Function flow out of bounds: ";
    errmsg << fromaddr.getShortcut();
    fromaddr.printRaw(errmsg);
    errmsg << " flows to ";
    errmsg << toaddr.getShortcut();
    toaddr.printRaw(errmsg);
    if ((flags&error_outofbounds)==0) {
      data.warning(errmsg.str(),toaddr);
      if (!hasOutOfBounds()) {
	flags |= outofbounds_present;
	data.warningHeader("Function flows out of bounds");
      }
    }
    else
      throw LowlevelError(errmsg.str());
  }
}

/// The address at the top stack that still needs processing is popped.
/// P-code is generated for instructions starting at this address until
/// one no longer has fall-thru flow (or some other error occurs).
void FlowInfo::fallthru(void)

{
  Address bound;

  if (!setFallthruBound(bound)) return;

  Address curaddr;
  bool startbasic = true;
  bool fallthruflag;
  
  for(;;) {
    curaddr = addrlist.back();
    addrlist.pop_back();
    fallthruflag = processInstruction(curaddr,startbasic);
    if (!fallthruflag) break;
    if (addrlist.empty()) break;
    if (bound <= addrlist.back()) {
      if (bound == eaddr) {
	handleOutOfBounds(eaddr,addrlist.back());
	unprocessed.push_back(addrlist.back());
	addrlist.pop_back();
	return;
      }
      if (bound == addrlist.back()) { // Hit the bound exactly
	if (startbasic) {
	  PcodeOp *op = target(addrlist.back());
	  data.opMarkStartBasic(op);
	}
	addrlist.pop_back();
	break;
      }
      if (!setFallthruBound(bound)) return; // Reset bound
    }
  }
}

/// An \b artificial \b halt, is a special form of RETURN op.
/// The op is annotated with the desired \e type of artificial halt.
///   - Bad instruction
///   - Unimplemented instruction
///   - Missing/truncated instruction
///   - (Previous) call that never returns
///
/// \param addr is the target address for the new p-code op
/// \param flag is the desired \e type
/// \return the new p-code op
PcodeOp *FlowInfo::artificialHalt(const Address &addr,uint4 flag)

{
  PcodeOp *haltop = data.newOp(1,addr);
  data.opSetOpcode(haltop,CPUI_RETURN);
  data.opSetInput(haltop,data.newConstant(4,1),0);
  if (flag != 0)
    data.opMarkHalt(haltop,flag); // What kind of halt
  return haltop;
}

/// A set of bytes is \b reinterpreted if there are at least two
/// different interpretations of the bytes as instructions.
/// \param addr is the address of a byte previously interpreted as (the interior of) an instruction
void FlowInfo::reinterpreted(const Address &addr)

{
  map<Address,VisitStat>::const_iterator iter;

  iter = visited.upper_bound(addr);
  if (iter==visited.begin()) return; // Should never happen
  --iter;
  const Address &addr2( (*iter).first );
  ostringstream s;

  s << "Instruction at (" << addr.getSpace()->getName() << ',';
  addr.printRaw(s);
  s << ") overlaps instruction at (" << addr2.getSpace()->getName() << ',';
  addr2.printRaw(s);
  s << ')' << endl;
  if ((flags & error_reinterpreted)!=0)
    throw LowlevelError(s.str());

  if ((flags & reinterpreted_present)==0) {
    flags |= reinterpreted_present;
    data.warningHeader(s.str());
  }
}

/// \brief Check for modifications to flow at a call site given the recovered FuncCallSpecs
///
/// The sub-function may be in-lined or never return.
/// \param fspecs is the given call site
/// \return \b true if the sub-function never returns
bool FlowInfo::checkForFlowModification(FuncCallSpecs &fspecs)

{
  if (fspecs.isInline())
    injectlist.push_back(fspecs.getOp());
  if (fspecs.isNoReturn()) {
    PcodeOp *op = fspecs.getOp();
    PcodeOp *haltop = artificialHalt(op->getAddr(),PcodeOp::noreturn);
    data.opDeadInsertAfter(haltop,op);
    if (!fspecs.isInline())
      data.warning("Subroutine does not return",op->getAddr());
    return true;
  }

  return false;
}

/// If there is an explicit target address for the given call site,
/// attempt to look up the function and adjust information in the FuncCallSpecs call site object.
/// \param fspecs is the call site object
void FlowInfo::queryCall(FuncCallSpecs &fspecs)

{
  if (!fspecs.getEntryAddress().isInvalid()) { // If this is a direct call
    Funcdata *otherfunc = data.getScopeLocal()->getParent()->queryFunction( fspecs.getEntryAddress() );
    if (otherfunc != (Funcdata *)0) {
      fspecs.setFuncdata(otherfunc); // Associate the symbol with the callsite
      if (!fspecs.hasModel()) {	// If the prototype was not overridden
	fspecs.copyFlowEffects(otherfunc->getFuncProto());	// Take the symbols's prototype
	// If the callsite is applying just the standard prototype from the symbol,
	// this postpones the full copy of the prototype until ActionDefaultParams
	// Which lets "last second" changes come in, between when the function is first walked and
	// when it is finally decompiled
      }
    }
  }
}

/// The new FuncCallSpecs object is created and initialized based on
/// the CALL op at the site and any matching function in the symbol table.
/// Any overriding prototype or control-flow is examined and applied.
/// \param op is the given CALL op
/// \param fc is non-NULL if \e injection is in progress and a cycle check needs to be made
/// \return \b true if it is discovered the sub-function never returns
bool FlowInfo::setupCallSpecs(PcodeOp *op,FuncCallSpecs *fc)

{
  FuncCallSpecs *res;
  res = new FuncCallSpecs(op);
  data.opSetInput(op,data.newVarnodeCallSpecs(res),0);
  qlst.push_back(res);

  data.getOverride().applyPrototype(data,*res);
  queryCall(*res);
  if (fc != (FuncCallSpecs *)0) {	// If we are already in the midst of an injection
    if (fc->getEntryAddress() == res->getEntryAddress())
      res->cancelInjectId();		// Don't allow recursion
  }
  return checkForFlowModification(*res);
}

/// \brief Set up the FuncCallSpecs object for a new indirect call site
///
/// The new FuncCallSpecs object is created and initialized based on
/// the CALLIND op at the site. Any overriding prototype or control-flow may be examined and applied.
/// \param op is the given CALLIND op
/// \param tryoverride is \b true is overrides should be applied for the call site
/// \param fc is non-NULL if \e injection is in progress and a cycle check needs to be made
/// \return \b true if it is discovered the sub-function never returns
bool FlowInfo::setupCallindSpecs(PcodeOp *op,bool tryoverride,FuncCallSpecs *fc)

{
  FuncCallSpecs *res;
  res = new FuncCallSpecs(op);
  qlst.push_back(res);

  if (tryoverride) {
    data.getOverride().applyIndirect(data,*res);
    data.getOverride().applyPrototype(data,*res);
  }
  queryCall(*res);
  if (fc != (FuncCallSpecs *)0) {
    if (fc->getEntryAddress() == res->getEntryAddress()) {
      res->cancelInjectId();
      res->setAddress(Address()); // Cancel any indirect override
    }
  }

  if (!res->getEntryAddress().isInvalid()) {	// If we are overridden to a direct call
    // Change indirect pcode call into a normal pcode call
    data.opSetOpcode(op,CPUI_CALL); // Set normal opcode
    data.opSetInput(op,data.newVarnodeCallSpecs(res),0);
  }
  return checkForFlowModification(*res);
}

/// \param op is the BRANCHIND operation to convert
/// \param failuremode is a code indicating the type of failure when trying to recover the jump table
void FlowInfo::truncateIndirectJump(PcodeOp *op,int4 failuremode)

{
  data.opSetOpcode(op,CPUI_CALLIND); // Turn jump into call
  bool tryoverride = (failuremode == 2);
  setupCallindSpecs(op,tryoverride,(FuncCallSpecs *)0);
  data.getCallSpecs(op)->setBadJumpTable(true);

  // Create an artificial return
  PcodeOp *truncop = artificialHalt(op->getAddr(),0);
  data.opDeadInsertAfter(truncop,op);

  data.warning("Treating indirect jump as call",op->getAddr());
}

/// \brief Test if the given p-code op is a member of an array
///
/// \param array is the array of p-code ops to search
/// \param op is the given p-code op to search for
/// \return \b true if the op is a member of the array
bool FlowInfo::isInArray(vector<PcodeOp *> &array,PcodeOp *op)

{
  for(int4 i=0;i<array.size();++i) {
    if (array[i] == op) return true;
  }
  return false;
}

void FlowInfo::generateOps(void)

{
  vector<PcodeOp *> notreached;	// indirect ops that are not reachable
  int4 notreachcnt = 0;
  clearProperties();
  addrlist.push_back(data.getAddress());
  while(!addrlist.empty())	// Recovering as much as possible except jumptables
    fallthru();
  do {
    bool collapsed_jumptable = false;
    while(!tablelist.empty()) {	// For each jumptable found
      PcodeOp *op = tablelist.back();
      tablelist.pop_back();
      int4 failuremode;
      JumpTable *jt = data.recoverJumpTable(op,this,failuremode); // Recover it
      if (jt == (JumpTable *)0) { // Could not recover jumptable
	if ((failuremode == 3) && (!tablelist.empty()) && (!isInArray(notreached,op))) {
	   // If the indirect op was not reachable with current flow AND there is more flow to generate,
	  //     AND we haven't tried to recover this table before
	  notreached.push_back(op); // Save this op so we can try to recovery table again later
	}
	else if (!isFlowForInline())	// Unless this flow is being inlined for something else
	  truncateIndirectJump(op,failuremode); // Treat the indirect jump as a call
      }
      else {
	int4 num = jt->numEntries();
	for(int4 i=0;i<num;++i)
	  newAddress(op,jt->getAddressByIndex(i));
	if (jt->isPossibleMultistage())
	  collapsed_jumptable = true;
	while(!addrlist.empty())	// Try to fill in as much more as possible
	  fallthru();
      }
    }
    
    checkContainedCall();	// Check for PIC constructions
    if (collapsed_jumptable)
      checkMultistageJumptables();
    while(notreachcnt < notreached.size()) {
      tablelist.push_back(notreached[notreachcnt]);
      notreachcnt += 1;
    }
    if (hasInject())
      injectPcode();
  } while(!tablelist.empty());	// Inlining or multistage may have added new indirect branches
}

void FlowInfo::generateBlocks(void)

{
  fillinBranchStubs();
  collectEdges();
  splitBasic();		// Split ops up into basic blocks
  connectBasic();		// Generate edges between basic blocks
  if (bblocks.getSize()!=0) {
    FlowBlock *startblock = bblocks.getBlock(0);
    if (startblock->sizeIn() != 0) { // Make sure the entry block has no incoming edges

      // If it does we create a new entry block that flows into the old entry block
      BlockBasic *newfront = bblocks.newBlockBasic(&data);
      bblocks.addEdge(newfront,startblock);
      bblocks.setStartBlock(newfront);
      data.setBasicBlockRange(newfront, data.getAddress(), data.getAddress());
    }
  }

  if (hasPossibleUnreachable())
    data.removeUnreachableBlocks(false,true);
}

/// In the case where additional flow is truncated, run through the list of
/// pending addresses, and if they don't have a p-code generated for them,
/// add the Address to the \b unprocessed array.
void FlowInfo::findUnprocessed(void)

{
  vector<Address>::iterator iter;

  for(iter=addrlist.begin();iter!=addrlist.end();++iter) {
    if (seenInstruction(*iter)) {
      PcodeOp *op = target(*iter);
      data.opMarkStartBasic(op);
    }
    else
      unprocessed.push_back(*iter);
  }
}

/// The list is also sorted
void FlowInfo::dedupUnprocessed(void)

{
  if (unprocessed.empty()) return;
  sort(unprocessed.begin(),unprocessed.end());
  vector<Address>::iterator iter1,iter2;

  iter1 = unprocessed.begin();
  Address lastaddr = *iter1++;
  iter2 = iter1;
  while(iter1 != unprocessed.end()) {
    if (*iter1==lastaddr)
      iter1++;
    else {
      lastaddr = *iter1++;
      *iter2++ = lastaddr;
    }
  }
  unprocessed.erase(iter2,unprocessed.end());
}

/// A special form of RETURN instruction is generated for every address in
/// the \b unprocessed list.
void FlowInfo::fillinBranchStubs(void)

{
  vector<Address>::iterator iter;

  findUnprocessed();
  dedupUnprocessed();
  for(iter=unprocessed.begin();iter!=unprocessed.end();++iter) {
    PcodeOp *op = artificialHalt(*iter,PcodeOp::missing);
    data.opMarkStartBasic(op);
    data.opMarkStartInstruction(op);
  }
}

/// An edge is held as matching PcodeOp entries in \b block_edge1 and \b block_edge2.
/// Edges are generated for fall-thru to a p-code op marked as the start of a basic block
/// or for an explicit branch.
void FlowInfo::collectEdges(void)

{
  list<PcodeOp *>::const_iterator iter,iterend,iter1,iter2;
  PcodeOp *op,*targ_op;
  JumpTable *jt;
  bool nextstart;
  int4 i,num;

  if (bblocks.getSize() != 0)
    throw RecovError("Basic blocks already calculated\n");

  iter = obank.beginDead();
  iterend = obank.endDead();
  while(iter!=iterend) {
    op = *iter++;
    if (iter==iterend)
      nextstart = true;
    else
      nextstart = (*iter)->isBlockStart();
    switch(op->code()) {
    case CPUI_BRANCH:
      targ_op = branchTarget(op);
      block_edge1.push_back(op);
      //      block_edge2.push_back(op->Input(0)->getAddr().Iop());
      block_edge2.push_back(targ_op);
      break;
    case CPUI_BRANCHIND:
      jt = data.findJumpTable(op);
      if (jt == (JumpTable *)0) break;
				// If we are in this routine and there is no table
				// Then we must be doing partial flow analysis
				// so assume there are no branches out
      num = jt->numEntries();
      for(i=0;i<num;++i) {
	targ_op = target(jt->getAddressByIndex(i));
	if (targ_op->isMark()) continue; // Already a link between these blocks
	targ_op->setMark();
	block_edge1.push_back(op);
	block_edge2.push_back(targ_op);
      }
      iter1 = block_edge1.end(); // Clean up our marks
      iter2 = block_edge2.end();
      while(iter1 != block_edge1.begin()) {
	--iter1;
	--iter2;
	if ((*iter1)==op)
	  (*iter2)->clearMark();
	else
	  break;
      }
      break;
    case CPUI_RETURN:
      break;
    case CPUI_CBRANCH:
      targ_op = fallthruOp(op); // Put in fallthru edge
      block_edge1.push_back(op);
      block_edge2.push_back(targ_op);
      targ_op = branchTarget(op);
      block_edge1.push_back(op);
      block_edge2.push_back(targ_op);
      break;
    default:
      if (nextstart) {		// Put in fallthru edge if new basic block
	targ_op = fallthruOp(op);
	block_edge1.push_back(op);
	block_edge2.push_back(targ_op);
      }
      break;
    }
  }
}

/// PcodeOp objects are moved out of the PcodeOpBank \e dead list into their
/// assigned PcodeBlockBasic.  Initial address ranges of instructions are recorded in the block.
/// PcodeBlockBasic objects are created based on p-code ops that have been
/// previously marked as \e start of basic block.
void FlowInfo::splitBasic(void)

{
  PcodeOp *op;
  BlockBasic *cur;
  list<PcodeOp *>::const_iterator iter,iterend;

  iter = obank.beginDead();
  iterend = obank.endDead();
  if (iter == iterend) return;
  op = *iter++;
  if (!op->isBlockStart())
    throw LowlevelError("First op not marked as entry point");
  cur = bblocks.newBlockBasic(&data);
  data.opInsert(op,cur,cur->endOp());
  bblocks.setStartBlock(cur);
  Address start = op->getAddr();
  Address stop = start;
  while(iter != iterend) {
    op = *iter++;
    if (op->isBlockStart()) {
      data.setBasicBlockRange(cur, start, stop);
      cur = bblocks.newBlockBasic(&data); // Set up the next basic block
      start = op->getSeqNum().getAddr();
      stop = start;
    }
    else {
      const Address &nextAddr( op->getAddr() );
      if (stop < nextAddr)
	stop = nextAddr;
    }
    data.opInsert(op,cur,cur->endOp());
  }
  data.setBasicBlockRange(cur, start, stop);
}

/// Directed edges between the PcodeBlockBasic objects are created based on the
/// previously collected p-code op pairs in \b block_edge1 and \b block_edge2
void FlowInfo::connectBasic(void)

{
  PcodeOp *op,*targ_op;
  BlockBasic *bs,*targ_bs;
  list<PcodeOp *>::const_iterator iter,iter2;

  iter = block_edge1.begin();
  iter2 = block_edge2.begin();
  while(iter != block_edge1.end()) {
    op = *iter++;
    targ_op = *iter2++;
    bs = op->getParent();
    targ_bs = targ_op->getParent();
    bblocks.addEdge(bs,targ_bs);
  }
}

/// When preparing p-code for an in-lined function, the generation process needs
/// to be informed of in-lining that has already been performed.
/// This method copies the in-lining information from the parent flow, prior to p-code generation.
/// \param op2 is the parent flow
void FlowInfo::forwardRecursion(const FlowInfo &op2)

{
  inline_recursion = op2.inline_recursion;
  inline_head = op2.inline_head;
}

/// If the given injected op is a CALL, CALLIND, or BRANCHIND,
/// we need to add references to it in other flow tables.
/// \param op is the given injected p-code op
void FlowInfo::xrefInlinedBranch(PcodeOp *op)

{
  if (op->code() == CPUI_CALL)
    setupCallSpecs(op,(FuncCallSpecs *)0);
  else if (op->code() == CPUI_CALLIND)
    setupCallindSpecs(op,true,(FuncCallSpecs *)0);
  else if (op->code() == CPUI_BRANCHIND) {
    JumpTable *jt = data.linkJumpTable(op);
    if (jt == (JumpTable *)0)
      tablelist.push_back(op); // Didn't recover a jumptable
  }
}

/// \brief Clone the given in-line flow into \b this flow using the \e hard model
///
/// Individual PcodeOps from the Funcdata being in-lined are cloned into
/// the Funcdata for \b this flow, preserving their original address.
/// Any RETURN op is replaced with jump to first address following the call site.
/// \param inlineflow is the given in-line flow to clone
/// \param retaddr is the first address after the call site in \b this flow
void FlowInfo::inlineClone(const FlowInfo &inlineflow,const Address &retaddr)

{
  list<PcodeOp *>::const_iterator iter;
  for(iter=inlineflow.data.beginOpDead();iter!=inlineflow.data.endOpDead();++iter) {
    PcodeOp *op = *iter;
    PcodeOp *cloneop;
    if ((op->code() == CPUI_RETURN)&&(!retaddr.isInvalid())) {
      cloneop = data.newOp(1,op->getSeqNum());
      data.opSetOpcode(cloneop,CPUI_BRANCH);
      Varnode *vn = data.newCodeRef(retaddr);
      data.opSetInput(cloneop,vn,0);
    }
    else
      cloneop = data.cloneOp(op,op->getSeqNum());
    if (cloneop->isCallOrBranch())
      xrefInlinedBranch(cloneop);
  }
  // Copy in the cross-referencing
  unprocessed.insert(unprocessed.end(),inlineflow.unprocessed.begin(),
		     inlineflow.unprocessed.end());
  addrlist.insert(addrlist.end(),inlineflow.addrlist.begin(),
		  inlineflow.addrlist.end());
  visited.insert(inlineflow.visited.begin(),inlineflow.visited.end());
  // We don't copy inline_recursion or inline_head here
}

/// \brief Clone the given in-line flow into \b this flow using the EZ model
///
/// Individual PcodeOps from the Funcdata being in-lined are cloned into
/// the Funcdata for \b this flow but are reassigned a new fixed address,
/// and the RETURN op is eliminated.
/// \param inlineflow is the given in-line flow to clone
/// \param calladdr is the fixed address assigned to the cloned PcodeOps
void FlowInfo::inlineEZClone(const FlowInfo &inlineflow,const Address &calladdr)

{
  list<PcodeOp *>::const_iterator iter;
  for(iter=inlineflow.data.beginOpDead();iter!=inlineflow.data.endOpDead();++iter) {
    PcodeOp *op = *iter;
    if (op->code() == CPUI_RETURN) break;
    SeqNum myseq(calladdr,op->getSeqNum().getTime());
    data.cloneOp(op,myseq);
  }
  // Because we are processing only straightline code and it is all getting assigned to one
  // address, we don't touch unprocessed, addrlist, or visited
}

/// \brief For in-lining using the \e hard model, make sure some restrictions are met
///
///   - Can only in-line the function once.
///   - There must be a p-code op to return to.
///   - There must be a distinct return address, so that the RETURN can be replaced with a BRANCH.
///
/// Pass back the distinct return address, unless the in-lined function doesn't return.
/// \param inlinefd is the function being in-lined into \b this flow
/// \param op is CALL instruction at the site of the in-line
/// \param retaddr holds the passed back return address
/// \return \b true if all the \e hard model restrictions are met
bool FlowInfo::testHardInlineRestrictions(Funcdata *inlinefd,PcodeOp *op,Address &retaddr)

{
  if (inline_recursion->find( inlinefd->getAddress() ) != inline_recursion->end()) {
    // This function has already been included with current inlining
    inline_head->warning("Could not inline here",op->getAddr());
    return false;
  }
  
  if (!inlinefd->getFuncProto().isNoReturn()) {
    list<PcodeOp *>::iterator iter = op->getInsertIter();
    ++iter;
    if (iter == obank.endDead()) {
      inline_head->warning("No fallthrough prevents inlining here",op->getAddr());
      return false;
    }
    PcodeOp *nextop = *iter;
    retaddr = nextop->getAddr();
    if (op->getAddr() == retaddr) {
      inline_head->warning("Return address prevents inlining here",op->getAddr());
      return false;
    }
    // If the inlining "jumps back" this starts a new basic block
    data.opMarkStartBasic(nextop);
  }

  inline_recursion->insert(inlinefd->getAddress());
  return true;
}

/// A function is in the EZ model if it is a straight-line leaf function.
/// \return \b true if this flow contains no CALL or BRANCH ops
bool FlowInfo::checkEZModel(void) const

{
  list<PcodeOp *>::const_iterator iter = obank.beginDead();
  while(iter != obank.endDead()) {
    PcodeOp *op = *iter;
    if (op->isCallOrBranch()) return false;
    ++iter;
  }
  return true;
}

/// \brief Inject the given payload into \b this flow
///
/// The injected p-code replaces the given op, and control-flow information
/// is updated.
/// \param payload is the specific \e injection payload
/// \param icontext is the specific context for the injection
/// \param op is the given p-code op being replaced by the payload
/// \param fc (if non-NULL) is information about the call site being in-lined
void FlowInfo::doInjection(InjectPayload *payload,InjectContext &icontext,PcodeOp *op,FuncCallSpecs *fc)

{
  // Create marker at current end of the deadlist
  list<PcodeOp *>::const_iterator iter = obank.endDead();
  --iter;			// There must be at least one op

  payload->inject(icontext,emitter);		// Do the injection

  bool startbasic = op->isBlockStart();
  ++iter;			// Now points to first op in the injection
  PcodeOp *firstop = *iter;
  bool isfallthru = true;
  PcodeOp *lastop = xrefControlFlow(iter,startbasic,isfallthru,fc);

  if (startbasic) {		// If the inject code does NOT fall thru
    iter = op->getInsertIter();
    ++iter;			// Mark next op after the call
    if (iter != obank.endDead())
      data.opMarkStartBasic(*iter); // as start of basic block
  }

  if (payload->isIncidentalCopy())
    obank.markIncidentalCopy(firstop, lastop);
  obank.moveSequenceDead(firstop,lastop,op); // Move the injection to right after the call

  map<Address,VisitStat>::iterator viter = visited.find(op->getAddr());
  if (viter != visited.end()) {				// Check if -op- is a possible branch target
    if ((*viter).second.seqnum == op->getSeqNum())	// (if injection op is the first op for its address)
      (*viter).second.seqnum = firstop->getSeqNum();	//    change the seqnum to the first injected op
  }
  // Get rid of the original call
  data.opDestroyRaw(op);
}

/// The op must already be established as a user defined op with an associated injection
/// \param op is the given PcodeOp
void FlowInfo::injectUserOp(PcodeOp *op)

{
  InjectedUserOp *userop = (InjectedUserOp *)glb->userops.getOp((int4)op->getIn(0)->getOffset());
  InjectPayload *payload = glb->pcodeinjectlib->getPayload(userop->getInjectId());
  InjectContext &icontext(glb->pcodeinjectlib->getCachedContext());
  icontext.clear();
  icontext.baseaddr = op->getAddr();
  icontext.nextaddr = icontext.baseaddr;
  for(int4 i=1;i<op->numInput();++i) {		// Skip the first operand containing the injectid
    Varnode *vn = op->getIn(i);
    icontext.inputlist.emplace_back();
    icontext.inputlist.back().space = vn->getSpace();
    icontext.inputlist.back().offset = vn->getOffset();
    icontext.inputlist.back().size = vn->getSize();
  }
  Varnode *outvn = op->getOut();
  if (outvn != (Varnode *)0) {
    icontext.output.emplace_back();
    icontext.output.back().space = outvn->getSpace();
    icontext.output.back().offset = outvn->getOffset();
    icontext.output.back().size = outvn->getSize();
  }
  doInjection(payload,icontext,op,(FuncCallSpecs *)0);
}

/// P-code is generated for the sub-function and then woven into \b this flow
/// at the call site.
/// \param fc is the given call site
/// \return \b true if the in-lining is successful
bool FlowInfo::inlineSubFunction(FuncCallSpecs *fc)

{
  Funcdata *fd = fc->getFuncdata();
  if (fd == (Funcdata *)0) return false;
  PcodeOp *op = fc->getOp();
  Address retaddr;

  if (!data.inlineFlow( fd, *this, op))
    return false;

  // Changing CALL to JUMP may make some original code unreachable
  setPossibleUnreachable();

  return true;
}

/// The call site must be previously marked with the \e injection id.
/// The PcodeInjectLibrary is queried for the associated payload, which is
/// then inserted into \b this flow, replacing the original CALL op.
/// \param fc is the given call site
/// \return \b true if the injection was successfully performed
bool FlowInfo::injectSubFunction(FuncCallSpecs *fc)

{
  PcodeOp *op = fc->getOp();

  // Inject to end of the deadlist
  InjectContext &icontext(glb->pcodeinjectlib->getCachedContext());
  icontext.clear();
  icontext.baseaddr = op->getAddr();
  icontext.nextaddr = icontext.baseaddr;
  icontext.calladdr = fc->getEntryAddress();
  InjectPayload *payload = glb->pcodeinjectlib->getPayload(fc->getInjectId());
  doInjection(payload,icontext,op,fc);
  // If the injection fills in the -paramshift- field of the context
  // pass this information on to the callspec of the injected call, which must be last in the list
  if (payload->getParamShift() != 0)
    qlst.back()->setParamshift(payload->getParamShift());

  return true;			// Return true to indicate injection happened and callspec should be deleted
}

/// \param fc is the given call site (which is freed by this method)
void FlowInfo::deleteCallSpec(FuncCallSpecs *fc)

{
  int4 i;
  for(i=0;i<qlst.size();++i)
    if (qlst[i] == fc) break;

  if (i == qlst.size())
    throw LowlevelError("Misplaced callspec");

  delete fc;
  qlst.erase(qlst.begin() + i);
}

/// Types of substitution include:
///   - Sub-function in-lining
///   - Sub-function injection
///   - User defined op injection
///
/// Make sure to truncate recursion, and otherwise don't
/// allow a sub-function to be in-lined more than once.
void FlowInfo::injectPcode(void)

{
  if (inline_head == (Funcdata *)0) {
    // This is the top level of inlining
    inline_head = &data;	// Set up head of inlining
    inline_recursion = &inline_base;
    inline_recursion->insert(data.getAddress()); // Insert ourselves
    //    inline_head = (Funcdata *)0;
  }
  else {
    inline_recursion->insert(data.getAddress()); // Insert ourselves
  }

  for(int4 i=0;i<injectlist.size();++i) {
    PcodeOp *op = injectlist[i];
    if (op == (PcodeOp *)0) continue;
    injectlist[i] = (PcodeOp *)0;	// Nullify entry, so we don't inject more than once
    if (op->code() == CPUI_CALLOTHER) {
      injectUserOp(op);
    }
    else {	// CPUI_CALL or CPUI_CALLIND
      FuncCallSpecs *fc = FuncCallSpecs::getFspecFromConst(op->getIn(0)->getAddr());
      if (fc->isInline()) {
	if (fc->getInjectId() >= 0) {
	  if (injectSubFunction(fc)) {
	    data.warningHeader("Function: "+fc->getName()+" replaced with injection: "+
			       glb->pcodeinjectlib->getCallFixupName(fc->getInjectId()));
	    deleteCallSpec(fc);
	  }
	}
	else if (inlineSubFunction(fc)) {
	  data.warningHeader("Inlined function: "+fc->getName());
	  deleteCallSpec(fc);
	}
      }
    }
  }
  injectlist.clear();
}

/// \brief Check if any of the calls this function makes are to already traced data-flow.
///
/// If so, we change the CALL to a BRANCH and issue a warning.
/// This situation is most likely due to a Position Indepent Code construction.
void FlowInfo::checkContainedCall(void)

{
  vector<FuncCallSpecs *>::iterator iter;
  for(iter=qlst.begin();iter!=qlst.end();++iter) {
    FuncCallSpecs *fc = *iter;
    Funcdata *fd = fc->getFuncdata();
    if (fd != (Funcdata *)0) continue;
    PcodeOp *op = fc->getOp();
    if (op->code() != CPUI_CALL) continue;

    const Address &addr( fc->getEntryAddress() );
    map<Address,VisitStat>::const_iterator miter;
    miter = visited.upper_bound(addr);
    if (miter == visited.begin()) continue;
    --miter;
    if ((*miter).first + (*miter).second.size <= addr)
      continue;
    if ((*miter).first == addr) {
      ostringstream s;
      s << "Possible PIC construction at ";
      op->getAddr().printRaw(s);
      s << ": Changing call to branch";
      data.warningHeader(s.str());
      data.opSetOpcode(op,CPUI_BRANCH);
      // Make sure target of new goto starts a basic block
      PcodeOp *targ = target(addr);
      data.opMarkStartBasic(targ);
      // Make sure the following op starts a basic block
      list<PcodeOp *>::const_iterator oiter = op->getInsertIter();
      ++oiter;
      if (oiter != obank.endDead())
	data.opMarkStartBasic(*oiter);
      // Restore original address
      data.opSetInput(op,data.newCodeRef(addr),0);
      iter = qlst.erase(iter);	// Delete the call
      delete fc;
      if (iter == qlst.end()) break;
    }
    else {
      data.warning("Call to offcut address within same function",op->getAddr());
    }
  }
  
}

/// \brief Look for changes in control-flow near indirect jumps that were discovered \e after the jumptable recovery
void FlowInfo::checkMultistageJumptables(void)

{
  int4 num = data.numJumpTables();
  for(int4 i=0;i<num;++i) {
    JumpTable *jt = data.getJumpTable(i);
    if (jt->checkForMultistage(&data))
      tablelist.push_back(jt->getIndirectOp());
  }  
}

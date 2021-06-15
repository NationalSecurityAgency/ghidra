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
#include "coreaction.hh"
#include "condexe.hh"
#include "double.hh"
#include "subflow.hh"

/// \brief A stack equation
struct StackEqn {
  int4 var1;			///< Variable with 1 coefficient
  int4 var2;			///< Variable with -1 coefficient
  int4 rhs;			///< Right hand side of the equation
  static bool compare(const StackEqn &a,const StackEqn &b);	///< Order two equations
};

/// \brief A class that solves for stack-pointer changes across unknown sub-functions
class StackSolver {
  vector<StackEqn> eqs;		///< Known equations based on operations that explicitly change the stack-pointer
  vector<StackEqn> guess;	///< Guessed equations for underdetermined systems
  vector<Varnode *> vnlist;	///< The indexed set of variables, one for each reference to the stack-pointer
  vector<int4> companion;	///< Index of companion input for variable produced by CPUI_INDIRECT
  Address spacebase;		///< Starting address of the stack-pointer
  vector<int4> soln;		///< Collected solutions (corresponding to array of variables)
  int4 missedvariables;		///< Number of variables for which we are missing an equation
  void duplicate(void);		///< Duplicate each equation, multiplying by -1
  void propagate(int4 varnum,int4 val);	///< Propagate solution for one variable to other variables
public:
  void solve(void);		///< Solve the system of equations
  void build(const Funcdata &data,AddrSpace *id,int4 spcbase);	///< Build the system of equations
  int4 getNumVariables(void) const { return vnlist.size(); }	///< Get the number of variables in the system
  Varnode *getVariable(int4 i) const { return vnlist[i]; }	///< Get the i-th Varnode variable
  int4 getCompanion(int4 i) const { return companion[i]; }	///< Get the i-th variable's companion index
  int4 getSolution(int4 i) const { return soln[i]; }		///< Get the i-th variable's solution
};

/// \param a is the first equation to compare
/// \param b is the second
/// \return true if the first equation comes before the second
bool StackEqn::compare(const StackEqn &a,const StackEqn &b)

{
  return (a.var1<b.var1);
}

/// Given a solution for one variable, look for equations containing the variable
/// and attempt to solve for the other variable. Continue propagating new
/// solutions to other equations to find even more solutions.  Populate
/// the \b soln array with the solutions.
/// \param varnum is the index of the initial variable
/// \param val is the solution for the variable
void StackSolver::propagate(int4 varnum,int4 val)

{
  if (soln[varnum] != 65535) return; // This variable already specified
  soln[varnum] = val;

  StackEqn eqn;
  vector<int4> workstack;
  workstack.reserve(soln.size());
  workstack.push_back(varnum);
  vector<StackEqn>::iterator top;

  while(!workstack.empty()) {
    varnum = workstack.back();
    workstack.pop_back();
    
    eqn.var1 = varnum;
    top = lower_bound(eqs.begin(),eqs.end(),eqn,StackEqn::compare);
    while((top!=eqs.end())&&((*top).var1 == varnum)) {
      int4 var2 = (*top).var2;
      if (soln[var2] == 65535) {
	soln[var2] = soln[varnum]-(*top).rhs;
	workstack.push_back(var2);
      }
      ++top;
    }
  }
}

void StackSolver::duplicate(void)

{
  int4 size,i;
  StackEqn eqn;

  size = eqs.size();
  for(i=0;i<size;++i) {
    eqn.var1 = eqs[i].var2;
    eqn.var2 = eqs[i].var1;
    eqn.rhs = -eqs[i].rhs;
    eqs.push_back(eqn);
  }
  stable_sort(eqs.begin(),eqs.end(),StackEqn::compare);
}

void StackSolver::solve(void)

{
  // Use guesses to resolve subsystems not uniquely determined
  int4 i,size,var1,var2,count,lastcount;

  soln.clear();
  soln.resize(vnlist.size(),65535); // Initialize solutions vector
  duplicate();			// Duplicate and sort the equations

  propagate(0,0);		// We know one variable
  size = guess.size();
  lastcount = size+2;
  do {
    count = 0;
    for(i=0;i<size;++i) {
      var1 = guess[i].var1;
      var2 = guess[i].var2;
      if ((soln[var1]!=65535)&&(soln[var2]==65535))
	propagate(var2,soln[var1]-guess[i].rhs);
      else if ((soln[var1]==65535)&&(soln[var2]!=65535))
	propagate(var1,soln[var2]+guess[i].rhs);
      else if ((soln[var1]==65535)&&(soln[var2]==65535))
	count += 1;
    }
    if (count == lastcount) break;
    lastcount = count;
  } while(count > 0);
}

/// Collect references to the stack-pointer as variables, and examine their defining PcodeOps
/// to determine equations and coefficient.
/// \param data is the function being analyzed
/// \param id is the \e stack address space
/// \param spcbase is the index, relative to the stack space, of the stack pointer
void StackSolver::build(const Funcdata &data,AddrSpace *id,int4 spcbase)

{
  const VarnodeData &spacebasedata(id->getSpacebase(spcbase));
  spacebase = Address(spacebasedata.space,spacebasedata.offset);
  VarnodeLocSet::const_iterator begiter,enditer;

  begiter = data.beginLoc(spacebasedata.size,spacebase);
  enditer = data.endLoc(spacebasedata.size,spacebase);

  while(begiter != enditer) {	// All instances of the spacebase
    if ((*begiter)->isFree()) break;
    vnlist.push_back(*begiter);
    companion.push_back(-1);
    ++begiter;
  }
  missedvariables = 0;
  if (vnlist.empty()) return;
  if (!vnlist[0]->isInput())
    throw LowlevelError("Input value of stackpointer is not used");

  vector<Varnode *>::iterator iter;
  StackEqn eqn;
  for(int4 i=1;i<vnlist.size();++i) {
    Varnode *vn = vnlist[i];
    Varnode *othervn,*constvn;
    PcodeOp *op = vn->getDef();

    if (op->code() == CPUI_INT_ADD) {
      othervn = op->getIn(0);
      constvn = op->getIn(1);
      if (othervn->isConstant()) {
	constvn = othervn;
	othervn = op->getIn(1);
      }
      if (!constvn->isConstant()) { missedvariables+=1; continue; }
      if (othervn->getAddr() != spacebase) { missedvariables+=1; continue; }
      iter = lower_bound(vnlist.begin(),vnlist.end(),othervn,Varnode::comparePointers);
      eqn.var1 = i;
      eqn.var2 = iter-vnlist.begin();
      eqn.rhs = constvn->getOffset();
      eqs.push_back(eqn);
    }
    else if (op->code() == CPUI_COPY) {
      othervn = op->getIn(0);
      if (othervn->getAddr() != spacebase) { missedvariables+=1; continue; }
      iter = lower_bound(vnlist.begin(),vnlist.end(),othervn,Varnode::comparePointers);
      eqn.var1 = i;
      eqn.var2 = iter-vnlist.begin();
      eqn.rhs = 0;
      eqs.push_back(eqn);
    }
    else if (op->code() == CPUI_INDIRECT) {
      othervn = op->getIn(0);
      if (othervn->getAddr() != spacebase) { missedvariables += 1; continue; }
      iter = lower_bound(vnlist.begin(),vnlist.end(),othervn,Varnode::comparePointers);
      eqn.var1 = i;
      eqn.var2 = iter-vnlist.begin();
      companion[i] = eqn.var2;
      Varnode *iopvn = op->getIn(1);
      if (iopvn->getSpace()->getType()==IPTR_IOP) { // If INDIRECT is due call
	PcodeOp *iop = PcodeOp::getOpFromConst(iopvn->getAddr());
	FuncCallSpecs *fc = data.getCallSpecs(iop); // Look up function proto
	if (fc != (FuncCallSpecs *)0) {
	  if (fc->getExtraPop() != ProtoModel::extrapop_unknown) { // Double check that extrapop is unknown
	    eqn.rhs = fc->getExtraPop(); // As the deindirect process may have filled it in
	    eqs.push_back(eqn);
	    continue;
	  }
	}
      }
      
      eqn.rhs = 4;		// Otherwise make a guess
      guess.push_back(eqn);
    }
    else if (op->code() == CPUI_MULTIEQUAL) {
      for(int4 j=0;j<op->numInput();++j) {
	othervn = op->getIn(j);
	if (othervn->getAddr() != spacebase) { missedvariables += 1; continue; }
	iter = lower_bound(vnlist.begin(),vnlist.end(),othervn,Varnode::comparePointers);
	eqn.var1 = i;
	eqn.var2 = iter-vnlist.begin();
	eqn.rhs = 0;
	eqs.push_back(eqn);
      }
    }
    else if (op->code() == CPUI_INT_AND) {
      // This can occur if a function aligns its stack pointer
      othervn = op->getIn(0);
      constvn = op->getIn(1);
      if (othervn->isConstant()) {
	constvn = othervn;
	othervn = op->getIn(1);
      }
      if (!constvn->isConstant()) { missedvariables+=1; continue; }
      if (othervn->getAddr() != spacebase) { missedvariables+=1; continue; }
      iter = lower_bound(vnlist.begin(),vnlist.end(),othervn,Varnode::comparePointers);
      eqn.var1 = i;
      eqn.var2 = iter-vnlist.begin();
      eqn.rhs = 0;		// Treat this as a copy
      eqs.push_back(eqn);
    }
    else
      missedvariables += 1;
  }
}

/// \brief Calculate stack-pointer change across \e undetermined sub-functions
///
/// If there are sub-functions for which \e extra \e pop is not explicit,
/// do full linear analysis to (attempt to) recover the values.
/// \param data is the function to analyze
/// \param stackspace is the space associated with the stack-pointer
/// \param spcbase is the index (relative to the stackspace) of the stack-pointer
void ActionStackPtrFlow::analyzeExtraPop(Funcdata &data,AddrSpace *stackspace,int4 spcbase)

{
  ProtoModel *myfp = data.getArch()->evalfp_called;
  if (myfp == (ProtoModel *)0)
    myfp = data.getArch()->defaultfp;
  if (myfp->getExtraPop()!=ProtoModel::extrapop_unknown) return;

  StackSolver solver;
  try {
    solver.build(data,stackspace,spcbase);
  } catch(LowlevelError &err) {
    ostringstream s;
    s << "Stack frame is not setup normally: " << err.explain;
    data.warningHeader(s.str());
    return;
  }
  if (solver.getNumVariables() == 0) return;
  solver.solve();		// Solve the equations
  
  Varnode *invn = solver.getVariable(0);
  bool warningprinted = false;

  for(int4 i=1;i<solver.getNumVariables();++i) {
    Varnode *vn = solver.getVariable(i);
    int4 soln = solver.getSolution(i);
    if (soln == 65535) {
      if (!warningprinted) {
	data.warningHeader("Unable to track spacebase fully for "+stackspace->getName());
	warningprinted = true;
      }
      continue;
    }
    PcodeOp *op = vn->getDef();

    if (op->code() == CPUI_INDIRECT) {
      Varnode *iopvn = op->getIn(1);
      if (iopvn->getSpace()->getType()==IPTR_IOP) {
	PcodeOp *iop = PcodeOp::getOpFromConst(iopvn->getAddr());
	FuncCallSpecs *fc = data.getCallSpecs(iop);
	if (fc != (FuncCallSpecs *)0) {
	  int4 soln2 = 0;
	  int4 comp = solver.getCompanion(i);
	  if (comp >= 0)
	    soln2 = solver.getSolution(comp);
	  fc->setEffectiveExtraPop(soln-soln2);
	}
      }
    }
    vector<Varnode *> paramlist;
    paramlist.push_back(invn);
    int4 sz = invn->getSize();
    paramlist.push_back(data.newConstant(sz,soln&calc_mask(sz)));
    data.opSetOpcode(op,CPUI_INT_ADD);
    data.opSetAllInput(op,paramlist);
  }
  return;
}

/// \brief Is the given Varnode defined as a pointer relative to the stack-pointer?
///
/// Return true if -vn- is defined as the stackpointer input plus a constant (or zero)
/// This works through the general case and the special case when the constant is zero.
/// The constant value is passed-back to the caller.
/// \param spcbasein is the Varnode holding the \e input value of the stack-pointer
/// \param vn is the Varnode to check for relativeness
/// \param constval is a reference for passing back the constant offset
/// \return true if \b vn is stack relative
bool ActionStackPtrFlow::isStackRelative(Varnode *spcbasein,Varnode *vn,uintb &constval)

{
  if (spcbasein == vn) {
    constval = 0;
    return true;
  }
  if (!vn->isWritten()) return false;
  PcodeOp *addop = vn->getDef();
  if (addop->code() != CPUI_INT_ADD) return false;
  if (addop->getIn(0) != spcbasein) return false;
  Varnode *constvn = addop->getIn(1);
  if (!constvn->isConstant()) return false;
  constval = constvn->getOffset();
  return true;
}

/// \brief Adjust the LOAD where the stack-pointer alias has been recovered.
///
/// We've matched a LOAD with its matching store, now convert the LOAD op to a COPY of what was stored.
/// \param data is the function being analyzed
/// \param loadop is the LOAD op to adjust
/// \param storeop is the matching STORE op
/// \return true if the adjustment is successful
bool ActionStackPtrFlow::adjustLoad(Funcdata &data,PcodeOp *loadop,PcodeOp *storeop)

{
  Varnode *vn = storeop->getIn(2);
  if (vn->isConstant())
    vn = data.newConstant(vn->getSize(),vn->getOffset());
  else if (vn->isFree())
    return false;

  data.opRemoveInput(loadop,1);
  data.opSetOpcode(loadop,CPUI_COPY);
  data.opSetInput(loadop,vn,0);
  return true;
}

/// \brief Link LOAD to matching STORE of a constant
///
/// Try to find STORE op using same stack relative pointer as a given LOAD op.
/// If we find it and the STORE stores a constant, change the LOAD to a COPY.
/// \param data is the function owning the LOAD
/// \param id is the stackspace
/// \param spcbasein is the stack-pointer
/// \param loadop is the given LOAD op
/// \param constz is the stack relative offset of the LOAD pointer
/// \return 1 if we successfully change LOAD to COPY, 0 otherwise
int4 ActionStackPtrFlow::repair(Funcdata &data,AddrSpace *id,Varnode *spcbasein,PcodeOp *loadop,uintb constz)

{
  int4 loadsize = loadop->getOut()->getSize();
  BlockBasic *curblock = loadop->getParent();
  list<PcodeOp *>::iterator begiter = curblock->beginOp();
  list<PcodeOp *>::iterator iter = loadop->getBasicIter();
  for(;;) {
    if (iter == begiter) {
      if (curblock->sizeIn() != 1) return 0; // Can trace back to next basic block if only one path
      curblock = (BlockBasic *)curblock->getIn(0);
      begiter = curblock->beginOp();
      iter = curblock->endOp();
      continue;
    }
    else {
      --iter;
    }
    PcodeOp *curop = *iter;
    if (curop->isCall()) return 0; // Don't try to trace aliasing through a call
    if (curop->code() == CPUI_STORE) {
      Varnode *ptrvn = curop->getIn(1);
      Varnode *datavn = curop->getIn(2);
      uintb constnew;
      if (isStackRelative(spcbasein,ptrvn,constnew)) {
	if ((constnew == constz)&&(loadsize == datavn->getSize())) {
	  // We found the matching store
	  if (adjustLoad(data,loadop,curop))
	    return 1;
	  return 0;
	}
	else if ((constnew <= constz + (loadsize-1))&&(constnew+(datavn->getSize()-1)>=constz))
	  return 0;
      }
      else
	return 0;		// Any other kind of STORE we can't solve aliasing
    }
    else {
      Varnode *outvn = curop->getOut();
      if (outvn != (Varnode *)0) {
	if (outvn->getSpace() == id) return 0; // Stack already traced, too late
      }
    }
  }
}

/// \brief Find any stack pointer clogs and pass it on to the repair routines
///
/// A stack pointer \b clog is a constant addition to the stack-pointer,
/// but where the constant comes from the stack.
/// \param data is the function to analyze
/// \param id is the stack space
/// \param spcbase is the index of the stack-pointer relative to the stack space
/// \return the number of clogs that were repaired
int4 ActionStackPtrFlow::checkClog(Funcdata &data,AddrSpace *id,int4 spcbase)

{
  const VarnodeData &spacebasedata(id->getSpacebase(spcbase));
  Address spacebase = Address(spacebasedata.space,spacebasedata.offset);
  VarnodeLocSet::const_iterator begiter,enditer;
  int4 clogcount = 0;

  begiter = data.beginLoc(spacebasedata.size,spacebase);
  enditer = data.endLoc(spacebasedata.size,spacebase);

  Varnode *spcbasein;
  if (begiter == enditer) return clogcount;
  spcbasein = *begiter;
  ++begiter;
  if (!spcbasein->isInput()) return clogcount;
  while(begiter != enditer) {
    Varnode *outvn = *begiter;
    ++begiter;
    if (!outvn->isWritten()) continue;
    PcodeOp *addop = outvn->getDef();
    if (addop->code() != CPUI_INT_ADD) continue;
    Varnode *y = addop->getIn(1);
    if (!y->isWritten()) continue; // y must not be a constant
    Varnode *x = addop->getIn(0); // is y is not constant than x (in position 0) isn't either
    uintb constx;
    if (!isStackRelative(spcbasein,x,constx)) {	// If x is not stack relative
      x = y;			// Swap x and y
      y = addop->getIn(0);
      if (!isStackRelative(spcbasein,x,constx)) continue; // Now maybe the new x is stack relative
    }
    PcodeOp *loadop = y->getDef();
    if (loadop->code() == CPUI_INT_MULT) { // If we multiply
      Varnode *constvn = loadop->getIn(1);
      if (!constvn->isConstant()) continue;
      if (constvn->getOffset() != calc_mask(constvn->getSize())) continue; // Must multiply by -1
      y = loadop->getIn(0);
      if (!y->isWritten()) continue;
      loadop = y->getDef();
    }
    if (loadop->code() != CPUI_LOAD) continue;
    Varnode *ptrvn = loadop->getIn(1);
    uintb constz;
    if (!isStackRelative(spcbasein,ptrvn,constz)) continue;
    clogcount += repair(data,id,spcbasein,loadop,constz);
  }
  return clogcount;
}

int4 ActionStackPtrFlow::apply(Funcdata &data)

{
  if (analysis_finished)
    return 0;
  if (stackspace == (AddrSpace *)0) {
    analysis_finished = true;		// No stack to do analysis on
    return 0;
  }
  int4 numchange = checkClog(data,stackspace,0);
  if (numchange > 0) {
    count += 1;
  }
  if (numchange == 0) {
    analyzeExtraPop(data,stackspace,0);
    analysis_finished = true;
  }
  return 0;
}

/// \brief Examine the PcodeOps using the given Varnode to determine possible lane sizes
///
/// Run through the defining op and any descendant ops of the given Varnode, looking for
/// CPUI_PIECE and CPUI_SUBPIECE. Use these to determine possible lane sizes and
/// register them with the given LanedRegister object.
/// \param vn is the given Varnode
/// \param allowedLanes is used to determine if a putative lane size is allowed
/// \param checkLanes collects the possible lane sizes
void ActionLaneDivide::collectLaneSizes(Varnode *vn,const LanedRegister &allowedLanes,LanedRegister &checkLanes)

{
  list<PcodeOp *>::const_iterator iter = vn->beginDescend();
  int4 step = 0;		// 0 = descendants, 1 = def, 2 = done
  if (iter == vn->endDescend()) {
    step = 1;
  }
  while(step < 2) {
    int4 curSize;		// Putative lane size
    if (step == 0) {
      PcodeOp *op = *iter;
      ++iter;
      if (iter == vn->endDescend())
	step = 1;
      if (op->code() != CPUI_SUBPIECE) continue;	// Is the big register split into pieces
      curSize = op->getOut()->getSize();
    }
    else {
      step = 2;
      if (!vn->isWritten()) continue;
      PcodeOp *op = vn->getDef();
      if (op->code() != CPUI_PIECE) continue;		// Is the big register formed from smaller pieces
      curSize = op->getIn(0)->getSize();
      int4 tmpSize = op->getIn(1)->getSize();
      if (tmpSize < curSize)
	curSize = tmpSize;
    }
    if (allowedLanes.allowedLane(curSize))
      checkLanes.addLaneSize(curSize);			// Register this possible size
  }
}

/// \brief Search for a likely lane size and try to divide a single Varnode into these lanes
///
/// There are different ways to search for a lane size:
///
/// Mode 0: Collect putative lane sizes based on the local ops using the Varnode. Attempt
/// to divide based on each of those lane sizes in turn.
///
/// Mode 1: Similar to mode 0, except we allow for SUBPIECE operations that truncate to
/// variables that are smaller than the lane size.
///
/// Mode 2: Attempt to divide based on a default lane size.
/// \param data is the function being transformed
/// \param vn is the given single Varnode
/// \param lanedRegister is acceptable set of lane sizes for the Varnode
/// \param mode is the lane size search mode (0, 1, or 2)
/// \return \b true if the Varnode (and its data-flow) was successfully split
bool ActionLaneDivide::processVarnode(Funcdata &data,Varnode *vn,const LanedRegister &lanedRegister,int4 mode)

{
  LanedRegister checkLanes;		// Lanes we are going to try, initialized to no lanes
  bool allowDowncast = (mode > 0);
  if (mode < 2)
    collectLaneSizes(vn,lanedRegister,checkLanes);
  else {
    checkLanes.addLaneSize(4);		// Default lane size
  }
  LanedRegister::const_iterator enditer = checkLanes.end();
  for(LanedRegister::const_iterator iter=checkLanes.begin();iter!=enditer;++iter) {
    int4 curSize = *iter;
    LaneDescription description(lanedRegister.getWholeSize(),curSize);	// Lane scheme dictated by curSize
    LaneDivide laneDivide(&data,vn,description,allowDowncast);
    if (laneDivide.doTrace()) {
      laneDivide.apply();
      count += 1;		// Indicate a change was made
      return true;
    }
  }
  return false;
}

int4 ActionLaneDivide::apply(Funcdata &data)

{
  map<VarnodeData,const LanedRegister *>::const_iterator iter;
  for(int4 mode=0;mode<3;++mode) {
    bool allStorageProcessed = true;
    for(iter=data.beginLaneAccess();iter!=data.endLaneAccess();++iter) {
      const LanedRegister *lanedReg = (*iter).second;
      Address addr = (*iter).first.getAddr();
      int4 sz = (*iter).first.size;
      VarnodeLocSet::const_iterator viter = data.beginLoc(sz,addr);
      VarnodeLocSet::const_iterator venditer = data.endLoc(sz,addr);
      bool allVarnodesProcessed = true;
      while(viter != venditer) {
	Varnode *vn = *viter;
	if (processVarnode(data, vn, *lanedReg, mode)) {
	  viter = data.beginLoc(sz,addr);
	  venditer = data.endLoc(sz, addr);	// Recalculate bounds
	  allVarnodesProcessed = true;
	}
	else {
	  ++viter;
	  allVarnodesProcessed = false;
	}
      }
      if (!allVarnodesProcessed)
	allStorageProcessed = false;
    }
    if (allStorageProcessed) break;
  }
  data.clearLanedAccessMap();
  data.setLanedRegGenerated();
  return 0;
}

int4 ActionSegmentize::apply(Funcdata &data)

{
  int4 numops = data.getArch()->userops.numSegmentOps();
  if (numops==0) return 0;
  if (localcount>0) return 0;	// Only perform once
  localcount = 1;		// Mark as having performed once

  vector<Varnode *> bindlist;
  bindlist.push_back((Varnode *)0);
  bindlist.push_back((Varnode *)0);
  
  for(int4 i=0;i<numops;++i) {
    SegmentOp *segdef = data.getArch()->userops.getSegmentOp(i);
    if (segdef == (SegmentOp *)0) continue;
    AddrSpace *spc = segdef->getSpace();

    list<PcodeOp *>::const_iterator iter,enditer;
    iter = data.beginOp(CPUI_CALLOTHER);
    enditer = data.endOp(CPUI_CALLOTHER);
    int4 uindex = segdef->getIndex();
    while(iter != enditer) {
      PcodeOp *segroot = *iter++;
      if (segroot->isDead()) continue;
      if (segroot->getIn(0)->getOffset() != uindex) continue;
      if (!segdef->unify(data,segroot,bindlist)) {
	ostringstream err;
	err << "Segment op in wrong form at ";
	segroot->getAddr().printRaw(err);
	throw LowlevelError(err.str());
      }

      if (segdef->getNumVariableTerms()==1)
	bindlist[1] = data.newConstant(4,0);
      // Redefine the op as a segmentop
      data.opSetOpcode(segroot,CPUI_SEGMENTOP);
      data.opSetInput(segroot,data.newVarnodeSpace(spc),0);
      data.opSetInput(segroot,bindlist[1],1);
      data.opSetInput(segroot,bindlist[0],2);
      for(int4 j=segroot->numInput()-1;j>2;--j) // Remove anything else
	data.opRemoveInput(segroot,j);
      count += 1;
    }
  }
  return 0;
}

int4 ActionForceGoto::apply(Funcdata &data)

{
  data.getOverride().applyForceGoto(data);
  return 0;
}

int4 ActionConstbase::apply(Funcdata &data)

{
  if (data.getBasicBlocks().getSize()==0) return 0; // No blocks
  // Get start block, which is constructed to have nothing
  // falling into it
  BlockBasic *bb = (BlockBasic *)data.getBasicBlocks().getBlock(0);

  int4 injectid = data.getFuncProto().getInjectUponEntry();
  if (injectid >= 0) {
    InjectPayload *payload = data.getArch()->pcodeinjectlib->getPayload(injectid);
    data.doLiveInject(payload,bb->getStart(),bb,bb->beginOp());
  }

  const TrackedSet trackset( data.getArch()->context->getTrackedSet(data.getAddress()));

  for(int4 i=0;i<trackset.size();++i) {
    const TrackedContext &ctx(trackset[i]);

    Address addr(ctx.loc.space,ctx.loc.offset);
    PcodeOp *op = data.newOp(1,bb->getStart());
    data.newVarnodeOut(ctx.loc.size,addr,op);
    Varnode *vnin = data.newConstant(ctx.loc.size,ctx.val);
    data.opSetOpcode(op,CPUI_COPY);
    data.opSetInput(op,vnin,0);
    data.opInsertBegin(op,bb);
  }
  return 0;
}

// int4 ActionCse::apply(Funcdata &data)

// {
//   vector< pair<uintm,PcodeOp *> > list;
//   vector<Varnode *> vlist;
//   PcodeOp *op;
//   list<PcodeOp *>::const_iterator iter;
//   uintm hash;
  
//   for(iter=data.op_alive_begin();iter!=data.op_alive_end();++iter) {
//     op = *iter;
//     hash = op->getCseHash();
//     if (hash == 0) continue;
//     list.push_back(pair<uintm,PcodeOp *>(hash,op));
//   }
//   if (list.empty()) return 0;

//   cseEliminateList(data,list,vlist);
//   while(!vlist.empty()) {
//     count += 1;			// Indicate that changes have been made
//     list.clear();
//     cse_build_fromvarnode(list,vlist);
//     vlist.clear();
//     cseEliminateList(data,list,vlist);
//   }
//   return 0;
// }

/// We are substituting either -out1- for -out2-  OR  -out2- for -out1-
/// Return true if we prefer substituting -out2- for -out1-
/// \param out1 is one output
/// \param out2 is the other output
/// \return preference
bool ActionMultiCse::preferredOutput(Varnode *out1,Varnode *out2)

{
  // Prefer the output that is used in a CPUI_RETURN
  list<PcodeOp *>::const_iterator iter,enditer;
  enditer = out1->endDescend();
  for(iter=out1->beginDescend();iter!=enditer;++iter) {
    PcodeOp *op = *iter;
    if (op->code() == CPUI_RETURN)
      return false;
  }
  enditer = out2->endDescend();
  for(iter=out2->beginDescend();iter!=enditer;++iter) {
    PcodeOp *op = *iter;
    if (op->code() == CPUI_RETURN)
      return true;
  }
  // Prefer addrtied over register over unique
  if (!out1->isAddrTied()) {
    if (out2->isAddrTied())
      return true;
    else {
      if (out1->getSpace()->getType()==IPTR_INTERNAL) {
	if (out2->getSpace()->getType()!=IPTR_INTERNAL)
	  return true;
      }
    }
  }
  return false;
}

/// Find any matching CPUI_MULTIEQUAL that occurs before \b target that has \b in as an input.
/// Then test to see if the \b target and the recovered op are functionally equivalent.
/// \param bl is the parent block
/// \param target is the given target CPUI_MULTIEQUAL
/// \param in is the specific input Varnode
PcodeOp *ActionMultiCse::findMatch(BlockBasic *bl,PcodeOp *target,Varnode *in)

{
  list<PcodeOp *>::iterator iter = bl->beginOp();

  for(;;) {
    PcodeOp *op = *iter;
    ++iter;
    if (op == target)		// Caught up with target, nothing else before it
      break;
    int4 i,numinput;
    numinput = op->numInput();
    for(i=0;i<numinput;++i) {
      Varnode *vn = op->getIn(i);
      if (vn->isWritten() && (vn->getDef()->code() == CPUI_COPY))
	vn = vn->getDef()->getIn(0);		// Allow for differences in copy propagation
      if (vn == in) break;
    }
    if (i < numinput) {
      int4 j;
      Varnode *buf1[2];
      Varnode *buf2[2];
      for(j=0;j<numinput;++j) {
	Varnode *in1 = op->getIn(j);
	if (in1->isWritten() && (in1->getDef()->code() == CPUI_COPY))
	  in1 = in1->getDef()->getIn(0);	// Allow for differences in copy propagation
	Varnode *in2 = target->getIn(j);
	if (in2->isWritten() && (in2->getDef()->code() == CPUI_COPY))
	  in2 = in2->getDef()->getIn(0);
	if (in1 == in2) continue;
	if (0!=functionalEqualityLevel(in1,in2,buf1,buf2))
	  break;
      }
      if (j==numinput)		// We have found a redundancy
	return op;
    }
  }
  return (PcodeOp *)0;
}

/// Search for pairs of CPUI_MULTIEQUAL ops in \b bl that share an input.
/// If the pairs found are functionally equivalent, delete one of the two.
/// \param data is the function owning the block
/// \param bl is the specific basic block
/// return \b true if a CPUI_MULTIEQUAL was (successfully) deleted
bool ActionMultiCse::processBlock(Funcdata &data,BlockBasic *bl)

{
  vector<Varnode *> vnlist;
  PcodeOp *targetop = (PcodeOp *)0;
  PcodeOp *pairop;
  list<PcodeOp *>::iterator iter = bl->beginOp();
  list<PcodeOp *>::iterator enditer = bl->endOp();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    OpCode opc = op->code();
    if (opc == CPUI_COPY) continue;
    if (opc != CPUI_MULTIEQUAL) break;
    int4 vnpos = vnlist.size();
    int4 i;
    int4 numinput = op->numInput();
    for(i=0;i<numinput;++i) {
      Varnode *vn = op->getIn(i);
      if (vn->isWritten() && (vn->getDef()->code() == CPUI_COPY))	// Some copies may not propagate into MULTIEQUAL
	vn = vn->getDef()->getIn(0);					// Allow for differences in copy propagation
      vnlist.push_back(vn);
      if (vn->isMark()) {		// If we've seen this varnode before
	pairop = findMatch(bl,op,vn);
	if (pairop != (PcodeOp *)0)
	  break;
      }
    }
    if (i<numinput) {
      targetop = op;
      break;
    }
    for(i=vnpos;i<vnlist.size();++i)
      vnlist[i]->setMark();		// Mark that we have seen this varnode
  }

  // Clear out any of the marks we put down
  for(int4 i=0;i<vnlist.size();++i)
    vnlist[i]->clearMark();

  if (targetop != (PcodeOp *)0) {
    Varnode *out1 = pairop->getOut();
    Varnode *out2 = targetop->getOut();
    if (preferredOutput(out1,out2)) {
      data.totalReplace(out1,out2);	// Replace pairop and out1 in favor of targetop and out2
      data.opDestroy(pairop);
    }
    else {
      data.totalReplace(out2,out1);
      data.opDestroy(targetop);
    }
    count += 1;		// Indicate that a change has taken place
    return true;
  }
  return false;
}

int4 ActionMultiCse::apply(Funcdata &data)

{
  const BlockGraph &bblocks( data.getBasicBlocks() );
  int4 sz = bblocks.getSize();
  for(int4 i=0;i<sz;++i) {
    BlockBasic *bl = (BlockBasic *)bblocks.getBlock(i);
    while(processBlock(data,bl)) {
    }
  }
  return 0;
}

int4 ActionShadowVar::apply(Funcdata &data)

{
  const BlockGraph &bblocks(data.getBasicBlocks());
  BlockBasic *bl;
  PcodeOp *op;
  Varnode *vn;
  vector<Varnode *> vnlist;
  list<PcodeOp *> oplist;
  uintb startoffset;
  for(int4 i=0;i<bblocks.getSize();++i) {
    vnlist.clear();
    bl = (BlockBasic *)bblocks.getBlock(i);
    // Iterator over all MULTIEQUALs in the block
    // We have to check all ops in the first address
    // We cannot stop at first non-MULTIEQUAL because
    // other ops creep in because of multi_collapse
    startoffset = bl->getStart().getOffset();
    list<PcodeOp *>::iterator iter = bl->beginOp();
    while(iter != bl->endOp()) {
      op = *iter++;
      if (op->getAddr().getOffset() != startoffset) break;
      if (op->code() != CPUI_MULTIEQUAL) continue;
      vn = op->getIn(0);
      if (vn->isMark())
	  oplist.push_back(op);
      else {
	vn->setMark();
	vnlist.push_back(vn);
      }
    }
    for(int4 j=0;j<vnlist.size();++j)
      vnlist[j]->clearMark();
  }
  list<PcodeOp *>::iterator oiter;
  for(oiter=oplist.begin();oiter!=oplist.end();++oiter) {
    op = *oiter;
    PcodeOp *op2;
    for(op2=op->previousOp();op2!=(PcodeOp *)0;op2=op2->previousOp()) {
      if (op2->code() != CPUI_MULTIEQUAL) continue;
      int4 i;
      for(i=0;i<op->numInput();++i) // Check for match in each branch
	if (op->getIn(i) != op2->getIn(i)) break;
      if (i != op->numInput()) continue; // All branches did not match

      vector<Varnode *> plist;
      plist.push_back(op2->getOut());
      data.opSetOpcode(op,CPUI_COPY);
      data.opSetAllInput(op,plist);
      count += 1;
    }
  }

  return 0;
}

/// \brief Make a limited search from a constant for a LOAD or STORE so we can see the AddrSpace being accessed
///
/// We traverse forward through the op reading the constant, through INT_ADD, INDIRECT, COPY, and MULTIEQUAL
/// until we hit a LOAD or STORE.
/// \param vn is the constant we are searching from
/// \param op is the PcodeOp reading the constant
/// \return the discovered AddrSpace or null
AddrSpace *ActionConstantPtr::searchForLoadStore(Varnode *vn,PcodeOp *op)

{
  for(int4 i=0;i<3;++i) {
    switch(op->code()) {
      case CPUI_INT_ADD:
      case CPUI_COPY:
      case CPUI_INDIRECT:
      case CPUI_MULTIEQUAL:
	vn = op->getOut();
	op = vn->loneDescend();
	break;
      case CPUI_LOAD:
	return Address::getSpaceFromConst(op->getIn(0)->getAddr());
      case CPUI_STORE:
	if (op->getIn(1) == vn)
	  return Address::getSpaceFromConst(op->getIn(0)->getAddr());
	return (AddrSpace *)0;
      default:
	return (AddrSpace *)0;
    }
    if (op == (PcodeOp *)0) break;
  }
  for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    op = *iter;
    OpCode opc = op->code();
    if (opc == CPUI_LOAD)
      return Address::getSpaceFromConst(op->getIn(0)->getAddr());
    else if (opc == CPUI_STORE && op->getIn(1) == vn)
      return Address::getSpaceFromConst(op->getIn(0)->getAddr());
  }
  return (AddrSpace *)0;
}

/// \brief Select the AddrSpace in which we infer with the given constant is a pointer
///
/// The constant must match the AddrSpace address size. If there is more than one possible match,
/// search for more information in the syntax tree.
/// \param vn is the given constant Varnode
/// \param op is the PcodeOp which uses the constant
/// \param spaceList is the list of address spaces to select from
/// \return the selected address space or null
AddrSpace *ActionConstantPtr::selectInferSpace(Varnode *vn,PcodeOp *op,const vector<AddrSpace *> &spaceList)

{
  AddrSpace *resSpace = (AddrSpace *)0;
  for(int4 i=0;i<spaceList.size();++i) {
    AddrSpace *spc = spaceList[i];
    int4 minSize = spc->getMinimumPtrSize();
    if (minSize == 0) {
      if (vn->getSize() != spc->getAddrSize())
	continue;
    }
    else if (vn->getSize() < minSize)
      continue;
    if (resSpace != (AddrSpace *)0) {
      AddrSpace *searchSpc = searchForLoadStore(vn,op);
      if (searchSpc != (AddrSpace *)0)
	resSpace = searchSpc;
      break;
    }
    resSpace = spc;
  }
  return resSpace;
}

/// \brief Determine if given Varnode might be a pointer constant.
///
/// If it is a pointer, return the symbol it points to, or NULL otherwise. If it is determined
/// that the Varnode is a pointer to a specific symbol, the encoding of the full pointer is passed back.
/// Usually this is just the constant value of the Varnode, but in this case of partial pointers
/// (like \e near pointers) the full pointer may contain additional information.
/// \param spc is the address space being pointed to
/// \param vn is the given Varnode
/// \param op is the lone descendant of the Varnode
/// \param slot is the slot index of the Varnode
/// \param rampoint will hold the Address of the resolved symbol
/// \param fullEncoding will hold the full pointer encoding being passed back
/// \param data is the function being analyzed
/// \return the recovered symbol or NULL
SymbolEntry *ActionConstantPtr::isPointer(AddrSpace *spc,Varnode *vn,PcodeOp *op,int4 slot,
					  Address &rampoint,uintb &fullEncoding,Funcdata &data)

{
  bool needexacthit;
  Architecture *glb = data.getArch();
  Varnode *outvn;
  if (vn->getType()->getMetatype() == TYPE_PTR) { // Are we explicitly marked as a pointer
    rampoint = glb->resolveConstant(spc,vn->getOffset(),vn->getSize(),op->getAddr(),fullEncoding);
    needexacthit = false;
  }
  else {
    if (vn->isTypeLock()) return (SymbolEntry *)0; // Locked as NOT a pointer
    needexacthit = true;
    // Check if the constant is involved in a potential pointer expression
    // as the base
    switch(op->code()) {
    case CPUI_RETURN:
    case CPUI_CALL:
    case CPUI_CALLIND:
      // A constant parameter or return value could be a pointer
      if (!glb->infer_pointers)
	return (SymbolEntry *)0;
      if (slot==0)
	return (SymbolEntry *)0;
      break;
    case CPUI_COPY:
    case CPUI_INT_EQUAL:
    case CPUI_INT_NOTEQUAL:
    case CPUI_INT_LESS:
    case CPUI_INT_LESSEQUAL:
      // A comparison with a constant could be a pointer
      break;
    case CPUI_INT_ADD:
      outvn = op->getOut();
      if (outvn->getType()->getMetatype()==TYPE_PTR) {
	// Is there another pointer base in this expression
	if (op->getIn(1-slot)->getType()->getMetatype()==TYPE_PTR)
	  return (SymbolEntry *)0; // If so, we are not a pointer
	// FIXME: need to fully explore additive tree
	needexacthit = false;
      }
      else if (!glb->infer_pointers)
	return (SymbolEntry *)0;
      break;
    case CPUI_STORE:
      if (slot != 2)
	return (SymbolEntry *)0;
      break;
    default:
      return (SymbolEntry *)0;
    }
    // Make sure the constant is in the expected range for a pointer
    if (spc->getPointerLowerBound() > vn->getOffset())
      return (SymbolEntry *)0;
    if (spc->getPointerUpperBound() < vn->getOffset())
      return (SymbolEntry *)0;
    // Check if the constant looks like a single bit or mask
    if (bit_transitions(vn->getOffset(),vn->getSize()) < 3)
      return (SymbolEntry *)0;
    rampoint = glb->resolveConstant(spc,vn->getOffset(),vn->getSize(),op->getAddr(),fullEncoding);
  }

  if (rampoint.isInvalid()) return (SymbolEntry *)0;
    // Since we are looking for a global address
    // Assume it is address tied and use empty usepoint
  SymbolEntry *entry = data.getScopeLocal()->getParent()->queryContainer(rampoint,1,Address());
  if (entry != (SymbolEntry *)0) {
    Datatype *ptrType = entry->getSymbol()->getType();
    if (ptrType->getMetatype() == TYPE_ARRAY) {
      Datatype *ct = ((TypeArray *)ptrType)->getBase();
      // In the special case of strings (character arrays) we allow the constant pointer to
      // refer to the middle of the string
      if (ct->isCharPrint())
	needexacthit = false;
    }
    if (needexacthit && entry->getAddr() != rampoint)
      return (SymbolEntry *)0;
  }
  return entry;
}

int4 ActionConstantPtr::apply(Funcdata &data)

{
  if (!data.isTypeRecoveryOn()) return 0;

  if (localcount >= 4)		// At most 4 passes (once type recovery starts)
    return 0;
  localcount += 1;

  VarnodeLocSet::const_iterator begiter,enditer;
  Architecture *glb = data.getArch();
  AddrSpace *cspc = glb->getConstantSpace();
  SymbolEntry *entry;
  Varnode *vn;

  begiter = data.beginLoc(cspc);
  enditer = data.endLoc(cspc);

  while(begiter!=enditer) {
    vn = *begiter++;
    if (!vn->isConstant()) break; // New varnodes may get inserted between begiter and enditer
    if (vn->getOffset() == 0) continue; // Never make constant 0 into spacebase
    if (vn->isPtrCheck()) continue; // Have we checked this variable before
    if (vn->hasNoDescend()) continue;
    if (vn->isSpacebase()) continue; // Don't use constant 0 which is already spacebase
    //    if (vn->getSize() != rspc->getAddrSize()) continue; // Must be size of pointer

    PcodeOp *op = vn->loneDescend();
    if (op == (PcodeOp *)0) continue;
    AddrSpace *rspc = selectInferSpace(vn, op, glb->inferPtrSpaces);
    if (rspc == (AddrSpace *)0) continue;
    int4 slot = op->getSlot(vn);
    OpCode opc = op->code();
    if (opc == CPUI_INT_ADD) {
      if (op->getIn(1-slot)->isSpacebase()) continue; // Make sure other side is not a spacebase already
    }
    else if ((opc == CPUI_PTRSUB)||(opc==CPUI_PTRADD))
      continue;
    Address rampoint;
    uintb fullEncoding;
    entry = isPointer(rspc,vn,op,slot,rampoint,fullEncoding,data);
    vn->setPtrCheck();		// Set check flag AFTER searching for symbol
    if (entry != (SymbolEntry *)0) {
      data.spacebaseConstant(op,slot,entry,rampoint,fullEncoding,vn->getSize());
      if ((opc == CPUI_INT_ADD)&&(slot==1))
	data.opSwapInput(op,0,1);
      count += 1;
    }
  }
  return 0;
}

int4 ActionDeindirect::apply(Funcdata &data)

{
  FuncCallSpecs *fc;
  PcodeOp *op;
  Varnode *vn;

  for(int4 i=0;i<data.numCalls();++i) {
    fc = data.getCallSpecs(i);
    op = fc->getOp();
    if (op->code() != CPUI_CALLIND) continue;
    vn = op->getIn(0);
    while(vn->isWritten()&&(vn->getDef()->code()==CPUI_COPY))
      vn = vn->getDef()->getIn(0);
    if (vn->isPersist() && vn->isExternalRef()) { // Check for possible external reference
      Funcdata *newfd = data.getScopeLocal()->getParent()->queryExternalRefFunction(vn->getAddr());
      if (newfd != (Funcdata *)0) {
	fc->deindirect(data,newfd);
	count += 1;
	continue;
      }
    }
    else if (vn->isConstant()) {
      AddrSpace *sp = data.getAddress().getSpace(); // Assume function is in same space as calling function
      // Convert constant to a byte address in this space
      uintb offset = AddrSpace::addressToByte(vn->getOffset(),sp->getWordSize());
      int4 align = data.getArch()->funcptr_align;
      if (align != 0) {		// If we know function pointer should be aligned
	offset >>= align;	// Remove any encoding bits before querying for the function
	offset <<= align;
      }
      Address codeaddr(sp,offset);
      Funcdata *newfd = data.getScopeLocal()->getParent()->queryFunction(codeaddr);
      if (newfd != (Funcdata *)0) {
	fc->deindirect(data,newfd);
	count += 1;
	continue;
      }
    }
    if (data.isTypeRecoveryOn()) {
      // Check for a function pointer that has an attached prototype
      Datatype *ct = op->getIn(0)->getType();
      if ((ct->getMetatype()==TYPE_PTR)&&
	  (((TypePointer *)ct)->getPtrTo()->getMetatype()==TYPE_CODE)) {
	TypeCode *tc = (TypeCode *)((TypePointer *)ct)->getPtrTo();
	const FuncProto *fp = tc->getPrototype();
	if (fp!=(const FuncProto *)0) {
	  if (!fc->isInputLocked()) {
	    // We use isInputLocked as a test of whether the
	    // function pointer prototype has been applied before
	    fc->forceSet(data,*fp);
	    count += 1;
	  }
	}
	// FIXME: If fc's input IS locked presumably this means
	// that this prototype is already set, but it MIGHT mean
	// we have conflicting locked prototypes
      }
    }
  }
  return 0;
}

int4 ActionVarnodeProps::apply(Funcdata &data)

{
  Architecture *glb = data.getArch();
  bool cachereadonly = glb->readonlypropagate;
  int4 pass = data.getHeritagePass();
  VarnodeLocSet::const_iterator iter;
  Varnode *vn;

  iter = data.beginLoc();
  while(iter != data.endLoc()) {
    vn = *iter++;		// Advance iterator in case vn is deleted
    if (vn->isAnnotation()) continue;
    int4 vnSize = vn->getSize();
    if (vn->isAutoLiveHold()) {
      if (pass > 0) {
	if (vn->isWritten()) {
	  PcodeOp *loadOp = vn->getDef();
	  if (loadOp->code() == CPUI_LOAD) {
	    Varnode *ptr = loadOp->getIn(1);
	    if (ptr->isConstant() || ptr->isReadOnly())
	      continue;
	    if (ptr->isWritten()) {
	      PcodeOp *copyOp = ptr->getDef();
	      if (copyOp->code() == CPUI_COPY) {
		ptr = copyOp->getIn(0);
		if (ptr->isConstant() || ptr->isReadOnly())
		  continue;
	      }
	    }
	  }
	}
	vn->clearAutoLiveHold();
	count += 1;
      }
    }
    else if (vn->hasActionProperty()) {
      if (cachereadonly&&vn->isReadOnly()) {
	if (data.fillinReadOnly(vn)) // Try to replace vn with its lookup in LoadImage
	  count += 1;
      }
      else if (vn->isVolatile())
	if (data.replaceVolatile(vn))
	  count += 1;		// Try to replace vn with pcode op
    }
    else if (((vn->getNZMask() & vn->getConsume())==0)&&(vnSize<=sizeof(uintb))) {
      // FIXME: uintb should be arbitrary precision
      if (vn->isConstant()) continue; // Don't replace a constant
      if (vn->isWritten()) {
	if (vn->getDef()->code() == CPUI_COPY) {
	  if (vn->getDef()->getIn(0)->isConstant()) {
	    // Don't replace a COPY 0, with a zero, let
	    // constant propagation do that. This prevents
	    // an infinite recursion
	    if (vn->getDef()->getIn(0)->getOffset() == 0)
	      continue;
	  }
	}
      }
      if (!vn->hasNoDescend()) {
	data.totalReplaceConstant(vn,0);
	count += 1;
      }
    }
  }
  data.setLanedRegGenerated();
  return 0;
}

int4 ActionDirectWrite::apply(Funcdata &data)

{
  VarnodeLocSet::const_iterator iter;
  list<PcodeOp *>::const_iterator oiter;
  Varnode *vn,*dvn;
  PcodeOp *op;
  vector<Varnode *> worklist;

				// Collect legal inputs and other auto direct writes
  for(iter=data.beginLoc();iter!=data.endLoc();++iter) {
    vn = *iter;
    vn->clearDirectWrite();
    if (vn->isInput()) {
      if (vn->isPersist()||vn->isSpacebase()) {
	vn->setDirectWrite();
	worklist.push_back(vn);
      }
      else if (data.getFuncProto().possibleInputParam(vn->getAddr(),vn->getSize())) {
	vn->setDirectWrite();
	worklist.push_back(vn);
      }
    }
    else if (vn->isWritten()) {
      op = vn->getDef();
      if (!op->isMarker()) {
	if (vn->isPersist()) {
	  // Anything that writes to a global variable (in a real way) is considered a direct write
	  vn->setDirectWrite();
	  worklist.push_back(vn);
	}
	else if (op->code() == CPUI_COPY) {	// For most COPYs, do not consider it a direct write
	  if (vn->isStackStore()) {		// But, if the original operation was really a CPUI_STORE
	    Varnode *invn = op->getIn(0);	// Trace COPY source
	    if (invn->isWritten()) {		// Through possible multiple COPYs
	      PcodeOp *curop = invn->getDef();
	      if (curop->code() == CPUI_COPY)
		invn = curop->getIn(0);
	    }
	    if (invn->isWritten() && invn->getDef()->isMarker()) {	// if source is from an INDIRECT
	      vn->setDirectWrite();					// then treat this as a direct write
	      worklist.push_back(vn);
	    }
	  }
	}
	else if ((op->code()!=CPUI_PIECE)&&(op->code()!=CPUI_SUBPIECE)) {
	  // Anything that writes to a variable in a way that isn't some form of COPY is a direct write
	  vn->setDirectWrite();
	  worklist.push_back(vn);
	}
      }
      else if (!propagateIndirect && op->code() == CPUI_INDIRECT) {
	Varnode *outvn = op->getOut();
	if (op->getIn(0)->getAddr() != outvn->getAddr())	// Check if storage address changes from input to output
	  vn->setDirectWrite();					// Indicates an active COPY, which is a direct write
	else if (outvn->isPersist())				// Value must be present at global storage at point call is made
	  vn->setDirectWrite();					//   so treat as direct write
	// We do NOT add vn to worklist as INDIRECT otherwise does not propagate
      }
    }
    else if (vn->isConstant()) {
      if (!vn->isIndirectZero()) {
	vn->setDirectWrite();
	worklist.push_back(vn);
      }
    }
  }
				// Let legalness taint
  while(!worklist.empty()) {
    vn = worklist.back();
    worklist.pop_back();
    for(oiter=vn->beginDescend();oiter!=vn->endDescend();++oiter) {
      op = *oiter;
      if (!op->isAssignment()) continue;
      dvn = op->getOut();
      if (!dvn->isDirectWrite()) {
	dvn->setDirectWrite();
	// For call based INDIRECTs, output is marked, but does not propagate depending on setting
	if (propagateIndirect || op->code() != CPUI_INDIRECT || op->isIndirectStore())
	  worklist.push_back(dvn);
      }
    }
  }
  return 0;
}

int4 ActionExtraPopSetup::apply(Funcdata &data)

{
  FuncCallSpecs *fc;
  PcodeOp *op;

  if (stackspace == (AddrSpace *)0) return 0; // No stack to speak of
  const VarnodeData &point(stackspace->getSpacebase(0));
  Address sb_addr(point.space,point.offset);
  int4 sb_size = point.size;
  
  for(int4 i=0;i<data.numCalls();++i) {
    fc = data.getCallSpecs(i);
    if (fc->getExtraPop() == 0) continue; // Stack pointer is undisturbed
    op = data.newOp(2,fc->getOp()->getAddr());
    data.newVarnodeOut(sb_size,sb_addr,op);
    data.opSetInput(op,data.newVarnode(sb_size,sb_addr),0);
    if (fc->getExtraPop() != ProtoModel::extrapop_unknown) { // We know exactly how stack pointer is changed
      fc->setEffectiveExtraPop(fc->getExtraPop());
      data.opSetOpcode(op,CPUI_INT_ADD);
      data.opSetInput(op,data.newConstant(sb_size,fc->getExtraPop()),1);
      data.opInsertAfter(op,fc->getOp());
    }
    else {			// We don't know exactly, so we create INDIRECT
      data.opSetOpcode(op,CPUI_INDIRECT);
      data.opSetInput(op,data.newVarnodeIop(fc->getOp()),1);
      data.opInsertBefore(op,fc->getOp());
    }
  }
  return 0;
}

/// \brief Set up the parameter recovery process for a single sub-function call
///
/// If the prototype is known (locked), insert stub Varnodes
/// If the prototype is varargs (dotdotdot), set up recovery of variable Varnodes
/// \param fc is the given sub-function
/// \param data is the function being analyzed
void ActionFuncLink::funcLinkInput(FuncCallSpecs *fc,Funcdata &data)

{
  bool inputlocked = fc->isInputLocked();
  bool varargs = fc->isDotdotdot();
  AddrSpace *spacebase = fc->getSpacebase();	// Non-zero spacebase indicates we need a stackplaceholder
  ParamActive *active = fc->getActiveInput();

  if ((!inputlocked)||varargs)
    fc->initActiveInput();
  if (inputlocked) {
    PcodeOp *op = fc->getOp();
    int4 numparam = fc->numParams();
    bool setplaceholder = varargs;
    for(int4 i=0;i<numparam;++i) {
      ProtoParameter *param = fc->getParam(i);
      active->registerTrial(param->getAddress(),param->getSize());
      active->getTrial(i).markActive(); // Parameter is not optional
      AddrSpace *spc = param->getAddress().getSpace();
      uintb off = param->getAddress().getOffset();
      int4 sz = param->getSize();
      if (spc->getType() == IPTR_SPACEBASE) { // Param is stack relative
	Varnode *loadval = data.opStackLoad(spc,off,sz,op,(Varnode *)0,false);
	data.opInsertInput(op,loadval,op->numInput());
	if (!setplaceholder) {
	  setplaceholder = true;
	  loadval->setSpacebasePlaceholder();
	  spacebase = (AddrSpace *)0;	// With a locked stack parameter, we don't need a stackplaceholder
	}
      }
      else
	data.opInsertInput(op,data.newVarnode(param->getSize(),param->getAddress()),op->numInput());
    }
  }
  if (spacebase != (AddrSpace *)0) {	// If we need it, create the stackplaceholder
    PcodeOp *op = fc->getOp();
    int4 slot = op->numInput();
    Varnode *loadval = data.opStackLoad(spacebase,0,1,op,(Varnode *)0,false);
    data.opInsertInput(op,loadval,slot);
    fc->setStackPlaceholderSlot(slot);
    loadval->setSpacebasePlaceholder();
  }
}

/// \brief Set up the return value recovery process for a single sub-function call
///
/// If the prototype is known(locked), insert an output Varnode on the call
/// If the prototype is unknown set-up the ParamActive, so that outputs will be "gathered"
/// \param fc is the given sub-function
/// \param data is the function being analyzed
void ActionFuncLink::funcLinkOutput(FuncCallSpecs *fc,Funcdata &data)

{
  if (fc->isOutputLocked()) {
    ProtoParameter *outparam = fc->getOutput();
    Datatype *outtype = outparam->getType();
    if (outtype->getMetatype() != TYPE_VOID) {
      int4 sz = outparam->getSize();
      Address addr = outparam->getAddress();
      data.newVarnodeOut(sz,addr,fc->getOp());
      VarnodeData vdata;
      OpCode res = fc->assumedOutputExtension(addr,sz,vdata);
      if (res == CPUI_PIECE) {		// Pick an extension based on type
	if (outtype->getMetatype() == TYPE_INT)
	  res = CPUI_INT_SEXT;
	else
	  res = CPUI_INT_ZEXT;
      }
      if (res != CPUI_COPY) { // We assume the (smallsize) output is extended to a full register
	PcodeOp *callop = fc->getOp();
	// Create the extension operation to eliminate artifact
	PcodeOp *op = data.newOp(1,callop->getAddr());
	data.newVarnodeOut(vdata.size,vdata.getAddr(),op);
	Varnode *invn = data.newVarnode(sz,addr);
	data.opSetInput(op,invn,0);
	data.opSetOpcode(op,res);
	data.opInsertAfter(op,callop); // Insert immediately after the call
      }
    }
  }
  else
    fc->initActiveOutput();
}

int4 ActionFuncLink::apply(Funcdata &data)

{
  int4 i,size;

  size = data.numCalls();
  for(i=0;i<size;++i) {
    funcLinkInput(data.getCallSpecs(i),data);
    funcLinkOutput(data.getCallSpecs(i),data);
  }
  return 0;
}

int4 ActionFuncLinkOutOnly::apply(Funcdata &data)

{
  int4 size = data.numCalls();
  for(int4 i=0;i<size;++i)
    ActionFuncLink::funcLinkOutput(data.getCallSpecs(i),data);
  return 0;
}

int4 ActionParamDouble::apply(Funcdata &data)

{
  for(int4 i=0;i<data.numCalls();++i) {
    FuncCallSpecs *fc = data.getCallSpecs(i);
    PcodeOp *op = fc->getOp();
    if (fc->isInputActive()) {
      ParamActive *active = fc->getActiveInput();
      for(int4 j=0;j<active->getNumTrials();++j) {
	const ParamTrial &paramtrial( active->getTrial(j) );
	if (paramtrial.isChecked()) continue;
	if (paramtrial.isUnref()) continue;
	AddrSpace *spc = paramtrial.getAddress().getSpace();
	if (spc->getType() != IPTR_SPACEBASE) continue;
	int4 slot = paramtrial.getSlot();
	Varnode *vn = op->getIn(slot);
	if (!vn->isWritten()) continue;
	PcodeOp *concatop = vn->getDef();
	if (concatop->code() != CPUI_PIECE) continue;
	if (!fc->hasModel()) continue;
	Varnode *mostvn = concatop->getIn(0);
	Varnode *leastvn = concatop->getIn(1);
	int4 splitsize = spc->isBigEndian() ? mostvn->getSize() : leastvn->getSize();
	if (fc->checkInputSplit(paramtrial.getAddress(),paramtrial.getSize(),splitsize)) {
	  active->splitTrial(j,splitsize);
	  if (spc->isBigEndian()) {
	    data.opInsertInput(op,mostvn,slot);
	    data.opSetInput(op,leastvn,slot+1);
	  }
	  else {
	    data.opInsertInput(op,leastvn,slot);
	    data.opSetInput(op,mostvn,slot+1);
	  }
	  count += 1;		// Indicate that a change was made
	  
	  j -= 1;	// Note we decrement j here, so that we can check nested CONCATs
	}
      }
    }
    else if ((!fc->isInputLocked())&&(data.isDoublePrecisOn())) {
      // Search for double precision objects that might become params
      int4 max = op->numInput() - 1;
      // Look for adjacent slots that form pieces of a double precision whole
      for(int4 j=1;j<max;++j) {
	Varnode *vn1 = op->getIn(j);
	Varnode *vn2 = op->getIn(j+1);
	SplitVarnode whole;
	bool isslothi;
	if (whole.inHandHi(vn1)) {
	  if (whole.getLo() != vn2) continue;
	  isslothi = true;
	}
	else if (whole.inHandLo(vn1)) {
	  if (whole.getHi() != vn2) continue;
	  isslothi = false;
	}	  
	else
	  continue;
	if (fc->checkInputJoin(j,isslothi,vn1,vn2)) {
	  data.opSetInput(op,whole.getWhole(),j);
	  data.opRemoveInput(op,j+1);
	  fc->doInputJoin(j,isslothi);
	  max = op->numInput() - 1;
	  count += 1;
	}
      }
    }
  }


  const FuncProto &fp( data.getFuncProto() );
  if (fp.isInputLocked() && data.isDoublePrecisOn()) {
    // Search for locked parameters that are being split into hi and lo components
    vector<Varnode *> lovec;
    vector<Varnode *> hivec;
    int4 minDoubleSize = data.getArch()->getDefaultSize();	// Minimum size to consider
    int4 numparams = fp.numParams();
    for(int4 i=0;i<numparams;++i) {
      ProtoParameter *param = fp.getParam(i);
      Datatype *tp = param->getType();
      type_metatype mt = tp->getMetatype();
      if ((mt==TYPE_ARRAY)||(mt==TYPE_STRUCT)) continue; // Not double precision objects
      Varnode *vn = data.findVarnodeInput(tp->getSize(),param->getAddress());
      if (vn == (Varnode *)0) continue;
      if (vn->getSize() < minDoubleSize) continue;
      int4 halfSize = vn->getSize() / 2;
      lovec.clear();
      hivec.clear();
      bool otherUse = false;		// Have we seen use other than splitting into hi and lo
      list<PcodeOp *>::const_iterator iter,enditer;
      iter = vn->beginDescend();
      enditer = vn->endDescend();
      while(iter != enditer) {
	PcodeOp *subop = *iter;
	++iter;
	if (subop->code() != CPUI_SUBPIECE) continue;
	Varnode *outvn = subop->getOut();
	if (outvn->getSize() != halfSize) continue;
	if (subop->getIn(1)->getOffset() == 0)	// Possible lo precision piece
	  lovec.push_back(outvn);
	else if (subop->getIn(1)->getOffset() == halfSize)	// Possible hi precision piece
	  hivec.push_back(outvn);
	else {
	  otherUse = true;
	  break;
	}
      }
      if ((!otherUse)&&(!lovec.empty())&&(!hivec.empty())) {	// Seen (only) hi and lo uses
	for(int4 j=0;j<lovec.size();++j) {
	  Varnode *piecevn = lovec[j];
	  if (!piecevn->isPrecisLo()) {
	    piecevn->setPrecisLo();
	    count += 1;		// Indicate we made change
	  }
	}
	for(int4 j=0;j<hivec.size();++j) {
	  Varnode *piecevn = hivec[j];
	  if (!piecevn->isPrecisHi()) {
	    piecevn->setPrecisHi();
	    count += 1;
	  }
	}
      }
    }
  }
  return 0;
}

int4 ActionActiveParam::apply(Funcdata &data)

{
  int4 i;
  FuncCallSpecs *fc;
  AliasChecker aliascheck;
  aliascheck.gather(&data,data.getArch()->getStackSpace(),true);

  for(i=0;i<data.numCalls();++i) {
    fc = data.getCallSpecs(i);
				// An indirect function is not trimmable until
				// there has been at least one simplification pass
				// there has been a change to deindirect
    try {
      if (fc->isInputActive()) {
	ParamActive *activeinput = fc->getActiveInput();
	bool trimmable = ((activeinput->getNumPasses()>0)||(fc->getOp()->code() != CPUI_CALLIND));
	if (!activeinput->isFullyChecked())
	  fc->checkInputTrialUse(data,aliascheck);
	activeinput->finishPass();
	if (activeinput->getNumPasses() > activeinput->getMaxPass())
	  activeinput->markFullyChecked();
	else
	  count += 1;		// Count a change, to indicate we still have work to do
	if (trimmable && activeinput->isFullyChecked()) {
	  if (activeinput->needsFinalCheck())
	    fc->finalInputCheck();
	  fc->resolveModel(activeinput);
	  fc->deriveInputMap(activeinput);
	  fc->buildInputFromTrials(data);
	  fc->clearActiveInput();
	  count += 1;
	}
      }
    }
    catch(LowlevelError &err) {
      ostringstream s;
      s << "Error processing " << fc->getName();
      PcodeOp *op = fc->getOp();
      if (op != (PcodeOp *)0)
	s << " called at " << op->getSeqNum();
      s << ": " << err.explain;
      throw LowlevelError(s.str());
    }
  }
  return 0;
}

int4 ActionActiveReturn::apply(Funcdata &data)

{
  int4 i;
  FuncCallSpecs *fc;

  for(i=0;i<data.numCalls();++i) {
    fc = data.getCallSpecs(i);
    if (fc->isOutputActive()) {
      ParamActive *activeoutput = fc->getActiveOutput();
      vector<Varnode *> trialvn;
      fc->checkOutputTrialUse(data,trialvn);
      fc->deriveOutputMap(activeoutput);
      fc->buildOutputFromTrials(data,trialvn);
      fc->clearActiveOutput();
      count += 1;
    }
  }
  return 0;
}

// int4 ActionParamShiftStart::apply(Funcdata &data)

// {
//   int4 i;
//   FuncCallSpecs *fc;

//   for(i=0;i<data.numCalls();++i) {
//     fc = data.getCallSpecs(i);
//     fc->paramshiftModifyStart();
//   }
//   return 0;
// }

// int4 ActionParamShiftStop::apply(Funcdata &data)

// {
//   int4 i;
//   FuncCallSpecs *fc;

//   if (!paramshiftsleft) return 0;
//   paramshiftsleft = false;
//   for(i=0;i<data.numCalls();++i) {
//     fc = data.getCallSpecs(i);
//     if (fc->getParamshift() != 0) {
//       if (!fc->isInputActive()) {
// 	if (fc->paramshiftModifyStop(data))
// 	  count += 1;
//       }
//       else
// 	paramshiftsleft = true;
//     }
//   }
//   return 0;
// }

/// \brief Rewrite a CPUI_RETURN op to reflect a recovered output parameter.
///
/// Add a second input Varnode to the given CPUI_RETURN PcodeOp holding the return value
/// for the function at that point. Construct concatentations if there are multiple pieces
/// \param active is the output parameter description
/// \param retop is the given CPUI_RETURN
/// \param data is the function being analyzed
void ActionReturnRecovery::buildReturnOutput(ParamActive *active,PcodeOp *retop,Funcdata &data)

{
  vector<Varnode *> newparam;

  newparam.push_back(retop->getIn(0)); // Keep the first param (the return indirect reference)
  for(int4 i=0;i<active->getNumTrials();++i) { // Gather all the used varnodes to this return in proper order
    ParamTrial &curtrial(active->getTrial(i));
    if (!curtrial.isUsed()) break;
    if (curtrial.getSlot() >= retop->numInput()) break;
    newparam.push_back(retop->getIn(curtrial.getSlot()));
  }
  if (newparam.size()<=2)	// Easy zero or one return varnode case
    data.opSetAllInput(retop,newparam);
  else if (newparam.size()==3) { // Two piece concatenation case
    Varnode *lovn = newparam[1];
    Varnode *hivn = newparam[2];
    ParamTrial &triallo( active->getTrial(0) );
    ParamTrial &trialhi( active->getTrial(1) );
    Address joinaddr = data.getArch()->constructJoinAddress(data.getArch()->translate,
							    trialhi.getAddress(),trialhi.getSize(),
							    triallo.getAddress(),triallo.getSize());
    PcodeOp *newop = data.newOp(2,retop->getAddr());
    data.opSetOpcode(newop,CPUI_PIECE);
    Varnode *newwhole = data.newVarnodeOut(trialhi.getSize()+triallo.getSize(),joinaddr,newop);
    newwhole->setWriteMask();		// Don't let new Varnode cause additional heritage
    data.opInsertBefore(newop,retop);
    newparam.pop_back();
    newparam.back() = newwhole;
    data.opSetAllInput(retop,newparam);
    data.opSetInput(newop,hivn,0);
    data.opSetInput(newop,lovn,1);
  }
  else { // We may have several varnodes from a single container
    // Concatenate them into a single result
    newparam.clear();
    newparam.push_back(retop->getIn(0));
    int4 offmatch = 0;
    Varnode *preexist = (Varnode *)0;
    for(int4 i=0;i<active->getNumTrials();++i) {
      ParamTrial &curtrial(active->getTrial(i));
      if (!curtrial.isUsed()) break;
      if (curtrial.getSlot() >= retop->numInput()) break;
      if (preexist == (Varnode *)0) {
	preexist = retop->getIn(curtrial.getSlot());
	offmatch = curtrial.getOffset() + curtrial.getSize();
      }
      else if (offmatch == curtrial.getOffset()) {
	offmatch += curtrial.getSize();
	Varnode *vn = retop->getIn(curtrial.getSlot());
	// Concatenate the preexisting pieces with this new piece
	PcodeOp *newop = data.newOp(2,retop->getAddr());
	data.opSetOpcode(newop,CPUI_PIECE);
	Address addr = preexist->getAddr();
	if (vn->getAddr() < addr)
	  addr = vn->getAddr();
	Varnode *newout = data.newVarnodeOut(preexist->getSize()+vn->getSize(),addr,newop);
	newout->setWriteMask();		// Don't let new Varnode cause additional heritage
	data.opSetInput(newop,vn,0);	// Most sig part
	data.opSetInput(newop,preexist,1);
	data.opInsertBefore(newop,retop);
	preexist = newout;
      }
      else
	break;
    }
    if (preexist != (Varnode *)0)
      newparam.push_back(preexist);
    data.opSetAllInput(retop,newparam);
  }
}

int4 ActionReturnRecovery::apply(Funcdata &data)

{
  ParamActive *active = data.getActiveOutput();
  if (active != (ParamActive *)0) {
    PcodeOp *op;
    Varnode *vn;
    list<PcodeOp *>::const_iterator iter,iterend;
    int4 i;
    
    int4 maxancestor = data.getArch()->trim_recurse_max;
    iterend = data.endOp(CPUI_RETURN);
    AncestorRealistic ancestorReal;
    for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
      op = *iter;
      if (op->isDead()) continue;
      if (op->getHaltType() != 0) continue; // Don't evaluate special halts
      for(i=0;i<active->getNumTrials();++i) {
	ParamTrial &trial(active->getTrial(i));
	if (trial.isChecked()) continue; // Already checked
	int4 slot = trial.getSlot();
	vn = op->getIn(slot);
	if (ancestorReal.execute(op,slot,&trial,false))
	  if (data.ancestorOpUse(maxancestor,vn,op,trial,0))
	    trial.markActive(); // This varnode sees active use as a parameter
	count += 1;
      }
    }

    active->finishPass();
    if (active->getNumPasses() > active->getMaxPass())
      active->markFullyChecked();
    
    if (active->isFullyChecked()) {
      data.getFuncProto().deriveOutputMap(active);
      iterend = data.endOp(CPUI_RETURN);
      for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
	op = *iter;
	if (op->isDead()) continue;
	if (op->getHaltType() != 0) continue;
	buildReturnOutput(active,op,data);
      }
      data.clearActiveOutput();
      count += 1;
    }
  }
  return 0;
}

int4 ActionRestrictLocal::apply(Funcdata &data)

{
  FuncCallSpecs *fc;
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  Varnode *vn;
  int4 i;
  vector<EffectRecord>::const_iterator eiter,endeiter;
  
  for(i=0;i<data.numCalls();++i) {
    fc = data.getCallSpecs(i);
    op = fc->getOp();

    if (!fc->isInputLocked()) continue;
    if (fc->getSpacebaseOffset() == FuncCallSpecs::offset_unknown) continue;
    int4 numparam = fc->numParams();
    for(int4 i=0;i<numparam;++i) {
      ProtoParameter *param = fc->getParam(i);
      Address addr = param->getAddress();
      if (addr.getSpace()->getType() != IPTR_SPACEBASE) continue;
      uintb off = addr.getSpace()->wrapOffset(fc->getSpacebaseOffset() + addr.getOffset());
      data.getScopeLocal()->markNotMapped(addr.getSpace(),off,param->getSize(),true);
    }
  }

  eiter = data.getFuncProto().effectBegin();
  endeiter = data.getFuncProto().effectEnd();
  for(;eiter!=endeiter;++eiter) { // Iterate through saved registers
    if ((*eiter).getType() == EffectRecord::killedbycall) continue;  // Not saved
    vn = data.findVarnodeInput((*eiter).getSize(),(*eiter).getAddress());
    if ((vn != (Varnode *)0)&&(vn->isUnaffected())) {
      // Mark storage locations for saved registers as not mapped
      // This should pickup unaffected, reload, and return_address effecttypes
      for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
	op = *iter;
	if (op->code() != CPUI_COPY) continue;
	Varnode *outvn = op->getOut();
	if (!data.getScopeLocal()->isUnaffectedStorage(outvn))	// Is this where unaffected values get saved
	  continue;
	data.getScopeLocal()->markNotMapped(outvn->getSpace(),outvn->getOffset(),outvn->getSize(),false);
      }
    }
  }
  return 0;
}

/// Count the number of inputs to \b op which have their mark set
/// \param op is the PcodeOp to count
/// \return the number of marks set
uint4 ActionLikelyTrash::countMarks(PcodeOp *op)

{
  uint4 res = 0;
  for(int4 i=0;i<op->numInput();++i) {
    Varnode *vn = op->getIn(i);
    for(;;) {
      if (vn->isMark()) {
	res += 1;
	break;
      }
      if (!vn->isWritten()) break;
      PcodeOp *defOp = vn->getDef();
      if (defOp == op) {	// We have looped all the way around
	res += 1;
	break;
      }
      else if (defOp->code() != CPUI_INDIRECT)	// Chain up through INDIRECTs
	break;
      vn = vn->getDef()->getIn(0);
    }
  }
  return res;
}

/// \brief Decide if the given Varnode only ever flows into CPUI_INDIRECT
///
/// Return all the CPUI_INDIRECT ops that the Varnode hits in a list.
/// Trace forward down all paths from -vn-, if we hit
///    - CPUI_INDIRECT  -> trim that path and store that op in the resulting -indlist-
///    - CPUI_SUBPIECE
///    - CPUI_MULTIEQUAL
///    - CPUI_PIECE
///    - CPUI_AND       -> follow through to output
///    - anything else  -> consider -vn- to NOT be trash
///
/// For any CPUI_MULTIEQUAL and CPUI_PIECE that are hit, all the other inputs must be hit as well
/// \param vn is the given Varnode
/// \param indlist is the list to populate with CPUI_INDIRECT ops
/// \return \b true if all flows look like trash
bool ActionLikelyTrash::traceTrash(Varnode *vn,vector<PcodeOp *> &indlist)

{
  vector<PcodeOp *> allroutes;	// Keep track of merging ops (with more than 1 input)
  vector<Varnode *> markedlist;	// All varnodes we have visited on paths from -vn-
  list<PcodeOp *>::const_iterator iter,enditer;
  Varnode *outvn;
  uintb val;
  uint4 traced = 0;
  vn->setMark();
  markedlist.push_back(vn);
  bool istrash = true;

  while(traced < markedlist.size()) {
    Varnode *curvn = markedlist[traced++];
    iter = curvn->beginDescend();
    enditer = curvn->endDescend();
    for(;iter!=enditer;++iter) {
      PcodeOp *op = *iter;
      outvn = op->getOut();
      switch(op->code()) {
      case CPUI_INDIRECT:
	if (outvn->isPersist())
	  istrash = false;
	else if (op->isIndirectStore()) {
	  if (!outvn->isMark()) {
	    outvn->setMark();
	    markedlist.push_back(outvn);
	  }
	}
	else
	  indlist.push_back(op);
	break;
      case CPUI_SUBPIECE:
	if (outvn->isPersist())
	  istrash = false;
	else {
	  if (!outvn->isMark()) {
	    outvn->setMark();
	    markedlist.push_back(outvn);
	  }
	}
	break;
      case CPUI_MULTIEQUAL:
      case CPUI_PIECE:
	if (outvn->isPersist())
	  istrash = false;
	else {
	  if (!op->isMark()) {
	    op->setMark();
	    allroutes.push_back(op);
	  }
	  uint4 nummark = countMarks(op);
	  if (nummark == op->numInput()) {
	    if (!outvn->isMark()) {
	      outvn->setMark();
	      markedlist.push_back(outvn);
	    }
	  }
	}
	break;
      case CPUI_INT_AND:
	// If the AND is using only the topmost significant bytes then it is likely trash
	if (op->getIn(1)->isConstant()) {
	  val = op->getIn(1)->getOffset();
	  uintb mask = calc_mask(op->getIn(1)->getSize());
	  if ((val == ((mask<<8)&mask))||(val == ((mask<<16)&mask))||(val==((mask<<32)&mask))) {
	    indlist.push_back(op);
	    break;
	  }
	}
	istrash = false;
	break;
      default:
	istrash = false;
	break;
      }
      if (!istrash) break;
    }
    if (!istrash) break;
  }

  for(uint4 i=0;i<allroutes.size();++i) {
    if (!allroutes[i]->getOut()->isMark())
      istrash = false;		// Didn't see all inputs
    allroutes[i]->clearMark();
  }
  for(uint4 i=0;i<markedlist.size();++i)
    markedlist[i]->clearMark();

  return istrash;
}

int4 ActionLikelyTrash::apply(Funcdata &data)

{
  vector<PcodeOp *> indlist;

  int4 num = data.getFuncProto().numLikelyTrash();
  for(int4 j=0;j<num;++j) {
    const VarnodeData &vdata( data.getFuncProto().getLikelyTrash(j) );
    Varnode *vn = data.findCoveredInput(vdata.size,vdata.getAddr());
    if (vn == (Varnode *)0) continue;
    if (vn->isTypeLock()||vn->isNameLock()) continue;
    indlist.clear();
    if (!traceTrash(vn,indlist)) continue;

    for(uint4 i=0;i<indlist.size();++i) {
      PcodeOp *op = indlist[i];
      if (op->code() == CPUI_INDIRECT) {
	// Trucate data-flow through INDIRECT, turning it into indirect creation
	data.opSetInput(op,data.newConstant(op->getOut()->getSize(), 0),0);
	data.markIndirectCreation(op,false);
      }
      else if (op->code() == CPUI_INT_AND) {
	data.opSetInput(op,data.newConstant(op->getIn(1)->getSize(),0),1);
      }
      count += 1;			// Indicate we made a change
    }
  }
  return 0;
}

int4 ActionRestructureVarnode::apply(Funcdata &data)

{
  ScopeLocal *l1 = data.getScopeLocal();

  bool aliasyes = data.isJumptableRecoveryOn() ? false : (numpass != 0);
  l1->restructureVarnode(aliasyes);
  // Note the alias calculation, may not be very good on the first pass
  if (data.syncVarnodesWithSymbols(l1,false))
    count += 1;

  numpass += 1;
#ifdef OPACTION_DEBUG
  if ((flags&rule_debug)==0) return 0;
  ostringstream s;
  data.getScopeLocal()->printEntries(s);
  data.getArch()->printDebug(s.str());
#endif
  return 0;
}

int4 ActionRestructureHigh::apply(Funcdata &data)

{
  if (!data.isHighOn()) return 0;
  ScopeLocal *l1 = data.getScopeLocal();

#ifdef OPACTION_DEBUG
  if ((flags&rule_debug)!=0)
    l1->turnOnDebug();
#endif

  l1->restructureHigh();
  if (data.syncVarnodesWithSymbols(l1,true))
    count += 1;
  
#ifdef OPACTION_DEBUG
  if ((flags&rule_debug)==0) return 0;
  l1->turnOffDebug();
  ostringstream s;
  data.getScopeLocal()->printEntries(s);
  data.getArch()->printDebug(s.str());
#endif
  return 0;
}

int4 ActionDefaultParams::apply(Funcdata &data)

{
  int4 i,size;
  FuncCallSpecs *fc;
  ProtoModel *evalfp = data.getArch()->evalfp_called; // Special model used when evaluating called funcs
  if (evalfp == (ProtoModel *)0) // If no special evaluation
    evalfp = data.getArch()->defaultfp;	// Use the default model

  size = data.numCalls();
  for(i=0;i<size;++i) {
    fc = data.getCallSpecs(i);
    if (!fc->hasModel()) {
      Funcdata *otherfunc = fc->getFuncdata();
      
      if (otherfunc != (Funcdata *)0) {
	fc->copy(otherfunc->getFuncProto());
	if ((!fc->isModelLocked())&&(!fc->hasMatchingModel(evalfp)))
	  fc->setModel(evalfp);
      }
      else
	fc->setInternal(evalfp,data.getArch()->types->getTypeVoid());
    }
    fc->insertPcode(data);	// Insert any necessary pcode
  }
  return 0;			// Indicate success
}

/// \brief Insert cast to output Varnode type after given PcodeOp if it is necessary
///
/// \param op is the given PcodeOp
/// \param data is the function being analyzed
/// \param castStrategy is used to determine if the cast is necessary
/// \return 1 if a cast inserted, 0 otherwise
int4 ActionSetCasts::castOutput(PcodeOp *op,Funcdata &data,CastStrategy *castStrategy)

{
  Datatype *outct,*ct,*tokenct;
  Varnode *vn,*outvn;
  PcodeOp *newop;
  bool force=false;

  tokenct = op->getOpcode()->getOutputToken(op,castStrategy);
  outvn = op->getOut();
  if (outvn->isImplied()) {
    // implied varnode must have parse type
    if (outvn->getType()->getMetatype() != TYPE_PTR) // If implied varnode has an atomic (non-pointer) type
      outvn->updateType(tokenct,false,false); // Ignore it in favor of the token type
    else if (tokenct->getMetatype() == TYPE_PTR) { // If the token is a pointer AND implied varnode is pointer
      outct = ((TypePointer *)outvn->getType())->getPtrTo();
      type_metatype meta = outct->getMetatype();
      // Preserve implied pointer if it points to a composite
      if ((meta!=TYPE_ARRAY)&&(meta!=TYPE_STRUCT))
	outvn->updateType(tokenct,false,false); // Otherwise ignore it in favor of the token type
    }
    if (outvn->getType() != tokenct)
      force=true;		// Make sure not to drop pointer type
  }
  if (!force) {
    outct = outvn->getHigh()->getType();	// Type of result
    ct = castStrategy->castStandard(outct,tokenct,false,true);
    if (ct == (Datatype *)0) return 0;
  }
				// Generate the cast op
  vn = data.newUnique(op->getOut()->getSize());
  vn->updateType(tokenct,false,false);
  vn->setImplied();
  newop = data.newOp(1,op->getAddr());
#ifdef CPUI_STATISTICS
  data.getArch()->stats->countCast();
#endif
  data.opSetOpcode(newop,CPUI_CAST);
  data.opSetOutput(newop,op->getOut());
  data.opSetInput(newop,vn,0);
  data.opSetOutput(op,vn);
  data.opInsertAfter(newop,op); // Cast comes AFTER this operation
  return 1;
}

/// \brief Insert cast to produce the input Varnode to a given PcodeOp if necessary
///
/// This method can also mark a Varnode as an explicit integer constant.
/// Guard against chains of casts.
/// \param op is the given PcodeOp
/// \param slot is the slot of the input Varnode
/// \param data is the function being analyzed
/// \param castStrategy is used to determine if a cast is necessary
/// \return 1 if a change is made, 0 otherwise
int4 ActionSetCasts::castInput(PcodeOp *op,int4 slot,Funcdata &data,CastStrategy *castStrategy)

{
  Datatype *ct;
  Varnode *vn;
  PcodeOp *newop;

  ct = op->getOpcode()->getInputCast(op,slot,castStrategy); // Input type expected by this operation
  if (ct == (Datatype *)0) {
    if (op->markExplicitUnsigned(slot))	// Decide if this input should be explicitly printed as unsigned constant
      return 1;
    return 0;
  }

  vn = op->getIn(slot);
  // Check to make sure we don't have a double cast
  if (vn->isWritten() && (vn->getDef()->code() == CPUI_CAST)) {
    if (vn->isImplied() && (vn->loneDescend() == op)) {
      vn->updateType(ct,false,false);
      if (vn->getType()==ct)
	return 1;
    }
  }
  else if (vn->isConstant()) {
    vn->updateType(ct,false,false);
    if (vn->getType() == ct)
      return 1;
  }
  newop = data.newOp(1,op->getAddr());
  vn = data.newUniqueOut(op->getIn(slot)->getSize(),newop);
  vn->updateType(ct,false,false);
  vn->setImplied();
#ifdef CPUI_STATISTICS
  data.getArch()->stats->countCast();
#endif
  data.opSetOpcode(newop,CPUI_CAST);
  data.opSetInput(newop,op->getIn(slot),0);
  data.opSetInput(op,vn,slot);
  data.opInsertBefore(newop,op); // Cast comes AFTER operation
  return 1;
}

int4 ActionSetCasts::apply(Funcdata &data)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;

  data.startCastPhase();
  CastStrategy *castStrategy = data.getArch()->print->getCastStrategy();
  // We follow data flow, doing basic blocks in dominance order
  // Doing operations in basic block order
  const BlockGraph &basicblocks( data.getBasicBlocks() );
  for(int4 j=0;j<basicblocks.getSize();++j) {
    BlockBasic *bb = (BlockBasic *)basicblocks.getBlock(j);
    for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
      op = *iter;
      if (op->notPrinted()) continue;
      OpCode opc = op->code();
      if (opc == CPUI_CAST) continue;
      if (opc == CPUI_PTRADD) {	// Check for PTRADD that no longer fits its pointer
	int4 sz = (int4)op->getIn(2)->getOffset();
	TypePointer *ct = (TypePointer *)op->getIn(0)->getHigh()->getType();
	if ((ct->getMetatype() != TYPE_PTR)||(ct->getPtrTo()->getSize() != AddrSpace::addressToByteInt(sz, ct->getWordSize())))
	  data.opUndoPtradd(op,true);
      }
      else if (opc == CPUI_PTRSUB) {	// Check for PTRSUB that no longer fits pointer
	if (!op->getIn(0)->getHigh()->getType()->isPtrsubMatching(op->getIn(1)->getOffset())) {
	  if (op->getIn(1)->getOffset() == 0) {
	    data.opRemoveInput(op, 1);
	    data.opSetOpcode(op, CPUI_COPY);
	  }
	  else
	    data.opSetOpcode(op, CPUI_INT_ADD);
	}
      }
      for(int4 i=0;i<op->numInput();++i) // Do input casts first, as output may depend on input
	count += castInput(op,i,data,castStrategy);
      if (opc == CPUI_LOAD) {
	TypePointer *ptrtype = (TypePointer *)op->getIn(1)->getHigh()->getType();
	int4 valsize = op->getOut()->getSize();
	if ((ptrtype->getMetatype()!=TYPE_PTR)||
	    (ptrtype->getPtrTo()->getSize() != valsize))
	  data.warning("Load size is inaccurate",op->getAddr());
      }
      else if (opc == CPUI_STORE) {
	TypePointer *ptrtype = (TypePointer *)op->getIn(1)->getHigh()->getType();
	int4 valsize = op->getIn(2)->getSize();
	if ((ptrtype->getMetatype()!=TYPE_PTR)||
	    (ptrtype->getPtrTo()->getSize() != valsize))
	  data.warning("Store size is inaccurate",op->getAddr());
      }
      Varnode *vn = op->getOut();
      if (vn == (Varnode *)0) continue;
      count += castOutput(op,data,castStrategy);
    }
  }
  return 0;			// Indicate full completion
}

/// Name the Varnode which seems to be the putative switch variable for an
/// unrecovered jump-table with a special name.
/// \param data is the function being analyzed
void ActionNameVars::lookForBadJumpTables(Funcdata &data)

{
  int4 numfunc = data.numCalls();
  ScopeLocal *localmap = data.getScopeLocal();
  for(int4 i=0;i<numfunc;++i) {
    FuncCallSpecs *fc = data.getCallSpecs(i);
    if (fc->isBadJumpTable()) {
      PcodeOp *op = fc->getOp();
      Varnode *vn = op->getIn(0);
      if (vn->isImplied()&&vn->isWritten()) { // Skip any cast into the function
	PcodeOp *castop = vn->getDef();
	if (castop->code() == CPUI_CAST)
	  vn = castop->getIn(0);
      }
      if (vn->isFree()) continue;
      Symbol *sym = vn->getHigh()->getSymbol();
      if (sym == (Symbol *)0) continue;
      if (sym->isNameLocked()) continue; // Override any unlocked name
      if (sym->getScope() != localmap) continue; // Only name this in the local scope
      string newname = "UNRECOVERED_JUMPTABLE";
      sym->getScope()->renameSymbol(sym,localmap->makeNameUnique(newname));
    }
  }
}

/// \brief Add a recommendation to the database based on a particular sub-function parameter.
///
/// We know \b vn holds data-flow for parameter \b param,  try to attach its name to \b vn's symbol.
/// We update map from \b vn to a name recommendation record.
/// If \b vn is input to multiple functions, the one whose parameter has the most specified type
/// will be preferred. If \b vn is passed to the function via a cast, this name will only be used
/// if there is no other function that takes \b vn as a parameter.
/// \param param is function prototype symbol
/// \param vn is the Varnode associated with the parameter
/// \param recmap is the recommendation map
void ActionNameVars::makeRec(ProtoParameter *param,Varnode *vn,map<HighVariable *,OpRecommend> &recmap)

{
  if (!param->isNameLocked()) return;
  if (param->isNameUndefined()) return;
  if (vn->getSize() != param->getSize()) return;
  Datatype *ct = param->getType();
  if (vn->isImplied()&&vn->isWritten()) { // Skip any cast into the function
    PcodeOp *castop = vn->getDef();
    if (castop->code() == CPUI_CAST) {
      vn = castop->getIn(0);
      ct = (Datatype *)0;	// Indicate that this is a less preferred name
    }
  }
  HighVariable *high = vn->getHigh();
  if (high->isAddrTied()) return;	// Don't propagate parameter name to address tied variable
  if (param->getName().compare(0,6,"param_")==0) return;

  map<HighVariable *,OpRecommend>::iterator iter = recmap.find(high);
  if (iter != recmap.end()) {	// We have seen this varnode before
    if (ct == (Datatype *)0) return; // Cannot override with null (casted) type
    Datatype *oldtype = (*iter).second.ct;
    if (oldtype != (Datatype *)0) {
      if (oldtype->typeOrder(*ct) <= 0) return; // oldtype is more specified
    }
    (*iter).second.ct = ct;
    (*iter).second.namerec = param->getName();
  }
  else {
    OpRecommend oprec;
    oprec.ct = ct;
    oprec.namerec = param->getName();
    recmap[high] = oprec;
  }
}

/// \brief Collect potential variable names from sub-function parameters.
///
/// Run through all sub-functions with a known prototype and collect potential
/// names for current Varnodes used to pass the parameters. For these Varnodes,
/// select from among these names.
/// \param data is the function being analyzed
/// \param varlist is a list of Varnodes representing HighVariables that need names
void ActionNameVars::lookForFuncParamNames(Funcdata &data,const vector<Varnode *> &varlist)

{
  int4 numfunc = data.numCalls();
  if (numfunc == 0) return;

  map<HighVariable *,OpRecommend> recmap;

  ScopeLocal *localmap = data.getScopeLocal();
  for(int4 i=0;i<numfunc;++i) {	// Run through all calls to functions
    FuncCallSpecs *fc = data.getCallSpecs(i);
    if (!fc->isInputLocked()) continue;
    PcodeOp *op = fc->getOp();
    int4 numparam = fc->numParams();
    if (numparam >= op->numInput())
      numparam = op->numInput()-1;
    for(int4 j=0;j<numparam;++j) {
      ProtoParameter *param = fc->getParam(j); // Looking for a parameter
      Varnode *vn = op->getIn(j+1);
      makeRec(param,vn,recmap);
    }
  }
  if (recmap.empty()) return;

  map<HighVariable *,OpRecommend>::iterator iter;
  for(uint4 i=0;i<varlist.size();++i) {	// Do the actual naming in the original (address based) order
    Varnode *vn = varlist[i];
    if (vn->isFree()) continue;
    if (vn->isInput()) continue;	// Don't override unaffected or input naming strategy
    HighVariable *high = vn->getHigh();
    if (high->getNumMergeClasses() > 1) continue;	// Don't inherit a name if speculatively merged
    Symbol *sym = high->getSymbol();
    if (sym == (Symbol *)0) continue;
    if (!sym->isNameUndefined()) continue;
    iter = recmap.find(high);
    if (iter != recmap.end()) {
      Symbol *sym = high->getSymbol();
      sym->getScope()->renameSymbol(sym,localmap->makeNameUnique((*iter).second.namerec));
    }
  }
}

/// \brief Link symbols associated with a given \e spacebase Varnode
///
/// Look for PTRSUB ops which indicate a symbol reference within the address space
/// referred to by the \e spacebase Varnode.  Decode any symbol reference and link it
/// to the appropriate HighVariable
/// \param vn is the given \e spacebase Varnode
/// \param data is the function containing the Varnode
/// \param namerec is used to store any recovered Symbol without a name
void ActionNameVars::linkSpacebaseSymbol(Varnode *vn,Funcdata &data,vector<Varnode *> &namerec)

{
  if (!vn->isConstant() && !vn->isInput()) return;
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->code() != CPUI_PTRSUB) continue;
    Varnode *offVn = op->getIn(1);
    Symbol *sym = data.linkSymbolReference(offVn);
    if ((sym != (Symbol *)0) && sym->isNameUndefined())
      namerec.push_back(offVn);
  }
}

/// \brief Link formal Symbols to their HighVariable representative in the given Function
///
/// Run through all HighVariables for the given function and set up the explicit mapping with
/// existing Symbol objects.  If there is no matching Symbol for a given HighVariable, a new
/// Symbol is created. Any Symbol that does not have a name is added to a list for further
/// name resolution.
/// \param data is the given function
/// \param namerec is the container for collecting Symbols with a name
void ActionNameVars::linkSymbols(Funcdata &data,vector<Varnode *> &namerec)

{
  const AddrSpaceManager *manage = data.getArch();
  VarnodeLocSet::const_iterator iter,enditer;
  AddrSpace *spc;
  AddrSpace *constSpace = manage->getConstantSpace();
  enditer = data.endLoc(constSpace);
  for(iter=data.beginLoc(constSpace);iter!=enditer;++iter) {
    Varnode *curvn = *iter;
    if (curvn->getSymbolEntry() != (SymbolEntry *)0)
      data.linkSymbol(curvn);		// Special equate symbol
    else if (curvn->isSpacebase())
      linkSpacebaseSymbol(curvn, data, namerec);
  }

  for(int4 i=0;i<manage->numSpaces();++i) { // Build a list of nameable highs
    spc = manage->getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    if (spc == constSpace) continue;
    enditer = data.endLoc(spc);
    for(iter=data.beginLoc(spc);iter!=enditer;++iter) {
      Varnode *curvn = *iter;
      if (curvn->isFree()) {
	continue;
      }
      if (curvn->isSpacebase())
	linkSpacebaseSymbol(curvn, data, namerec);
      Varnode *vn = curvn->getHigh()->getNameRepresentative();
      if (vn != curvn) continue; // Hit each high only once
      HighVariable *high = vn->getHigh();
      if (!high->hasName()) continue;
      Symbol *sym = data.linkSymbol(vn);
      if (sym != (Symbol *)0) {	// Can we associate high with a nameable symbol
	if (sym->isNameUndefined() && high->getSymbolOffset() < 0)
	  namerec.push_back(vn);	// Add if no name, and we have a high representing the whole
	if (sym->isSizeTypeLocked()) {
	  if (vn->getSize() == sym->getType()->getSize())
	    sym->getScope()->overrideSizeLockType(sym,high->getType());
	}
      }
    }
  }
}

int4 ActionNameVars::apply(Funcdata &data)

{
  vector<Varnode *> namerec;

  linkSymbols(data, namerec);
  data.getScopeLocal()->recoverNameRecommendationsForSymbols(); // Make sure recommended names hit before subfunc
  lookForBadJumpTables(data);
  lookForFuncParamNames(data,namerec);

  int4 base = 1;
  for(uint4 i=0;i<namerec.size();++i) {
    Varnode *vn = namerec[i];
    Symbol *sym = vn->getHigh()->getSymbol();
    if (sym->isNameUndefined()) {
      Scope *scope = sym->getScope();
      string newname = scope->buildDefaultName(sym, base, vn);
      scope->renameSymbol(sym,newname);
    }
  }
  data.getScopeLocal()->assignDefaultNames(base);
  return 0;
}

/// If the given Varnode is defined by CPUI_NEW, return -2 indicating it should be explicit
/// and that it needs special printing.
/// \param vn is the given Varnode
/// \param maxref is the maximum number of references to consider before forcing explicitness
/// \return -1 if given Varnode should be marked explicit, the number of descendants otherwise
int4 ActionMarkExplicit::baseExplicit(Varnode *vn,int4 maxref)

{
  list<PcodeOp *>::const_iterator iter;

  PcodeOp *def = vn->getDef();
  if (def == (PcodeOp *)0) return -1;
  if (def->isMarker()) return -1;
  if (def->isCall()) {
    if ((def->code() == CPUI_NEW)&&(def->numInput() == 1))
      return -2;		// Explicit, but may need special printing
    return -1;
  }
  HighVariable *high = vn->getHigh();
  if ((high!=(HighVariable *)0)&&(high->numInstances()>1)) return -1; // Must not be merged at all
  if (vn->isAddrTied()) {		// We need to see addrtied as explicit because pointers may reference it
    if (def->code() == CPUI_SUBPIECE) {
      Varnode *vin = def->getIn(0);
      if (vin->isAddrTied()) {
	if (vn->overlap(*vin) == def->getIn(1)->getOffset())
	  return -1;		// Should be explicit, will be a copymarker and not printed
      }
    }
    // (Part of) an addrtied location into itself is hopefully implicit
    bool shouldbeimplicit = true;
    for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      PcodeOp *op = *iter;
      if ((op->code()!=CPUI_INT_ZEXT)&&(op->code()!=CPUI_PIECE)) {
	shouldbeimplicit = false;
	break;
      }
      Varnode *vnout = op->getOut();
      if ((!vnout->isAddrTied())||(0!=vnout->contains(*vn))) {
	shouldbeimplicit = false;
	break;
      }
    }
    if (!shouldbeimplicit) return -1;
  }
  else if (vn->isMapped()) {
    // If NOT addrtied but is still mapped, there must be either a first use (register) mapping
    // or a dynamic mapping causing the bit to be set. In either case, it should probably be explicit
    return -1;
  }
  if (vn->hasNoDescend()) return -1;	// Must have at least one descendant

  if (def->code() == CPUI_PTRSUB) { // A dereference
    Varnode *basevn = def->getIn(0);
    if (basevn->isSpacebase()) { // of a spacebase
      if (basevn->isConstant() || basevn->isInput())
	maxref = 1000000;	// Should always be implicit, so remove limit on max references
    }
  }
  int4 desccount = 0;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->isMarker()) return -1;
    desccount += 1;
    if (desccount > maxref) return -1; // Must not exceed max descendants
  }
  
  return desccount;
}

/// Look for certain situations where one Varnode with multiple descendants has one descendant who also has
/// multiple descendants.  This routine is handed the list of Varnodes with multiple descendants;
/// These all must already have their mark set.
/// For the situations we can find with one flowing into another, mark the top Varnode
/// as \e explicit.
/// \param multlist is the list Varnodes with multiple descendants
/// \return the number Varnodes that were marked as explicit
int4 ActionMarkExplicit::multipleInteraction(vector<Varnode *> &multlist)

{
  vector<Varnode *> purgelist;

  for(int4 i=0;i<multlist.size();++i) {
    Varnode *vn = multlist[i];	// All elements in this list should have a defining op
    PcodeOp *op = vn->getDef();
    OpCode opc = op->code();
    if (op->isBoolOutput() || (opc == CPUI_INT_ZEXT) || (opc == CPUI_INT_SEXT) || (opc == CPUI_PTRADD)) {
      int4 maxparam = 2;
      if (op->numInput() < maxparam)
	maxparam = op->numInput();
      Varnode *topvn = (Varnode *)0;
      for(int4 j=0;j<maxparam;++j) {
	topvn = op->getIn(j);
	if (topvn->isMark()) {	// We have a "multiple" interaction between -topvn- and -vn-
	  OpCode topopc = CPUI_COPY;
	  if (topvn->isWritten()) {
	    if (topvn->getDef()->isBoolOutput())
	      continue;		// Try not to make boolean outputs explicit
	    topopc = topvn->getDef()->code();
	  }
	  if (opc == CPUI_PTRADD) {
	    if (topopc == CPUI_PTRADD)
	      purgelist.push_back(topvn);
	  }
	  else
	    purgelist.push_back(topvn);
	}
      }
    }
  }

  for(int4 i=0;i<purgelist.size();++i) {
    Varnode *vn = purgelist[i];
    vn->setExplicit();
    vn->clearImplied();
    vn->clearMark();
  }
  return purgelist.size();
}

/// Record the Varnode just encountered and set-up the next (backward) edges to traverse.
/// \param v is the Varnode just encountered
ActionMarkExplicit::OpStackElement::OpStackElement(Varnode *v)

{
  vn = v;
  slot = 0;
  slotback = 0;
  if (v->isWritten()) {
    OpCode opc = v->getDef()->code();
    if (opc == CPUI_LOAD) {
      slot = 1;
      slotback = 2;
    }
    else if (opc == CPUI_PTRADD)
      slotback = 1;			// Don't traverse the multiplier slot
    else
      slotback = v->getDef()->numInput();
  }
}

/// Count the number of terms in the expression making up \b vn. If
/// there are more than \b max terms, mark \b vn as \e explicit.
/// The given Varnode is already assumed to have multiple descendants.
/// We do a depth first traversal along op inputs, to recursively
/// calculate the number of explicit terms in an expression.
/// \param vn is the given Varnode
/// \param max is the maximum number of terms to allow
void ActionMarkExplicit::processMultiplier(Varnode *vn,int4 max)

{
  vector<OpStackElement> opstack;
  Varnode *vncur;
  int4 finalcount = 0;

  opstack.push_back(vn);
  do {
    vncur = opstack.back().vn;
    bool isaterm = vncur->isExplicit() || (!vncur->isWritten());
    if (isaterm || (opstack.back().slotback<=opstack.back().slot)) { // Trimming condition
      if (isaterm) {
	if (!vncur->isSpacebase()) // Don't count space base
	  finalcount += 1;
      }
      if (finalcount > max) {
	vn->setExplicit();	// Make this variable explicit
	vn->clearImplied();
	return;
      }
      opstack.pop_back();
    }
    else {
      PcodeOp *op = vncur->getDef();
      Varnode *newvn = op->getIn(opstack.back().slot++);
      if (newvn->isMark()) {	// If an ancestor is marked(also possible implied with multiple descendants)
	vn->setExplicit();	// then automatically consider this to be explicit
	vn->clearImplied();
      }
      opstack.push_back(newvn);
    }
  } while(!opstack.empty());
}

/// Assume \b vn is produced via a CPUI_NEW operation. If it is immediately fed to a constructor,
/// set special printing flags on the Varnode.
/// \param data is the function being analyzed
/// \param vn is the given Varnode
void ActionMarkExplicit::checkNewToConstructor(Funcdata &data,Varnode *vn)

{  PcodeOp *op = vn->getDef();
  BlockBasic *bb = op->getParent();
  PcodeOp *firstuse = (PcodeOp *)0;
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *curop = *iter;
    if (curop->getParent() != bb) continue;
    if (firstuse == (PcodeOp *)0)
      firstuse = curop;
    else if (curop->getSeqNum().getOrder() < firstuse->getSeqNum().getOrder())
      firstuse = curop;
    else if (curop->code() == CPUI_CALLIND) {
      Varnode *ptr = curop->getIn(0);
      if (ptr->isWritten()) {
	if (ptr->getDef() == firstuse)
	  firstuse = curop;
      }
    }
  }
  if (firstuse == (PcodeOp *)0) return;

  if (!firstuse->isCall()) return;
  if (firstuse->getOut() != (Varnode *)0) return;
  if (firstuse->numInput() < 2) return;		// Must have at least 1 parameter (plus destination varnode)
  if (firstuse->getIn(1) != vn) return;		// First parameter must result of new
//  if (!fc->isConstructor()) return;		// Function must be a constructor
  data.opMarkSpecialPrint(firstuse);		// Mark call to print the new operator as well
  data.opMarkNonPrinting(op);			// Don't print the new operator as stand-alone operation
}

int4 ActionMarkExplicit::apply(Funcdata &data)

{
  VarnodeDefSet::const_iterator viter,enditer;
  vector<Varnode *> multlist;		// implied varnodes with >1 descendants
  int4 maxref;

  maxref = data.getArch()->max_implied_ref;
  enditer = data.beginDef(0); // Cut out free varnodes
  for(viter=data.beginDef();viter!=enditer;++viter) {
    Varnode *vn = *viter;

    int4 desccount = baseExplicit(vn,maxref);
    if (desccount < 0) {
      vn->setExplicit();
      count += 1;
      if (desccount < -1)
	checkNewToConstructor(data,vn);
    }
    else if (desccount > 1) {	// Keep track of possible implieds with more than one descendant
      vn->setMark();
      multlist.push_back(vn);
    }
  }

  count += multipleInteraction(multlist);
  int4 maxdup = data.getArch()->max_term_duplication;
  for(int4 i=0;i<multlist.size();++i) {
    Varnode *vn = multlist[i];
    if (vn->isMark())		// Mark may have been cleared by multipleInteraction
      processMultiplier(vn,maxdup);
  }
  for(int4 i=0;i<multlist.size();++i)
    multlist[i]->clearMark();
  return 0;
}

/// Return false only if one Varnode is obtained by adding non-zero thing to another Varnode.
/// The order of the Varnodes is not important.
/// \param vn1 is the first Varnode
/// \param vn2 is the second Varnode
/// \return false if the additive relationship holds
bool ActionMarkImplied::isPossibleAliasStep(Varnode *vn1,Varnode *vn2)

{
  Varnode *var[2];
  var[0] = vn1;
  var[1] = vn2;
  for(int4 i=0;i<2;++i) {
    Varnode *vncur = var[i];
    if (!vncur->isWritten()) continue;
    PcodeOp *op = vncur->getDef();
    OpCode opc = op->code();
    if ((opc!=CPUI_INT_ADD)&&(opc!=CPUI_PTRSUB)&&(opc!=CPUI_PTRADD)&&(opc!=CPUI_INT_XOR)) continue;
    if (var[1-i] != op->getIn(0)) continue;
    if (op->getIn(1)->isConstant()) return false;
  }
  return true;
}


/// Return false \b only if we can guarantee two Varnodes have different values.
/// \param vn1 is the first Varnode
/// \param vn2 is the second Varnode
/// \param depth is the maximum level to recurse
/// \return true if its possible the Varnodes hold the same value
bool ActionMarkImplied::isPossibleAlias(Varnode *vn1,Varnode *vn2,int4 depth)

{
  if (vn1 == vn2) return true;	// Definite alias
  if ((!vn1->isWritten())||(!vn2->isWritten())) {
    if (vn1->isConstant() && vn2->isConstant())
      return (vn1->getOffset()==vn2->getOffset()); // FIXME: these could be NEAR each other and still have an alias
    return isPossibleAliasStep(vn1,vn2);
  }

  if (!isPossibleAliasStep(vn1,vn2))
    return false;
  Varnode *cvn1,*cvn2;
  PcodeOp *op1 = vn1->getDef();
  PcodeOp *op2 = vn2->getDef();
  OpCode opc1 = op1->code();
  OpCode opc2 = op2->code();
  int4 mult1 = 1;
  int4 mult2 = 1;
  if (opc1 == CPUI_PTRSUB)
    opc1 = CPUI_INT_ADD;
  else if (opc1 == CPUI_PTRADD) {
    opc1 = CPUI_INT_ADD;
    mult1 = (int4) op1->getIn(2)->getOffset();
  }
  if (opc2 == CPUI_PTRSUB)
    opc2 = CPUI_INT_ADD;
  else if (opc2 == CPUI_PTRADD) {
    opc2 = CPUI_INT_ADD;
    mult2 = (int4) op2->getIn(2)->getOffset();
  }
  if (opc1 != opc2) return true;
  if (depth == 0) return true;	// Couldn't find absolute difference
  depth -= 1;
  switch(opc1) {
  case CPUI_COPY:
  case CPUI_INT_ZEXT:
  case CPUI_INT_SEXT:
  case CPUI_INT_2COMP:
  case CPUI_INT_NEGATE:
    return isPossibleAlias(op1->getIn(0),op2->getIn(0),depth);
  case CPUI_INT_ADD:
    cvn1 = op1->getIn(1);
    cvn2 = op2->getIn(1);
    if (cvn1->isConstant() && cvn2->isConstant()) {
      uintb val1 = mult1 * cvn1->getOffset();
      uintb val2 = mult2 * cvn2->getOffset();
      if (val1 == val2)
	return isPossibleAlias(op1->getIn(0),op2->getIn(0),depth);
      return !functionalEquality(op1->getIn(0),op2->getIn(0));
    }
    if (mult1 != mult2) return true;
    if (functionalEquality(op1->getIn(0),op2->getIn(0)))
      return isPossibleAlias(op1->getIn(1),op2->getIn(1),depth);
    if (functionalEquality(op1->getIn(1),op2->getIn(1)))
      return isPossibleAlias(op1->getIn(0),op2->getIn(0),depth);
    if (functionalEquality(op1->getIn(0),op2->getIn(1)))
      return isPossibleAlias(op1->getIn(1),op2->getIn(0),depth);
    if (functionalEquality(op1->getIn(1),op2->getIn(0)))
      return isPossibleAlias(op1->getIn(0),op2->getIn(1),depth);
    break;
  default:
    break;
  }
  return true;
}

/// Marking a Varnode as \e implied causes the input Varnodes to its defining op to propagate farther
/// in the output.  This may cause eventual variables to hold different values at the same
/// point in the code. Any input must test that its propagated Cover doesn't intersect its current Cover.
/// \param data is the function being analyzed
/// \param vn is the given Varnode
/// \return \b true if there is a Cover violation
bool ActionMarkImplied::checkImpliedCover(Funcdata &data,Varnode *vn)

{
  PcodeOp *op,*storeop,*callop;
  Varnode *defvn;
  int4 i;

  op = vn->getDef();
  if (op->code() == CPUI_LOAD) { // Check for loads crossing stores
    list<PcodeOp *>::const_iterator oiter,iterend;
    iterend = data.endOp(CPUI_STORE);
    for(oiter=data.beginOp(CPUI_STORE);oiter!=iterend;++oiter) {
      storeop = *oiter;
      if (storeop->isDead()) continue;
      if (vn->getCover()->contain(storeop,2)) {
				// The LOAD crosses a STORE. We are cavalier
				// and let it through unless we can verify
				// that the pointers are actually the same
	if (storeop->getIn(0)->getOffset() == op->getIn(0)->getOffset()) {
	  //	  if (!functionalDifference(storeop->getIn(1),op->getIn(1),2)) return false;
	  if (isPossibleAlias(storeop->getIn(1),op->getIn(1),2)) return false;
	}
      }
    }
  }
  if (op->isCall() || (op->code() == CPUI_LOAD)) { // loads crossing calls
    for(i=0;i<data.numCalls();++i) {
      callop = data.getCallSpecs(i)->getOp();
      if (vn->getCover()->contain(callop,2)) return false;
    }
  }
  for(i=0;i<op->numInput();++i) {
    defvn = op->getIn(i);
    if (defvn->isConstant()) continue;
    if (data.getMerge().inflateTest(defvn,vn->getHigh()))	// Test for intersection
      return false;
  }
  return true;
}

int4 ActionMarkImplied::apply(Funcdata &data)

{
  VarnodeLocSet::const_iterator viter;
  list<PcodeOp *>::const_iterator oiter;
  Varnode *vn,*vncur,*defvn,*outvn;
  PcodeOp *op;
  vector<DescTreeElement> varstack; // Depth first varnode traversal stack

  for(viter=data.beginLoc();viter!=data.endLoc();++viter) {
    vn = *viter;
    if (vn->isFree()) continue;
    if (vn->isExplicit()) continue;
    if (vn->isImplied()) continue;
    varstack.push_back(vn);
    do {
      vncur = varstack.back().vn;
      if (varstack.back().desciter == vncur->endDescend()) {
	// All descendants are traced first, try to make vncur implied
	count += 1;		// Will be marked either explicit or implied
	if (!checkImpliedCover(data,vncur)) // Can this variable be implied
	  vncur->setExplicit();	// if not, mark explicit
	else {
	  vncur->setImplied();	// Mark as implied
	  op = vncur->getDef();
	  // setting the implied type is now taken care of by ActionSetCasts
	  //    vn->updatetype(op->outputtype_token(),false,false); // implied must have parsed type
	  // Back propagate varnode's cover to inputs of defining op
	  for(int4 i=0;i<op->numInput();++i) {
	    defvn = op->getIn(i);
	    if (!defvn->hasCover()) continue;
	    data.getMerge().inflate(defvn,vncur->getHigh());
	  }
	}
	varstack.pop_back();
      }
      else {
	outvn = (*varstack.back().desciter++)->getOut();
	if (outvn != (Varnode *)0) {
	  if ((!outvn->isExplicit())&&(!outvn->isImplied()))
	    varstack.push_back(outvn);
	}
      }
    } while(!varstack.empty());
  }

  return 0;
}

int4 ActionUnreachable::apply(Funcdata &data)

{				// Detect unreachable blocks and remove
  if (data.removeUnreachableBlocks(true,false))
    count += 1;			// Deleting at least one block

  return 0;
}

int4 ActionDoNothing::apply(Funcdata &data)

{				// Remove blocks that do nothing
  int4 i;
  const BlockGraph &graph(data.getBasicBlocks());
  BlockBasic *bb;
  
  for(i=0;i<graph.getSize();++i) {
    bb = (BlockBasic *) graph.getBlock(i);
    if (bb->isDoNothing()) {
      if ((bb->sizeOut()==1)&&(bb->getOut(0)==bb)) { // Infinite loop
	if (!bb->isDonothingLoop()) {
	  bb->setDonothingLoop();
	  data.warning("Do nothing block with infinite loop",bb->getStart());
	}
      }
      else if (bb->unblockedMulti(0)) {
	data.removeDoNothingBlock(bb);
	count += 1;
	return 0;
      }
    }
  }
  return 0;
}

int4 ActionRedundBranch::apply(Funcdata &data)

{
  // Remove redundant branches, i.e. a CPUI_CBRANCH that falls thru and branches to the same place
  int4 i,j;
  const BlockGraph &graph(data.getBasicBlocks());
  BlockBasic *bb;
  FlowBlock *bl;

  for(i=0;i<graph.getSize();++i) {
    bb = (BlockBasic *) graph.getBlock(i);
    if (bb->sizeOut() == 0) continue;
    bl = bb->getOut(0);
    if (bb->sizeOut() == 1) {
      if ((bl->sizeIn() == 1)&&(!bl->isEntryPoint())&&(!bb->isSwitchOut())) {
	// Do not splice block coming from single exit switch as this prevents possible second stage recovery
	data.spliceBlockBasic(bb);
	count += 1;
	// This will remove one block, so reset i
	i = -1;
      }
      continue;
    }
    for(j=1;j<bb->sizeOut();++j) // Are all exits to the same block? (bl)
      if (bb->getOut(j) != bl) break;
    if (j!=bb->sizeOut()) continue;

    //    ostringstream s;
    //    s << "Removing redundant branch out of block ";
    //    s << "code_" << bb->start.Target().getShortcut();
    //    bb->start.Target().printRaw(s);
    //    data.warningHeader(s.str());
    data.removeBranch(bb,1);	// Remove the branch instruction
    count += 1;
  }
  return 0;			// Indicate full rule was applied
}

int4 ActionDeterminedBranch::apply(Funcdata &data)

{
  int4 i;
  const BlockGraph &graph(data.getBasicBlocks());
  BlockBasic *bb;
  PcodeOp *cbranch;

  for(i=0;i<graph.getSize();++i) {
    bb = (BlockBasic *) graph.getBlock(i);
    cbranch = bb->lastOp();
    if ((cbranch == (PcodeOp *)0)||(cbranch->code() != CPUI_CBRANCH)) continue;
    if (!cbranch->getIn(1)->isConstant()) continue;
    if (cbranch->isSplitting()) continue;	// Already tried to remove before
    uintb val = cbranch->getIn(1)->getOffset();
    int4 num = ((val!=0)!=cbranch->isBooleanFlip()) ? 0 : 1;
    data.removeBranch(bb,num);
    count += 1;
  }
  return 0;
}

/// Given a new \e consume value to push to a Varnode, determine if this changes
/// the Varnodes consume value and whether to push the Varnode onto the work-list.
/// \param val is the new consume value
/// \param vn is the Varnode to push to
/// \param worklist is the current work-list
inline void ActionDeadCode::pushConsumed(uintb val,Varnode *vn,vector<Varnode *> &worklist)

{
  uintb newval = (val | vn->getConsume())&calc_mask(vn->getSize());
  if ((newval == vn->getConsume())&&vn->isConsumeVacuous()) return;
  vn->setConsumeVacuous();
  if (!vn->isConsumeList()) { // Check if already in list
    vn->setConsumeList();	// Mark as in the list
    if (vn->isWritten())
      worklist.push_back(vn);	// add to list
  }
  vn->setConsume(newval);
}

/// \brief Propagate the \e consumed value for one Varnode
///
/// The Varnode at the top of the stack is popped off, and its current
/// \e consumed value is propagated  backward to the inputs of the op
/// that produced it.
/// \param worklist is the current stack of dirty Varnodes
void ActionDeadCode::propagateConsumed(vector<Varnode *> &worklist)

{
  Varnode *vn = worklist.back();
  worklist.pop_back();
  uintb outc = vn->getConsume();
  vn->clearConsumeList();

  PcodeOp *op = vn->getDef();	// Assume vn is written

  int4 sz;
  uintb a,b;

  switch(op->code()) {
  case CPUI_INT_MULT:
    b = coveringmask(outc);
    if (op->getIn(1)->isConstant()) {
      int4 leastSet = leastsigbit_set(op->getIn(1)->getOffset());
      if (leastSet >= 0) {
	a = calc_mask(vn->getSize()) >> leastSet;
	a &= b;
      }
      else
	a = 0;
    }
    else
      a = b;
    pushConsumed(a,op->getIn(0),worklist);
    pushConsumed(b,op->getIn(1),worklist);
    break;
  case CPUI_INT_ADD:
  case CPUI_INT_SUB:
    a = coveringmask(outc);	// Make sure value is filled out as a contiguous mask
    pushConsumed(a,op->getIn(0),worklist);
    pushConsumed(a,op->getIn(1),worklist);
    break;
  case CPUI_SUBPIECE:
    sz = op->getIn(1)->getOffset();
    if (sz >= sizeof(uintb))	// If we are truncating beyond the precision of the consume field
      a = 0;			// this tells us nothing about consuming bits within the field
    else
      a = outc << (sz*8);
    if ((a==0)&&(outc!=0)&&(op->getIn(0)->getSize() > sizeof(uintb))) {
      // If the consumed mask is zero because
      // it isn't big enough to cover the whole varnode and
      // there are still upper bits that are consumed
      a = ~((uintb)0);
      a = a ^ (a >> 1);		// Set the highest bit possible in the mask to indicate some consumption
    }
    b = (outc == 0) ? 0 : ~((uintb)0);
    pushConsumed(a,op->getIn(0),worklist);
    pushConsumed(b,op->getIn(1),worklist);
    break;
  case CPUI_PIECE:
    sz = op->getIn(1)->getSize();
    if (vn->getSize() > sizeof(uintb)) { // If the concatenation goes beyond the consume precision
      if (sz >= sizeof(uintb)) {
	a = ~((uintb)0);	// Assume the bits not in the consume field are consumed
	b = outc;
      }
      else {
	a = (outc >> (sz*8)) ^ ( (~((uintb)0)) << 8*(sizeof(uintb)-sz));
	b = outc ^ (a << (sz*8));
      }
    }
    else {
      a = outc >> (sz*8);
      b = outc ^ (a << (sz*8));
    }
    pushConsumed(a,op->getIn(0),worklist);
    pushConsumed(b,op->getIn(1),worklist);
    break;
  case CPUI_INDIRECT:
    pushConsumed(outc,op->getIn(0),worklist);
    if (op->getIn(1)->getSpace()->getType()==IPTR_IOP) {
      PcodeOp *indop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
      if (!indop->isDead()) {
	if (indop->code() == CPUI_COPY) {
	  if (indop->getOut()->characterizeOverlap(*op->getOut())>0) {
	    pushConsumed(~((uintb)0),indop->getOut(),worklist);	// Mark the copy as consumed
	    indop->setIndirectSource();
	  }
	  // If we reach here, there isn't a true block of INDIRECT (RuleIndirectCollapse will convert it to COPY)
	}
	else
	  indop->setIndirectSource();
      }
    }
    break;
  case CPUI_COPY:
  case CPUI_INT_NEGATE:
    pushConsumed(outc,op->getIn(0),worklist);
    break;
  case CPUI_INT_XOR:
  case CPUI_INT_OR:
    pushConsumed(outc,op->getIn(0),worklist);
    pushConsumed(outc,op->getIn(1),worklist);
    break;
  case CPUI_INT_AND:
    if (op->getIn(1)->isConstant()) {
      uintb val = op->getIn(1)->getOffset();
      pushConsumed(outc&val,op->getIn(0),worklist);
      pushConsumed(outc,op->getIn(1),worklist);
    }
    else {
      pushConsumed(outc,op->getIn(0),worklist);
      pushConsumed(outc,op->getIn(1),worklist);
    }
    break;
  case CPUI_MULTIEQUAL:
    for(int4 i=0;i<op->numInput();++i)
      pushConsumed(outc,op->getIn(i),worklist);
    break;
  case CPUI_INT_ZEXT:
    pushConsumed(outc,op->getIn(0),worklist);
    break;
  case CPUI_INT_SEXT:
    b = calc_mask(op->getIn(0)->getSize());
    a = outc & b;
    if (outc > b)
      a |= (b ^ (b>>1));	// Make sure signbit is marked used
    pushConsumed(a,op->getIn(0),worklist);
    break;
  case CPUI_INT_LEFT:
    if (op->getIn(1)->isConstant()) {
      sz = vn->getSize();
      int4 sa = op->getIn(1)->getOffset();
      if (sz > sizeof(uintb)) {	// If there exists bits beyond the precision of the consume field
	if (sa >= 8*sizeof(uintb))
	  a = ~((uintb)0);	// Make sure we assume one bits where we shift in unrepresented bits
	else
	  a = (outc >> sa) ^ ( (~((uintb)0)) << (8*sizeof(uintb)-sa));
	sz = 8*sz -sa;
	if (sz < 8*sizeof(uintb)) {
	  uintb mask = ~((uintb)0);
	  mask <<= sz;
	  a = a & ~mask;	// Make sure high bits that are left shifted out are not marked consumed
	}
      }
      else
	a = outc >> sa;		// Most cases just do this
      b = (outc == 0) ? 0 : ~((uintb)0);
      pushConsumed(a,op->getIn(0),worklist);
      pushConsumed(b,op->getIn(1),worklist);
    }
    else {
      a = (outc==0) ? 0 : ~((uintb)0);
      pushConsumed(a,op->getIn(0),worklist);
      pushConsumed(a,op->getIn(1),worklist);
    }
    break;
  case CPUI_INT_RIGHT:
    if (op->getIn(1)->isConstant()) {
      int4 sa = op->getIn(1)->getOffset();
      if (sa >= 8*sizeof(uintb)) // If the shift is beyond the precision of the consume field
	a = 0;			// We know nothing about the low order consumption of the input bits
      else
	a = outc << sa;		// Most cases just do this
      b = (outc == 0) ? 0 : ~((uintb)0);
      pushConsumed(a,op->getIn(0),worklist);
      pushConsumed(b,op->getIn(1),worklist);
    }
    else {
      a = (outc==0) ? 0 : ~((uintb)0);
      pushConsumed(a,op->getIn(0),worklist);
      pushConsumed(a,op->getIn(1),worklist);
    }
    break;
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
    if (outc==0)
      a = 0;
    else			// Anywhere we know is zero, is not getting "consumed"
      a = op->getIn(0)->getNZMask() | op->getIn(1)->getNZMask();
    pushConsumed(a,op->getIn(0),worklist);
    pushConsumed(a,op->getIn(1),worklist);
    break;
  case CPUI_INSERT:
    a = 1;
    a <<= (int4)op->getIn(3)->getOffset();
    a -= 1;	// Insert mask
    pushConsumed(a,op->getIn(1),worklist);
    a <<= (int4)op->getIn(2)->getOffset();
    pushConsumed(outc & ~a, op->getIn(0), worklist);
    b = (outc == 0) ? 0 : ~((uintb)0);
    pushConsumed(b,op->getIn(2), worklist);
    pushConsumed(b,op->getIn(3), worklist);
    break;
  case CPUI_EXTRACT:
    a = 1;
    a <<= (int4)op->getIn(2)->getOffset();
    a -= 1;	// Extract mask
    a &= outc;	// Consumed bits of mask
    a <<= (int4)op->getIn(1)->getOffset();
    pushConsumed(a,op->getIn(0),worklist);
    b = (outc == 0) ? 0 : ~((uintb)0);
    pushConsumed(b,op->getIn(1), worklist);
    pushConsumed(b,op->getIn(2), worklist);
    break;
  case CPUI_POPCOUNT:
    a = 16 * op->getIn(0)->getSize() - 1;	// Mask for possible bits that could be set
    a &= outc;					// Of the bits that could be set, which are consumed
    b = (a == 0) ? 0 : ~((uintb)0);		// if any consumed, treat all input bits as consumed
    pushConsumed(b,op->getIn(0), worklist);
    break;
  case CPUI_CALL:
  case CPUI_CALLIND:
    break;		// Call output doesn't indicate consumption of inputs
  default:
    a = (outc==0) ? 0 : ~((uintb)0); // all or nothing
    for(int4 i=0;i<op->numInput();++i)
      pushConsumed(a,op->getIn(i),worklist);
    break;
  }

}

/// \brief Deal with unconsumed Varnodes
///
/// For a Varnode, none of whose bits are consumed, eliminate the PcodeOp defining it
/// and replace Varnode inputs to ops that officially read it with zero constants.
/// \param vn is the Varnode
/// \param data is the function being analyzed
/// \return true if the Varnode was eliminated
bool ActionDeadCode::neverConsumed(Varnode *vn,Funcdata &data)

{
  if (vn->getSize() > sizeof(uintb)) return false; // Not enough precision to really tell
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  iter = vn->beginDescend();
  while(iter != vn->endDescend()) {
    op = *iter++;		// Advance before ref is removed
    int4 slot = op->getSlot(vn);
    // Replace vn with 0 whereever it is read
    // We don't worry about putting a constant in a marker
    // because if vn is not consumed and is input to a marker
    // then the output is also not consumed and the marker
    // op is about to be deleted anyway
    data.opSetInput(op,data.newConstant(vn->getSize(),0),slot);
  }
  op = vn->getDef();
  if (op->isCall())
    data.opUnsetOutput(op); // For calls just get rid of output
  else
    data.opDestroy(op);	// Otherwise completely remove the op
  return true;
}

/// \brief Determine how the given sub-function parameters are consumed
///
/// Set the consume property for each input Varnode of a CPUI_CALL or CPUI_CALLIND.
/// If the prototype is locked, assume parameters are entirely consumed.
/// \param fc is the call specification for the given sub-function
/// \param worklist will hold input Varnodes that can propagate their consume property
void ActionDeadCode::markConsumedParameters(FuncCallSpecs *fc,vector<Varnode *> &worklist)

{
  PcodeOp *callOp = fc->getOp();
  pushConsumed(~((uintb)0),callOp->getIn(0),worklist);		// In all cases the first operand is fully consumed
  if (fc->isInputLocked() || fc->isInputActive()) {		// If the prototype is locked in, or in active recovery
    for(int4 i=1;i<callOp->numInput();++i)
      pushConsumed(~((uintb)0),callOp->getIn(i),worklist);	// Treat all parameters as fully consumed
    return;
  }
  for(int4 i=1;i<callOp->numInput();++i) {
    Varnode *vn = callOp->getIn(i);
    uintb consumeVal;
    if (vn->isAutoLive())
      consumeVal = ~((uintb)0);
    else
      consumeVal = minimalmask(vn->getNZMask());
    int4 bytesConsumed = fc->getInputBytesConsumed(i);
    if (bytesConsumed != 0)
      consumeVal &= calc_mask(bytesConsumed);
    pushConsumed(consumeVal,vn,worklist);
  }
}

/// \brief Determine how the \e return \e values for the given function are consumed
///
/// Examine each CPUI_RETURN to see how the Varnode input is consumed.
/// If the function's prototype is locked, assume the Varnode is entirely consumed.
/// If there are no CPUI_RETURN ops, return 0
/// \param data is the given function
/// \return the bit mask of what is consumed
uintb ActionDeadCode::gatherConsumedReturn(Funcdata &data)

{
  if (data.getFuncProto().isOutputLocked() || data.getActiveOutput() != (ParamActive *)0)
    return ~((uintb)0);
  list<PcodeOp *>::const_iterator iter,enditer;
  enditer = data.endOp(CPUI_RETURN);
  uintb consumeVal = 0;
  for(iter=data.beginOp(CPUI_RETURN);iter!=enditer;++iter) {
    PcodeOp *returnOp = *iter;
    if (returnOp->isDead()) continue;
    if (returnOp->numInput() > 1) {
      Varnode *vn = returnOp->getIn(1);
      consumeVal |= minimalmask(vn->getNZMask());
    }
  }
  int4 val = data.getFuncProto().getReturnBytesConsumed();
  if (val != 0) {
    consumeVal &= calc_mask(val);
  }
  return consumeVal;
}

/// \brief Determine if the given Varnode may eventually collapse to a constant
///
/// Recursively check if the Varnode is either:
///   - Copied from a constant
///   - The result of adding constants
///   - Loaded from a pointer that is a constant
///
/// \param vn is the given Varnode
/// \param addCount is the number of CPUI_INT_ADD operations seen so far
/// \param loadCount is the number of CPUI_LOAD operations seen so far
/// \return \b true if the Varnode (might) collapse to a constant
bool ActionDeadCode::isEventualConstant(Varnode *vn,int4 addCount,int4 loadCount)

{
  if (vn->isConstant()) return true;
  if (!vn->isWritten()) return false;
  PcodeOp *op = vn->getDef();
  while(op->code() == CPUI_COPY) {
    vn = op->getIn(0);
    if (vn->isConstant()) return true;
    if (!vn->isWritten()) return false;
    op = vn->getDef();
  }
  switch(op->code()) {
    case CPUI_INT_ADD:
      if (addCount > 0) return false;
      if (!isEventualConstant(op->getIn(0),addCount+1,loadCount))
	return false;
      return isEventualConstant(op->getIn(1),addCount+1,loadCount);
    case CPUI_LOAD:
      if (loadCount > 0) return false;
      return isEventualConstant(op->getIn(1),0,loadCount+1);
    case CPUI_INT_LEFT:
    case CPUI_INT_RIGHT:
    case CPUI_INT_SRIGHT:
    case CPUI_INT_MULT:
      if (!op->getIn(1)->isConstant())
	return false;
      return isEventualConstant(op->getIn(0),addCount,loadCount);
    case CPUI_INT_ZEXT:
    case CPUI_INT_SEXT:
      return isEventualConstant(op->getIn(0),addCount,loadCount);
    default:
      break;
  }
  return false;
}

/// \brief Check if there are any unconsumed LOADs that may be from volatile addresses.
///
/// It may be too early to remove certain LOAD operations even though their result isn't
/// consumed because it may be of a volatile address with side effects.  If a LOAD meets this
/// criteria, it is added to the worklist and \b true is returned.
/// \param data is the function being analyzed
/// \param worklist is the container of consumed Varnodes to further process
/// \return \b true if there was at least one LOAD added to the worklist
bool ActionDeadCode::lastChanceLoad(Funcdata &data,vector<Varnode *> &worklist)

{
  if (data.getHeritagePass() > 1) return false;
  if (data.isJumptableRecoveryOn()) return false;
  list<PcodeOp *>::const_iterator iter = data.beginOp(CPUI_LOAD);
  list<PcodeOp *>::const_iterator enditer = data.endOp(CPUI_LOAD);
  bool res = false;
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->isDead()) continue;
    Varnode *vn = op->getOut();
    if (vn->isConsumeVacuous()) continue;
    if (isEventualConstant(op->getIn(1), 0, 0)) {
      pushConsumed(~(uintb)0, vn, worklist);
      vn->setAutoLiveHold();
      res = true;
    }
  }
  return res;
}

int4 ActionDeadCode::apply(Funcdata &data)

{
  int4 i;
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *op;
  Varnode *vn;
  uintb returnConsume;
  vector<Varnode *> worklist;
  VarnodeLocSet::const_iterator viter,endviter;
  const AddrSpaceManager *manage = data.getArch();
  AddrSpace *spc;

				// Clear consume flags
  for(viter=data.beginLoc();viter!=data.endLoc();++viter) {
    vn = *viter;
    vn->clearConsumeList();
    vn->clearConsumeVacuous();
    vn->setConsume(0);
    if (vn->isAddrForce()&&(!vn->isDirectWrite()))
      vn->clearAddrForce();
  }

				// Set pre-live registers
  for(i=0;i<manage->numSpaces();++i) {
    spc = manage->getSpace(i);
    if (spc == (AddrSpace *)0 || !spc->doesDeadcode()) continue;
    if (data.deadRemovalAllowed(spc)) continue; // Mark consumed if we have NOT heritaged
    viter = data.beginLoc(spc);
    endviter = data.endLoc(spc);
    while(viter != endviter) {
      vn = *viter++;
      pushConsumed(~((uintb)0),vn,worklist);
    }
  }

  returnConsume = gatherConsumedReturn(data);
  for(iter=data.beginOpAlive();iter!=data.endOpAlive();++iter) {
    op = *iter;

    op->clearIndirectSource();
    if (op->isCall()) {
      // Postpone setting consumption on CALL and CALLIND inputs
      if (op->isCallWithoutSpec()) {
	for(i=0;i<op->numInput();++i)
	  pushConsumed(~((uintb)0),op->getIn(i),worklist);
      }
      if (!op->isAssignment())
	continue;
    }
    else if (!op->isAssignment()) {
      OpCode opc = op->code();
      if (opc == CPUI_RETURN) {
	pushConsumed(~((uintb)0),op->getIn(0),worklist);
	for(i=1;i<op->numInput();++i)
	  pushConsumed(returnConsume,op->getIn(i),worklist);
      }
      else if (opc == CPUI_BRANCHIND) {
	JumpTable *jt = data.findJumpTable(op);
	uintb mask;
	if (jt != (JumpTable *)0)
	  mask = jt->getSwitchVarConsume();
	else
	  mask = ~((uintb)0);
	pushConsumed(mask,op->getIn(0),worklist);
      }
      else {
	for(i=0;i<op->numInput();++i)
	  pushConsumed(~((uintb)0),op->getIn(i),worklist);
      }
      // Postpone setting consumption on RETURN input
      continue;
    }
    else {
      for(i=0;i<op->numInput();++i) {
	vn = op->getIn(i);
	if (vn->isAutoLive())
	  pushConsumed(~((uintb)0),vn,worklist);
      }
    }
    vn = op->getOut();
    if (vn->isAutoLive())
      pushConsumed(~((uintb)0),vn,worklist);
  }

				// Mark consumption of call parameters
  for(i=0;i<data.numCalls();++i)
    markConsumedParameters(data.getCallSpecs(i),worklist);

				// Propagate the consume flags
  while(!worklist.empty())
    propagateConsumed(worklist);

  if (lastChanceLoad(data, worklist)) {
    while(!worklist.empty())
      propagateConsumed(worklist);
  }

  for(i=0;i<manage->numSpaces();++i) {
    spc = manage->getSpace(i);
    if (spc == (AddrSpace *)0 || !spc->doesDeadcode()) continue;
    if (!data.deadRemovalAllowed(spc)) continue; // Don't eliminate if we haven't heritaged
    viter = data.beginLoc(spc);
    endviter = data.endLoc(spc);
    int4 changecount = 0;
    while(viter != endviter) {
      vn = *viter++;		// Advance iterator BEFORE (possibly) deleting varnode
      if (!vn->isWritten()) continue;
      bool vacflag = vn->isConsumeVacuous();
      vn->clearConsumeList();
      vn->clearConsumeVacuous();
      if (!vacflag) {		// Not even vacuously consumed
	op = vn->getDef();
	changecount += 1;
	if (op->isCall())
	  data.opUnsetOutput(op); // For calls just get rid of output
	else
	  data.opDestroy(op);	// Otherwise completely remove the op
      }
      else {
	// Check for values that are never used, but bang around
	// for a while
	if (vn->getConsume()==0) {
	  if (neverConsumed(vn,data))
	    changecount += 1;
	}
      }
    }
    if (changecount != 0)
      data.seenDeadcode(spc);	// Record that we have seen dead code for this space
  }
#ifdef OPACTION_DEBUG
  data.debugModPrint(getName()); // Print dead ops before freeing them
#endif
  data.clearDeadVarnodes();
  data.clearDeadOps();
  return 0;
}

/// \brief Replace reads of a given Varnode with a constant.
///
/// For each read op, check that is in or dominated by a specific block we known
/// the Varnode is constant in.
/// \param varVn is the given Varnode
/// \param constVn is the constant Varnode to replace with
/// \param constBlock is the block which dominates ops reading the constant value
/// \param data is the function being analyzed
void ActionConditionalConst::propagateConstant(Varnode *varVn,Varnode *constVn,FlowBlock *constBlock,Funcdata &data)

{
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = varVn->beginDescend();
  enditer = varVn->endDescend();
  FlowBlock *rootBlock = (FlowBlock *)0;
  if (varVn->isWritten())
    rootBlock = varVn->getDef()->getParent();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;		// Advance iterator before possibly destroying descendant
    if (op->isMarker()) continue;		// Don't propagate constant into these
    if (op->code() == CPUI_COPY) {		// Don't propagate into COPY unless...
      PcodeOp *followOp = op->getOut()->loneDescend();
      if (followOp == (PcodeOp *)0) continue;
      if (followOp->isMarker()) continue;
      if (followOp->code() == CPUI_COPY) continue;
						// ...unless COPY is into something more interesting
    }
    FlowBlock *bl = op->getParent();
    while(bl != (FlowBlock *)0) {
      if (bl == rootBlock) break;
      if (bl == constBlock) {		// Is op dominated by constBlock?
	int4 slot = op->getSlot(varVn);
	data.opSetInput(op,data.newConstant(varVn->getSize(),constVn->getOffset()),slot);	// Replace ref with constant!
	count += 1;			// We made a change
	break;
      }
      bl = bl->getImmedDom();
    }
  }
}

int4 ActionConditionalConst::apply(Funcdata &data)

{
  const BlockGraph &blockGraph(data.getBasicBlocks());
  for(int4 i=0;i<blockGraph.getSize();++i) {
    FlowBlock *bl = blockGraph.getBlock(i);
    PcodeOp *cBranch = bl->lastOp();
    if (cBranch == (PcodeOp *)0 || cBranch->code() != CPUI_CBRANCH) continue;
    Varnode *boolVn = cBranch->getIn(1);
    if (!boolVn->isWritten()) continue;
    PcodeOp *compOp = boolVn->getDef();
    OpCode opc = compOp->code();
    bool flipEdge = cBranch->isBooleanFlip();
    if (opc == CPUI_BOOL_NEGATE) {
      flipEdge = !flipEdge;
      boolVn = compOp->getIn(0);
      if (!boolVn->isWritten()) continue;
      compOp = boolVn->getDef();
      opc = compOp->code();
    }
    int4 constEdge;			// Out edge where value is constant
    if (opc == CPUI_INT_EQUAL)
      constEdge = 1;
    else if (opc == CPUI_INT_NOTEQUAL)
      constEdge = 0;
    else
      continue;
    // Find the variable and verify that it is compared to a constant
    Varnode *varVn = compOp->getIn(0);
    Varnode *constVn = compOp->getIn(1);
    if (!constVn->isConstant()) {
      if (!varVn->isConstant())
	continue;
      Varnode *tmp = constVn;
      constVn = varVn;
      varVn = tmp;
    }
    if (flipEdge)
      constEdge = 1 - constEdge;
    FlowBlock *constBlock = bl->getOut(constEdge);
    if (!constBlock->restrictedByConditional(bl)) continue;	// Make sure condition holds
    propagateConstant(varVn,constVn,constBlock,data);
  }
  return 0;
}

int4 ActionSwitchNorm::apply(Funcdata &data)

{
  for(int4 i=0;i<data.numJumpTables();++i) {
    JumpTable *jt = data.getJumpTable(i);
    if (!jt->isLabelled()) {
      if (jt->recoverLabels(&data)) { // Recover case statement labels
	// If this returns true, the jumptable was not fully recovered during flow analysis
	// So we need to issue a restart
	data.getOverride().insertMultistageJump(jt->getOpAddress());
	data.setRestartPending(true);
      }
      jt->foldInNormalization(&data);
      count += 1;
    }
    if (jt->foldInGuards(&data)) {
      data.getStructure().clear();	// Make sure we redo structure
      count += 1;
    }
  }
  return 0;
}

int4 ActionNormalizeSetup::apply(Funcdata &data)

{
  FuncProto &fp( data.getFuncProto() );
  fp.clearInput();
  fp.setModelLock(false);	// This will cause the model to get reevaluated
  fp.setOutputLock(false);

  // FIXME:  This should probably save and restore symbols, model, and state
  //   If we are calculating normalized trees in console mode, this currently eliminates locks
  //   that may be needed by other normalizing calculations
  return 0;
}

/// \brief Extend Varnode inputs to match prototype model.
///
/// For prototype models that assume input variables are already extended in some way,
/// insert the appropriate extension operation to allow correct small-size input
/// Varnode to exist.
/// \param data is the function being analyzed
/// \param invn is the given (small) input Varnode
/// \param param is the matching symbol info for the Varnode
/// \param topbl is the entry block for the function
void ActionPrototypeTypes::extendInput(Funcdata &data,Varnode *invn,ProtoParameter *param,BlockBasic *topbl)

{
  VarnodeData vdata;
  OpCode res = data.getFuncProto().assumedInputExtension(invn->getAddr(),invn->getSize(),vdata);
  if (res == CPUI_COPY) return;		// no extension
  if (res == CPUI_PIECE) {	// Do an extension based on type of parameter
    if (param->getType()->getMetatype() == TYPE_INT)
      res = CPUI_INT_SEXT;
    else
      res = CPUI_INT_ZEXT;
  }
  PcodeOp *op = data.newOp(1,topbl->getStart());
  data.newVarnodeOut(vdata.size,vdata.getAddr(),op);
  data.opSetOpcode(op,res);
  data.opSetInput(op,invn,0);
  data.opInsertBegin(op,topbl);
}

int4 ActionPrototypeTypes::apply(Funcdata &data)

{
  int4 i;
  PcodeOp *op;
  Varnode *vn;
  list<PcodeOp *>::const_iterator iter,iterend;

  // Set the evalutation prototype if we are not already locked
  ProtoModel *evalfp = data.getArch()->evalfp_current;
  if (evalfp == (ProtoModel *)0)
    evalfp = data.getArch()->defaultfp;
  if ((!data.getFuncProto().isModelLocked())&&(!data.getFuncProto().hasMatchingModel(evalfp)))
    data.getFuncProto().setModel(evalfp);

  iterend = data.endOp(CPUI_RETURN);

				// Strip the indirect register from all RETURN ops
				// (Because we don't want to see this compiler
				// mechanism in the high-level C output)
  for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
    op = *iter;
    if (op->isDead()) continue;
    if (!op->getIn(0)->isConstant()) {
      vn = data.newConstant(op->getIn(0)->getSize(),0);
      data.opSetInput(op,vn,0);
    }
  }
  
  if (data.getFuncProto().isOutputLocked()) {
    ProtoParameter *outparam = data.getFuncProto().getOutput();
    if (outparam->getType()->getMetatype() != TYPE_VOID) {
      for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
	op = *iter;
	if (op->isDead()) continue;
	if (op->getHaltType() != 0) continue;
	vn = data.newVarnode(outparam->getSize(),outparam->getAddress());
	data.opInsertInput(op,vn,op->numInput());
	vn->updateType(outparam->getType(),true,true);
      }
    }
  }
  else
    data.initActiveOutput(); // Initiate gathering potential return values

  AddrSpace *spc = data.getArch()->getDefaultCodeSpace();
  if (spc->isTruncated()) {
    // For truncated spaces we need a zext op, from the truncated stack pointer
    // into the full stack pointer
    AddrSpace *stackspc = data.getArch()->getStackSpace();
    BlockBasic *topbl = (BlockBasic *)0;
    if (data.getBasicBlocks().getSize() > 0)
      topbl = (BlockBasic *)data.getBasicBlocks().getBlock(0);
    if ((stackspc != (AddrSpace *)0)&&(topbl != (BlockBasic *)0)) {
      for(int4 i=0;i<stackspc->numSpacebase();++i) {
	const VarnodeData &fullReg( stackspc->getSpacebaseFull(i) );
	const VarnodeData &truncReg( stackspc->getSpacebase(i) );
	Varnode *invn = data.newVarnode( truncReg.size, truncReg.getAddr() );
	invn = data.setInputVarnode(invn);
	PcodeOp *extop = data.newOp(1,topbl->getStart());
	data.newVarnodeOut(fullReg.size,fullReg.getAddr(),extop);
	data.opSetOpcode(extop,CPUI_INT_ZEXT);
	data.opSetInput(extop,invn,0);
	data.opInsertBegin(extop,topbl);
      }
    }
  }

  // Force locked inputs to exist as varnodes

  // This is needed if we want to force a big input to exist
  // but only part of it is getting used. This is allows
  // a SUBPIECE instruction to get built with the big variable
  // as input and the part getting used as output.
  if (data.getFuncProto().isInputLocked()) {

    int4 ptr_size = spc->isTruncated() ? spc->getAddrSize() : 0; // Check if we need to do pointer trimming
    BlockBasic *topbl = (BlockBasic *)0;
    if (data.getBasicBlocks().getSize() > 0)
      topbl = (BlockBasic *)data.getBasicBlocks().getBlock(0);
    
    int4 numparams = data.getFuncProto().numParams();
    for(i=0;i<numparams;++i) {
      ProtoParameter *param = data.getFuncProto().getParam(i);
      Varnode *vn = data.newVarnode( param->getSize(), param->getAddress());
      vn = data.setInputVarnode(vn);
      vn->setLockedInput();
      if (topbl != (BlockBasic *)0)
	extendInput(data,vn,param,topbl);
      if (ptr_size > 0) {
	Datatype *ct = param->getType();
	if ((ct->getMetatype() == TYPE_PTR)&&(ct->getSize() == ptr_size))
	  vn->setPtrFlow();
      }
    }
  }
  return 0;
}

int4 ActionInputPrototype::apply(Funcdata &data)

{
  vector<Varnode *> triallist;
  ParamActive active(false);
  Varnode *vn;

  // Clear any unlocked local variables because these are
  // getting cleared anyway in the restructure and may be
  // using symbol names that we want
  data.getScopeLocal()->clearUnlockedCategory(-1);
  data.getFuncProto().clearUnlockedInput();
  if (!data.getFuncProto().isInputLocked()) {
    VarnodeDefSet::const_iterator iter,enditer;
    iter = data.beginDef(Varnode::input);
    enditer = data.endDef(Varnode::input);
    while(iter != enditer) {
      vn = *iter;
      ++iter;
      if (data.getFuncProto().possibleInputParam(vn->getAddr(),vn->getSize())) {
	int4 slot = active.getNumTrials();
	active.registerTrial(vn->getAddr(),vn->getSize());
	if (!vn->hasNoDescend())
	  active.getTrial(slot).markActive(); // Mark as active if it has descendants
	triallist.push_back(vn);
      }
    }
    data.getFuncProto().resolveModel(&active);
    data.getFuncProto().deriveInputMap(&active); // Derive the correct prototype from trials
    // Create any unreferenced input varnodes
    for(int4 i=0;i<active.getNumTrials();++i) {
      ParamTrial &paramtrial(active.getTrial(i));
      if (paramtrial.isUnref() && paramtrial.isUsed()) {
	vn = data.newVarnode(paramtrial.getSize(),paramtrial.getAddress());
	vn = data.setInputVarnode(vn);
	int4 slot = triallist.size();
	triallist.push_back(vn);
	paramtrial.setSlot(slot + 1);
      }
    }
    if (data.isHighOn())
      data.getFuncProto().updateInputTypes(data,triallist,&active);
    else
      data.getFuncProto().updateInputNoTypes(data,triallist,&active);
  }
  data.clearDeadVarnodes();
#ifdef OPACTION_DEBUG
  if ((flags&rule_debug)==0) return 0;
  ostringstream s;
  data.getScopeLocal()->printEntries(s);
  data.getArch()->printDebug(s.str());
#endif
  return 0;
}

int4 ActionOutputPrototype::apply(Funcdata &data)

{
  ProtoParameter *outparam = data.getFuncProto().getOutput();
  if ((!outparam->isTypeLocked())||outparam->isSizeTypeLocked()) {
    PcodeOp *op = data.getFirstReturnOp();
    vector<Varnode *> vnlist;
    if (op != (PcodeOp *)0) {
      for(int4 i=1;i<op->numInput();++i)
	vnlist.push_back(op->getIn(i));
    }
    if (data.isHighOn())
      data.getFuncProto().updateOutputTypes(vnlist);
    else
      data.getFuncProto().updateOutputNoTypes(vnlist,data.getArch()->types);
  }
  return 0;
}

int4 ActionUnjustifiedParams::apply(Funcdata &data)

{
  VarnodeDefSet::const_iterator iter,enditer;
  FuncProto &proto( data.getFuncProto() );

  iter = data.beginDef(Varnode::input);
  enditer = data.endDef(Varnode::input);

  while(iter != enditer) {
    Varnode *vn = *iter++;
    VarnodeData vdata;
    if (!proto.unjustifiedInputParam(vn->getAddr(),vn->getSize(),vdata)) continue;

    bool newcontainer;
    do {
      newcontainer = false;
      VarnodeDefSet::const_iterator begiter,iter2;
      begiter = data.beginDef(Varnode::input);
      iter2 = iter;
      bool overlaps = false;
      while(iter2 != begiter) {
	--iter2;
	vn = *iter2;
	if (vn->getSpace() != vdata.space) continue;
	uintb offset = vn->getOffset() + vn->getSize()-1; // Last offset in varnode
	if ((offset >= vdata.offset)&&(vn->getOffset()<vdata.offset)) { // If there is overlap that extends size
	  overlaps = true;
	  uintb endpoint = vdata.offset + vdata.size;
	  vdata.offset = vn->getOffset();
	  vdata.size = endpoint - vdata.offset;
	}
      }
      if (!overlaps) break;	// Found no additional overlaps, go with current justified container
      // If there were overlaps, container may no longer be justified
      newcontainer = proto.unjustifiedInputParam(vdata.getAddr(),vdata.size,vdata);
    } while(newcontainer);

    data.adjustInputVarnodes(vdata.getAddr(),vdata.size);
    // Reset iterator because of additions and deletions
    iter = data.beginDef(Varnode::input,vdata.getAddr());
    enditer = data.endDef(Varnode::input);
    count += 1;
  }
  return 0;
}

int4 ActionHideShadow::apply(Funcdata &data)

{
  VarnodeDefSet::const_iterator iter,enditer;
  HighVariable *high;

  enditer = data.endDef(Varnode::written);
  for(iter=data.beginDef();iter!=enditer;++iter) {
    high = (*iter)->getHigh();
    if (high->isMark()) continue;
    if (data.getMerge().hideShadows(high))
      count += 1;
    high->setMark();
  }
  for(iter=data.beginDef();iter!=enditer;++iter) {
    high = (*iter)->getHigh();
    high->clearMark();
  }
  return 0;
}

int4 ActionDynamicMapping::apply(Funcdata &data)

{
  ScopeLocal *localmap = data.getScopeLocal();
  list<SymbolEntry>::iterator iter,enditer;
  iter = localmap->beginDynamic();
  enditer = localmap->endDynamic();
  DynamicHash dhash;
  while(iter != enditer) {
    SymbolEntry *entry = &(*iter);
    ++iter;
    if (data.attemptDynamicMapping(entry,dhash))
      count += 1;
  }
  return 0;
}

int4 ActionDynamicSymbols::apply(Funcdata &data)

{
  ScopeLocal *localmap = data.getScopeLocal();
  list<SymbolEntry>::iterator iter,enditer;
  iter = localmap->beginDynamic();
  enditer = localmap->endDynamic();
  DynamicHash dhash;
  while(iter != enditer) {
    SymbolEntry *entry = &(*iter);
    ++iter;
    if (data.attemptDynamicMappingLate(entry, dhash))
      count += 1;
  }
  return 0;
}

int4 ActionPrototypeWarnings::apply(Funcdata &data)

{
  vector<string> overridemessages;
  data.getOverride().generateOverrideMessages(overridemessages,data.getArch());
  for(int4 i=0;i<overridemessages.size();++i)
    data.warningHeader(overridemessages[i]);

  FuncProto &ourproto( data.getFuncProto() );
  if (ourproto.hasInputErrors()) {
    data.warningHeader("Cannot assign parameter locations for this function: Prototype may be inaccurate");
  }
  if (ourproto.hasOutputErrors()) {
    data.warningHeader("Cannot assign location of return value for this function: Return value may be inaccurate");
  }
  if (ourproto.isUnknownModel() && (!ourproto.hasCustomStorage()) && 
  	(ourproto.isInputLocked() || ourproto.isOutputLocked())) {
    data.warningHeader("Unknown calling convention yet parameter storage is locked");
  }
  int4 numcalls = data.numCalls();
  for(int4 i=0;i<numcalls;++i) {
    FuncCallSpecs *fc = data.getCallSpecs(i);
    Funcdata *fd = fc->getFuncdata();
    if (fc->hasInputErrors()) {
      ostringstream s;
      s << "Cannot assign parameter location for function ";
      if (fd != (Funcdata *)0)
	s << fd->getName();
      else
	s << "<indirect>";
      s << ": Prototype may be inaccurate";
      data.warning(s.str(),fc->getEntryAddress());
    }
    if (fc->hasOutputErrors()) {
      ostringstream s;
      s << "Cannot assign location of return value for function ";
      if (fd != (Funcdata *)0)
	s << fd->getName();
      else
	s << "<indirect>";
      s << ": Return value may be inaccurate";
      data.warning(s.str(),fc->getEntryAddress());
    }
  }
  return 0;
}

#ifdef TYPEPROP_DEBUG
/// \brief Log a particular data-type propagation action.
///
/// Print the Varnode updated, the new data-type it contains, and
/// where the data-type propagated from.
/// \param glb is the Architecture holding the error console
/// \param vn is the target Varnode
/// \param newtype is the new data-type
/// \param op is the PcodeOp through which the data-type propagated
/// \param slot is the slot from which the data-type propagated
/// \param ptralias if not NULL holds the pointer that aliased the target Varnode
void ActionInferTypes::propagationDebug(Architecture *glb,Varnode *vn,const Datatype *newtype,PcodeOp *op,int4 slot,Varnode *ptralias)

{
  ostringstream s;

  vn->printRaw(s);
  s << " : ";
  newtype->printRaw(s);
  if ((op == (PcodeOp *)0)&&(ptralias == (Varnode *)0)) {
    s << " init";
  }
  else if (ptralias != (Varnode *)0) {
    s << " alias ";
    ptralias->printRaw(s);
  }
  else {
    s << " from ";
    op->printRaw(s);
    s << " slot=" << dec << slot;
  }
  glb->printDebug(s.str());
}
#endif

/// Collect \e local data-type information on each Varnode inferred
/// from the PcodeOps that read and write to it.
/// \param data is the function being analyzed
void ActionInferTypes::buildLocaltypes(Funcdata &data)

{
  Datatype *ct;
  Varnode *vn;
  VarnodeLocSet::const_iterator iter;

  for(iter=data.beginLoc();iter!=data.endLoc();++iter) {
    vn = *iter;
    if (vn->isAnnotation()) continue;
    if ((!vn->isWritten())&&(vn->hasNoDescend())) continue;
    ct = vn->getLocalType();
#ifdef TYPEPROP_DEBUG
    propagationDebug(data.getArch(),vn,ct,(PcodeOp *)0,0,(Varnode *)0);
#endif
    vn->setTempType(ct);
  }
}

/// For each Varnode copy the temporary data-type to the permament
/// field, taking into account previous locks.
/// \param data is the function being analyzed
/// \return \b true if any Varnode's data-type changed from the last round of propagation
bool ActionInferTypes::writeBack(Funcdata &data)

{
  bool change = false;
  Datatype *ct;
  Varnode *vn;
  VarnodeLocSet::const_iterator iter;

  for(iter=data.beginLoc();iter!=data.endLoc();++iter) {
    vn = *iter;
    if (vn->isAnnotation()) continue;
    if ((!vn->isWritten())&&(vn->hasNoDescend())) continue;
    ct = vn->getTempType();
    if (vn->updateType(ct,false,false))
      change = true;
  }
  return change;
}

/// Determine if the given data-type edge looks like a pointer
/// propagating through an "add a constant" operation. We assume the input
/// Varnode has a pointer data-type.
/// \param op is the PcodeOp propagating the data-type
/// \param slot is the input edge being propagated
/// \return the offset of the added constant or -1 if not a pointer add operation
int4 ActionInferTypes::propagateAddPointer(PcodeOp *op,int4 slot)
  
{
  if ((op->code() == CPUI_PTRADD)&&(slot==0))
    return op->getIn(2)->getOffset();
  if ((op->code() == CPUI_PTRSUB)&&(slot==0))
    return op->getIn(1)->getOffset();
  if (op->code() == CPUI_INT_ADD) {
    Varnode *othervn = op->getIn(1-slot);
				// Check if othervn is an offset
    if (!othervn->isConstant()) {
      if ((!othervn->isWritten())||(othervn->getDef()->code() != CPUI_INT_MULT))
	return -1;
    }
    if (othervn->getTempType()->getMetatype() == TYPE_PTR) // Check if othervn marked as ptr
      return -1;
    if (othervn->isConstant())
      return othervn->getOffset();
    return 0;
  }
  return -1;
}

/// \brief Propagate a pointer data-type through an ADD operation.
///
/// Assuming a pointer data-type from an ADD PcodeOp propagates from an input to
/// its output, calculate the transformed data-type of the output Varnode, which
/// will depend on details of the operation. If the edge doesn't make sense as
/// "an ADD to a pointer", prevent the propagation by returning the output Varnode's
/// current data-type.
/// \param typegrp is the TypeFactory for constructing the transformed Datatype
/// \param op is the ADD operation
/// \param inslot is the edge to propagate along
/// \return the transformed Datatype or the original output Datatype
Datatype *ActionInferTypes::propagateAddIn2Out(TypeFactory *typegrp,PcodeOp *op,int4 inslot)
  
{
  Datatype *rettype = op->getIn(inslot)->getTempType(); // We know this is a pointer type
  Datatype *tstruct = ((TypePointer *)rettype)->getPtrTo();
  int4 offset = propagateAddPointer(op,inslot);
  if (offset==-1) return op->getOut()->getTempType(); // Doesn't look like a good pointer add
  uintb uoffset = AddrSpace::addressToByte(offset,((TypePointer *)rettype)->getWordSize());
  if (tstruct->getSize() > 0 && !tstruct->isVariableLength())
    uoffset = uoffset % tstruct->getSize();
  if (uoffset==0) {
    if (op->code() == CPUI_PTRSUB) // Go down at least one level
      rettype = typegrp->downChain(rettype,uoffset);
    if (rettype == (Datatype *)0)
      rettype = op->getOut()->getTempType();
  }
  else {
    while(uoffset != 0) {
      rettype = typegrp->downChain(rettype,uoffset);
      if (rettype == (Datatype *)0) {
	rettype = op->getOut()->getTempType(); // Don't propagate anything
	break;
      }
    }
  }
  if (op->getIn(inslot)->isSpacebase()) {
    if (rettype->getMetatype() == TYPE_PTR) {
      TypePointer *ptype = (TypePointer *)rettype;
      if (ptype->getPtrTo()->getMetatype() == TYPE_SPACEBASE)
	rettype = typegrp->getTypePointer(ptype->getSize(),typegrp->getBase(1,TYPE_UNKNOWN),ptype->getWordSize());
    }
  }
  return rettype;
}

/// \brief Determine if propagation should happen along the given edge
///
/// This enforces a series of rules about how a data-type can propagate
/// between the input and output Varnodes of a single PcodeOp. An input to the
/// edge may either an input or output to the PcodeOp.  A \e slot value of -1
/// indicates the PcodeOp output, a non-negative value indicates a PcodeOp input index.
/// \param op is the PcodeOp to test propagation through
/// \param inslot indicates the edge's input Varnode
/// \param outslot indicates the edge's output Varnode
/// \param invn is the input Varnode
/// \return \b false if edge cannot propagate type
bool ActionInferTypes::propagateGoodEdge(PcodeOp *op,int4 inslot,int4 outslot,Varnode *invn)

{
  if (inslot == outslot) return false; // don't backtrack
  type_metatype metain = invn->getTempType()->getMetatype();
  switch(op->code()) {
  case CPUI_NEW:
    if ((inslot != 0)||(outslot != -1)) return false;
    break;
  case CPUI_INDIRECT:
    if (op->isIndirectCreation()) return false;
    if ((inslot==1)||(outslot==1)) return false;
    if ((inslot!=-1)&&(outslot!=-1)) return false; // Must propagate input <-> output
    break;
  case CPUI_COPY:
    if ((inslot!=-1)&&(outslot!=-1)) return false; // Must propagate input <-> output
    break;
  case CPUI_MULTIEQUAL:
    if ((inslot!=-1)&&(outslot!=-1)) return false; // Must propagate input <-> output
    break;
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
    if ((inslot==-1)||(outslot==-1)) return false; // Must propagate input <-> input
    break;
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
    if ((inslot==-1)||(outslot==-1)) return false; // Must propagate input <-> input
    break;
  case CPUI_LOAD:
  case CPUI_STORE:
    if ((inslot==0)||(outslot==0)) return false; // Don't propagate along this edge
    if (invn->isSpacebase()) return false;
    break;
  case CPUI_PTRADD:
    if ((inslot==2)||(outslot==2)) return false; // Don't propagate along this edge
  case CPUI_PTRSUB:
    if ((inslot!=-1)&&(outslot!=-1)) return false; // Must propagate input <-> output
    if (metain != TYPE_PTR) return false;
    break;
  case CPUI_INT_ADD:
    if (metain != TYPE_PTR) {
      if ((metain == TYPE_INT)||(metain == TYPE_UINT)) {
	if ((outslot==1) && (op->getIn(1)->isConstant()))
	    return true;
      }
      return false;
    }
    if ((inslot!=-1)&&(outslot!=-1)) return false; // Must propagate input <-> output
    break;
  case CPUI_SEGMENTOP:
    // Must propagate  slot2 <-> output
    if ((inslot==0)||(inslot==1)) return false;
    if ((outslot==0)||(outslot==1)) return false;
    if (invn->isSpacebase()) return false;
    if (metain != TYPE_PTR) return false;
    break;
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_XOR:
    if (!invn->getTempType()->isPowerOfTwo()) return false; // Only propagate flag enums
    break;
  default:
    return false;
  }
  return true;
}

/// \brief Attempt to propagate a data-type across a single PcodeOp edge
///
/// Given an \e input Varnode and an \e output Varnode defining a directed edge
/// through a PcodeOp, determine if and how the input data-type propagates to the
/// output. Update the output Varnode's (temporary) data-type. An input to the
/// edge may either an input or output to the PcodeOp.  A \e slot value of -1
/// indicates the PcodeOp output, a non-negative value indicates a PcodeOp input index.
/// \param typegrp is the TypeFactory for building a possibly transformed data-type
/// \param op is the PcodeOp through which the propagation edge flows
/// \param inslot indicates the edge's input Varnode
/// \param outslot indicates the edge's output Varnode
/// \return \b true if the data-type propagates
bool ActionInferTypes::propagateTypeEdge(TypeFactory *typegrp,PcodeOp *op,int4 inslot,int4 outslot)
  
{
  Varnode *invn,*outvn;
  Datatype *newtype;

  outvn = (outslot==-1) ? op->getOut() : op->getIn(outslot);
  if (outvn->isAnnotation()) return false;
  if (outvn->isTypeLock()) return false; // Can't propagate through typelock
  invn = (inslot==-1) ? op->getOut() : op->getIn(inslot);
  if (!propagateGoodEdge(op,inslot,outslot,invn))
    return false;

  Datatype *alttype = invn->getTempType();
  if (alttype->getMetatype() == TYPE_BOOL) {	// Only propagate boolean
    if (outvn->getNZMask() > 1)			// If we know output can only take boolean values
      return false;
  }
  switch(op->code()) {
  case CPUI_INDIRECT:
  case CPUI_COPY:
  case CPUI_MULTIEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_XOR:
    if (invn->isSpacebase()) {
      AddrSpace *spc = typegrp->getArch()->getDefaultDataSpace();
      newtype = typegrp->getTypePointer(alttype->getSize(),typegrp->getBase(1,TYPE_UNKNOWN),spc->getWordSize());
    }
    else
      newtype = alttype;
    break;
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
    if (alttype->getMetatype() != TYPE_INT) return false;	// Only propagate signed things
    newtype = alttype;
    break;
  case CPUI_NEW:
    {
      Varnode *invn = op->getIn(0);
      if (!invn->isWritten()) return false;		// Don't propagate
      if (invn->getDef()->code() != CPUI_CPOOLREF) return false;
      newtype = alttype;		// Propagate cpool result as result of new operator
    }
    break;
  case CPUI_SEGMENTOP:
    {
      AddrSpace *spc = typegrp->getArch()->getDefaultDataSpace();
      Datatype *btype = ((TypePointer *)alttype)->getPtrTo();
      newtype = typegrp->getTypePointer(outvn->getSize(),btype,spc->getWordSize());
    }
    break;
  case CPUI_LOAD:
    if (inslot == -1) {	 // Propagating output to input (value to ptr)
      AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
      newtype = typegrp->getTypePointerNoDepth(outvn->getTempType()->getSize(),alttype,spc->getWordSize());
    }
    else if (alttype->getMetatype()==TYPE_PTR) {
      newtype = ((TypePointer *)alttype)->getPtrTo();
      if (newtype->getSize() != outvn->getTempType()->getSize() || newtype->isVariableLength()) // Size must be appropriate
	newtype = outvn->getTempType();
    }
    else
      newtype = outvn->getTempType(); // Don't propagate anything
    break;
  case CPUI_STORE:
    if (inslot==2) {		// Propagating value to ptr
      AddrSpace *spc = Address::getSpaceFromConst(op->getIn(0)->getAddr());
      newtype = typegrp->getTypePointerNoDepth(outvn->getTempType()->getSize(),alttype,spc->getWordSize());
    }
    else if (alttype->getMetatype()==TYPE_PTR) {
      newtype = ((TypePointer *)alttype)->getPtrTo();
      if (newtype->getSize() != outvn->getTempType()->getSize() || newtype->isVariableLength())
	newtype = outvn->getTempType();
    }
    else
      newtype = outvn->getTempType(); // Don't propagate anything
    break;
  case CPUI_PTRADD:
  case CPUI_PTRSUB:
    if (inslot == -1)		// Propagating output to input
      newtype = op->getIn(outslot)->getTempType();	// Don't propagate pointer types this direction
    else
      newtype = propagateAddIn2Out(typegrp,op,inslot);
    break;
  case CPUI_INT_ADD:
    if (outvn->isConstant() && (alttype->getMetatype() != TYPE_PTR))
      newtype = alttype;
    else if (inslot == -1)		// Propagating output to input
      newtype = op->getIn(outslot)->getTempType();	// Don't propagate pointer types this direction
    else
      newtype = propagateAddIn2Out(typegrp,op,inslot);
    break;
  default:
    return false;		// Don't propagate along this edge
  }
  if (0>newtype->typeOrder(*outvn->getTempType())) {
#ifdef TYPEPROP_DEBUG
    propagationDebug(typegrp->getArch(),outvn,newtype,op,inslot,(Varnode *)0);
#endif
    outvn->setTempType(newtype);
    return !outvn->isMark();
  }
  return false;
}

/// \param v is the root Varnode to iterate over
PropagationState::PropagationState(Varnode *v)

{
  vn = v;
  iter = vn->beginDescend();
  if (iter != vn->endDescend()) {
    op = *iter++;
    if (op->getOut() != (Varnode *)0)
      slot = -1;
    else
      slot = 0;
    inslot = op->getSlot(vn);
  }
  else {
    op = vn->getDef();
    inslot = -1;
    slot = 0;
  }
}

/// At the high level, this iterates through all the descendant
/// PcodeOps of the root Varnode, then the defining PcodeOp.
/// At the low level, this iterates from the output Varnode
/// of the current PcodeOp then through all the input Varnodes
void PropagationState::step(void)

{
  slot += 1;
  if (slot < op->numInput())
    return;
  if (iter != vn->endDescend()) {
    op = *iter++;
    if (op->getOut() != (Varnode *)0)
      slot = -1;
    else
      slot = 0;
    inslot = op->getSlot(vn);
    return;
  }
  if (inslot == -1)
    op = (PcodeOp *)0;
  else
    op = vn->getDef();
  inslot = -1;
  slot = 0;
}

/// \brief Propagate a data-type starting from one Varnode across the function
///
/// Given a starting Varnode, propagate its Datatype as far as possible through
/// the data-flow graph, transforming the data-type through PcodeOps as necessary.
/// The data-type is push through all possible propagating edges, but each
/// Varnode is visited at most once.  Propagation is trimmed along any particular
/// path if the pushed data-type isn't \e more \e specific than the current
/// data-type on a Varnode, under the data-type ordering.
/// \param typegrp is the TypeFactory for constructing transformed data-types
/// \param vn is the Varnode holding the root data-type to push
void ActionInferTypes::propagateOneType(TypeFactory *typegrp,Varnode *vn)

{
  PropagationState *ptr;
  vector<PropagationState> state;

  state.emplace_back(vn);
  vn->setMark();

  while(!state.empty()) {
    ptr = &state.back();
    if (!ptr->valid()) {	// If we are out of edges to traverse
      ptr->vn->clearMark();
      state.pop_back();
    }
    else {
      if (propagateTypeEdge(typegrp,ptr->op,ptr->inslot,ptr->slot)) {
	vn = (ptr->slot==-1) ? ptr->op->getOut() : ptr->op->getIn(ptr->slot);
	ptr->step();		// Make sure to step before push_back
	state.emplace_back(vn);
	vn->setMark();
      }
      else
	ptr->step();
    }
  }
}

/// \brief Try to propagate a pointer data-type to known aliases.
///
/// Given a Varnode which is a likely pointer and an Address that
/// is a known alias of the pointer, attempt to propagate the Varnode's
/// data-type to Varnodes at that address.
/// \param data is the function being analyzed
/// \param vn is the given Varnode
/// \param addr is the aliased address
void ActionInferTypes::propagateRef(Funcdata &data,Varnode *vn,const Address &addr)

{
  Datatype *ct = vn->getTempType();
  if (ct->getMetatype() != TYPE_PTR) return;
  ct = ((TypePointer *)ct)->getPtrTo();
  if (ct->getMetatype() == TYPE_SPACEBASE) return;
  if (ct->getMetatype() == TYPE_UNKNOWN) return; // Don't bother propagating this
  VarnodeLocSet::const_iterator iter,enditer;
  uintb off = addr.getOffset();
  TypeFactory *typegrp = data.getArch()->types;
  Address endaddr = addr + ct->getSize();
  if (endaddr.getOffset() < off) // If the address wrapped
    enditer = data.endLoc(addr.getSpace());	// Go to end of space
  else
    enditer = data.endLoc(endaddr);
  iter = data.beginLoc(addr);
  uintb lastoff = 0;
  int4 lastsize = ct->getSize();
  Datatype *lastct = ct;
  while(iter != enditer) {
    Varnode *curvn = *iter;
    ++iter;
    if (curvn->isAnnotation()) continue;
    if ((!curvn->isWritten())&&curvn->hasNoDescend()) continue;
    uintb curoff = curvn->getOffset() - off;
    int4 cursize = curvn->getSize();
    if (curoff + cursize > ct->getSize()) continue;
    if ((cursize!=lastsize)||(curoff!=lastoff)) {
      lastoff = curoff;
      lastsize = cursize;
      Datatype *cur = ct;
      do {
	lastct = cur;
	cur = cur->getSubType(curoff,&curoff);
      } while(cur != (Datatype *)0);
    }
    if (lastct->getSize() != cursize) continue;
    
    // Try to propagate the reference type into a varnode that is pointed to by that reference
    if (0>lastct->typeOrder(*curvn->getTempType())) {
#ifdef TYPEPROP_DEBUG
      propagationDebug(data.getArch(),curvn,lastct,(PcodeOp *)0,0,vn);
#endif
      curvn->setTempType(lastct);
      propagateOneType(typegrp,curvn); // Try to propagate the new type as far as possible
    }
  }
}

/// \brief Search for pointers and propagate its data-type to known aliases
///
/// This routine looks for ADD operations off of a specific
/// \e spacebase register that produce output Varnodes with a known
/// data-type. The offset of the ADD is calculated into the corresponding
/// address space, and an attempt is made to propagate the Varnodes data-type
/// to other Varnodes in the address space at that offset.
/// \param data is the function being analyzed
/// \param spcvn is the spacebase register
void ActionInferTypes::propagateSpacebaseRef(Funcdata &data,Varnode *spcvn)

{
  Datatype *spctype = spcvn->getType();	// This is an absolute property of the varnode, so not temptype
  if (spctype->getMetatype() != TYPE_PTR) return;
  spctype = ((TypePointer *)spctype)->getPtrTo();
  if (spctype->getMetatype() != TYPE_SPACEBASE) return;
  TypeSpacebase *sbtype = (TypeSpacebase *)spctype;
  list<PcodeOp *>::const_iterator iter;
  Address addr;

  for(iter=spcvn->beginDescend();iter!=spcvn->endDescend();++iter) {
    PcodeOp *op = *iter;
    Varnode *vn;
    switch(op->code()) {
    case CPUI_COPY:
      vn = op->getIn(0);
      addr = sbtype->getAddress(0,vn->getSize(),op->getAddr());
      propagateRef(data,op->getOut(),addr);
      break;
    case CPUI_INT_ADD:
    case CPUI_PTRSUB:
      vn = op->getIn(1);
      if (vn->isConstant()) {
	addr = sbtype->getAddress(vn->getOffset(),vn->getSize(),op->getAddr());
	propagateRef(data,op->getOut(),addr);
      }
      break;
    case CPUI_PTRADD:
      vn = op->getIn(1);
      if (vn->isConstant()) {
	uintb off = vn->getOffset() * op->getIn(2)->getOffset();
	addr = sbtype->getAddress(off,vn->getSize(),op->getAddr());
	propagateRef(data,op->getOut(),addr);
      }
      break;
    default:
      break;
    }
  }
}

/// Return the CPUI_RETURN op with the most specialized data-type, which is not
/// dead and is not a special halt.
/// \param data is the function
/// \return the representative CPUI_RETURN op or NULL
PcodeOp *ActionInferTypes::canonicalReturnOp(Funcdata &data)

{
  PcodeOp *res = (PcodeOp *)0;
  Datatype *bestdt = (Datatype *)0;
  list<PcodeOp *>::const_iterator iter,iterend;
  iterend = data.endOp(CPUI_RETURN);
  for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
    PcodeOp *retop = *iter;
    if (retop->isDead()) continue;
    if (retop->getHaltType()!=0) continue;
    if (retop->numInput() > 1) {
      Varnode *vn = retop->getIn(1);
      Datatype *ct = vn->getTempType();
      if (bestdt == (Datatype *)0) {
	res = retop;
	bestdt = ct;
      }
      else if (ct->typeOrder(*bestdt) < 0) {
	res = retop;
	bestdt = ct;
      }
    }
  }
  return res;
}

/// \brief Give data-types a chance to propagate between CPUI_RETURN operations.
///
/// Since a function is intended to return a single data-type, data-types effectively
/// propagate between the input Varnodes to CPUI_RETURN ops, if there are more than one.
void ActionInferTypes::propagateAcrossReturns(Funcdata &data)

{
  PcodeOp *op = canonicalReturnOp(data);
  if (op == (PcodeOp *)0) return;
  TypeFactory *typegrp = data.getArch()->types;
  Varnode *baseVn = op->getIn(1);
  Datatype *ct = baseVn->getTempType();
  int4 baseSize = baseVn->getSize();
  bool isBool = ct->getMetatype() == TYPE_BOOL;
  list<PcodeOp *>::const_iterator iter,iterend;
  iterend = data.endOp(CPUI_RETURN);
  for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
    PcodeOp *retop = *iter;
    if (retop == op) continue;
    if (retop->isDead()) continue;
    if (retop->getHaltType()!=0) continue;
    if (retop->numInput() > 1) {
      Varnode *vn = retop->getIn(1);
      if (vn->getSize() != baseSize) continue;
      if (isBool && vn->getNZMask() > 1) continue;	// Don't propagate bool if value is not necessarily 0 or 1
      if (vn->getTempType() == ct) continue;		// Already propagated
      vn->setTempType(ct);
#ifdef TYPEPROP_DEBUG
      propagationDebug(typegrp->getArch(),vn,ct,retop,1,(Varnode *)0);
#endif
      propagateOneType(typegrp, vn);
    }
  }
}

int4 ActionInferTypes::apply(Funcdata &data)

{
  // Make sure spacebase is accurate or bases could get typed and then ptrarithed
  if (!data.isTypeRecoveryOn()) return 0;
  TypeFactory *typegrp = data.getArch()->types;
  Varnode *vn;
  VarnodeLocSet::const_iterator iter;

#ifdef TYPEPROP_DEBUG
  ostringstream s;
  s << "Type propagation pass - " << dec << localcount;
  data.getArch()->printDebug(s.str());
#endif
  if (localcount >= 7) {       // This constant arrived at empirically
    if (localcount == 7) {
      data.warningHeader("Type propagation algorithm not settling");
      localcount += 1;
    }
    return 0;
  }
  data.getScopeLocal()->applyTypeRecommendations();
  buildLocaltypes(data);	// Set up initial types (based on local info)
  for(iter=data.beginLoc();iter!=data.endLoc();++iter) {
    vn = *iter;
    if (vn->isAnnotation()) continue;
    if ((!vn->isWritten())&&(vn->hasNoDescend())) continue;
    propagateOneType(typegrp,vn);
  }
  propagateAcrossReturns(data);
  AddrSpace *spcid = data.getScopeLocal()->getSpaceId();
  Varnode *spcvn = data.findSpacebaseInput(spcid);
  if (spcvn != (Varnode *)0)
    propagateSpacebaseRef(data,spcvn);
  if (writeBack(data)) {
    // count += 1;			// Do not consider this a data-flow change
    localcount += 1;
  }
  return 0;
}

/// Assuming root->getOut() is the root of an expression formed with the
/// CPUI_INT_ADD op, collect all the Varnode \e terms of the expression.
void TermOrder::collect(void)

{
  Varnode *curvn;
  PcodeOp *curop;
  PcodeOp *subop,*multop;

  vector<PcodeOp *> opstack;	// Depth first traversal path
  vector<PcodeOp *> multstack;

  opstack.push_back(root);
  multstack.push_back((PcodeOp *)0);

  while(!opstack.empty()) {
    curop = opstack.back();
    multop = multstack.back();
    opstack.pop_back();
    multstack.pop_back();
    for(int4 i=0;i<curop->numInput();++i) {
      curvn = curop->getIn(i);	// curvn is a node of the subtree IF
      if (!curvn->isWritten()) { // curvn is not defined by another operation
	terms.push_back(PcodeOpEdge(curop,i,multop));
	continue;
      }
      if (curvn->loneDescend() == (PcodeOp *)0) { // curvn has more then one use
	terms.push_back(PcodeOpEdge(curop,i,multop));
	continue;
      }
      subop = curvn->getDef();
      if (subop->code() != CPUI_INT_ADD) { // or if curvn is defined with some other type of op
	if ((subop->code()==CPUI_INT_MULT)&&(subop->getIn(1)->isConstant())) {
	  PcodeOp *addop = subop->getIn(0)->getDef();
	  if ((addop!=(PcodeOp *)0)&&(addop->code()==CPUI_INT_ADD)) {
	    if (addop->getOut()->loneDescend()!=(PcodeOp *)0) {
	      opstack.push_back(addop);
	      multstack.push_back(subop);
	      continue;
	    }
	  }
	}
	terms.push_back(PcodeOpEdge(curop,i,multop));
	continue;
      }
      opstack.push_back(subop);
      multstack.push_back(multop);
    }
  }
}

void TermOrder::sortTerms(void)

{
  for(vector<PcodeOpEdge>::iterator iter=terms.begin();iter!=terms.end();++iter)
    sorter.push_back( &(*iter) );

  sort(sorter.begin(),sorter.end(),additiveCompare);
}

/// (Re)build the default \e root Actions: decompile, jumptable, normalize, paramid, register, firstpass
void ActionDatabase::buildDefaultGroups(void)

{
  if (isDefaultGroups) return;
  groupmap.clear();
  const char *members[] = { "base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
			    "deadcode", "typerecovery", "stackptrflow",
			    "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
			    "cleanup", "merge", "dynamic", "casts", "analysis",
			    "fixateglobals", "fixateproto",
			    "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
			    "unreachable", "subvar", "floatprecision", 
			    "conditionalexe", "" };
  setGroup("decompile",members);

  const char *jumptab[] = { "base", "noproto", "localrecovery", "deadcode", "stackptrflow",
			    "stackvars", "analysis", "segment", "subvar", "conditionalexe", "" };
  setGroup("jumptable",jumptab);

 const  char *normali[] = { "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
			    "deadcode", "stackptrflow", "normalanalysis",
			    "stackvars", "deadcontrolflow", "analysis", "fixateproto", "nodejoin",
			    "unreachable", "subvar", "floatprecision", "normalizebranches",
			    "conditionalexe", "" };
  setGroup("normalize",normali);

  const  char *paramid[] = { "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
                             "deadcode", "typerecovery", "stackptrflow", "siganalysis",
                             "stackvars", "deadcontrolflow", "analysis", "fixateproto",
                             "unreachable", "subvar", "floatprecision",
                             "conditionalexe", "" };
  setGroup("paramid",paramid);

  const char *regmemb[] = { "base", "analysis", "subvar", "" };
  setGroup("register",regmemb);

  const char *firstmem[] = { "base", "" };
  setGroup("firstpass",firstmem);
  isDefaultGroups = true;
}

/// Construct the \b universal Action that contains all possible components
/// \param conf is the Architecture that will use the Action
void ActionDatabase::universalAction(Architecture *conf)

{
  vector<Rule *>::iterator iter;
  ActionGroup *act;
  ActionGroup *actmainloop;
  ActionGroup *actfullloop;
  ActionPool *actprop,*actprop2;
  ActionPool *actcleanup;
  ActionGroup *actstackstall;
  AddrSpace *stackspace = conf->getStackSpace();

  act = new ActionRestartGroup(Action::rule_onceperfunc,"universal",1);
  registerAction(universalname,act);

  act->addAction( new ActionStart("base"));
  act->addAction( new ActionConstbase("base"));
  act->addAction( new ActionNormalizeSetup("normalanalysis"));
  act->addAction( new ActionDefaultParams("base"));
  //  act->addAction( new ActionParamShiftStart("paramshift") );
  act->addAction( new ActionExtraPopSetup("base",stackspace) );
  act->addAction( new ActionPrototypeTypes("protorecovery"));
  act->addAction( new ActionFuncLink("protorecovery") );
  act->addAction( new ActionFuncLinkOutOnly("noproto") );
  {
    actfullloop = new ActionGroup(Action::rule_repeatapply,"fullloop");
    {
      actmainloop = new ActionGroup(Action::rule_repeatapply,"mainloop");
      actmainloop->addAction( new ActionUnreachable("base") );
      actmainloop->addAction( new ActionVarnodeProps("base") );
      actmainloop->addAction( new ActionHeritage("base") );
      actmainloop->addAction( new ActionParamDouble("protorecovery") );
      actmainloop->addAction( new ActionSegmentize("base"));
      actmainloop->addAction( new ActionForceGoto("blockrecovery") );
      actmainloop->addAction( new ActionDirectWrite("protorecovery_a", true) );
      actmainloop->addAction( new ActionDirectWrite("protorecovery_b", false) );
      actmainloop->addAction( new ActionActiveParam("protorecovery") );
      actmainloop->addAction( new ActionReturnRecovery("protorecovery") );
      //      actmainloop->addAction( new ActionParamShiftStop("paramshift") );
      actmainloop->addAction( new ActionRestrictLocal("localrecovery") ); // Do before dead code removed
      actmainloop->addAction( new ActionDeadCode("deadcode") );
      actmainloop->addAction( new ActionDynamicMapping("dynamic") ); // Must come before restructurevarnode and infertypes
      actmainloop->addAction( new ActionRestructureVarnode("localrecovery") );
      actmainloop->addAction( new ActionSpacebase("base") );	// Must come before infertypes and nonzeromask
      actmainloop->addAction( new ActionNonzeroMask("analysis") );
      actmainloop->addAction( new ActionInferTypes("typerecovery") );
      actstackstall = new ActionGroup(Action::rule_repeatapply,"stackstall");
      {
	actprop = new ActionPool(Action::rule_repeatapply,"oppool1");
	actprop->addRule( new RuleEarlyRemoval("deadcode"));
	actprop->addRule( new RuleTermOrder("analysis"));
	actprop->addRule( new RuleSelectCse("analysis"));
	actprop->addRule( new RuleCollectTerms("analysis"));
	actprop->addRule( new RulePullsubMulti("analysis"));
	actprop->addRule( new RulePullsubIndirect("analysis"));
	actprop->addRule( new RulePushMulti("nodejoin"));
	actprop->addRule( new RuleSborrow("analysis") );
	actprop->addRule( new RuleIntLessEqual("analysis") );
	actprop->addRule( new RuleTrivialArith("analysis") );
	actprop->addRule( new RuleTrivialBool("analysis") );
	actprop->addRule( new RuleTrivialShift("analysis") );
	actprop->addRule( new RuleSignShift("analysis") );
	actprop->addRule( new RuleTestSign("analysis") );
	actprop->addRule( new RuleIdentityEl("analysis") );
	actprop->addRule( new RuleOrMask("analysis") );
	actprop->addRule( new RuleAndMask("analysis") );
	actprop->addRule( new RuleOrConsume("analysis") );
	actprop->addRule( new RuleOrCollapse("analysis") );
	actprop->addRule( new RuleAndOrLump("analysis") );
	actprop->addRule( new RuleShiftBitops("analysis") );
	actprop->addRule( new RuleRightShiftAnd("analysis") );
	actprop->addRule( new RuleNotDistribute("analysis") );
	actprop->addRule( new RuleHighOrderAnd("analysis") );
	actprop->addRule( new RuleAndDistribute("analysis") );
	actprop->addRule( new RuleAndCommute("analysis") );
	actprop->addRule( new RuleAndPiece("analysis") );
	actprop->addRule( new RuleAndCompare("analysis") );
	actprop->addRule( new RuleDoubleSub("analysis") );
	actprop->addRule( new RuleDoubleShift("analysis") );
	actprop->addRule( new RuleDoubleArithShift("analysis") );
	actprop->addRule( new RuleConcatShift("analysis") );
	actprop->addRule( new RuleLeftRight("analysis") );
	actprop->addRule( new RuleShiftCompare("analysis") );
	actprop->addRule( new RuleShift2Mult("analysis") );
	actprop->addRule( new RuleShiftPiece("analysis") );
	actprop->addRule( new RuleMultiCollapse("analysis") );
	actprop->addRule( new RuleIndirectCollapse("analysis") );
	actprop->addRule( new Rule2Comp2Mult("analysis") );
	actprop->addRule( new RuleSub2Add("analysis") );
	actprop->addRule( new RuleCarryElim("analysis") );
	actprop->addRule( new RuleBxor2NotEqual("analysis") );
	actprop->addRule( new RuleLess2Zero("analysis") );
	actprop->addRule( new RuleLessEqual2Zero("analysis") );
	actprop->addRule( new RuleSLess2Zero("analysis") );
	actprop->addRule( new RuleEqual2Zero("analysis") );
	actprop->addRule( new RuleEqual2Constant("analysis") );
	actprop->addRule( new RuleThreeWayCompare("analysis") );
	actprop->addRule( new RuleXorCollapse("analysis") );
	actprop->addRule( new RuleAddMultCollapse("analysis") );
	actprop->addRule( new RuleCollapseConstants("analysis") );
	actprop->addRule( new RuleTransformCpool("analysis") );
	actprop->addRule( new RulePropagateCopy("analysis") );
	actprop->addRule( new RuleZextEliminate("analysis") );
	actprop->addRule( new RuleSlessToLess("analysis") );
	actprop->addRule( new RuleZextSless("analysis") );
	actprop->addRule( new RuleBitUndistribute("analysis") );
	actprop->addRule( new RuleBoolZext("analysis") );
	actprop->addRule( new RuleBooleanNegate("analysis") );
	actprop->addRule( new RuleLogic2Bool("analysis") );
	actprop->addRule( new RuleSubExtComm("analysis") );
	actprop->addRule( new RuleSubCommute("analysis") );
	actprop->addRule( new RuleConcatCommute("analysis") );
	actprop->addRule( new RuleConcatZext("analysis") );
	actprop->addRule( new RuleZextCommute("analysis") );
	actprop->addRule( new RuleZextShiftZext("analysis") );
	actprop->addRule( new RuleShiftAnd("analysis") );
	actprop->addRule( new RuleConcatZero("analysis") );
	actprop->addRule( new RuleConcatLeftShift("analysis") );
	actprop->addRule( new RuleEmbed("analysis") );
	actprop->addRule( new RuleSubZext("analysis") );
	actprop->addRule( new RuleSubCancel("analysis") );
	actprop->addRule( new RuleShiftSub("analysis") );
	actprop->addRule( new RuleHumptyDumpty("analysis") );
	actprop->addRule( new RuleDumptyHump("analysis") );
	actprop->addRule( new RuleHumptyOr("analysis") );
	actprop->addRule( new RuleNegateIdentity("analysis") );
	actprop->addRule( new RuleSubNormal("analysis") );
	actprop->addRule( new RulePositiveDiv("analysis") );
	actprop->addRule( new RuleDivTermAdd("analysis") );
	actprop->addRule( new RuleDivTermAdd2("analysis") );
	actprop->addRule( new RuleDivOpt("analysis") );
	actprop->addRule( new RuleSignForm("analysis") );
	actprop->addRule( new RuleSignDiv2("analysis") );
	actprop->addRule( new RuleSignNearMult("analysis") );
	actprop->addRule( new RuleModOpt("analysis") );
	actprop->addRule( new RuleSwitchSingle("analysis") );
	actprop->addRule( new RuleCondNegate("analysis") );
	actprop->addRule( new RuleBoolNegate("analysis") );
	actprop->addRule( new RuleLessEqual("analysis") );
	actprop->addRule( new RuleLessNotEqual("analysis") );
	actprop->addRule( new RuleLessOne("analysis") );
	actprop->addRule( new RuleRangeMeld("analysis") );
	actprop->addRule( new RuleFloatRange("analysis") );
	actprop->addRule( new RulePiece2Zext("analysis") );
	actprop->addRule( new RulePiece2Sext("analysis") );
	actprop->addRule( new RulePopcountBoolXor("analysis") );
	actprop->addRule( new RuleXorSwap("analysis") );
	actprop->addRule( new RuleSubvarAnd("subvar") );
	actprop->addRule( new RuleSubvarSubpiece("subvar") );
	actprop->addRule( new RuleSplitFlow("subvar") );
	actprop->addRule( new RulePtrFlow("subvar",conf) );
	actprop->addRule( new RuleSubvarCompZero("subvar") );
	actprop->addRule( new RuleSubvarShift("subvar") );
	actprop->addRule( new RuleSubvarZext("subvar") );
	actprop->addRule( new RuleSubvarSext("subvar") );
	actprop->addRule( new RuleNegateNegate("analysis") );
	actprop->addRule( new RuleConditionalMove("conditionalexe") );
	actprop->addRule( new RuleOrPredicate("conditionalexe") );
	actprop->addRule( new RuleFuncPtrEncoding("analysis") );
	actprop->addRule( new RuleSubfloatConvert("floatprecision") );
	actprop->addRule( new RuleFloatCast("floatprecision") );
	actprop->addRule( new RuleIgnoreNan("floatprecision") );
	actprop->addRule( new RulePtraddUndo("typerecovery") );
	actprop->addRule( new RulePtrsubUndo("typerecovery") );
	actprop->addRule( new RuleSegment("segment") );
	actprop->addRule( new RulePiecePathology("protorecovery") );

	actprop->addRule( new RuleDoubleLoad("doubleload") );
	actprop->addRule( new RuleDoubleIn("doubleprecis") );
	for(iter=conf->extra_pool_rules.begin();iter!=conf->extra_pool_rules.end();++iter)
	  actprop->addRule( *iter ); // Add CPU specific rules
	conf->extra_pool_rules.clear(); // Rules are now absorbed into universal
      }
      actstackstall->addAction( actprop );
      actstackstall->addAction( new ActionLaneDivide("base") );
      actstackstall->addAction( new ActionMultiCse("analysis") );
      actstackstall->addAction( new ActionShadowVar("analysis") );
      actstackstall->addAction( new ActionDeindirect("deindirect") );
      actstackstall->addAction( new ActionStackPtrFlow("stackptrflow",stackspace));
      actmainloop->addAction( actstackstall );
      actmainloop->addAction( new ActionRedundBranch("deadcontrolflow") ); // dead code removal
      actmainloop->addAction( new ActionBlockStructure("blockrecovery"));
      actmainloop->addAction( new ActionConstantPtr("typerecovery") );
      {
	actprop2 = new ActionPool(Action::rule_repeatapply,"oppool2");

	actprop2->addRule( new RulePushPtr("typerecovery") );
	actprop2->addRule( new RuleStructOffset0("typerecovery") );
	actprop2->addRule( new RulePtrArith("typerecovery") );
	//	actprop2->addRule( new RuleIndirectConcat("analysis") );
	actprop2->addRule( new RuleLoadVarnode("stackvars") );
	actprop2->addRule( new RuleStoreVarnode("stackvars") );
      }
      actmainloop->addAction( actprop2 );
      actmainloop->addAction( new ActionDeterminedBranch("unreachable") );
      actmainloop->addAction( new ActionUnreachable("unreachable") );
      actmainloop->addAction( new ActionNodeJoin("nodejoin") );
      actmainloop->addAction( new ActionConditionalExe("conditionalexe") );
      actmainloop->addAction( new ActionConditionalConst("analysis") );
    }
    actfullloop->addAction( actmainloop );
    actfullloop->addAction( new ActionLikelyTrash("protorecovery") );
    actfullloop->addAction( new ActionDirectWrite("protorecovery_a", true) );
    actfullloop->addAction( new ActionDirectWrite("protorecovery_b", false) );
    actfullloop->addAction( new ActionDeadCode("deadcode") );
    actfullloop->addAction( new ActionDoNothing("deadcontrolflow") );
    actfullloop->addAction( new ActionSwitchNorm("switchnorm") );
    actfullloop->addAction( new ActionReturnSplit("returnsplit") );
    actfullloop->addAction( new ActionUnjustifiedParams("protorecovery") );
    actfullloop->addAction( new ActionStartTypes("typerecovery") );
    actfullloop->addAction( new ActionActiveReturn("protorecovery") );
  }
  act->addAction( actfullloop );
  act->addAction( new ActionStartCleanUp("cleanup") );
  {
    actcleanup = new ActionPool(Action::rule_repeatapply,"cleanup");

    actcleanup->addRule( new RuleMultNegOne("cleanup") );
    actcleanup->addRule( new RuleAddUnsigned("cleanup") );
    actcleanup->addRule( new Rule2Comp2Sub("cleanup") );
    actcleanup->addRule( new RuleSubRight("cleanup") );
    actcleanup->addRule( new RulePtrsubCharConstant("cleanup") );
  }
  act->addAction( actcleanup );

  act->addAction( new ActionPreferComplement("blockrecovery") );
  act->addAction( new ActionStructureTransform("blockrecovery") );
  act->addAction( new ActionNormalizeBranches("normalizebranches") );
  act->addAction( new ActionAssignHigh("merge") );
  act->addAction( new ActionMergeRequired("merge") );
  act->addAction( new ActionMarkExplicit("merge") );
  act->addAction( new ActionMarkImplied("merge") ); // This must come BEFORE general merging
  act->addAction( new ActionMergeMultiEntry("merge") );
  act->addAction( new ActionMergeCopy("merge") );
  act->addAction( new ActionDominantCopy("merge") );
  act->addAction( new ActionDynamicSymbols("dynamic") );
  act->addAction( new ActionMarkIndirectOnly("merge") ); // Must come after required merges but before speculative
  act->addAction( new ActionMergeAdjacent("merge") );
  act->addAction( new ActionMergeType("merge") );
  act->addAction( new ActionHideShadow("merge") );
  act->addAction( new ActionCopyMarker("merge") );
  act->addAction( new ActionOutputPrototype("localrecovery") );
  act->addAction( new ActionInputPrototype("fixateproto") );
  act->addAction( new ActionRestructureHigh("localrecovery") );
  act->addAction( new ActionMapGlobals("fixateglobals") );
  act->addAction( new ActionDynamicSymbols("dynamic") );
  act->addAction( new ActionNameVars("merge") );
  act->addAction( new ActionSetCasts("casts") );
  act->addAction( new ActionFinalStructure("blockrecovery") );
  act->addAction( new ActionPrototypeWarnings("protorecovery") );
  act->addAction( new ActionStop("base") );
}

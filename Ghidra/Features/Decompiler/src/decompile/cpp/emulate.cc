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
#include "emulate.hh"

/// Any time the emulator is about to execute a user-defined pcode op with the given name,
/// the indicated breakpoint is invoked first. The break table does \e not assume responsibility
/// for freeing the breakpoint object.
/// \param name is the name of the user-defined pcode op
/// \param func is the breakpoint object to associate with the pcode op
void BreakTableCallBack::registerPcodeCallback(const string &name,BreakCallBack *func)

{
  func->setEmulate(emulate);
  vector<string> userops;
  trans->getUserOpNames(userops);
  for(int4 i=0;i<userops.size();++i) {
    if (userops[i] == name) {
      pcodecallback[(uintb)i] = func;
      return;
    }
  }
  throw LowlevelError("Bad userop name: "+name);
}

/// Any time the emulator is about to execute (the pcode translation of) a particular machine
/// instruction at this address, the indicated breakpoint is invoked first. The break table
/// does \e not assume responsibility for freeing the breakpoint object.
/// \param addr is the address associated with the breakpoint
/// \param func is the breakpoint being registered
void BreakTableCallBack::registerAddressCallback(const Address &addr,BreakCallBack *func)

{
  func->setEmulate(emulate);
  addresscallback[addr] = func;
}

/// This routine invokes the setEmulate method on each breakpoint currently in the table
/// \param emu is the emulator to be associated with the breakpoints
void BreakTableCallBack::setEmulate(Emulate *emu)

{ // Make sure all callbbacks are aware of new emulator
  emulate = emu;
  map<Address,BreakCallBack *>::iterator iter1;

  for(iter1=addresscallback.begin();iter1!=addresscallback.end();++iter1)
    (*iter1).second->setEmulate(emu);

  map<uintb,BreakCallBack *>::iterator iter2;


  for(iter2=pcodecallback.begin();iter2!=pcodecallback.end();++iter2)
    (*iter2).second->setEmulate(emu);
}

/// This routine examines the pcode-op based container for any breakpoints associated with the
/// given op.  If one is found, its pcodeCallback method is invoked.
/// \param curop is pcode op being checked for breakpoints
/// \return \b true if the breakpoint exists and returns \b true, otherwise return \b false
bool BreakTableCallBack::doPcodeOpBreak(PcodeOpRaw *curop)

{
  uintb val = curop->getInput(0)->offset;
  map<uintb,BreakCallBack *>::const_iterator iter;

  iter = pcodecallback.find(val);
  if (iter == pcodecallback.end()) return false;
  return (*iter).second->pcodeCallback(curop);
}

/// This routine examines the address based container for any breakpoints associated with the
/// given address. If one is found, its addressCallback method is invoked.
/// \param addr is the address being checked for breakpoints
/// \return \b true if the breakpoint exists and returns \b true, otherwise return \b false
bool BreakTableCallBack::doAddressBreak(const Address &addr)

{
  map<Address,BreakCallBack *>::const_iterator iter;
  
  iter = addresscallback.find(addr);
  if (iter == addresscallback.end()) return false;
  return (*iter).second->addressCallback(addr);
}

/// Provide the emitter with the containers that will hold the cached p-code ops and varnodes.
/// \param ocache is the container for cached PcodeOpRaw
/// \param vcache is the container for cached VarnodeData
/// \param in is the map of OpBehavior
/// \param uniqReserve is the starting offset for temporaries in the \e unique space
PcodeEmitCache::PcodeEmitCache(vector<PcodeOpRaw *> &ocache,vector<VarnodeData *> &vcache,
			       const vector<OpBehavior *> &in,uintb uniqReserve)
  : opcache(ocache), varcache(vcache), inst(in)
{
  uniq = uniqReserve;
}

/// Create an internal copy of the VarnodeData and cache it.
/// \param var is the incoming VarnodeData being dumped
/// \return the cloned VarnodeData
VarnodeData *PcodeEmitCache::createVarnode(const VarnodeData *var)

{
  VarnodeData *res = new VarnodeData();
  *res = *var;
  varcache.push_back(res);
  return res;
}

void PcodeEmitCache::dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize)

{
  PcodeOpRaw *op = new PcodeOpRaw();
  op->setSeqNum(addr,uniq);
  opcache.push_back(op);
  op->setBehavior( inst[opc] );
  uniq += 1;
  if (outvar != (VarnodeData *)0) {
    VarnodeData *outvn = createVarnode(outvar);
    op->setOutput(outvn);
  }
  for(int4 i=0;i<isize;++i) {
    VarnodeData *invn = createVarnode(vars+i);
    op->addInput(invn);
  }
}

/// This method executes a single pcode operation, the current one (returned by getCurrentOp()).
/// The MemoryState of the emulator is queried and changed as needed to accomplish this.
void Emulate::executeCurrentOp(void)

{
  if (currentBehave == (OpBehavior *)0) {	// Presumably a NO-OP
    fallthruOp();
    return;
  }
  if (currentBehave->isSpecial()) {
    switch(currentBehave->getOpcode()) {
    case CPUI_LOAD:
      executeLoad();
      fallthruOp();
      break;
    case CPUI_STORE:
      executeStore();
      fallthruOp();
      break;
    case CPUI_BRANCH:
      executeBranch();
      break;
    case CPUI_CBRANCH:
      if (executeCbranch())
	executeBranch();
      else
	fallthruOp();
      break;
    case CPUI_BRANCHIND:
      executeBranchind();
      break;
    case CPUI_CALL:
      executeCall();
      break;
    case CPUI_CALLIND:
      executeCallind();
      break;
    case CPUI_CALLOTHER:
      executeCallother();
      break;
    case CPUI_RETURN:
      executeBranchind();
      break;
    case CPUI_MULTIEQUAL:
      executeMultiequal();
      fallthruOp();
      break;
    case CPUI_INDIRECT:
      executeIndirect();
      fallthruOp();
      break;
    case CPUI_SEGMENTOP:
      executeSegmentOp();
      fallthruOp();
      break;
    case CPUI_CPOOLREF:
      executeCpoolRef();
      fallthruOp();
      break;
    case CPUI_NEW:
      executeNew();
      fallthruOp();
      break;
    default:
      throw LowlevelError("Bad special op");
    }
  }
  else if (currentBehave->isUnary()) {	// Unary operation
    executeUnary();
    fallthruOp();
  }
  else {			// Binary operation
    executeBinary();
    fallthruOp();		// All binary ops are fallthrus
  }
}

void EmulateMemory::executeUnary(void)

{
  uintb in1 = memstate->getValue(currentOp->getInput(0));
  uintb out = currentBehave->evaluateUnary(currentOp->getOutput()->size,
					   currentOp->getInput(0)->size,in1);
  memstate->setValue(currentOp->getOutput(),out);
}

void EmulateMemory::executeBinary(void)

{
  uintb in1 = memstate->getValue(currentOp->getInput(0));
  uintb in2 = memstate->getValue(currentOp->getInput(1));
  uintb out = currentBehave->evaluateBinary(currentOp->getOutput()->size,
					    currentOp->getInput(0)->size,in1,in2);
  memstate->setValue(currentOp->getOutput(),out);
}

void EmulateMemory::executeLoad(void)

{
  uintb off = memstate->getValue(currentOp->getInput(1));
  AddrSpace *spc = Address::getSpaceFromConst(currentOp->getInput(0)->getAddr());

  off = AddrSpace::addressToByte(off,spc->getWordSize());
  uintb res = memstate->getValue(spc,off,currentOp->getOutput()->size);
  memstate->setValue(currentOp->getOutput(),res);
}

void EmulateMemory::executeStore(void)

{
  uintb val = memstate->getValue(currentOp->getInput(2)); // Value being stored
  uintb off = memstate->getValue(currentOp->getInput(1)); // Offset to store at
  AddrSpace *spc = Address::getSpaceFromConst(currentOp->getInput(0)->getAddr()); // Space to store in

  off = AddrSpace::addressToByte(off,spc->getWordSize());
  memstate->setValue(spc,off,currentOp->getInput(2)->size,val);
}

void EmulateMemory::executeBranch(void)

{
  setExecuteAddress(currentOp->getInput(0)->getAddr());
}

bool EmulateMemory::executeCbranch(void)

{
  uintb cond = memstate->getValue(currentOp->getInput(1));
  return (cond != 0);
}

void EmulateMemory::executeBranchind(void)

{
  uintb off = memstate->getValue(currentOp->getInput(0));
  setExecuteAddress(Address(currentOp->getAddr().getSpace(),off));
}

void EmulateMemory::executeCall(void)

{
  setExecuteAddress(currentOp->getInput(0)->getAddr());
}

void EmulateMemory::executeCallind(void)

{
  uintb off = memstate->getValue(currentOp->getInput(0));
  setExecuteAddress(Address(currentOp->getAddr().getSpace(),off));
}

void EmulateMemory::executeCallother(void)

{
  throw LowlevelError("CALLOTHER emulation not currently supported");
}

void EmulateMemory::executeMultiequal(void)

{
  throw LowlevelError("MULTIEQUAL appearing in unheritaged code?");
}

void EmulateMemory::executeIndirect(void)

{
  throw LowlevelError("INDIRECT appearing in unheritaged code?");
}

void EmulateMemory::executeSegmentOp(void)

{
  throw LowlevelError("SEGMENTOP emulation not currently supported");
}

void EmulateMemory::executeCpoolRef(void)

{
  throw LowlevelError("Cannot currently emulate cpool operator");
}

void EmulateMemory::executeNew(void)

{
  throw LowlevelError("Cannot currently emulate new operator");
}

/// \param t is the SLEIGH translator
/// \param s is the MemoryState the emulator should manipulate
/// \param b is the table of breakpoints the emulator should invoke
EmulatePcodeCache::EmulatePcodeCache(Translate *t,MemoryState *s,BreakTable *b)
  : EmulateMemory(s)
{
  trans = t;
  OpBehavior::registerInstructions(inst,t);
  breaktable = b;
  breaktable->setEmulate(this);
}

/// Free all the VarnodeData and PcodeOpRaw objects and clear the cache
void EmulatePcodeCache::clearCache(void)

{
  for(int4 i=0;i<opcache.size();++i)
    delete opcache[i];
  for(int4 i=0;i<varcache.size();++i)
    delete varcache[i];
  opcache.clear();
  varcache.clear();
}

EmulatePcodeCache::~EmulatePcodeCache(void)

{
  clearCache();
  for(int4 i=0;i<inst.size();++i) {
    OpBehavior *t_op = inst[i];
    if (t_op != (OpBehavior *)0)
      delete t_op;
  }
}

/// This is a private routine which does the work of translating a machine instruction
/// into pcode, putting it into the cache, and setting up the iterators
/// \param addr is the address of the instruction to translate
void EmulatePcodeCache::createInstruction(const Address &addr)

{
  clearCache();
  PcodeEmitCache emit(opcache,varcache,inst,0);
  instruction_length = trans->oneInstruction(emit,addr);
  current_op = 0;
  instruction_start = true;
}

/// Set-up currentOp and currentBehave
void EmulatePcodeCache::establishOp(void)

{
  if (current_op < opcache.size()) {
    currentOp = opcache[current_op];
    currentBehave = currentOp->getBehavior();
    return;
  }
  currentOp = (PcodeOpRaw *)0;
  currentBehave = (OpBehavior *)0;
}

/// Update the iterator into the current pcode cache, and if necessary, generate
/// the pcode for the fallthru instruction and reset the iterator.
void EmulatePcodeCache::fallthruOp(void)

{
  instruction_start = false;
  current_op += 1;
  if (current_op >= opcache.size()) {
    current_address = current_address + instruction_length;
    createInstruction(current_address);
  }
  establishOp();
}

/// Since the full instruction is cached, we can do relative branches properly
void EmulatePcodeCache::executeBranch(void)

{
  const Address &destaddr( currentOp->getInput(0)->getAddr() );
  if (destaddr.isConstant()) {
    uintm id = destaddr.getOffset();
    id = id + (uintm)current_op;
    current_op = id;
    if (current_op == opcache.size())
      fallthruOp();
    else if ((current_op < 0)||(current_op >= opcache.size()))
      throw LowlevelError("Bad intra-instruction branch");
  }
  else
    setExecuteAddress(destaddr);
}

/// Look for a breakpoint for the given user-defined op and invoke it.
/// If it doesn't exist, or doesn't replace the action, throw an exception
void EmulatePcodeCache::executeCallother(void)

{
  if (!breaktable->doPcodeOpBreak(currentOp))
    throw LowlevelError("Userop not hooked");
  fallthruOp();
}

/// Set the current execution address and cache the pcode translation of the machine instruction
/// at that address
/// \param addr is the address where execution should continue
void EmulatePcodeCache::setExecuteAddress(const Address &addr)

{
  current_address = addr;	// Copy -addr- BEFORE calling createInstruction
                                // as it calls clear and may delete -addr-
  createInstruction(current_address);
  establishOp();
}

/// This routine executes an entire machine instruction at once, as a conventional debugger step
/// function would do.  If execution is at the start of an instruction, the breakpoints are checked
/// and invoked as needed for the current address.  If this routine is invoked while execution is
/// in the middle of a machine instruction, execution is continued until the current instruction
/// completes.
void EmulatePcodeCache::executeInstruction(void)

{
  if (instruction_start) {
    if (breaktable->doAddressBreak(current_address))
      return;
  }
  do {
    executeCurrentOp();
  } while(!instruction_start);
}

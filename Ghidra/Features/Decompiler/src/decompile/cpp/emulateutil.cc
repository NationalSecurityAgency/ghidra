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
#include "architecture.hh"
#include "emulateutil.hh"

/// \param g is the Architecture providing the LoadImage
EmulatePcodeOp::EmulatePcodeOp(Architecture *g)

{
  glb = g;
  currentOp = (PcodeOp *)0;
  lastOp = (PcodeOp *)0;
}

uintb EmulatePcodeOp::getLoadImageValue(AddrSpace *spc,uintb off,int4 sz) const

{
  LoadImage *loadimage = glb->loader;
  uintb res;

  loadimage->loadFill((uint1 *)&res,sizeof(uintb),Address(spc,off));

  if ((HOST_ENDIAN==1) != spc->isBigEndian())
    res = byte_swap(res,sizeof(uintb));
  if (spc->isBigEndian() && (sz < sizeof(uintb)))
    res >>= (sizeof(uintb)-sz)*8;
  else
    res &= calc_mask(sz);
  return res;
}

void EmulatePcodeOp::executeUnary(void)

{
  uintb in1 = getVarnodeValue(currentOp->getIn(0));
  uintb out = currentBehave->evaluateUnary(currentOp->getOut()->getSize(),
					   currentOp->getIn(0)->getSize(),in1);
  setVarnodeValue(currentOp->getOut(), out);
}

void EmulatePcodeOp::executeBinary(void)

{
  uintb in1 = getVarnodeValue(currentOp->getIn(0));
  uintb in2 = getVarnodeValue(currentOp->getIn(1));
  uintb out = currentBehave->evaluateBinary(currentOp->getOut()->getSize(),
					    currentOp->getIn(0)->getSize(),in1,in2);
  setVarnodeValue(currentOp->getOut(), out);
}

void EmulatePcodeOp::executeLoad(void)

{
  // op will be null, use current_op
  uintb off = getVarnodeValue(currentOp->getIn(1));
  AddrSpace *spc = Address::getSpaceFromConst(currentOp->getIn(0)->getAddr());
  off = AddrSpace::addressToByte(off,spc->getWordSize());
  int4 sz = currentOp->getOut()->getSize();
  uintb res = getLoadImageValue(spc,off,sz);
  setVarnodeValue(currentOp->getOut(),res);
}

void EmulatePcodeOp::executeStore(void)

{
  // There is currently nowhere to store anything since the memstate is null
  //  uintb val = getVarnodeValue(current_op->getIn(2)); // Value being stored
  //  uintb off = getVarnodeValue(current_op->getIn(1));
  //  AddrSpace *spc = Address::getSpaceFromConst(current_op->getIn(0)->getAddr());
}

bool EmulatePcodeOp::executeCbranch(void)

{
  // op will be null, use current_op
  uintb cond = getVarnodeValue(currentOp->getIn(1));
  // We must take into account the booleanflip bit with pcode from the syntax tree
  return ((cond != 0) != currentOp->isBooleanFlip());
}

void EmulatePcodeOp::executeMultiequal(void)

{
  // op will be null, use current_op
  int4 i;
  FlowBlock *bl = currentOp->getParent();
  FlowBlock *last_bl = lastOp->getParent();

  for(i=0;i<bl->sizeIn();++i)
    if (bl->getIn(i) == last_bl) break;
  if (i == bl->sizeIn())
    throw LowlevelError("Could not execute MULTIEQUAL");
  uintb val = getVarnodeValue(currentOp->getIn(i));
  setVarnodeValue( currentOp->getOut(), val );
}

void EmulatePcodeOp::executeIndirect(void)

{
  // We could probably safely ignore this in the
  // context we are using it (jumptable recovery)
  // But we go ahead and assume it is equivalent to copy
  uintb val = getVarnodeValue(currentOp->getIn(0));
  setVarnodeValue( currentOp->getOut(), val);
}

void EmulatePcodeOp::executeSegmentOp(void)

{
  SegmentOp *segdef = glb->userops.getSegmentOp(Address::getSpaceFromConst(currentOp->getIn(0)->getAddr())->getIndex());
  if (segdef == (SegmentOp *)0)
    throw LowlevelError("Segment operand missing definition");

  uintb in1 = getVarnodeValue(currentOp->getIn(1));
  uintb in2 = getVarnodeValue(currentOp->getIn(2));
  vector<uintb> bindlist;
  bindlist.push_back(in2);
  bindlist.push_back(in1);
  uintb res = segdef->execute(bindlist);
  setVarnodeValue(currentOp->getOut(), res);
}

void EmulatePcodeOp::executeCpoolRef(void)

{
  // Ignore references to constant pool
}

void EmulatePcodeOp::executeNew(void)

{
  // Ignore new operations
}

uintb EmulateSnippet::getLoadImageValue(AddrSpace *spc,uintb off,int4 sz) const

{
  LoadImage *loadimage = glb->loader;
  uintb res;

  loadimage->loadFill((uint1 *)&res,sizeof(uintb),Address(spc,off));

  if ((HOST_ENDIAN==1) != spc->isBigEndian())
    res = byte_swap(res,sizeof(uintb));
  if (spc->isBigEndian() && (sz < sizeof(uintb)))
    res >>= (sizeof(uintb)-sz)*8;
  else
    res &= calc_mask(sz);
  return res;
}

void EmulateSnippet::executeUnary(void)

{
  uintb in1 = getVarnodeValue(currentOp->getInput(0));
  uintb out = currentBehave->evaluateUnary(currentOp->getOutput()->size,
					   currentOp->getInput(0)->size,in1);
  setVarnodeValue(currentOp->getOutput()->offset, out);
}

void EmulateSnippet::executeBinary(void)

{
  uintb in1 = getVarnodeValue(currentOp->getInput(0));
  uintb in2 = getVarnodeValue(currentOp->getInput(1));
  uintb out = currentBehave->evaluateBinary(currentOp->getOutput()->size,
					    currentOp->getInput(0)->size,in1,in2);
  setVarnodeValue(currentOp->getOutput()->offset, out);
}

void EmulateSnippet::executeLoad(void)

{
  // op will be null, use current_op
  uintb off = getVarnodeValue(currentOp->getInput(1));
  AddrSpace *spc = Address::getSpaceFromConst(currentOp->getInput(0)->getAddr());
  off = AddrSpace::addressToByte(off,spc->getWordSize());
  int4 sz = currentOp->getOutput()->size;
  uintb res = getLoadImageValue(spc,off,sz);
  setVarnodeValue(currentOp->getOutput()->offset,res);
}

void EmulateSnippet::executeStore(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeBranch(void)

{
  VarnodeData *vn = currentOp->getInput(0);
  if (vn->space->getType() != IPTR_CONSTANT)
    throw LowlevelError("Tried to emulate absolute branch in snippet code");
  int4 rel = (int4)vn->offset;
  pos += rel;
  if ((pos < 0)||(pos>opList.size()))
    throw LowlevelError("Relative branch out of bounds in snippet code");
  if (pos == opList.size()) {
    emu_halted = true;
    return;
  }
  setCurrentOp(pos);
}

bool EmulateSnippet::executeCbranch(void)

{
  // op will be null, use current_op
  uintb cond = getVarnodeValue(currentOp->getInput(1));
  // We must take into account the booleanflip bit with pcode from the syntax tree
  return (cond != 0);
}

void EmulateSnippet::executeBranchind(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeCall(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeCallind(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeCallother(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeMultiequal(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeIndirect(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeSegmentOp(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeCpoolRef(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::executeNew(void)

{
  throw LowlevelError("Illegal p-code operation in snippet: "+ (string)get_opname(currentOp->getOpcode()));
}

void EmulateSnippet::fallthruOp(void)

{
  pos += 1;
  if (pos == opList.size()) {
    emu_halted = true;
    return;
  }
  setCurrentOp(pos);
}

EmulateSnippet::~EmulateSnippet(void)

{
  for(int4 i=0;i<opList.size();++i)
    delete opList[i];
  for(int4 i=0;i<varList.size();++i)
    delete varList[i];
}

/// \brief Provide the caller with an emitter for building the p-code snippet
///
/// Any p-code produced by the PcodeEmit, when triggered by the caller, becomes
/// part of the \e snippet that will get emulated by \b this. The caller should
/// free the PcodeEmit object immediately after use.
/// \param inst is the \e opcode to \e behavior map the emitter will use
/// \param uniqReserve is the starting offset within the \e unique address space for any temporary registers
/// \return the newly constructed emitter
PcodeEmit *EmulateSnippet::buildEmitter(const vector<OpBehavior *> &inst,uintb uniqReserve)

{
  return new PcodeEmitCache(opList,varList,inst,uniqReserve);
}

/// \brief Check for p-code that is deemed illegal for a \e snippet
///
/// This method facilitates enforcement of the formal rules for snippet code.
///   - Branches must use p-code relative addressing.
///   - Snippets can only read/write from temporary registers
///   - Snippets cannot use BRANCHIND, CALL, CALLIND, CALLOTHER, STORE, SEGMENTOP, CPOOLREF,
///              NEW, MULTIEQUAL, or INDIRECT
///
/// \return \b true if the current snippet is legal
bool EmulateSnippet::checkForLegalCode(void) const

{
  for(int4 i=0;i<opList.size();++i) {
    PcodeOpRaw *op = opList[i];
    VarnodeData *vn;
    OpCode opc = op->getOpcode();
    if (opc == CPUI_BRANCHIND || opc == CPUI_CALL || opc == CPUI_CALLIND || opc == CPUI_CALLOTHER ||
	opc == CPUI_STORE || opc == CPUI_SEGMENTOP || opc == CPUI_CPOOLREF ||
	opc == CPUI_NEW || opc == CPUI_MULTIEQUAL || opc == CPUI_INDIRECT)
      return false;
    if (opc == CPUI_BRANCH) {
      vn = op->getInput(0);
      if (vn->space->getType() != IPTR_CONSTANT)	// Only relative branching allowed
	return false;
    }
    vn = op->getOutput();
    if (vn != (VarnodeData *)0) {
      if (vn->space->getType() != IPTR_INTERNAL)
	return false;					// Can only write to temporaries
    }
    for(int4 j=0;j<op->numInput();++j) {
      vn = op->getInput(j);
      if (vn->space->getType() == IPTR_PROCESSOR)
	return false;					// Cannot read from normal registers
    }
  }
  return true;
}

/// \brief Retrieve the value of a Varnode from the current machine state
///
/// If the Varnode is a temporary registers, the storage offset is used to look up
/// the value from the machine state cache. If the Varnode represents a RAM location,
/// the value is pulled directly out of the load-image.
/// If the value does not exist, a "Read before write" exception is thrown.
/// \param vn is the Varnode to read
/// \return the retrieved value
uintb EmulateSnippet::getVarnodeValue(VarnodeData *vn) const

{
  AddrSpace *spc = vn->space;
  if (spc->getType() == IPTR_CONSTANT)
    return vn->offset;
  if (spc->getType() == IPTR_INTERNAL) {
    map<uintb,uintb>::const_iterator iter;
    iter = tempValues.find(vn->offset);
    if (iter != tempValues.end())
      return (*iter).second;	// We have seen this varnode before
    throw LowlevelError("Read before write in snippet emulation");
  }

  return getLoadImageValue(vn->space,vn->offset,vn->size);
}

/// \brief Retrieve a temporary register value directly
///
/// This allows the user to obtain the final value of the snippet calculation, without
/// having to have the Varnode object in hand.
/// \param offset is the offset of the temporary register to retrieve
/// \return the calculated value or 0 if the register was never written
uintb EmulateSnippet::getTempValue(uintb offset) const

{
  map<uintb,uintb>::const_iterator iter = tempValues.find(offset);
  if (iter == tempValues.end())
    return 0;
  return (*iter).second;
}

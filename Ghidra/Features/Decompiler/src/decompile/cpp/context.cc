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
#include "context.hh"
#include "slghsymbol.hh"
#include "translate.hh"

ParserContext::ParserContext(ContextCache *ccache)

{
  parsestate = 0;
  contcache = ccache;
  if (ccache != (ContextCache *)0) {
    contextsize = ccache->getDatabase()->getContextSize();
    context = new uintm[ contextsize ];
  }
  else {
    contextsize = 0;
    context = (uintm *)0;
  }
}

void ParserContext::initialize(int4 maxstate,int4 maxparam,AddrSpace *spc)

{
  const_space = spc;
  state.resize(maxstate);
  state[0].parent = (ConstructState *)0;
  for(int4 i=0;i<maxstate;++i)
    state[i].resolve.resize(maxparam);
  base_state = &state[0];
}

uintm ParserContext::getInstructionBytes(int4 bytestart,int4 size,uint4 off) const

{				// Get bytes from the instruction stream into a intm
				// (assuming big endian format)
  off += bytestart;
  if (off >=16)
    throw BadDataError("Instruction is using more than 16 bytes"); 
  const uint1 *ptr = buf + off;
  uintm res = 0;
  for(int4 i=0;i<size;++i) {
    res <<= 8;
    res |= ptr[i];
  }
  return res;
}

uintm ParserContext::getInstructionBits(int4 startbit,int4 size,uint4 off) const

{
  off += (startbit/8);
  if (off >= 16)
    throw BadDataError("Instruction is using more than 16 bytes");
  const uint1 *ptr = buf + off;
  startbit = startbit % 8;
  int4 bytesize = (startbit+size-1)/8 + 1;
  uintm res = 0;
  for(int4 i=0;i<bytesize;++i) {
    res <<= 8;
    res |= ptr[i];
  }
  res <<= 8*(sizeof(uintm)-bytesize)+startbit; // Move starting bit to highest position
  res >>= 8*sizeof(uintm)-size;	// Shift to bottom of intm
  return res;
}

uintm ParserContext::getContextBytes(int4 bytestart,int4 size) const

{				// Get bytes from context into a uintm
  int4 intstart = bytestart / sizeof(uintm);
  uintm res = context[ intstart ];
  int4 byteOffset = bytestart % sizeof(uintm);
  int4 unusedBytes = sizeof(uintm) - size;
  res <<= byteOffset*8;
  res >>= unusedBytes*8;
  int4 remaining = size - sizeof(uintm) + byteOffset;
  if ((remaining > 0)&&(++intstart < contextsize)) { // If we extend beyond boundary of a single uintm
    uintm res2 = context[ intstart ];
    unusedBytes = sizeof(uintm) - remaining;
    res2 >>= unusedBytes * 8;
    res |= res2;
  }
  return res;
}

uintm ParserContext::getContextBits(int4 startbit,int4 size) const

{
  int4 intstart = startbit / (8*sizeof(uintm));
  uintm res = context[ intstart ]; // Get intm containing highest bit
  int4 bitOffset = startbit % (8*sizeof(uintm));
  int4 unusedBits = 8*sizeof(uintm) - size;
  res <<= bitOffset;	// Shift startbit to highest position
  res >>= unusedBits;
  int4 remaining = size - 8*sizeof(uintm) + bitOffset;
  if ((remaining > 0) && (++intstart < contextsize)) {
    uintm res2 = context[ intstart ];
    unusedBits = 8*sizeof(uintm) - remaining;
    res2 >>= unusedBits;
    res |= res2;
  }
  return res;
}

void ParserContext::addCommit(TripleSymbol *sym,int4 num,uintm mask,bool flow,ConstructState *point)

{
  contextcommit.emplace_back();
  ContextSet &set(contextcommit.back());

  set.sym = sym;
  set.point = point;		// This is the current state
  set.num = num;
  set.mask = mask;
  set.value = context[num] & mask;
  set.flow = flow;
}

void ParserContext::applyCommits(void)

{
  if (contextcommit.empty()) return;
  ParserWalker walker(this);
  walker.baseState();

  vector<ContextSet>::iterator iter;

  for(iter=contextcommit.begin();iter!=contextcommit.end();++iter) {
    TripleSymbol *sym = (*iter).sym;
    Address commitaddr;
    if (sym->getType() == SleighSymbol::operand_symbol) {
      // The value for an OperandSymbol is probabably already
      // calculated, we just need to find the right
      // tree node of the state
      int4 i = ((OperandSymbol *)sym)->getIndex();
      FixedHandle &h((*iter).point->resolve[i]->hand);
      commitaddr = Address(h.space,h.offset_offset);
    }
    else {
      FixedHandle hand;
      sym->getFixedHandle(hand,walker);
      commitaddr = Address(hand.space,hand.offset_offset);
    }
    if (commitaddr.isConstant()) {
      // If the symbol handed to globalset was a computed value, the getFixedHandle calculation
      // will return a value in the constant space. If this is a case, we explicitly convert the
      // offset into the current address space
      uintb newoff = AddrSpace::addressToByte(commitaddr.getOffset(),addr.getSpace()->getWordSize());
      commitaddr = Address(addr.getSpace(),newoff);
    }

				// Commit context change
    if ((*iter).flow)		// The context flows
      contcache->setContext(commitaddr,(*iter).num,(*iter).mask,(*iter).value);
    else {  // Set the context so that is doesn't flow
      Address nextaddr = commitaddr + 1;
      if (nextaddr.getOffset() < commitaddr.getOffset())
	contcache->setContext(commitaddr,(*iter).num,(*iter).mask,(*iter).value);
      else
	contcache->setContext(commitaddr,nextaddr,(*iter).num,(*iter).mask,(*iter).value);
    }
  }
}

void ParserWalker::setOutOfBandState(Constructor *ct,int4 index,ConstructState *tempstate,const ParserWalker &otherwalker)

{ // Initialize walker for future calls into getInstructionBytes assuming -ct- is the current position in the walk
  const ConstructState *pt = otherwalker.point;
  int4 curdepth = otherwalker.depth;
  while(pt->ct != ct) {
    if (curdepth <= 0) return;
    curdepth -= 1;
    pt = pt->parent;
  }
  OperandSymbol *sym = ct->getOperand(index);
  int4 i = sym->getOffsetBase();
  // if i<0, i.e. the offset of the operand is constructor relative
  // its possible that the branch corresponding to the operand
  // has not been constructed yet. Context expressions are
  // evaluated BEFORE the constructors branches are created.
  // So we have to construct the offset explicitly.
  if (i<0)
    tempstate->offset = pt->offset + sym->getRelativeOffset();
  else
    tempstate->offset = pt->resolve[index]->offset;

  tempstate->ct = ct;
  tempstate->length = pt->length;
  point = tempstate;
  depth = 0;
  breadcrumb[0] = 0;
}

void ParserWalkerChange::calcCurrentLength(int4 length,int4 numopers)

{				// Calculate the length of the current constructor
				// state assuming all its operands are constructed
  length += point->offset;	// Convert relative length to absolute length
  for(int4 i=0;i<numopers;++i) {
    ConstructState *subpoint = point->resolve[i];
    int4 sublength = subpoint->length + subpoint->offset;
				// Since subpoint->offset is an absolute offset
				// (relative to beginning of instruction) sublength
    if (sublength > length)	// is absolute and must be compared to absolute length
      length = sublength;
  }
  point->length = length - point->offset; // Convert back to relative length
}


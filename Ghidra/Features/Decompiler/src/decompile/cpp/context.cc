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

namespace ghidra {

ConstructState::ConstructState(void)

{
  ct = (Constructor *)0;
  resolve = (ConstructState **)0;
  parent = (ConstructState *)0;
  length = 0;
  offset = 0;
}

/// The array holding pointers to child nodes is preallocated.
/// \param numOperands is maximum number of children this node can have
ConstructState::ConstructState(int4 numOperands)

{
  ct = (Constructor *)0;
  parent = (ConstructState *)0;
  length = 0;
  offset = 0;
  resolve = new ConstructState *[numOperands];
  for(int4 i=0;i<numOperands;++i)
    resolve[i] = (ConstructState *)0;
}

ConstructState::~ConstructState(void)

{
  if (resolve != (ConstructState **)0)
    delete [] resolve;
}

/// \param ccache is the cache to use for formal context changes
/// \param trans is the parent parser
ParserContext::ParserContext(ContextCache *ccache,Translate *trans)

{
  parsestate = uninitialized;
  contcache = ccache;
  translate = trans;
  if (ccache != (ContextCache *)0) {
    contextsize = ccache->getDatabase()->getContextSize();
    context = new uintm[ contextsize ];
  }
  else {
    contextsize = 0;
    context = (uintm *)0;
  }
}

ParserContext::~ParserContext(void)

{
  if (context != (uintm *)0)
    delete [] context;
  for(int4 i=0;i<state.size();++i)
    delete state[i];
}

/// \param spc is the address space used for constants
/// \param maxstate is the number of nodes to allocate (initially)
void ParserContext::initialize(AddrSpace *spc,int4 maxstate)

{
  const_space = spc;
  state.resize(maxstate);
  for(int4 i=0;i<maxstate;++i)
    state[i] = new ConstructState(MAX_OPERAND);
  base_state = state[maxstate-1];
}

const Address &ParserContext::getN2addr(void) const

{
  if (n2addr.isInvalid()) {
    if (translate == (Translate *)0 || parsestate == uninitialized)
      throw LowlevelError("inst_next2 not available in this context");
    int4 length = translate->instructionLength(naddr);
    n2addr = naddr + length;
  }
  return n2addr;
}

/// Get bytes from the instruction stream into a packed value assuming a big endian encoding.
/// \param bytestart is the number of bytes to skip
/// \param size is the number of bytes to pack
/// \param off is the number of bytes in the instruction already read
/// \return the packed bytes from the instruction
uintm ParserContext::getInstructionBytes(int4 bytestart,int4 size,uint4 off) const

{
  off += bytestart;
  if (off >= MAX_INSTRUCTION_LEN)
    throw BadDataError("Instruction is using more than " + to_string(MAX_INSTRUCTION_LEN) + " bytes");
  const uint1 *ptr = buf + off;
  uintm res = 0;
  for(int4 i=0;i<size;++i) {
    res <<= 8;
    res |= ptr[i];
  }
  return res;
}

/// Get bits from the instruction stream assuming big endian encoding.
/// \param startbit is the offset of the first bit (within the instruction stream)
/// \param size is the number of bits to grab
/// \param off is the number of bytes in the instruction already read
/// \return the requested range of bits (in the least significant positions and padded out with zero bits)
uintm ParserContext::getInstructionBits(int4 startbit,int4 size,uint4 off) const

{
  off += (startbit/8);
  if (off >= MAX_INSTRUCTION_LEN)
    throw BadDataError("Instruction is using more than " + to_string(MAX_INSTRUCTION_LEN) + " bytes");
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

/// \param bytestart is the offset of the first byte to grab
/// \param size is the number of bytes to grab
/// \return the context bytes in a packed value
uintm ParserContext::getContextBytes(int4 bytestart,int4 size) const

{
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

/// \param startbit is the offset of the first bit
/// \param size is the number of bits to return
/// \return the requested range of bits (in the least significant positions and padded out with zero bits)
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

/// \param sym is a symbol that resolves to the address where the setting takes effect
/// \param num is the index of the context word being affected
/// \param mask indicates the bits within the context word that are affected
/// \param flow is \b true if the context change \e flows forward from the point where it is set
/// \param point is the parse point where the change was made
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

/// This can be called in the middle of a parse to accommodate larger constructor trees.
/// \param amount is the number of additional nodes to add
void ParserContext::expandState(int4 amount)

{
  state.insert(state.begin(),amount,(ConstructState *)0);
  for(int4 i=0;i<amount;++i)
    state[i] = new ConstructState(MAX_OPERAND);

  alloc += amount;
}

/// \brief Initialize \b this from another walker assuming a given constructor and operand is the current position in the walk
///
/// The constructor tree state is simulated using only a single provided node.
/// This allows TokenField to behave as if it were just parsed so its getValue() will return the correct value.
/// \param ct is the given constructor
/// \param index is the index of the operand
/// \param tempstate is provided storage used to simulate the mid-walk tree node
/// \param otherwalker is the walker with the complete parse state
void ParserWalker::setOutOfBandState(Constructor *ct,int4 index,ConstructState *tempstate,const ParserWalker &otherwalker)

{
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

/// This assumes all the current nodes operands have been parsed into the tree.
/// \param length is the minimum length of the current constructor
/// \param numopers is the number of operands
void ParserWalkerChange::calcCurrentLength(int4 length,int4 numopers)

{
  length += point->offset;	// Convert relative length to absolute length
  for(int4 i=0;i<numopers;++i) {
    ConstructState *subpoint = point->resolve[i];
    int4 sublength = subpoint->length + subpoint->offset;
				// Since subpoint->offset is an absolutee (relative to beginning of instruction)
    if (sublength > length)	// sublength is absolute and must be compared to absolute length
      length = sublength;
  }
  point->length = length - point->offset; // Convert back to relative length
}

} // End namespace ghidra

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
#ifndef __CONTEXT_HH__
#define __CONTEXT_HH__

#include "globalcontext.hh"
#include "opcodes.hh"

namespace ghidra {

class Token {			// A multiple-byte sized chunk of pattern in a bitstream
  string name;
  int4 size;			// Number of bytes in token;
  int4 index;			// Index of this token, for resolving offsets
  bool bigendian;
public:
  Token(const string &nm,int4 sz,bool be,int4 ind) : name(nm) { size = sz; bigendian=be; index = ind; }
  int4 getSize(void) const { return size; }
  bool isBigEndian(void) const { return bigendian; }
  int4 getIndex(void) const { return index; }
  const string &getName(void) const { return name; }
};

struct FixedHandle {		// A handle that is fully resolved
  AddrSpace *space;
  uint4 size;
  AddrSpace *offset_space;	// Either null or where dynamic offset is stored
  uintb offset_offset;		// Either static offset or ptr offset
  uint4 offset_size;		// Size of pointer
  AddrSpace *temp_space;	// Consistent temporary location for value
  uintb temp_offset;
};

class Constructor;
struct ConstructState {
  Constructor *ct;
  FixedHandle hand;
  vector<ConstructState *> resolve;
  ConstructState *parent;
  int4 length;			// Length of this instantiation of the constructor
  uint4 offset;			// Absolute offset (from start of instruction)
};

class TripleSymbol;
struct ContextSet {		// Instructions for setting a global context value
  TripleSymbol *sym;		// Resolves to address where setting takes effect
  ConstructState *point;	// Point at which context set was made
  int4 num;			// Number of context word affected
  uintm mask;			// Bits within word affected
  uintm value;			// New setting for bits
  bool flow;			// Does the new context flow from its set point
};

class ParserWalker;		// Forward declaration
class ParserWalkerChange;
class Translate;

class ParserContext {
  friend class ParserWalker;
  friend class ParserWalkerChange;
public:
  enum {			// Possible states of the ParserContext
    uninitialized = 0,		// Instruction has not been parsed at all
    disassembly = 1,		// Instruction is parsed in preparation for disassembly
    pcode = 2			// Instruction is parsed in preparation for generating p-code
  };
private:
  Translate *translate;		// Instruction parser
  int4 parsestate;
  AddrSpace *const_space;
  uint1 buf[16];		// Buffer of bytes in the instruction stream
  uintm *context;		// Pointer to local context
  int4 contextsize;		// Number of entries in context array
  ContextCache *contcache;   // Interface for getting/setting context
  vector<ContextSet> contextcommit;
  Address addr;		// Address of start of instruction
  Address naddr;		// Address of next instruction
  mutable Address n2addr;	// Address of instruction after the next
  Address calladdr;		// For injections, this is the address of the call being overridden
  vector<ConstructState> state; // Current resolved instruction
  ConstructState *base_state;
  int4 alloc;			// Number of ConstructState's allocated
  int4 delayslot;		// delayslot depth
public:
  ParserContext(ContextCache *ccache,Translate *trans);
  ~ParserContext(void) { if (context != (uintm *)0) delete [] context; }
  uint1 *getBuffer(void) { return buf; }
  void initialize(int4 maxstate,int4 maxparam,AddrSpace *spc);
  int4 getParserState(void) const { return parsestate; }
  void setParserState(int4 st) { parsestate = st; }
  void deallocateState(ParserWalkerChange &walker);
  void allocateOperand(int4 i,ParserWalkerChange &walker);
  void setAddr(const Address &ad) { addr = ad; n2addr = Address(); }
  void setNaddr(const Address &ad) { naddr = ad; }
  void setCalladdr(const Address &ad) { calladdr = ad; }
  void addCommit(TripleSymbol *sym,int4 num,uintm mask,bool flow,ConstructState *point);
  void clearCommits(void) { contextcommit.clear(); }
  void applyCommits(void);
  const Address &getAddr(void) const { return addr; }
  const Address &getNaddr(void) const { return naddr; }
  const Address &getN2addr(void) const;
  const Address &getDestAddr(void) const { return calladdr; }
  const Address &getRefAddr(void) const { return calladdr; }
  AddrSpace *getCurSpace(void) const { return addr.getSpace(); }
  AddrSpace *getConstSpace(void) const { return const_space; }
  uintm getInstructionBytes(int4 byteoff,int4 numbytes,uint4 off) const;
  uintm getContextBytes(int4 byteoff,int4 numbytes) const;
  uintm getInstructionBits(int4 startbit,int4 size,uint4 off) const;
  uintm getContextBits(int4 startbit,int4 size) const;
  void setContextWord(int4 i,uintm val,uintm mask) { context[i] = (context[i]&(~mask))|(mask&val); }
  void loadContext(void) { contcache->getContext(addr,context); }
  int4 getLength(void) const { return base_state->length; }
  void setDelaySlot(int4 val) { delayslot = val; }
  int4 getDelaySlot(void) const { return delayslot; }
};
  
class ParserWalker {		// A class for walking the ParserContext
  const ParserContext *const_context;
  const ParserContext *cross_context;
protected:
  ConstructState *point;	// The current node being visited
  int4 depth;			// Depth of the current node
  int4 breadcrumb[32];	// Path of operands from root
public:
  ParserWalker(const ParserContext *c) { const_context = c; cross_context = (const ParserContext *)0; }
  ParserWalker(const ParserContext *c,const ParserContext *cross) { const_context = c; cross_context = cross; }
  const ParserContext *getParserContext(void) const { return const_context; }
  void baseState(void) { point = const_context->base_state; depth=0; breadcrumb[0] = 0; }
  void setOutOfBandState(Constructor *ct,int4 index,ConstructState *tempstate,const ParserWalker &otherwalker);
  bool isState(void) const { return (point != (ConstructState *)0); }
  void pushOperand(int4 i) { breadcrumb[depth++] = i+1; point = point->resolve[i]; breadcrumb[depth] = 0; }
  void popOperand(void) { point = point->parent; depth-= 1; }
  uint4 getOffset(int4 i) const { if (i<0) return point->offset; 
    ConstructState *op=point->resolve[i]; return op->offset + op->length; }
  Constructor *getConstructor(void) const { return point->ct; }
  int4 getOperand(void) const { return breadcrumb[depth]; }
  FixedHandle &getParentHandle(void) { return point->hand; }
  const FixedHandle &getFixedHandle(int4 i) const { return point->resolve[i]->hand; }
  AddrSpace *getCurSpace(void) const { return const_context->getCurSpace(); }
  AddrSpace *getConstSpace(void) const { return const_context->getConstSpace(); }
  const Address &getAddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getAddr(); } return const_context->getAddr(); }
  const Address &getNaddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getNaddr();} return const_context->getNaddr(); }
  const Address &getN2addr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getN2addr();} return const_context->getN2addr(); }
  const Address &getRefAddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getRefAddr();} return const_context->getRefAddr(); }
  const Address &getDestAddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getDestAddr();} return const_context->getDestAddr(); }
  int4 getLength(void) const { return const_context->getLength(); }
  uintm getInstructionBytes(int4 byteoff,int4 numbytes) const {
    return const_context->getInstructionBytes(byteoff,numbytes,point->offset); }
  uintm getContextBytes(int4 byteoff,int4 numbytes) const {
    return const_context->getContextBytes(byteoff,numbytes); }
  uintm getInstructionBits(int4 startbit,int4 size) const {
    return const_context->getInstructionBits(startbit,size,point->offset); }
  uintm getContextBits(int4 startbit,int4 size) const {
    return const_context->getContextBits(startbit,size); }
};

class ParserWalkerChange : public ParserWalker { // Extension to walker that allows for on the fly modifications to tree
  friend class ParserContext;
  ParserContext *context;
public:
  ParserWalkerChange(ParserContext *c) : ParserWalker(c) { context = c; }
  ParserContext *getParserContext(void) { return context; }
  ConstructState *getPoint(void) { return point; }
  void setOffset(uint4 off) { point->offset = off; }
  void setConstructor(Constructor *c) { point->ct = c; }
  void setCurrentLength(int4 len) { point->length = len; }
  void calcCurrentLength(int4 length,int4 numopers);
};

struct SleighError : public LowlevelError {
  SleighError(const string &s) : LowlevelError(s) {}
};

inline void ParserContext::deallocateState(ParserWalkerChange &walker) {
  alloc = 1;
  walker.context=this;
  walker.baseState();
}

inline void ParserContext::allocateOperand(int4 i,ParserWalkerChange &walker) {
  ConstructState *opstate = &state[alloc++];
  opstate->parent = walker.point;
  opstate->ct = (Constructor *)0;
  walker.point->resolve[i] = opstate;
  walker.breadcrumb[walker.depth++] += 1;
  walker.point = opstate;
  walker.breadcrumb[walker.depth] = 0;
}

} // End namespace ghidra
#endif

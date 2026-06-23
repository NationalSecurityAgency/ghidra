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
/// \file context.hh
/// \brief Objects for describing the context around the parsing of an instruction by the SLEIGH engine
#ifndef __CONTEXT_HH__
#define __CONTEXT_HH__

#include "globalcontext.hh"
#include "opcodes.hh"

namespace ghidra {

/// \brief A multiple-byte sized chunk of pattern in the instruction byte stream
class Token {
  string name;			///< Name of the token
  int4 size;			///< Number of bytes in token
  int4 index;			///< Index of \b this token, for resolving offsets
  bool bigendian;		///< Set to \b true if encodings within \b this token are big endian
public:
  Token(const string &nm,int4 sz,bool be,int4 ind) : name(nm) { size = sz; bigendian=be; index = ind; }	///< Constructor
  int4 getSize(void) const { return size; }		///< Get the size in bytes
  bool isBigEndian(void) const { return bigendian; }	///< Return \b true if encodings within \b this are big endian
  int4 getIndex(void) const { return index; }		///< Get the index associated with \b this token
  const string &getName(void) const { return name; }	///< Get the name of the token
};

/// \brief A resolved version of (or pointer to) a SLEIGH defined Varnode
///
/// For a static Varnode, this is the triple  (address space, offset, size) for the Varnode.
/// For a dynamic Varnode, this also encodes the pointer Varnode containing the dynamic offset
/// and a temporary storage location for the dereferenced value.
struct FixedHandle {
  AddrSpace *space;		///< The address space of the Varnode
  uint4 size;			///< Number of bytes in the Varnode
  AddrSpace *offset_space;	///< Null \e or the space where the dynamic offset is stored
  uintb offset_offset;		///< The offset for the static Varnode \e or the offset for the pointer
  uint4 offset_size;		///< Size of pointer
  AddrSpace *temp_space;	///< Address space for temporary location for value
  uintb temp_offset;		///< Offset of the temporary location
};

class Constructor;

/// \brief A node in a tree of subconstructors
///
/// This knows its position in the tree (parent node, child nodes) and the underlying SLEIGH constructor that was matched.
/// Child nodes correspond to the operands for the specific constructor.
struct ConstructState {
  Constructor *ct;		///< The matched Constructor
  FixedHandle hand;		///< Resolved Varnode associated with the Constructor
  ConstructState **resolve;	///< An array of pointers to child nodes
  ConstructState *parent;	///< Pointer to parent node
  int4 length;			///< Length of this instantiation of the constructor
  uint4 offset;			///< Absolute offset (from start of instruction)
  ConstructState(void);		///< Construct a node with no children
  ConstructState(int4 numOperands);	///< Construct a node with given number of possible children
  ~ConstructState(void);	///< Destructor
};

class TripleSymbol;

/// \brief Command for globally setting a formal SLEIGH context value
struct ContextSet {
  TripleSymbol *sym;		///< Symbol resolving to address where setting takes effect
  ConstructState *point;	///< Point at which context set was made
  int4 num;			///< Index of the specific context word affected
  uintm mask;			///< Bits within word affected
  uintm value;			///< New setting for bits
  bool flow;			///< Does the new context flow from its set point
};

class ParserWalker;		// Forward declaration
class ParserWalkerChange;
class Translate;

/// \brief Context maintained while parsing a single instruction
///
/// This contains:
///   - the bytes encoding the instruction
///   - the tree structure of the SLEIGH Constructors encountered while parsing the instruction
///   - any formal named SLEIGH context values referenced by the instruction
class ParserContext {
  friend class ParserWalker;
  friend class ParserWalkerChange;
public:
  static constexpr int4 MAX_DEPTH = 32;			///< Maximum subconstructor depth in a single instruction
  static constexpr int4 MAX_OPERAND = 20;		///< Maximum operands for a single constructor
  static constexpr int4 MAX_INSTRUCTION_LEN = 16;	///< Maximum number of bytes in a single instruction
  static constexpr int4 INITIAL_STATE_NUM = 64;		///< Recommended number of initial states
  static constexpr int4 STATE_GROWTH = 64;		///< Number of states to add for each expansion
  /// \brief Possible states of the ParserContext
  enum parse_state {
    uninitialized = 0,		///< Instruction has not been parsed at all
    disassembly = 1,		///< Instruction is parsed in preparation for disassembly
    pcode = 2			///< Instruction is parsed in preparation for generating p-code
  };
private:
  Translate *translate;			///< The parent instruction parser
  parse_state parsestate;		///< Overall state of the parse
  AddrSpace *const_space;		///< Address space for constants
  uint1 buf[MAX_INSTRUCTION_LEN];	///< Buffer of bytes in the instruction stream
  uintm *context;			///< Pointer to local context
  int4 contextsize;			///< Number of entries in local context array
  ContextCache *contcache;   		///< Interface for getting/setting context
  vector<ContextSet> contextcommit;	///< Changes to SLEIGH context slated by this instruction
  Address addr;				///< Address of start of instruction
  Address naddr;			///< Address of next instruction
  mutable Address n2addr;		///< Address of instruction after the next
  Address calladdr;			///< For injections, this is the address of the call being overridden
  vector<ConstructState *> state; 	///< Available nodes for the constructor tree
  ConstructState *base_state;		///< Root node of the constructor tree
  int4 alloc;				///< Number of unallocated ConstructState nodes remaining
  int4 delayslot;			///< delayslot depth
public:
  ParserContext(ContextCache *ccache,Translate *trans);	///< Constructor
  ~ParserContext(void);					///< Destructor
  uint1 *getBuffer(void) { return buf; }		///< Get bytes in the stream at the point this instruction is encoded
  void initialize(AddrSpace *spc,int4 maxstate = INITIAL_STATE_NUM);	///< Preallocate nodes for constructor trees
  parse_state getParserState(void) const { return parsestate; }		///< Get the overall state of the parse
  void setParserState(parse_state st) { parsestate = st; }		///< Update the overall parse state
  void deallocateState(ParserWalkerChange &walker);			///< Clear any existing constructor tree
  void allocateOperand(int4 i,ParserWalkerChange &walker);		///< Allocate a new child node in the constructor tree
  void setAddr(const Address &ad) { addr = ad; n2addr = Address(); }	///< Set the starting address of the instruction
  void setNaddr(const Address &ad) { naddr = ad; }			///< Set the ending address of the instruction
  void setCalladdr(const Address &ad) { calladdr = ad; }		///< Set the address of the call being overridden
  void addCommit(TripleSymbol *sym,int4 num,uintm mask,bool flow,ConstructState *point);	///< Add a formal SLEIGH context change command
  void clearCommits(void) { contextcommit.clear(); }			///< Clear all context commits
  void applyCommits(void);						///< Apply any pending commits to the context cache
  const Address &getAddr(void) const { return addr; }			///< Get the starting address of the current instruction
  const Address &getNaddr(void) const { return naddr; }			///< Get the address of the next instruction
  const Address &getN2addr(void) const;					///< Get the address of the instruction after the next
  const Address &getDestAddr(void) const { return calladdr; }		///< Get the destination address (inst_dest) for the overriden call
  const Address &getRefAddr(void) const { return calladdr; }		///< Get the reference address (inst_ref) for the p-code snippet
  AddrSpace *getCurSpace(void) const { return addr.getSpace(); }	///< Get the address space of the current instruction
  AddrSpace *getConstSpace(void) const { return const_space; }		///< Get the address space for constants
  uintm getInstructionBytes(int4 byteoff,int4 numbytes,uint4 off) const;	///< Get the specified instruction bytes
  uintm getContextBytes(int4 byteoff,int4 numbytes) const;		///< Get bytes from the local context
  uintm getInstructionBits(int4 startbit,int4 size,uint4 off) const;	///< Get the specific range of bits from the instruction stream
  uintm getContextBits(int4 startbit,int4 size) const;			///< Get the specific range of bits from the local context
  void setContextWord(int4 i,uintm val,uintm mask) { context[i] = (context[i]&(~mask))|(mask&val); }	///< Modify a context word, using given mask and value
  void loadContext(void) { contcache->getContext(addr,context); }	///< Pull context words associated with the starting address into the local array
  int4 getLength(void) const { return base_state->length; }		///< Get the length of the current instruction
  void setDelaySlot(int4 val) { delayslot = val; }			///< Set (the number of instruction bytes) in the delay slot
  int4 getDelaySlot(void) const { return delayslot; }			///< Get the number of instruction bytes in the delay slot
  void expandState(int4 amount);					///< Expand the number of available nodes for the constructor tree
};

/// \brief A class for walking the constructor tree (ParserContext)
class ParserWalker {
private:
  const ParserContext *const_context;		///< Context for the main instruction parse
  const ParserContext *cross_context;		///< Context for an additional instruction parse needed to resolve a \e crossbuild
protected:
  ConstructState *point;			///< The current node being visited
  int4 depth;					///< Depth of the current node
  int4 breadcrumb[ParserContext::MAX_DEPTH];	///< Path of operands from root
public:
  ParserWalker(const ParserContext *c) { const_context = c; cross_context = (const ParserContext *)0; }	///< Constructor
  ParserWalker(const ParserContext *c,const ParserContext *cross) { const_context = c; cross_context = cross; }	///< Constructor for crossbuilds
  const ParserContext *getParserContext(void) const { return const_context; }	///< Get the current context
  void baseState(void) { point = const_context->base_state; depth=0; breadcrumb[0] = 0; }	///< Initialize for a new walk
  void setOutOfBandState(Constructor *ct,int4 index,ConstructState *tempstate,const ParserWalker &otherwalker);
  bool isState(void) const { return (point != (ConstructState *)0); }	///< Return \b true if there are more nodes to traverse
  void pushOperand(int4 i);						///< Make the indicated child (operand) the current node
  void popOperand(void) { point = point->parent; depth-= 1; }		///< Make the parent constructor the current node

  uint4 getOffset(int4 i) const { if (i<0) return point->offset; 
    ConstructState *op=point->resolve[i]; return op->offset + op->length; }	///< Get the byte offset of the indicated operand within the instruction stream
  Constructor *getConstructor(void) const { return point->ct; }		///< Get the current constructor
  int4 getOperand(void) const { return breadcrumb[depth]; }		///< Get the operand index of the next constructor in the walk
  FixedHandle &getParentHandle(void) { return point->hand; }		///< Get the resolved value associated with the current constructor
  const FixedHandle &getFixedHandle(int4 i) const { return point->resolve[i]->hand; }	///< Get the resolved value associated with the indicated child operand
  AddrSpace *getCurSpace(void) const { return const_context->getCurSpace(); }	///< Get the address space associated with the instruction stream
  AddrSpace *getConstSpace(void) const { return const_context->getConstSpace(); }	///< Get the constant address space

  /// \brief Get the starting address of the instruction
  const Address &getAddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getAddr(); } return const_context->getAddr(); }
  /// \brief Get the address of the next instruction
  const Address &getNaddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getNaddr();} return const_context->getNaddr(); }
  /// \brief Get the address of the instruction after next
  const Address &getN2addr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getN2addr();} return const_context->getN2addr(); }
  /// \brief Get the reference address (inst_ref) for the p-code snippet
  const Address &getRefAddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getRefAddr();} return const_context->getRefAddr(); }
  /// \brief Get the destination address (inst_dest) for the overridden call
  const Address &getDestAddr(void) const { if (cross_context != (const ParserContext *)0) { return cross_context->getDestAddr();} return const_context->getDestAddr(); }

  int4 getLength(void) const { return const_context->getLength(); }	///< Get the length of the instruction in bytes

  /// \brief Get packed instruction bytes associated with the current constructor
  ///
  /// \param byteoff is an offset from the starting point associated with the constructor
  /// \param numbytes is the number of bytes to pack
  /// \return the packed instruction bytes in big endian encoding
  uintm getInstructionBytes(int4 byteoff,int4 numbytes) const {
    return const_context->getInstructionBytes(byteoff,numbytes,point->offset); }

  /// \brief Get packed context bytes from the local context
  ///
  /// \param byteoff is the offset of the first byte to grab
  /// \param numbytes is the number of bytes to grab
  /// \return the context bytes in a packed value
  uintm getContextBytes(int4 byteoff,int4 numbytes) const {
    return const_context->getContextBytes(byteoff,numbytes); }

  /// \brief Get bits from the instruction stream associated with the current constructor
  ///
  /// \param startbit is the offset of the first bit (relative to the starting point associated with the constructor)
  /// \param size is the number of bits to grab
  /// \return the requested range of bits (in the least significant positions and padded out with zero bits)
  uintm getInstructionBits(int4 startbit,int4 size) const {
    return const_context->getInstructionBits(startbit,size,point->offset); }

  /// \brief Get a range of bits from the local context
  ///
  /// \param startbit is the offset of the first bit
  /// \param size is the number of bits to return
  /// \return the requested range of bits (in the least significant positions and padded out with zero bits)
 uintm getContextBits(int4 startbit,int4 size) const {
    return const_context->getContextBits(startbit,size); }
};

/// \brief A walker extension that allows for on the fly modifications to the constructor tree
///
/// This is used to build the constructor tree as the instruction is parsed (Sleigh::resolve)
class ParserWalkerChange : public ParserWalker {
  friend class ParserContext;
  ParserContext *context;		///< The (currently active) context
public:
  ParserWalkerChange(ParserContext *c) : ParserWalker(c) { context = c; }	///< Constructor
  ParserContext *getParserContext(void) { return context; }	///< Get the currently active context
  ConstructState *getPoint(void) { return point; }		///< Get the current
  void setOffset(uint4 off) { point->offset = off; }		///< Get the current node in the constructor tree
  void setConstructor(Constructor *c) { point->ct = c; }	///< Set the underlying Constructor for the current node
  void setCurrentLength(int4 len) { point->length = len; }	///< Set the length associated with the current constructor
  void calcCurrentLength(int4 length,int4 numopers);		///< Calculate the length of the current constructor
};

/// \brief Exception thrown by the SLEIGH engine
struct SleighError : public LowlevelError {
  SleighError(const string &s) : LowlevelError(s) {}	///< Constructor
};

/// The tree is reset to a single root node and the walker is prepared for a new parse
/// \param walker is the walker to initialize for a traversal
inline void ParserContext::deallocateState(ParserWalkerChange &walker) {
  alloc = state.size() - 2;	// Number of allocations left
  walker.context=this;
  walker.baseState();
}

/// The next available node is linked to the current active node in the walker at the given operand index.
/// The child node becomes the new active node for the walker. The underlying constructor is not yet assigned.
/// \param i is the operand index of the new child
/// \param walker is the walker for the parse
inline void ParserContext::allocateOperand(int4 i,ParserWalkerChange &walker) {
  if (i >= MAX_OPERAND)
    throw LowlevelError("SLEIGH parser out of state space");
  if (alloc < 0)
    expandState(STATE_GROWTH);
  ConstructState *opstate = state[alloc--];
  opstate->parent = walker.point;
  opstate->ct = (Constructor *)0;
  walker.point->resolve[i] = opstate;
  if (walker.depth > MAX_DEPTH-2)
    throw LowlevelError("SLEIGH exceeded maximum parse depth");
  walker.breadcrumb[walker.depth++] += 1;
  walker.point = opstate;
  walker.breadcrumb[walker.depth] = 0;
}

/// \param i is the index of child/operand
inline void ParserWalker::pushOperand(int4 i) {
  if (depth > ParserContext::MAX_DEPTH-2)
    throw LowlevelError("SLEIGH exceeded maximum parse depth");
  breadcrumb[depth++] = i+1;
  point = point->resolve[i];
  breadcrumb[depth] = 0;
}

} // End namespace ghidra
#endif

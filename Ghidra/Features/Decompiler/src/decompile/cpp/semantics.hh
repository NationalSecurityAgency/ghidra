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
/// \file semantics.hh
/// \brief Classes describing p-code operations as parsed from a SLEIGH specification

#ifndef __SEMANTICS_HH__
#define __SEMANTICS_HH__

#include "context.hh"
#include "slaformat.hh"

namespace ghidra {

// We remap these opcodes for internal use during pcode generation

/// \brief The \b build directive op-code, overlayed on CPUI_MULTIEQUAL
#define BUILD CPUI_MULTIEQUAL

/// \brief The \b delayslot directive op-code, overlayed on CPUI_INDIRECT
#define DELAY_SLOT CPUI_INDIRECT

/// \brief The \b crossbuild directive op-code, overlayed on CPUI_PTRSUB
#define CROSSBUILD CPUI_PTRSUB

/// \brief The \b macro directive op-code, overlayed on CPUI_CAST
#define MACROBUILD CPUI_CAST

/// \brief The SLEIGH label op-code, overlayed on CPUI_PTRADD
#define LABELBUILD CPUI_PTRADD

class Translate;		// Forward declaration
class HandleTpl;		// Forward declaration

/// \brief A constant value encountered during SLEIGH parsing
///
/// Any offset, size, address space, or literal constant encountered during parsing that ultimately resolves
/// to a constant value when disassembling or generating p-code for a specific instruction.  The object holds details about
/// how to calculate the final constant from the SLEIGH context for the instruction.
class ConstTpl {
public:
  /// Types of constant values encountered during SLEIGH parsing.
  enum const_type {
    real=0,			///< A literal constant
    handle=1,			///< Placeholder for a value passed back by a sub-constructor
    j_start=2,			///< Address offset for the start of the current instruction
    j_next=3,			///< Address offset for the start of the next instruction
    j_next2=4,			///< Address offset of the instruction immediately after the next instruction
    j_curspace=5,		///< Address space containing the current instruction
    j_curspace_size=6,		///< Number of bytes encoding the address of the current instruction
    spaceid=7,			///< An address space (encoded as a constant)
    j_relative=8,		///< A relative p-code branch offset
    j_flowref=9,		///< Address offset of any call reference at site of p-code injection
    j_flowref_size=10,		///< Number of bytes encoding address of call reference
    j_flowdest=11,		///< Address offset of call destination being injected
    j_flowdest_size=12		///< Number of bytes encoding address of call destination
  };
  /// For a \b handle (a value calculated in a sub-constructor), we can sub-select which part of the value to use.
  enum v_field {
    v_space=0,			///< The address space associated with the \b handle
    v_offset=1,			///< The offset associated with the \b handle
    v_size=2,			///< Number of bytes in the \b handle
    v_offset_plus=3		///< The offset associated with the \b handle plus an additional constant offset
  };
private:
  const_type type;		///< The type of constant
  union {
    AddrSpace *spaceid;		///< Id referring to a registered address space
    int4 handle_index;		///< For a \b handle, the index of the specific sub-constructor passing back the value
  } value;			///< Specialized values a ConstTpl can represent
  uintb value_real;		///< An immediate constant value or other constant offset a ConstTpl represents
  v_field select;		///< Assuming ConstTpl is a \b handle, the part of the \b handle to use as constant
public:
  ConstTpl(void) { type = real; value_real = 0; }	///< Construct a zero constant
  ConstTpl(const ConstTpl &op2) {
    type=op2.type; value=op2.value; value_real=op2.value_real; select=op2.select; }	///< Copy constructor
  ConstTpl(const_type tp,uintb val);					///< Constructor for real constants or relative offsets
  ConstTpl(const_type tp);						///< Constructor for special constants from context
  ConstTpl(AddrSpace *sid);						///< Constructor for a constant representing an address space
  ConstTpl(const_type tp,int4 ht,v_field vf);				///< Constructor for a \b handle constant
  ConstTpl(const_type tp,int4 ht,v_field vf,uintb plus);		///< Constructor for a \b handle offset plus a constant
  bool isConstSpace(void) const;					///< Return \b true if \b this represents the \e constant address space
  bool isUniqueSpace(void) const;					///< Return \b true if \b this represents the \e unique address space
  bool operator==(const ConstTpl &op2) const;				///< Compare two constants for equality
  bool operator<(const ConstTpl &op2) const;				///< Order two constants by type then value
  uintb getReal(void) const { return value_real; }			///< Get the literal constant value associated with \b this
  AddrSpace *getSpace(void) const { return value.spaceid; }		///< Get the address space \b this is encoding
  int4 getHandleIndex(void) const { return value.handle_index; }	///< Get the index of the sub-constructor computing \b this
  const_type getType(void) const { return type; }			///< Get the constant type
  v_field getSelect(void) const { return select; }			///< Get the type of \b handle piece \b this is encoding
  uintb fix(const ParserWalker &walker) const;				///< Get the final constant value of \b this in context
  AddrSpace *fixSpace(const ParserWalker &walker) const;		///< Get the final address space \b this represents in context
  void transfer(const vector<HandleTpl *> &params);			///< Copy a \b handle into \b this based on the \b handle_index
  bool isZero(void) const { return ((type==real)&&(value_real==0)); }	///< Return \b true if \b this is a literal zero
  void changeHandleIndex(const vector<int4> &handmap);			///< Remap the \b handle index for \b this
  void fillinSpace(FixedHandle &hand,const ParserWalker &walker) const;	///< Fill in the address space of a FixedHandle, based on \b this
  void fillinOffset(FixedHandle &hand,const ParserWalker &walker) const;	///< Fill in the offset of a FixedHandle, based on \b this
  void encode(Encoder &encoder) const;					///< Encode \b this SLEIGH constant to an output stream
  void decode(Decoder &decoder);					///< Decode \b this SLEIGH constant from a stream
};

/// \brief A (partially) resolved Varnode in a SLEIGH specification
///
/// Variable symbols in SLEIGH are represented using \b this object.  It encodes the
/// address space, offset, and size associated with the variable.  In the context of
/// a specific instruction, \b this is translated into a Varnode object.
class VarnodeTpl {
  friend class OpTpl;
  friend class HandleTpl;
  ConstTpl space;		///< Address space associated with \b this variable
  ConstTpl offset;		///< Offset into the address space
  ConstTpl size;		///< Number of bytes in \b this variable
  bool unnamed_flag;		///< Set to \b true if \b this is an unnamed temporary register
public:
  VarnodeTpl(int4 hand,bool zerosize);						///< Construct a handle
  VarnodeTpl(void) : space(), offset(), size() { unnamed_flag=false; }		///< Construct an uninitialized VarnodeTpl
  VarnodeTpl(const ConstTpl &sp,const ConstTpl &off,const ConstTpl &sz);	///< Construct directly from ConstTpl
  VarnodeTpl(const VarnodeTpl &vn);						///< Copy constructor
  const ConstTpl &getSpace(void) const { return space; }			///< Get the address space
  const ConstTpl &getOffset(void) const { return offset; }			///< Get the offset
  const ConstTpl &getSize(void) const { return size; }				///< Get the size
  bool isDynamic(const ParserWalker &walker) const;		///< Return \b true if \b this is a dynamically computed \b handle
  int4 transfer(const vector<HandleTpl *> &params);		///< Copy a computed HandleTpl into \b this from the given array
  bool isZeroSize(void) const { return size.isZero(); }		///< Return \b true if \b this currently has a size of zero
  bool operator==(const VarnodeTpl &op2) const;			///< Test if two VarnodeTpl are equal
  bool operator!=(const VarnodeTpl &op2) const;			///< Test if two VarnodeTpl are not equal
  bool operator<(const VarnodeTpl &op2) const;			///< Order two VarnodeTpl
  void setOffset(uintb constVal) { offset = ConstTpl(ConstTpl::real,constVal); }		///< Set the offset piece to a literal constant
  void setRelative(uintb constVal) { offset = ConstTpl(ConstTpl::j_relative,constVal); }	///< Set the offset piece to a relative branch offset
  void setSize(const ConstTpl &sz ) { size = sz; }		///< Set the size piece
  bool isUnnamed(void) const { return unnamed_flag; }		///< Return \b true if \b this is an unnamed temporary register
  void setUnnamed(bool val) { unnamed_flag = val; }		///< Mark \b this as an unnamed temporary register
  bool isLocalTemp(void) const;					///< Return \b true if \b this is a temporary register
  bool isRelative(void) const { return (offset.getType() == ConstTpl::j_relative); }	///< Return \b true if \b this is a relative branch offset
  void changeHandleIndex(const vector<int4> &handmap);		///< Remap any handle indices for \b this
  bool adjustTruncation(int4 sz,bool isbigendian);		///< Adjust truncation given final size of the Varnode
  void encode(Encoder &encoder) const;				///< Encode \b this VarnodeTpl to an output stream
  void decode(Decoder &decoder);				///< Decode \b this VarnodeTpl from a stream
};

/// \brief An \e exported value of a sub-constructor in a SLEIGH specification
///
/// For an output value that is equivalent to a VarnodeTpl, \b space, \b ptroffset, and \b size correspond to
/// Varnode::space, Varnode::offset, and Varnode::size.  But a HandleTpl can also represent a dynamic value loaded
/// at run-time.  In this case, the final value is stored in a temporary register specified by
/// \b temp_space, \b temp_offset (and \b size), and the pointer used to load the final value is specified by
/// \b ptrspace, \b ptroffset, and \b ptrsize.
class HandleTpl {
  ConstTpl space;		///< The address space of the value
  ConstTpl size;		///< The size of the value
  ConstTpl ptrspace;		///< (If dynamic) the address space of the pointer
  ConstTpl ptroffset;		///< If dynamic, the offset of the pointer, or the offset of the value otherwise
  ConstTpl ptrsize;		///< (If dynamic) the size of the pointer
  ConstTpl temp_space;		///< (If dynamic) the address space of the temporary register holding the final value
  ConstTpl temp_offset;		///< (If dynamic) the offset of the temporary register
public:
  HandleTpl(void) {}				///< Construct an uninitialized HandleTpl
  HandleTpl(const VarnodeTpl *vn);		///< Construct HandleTpl representing the given VarnodeTpl
  HandleTpl(const ConstTpl &spc,const ConstTpl &sz,const VarnodeTpl *vn,
	     AddrSpace *t_space,uintb t_offset);				///< Construct a dynamic HandleTpl
  const ConstTpl &getSpace(void) const { return space; }			///< Get the address space
  const ConstTpl &getPtrSpace(void) const { return ptrspace; }			///< Get the pointer address space
  const ConstTpl &getPtrOffset(void) const { return ptroffset; }		///< Get the offset (or the pointer offset)
  const ConstTpl &getPtrSize(void) const { return ptrsize; }			///< Get the pointer size
  const ConstTpl &getSize(void) const { return size; }				///< Get the size
  const ConstTpl &getTempSpace(void) const { return temp_space; }		///< Get the temporary register address space
  const ConstTpl &getTempOffset(void) const { return temp_offset; }		///< Get the temporary register offset
  void setSize(const ConstTpl &sz) { size = sz; }				///< Set the size
  void setPtrSize(const ConstTpl &sz) { ptrsize=sz; }				///< Set the pointer size
  void setPtrOffset(uintb val) { ptroffset = ConstTpl(ConstTpl::real,val); }	///< Set the pointer offset
  void setTempOffset(uintb val) { temp_offset = ConstTpl(ConstTpl::real,val); }	///< Set the temporary register offset
  void fix(FixedHandle &hand,const ParserWalker &walker) const;			///< Calculate final fixed values for \b this
  void changeHandleIndex(const vector<int4> &handmap);				///< Remap any handle indices for \b this
  void encode(Encoder &encoder) const;						///< Encode \b this HandleTpl to an output stream
  void decode(Decoder &decoder);						///< Decode \b this HandleTpl from a stream
};

/// \brief A p-code operation in a SLEIGH specification
///
/// Each input and output to the operation is a VarnodeTpl.
class OpTpl {
  VarnodeTpl *output;			///< The output variable of the operation, or NULL
  OpCode opc;				///< The code describing the operation
  vector<VarnodeTpl *> input;		///< Inputs to the operation
public:
  OpTpl(void) : output(nullptr) {}				///< Construct an uninitialized OpTpl
  OpTpl(OpCode oc) : output(nullptr) { opc = oc; }		///< Construct an OpTpl with not inputs or output
  ~OpTpl(void);							///< Destructor
  VarnodeTpl *getOut(void) const { return output; }		///< Get the output VarnodeTpl (or NULL)
  int4 numInput(void) const { return input.size(); }		///< Return the number of inputs to \b this
  VarnodeTpl *getIn(int4 i) const { return input[i]; }		///< Get the i-th input VarnodeTpl
  OpCode getOpcode(void) const { return opc; }			///< Get the operation code
  bool isZeroSize(void) const;					///< Return \b true if any input or output has zero size
  void setOpcode(OpCode o) { opc = o; }				///< Set the operation code
  void setOutput(VarnodeTpl *vt) { output = vt; }		///< Set the output VarnodeTpl
  void clearOutput(void) { delete output; output = (VarnodeTpl *)0; }	///< Remove the existing output VarnodeTpl
  void addInput(VarnodeTpl *vt) { input.push_back(vt); }	///< Add an input VarnodeTpl
  void setInput(VarnodeTpl *vt,int4 slot) { input[slot] = vt; }	///< Set the VarnodeTpl for a specific input slot
  void removeInput(int4 index);					///< Remove the indicated input
  void changeHandleIndex(const vector<int4> &handmap);		///< Remap any handle indices for inputs and outputs to \b this
  void encode(Encoder &encoder) const;				///< Encode \b this OpTpl to an output stream
  void decode(Decoder &decoder);				///< Decode \b this OpTpl from a stream
};

/// \brief P-code semantics for Constructor in a SLEIGH specification
///
/// This encodes a sequence of OpTpl representing the semantic action of the Constructor, and
/// if present, the HandleTpl representing the final \e exported value.
class ConstructTpl {
  friend class SleighCompile;
protected:
  uint4 delayslot;		///< (Minimum) number of bytes in the delay slot
  uint4 numlabels;		///< Number of label templates
  vector<OpTpl *> vec;		///< Sequence of operations performed by the Constructor
  HandleTpl *result;		///< Final \e exported value (or NULL)
  void setOpvec(vector<OpTpl *> &opvec) { vec = opvec; }	///< Set the sequence of OpTpl
  void setNumLabels(uint4 val) { numlabels = val; }		///< Set the number of labels
public:
  ConstructTpl(void) { delayslot=0; numlabels=0; result = (HandleTpl *)0; }	///< Construct an empty ConstructTpl
  ~ConstructTpl(void);						///< Destructor
  uint4 delaySlot(void) const { return delayslot; }		///< Return the number of bytes in the delay slot
  uint4 numLabels(void) const { return numlabels; }		///< Get the number of labels
  const vector<OpTpl *> &getOpvec(void) const { return vec; }	///< Get the sequence of p-code operations
  HandleTpl *getResult(void) const { return result; }		///< Get the \e export result
  bool addOp(OpTpl *ot);					///< Add an operation to the end of the sequence
  bool addOpList(const vector<OpTpl *> &oplist);		///< Add a list of operations to the end of the sequence
  void setResult(HandleTpl *t) { result = t; }			///< Set the \e export HandleTpl for \b this
  int4 fillinBuild(vector<int4> &check,AddrSpace *const_space); ///< Make sure there is a \b build directive for all sub-constructors
  bool buildOnly(void) const;					///< Check if all operations are \b build directives
  void changeHandleIndex(const vector<int4> &handmap);		///< Remap handle indices for all operations
  void setInput(VarnodeTpl *vn,int4 index,int4 slot);		///< Set the VarnodeTpl input for a particular OpTpl in the sequence
  void setOutput(VarnodeTpl *vn,int4 index);			///< Set the VarnodeTpl output for a particular OpTpl in the sequence
  void deleteOps(const vector<int4> &indices);			///< Delete the given set of operations
  void encode(Encoder &encoder,int4 sectionid) const;		///< Encode details of \b this semantic sequence to an output stream
  int4 decode(Decoder &decoder);				///< Decode a semantic sequence from a stream
};

class PcodeEmit;   // Forward declaration for emitter

/// \brief An abstract, SLEIGH specific, p-code generator
///
/// This is a base class for output, filtering, or otherwise processing sequences of p-code for a single
/// instruction decoded by the SLEIGH engine.  The ConstructTpl of the root constructor for the instruction is fed to the
/// build() method.  Each normal p-code operation then makes it to the dump() method in sequence for processing.
/// Hook points are provided to recurse into different instructions/constructors via \b build, \b delayslot, and
/// \b crossbuild directives.
class PcodeBuilder {
  uint4 labelbase;			///< Starting label index for this builder
  uint4 labelcount;			///< Current number of defined labels
protected:
  ParserWalker *walker;			///< Current instruction context

  /// \brief Output/build the given p-code operation
  ///
  /// This is the main hook point for different p-code generation strategies.  It is called once, in sequence, for
  /// each p-code operation generated for a specific instruction.  Directives and labels have had the opportunity to
  /// be expanded or filtered by other methods.
  /// \param op is the p-code operation to process
  virtual void dump( OpTpl *op )=0;
public:
  PcodeBuilder(uint4 lbcnt) { labelbase=labelcount=lbcnt; }	///< Construct with a starting label index
  virtual ~PcodeBuilder(void) {}				///< Destructor

  uint4 getLabelBase(void) const { return labelbase; }		///< Get the starting label index for \b this builder
  ParserWalker *getCurrentWalker() const { return walker; }	///< Get the current instruction context
  void build(ConstructTpl *construct,int4 secnum);		///< Build the semantics for the given constructor

  /// \brief Execute or filter a \b build directive in sequence
  ///
  /// Any recursion through \b build directives into ConstructTpl for sub-constructors happens here.
  /// \param bld is the \b build directive, which encodes the particular sub-construction
  /// \param secnum is the current section number of the constructor
  virtual void appendBuild(OpTpl *bld,int4 secnum)=0;

  /// \brief Execute or filter a \b delayslot directive in sequence
  ///
  /// Any recursion through \b delayslot directives into new instructions happens here.
  /// \param op is the \b delayslot directive, which encodes the number of bytes in the particular delay slot.
  virtual void delaySlot(OpTpl *op)=0;

  /// \brief Process or filter a label in sequence
  ///
  /// The builder has the opportunity to record exactly where in sequence the given label occurs.
  /// \param op is the OpTpl encoding the label index
  virtual void setLabel(OpTpl *op)=0;

  /// \brief Process or filter a \b crossbuild directive in sequence
  ///
  /// Any recursion through \b crossbuild directives into new instructions and sections happens here.
  /// \param bld is the \b crossbuild directive
  /// \param secnum is the current section number being processed
  virtual void appendCrossBuild(OpTpl *bld,int4 secnum)=0;
};

} // End namespace ghidra
#endif

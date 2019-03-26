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
/// \file emulateutil.hh
/// \brief (Lightweight) emulation interface for executing PcodeOp objects within a syntax tree
/// or for executing snippets defined with PcodeOpRaw objects
#ifndef __CPUI_EMUTREE__
#define __CPUI_EMUTREE__

#include "emulate.hh"
#include "op.hh"

/// \brief Emulation based on (existing) PcodeOps and Varnodes.
///
/// This is still an abstract class.  It does most of the work of emulating
/// p-code using PcodeOp and Varnode objects (as opposed to PcodeOpRaw and VarnodeData).
/// This class leaves implementation of control-flow to the derived class. This class
/// implements most operations by going through new virtual methods:
///    - getVarnodeValue()
///    - setVarnodeValue()
///    - getLoadImageValue()
///
/// The default executeLoad() implementation pulls values from the underlying LoadImage
/// object. The following p-code ops are provided \e NULL implementations, as some tasks
/// don't need hard emulation of them:
///   - STORE
///   - CPOOLREF
///   - NEW
class EmulatePcodeOp : public Emulate {
protected:
  Architecture *glb;		///< The underlying Architecture for the program being emulated
  PcodeOp *currentOp;		///< Current PcodeOp being executed
  PcodeOp *lastOp;		///< Last PcodeOp that was executed

  /// \brief Pull a value from the load-image given a specific address
  ///
  /// A contiguous chunk of memory is pulled from the load-image and returned as a
  /// constant value, respecting the endianess of the address space. The default implementation
  /// of this method pulls the value directly from the LoadImage object.
  /// \param spc is the address space to pull the value from
  /// \param offset is the starting address offset (from within the space) to pull the value from
  /// \param sz is the number of bytes to pull from memory
  /// \return indicated bytes arranged as a constant value
  virtual uintb getLoadImageValue(AddrSpace *spc,uintb offset,int4 sz) const;
  virtual void executeUnary(void);
  virtual void executeBinary(void);
  virtual void executeLoad(void);
  virtual void executeStore(void);
//  virtual void executeBranch(void)=0;
  virtual bool executeCbranch(void);
//  virtual void executeBranchind(void)=0;
//  virtual void executeCall(void)=0;
//  virtual void executeCallind(void)=0;
//  virtual void executeCallother(void)=0;
  virtual void executeMultiequal(void);
  virtual void executeIndirect(void);
  virtual void executeSegmentOp(void);
  virtual void executeCpoolRef(void);
  virtual void executeNew(void);
//  virtual void fallthruOp(void)=0;
public:
  EmulatePcodeOp(Architecture *g);		///< Constructor

  /// \brief Establish the current PcodeOp being emulated
  ///
  /// \param op is the PcodeOp that will next be executed via executeCurrentOp()
  void setCurrentOp(PcodeOp *op) { currentOp = op; currentBehave = op->getOpcode()->getBehavior(); }
  virtual Address getExecuteAddress(void) const { return currentOp->getAddr(); }

  /// \brief Given a specific Varnode, set the given value for it in the current machine state
  ///
  /// This is the placeholder internal operation for setting a Varnode value during emulation.
  /// The value is \e stored using the Varnode as the \e address and \e storage \e size.
  /// \param vn is the specific Varnode
  /// \param val is the constant value to store
  virtual void setVarnodeValue(Varnode *vn,uintb val)=0;

  /// \brief Given a specific Varnode, retrieve the current value for it from the machine state
  ///
  /// This is the placeholder internal operation for obtaining a Varnode value during emulation.
  /// The value is \e loaded using the Varnode as the \e address and \e storage \e size.
  /// \param vn is the specific Varnode
  /// \return the corresponding value from the machine state
  virtual uintb getVarnodeValue(Varnode *vn) const=0;
};

/// \brief Emulate a \e snippet of PcodeOps out of a functional context
///
/// Emulation is performed on a short sequence (\b snippet) of PcodeOpRaw objects.
/// Control-flow emulation is limited to this snippet; BRANCH and CBRANCH operations
/// can happen using p-code relative branching.  Executing BRANCHIND, CALL, CALLIND,
/// CALLOTHER, STORE, MULTIEQUAL, INDIRECT, SEGMENTOP, CPOOLOP, and NEW
/// ops is treated as illegal and an exception is thrown.
/// Expressions can only use temporary registers or read from the LoadImage.
///
/// The set of PcodeOpRaw objects in the snippet is provided by emitting p-code to the object
/// returned by buildEmitter().  This is designed for one-time initialization of this
/// class, which can be repeatedly used by calling resetMemory() between executions.
class EmulateSnippet : public Emulate {
  Architecture *glb;			///< The underlying Architecture for the program being emulated
  vector<PcodeOpRaw *> opList;		///< Sequence of p-code ops to be executed
  vector<VarnodeData *> varList;	///< Varnodes allocated for ops
  map<uintb,uintb> tempValues;		///< Values stored in temporary registers
  PcodeOpRaw *currentOp;		///< Current p-code op being executed
  int4 pos;				///< Index of current p-code op being executed

  /// \brief Pull a value from the load-image given a specific address
  ///
  /// A contiguous chunk of memory is pulled from the load-image and returned as a
  /// constant value, respecting the endianess of the address space.
  /// \param spc is the address space to pull the value from
  /// \param offset is the starting address offset (from within the space) to pull the value from
  /// \param sz is the number of bytes to pull from memory
  /// \return indicated bytes arranged as a constant value
  uintb getLoadImageValue(AddrSpace *spc,uintb offset,int4 sz) const;
  virtual void executeUnary(void);
  virtual void executeBinary(void);
  virtual void executeLoad(void);
  virtual void executeStore(void);
  virtual void executeBranch(void);
  virtual bool executeCbranch(void);
  virtual void executeBranchind(void);
  virtual void executeCall(void);
  virtual void executeCallind(void);
  virtual void executeCallother(void);
  virtual void executeMultiequal(void);
  virtual void executeIndirect(void);
  virtual void executeSegmentOp(void);
  virtual void executeCpoolRef(void);
  virtual void executeNew(void);
  virtual void fallthruOp(void);
public:
  EmulateSnippet(Architecture *g) { glb = g; pos = 0; currentOp = (PcodeOpRaw *)0; }	///< Constructor
  virtual ~EmulateSnippet(void);							///< Destructor
  virtual void setExecuteAddress(const Address &addr) { setCurrentOp(0); }
  virtual Address getExecuteAddress(void) const { return currentOp->getAddr(); }
  Architecture *getArch(void) const { return glb; }				///< Get the underlying Architecture

  /// \brief Reset the emulation snippet
  ///
  /// Reset the memory state, and set the first p-code op as current.
  void resetMemory(void) { tempValues.clear(); setCurrentOp(0); emu_halted = false; }

  PcodeEmit *buildEmitter(const vector<OpBehavior *> &inst,uintb uniqReserve);
  bool checkForLegalCode(void) const;

  /// \brief Set the current executing p-code op by index
  ///
  /// The i-th p-code op in the snippet sequence is set as the currently executing op.
  /// \param i is the index
  void setCurrentOp(int4 i) { pos = i; currentOp = opList[i]; currentBehave = currentOp->getBehavior(); }

  /// \brief Set a temporary register value in the machine state
  ///
  /// The temporary Varnode's storage offset is used as key into the machine state map.
  /// \param offset is the temporary storage offset
  /// \param val is the value to put into the machine state
  void setVarnodeValue(uintb offset,uintb val) { tempValues[offset] = val; }
  uintb getVarnodeValue(VarnodeData *vn) const;
  uintb getTempValue(uintb offset) const;
};

#endif

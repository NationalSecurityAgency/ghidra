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
/// \file emulate.hh
/// \brief Classes for emulating p-code

#ifndef __EMULATE_HH__
#define __EMULATE_HH__

#include "memstate.hh"
#include "translate.hh"

namespace ghidra {

class Emulate;			// Forward declaration

/// \brief A collection of breakpoints for the emulator
///
/// A BreakTable keeps track of an arbitrary number of breakpoints for an emulator.
/// Breakpoints are either associated with a particular user-defined pcode op,
/// or with a specific machine address (as in a standard debugger). Through the BreakTable
/// object, an emulator can invoke breakpoints through the two methods
///  - doPcodeOpBreak()
///  - doAddressBreak()
///
/// depending on the type of breakpoint they currently want to invoke
class BreakTable {
public:
  virtual ~BreakTable(void) {};

  /// \brief Associate a particular emulator with breakpoints in this table
  ///
  /// Breakpoints may need access to the context in which they are invoked. This
  /// routine provides the context for all breakpoints in the table.
  /// \param emu is the Emulate context
  virtual void setEmulate(Emulate *emu)=0;

  /// \brief Invoke any breakpoints associated with this particular pcodeop
  ///
  /// Within the table, the first breakpoint which is designed to work with this particular
  /// kind of pcode operation is invoked.  If there was a breakpoint and it was designed
  /// to \e replace the action of the pcode op, then \b true is returned.
  /// \param curop is the instance of a pcode op to test for breakpoints
  /// \return \b true if the action of the pcode op is performed by the breakpoint
  virtual bool doPcodeOpBreak(PcodeOpRaw *curop)=0;

  /// \brief Invoke any breakpoints associated with this machine address
  ///
  /// Within the table, the first breakpoint which is designed to work with at this address
  /// is invoked.  If there was a breakpoint, and if it was designed to \e replace
  /// the action of the machine instruction, then \b true is returned.
  /// \param addr is address to test for breakpoints
  /// \return \b true if the machine instruction has been replaced by a breakpoint
  virtual bool doAddressBreak(const Address &addr)=0;
};

/// \brief A breakpoint object
///
/// This is a base class for breakpoint objects in an emulator.  The breakpoints are implemented
/// as callback method, which is overridden for the particular behavior needed by the emulator.
/// Each derived class must override either
///   - pcodeCallback()
///   - addressCallback()
///
/// depending on whether the breakpoint is tailored for a particular pcode op or for
/// a machine address.
class BreakCallBack {
protected:
  Emulate *emulate;		///< The emulator currently associated with this breakpoint
public:
  BreakCallBack(void);		///< Generic breakpoint constructor
  virtual ~BreakCallBack(void) {}
  virtual bool pcodeCallback(PcodeOpRaw *op); ///< Call back method for pcode based breakpoints
  virtual bool addressCallback(const Address &addr); ///< Call back method for address based breakpoints
  void setEmulate(Emulate *emu); ///< Associate a particular emulator with this breakpoint
};

/// The base breakpoint needs no initialization parameters, the setEmulate() method must be
/// called before the breakpoint can be invoked
inline BreakCallBack::BreakCallBack(void)

{
  emulate = (Emulate *)0;
}

/// This routine is invoked during emulation, if this breakpoint has somehow been associated with
/// this kind of pcode op.  The callback can perform any operation on the emulator context it wants.
/// It then returns \b true if these actions are intended to replace the action of the pcode op itself.
/// Or it returns \b false if the pcode op should still have its normal effect on the emulator context.
/// \param op is the particular pcode operation where the break occurs.
/// \return \b true if the normal pcode op action should not occur
inline bool BreakCallBack::pcodeCallback(PcodeOpRaw *op)

{
  return true;
}

/// This routine is invoked during emulation, if this breakpoint has somehow been associated with
/// this address.  The callback can perform any operation on the emulator context it wants. It then
/// returns \b true if these actions are intended to replace the action of the \b entire machine
/// instruction at this address. Or it returns \b false if the machine instruction should still be
/// executed normally.
/// \param addr is the address where the break has occurred
/// \return \b true if the machine instruction should not be executed
inline bool BreakCallBack::addressCallback(const Address &addr)

{
  return true;
}

/// Breakpoints can be associated with one emulator at a time.
/// \param emu is the emulator to associate this breakpoint with
inline void BreakCallBack::setEmulate(Emulate *emu)

{
  emulate = emu;
}

/// \brief A basic instantiation of a breakpoint table
///
/// This object allows breakpoints to registered in the table via either
///   - registerPcodeCallback()  or
///   = registerAddressCallback()
///
/// Breakpoints are stored in map containers, and the core BreakTable methods
/// are implemented to search in these containers
class BreakTableCallBack : public BreakTable {
  Emulate *emulate;		///< The emulator associated with this table
  Translate *trans;		///< The translator 
  map<Address,BreakCallBack *> addresscallback;	///< a container of pcode based breakpoints
  map<uintb,BreakCallBack *> pcodecallback; ///< a container of addressed based breakpoints
public:
  BreakTableCallBack(Translate *t); ///< Basic breaktable constructor
  void registerPcodeCallback(const string &nm,BreakCallBack *func); ///< Register a pcode based breakpoint
  void registerAddressCallback(const Address &addr,BreakCallBack *func); ///< Register an address based breakpoint
  virtual void setEmulate(Emulate *emu); ///< Associate an emulator with all breakpoints in the table
  virtual bool doPcodeOpBreak(PcodeOpRaw *curop); ///< Invoke any breakpoints for the given pcode op
  virtual bool doAddressBreak(const Address &addr); ///< Invoke any breakpoints for the given address
};

/// The break table needs a translator object so user-defined pcode ops can be registered against
/// by name.
/// \param t is the translator object
inline BreakTableCallBack::BreakTableCallBack(Translate *t)

{
  emulate = (Emulate *)0;
  trans = t;
}

/// \brief A pcode-based emulator interface.
///
/// The interface expects that the underlying emulation engine operates on individual pcode
/// operations as its atomic operation.  The interface allows execution stepping through
/// individual pcode operations. The interface allows
/// querying of the \e current pcode op, the current machine address, and the rest of the
/// machine state.
class Emulate {
protected:
  bool emu_halted;		///< Set to \b true if the emulator is halted
  OpBehavior *currentBehave;	///< Behavior of the next op to execute
  virtual void executeUnary(void)=0; ///< Execute a unary arithmetic/logical operation
  virtual void executeBinary(void)=0; ///< Execute a binary arithmetic/logical operation
  virtual void executeLoad(void)=0; ///< Standard behavior for a p-code LOAD
  virtual void executeStore(void)=0; ///< Standard behavior for a p-code STORE

  /// \brief Standard behavior for a BRANCH
  ///
  /// This routine performs a standard p-code BRANCH operation on the memory state.
  /// This same routine is used for CBRANCH operations if the condition
  /// has evaluated to \b true.
  virtual void executeBranch(void)=0;

  /// \brief Check if the conditional of a CBRANCH is \b true
  ///
  /// This routine only checks if the condition for a p-code CBRANCH is true.
  /// It does \e not perform the actual branch.
  /// \return the boolean state indicated by the condition
  virtual bool executeCbranch(void)=0;
  virtual void executeBranchind(void)=0; ///< Standard behavior for a BRANCHIND
  virtual void executeCall(void)=0; ///< Standard behavior for a p-code CALL
  virtual void executeCallind(void)=0; ///< Standard behavior for a CALLIND
  virtual void executeCallother(void)=0; ///< Standard behavior for a user-defined p-code op
  virtual void executeMultiequal(void)=0; ///< Standard behavior for a MULTIEQUAL (phi-node)
  virtual void executeIndirect(void)=0;	///< Standard behavior for an INDIRECT op
  virtual void executeSegmentOp(void)=0; ///< Behavior for a SEGMENTOP
  virtual void executeCpoolRef(void)=0; ///< Standard behavior for a CPOOLREF (constant pool reference) op
  virtual void executeNew(void)=0; ///< Standard behavior for (low-level) NEW op
  virtual void fallthruOp(void)=0; ///< Standard p-code fall-thru semantics
public:
  Emulate(void) { emu_halted = true; currentBehave = (OpBehavior *)0; }	///< generic emulator constructor
  virtual ~Emulate(void) {}
  void setHalt(bool val);	///< Set the \e halt state of the emulator
  bool getHalt(void) const;	///< Get the \e halt state of the emulator
  virtual void setExecuteAddress(const Address &addr)=0; ///< Set the address of the next instruction to emulate
  virtual Address getExecuteAddress(void) const=0; ///< Get the address of the current instruction being executed
  void executeCurrentOp(void); ///< Do a single pcode op step
};

/// Applications and breakpoints can use this method and its companion getHalt() to
/// terminate and restart the main emulator loop as needed. The emulator itself makes no use
/// of this routine or the associated state variable \b emu_halted.
/// \param val is what the halt state of the emulator should be set to
inline void Emulate::setHalt(bool val)

{
  emu_halted = val;
}

/// Applications and breakpoints can use this method and its companion setHalt() to
/// terminate and restart the main emulator loop as needed.  The emulator itself makes no use
/// of this routine or the associated state variable \b emu_halted.
/// \return \b true if the emulator is in a "halted" state.
inline bool Emulate::getHalt(void) const

{
  return emu_halted;
}

/// \brief An abstract Emulate class using a MemoryState object as the backing machine state
///
/// Most p-code operations are implemented using the MemoryState to fetch and store
/// values.  Control-flow is implemented partially in that setExecuteAddress() is called
/// to indicate which instruction is being executed. The derived class must provide
///   - fallthruOp()
///   - setExecuteAddress()
///   - getExecuteAddress()
///
/// The following p-code operations are stubbed out and will throw an exception:
/// CALLOTHER, MULTIEQUAL, INDIRECT, CPOOLREF, SEGMENTOP, and NEW.
/// Of course the derived class can override these.

class EmulateMemory : public Emulate {
protected:
  MemoryState *memstate;	///< The memory state of the emulator
  PcodeOpRaw *currentOp;	///< Current op to execute
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
public:
  /// Construct given a memory state
  EmulateMemory(MemoryState *mem) { memstate = mem; currentOp = (PcodeOpRaw *)0; }
  MemoryState *getMemoryState(void) const; ///< Get the emulator's memory state
};

/// \return the memory state object which this emulator uses
inline MemoryState *EmulateMemory::getMemoryState(void) const

{
  return memstate;
}

/// \brief P-code emitter that dumps its raw Varnodes and PcodeOps to an in memory cache
///
/// This is used for emulation when full Varnode and PcodeOp objects aren't needed
class PcodeEmitCache : public PcodeEmit {
  vector<PcodeOpRaw *> &opcache;	///< The cache of current p-code ops
  vector<VarnodeData *> &varcache;	///< The cache of current varnodes
  const vector<OpBehavior *> &inst;	///< Array of behaviors for translating OpCode
  uintm uniq;				///< Starting offset for defining temporaries in \e unique space
  VarnodeData *createVarnode(const VarnodeData *var);	///< Clone and cache a raw VarnodeData
public:
  PcodeEmitCache(vector<PcodeOpRaw *> &ocache,vector<VarnodeData *> &vcache,
		 const vector<OpBehavior *> &in,uintb uniqReserve);	///< Constructor
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize);
};

/// \brief A SLEIGH based implementation of the Emulate interface
///
/// This implementation uses a Translate object to translate machine instructions into
/// pcode and caches pcode ops for later use by the emulator.  The pcode is cached as soon
/// as the execution address is set, either explicitly, or via branches and fallthrus.  There
/// are additional methods for inspecting the pcode ops in the current instruction as a sequence.
class EmulatePcodeCache : public EmulateMemory {
  Translate *trans;		///< The SLEIGH translator
  vector<PcodeOpRaw *> opcache;	///< The cache of current p-code ops
  vector<VarnodeData *> varcache;	///< The cache of current varnodes
  vector<OpBehavior *> inst;	///< Map from OpCode to OpBehavior
  BreakTable *breaktable;	///< The table of breakpoints
  Address current_address;	///< Address of current instruction being executed
  bool instruction_start;	///< \b true if next pcode op is start of instruction
  int4 current_op;		///< Index of current pcode op within machine instruction
  int4 instruction_length;	///< Length of current instruction in bytes
  void clearCache(void);	///< Clear the p-code cache
  void createInstruction(const Address &addr); ///< Cache pcode for instruction at given address
  void establishOp(void);
protected:
  virtual void fallthruOp(void); ///< Execute fallthru semantics for the pcode cache
  virtual void executeBranch(void); ///< Execute branch (including relative branches)
  virtual void executeCallother(void); ///< Execute breakpoint for this user-defined op
public:
  EmulatePcodeCache(Translate *t,MemoryState *s,BreakTable *b);	///< Pcode cache emulator constructor
  ~EmulatePcodeCache(void);
  bool isInstructionStart(void) const; ///< Return \b true if we are at an instruction start
  int4 numCurrentOps(void) const; ///< Return number of pcode ops in translation of current instruction
  int4 getCurrentOpIndex(void) const; ///< Get the index of current pcode op within current instruction
  PcodeOpRaw *getOpByIndex(int4 i) const; ///< Get pcode op in current instruction translation by index
  virtual void setExecuteAddress(const Address &addr); ///< Set current execution address
  virtual Address getExecuteAddress(void) const; ///< Get current execution address
  void executeInstruction(void); ///< Execute (the rest of) a single machine instruction
};

/// Since the emulator can single step through individual pcode operations, the machine state
/// may be halted in the \e middle of a single machine instruction, unlike conventional debuggers.
/// This routine can be used to determine if execution is actually at the beginning of a machine
/// instruction.
/// \return \b true if the next pcode operation is at the start of the instruction translation
inline bool EmulatePcodeCache::isInstructionStart(void) const

{
  return instruction_start;
}

/// A typical machine instruction translates into a sequence of pcode ops.
/// \return the number of ops in the sequence
inline int4 EmulatePcodeCache::numCurrentOps(void) const

{
  return opcache.size();
}

/// This routine can be used to determine where, within the sequence of ops in the translation
/// of the entire machine instruction, the currently executing op is.
/// \return the index of the current (next) pcode op.
inline int4 EmulatePcodeCache::getCurrentOpIndex(void) const

{
  return current_op;
}

/// This routine can be used to examine ops other than the currently executing op in the
/// machine instruction's translation sequence.
/// \param i is the desired op index
/// \return the pcode op at the indicated index
inline PcodeOpRaw *EmulatePcodeCache::getOpByIndex(int4 i) const

{
  return opcache[i];
}

/// \return the currently executing machine address
inline Address EmulatePcodeCache::getExecuteAddress(void) const

{
  return current_address;
}

/** \page sleighAPIemulate The SLEIGH Emulator
    
  \section emu_overview Overview
  
  \b SLEIGH provides a framework for emulating the processors which have a specification written
   for them.  The key classes in this framework are:

  \b Key \b Classes
    - \ref MemoryState
    - \ref MemoryBank
    - \ref BreakTable
    - \ref BreakCallBack
    - \ref Emulate
    - \ref EmulatePcodeCache

  The MemoryState object holds the representation of registers and memory during emulation.  It
  understands the address spaces defined in the \b SLEIGH specification and how data is encoded
  in these spaces.  It also knows any register names defined by the specification, so these
  can be used to set or query the state of these registers naturally.

  The emulation framework can be tailored to a particular environment by creating \b breakpoint
  objects, which derive off the BreakCallBack interface.  These can be used to create callbacks
  during emulation that have full access to the memory state and the emulator, so any action
  can be accomplished.  The breakpoint callbacks can be designed to either augment or replace
  the instruction at a particular address, or the callback can be used to implement the action
  of a user-defined pcode op.  The BreakCallBack objects are managed by the BreakTable object,
  which takes care of invoking the callback at the appropriate time.

  The Emulate object serves as a basic execution engine.  Its main method is
  Emulate::executeCurrentOp() which executes a single pcode operation on the memory state.
  Methods exist for querying and setting the current execution address and examining the pcode
  op being executed.

  The main implementation of the Emulate interface is the EmulatePcodeCache object.  It uses
  SLEIGH to translate machine instructions as they are executed.  The currently executing instruction
  is translated into a cached sequence of pcode operations.  Additional methods allow this entire
  sequence to be inspected, and there is another stepping function which allows the emulator
  to be stepped through an entire machine instruction at a time.  The single pcode stepping methods
  are of course still available and the two methods can be used together without conflict.

  \section emu_membuild Building a Memory State

  Assuming the SLEIGH Translate object and the LoadImage object have already been built
  (see \ref sleighAPIbasic), the only required step left before instantiating an emulator
  is to create a MemoryState object.  The MemoryState object can be instantiated simply by
  passing the constructor the Translate object, but before it will work properly, you need
  to register individual MemoryBank objects with it, for each address space that might
  get used by the emulator.

  A MemoryBank is a representation of data stored in a single address space
  There are some choices for the type of MemoryBank associated with an address space.
  A MemoryImage is a read-only memory bank that gets its data from a LoadImage.  In order
  to make this writeable, or to create a writeable memory bank which starts with its bytes
  initialized to zero, you can use a MemoryHashOverlay or a MemoryPageOverlay.

  A MemoryHashOverlay overlays some other memory bank, such as a MemoryImage.  If you read
  from a location that hasn't been written to directly before, you get the data in the underlying
  memory bank.  But if you write to this overlay, the value is stored in a hash table, and
  subsequent reads will return this value.  Internally, the hashtable stores values in a \e preferred
  wordsize only on aligned addresses, but this is irrelevant to the interface. Unaligned requests
  are split up and handled transparently.

  A MemoryPageOverlay overlays another memory bank as well.  But it implements writes to the bank
  by caching memory \e pages.  Any write creates an aligned page to hold the new data.  The class
  takes care of loading and filling in pages as needed.

  Here is an example of instantiating a MemoryState and registering memory banks for a
  \e ram space which is initialized with the load image. The \e ram space is implemented
  with the MemoryPageOverlay, and the \e register space and the \e temporary space are implemented
  using the MemoryHashOverlay.

  \code
    void setupMemoryState(Translate &trans,LoadImage &loader) {
      // Set up memory state object
      MemoryImage loadmemory(trans.getDefaultCodeSpace(),8,4096,&loader);
      MemoryPageOverlay ramstate(trans.getDefaultCodeSpace(),8,4096,&loadmemory);
      MemoryHashOverlay registerstate(trans.getSpaceByName("register"),8,4096,4096,(MemoryBank *)0);
      MemoryHashOverlay tmpstate(trans.getUniqueSpace(),8,4096,4096,(MemoryBank *)0);

      MemoryState memstate(&trans);	// Instantiate the memory state object
      memstate.setMemoryBank(&ramstate);
      memstate.setMemoryBank(&registerstate);
      memstate.setMemoryBank(&tmpstate);
   }
  \endcode

  All the memory bank constructors need a preferred wordsize, which is most relevant to the hashtable
  implementation, and a page size, which is most relevant to the page implementation.  The hash
  overlays need an additional initializer specifying how big the hashtable should be.  The
  null pointers passed in, in place of a real memory bank, indicate that the memory bank is initialized
  with all zeroes. Once the memory banks are instantiated, they are registered with the memory state
  via the MemoryState::setMemoryBank() method.

  \section emu_breakpoints Breakpoints

  In order to provide behavior within the emulator beyond just what the core instruction emulation
  provides, the framework supports \b breakpoint classes.  A breakpoint is created by deriving a
  class from the BreakCallBack class and overriding either BreakCallBack::addressCallback() or
  BreakCallBack::pcodeCallback().  Here is an example of a breakpoint that implements a
  standard C library \e puts call an the x86 architecture.  When the breakpoint is invoked,
  a call to \e puts has just been made, so the stack pointer is pointing to the return address
  and the next 4 bytes on the stack are a pointer to the string being passed in.

  \code
    class PutsCallBack : public BreakCallBack {
    public:
      virtual bool addressCallback(const Address &addr);
    };

    bool PutsCallBack::addressCallback(const Address &addr)

    {
      MemoryState *mem = emulate->getMemoryState();
      uint1 buffer[256];
      uint4 esp = mem->getValue("ESP");
      AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

      uint4 param1 = mem->getValue(ram,esp+4,4);
      mem->getChunk(buffer,ram,param1,255);

      cout << (char *)&buffer << endl;

      uint4 returnaddr = mem->getValue(ram,esp,4);
      mem->setValue("ESP",esp+8);
      emulate->setExecuteAddress(Address(ram,returnaddr));
  
      return true;			// This replaces the indicated instruction
    }
      
  \endcode

  Notice that the callback retrieves the value of the stack pointer by name.  Using this
  value, the string pointer is retrieved, then the data for the actual string is retrieved.
  After dumping the string to standard out, the return address is recovered and the \e return
  instruction is emulated by explicitly setting the next execution address to be the return value.

  \section emu_finalsetup Running the Emulator
  Here is an example of instantiating an EmulatePcodeCache object. A breakpoint is also instantiated
  and registered with the BreakTable.  

  \code
    ...
    Sleigh trans(&loader,&context);    // Instantiate the translator
    ...
    MemoryState memstate(&trans);      // Instantiate the memory state
    ...
    BreakTableCallBack breaktable(&trans);  // Instantiate a breakpoint table
    EmulatePcodeCache emulator(&trans,&memstate,&breaktable);  // Instantiate the emulator

    // Set up the initial stack pointer
    memstate.setValue("ESP",0xbffffffc);
    emulator.setExecuteAddress(Address(trans.getDefaultCodeSpace(),0x1D00114));  // Initial execution address
    
    PutsCallBack putscallback;
    breaktable.registerAddressCallback(Address(trans.getDefaultCodeSpace(),0x1D00130),&putscallback);

    AssemblyRaw assememit;
    for(;;) {
      Address addr = emulator.getExecuteAddress();
      trans.printAssembly(assememit,addr);
      emulator.executeInstruction();
    }

  \endcode

  Notice how the initial stack pointer and initial execute address is set up.  The breakpoint
  is registered with the BreakTable, giving it a specific address.  The executeInstruction method
  is called inside the loop, to actually run the emulator.  Notice that a disassembly of each
  instruction is printed after each step of the emulator.

  Other information can be examined from within this execution loop or in other tailored breakpoints.
  In particular, the Emulate::getCurrentOp() method can be used to retrieve the an instance
  of the currently executing pcode operation. From this starting point, you can examine the
  low-level objects:
    - PcodeOpRaw   and
    - VarnodeData
 */

} // End namespace ghidra
#endif

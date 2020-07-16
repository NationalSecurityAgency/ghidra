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
package ghidra.app.emulator;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import ghidra.app.emulator.memory.*;
import ghidra.app.emulator.state.DumpMiscState;
import ghidra.app.emulator.state.RegisterState;
import ghidra.framework.store.LockException;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class EmulatorHelper implements MemoryFaultHandler, EmulatorConfiguration {

	private final Program program;
	private final Emulator emulator;

	private Register stackPtrReg;
	private AddressSpace stackMemorySpace;

	private String lastError;
	private MemoryWriteTracker memoryWriteTracker;

	private MemoryFaultHandler faultHandler;

	private DataConverter converter;

	private BreakCallBack addressBreak = new BreakCallBack() {
		@Override
		public boolean addressCallback(Address addr) {
			emulator.setHalt(true);
			return true;
		}
	};

	public EmulatorHelper(Program program) {

		this.program = program;

		stackPtrReg = program.getCompilerSpec().getStackPointer();
		stackMemorySpace = program.getCompilerSpec().getStackBaseSpace();

		emulator = new Emulator(this);

		converter = DataConverter.getInstance(program.getMemory().isBigEndian());
	}

	public void dispose() {
		emulator.dispose();
		if (memoryWriteTracker != null) {
			memoryWriteTracker.dispose();
			memoryWriteTracker = null;
		}
	}

	@Override
	public MemoryFaultHandler getMemoryFaultHandler() {
		return this;
	}

	@Override
	public EmulatorLoadData getLoadData() {

		return new EmulatorLoadData() {

			@Override
			public MemoryLoadImage getMemoryLoadImage() {
				return new ProgramMappedLoadImage(
					new ProgramMappedMemory(program, EmulatorHelper.this));
			}

			@Override
			public RegisterState getInitialRegisterState() {
				return new DumpMiscState(getLanguage());
			}
		};
	}

	@Override
	public Language getLanguage() {
		return program.getLanguage();
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * Get Program Counter (PC) register defined by applicable processor specification
	 * @return Program Counter register
	 */
	public Register getPCRegister() {
		return program.getLanguage().getProgramCounter();
	}

	/**
	 * Get Stack Pointer register defined by applicable compiler specification
	 * @return Stack Pointer register
	 */
	public Register getStackPointerRegister() {
		return stackPtrReg;
	}

	/**
	 * Provides ability to install a low-level memory fault handler. 
	 * The handler methods should generally return 'false' to allow 
	 * the default handler to generate the appropriate target error. 
	 * Within the fault handler, the EmulateExecutionState can be used 
	 * to distinguish the pcode-emit state and the actual execution state
	 * since an attempt to execute an instruction at an uninitialized 
	 * memory location will cause an uninitializedRead during the PCODE_EMIT
	 * state.
	 * @param handler memory fault handler.
	 */
	public void setMemoryFaultHandler(MemoryFaultHandler handler) {
		faultHandler = handler;
	}

	/**
	 * @return the low-level emulator execution state
	 */
	public EmulateExecutionState getEmulateExecutionState() {
		return emulator.getEmulateExecutionState();
	}

	private Register getRegister(String regName) throws IllegalArgumentException {
		Register reg = program.getRegister(regName);
		if (reg == null) {
			throw new IllegalArgumentException("Undefined register: " + regName);
		}
		return reg;
	}

	public BigInteger readRegister(Register reg) {
		if (reg.isProcessorContext()) {
			RegisterValue contextRegisterValue = emulator.getContextRegisterValue();
			if (!reg.equals(contextRegisterValue.getRegister())) {
				contextRegisterValue = contextRegisterValue.getRegisterValue(reg);
			}
			return contextRegisterValue.getSignedValueIgnoreMask();
		}
		if (reg.getName().equals(emulator.getPCRegisterName())) {
			return BigInteger.valueOf(emulator.getPC());
		}
		return emulator.getMemState().getBigInteger(reg);
	}

	public BigInteger readRegister(String regName) {
		Register reg = getRegister(regName);
		if (reg == null) {
			throw new IllegalArgumentException("Undefined register: " + regName);
		}
		return readRegister(reg);
	}

	public void writeRegister(Register reg, long value) {
		writeRegister(reg, BigInteger.valueOf(value));
	}

	public void writeRegister(String regName, long value) {
		writeRegister(regName, BigInteger.valueOf(value));
	}

	public void writeRegister(Register reg, BigInteger value) {
		if (reg.isProcessorContext()) {
			RegisterValue contextRegisterValue = new RegisterValue(reg, value);
			RegisterValue existingRegisterValue = emulator.getContextRegisterValue();
			if (!reg.equals(existingRegisterValue.getRegister())) {
				contextRegisterValue = existingRegisterValue.combineValues(contextRegisterValue);
			}
			emulator.setContextRegisterValue(contextRegisterValue);
			return;
		}
		emulator.getMemState().setValue(reg, value);
		if (reg.getName().equals(emulator.getPCRegisterName())) {
			emulator.setExecuteAddress(value.longValue());
		}
	}

	public void writeRegister(String regName, BigInteger value) {
		Register reg = getRegister(regName);
		if (reg == null) {
			throw new IllegalArgumentException("Undefined register: " + regName);
		}
		writeRegister(reg, value);
	}

	/**
	 * Read string from memory state.
	 * @param addr memory address
	 * @param maxLength limit string read to this length.  If return string is
	 * truncated, "..." will be appended.
	 * @return string read from memory state
	 */
	public String readNullTerminatedString(Address addr, int maxLength) {
		int len = 0;
		byte[] bytes = new byte[maxLength];
		byte b = 0;
		while (len < maxLength && (b = readMemoryByte(addr)) != 0) {
			bytes[len++] = b;
			addr = addr.next();
		}
		String str = new String(bytes, 0, len);
		if (b != 0) {
			str += "..."; // indicate string truncation
		}
		return str;
	}

	public byte readMemoryByte(Address addr) {
		byte[] value = readMemory(addr, 1);
		return value[0];
	}

	public byte[] readMemory(Address addr, int length) {
		byte[] res = new byte[length];
		int len = emulator.getMemState().getChunk(res, addr.getAddressSpace(), addr.getOffset(),
			length, false);
		if (len == 0) {
			Msg.error(this, "Failed to read memory from Emulator at: " + addr);
			return null;
		}
		else if (len < length) {
			Msg.error(this,
				"Only " + len + " of " + length + " bytes read memory from Emulator at: " + addr);
		}
		return res;
	}

	public void writeMemory(Address addr, byte[] bytes) {
		emulator.getMemState().setChunk(bytes, addr.getAddressSpace(), addr.getOffset(),
			bytes.length);
	}

	public void writeMemoryValue(Address addr, int size, long value) {
		emulator.getMemState().setValue(addr.getAddressSpace(), addr.getOffset(), size, value);
	}

	/**
	 * Read a stack value from the memory state. 
	 * @param relativeOffset offset relative to current stack pointer
	 * @param size data size in bytes
	 * @param signed true if value read is signed, false if unsigned
	 * @return value
	 * @throws Exception error occurs reading stack pointer
	 */
	public BigInteger readStackValue(int relativeOffset, int size, boolean signed)
			throws Exception {
		long offset = readRegister(stackPtrReg).longValue() + relativeOffset;
		byte[] bytes = readMemory(stackMemorySpace.getAddress(offset), size);
		return converter.getBigInteger(bytes, size, signed);
	}

	/**
	 * Write a value onto the stack
	 * @param relativeOffset offset relative to current stack pointer
	 * @param size data size in bytes
	 * @param value
	 * @throws Exception error occurs reading stack pointer
	 */
	public void writeStackValue(int relativeOffset, int size, long value) throws Exception {
		long offset = readRegister(stackPtrReg).longValue() + relativeOffset;
		byte[] bytes = new byte[size];
		converter.getBytes(value, size, bytes, 0);
		writeMemory(stackMemorySpace.getAddress(offset), bytes);
	}

	/**
	 * Write a value onto the stack
	 * @param relativeOffset offset relative to current stack pointer
	 * @param size data size in bytes
	 * @param value
	 * @throws Exception error occurs reading stack pointer
	 */
	public void writeStackValue(int relativeOffset, int size, BigInteger value) throws Exception {
		// TODO: verify that sign byte is not added to size of bytes
		long offset = readRegister(stackPtrReg).longValue() + relativeOffset;
		byte[] bytes = converter.getBytes(value, size);
		writeMemory(stackMemorySpace.getAddress(offset), bytes);
	}

	/**
	 * Establish breakpoint
	 * @param addr memory address for new breakpoint
	 */
	public void setBreakpoint(Address addr) {
		emulator.getBreakTable().registerAddressCallback(addr, addressBreak);
	}

	/**
	 * Clear breakpoint
	 * @param addr memory address for breakpoint to be cleared
	 */
	public void clearBreakpoint(Address addr) {
		emulator.getBreakTable().unregisterAddressCallback(addr);
	}

	/**
	 * Set current context register value.
	 * Keep in mind that any non-flowing context values will be stripped.
	 * @param ctxRegValue
	 */
	public void setContextRegister(RegisterValue ctxRegValue) {
		emulator.setContextRegisterValue(ctxRegValue);
	}

	/**
	 * Set current context register value.
	 * Keep in mind that any non-flowing context values will be stripped.
	 * @param ctxReg context register
	 * @param value context value
	 */
	public void setContextRegister(Register ctxReg, BigInteger value) {
		emulator.setContextRegisterValue(new RegisterValue(ctxReg, value));
	}

	/**
	 * Get the current context register value
	 * @return context register value or null if not set or unknown
	 */
	public RegisterValue getContextRegister() {
		return emulator.getContextRegisterValue();
	}

	/**
	 * Register callback for language defined pcodeop (call other).
	 * WARNING! Using this method may circumvent the default CALLOTHER emulation support
	 * when supplied by the Processor module.
	 * @param pcodeOpName the name of the pcode op
	 * @param callback the callback to register
	 */
	public void registerCallOtherCallback(String pcodeOpName, BreakCallBack callback) {
		emulator.getBreakTable().registerPcodeCallback(pcodeOpName, callback);
	}

	/**
	 * Register default callback for language defined pcodeops (call other).
	 * WARNING! Using this method may circumvent the default CALLOTHER emulation support
	 * when supplied by the Processor module.
	 * @param callback the default callback to register
	 */
	public void registerDefaultCallOtherCallback(BreakCallBack callback) {
		emulator.getBreakTable().registerPcodeCallback("*", callback);
	}

	/**
	 * Unregister callback for language defined pcodeop (call other).
	 * @param pcodeOpName the name of the pcode op
	 */
	public void unregisterCallOtherCallback(String pcodeOpName) {
		emulator.getBreakTable().unregisterPcodeCallback(pcodeOpName);
	}

	/**
	 * Unregister default callback for language defined pcodeops (call other).
	 * WARNING! Using this method may circumvent the default CALLOTHER emulation support
	 * when supplied by the Processor module.
	 */
	public void unregisterDefaultCallOtherCallback() {
		emulator.getBreakTable().unregisterPcodeCallback("*");
	}

	/**
	 * Get current execution address
	 * @return current execution address
	 */
	public Address getExecutionAddress() {
		return emulator.getExecuteAddress();
	}

	/**
	 * Start execution at the specified address using the initial context specified.
	 * Method will block until execution stops.  This method will initialize context
	 * register based upon the program stored context if not already done.  In addition,
	 * both general register value and the context register may be further modified
	 * via the context parameter if specified.
	 * @param addr initial program address
	 * @param context optional context settings which override current program context
	 * @param monitor
	 * @return true if execution completes without error (i.e., is at breakpoint)
	 * @throws CancelledException if execution cancelled via monitor
	 */
	public boolean run(Address addr, ProcessorContext context, TaskMonitor monitor)
			throws CancelledException {

		if (emulator.isExecuting()) {
			throw new IllegalStateException("Emulator is already running");
		}

		// Initialize context
		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue contextRegValue = null;
		boolean mustSetContextReg = false;

		if (baseContextRegister != null) {
			contextRegValue = getContextRegister();
			if (contextRegValue == null) {
				contextRegValue = programContext.getRegisterValue(baseContextRegister, addr);
				mustSetContextReg = (contextRegValue != null);
			}
		}

		if (context != null) {
			for (Register reg : context.getRegisters()) {
				// skip non-base registers
				if (reg.isBaseRegister() && context.hasValue(reg)) {
					RegisterValue registerValue = context.getRegisterValue(reg);
					if (reg.isProcessorContext()) {
						if (contextRegValue != null) {
							contextRegValue = contextRegValue.combineValues(registerValue);
						}
						else {
							contextRegValue = registerValue;
						}
						mustSetContextReg = true;
					}
					else {
						BigInteger value = registerValue.getUnsignedValueIgnoreMask();
						writeRegister(reg, value);
					}
				}
			}
		}

		long pcValue = addr.getAddressableWordOffset();
		emulator.setExecuteAddress(pcValue);

		if (mustSetContextReg) {
			setContextRegister(contextRegValue);
		}

		continueExecution(monitor);
		return emulator.isAtBreakpoint();
	}

	/**
	 * Continue execution from the current execution address.
	 * No adjustment will be made to the context beyond the normal 
	 * context flow behavior defined by the language.
	 * Method will block until execution stops.
	 * @param monitor
	 * @return true if execution completes without error (i.e., is at breakpoint)
	 * @throws CancelledException if execution cancelled via monitor
	 */
	public synchronized boolean run(TaskMonitor monitor) throws CancelledException {

		if (emulator.isExecuting()) {
			throw new IllegalStateException("Emulator is already running");
		}
		continueExecution(monitor);
		return emulator.isAtBreakpoint();
	}

	/**
	 * Continue execution and block until either a breakpoint hits or error occurs.
	 * @throws CancelledException if execution was cancelled
	 */
	private void continueExecution(TaskMonitor monitor) throws CancelledException {
		emulator.setHalt(false);
		do {
			executeInstruction(true, monitor);
		}
		while (!emulator.getHalt());
	}

	/**
	 * Execute instruction at current address
	 * @param stopAtBreakpoint if true and breakpoint hits at current execution address
	 * execution will halt without executing instruction.
	 * @throws CancelledException if execution was cancelled
	 */
	private void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException {

		lastError = null;
		try {
			if (emulator.getLastExecuteAddress() == null) {
				setProcessorContext();
			}
			emulator.executeInstruction(stopAtBreakpoint, monitor);
		}
		catch (Throwable t) {
//	TODO: need to enumerate errors better !!
			lastError = t.getMessage();
			emulator.setHalt(true); // force execution to stop
			if (t instanceof CancelledException) {
				throw (CancelledException) t;
			}
		}
	}

	/**
	 * Used when the emulator has had the execution address changed to
	 * make sure it has a context consistent with the program context
	 * if there is one.
	 */
	private void setProcessorContext() {
		// this assumes you have set the emulation address
		//   the emu will have cleared the context for the new address
		RegisterValue contextRegisterValue = emulator.getContextRegisterValue();
		if (contextRegisterValue != null) {
			return;
		}

		Address executeAddress = emulator.getExecuteAddress();
		Instruction instructionAt = program.getListing().getInstructionAt(executeAddress);
		if (instructionAt != null) {
			RegisterValue disassemblyContext =
				instructionAt.getRegisterValue(instructionAt.getBaseContextRegister());
			emulator.setContextRegisterValue(disassemblyContext);
		}
	}

	/**
	 * @return last error message associated with execution failure
	 */
	public String getLastError() {
		return lastError;
	}

	/**
	 * Step execution one instruction which may consist of multiple
	 * pcode operations.  No adjustment will be made to the context beyond the normal 
	 * context flow behavior defined by the language.
	 * Method will block until execution stops.
	 * @return true if execution completes without error
	 * @throws CancelledException if execution cancelled via monitor
	 */
	public synchronized boolean step(TaskMonitor monitor) throws CancelledException {
		executeInstruction(true, monitor);
		return lastError == null;
	}

	/**
	 * Create a new initialized memory block using the current emulator memory state
	 * @param name block name
	 * @param start start address of the block 
	 * @param length the size of the block
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new 
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @param monitor
	 * @return new memory block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws AddressOverflowException if the start is beyond the
	 * address space
	 * @throws CancelledException user cancelled operation
	 * @throws DuplicateNameException
	 */
	public MemoryBlock createMemoryBlockFromMemoryState(String name, final Address start,
			final int length, boolean overlay, TaskMonitor monitor) throws MemoryConflictException,
			AddressOverflowException, CancelledException, LockException, DuplicateNameException {

		if (emulator.isExecuting()) {
			throw new IllegalStateException("Emulator must be paused to access memory state");
		}

		InputStream memStateStream = new InputStream() {

			private MemoryState memState = emulator.getMemState();

			private byte[] buffer = new byte[1024];
			private long nextBufferOffset = start.getOffset();
			private int bytesRemaining = length;
			private int bufferPos = buffer.length;

			@Override
			public int read() throws IOException {

				if (bytesRemaining <= 0) {
					return -1;
				}

				if (bufferPos == buffer.length) {
					int size = Math.min(buffer.length, bytesRemaining);
					memState.getChunk(buffer, start.getAddressSpace(), nextBufferOffset, size,
						false);
					nextBufferOffset += buffer.length;
					bufferPos = 0;
				}

				byte b = buffer[bufferPos++];
				--bytesRemaining;
				return b;
			}
		};

		MemoryBlock block;
		boolean success = false;
		int txId = program.startTransaction("Create Memory Block");
		try {
			block = program.getMemory().createInitializedBlock(name, start, memStateStream, length,
				monitor, overlay);
			success = true;
		}
		finally {
			program.endTransaction(txId, success);
		}
		return block;
	}

	/**
	 * Enable/Disable tracking of memory writes in the form of an
	 * address set.
	 * @param enable
	 */
	public void enableMemoryWriteTracking(boolean enable) {

		if (!enable) {
			if (memoryWriteTracker != null) {
				memoryWriteTracker.dispose();
				memoryWriteTracker = null;
			}
			return;
		}

		memoryWriteTracker = new MemoryWriteTracker();
		emulator.addMemoryAccessFilter(memoryWriteTracker);
	}

	/**
	 * @return address set of memory locations written by the emulator
	 * if memory write tracking is enabled, otherwise null is returned.
	 * The address set returned will continue to be updated unless
	 * memory write tracking becomes disabled.
	 */
	public AddressSetView getTrackedMemoryWriteSet() {
		if (memoryWriteTracker != null) {
			return memoryWriteTracker.writeSet;
		}
		return null;
	}

	private class MemoryWriteTracker extends MemoryAccessFilter {

		AddressSet writeSet = new AddressSet();

		@Override
		protected void processRead(AddressSpace spc, long off, int size, byte[] values) {
			// do nothing
		}

		@Override
		protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
			AddressRange range =
				new AddressRangeImpl(spc.getAddress(off), spc.getAddress(off + size - 1));
			writeSet.add(range);
		}
	}

	@Override
	public boolean unknownAddress(Address address, boolean write) {
		if (faultHandler != null) {
			return faultHandler.unknownAddress(address, write);
		}
		Address pc = emulator.getExecuteAddress();
		String access = write ? "written" : "read";
		Msg.warn(this, "Unknown address " + access + " at " + pc + ": " + address);
		return false;
	}

	@Override
	public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
		if (faultHandler != null) {
			return faultHandler.uninitializedRead(address, size, buf, bufOffset);
		}
		if (emulator.getEmulateExecutionState() == EmulateExecutionState.INSTRUCTION_DECODE) {
			return false;
		}
		Address pc = emulator.getExecuteAddress();
		Register reg = program.getRegister(address, size);
		if (reg != null) {
			Msg.warn(this, "Uninitialized register read at " + pc + ": " + reg);
			return true;
		}
		Msg.warn(this,
			"Uninitialized memory read at " + pc + ": " + address.toString(true) + ":" + size);
		return true;
	}

	public Emulator getEmulator() {
		return emulator;
	}
}

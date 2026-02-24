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
package ghidra.test.processors.support;

import java.math.BigInteger;
import java.util.*;

import generic.timer.GhidraSwinglessTimer;
import generic.timer.TimerCallback;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.PcodeMachine.SwiMode;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.test.processors.support.PCodeTestAbstractControlBlock.FunctionInfo;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

public class EmulatorTestRunner {

	private Program program;
	private PCodeTestGroup testGroup;

	private MyCallbacks emuCallbacks;
	private PcodeEmulator emu;
	private PcodeThread<byte[]> emuThread;
	private PcodeArithmetic<byte[]> emuArithmetic;
	private ExecutionListener executionListener;

	private volatile boolean haltedOnTimer = false;
	private String lastError;
	private int callOtherErrors; // only incremented on pass with callOtherCount != 0
	private int callOtherCount;

	private TreeSet<String> unimplementedSet = new TreeSet<>();

	private HashMap<Address, List<DumpPoint>> dumpPointMap = new HashMap<>();

	public EmulatorTestRunner(Program program, PCodeTestGroup testGroup,
			ExecutionListener executionListener) {
		this.program = program;
		this.testGroup = testGroup;
		this.executionListener = executionListener;

		this.emuCallbacks = new MyCallbacks();
		this.emu = new PcodeEmulator(program.getLanguage(), emuCallbacks) {
			/**
			 * {@inheritDoc}
			 * <p>
			 * Overriding this method is not ideal, but the callbacks do not support carte-blanche
			 * overriding of all state reads and writes, only hooks for uninitialized reads, but all
			 * writes. Perhaps we should support all reads, too, but only for monitoring/logging
			 * purposes. Modifying state behavior should probably still require, well, overriding
			 * the state.
			 * <p>
			 * We use guilty knowledge of the implementation: We know which method all the calls
			 * will get funneled through.
			 */
			@Override
			protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
				PcodeStateCallbacks scb = emuCallbacks.wrapFor(thread);
				return new BytesPcodeExecutorState(language, scb) {
					@Override
					public byte[] getVar(AddressSpace space, long offset, int size,
							boolean quantize, Reason reason) {
						byte[] result = super.getVar(space, offset, size, quantize, reason);
						if (emuCallbacks.logRWEnabled && reason == Reason.EXECUTE_READ) {
							Address addr = space.getAddress(offset);
							executionListener.logRead(EmulatorTestRunner.this, addr, size, result);
						}
						return result;
					}

					@Override
					public void setVar(AddressSpace space, long offset, int size, boolean quantize,
							byte[] val) {
						if (emuCallbacks.logRWEnabled) {
							Address addr = space.getAddress(offset);
							executionListener.logWrite(EmulatorTestRunner.this, addr, size, val);
						}
						super.setVar(space, offset, size, quantize, val);
					}
				};
			}
		};
		loadProgram();
		this.emuThread = emu.newThread();
		this.emuArithmetic = emuThread.getArithmetic();
	}

	private void loadProgram() {

		byte[] buf = new byte[4096];
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isInitialized() || !block.isLoaded() || block.isArtificial() ||
				block.isOverlay() || block.isMapped()) {
				continue;
			}
			for (AddressRange rng : new AddressRangeChunker(block.getAddressRange(), buf.length)) {
				try {
					int len = block.getBytes(rng.getMinAddress(), buf);
					byte[] value = len == buf.length
							? buf
							: Arrays.copyOf(buf, len);
					emu.getSharedState().setVar(rng.getMinAddress(), len, false, value);
				}
				catch (MemoryAccessException e) {
					Msg.error(this, "Cannot load part of program", e);
				}
			}
		}
	}

	public void dispose() {
		emuThread = null;
		emu = null;
		program = null;
		executionListener = null;
		testGroup = null;
	}

	Set<String> getUnimplementedPcodeops() {
		return unimplementedSet;
	}

	public PCodeTestGroup getTestGroup() {
		return testGroup;
	}

	public Program getProgram() {
		return program;
	}

	public PcodeThread<byte[]> getEmulatorThread() {
		return emuThread;
	}

	public void setContextRegister(RegisterValue ctxRegValue) {
		if (ctxRegValue == null) {
			emuThread.overrideContextWithDefault();
		}
		else {
			emuThread.overrideContext(ctxRegValue);
		}
	}

	public Address getCurrentAddress() {
		return emuThread.getCounter();
	}

	public Instruction getCurrentInstruction() {
		// TODO: Pull instruction from emulator instead of program after 
		// merge with SleighRefactor branch
		return emuThread.getInstruction();
		//return program.getListing().getInstructionAt(emuThread.getCounter());
	}

	public RegisterValue getRegisterValue(Register reg) {
		byte[] bytes = emuThread.getState().getVar(reg, Reason.INSPECT);
		return emuArithmetic.toRegisterValue(reg, bytes, Purpose.INSPECT);
	}

	public String getRegisterValueString(Register reg) {
		String valStr = getRegisterValue(reg).getUnsignedValue().toString(16);
		return StringUtilities.pad(valStr, '0', reg.getMinimumByteSize() * 2);
	}

	public void setRegister(String regName, long value) {
		Register reg = program.getRegister(regName);
		if (reg == null) {
			throw new IllegalArgumentException("Undefined register: " + regName);
		}
		emuThread.getState().setVar(reg, emuArithmetic.fromConst(value, reg.getNumBytes()));
	}

	public void setRegister(String regName, BigInteger value) {
		Register reg = program.getRegister(regName);
		if (reg == null) {
			throw new IllegalArgumentException("Undefined register: " + regName);
		}
		emuThread.getState().setVar(reg, emuArithmetic.fromConst(value, reg.getNumBytes()));
	}

	/**
	 * Add memory dump point
	 * 
	 * @param breakAddr instruction address at which execution should pause (before it is executed)
	 *            so that the specified memory may be dumped to the log during trace execution mode.
	 * @param dumpAddr memory address which should be dumped
	 * @param dumpSize number elements which should be dumped
	 * @param elementSize size of each element in bytes (be reasonable!)
	 * @param elementFormat HEX, DECIMAL or FLOAT
	 * @param comment dump comment
	 */
	public void addDumpPoint(Address breakAddr, Address dumpAddr, int dumpSize, int elementSize,
			DumpFormat elementFormat, String comment) {
		List<DumpPoint> list = dumpPointMap.get(breakAddr);
		if (list == null) {
			list = new ArrayList<>();
			dumpPointMap.put(breakAddr, list);
		}
		list.add(new AddressDumpPoint(breakAddr, dumpAddr, dumpSize, elementSize, elementFormat,
			comment));
	}

	/**
	 * Add memory dump point
	 * 
	 * @param breakAddr instruction address at which execution should pause (before it is executed)
	 *            so that the specified memory may be dumped to the log during trace execution mode.
	 * @param dumpAddrReg register containing the memory address offset which should be dumped
	 * @param relativeOffset dump register relative offset
	 * @param dumpAddrSpace address space to which memory offset should be applied
	 * @param dumpSize number elements which should be dumped
	 * @param elementSize size of each element in bytes (be reasonable!)
	 * @param elementFormat HEX, DECIMAL or FLOAT
	 * @param comment dump comment
	 */
	public void addDumpPoint(Address breakAddr, Register dumpAddrReg, int relativeOffset,
			AddressSpace dumpAddrSpace, int dumpSize, int elementSize, DumpFormat elementFormat,
			String comment) {
		List<DumpPoint> list = dumpPointMap.get(breakAddr);
		if (list == null) {
			list = new ArrayList<>();
			dumpPointMap.put(breakAddr, list);
		}
		list.add(new RegisterRelativeDumpPoint(breakAddr, dumpAddrReg, relativeOffset,
			dumpAddrSpace, dumpSize, elementSize, elementFormat, comment));
	}

	private void dump(List<DumpPoint> dumpList) {
		for (DumpPoint dumpPoint : dumpList) {
			Address dumpAddr = dumpPoint.getDumpAddress();
			executionListener.logState(this, dumpAddr, dumpPoint.dumpSize, dumpPoint.elementSize,
				dumpPoint.elementFormat, dumpPoint.comment);
		}
	}

	private String getLastFunctionName(PCodeTestGroup testGroup, boolean logError) {
		return testGroup.mainTestControlBlock.getLastFunctionName(this,
			logError ? executionListener : null, testGroup);
	}

	public String getEmuError() {
		return lastError;
	}

	/**
	 * Get number of CALLOTHER errors detected when a test pass was registered. This number should
	 * be subtracted from the pass count and possibly added to the failure count. Number does not
	 * reflect total number of CALLOTHER pcodeops encountered but only the number of passed tests
	 * affected. See log for all CALLOTHER executions detected.
	 * 
	 * @return number of CALLOTHER errors
	 */
	public int getCallOtherErrors() {
		return callOtherErrors;
	}

	/**
	 * Allows the emulator to run until it's interrupted, returning true if the interrupt is caused
	 * by a breakpoint.
	 * 
	 * @return true if interrupted by a breakpoint, false otherwise. This may also run indefinitely.
	 */
	public boolean runToBreakpoint() {
		try {
			emuThread.run();
		}
		catch (InterruptPcodeExecutionException e) {
			return true;
		}
		catch (Throwable t) {
			lastError = t.getLocalizedMessage();
		}
		return false;
	}

	/**
	 * Step the emulator one instruction, returning true if it's completed without interruption.
	 * 
	 * @return true if completed, false if interrupted. Though unlikely, this may also run
	 *         indefinitely.
	 */
	public boolean stepIgnoreBreakpoints() {
		SwiMode restore = emu.getSoftwareInterruptMode();
		try {
			emu.setSoftwareInterruptMode(SwiMode.IGNORE_ALL);
			emuThread.stepInstruction();
			return true;
		}
		catch (Throwable t) {
			lastError = t.getLocalizedMessage();
			return false;
		}
		finally {
			emu.setSoftwareInterruptMode(restore);
		}
	}

	/**
	 * Execute test group without instruction stepping/tracing
	 * 
	 * @param timeLimitMS the maximum number of milliseconds to execute before suspending and
	 *            terminating
	 * @return true if execution reached the "done" breakpoint
	 */
	public boolean execute(int timeLimitMS) {

		testGroup.clearFailures();
		lastError = null;
		callOtherErrors = 0;

		// Disable sprintf use
		testGroup.mainTestControlBlock.setSprintfEnabled(this, false);

		int alignment = program.getLanguage().getInstructionAlignment();

		Address breakOnDoneAddr =
			alignAddress(testGroup.mainTestControlBlock.getBreakOnDoneAddress(), alignment);
		Address breakOnPassAddr =
			alignAddress(testGroup.mainTestControlBlock.getBreakOnPassAddress(), alignment);
		Address breakOnErrorAddr =
			alignAddress(testGroup.mainTestControlBlock.getBreakOnErrorAddress(), alignment);

		executionListener.log(testGroup, "TestInfo pointers of interest:");
		executionListener.log(testGroup, " onDone -> " + breakOnDoneAddr);
		executionListener.log(testGroup, " onPass -> " + breakOnPassAddr);
		executionListener.log(testGroup, " onError -> " + breakOnErrorAddr);

		emu.addBreakpoint(breakOnDoneAddr, "1:1");
		emu.addBreakpoint(breakOnPassAddr, "1:1");
		emu.addBreakpoint(breakOnErrorAddr, "1:1");

		GhidraSwinglessTimer safetyTimer = null;
		haltedOnTimer = false;
		boolean atBreakpoint = false;
		try {
			if (timeLimitMS > 0) {
				safetyTimer = new GhidraSwinglessTimer(timeLimitMS, new TimerCallback() {
					@Override
					public synchronized void timerFired() {
						haltedOnTimer = true;
						emu.setSuspended(true);
					}
				});
				safetyTimer.setRepeats(false);
				safetyTimer.start();
			}
			while (true) {
				callOtherCount = 0;

				boolean success;
				if (atBreakpoint) {
					success = runToBreakpoint();
				}
				else {
					Address aligned = alignAddress(testGroup.functionEntryPtr, alignment);
					EmulatorUtilities.initializeRegisters(emuThread, program, aligned);
					success = runToBreakpoint();
				}

				String lastFuncName = getLastFunctionName(testGroup, false);
				String errFileName = testGroup.mainTestControlBlock.getLastErrorFile(this);
				int errLineNum = testGroup.mainTestControlBlock.getLastErrorLine(this);

				Address executeAddr = emuThread.getCounter();
				if (!success) {
					testGroup.severeTestFailure(lastFuncName, errFileName, errLineNum, program,
						executionListener);
					return false;
				}

				if (haltedOnTimer) {
					lastError = "Emulation halted due to execution timeout";
					testGroup.severeTestFailure(lastFuncName, errFileName, errLineNum, program,
						executionListener);
					return false;
				}

				if (executeAddr.equals(breakOnDoneAddr)) {
					return true; // done
				}

				if (executeAddr.equals(breakOnPassAddr)) {
					if (callOtherCount != 0) {
						// force error even if test passed - need to adjust pass count
						testGroup.testFailed(lastFuncName, errFileName, errLineNum, true, program,
							executionListener);
						++callOtherErrors;
					}
					else {
						testGroup.testPassed(lastFuncName, errFileName, errLineNum, program,
							executionListener);
					}
					atBreakpoint = true;
					continue;
				}
				else if (executeAddr.equals(breakOnErrorAddr)) {
					testGroup.testFailed(lastFuncName, errFileName, errLineNum, false, program,
						executionListener);
					atBreakpoint = true;
					continue; // resume from breakpoint
				}

				throw new AssertException("Unexpected condition (executeAddr=" + executeAddr + ")");
			}
		}
		finally {
			if (safetyTimer != null) {
				synchronized (safetyTimer) {
					safetyTimer.stop();
				}
			}
		}

	}

	public boolean executeSingleStep(int stepLimit) {

		testGroup.clearFailures();
		lastError = null;
		callOtherErrors = 0;
		callOtherCount = 0;

		// force function address alignment to compensate for address encoding (e.g., Thumb mode)
		int alignment = program.getLanguage().getInstructionAlignment();

		HashMap<Address, FunctionInfo> subFunctionMap = new HashMap<>();
		int subFunctionCnt = testGroup.controlBlock.getNumberFunctions();
		for (int i = 1; i < subFunctionCnt; i++) {
			FunctionInfo functionInfo = testGroup.controlBlock.getFunctionInfo(i);
			subFunctionMap.put(alignAddress(functionInfo.functionAddr, alignment), functionInfo);
		}

		Address executeAddr = alignAddress(testGroup.functionEntryPtr, alignment);

		emuThread.overrideCounter(executeAddr);

		// Enable sprintf use
		testGroup.mainTestControlBlock.setSprintfEnabled(this, true);

		Address breakOnDoneAddr =
			alignAddress(testGroup.mainTestControlBlock.getBreakOnDoneAddress(), alignment);
		Address breakOnPassAddr =
			alignAddress(testGroup.mainTestControlBlock.getBreakOnPassAddress(), alignment);
		Address breakOnErrorAddr =
			alignAddress(testGroup.mainTestControlBlock.getBreakOnErrorAddress(), alignment);
		Address printfAddr =
			alignAddress(testGroup.mainTestControlBlock.getSprintf5Address(), alignment);

		executionListener.log(testGroup, "TestInfo pointers of interest:");
		executionListener.log(testGroup, " onDone -> " + breakOnDoneAddr);
		executionListener.log(testGroup, " onPass -> " + breakOnPassAddr);
		executionListener.log(testGroup, " onError -> " + breakOnErrorAddr);
		executionListener.log(testGroup, " printf5 -> " + printfAddr);

		if (!dumpPointMap.isEmpty()) {
			executionListener.log(testGroup, "Dump points:");
			List<Address> addressList = new ArrayList<>(dumpPointMap.keySet());
			Collections.sort(addressList);
			for (Address addr : addressList) {
				List<DumpPoint> dumpList = dumpPointMap.get(addr);
				for (DumpPoint dumpPoint : dumpList) {
					executionListener.log(testGroup, " " + dumpPoint);
				}
			}
		}

		int stepCount = 0;
		Address lastAddress = null;
		Address printfCallAddr = null;
		boolean assertTriggered = false;
		FunctionInfo currentFunction = null;

		emuCallbacks.logRWEnabled = true;
		try {

			while (true) {
				if (!stepIgnoreBreakpoints()) {
					String lastFuncName = getLastFunctionName(testGroup, true);
					String errFileName = testGroup.mainTestControlBlock.getLastErrorFile(this);
					int errLineNum = testGroup.mainTestControlBlock.getLastErrorLine(this);

					testGroup.severeTestFailure(lastFuncName, errFileName, errLineNum, program,
						executionListener);

					return false;
				}

				executeAddr = emuThread.getCounter();

				List<DumpPoint> dumpList = dumpPointMap.get(executeAddr);
				if (dumpList != null) {
					dump(dumpList);
				}

				if (executeAddr.equals(breakOnDoneAddr)) {
					return true; // done
				}

				boolean onPass = executeAddr.equals(breakOnPassAddr);
				if (onPass || executeAddr.equals(breakOnErrorAddr)) {
					assertTriggered = true;
					String lastFuncName = getLastFunctionName(testGroup, true);
					String errFileName = testGroup.mainTestControlBlock.getLastErrorFile(this);
					int errLineNum = testGroup.mainTestControlBlock.getLastErrorLine(this);
					if (onPass) {
						if (callOtherCount != 0) {
							// force error even if test passed - need to adjust pass count
							testGroup.testFailed(lastFuncName, errFileName, errLineNum, true,
								program, executionListener);
							++callOtherErrors;
							callOtherCount = 0;
						}
						else {
							testGroup.testPassed(lastFuncName, errFileName, errLineNum, program,
								executionListener);
						}
					}
					else {
						testGroup.testFailed(lastFuncName, errFileName, errLineNum, false, program,
							executionListener);
					}
				}
				else if (executeAddr.equals(printfAddr)) {
					// enter printf function
					printfCallAddr = lastAddress;
					emuCallbacks.logRWEnabled = false;
					executionListener.log(testGroup, "printf invocation (log supressed) ...");
				}
				else if (printfCallAddr != null && isPrintfReturn(executeAddr, printfCallAddr)) {
					// return from printf function 
					printfCallAddr = null;
					emuCallbacks.logRWEnabled = true;

					String str = testGroup.controlBlock.emuReadString(emuThread,
						testGroup.mainTestControlBlock.getPrintfBufferAddress());
					executionListener.log(testGroup, "  " + str);
				}
				else {
					// detect start of new group test and remove from map 
					FunctionInfo functionInfo = subFunctionMap.remove(executeAddr);
					if (functionInfo != null) {
						if (currentFunction != null && !assertTriggered) {
							executionListener.log(testGroup,
								"ERROR! Group test never executed pass/fail: " + currentFunction);
						}
						currentFunction = functionInfo;
						assertTriggered = (functionInfo.numberOfAsserts == 0);
						executionListener.log(testGroup,
							"-------- " + functionInfo.functionName + " (" +
								functionInfo.numberOfAsserts + functionInfo.numberOfAsserts +
								"-Asserts) --------");
					}
				}

				if (++stepCount > stepLimit) {
					executionListener.log(testGroup,
						"Emulation halted due to excessive execution steps");

					String lastFuncName = getLastFunctionName(testGroup, true);
					String errFileName = testGroup.mainTestControlBlock.getLastErrorFile(this);
					int errLineNum = testGroup.mainTestControlBlock.getLastErrorLine(this);

					testGroup.severeTestFailure(lastFuncName, errFileName, errLineNum, program,
						executionListener);
					return false;
				}

				lastAddress = executeAddr;
			}
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception", t);
			return false;
		}
		finally {
			List<FunctionInfo> list = new ArrayList<>(subFunctionMap.values());
			if (!list.isEmpty()) {
				// Show list of sub-functions which were never executed
				Collections.sort(list);
				executionListener.log(testGroup,
					"The following sub-functions were never executed:");
				for (FunctionInfo functionInfo : list) {
					executionListener.log(testGroup, "  " + functionInfo);
				}
			}
			else {
				executionListener.log(testGroup,
					"All " + (testGroup.controlBlock.getNumberFunctions() - 1) +
						" sub-functions were executed");
			}
		}

	}

	static long alignAddressOffset(long offset, int alignment) {
		return (offset / alignment) * alignment;
	}

	static Address alignAddress(Address addr, int alignment) {
		Address alignedAddr = addr;
		long offset = addr.getOffset();
		long alignedOffset = alignAddressOffset(offset, alignment);
		if (offset != alignedOffset) {
			alignedAddr = addr.getNewAddress(alignedOffset);
		}
		return alignedAddr;
	}

	private boolean isPrintfReturn(Address executeAddr, Address printfCallAddr) {
		// look for approximate return relative to address of printf call
		long offset = executeAddr.getOffset();
		long maxEnd = printfCallAddr.getOffset() + 32;
		return (offset > printfCallAddr.getOffset() && offset <= maxEnd);
	}

	private class MyCallbacks implements PcodeEmulationCallbacks<byte[]> {
		private static final AddressSetView EMPTY = new AddressSet();

		boolean logRWEnabled = false;

		@Override
		public void beforeStore(PcodeThread<byte[]> thread, PcodeOp op, AddressSpace space,
				byte[] offset, int size, byte[] value) {
			if (!logRWEnabled) {
				return;
			}
			executionListener.logWrite(EmulatorTestRunner.this,
				emuArithmetic.toAddress(offset, space, Purpose.INSPECT), size, value);
		}

		@Override
		public void afterLoad(PcodeThread<byte[]> thread, PcodeOp op, AddressSpace space,
				byte[] offset, int size, byte[] value) {
			if (!logRWEnabled) {
				return;
			}
			executionListener.logRead(EmulatorTestRunner.this,
				emuArithmetic.toAddress(offset, space, Purpose.INSPECT), size, value);
		}

		@Override
		public void beforeExecuteInstruction(PcodeThread<byte[]> thread, Instruction instruction,
				PcodeProgram program) {
			if (!logRWEnabled) {
				return;
			}
			executionListener.logState(EmulatorTestRunner.this);
		}

		@Override
		public boolean handleMissingUserop(PcodeThread<byte[]> thread, PcodeOp op, PcodeFrame frame,
				String opName, PcodeUseropLibrary<byte[]> library) {
			unimplementedSet.add(opName);
			Varnode output = op.getOutput();
			String outStr = output == null ? ""
					: ", unable to set output " + output.toString(program.getLanguage());
			executionListener.log(testGroup, """
					Unimplemented pcodeop '%s' at: %s%s""".formatted(
				opName, thread.getCounter(), outStr));
			++callOtherCount;
			return true;
		}

		@Override
		public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread,
				PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
			if (reason == Reason.EXECUTE_DECODE) {
				return set;
			}
			/**
			 * HACK: Because of limitations in PcodeExecutorState, we can't know what thread is
			 * accessing a shared state, i.e., memory. We'd need either to require a thread argument
			 * in all the set/getVar methods (eww), or we need to use the newer JDK stuff for
			 * passing context vars down (alternative to the now decried ThreadLocal thing). Thus,
			 * thread may be null. emuThread is being constructed when it first tries to read
			 * pc,ctx; so it'll be null at that moment. So, we have to try both.
			 */
			if (thread == null) {
				thread = emuThread;
			}
			Address pc = thread.getCounter();
			for (AddressRange rng : set) {
				Register reg = program.getRegister(rng.getMinAddress(), (int) rng.getLength());
				if (reg != null) {
					executionListener.log(testGroup,
						"Uninitialized register read at %s: %s".formatted(pc, reg));
				}
				else {
					executionListener.log(testGroup, "Uninitialized read at %s: %s:%d".formatted(pc,
						rng.getMinAddress(), rng.getLength()));
				}
			}
			return EMPTY;
		}
	}

	public static enum DumpFormat {
		HEX, DECIMAL, FLOAT;
	}

	private abstract class DumpPoint {
		//final Address breakAddr;
		final int dumpSize;
		final int elementSize;
		final DumpFormat elementFormat;
		final String comment;

		DumpPoint(Address breakAddr, int dumpSize, int elementSize, DumpFormat elementFormat,
				String comment) {
			//this.breakAddr = breakAddr;
			this.dumpSize = dumpSize;
			this.elementSize = elementSize;
			this.elementFormat = elementFormat;
			this.comment = comment;
		}

		abstract Address getDumpAddress();

		public String toString(String addrStr) {
			return getClass().getSimpleName() + ": " + dumpSize + " " + elementSize +
				"-byte elements at " + addrStr;
		}
	}

	private class AddressDumpPoint extends DumpPoint {
		final Address dumpAddr;

		AddressDumpPoint(Address breakAddr, Address dumpAddr, int dumpSize, int elementSize,
				DumpFormat elementFormat, String comment) {
			super(breakAddr, dumpSize, elementSize, elementFormat, comment);
			this.dumpAddr = dumpAddr;
		}

		@Override
		Address getDumpAddress() {
			return dumpAddr;
		}

		@Override
		public String toString() {
			return toString(dumpAddr.toString(true));
		}
	}

	private class RegisterRelativeDumpPoint extends DumpPoint {
		final Register dumpAddrReg;
		final int relativeOffset;
		final AddressSpace dumpAddrSpace;

		RegisterRelativeDumpPoint(Address breakAddr, Register dumpAddrReg, int relativeOffset,
				AddressSpace dumpAddrSpace, int dumpSize, int elementSize, DumpFormat elementFormat,
				String comment) {
			super(breakAddr, dumpSize, elementSize, elementFormat, comment);
			this.dumpAddrReg = dumpAddrReg;
			this.relativeOffset = relativeOffset;
			this.dumpAddrSpace = dumpAddrSpace;
		}

		@Override
		Address getDumpAddress() {
			RegisterValue regVal = getRegisterValue(dumpAddrReg);
			return dumpAddrSpace.getAddress(regVal.getUnsignedValue().longValue())
					.add(relativeOffset);
		}

		@Override
		public String toString() {
			return toString("0x" + Integer.toHexString(relativeOffset) + "[" + dumpAddrReg + "]");
		}

	}

}

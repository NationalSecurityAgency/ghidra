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
import ghidra.app.emulator.*;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.test.processors.support.PCodeTestAbstractControlBlock.FunctionInfo;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EmulatorTestRunner {

	private Program program;
	private PCodeTestGroup testGroup;

	private EmulatorHelper emuHelper;
	private Emulator emu;
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
		emuHelper = new EmulatorHelper(program);
		emu = emuHelper.getEmulator();
		emuHelper.setMemoryFaultHandler(new MyMemoryFaultHandler(executionListener));

		emuHelper.registerDefaultCallOtherCallback(new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) throws LowlevelError {
				int userOp = (int) op.getInput(0).getOffset();
				String pcodeOpName = emulate.getLanguage().getUserDefinedOpName(userOp);
				unimplementedSet.add(pcodeOpName);
				String outStr = "";
				Varnode output = op.getOutput();
				if (output != null) {
					outStr = ", unable to set output " + output.toString(program.getLanguage());
				}
				EmulatorTestRunner.this.executionListener.log(testGroup, "Unimplemented pcodeop '" +
					pcodeOpName + "' at: " + emu.getExecuteAddress() + outStr);
				++callOtherCount;
				return true;
			}
		});
	}

	public void dispose() {
		emuHelper.dispose();
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

	public EmulatorHelper getEmulatorHelper() {
		return emuHelper;
	}

	public void setContextRegister(RegisterValue ctxRegValue) {
		emuHelper.setContextRegister(ctxRegValue);
	}

	public Address getCurrentAddress() {
		return emuHelper.getExecutionAddress();
	}

	public Instruction getCurrentInstruction() {
		// TODO: Pull instruction from emulator instead of program after 
		// merge with SleighRefactor branch
		return program.getListing().getInstructionAt(emu.getExecuteAddress());
	}

	private void flipBytes(byte[] bytes) {
		for (int i = 0; i < bytes.length / 2; i++) {
			byte b = bytes[i];
			int otherIndex = bytes.length - i - 1;
			bytes[i] = bytes[otherIndex];
			bytes[otherIndex] = b;
		}
	}

	public RegisterValue getRegisterValue(Register reg) {
		Register baseReg = reg.getBaseRegister();
		byte[] bytes = emuHelper.readMemory(baseReg.getAddress(), baseReg.getMinimumByteSize());
		if (!reg.isBigEndian()) {
			flipBytes(bytes);
		}
		byte[] maskValue = new byte[2 * bytes.length];
		Arrays.fill(maskValue, (byte) 0xff);
		System.arraycopy(bytes, 0, maskValue, bytes.length, bytes.length);
		RegisterValue baseValue = new RegisterValue(baseReg, maskValue);
		return baseValue.getRegisterValue(reg);
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
		emuHelper.writeRegister(reg, value);
	}

	public void setRegister(String regName, BigInteger value) {
		Register reg = program.getRegister(regName);
		if (reg == null) {
			throw new IllegalArgumentException("Undefined register: " + regName);
		}
		emuHelper.writeRegister(reg, value);
	}

	/**
	 * Add memory dump point
	 * @param breakAddr instruction address at which execution should pause (before it is executed)
	 * so that the specified memory may be dumped to the log during trace execution mode.
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
	 * @param breakAddr instruction address at which execution should pause (before it is executed)
	 * so that the specified memory may be dumped to the log during trace execution mode.
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
	 * Get number of CALLOTHER errors detected when a test pass was registered.
	 * This number should be subtracted from the pass count and possibly added
	 * to the failure count.  Number does not reflect total number of CALLOTHER 
	 * pcodeops encountered but only the number of passed tests affected.
	 * See log for all CALLOTHER executions detected.
	 * @return number of CALLOTHER errors
	 */
	public int getCallOtherErrors() {
		return callOtherErrors;
	}

	/**
	 * Execute test group without instruction stepping/tracing
	 * @param timeLimitMS 
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	public boolean execute(int timeLimitMS, TaskMonitor monitor) throws CancelledException {

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

		emuHelper.setBreakpoint(breakOnDoneAddr);
		emuHelper.setBreakpoint(breakOnPassAddr);
		emuHelper.setBreakpoint(breakOnErrorAddr);

		GhidraSwinglessTimer safetyTimer = null;
		haltedOnTimer = false;
		boolean atBreakpoint = false;
		try {
			if (timeLimitMS > 0) {
				safetyTimer = new GhidraSwinglessTimer(timeLimitMS, new TimerCallback() {
					@Override
					public synchronized void timerFired() {
						haltedOnTimer = true;
						emuHelper.getEmulator().setHalt(true);
					}
				});
				safetyTimer.setRepeats(false);
				safetyTimer.start();
			}
			while (true) {
				callOtherCount = 0;

				boolean success;
				if (atBreakpoint) {
					success = emuHelper.run(monitor);
				}
				else {
					success = emuHelper.run(alignAddress(testGroup.functionEntryPtr, alignment),
						null, monitor);
				}

				String lastFuncName = getLastFunctionName(testGroup, false);
				String errFileName = testGroup.mainTestControlBlock.getLastErrorFile(this);
				int errLineNum = testGroup.mainTestControlBlock.getLastErrorLine(this);

				Address executeAddr = emuHelper.getExecutionAddress();
				if (!success) {
					lastError = emuHelper.getLastError();
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

		emuHelper.writeRegister(program.getLanguage().getProgramCounter(),
			executeAddr.getAddressableWordOffset());

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

		executionListener.logState(this);

		int stepCount = 0;
		Address lastAddress = null;
		Address printfCallAddr = null;
		boolean assertTriggered = false;
		FunctionInfo currentFunction = null;

		MyMemoryAccessFilter memoryFilter = new MyMemoryAccessFilter();
		emu.addMemoryAccessFilter(memoryFilter);
		try {

			while (true) {
				if (!emuHelper.step(TaskMonitor.DUMMY)) {
					lastError = emuHelper.getLastError();

					String lastFuncName = getLastFunctionName(testGroup, true);
					String errFileName = testGroup.mainTestControlBlock.getLastErrorFile(this);
					int errLineNum = testGroup.mainTestControlBlock.getLastErrorLine(this);

					testGroup.severeTestFailure(lastFuncName, errFileName, errLineNum, program,
						executionListener);

					return false;
				}

				executeAddr = emuHelper.getExecutionAddress();

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
					memoryFilter.enabled = false;
					executionListener.log(testGroup, "printf invocation (log supressed) ...");
				}
				else if (printfCallAddr != null && isPrintfReturn(executeAddr, printfCallAddr)) {
					// return from printf function 
					printfCallAddr = null;
					memoryFilter.enabled = true;

					String str = testGroup.controlBlock.emuReadString(emuHelper,
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

				if (memoryFilter.enabled) {
					executionListener.logState(this);
				}

				lastAddress = executeAddr;
			}
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception", t);
			return false;
		}
		finally {
			memoryFilter.dispose();

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

	private class MyMemoryAccessFilter extends MemoryAccessFilter {

		boolean enabled = true;

		@Override
		protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
			if (enabled) {
				executionListener.logWrite(EmulatorTestRunner.this, spc.getAddress(off), size,
					values);
			}
		}

		@Override
		protected void processRead(AddressSpace spc, long off, int size, byte[] values) {
			if (enabled &&
				emu.getEmulateExecutionState() != EmulateExecutionState.INSTRUCTION_DECODE) {
				executionListener.logRead(EmulatorTestRunner.this, spc.getAddress(off), size,
					values);
			}
		}
	}

	private class MyMemoryFaultHandler implements MemoryFaultHandler {

		private ExecutionListener executionListener;

		public MyMemoryFaultHandler(ExecutionListener executionListener) {
			this.executionListener = executionListener;
		}

		@Override
		public boolean unknownAddress(Address address, boolean write) {
			Address pc = emuHelper.getExecutionAddress();
			String access = write ? "written" : "read";
			executionListener.log(testGroup,
				"Unknown address " + access + " at " + pc + ": " + address);
			return false;
		}

		@Override
		public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
			if (emu.getEmulateExecutionState() == EmulateExecutionState.INSTRUCTION_DECODE) {
				return false;
			}
			Address pc = emuHelper.getExecutionAddress();
			if (!address.isUniqueAddress()) {
				Register reg = program.getRegister(address, size);
				if (reg != null) {
					executionListener.log(testGroup,
						"Uninitialized register read at " + pc + ": " + reg);
					return true;
				}
			}
			executionListener.log(testGroup,
				"Uninitialized read at " + pc + ": " + address.toString(true) + ":" + size);
			return true;
		}
	}

	public static enum DumpFormat {
		HEX, DECIMAL, FLOAT;
	}

	private abstract class DumpPoint {
		final Address breakAddr;
		final int dumpSize;
		final int elementSize;
		final DumpFormat elementFormat;
		final String comment;

		DumpPoint(Address breakAddr, int dumpSize, int elementSize, DumpFormat elementFormat,
				String comment) {
			this.breakAddr = breakAddr;
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
			return dumpAddrSpace.getAddress(regVal.getUnsignedValue().longValue()).add(
				relativeOffset);
		}

		@Override
		public String toString() {
			return toString("0x" + Integer.toHexString(relativeOffset) + "[" + dumpAddrReg + "]");
		}

	}

}

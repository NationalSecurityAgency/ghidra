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

import generic.ULongSpan;
import generic.ULongSpan.ULongSpanSet;
import ghidra.app.emulator.memory.MemoryLoadImage;
import ghidra.app.emulator.state.RegisterState;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.lifecycle.Transitional;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.PcodeMachine.SwiMode;
import ghidra.pcode.emulate.*;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of {@link Emulator} that wraps the newer {@link PcodeEmulator}
 * 
 * <p>
 * This is a transitional utility only. It is currently used only by the pcode tests until that is
 * ported to use the new {@link PcodeEmulator} directly. New use cases based on p-code emulation
 * should use the {@link PcodeEmulator} directly. Older use cases still being actively maintained
 * should begin work porting to {@link PcodeEmulator}. Old use cases without active maintenance may
 * try this wrapper, but may have to remain using {@link DefaultEmulator}. At a minimum, to update
 * such old use cases, `new Emulator(...)` must be replaced by `new DefaultEmulator(...)`.
 */
@Transitional
public class AdaptedEmulator implements Emulator {
	class AdaptedPcodeEmulator extends PcodeEmulator {
		private final MemoryLoadImage loadImage;
		private final MemoryFaultHandler faultHandler;

		public AdaptedPcodeEmulator(Language language, MemoryLoadImage loadImage,
				MemoryFaultHandler faultHandler) {
			super(language);
			this.loadImage = loadImage;
			this.faultHandler = faultHandler;
		}

		@Override
		protected PcodeExecutorState<byte[]> createSharedState() {
			return new AdaptedBytesPcodeExecutorState(language,
				new StateBacking(faultHandler, loadImage));
		}

		@Override
		protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
			return new AdaptedBytesPcodeExecutorState(language,
				new StateBacking(faultHandler, null));
		}

		@Override
		protected AdaptedPcodeThread createThread(String name) {
			return new AdaptedPcodeThread(name, this);
		}

		@Override
		public AdaptedPcodeThread newThread() {
			return (AdaptedPcodeThread) super.newThread();
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			return new AdaptedPcodeUseropLibrary();
		}
	}

	@Transitional
	public class AdaptedPcodeUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		@PcodeUserop
		public void __addr_cb() {
			adaptedBreakTable.doAddressBreak(thread.getCounter());
			if (thread.isSuspended()) {
				/**
				 * This is the convention in DefaultEmulator: A breakpoint sets halt on the emulator
				 * to cause it to actually break. We'll translate that into an interrupt.
				 */
				throw new InterruptPcodeExecutionException(null, null);
			}
		}
	}

	class AdaptedPcodeThread extends BytesPcodeThread {
		Address lastExecuteAddress;

		public AdaptedPcodeThread(String name, AbstractPcodeMachine<byte[]> machine) {
			super(name, machine);
		}

		@Override
		protected void preExecuteInstruction() {
			super.preExecuteInstruction();
			lastExecuteAddress = getCounter();
		}

		@Override
		protected boolean onMissingUseropDef(PcodeOp op, String opName) {
			if (super.onMissingUseropDef(op, opName)) {
				return true;
			}
			return adaptedBreakTable.doPcodeOpBreak(new PcodeOpRaw(op));
		}
	}

	record StateBacking(MemoryFaultHandler faultHandler, MemoryLoadImage loadImage) {
	}

	static class AdaptedBytesPcodeExecutorState extends BytesPcodeExecutorState {
		public AdaptedBytesPcodeExecutorState(Language language, StateBacking backing) {
			super(new AdaptedBytesPcodeExecutorStatePiece(language, backing));
		}
	}

	static class AdaptedBytesPcodeExecutorStatePiece
			extends AbstractBytesPcodeExecutorStatePiece<AdaptedBytesPcodeExecutorStateSpace> {
		private final StateBacking backing;

		public AdaptedBytesPcodeExecutorStatePiece(Language language, StateBacking backing) {
			super(language);
			this.backing = backing;
		}

		@Override
		protected AbstractSpaceMap<AdaptedBytesPcodeExecutorStateSpace> newSpaceMap() {
			return new SimpleSpaceMap<>() {
				@Override
				protected AdaptedBytesPcodeExecutorStateSpace newSpace(AddressSpace space) {
					return new AdaptedBytesPcodeExecutorStateSpace(language, space, backing);
				}
			};
		}
	}

	static class AdaptedBytesPcodeExecutorStateSpace
			extends BytesPcodeExecutorStateSpace<StateBacking> {
		public AdaptedBytesPcodeExecutorStateSpace(Language language, AddressSpace space,
				StateBacking backing) {
			super(language, space, backing);
		}

		@Override
		protected ULongSpanSet readUninitializedFromBacking(ULongSpanSet uninitialized) {
			if (uninitialized.isEmpty()) {
				return uninitialized;
			}
			if (backing.loadImage == null) {
				if (space.isUniqueSpace()) {
					throw new AccessPcodeExecutionException(
						"Attempted to read from uninitialized unique: " + uninitialized);
				}
				return uninitialized;
			}
			ULongSpan bound = uninitialized.bound();
			byte[] data = new byte[(int) bound.length()];
			backing.loadImage.loadFill(data, data.length, space.getAddress(bound.min()), 0,
				false);
			for (ULongSpan span : uninitialized.spans()) {
				bytes.putData(span.min(), data, (int) (span.min() - bound.min()),
					(int) span.length());
			}
			return bytes.getUninitialized(bound.min(), bound.max());
		}

		@Override
		protected void warnUninit(ULongSpanSet uninit) {
			ULongSpan bound = uninit.bound();
			byte[] data = new byte[(int) bound.length()];
			if (backing.faultHandler.uninitializedRead(space.getAddress(bound.min()), data.length,
				data, 0)) {
				for (ULongSpan span : uninit.spans()) {
					bytes.putData(span.min(), data, (int) (span.min() - bound.min()),
						(int) span.length());
				}
			}
		}
	}

	class AdaptedBreakTableCallback extends BreakTableCallBack {
		public AdaptedBreakTableCallback() {
			super((SleighLanguage) language);
		}

		@Override
		public void registerAddressCallback(Address addr, BreakCallBack func) {
			super.registerAddressCallback(addr, func);
			emu.inject(addr, """
					__addr_cb();
					emu_exec_decoded();
					""");
		}

		@Override
		public void unregisterAddressCallback(Address addr) {
			emu.clearInject(addr);
			super.unregisterAddressCallback(addr);
		}
	}

	private final Language language;
	private final Register pcReg;
	private final AdaptedPcodeEmulator emu;
	private final AdaptedPcodeThread thread;
	private final MemoryState adaptedMemState;
	private final AdaptedBreakTableCallback adaptedBreakTable;

	private boolean isExecuting = false;
	private RuntimeException lastError;

	public AdaptedEmulator(EmulatorConfiguration config) {
		this.language = config.getLanguage();
		this.pcReg = language.getProgramCounter();
		if (config.isWriteBackEnabled()) {
			throw new IllegalArgumentException("write-back is not supported");
		}
		// I don't think we use page size directly.

		this.emu = newPcodeEmulator(config);
		this.thread = emu.newThread();
		initializeRegisters(config);

		this.adaptedMemState = new AdaptedMemoryState<>(thread.getState(), Reason.INSPECT);
		this.adaptedBreakTable = new AdaptedBreakTableCallback();
	}

	protected AdaptedPcodeEmulator newPcodeEmulator(EmulatorConfiguration config) {
		return new AdaptedPcodeEmulator(language, config.getLoadData().getMemoryLoadImage(),
			config.getMemoryFaultHandler());
	}

	protected void initializeRegisters(EmulatorConfiguration config) {
		RegisterState initRegs = config.getLoadData().getInitialRegisterState();
		PcodeExecutorState<byte[]> regState = thread.getState(); // NB. No .getLocalState()
		for (String key : initRegs.getKeys()) {
			if (!initRegs.isInitialized(key).get(0)) {
				continue;
			}
			Register register = language.getRegister(key);
			if (register == null) {
				Msg.warn(this, "No such register '" + key + "' in language " + language);
				continue;
			}
			// Yes, allow memory-mapped registers to be initialized in this manner
			byte[] val = initRegs.getVals(key).get(0);
			// TODO: GDTR/IDTR/LDTR _Limit, _Address stuff.... Is that arch specific?
			regState.setVar(register, val);
		}
	}

	@Override
	public String getPCRegisterName() {
		return pcReg.getName();
	}

	@Override
	public void setExecuteAddress(long addressableWordOffset) {
		Address address =
			language.getDefaultSpace().getTruncatedAddress(addressableWordOffset, true);
		thread.overrideCounter(address);
	}

	@Override
	public Address getExecuteAddress() {
		return thread.getCounter();
	}

	@Override
	public Address getLastExecuteAddress() {
		return thread.lastExecuteAddress;
	}

	@Override
	public long getPC() {
		return Utils.bytesToLong(thread.getState().getVar(pcReg, Reason.INSPECT),
			pcReg.getNumBytes(), language.isBigEndian());
	}

	@Override
	public void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException, LowlevelError, InstructionDecodeException {
		if (!(lastError == null || lastError instanceof InterruptPcodeExecutionException)) {
			throw lastError;
		}
		try {
			emu.setSoftwareInterruptMode(stopAtBreakpoint ? SwiMode.ACTIVE : SwiMode.IGNORE_ALL);
			isExecuting = true;
			if (thread.getFrame() != null) {
				thread.finishInstruction();
			}
			else {
				thread.stepInstruction();
			}
			lastError = null;
		}
		catch (RuntimeException e) {
			lastError = e;
		}
		finally {
			emu.setSoftwareInterruptMode(SwiMode.ACTIVE);
			isExecuting = false;
		}
	}

	@Override
	public boolean isExecuting() {
		return isExecuting;
	}

	@Override
	public EmulateExecutionState getEmulateExecutionState() {
		if (lastError instanceof InterruptPcodeExecutionException) {
			return EmulateExecutionState.BREAKPOINT;
		}
		if (lastError != null) {
			return EmulateExecutionState.FAULT;
		}
		PcodeFrame frame = thread.getFrame();
		if (frame != null) {
			return EmulateExecutionState.EXECUTE;
		}
		if (isExecuting) {
			return EmulateExecutionState.INSTRUCTION_DECODE;
		}
		return EmulateExecutionState.STOPPED;
	}

	@Override
	public MemoryState getMemState() {
		return adaptedMemState;
	}

	@Override
	public void addMemoryAccessFilter(MemoryAccessFilter filter) {
		filter.addFilter(this);
	}

	@Override
	public FilteredMemoryState getFilteredMemState() {
		// Just a dummy to prevent NPEs
		return new FilteredMemoryState(language);
	}

	@Override
	public void setContextRegisterValue(RegisterValue regValue) {
		if (regValue == null) {
			return;
		}
		thread.overrideContext(regValue);
	}

	@Override
	public RegisterValue getContextRegisterValue() {
		return thread.getContext();
	}

	@Override
	public BreakTableCallBack getBreakTable() {
		return adaptedBreakTable;
	}

	@Override
	public boolean isAtBreakpoint() {
		return lastError instanceof InterruptPcodeExecutionException;
	}

	@Override
	public void setHalt(boolean halt) {
		thread.setSuspended(halt);
	}

	@Override
	public boolean getHalt() {
		return thread.isSuspended();
	}

	@Override
	public void dispose() {
	}
}

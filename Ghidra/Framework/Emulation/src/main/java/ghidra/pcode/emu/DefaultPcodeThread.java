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
package ghidra.pcode.emu;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.emulator.Emulator;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.ProgramContextImpl;
import ghidra.util.Msg;

/**
 * The default implementation of {@link PcodeThread} suitable for most applications
 * 
 * <p>
 * When emulating on concrete state, consider using {@link ModifiedPcodeThread}, so that state
 * modifiers from the older {@link Emulator} are incorporated. In either case, it may be worthwhile
 * to examine existing state modifiers to ensure they are appropriately represented in any abstract
 * state. It may be necessary to port them.
 * 
 * <p>
 * This class implements the control-flow logic of the target machine, cooperating with the p-code
 * program flow implemented by the {@link PcodeExecutor}. This implementation exists primarily in
 * {@link #beginInstructionOrInject()} and {@link #advanceAfterFinished()}.
 */
public class DefaultPcodeThread<T> implements PcodeThread<T> {

	/**
	 * A userop library exporting some methods for emulated thread control
	 *
	 * <p>
	 * TODO: Since p-code userops can now receive the executor, it may be better to receive it, cast
	 * it, and obtain the thread, rather than binding a library to each thread.
	 *
	 * @param <T> no particular type, except to match the thread's
	 */
	public static class PcodeEmulationLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final DefaultPcodeThread<T> thread;

		/**
		 * Construct a library to control the given thread
		 * 
		 * @param thread the thread
		 */
		public PcodeEmulationLibrary(DefaultPcodeThread<T> thread) {
			this.thread = thread;
		}

		/**
		 * Execute the actual machine instruction at the current program counter
		 * 
		 * <p>
		 * Because "injects" override the machine instruction, injects which need to defer to the
		 * machine instruction must invoke this userop.
		 * 
		 * @see #emu_skip_decoded()
		 */
		@PcodeUserop
		public void emu_exec_decoded() {
			/**
			 * TODO: This idea of "pushing" a frame could be formalized, and the full stack made
			 * accessible to the client. This would permit "stepping into", and provide continuation
			 * after an interrupt. The caveat however, is whatever Java code invoked the inner frame
			 * cannot be continued/resumed. Such code could provide nothing more than glue.
			 */
			PcodeFrame saved = thread.frame;
			thread.dropInstruction();
			thread.executeInstruction();
			thread.frame = saved;
		}

		/**
		 * Advance the program counter beyond the current machine instruction
		 * 
		 * <p>
		 * Because "injects" override the machine instruction, they must specify the effect on the
		 * program counter, lest the thread become caught in an infinite loop on the inject. To
		 * emulate fall-through without executing the machine instruction, the inject must invoke
		 * this userop.
		 * 
		 * @see #emu_exec_decoded()
		 */
		@PcodeUserop
		public void emu_skip_decoded() {
			PcodeFrame saved = thread.frame;
			thread.dropInstruction();
			thread.skipInstruction();
			thread.frame = saved;
		}

		/**
		 * Interrupt execution
		 * 
		 * <p>
		 * This immediately throws an {@link InterruptPcodeExecutionException}. To implement
		 * out-of-band breakpoints, inject an invocation of this userop at the desired address.
		 * 
		 * @see PcodeMachine#addBreakpoint(Address, String)
		 */
		@PcodeUserop
		public void emu_swi() {
			thread.swi();
		}

		/**
		 * Notify the client of a failed Sleigh inject compilation.
		 * 
		 * <p>
		 * To avoid pestering the client during emulator set-up, a service may effectively defer
		 * notifying the user of Sleigh compilation errors by replacing the erroneous injects with
		 * calls to this p-code op. Then, only if and when an erroneous inject is encountered will
		 * the client be notified.
		 */
		@PcodeUserop
		public void emu_injection_err() {
			throw new InjectionErrorPcodeExecutionException(null, null);
		}
	}

	/**
	 * An executor for the p-code thread
	 * 
	 * <p>
	 * This executor checks for thread suspension and updates the program counter register upon
	 * execution of (external) branches.
	 */
	public static class PcodeThreadExecutor<T> extends PcodeExecutor<T> {
		volatile boolean suspended = false;
		protected final DefaultPcodeThread<T> thread;

		/**
		 * Construct the executor
		 * 
		 * @see DefaultPcodeThread#createExecutor()
		 * @param language the language of the containing machine
		 * @param arithmetic the arithmetic of the containing machine
		 * @param state the composite state assigned to the thread
		 */
		public PcodeThreadExecutor(DefaultPcodeThread<T> thread) {
			// NB. The executor itself is not decoding. So reads are in fact data reads.
			super(thread.language, thread.arithmetic, thread.state, Reason.EXECUTE_READ);
			this.thread = thread;
		}

		@Override
		public void executeSleigh(String source) {
			PcodeProgram program =
				SleighProgramCompiler.compileProgram(language, "exec", source, thread.library);
			execute(program, thread.library);
		}

		@Override
		public void stepOp(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<T> library) {
			if (suspended || thread.machine.suspended) {
				throw new SuspendedPcodeExecutionException(frame, null);
			}
			super.stepOp(op, frame, library);
			thread.stepped();
		}

		@Override
		protected void checkLoad(AddressSpace space, T offset, int size) {
			thread.checkLoad(space, offset, size);
		}

		@Override
		protected void checkStore(AddressSpace space, T offset, int size) {
			thread.checkStore(space, offset, size);
		}

		@Override
		protected void branchToAddress(Address target) {
			thread.branchToAddress(target);
		}

		@Override
		protected void onMissingUseropDef(PcodeOp op, PcodeFrame frame, String opName,
				PcodeUseropLibrary<T> library) {
			if (!thread.onMissingUseropDef(op, opName)) {
				super.onMissingUseropDef(op, frame, opName, library);
			}
		}

		/**
		 * Get the thread owning this executor
		 * 
		 * @return the thread
		 */
		public DefaultPcodeThread<T> getThread() {
			return thread;
		}
	}

	private final String name;
	private final AbstractPcodeMachine<T> machine;
	protected final SleighLanguage language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final ThreadPcodeExecutorState<T> state;
	protected final InstructionDecoder decoder;
	protected final PcodeUseropLibrary<T> library;

	protected final PcodeThreadExecutor<T> executor;
	protected final Register pc;
	protected final Register contextreg;

	private Address counter;
	private RegisterValue context;

	protected Instruction instruction;
	protected PcodeFrame frame;

	protected final ProgramContextImpl defaultContext;
	protected final Map<Address, PcodeProgram> injects = new HashMap<>();

	/**
	 * Construct a new thread
	 * 
	 * @see AbstractPcodeMachine#createThread(String)
	 * @param name the name of the thread
	 * @param machine the machine containing the thread
	 */
	public DefaultPcodeThread(String name, AbstractPcodeMachine<T> machine) {
		this.name = name;
		this.machine = machine;
		this.language = machine.language;
		this.arithmetic = machine.arithmetic;
		PcodeExecutorState<T> sharedState = machine.getSharedState();
		PcodeExecutorState<T> localState = machine.createLocalState(this);
		this.state = new ThreadPcodeExecutorState<>(sharedState, localState);
		this.decoder = createInstructionDecoder(sharedState);
		this.library = createUseropLibrary();

		this.executor = createExecutor();
		this.pc =
			Objects.requireNonNull(language.getProgramCounter(), "Language has no program counter");
		this.contextreg = language.getContextBaseRegister();

		if (contextreg != Register.NO_CONTEXT) {
			defaultContext = new ProgramContextImpl(language);
			language.applyContextSettings(defaultContext);
			this.context = defaultContext.getDefaultDisassemblyContext();
		}
		else {
			defaultContext = null;
		}
		this.reInitialize();
	}

	/**
	 * A factory method for the instruction decoder
	 * 
	 * @param sharedState the machine's shared (memory state)
	 * @return
	 */
	protected SleighInstructionDecoder createInstructionDecoder(PcodeExecutorState<T> sharedState) {
		return new SleighInstructionDecoder(language, sharedState);
	}

	/**
	 * A factory method to create the complete userop library for this thread
	 * 
	 * <p>
	 * The returned library must compose the containing machine's shared userop library. See
	 * {@link PcodeUseropLibrary#compose(PcodeUseropLibrary)}.
	 * 
	 * @return the thread's complete userop library
	 */
	protected PcodeUseropLibrary<T> createUseropLibrary() {
		return new PcodeEmulationLibrary<>(this).compose(machine.library);
	}

	/**
	 * A factory method to create the executor for this thread
	 * 
	 * @return the executor
	 */
	protected PcodeThreadExecutor<T> createExecutor() {
		return new PcodeThreadExecutor<>(this);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public AbstractPcodeMachine<T> getMachine() {
		return machine;
	}

	@Override
	public void setCounter(Address counter) {
		this.counter = counter;
	}

	@Override
	public Address getCounter() {
		return counter;
	}

	protected void branchToAddress(Address target) {
		writeCounter(target);
		decoder.branched(counter);
	}

	protected void writeCounter(Address counter) {
		setCounter(counter);
		state.setVar(pc,
			arithmetic.fromConst(counter.getAddressableWordOffset(), pc.getMinimumByteSize()));
	}

	@Override
	public void overrideCounter(Address counter) {
		writeCounter(counter);
	}

	@Override
	public void assignContext(RegisterValue context) {
		if (!context.getRegister().isProcessorContext()) {
			throw new IllegalArgumentException("context must be the contextreg value");
		}
		this.context = this.context.assign(context.getRegister(), context);
	}

	@Override
	public RegisterValue getContext() {
		return context;
	}

	@Override
	public void overrideContext(RegisterValue context) {
		assignContext(context);
		state.setVar(contextreg, arithmetic.fromConst(
			this.context.getUnsignedValueIgnoreMask(),
			contextreg.getMinimumByteSize(), true));
	}

	@Override
	public void overrideContextWithDefault() {
		if (contextreg != Register.NO_CONTEXT) {
			RegisterValue defaultValue = defaultContext.getDefaultValue(contextreg, counter);
			if (defaultValue != null) {
				overrideContext(defaultValue);
			}
		}
	}

	/**
	 * Execute the initializer upon this thread, if applicable
	 * 
	 * @see AbstractPcodeMachine#getPluggableInitializer(Language)
	 */
	protected void doPluggableInitialization() {
		if (machine.initializer != null) {
			machine.initializer.initializeThread(this);
		}
	}

	@Override
	public void reInitialize() {
		long offset = arithmetic.toLong(state.getVar(pc, Reason.RE_INIT), Purpose.BRANCH);
		setCounter(language.getDefaultSpace().getAddress(offset, true));

		if (contextreg != Register.NO_CONTEXT) {
			try {
				BigInteger ctx = arithmetic.toBigInteger(state.getVar(contextreg, Reason.RE_INIT),
					Purpose.CONTEXT);
				assignContext(new RegisterValue(contextreg, ctx));
			}
			catch (AccessPcodeExecutionException e) {
				Msg.info(this, "contextreg not recorded in trace. This is pretty normal.");
			}
		}

		doPluggableInitialization();
	}

	@Override
	public void stepInstruction() {
		PcodeProgram inj = getInject(counter);
		if (inj != null) {
			instruction = null;
			try {
				executor.execute(inj, library);
			}
			catch (PcodeExecutionException e) {
				frame = e.getFrame();
				throw e;
			}
		}
		else {
			executeInstruction();
		}
	}

	@Override
	public void stepPcodeOp() {
		if (frame == null) {
			beginInstructionOrInject();
		}
		else if (!frame.isFinished()) {
			executor.step(frame, library);
		}
		else {
			advanceAfterFinished();
		}
	}

	@Override
	public void skipPcodeOp() {
		if (frame == null) {
			beginInstructionOrInject();
		}
		else if (!frame.isFinished()) {
			executor.skip(frame);
		}
		else {
			advanceAfterFinished();
		}
	}

	/**
	 * Start execution of the instruction or inject at the program counter
	 */
	protected void beginInstructionOrInject() {
		PcodeProgram inj = getInject(counter);
		if (inj != null) {
			instruction = null;
			frame = executor.begin(inj);
		}
		else {
			instruction = decoder.decodeInstruction(counter, context);
			PcodeProgram pcode = PcodeProgram.fromInstruction(instruction);
			frame = executor.begin(pcode);
		}
	}

	/**
	 * Resolve a finished instruction, advancing the program counter if necessary
	 */
	protected void advanceAfterFinished() {
		if (instruction == null) { // Frame resulted from an inject
			frame = null;
			return;
		}
		if (frame.isFallThrough()) {
			overrideCounter(counter.addWrap(decoder.getLastLengthWithDelays()));
		}
		if (contextreg != Register.NO_CONTEXT) {
			overrideContext(defaultContext.getFlowValue(instruction.getRegisterValue(contextreg)));
		}
		postExecuteInstruction();
		frame = null;
		instruction = null;
	}

	@Override
	public PcodeFrame getFrame() {
		return frame;
	}

	@Override
	public Instruction getInstruction() {
		return instruction;
	}

	/**
	 * A sanity-checking measure: Cannot start a new instruction while one is still being executed
	 */
	protected void assertCompletedInstruction() {
		if (frame != null) {
			throw new IllegalStateException("The current instruction or inject has not finished.");
		}
	}

	/**
	 * A sanity-checking measure: Cannot finish an instruction unless one is currently being
	 * executed
	 */
	protected void assertMidInstruction() {
		if (frame == null) {
			throw new IllegalStateException("There is no current instruction to finish.");
		}
	}

	/**
	 * Extension point: Extra behavior before executing an instruction
	 * 
	 * <p>
	 * This is currently used for incorporating state modifiers from the older {@link Emulator}
	 * framework. There is likely utility here when porting those to this framework.
	 */
	protected void preExecuteInstruction() {
	}

	/**
	 * Extension point: Extra behavior after executing an instruction
	 * 
	 * <p>
	 * This is currently used for incorporating state modifiers from the older {@link Emulator}
	 * framework. There is likely utility here when porting those to this framework.
	 */
	protected void postExecuteInstruction() {
	}

	/**
	 * Extension point: Behavior when a p-code userop definition is not found
	 * 
	 * @param op the op
	 * @param opName the name of the p-code userop
	 * @return true if handle, false if still undefined
	 */
	protected boolean onMissingUseropDef(PcodeOp op, String opName) {
		return false;
	}

	@Override
	public void executeInstruction() {
		assertCompletedInstruction();
		instruction = decoder.decodeInstruction(counter, context);
		PcodeProgram insProg = PcodeProgram.fromInstruction(instruction);
		preExecuteInstruction();
		try {
			frame = executor.execute(insProg, library);
		}
		catch (PcodeExecutionException e) {
			frame = e.getFrame();
			throw e;
		}
		advanceAfterFinished();
	}

	@Override
	public void finishInstruction() {
		assertMidInstruction();
		executor.finish(frame, library);
		advanceAfterFinished();
	}

	@Override
	public void skipInstruction() {
		assertCompletedInstruction();
		instruction = decoder.decodeInstruction(counter, context);
		overrideCounter(counter.addWrap(decoder.getLastLengthWithDelays()));
	}

	@Override
	public void dropInstruction() {
		frame = null;
	}

	@Override
	public void run() {
		executor.suspended = false;
		if (frame != null) {
			finishInstruction();
		}
		while (true) {
			stepInstruction();
		}
	}

	@Override
	public void setSuspended(boolean suspended) {
		executor.suspended = suspended;
	}

	@Override
	public boolean isSuspended() {
		return executor.suspended;
	}

	@Override
	public SleighLanguage getLanguage() {
		return language;
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
		return arithmetic;
	}

	@Override
	public PcodeExecutor<T> getExecutor() {
		return executor;
	}

	@Override
	public PcodeUseropLibrary<T> getUseropLibrary() {
		return library;
	}

	@Override
	public ThreadPcodeExecutorState<T> getState() {
		return state;
	}

	/**
	 * Check for a p-code injection (override) at the given address
	 * 
	 * <p>
	 * This checks this thread's particular injects and then defers to the machine's injects.
	 * 
	 * @param address the address, usually the program counter
	 * @return the injected program, most likely {@code null}
	 */
	protected PcodeProgram getInject(Address address) {
		PcodeProgram inj = injects.get(address);
		if (inj != null) {
			return inj;
		}
		return machine.getInject(address);
	}

	@Override
	public void inject(Address address, String source) {
		PcodeProgram pcode = SleighProgramCompiler.compileProgram(
			language, "thread_inject:" + address, source, library);
		injects.put(address, pcode);
	}

	@Override
	public void clearInject(Address address) {
		injects.remove(address);
	}

	@Override
	public void clearAllInjects() {
		injects.clear();
	}

	/**
	 * Perform checks on a requested LOAD
	 * 
	 * <p>
	 * Throw an exception if the LOAD should cause an interrupt.
	 * 
	 * @param space the address space being accessed
	 * @param offset the offset being accessed
	 * @param size the size of the variable being accessed
	 */
	protected void checkLoad(AddressSpace space, T offset, int size) {
		machine.checkLoad(space, offset, size);
	}

	/**
	 * Perform checks on a requested STORE
	 * 
	 * <p>
	 * Throw an exception if the STORE should cause an interrupt.
	 * 
	 * @param space the address space being accessed
	 * @param offset the offset being accessed
	 * @param size the size of the variable being accessed
	 */
	protected void checkStore(AddressSpace space, T offset, int size) {
		machine.checkStore(space, offset, size);
	}

	/**
	 * Throw a software interrupt exception if those interrupts are active
	 */
	protected void swi() {
		machine.swi();
	}

	/**
	 * Notify the machine a thread has been stepped a p-code op, so that it may re-enable software
	 * interrupts, if applicable
	 */
	protected void stepped() {
		machine.stepped();
	}
}

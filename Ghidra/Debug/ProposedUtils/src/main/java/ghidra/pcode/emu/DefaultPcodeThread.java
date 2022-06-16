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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.ProgramContextImpl;
import ghidra.util.Msg;

/**
 * The default implementation of {@link PcodeThread} suitable for most applications
 * 
 * <p>
 * When emulating on concrete state, consider using {@link AbstractModifiedPcodeThread}, so that
 * state modifiers from the older {@link Emulator} are incorporated. In either case, it may be
 * worthwhile to examine existing state modifiers to ensure they are appropriately represented in
 * any abstract state. It may be necessary to port them.
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
			throw new InterruptPcodeExecutionException(null, null);
		}
	}

	/**
	 * An executor for the p-code thread
	 * 
	 * <p>
	 * This executor checks for thread suspension and updates the program counter register upon
	 * execution of (external) branches.
	 */
	public class PcodeThreadExecutor extends PcodeExecutor<T> {
		volatile boolean suspended = false;

		/**
		 * Construct the executor
		 * 
		 * @see DefaultPcodeThread#createExecutor()
		 * @param language the language of the containing machine
		 * @param arithmetic the arithmetic of the containing machine
		 * @param state the composite state assigned to the thread
		 */
		public PcodeThreadExecutor(SleighLanguage language, PcodeArithmetic<T> arithmetic,
				PcodeExecutorStatePiece<T, T> state) {
			super(language, arithmetic, state);
		}

		@Override
		public void stepOp(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<T> library) {
			if (suspended) {
				throw new SuspendedPcodeExecutionException(frame, null);
			}
			super.stepOp(op, frame, library);
		}

		@Override
		protected void branchToAddress(Address target) {
			overrideCounter(target);
		}

		public Instruction getInstruction() {
			return instruction;
		}
	}

	private final String name;
	private final AbstractPcodeMachine<T> machine;
	protected final SleighLanguage language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final ThreadPcodeExecutorState<T> state;
	protected final InstructionDecoder decoder;
	protected final PcodeUseropLibrary<T> library;

	protected final PcodeThreadExecutor executor;
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
		this.pc = language.getProgramCounter();
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
	protected PcodeThreadExecutor createExecutor() {
		return new PcodeThreadExecutor(language, arithmetic, state);
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

	@Override
	public void overrideCounter(Address counter) {
		setCounter(counter);
		state.setVar(pc,
			arithmetic.fromConst(counter.getAddressableWordOffset(), pc.getMinimumByteSize()));
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
			overrideContext(defaultContext.getDefaultValue(contextreg, counter));
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
		long offset = arithmetic.toConcrete(state.getVar(pc)).longValue();
		setCounter(language.getDefaultSpace().getAddress(offset, true));

		if (contextreg != Register.NO_CONTEXT) {
			try {
				BigInteger ctx = arithmetic.toConcrete(state.getVar(contextreg), true);
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
			overrideContext(instruction.getRegisterValue(contextreg));
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
	 * An extension point for hooking instruction execution before the fact
	 * 
	 * <p>
	 * This is currently used for incorporating state modifiers from the older {@link Emulator}
	 * framework. There is likely utility here when porting those to this framework.
	 */
	protected void preExecuteInstruction() {
		// Extension point
	}

	/**
	 * An extension point for hooking instruction execution after the fact
	 * 
	 * <p>
	 * This is currently used for incorporating state modifiers from the older {@link Emulator}
	 * framework. There is likely utility here when porting those to this framework.
	 */
	protected void postExecuteInstruction() {
		// Extension point
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
	public void inject(Address address, List<String> sleigh) {
		PcodeProgram pcode = SleighProgramCompiler.compileProgram(
			language, "thread_inject:" + address, sleigh, library);
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
}

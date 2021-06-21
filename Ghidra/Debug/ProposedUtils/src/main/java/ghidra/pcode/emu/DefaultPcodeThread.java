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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.AbstractPcodeMachine.ThreadPcodeExecutorState;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.ProgramContextImpl;
import ghidra.util.Msg;

/**
 * The default implementation of {@link PcodeThread} suitable for most applications
 */
public class DefaultPcodeThread<T> implements PcodeThread<T> {
	protected static class SleighEmulationLibrary<T> extends AnnotatedSleighUseropLibrary<T> {
		private final DefaultPcodeThread<T> thread;

		public SleighEmulationLibrary(DefaultPcodeThread<T> thread) {
			this.thread = thread;
		}

		@SleighUserop
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

		@SleighUserop
		public void emu_skip_decoded() {
			PcodeFrame saved = thread.frame;
			thread.dropInstruction();
			thread.skipInstruction();
			thread.frame = saved;
		}

		@SleighUserop
		public void emu_swi() {
			throw new InterruptPcodeExecutionException(null, null);
		}
	}

	protected class PcodeThreadExecutor extends PcodeExecutor<T> {
		volatile boolean suspended = false;

		public PcodeThreadExecutor(Language language, PcodeArithmetic<T> arithmetic,
				PcodeExecutorStatePiece<T, T> state) {
			super(language, arithmetic, state);
		}

		@Override
		public void stepOp(PcodeOp op, PcodeFrame frame, SleighUseropLibrary<T> library) {
			if (suspended) {
				throw new SuspendedPcodeExecutionException(frame, null);
			}
			super.stepOp(op, frame, library);
		}

		@Override
		protected void branchToAddress(Address target) {
			overrideCounter(target);
		}
	}

	private final String name;
	private final AbstractPcodeMachine<T> machine;
	protected final SleighLanguage language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final ThreadPcodeExecutorState<T> state;
	protected final InstructionDecoder decoder;
	protected final SleighUseropLibrary<T> library;

	protected final PcodeThreadExecutor executor;
	protected final Register pc;
	protected final Register contextreg;

	private Address counter;
	private RegisterValue context;

	protected Instruction instruction;
	protected PcodeFrame frame;

	protected final ProgramContextImpl defaultContext;
	protected final Map<Address, PcodeProgram> injects = new HashMap<>();

	public DefaultPcodeThread(String name, AbstractPcodeMachine<T> machine,
			SleighUseropLibrary<T> library) {
		this.name = name;
		this.machine = machine;
		this.language = machine.language;
		this.arithmetic = machine.arithmetic;
		PcodeExecutorState<T> memoryState = machine.getMemoryState();
		PcodeExecutorState<T> registerState = machine.createRegisterState(this);
		this.state = new ThreadPcodeExecutorState<>(memoryState, registerState);
		this.decoder = new SleighInstructionDecoder(language, memoryState);
		this.library = new SleighEmulationLibrary<>(this).compose(library);

		this.executor = createExecutor();
		this.pc = language.getProgramCounter();
		this.contextreg = language.getContextBaseRegister();

		if (contextreg != null) {
			defaultContext = new ProgramContextImpl(language);
			language.applyContextSettings(defaultContext);
			this.context = defaultContext.getDefaultDisassemblyContext();
		}
		else {
			defaultContext = null;
		}
		this.reInitialize();
	}

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
		state.setVar(pc, arithmetic.fromConst(counter.getOffset(), pc.getMinimumByteSize()));
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
			contextreg.getMinimumByteSize()));
	}

	@Override
	public void overrideContextWithDefault() {
		if (contextreg != null) {
			overrideContext(defaultContext.getDefaultValue(contextreg, counter));
		}
	}

	protected void doPluggableInitialization() {
		if (machine.initializer != null) {
			machine.initializer.initializeThread(this);
		}
	}

	@Override
	public void reInitialize() {
		long offset = arithmetic.toConcrete(state.getVar(pc)).longValue();
		setCounter(language.getDefaultSpace().getAddress(offset));

		if (contextreg != null) {
			try {
				BigInteger ctx = arithmetic.toConcrete(state.getVar(contextreg));
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

	protected void beginInstructionOrInject() {
		PcodeProgram inj = injects.get(counter);
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

	protected void advanceAfterFinished() {
		if (instruction == null) { // Frame resulted from an inject
			frame = null;
			return;
		}
		if (frame.isFallThrough()) {
			overrideCounter(counter.addWrap(decoder.getLastLengthWithDelays()));
		}
		if (contextreg != null) {
			overrideContext(instruction.getRegisterValue(contextreg));
		}
		postExecuteInstruction();
		frame = null;
	}

	@Override
	public PcodeFrame getFrame() {
		return frame;
	}

	protected void assertCompletedInstruction() {
		if (frame != null) {
			throw new IllegalStateException("The current instruction or inject has not finished.");
		}
	}

	protected void assertMidInstruction() {
		if (frame == null) {
			throw new IllegalStateException("There is no current instruction to finish.");
		}
	}

	/**
	 * An extension point for hooking instruction execution before the fact
	 */
	protected void preExecuteInstruction() {
		// Extension point
	}

	/**
	 * An extension point for hooking instruction execution after the fact
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
	public SleighUseropLibrary<T> getUseropLibrary() {
		return library;
	}

	@Override
	public ThreadPcodeExecutorState<T> getState() {
		return state;
	}

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

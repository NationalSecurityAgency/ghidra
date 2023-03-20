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

import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeEmulationLibrary;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;

/**
 * An emulated thread of execution
 * 
 * @param <T> the type of values in the emulated machine state
 */
public interface PcodeThread<T> {

	/**
	 * Get the name of this thread
	 * 
	 * @return the name
	 */
	String getName();

	/**
	 * Get the machine within which this thread executes
	 * 
	 * @return the containing machine
	 */
	PcodeMachine<T> getMachine();

	/**
	 * Set the thread's program counter without writing to its executor state
	 * 
	 * @see #overrideCounter(Address)
	 * @param counter the new target address
	 */
	void setCounter(Address counter);

	/**
	 * Get the value of the program counter of this thread
	 * 
	 * @return the value
	 */
	Address getCounter();

	/**
	 * Set the thread's program counter and write the pc register of its executor state
	 * 
	 * <p>
	 * <b>Warning:</b> Setting the counter into the middle of group constructs, e.g., parallel
	 * instructions or delay-slotted instructions, may cause undefined behavior.
	 * 
	 * @see #setCounter(Address)
	 * @param counter the new target address
	 */
	void overrideCounter(Address counter);

	/**
	 * Adjust the thread's decoding context without writing to its executor state
	 * 
	 * <p>
	 * As in {@link RegisterValue#assign(Register, RegisterValue)}, only those bits having a value
	 * in the given context are applied to the current context.
	 * 
	 * @see #overrideContext(RegisterValue)
	 * @param context the new context
	 */
	void assignContext(RegisterValue context);

	/**
	 * Get the thread's decoding context
	 * 
	 * @return the context
	 */
	RegisterValue getContext();

	/**
	 * Adjust the thread's decoding context and write the contextreg of its executor state
	 * 
	 * @see #assignContext(RegisterValue)
	 * @param context the new context
	 */
	void overrideContext(RegisterValue context);

	/**
	 * Set the context at the current counter to the default given by the language
	 * 
	 * <p>
	 * This also writes the context to the thread's state. For languages without context, this call
	 * does nothing.
	 */
	void overrideContextWithDefault();

	/**
	 * Re-sync the decode context and counter address from the machine state
	 */
	void reInitialize();

	/**
	 * Step emulation a single instruction
	 * 
	 * <p>
	 * Note because of the way Ghidra and Sleigh handle delay slots, the execution of an instruction
	 * with delay slots cannot be separated from the instructions filling those slots. It and its
	 * slotted instructions are executed in a single "step." However, stepping the individual p-code
	 * ops is still possible using {@link #stepPcodeOp()}.
	 */
	void stepInstruction();

	/**
	 * Repeat {@link #stepInstruction()} count times
	 * 
	 * @param count the number of instructions to step
	 */
	default void stepInstruction(long count) {
		for (long i = 0; i < count; i++) {
			stepInstruction();
		}
	}

	/**
	 * Step emulation a single p-code operation
	 * 
	 * <p>
	 * Execution of the current instruction begins if there is no current frame: A new frame is
	 * constructed and its counter is initialized. If a frame is present, and it has not been
	 * completed, its next operation is executed and its counter is stepped. If the current frame is
	 * completed, the machine's program counter is advanced and the current frame is removed.
	 * 
	 * <p>
	 * Consider the case of a fall-through instruction: The first p-code step decodes the
	 * instruction and sets up the p-code frame. The second p-code step executes the first p-code op
	 * of the frame. Each subsequent p-code step executes the next p-code op until no ops remain.
	 * The final p-code step detects the fall-through result, advances the counter, and disposes the
	 * frame. The next p-code step is actually the first p-code step of the next instruction.
	 * 
	 * <p>
	 * Consider the case of a branching instruction: The first p-code step decodes the instruction
	 * and sets up the p-code frame. The second p-code step executes the first p-code op of the
	 * frame. Each subsequent p-code step executes the next p-code op until an (external) branch is
	 * executed. That branch itself sets the program counter appropriately. The final p-code step
	 * detects the branch result and simply disposes the frame. The next p-code step is actually the
	 * first p-code step of the next instruction.
	 * 
	 * <p>
	 * The decode step in both examples is subject to p-code injections. In order to provide the
	 * most flexibility, there is no enforcement of various emulation state on this method. Expect
	 * strange behavior for strange call sequences.
	 * 
	 * <p>
	 * While this method heeds injects, such injects will obscure the p-code of the instruction
	 * itself. If the inject executes the instruction, the entire instruction will be executed when
	 * stepping the {@link PcodeEmulationLibrary#emu_exec_decoded()} userop, since there is not
	 * (currently) any way to "step into" a userop.
	 */
	void stepPcodeOp();

	/**
	 * Repeat {@link #stepPcodeOp()} count times
	 * 
	 * @param count the number of p-code operations to step
	 */
	default void stepPcodeOp(long count) {
		for (long i = 0; i < count; i++) {
			stepPcodeOp();
		}
	}

	/**
	 * Skip emulation of a single p-code operation
	 * 
	 * <p>
	 * If there is no current frame, this behaves as in {@link #stepPcodeOp()}. Otherwise, this
	 * skips the current pcode op, advancing as if a fall-through op. If no ops remain in the frame,
	 * this behaves as in {@link #stepPcodeOp()}. Please note to skip an extranal branch, the op
	 * itself must be skipped. "Skipping" the following op, which disposes the frame, cannot prevent
	 * the branch.
	 */
	void skipPcodeOp();

	/**
	 * Get the current frame, if present
	 * 
	 * <p>
	 * If the client only calls {@link #stepInstruction()} and execution completes normally, this
	 * method will always return {@code null}. If interrupted, the frame marks where execution of an
	 * instruction or inject should resume. Depending on the case, the frame may need to be stepped
	 * back in order to retry the failed p-code operation. If this frame is present, it means that
	 * the instruction has not been executed completed. Even if the frame
	 * {@link PcodeFrame#isFinished()},
	 * 
	 * @return the current frame
	 */
	PcodeFrame getFrame();

	/**
	 * Get the current decoded instruction, if applicable
	 * 
	 * @return the instruction
	 */
	Instruction getInstruction();

	/**
	 * Execute the next instruction, ignoring injects
	 * 
	 * <p>
	 * <b>WARNING:</b> This method should likely only be used internally. It steps the current
	 * instruction, but without any consideration for user injects, e.g., breakpoints. Most clients
	 * should call {@link #stepInstruction()} instead.
	 * 
	 * @throws IllegalStateException if the emulator is still in the middle of an instruction. That
	 *             can happen if the machine is interrupted, or if the client has called
	 *             {@link #stepPcodeOp()}.
	 */
	void executeInstruction();

	/**
	 * Finish execution of the current instruction or inject
	 * 
	 * <p>
	 * In general, this method is only used after an interrupt or fault in order to complete the
	 * p-code of the faulting instruction. Depending on the nature of the interrupt, this behavior
	 * may not be desired.
	 * 
	 * @throws IllegalStateException if there is no current instruction, i.e., the emulator has not
	 *             started executing the next instruction, yet.
	 */
	void finishInstruction();

	/**
	 * Decode, but skip the next instruction
	 */
	void skipInstruction();

	/**
	 * If there is a current instruction, drop its frame of execution
	 * 
	 * <p>
	 * <b>WARNING:</b> This does not revert any state changes caused by a partially-executed
	 * instruction. It is up to the client to revert the underlying machine state if desired. Note
	 * the thread's program counter will not be advanced. Likely, the next call to
	 * {@link #stepInstruction()} will re-start the same instruction. If there is no current
	 * instruction, this method has no effect.
	 */
	void dropInstruction();

	/**
	 * Emulate indefinitely
	 * 
	 * <p>
	 * This begins or resumes execution of the emulator. If there is a current instruction, that
	 * instruction is finished. By calling this method, you are "donating" the current Java thread
	 * to the emulator. This method will not likely return, but instead only terminates via
	 * exception, e.g., hitting a user breakpoint or becoming suspended. Depending on the use case,
	 * this method might be invoked from a Java thread dedicated to this emulated thread.
	 */
	void run();

	/**
	 * Set the suspension state of the thread's executor
	 * 
	 * <p>
	 * When {@link #run()} is invoked by a dedicated thread, suspending the pcode thread is the most
	 * reliable way to halt execution. Note the emulator may halt mid instruction. If this is not
	 * desired, then upon catching the exception, un-suspend the p-code thread and call
	 * {@link #finishInstruction()} or {@link #dropInstruction()}.
	 */
	void setSuspended(boolean suspended);

	/**
	 * Check the suspension state of the thread's executor
	 * 
	 * @return true if suspended
	 */
	boolean isSuspended();

	/**
	 * Get the thread's Sleigh language (processor model)
	 * 
	 * @return the language
	 */
	SleighLanguage getLanguage();

	/**
	 * Get the thread's p-code arithmetic
	 * 
	 * @return the arithmetic
	 */
	PcodeArithmetic<T> getArithmetic();

	/**
	 * Get the thread's p-code executor
	 * 
	 * <p>
	 * This can be used to execute injected p-code, e.g., as part of implementing a userop, or as
	 * part of testing, outside the thread's usual control flow. Any new frame generated by the
	 * executor is ignored by the thread. It retains the instruction frame, if any. Note that
	 * suspension is implemented by the executor, so if this p-code thread is suspended, the
	 * executor cannot execute any code.
	 * 
	 * @return the executor
	 */
	PcodeExecutor<T> getExecutor();

	/**
	 * Get the complete userop library for this thread
	 * 
	 * @return the library
	 */
	PcodeUseropLibrary<T> getUseropLibrary();

	/**
	 * Get the thread's memory and register state
	 * 
	 * <p>
	 * The memory part of this state is shared among all threads in the same machine. See
	 * {@link PcodeMachine#getSharedState()}.
	 * 
	 */
	ThreadPcodeExecutorState<T> getState();

	/**
	 * Override the p-code at the given address with the given Sleigh source for only this thread
	 * 
	 * <p>
	 * This works the same {@link PcodeMachine#inject(Address, List)} but on a per-thread basis.
	 * Where there is both a machine-level and thread-level inject the thread inject takes
	 * precedence. Furthermore, the machine-level inject cannot be accessed by the thread-level
	 * inject.
	 * 
	 * @param address the address to inject at
	 * @param source the Sleigh source to compile and inject
	 */
	void inject(Address address, String source);

	/**
	 * Remove the per-thread inject, if present, at the given address
	 * 
	 * <p>
	 * This has no effect on machine-level injects. If there is one present, it will still override
	 * this thread's p-code if execution reaches the address.
	 * 
	 * @param address the address to clear
	 */
	void clearInject(Address address);

	/**
	 * Remove all per-thread injects from this thread
	 * 
	 * <p>
	 * All machine-level injects are still effective after this call.
	 */
	void clearAllInjects();
}

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

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emulate.*;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The emulator interface
 * 
 * <p>
 * This interface may soon be deprecated. It was extracted from what has now been renamed
 * {@link DefaultEmulator}. Please consider using {@link PcodeEmulator} instead.
 */
public interface Emulator {

	/**
	 * Get the name of the program counter register
	 * 
	 * @return the name
	 */
	String getPCRegisterName();

	/**
	 * Set the value of the program counter
	 * 
	 * @param addressableWordOffset the <em>word</em> offset of the instruction to execute next.
	 */
	void setExecuteAddress(long addressableWordOffset);

	/**
	 * Get current execution address (or the address of the next instruction to be executed)
	 * 
	 * @return current execution address
	 */
	Address getExecuteAddress();

	/**
	 * Get the address of the last instruction executed (or the instructed currently being executed)
	 * 
	 * @return the address
	 */
	Address getLastExecuteAddress();

	/**
	 * Get the value of the program counter
	 * 
	 * @return the value, i.e., offset in code space
	 */
	long getPC();

	/**
	 * Execute instruction at current address
	 * 
	 * @param stopAtBreakpoint if true and breakpoint hits at current execution address execution
	 *            will halt without executing instruction.
	 * @throws CancelledException if execution was cancelled
	 */
	void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException, LowlevelError, InstructionDecodeException;

	/**
	 * @return true if emulator is busy executing an instruction
	 */
	boolean isExecuting();

	/**
	 * Get the low-level execution state
	 * 
	 * <p>
	 * This can be useful within a memory fault handler to determine if a memory read was associated
	 * with instruction parsing (i.e., {@link EmulateExecutionState#INSTRUCTION_DECODE}) or an
	 * actual emulated read (i.e., {@link EmulateExecutionState#EXECUTE}).
	 * 
	 * @return emulator execution state.
	 */
	EmulateExecutionState getEmulateExecutionState();

	/**
	 * Get the memory state
	 * 
	 * @return the state
	 */
	MemoryState getMemState();

	/**
	 * Add a filter on memory access
	 * 
	 * @param filter the filter
	 */
	void addMemoryAccessFilter(MemoryAccessFilter filter);

	/**
	 * Get the memory state, modified by all installed access filters
	 * 
	 * @return the state
	 */
	FilteredMemoryState getFilteredMemState();

	/**
	 * Sets the context register value at the current execute address.
	 * 
	 * <p>
	 * The Emulator should not be running when this method is invoked. Only flowing context bits
	 * should be set, as non-flowing bits will be cleared prior to parsing on instruction. In
	 * addition, any future context state set by the pcode emitter will take precedence over context
	 * set using this method. This method is primarily intended to be used to establish the initial
	 * context state.
	 * 
	 * @param regValue is the value to set context to
	 */
	void setContextRegisterValue(RegisterValue regValue);

	/**
	 * Returns the current context register value.
	 * 
	 * <p>
	 * The context value returned reflects its state when the previously executed instruction was
	 * parsed/executed. The context value returned will feed into the next instruction to be parsed
	 * with its non-flowing bits cleared and any future context state merged in.
	 * 
	 * @return context as a RegisterValue object
	 */
	RegisterValue getContextRegisterValue();

	/**
	 * Get the breakpoint table
	 * 
	 * @return the breakpoint table
	 */
	BreakTableCallBack getBreakTable();

	/**
	 * @return true if halted at a breakpoint
	 */
	boolean isAtBreakpoint();

	/**
	 * Halt or un-halt the emulator
	 * 
	 * @param halt true to halt
	 */
	void setHalt(boolean halt);

	/**
	 * Check if the emulator has been halted
	 * 
	 * @return true if halted
	 */
	boolean getHalt();

	/**
	 * Clean up resources used by the emulator
	 */
	void dispose();

}

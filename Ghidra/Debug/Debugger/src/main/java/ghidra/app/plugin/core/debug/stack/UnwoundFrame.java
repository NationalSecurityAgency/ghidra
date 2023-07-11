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
package ghidra.app.plugin.core.debug.stack;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueUtils;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A frame that has been unwound through analysis or annotated in the listing
 * 
 * <p>
 * An unwound frame can be obtained via {@link StackUnwinder} or {@link ListingUnwoundFrame}. The
 * former is used when stack unwind analysis has not yet been applied to the current trace snapshot.
 * It actually returns a {@link AnalysisUnwoundFrame}, which can apply the resulting analysis to the
 * snapshot. The latter is used when those annotations are already present.
 *
 * @param <T> the type of values retrievable from the unwound frame
 */
public interface UnwoundFrame<T> {
	/**
	 * Check if this is an actual frame
	 * 
	 * @see FakeUnwoundFrame
	 * @return true if fake
	 */
	boolean isFake();

	/**
	 * Get the level of this frame, 0 being the innermost
	 * 
	 * @return the level
	 */
	int getLevel();

	/**
	 * Get a description of this frame, for display purposes
	 * 
	 * @return the description
	 */
	String getDescription();

	/**
	 * Get the frame's program counter
	 * 
	 * <p>
	 * If this is the innermost frame, this is the next instruction to be executed. Otherwise, this
	 * is the return address of the next inner frame, i.e., the instruction to be executed after
	 * control is returned to the function that allocated this frame.
	 * 
	 * @return the frame's program counter
	 */
	Address getProgramCounter();

	/**
	 * Get the function that allocated this frame
	 * 
	 * <p>
	 * This is the function whose body contains the program counter
	 * 
	 * @return the frame's allocating function
	 */
	Function getFunction();

	/**
	 * Get the base pointer for this frame
	 * 
	 * <p>
	 * This is the value of the stack pointer at entry of the allocating function. Note while
	 * related, this is a separate thing from the "base pointer" register. Not all architectures
	 * offer one, and even on those that do, not all functions use it. Furthermore, a function that
	 * does use it may place a different value in the than we define as the base pointer. The value
	 * here is that recovered from an examination of stack operations from the function's entry to
	 * the program counter. It is designed such that varnodes with stack offsets can be located in
	 * this frame by adding the offset to this base pointer.
	 * 
	 * @return the frame's base pointer
	 */
	Address getBasePointer();

	/**
	 * Get the frame's return address
	 * 
	 * <p>
	 * The address of the return address is determined by an examination of stack and register
	 * operations from the program counter to a return of the function allocating this frame. Three
	 * cases are known:
	 * <ol>
	 * <li>The return address is on the stack. This happens for architectures where the caller must
	 * push the return address to the stack. It can also happen on architectures with a link
	 * register if the callee saves that register to the stack.</li>
	 * <li>The return address is in a register. This happens for architectures with a link register
	 * assuming the callee has not saved that register to the stack.</li>
	 * <li>The return address cannot be recovered. This happens when the function appears to be non
	 * returning, or the analysis otherwise fails to recover the return address. In this case, this
	 * method will throw an exception.
	 * </ol>
	 * 
	 * @return the return address
	 */
	Address getReturnAddress();

	/**
	 * Get the warnings generated during analysis
	 * 
	 * @return the warnings
	 */
	StackUnwindWarningSet getWarnings();

	/**
	 * If the unwind is in error or incomplete, get the error explaining why.
	 * 
	 * <p>
	 * When analysis is incomplete, the frame may still be partially unwound, meaning only certain
	 * variables can be evaluated, and the return address may not be available. Typically, a
	 * partially unwound frame is the last frame that can be recovered in the stack. If the base
	 * pointer could not be recovered, then only register variables and static variables can be
	 * evaluated.
	 * 
	 * @return the error
	 */
	Exception getError();

	/**
	 * Get the value of the storage from the frame
	 * 
	 * <p>
	 * Each varnode in the storage is retrieved and concatenated together. The lower-indexed
	 * varnodes have higher significance -- like big endian. A varnode is retrieved from the state,
	 * with register accesses potentially redirected to a location where its value has been saved to
	 * the stack.
	 * 
	 * <p>
	 * Each varnode's value is simply retrieved from the state, in contrast to
	 * {@link #evaluate(VariableStorage, AddressSetView)}, which ascends to varnodes' defining
	 * p-code ops.
	 * 
	 * <p>
	 * <b>WARNING:</b> Never invoke this method from the Swing thread. The state could be associated
	 * with a live session, and this may block to retrieve live state.
	 * 
	 * @param program the program containing the variable storage
	 * @param storage the storage
	 * @return the value
	 */
	T getValue(Program program, VariableStorage storage);

	/**
	 * Get the value of the variable from the frame
	 * 
	 * <p>
	 * <b>WARNING:</b> Never invoke this method from the Swing thread. The state could be associated
	 * with a live session, and this may block to retrieve live state.
	 * 
	 * @see #getValue(VariableStorage)
	 * @param variable the variable
	 * @return the value
	 */
	default T getValue(Variable variable) {
		return getValue(variable.getProgram(), variable.getVariableStorage());
	}

	/**
	 * Get the value of the register, possible saved elsewhere on the stack, relative to this frame
	 * 
	 * <p>
	 * <b>WARNING:</b> Never invoke this method from the Swing thread. The state could be associated
	 * with a live session, and this may block to retrieve live state.
	 * 
	 * @param register the register
	 * @return the value
	 */
	T getValue(Register register);

	/**
	 * Evaluate the given storage, following defining p-code ops until symbol storage is reached
	 * 
	 * <p>
	 * This behaves similarly to {@link #getValue(VariableStorage)}, except this one will ascend
	 * recursively to each varnode's defining p-code op. The recursion terminates when a varnode is
	 * contained in the given symbol storage. The symbol storage is usually collected by examining
	 * the tokens on the same line, searching for ones that represent "high symbols." This ensures
	 * that any temporary storage used by the original program in the evaluation of, e.g., a field
	 * access, are not read from the current state but re-evaluated in terms of the symbols' current
	 * values.
	 * 
	 * <p>
	 * <b>WARNING:</b> Never invoke this method from the Swing thread. The state could be associated
	 * with a live session, and this may block to retrieve live state.
	 * 
	 * @see VariableValueUtils#collectSymbolStorage(ClangLine)
	 * @param program the program containing the variable storage
	 * @param storage the storage to evaluate
	 * @param symbolStorage the terminal storage, usually that of symbols
	 * @return the value
	 */
	T evaluate(Program program, VariableStorage storage, AddressSetView symbolStorage);

	/**
	 * Evaluate the output for the given p-code op, ascending until symbol storage is reached
	 * 
	 * <p>
	 * <b>WARNING:</b> Never invoke this method from the Swing thread. The state could be associated
	 * with a live session, and this may block to retrieve live state.
	 * 
	 * @see #evaluate(VariableStorage, AddressSetView)
	 * @param program the program containing the op
	 * @param op the op
	 * @param symbolStorage the terminal storage, usually that of symbols
	 * @return the value
	 */
	T evaluate(Program program, PcodeOp op, AddressSetView symbolStorage);

	/**
	 * Set the value of the given storage
	 * 
	 * <p>
	 * Register accesses may be redirected to the location where its current value is saved to the
	 * stack.
	 * 
	 * @param editor the editor for setting values
	 * @param program the program containing the variable storage
	 * @param storage the storage to modify
	 * @param value the desired value
	 * @return a future which completes when the necessary commands have all completed
	 */
	CompletableFuture<Void> setValue(StateEditor editor, Program program, VariableStorage storage,
			BigInteger value);

	/**
	 * Set the value of the given variable
	 * 
	 * @see #setValue(StateEditor, VariableStorage, BigInteger)
	 * @param editor the editor for setting values
	 * @param variable the variable to modify
	 * @param value the desired value
	 * @return a future which completes when the necessary commands have all completed
	 */
	default CompletableFuture<Void> setValue(StateEditor editor, Variable variable,
			BigInteger value) {
		return setValue(editor, variable.getProgram(), variable.getVariableStorage(), value);
	}

	/**
	 * Set the return address of this frame
	 * 
	 * <p>
	 * This is typically used to set up a mechanism in pure emulation that traps execution when the
	 * entry function has returned. For example, to emulate a target function in isolation, a script
	 * could load or map the target program into a trace, initialize a thread at the target
	 * function's entry, allocate a stack, and "unwind" that stack. Then, it can initialize the
	 * function's parameters and return address. The return address is usually a fake but
	 * recognizable address, such as {@code 0xdeadbeef}. The script would then place a breakpoint at
	 * that address and allow the emulator to run. Once it breaks at {@code 0xdeadbeef}, the script
	 * can read the return value, if applicable.
	 * 
	 * @param editor the editor for setting values
	 * @param address the desired return address
	 * @return a future which completes when the necessary commands have all completed
	 */
	CompletableFuture<Void> setReturnAddress(StateEditor editor, Address address);

	/**
	 * Match length by zero extension or truncation
	 * 
	 * <p>
	 * This is to cope with a small imperfection in field expression evaluation: Fields are
	 * evaluated using the high p-code from the decompiled function that yielded the expression.
	 * That code is likely loading the value into a register, which is likely a machine word in
	 * size, even if the field being accessed is smaller. Thus, the type of a token's high variable
	 * may disagree in size with the output varnode of the token's associated high p-code op. To
	 * rectify this discrepancy during evaluation, the type's size is assumed correct, and the
	 * output value is resized to match.
	 * 
	 * @param value the value
	 * @param length the desired length
	 * @return the extended or truncated value
	 */
	T zext(T value, int length);
}

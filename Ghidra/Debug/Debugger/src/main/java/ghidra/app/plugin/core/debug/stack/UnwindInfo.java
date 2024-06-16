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

import java.util.Map;
import java.util.Map.Entry;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.task.TaskMonitor;

/**
 * Information for interpreting the current stack frame and unwinding to the next
 */
public record UnwindInfo(Function function, Long depth, Long adjust, Address ofReturn,
		Map<Register, Address> saved, StackUnwindWarningSet warnings, Exception error) {

	public static UnwindInfo errorOnly(Exception error) {
		return new UnwindInfo(null, null, null, null, null, new StackUnwindWarningSet(), error);
	}

	/**
	 * The function that was analyzed
	 * 
	 * @return the function
	 */
	public Function function() {
		return function;
	}

	/**
	 * The change in the stack pointer from function entry to the given program counter
	 * 
	 * <p>
	 * This is necessary to retrieve stack variables from the current frame. By subtracting this
	 * from the current stack pointer, the frame's base address is computed. See
	 * {@link #computeBase(Address)}. The offsets of stack variables are all relative to that base
	 * address. See {@link AnalysisUnwoundFrame#getValue(Variable)}.
	 * 
	 * @return the depth
	 */
	public Long depth() {
		return depth;
	}

	/**
	 * The adjustment to the stack pointer, at function entry, to return from this function
	 * 
	 * <p>
	 * This is used to unwind the stack pointer value for the next frame.
	 * 
	 * @return the adjustment
	 */
	public Long adjust() {
		return adjust;
	}

	/**
	 * The <em>address of</em> the return address
	 * 
	 * <p>
	 * The address may be a register or a stack offset, relative to the stack pointer at function
	 * entry.
	 * 
	 * @return the address of the return address
	 */
	public Address ofReturn() {
		return ofReturn;
	}

	/**
	 * The <em>address of</em> the return address, given a stack base
	 * 
	 * <p>
	 * The address may be a register or a stack offset, relative to the stack pointer at function
	 * entry, i.e., base. If it's the latter, then this will resolve it with respect to the given
	 * base. The result can be used to retrieve the return address from a state. See
	 * {@link #computeNextPc(Address, PcodeExecutorState, Register)}.
	 * 
	 * @param base the stack pointer at function entry
	 * @return the address of the return address
	 */
	public Address ofReturn(Address base) {
		if (ofReturn.isRegisterAddress()) {
			return ofReturn;
		}
		else if (ofReturn.isStackAddress()) {
			return base.add(ofReturn.getOffset());
		}
		throw new AssertionError();
	}

	/**
	 * The map of registers to stack offsets for saved registers
	 * 
	 * <p>
	 * This is not necessary until its time to unwind the next frame. The saved registers should be
	 * restored, then the next PC and SP computed, then the next frame unwound. See
	 * {@link AnalysisUnwoundFrame#unwindNext(TaskMonitor)}.
	 * 
	 * @return the map of registers to stack addresses
	 */
	public Map<Register, Address> saved() {
		return saved;
	}

	/**
	 * The list of warnings issues during analysis
	 * 
	 * @return the warnings
	 */
	public StackUnwindWarningSet warnings() {
		return warnings;
	}

	/**
	 * Compute the current frame's base address given the current (or unwound) stack pointer.
	 * 
	 * <p>
	 * This is used to retrieve variable values for the current frame.
	 * 
	 * @param spVal the stack pointer
	 * @return the base address
	 */
	public Address computeBase(Address spVal) {
		return depth == null ? null : spVal.subtract(depth);
	}

	/**
	 * Restore saved registers in the given state
	 * 
	 * <p>
	 * This is used as part of unwinding the next frame.
	 * 
	 * @param <T> the type of values in the state
	 * @param base the current frame's base pointer, as in {@link #computeBase(Address)}.
	 * @param state the state to modify, usually forked from the current frame's state
	 * @see AnalysisUnwoundFrame#unwindNext(TaskMonitor)
	 */
	public <T> void restoreRegisters(Address base, PcodeExecutorState<T> state) {
		for (Entry<Register, Address> ent : saved.entrySet()) {
			Register reg = ent.getKey();
			Address offset = ent.getValue();
			assert offset.isStackAddress();
			Address address = base.add(offset.getOffset());
			T value = state.getVar(address, reg.getNumBytes(), true, Reason.INSPECT);
			state.setVar(reg, value);
		}
	}

	/**
	 * Add register map entries for the saved registers in this frame
	 * 
	 * @param base the current frame's base pointer, as in {@link #computeBase(Address)}
	 * @param registerMap the register map of the stack to this point, to be modified
	 */
	public void mapSavedRegisters(Address base, SavedRegisterMap map) {
		for (Entry<Register, Address> ent : saved.entrySet()) {
			Register reg = ent.getKey();
			Address offset = ent.getValue();
			assert offset.isStackAddress();
			Address address = base.add(offset.getOffset());
			map.put(TraceRegisterUtils.rangeForRegister(reg), address);
		}
	}

	/**
	 * Compute the return address of the current frame, giving the unwound program counter of the
	 * next frame
	 * 
	 * <p>
	 * This is used as part of unwinding the next frame.
	 * 
	 * @param <T> the type of values in the state
	 * @param base the current frame's base pointer, as in {@link #computeBase(Address)}
	 * @param state the state of the next frame, whose program counter this method is computing
	 * @param pc the program counter register, used for its size
	 * @return the value of the program counter for the next frame
	 * @see AnalysisUnwoundFrame#unwindNext(TaskMonitor)
	 */
	public <T> T computeNextPc(Address base, PcodeExecutorState<T> state, Register pc) {
		return state.getVar(ofReturn(base), pc.getNumBytes(), true, Reason.INSPECT);
	}

	/**
	 * Compute the return address of the current frame, giving the unwound program counter (as a
	 * code address) of the next frame.
	 * 
	 * <p>
	 * This is used as part of unwinding the next frame.
	 * 
	 * @param <T> the type of values in the state
	 * @param base the current frame's base pointer, as in {@link #computeBase(Address)}
	 * @param state the state of the next frame, whose program counter this method is computing
	 * @param codeSpace the address space where the program counter points
	 * @param pc the program counter register, used for its size
	 * @return the address of the next instruction for the next frame
	 * @see AnalysisUnwoundFrame#unwindNext(TaskMonitor)
	 */
	public <T> Address computeNextPc(Address base, PcodeExecutorState<T> state,
			AddressSpace codeSpace, Register pc) {
		T value = computeNextPc(base, state, pc);
		long concrete = state.getArithmetic().toLong(value, Purpose.INSPECT);
		return codeSpace.getAddress(concrete);
	}

	/**
	 * Compute the unwound stack pointer for the next frame
	 * 
	 * <p>
	 * This is used as part of unwinding the next frame.
	 * 
	 * @param base the current frame's based pointer, as in {@link #computeBase(Address)}
	 * @return the stack pointer for the next frame
	 * @see AnalysisUnwoundFrame#unwindNext(TaskMonitor)
	 */
	public Address computeNextSp(Address base) {
		return base.add(adjust);
	}

	/**
	 * Get the number of bytes in the parameter portion of the frame
	 * 
	 * <p>
	 * These are the entries on the opposite side of the base pointer from the rest of the frame. In
	 * fact, these are pushed onto the stack by the caller, so these slots should be "stolen" from
	 * the caller's frame and given to the callee's frame.
	 * 
	 * @return the total parameter size in bytes
	 */
	public int computeParamSize() {
		return function.getStackFrame().getParameterSize();
	}
}

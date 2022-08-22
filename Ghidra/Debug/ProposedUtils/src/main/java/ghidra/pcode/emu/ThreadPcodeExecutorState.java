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

import java.util.Objects;

import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

/**
 * A p-code executor state that multiplexes shared and thread-local states for use in a machine that
 * models multi-threading
 * 
 * @param <T> the type of values stored in the states
 */
public class ThreadPcodeExecutorState<T> implements PcodeExecutorState<T> {
	protected final PcodeExecutorState<T> sharedState;
	protected final PcodeExecutorState<T> localState;
	protected final PcodeArithmetic<T> arithmetic;

	/**
	 * Create a multiplexed state
	 * 
	 * @see {@link DefaultPcodeThread#DefaultPcodeThread(String, AbstractPcodeMachine)}
	 * @param sharedState the shared part of the state
	 * @param localState the thread-local part of the state
	 */
	public ThreadPcodeExecutorState(PcodeExecutorState<T> sharedState,
			PcodeExecutorState<T> localState) {
		assert Objects.equals(sharedState.getArithmetic(), localState.getArithmetic());
		this.sharedState = sharedState;
		this.localState = localState;
		this.arithmetic = sharedState.getArithmetic();
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
		return arithmetic;
	}

	/**
	 * Decide whether or not access to the given space is directed to thread-local state
	 * 
	 * @param space the space
	 * @return true for thread-local state, false for shared state
	 */
	protected boolean isThreadLocalSpace(AddressSpace space) {
		return space.isRegisterSpace() || space.isUniqueSpace();
	}

	@Override
	public void setVar(AddressSpace space, T offset, int size, boolean quantize, T val) {
		if (isThreadLocalSpace(space)) {
			localState.setVar(space, offset, size, quantize, val);
			return;
		}
		sharedState.setVar(space, offset, size, quantize, val);
	}

	@Override
	public T getVar(AddressSpace space, T offset, int size, boolean quantize) {
		if (isThreadLocalSpace(space)) {
			return localState.getVar(space, offset, size, quantize);
		}
		return sharedState.getVar(space, offset, size, quantize);
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		assert !isThreadLocalSpace(address.getAddressSpace());
		return sharedState.getConcreteBuffer(address, purpose);
	}

	/**
	 * Get the shared state
	 * 
	 * @return the shared state
	 */
	public PcodeExecutorState<T> getSharedState() {
		return sharedState;
	}

	/**
	 * Get the thread-local state
	 * 
	 * @return the thread-local state
	 */
	public PcodeExecutorState<T> getLocalState() {
		return localState;
	}
}

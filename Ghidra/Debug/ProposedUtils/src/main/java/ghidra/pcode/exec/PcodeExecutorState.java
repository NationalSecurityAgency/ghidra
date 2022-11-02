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
package ghidra.pcode.exec;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.program.model.address.AddressSpace;

/**
 * An interface that provides storage for values of type {@code T}
 * 
 * <p>
 * This is not much more than a stricter form of {@link PcodeExecutorStatePiece}, in that it
 * requires the value and address offset types to agree, so that a p-code executor or emulator can
 * perform loads and stores using indirect addresses. The typical pattern for implementing a state
 * is to compose it from pieces. See {@link PcodeExecutorStatePiece}.
 * 
 * @param <T> the type of offsets and values
 */
public interface PcodeExecutorState<T> extends PcodeExecutorStatePiece<T, T> {

	@Override
	default PcodeArithmetic<T> getAddressArithmetic() {
		return getArithmetic();
	}

	/**
	 * Use this state as the control, paired with the given auxiliary state.
	 * 
	 * <p>
	 * <b>CAUTION:</b> Often, the default paired state is not quite sufficient. Consider
	 * {@link #getVar(AddressSpace, Object, int, boolean)}. The rider on the offset may offer
	 * information that must be incorporated into the rider of the value just read. This is the
	 * case, for example, with taint propagation. In those cases, an anonymous inner class extending
	 * {@link PairedPcodeExecutorState} is sufficient.
	 * 
	 * @param <U> the type of values and offsets stored by the rider
	 * @param right the rider state
	 * @return the paired state
	 */
	default <U> PcodeExecutorState<Pair<T, U>> paired(
			PcodeExecutorStatePiece<T, U> right) {
		return new PairedPcodeExecutorState<>(this, right);
	}
}

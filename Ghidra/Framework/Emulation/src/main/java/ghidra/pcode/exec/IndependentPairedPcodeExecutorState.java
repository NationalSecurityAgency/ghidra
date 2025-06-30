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

import java.util.*;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;

/**
 * A paired executor state
 * 
 * <p>
 * This composes a delegate state and piece "left" and "write" creating a single state which instead
 * stores pairs of values, where the left component has the value type of the left state, and the
 * right component has the value type of the right state. Note that each states is addressed using
 * its own value type. Every operation on this state is decomposed into operations upon the delegate
 * states, and the final result composed from the results of those operations.
 * 
 * <p>
 * Where a response cannot be composed of both states, the paired state defers to the left. In this
 * way, the left state controls the machine, while the right is computed in tandem. The right never
 * directly controls the machine
 * 
 * @param <L> the type of values for the "left" state
 * @param <R> the type of values for the "right" state
 */
public class IndependentPairedPcodeExecutorState<L, R>
		implements PcodeExecutorState<Pair<L, R>> {
	private final PcodeExecutorStatePiece<L, L> left;
	private final PcodeExecutorStatePiece<R, R> right;
	private final PcodeArithmetic<Pair<L, R>> arithmetic;

	public IndependentPairedPcodeExecutorState(PcodeExecutorStatePiece<L, L> left,
			PcodeExecutorStatePiece<R, R> right, PcodeArithmetic<Pair<L, R>> arithmetic) {
		this.left = left;
		this.right = right;
		this.arithmetic = arithmetic;
	}

	/**
	 * Compose a paired state from the given left and right states
	 * 
	 * @param left the state backing the left side of paired values ("control")
	 * @param right the state backing the right side of paired values ("auxiliary")
	 */
	public IndependentPairedPcodeExecutorState(PcodeExecutorStatePiece<L, L> left,
			PcodeExecutorStatePiece<R, R> right) {
		this(left, right, new PairedPcodeArithmetic<>(left.getArithmetic(), right.getArithmetic()));
	}

	@Override
	public Language getLanguage() {
		return left.getLanguage();
	}

	@Override
	public PcodeArithmetic<Pair<L, R>> getArithmetic() {
		return arithmetic;
	}

	@Override
	public IndependentPairedPcodeExecutorState<L, R> fork() {
		return new IndependentPairedPcodeExecutorState<>(left.fork(), right.fork(), arithmetic);
	}

	@Override
	public Map<Register, Pair<L, R>> getRegisterValues() {
		Map<Register, L> leftRVs = left.getRegisterValues();
		Map<Register, R> rightRVs = right.getRegisterValues();
		Set<Register> union = new HashSet<>();
		union.addAll(leftRVs.keySet());
		union.addAll(rightRVs.keySet());
		Map<Register, Pair<L, R>> result = new HashMap<>();
		for (Register k : union) {
			result.put(k, Pair.of(leftRVs.get(k), rightRVs.get(k)));
		}
		return result;
	}

	@Override
	public void setVar(AddressSpace space, Pair<L, R> offset, int size, boolean quantize,
			Pair<L, R> val) {
		left.setVar(space, offset.getLeft(), size, quantize, val.getLeft());
		right.setVar(space, offset.getRight(), size, quantize, val.getRight());
	}

	@Override
	public Pair<L, R> getVar(AddressSpace space, Pair<L, R> offset, int size, boolean quantize,
			Reason reason) {
		return Pair.of(
			left.getVar(space, offset.getLeft(), size, quantize, reason),
			right.getVar(space, offset.getRight(), size, quantize, reason));
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		return left.getConcreteBuffer(address, purpose);
	}

	/**
	 * Get the delegate backing the left side of paired values
	 * 
	 * @return the left state
	 */
	public PcodeExecutorStatePiece<L, L> getLeft() {
		return left;
	}

	/**
	 * Get the delegate backing the right side of paired values
	 * 
	 * @return the right state
	 */
	public PcodeExecutorStatePiece<R, R> getRight() {
		return right;
	}

	@Override
	public void clear() {
		left.clear();
		right.clear();
	}
}
